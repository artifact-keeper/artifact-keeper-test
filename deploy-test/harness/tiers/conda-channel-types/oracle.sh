#!/usr/bin/env bash
# =============================================================================
# tiers/conda-channel-types/oracle.sh — conda channel documents by repository
#   type, conda audit rows, conda security metrics
#   (artifact-keeper#4708 / #4709 / #4711)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH. The mock channel lives at http://172.16.<slot>.70/ and stamps
# every document with the marker "dtfmockconda<slot>" (see
# fixtures/mock_conda.py), so a document PROXIED from it is told apart from
# one Artifact Keeper built from its own (for a remote: nonexistent) rows.
#
# Topology the oracle builds (keys suffixed per run):
#   H  hosted conda channel: dtfhost-pkg 1.0 + 2.0 (control), dtfhost-wd 1.0
#      (withdrawn), dtfhost-hook 1.0 (carries a post-link script)
#   R  remote conda channel -> the mock
#   V  virtual, only member R
#   A  virtual, only member R, allowlist admits only `dtfup-alpha`
#   S  virtual, only member R, with an RSA metadata signing key
#
# Gates (each fix assertion is RED on 1.11.1, each CONTROL holds on both):
#   #4708  R serves the UPSTREAM current_repodata / run_exports /
#          patch_instructions / repodata.json.sig; V derives current_repodata
#          (newest version only) and merges run_exports from R; V and H answer
#          404 for patch_instructions; S's .sig verifies against the
#          repodata.json S serves, with the key S publishes.
#          CONTROL: H's repodata/current_repodata list its uploads; R and V
#          repodata.json carry the upstream records; H's .sig is 404 (no key).
#   #4709  exactly one audit_log row per native publish (ARTIFACT_UPLOADED with
#          conda coordinates), per withdraw (CONDA_PACKAGE_WITHDRAWN), per
#          refused attestation PUT (ATTESTATION_REJECTED), per environment
#          ingest/delete (ENVIRONMENT_REGISTERED / ENVIRONMENT_DELETED).
#          CONTROL: the operations themselves succeed with the same answers.
#   #4711  /api/v1/admin/metrics carries ak_conda_allowlist_dropped_total for
#          (A, R), ak_conda_install_script_findings_total{kind="post-link"} for
#          H, and ak_conda_attestation_total for H with outcome rejected and
#          absent. CONTROL: A's repodata.json drops the non-allowlisted record.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MARKER="dtfmockconda${SLOT}"
UPSTREAM="http://172.16.${SLOT}.70/"

H="cct-host-${SUF}"
R="cct-remote-${SUF}"
V="cct-virt-${SUF}"
A="cct-allow-${SUF}"
S="cct-signed-${SUF}"

ALPHA1="dtfup-alpha-1.0-0.tar.bz2"
ALPHA2="dtfup-alpha-2.0-0.tar.bz2"
BLOCKED="dtfup-blocked-1.0-0.tar.bz2"
PKG1="dtfhost-pkg-1.0-0.tar.bz2"
PKG2="dtfhost-pkg-2.0-0.tar.bz2"
WD="dtfhost-wd-1.0-0.tar.bz2"
HOOK="dtfhost-hook-1.0-0.tar.bz2"
WD_REASON="dtf withdraw ${SUF}"
ENV_NAME="dtf-env-${SUF}"

WORK="$(mktemp -d -t dtf-cct-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

AUDIT_WAIT=30

# --- helpers ------------------------------------------------------------------

# hget <path> <outfile> -> echoes HTTP status (anonymous; every repo is public)
hget() {
  curl -s --max-time 60 -o "$2" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000
}

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null
}

# audit_rows <action> <sql predicate on details/resource_id> -> row count
audit_rows() {
  psql_q "SELECT count(*) FROM audit_log WHERE action = '$1' AND ($2)"
}
audit_rows_at_least_one() { [ "$(audit_rows "$1" "$2")" -ge 1 ] 2>/dev/null; }

# metric_value <name> <label=value>... -> the sample value, or empty
METRICS="$WORK/metrics.txt"
scrape_metrics() {
  curl -s --max-time 30 -o "$METRICS" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}
metric_value() {
  local name="$1"; shift
  python3 -I - "$METRICS" "$name" "$@" <<'PY'
import re, sys
path, name, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
want = dict(w.split("=", 1) for w in wanted)
for line in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r'^([A-Za-z_:][\w:]*)\{(.*)\}\s+(\S+)', line)
    if not m or m.group(1) != name:
        continue
    labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2)))
    if all(labels.get(k) == v for k, v in want.items()):
        print(m.group(3))
        break
PY
}
metric_ge() {  # metric_ge <min> <name> <labels...>
  local min="$1"; shift
  local v; v="$(metric_value "$@")"
  [ -n "$v" ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' "$v" "$min"
}

# metric_eventually <min> <name> <labels...>: re-scrape until the sample is
# >= min (the counters are bumped in the request path, but give the upload's
# best-effort harvest a few seconds before calling the metric absent).
_rescrape_ge() { scrape_metrics >/dev/null; metric_ge "$@"; }
metric_eventually() { wait_until "$2 >= $1" 15 _rescrape_ge "$@"; }

conda_put() {  # conda_put <repo> <file> <filename> -> status, body in $WORK/put.out
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$2" \
    "${BASE_URL}/conda/$1/noarch/$3" 2>/dev/null || echo 000
}

# A conda v1 package with a post-link install script in its payload.
build_hook_pkg() {
  local d="$WORK/hook"
  mkdir -p "$d/info" "$d/bin"
  printf '%s\n' '{"name":"dtfhost-hook","version":"1.0","build":"0","build_number":0,"noarch":"generic","platform":null,"subdir":"noarch","depends":[],"license":"MIT"}' > "$d/info/index.json"
  printf '#!/bin/sh\necho dtf post-link\n' > "$d/bin/.dtfhost-hook-post-link.sh"
  printf '%s\n' '{"paths_version":1,"paths":[]}' > "$d/info/paths.json"
  printf 'bin/.dtfhost-hook-post-link.sh\n' > "$d/info/files"
  tar -cjf "$WORK/${HOOK}" -C "$d" info bin
}

begin_suite "conda-channel-types (#4708 #4709 #4711)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, repositories, uploads"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$R" conda remote "$UPSTREAM" || setup_err+="create remote; "
for v in "$V" "$A" "$S"; do
  create_repo "$v" conda virtual || setup_err+="create virtual ${v}; "
  api_post "/api/v1/repositories/${v}/members" "{\"member_key\":\"${R}\"}" >/dev/null \
    || setup_err+="add member to ${v}; "
done
api_put "/api/v1/repositories/${A}/allowlist" \
  '{"enabled":true,"entries":[{"name":"dtfup-alpha"}]}' >/dev/null \
  || setup_err+="set allowlist on ${A}; "

S_ID="$(api_get "/api/v1/repositories/${S}" | jq -r '.id // empty')"
KEY_ID=""
if [ -n "$S_ID" ]; then
  KEY_ID="$(api_post "/api/v1/signing/keys" \
    "{\"name\":\"cct-${SUF}\",\"key_type\":\"rsa\",\"algorithm\":\"rsa2048\",\"repository_id\":\"${S_ID}\"}" \
    | jq -r '.id // empty')"
fi
if [ -n "$KEY_ID" ]; then
  api_post "/api/v1/signing/repositories/${S_ID}/config" \
    "{\"signing_key_id\":\"${KEY_ID}\",\"sign_metadata\":true}" >/dev/null \
    || setup_err+="attach signing key; "
else
  setup_err+="create signing key; "
fi

BUILD="${DTF_DIR}/fixtures/conda/build.sh"
for spec in "dtfhost-pkg 1.0" "dtfhost-pkg 2.0" "dtfhost-wd 1.0"; do
  # shellcheck disable=SC2086
  set -- $spec
  bash "$BUILD" "$WORK" "$1" "$2" 0 noarch >/dev/null 2>&1 || setup_err+="build $1-$2; "
done
build_hook_pkg || setup_err+="build hook pkg; "

UPLOADS=0
for fn in "$PKG1" "$PKG2" "$WD" "$HOOK"; do
  st="$(conda_put "$H" "$WORK/$fn" "$fn")"
  if [ "$st" = "201" ] || [ "$st" = "200" ]; then
    UPLOADS=$((UPLOADS + 1))
  else
    setup_err+="upload ${fn} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); "
  fi
done

if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4708 CONTROL — what already worked must keep working
# =============================================================================
begin_test "CONTROL #4708: hosted repodata.json and current_repodata.json list the uploads"
st1="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd.json")"
st2="$(hget "/conda/${H}/noarch/current_repodata.json" "$WORK/h_cur.json")"
rd_keys="$(jq -c '.packages | keys' "$WORK/h_rd.json" 2>/dev/null)"
cur_keys="$(jq -c '.packages | keys' "$WORK/h_cur.json" 2>/dev/null)"
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && jq -e --arg a "$PKG1" --arg b "$PKG2" '.packages | has($a) and has($b)' "$WORK/h_rd.json" >/dev/null 2>&1 \
   && jq -e --arg b "$PKG2" '.packages | has($b)' "$WORK/h_cur.json" >/dev/null 2>&1; then
  pass
else
  fail "hosted channel documents do not list the uploads" \
    "repodata.json HTTP ${st1} keys=${rd_keys}; current_repodata.json HTTP ${st2} keys=${cur_keys}"
fi

begin_test "CONTROL #4708: remote and virtual repodata.json carry the upstream records"
st1="$(hget "/conda/${R}/noarch/repodata.json" "$WORK/r_rd.json")"
st2="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_rd.json")"
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && jq -e --arg a "$ALPHA1" --arg b "$ALPHA2" --arg c "$BLOCKED" '.packages | has($a) and has($b) and has($c)' "$WORK/r_rd.json" >/dev/null 2>&1 \
   && jq -e --arg a "$ALPHA1" --arg b "$ALPHA2" --arg c "$BLOCKED" '.packages | has($a) and has($b) and has($c)' "$WORK/v_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "remote/virtual repodata.json lost the upstream records" \
    "remote HTTP ${st1} keys=$(jq -c '.packages|keys' "$WORK/r_rd.json" 2>/dev/null); virtual HTTP ${st2} keys=$(jq -c '.packages|keys' "$WORK/v_rd.json" 2>/dev/null)"
fi

begin_test "CONTROL #4708: hosted repodata.json.sig is 404 without a signing key"
st="$(hget "/conda/${H}/noarch/repodata.json.sig" "$WORK/h_sig")"
assert_eq "$st" "404" "hosted .sig without a key: want 404, got HTTP ${st}" && pass

# =============================================================================
# #4708 — Remote proxies the siblings from upstream
# =============================================================================
begin_test "#4708: remote current_repodata.json is the upstream document"
st="$(hget "/conda/${R}/noarch/current_repodata.json" "$WORK/r_cur.json")"
if [ "$st" = "200" ] \
   && jq -e --arg m "${MARKER}-current" --arg b "$ALPHA2" \
        '.info.dtf_marker == $m and (.packages | keys) == [$b]' "$WORK/r_cur.json" >/dev/null 2>&1; then
  pass
else
  fail "remote current_repodata.json is not the upstream's" "HTTP ${st}: $(head -c 400 "$WORK/r_cur.json")"
fi

begin_test "#4708: remote run_exports.json is the upstream document"
st="$(hget "/conda/${R}/noarch/run_exports.json" "$WORK/r_rx.json")"
if [ "$st" = "200" ] \
   && jq -e --arg m "${MARKER}-runexp" --arg b "$ALPHA2" \
        '.packages[$b].run_exports.weak == [$m]' "$WORK/r_rx.json" >/dev/null 2>&1; then
  pass
else
  fail "remote run_exports.json is not the upstream's" "HTTP ${st}: $(head -c 400 "$WORK/r_rx.json")"
fi

begin_test "#4708: remote patch_instructions.json is the upstream document"
st="$(hget "/conda/${R}/noarch/patch_instructions.json" "$WORK/r_pi.json")"
if [ "$st" = "200" ] \
   && jq -e --arg m "${MARKER}-removed-1.0-0.tar.bz2" '.remove == [$m]' "$WORK/r_pi.json" >/dev/null 2>&1; then
  pass
else
  fail "remote patch_instructions.json is not the upstream's" "HTTP ${st}: $(head -c 400 "$WORK/r_pi.json")"
fi

begin_test "#4708: remote repodata.json.sig is the upstream signature, byte for byte"
st="$(hget "/conda/${R}/noarch/repodata.json.sig" "$WORK/r_sig")"
printf '%s\n' "${MARKER}-SIG" > "$WORK/expected_sig"
if [ "$st" = "200" ] && cmp -s "$WORK/r_sig" "$WORK/expected_sig"; then
  pass
else
  fail "remote .sig is not the upstream's" "HTTP ${st}: $(head -c 200 "$WORK/r_sig")"
fi

# =============================================================================
# #4708 — Virtual derives / merges from its members
# =============================================================================
begin_test "#4708: virtual current_repodata.json keeps the newest upstream version of each name"
st="$(hget "/conda/${V}/noarch/current_repodata.json" "$WORK/v_cur.json")"
if [ "$st" = "200" ] \
   && jq -e --arg b "$ALPHA2" --arg c "$BLOCKED" \
        '(.packages | keys) == ([$b, $c] | sort)' "$WORK/v_cur.json" >/dev/null 2>&1; then
  pass
else
  fail "virtual current_repodata.json is not derived from the merged repodata" \
    "HTTP ${st}: keys=$(jq -c '.packages|keys' "$WORK/v_cur.json" 2>/dev/null) (want ${ALPHA2} + ${BLOCKED}, not ${ALPHA1})"
fi

begin_test "#4708: virtual run_exports.json merges the remote member's entries"
st="$(hget "/conda/${V}/noarch/run_exports.json" "$WORK/v_rx.json")"
if [ "$st" = "200" ] \
   && jq -e --arg m "${MARKER}-runexp" --arg b "$ALPHA2" \
        '.packages[$b].run_exports.weak == [$m]' "$WORK/v_rx.json" >/dev/null 2>&1; then
  pass
else
  fail "virtual run_exports.json lacks the remote member's entries" "HTTP ${st}: $(head -c 400 "$WORK/v_rx.json")"
fi

begin_test "#4708: virtual and hosted patch_instructions.json answer 404 (no invented empty document)"
st_v="$(hget "/conda/${V}/noarch/patch_instructions.json" "$WORK/v_pi.json")"
st_h="$(hget "/conda/${H}/noarch/patch_instructions.json" "$WORK/h_pi.json")"
if [ "$st_v" = "404" ] && [ "$st_h" = "404" ]; then
  pass
else
  fail "patch_instructions.json served for a non-remote channel" \
    "virtual HTTP ${st_v}: $(head -c 200 "$WORK/v_pi.json"); hosted HTTP ${st_h}: $(head -c 200 "$WORK/h_pi.json")"
fi

begin_test "#4708: signed virtual's repodata.json.sig verifies against the repodata.json it serves"
st_k="$(hget "/conda/${S}/keys/repo.pub" "$WORK/s_pub.pem")"
st_r="$(hget "/conda/${S}/noarch/repodata.json" "$WORK/s_rd.json")"
st_s="$(hget "/conda/${S}/noarch/repodata.json.sig" "$WORK/s_sig")"
if [ "$st_k" != "200" ] || [ "$st_r" != "200" ]; then
  infra_fail "signed virtual: key or repodata not served" "repo.pub HTTP ${st_k}; repodata.json HTTP ${st_r}"
elif ! jq -e --arg b "$ALPHA2" '.packages | has($b)' "$WORK/s_rd.json" >/dev/null 2>&1; then
  infra_fail "signed virtual's repodata.json does not carry the upstream records" "$(head -c 300 "$WORK/s_rd.json")"
elif [ "$st_s" = "200" ] && verify_out="$(openssl dgst -sha256 -verify "$WORK/s_pub.pem" \
        -signature "$WORK/s_sig" "$WORK/s_rd.json" 2>&1)"; then
  pass
else
  fail "virtual .sig does not cover the served repodata.json" \
    "sig HTTP ${st_s}; openssl: ${verify_out:-not run}"
fi

# =============================================================================
# #4709 — audit rows
# =============================================================================
begin_test "#4709: native publish writes one ARTIFACT_UPLOADED row with conda coordinates"
pred="details->>'repository' = '${H}' AND details->'package'->>'filename' = '${PKG1}' AND details->'package'->>'name' = 'dtfhost-pkg' AND details->'package'->>'version' = '1.0' AND resource_type = 'artifact'"
if wait_until "ARTIFACT_UPLOADED for ${PKG1}" "$AUDIT_WAIT" audit_rows_at_least_one ARTIFACT_UPLOADED "$pred"; then
  n="$(audit_rows ARTIFACT_UPLOADED "$pred")"
  assert_eq "$n" "1" "want exactly 1 ARTIFACT_UPLOADED row for ${PKG1}, got ${n}" && pass
else
  fail "no ARTIFACT_UPLOADED audit row for the conda publish" \
    "$(psql_q "SELECT action, details FROM audit_log WHERE action='ARTIFACT_UPLOADED' ORDER BY created_at DESC LIMIT 3")"
fi

begin_test "#4709: withdraw writes one CONDA_PACKAGE_WITHDRAWN row"
wd_st="$(curl -s --max-time 60 -o "$WORK/wd.json" -w '%{http_code}' -X DELETE \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"reason\":\"${WD_REASON}\"}" "${BASE_URL}/conda/${H}/noarch/${WD}" 2>/dev/null || echo 000)"
WD_ART="$(jq -r '.artifact_id // empty' "$WORK/wd.json" 2>/dev/null)"
if [ "$wd_st" != "200" ] || [ -z "$WD_ART" ] || ! jq -e '.withdrawn == true' "$WORK/wd.json" >/dev/null 2>&1; then
  fail "CONTROL: withdraw did not succeed" "HTTP ${wd_st}: $(head -c 300 "$WORK/wd.json")"
else
  pred="resource_id = '${WD_ART}' AND details->>'reason' = '${WD_REASON}' AND (details->'hold'->>'permanent')::boolean AND details->'package'->>'name' = 'dtfhost-wd'"
  if wait_until "CONDA_PACKAGE_WITHDRAWN" "$AUDIT_WAIT" audit_rows_at_least_one CONDA_PACKAGE_WITHDRAWN "$pred"; then
    n="$(audit_rows CONDA_PACKAGE_WITHDRAWN "$pred")"
    assert_eq "$n" "1" "want exactly 1 CONDA_PACKAGE_WITHDRAWN row, got ${n}" && pass
  else
    fail "no CONDA_PACKAGE_WITHDRAWN audit row" \
      "$(psql_q "SELECT action, resource_id FROM audit_log WHERE resource_id = '${WD_ART}'")"
  fi
fi

begin_test "#4709: refused attestation PUTs write ATTESTATION_REJECTED rows"
att_url="${BASE_URL}/conda/${H}/noarch/${PKG2}/attestation"
st_bad="$(curl -s --max-time 60 -o "$WORK/att1" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d '{not json' "$att_url" 2>/dev/null || echo 000)"
st_uns="$(curl -s --max-time 60 -o "$WORK/att2" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d '{}' "$att_url" 2>/dev/null || echo 000)"
if [ "$st_bad" != "400" ] || [ "$st_uns" != "400" ]; then
  fail "CONTROL: attestation PUTs were not refused" \
    "malformed HTTP ${st_bad}: $(head -c 200 "$WORK/att1"); unsigned HTTP ${st_uns}: $(head -c 200 "$WORK/att2")"
else
  base="details->>'repository' = '${H}' AND details->'package'->>'filename' = '${PKG2}' AND details->>'stored' = 'false'"
  p_bad="${base} AND details->>'reason' = 'Invalid JSON body'"
  p_uns="${base} AND details->>'reason' <> 'Invalid JSON body'"
  if wait_until "ATTESTATION_REJECTED x2" "$AUDIT_WAIT" audit_rows_at_least_one ATTESTATION_REJECTED "$p_uns" \
     && [ "$(audit_rows ATTESTATION_REJECTED "$p_bad")" = "1" ] \
     && [ "$(audit_rows ATTESTATION_REJECTED "$p_uns")" = "1" ]; then
    pass
  else
    fail "refused attestations not audited (want one row each for malformed and unsigned)" \
      "malformed rows=$(audit_rows ATTESTATION_REJECTED "$p_bad") unsigned rows=$(audit_rows ATTESTATION_REJECTED "$p_uns")"
  fi
fi

begin_test "#4709: environment ingest and delete write ENVIRONMENT_REGISTERED / ENVIRONMENT_DELETED"
cat > "$WORK/conda-lock.yml" <<'YAML'
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: pillow
    version: 10.0.0
    manager: conda
    platform: linux-64
    dependencies:
      libwebp: ">=1.3.2"
  - name: libwebp
    version: 1.3.2
    manager: conda
    platform: linux-64
    dependencies: {}
YAML
env_st="$(curl -s --max-time 60 -o "$WORK/env.json" -w '%{http_code}' -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/conda-lock.yml" \
  "${BASE_URL}/api/v1/repositories/${H}/environments?filename=conda-lock.yml&name=${ENV_NAME}" 2>/dev/null || echo 000)"
ENV_ID="$(jq -r '.id // empty' "$WORK/env.json" 2>/dev/null)"
if [ "$env_st" != "201" ] || [ -z "$ENV_ID" ]; then
  fail "CONTROL: environment ingest failed" "HTTP ${env_st}: $(head -c 300 "$WORK/env.json")"
else
  del_st="$(curl -s --max-time 60 -o "$WORK/envdel" -w '%{http_code}' -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${H}/environments/${ENV_ID}" 2>/dev/null || echo 000)"
  p_reg="resource_type = 'environment' AND resource_id = '${ENV_ID}' AND details->>'name' = '${ENV_NAME}' AND details->>'lockfile_format' = 'conda-lock' AND details->>'package_count' = '2' AND details->>'repository' = '${H}'"
  p_del="resource_type = 'environment' AND resource_id = '${ENV_ID}' AND details->>'name' = '${ENV_NAME}'"
  if [ "$del_st" != "204" ]; then
    fail "CONTROL: environment delete failed" "HTTP ${del_st}: $(head -c 300 "$WORK/envdel")"
  elif wait_until "ENVIRONMENT_DELETED" "$AUDIT_WAIT" audit_rows_at_least_one ENVIRONMENT_DELETED "$p_del" \
       && [ "$(audit_rows ENVIRONMENT_REGISTERED "$p_reg")" = "1" ] \
       && [ "$(audit_rows ENVIRONMENT_DELETED "$p_del")" = "1" ]; then
    pass
  else
    fail "environment lifecycle not audited" \
      "registered rows=$(audit_rows ENVIRONMENT_REGISTERED "$p_reg") deleted rows=$(audit_rows ENVIRONMENT_DELETED "$p_del")"
  fi
fi

# =============================================================================
# #4711 — metrics
# =============================================================================
begin_test "CONTROL #4711: the allowlisted virtual's repodata.json drops the non-admitted record"
st="$(hget "/conda/${A}/noarch/repodata.json" "$WORK/a_rd.json")"
if [ "$st" = "200" ] \
   && jq -e --arg a "$ALPHA1" --arg b "$ALPHA2" '(.packages | keys) == [$a, $b]' "$WORK/a_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "allowlist not applied to the virtual's repodata.json" \
    "HTTP ${st}: keys=$(jq -c '.packages|keys' "$WORK/a_rd.json" 2>/dev/null)"
fi

begin_test "CONTROL #4711: /api/v1/admin/metrics answers with Prometheus text"
mst="$(scrape_metrics)"
if [ "$mst" = "200" ] && grep -q '^# TYPE ' "$METRICS"; then
  pass
else
  infra_fail "metrics endpoint unusable" "HTTP ${mst}: $(head -c 200 "$METRICS")"
fi

begin_test "#4711: ak_conda_allowlist_dropped_total counts the drop for (virtual, remote member)"
if metric_eventually 1 ak_conda_allowlist_dropped_total "repository=${A}" "member=${R}"; then
  pass
else
  fail "no ak_conda_allowlist_dropped_total{repository=${A},member=${R}} >= 1" \
    "$(grep '^ak_conda_' "$METRICS" | head -20)"
fi

begin_test "#4711: ak_conda_install_script_findings_total counts the post-link script"
if metric_eventually 1 ak_conda_install_script_findings_total "repository=${H}" "kind=post-link"; then
  pass
else
  fail "no ak_conda_install_script_findings_total{repository=${H},kind=post-link} >= 1" \
    "$(grep '^ak_conda_' "$METRICS" | head -20)"
fi

begin_test "#4711: ak_conda_attestation_total counts rejected and absent outcomes"
if metric_eventually 1 ak_conda_attestation_total "repository=${H}" "outcome=rejected" \
   && metric_eventually "$UPLOADS" ak_conda_attestation_total "repository=${H}" "outcome=absent"; then
  pass
else
  fail "ak_conda_attestation_total for ${H}: want rejected >= 1 and absent >= ${UPLOADS}" \
    "rejected=$(metric_value ak_conda_attestation_total "repository=${H}" "outcome=rejected") absent=$(metric_value ak_conda_attestation_total "repository=${H}" "outcome=absent")"
fi

end_suite
