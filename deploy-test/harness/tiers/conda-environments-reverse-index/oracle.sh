#!/usr/bin/env bash
# =============================================================================
# tiers/conda-environments-reverse-index/oracle.sh - environment SBOM graphs,
#   stored environments, the component -> environment reverse index and its
#   advisory re-evaluation (artifact-keeper#4053, #4054, #4055, #4670)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-osv` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH, TRIVY_PORT. The backend's api.osv.dev is the mock; its control
# port is http://127.0.0.1:${TRIVY_PORT}.
#
# The lockfile (conda-lock.yml) has two graphs:
#   linux-64: pillow 10.0.1 -> libwebp 1.3.2, and requests 2.18.4 (pip)
#   osx-64:   libwebp 1.3.2 alone
# It is stored as environment E in a public hosted conda repo PUB, and as
# environment Q in a PRIVATE repo PRIV that a plain user U cannot read.
#
# #4055 drive: the delta DETECTION is the advisory client's in-memory cache
# noticing a changed answer after its one-hour TTL, which no tier can wait
# out; the oracle therefore records the pending delta row exactly as
# DbAdvisoryDeltaSink does (advisory_deltas upsert) and lets the real
# scheduler tick (60 s, singleton lease) drain it against the mock feed. The
# backend is restarted between phases so the feed is asked afresh rather than
# answered from that cache.
#
# RED on 1.10.0 for every 1.11.0 case; the #4670 cases are RED on 1.11.0 too.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
: "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below must survive a non-2xx or a
# non-JSON body (the baseline images answer both), so evaluate them explicitly.
set +e

SUF="${RUN_ID##*-}-$$"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
PUB="cer-pub-${SUF}"
PRIV="cer-priv-${SUF}"
ENV_E="dtf-env-${SUF}"
ENV_Q="dtf-priv-env-${SUF}"
USER_U="cer-user-${SUF//-/}"
USER_PW="Dtf!${SUF//-/}Pw9"
GHSA="GHSA-dtfe-${SUF//-/}-0001"

WORK="$(mktemp -d -t dtf-cer-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

TICK_WAIT=150

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null
}

# req <METHOD> <path> <outname> [curl args] -> status (admin bearer)
req() {
  local m="$1" p="$2" o="$3"; shift 3
  curl -s --max-time 60 -o "$WORK/$o" -w '%{http_code}' -X "$m" -H "$(auth_header)" "$@" \
    "${BASE_URL}${p}" 2>/dev/null || echo 000
}
# post_lock <path> <outname> -> status
post_lock() {
  req POST "$1" "$2" -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/conda-lock.yml"
}

cat > "$WORK/conda-lock.yml" <<'YAML'
version: 1
metadata:
  content_hash:
    linux-64: hash-linux
    osx-64: hash-osx
  channels:
  - url: conda-forge
    used_env_vars: []
  platforms:
  - linux-64
  - osx-64
package:
- name: libwebp
  version: 1.3.2
  manager: conda
  platform: linux-64
  dependencies: {}
  url: https://conda.anaconda.org/conda-forge/linux-64/libwebp-1.3.2-h1234_0.conda
  hash:
    sha256: aaaa1111
- name: pillow
  version: 10.0.1
  manager: conda
  platform: linux-64
  dependencies:
    libwebp: '>=1.3.2,<2.0a0'
  url: https://conda.anaconda.org/conda-forge/linux-64/pillow-10.0.1-py311h1111_0.conda
  hash:
    sha256: dddd1111
- name: requests
  version: 2.18.4
  manager: pip
  platform: linux-64
  dependencies: {}
  url: https://files.pythonhosted.org/packages/requests-2.18.4-py2.py3-none-any.whl
  hash:
    sha256: bbbb2222
- name: libwebp
  version: 1.3.2
  manager: conda
  platform: osx-64
  dependencies: {}
  url: https://conda.anaconda.org/conda-forge/osx-64/libwebp-1.3.2-h8888_0.conda
  hash:
    sha256: aaaa3333
YAML

# --- mock OSV control --------------------------------------------------------
mock_mode() { curl -s --max-time 5 -X PUT --data "$1" "${MOCK}/__mode" | jq -r '.mode // empty' 2>/dev/null; }
mock_advisories() { curl -s --max-time 5 -X PUT --data "$1" "${MOCK}/__advisories" | jq -r '.rules // empty' 2>/dev/null; }
ADV_ON="$(jq -nc --arg id "$GHSA" '{
  rules:[{ecosystem:"PyPI", name:"requests", version:"2.18.4", ids:[$id]}],
  records:{($id):{id:$id, modified:"2026-01-01T00:00:00Z",
    summary:"DTF requests credential leak on redirect", details:"dtf",
    aliases:["CVE-2099-4055"], database_specific:{severity:"HIGH"},
    affected:[{package:{ecosystem:"PyPI", name:"requests"},
      ranges:[{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"2.20.0"}]}]}]}}}')"
ADV_OFF='{"rules":[],"records":{}}'

# re-arm the pending delta exactly as DbAdvisoryDeltaSink::record does
arm_delta() {
  psql_q "INSERT INTO advisory_deltas (ecosystem, name, advisory_ids) VALUES ('PyPI', 'requests', ARRAY['$1']::text[]) ON CONFLICT (ecosystem, name) DO UPDATE SET advisory_ids = EXCLUDED.advisory_ids, detected_at = now(), processed_at = NULL, attempts = 0 RETURNING id"
}
delta_state() { psql_q "SELECT coalesce(processed_at::text, 'pending') || '|' || attempts FROM advisory_deltas WHERE ecosystem = 'PyPI' AND name = 'requests'"; }
delta_processed() { [[ "$(delta_state)" != pending* ]] && [ -n "$(delta_state)" ]; }
delta_attempted() { [[ "$(delta_state)" == pending\|[1-9]* ]]; }
transitions() {  # transitions <outname> -> status
  req GET "/api/v1/environments/advisory-transitions?advisory=${GHSA}" "$1"
}
transition_count() {  # transition_count <outname> <kind> -> count for env E
  jq --arg k "$2" --arg e "$ENV_E" '[.transitions[] | select(.kind == $k and .environment.name == $e)] | length' "$WORK/$1" 2>/dev/null || echo 0
}
has_transition() { transitions tr_poll.json >/dev/null; [ "$(transition_count tr_poll.json "$1")" -ge 1 ] 2>/dev/null; }

restart_backend() {
  docker restart "$BACKEND_CTR" >/dev/null 2>&1 || return 1
  wait_until "backend healthy after restart" 120 curl -sf --max-time 5 "${BASE_URL}/health" >/dev/null
}

begin_suite "conda-environments-reverse-index (#4053 #4054 #4055 #4670)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: repositories (public + private), plain user, mock feed"
auth_admin
setup_err=""
create_repo "$PUB" conda local || setup_err+="create ${PUB}; "
pst="$(req POST /api/v1/repositories priv.json -H 'Content-Type: application/json' \
  -d "{\"key\":\"${PRIV}\",\"name\":\"${PRIV}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":false}")"
{ [ "$pst" = "200" ] || [ "$pst" = "201" ]; } || setup_err+="create private ${PRIV} HTTP ${pst}; "
create_test_user "$USER_U" "$USER_PW" "${USER_U}@dtf.invalid" >/dev/null || setup_err+="create user; "
USER_TOKEN="$(login_as "$USER_U" "$USER_PW")" || USER_TOKEN=""
[ -n "$USER_TOKEN" ] || setup_err+="user login; "
[ "$(mock_mode ok)" = "ok" ] || setup_err+="mock mode; "
[ "$(mock_advisories "$ADV_OFF")" = "0" ] || setup_err+="mock advisories; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROL - the visibility the reverse index must respect
# =============================================================================
begin_test "CONTROL: the plain user cannot read the private repository and can read the public one"
s_priv="$(curl -s --max-time 30 -o "$WORK/u_priv" -w '%{http_code}' -H "Authorization: Bearer ${USER_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${PRIV}" 2>/dev/null || echo 000)"
s_pub="$(curl -s --max-time 30 -o "$WORK/u_pub" -w '%{http_code}' -H "Authorization: Bearer ${USER_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${PUB}" 2>/dev/null || echo 000)"
if { [ "$s_priv" = "403" ] || [ "$s_priv" = "404" ]; } && [ "$s_pub" = "200" ] \
   && jq -e --arg k "$PUB" '.key == $k' "$WORK/u_pub" >/dev/null 2>&1; then
  pass
else
  fail "repository visibility for the plain user is not what the tier assumes" \
    "private HTTP ${s_priv}: $(head -c 200 "$WORK/u_priv"); public HTTP ${s_pub}"
fi

# =============================================================================
# #4053 - environment SBOM graphs
# =============================================================================
begin_test "#4053: the environment SBOM is one CycloneDX document per platform, with the pillow -> libwebp edge only on linux-64"
st="$(post_lock "/api/v1/sbom/environment?filename=conda-lock.yml&format=cyclonedx" sbom_all.json)"
if [ "$st" = "200" ] && jq -e '
     .lockfileFormat == "conda-lock"
     and (.graphs | length) == 2
     and ([.graphs[].platform] | sort) == ["linux-64", "osx-64"]
     and (.graphs[] | select(.platform == "linux-64") | .document
          | (.components[] | select(.name == "pillow") | ."bom-ref") as $p
          | any(.dependencies[]; .ref == $p and any(.dependsOn[]; contains("libwebp"))))
     and (.graphs[] | select(.platform == "osx-64") | .document | tostring | contains("pillow") | not)
     and (.graphs[] | select(.platform == "osx-64") | .document.bomFormat) == "CycloneDX"' \
     "$WORK/sbom_all.json" >/dev/null 2>&1; then
  pass
else
  fail "environment SBOM does not carry per-platform graphs" "HTTP ${st}: $(head -c 500 "$WORK/sbom_all.json")"
fi

begin_test "#4053: the SPDX rendering carries a DEPENDS_ON relationship on the linux-64 graph"
st="$(post_lock "/api/v1/sbom/environment?filename=conda-lock.yml&format=spdx" sbom_spdx.json)"
if [ "$st" = "200" ] && jq -e '
     (.graphs[] | select(.platform == "linux-64") | .document
      | .spdxVersion == "SPDX-2.3" and any(.relationships[]; .relationshipType == "DEPENDS_ON"))' \
     "$WORK/sbom_spdx.json" >/dev/null 2>&1; then
  pass
else
  fail "SPDX environment SBOM lacks the dependency edge" "HTTP ${st}: $(head -c 400 "$WORK/sbom_spdx.json")"
fi

# =============================================================================
# #4670 (1.11.1) - platform filter and the graph-listing 400
# =============================================================================
begin_test "#4670: ?platform=osx-64 renders that graph alone"
st="$(post_lock "/api/v1/sbom/environment?filename=conda-lock.yml&platform=osx-64" sbom_osx.json)"
if [ "$st" = "200" ] && jq -e '(.graphs | length) == 1 and .graphs[0].platform == "osx-64"' "$WORK/sbom_osx.json" >/dev/null 2>&1; then
  pass
else
  fail "platform filter ignored" "HTTP ${st}: graphs=$(jq -c '[.graphs[]?.platform]' "$WORK/sbom_osx.json" 2>/dev/null)"
fi

begin_test "#4670: a platform matching no graph is 400 and the error names the graphs"
st="$(post_lock "/api/v1/sbom/environment?filename=conda-lock.yml&platform=dtf-nope-64" sbom_nope.json)"
if [ "$st" = "400" ] && grep -q 'linux-64' "$WORK/sbom_nope.json" && grep -q 'osx-64' "$WORK/sbom_nope.json"; then
  pass
else
  fail "unmatched platform filter not refused with the graph list" "HTTP ${st}: $(head -c 300 "$WORK/sbom_nope.json")"
fi

# =============================================================================
# #4054 - stored environments
# =============================================================================
begin_test "#4054: an environment is stored (201), re-ingest under the same name replaces it (200), list and detail show it per platform"
s1="$(post_lock "/api/v1/repositories/${PUB}/environments?filename=conda-lock.yml&name=${ENV_E}" env1.json)"
s2="$(post_lock "/api/v1/repositories/${PUB}/environments?filename=conda-lock.yml&name=${ENV_E}" env2.json)"
ENV_ID="$(jq -r '.id // empty' "$WORK/env1.json" 2>/dev/null)"
sl="$(req GET "/api/v1/repositories/${PUB}/environments" envlist.json)"
sd="$(req GET "/api/v1/repositories/${PUB}/environments/${ENV_ID}" envdet.json)"
if [ "$s1" = "201" ] && [ -n "$ENV_ID" ] \
   && jq -e '.replaced == false and .summary.scopes == 2 and .summary.edges == 1' "$WORK/env1.json" >/dev/null 2>&1 \
   && [ "$s2" = "200" ] && jq -e --arg id "$ENV_ID" '.replaced == true and .id == $id' "$WORK/env2.json" >/dev/null 2>&1 \
   && [ "$sl" = "200" ] && jq -e --arg n "$ENV_E" '[.environments[] | select(.name == $n)] | length == 1' "$WORK/envlist.json" >/dev/null 2>&1 \
   && [ "$sd" = "200" ] && jq -e '([.scopes[].platform] | sort) == ["linux-64", "osx-64"] and .lockfileFormat == "conda-lock"' "$WORK/envdet.json" >/dev/null 2>&1; then
  pass
else
  fail "stored environment lifecycle wrong" \
    "ingest HTTP ${s1}: $(head -c 300 "$WORK/env1.json"); re-ingest HTTP ${s2}: $(head -c 200 "$WORK/env2.json"); list HTTP ${sl}; detail HTTP ${sd}: $(head -c 300 "$WORK/envdet.json")"
fi

begin_test "#4054: lookup by purl names the environment per platform with inclusion paths; a build-qualified purl matches on its base"
sq="$(post_lock "/api/v1/repositories/${PRIV}/environments?filename=conda-lock.yml&name=${ENV_Q}" envq.json)"
s_l="$(req GET "/api/v1/environments/lookup?purl=pkg:conda/libwebp@1.3.2" lookup.json)"
s_q="$(req GET "/api/v1/environments/lookup?purl=pkg%3Aconda%2Flibwebp%401.3.2%3Fbuild%3Dh1234_0%26channel%3Dconda-forge%26subdir%3Dlinux-64" lookup_q.json)"
if [ "$sq" = "201" ] && [ "$s_l" = "200" ] && jq -e --arg e "$ENV_E" --arg r "$PUB" '
     [.hits[] | select(.environment.name == $e)] as $h
     | ($h | length) == 2
     and ([$h[].scope.platform] | sort) == ["linux-64", "osx-64"]
     and all($h[]; .repository.key == $r and .package.name == "libwebp" and .package.version == "1.3.2")
     and ($h[] | select(.scope.platform == "linux-64") | .paths | tostring | contains("pillow"))' \
     "$WORK/lookup.json" >/dev/null 2>&1 \
   && [ "$s_q" = "200" ] && jq -e --arg e "$ENV_E" '[.hits[] | select(.environment.name == $e)] | length >= 1' "$WORK/lookup_q.json" >/dev/null 2>&1; then
  pass
else
  fail "reverse index lookup wrong" \
    "private ingest HTTP ${sq}; lookup HTTP ${s_l}: $(head -c 600 "$WORK/lookup.json"); qualified HTTP ${s_q}: $(head -c 200 "$WORK/lookup_q.json")"
fi

begin_test "#4054: the reverse index never names an environment in a repository the caller cannot read"
s_u="$(curl -s --max-time 30 -o "$WORK/lookup_u.json" -w '%{http_code}' -H "Authorization: Bearer ${USER_TOKEN}" \
  "${BASE_URL}/api/v1/environments/lookup?purl=pkg:conda/libwebp@1.3.2" 2>/dev/null || echo 000)"
if [ "$s_u" = "200" ] \
   && jq -e --arg e "$ENV_E" --arg q "$ENV_Q" --arg p "$PRIV" '
        ([.hits[] | select(.environment.name == $e)] | length) == 2
        and ([.hits[] | select(.environment.name == $q or .repository.key == $p)] | length) == 0' \
        "$WORK/lookup_u.json" >/dev/null 2>&1 \
   && jq -e --arg q "$ENV_Q" '[.hits[] | select(.environment.name == $q)] | length == 2' "$WORK/lookup.json" >/dev/null 2>&1; then
  pass
else
  fail "private environment leaked through (or missing from) the reverse index" \
    "user HTTP ${s_u}: $(jq -c '[.hits[]?.environment.name]' "$WORK/lookup_u.json" 2>/dev/null); admin: $(jq -c '[.hits[]?.environment.name]' "$WORK/lookup.json" 2>/dev/null)"
fi

# =============================================================================
# #4055 - advisory-delta re-evaluation
# =============================================================================
begin_test "#4055: a pending delta for an installed component becomes a new-affected transition and current affectedness"
mock_advisories "$ADV_ON" >/dev/null
armed="$(arm_delta "$GHSA")"
if [ -z "$armed" ]; then
  fail "could not record a pending advisory delta (no advisory_deltas table?)" "$(delta_state)"
elif wait_until "new-affected transition" "$TICK_WAIT" has_transition new-affected; then
  transitions tr_a.json >/dev/null
  sa="$(req GET "/api/v1/repositories/${PUB}/environments/${ENV_ID}/advisories" adv_a.json)"
  if jq -e --arg id "$GHSA" --arg e "$ENV_E" '
       [.transitions[] | select(.environment.name == $e)] | length == 1
       and .[0].kind == "new-affected" and .[0].advisory.id == $id
       and .[0].package.name == "requests" and .[0].package.version == "2.18.4"' "$WORK/tr_a.json" >/dev/null 2>&1 \
     && [ "$sa" = "200" ] \
     && jq -e --arg id "$GHSA" 'any(.affected[]; .advisory.id == $id and .package.name == "requests")' "$WORK/adv_a.json" >/dev/null 2>&1; then
    pass
  else
    fail "transition or affectedness wrong" "transitions: $(head -c 500 "$WORK/tr_a.json"); advisories HTTP ${sa}: $(head -c 300 "$WORK/adv_a.json")"
  fi
else
  fail "no new-affected transition within ${TICK_WAIT}s" "delta=$(delta_state); transitions: $(head -c 300 "$WORK/tr_poll.json")"
fi

begin_test "#4055: with the feed down the delta stays pending (attempted) and no transition is recorded"
mock_mode down >/dev/null
mock_advisories "$ADV_OFF" >/dev/null
if ! restart_backend; then
  infra_fail "backend did not come back after restart" "$(docker logs --tail 20 "$BACKEND_CTR" 2>&1 | tail -5)"
  end_suite
fi
rearmed="$(arm_delta "$GHSA")"
if [ -z "$rearmed" ]; then
  fail "could not record a pending advisory delta (no advisory_deltas table?)" "$(delta_state)"
elif wait_until "degraded attempt" "$TICK_WAIT" delta_attempted; then
  transitions tr_b.json >/dev/null
  if [ "$(transition_count tr_b.json no-longer-affected)" = "0" ] && [ "$(transition_count tr_b.json new-affected)" = "1" ]; then
    pass
  else
    fail "a degraded feed answer recorded a transition" "transitions: $(head -c 500 "$WORK/tr_b.json")"
  fi
else
  fail "the delta was not attempted (or was consumed) under an outage" "delta=$(delta_state)"
fi

begin_test "#4055: once the feed answers without the advisory, the same delta records no-longer-affected and clears affectedness"
mock_mode ok >/dev/null
if [ -z "$rearmed" ]; then
  fail "no pending advisory delta to re-evaluate (no advisory_deltas table?)" "$(delta_state)"
elif wait_until "no-longer-affected transition" "$TICK_WAIT" has_transition no-longer-affected; then
  sc="$(req GET "/api/v1/repositories/${PUB}/environments/${ENV_ID}/advisories" adv_c.json)"
  if delta_processed && [ "$sc" = "200" ] \
     && jq -e --arg id "$GHSA" '[.affected[] | select(.advisory.id == $id)] | length == 0' "$WORK/adv_c.json" >/dev/null 2>&1; then
    pass
  else
    fail "affectedness not cleared" "delta=$(delta_state); advisories HTTP ${sc}: $(head -c 300 "$WORK/adv_c.json")"
  fi
else
  fail "no no-longer-affected transition within ${TICK_WAIT}s" "delta=$(delta_state); transitions: $(head -c 400 "$WORK/tr_poll.json")"
fi

end_suite
