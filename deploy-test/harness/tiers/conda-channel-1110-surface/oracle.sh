#!/usr/bin/env bash
# =============================================================================
# tiers/conda-channel-1110-surface/oracle.sh: the 1.11.0 hosted and virtual
#   conda channel surface: patch-generation attribution, per-package
#   withdrawal and CEP-6 notices, the `unknown` subdir, upload subdir checks,
#   the virtual allowlist, a token scoped to a virtual, and the absent
#   info.base_url
#   (artifact-keeper#4051, #4059, #4146, #4555, #4576, #4559, #4580)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. The mock channel publishes
# dtfup-alpha 1.0 + 2.0 and dtfup-blocked 1.0 (noarch; only alpha 2.0 has
# bytes), a patch_instructions.json, and a channeldata.json naming only
# dtfup-alpha, and logs one line per request.
#
# Topology (keys suffixed per run):
#   H    public hosted: c11-keep 1.0, c11-wd 1.0 (withdrawn), c11-up 1.0 (POST)
#   HW   public hosted: c11-cw1..8 1.0 (eight concurrent withdrawals)
#   HP   private hosted: c11-priv 1.0
#   HQ   private hosted: c11-hidden 1.0 (no grant for the service account)
#   R    remote -> mock
#   V    virtual {H, R}
#   AL   virtual {H, R}, allowlist: dtfup-a* at >=2, dtfup-blocked on linux-64
#   AL2  virtual {R},    allowlist: dtfup-blocked only
#   SV   private virtual {HP, HQ}; a service account holds read on SV and HP
#        (not HQ) and a token whose repository_ids name SV only
#
# Every FIX case is RED on ak-backend:1.10.0 and GREEN on 1.11.0+; every
# CONTROL holds on both. See the manifest for the bugs.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on
# it explicitly, so a non-zero helper (grep with no match, jq on a non-JSON
# error body) must not end the suite before the assertion runs.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
UPSTREAM="http://172.16.${SLOT}.70/"
MOCK_CTR="ak-dtf${SLOT}-mock-conda"

H="c11-host-${SUF}"
HW="c11-wdraw-${SUF}"
HP="c11-priv-${SUF}"
HQ="c11-hidden-${SUF}"
R="c11-remote-${SUF}"
V="c11-virt-${SUF}"
AL="c11-allow-${SUF}"
AL2="c11-allow2-${SUF}"
SV="c11-scoped-${SUF}"

KEEP="c11-keep-1.0-0.tar.bz2"
WD="c11-wd-1.0-0.tar.bz2"
UPL="c11-up-1.0-0.tar.bz2"          # linux-64 package POSTed with no X-Conda-Subdir
MIS="c11-mis-1.0-0.tar.bz2"         # linux-64 package PUT under /noarch/
NAP="c11-nap-1.0-0.tar.bz2"         # noarch package POSTed with X-Conda-Subdir: noarch
PRIV="c11-priv-1.0-0.tar.bz2"
HIDDEN="c11-hidden-1.0-0.tar.bz2"
UP_ALPHA1="dtfup-alpha-1.0-0.tar.bz2"
UP_ALPHA2="dtfup-alpha-2.0-0.tar.bz2"
UP_BLOCKED="dtfup-blocked-1.0-0.tar.bz2"
WD_REASON="dtf c11 withdraw ${SUF}"

WORK="$(mktemp -d -t dtf-c11-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
BUILD="${DTF_DIR}/fixtures/conda/build.sh"

# --- helpers ------------------------------------------------------------------
# hget PATH OUTFILE [curl args...] -> HTTP status; headers in OUTFILE.hdr
hget() {
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -D "${out}.hdr" -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
hdr() { grep -i "^$2:" "${1}.hdr" 2>/dev/null | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }
conda_put() {  # conda_put <repo> <subdir> <file> <filename> -> status, body in $WORK/put.out
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$3" \
    "${BASE_URL}/conda/$1/$2/$4" 2>/dev/null || echo 000
}
withdraw() {  # withdraw <repo> <filename> <outfile> [auth header] -> status
  curl -s --max-time 60 -o "$3" -w '%{http_code}' -X DELETE \
    -H "${4:-$(auth_header)}" -H 'Content-Type: application/json' \
    -d "{\"reason\":\"${WD_REASON}\"}" "${BASE_URL}/conda/$1/noarch/$2" 2>/dev/null || echo 000
}
keys_of() { jq -c '[(.packages // {}), (.["packages.conda"] // {})] | add | keys' "$1" 2>/dev/null; }
mock_hits() { docker logs "$MOCK_CTR" 2>&1 | grep -c "GET /noarch/$1 " || true; }
audit_rows() { psql_q "SELECT count(*) FROM audit_log WHERE action = '$1' AND ($2)"; }
audit_rows_ge() { [ "$(audit_rows "$2" "$3")" -ge "$1" ] 2>/dev/null; }

begin_suite "conda-channel-1110-surface (#4051 #4059 #4146 #4555 #4576 #4559 #4580)"

# =============================================================================
# SETUP. Only what exists on every image is fatal; the allowlist and the
# service-account grants are 1.11.0 surfaces on some images and are recorded
# so the cases that need them fail instead of the whole suite.
# =============================================================================
begin_test "setup: admin auth, repositories, packages, uploads"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create H; "
create_repo "$HW" conda local || setup_err+="create HW; "
create_repo "$R" conda remote "$UPSTREAM" || setup_err+="create R; "
for k in "$HP" "$HQ"; do
  api_post "/api/v1/repositories" \
    "{\"key\":\"${k}\",\"name\":\"${k}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":false}" \
    >/dev/null 2>&1 || setup_err+="create ${k}; "
done
api_post "/api/v1/repositories" \
  "{\"key\":\"${SV}\",\"name\":\"${SV}\",\"format\":\"conda\",\"repo_type\":\"virtual\",\"is_public\":false}" \
  >/dev/null 2>&1 || setup_err+="create SV; "
for v in "$V" "$AL" "$AL2"; do create_repo "$v" conda virtual || setup_err+="create ${v}; "; done
for pair in "$V:$H" "$V:$R" "$AL:$H" "$AL:$R" "$AL2:$R" "$SV:$HP" "$SV:$HQ"; do
  api_post "/api/v1/repositories/${pair%%:*}/members" "{\"member_key\":\"${pair#*:}\"}" >/dev/null \
    || setup_err+="add ${pair#*:} to ${pair%%:*}; "
done

for spec in "c11-keep noarch" "c11-wd noarch" "c11-up linux-64" "c11-mis linux-64" "c11-nap noarch" \
            "c11-priv noarch" "c11-hidden noarch" "c11-cw1 noarch" "c11-cw2 noarch" "c11-cw3 noarch" \
            "c11-cw4 noarch" "c11-cw5 noarch" "c11-cw6 noarch" "c11-cw7 noarch" "c11-cw8 noarch"; do
  # shellcheck disable=SC2086
  set -- $spec
  bash "$BUILD" "$WORK" "$1" 1.0 0 "$2" >/dev/null 2>&1 || setup_err+="build $1; "
done
for spec in "$H:$KEEP" "$H:$WD" "$HP:$PRIV" "$HQ:$HIDDEN" \
            "$HW:c11-cw1-1.0-0.tar.bz2" "$HW:c11-cw2-1.0-0.tar.bz2" "$HW:c11-cw3-1.0-0.tar.bz2" \
            "$HW:c11-cw4-1.0-0.tar.bz2" "$HW:c11-cw5-1.0-0.tar.bz2" "$HW:c11-cw6-1.0-0.tar.bz2" \
            "$HW:c11-cw7-1.0-0.tar.bz2" "$HW:c11-cw8-1.0-0.tar.bz2"; do
  st="$(conda_put "${spec%%:*}" noarch "$WORK/${spec#*:}" "${spec#*:}")"
  [ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="upload ${spec} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); "
done

# 1.11.0 surfaces: recorded, not fatal.
AL_SETUP="$(curl -s --max-time 30 -o "$WORK/al_put.json" -w '%{http_code}' -X PUT \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"entries":[{"name":"dtfup-a*","version":">=2"},{"name":"dtfup-blocked","subdirs":["linux-64"]}]}' \
  "${BASE_URL}/api/v1/repositories/${AL}/allowlist" 2>/dev/null || echo 000)"
AL2_SETUP="$(curl -s --max-time 30 -o "$WORK/al2_put.json" -w '%{http_code}' -X PUT \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"entries":[{"name":"dtfup-blocked"}]}' \
  "${BASE_URL}/api/v1/repositories/${AL2}/allowlist" 2>/dev/null || echo 000)"

SV_ID="$(api_get "/api/v1/repositories/${SV}" | jq -r '.id // empty')"
HP_ID="$(api_get "/api/v1/repositories/${HP}" | jq -r '.id // empty')"
SA_ID="$(api_post "/api/v1/service-accounts" "{\"name\":\"c11sa${SUF//-/}\"}" | jq -r '.id // empty')"
[ -n "$SV_ID" ] && [ -n "$HP_ID" ] && [ -n "$SA_ID" ] || setup_err+="resolve SV/HP/service account ids; "
for tid in "$SV_ID" "$HP_ID"; do
  api_post "/api/v1/permissions" \
    "{\"principal_type\":\"service_account\",\"principal_id\":\"${SA_ID}\",\"target_type\":\"repository\",\"target_id\":\"${tid}\",\"actions\":[\"read\"]}" \
    >/dev/null 2>&1 || setup_err+="grant service account read on ${tid}; "
done
SA_TOKEN="$(api_post "/api/v1/service-accounts/${SA_ID}/tokens" \
  "{\"name\":\"c11-sv-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repository_ids\":[\"${SV_ID}\"]}" \
  | jq -r '.token // empty')"
[ -n "$SA_TOKEN" ] || setup_err+="mint service-account token; "
# A token of the admin WITHOUT delete:artifacts (withdraw's scope gate).
NODEL_TOKEN="$(api_post "/api/v1/auth/tokens" \
  "{\"name\":\"c11-nodel-${SUF}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"]}" | jq -r '.token // empty')"
[ -n "$NODEL_TOKEN" ] || setup_err+="mint no-delete token; "
U_NAME="c11user${SUF//-/}"
U_PASS="Dtf-c11-${SUF}-pw!"
create_test_user "$U_NAME" "$U_PASS" "${U_NAME}@dtf.test" >/dev/null || setup_err+="create user; "
U_TOKEN="$(login_as "$U_NAME" "$U_PASS")" || setup_err+="login user; "

if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4576 download leg first: nothing has fetched dtfup-alpha 2.0 yet, so the
# mock's request log tells whether the virtual contacted the upstream.
# =============================================================================
begin_test "FIX #4576: a download of a package the allowlist drops answers 404 through the virtual and never reaches the upstream"
before="$(mock_hits "$UP_ALPHA2")"
st="$(hget "/conda/${AL2}/noarch/${UP_ALPHA2}" "$WORK/al2_dl.bin")"
after="$(mock_hits "$UP_ALPHA2")"
if [ "$AL2_SETUP" = "200" ] && [ "$st" = "404" ] && [ "$after" = "$before" ]; then
  pass
else
  fail "allowlisted virtual served or fetched a non-admitted package" \
    "allowlist PUT HTTP ${AL2_SETUP}; download HTTP ${st}; mock GETs for ${UP_ALPHA2} ${before}->${after}"
fi

begin_test "CONTROL: the unrestricted virtual proxies dtfup-alpha 2.0 from the upstream"
st="$(hget "/conda/${V}/noarch/${UP_ALPHA2}" "$WORK/v_dl.bin")"
hits="$(mock_hits "$UP_ALPHA2")"
if [ "$st" = "200" ] && [ -s "$WORK/v_dl.bin" ] && [ "$hits" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "virtual download of the upstream package broke" "HTTP ${st}; mock GETs ${hits}"
fi

# =============================================================================
# CONTROLS on the hosted channel
# =============================================================================
begin_test "CONTROL: hosted repodata.json lists the uploads; remote repodata.json carries the upstream records"
st1="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd0.json")"
st2="$(hget "/conda/${R}/noarch/repodata.json" "$WORK/r_rd.json")"
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && jq -e --arg a "$KEEP" --arg b "$WD" '.packages | has($a) and has($b)' "$WORK/h_rd0.json" >/dev/null 2>&1 \
   && jq -e --arg a "$UP_ALPHA1" --arg b "$UP_ALPHA2" --arg c "$UP_BLOCKED" \
        '.packages | has($a) and has($b) and has($c)' "$WORK/r_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "hosted or remote repodata.json lost records" \
    "hosted HTTP ${st1} keys=$(keys_of "$WORK/h_rd0.json"); remote HTTP ${st2} keys=$(keys_of "$WORK/r_rd.json")"
fi

# =============================================================================
# #4051 patch generation attribution on the Remote
# =============================================================================
begin_test "FIX #4051: remote repodata.json carries X-Repodata-Patch-Generation = BLAKE2b-256 of the upstream patch_instructions.json, recorded in conda_repodata_patch_generations"
expected="$(docker exec "$MOCK_CTR" python3 -c 'import urllib.request,hashlib;print(hashlib.blake2b(urllib.request.urlopen("http://127.0.0.1/noarch/patch_instructions.json").read(),digest_size=32).hexdigest())' 2>/dev/null)"
got="$(hdr "$WORK/r_rd.json" X-Repodata-Patch-Generation)"
rows="$(psql_q "SELECT g.subdir || ':' || g.generation FROM conda_repodata_patch_generations g JOIN repositories r ON r.id = g.repository_id WHERE r.key = '${R}'")"
if [ -n "$expected" ] && [ "$got" = "$expected" ] && [ "$rows" = "noarch:${expected}" ]; then
  pass
else
  fail "remote repodata is not attributed to the upstream patch generation" \
    "header='${got}' expected='${expected}' db rows='${rows}'"
fi

begin_test "CONTROL #4051: hosted and virtual repodata.json carry no patch-generation header"
st1="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/h_pg.json")"
st2="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_pg.json")"
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && [ -z "$(hdr "$WORK/h_pg.json" X-Repodata-Patch-Generation)" ] \
   && [ -z "$(hdr "$WORK/v_pg.json" X-Repodata-Patch-Generation)" ]; then
  pass
else
  fail "a non-remote channel claims an upstream patch generation" \
    "hosted HTTP ${st1} '$(hdr "$WORK/h_pg.json" X-Repodata-Patch-Generation)'; virtual HTTP ${st2} '$(hdr "$WORK/v_pg.json" X-Repodata-Patch-Generation)'"
fi

# =============================================================================
# #4580 no info.base_url
# =============================================================================
begin_test "FIX #4580: hosted repodata.json (plain, .bz2, .zst), current_repodata.json and the virtual's repodata.json carry no info.base_url"
bad=""
hget "/conda/${H}/noarch/repodata.json.bz2" "$WORK/h_rd.bz2" >/dev/null
hget "/conda/${H}/noarch/repodata.json.zst" "$WORK/h_rd.zst" >/dev/null
hget "/conda/${H}/noarch/current_repodata.json" "$WORK/h_cur.json" >/dev/null
bzip2 -dc "$WORK/h_rd.bz2" > "$WORK/h_rd_bz2.json" 2>/dev/null
zstd -qdc "$WORK/h_rd.zst" > "$WORK/h_rd_zst.json" 2>/dev/null
for f in h_pg.json h_rd_bz2.json h_rd_zst.json h_cur.json v_pg.json; do
  if ! jq -e '(.info | type == "object") and (.info.subdir == "noarch") and (.info | has("base_url") | not)' \
       "$WORK/$f" >/dev/null 2>&1; then
    bad+="${f}: info=$(jq -c '.info' "$WORK/$f" 2>/dev/null | head -c 160); "
  fi
done
if [ -z "$bad" ]; then pass; else fail "repodata still carries info.base_url (or did not decode)" "$bad"; fi

# =============================================================================
# #4555 `unknown` subdir and upload subdir checks
# =============================================================================
begin_test "FIX #4555: GET /conda/<hosted>/unknown/repodata.json is an empty index (200), not 400"
st="$(hget "/conda/${H}/unknown/repodata.json" "$WORK/h_unknown.json")"
if [ "$st" = "200" ] \
   && jq -e '.info.subdir == "unknown" and (.packages == {}) and (.["packages.conda"] == {})' "$WORK/h_unknown.json" >/dev/null 2>&1; then
  pass
else
  fail "unknown subdir not served as an empty index" "HTTP ${st}: $(head -c 300 "$WORK/h_unknown.json")"
fi

begin_test "CONTROL #4555: an upload to the unknown subdir is still refused with 400"
st="$(conda_put "$H" unknown "$WORK/$KEEP" "$KEEP")"
assert_eq "$st" "400" "upload to unknown/: want 400, got HTTP ${st}: $(head -c 200 "$WORK/put.out")" && pass

begin_test "FIX #4555: PUT of a linux-64 package under /noarch/ is refused 400 naming both subdirs, and not listed"
st="$(conda_put "$H" noarch "$WORK/$MIS" "$MIS")"
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd_mis.json" >/dev/null
if [ "$st" = "400" ] && grep -q "noarch" "$WORK/put.out" && grep -q "linux-64" "$WORK/put.out" \
   && ! jq -e --arg m "$MIS" '.packages | has($m)' "$WORK/h_rd_mis.json" >/dev/null 2>&1; then
  pass
else
  fail "subdir mismatch accepted" "HTTP ${st}: $(head -c 300 "$WORK/put.out"); noarch keys=$(keys_of "$WORK/h_rd_mis.json")"
fi

begin_test "FIX #4555: POST /upload without X-Conda-Subdir files a linux-64 package under linux-64"
st="$(curl -s --max-time 60 -o "$WORK/post.out" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H "X-Package-Filename: ${UPL}" --data-binary "@$WORK/${UPL}" "${BASE_URL}/conda/${H}/upload" 2>/dev/null || echo 000)"
st2="$(hget "/conda/${H}/linux-64/repodata.json" "$WORK/h_l64.json")"
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd_post.json" >/dev/null
if [ "$st" = "201" ] && jq -e '.subdir == "linux-64"' "$WORK/post.out" >/dev/null 2>&1 && [ "$st2" = "200" ] \
   && jq -e --arg u "$UPL" '.packages | has($u)' "$WORK/h_l64.json" >/dev/null 2>&1 \
   && ! jq -e --arg u "$UPL" '.packages | has($u)' "$WORK/h_rd_post.json" >/dev/null 2>&1; then
  pass
else
  fail "header-less POST did not use the package's own subdir" \
    "POST HTTP ${st}: $(head -c 200 "$WORK/post.out"); linux-64 keys=$(keys_of "$WORK/h_l64.json"); noarch keys=$(keys_of "$WORK/h_rd_post.json")"
fi

begin_test "CONTROL: POST /upload with X-Conda-Subdir: noarch files a noarch package under noarch"
st="$(curl -s --max-time 60 -o "$WORK/post2.out" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H "X-Conda-Subdir: noarch" -H "X-Package-Filename: ${NAP}" --data-binary "@$WORK/${NAP}" \
  "${BASE_URL}/conda/${H}/upload" 2>/dev/null || echo 000)"
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd_nap.json" >/dev/null
if [ "$st" = "201" ] && jq -e --arg n "$NAP" '.packages | has($n)' "$WORK/h_rd_nap.json" >/dev/null 2>&1; then
  pass
else
  fail "POST with a matching header failed" "HTTP ${st}: $(head -c 200 "$WORK/post2.out")"
fi

# =============================================================================
# #4059 per-package withdrawal
# =============================================================================
begin_test "FIX #4059: withdraw is refused without delete:artifacts or admin (403), and the package stays listed"
st_tok="$(withdraw "$H" "$WD" "$WORK/wd_nodel.json" "Authorization: Bearer ${NODEL_TOKEN}")"
st_usr="$(withdraw "$H" "$WD" "$WORK/wd_user.json" "Authorization: Bearer ${U_TOKEN}")"
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd_pre.json" >/dev/null
if [ "$st_tok" = "403" ] && [ "$st_usr" = "403" ] \
   && jq -e --arg w "$WD" '.packages | has($w)' "$WORK/h_rd_pre.json" >/dev/null 2>&1; then
  pass
else
  fail "withdraw gate wrong" "no-delete token HTTP ${st_tok}: $(head -c 150 "$WORK/wd_nodel.json"); non-admin HTTP ${st_usr}: $(head -c 150 "$WORK/wd_user.json")"
fi

begin_test "FIX #4059: DELETE /conda/<hosted>/noarch/<file> withdraws it (200 withdrawn:true)"
st="$(withdraw "$H" "$WD" "$WORK/wd.json")"
if [ "$st" = "200" ] && jq -e '.withdrawn == true and (.artifact_id | length > 0) and (.notice_id | length > 0)' "$WORK/wd.json" >/dev/null 2>&1; then
  pass
else
  fail "withdraw did not succeed" "HTTP ${st}: $(head -c 300 "$WORK/wd.json")"
fi

begin_test "FIX #4059: the withdrawn package leaves repodata.json (named in removed), .bz2, current_repodata, channeldata and the virtual merge"
bad=""
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd_wd.json" >/dev/null
hget "/conda/${H}/noarch/repodata.json.bz2" "$WORK/h_rd_wd.bz2" >/dev/null
bzip2 -dc "$WORK/h_rd_wd.bz2" > "$WORK/h_rd_wd_bz2.json" 2>/dev/null
hget "/conda/${H}/noarch/current_repodata.json" "$WORK/h_cur_wd.json" >/dev/null
hget "/conda/${H}/channeldata.json" "$WORK/h_cd_wd.json" >/dev/null
hget "/conda/${V}/noarch/repodata.json" "$WORK/v_rd_wd.json" >/dev/null
jq -e --arg w "$WD" --arg k "$KEEP" '(.packages | has($w) | not) and (.packages | has($k)) and ((.removed // []) | index($w) != null)' \
  "$WORK/h_rd_wd.json" >/dev/null 2>&1 || bad+="repodata.json keys=$(keys_of "$WORK/h_rd_wd.json") removed=$(jq -c '.removed' "$WORK/h_rd_wd.json" 2>/dev/null); "
for f in h_rd_wd_bz2.json h_cur_wd.json v_rd_wd.json; do
  jq -e --arg w "$WD" --arg k "$KEEP" '(.packages | has($w) | not) and (.packages | has($k))' "$WORK/$f" >/dev/null 2>&1 \
    || bad+="${f} keys=$(keys_of "$WORK/$f"); "
done
jq -e '(.packages | has("c11-wd") | not) and (.packages | has("c11-keep"))' "$WORK/h_cd_wd.json" >/dev/null 2>&1 \
  || bad+="channeldata names=$(jq -c '.packages | keys' "$WORK/h_cd_wd.json" 2>/dev/null); "
if [ -z "$bad" ]; then pass; else fail "withdrawn package still indexed" "$bad"; fi

begin_test "FIX #4059: download of the withdrawn package is refused 409; the sibling still downloads"
st_wd="$(hget "/conda/${H}/noarch/${WD}" "$WORK/wd.bin")"
st_k="$(hget "/conda/${H}/noarch/${KEEP}" "$WORK/keep.bin")"
if [ "$st_wd" = "409" ] && [ "$st_k" = "200" ] && cmp -s "$WORK/keep.bin" "$WORK/${KEEP}"; then
  pass
else
  fail "withdrawn package download not gated" "withdrawn HTTP ${st_wd}: $(head -c 200 "$WORK/wd.bin" | tr -d '\0'); sibling HTTP ${st_k}"
fi

begin_test "FIX #4059: notices.json carries a CEP-6 warning naming the package and quoting the reason"
st="$(hget "/conda/${H}/notices.json" "$WORK/h_notices.json")"
if [ "$st" = "200" ] && jq -e --arg w "$WD" --arg r "$WD_REASON" \
     '[.notices[] | select(.level == "warning" and .package == $w and .reason == $r and (.message | contains($w)) and (.message | contains($r)))] | length == 1' \
     "$WORK/h_notices.json" >/dev/null 2>&1; then
  pass
else
  fail "no withdrawal notice" "HTTP ${st}: $(head -c 400 "$WORK/h_notices.json")"
fi

begin_test "CONTROL #4059: withdraw on a remote channel is refused (405) and its index is unchanged"
st="$(withdraw "$R" "$UP_ALPHA1" "$WORK/wd_remote.json")"
hget "/conda/${R}/noarch/repodata.json" "$WORK/r_rd2.json" >/dev/null
if [ "$st" = "405" ] && jq -e --arg a "$UP_ALPHA1" '.packages | has($a)' "$WORK/r_rd2.json" >/dev/null 2>&1; then
  pass
else
  fail "remote withdraw not refused" "HTTP ${st}: $(head -c 200 "$WORK/wd_remote.json")"
fi

# =============================================================================
# #4146 notices.json visibility and concurrent withdrawals
# =============================================================================
# 1.10.0 also answers 401 here: its notices.json was a `[]` stub behind the
# same visibility middleware, so this pins the gate rather than discriminating.
begin_test "CONTROL #4146: anonymous notices.json on a private channel is refused 401, like channeldata.json"
st_n="$(hget "/conda/${HP}/notices.json" "$WORK/hp_notices_anon.json")"
st_c="$(hget "/conda/${HP}/channeldata.json" "$WORK/hp_cd_anon.json")"
if [ "$st_n" = "401" ] && [ "$st_c" = "401" ]; then
  pass
else
  fail "private channel notices.json readable anonymously" "notices HTTP ${st_n}: $(head -c 200 "$WORK/hp_notices_anon.json"); channeldata HTTP ${st_c}"
fi

begin_test "CONTROL #4146: an authenticated notices.json on the private channel answers 200"
st="$(hget "/conda/${HP}/notices.json" "$WORK/hp_notices.json" -H "$(auth_header)")"
if [ "$st" = "200" ] && jq -e '.notices | type == "array"' "$WORK/hp_notices.json" >/dev/null 2>&1; then
  pass
else
  fail "authenticated notices.json broke" "HTTP ${st}: $(head -c 200 "$WORK/hp_notices.json")"
fi

begin_test "FIX #4146: eight concurrent withdrawals keep all eight notices and drop all eight records"
for i in 1 2 3 4 5 6 7 8; do
  withdraw "$HW" "c11-cw${i}-1.0-0.tar.bz2" "$WORK/cw${i}.json" > "$WORK/cw${i}.st" &
done
wait
codes="$(for i in 1 2 3 4 5 6 7 8; do printf '%s ' "$(cat "$WORK/cw${i}.st")"; done)"
hget "/conda/${HW}/notices.json" "$WORK/hw_notices.json" >/dev/null
hget "/conda/${HW}/noarch/repodata.json" "$WORK/hw_rd.json" >/dev/null
n="$(jq '[.notices[] | select(.package | test("^c11-cw[1-8]-1.0-0.tar.bz2$"))] | map(.package) | unique | length' "$WORK/hw_notices.json" 2>/dev/null)"
left="$(jq '.packages | length' "$WORK/hw_rd.json" 2>/dev/null)"
if [ "$codes" = "200 200 200 200 200 200 200 200 " ] && [ "$n" = "8" ] && [ "$left" = "0" ]; then
  pass
else
  fail "concurrent withdrawals lost notices or records" "statuses: ${codes}; distinct notices=${n:-?}; records left=${left:-?}"
fi

# =============================================================================
# #4576 allowlist on the index
# =============================================================================
begin_test "FIX #4576: glob + version-spec + subdirs entries filter the remote records of repodata.json and .bz2, report X-AK-Allowlist-Dropped, and leave hosted records alone"
st="$(hget "/conda/${AL}/noarch/repodata.json" "$WORK/al_rd.json")"
hget "/conda/${AL}/noarch/repodata.json.bz2" "$WORK/al_rd.bz2" >/dev/null
bzip2 -dc "$WORK/al_rd.bz2" > "$WORK/al_rd_bz2.json" 2>/dev/null
dropped="$(hdr "$WORK/al_rd.json" X-AK-Allowlist-Dropped)"
if [ "$AL_SETUP" = "200" ] && [ "$st" = "200" ] && [ "$dropped" = "2" ] \
   && jq -e --arg a2 "$UP_ALPHA2" --arg k "$KEEP" --arg n "$NAP" "(.packages | keys) == ([\$a2, \$k, \$n] | sort)" "$WORK/al_rd.json" >/dev/null 2>&1 \
   && jq -e --arg a2 "$UP_ALPHA2" --arg k "$KEEP" --arg n "$NAP" "(.packages | keys) == ([\$a2, \$k, \$n] | sort)" "$WORK/al_rd_bz2.json" >/dev/null 2>&1; then
  pass
else
  fail "allowlist entries not applied (want ${UP_ALPHA2} + hosted ${KEEP}/${NAP}, X-AK-Allowlist-Dropped: 2)" \
    "PUT HTTP ${AL_SETUP}; GET HTTP ${st}; header='${dropped}'; json keys=$(keys_of "$WORK/al_rd.json"); bz2 keys=$(keys_of "$WORK/al_rd_bz2.json")"
fi

begin_test "FIX #4576: channeldata.json of an allowlisted virtual omits the name the list does not admit"
st="$(hget "/conda/${AL2}/channeldata.json" "$WORK/al2_cd.json")"
st_v="$(hget "/conda/${V}/channeldata.json" "$WORK/v_cd.json")"
if [ "$st" = "200" ] && [ "$st_v" = "200" ] \
   && jq -e '.packages | has("dtfup-alpha") | not' "$WORK/al2_cd.json" >/dev/null 2>&1 \
   && jq -e '.packages | has("dtfup-alpha")' "$WORK/v_cd.json" >/dev/null 2>&1; then
  pass
else
  fail "channeldata not filtered by the allowlist" \
    "allowlisted HTTP ${st} names=$(jq -c '.packages|keys' "$WORK/al2_cd.json" 2>/dev/null); unrestricted HTTP ${st_v} names=$(jq -c '.packages|keys' "$WORK/v_cd.json" 2>/dev/null)"
fi

begin_test "FIX #4576: GET returns the list; enabled:false restores the full merge without the header; DELETE removes it; each change is audited"
st_g="$(hget "/api/v1/repositories/${AL}/allowlist" "$WORK/al_get.json" -H "$(auth_header)")"
st_off="$(curl -s --max-time 30 -o "$WORK/al_off.json" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":false,"entries":[{"name":"dtfup-a*","version":">=2"}]}' \
  "${BASE_URL}/api/v1/repositories/${AL}/allowlist" 2>/dev/null || echo 000)"
hget "/conda/${AL}/noarch/repodata.json" "$WORK/al_rd_off.json" >/dev/null
st_d="$(curl -s --max-time 30 -o "$WORK/al_del.json" -w '%{http_code}' -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${AL}/allowlist" 2>/dev/null || echo 000)"
st_g2="$(hget "/api/v1/repositories/${AL}/allowlist" "$WORK/al_get2.json" -H "$(auth_header)")"
AL_ID="$(api_get "/api/v1/repositories/${AL}" | jq -r '.id // empty')"
audit=0
if [ -n "$AL_ID" ] && [ "$st_off" = "200" ]; then
  wait_until "3 REPOSITORY_ALLOWLIST_CHANGED rows" 20 audit_rows_ge 3 REPOSITORY_ALLOWLIST_CHANGED "resource_id = '${AL_ID}'" >/dev/null 2>&1
  audit="$(audit_rows REPOSITORY_ALLOWLIST_CHANGED "resource_id = '${AL_ID}'")"
fi
if [ "$st_g" = "200" ] && jq -e '.enabled == true and .entry_count == 2 and .entries[0].name == "dtfup-a*" and .entries[0].version == ">=2" and .entries[1].subdirs == ["linux-64"]' "$WORK/al_get.json" >/dev/null 2>&1 \
   && [ "$st_off" = "200" ] && [ -z "$(hdr "$WORK/al_rd_off.json" X-AK-Allowlist-Dropped)" ] \
   && jq -e --arg a "$UP_ALPHA1" --arg b "$UP_BLOCKED" '.packages | has($a) and has($b)' "$WORK/al_rd_off.json" >/dev/null 2>&1 \
   && [ "$st_d" = "200" ] && [ "$st_g2" = "200" ] && jq -e '.enabled == false and .entry_count == 0' "$WORK/al_get2.json" >/dev/null 2>&1 \
   && [ "$audit" = "3" ]; then
  pass
else
  fail "allowlist lifecycle wrong" \
    "GET HTTP ${st_g} $(head -c 200 "$WORK/al_get.json"); disable HTTP ${st_off}, keys=$(keys_of "$WORK/al_rd_off.json") header='$(hdr "$WORK/al_rd_off.json" X-AK-Allowlist-Dropped)'; DELETE HTTP ${st_d}; GET after HTTP ${st_g2} $(head -c 150 "$WORK/al_get2.json"); audit rows=${audit}"
fi

# =============================================================================
# #4559 a token scoped to a virtual reads its members through it
# =============================================================================
begin_test "FIX #4559: a token scoped to the private virtual reads the granted member's records and package through it, never the ungranted member's"
st="$(hget "/conda/${SV}/noarch/repodata.json" "$WORK/sv_rd.json" -H "Authorization: Bearer ${SA_TOKEN}")"
st_dl="$(hget "/conda/${SV}/noarch/${PRIV}" "$WORK/sv_priv.bin" -H "Authorization: Bearer ${SA_TOKEN}")"
st_hid="$(hget "/conda/${SV}/noarch/${HIDDEN}" "$WORK/sv_hidden.bin" -H "Authorization: Bearer ${SA_TOKEN}")"
if [ "$st" = "200" ] && jq -e --arg p "$PRIV" '(.packages | keys) == [$p]' "$WORK/sv_rd.json" >/dev/null 2>&1 \
   && [ "$st_dl" = "200" ] && cmp -s "$WORK/sv_priv.bin" "$WORK/${PRIV}" \
   && { [ "$st_hid" = "404" ] || [ "$st_hid" = "403" ]; }; then
  pass
else
  fail "virtual-scoped token cannot read its members through the virtual" \
    "repodata HTTP ${st} keys=$(keys_of "$WORK/sv_rd.json"); download HTTP ${st_dl}: $(head -c 150 "$WORK/sv_priv.bin" | tr -d '\0'); ungranted member download HTTP ${st_hid}"
fi

begin_test "CONTROL #4559: the same token is refused on the member's own URL, and anonymous reads of the private virtual are refused"
st_h="$(hget "/conda/${HP}/noarch/repodata.json" "$WORK/hp_tok.json" -H "Authorization: Bearer ${SA_TOKEN}")"
st_a="$(hget "/conda/${SV}/noarch/repodata.json" "$WORK/sv_anon.json")"
if { [ "$st_h" = "404" ] || [ "$st_h" = "403" ]; } && [ "$st_a" = "401" ] \
   && ! grep -q "$PRIV" "$WORK/hp_tok.json" && ! grep -q "$PRIV" "$WORK/sv_anon.json"; then
  pass
else
  fail "token scope or visibility leak" "member URL with SV token HTTP ${st_h}: $(head -c 150 "$WORK/hp_tok.json"); anonymous SV HTTP ${st_a}"
fi

end_suite
