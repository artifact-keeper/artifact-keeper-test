#!/usr/bin/env bash
# =============================================================================
# tiers/conda-virtual-shadow-and-cache/oracle.sh: conda virtual name
#   shadowing, Cache-Control on authenticated reads, indexed_timestamp, the
#   rattler /t/<TOKEN> layout, and origin policies on Remote content
#   (artifact-keeper#4555, #4506)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. The mock channel publishes
# dtfup-alpha 1.0 + 2.0 and dtfup-blocked 1.0 (noarch) and logs one line per
# request ("mock-conda: "GET <path> HTTP/1.1" <code> -").
#
# Topology (keys suffixed per run):
#   H   public hosted channel: dtfup-alpha 0.5 (the internal package whose name
#       the upstream also publishes), dtfhost-own 1.0
#   R   remote -> mock          V   virtual {H, R}
#   R2  remote -> mock, with a repository-scoped origin policy denying the
#       mock's upstream URL      V2  virtual {R2}
#   P   private hosted channel: dtfpriv-pkg 1.0 (token-channel reads)
#
# Every FIX case is RED on 1.10.0 and GREEN on 1.11.0+; every CONTROL holds on
# both. See the manifest for the bugs.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly, so a non-zero helper (grep with no match, jq on a
# non-JSON error body) must not end the suite before the assertion runs.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
UPSTREAM="http://172.16.${SLOT}.70/"
UPSTREAM_NORM="http://172.16.${SLOT}.70"
MOCK_CTR="ak-dtf${SLOT}-mock-conda"

H="cvs-host-${SUF}"
R="cvs-remote-${SUF}"
V="cvs-virt-${SUF}"
R2="cvs-remote2-${SUF}"
V2="cvs-virt2-${SUF}"
P="cvs-priv-${SUF}"

OWNED_HOSTED="dtfup-alpha-0.5-0.tar.bz2"   # internal package, same NAME as upstream
OWN="dtfhost-own-1.0-0.tar.bz2"
UP_ALPHA1="dtfup-alpha-1.0-0.tar.bz2"      # upstream impostors (name owned by H)
UP_ALPHA2="dtfup-alpha-2.0-0.tar.bz2"      # the one the mock has bytes for
UP_BLOCKED="dtfup-blocked-1.0-0.tar.bz2"   # upstream name H does not own
PRIV="dtfpriv-pkg-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-cvs-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# hget PATH OUTFILE [curl args...] -> HTTP status; headers in OUTFILE.hdr
hget() {
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -D "${out}.hdr" -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
hdr() { grep -i "^$2:" "${1}.hdr" 2>/dev/null | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }
conda_put() {  # conda_put <repo> <file> <filename> -> status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$2" \
    "${BASE_URL}/conda/$1/noarch/$3" 2>/dev/null || echo 000
}
mock_hits() { docker logs "$MOCK_CTR" 2>&1 | grep -c "GET /noarch/$1 " || true; }

begin_suite "conda-virtual-shadow-and-cache (#4555 #4506)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: admin auth, repositories, uploads, channel token"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$R" conda remote "$UPSTREAM" || setup_err+="create remote; "
create_repo "$R2" conda remote "$UPSTREAM" || setup_err+="create remote2; "
create_repo "$V" conda virtual || setup_err+="create virtual; "
create_repo "$V2" conda virtual || setup_err+="create virtual2; "
api_post "/api/v1/repositories" \
  "{\"key\":\"${P}\",\"name\":\"${P}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":false}" \
  >/dev/null 2>&1 || setup_err+="create private; "
# Hosted member first, so priority alone cannot explain a hosted-first merge.
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${H}\"}" >/dev/null || setup_err+="add H to V; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\"}" >/dev/null || setup_err+="add R to V; "
api_post "/api/v1/repositories/${V2}/members" "{\"member_key\":\"${R2}\"}" >/dev/null || setup_err+="add R2 to V2; "

BUILD="${DTF_DIR}/fixtures/conda/build.sh"
bash "$BUILD" "$WORK" dtfup-alpha 0.5 0 noarch >/dev/null 2>&1 || setup_err+="build ${OWNED_HOSTED}; "
bash "$BUILD" "$WORK" dtfhost-own 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${OWN}; "
bash "$BUILD" "$WORK" dtfpriv-pkg 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${PRIV}; "
for spec in "$H:$OWNED_HOSTED" "$H:$OWN" "$P:$PRIV"; do
  st="$(conda_put "${spec%%:*}" "$WORK/${spec#*:}" "${spec#*:}")"
  [ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="upload ${spec} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); "
done
CHANNEL_TOKEN="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"name\":\"cvs-channel-${SUF}\",\"scopes\":[\"read:artifacts\"]}" 2>/dev/null \
  | jq -r '.token // empty' 2>/dev/null || true)"
[ -n "$CHANNEL_TOKEN" ] || setup_err+="mint channel token; "
R2_ID="$(api_get "/api/v1/repositories/${R2}" | jq -r '.id // empty')"
[ -n "$R2_ID" ] || setup_err+="resolve R2 id; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4555 name shadowing in the virtual merge
# =============================================================================
st_v="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_rd.json")"
V_KEYS="$(jq -c '[(.packages // {}), (.["packages.conda"] // {})] | add | keys' "$WORK/v_rd.json" 2>/dev/null)"

begin_test "CONTROL: virtual repodata.json lists the hosted package and the remote's non-owned record"
if [ "$st_v" = "200" ] \
   && jq -e --arg h "$OWNED_HOSTED" --arg o "$OWN" --arg b "$UP_BLOCKED" \
        '.packages | has($h) and has($o) and has($b)' "$WORK/v_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "virtual merge lost the hosted records or the remote's unowned record (HTTP ${st_v})" "keys=${V_KEYS}"
fi

begin_test "FIX #4555: virtual repodata.json carries NO remote record under the hosted-owned name dtfup-alpha"
if [ "$st_v" = "200" ] \
   && jq -e --arg a "$UP_ALPHA1" --arg b "$UP_ALPHA2" \
        '([(.packages // {}), (.["packages.conda"] // {})] | add) as $p
         | ($p | has($a) | not) and ($p | has($b) | not)
         and ([$p[] | select(.name == "dtfup-alpha") | .version] == ["0.5"])' \
        "$WORK/v_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "the upstream's dtfup-alpha records shadow the hosted-owned name in the virtual merge (dependency confusion)" "keys=${V_KEYS}"
fi

begin_test "FIX #4555: virtual channeldata.json names only the hosted dtfup-alpha (0.5), not the upstream's 2.0"
st="$(hget "/conda/${V}/channeldata.json" "$WORK/v_cd.json")"
CD_VER="$(jq -r '.packages["dtfup-alpha"].version // empty' "$WORK/v_cd.json" 2>/dev/null)"
if [ "$st" = "200" ] && [ "$CD_VER" = "0.5" ] \
   && jq -e '.packages | has("dtfhost-own")' "$WORK/v_cd.json" >/dev/null 2>&1; then
  pass
else
  fail "channeldata.json dtfup-alpha entry is not the hosted one (HTTP ${st}, version='${CD_VER}')" \
    "$(jq -c '.packages' "$WORK/v_cd.json" 2>/dev/null | head -c 400)"
fi

begin_test "FIX #4555: downloading the upstream's dtfup-alpha 2.0 through the virtual is refused and never proxied"
before="$(mock_hits "$UP_ALPHA2")"
st="$(hget "/conda/${V}/noarch/${UP_ALPHA2}" "$WORK/v_alpha2.bin")"
after="$(mock_hits "$UP_ALPHA2")"
if [ "$st" != "200" ] && [ "$after" = "$before" ]; then
  pass
else
  fail "the virtual served (or fetched) the upstream impostor for a hosted-owned name: HTTP ${st}, mock GETs ${before}->${after}"
fi

begin_test "CONTROL: the remote alone still proxies dtfup-alpha 2.0, and the virtual serves the hosted 0.5"
st_r="$(hget "/conda/${R}/noarch/${UP_ALPHA2}" "$WORK/r_alpha2.bin")"
st_h="$(hget "/conda/${V}/noarch/${OWNED_HOSTED}" "$WORK/v_alpha05.bin")"
if [ "$st_r" = "200" ] && [ "$st_h" = "200" ] \
   && cmp -s "$WORK/v_alpha05.bin" "$WORK/${OWNED_HOSTED}" && [ -s "$WORK/r_alpha2.bin" ]; then
  pass
else
  fail "remote proxy or virtual hosted download broke (remote HTTP ${st_r}, virtual hosted HTTP ${st_h})"
fi

# =============================================================================
# #4555 indexed_timestamp (CEP-47)
# =============================================================================
begin_test "FIX #4555: hosted records carry indexed_timestamp == created_at (ms), stable across rebuilds and in the virtual merge"
CREATED_MS="$(psql_q "SELECT floor(extract(epoch FROM a.created_at) * 1000)::bigint FROM artifacts a
  JOIN repositories r ON r.id = a.repository_id
  WHERE r.key = '${H}' AND a.path LIKE '%${OWNED_HOSTED}' AND a.is_deleted = false LIMIT 1")"
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd1.json" >/dev/null
hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd2.json" -H "$(auth_header)" >/dev/null
IT1="$(jq -r --arg f "$OWNED_HOSTED" '.packages[$f].indexed_timestamp // empty' "$WORK/h_rd1.json" 2>/dev/null)"
IT2="$(jq -r --arg f "$OWNED_HOSTED" '.packages[$f].indexed_timestamp // empty' "$WORK/h_rd2.json" 2>/dev/null)"
ITV="$(jq -r --arg f "$OWNED_HOSTED" '.packages[$f].indexed_timestamp // empty' "$WORK/v_rd.json" 2>/dev/null)"
if [ -n "$CREATED_MS" ] && [ "$IT1" = "$CREATED_MS" ] && [ "$IT2" = "$CREATED_MS" ] && [ "$ITV" = "$CREATED_MS" ]; then
  pass
else
  fail "indexed_timestamp missing or not the row's created_at: db=${CREATED_MS} hosted=${IT1}/${IT2} virtual=${ITV}"
fi

# =============================================================================
# #4555 Cache-Control on authenticated reads
# =============================================================================
begin_test "CONTROL: anonymous repodata.json of a public channel stays Cache-Control public"
st="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/cc_anon.json")"
CC_ANON="$(hdr "$WORK/cc_anon.json" cache-control)"
if [ "$st" = "200" ] && echo "$CC_ANON" | grep -qiw "public" && ! echo "$CC_ANON" | grep -qiw "private"; then
  pass
else
  fail "anonymous public-channel repodata.json: HTTP ${st}, Cache-Control '${CC_ANON}'"
fi

begin_test "FIX #4555: authenticated repodata.json and channeldata.json (hosted and virtual) are Cache-Control private, never public"
cc_bad=""
for p in "/conda/${H}/noarch/repodata.json" "/conda/${H}/channeldata.json" \
         "/conda/${V}/noarch/repodata.json" "/conda/${V}/channeldata.json"; do
  st="$(hget "$p" "$WORK/cc_auth" -H "$(auth_header)")"
  cc="$(hdr "$WORK/cc_auth" cache-control)"
  if [ "$st" != "200" ] || ! echo "$cc" | grep -qiw "private" || echo "$cc" | grep -qiw "public"; then
    cc_bad+="${p} -> HTTP ${st} Cache-Control '${cc}'; "
  fi
done
if [ -z "$cc_bad" ]; then
  pass
else
  fail "a credentialed conda channel response is shared-cacheable" "$cc_bad"
fi

# =============================================================================
# #4555 rattler token layout /t/<TOKEN>/conda/<repo>/...
# =============================================================================
begin_test "CONTROL: private channel: anonymous repodata.json refused; /conda/t/<TOKEN>/ form serves it"
st_anon="$(hget "/conda/${P}/noarch/repodata.json" "$WORK/p_anon.json")"
st_tok="$(hget "/conda/t/${CHANNEL_TOKEN}/${P}/noarch/repodata.json" "$WORK/p_tok.json")"
if { [ "$st_anon" = "401" ] || [ "$st_anon" = "403" ] || [ "$st_anon" = "404" ]; } \
   && [ "$st_tok" = "200" ] && jq -e --arg f "$PRIV" '.packages | has($f)' "$WORK/p_tok.json" >/dev/null 2>&1; then
  pass
else
  fail "private channel reads: anonymous HTTP ${st_anon}, /conda/t/<TOKEN>/ HTTP ${st_tok}" "$(head -c 300 "$WORK/p_tok.json")"
fi

begin_test "FIX #4555: rattler layout /t/<TOKEN>/conda/<repo>/noarch/repodata.json serves the private channel (private, no-store)"
st="$(hget "/t/${CHANNEL_TOKEN}/conda/${P}/noarch/repodata.json" "$WORK/p_rat.json")"
CC_RAT="$(hdr "$WORK/p_rat.json" cache-control)"
if [ "$st" = "200" ] && jq -e --arg f "$PRIV" '.packages | has($f)' "$WORK/p_rat.json" >/dev/null 2>&1 \
   && echo "$CC_RAT" | grep -qiw "private" && echo "$CC_RAT" | grep -qiw "no-store"; then
  pass
else
  fail "rattler token URL does not serve the private channel: HTTP ${st}, Cache-Control '${CC_RAT}'" "$(head -c 300 "$WORK/p_rat.json")"
fi

# 1.10.0 also answers 401 here (its auth layer refuses the unknown /t/ path
# before routing), so this is a control on the refusal, not a fix gate.
begin_test "CONTROL: rattler layout with a bogus token answers 401"
st="$(hget "/t/not-a-real-token-${SUF}/conda/${P}/noarch/repodata.json" "$WORK/p_bogus.json")"
if [ "$st" = "401" ]; then
  pass
else
  fail "bogus token on the rattler layout: want 401, got HTTP ${st}" "$(head -c 300 "$WORK/p_bogus.json")"
fi

# =============================================================================
# #4506 origin policy on a Remote's proxied content
# =============================================================================
begin_test "CONTROL #4506: before any policy, R2 proxies dtfup-alpha 2.0 (now cached) and V2 serves it"
st_r2="$(hget "/conda/${R2}/noarch/${UP_ALPHA2}" "$WORK/r2_pre.bin")"
st_v2="$(hget "/conda/${V2}/noarch/${UP_ALPHA2}" "$WORK/v2_pre.bin")"
if [ "$st_r2" = "200" ] && [ "$st_v2" = "200" ] && cmp -s "$WORK/r2_pre.bin" "$WORK/r_alpha2.bin"; then
  pass
else
  fail "pre-policy proxy fetch failed (R2 HTTP ${st_r2}, V2 HTTP ${st_v2})"
fi

POLICY_BODY="{\"name\":\"cvs-deny-${SUF}\",\"repository_id\":\"${R2_ID}\",\"max_severity\":\"critical\",\"block_unscanned\":false,\"block_on_fail\":false,\"predicates\":{\"origin\":{\"denied_upstreams\":[\"${UPSTREAM_NORM}\"]}}}"
POLICY_CODE="$(curl -s -o "$WORK/policy.json" -w '%{http_code}' --max-time 30 -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/json' -d "$POLICY_BODY" \
  "${BASE_URL}/api/v1/security/policies" 2>/dev/null || echo 000)"

begin_test "FIX #4506: R2 with an origin policy denying its upstream refuses the CACHED package 403 (scan-policy body)"
st="$(hget "/conda/${R2}/noarch/${UP_ALPHA2}" "$WORK/r2_post.bin")"
if [ "$st" = "403" ] && grep -q "blocked by the repository's scan policy" "$WORK/r2_post.bin"; then
  pass
else
  fail "origin-denied Remote still serves its cached content: HTTP ${st} (policy create HTTP ${POLICY_CODE})" \
    "policy=$(head -c 300 "$WORK/policy.json") body=$(head -c 200 "$WORK/r2_post.bin" | tr -cd '[:print:]')"
fi

begin_test "FIX #4506: the virtual over R2 does not serve the origin-denied package"
st="$(hget "/conda/${V2}/noarch/${UP_ALPHA2}" "$WORK/v2_post.bin")"
if [ "$st" != "200" ] && ! cmp -s "$WORK/v2_post.bin" "$WORK/r_alpha2.bin"; then
  pass
else
  fail "virtual V2 served the package its only member's origin policy refuses: HTTP ${st}"
fi

begin_test "CONTROL #4506: the policy is scoped to R2; R (same upstream, no policy) still serves the package"
st="$(hget "/conda/${R}/noarch/${UP_ALPHA2}" "$WORK/r_post.bin")"
if [ "$st" = "200" ] && cmp -s "$WORK/r_post.bin" "$WORK/r_alpha2.bin"; then
  pass
else
  fail "an unrelated Remote stopped serving after R2's policy was attached: HTTP ${st}"
fi

end_suite
