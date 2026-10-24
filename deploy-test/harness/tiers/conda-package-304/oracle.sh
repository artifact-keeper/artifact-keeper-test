#!/usr/bin/env bash
# =============================================================================
# tiers/conda-package-304/oracle.sh: conditional conda package downloads
#   (artifact-keeper#4579): ETag / Last-Modified on every package response and
#   304 Not Modified on a matching validator, hosted, cached Remote, Virtual,
#   and both token layouts.
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Topology (keys suffixed per run):
#   H   public hosted channel: dtf304-own 1.0
#   R   remote -> mock (serves dtfup-alpha-2.0-0.tar.bz2)
#   VH  virtual {H}     VR  virtual {R}
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe records its outcome instead.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
UPSTREAM="http://172.16.${SLOT}.70/"
MOCK_CTR="ak-dtf${SLOT}-mock-conda"

H="c304-host-${SUF}"
R="c304-remote-${SUF}"
VH="c304-vhost-${SUF}"
VR="c304-vrem-${SUF}"
Q="c304-held-${SUF}"
OWN="dtf304-own-1.0-0.tar.bz2"
HELD="dtf304-held-1.0-0.tar.bz2"
UP="dtfup-alpha-2.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-c304-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# hget PATH OUTFILE [curl args...] -> HTTP status; headers in OUTFILE.hdr
hget() {
  local p="$1" out="$2"; shift 2
  : >"$out"
  curl -s --max-time 60 -D "${out}.hdr" -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
hdr() { grep -i "^$2:" "${1}.hdr" 2>/dev/null | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
conda_put() {  # conda_put <repo> <file> <filename> -> status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$2" \
    "${BASE_URL}/conda/$1/noarch/$3" 2>/dev/null || echo 000
}
mock_hits() { docker logs "$MOCK_CTR" 2>&1 | grep -c "GET /noarch/$1 " || true; }

FAILS=0; DETAIL=""
reset_case(){ FAILS=0; DETAIL=""; }
fail_g(){ echo "   !!! $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}$1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# conditional_case <label> <url path> <expected sha> [check_mock]
#   200 carries ETag "<sha>" and Last-Modified; If-None-Match (exact, W/, and
#   in a list) is 304 with no body; If-Modified-Since <Last-Modified> is 304.
#   With check_mock, none of the conditional requests reaches the mock.
conditional_case() {
  local label="$1" p="$2" sha="$3" check_mock="${4:-}"
  local etag="\"${sha}\"" st lm before after
  st="$(hget "$p" "$WORK/c.bin")"
  note "${label} GET: ${st} ETag=$(hdr "$WORK/c.bin" etag) Last-Modified=$(hdr "$WORK/c.bin" last-modified)"
  [ "$st" = "200" ] && [ "$(sha_of "$WORK/c.bin")" = "$sha" ] || fail_g "${label}: GET is ${st}, not the package bytes"
  [ "$(hdr "$WORK/c.bin" etag)" = "$etag" ] || fail_g "${label}: ETag is '$(hdr "$WORK/c.bin" etag)', not ${etag}"
  lm="$(hdr "$WORK/c.bin" last-modified)"
  [ -n "$lm" ] || fail_g "${label}: no Last-Modified"
  before="$(mock_hits "$UP")"
  local inm
  for inm in "$etag" "W/${etag}" "\"0000\", ${etag}"; do
    st="$(hget "$p" "$WORK/c304.bin" -H "If-None-Match: ${inm}")"
    note "${label} If-None-Match ${inm}: ${st} body=$(wc -c <"$WORK/c304.bin" | tr -d ' ')B"
    [ "$st" = "304" ] || fail_g "${label}: If-None-Match ${inm} answered ${st}, not 304"
    [ ! -s "$WORK/c304.bin" ] || fail_g "${label}: the 304 for ${inm} carried a body"
  done
  if [ -n "$lm" ]; then
    st="$(hget "$p" "$WORK/c304.bin" -H "If-Modified-Since: ${lm}")"
    note "${label} If-Modified-Since: ${st}"
    [ "$st" = "304" ] || fail_g "${label}: If-Modified-Since <Last-Modified> answered ${st}, not 304"
  fi
  if [ -n "$check_mock" ]; then
    after="$(mock_hits "$UP")"
    note "${label} mock requests for ${UP} during the conditional GETs: $((after - before))"
    [ "$after" = "$before" ] || fail_g "${label}: the conditional GETs reached the upstream"
  fi
}

begin_suite "conda-package-304 (#4579 #4181)"

# =============================================================================
begin_test "setup: admin auth, repositories, a hosted upload, a channel token, a warm remote cache"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$Q" conda local || setup_err+="create held; "
create_repo "$R" conda remote "$UPSTREAM" || setup_err+="create remote; "
create_repo "$VH" conda virtual || setup_err+="create vhost; "
create_repo "$VR" conda virtual || setup_err+="create vrem; "
api_post "/api/v1/repositories/${VH}/members" "{\"member_key\":\"${H}\"}" >/dev/null || setup_err+="add H to VH; "
api_post "/api/v1/repositories/${VR}/members" "{\"member_key\":\"${R}\"}" >/dev/null || setup_err+="add R to VR; "
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
bash "$BUILD" "$WORK" dtf304-own 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${OWN}; "
bash "$BUILD" "$WORK" dtf304-held 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${HELD}; "
for spec in "$H:$OWN" "$Q:$HELD"; do
  st="$(conda_put "${spec%%:*}" "$WORK/${spec#*:}" "${spec#*:}")"
  [ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="upload ${spec} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); "
done
OWN_SHA="$(sha_of "$WORK/$OWN" 2>/dev/null)"
HELD_SHA="$(sha_of "$WORK/$HELD" 2>/dev/null)"
CHANNEL_TOKEN="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"name\":\"c304-channel-${SUF}\",\"scopes\":[\"read:artifacts\"]}" 2>/dev/null \
  | jq -r '.token // empty' 2>/dev/null || true)"
[ -n "$CHANNEL_TOKEN" ] || setup_err+="mint channel token; "
# Warm the remote: the first GET fills the cache; wait for its catalog row.
st="$(hget "/conda/${R}/noarch/${UP}" "$WORK/up.bin")"
[ "$st" = "200" ] || setup_err+="first remote GET ${st}; "
UP_SHA="$(sha_of "$WORK/up.bin")"
R_ID="$(api_get "/api/v1/repositories/${R}" | jq -r '.id // empty')"
for _ in $(seq 1 50); do
  [ -n "$(psql_q "SELECT 1 FROM proxy_cache_artifacts WHERE repository_id = '${R_ID}' AND path = 'noarch/${UP}' AND checksum_sha256 IS NOT NULL")" ] && break
  sleep 0.2
done
[ -n "$(psql_q "SELECT 1 FROM proxy_cache_artifacts WHERE repository_id = '${R_ID}' AND path = 'noarch/${UP}'")" ] \
  || setup_err+="remote cache entry never catalogued; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
echo "-- ${OWN} sha ${OWN_SHA}; ${UP} sha ${UP_SHA}"
pass

# =============================================================================
# CONTROLS
# =============================================================================
begin_test "CONTROL: hosted, remote and virtual package GETs are 200 with the right bytes, also with a stale validator"
reset_case
for spec in "${H}:${OWN}:${OWN_SHA}" "${VH}:${OWN}:${OWN_SHA}" "${R}:${UP}:${UP_SHA}" "${VR}:${UP}:${UP_SHA}"; do
  IFS=: read -r repo file sha <<<"$spec"
  st="$(hget "/conda/${repo}/noarch/${file}" "$WORK/ctl.bin")"
  [ "$st" = "200" ] && [ "$(sha_of "$WORK/ctl.bin")" = "$sha" ] || fail_g "${repo}/${file}: ${st}, not the package bytes"
  st="$(hget "/conda/${repo}/noarch/${file}" "$WORK/ctl.bin" -H 'If-None-Match: "0000"')"
  [ "$st" = "200" ] && [ "$(sha_of "$WORK/ctl.bin")" = "$sha" ] || fail_g "${repo}/${file} with a stale validator: ${st}"
done
finish_case "conda package downloads broken"

# =============================================================================
# FIX #4579
# =============================================================================
begin_test "FIX #4579: a hosted package carries ETag/Last-Modified and revalidates 304 with no body"
reset_case
conditional_case "hosted" "/conda/${H}/noarch/${OWN}" "$OWN_SHA"
finish_case "hosted package downloads ignore conditional requests"

begin_test "FIX #4579: both token layouts revalidate the hosted package 304"
reset_case
conditional_case "conda token layout" "/conda/t/${CHANNEL_TOKEN}/${H}/noarch/${OWN}" "$OWN_SHA"
conditional_case "rattler token layout" "/t/${CHANNEL_TOKEN}/conda/${H}/noarch/${OWN}" "$OWN_SHA"
finish_case "token-layout package downloads ignore conditional requests"

begin_test "FIX #4579: a virtual served by its hosted member revalidates 304"
reset_case
conditional_case "virtual over hosted" "/conda/${VH}/noarch/${OWN}" "$OWN_SHA"
finish_case "virtual package downloads ignore conditional requests"

begin_test "FIX #4579: a cached remote package revalidates 304 without contacting the upstream"
reset_case
conditional_case "cached remote" "/conda/${R}/noarch/${UP}" "$UP_SHA" check_mock
finish_case "cached remote package downloads ignore conditional requests"

begin_test "FIX #4579: a virtual served by its cached remote member revalidates 304 without contacting the upstream"
reset_case
conditional_case "virtual over cached remote" "/conda/${VR}/noarch/${UP}" "$UP_SHA" check_mock
finish_case "virtual-over-remote package downloads ignore conditional requests"

begin_test "CONTROL: a quarantined hosted package is 409 even with a matching validator"
reset_case
psql_q "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_until = NOW() + INTERVAL '1 hour' WHERE path = 'noarch/${HELD}' AND repository_id = (SELECT id FROM repositories WHERE key = '${Q}')" >/dev/null
st="$(hget "/conda/${Q}/noarch/${HELD}" "$WORK/held.bin" -H "If-None-Match: \"${HELD_SHA}\"")"
note "held package with matching If-None-Match: ${st}"
[ "$st" = "409" ] || fail_g "a quarantined package answered ${st} to a conditional GET, not 409"
finish_case "a held package leaks through a conditional request"

end_suite
