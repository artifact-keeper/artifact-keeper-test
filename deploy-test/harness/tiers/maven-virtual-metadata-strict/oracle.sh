#!/usr/bin/env bash
# =============================================================================
# tiers/maven-virtual-metadata-strict/oracle.sh: with
#   `virtual_member_fallback=strict`, a Maven virtual whose Remote member is
#   unavailable answers maven-metadata.xml and its .sha1 with 503 +
#   Retry-After instead of a partial merge; the default keeps the marked
#   partial merge, and .meta/prefixes.txt is unchanged (artifact-keeper#5777)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-files` and exported
# BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# host port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Topology: see the manifest. VS strict [RS, H], VA available [RA, H],
# VD untouched [RD, H], VN strict [RN (404s), H].
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on it.
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"   # where the BACKEND reaches the mock
RECOVER_SECS=75                      # breaker open period 10-12 s, doubling

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mock_put(){ # <path> <file> [content-type]
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-text/xml}" | jqr '.bytes // empty'
}
mock_status(){ curl -s --max-time 5 -X POST "${MOCK}/__status?path=$1&code=$2" | jqr '.code // empty'; }

# get <path> <out> -> sets ST (status); headers in <out>.h
get(){
  ST="$(curl -s --max-time 60 -D "$2.h" -o "$2" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "${BASE}$1" || true)"
}
hdr(){ grep -i "^$2:" "$1.h" 2>/dev/null | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true; }
snip(){ head -c 220 "$1" 2>/dev/null | tr '\n' ' ' || true; }
sha1_of(){ sha1sum "$1" 2>/dev/null | awk '{print $1}'; }
body_sha1(){ tr -d ' \r\n' < "$1" 2>/dev/null | cut -c1-40; }

mk(){ # <key> <type> [upstream]
  local body
  body="$(jq -n --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"maven",repo_type:$t,is_public:true}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  [ "$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty')" = "$1" ] \
    || SETUP_ERR="${SETUP_ERR} create:$1"
}
virt(){ # <key> <member>...
  local key="$1" prio=1 m c; shift
  mk "$key" virtual
  for m in "$@"; do
    c="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/${key}/members" \
      -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
      -d "{\"member_key\":\"${m}\",\"priority\":${prio}}" || true)"
    case "$c" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} member:${key}<-${m}:${c}";; esac
    prio=$((prio + 1))
  done
}
set_fallback(){ # <key> <value>
  local c
  c="$(curl -s --max-time 30 -o "$W/patch-$1.json" -w '%{http_code}' -X PATCH \
    "$BASE/api/v1/repositories/$1" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "{\"virtual_member_fallback\":\"$2\"}" || echo 000)"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} fallback:$1:$2:${c}"
}
fallback_of(){ curl -s --max-time 30 -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/$1" \
  | jqr '.virtual_member_fallback // "absent"'; }

# check_partial <file> <member-key> <label>: 200 marks of a #5809 partial merge
check_partial(){
  local pm cc wv
  pm="$(hdr "$1" x-ak-partial-members)"; cc="$(hdr "$1" cache-control)"; wv="$(hdr "$1" warning)"
  note "$3: X-AK-Partial-Members='${pm}' Cache-Control='${cc}' Warning='${wv}'"
  case ",${pm// /}," in *",$2,"*) ;; *) fail_g "$3: X-AK-Partial-Members='${pm}', expected it to name '$2'";; esac
  case "$cc" in *no-store*) ;; *) fail_g "$3: Cache-Control='${cc}', expected no-store on a partial merge";; esac
  case "$wv" in 199*) ;; *) fail_g "$3: Warning='${wv}', expected 'Warning: 199' on a partial merge";; esac
}
# check_unavailable <file> <label>: the retryable 503, not a document, not cacheable
check_unavailable(){
  local ra cc
  ra="$(hdr "$1" retry-after)"; cc="$(hdr "$1" cache-control)"
  note "$2: HTTP ${ST} Retry-After='${ra}' Cache-Control='${cc}' X-AK-Partial-Members='$(hdr "$1" x-ak-partial-members)': $(snip "$1")"
  [ "$ST" = "503" ] || fail_g "$2 answered ${ST}, expected 503"
  [ -n "$ra" ] || fail_g "$2: no Retry-After"
  ! grep -q '<metadata' "$1" 2>/dev/null || fail_g "$2: the body is a metadata document (a partial merge)"
  case "$cc" in *public*) fail_g "$2: Cache-Control='${cc}' lets a cache store the answer";; esac
  if echo "$cc" | grep -Eq 'max-age=[1-9]'; then fail_g "$2: Cache-Control='${cc}' has a positive max-age"; fi
}

begin_suite "maven-virtual-metadata-strict"

begin_test "setup: admin login, hosted jar, Remote metadata forced to 503, four virtuals"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
P="mvs${SUF}"   # mock path prefixes carry the run, so reruns never share state
SETUP_ERR=""
GID="com.example.dtfmvs${SUF}"
G="${GID//.//}"
MD="${G}/a/maven-metadata.xml"
RPREFIX="/org/dtfmvs${SUF}"
cat > "$W/remote.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>${GID}</groupId>
  <artifactId>a</artifactId>
  <versioning>
    <latest>2.0</latest>
    <release>2.0</release>
    <versions>
      <version>2.0</version>
    </versions>
    <lastUpdated>20240101000000</lastUpdated>
  </versioning>
</metadata>
EOF
printf '## repository-prefixes/2.0\n%s\n' "$RPREFIX" > "$W/remote-prefixes.txt"
for m in s a d; do
  [ -n "$(mock_put "/${P}-${m}/${MD}" "$W/remote.xml")" ] || SETUP_ERR="${SETUP_ERR} mock-put:${m}"
  [ -n "$(mock_put "/${P}-${m}/${MD}.sha1" <(printf '%s' "$(sha1_of "$W/remote.xml")") text/plain)" ] \
    || SETUP_ERR="${SETUP_ERR} mock-put-sha1:${m}"
  [ -n "$(mock_put "/${P}-${m}/.meta/prefixes.txt" "$W/remote-prefixes.txt" text/plain)" ] \
    || SETUP_ERR="${SETUP_ERR} mock-put-prefixes:${m}"
  for f in "${MD}" "${MD}.sha1" ".meta/prefixes.txt"; do
    [ "$(mock_status "/${P}-${m}/${f}" 503)" = "503" ] || SETUP_ERR="${SETUP_ERR} mock-503:${m}:${f}"
  done
done

H="mvs-h-${SUF}"; RS="mvs-rs-${SUF}"; RA="mvs-ra-${SUF}"; RD="mvs-rd-${SUF}"; RN="mvs-rn-${SUF}"
VS="mvs-vs-${SUF}"; VA="mvs-va-${SUF}"; VD="mvs-vd-${SUF}"; VN="mvs-vn-${SUF}"
mk "$H" local
for pair in "$RS:s" "$RA:a" "$RD:d" "$RN:n"; do mk "${pair%%:*}" remote "${UP}/${P}-${pair#*:}/"; done
virt "$VS" "$RS" "$H"
virt "$VA" "$RA" "$H"
virt "$VD" "$RD" "$H"
virt "$VN" "$RN" "$H"
set_fallback "$VS" strict
set_fallback "$VN" strict
set_fallback "$VA" available
head -c 3000 /dev/urandom > "$W/a.jar"
c="$(curl -s -o "$W/up.out" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer $TOK" \
  --data-binary @"$W/a.jar" "${BASE}/maven/${H}/${G}/a/1.0/a-1.0.jar" || true)"
case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} upload:${c}:$(snip "$W/up.out")";; esac
note "virtual_member_fallback: ${VS}=$(fallback_of "$VS") ${VA}=$(fallback_of "$VA") ${VD}=$(fallback_of "$VD") ${VN}=$(fallback_of "$VN")"
[ "$(fallback_of "$VS")" = "strict" ] || SETUP_ERR="${SETUP_ERR} readback:${VS}"
if [ -n "$SETUP_ERR" ]; then fail "setup failed:${SETUP_ERR}" "$DETAIL"; end_suite; fi
pass

# -----------------------------------------------------------------------------
reset_case
begin_test "FIX #5777: strict virtual [503 Remote, hosted]: maven-metadata.xml answers 503 + Retry-After, not the partial merge, and is not cached"
get "/maven/${VS}/${MD}" "$W/vs.xml"
check_unavailable "$W/vs.xml" "strict maven-metadata.xml"
get "/maven/${VS}/${MD}" "$W/vs2.xml"
check_unavailable "$W/vs2.xml" "strict maven-metadata.xml (repeat)"
finish_case "a strict virtual served a merge missing its unavailable member"

reset_case
begin_test "FIX #5777: strict virtual [503 Remote, hosted]: maven-metadata.xml.sha1 answers 503 + Retry-After"
get "/maven/${VS}/${MD}.sha1" "$W/vs.sha1"
check_unavailable "$W/vs.sha1" "strict maven-metadata.xml.sha1"
grep -Eq '^[0-9a-f]{40}' "$W/vs.sha1" && fail_g "the .sha1 body is a checksum: $(snip "$W/vs.sha1")"
finish_case "a strict virtual served the checksum of a partial merge"

# -----------------------------------------------------------------------------
for pair in "$VD:$RD:untouched" "$VA:$RA:explicit available"; do
  v="${pair%%:*}"; rest="${pair#*:}"; r="${rest%%:*}"; label="${rest#*:}"
  reset_case
  begin_test "GUARD #5809: ${label} virtual [503 Remote, hosted]: the marked partial merge (200, hosted 1.0 only) and its .sha1"
  get "/maven/${v}/${MD}" "$W/${v}.xml"
  note "maven-metadata.xml -> ${ST}: $(snip "$W/${v}.xml")"
  [ "$ST" = "200" ] || fail_g "maven-metadata.xml answered ${ST}, expected the partial 200"
  grep -q '<version>1.0</version>' "$W/${v}.xml" || fail_g "the hosted member's 1.0 is missing"
  ! grep -q '<version>2.0</version>' "$W/${v}.xml" || fail_g "the down member's 2.0 is listed"
  check_partial "$W/${v}.xml" "$r" "${label} maven-metadata.xml"
  get "/maven/${v}/${MD}.sha1" "$W/${v}.sha1"
  note ".sha1 -> ${ST}: $(snip "$W/${v}.sha1") (document SHA-1 $(sha1_of "$W/${v}.xml"))"
  [ "$ST" = "200" ] || fail_g ".sha1 answered ${ST}, expected 200"
  [ "$(body_sha1 "$W/${v}.sha1")" = "$(sha1_of "$W/${v}.xml")" ] || fail_g "the .sha1 is not the SHA-1 of the partial document"
  check_partial "$W/${v}.sha1" "$r" "${label} maven-metadata.xml.sha1"
  finish_case "the default (${label}) no longer serves the marked partial merge"
done

# -----------------------------------------------------------------------------
reset_case
begin_test "CONTROL: strict virtual [404 Remote, hosted]: a 404 member is a miss, so maven-metadata.xml is a complete 200"
get "/maven/${VN}/${MD}" "$W/vn.xml"
note "maven-metadata.xml -> ${ST} X-AK-Partial-Members='$(hdr "$W/vn.xml" x-ak-partial-members)': $(snip "$W/vn.xml")"
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200"
grep -q '<version>1.0</version>' "$W/vn.xml" || fail_g "the hosted member's 1.0 is missing"
[ -z "$(hdr "$W/vn.xml" x-ak-partial-members)" ] || fail_g "a 404 member was reported partial"
finish_case "strict mode treated a 404 member as unavailable"

# -----------------------------------------------------------------------------
reset_case
begin_test "GUARD: .meta/prefixes.txt is unchanged by strict mode: the same non-200 on strict and default during the outage, 404 behind a 404 Remote"
get "/maven/${VS}/.meta/prefixes.txt" "$W/vs.pfx"; s_st="$ST"
note "strict ${VS} prefixes.txt -> ${s_st} X-AK-Partial-Members='$(hdr "$W/vs.pfx" x-ak-partial-members)': $(snip "$W/vs.pfx")"
get "/maven/${VD}/.meta/prefixes.txt" "$W/vd.pfx"; d_st="$ST"
note "default ${VD} prefixes.txt -> ${d_st}: $(snip "$W/vd.pfx")"
[ "$s_st" != "200" ] || fail_g "strict prefixes.txt served a 200 union without its unavailable member"
[ "$d_st" != "200" ] || fail_g "default prefixes.txt served a 200 union without its unavailable member"
[ "$s_st" = "$d_st" ] || fail_g "strict prefixes.txt answered ${s_st}, the default ${d_st}: strict mode changed prefixes.txt"
get "/maven/${VN}/.meta/prefixes.txt" "$W/vn.pfx"
note "strict ${VN} [404 Remote, hosted] prefixes.txt -> ${ST}: $(snip "$W/vn.pfx")"
[ "$ST" = "404" ] || fail_g "behind a Remote that 404s prefixes.txt answered ${ST}, expected 404 (#5743)"
finish_case "strict mode changed .meta/prefixes.txt"

# -----------------------------------------------------------------------------
reset_case
begin_test "CONTROL: once the Remote is back, the strict virtual serves the full merge (1.0 and 2.0) with 200, unmarked, and its .sha1 matches"
for m in s d; do
  for f in "${MD}" "${MD}.sha1" ".meta/prefixes.txt"; do mock_status "/${P}-${m}/${f}" 0 >/dev/null; done
done
t0="$(date +%s)"; tries=0
while :; do
  tries=$((tries + 1))
  get "/maven/${VS}/${MD}" "$W/vs-back.xml"
  if [ "$ST" = "200" ] && [ -z "$(hdr "$W/vs-back.xml" x-ak-partial-members)" ]; then break; fi
  [ $(( $(date +%s) - t0 )) -ge "$RECOVER_SECS" ] && break
  sleep 3
done
note "after ${tries} request(s) in $(( $(date +%s) - t0 ))s: HTTP ${ST} X-AK-Partial-Members='$(hdr "$W/vs-back.xml" x-ak-partial-members)': $(snip "$W/vs-back.xml")"
[ "$ST" = "200" ] || fail_g "maven-metadata.xml answered ${ST} ${RECOVER_SECS}s after the member came back, expected 200"
grep -q '<version>1.0</version>' "$W/vs-back.xml" || fail_g "the hosted member's 1.0 is missing"
grep -q '<version>2.0</version>' "$W/vs-back.xml" || fail_g "the recovered member's 2.0 is missing (an outage answer was kept)"
[ -z "$(hdr "$W/vs-back.xml" x-ak-partial-members)" ] || fail_g "the merge is still marked partial"
get "/maven/${VS}/${MD}.sha1" "$W/vs-back.sha1"
note ".sha1 -> ${ST}: $(snip "$W/vs-back.sha1") (document SHA-1 $(sha1_of "$W/vs-back.xml"))"
[ "$ST" = "200" ] || fail_g ".sha1 answered ${ST}, expected 200"
[ "$(body_sha1 "$W/vs-back.sha1")" = "$(sha1_of "$W/vs-back.xml")" ] || fail_g "the .sha1 does not match the full document"
finish_case "the strict virtual did not serve the full merge once its member was back"

reset_case
begin_test "CONTROL: with the Remotes' prefix files served, prefixes.txt is the same 200 union on strict and default"
for v in "$VS" "$VD"; do
  t0="$(date +%s)"
  while :; do
    get "/maven/${v}/.meta/prefixes.txt" "$W/${v}-back.pfx"
    [ "$ST" = "200" ] && break
    [ $(( $(date +%s) - t0 )) -ge "$RECOVER_SECS" ] && break
    sleep 3
  done
  note "${v} prefixes.txt -> ${ST}: $(snip "$W/${v}-back.pfx")"
  [ "$ST" = "200" ] || fail_g "${v} prefixes.txt answered ${ST}, expected 200"
  grep -qx "$RPREFIX" "$W/${v}-back.pfx" || fail_g "${v} prefixes.txt does not list the Remote's ${RPREFIX}"
  grep -q '^/com/example' "$W/${v}-back.pfx" || fail_g "${v} prefixes.txt does not list the hosted member's groupId"
  [ -z "$(hdr "$W/${v}-back.pfx" x-ak-partial-members)" ] || fail_g "${v} prefixes.txt is marked partial"
done
cmp -s "$W/${VS}-back.pfx" "$W/${VD}-back.pfx" || fail_g "strict and default prefixes.txt differ"
finish_case "the prefixes.txt union changed"

end_suite
