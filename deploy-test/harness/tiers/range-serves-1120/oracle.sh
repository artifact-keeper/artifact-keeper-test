#!/usr/bin/env bash
# =============================================================================
# tiers/range-serves-1120/oracle.sh
#   #5145 Hugging Face resolve honours Range (hosted and cached Remote)
#   #5478 hosted .apk downloads honour Range
#   #5502 the generic route honours Range on a Remote's proxied serves
#   #5509 a ranged GET on a cold alpine Remote still fills the proxy cache
#   #5668 the native Maven route honours Range (Range part only)
#   #5139 small downloads on a keep-alive connection are not held ~40 ms
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-files"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mock_put(){ # <path> <file>
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=application/octet-stream" | jqr '.bytes // empty'
}
mock_gets(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get // empty'; }

# rget <url> <out> [range] -> sets ST (status), H (header file path)
H="$W/h.txt"
rget(){
  local url="$1" out="$2" range="${3:-}" args=()
  [ -n "$range" ] && args=(-H "Range: bytes=${range}")
  : > "$H"; : > "$out"
  ST="$(curl -s --max-time 60 -D "$H" -o "$out" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "${args[@]}" "$url" || true)"
}
hdr(){ grep -i "^$1:" "$H" | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true; }
# slice <file> <start> <end-inclusive> <out>
slice(){ dd if="$1" of="$4" iflag=skip_bytes,count_bytes skip="$2" count="$(( $3 - $2 + 1 ))" status=none 2>/dev/null || true; }

# check_window <label> <url> <ref-file> <start> <end>: 206, Content-Range,
# Content-Length and the exact bytes of the window.
check_window(){
  local label="$1" url="$2" ref="$3" s="$4" e="$5" size
  size="$(stat -c %s "$ref")"
  rget "$url" "$W/win.bin" "${s}-${e}"
  slice "$ref" "$s" "$e" "$W/want.bin"
  local cr; cr="$(hdr content-range)"
  [ "$ST" = "206" ] || fail_g "${label}: Range ${s}-${e} answered ${ST}, expected 206 (body $(stat -c %s "$W/win.bin") bytes, Accept-Ranges '$(hdr accept-ranges)')"
  [ "$cr" = "bytes ${s}-${e}/${size}" ] || fail_g "${label}: Content-Range '${cr}', expected 'bytes ${s}-${e}/${size}'"
  [ "$(sha_of "$W/win.bin")" = "$(sha_of "$W/want.bin")" ] || fail_g "${label}: the ${s}-${e} body ($(stat -c %s "$W/win.bin") bytes) is not that window of the file"
  note "${label}: Range ${s}-${e} -> ${ST} '${cr}' $(stat -c %s "$W/win.bin") bytes"
}
# check_416 <label> <url> <ref-file>
check_416(){
  local label="$1" url="$2" size; size="$(stat -c %s "$3")"
  rget "$url" "$W/416.bin" "$(( size + 10 ))-"
  [ "$ST" = "416" ] || fail_g "${label}: Range past the end answered ${ST}, expected 416"
  [ "$(hdr content-range)" = "bytes */${size}" ] || fail_g "${label}: 416 Content-Range '$(hdr content-range)', expected 'bytes */${size}'"
}
# check_whole <label> <url> <ref-file>
check_whole(){
  rget "$2" "$W/whole.bin"
  [ "$ST" = "200" ] || fail_g "$1: whole GET answered ${ST}, expected 200"
  [ "$(sha_of "$W/whole.bin")" = "$(sha_of "$3")" ] || fail_g "$1: whole GET body ($(stat -c %s "$W/whole.bin") bytes) is not the file"
}

# =============================================================================
begin_suite "range-serves-1120"

begin_test "setup: admin login, upstream files, hosted and Remote repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
HF_H="rng-hfh-${SUF}"     # huggingface hosted
HF_R="rng-hfr-${SUF}"     # huggingface Remote on ${UP}/hf/
GEN_R="rng-genr-${SUF}"   # generic Remote on ${UP}/gen/
APK_H="rng-apkh-${SUF}"   # alpine hosted
APK_R="rng-apkr-${SUF}"   # alpine Remote on ${UP}/apk/
MVN_H="rng-mvnh-${SUF}"   # maven hosted (public, for the anonymous #5139 client)

mk(){ # <key> <format> <type> [upstream] [public]
  local body
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" --arg p "${5:-false}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:($p=="true")}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty'
}

# Random (incompressible) payloads, 300 KiB: a window that ends well before
# EOF is what hyper cut short in #5509.
head -c 307200 /dev/urandom > "$W/hf.bin"
head -c 307200 /dev/urandom > "$W/hfr.bin"
head -c 307200 /dev/urandom > "$W/gen-warm.bin"
head -c 307200 /dev/urandom > "$W/gen-cold.bin"
head -c 1000 /dev/urandom > "$W/small.jar"
head -c 300000 /dev/urandom > "$W/big.jar"
head -c 20000 /dev/urandom > "$W/lib.jar"

# A real apk v2 shape: a gzipped tar with .PKGINFO and a payload. Random
# payload bytes keep the archive ~300 KiB after gzip.
build_apk(){ # <name> <version> <out>
  local d="$W/apk-$1"; mkdir -p "$d/usr/share/$1"
  head -c 300000 /dev/urandom > "$d/usr/share/$1/blob"
  cat > "$d/.PKGINFO" <<P
pkgname = $1
pkgver = $2
pkgdesc = DTF range fixture
url = https://example.invalid/$1
builddate = 1700000000
packager = DTF <dtf@example.invalid>
size = 300000
arch = x86_64
origin = $1
license = MIT
P
  (cd "$d" && tar -czf "$3" .PKGINFO usr)
}
APKN_H="dtfrngh${SUF}"; APKN_R="dtfrngr${SUF}"
build_apk "$APKN_H" 1.0-r0 "$W/hosted.apk"
build_apk "$APKN_R" 1.0-r0 "$W/remote.apk"
APK_DIR="v3.20/main/x86_64"

MODEL="dtf/rng-${SUF}"
SETUP_ERR=""
[ -n "$(mock_put "/hf/${MODEL}/resolve/main/weights.bin" "$W/hfr.bin")" ] || SETUP_ERR="${SETUP_ERR} mock:hf"
[ -n "$(mock_put "/gen/r/warm-${SUF}.bin" "$W/gen-warm.bin")" ] || SETUP_ERR="${SETUP_ERR} mock:gen-warm"
[ -n "$(mock_put "/gen/r/cold-${SUF}.bin" "$W/gen-cold.bin")" ] || SETUP_ERR="${SETUP_ERR} mock:gen-cold"
[ -n "$(mock_put "/apk/${APK_DIR}/${APKN_R}-1.0-r0.apk" "$W/remote.apk")" ] || SETUP_ERR="${SETUP_ERR} mock:apk"

[ "$(mk "$HF_H" huggingface local)" = "$HF_H" ] || SETUP_ERR="${SETUP_ERR} ${HF_H}"
[ "$(mk "$HF_R" huggingface remote "${UP}/hf")" = "$HF_R" ] || SETUP_ERR="${SETUP_ERR} ${HF_R}"
[ "$(mk "$GEN_R" generic remote "${UP}/gen/")" = "$GEN_R" ] || SETUP_ERR="${SETUP_ERR} ${GEN_R}"
[ "$(mk "$APK_H" alpine local)" = "$APK_H" ] || SETUP_ERR="${SETUP_ERR} ${APK_H}"
[ "$(mk "$APK_R" alpine remote "${UP}/apk")" = "$APK_R" ] || SETUP_ERR="${SETUP_ERR} ${APK_R}"
[ "$(mk "$MVN_H" maven local "" true)" = "$MVN_H" ] || SETUP_ERR="${SETUP_ERR} ${MVN_H}"

up_code(){ # <url> <file> [extra header]
  curl -s -o "$W/up.out" -w '%{http_code}' --max-time 60 -X "${4:-PUT}" \
    -H "Authorization: Bearer $TOK" ${3:+-H "$3"} --data-binary @"$2" "$1" || true
}
c="$(up_code "$BASE/huggingface/${HF_H}/api/models/${MODEL}/upload/main" "$W/hf.bin" "X-Filename: weights.bin" POST)"
case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} hf-upload:${c}:$(head -c 200 "$W/up.out")";; esac
c="$(up_code "$BASE/alpine/${APK_H}/${APK_DIR}/${APKN_H}-1.0-r0.apk" "$W/hosted.apk")"
case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} apk-upload:${c}:$(head -c 200 "$W/up.out")";; esac
MVN_DIR="com/dtf/rng${SUF}"
for f in small big lib; do
  c="$(up_code "$BASE/maven/${MVN_H}/${MVN_DIR}/${f}/1.0/${f}-1.0.jar" "$W/${f}.jar")"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} maven-deploy-${f}:${c}";; esac
done
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi

U_HF_H="$BASE/huggingface/${HF_H}/${MODEL}/resolve/main/weights.bin"
U_HF_R="$BASE/huggingface/${HF_R}/${MODEL}/resolve/main/weights.bin"
U_GEN_W="$BASE/api/v1/repositories/${GEN_R}/download/r/warm-${SUF}.bin"
U_GEN_C="$BASE/api/v1/repositories/${GEN_R}/download/r/cold-${SUF}.bin"
U_APK_H="$BASE/alpine/${APK_H}/${APK_DIR}/${APKN_H}-1.0-r0.apk"
U_APK_R="$BASE/alpine/${APK_R}/${APK_DIR}/${APKN_R}-1.0-r0.apk"
U_MVN="$BASE/maven/${MVN_H}/${MVN_DIR}/lib/1.0/lib-1.0.jar"
pass

# =============================================================================
begin_test "CONTROL: whole GETs on the HF, generic, alpine and Maven routes serve the exact bytes"
reset_case
check_whole "hf hosted" "$U_HF_H" "$W/hf.bin"
check_whole "hf remote (fills the cache)" "$U_HF_R" "$W/hfr.bin"
check_whole "generic remote (fills the cache)" "$U_GEN_W" "$W/gen-warm.bin"
check_whole "alpine hosted" "$U_APK_H" "$W/hosted.apk"
check_whole "maven hosted" "$U_MVN" "$W/lib.jar"
finish_case "a whole GET did not serve the stored or upstream bytes"

# =============================================================================
begin_test "FIX #5145: HF resolve of a hosted file honours Range (206 + window, 416 past the end, Accept-Ranges)"
reset_case
check_window "hf hosted" "$U_HF_H" "$W/hf.bin" 1000 1999
check_416 "hf hosted" "$U_HF_H" "$W/hf.bin"
rget "$U_HF_H" "$W/x.bin"
[ "$(hdr accept-ranges)" = "bytes" ] || fail_g "hf hosted: whole GET carries Accept-Ranges '$(hdr accept-ranges)', expected 'bytes'"
finish_case "the HF resolve route ignored Range on a hosted file"

begin_test "FIX #5145: an interrupted download of a cached HF Remote file resumes with curl -C - to the exact file"
reset_case
# The cache was filled by the CONTROL case. Take the first 100000 bytes, as an
# interrupted client would hold in its .incomplete file, then resume.
rget "$U_HF_R" "$W/part.bin" "0-99999"
[ "$ST" = "206" ] || fail_g "hf remote: the first window answered ${ST}, expected 206"
head -c 100000 "$W/hfr.bin" > "$W/resume.bin"
rc=0
curl -s --max-time 60 -C - -o "$W/resume.bin" -H "Authorization: Bearer $TOK" "$U_HF_R" 2>"$W/curl.err" || rc=$?
[ "$rc" = "0" ] || fail_g "hf remote: curl -C - exited ${rc} ($(head -c 200 "$W/curl.err"); exit 33 = the server does not support byte ranges)"
[ "$(sha_of "$W/resume.bin")" = "$(sha_of "$W/hfr.bin")" ] || fail_g "hf remote: the resumed file ($(stat -c %s "$W/resume.bin") bytes) is not the upstream file"
check_window "hf remote" "$U_HF_R" "$W/hfr.bin" 200000 200999
finish_case "a cached HF Remote file could not be resumed"

# =============================================================================
begin_test "FIX #5478: a hosted .apk honours Range (206 + window, 416 past the end, Accept-Ranges)"
reset_case
check_window "apk hosted" "$U_APK_H" "$W/hosted.apk" 0 1023
check_window "apk hosted" "$U_APK_H" "$W/hosted.apk" 1024 4095
check_416 "apk hosted" "$U_APK_H" "$W/hosted.apk"
rget "$U_APK_H" "$W/x.bin"
[ "$(hdr accept-ranges)" = "bytes" ] || fail_g "apk hosted: whole GET carries Accept-Ranges '$(hdr accept-ranges)', expected 'bytes'"
finish_case "the alpine download route ignored Range on a hosted .apk"

# =============================================================================
begin_test "FIX #5502: the generic route honours Range on a Remote's cache hit and on a cold upstream fetch"
reset_case
check_window "generic remote (cache hit)" "$U_GEN_W" "$W/gen-warm.bin" 0 9
check_416 "generic remote (cache hit)" "$U_GEN_W" "$W/gen-warm.bin"
check_window "generic remote (cold fetch)" "$U_GEN_C" "$W/gen-cold.bin" 100 199
finish_case "the generic route ignored Range on a proxied serve"

# =============================================================================
begin_test "FIX #5509: a ranged GET on a cold alpine Remote answers 206 and still fills the cache"
reset_case
check_window "apk remote (cold)" "$U_APK_R" "$W/remote.apk" 0 99
n1="$(mock_gets "/apk/${APK_DIR}/${APKN_R}-1.0-r0.apk")"
# The fixed image finishes the fill on a detached task; give it time.
filled=0
for _i in $(seq 1 20); do
  sleep 1
  rget "$U_APK_R" "$W/x.bin" "100-199"
  n2="$(mock_gets "/apk/${APK_DIR}/${APKN_R}-1.0-r0.apk")"
  [ "$n2" = "$n1" ] && { filled=1; break; }
  n1="$n2"
done
check_whole "apk remote (after the ranged GET)" "$U_APK_R" "$W/remote.apk"
n3="$(mock_gets "/apk/${APK_DIR}/${APKN_R}-1.0-r0.apk")"
note "upstream GETs: after the cold window ${n1}, after the whole GET ${n3}"
[ "$filled" = "1" ] && [ "$n3" = "1" ] || fail_g "apk remote: the upstream saw ${n3} GETs for the file, expected 1 (the cold ranged GET did not fill the cache)"
finish_case "a cold ranged alpine GET did not fill the proxy cache"

# =============================================================================
begin_test "FIX #5668: the native Maven route honours Range (206 + window, 416 past the end, Accept-Ranges)"
reset_case
check_window "maven hosted" "$U_MVN" "$W/lib.jar" 2 5
check_window "maven hosted" "$U_MVN" "$W/lib.jar" 10000 19999
check_416 "maven hosted" "$U_MVN" "$W/lib.jar"
rget "$U_MVN" "$W/x.bin"
[ "$(hdr accept-ranges)" = "bytes" ] || fail_g "maven hosted: whole GET carries Accept-Ranges '$(hdr accept-ranges)', expected 'bytes'"
finish_case "the native Maven route ignored Range"

# =============================================================================
# #5139: time GETs on ONE keep-alive connection from a container on the
# backend's network (the mock's python), as a Maven client fetching .sha1/.pom
# files does. Prints "<median ms> <p90 ms> <bad-bodies>".
BIP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"ak-dtf${DTF_SLOT}-mockfiles\").IPAddress}}" "$BACKEND_CTR" 2>/dev/null || true)"
latency(){ # <path> <expected size>
  docker exec "$MOCK_CTR" python3 -c '
import http.client, statistics, sys, time
host, path, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
c = http.client.HTTPConnection(host, 8080, timeout=10)
ts, bad = [], 0
for i in range(45):
    t = time.perf_counter()
    c.request("GET", path)
    r = c.getresponse()
    b = r.read()
    dt = (time.perf_counter() - t) * 1000.0
    if r.status != 200 or len(b) != size:
        bad += 1
    if i >= 5:
        ts.append(dt)
ts.sort()
print("%.1f %.1f %d" % (statistics.median(ts), ts[int(len(ts) * 0.9)], bad))
' "$BIP" "$1" "$2" 2>&1 || true
}
LAT_BIG=""; LAT_SMALL=""

begin_test "CONTROL #5139: a 300 kB Maven file on the same kind of keep-alive connection is served in under 20 ms (median)"
reset_case
if [ -z "$BIP" ]; then infra_fail "no backend address on ak-dtf${DTF_SLOT}-mockfiles"; else
  LAT_BIG="$(latency "/maven/${MVN_H}/${MVN_DIR}/big/1.0/big-1.0.jar" 300000)"
  read -r med p90 bad <<<"$LAT_BIG"
  note "300 kB: median ${med} ms, p90 ${p90} ms, bad responses ${bad}"
  [ "${bad:-x}" = "0" ] || fail_g "300 kB: ${bad:-?} of 45 GETs were not 200 with the full body (${LAT_BIG})"
  awk -v m="${med:-999}" 'BEGIN{exit !(m < 20)}' || fail_g "300 kB: median ${med:-?} ms, expected < 20 ms (the host is too slow to judge #5139)"
  finish_case "the 300 kB control was not served promptly"
fi

begin_test "FIX #5139: a 1000-byte Maven file on one keep-alive connection is served in under 20 ms (median; pre-fix ~44 ms)"
reset_case
if [ -z "$BIP" ]; then infra_fail "no backend address on ak-dtf${DTF_SLOT}-mockfiles"; else
  LAT_SMALL="$(latency "/maven/${MVN_H}/${MVN_DIR}/small/1.0/small-1.0.jar" 1000)"
  read -r med p90 bad <<<"$LAT_SMALL"
  note "1000 B: median ${med} ms, p90 ${p90} ms, bad responses ${bad}"
  [ "${bad:-x}" = "0" ] || fail_g "1000 B: ${bad:-?} of 45 GETs were not 200 with the full body (${LAT_SMALL})"
  awk -v m="${med:-999}" 'BEGIN{exit !(m < 20)}' || fail_g "1000 B: median ${med:-?} ms, expected < 20 ms (Nagle + delayed ACK: TCP_NODELAY not set)"
  finish_case "small responses were held by Nagle + delayed ACK"
fi

end_suite
