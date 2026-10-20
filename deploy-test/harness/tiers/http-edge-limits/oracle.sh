#!/usr/bin/env bash
# =============================================================================
# tiers/http-edge-limits/oracle.sh
#   #4665 a connection that trickles its request head, or sends nothing, is
#         closed after HTTP_HEADER_READ_TIMEOUT_SECS and counted in
#         ak_http_header_read_timeouts_total
#   #4672 POST /v2/<name>/blobs/uploads/ (session create with a body, and the
#         monolithic ?digest= form) with a declared Content-Length over
#         MAX_UPLOAD_SIZE is answered 413 at once, before the body is read
#   #4664 the login limiter's 429 carries the login bucket's
#         X-RateLimit-Limit / -Remaining, not the general API bucket's 10000
#   #4671 POST /api/v1/plugins/install/local answers 501 NOT_IMPLEMENTED
#         whatever the path, without touching the filesystem (was 500 / 400)
#   #4673 a .vsix whose entries carry traversal or absolute names is refused
#         400 VALIDATION_ERROR at publish and nothing is stored, on both the
#         manifest path and the legacy x-* header path
# See the manifest for the topology and the limits.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH, DTF_DIR.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
PORT="${BASE##*:}"
DBC="$DB_CONTAINER"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="${HERE}/fixtures/edge_probe.py"
HEADER_TIMEOUT=5          # HTTP_HEADER_READ_TIMEOUT_SECS in profiles/limits.http-edge.yml
MAX_UPLOAD=1048576        # MAX_UPLOAD_SIZE in the same profile
OVER=$((MAX_UPLOAD * 2))  # declared Content-Length for the #4672 probes

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
probe(){ python3 -I "$PROBE" "$@" 2>&1 || true; }
hdr(){ grep -i "^$1:" "$2" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

metric(){ # <name>: the counter's value, or "absent"
  local v
  v="$(curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/metrics" \
    | awk -v m="$1" '$1==m {print $2; exit}')"
  echo "${v:-absent}"
}
art_count(){ psql_q "SELECT COUNT(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1' AND NOT a.is_deleted"; }

# =============================================================================
begin_suite "http-edge-limits"

begin_test "setup: admin login, local docker and vscode repositories"
if ! command -v python3 >/dev/null 2>&1; then infra_fail "python3 is required for the raw-socket probes"; end_suite; fi
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
BASIC="Basic $(printf 'admin:%s' "$ADMIN_PASS" | base64 | tr -d '\n')"
SUF="${RUN_ID##*-}-$$"
R_OCI="hel-oci-${SUF}"; R_VSX="hel-vsx-${SUF}"
mk(){ # <key> <format>
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')" \
    | jqr '.key // empty'
}
SETUP_ERR=""
[ "$(mk "$R_OCI" docker)" = "$R_OCI" ] || SETUP_ERR="${SETUP_ERR} docker"
[ "$(mk "$R_VSX" vscode)" = "$R_VSX" ] || SETUP_ERR="${SETUP_ERR} vscode"
if [ -n "$SETUP_ERR" ]; then infra_fail "could not create repositories:${SETUP_ERR}"; end_suite; fi
echo "-- repos: ${R_OCI}, ${R_VSX}"
pass

# =============================================================================
# #4665 header-read timeout
# =============================================================================
begin_test "CONTROL: a complete request head trickled over 3 s (inside the ${HEADER_TIMEOUT} s window) is served 200"
reset_case
read -r st secs <<<"$(probe trickle "$PORT" /health 3)"
note "trickled GET /health: status ${st} after ${secs}s"
[ "$st" = "200" ] || fail_g "a slow but complete request head was not served (status ${st})"
finish_case "a request head delivered inside the header-read window must still be served"

begin_test "#4665: a partial request head and a silent connection are both closed within ${HEADER_TIMEOUT}+3 s and counted in ak_http_header_read_timeouts_total"
reset_case
m_before="$(metric ak_http_header_read_timeouts_total)"
probe head "$PORT" 'GET /health HTTP/1.1\r\nHost: dtf\r\n' 20 > "$W/partial.out" &
probe head "$PORT" '' 20 > "$W/silent.out" &
wait
read -r p_state p_secs p_bytes < "$W/partial.out"
read -r s_state s_secs s_bytes < "$W/silent.out"
note "partial head: ${p_state} after ${p_secs}s (${p_bytes} bytes back); silent: ${s_state} after ${s_secs}s (${s_bytes} bytes back)"
lim=$((HEADER_TIMEOUT + 3))
for pair in "partial:${p_state}:${p_secs}" "silent:${s_state}:${s_secs}"; do
  IFS=: read -r what state secs <<<"$pair"
  if [ "$state" != "closed" ]; then
    fail_g "${what} connection still open after ${secs}s (the server never enforces a header-read deadline)"
  elif ! awk -v s="$secs" -v l="$lim" 'BEGIN{exit !(s <= l)}'; then
    fail_g "${what} connection closed only after ${secs}s, expected within ${lim}s"
  fi
done
m_after="$(metric ak_http_header_read_timeouts_total)"
note "ak_http_header_read_timeouts_total: ${m_before} -> ${m_after}"
if [ "$m_after" = "absent" ]; then
  fail_g "ak_http_header_read_timeouts_total is not exported"
else
  [ "$m_before" = "absent" ] && m_before=0
  delta="$(awk -v a="$m_after" -v b="$m_before" 'BEGIN{printf "%d", a-b}')"
  [ "$delta" -ge 2 ] || fail_g "counter delta ${delta}, expected >= 2 (one per closed connection)"
fi
finish_case "slow-loris connections must be closed after HTTP_HEADER_READ_TIMEOUT_SECS and counted"

# =============================================================================
# #4672 OCI upload start with an over-limit declared Content-Length
# =============================================================================
begin_test "CONTROL: a within-limit monolithic OCI upload (?digest=) is 201 and the blob is served"
reset_case
printf 'dtf-http-edge-%s' "$SUF" > "$W/small.blob"
SMALL_D="sha256:$(sha256sum "$W/small.blob" | awk '{print $1}')"
code="$(curl -s -o "$W/small.resp" -w '%{http_code}' -X POST -H "Authorization: $BASIC" \
  -H 'Content-Type: application/octet-stream' --data-binary @"$W/small.blob" \
  "$BASE/v2/${R_OCI}/edge/blobs/uploads/?digest=${SMALL_D}")"
note "monolithic POST: HTTP ${code}"
[ "$code" = "201" ] || fail_g "small monolithic upload answered ${code}: $(head -c 300 "$W/small.resp")"
curl -s -o "$W/small.get" -H "Authorization: $BASIC" "$BASE/v2/${R_OCI}/edge/blobs/${SMALL_D}" || true
cmp -s "$W/small.blob" "$W/small.get" || fail_g "GET of the uploaded blob did not return its bytes"
finish_case "a within-limit OCI blob upload must still succeed"

begin_test "CONTROL: PATCH with an over-limit Content-Length is refused 413 at once (the pre-existing PATCH check)"
reset_case
LOC="$(curl -s -D- -o /dev/null -X POST -H "Authorization: $BASIC" "$BASE/v2/${R_OCI}/edge/blobs/uploads/" \
  | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')"
if [ -z "$LOC" ]; then
  fail_g "an empty POST did not open an upload session"
else
  read -r st secs sent body <<<"$(probe send PATCH "$PORT" "$LOC" "$BASIC" "$OVER" 4096 8)"
  note "PATCH ${LOC}: status ${st} after ${secs}s, ${sent} body bytes sent; ${body}"
  [ "$st" = "413" ] || fail_g "PATCH declared ${OVER} answered ${st}"
fi
finish_case "PATCH must keep refusing an over-limit declared length"

begin_test "#4672: POST blobs/uploads/ (?digest= and session-create) declaring ${OVER} bytes is 413 BLOB_UPLOAD_INVALID within 2 s, before the body is sent"
reset_case
BIG_D="sha256:$(head -c "$OVER" /dev/zero | sha256sum | awk '{print $1}')"
sessions_before="$(psql_q "SELECT COUNT(*) FROM oci_upload_sessions")"
for form in "monolithic:/v2/${R_OCI}/edge/blobs/uploads/?digest=${BIG_D}" "session:/v2/${R_OCI}/edge/blobs/uploads/"; do
  what="${form%%:*}"; path="${form#*:}"
  read -r st secs sent body <<<"$(probe send POST "$PORT" "$path" "$BASIC" "$OVER" 4096 8)"
  note "${what} POST: status ${st} after ${secs}s with ${sent} of ${OVER} body bytes sent; ${body}"
  if [ "$st" != "413" ]; then
    fail_g "${what} start answered '${st}' within 8 s, expected an immediate 413"
  else
    awk -v s="$secs" 'BEGIN{exit !(s <= 2)}' || fail_g "${what} 413 took ${secs}s, expected within 2 s"
    case "$body" in *BLOB_UPLOAD_INVALID*) ;; *) fail_g "${what} 413 body lacks BLOB_UPLOAD_INVALID";; esac
  fi
done
blob_n="$(psql_q "SELECT COUNT(*) FROM oci_blobs WHERE digest = '${BIG_D}'")"
note "oci_blobs rows for the oversized digest: ${blob_n:-?}; upload sessions ${sessions_before:-?} -> $(psql_q "SELECT COUNT(*) FROM oci_upload_sessions")"
[ "${blob_n:-0}" = "0" ] || fail_g "the oversized digest was stored"
finish_case "an over-limit declared Content-Length on upload start must be refused before the body is read"

# =============================================================================
# #4664 login 429 headers
# =============================================================================
begin_test "CONTROL: the general API bucket's X-RateLimit-* headers are on an ordinary authenticated response"
reset_case
curl -s -o /dev/null -D "$W/general.h" -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories?per_page=1" || true
g_lim="$(hdr x-ratelimit-limit "$W/general.h")"
note "GET /api/v1/repositories: X-RateLimit-Limit=${g_lim:-<none>} X-RateLimit-Remaining=$(hdr x-ratelimit-remaining "$W/general.h")"
[ -n "$g_lim" ] || fail_g "no X-RateLimit-Limit on an ordinary response (is RATE_LIMIT_ENABLED on?)"
finish_case "the API limiter must be on and reporting for this tier to mean anything"

LIM_USER="hel-limit-${SUF}"
begin_test "CONTROL: 10 failed logins for one account are 401 and the 11th is 429 with Retry-After"
reset_case
codes=""
for i in $(seq 1 11); do
  c="$(curl -s -o /dev/null -D "$W/login.$i.h" -w '%{http_code}' --max-time 15 -X POST "$BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' -d "{\"username\":\"${LIM_USER}\",\"password\":\"wrong-${i}\"}")" || c=000
  codes="${codes} ${c}"
done
note "codes:${codes}"
[ "$codes" = " 401 401 401 401 401 401 401 401 401 401 429" ] || fail_g "expected ten 401s then a 429"
ra="$(hdr retry-after "$W/login.11.h")"
note "429 Retry-After=${ra:-<none>}"
[ "${ra:-0}" -gt 0 ] 2>/dev/null || fail_g "the login 429 carries no positive Retry-After"
finish_case "the login limiter must engage after 10 failures"

begin_test "#4664: the login 429 reports the login bucket: X-RateLimit-Limit 10, X-RateLimit-Remaining 0"
reset_case
l_lim="$(hdr x-ratelimit-limit "$W/login.11.h")"; l_rem="$(hdr x-ratelimit-remaining "$W/login.11.h")"
note "429 X-RateLimit-Limit=${l_lim:-<none>} X-RateLimit-Remaining=${l_rem:-<none>} (general bucket reports ${g_lim:-?})"
[ "$l_lim" = "10" ] || fail_g "X-RateLimit-Limit on the login 429 is '${l_lim}', expected 10 (the login bucket)"
[ "$l_rem" = "0" ] || fail_g "X-RateLimit-Remaining on the login 429 is '${l_rem}', expected 0"
finish_case "the login 429's limit headers must describe the bucket that refused it"

# =============================================================================
# #4671 plugin install from a local path
# =============================================================================
begin_test "CONTROL: GET /api/v1/plugins as admin is 200 with a JSON body"
reset_case
code="$(curl -s -o "$W/plugins.json" -w '%{http_code}' -H "Authorization: Bearer $TOK" "$BASE/api/v1/plugins")"
note "GET /api/v1/plugins: HTTP ${code}"
if [ "$code" != "200" ] || ! jq -e . "$W/plugins.json" >/dev/null 2>&1; then fail_g "plugin listing answered ${code}"; fi
finish_case "the plugin admin surface must be mounted"

begin_test "#4671: POST /api/v1/plugins/install/local is 501 NOT_IMPLEMENTED for an existing and a missing path"
reset_case
for p in "/" "/definitely/not/here-${SUF}"; do
  code="$(curl -s -o "$W/local.json" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$(jq -n --arg p "$p" '{path:$p}')" "$BASE/api/v1/plugins/install/local")"
  ec="$(jqr '.code // empty' < "$W/local.json")"
  note "path ${p}: HTTP ${code} code=${ec} message=$(jqr '.message // empty' < "$W/local.json")"
  [ "$code" = "501" ] || fail_g "path ${p} answered ${code}, expected 501"
  [ "$ec" = "NOT_IMPLEMENTED" ] || fail_g "path ${p} error code '${ec}', expected NOT_IMPLEMENTED"
done
finish_case "the unimplemented local install must be a stable 501, not a 500 or a filesystem probe"

# =============================================================================
# #4673 VSIX entry-name validation
# =============================================================================
PUB="dtfedge"; EXT="edge${SUF//-/}"
vsx_publish(){ # <file> [curl args...] -> http code, body in $W/pub.json
  local f="$1"; shift
  curl -s -o "$W/pub.json" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" "$@" \
    --data-binary @"$f" "$BASE/vscode/${R_VSX}/api/extensions" || echo 000
}
vsx_download(){ # <ext> <version> <out> -> http code
  curl -s -o "$3" -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "$BASE/vscode/${R_VSX}/extensions/${PUB}/$1/$2/download" || echo 000
}

begin_test "CONTROL: a benign VSIX (an entry with '..' inside a name, not a segment) publishes and downloads byte-identical"
reset_case
probe vsix "$W/ok.vsix" "$PUB" "$EXT" 1.0.0 'extension/dist/a..b.js' >/dev/null
code="$(vsx_publish "$W/ok.vsix")"
note "publish benign: HTTP ${code} $(head -c 200 "$W/pub.json")"
[ "$code" = "201" ] || [ "$code" = "200" ] || fail_g "benign VSIX publish answered ${code}"
code="$(vsx_download "$EXT" 1.0.0 "$W/ok.get")"
if [ "$code" != "200" ] || ! cmp -s "$W/ok.vsix" "$W/ok.get"; then fail_g "benign VSIX download answered ${code} or bytes differ"; fi
finish_case "a well-formed VSIX must still publish"

begin_test "#4673: VSIX entries '../../etc/passwd', '/tmp/x', '\\\\win\\\\x.dll', 'C:/x.js' and a legacy x-* zip are 400 VALIDATION_ERROR and nothing is stored"
reset_case
before="$(art_count "$R_VSX")"
v=1
for hostile in '../../etc/passwd' '/tmp/x' '\windows\system32\x.dll' 'C:/x.js'; do
  ver="1.1.${v}"; v=$((v+1))
  probe vsix "$W/h.vsix" "$PUB" "$EXT" "$ver" "$hostile" >/dev/null
  code="$(vsx_publish "$W/h.vsix")"
  note "manifest VSIX with '${hostile}' (v${ver}): HTTP ${code} $(head -c 200 "$W/pub.json")"
  [ "$code" = "400" ] || fail_g "'${hostile}' publish answered ${code}, expected 400"
  [ "$(jqr '.code // empty' < "$W/pub.json")" = "VALIDATION_ERROR" ] || fail_g "'${hostile}' refusal is not VALIDATION_ERROR"
  dl="$(vsx_download "$EXT" "$ver" "$W/h.get")"
  [ "$dl" = "404" ] || fail_g "'${hostile}' archive is downloadable (HTTP ${dl})"
done
probe zip "$W/legacy.zip" '../escape.sh' >/dev/null
L_EXT="legacy${SUF//-/}"
code="$(vsx_publish "$W/legacy.zip" -H "x-publisher: ${PUB}" -H "x-extension-name: ${L_EXT}" -H 'x-extension-version: 2.0.0')"
note "legacy x-* zip with '../escape.sh': HTTP ${code} $(head -c 200 "$W/pub.json")"
[ "$code" = "400" ] || fail_g "legacy-header publish answered ${code}, expected 400"
dl="$(vsx_download "$L_EXT" 2.0.0 "$W/l.get")"
[ "$dl" = "404" ] || fail_g "the legacy archive is downloadable (HTTP ${dl})"
after="$(art_count "$R_VSX")"
note "artifact rows in ${R_VSX}: ${before} -> ${after}"
[ -n "$after" ] && [ "$after" = "$before" ] || fail_g "hostile publishes stored $((after - before)) artifact(s)"
finish_case "a VSIX that would write outside a client's extraction directory must be refused before it is stored"

end_suite
