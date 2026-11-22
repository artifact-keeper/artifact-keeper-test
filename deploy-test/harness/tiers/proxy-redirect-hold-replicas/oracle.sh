#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-redirect-hold-replicas/oracle.sh
#   #6361 a presigned-redirect fast path takes the Package Age Policy hold from
#         the sidecar its freshness probe read, so a sidecar read that comes
#         back empty (an eviction, or a miss this replica memoised before
#         another replica filled the entry) cannot sign a held object.
# See the manifest for the bug and the gates.
#
# #6416 a PyPI virtual's member row whose storage_key is a proxy-cache key is
#       redirected to only through the same single-read gate (fresh, outside
#       its hold), not after an existence check of the object alone.
# #6418 a HEAD of a fresh cached PyPI file is not redirected to a URL signed
#       for GET.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# S3_PORT, TRIVY_PORT (the mock's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${TRIVY_PORT:?}"; : "${S3_PORT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"            # the mock, as the backends reach it
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"      # backend-b listens on its :8081
MINIO_CTR="ak-dtf${DTF_SLOT}-minio"
MC_IMAGE="${PRH_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
MC_CTR="l2-s${DTF_SLOT}-prh-mc"              # transient mc client, removed by name

setup_workdir
W="$WORK_DIR"

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

# sidecar_stored <repo-key> <path>: the entry's __cache_meta__.json is in the
# bucket (its key is proxy-cache/<scope>/<repo-key>/<path>/__cache_meta__.json).
sidecar_stored(){
  docker rm -f "$MC_CTR" >/dev/null 2>&1
  docker run --rm --name "$MC_CTR" --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && mc ls -r local/ak-artifacts/proxy-cache/" \
    2>/dev/null | grep -qF "/$1/$2/__cache_meta__.json"
}
add_exit_handler 'docker rm -f "'"$MC_CTR"'" >/dev/null 2>&1'

mock_put(){ # <path> <file>
  curl -s --max-time 10 -X PUT --data-binary @"$2" "${MOCK}/__file?path=$1" | jqr '.bytes // empty'
}
mock_status(){ curl -s --max-time 5 -X POST "${MOCK}/__status?path=$1&code=$2" | jqr '.code // empty'; }
mock_gets(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get // empty'; }

api(){ # <METHOD> <path> [json] -> HTTP code
  local -a a=(-s --max-time 30 -o "$W/api.out" -w '%{http_code}' -X "$1" -H "$AH")
  [ -n "${3:-}" ] && a+=(-H 'Content-Type: application/json' -d "$3")
  curl "${a[@]}" "$BASE$2" || true
}
mk(){ # <key> <format> <type> [upstream]
  local body
  body="$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  case "$(api POST /api/v1/repositories "$body")" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} create:$1:$(head -c 120 "$W/api.out")";; esac
}
member(){ # <virtual> <member>
  case "$(api POST "/api/v1/repositories/$1/members" "$(jq -nc --arg k "$2" '{member_key:$k,priority:1}')")" in
    2??) ;; *) SETUP_ERR="${SETUP_ERR} member:$1<-$2";; esac
}
# get_a <path> <out>: GET on backend (presigned), no redirect following.
get_a(){
  ST="$(curl -s --max-time 60 -D "$2.h" -o "$2" -w '%{http_code}' -H "$AH" "${BASE}$1" || true)"
  LOC="$(grep -i '^location:' "$2.h" 2>/dev/null | head -n1 | cut -d' ' -f2- | tr -d '\r')"
  WARN="$(grep -i '^warning:' "$2.h" 2>/dev/null | head -n1 | cut -d' ' -f2- | tr -d '\r')"
}
# get_b <path>: GET on backend-b, through backend's network namespace.
get_b(){
  docker exec "$BACKEND_CTR" curl -s --max-time 60 -o /dev/null -w '%{http_code}' \
    -H "$AH" "http://127.0.0.1:8081$1" 2>/dev/null || echo 000
}

# =============================================================================
begin_suite "proxy-redirect-hold-replicas"

begin_test "setup: admin login, both replicas up, CRAN Remotes (one held) and virtuals over them"
AH="Authorization: Bearer $(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // .token // empty')"
if [ "$AH" = "Authorization: Bearer " ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK}"; end_suite
fi
# The mc client is used inside the 30 s window; pull it now so a cold pull
# cannot eat that window.
if ! docker image inspect "$MC_IMAGE" >/dev/null 2>&1 && ! docker pull -q "$MC_IMAGE" >/dev/null 2>&1; then
  infra_fail "could not pull ${MC_IMAGE}"; end_suite
fi
b="$(docker exec "$BACKEND_CTR" curl -s --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/health 2>/dev/null || echo 000)"
if [ "$b" != "200" ]; then infra_fail "backend-b is not healthy on :8081 (${b})"; end_suite; fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
P="prh${SUF}"
SETUP_ERR=""
R_HOLD="prh-held-${SUF}"; V_HOLD="prh-vheld-${SUF}"
R_FREE="prh-free-${SUF}"; V_FREE="prh-vfree-${SUF}"
mk "$R_HOLD" cran remote "${UP}/${P}/held"
mk "$R_FREE" cran remote "${UP}/${P}/free"
mk "$V_HOLD" cran virtual; member "$V_HOLD" "$R_HOLD"
mk "$V_FREE" cran virtual; member "$V_FREE" "$R_FREE"
c="$(api PATCH "/api/v1/repositories/${R_HOLD}" '{"quarantine_enabled":true,"quarantine_duration_minutes":60}')"
case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} hold:${c}:$(head -c 120 "$W/api.out")";; esac
head -c 300000 /dev/urandom > "$W/pkg.tar.gz"
PKG_SHA="$(sha_of "$W/pkg.tar.gz")"
FREE_F="dtffree_1.0.tar.gz"; HELD_F="dtfheld_1.0.tar.gz"
for f in "free/src/contrib/${FREE_F}" "held/src/contrib/${HELD_F}"; do
  [ -n "$(mock_put "/${P}/${f}" "$W/pkg.tar.gz")" ] || SETUP_ERR="${SETUP_ERR} mock:${f}"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
pass

# -----------------------------------------------------------------------------
begin_test "CONTROL: a CRAN virtual over a Remote with no hold redirects a fresh cache hit to a presigned URL that serves the exact bytes"
reset_case
get_a "/cran/${V_FREE}/src/contrib/${FREE_F}" "$W/free1"; s1="$ST"
# The cold GET's cache write is published after its response; ask again until
# the entry is fresh (a GET before that streams, 200).
for _ in $(seq 1 20); do
  get_a "/cran/${V_FREE}/src/contrib/${FREE_F}" "$W/free2"; s2="$ST"
  [ "$s2" = "200" ] || break
  sleep 0.5
done
note "cold GET -> ${s1}; warm GET -> ${s2} Location ${LOC:0:90}"
[ "$s1" = "200" ] && [ "$(sha_of "$W/free1")" = "$PKG_SHA" ] || fail_g "the cold GET answered ${s1} or other bytes"
case "$s2" in
  301|302|303|307|308)
    case "$LOC" in "http://127.0.0.1:${S3_PORT}/"*) ;; *) fail_g "the redirect does not point at the public S3 endpoint: ${LOC}";; esac
    c="$(curl -s --max-time 60 -o "$W/free3" -w '%{http_code}' "$LOC" || true)"
    [ "$c" = "200" ] && [ "$(sha_of "$W/free3")" = "$PKG_SHA" ] || fail_g "the presigned URL answered ${c} or other bytes" ;;
  *) fail_g "the warm GET answered ${s2}, expected a redirect (is the presigned fast path on?)" ;;
esac
finish_case "the member redirect fast path is not active here"

# -----------------------------------------------------------------------------
# The window: backend memoises "no sidecar" for the held path (its upstream
# answers 503, so nothing is cached and the walk answers 503), backend-b then
# fills the entry inside its hold, and backend asks again within the 30 s the
# memoised miss lives.
begin_test "CONTROL: backend's first GET while the upstream answers 503 is 503; backend-b's cold GET once it answers is 409 (held, and cached)"
reset_case
[ "$(mock_status "/${P}/held/src/contrib/${HELD_F}" 503)" = "503" ] || fail_g "could not force 503 on the mock"
T0=$(date +%s)
get_a "/cran/${V_HOLD}/src/contrib/${HELD_F}" "$W/held0"; s0="$ST"
mock_status "/${P}/held/src/contrib/${HELD_F}" 0 >/dev/null
sb="$(get_b "/cran/${R_HOLD}/src/contrib/${HELD_F}")"
# backend-b publishes the entry after its 409; wait until the sidecar is in
# the bucket, so backend's freshness probe finds it.
stored=""
for _ in $(seq 1 20); do sidecar_stored "$R_HOLD" "src/contrib/${HELD_F}" && { stored=1; break; }; sleep 0.5; done
note "backend (upstream 503) -> ${s0}; backend-b cold GET -> ${sb}; upstream GETs $(mock_gets "/${P}/held/src/contrib/${HELD_F}"); sidecar stored after $(( $(date +%s) - T0 ))s: ${stored:-no}"
[ "$s0" = "503" ] || fail_g "backend answered ${s0} while the upstream answered 503, expected 503"
[ "$sb" = "409" ] || fail_g "backend-b's cold GET of the held path answered ${sb}, expected 409"
[ -n "$stored" ] || fail_g "backend-b's entry never reached the bucket"
finish_case "the window could not be set up"

begin_test "FIX #6361: within the memoised miss's 30 s, backend answers the held path through the virtual 409, not a redirect to the held object"
reset_case
get_a "/cran/${V_HOLD}/src/contrib/${HELD_F}" "$W/held1"
ELAPSED=$(( $(date +%s) - T0 ))
note "backend GET ${ELAPSED}s after its miss -> ${ST}${LOC:+ Location ${LOC:0:90}}"
if [ "$ELAPSED" -ge 30 ]; then
  infra_fail "the case started ${ELAPSED}s after the memoised miss; it has to run inside 30 s"
elif [ "$s0" != "503" ] || [ "$sb" != "409" ] || [ -z "$stored" ]; then
  infra_fail "the window was not set up (backend ${s0}, backend-b ${sb}, sidecar stored '${stored}')"
else
  [ -z "$LOC" ] || fail_g "backend redirected to the held object (${ST} ${LOC:0:120})"
  [ "$ST" = "409" ] || fail_g "backend answered ${ST}, expected the hold's 409: $(head -c 200 "$W/held1")"
  finish_case "a held object was signed because the second sidecar read came back empty"
fi

begin_test "CONTROL: once the memoised miss has expired, backend answers the held path 409"
reset_case
w=$(( 31 - ( $(date +%s) - T0 ) )); [ "$w" -gt 0 ] && sleep "$w"
get_a "/cran/${V_HOLD}/src/contrib/${HELD_F}" "$W/held2"
note "backend GET $(( $(date +%s) - T0 ))s after its miss -> ${ST}${LOC:+ Location ${LOC:0:90}}"
[ "$ST" = "409" ] || fail_g "backend answered ${ST}, expected 409"
finish_case "the hold is not enforced on the virtual even without the stale read"

# =============================================================================
# #6416 / #6418: PyPI. The entries are written straight into the bucket (body
# and sidecar, as the cache writer lays them out) and, for #6416, recorded as
# `artifacts` rows of the Remote the way releases before 1.2.0 recorded a
# cached file. The mock upstream has none of these files, so a request that
# reaches the upstream answers 404.
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
# mc_put <key> <file>: write one object into the bucket.
mc_put(){
  docker rm -f "$MC_CTR" >/dev/null 2>&1
  docker run --rm -i --name "$MC_CTR" --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && mc pipe local/ak-artifacts/$1 >/dev/null" \
    < "$2" 2>/dev/null
}
# sidecar <file> <body> <hold-minutes|0> [expires]: a sidecar for <body>,
# fresh for an hour unless <expires> (a `date -d` offset) says otherwise.
sidecar(){
  local now exp hold=null
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; exp="$(date -u -d "${4:-+1 hour}" +%Y-%m-%dT%H:%M:%SZ)"
  [ "$3" -gt 0 ] && hold="\"$(date -u -d "+$3 minutes" +%Y-%m-%dT%H:%M:%SZ)\""
  jq -nc --arg now "$now" --arg exp "$exp" --argjson hold "$hold" \
    --argjson size "$(stat -c %s "$2")" --arg sha "$(sha_of "$2")" \
    '{cached_at:$now, upstream_etag:null, storage_etag:null, last_modified:null,
      negative_cached_until:null, quarantine_until:$hold, expires_at:$exp,
      content_type:"application/x-tar", content_encoding:null,
      upstream_commit_sha:null, size_bytes:$size, checksum_sha256:$sha}' > "$1"
}
# get_h <path> <out>: HEAD on backend, no redirect following.
get_h(){
  ST="$(curl -s --max-time 60 -I -D "$2.h" -o /dev/null -w '%{http_code}' -H "$AH" "${BASE}$1" || true)"
  LOC="$(grep -i '^location:' "$2.h" 2>/dev/null | head -n1 | cut -d' ' -f2- | tr -d '\r')"
  CLEN="$(grep -i '^content-length:' "$2.h" 2>/dev/null | head -n1 | cut -d' ' -f2- | tr -d '\r')"
}
# get_bb <path> <out> [HEAD]: GET (or HEAD) on backend-b (presigned downloads
# off, the default), body to <out>, status in ST.
get_bb(){
  local m=(); [ "${3:-}" = "HEAD" ] && m=(-I)
  # The image has no shell: the body goes to curl's stderr, the status to stdout.
  local out
  out="$(docker exec "$BACKEND_CTR" curl -s --max-time 60 "${m[@]}" -o /dev/stderr \
    -w '%{http_code} %header{warning}' -H "$AH" "http://127.0.0.1:8081$1" 2>"$2" || echo 000)"
  ST="${out%% *}"; WARN="${out#* }"; [ "$WARN" != "$out" ] || WARN=""
}
# not_from_row <label> <status> <body> <warning>: the response did not come
# from the row. A 2xx is allowed only as the Remote path's own stale-if-error
# serve (#4581), which carries `Warning: 110` and ran the Remote's gates.
not_from_row(){
  if [ -n "$4" ] && [ "${2:0:1}" = "2" ]; then
    case "$4" in 110*) return 0 ;; esac
  fi
  [ "$(sha_of "$3")" != "$PY_SHA" ] || fail_g "$1: served the row's bytes ($2)"
  case "$2" in 2??|3??) fail_g "$1: answered $2; the upstream has no such file, so the Remote path answers 404" ;; esac
}

begin_test "setup (#6416/#6418): PyPI Remotes and virtuals over them; cache entries written into the bucket, most recorded as artifacts rows"
SETUP_ERR=""
R_PY="prh-pypi-${SUF}"; V_PY="prh-vpypi-${SUF}"
R_OT="prh-pyoth-${SUF}"
R_SC="prh-pyscan-${SUF}"; V_SC="prh-vpyscan-${SUF}"
mk "$R_PY" pypi remote "${UP}/${P}/pypi"
mk "$V_PY" pypi virtual; member "$V_PY" "$R_PY"
mk "$R_OT" pypi remote "${UP}/${P}/pyoth"
mk "$R_SC" pypi remote "${UP}/${P}/pyscan"
mk "$V_SC" pypi virtual; member "$V_SC" "$R_SC"
# A virtual that scans over R_PY, which does not (#3023 stricter-of-two).
V_VS="prh-vpyvs-${SUF}"
mk "$V_VS" pypi virtual; member "$V_VS" "$R_PY"
# The cache root (`proxy-cache/` plus this deployment's scope segment), from
# the CRAN entry the CONTROL above cached.
ROOT_REL="$(docker run --rm --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
  "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && mc ls -r local/ak-artifacts/proxy-cache/" \
  2>/dev/null | awk '{print $NF}' | grep -F "/${R_FREE}/" | head -n1)"
case "$ROOT_REL" in
  "${R_FREE}/"*) ROOT="proxy-cache/" ;;
  *"/${R_FREE}/"*) ROOT="proxy-cache/${ROOT_REL%%/"${R_FREE}"/*}/" ;;
  *) ROOT=""; SETUP_ERR="${SETUP_ERR} no cached CRAN entry to read the cache root from" ;;
esac
repo_id(){ psqlq "SELECT id FROM repositories WHERE key = '$1'"; }
R_PY_ID="$(repo_id "$R_PY")"; R_SC_ID="$(repo_id "$R_SC")"; V_VS_ID="$(repo_id "$V_VS")"
ADMIN_ID="$(psqlq "SELECT id FROM users WHERE username = 'admin'")"
[ -n "$R_PY_ID" ] && [ -n "$R_SC_ID" ] && [ -n "$V_VS_ID" ] && [ -n "$ADMIN_ID" ] || SETUP_ERR="${SETUP_ERR} repo/admin id"
head -c 200000 /dev/urandom > "$W/py.tar.gz"; PY_SHA="$(sha_of "$W/py.tar.gz")"
# One body per scan probe, so each probe's scan record is its own.
for b in scana scanb scand vsa vsb; do
  head -c 150000 /dev/urandom > "$W/$b.tar.gz"; sidecar "$W/meta-$b.json" "$W/$b.tar.gz" 0
done
sidecar "$W/meta-free.json" "$W/py.tar.gz" 0
sidecar "$W/meta-held.json" "$W/py.tar.gz" 60
sidecar "$W/meta-stale.json" "$W/py.tar.gz" 0 "-1 hour"
# entry <cache-repo> <project> <sidecar|none> <row-repo-id|norow> <body>: the
# cache entry of <cache-repo>, and an artifacts row of <row-repo-id> keyed on it.
entry(){
  local cp="simple/$2/$2-1.0.tar.gz"
  local key="${ROOT}$1/${cp}"
  mc_put "${key}/__content__" "$5" || SETUP_ERR="${SETUP_ERR} put:$2"
  [ "$3" = "none" ] || mc_put "${key}/__cache_meta__.json" "$W/$3" || SETUP_ERR="${SETUP_ERR} sidecar:$2"
  if [ "$4" != "norow" ]; then
    [[ "$(psqlq "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by)
                VALUES ('$4', '${cp}', '$2', '1.0', $(stat -c %s "$5"), '$(sha_of "$5")', 'application/x-tar',
                        '${key}/__content__', '${ADMIN_ID}') RETURNING 'row-ok'")" = *row-ok* ]] || SETUP_ERR="${SETUP_ERR} row:$2"
  fi
}
if [ -n "$ROOT" ] && [ -z "$SETUP_ERR" ]; then
  entry "$R_PY" dtfrowfree meta-free.json "$R_PY_ID" "$W/py.tar.gz"
  entry "$R_PY" dtfrowheld meta-held.json "$R_PY_ID" "$W/py.tar.gz"
  entry "$R_PY" dtfrownoside none "$R_PY_ID" "$W/py.tar.gz"
  entry "$R_PY" dtfrowstale meta-stale.json "$R_PY_ID" "$W/py.tar.gz"
  # A row of R_PY keyed on ANOTHER Remote's fresh, unheld entry.
  entry "$R_OT" dtfrowforeign meta-free.json "$R_PY_ID" "$W/py.tar.gz"
  entry "$R_PY" dtfheadfree meta-free.json norow "$W/py.tar.gz"
  # R_SC scans on proxy; V_VS scans over R_PY, which does not (#3023). The
  # stack runs a live scanner, so the scan gate scans each body inline
  # (fail_closed) and records a verdict for its digest; a serve that skips
  # the gate records none.
  scan_on(){
    [[ "$(psqlq "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, scan_on_proxy, block_on_policy_violation, severity_threshold, proxy_scan_action)
                VALUES ('$1', true, false, true, false, 'high', 'fail_closed')
                ON CONFLICT (repository_id) DO UPDATE SET scan_enabled = true, scan_on_proxy = true, severity_threshold = 'high', proxy_scan_action = 'fail_closed'
                RETURNING 'cfg-ok'")" = *cfg-ok* ]] || SETUP_ERR="${SETUP_ERR} scan-config:$1"
  }
  scan_on "$R_SC_ID"; scan_on "$V_VS_ID"
  for b in scana scanb scand; do entry "$R_SC" "dtfrow$b" "meta-$b.json" "$R_SC_ID" "$W/$b.tar.gz"; done
  for b in vsa vsb; do entry "$R_PY" "dtfrow$b" "meta-$b.json" "$R_PY_ID" "$W/$b.tar.gz"; done
fi
note "cache root ${ROOT:-?}; Remote ${R_PY} (${R_PY_ID:-?})"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; else pass; fi

ROW(){ echo "/pypi/$1/simple/$2/$2-1.0.tar.gz"; }
# scanned <label> <body> <status> <location>: the response went through the
# scan gate: no redirect, a scan recorded for the body's digest, and a 2xx
# only for a body that scan let through (403/423 are its refusals).
scanned(){
  local n
  n="$(psqlq "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256 = '$(sha_of "$2")'")"
  note "$1: ${3}${4:+ Location ${4:0:90}}; scans recorded for the body: ${n:-?}"
  [ -z "$4" ] || fail_g "$1: redirected to a body the scan gate never saw (${3})"
  [ "${n:-0}" -ge 1 ] || fail_g "$1: answered ${3} with no scan of the body recorded (served unscanned)"
  case "$3" in 200|403|423) ;; *) fail_g "$1: answered ${3}" ;; esac
}

# --- presigned downloads on (backend) ----------------------------------------
begin_test "CONTROL: the virtual redirects a fresh, unheld proxy-cache row to a presigned URL that serves the exact bytes"
reset_case
get_a "$(ROW "$V_PY" dtfrowfree)" "$W/rowfree"
note "virtual GET -> ${ST}${LOC:+ Location ${LOC:0:90}}"
case "$ST" in
  301|302|303|307|308)
    c="$(curl -s --max-time 60 -o "$W/rowfree2" -w '%{http_code}' "$LOC" || true)"
    [ "$c" = "200" ] && [ "$(sha_of "$W/rowfree2")" = "$PY_SHA" ] || fail_g "the presigned URL answered ${c} or other bytes" ;;
  *) fail_g "answered ${ST}, expected a redirect (is the row's presigned path on?): $(head -c 200 "$W/rowfree")" ;;
esac
finish_case "the proxy-cache row redirect is not active here"

begin_test "FIX #6416: a proxy-cache row inside its Package Age Policy hold answers the hold's 409 through the virtual, not a redirect to the held object"
reset_case
get_a "$(ROW "$V_PY" dtfrowheld)" "$W/rowheld"
note "virtual GET -> ${ST}${LOC:+ Location ${LOC:0:90}}"
[ -z "$LOC" ] || fail_g "redirected to the held object (${ST} ${LOC:0:120})"
[ "$ST" = "409" ] || fail_g "answered ${ST}, expected the hold's 409: $(head -c 200 "$W/rowheld")"
finish_case "a held proxy-cache row was signed after only an existence check"

begin_test "FIX #6416: a proxy-cache row of a Remote that scans on proxy is served through the scan gate, not redirected to unscanned"
reset_case
get_a "$(ROW "$V_SC" dtfrowscana)" "$W/rowscan"
scanned "virtual GET" "$W/scana.tar.gz" "$ST" "$LOC"
finish_case "a scanning Remote's proxy-cache row was signed without a scan"

begin_test "FIX #6416: a proxy-cache row with no sidecar, a stale one, or a key naming another Remote is not redirected to; the first and last are not served at all"
reset_case
# A stale row is declined like the others and the walk goes on to the Remote
# path, which owns what it does with its own expired entry (it may serve it,
# under its own hold and scan checks), so for it only the redirect is asserted.
get_a "$(ROW "$V_PY" dtfrowstale)" "$W/dtfrowstale"
note "dtfrowstale: virtual GET -> ${ST}${LOC:+ Location ${LOC:0:90}}"
[ -z "$LOC" ] || fail_g "dtfrowstale: redirected to a stale entry (${ST})"
for proj in dtfrownoside dtfrowforeign; do
  get_a "$(ROW "$V_PY" "$proj")" "$W/$proj"
  note "${proj}: virtual GET -> ${ST}${LOC:+ Location ${LOC:0:90}}${WARN:+ Warning ${WARN}}"
  [ -z "$LOC" ] || fail_g "${proj}: redirected to an entry nothing vouches for (${ST})"
  [ -n "$LOC" ] || not_from_row "$proj" "$ST" "$W/$proj" "$WARN"
done
finish_case "a proxy-cache row nothing vouches for was signed after only an existence check"

# --- presigned downloads off (backend-b, the default) ------------------------
begin_test "CONTROL: with presigned downloads off, the virtual streams a fresh, unheld proxy-cache row (the exact bytes)"
reset_case
get_bb "$(ROW "$V_PY" dtfrowfree)" "$W/bfree"
note "backend-b virtual GET -> ${ST}"
[ "$ST" = "200" ] && [ "$(sha_of "$W/bfree")" = "$PY_SHA" ] || fail_g "answered ${ST} or other bytes"
finish_case "backend-b does not serve the proxy-cache row"

begin_test "FIX #6416: with presigned downloads off, a held proxy-cache row answers 409 to a GET and to a HEAD, not the held bytes"
reset_case
get_bb "$(ROW "$V_PY" dtfrowheld)" "$W/bheld"; g="$ST"; gs="$(sha_of "$W/bheld")"
get_bb "$(ROW "$V_PY" dtfrowheld)" "$W/bheldh" HEAD; h="$ST"
note "backend-b virtual GET -> ${g}; HEAD -> ${h}"
[ "$gs" != "$PY_SHA" ] || fail_g "the GET served the held bytes (${g})"
[ "$g" = "409" ] || fail_g "the GET answered ${g}, expected 409"
[ "$h" = "409" ] || fail_g "the HEAD answered ${h}, expected 409 (as the GET)"
finish_case "a held proxy-cache row was streamed without a look at its sidecar"

begin_test "FIX #6416: with presigned downloads off, a scanning Remote's row is served through the scan gate, and a row with no sidecar or a foreign key is not served"
reset_case
get_bb "$(ROW "$V_SC" dtfrowscanb)" "$W/bscan"
scanned "backend-b virtual GET" "$W/scanb.tar.gz" "$ST" ""
for proj in dtfrownoside dtfrowforeign; do
  get_bb "$(ROW "$V_PY" "$proj")" "$W/b$proj"
  note "backend-b ${proj} GET -> ${ST}${WARN:+ Warning ${WARN}}"
  not_from_row "$proj" "$ST" "$W/b$proj" "$WARN"
done
finish_case "a proxy-cache row was streamed without a look at its sidecar"

# --- the stricter-of-two policy and the direct Remote route ------------------
begin_test "FIX #6416: through a virtual that scans over a member that does not, a fresh row is served only through the scan gate (presign on and off)"
reset_case
get_a "$(ROW "$V_VS" dtfrowvsa)" "$W/vsa"
scanned "backend virtual GET" "$W/vsa.tar.gz" "$ST" "$LOC"
get_bb "$(ROW "$V_VS" dtfrowvsb)" "$W/vsb"
scanned "backend-b virtual GET" "$W/vsb.tar.gz" "$ST" ""
finish_case "the virtual's scan policy was not applied to the member's proxy-cache row"

begin_test "FIX #6416: the Remote's own route serves a cached row of a scanning Remote only through the scan gate (it checked only the hold)"
reset_case
get_bb "$(ROW "$R_SC" dtfrowscand)" "$W/dirscan"
scanned "backend-b Remote GET" "$W/scand.tar.gz" "$ST" ""
finish_case "the Remote route served a scanning Remote's proxy-cache row unscanned"

# --- #6418 ---------------------------------------------------------------------
begin_test "CONTROL: a GET of a fresh cached file on the PyPI Remote is a presigned redirect"
reset_case
get_a "$(ROW "$R_PY" dtfheadfree)" "$W/headget"
note "Remote GET -> ${ST}${LOC:+ Location ${LOC:0:90}}"
case "$ST" in 301|302|303|307|308) ;; *) fail_g "answered ${ST}, expected a redirect: $(head -c 200 "$W/headget")" ;; esac
finish_case "the PyPI cache redirect is not active here"

begin_test "FIX #6418: a HEAD of the same cached file answers 200 with its length, not a redirect to a URL signed for GET"
reset_case
get_h "$(ROW "$R_PY" dtfheadfree)" "$W/head"
note "Remote HEAD -> ${ST} Content-Length ${CLEN:-none}${LOC:+ Location ${LOC:0:90}}"
if [ -n "$LOC" ]; then
  c="$(curl -s --max-time 30 -I -o /dev/null -w '%{http_code}' "$LOC" || true)"
  fail_g "a HEAD was redirected (${ST}); a HEAD of the signed URL answers ${c}"
fi
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200"
[ "$CLEN" = "$(stat -c %s "$W/py.tar.gz")" ] || fail_g "Content-Length ${CLEN:-none}, expected $(stat -c %s "$W/py.tar.gz")"
finish_case "a HEAD got a redirect to a URL signed for GET"

# =============================================================================
# #6433: every other route that serves an `artifacts` row whose storage_key is
# a proxy-cache key (#6416 covered the PyPI virtual walk). For each route a
# Remote gets three rows keyed on its own cache entries: fresh, held and stale.
# The stale row's entry sits under a legacy cache path (`legacy/<row path>`), so
# the Remote's proxy path, which caches the file under the route's upstream
# path, has no copy of it and asks the mock upstream, which serves OTHER bytes
# for the stale file: a response with the row's bytes came from the row, one
# with the upstream's bytes came from the Remote's path. A route is probed on
# `backend` (presigned downloads on) and on `backend-b` (off, the default), GET
# and HEAD.
# rowspec: <label> <format> <row path (@F@ = file stem)> <row name> <row version>
#          <route on the Remote (@K@ = repo key)>
#          <the file's path under the Remote's upstream, or - when the Remote
#           resolves it through an index first (Helm, Cargo)>
G_SPECS="
generic|generic|pkg/@F@.bin|@F@|1.0|/api/v1/repositories/@K@/download/pkg/@F@.bin|pkg/@F@.bin
conda|conda|noarch/@F@-1.0-0.tar.bz2|@F@|1.0|/conda/@K@/noarch/@F@-1.0-0.tar.bz2|noarch/@F@-1.0-0.tar.bz2
alpine|alpine|v3.20/main/x86_64/@F@-1.0-r0.apk|@F@|1.0-r0|/alpine/@K@/v3.20/main/x86_64/@F@-1.0-r0.apk|v3.20/main/x86_64/@F@-1.0-r0.apk
rpm|rpm|packages/@F@-1.0-1.x86_64.rpm|@F@|1.0|/rpm/@K@/packages/@F@-1.0-1.x86_64.rpm|packages/@F@-1.0-1.x86_64.rpm
debian|debian|pool/main/d/@F@/@F@_1.0_amd64.deb|@F@|1.0|/debian/@K@/pool/main/d/@F@/@F@_1.0_amd64.deb|pool/main/d/@F@/@F@_1.0_amd64.deb
go|go|example.com/@F@/@v/v1.0.0.zip|example.com/@F@|v1.0.0|/go/@K@/example.com/@F@/@v/v1.0.0.zip|example.com/@F@/@v/v1.0.0.zip
helm|helm|charts/@F@-1.0.0.tgz|@F@|1.0.0|/helm/@K@/charts/@F@-1.0.0.tgz|-
cargo|cargo|crates/@F@/@F@-1.0.0.crate|@F@|1.0.0|/cargo/@K@/api/v1/crates/@F@/1.0.0/download|-
"
# row_entry <repo-key> <repo-id> <row-path> <name> <version> <sidecar|none> <body>
#           [cache path of the entry, default the row path]
row_entry(){
  local key="${ROOT}$1/${8:-$3}"
  mc_put "${key}/__content__" "$7" || SETUP_ERR="${SETUP_ERR} put:$3"
  [ "$6" = "none" ] || mc_put "${key}/__cache_meta__.json" "$W/$6" || SETUP_ERR="${SETUP_ERR} sidecar:$3"
  [[ "$(psqlq "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by)
              VALUES ('$2', '$3', '$4', '$5', $(stat -c %s "$7"), '$(sha_of "$7")', 'application/octet-stream',
                      '${key}/__content__', '${ADMIN_ID}') RETURNING 'row-ok'")" = *row-ok* ]] || SETUP_ERR="${SETUP_ERR} row:$3"
}
sub(){ local x="${1//@F@/$2}"; echo "${x//@K@/$3}"; }

begin_test "setup (#6433): a Remote per format route, with fresh, held and stale proxy-cache rows; a PyPI virtual over a Remote with wheel rows"
SETUP_ERR=""
head -c 120000 /dev/urandom > "$W/g.bin"; G_SHA="$(sha_of "$W/g.bin")"
sidecar "$W/g-free.json" "$W/g.bin" 0
sidecar "$W/g-held.json" "$W/g.bin" 60
sidecar "$W/g-stale.json" "$W/g.bin" 0 "-1 hour"
head -c 90000 /dev/urandom > "$W/g-up.bin"; G_UP_SHA="$(sha_of "$W/g-up.bin")"
G_ROUTES=""
while IFS='|' read -r label fmt rpath rname rver route upath; do
  [ -n "$label" ] || continue
  key="prh-g${label}-${SUF}"
  mk "$key" "$fmt" remote "${UP}/${P}/g${label}"
  rid="$(repo_id "$key")"; [ -n "$rid" ] || { SETUP_ERR="${SETUP_ERR} id:${key}"; continue; }
  for st in free held stale; do
    stem="dtfg${label}${st}${SUF}"
    rp="$(sub "$rpath" "$stem" "$key")"; kp="$rp"; [ "$st" = stale ] && kp="legacy/$rp"
    row_entry "$key" "$rid" "$rp" "$(sub "$rname" "$stem" "$key")" "$rver" "g-${st}.json" "$W/g.bin" "$kp"
  done
  if [ "$upath" != "-" ]; then
    [ -n "$(mock_put "/${P}/g${label}/$(sub "$upath" "dtfg${label}stale${SUF}" "$key")" "$W/g-up.bin")" ] \
      || SETUP_ERR="${SETUP_ERR} mock:${label}"
  fi
  G_ROUTES="${G_ROUTES}${label}|${key}|${route}|${upath}
"
done <<< "$G_SPECS"
# PyPI PEP 658 metadata: read from a Remote member's row through a virtual.
# A real wheel, so the row's METADATA is what main served.
python3 - "$W/wheel.whl" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("dtfmeta-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: dtfmeta\nVersion: 1.0\nSummary: dtf-6433-row-metadata\n")
    z.writestr("dtfmeta/__init__.py", "")
PY
sidecar "$W/w-free.json" "$W/wheel.whl" 0
sidecar "$W/w-held.json" "$W/wheel.whl" 60
sidecar "$W/w-stale.json" "$W/wheel.whl" 0 "-1 hour"
R_PM="prh-pymeta-${SUF}"; V_PM="prh-vpymeta-${SUF}"
mk "$R_PM" pypi remote "${UP}/${P}/pymeta"
mk "$V_PM" pypi virtual; member "$V_PM" "$R_PM"
R_PM_ID="$(repo_id "$R_PM")"
for st in free held stale; do
  proj="dtfmeta${st}${SUF}"
  row_entry "$R_PM" "$R_PM_ID" "simple/${proj}/${proj}-1.0-py3-none-any.whl" "$proj" "1.0" "w-${st}.json" "$W/wheel.whl"
done
note "routes: $(echo "$G_ROUTES" | cut -d'|' -f1 | tr '\n' ' ')"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; else pass; fi

# g_probe <label> <key> <route> <state> -> GA (backend GET), GH (backend HEAD),
# BB (backend-b GET), BH (backend-b HEAD); bodies in $W/g-<label>-<state>-*
g_probe(){
  local path; path="$(sub "$3" "dtfg$1$4${SUF}" "$2")"
  get_a "$path" "$W/g-$1-$4-a"; GA="$ST"; GA_LOC="$LOC"
  get_h "$path" "$W/g-$1-$4-h"; GH="$ST"
  get_bb "$path" "$W/g-$1-$4-b"; BB="$ST"
  get_bb "$path" "$W/g-$1-$4-bh" HEAD; BH="$ST"
}

begin_test "CONTROL: each route serves a fresh, unheld proxy-cache row of its Remote (presigned downloads off: the exact bytes)"
reset_case
while IFS='|' read -r label key route _; do
  [ -n "$label" ] || continue
  g_probe "$label" "$key" "$route" free
  note "${label} fresh: backend GET ${GA}${GA_LOC:+ (redirect)} HEAD ${GH}; backend-b GET ${BB} HEAD ${BH}"
  [ "$BB" = "200" ] && [ "$(sha_of "$W/g-${label}-free-b")" = "$G_SHA" ] || fail_g "${label}: backend-b answered ${BB} or other bytes for a fresh row"
done <<< "$G_ROUTES"
finish_case "a route does not serve its Remote's proxy-cache rows here, so the FIX cases below prove nothing"

begin_test "FIX #6433: a held proxy-cache row answers the hold's 409 on every route, GET and HEAD, presigned downloads on and off"
reset_case
while IFS='|' read -r label key route _; do
  [ -n "$label" ] || continue
  g_probe "$label" "$key" "$route" held
  note "${label} held: backend GET ${GA}${GA_LOC:+ Location ${GA_LOC:0:60}} HEAD ${GH}; backend-b GET ${BB} HEAD ${BH}"
  for v in "backend GET:$GA" "backend HEAD:$GH" "backend-b GET:$BB" "backend-b HEAD:$BH"; do
    [ "${v##*:}" = "409" ] || fail_g "${label} ${v%:*}: answered ${v##*:}, expected the hold's 409"
  done
  [ -z "$GA_LOC" ] || fail_g "${label}: redirected to the held object"
  [ "$(sha_of "$W/g-${label}-held-b")" != "$G_SHA" ] || fail_g "${label}: backend-b served the held bytes"
done <<< "$G_ROUTES"
finish_case "a held proxy-cache row was served from its artifacts row with no look at its sidecar"

# A stale row is declined and the Remote's proxy path answers. Its upstream
# serves other bytes for the stale file than the row holds (see the setup), so
# where the Remote fetches the file itself the response must be the upstream's
# bytes; for Helm and Cargo, which resolve the file through an index the mock
# does not serve, a non-2xx without the row's bytes. A serve from the row is
# also recorded against the row in download_statistics, off the response path:
# each route's own fresh row (served by the CONTROL above) is the reference
# that the recorder has caught up before a 0 is believed.
row_served(){ # <row path> -> count of downloads recorded against the row
  psqlq "SELECT count(*) FROM download_statistics d JOIN artifacts a ON a.id = d.artifact_id WHERE a.path = '$1'" | tr -d '[:space:]'
}
row_of(){ local rpath; rpath="$(grep "^$1|" <<< "$G_SPECS" | cut -d'|' -f3)"; sub "$rpath" "dtfg$1$2${SUF}" "$3"; }
begin_test "FIX #6433: a stale proxy-cache row is not served from the row; the status and body come from the Remote's proxy path"
reset_case
UNCALIBRATED=""
while IFS='|' read -r label key route upath; do
  [ -n "$label" ] || continue
  g_probe "$label" "$key" "$route" stale
  a_sha="$(sha_of "$W/g-${label}-stale-a")"; b_sha="$(sha_of "$W/g-${label}-stale-b")"
  src(){ case "$1" in "$G_SHA") echo row ;; "$G_UP_SHA") echo upstream ;; *) echo other ;; esac; }
  note "${label} stale: backend GET ${GA} ($(src "$a_sha"))${GA_LOC:+ Location ${GA_LOC:0:60}}; backend-b GET ${BB} ($(src "$b_sha"))"
  [ -z "$GA_LOC" ] || fail_g "${label}: redirected to a stale entry (${GA})"
  for v in "backend:${GA}:${a_sha}" "backend-b:${BB}:${b_sha}"; do
    who="${v%%:*}"; rest="${v#*:}"; st="${rest%%:*}"; sh="${rest#*:}"
    if [ "$upath" != "-" ]; then
      [ "$st" = "200" ] && [ "$sh" = "$G_UP_SHA" ] \
        || fail_g "${label} ${who}: answered ${st} with the $(src "$sh") bytes, expected 200 with the upstream's bytes (the Remote's path)"
    else
      case "$st" in 2??|3??) fail_g "${label} ${who}: answered ${st}; the Remote's path has no such file (its index is not served)" ;; esac
      [ "$sh" != "$G_SHA" ] || fail_g "${label} ${who}: served the row's bytes"
    fi
  done
  cal="$(row_of "$label" free "$key")"
  for _ in $(seq 1 30); do [ "$(row_served "$cal")" != "0" ] && break; sleep 1; done
  if [ "$(row_served "$cal")" = "0" ]; then
    UNCALIBRATED="${UNCALIBRATED} ${label}"
  else
    n="$(row_served "$(row_of "$label" stale "$key")")"
    note "${label}: downloads recorded against the fresh row $(row_served "$cal"), against the stale row ${n:-?}"
    [ "${n:-1}" = "0" ] || fail_g "${label}: the stale row was served from its artifacts row (${n:-?} downloads recorded against it)"
  fi
done <<< "$G_ROUTES"
if [ -n "$UNCALIBRATED" ]; then
  infra_fail "the fresh row's download was never recorded for:${UNCALIBRATED}; cannot tell a row serve from a proxy serve"
else
  finish_case "a stale proxy-cache row was served from its artifacts row"
fi

PMETA(){ echo "/pypi/${V_PM}/simple/dtfmeta$1${SUF}/dtfmeta$1${SUF}-1.0-py3-none-any.whl.metadata"; }
begin_test "CONTROL: a PyPI virtual serves the PEP 658 metadata of a fresh proxy-cache wheel row of its Remote member"
reset_case
get_a "$(PMETA free)" "$W/pmfree"
note "virtual .metadata (fresh row) -> ${ST}: $(head -c 80 "$W/pmfree" | tr '\n' ' ')"
if [ "$ST" != "200" ] || ! grep -q 'dtf-6433-row-metadata' "$W/pmfree"; then
  fail_g "answered ${ST} without the row's METADATA"
fi
finish_case "the virtual does not read PEP 658 metadata from a member's row here"

begin_test "FIX #6433: PEP 658 metadata of a held proxy-cache wheel row answers 409 through the virtual (GET and HEAD); a stale row's metadata is not read from the row"
reset_case
get_a "$(PMETA held)" "$W/pmheld"; g="$ST"
get_h "$(PMETA held)" "$W/pmheldh"; h="$ST"
get_bb "$(PMETA held)" "$W/pmheldb"; b="$ST"
get_a "$(PMETA stale)" "$W/pmstale"; s="$ST"
note "held: backend GET ${g} HEAD ${h}, backend-b GET ${b}; stale: GET ${s}"
for v in "backend GET:$g" "backend HEAD:$h" "backend-b GET:$b"; do
  [ "${v##*:}" = "409" ] || fail_g "held ${v%:*}: answered ${v##*:}, expected the hold's 409"
done
! grep -q 'dtf-6433-row-metadata' "$W/pmheld" || fail_g "served the held row's METADATA"
! grep -q 'dtf-6433-row-metadata' "$W/pmstale" || fail_g "served the stale row's METADATA (${s})"
finish_case "PEP 658 metadata was extracted from a proxy-cache row with no look at its sidecar"

end_suite
