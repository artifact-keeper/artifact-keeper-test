#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-redirect-hold-replicas/oracle.sh
#   #6361 a presigned-redirect fast path takes the Package Age Policy hold from
#         the sidecar its freshness probe read, so a sidecar read that comes
#         back empty (an eviction, or a miss this replica memoised before
#         another replica filled the entry) cannot sign a held object.
# See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# S3_PORT, TRIVY_PORT (the mock's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${TRIVY_PORT:?}"; : "${S3_PORT:?}"

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

end_suite
