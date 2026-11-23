#!/usr/bin/env bash
# =============================================================================
# tiers/mcp-sync-interrupted-pass/oracle.sh
#   #6390 a Remote MCP sync pass whose process is killed is reported as ended
#         by GET .../mcp/sync, not as `running: false` beside a stale state
# See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
BACKEND="ak-dtf${DTF_SLOT}-backend"
HOLE="http://172.16.${DTF_SLOT}.79:81"
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
KEY="mcpkill-${SFX: -10}"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

login(){
  TOK="$(curl -s --max-time 30 -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
}
api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 30 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }
status(){ api GET "/api/v1/repositories/${KEY}/mcp/sync" >/dev/null; abody; }
healthy(){ curl -sf --max-time 5 "$BASE/health" >/dev/null 2>&1; }

begin_suite "mcp-sync-interrupted-pass"

# =============================================================================
begin_test "setup: a Remote MCP repository whose upstream never answers"
err=""
login
[ -n "$TOK" ] || err="admin login failed at $BASE;"
if [ -z "$err" ]; then
  c="$(api POST /api/v1/repositories "$(jq -nc --arg k "$KEY" --arg u "$HOLE" \
    '{key:$k,name:$k,format:"mcp",repo_type:"remote",upstream_url:$u,is_public:false}')")"
  [[ "$c" =~ ^20[01]$ ]] || err="create ${KEY} -> ${c}: $(abody | head -c 300);"
fi
if [ -z "$err" ]; then pass; else infra_fail "$err"; end_suite; exit $?; fi

# =============================================================================
begin_test "CONTROL: a manual pass runs against the black hole, then its process is killed and the backend restarts"
reset_case
c="$(api POST "/api/v1/repositories/${KEY}/mcp/sync")"
note "POST .../mcp/sync -> ${c}: $(abody | head -c 200)"
[ "$c" = "202" ] || fail_g "the manual trigger answered ${c}, not 202"
RUN_ST=""
for _ in $(seq 1 100); do
  st="$(status)"
  if [ "$(jqr '.running' <<<"$st")" = "true" ] && [ -n "$(jqr '.lastStartedAt // empty' <<<"$st")" ]; then
    RUN_ST="$st"; break
  fi
  sleep 0.2
done
note "running poll: ${RUN_ST:-never seen running}"
[ -n "$RUN_ST" ] || fail_g "the pass was never seen running"
STARTED="$(jqr '.lastStartedAt // empty' <<<"$RUN_ST")"
[ "$(jqr '.lastFinishedAt' <<<"$RUN_ST")" = "null" ] || fail_g "the running pass already has a lastFinishedAt"
# The loss of the pass's process: SIGKILL, no shutdown path runs.
docker kill "$BACKEND" >/dev/null 2>&1 || fail_g "docker kill ${BACKEND} failed"
docker start "$BACKEND" >/dev/null 2>&1 || fail_g "docker start ${BACKEND} failed"
up=0
for _ in $(seq 1 90); do healthy && { up=1; break; }; sleep 1; done
[ "$up" = 1 ] || fail_g "the backend did not come back healthy within 90 s"
login
[ -n "$TOK" ] || fail_g "admin login after the restart failed"
finish_case "the pass could not be put in flight and killed"
if [ "$FAILS" -ne 0 ] || [ -z "$STARTED" ]; then end_suite; exit $?; fi

# =============================================================================
begin_test "FIX #6390: the killed pass is reported as ended, not as running:false beside the previous state"
reset_case
st="$(status)"
again="$(status)"
note "first poll after the restart: ${st}"
note "second poll: ${again}"
[ "$(jqr '.running' <<<"$st")" = "false" ] || fail_g "running is not false after the restart"
[ "$(jqr '.lastStartedAt' <<<"$st")" = "$STARTED" ] || fail_g "lastStartedAt changed: a new pass started?"
fin="$(jqr '.lastFinishedAt // empty' <<<"$st")"
if [ -z "$fin" ]; then
  fail_g "lastFinishedAt is null: the poll pairs running:false with no outcome for the killed pass"
else
  [ "$(jq -rn --arg f "$fin" --arg s "$STARTED" '($f|sub("\\.[0-9]+";"")|fromdateiso8601) >= ($s|sub("\\.[0-9]+";"")|fromdateiso8601)')" = "true" ] \
    || fail_g "lastFinishedAt ${fin} is before lastStartedAt ${STARTED}"
fi
jqr '.lastError // ""' <<<"$st" | grep -q "ended without recording an outcome" \
  || fail_g "lastError does not report the pass that ended without an outcome: '$(jqr '.lastError' <<<"$st")'"
[ "$(jqr '.lastFinishedAt' <<<"$again")" = "$(jqr '.lastFinishedAt' <<<"$st")" ] \
  || fail_g "a second poll recorded the end again (lastFinishedAt moved)"
finish_case "GET .../mcp/sync reports the killed pass with the previous pass's state"

end_suite
