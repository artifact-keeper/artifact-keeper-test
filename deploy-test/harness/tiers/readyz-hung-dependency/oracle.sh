#!/usr/bin/env bash
# =============================================================================
# tiers/readyz-hung-dependency/oracle.sh - a hung /readyz dependency costs its
#                                          2 s deadline once per cache TTL
#                                          (artifact-keeper#4781 / #4796)
# =============================================================================
# run.sh has stood up filesystem + scanners.mock-hang and exported BASE_URL,
# TRIVY_PORT (the mock's control port), DB_CONTAINER, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. The backend's TRIVY_URL points at the mock, and
# EXPOSE_DETAILED_HEALTH=true puts the probe message on /readyz.
#
# Gates (see the manifest for the full prose):
#   (CONTROL) /healthz and /readyz are 200 with the scanner healthy before
#             the hang and again after it; while the scanner hangs /readyz
#             stays 200 (an optional dependency never gates readiness), the
#             first call reports the scanner unhealthy with "Scanner probe
#             timed out (2s)" within the 2 s deadline plus a margin; the
#             lock-wait primitive really happens (the cancelled first call
#             released the lock unstored, so the waiter probed again); after
#             the mock answers again /readyz recovers within one TTL plus one
#             deadline. True on both images.
#   (FIX)     after a lock-waiting /readyz timed the hung probe out, the next
#             /readyz and a burst behind it answer from the cache (each well
#             under the 2 s deadline, same timed-out message) and the mock
#             sees no new probe inside the TTL. Three cycles. RED on 1.11.2:
#             the next call re-probes and pays ~2 s every cycle.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
TIMEOUT_MSG="Scanner probe timed out (2s)"
# DEPENDENCY_HEALTH_TTL (5 s) plus slack: sleeping this long guarantees the
# scanner cache entry is stale and the next /readyz probes.
TTL_WAIT=6
CYCLES=3
BURST=8
# A cache hit is a lock + clone; anything over this is a probe.
FAST_MAX=0.5
# The single hung call must end at the 2 s deadline (2.1 s lock-wait bound on
# the fixed image), never at the probe client's 5 s timeout.
DEADLINE_MIN=1.8
DEADLINE_MAX=3.0

WORK="$(mktemp -d -t dtf-readyz-XXXXXX)"
cleanup() {
  # Leave the mock answering, so run.sh teardown and --keep see a sane stack.
  curl -s -m 5 -X POST "${MOCK}/__mode?m=ok" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mock_mode() { [ "$(curl -s -m 5 -X POST "${MOCK}/__mode?m=$1" 2>/dev/null)" = "$1" ]; }
mock_now() { curl -s -m 5 "${MOCK}/__hits" 2>/dev/null | jq -r '.now // empty' 2>/dev/null; }
# probes_since T -> number of /healthz probes that arrived after mock time T
# and were given up at the /readyz deadline (held < 4 s). The backend's 60 s
# health monitor holds for its 5 s client timeout and is not counted.
probes_since() {
  curl -s -m 5 "${MOCK}/__hits" 2>/dev/null \
    | jq -r --argjson t "$1" '[.hits[] | select(.t > $t and .mode == "hang" and .held != null and .held < 4)] | length' 2>/dev/null
}
# open_since T -> probes after T the mock is still holding (held == null).
open_since() {
  curl -s -m 5 "${MOCK}/__hits" 2>/dev/null \
    | jq -r --argjson t "$1" '[.hits[] | select(.t > $t and .held == null)] | length' 2>/dev/null
}
no_open_since() { [ "$(open_since "$1")" = "0" ]; }

# readyz -> "CODE SECONDS SCANNER_STATUS" on stdout; body in $WORK/rz.
readyz() {
  local out code t
  out="$(curl -s -m 15 -o "${WORK}/rz" -w '%{http_code} %{time_total}' "${BASE_URL}/readyz" 2>/dev/null || echo '000 0')"
  code="${out%% *}"; t="${out##* }"
  printf '%s %s %s\n' "$code" "$t" "$(jq -r '.dependencies.scanner.status // "none"' "${WORK}/rz" 2>/dev/null || echo none)"
}
scanner_msg() { jq -r '.dependencies.scanner.message // ""' "${WORK}/rz" 2>/dev/null; }
le() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 <= b + 0) }'; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'; }
scanner_healthy_ready() { [ "$(readyz | awk '{print $1" "$3}')" = "200 healthy" ]; }

begin_suite "readyz-hung-dependency"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: the scanner mock answers and the backend probes it"
if ! mock_mode ok; then infra_fail "mock-scanner control endpoint ${MOCK} did not answer"; end_suite; fi
if ! wait_until "/readyz reports the scanner healthy" 60 scanner_healthy_ready; then
  infra_fail "/readyz never reported dependencies.scanner healthy against the mock" "$(head -c 400 "${WORK}/rz" 2>/dev/null)"
  end_suite
fi
pass

# =============================================================================
# BEFORE (CONTROL, both images)
# =============================================================================
begin_test "CONTROL before: /healthz 200 with security_scanner healthy, /readyz 200 with scanner healthy"
HC="$(curl -s -m 15 -o "${WORK}/hz" -w '%{http_code}' "${BASE_URL}/healthz" 2>/dev/null || echo 000)"
HS="$(jq -r '.checks.security_scanner.status // "none"' "${WORK}/hz" 2>/dev/null)"
read -r RC _ RS <<<"$(readyz)"
if [ "$HC" = "200" ] && [ "$HS" = "healthy" ] && [ "$RC" = "200" ] && [ "$RS" = "healthy" ]; then
  pass
else
  fail "/healthz=${HC} scanner=${HS}, /readyz=${RC} scanner=${RS}" "$(head -c 400 "${WORK}/hz")"
fi

# =============================================================================
# THE HANG
# =============================================================================
if ! mock_mode hang; then infra_fail "could not switch the mock to hang"; end_suite; fi
sleep "$TTL_WAIT"

begin_test "CONTROL hung: one /readyz ends at the 2 s deadline, 200, scanner unhealthy, '${TIMEOUT_MSG}'"
read -r RC RT RS <<<"$(readyz)"
RM="$(scanner_msg)"
if [ "$RC" = "200" ] && [ "$RS" = "unhealthy" ] && [ "$RM" = "$TIMEOUT_MSG" ] \
   && ge "$RT" "$DEADLINE_MIN" && le "$RT" "$DEADLINE_MAX"; then
  pass
else
  fail "/readyz=${RC} in ${RT}s, scanner=${RS} message='${RM}' (want 200, unhealthy, '${TIMEOUT_MSG}', ${DEADLINE_MIN}..${DEADLINE_MAX}s)" \
    "$(head -c 400 "${WORK}/rz")"
fi

# Per-cycle evidence for the two gates below. PRIM_OK counts the cycles in
# which the lock-wait primitive demonstrably happened (A's probe AND B's probe
# reached the mock). A is a 0.5 s client that is dropped on purpose; when hyper
# drops it before its probe has left the backend the mock sees only B's probe
# (lock-window probes=1). That cycle shows no lock-wait and is inconclusive for
# the primitive, not a regression (seen once in three cycles on the 1.11.4
# gate), so the primitive gate wants PRIM_MIN of CYCLES cycles, and B's own
# contract and the FIX gate stay strict in every cycle.
SETUP_OK=1
PRIM_OK=0
PRIM_MIN=$(( CYCLES - 1 ))
CYCLE_EV=""
FIX_BAD=0
for c in $(seq 1 "$CYCLES"); do
  sleep "$TTL_WAIT"
  M0="$(mock_now)"
  if [ -z "$M0" ]; then SETUP_OK=0; CYCLE_EV+="cycle ${c}: mock clock unreadable; "; continue; fi
  # A: takes the scanner cache lock, starts probing the hung mock, and goes
  # away at 0.5 s. hyper drops the handler; the lock is released unstored.
  curl -s -m 0.5 -o /dev/null "${BASE_URL}/readyz" >/dev/null 2>&1 &
  APID=$!
  sleep 0.15
  # B: waits for the lock, then probes with its outer deadline partly spent.
  read -r BC BT BS <<<"$(readyz)"
  BM="$(scanner_msg)"
  wait "$APID" 2>/dev/null || true
  M1="$(mock_now)"
  # C + burst: inside the TTL B's result (if it was stored) must answer them.
  TIMES=()
  BAD=""
  for i in $(seq 0 "$BURST"); do
    read -r XC XT XS <<<"$(readyz)"
    XM="$(scanner_msg)"
    TIMES+=("$XT")
    if [ "$XC" != "200" ] || [ "$XS" != "unhealthy" ] || [ "$XM" != "$TIMEOUT_MSG" ] || ! le "$XT" "$FAST_MAX"; then
      BAD+="call${i}=${XC}/${XS}/${XT}s "
    fi
  done
  # Let any probe the burst started reach its deadline before counting.
  wait_until "cycle ${c}: mock probes closed" 10 no_open_since "$M0" || true
  LOCKWAIT_PROBES="$(probes_since "$M0")"; NEW_PROBES="$(probes_since "$M1")"
  LOCKWAIT_PROBES=$(( LOCKWAIT_PROBES - NEW_PROBES ))
  MEDIAN="$(printf '%s\n' "${TIMES[@]}" | sort -g | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"
  CYCLE_EV+="cycle ${c}: B=${BC}/${BS}/${BT}s '${BM}', lock-window probes=${LOCKWAIT_PROBES}, after-B probes=${NEW_PROBES}, burst first=${TIMES[0]}s median=${MEDIAN}s ${BAD:+slow/wrong: ${BAD}}; "
  # B's contract holds in every cycle: it timed the hung scanner out at its
  # deadline. The primitive itself (A's probe and B's probe both reached the
  # mock) is counted per cycle; one probe means A was dropped before probing.
  if [ "$BC" != "200" ] || [ "$BS" != "unhealthy" ] || [ "$BM" != "$TIMEOUT_MSG" ]; then
    SETUP_OK=0
  elif [ "$LOCKWAIT_PROBES" = "2" ]; then
    PRIM_OK=$(( PRIM_OK + 1 ))
  elif [ "$LOCKWAIT_PROBES" = "1" ]; then
    CYCLE_EV+="(cycle ${c}: A was dropped before its probe left, inconclusive for the primitive) "
  else
    SETUP_OK=0
  fi
  if [ -n "$BAD" ] || [ "$NEW_PROBES" != "0" ]; then FIX_BAD=$(( FIX_BAD + 1 )); fi
done
[ "$PRIM_OK" -ge "$PRIM_MIN" ] || SETUP_OK=0

begin_test "CONTROL hung: the lock-wait primitive happens in at least ${PRIM_MIN} of ${CYCLES} cycles (a cancelled /readyz releases the lock unstored, the waiter re-probes and times out at its deadline)"
if [ "$SETUP_OK" = "1" ]; then pass; else fail "the lock-wait primitive did not happen as designed (${PRIM_OK}/${CYCLES} cycles showed both probes)" "$CYCLE_EV"; fi

begin_test "FIX #4781: after a lock-waiting /readyz times the hung scanner out, the next ${BURST}+1 calls are cache hits (each <= ${FAST_MAX}s) and the scanner is not probed again inside the TTL (${CYCLES} cycles)"
echo "  ${CYCLE_EV}" >&2
if [ "$FIX_BAD" = "0" ]; then
  pass
else
  fail "${FIX_BAD}/${CYCLES} cycles re-probed the hung scanner inside the TTL (1.11.2: the outer deadline dropped the waiter's probe before it was cached)" "$CYCLE_EV"
fi

# =============================================================================
# RECOVERY (CONTROL, both images)
# =============================================================================
begin_test "CONTROL recovery: once the scanner answers, /readyz reports it healthy within one TTL plus one deadline"
mock_mode ok || true
R0="$(date +%s)"
if wait_until "/readyz scanner healthy again" 10 scanner_healthy_ready; then
  echo "  recovered in $(( $(date +%s) - R0 ))s" >&2
  pass
else
  fail "/readyz still did not report the scanner healthy 10s after the mock recovered" "$(head -c 400 "${WORK}/rz")"
fi

begin_test "CONTROL after: /healthz 200 with security_scanner healthy, /readyz 200 with scanner healthy"
HC="$(curl -s -m 15 -o "${WORK}/hz" -w '%{http_code}' "${BASE_URL}/healthz" 2>/dev/null || echo 000)"
HS="$(jq -r '.checks.security_scanner.status // "none"' "${WORK}/hz" 2>/dev/null)"
read -r RC _ RS <<<"$(readyz)"
if [ "$HC" = "200" ] && [ "$HS" = "healthy" ] && [ "$RC" = "200" ] && [ "$RS" = "healthy" ]; then
  pass
else
  fail "/healthz=${HC} scanner=${HS}, /readyz=${RC} scanner=${RS}" "$(head -c 400 "${WORK}/hz")"
fi

end_suite
