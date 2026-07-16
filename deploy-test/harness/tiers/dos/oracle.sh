#!/usr/bin/env bash
# =============================================================================
# tiers/dos/oracle.sh — rate-limit + worker-starvation discriminating oracle (#9)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=true
# (the manifest sets it explicitly; today's k8s gate overlay leaves it FALSE, so
# this whole class goes untested). It exported BASE_URL, ADMIN_USER, ADMIN_PASS,
# RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR. We source common.sh for the assertion
# + JUnit harness.
#
# The gate has TWO halves; BOTH must hold or the tier fails:
#
#   (A) LOGIN-LIMITER HOLDS — repeated FAILED logins for one account get 429
#       after a threshold. The AK login limiter is keyed PER USERNAME (verified:
#       tripping a bogus account does not touch `admin`), so we hammer a
#       dedicated throwaway username and assert 429 appears. DISCRIMINATING: with
#       RATE_LIMIT_ENABLED=false the same hammering returns 401 forever and no
#       429 ever appears -> this assertion FAILS. That is the exact today's-gate
#       blind spot (uncapped credential brute-force / login DoS, matrix row 9).
#
#   (B) WORKER-STARVATION IS BOUNDED — a CPU-heavy auth path (bcrypt on login)
#       must not wedge the runtime and starve unrelated requests. We fire a
#       BOUNDED, capped burst of bcrypt logins and, DURING the burst, poll the
#       cheap /health endpoint: it must keep answering 200 quickly (the backend
#       is not wedged) and the backend must never emit a genuine 5xx fault
#       (500/502/504). 429/503 backpressure is acceptable — that is the control
#       working. On a backend whose bcrypt work is uncapped (bypasses the auth
#       semaphore, per the availability-DoS class) the runtime stalls and /health
#       times out -> this assertion FAILS.
#
#       BOUNDED BY DESIGN: this is a test, not a real DoS. The burst concurrency
#       and total request count are capped (DOS_BURST, default 20) with per-
#       request timeouts, one single wave, so it cannot wedge the shared rig.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "dos-rate-limit-worker-starvation"
setup_workdir

# Readiness wait (do not burn admin login budget via auth_admin; Half B needs it).
ready=0
for _ in $(seq 1 20); do
  if curl -sf --max-time 5 "${BASE_URL}/health" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ "$ready" = "1" ] || { echo "FATAL: backend not ready at ${BASE_URL}"; exit 1; }

# ---------------------------------------------------------------------------
# Half A — the login limiter must engage (429) on repeated failed logins.
# ---------------------------------------------------------------------------
LIMIT_USER="dtf-dos-limiter-${RUN_ID}"
MAX_ATTEMPTS="${DOS_LOGIN_ATTEMPTS:-30}"

begin_test "Login limiter engages: repeated failed logins return 429 (needs RATE_LIMIT_ENABLED=true)"
count_401=0; count_429=0; first_429=0; codes=""
for i in $(seq 1 "$MAX_ATTEMPTS"); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"${LIMIT_USER}\",\"password\":\"wrong-${i}\"}" 2>/dev/null) || code="000"
  codes="${codes} ${code}"
  case "$code" in
    401) count_401=$(( count_401 + 1 )) ;;
    429) count_429=$(( count_429 + 1 )); [ "$first_429" -eq 0 ] && first_429="$i" ;;
  esac
done
echo "  ${MAX_ATTEMPTS} failed logins for ${LIMIT_USER}: ${count_401}x401  ${count_429}x429  first-429=attempt#${first_429}"
echo "  codes:${codes}"
if [ "$count_429" -ge 1 ] && [ "$count_401" -ge 1 ]; then
  # Some attempts were processed (401) and then the limiter shed the rest (429):
  # the control is enabled and actually caps brute-force.
  pass
elif [ "$count_401" -ge 1 ] && [ "$count_429" -eq 0 ]; then
  fail "login limiter did NOT engage: all ${MAX_ATTEMPTS} failed logins returned 401, ZERO 429" \
"RATE_LIMIT_ENABLED is effectively OFF -- credential brute-force / login DoS is
uncapped (matrix row 9). Today's k8s gate overlay sets RATE_LIMIT_ENABLED=false,
which is exactly why this class goes untested; the dos tier must run it ON."
else
  fail "unexpected login responses (401=${count_401} 429=${count_429}); endpoint may be misbehaving" "codes:${codes}"
fi

# ---------------------------------------------------------------------------
# Half B — worker-starvation is bounded: a capped bcrypt burst must not wedge
# availability. Fire DOS_BURST concurrent admin logins (full bcrypt each) and,
# during the burst, poll /health; it must keep returning 200 fast and no
# genuine 5xx may appear.
# ---------------------------------------------------------------------------
DOS_BURST="${DOS_BURST:-20}"
BURST_DIR="${WORK_DIR}/burst"; mkdir -p "$BURST_DIR"

begin_test "Baseline: /health responds 200 before load"
b_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}/health" 2>/dev/null) || b_code="000"
if [ "$b_code" = "200" ]; then pass; else fail "baseline /health returned ${b_code}, expected 200"; fi

# Launch the bounded burst (single wave, per-request timeout, capped concurrency).
echo "  firing bounded bcrypt burst: ${DOS_BURST} concurrent admin logins (capped)"
for i in $(seq 1 "$DOS_BURST"); do
  (
    c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
      -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || c="000"
    echo "$c" > "${BURST_DIR}/req-${i}.code"
  ) &
done

# Poll /health WHILE the burst runs.
begin_test "Worker-starvation bounded: /health stays live during the bcrypt burst"
health_ok=0; health_bad=0; max_ht="0.000"
for p in $(seq 1 12); do
  hr=$(curl -s -o /dev/null -w '%{http_code}:%{time_total}' --max-time 6 "${BASE_URL}/health" 2>/dev/null) || hr="000:6.0"
  hcode="${hr%%:*}"; htime="${hr##*:}"
  awk "BEGIN{exit !($htime > $max_ht)}" && max_ht="$htime"
  if [ "$hcode" = "200" ]; then health_ok=$(( health_ok + 1 )); else health_bad=$(( health_bad + 1 )); fi
done
wait

# Tally the burst response codes: 429/503 backpressure is fine; a genuine 5xx
# (500/502/504) or total blackout (000) is a wedge/fault.
b_2xx=0; b_429=0; b_503=0; b_5xx=0; b_000=0
for f in "${BURST_DIR}"/*.code; do
  [ -f "$f" ] || continue
  c=$(cat "$f")
  case "$c" in
    2*) b_2xx=$(( b_2xx + 1 )) ;;
    429) b_429=$(( b_429 + 1 )) ;;
    503) b_503=$(( b_503 + 1 )) ;;
    5*) b_5xx=$(( b_5xx + 1 )) ;;
    000) b_000=$(( b_000 + 1 )) ;;
  esac
done
echo "  health during burst: ${health_ok}/12 ok, ${health_bad}/12 bad, slowest=${max_ht}s"
echo "  burst codes: ${b_2xx}x2xx ${b_429}x429 ${b_503}x503 ${b_5xx}x5xx(fault) ${b_000}x000"
# Discriminating: a wedged runtime makes /health time out (health_ok collapses).
# Require the clear majority of health probes to succeed AND no genuine 5xx fault.
if [ "$health_ok" -ge 9 ] && [ "$b_5xx" -eq 0 ]; then
  pass
else
  fail "availability degraded under a bounded bcrypt burst: health_ok=${health_ok}/12 (need >=9), burst 5xx faults=${b_5xx}" \
"A capped auth burst must not wedge the runtime. health_ok collapsing or a genuine
5xx (500/502/504) means the bcrypt/auth CPU path is starving unrelated requests
(the worker-starvation / auth-semaphore-bypass availability-DoS class, row 9).
429/503 backpressure is acceptable; a wedge or server fault is not."
fi

begin_test "Backend recovers: /health 200 after the burst"
rec=0
for _ in $(seq 1 10); do
  rc=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}/health" 2>/dev/null) || rc="000"
  if [ "$rc" = "200" ]; then rec=1; break; fi
  sleep 2
done
if [ "$rec" = "1" ]; then pass; else fail "backend did not return healthy after the bounded burst"; fi

end_suite
