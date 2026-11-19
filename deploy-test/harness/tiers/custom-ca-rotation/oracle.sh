#!/usr/bin/env bash
# Prove that mounted CA additions and removals reach the retained health client.
set -uo pipefail
: "${BASE_URL:?}" "${COMMON_SH:?}" "${TRIVY_PORT:?}" "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The reload interval and the scanner health cache TTL are each five seconds.
# Allow a margin for scheduling and a TLS handshake on a busy runner.
BOUND=20

mock_change() { curl -fsS -m 5 -X POST "$MOCK/$1" >/dev/null; }
scanner_status() {
  curl -fsS -m 8 "${BASE_URL}/healthz" \
    | jq -er '.checks.security_scanner.status'
}
scanner_healthy() { [ "$(scanner_status)" = healthy ]; }
scanner_unavailable() { [ "$(scanner_status)" = unavailable ]; }
backend_instance() {
  docker inspect -f '{{.Id}} {{.State.StartedAt}}' "ak-dtf${DTF_SLOT}-backend"
}

begin_suite "custom-ca-rotation"

begin_test "CONTROL: mounted CA A initially trusts the scanner"
if ! STARTED="$(backend_instance)" || ! wait_until "CA A trusted" "$BOUND" scanner_healthy; then
  infra_fail "Could not establish healthy scanner TLS against the initial CA"
  end_suite
fi
pass

begin_test "CONTROL: CA B is untrusted before publishing it"
if ! mock_change leaf/b || ! wait_until "CA B untrusted" "$BOUND" scanner_unavailable; then
  infra_fail "Scanner fixture did not switch to the untrusted CA"
  end_suite
fi
pass

begin_test "FIX #5193: atomically adding CA B makes it trusted"
if ! mock_change bundle/ab; then
  infra_fail "Fixture could not publish the combined bundle"
  end_suite
fi
if wait_until "CA B trusted" "$BOUND" scanner_healthy; then
  pass
else
  fail "Retained scanner client did not trust the added CA within ${BOUND}s"
fi

begin_test "CONTROL: CA A is still trusted while both roots are mounted"
if ! mock_change leaf/a || ! wait_until "CA A still trusted" "$BOUND" scanner_healthy; then
  infra_fail "CA A did not recover while it was still in the bundle"
  end_suite
fi
pass

begin_test "FIX #5193: atomically removing CA A makes it untrusted"
if ! mock_change bundle/b; then
  infra_fail "Fixture could not publish the replacement bundle"
  end_suite
fi
if wait_until "CA A untrusted" "$BOUND" scanner_unavailable; then
  pass
else
  fail "Retained scanner client still trusted the removed CA after ${BOUND}s"
fi

begin_test "FIX #5193: CA B stays trusted without a backend restart"
if ! mock_change leaf/b; then
  infra_fail "Fixture could not switch back to CA B"
  end_suite
fi
if wait_until "CA B still trusted" "$BOUND" scanner_healthy && [ "$(backend_instance)" = "$STARTED" ]; then
  pass
else
  fail "Scanner still unavailable with CA B or the backend restarted"
fi

end_suite
