#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-egress/oracle.sh — egress-proxy / SSRF discriminating oracle (#2570)
# =============================================================================
# run.sh has already stood up the `filesystem + squid` profile-set (backend
# forced through the egress proxy `squid`, a legit mock-upstream on a 172.16/12
# address, and a decoy `mock-evil` on a NON-allowlisted egress address) and
# exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT,
# JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit harness.
#
# The gate has TWO halves; BOTH must hold or the tier fails:
#
#   (A) #2570 REGRESSION GUARD — legit egress THROUGH the configured proxy WORKS.
#       A remote/pull-through repo whose upstream is fetched via `squid` must
#       succeed, NOT 502. On a pre-#2570 backend the SSRF DNS guard resolves the
#       proxy host `squid` (a private 10.201.x address), blocks it, and the fetch
#       dies as a 502 "egress proxy connection refused by SSRF egress policy".
#       The fix exempts the exact configured proxy host, so the fetch goes green.
#         A1. POST .../test-upstream  -> 200 {status:ok}   (the direct 502/200 signal)
#         A2. GET  /general/<key>/... -> 200 + body bytes   (real proxied fetch,
#             body-asserted, not curl -o /dev/null)
#
#   (B) SSRF GUARD STILL HOLDS — the fix did NOT open a hole. A repo whose
#       upstream resolves to a private IP that is NOT the configured proxy must
#       still be REFUSED (4xx at create), NOT fetched and NOT 502'd-as-a-proxy:
#         B1. IP-literal private upstream (10.13.37.9)   -> 400/422
#         B2. hostname upstream resolving to a private IP (mock-evil -> 10.201.x)
#             -> 400/422   (the DNS-resolution SSRF path #2570 must not weaken)
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-egress-ssrf-2570"
auth_admin
setup_workdir

LEGIT_KEY="dtf-proxy-legit-${RUN_ID}"
SSRF_IP_KEY="dtf-proxy-ssrf-ip-${RUN_ID}"
SSRF_HOST_KEY="dtf-proxy-ssrf-host-${RUN_ID}"

# The legit origin lives at a fixed 172.16/12 address on the proxy's upstream
# net (see profiles/proxy.squid.yml). It is reached ONLY via `squid`.
LEGIT_UPSTREAM="http://172.31.${DTF_SLOT}.50/"
# A private RFC1918 address that is NOT in AK_SSRF_ALLOW_PRIVATE_CIDRS (172.16/12)
# and is NOT the configured proxy host — the SSRF guard must still block it.
SSRF_IP_UPSTREAM="http://10.13.37.9/"
# A container hostname that resolves (docker DNS, from the backend) to a private
# 10.201.x address outside the allowlist — the DNS-resolution SSRF path.
SSRF_HOST_UPSTREAM="http://mock-evil/"

cleanup_repos() {
  api_delete "/api/v1/repositories/${LEGIT_KEY}"     >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${SSRF_IP_KEY}"   >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${SSRF_HOST_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

# create_remote_generic KEY URL -> echoes "<status>|<body>" (raw first response).
create_remote_generic() {
  local key="$1" url="$2" body_file status body
  body_file="${WORK_DIR}/create-body.$$"
  local payload
  payload=$(jq -n --arg key "$key" --arg url "$url" \
    '{key:$key, name:$key, format:"generic", repo_type:"remote", upstream_url:$url, is_public:true}')
  status=$(curl -s -o "$body_file" -w '%{http_code}' --max-time 30 \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$payload" "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"
  body=$(cat "$body_file" 2>/dev/null || echo ""); rm -f "$body_file"
  echo "${status}|${body}"
}

# ---------------------------------------------------------------------------
# Half A — #2570 regression guard: legit egress THROUGH the proxy must WORK.
# ---------------------------------------------------------------------------

begin_test "Create legit remote repo (upstream ${LEGIT_UPSTREAM} on allowlisted 172.16/12)"
resp=$(create_remote_generic "$LEGIT_KEY" "$LEGIT_UPSTREAM")
status="${resp%%|*}"; body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  # If the allowlisted-upstream create itself is rejected, the whole legit half
  # is untestable — surface it loudly rather than false-passing.
  fail "legit remote create REJECTED (HTTP ${status}); expected 2xx for an allowlisted 172.16/12 upstream. body=${body:0:200}"
fi

begin_test "A1: test-upstream through the configured egress proxy SUCCEEDS (not 502) [#2570 regression guard]"
tu_body_file="${WORK_DIR}/tu-body.$$"
tu_status=$(curl -s -o "$tu_body_file" -w '%{http_code}' --max-time 40 \
  -X POST -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${LEGIT_KEY}/test-upstream" 2>/dev/null) || tu_status="000"
tu_body=$(cat "$tu_body_file" 2>/dev/null || echo ""); rm -f "$tu_body_file"
if [ "$tu_status" = "200" ] && printf '%s' "$tu_body" | grep -q '"status":"ok"'; then
  pass
elif [ "$tu_status" = "502" ]; then
  fail "#2570 REGRESSION: egress-through-proxy fetch returned 502 (the SSRF DNS guard blocked the configured proxy host). body=${tu_body:0:250}"
else
  fail "expected 200 {status:ok} from test-upstream via proxy, got ${tu_status}. body=${tu_body:0:250}"
fi

begin_test "A2: real proxied GET returns the upstream body bytes (discriminating, not /dev/null)"
dl_body_file="${WORK_DIR}/dl-body.$$"
dl_status=$(curl -s -o "$dl_body_file" -w '%{http_code}' --max-time 40 \
  -H "$(auth_header)" \
  "${BASE_URL}/general/${LEGIT_KEY}/probe.txt" 2>/dev/null) || dl_status="000"
dl_body=$(cat "$dl_body_file" 2>/dev/null || echo ""); rm -f "$dl_body_file"
if [ "$dl_status" = "200" ] && printf '%s' "$dl_body" | grep -q 'DTF-PROXY-EGRESS-OK'; then
  pass
elif [ "$dl_status" -ge 500 ] 2>/dev/null; then
  fail "#2570 REGRESSION: proxied GET failed ${dl_status} (proxy host blocked by SSRF guard). body=${dl_body:0:250}"
else
  fail "expected 200 with upstream marker body, got ${dl_status}. body=${dl_body:0:250}"
fi

# ---------------------------------------------------------------------------
# Half B — SSRF guard still holds (the fix did NOT open a hole).
# A repo whose upstream is a private IP that is NOT the configured proxy host
# must be REFUSED at create time: 400/422, never 2xx (accepted) and never 5xx
# (which would mean it reached the fetch path / was mislabeled as a proxy fail).
# ---------------------------------------------------------------------------

assert_ssrf_refused() {
  local label="$1" key="$2" url="$3"
  begin_test "B: SSRF upstream still REFUSED — ${label} (${url})"
  local resp status body
  resp=$(create_remote_generic "$key" "$url")
  status="${resp%%|*}"; body="${resp#*|}"
  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    api_delete "/api/v1/repositories/${key}" >/dev/null 2>&1 || true
    fail "SSRF HOLE: private upstream '${url}' was ACCEPTED (HTTP ${status}); the proxy exemption must NOT allowlist non-proxy private hosts. body=${body:0:200}"
  elif [ "$status" -ge 500 ] 2>/dev/null; then
    fail "expected 400 for '${url}', got ${status} (5xx suggests it reached the fetch path instead of being refused up-front). body=${body:0:200}"
  else
    fail "expected 400 for '${url}', got ${status}. body=${body:0:200}"
  fi
}

assert_ssrf_refused "IP-literal private (not the proxy)" "$SSRF_IP_KEY"   "$SSRF_IP_UPSTREAM"
assert_ssrf_refused "hostname resolving to a private IP" "$SSRF_HOST_KEY" "$SSRF_HOST_UPSTREAM"

end_suite
