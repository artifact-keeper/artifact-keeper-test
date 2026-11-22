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

# ---------------------------------------------------------------------------
# Half C — artifact-keeper#6359: an ALL_PROXY host the matcher never uses is
# not exempt from the connect-time SSRF filter.
# profiles/proxy.squid-allproxy-shadowed.yml sets ALL_PROXY=http://mock-evil:80
# while HTTP_PROXY/HTTPS_PROXY name squid (so ALL_PROXY routes nothing), and
# lists mock-evil in NO_PROXY (so a request for it goes direct). A Helm Remote
# whose index (served by mock-upstream, through squid) names an absolute chart
# URL on http://mock-evil/ fetches that URL as given; only the connect-time
# resolver stands between it and mock-evil's private address.
# ---------------------------------------------------------------------------
HELM_KEY="dtf-proxy-helm-shadow-${RUN_ID}"
HELM_CHART="dtfshadow-1.0.0.tgz"
EVIL_CTR="ak-dtf${DTF_SLOT}-mock-evil"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
add_exit_handler "api_delete /api/v1/repositories/${HELM_KEY} >/dev/null 2>&1 || true"
# GETs for the chart that reached mock-evil (nginx logs each request to stdout).
evil_hits() { docker logs "$EVIL_CTR" 2>&1 | grep -c "GET /${HELM_CHART}" || true; }

begin_test "CONTROL: a Helm Remote over the squid-routed mock-upstream reads its index (the chart URL names mock-evil)"
payload=$(jq -n --arg key "$HELM_KEY" --arg url "http://172.31.${DTF_SLOT}.50/helm" \
  '{key:$key, name:$key, format:"helm", repo_type:"remote", upstream_url:$url, is_public:true}')
c_status=$(curl -s -o "${WORK_DIR}/helm-create" -w '%{http_code}' --max-time 30 -X POST \
  -H "$(auth_header)" -H "Content-Type: application/json" -d "$payload" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || c_status="000"
i_status=$(curl -s -o "${WORK_DIR}/helm-index" -w '%{http_code}' --max-time 40 \
  -H "$(auth_header)" "${BASE_URL}/helm/${HELM_KEY}/index.yaml" 2>/dev/null) || i_status="000"
if ! docker exec "$BACKEND_CTR" printenv ALL_PROXY 2>/dev/null | grep -q 'mock-evil'; then
  infra_fail "the backend's ALL_PROXY does not name mock-evil: profile proxy.squid-allproxy-shadowed not applied"
elif [ "${c_status:0:1}" != "2" ]; then
  fail "Helm Remote create answered ${c_status}: $(head -c 200 "${WORK_DIR}/helm-create")"
elif [ "$i_status" = "200" ] && grep -q 'dtfshadow' "${WORK_DIR}/helm-index"; then
  pass
else
  fail "the Helm Remote's index answered ${i_status} without the dtfshadow chart: $(head -c 200 "${WORK_DIR}/helm-index")"
fi

begin_test "FIX #6359: a chart URL on the NO_PROXY host that only a shadowed ALL_PROXY names is refused by the SSRF resolver, and mock-evil is never contacted"
hits_before=$(evil_hits)
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
d_status=$(curl -s -o "${WORK_DIR}/helm-chart" -w '%{http_code}' --max-time 40 \
  -H "$(auth_header)" "${BASE_URL}/helm/${HELM_KEY}/charts/${HELM_CHART}" 2>/dev/null) || d_status="000"
sleep 1
hits_after=$(evil_hits)
blocked=$(docker logs --since "$since" "$BACKEND_CTR" 2>&1 | grep 'SSRF DNS guard blocked' | grep -c 'mock-evil' || true)
detail="chart GET -> ${d_status}; mock-evil chart GETs ${hits_before} -> ${hits_after}; resolver refusals of mock-evil logged: ${blocked}"
echo "   ${detail}"
if grep -q 'DTF-EVIL-INTERNAL' "${WORK_DIR}/helm-chart" 2>/dev/null || [ "$hits_after" -gt "$hits_before" ]; then
  fail "SSRF: the backend connected to mock-evil (a private address outside the allowlist) because the unused ALL_PROXY host was exempt. ${detail}"
elif [ "$d_status" = "200" ]; then
  fail "the chart GET answered 200 without reaching mock-evil; expected a refusal. ${detail}"
elif [ "$blocked" -lt 1 ]; then
  fail "the chart GET answered ${d_status} but the resolver logged no refusal of mock-evil, so the request may not have reached it at all. ${detail}"
else
  pass
fi

end_suite
