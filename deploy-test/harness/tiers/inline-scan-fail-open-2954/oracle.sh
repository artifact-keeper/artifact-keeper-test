#!/usr/bin/env bash
# =============================================================================
# tiers/inline-scan-fail-open-2954/oracle.sh — fail-open is loud, then blocks
# =============================================================================
# #2954 Part 4: fail-open (default) serves the first pull of an unknown digest
# immediately with `X-AK-Scan: pending` (never a silent #1274 serve) while an
# async Grype scan populates the digest-keyed verdict; the NEXT pull of that
# digest is blocked (403) once the vulnerable verdict lands.
#
# run.sh has stood up `storage.filesystem scanners.trivy` and exported BASE_URL,
# ADMIN_USER, ADMIN_PASS, RUN_ID, COMMON_SH, DTF_SLOT, DB_CONTAINER. The probe
# wheel is pulled from pypi.org (NEEDS_INTERNET).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "inline-scan-fail-open-2954"
auth_admin
setup_workdir

REPO_KEY="dtf-pypi-failopen-${RUN_ID}"
UPSTREAM="https://pypi.org"
# A distinct CVE wheel from the fail-closed tier so verdict state does not
# collide when both tiers share a slot's DB.
CVE_WHEEL="urllib3-1.24-py2.py3-none-any.whl"
CVE_PROJECT="urllib3"

cleanup() { api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup"

pull() { # <project> <wheel> -> "<status>|<x-ak-scan>"
  local hdr="${WORK_DIR}/h.$$" st scan
  st=$(curl -s -D "$hdr" -o /dev/null -w '%{http_code}' --max-time 90 \
    "${BASE_URL}/pypi/${REPO_KEY}/simple/$1/$2" 2>/dev/null) || st="000"
  scan=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1)
  rm -f "$hdr"; echo "${st}|${scan}"
}

vulnerable_rows() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -t -A \
    -c "SELECT count(*) FROM proxy_scan_results WHERE verdict='vulnerable';" 2>/dev/null | tr -d '[:space:]'
}

# ---------------------------------------------------------------------------
# Setup: remote PyPI repo over pypi.org, scan-on-proxy, fail_open (default).
# ---------------------------------------------------------------------------
begin_test "Setup: create remote PyPI repo over ${UPSTREAM}"
if create_repo "$REPO_KEY" "pypi" "remote" "$UPSTREAM"; then pass; else fail "create remote pypi repo failed"; end_suite; fi

begin_test "Setup: enable scan + scan_on_proxy, proxy_scan_action=fail_open"
resp=$(api_put "/api/v1/repositories/${REPO_KEY}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_open","block_on_policy_violation":true}' 2>/dev/null)
if [ "$(printf '%s' "$resp" | jq -r '.proxy_scan_action' 2>/dev/null)" = "fail_open" ]; then
  pass
else
  fail "security config did not persist fail_open: ${resp:0:200}"
fi

BEFORE=$(vulnerable_rows); [ -n "$BEFORE" ] || BEFORE=0

# ---------------------------------------------------------------------------
# Discriminating assertions.
# ---------------------------------------------------------------------------
begin_test "#2954: fail-open FIRST pull of ${CVE_WHEEL} serves 200 with X-AK-Scan: pending"
r=$(pull "$CVE_PROJECT" "$CVE_WHEEL"); st="${r%%|*}"; scan="${r#*|}"
if [ "$st" = "200" ] && [ "$scan" = "pending" ]; then
  pass
else
  fail "fail-open first pull must be 200 + X-AK-Scan: pending, got status=${st} scan='${scan}' (pre-#2954 serves 200 with no header = silent unscanned serve)"
fi

begin_test "#2954: async Grype scan lands a 'vulnerable' verdict for the digest"
ok=0
for _ in $(seq 1 20); do
  now=$(vulnerable_rows); [ -n "$now" ] || now=0
  if [ "$now" -gt "$BEFORE" ] 2>/dev/null; then ok=1; break; fi
  sleep 2
done
if [ "$ok" = "1" ]; then pass; else fail "async fail-open scan never recorded a vulnerable verdict"; fi

begin_test "#2954: fail-open SECOND pull is now BLOCKED (403)"
r=$(pull "$CVE_PROJECT" "$CVE_WHEEL"); st="${r%%|*}"
if [ "$st" = "403" ]; then
  pass
else
  fail "second pull must be 403 once the async verdict landed, got ${st}"
fi

end_suite
