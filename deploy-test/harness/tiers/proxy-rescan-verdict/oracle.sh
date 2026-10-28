#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-rescan-verdict/oracle.sh - a proxy rescan that cannot grade a
# package archive leaves the stored verdict unchanged
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (mock_scan_upstream.py, shared with scan-on-proxy-maven-nuget):
# Newtonsoft.Json 12.0.1 (GHSA-5crp-9r3c-p9vr, high) and log4j-core 2.14.1
# (critical). Each Remote is rescanned once: the rescan cooldown is per
# repository.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-rescan-verdict"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

NUG="rsv-nug-${SUF}"   # NuGet Remote, scan_on_proxy, fail_closed
MVN="rsv-mvn-${SUF}"   # Maven Remote, scan_on_proxy, fail_closed (control)

LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1"
NJ_NUPKG="newtonsoft.json/12.0.1/newtonsoft.json.12.0.1.nupkg"

cleanup() {
  local k
  for k in "$NUG" "$MVN"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"; }
cached_path() { # repo-key suffix -> the proxy cache path ending in suffix
  psql_q "SELECT p.path FROM proxy_cache_artifacts p JOIN repositories r ON r.id = p.repository_id WHERE r.key='$1' AND p.path LIKE '%$2' ORDER BY length(p.path) LIMIT 1"
}

BODY="${WORK_DIR}/body"
pull() {
  local hdr="${WORK_DIR}/hdr"
  ST=$(curl -s -D "$hdr" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
}
RBODY="${WORK_DIR}/rescan"
rescan() { # key path -> sets RST and RBODY
  RST=$(curl -s -o "$RBODY" -w '%{http_code}' --max-time 150 -X POST \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg p "$2" '{path:$p}')" \
    "${BASE_URL}/api/v1/repositories/$1/security/proxy-scans/rescan" 2>/dev/null) || RST="000"
}
rjson() { jq -r "$1 // empty" "$RBODY" 2>/dev/null; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null; }
snippet() { head -c 200 "$1" | tr -c '[:print:]' '.'; }
scan_cfg() {
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

begin_test "Setup: mock reachable; NuGet and Maven Remotes with fail_closed scan-on-proxy"
ok=1
[ -n "$(golden_sha "nuget/v3-flatcontainer/${NJ_NUPKG}")" ] || ok=0
create_repo "$NUG" nuget remote "${UP}/nuget/v3/index.json" || ok=0
create_repo "$MVN" maven remote "${UP}/maven2" || ok=0
a="$(scan_cfg "$NUG" fail_closed)$(scan_cfg "$MVN" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closedfail_closed" ]; then
  pass
else
  infra_fail "setup failed (ok=${ok}, actions '${a}')"; end_suite
fi

N="${BASE_URL}/nuget"
M="${BASE_URL}/maven"
NJ_D=$(golden_sha "nuget/v3-flatcontainer/${NJ_NUPKG}")
L4_D=$(golden_sha "maven2/${LOG4J}.jar")

begin_test "control: the fail_closed pull of Newtonsoft.Json 12.0.1 is 403 and records a vulnerable verdict"
pull "${N}/${NUG}/v3/flatcontainer/${NJ_NUPKG}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$NJ_D")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} body=$(snippet "$BODY") verdict='$(verdict_of "$NJ_D")'"
fi

NJ_PATH=$(cached_path "$NUG" ".nupkg")
begin_test "control: the package is in the Remote's proxy cache catalog"
if [ -n "$NJ_PATH" ]; then pass; else fail "no cached .nupkg row for ${NUG}"; fi

begin_test "FIX: a rescan of the cached .nupkg is inconclusive (503 RESCAN_SCAN_FAILED), not clean"
rescan "$NUG" "$NJ_PATH"
if [ "$RST" = "503" ] && [ "$(rjson .code)" = "RESCAN_SCAN_FAILED" ]; then
  pass
else
  fail "rescan ${NJ_PATH}: HTTP ${RST} state='$(rjson .state)' package_count='$(rjson .package_count)' body=$(snippet "$RBODY")"
fi

begin_test "FIX: the stored verdict for the .nupkg digest is still vulnerable"
v=$(verdict_of "$NJ_D")
if [ "$v" = "vulnerable" ]; then pass; else fail "verdict='${v}'"; fi

begin_test "FIX: the next fail_closed pull of the package is still 403 scan_blocked"
pull "${N}/${NUG}/v3/flatcontainer/${NJ_NUPKG}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} X-AK-Scan='${SCAN}' body=$(snippet "$BODY")"
fi

begin_test "control: log4j-core-2.14.1.jar is 403 under fail_closed"
pull "${M}/${MVN}/${LOG4J}.jar"
if [ "$ST" = "403" ] && [ "$(verdict_of "$L4_D")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} verdict='$(verdict_of "$L4_D")'"
fi

L4_PATH=$(cached_path "$MVN" ".jar")
begin_test "control: a rescan of the cached jar (which catalogs itself) grades it vulnerable again"
rescan "$MVN" "$L4_PATH"
if [ "$RST" = "200" ] && [ "$(rjson .state)" = "vulnerable" ] && [ "$(verdict_of "$L4_D")" = "vulnerable" ]; then
  pass
else
  fail "rescan ${L4_PATH}: HTTP ${RST} body=$(snippet "$RBODY")"
fi

end_suite
