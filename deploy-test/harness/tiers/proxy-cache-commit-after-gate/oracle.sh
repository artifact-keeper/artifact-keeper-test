#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-cache-commit-after-gate/oracle.sh - an inconclusive proxied body
# is not committed to the proxy cache under fail_closed; a vulnerable one is
# =============================================================================
# artifact-keeper 1.12.0: #4514 plan item A2 as adopted ("option (c)"),
# backend PR #5070. serve_scanned_proxy_file now fetches through
# ProxyService::fetch_artifact_with_cache_path_capped_deferred and holds the
# commit of a fresh fill until the scan gate decides:
#   * served (clean, pending, recorded): committed, then served;
#   * 403 scan_blocked: committed as before; readers refuse it from the stored
#     verdict, and the cached copy keeps it listed and rescannable;
#   * 423 under fail_closed (inconclusive): dropped, nothing is cached.
#
# Inconclusive fixtures: archives whose own metadata declares another version
# than the requested coordinate (Maven pom.properties, NuGet .nuspec, Go
# zip entries), which the gate withholds under fail_closed with no verdict.
# Vulnerable fixture: log4j-core 2.14.1.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Green: an image carrying #5070. Red: ak-backend:1.11.9 (every FIX case;
# the controls pass on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

begin_suite "proxy-cache-commit-after-gate"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

MVN="pcg-mvn-${SUF}"   # Maven Remote, fail_closed
NUG="pcg-nug-${SUF}"   # NuGet Remote, fail_closed
GO="pcg-go-${SUF}"     # Go Remote, fail_closed

MVN_LIAR="com/example/dtfscan/dtf-liar/2.0.0/dtf-liar-2.0.0.jar"
LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
NUG_LIAR="dtf.scanliar/2.0.0/dtf.scanliar.2.0.0.nupkg"
GO_LIAR="example.com/dtfscan/liarmod/@v/v2.0.0.zip"

cleanup() {
  local k
  for k in "$MVN" "$NUG" "$GO"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$1" | jq -r '.count // empty' 2>/dev/null; }
# GETs of exactly this upstream file (the mock counts by prefix, so a Maven
# jar's count would include its .sha1 sidecar).
file_hits() {
  local all side
  all=$(hits "$1"); side=$(hits "$1.sha1")
  [ -n "$all" ] && [ -n "$side" ] && echo $(( all - side ))
}

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 -H "$(auth_header)" "$1" 2>/dev/null) || ST="000"
  SCAN=$(grep -i '^x-ak-scan:' "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true)
}
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
# cache_rows key file-name -> proxy-cache catalog rows of that repository for the file
cache_rows() {
  psql_q "SELECT count(*) FROM proxy_cache_artifacts p JOIN repositories r ON r.id=p.repository_id
          WHERE r.key='$1' AND p.path LIKE '%$2'"
}
# listed key file-name -> how many items of the repository's artifact listing name the file
listed() {
  api_get "/api/v1/repositories/$1/artifacts?per_page=200" 2>/dev/null \
    | jq -r --arg f "$2" '[(.items // .)[]? | select((.path // "") | endswith($f))] | length' 2>/dev/null || echo "?"
}
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}
settle() { sleep 3; } # let a background commit (if any) land before reading the catalog

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and the Maven, NuGet and Go fixtures present"
if [ -n "$(golden_sha "maven2/${MVN_LIAR}")" ] && [ -n "$(golden_sha "maven2/${LOG4J}")" ] \
   && [ -n "$(golden_sha "nuget/v3-flatcontainer/${NUG_LIAR}")" ] && [ -n "$(golden_sha "goproxy/${GO_LIAR}")" ]; then
  pass
else
  infra_fail "mock control endpoint ${MOCK} did not answer (or this mock predates the fixtures)"
  end_suite
fi

begin_test "Setup: fail_closed Maven, NuGet and Go Remotes"
ok=1
create_repo "$MVN" maven remote "${UP}/maven2" || ok=0
create_repo "$NUG" nuget remote "${UP}/nuget/v3/index.json" || ok=0
create_repo "$GO" go remote "${UP}/goproxy" || ok=0
a="$(scan_cfg "$MVN" fail_closed) $(scan_cfg "$NUG" fail_closed) $(scan_cfg "$GO" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_closed fail_closed" ]; then
  pass
else
  infra_fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
  end_suite
fi

M="${BASE_URL}/maven"
N="${BASE_URL}/nuget"
G="${BASE_URL}/go"

# ---------------------------------------------------------------------------
# Inconclusive under fail_closed: 423 and not cached
# ---------------------------------------------------------------------------
begin_test "control: a jar whose pom.properties declares another version is withheld under fail_closed (423 scan_pending, no verdict)"
h0=$(file_hits "/maven2/${MVN_LIAR}")
pull "${M}/${MVN}/${MVN_LIAR}"
d=$(golden_sha "maven2/${MVN_LIAR}")
h1=$(file_hits "/maven2/${MVN_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi
settle

begin_test "FIX #4514: the withheld Maven jar is not in the proxy cache (no catalog row, not in the artifact listing)"
c=$(cache_rows "$MVN" "dtf-liar-2.0.0.jar"); l=$(listed "$MVN" "dtf-liar-2.0.0.jar")
if [ "$c" = "0" ] && [ "$l" = "0" ]; then
  pass
else
  fail "catalog rows=${c} listing items=${l} (a cached inconclusive body)"
fi

begin_test "FIX #4514: a re-pull of the withheld Maven jar fetches it from the upstream again and is withheld again (423)"
pull "${M}/${MVN}/${MVN_LIAR}"
h2=$(file_hits "/maven2/${MVN_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -n "$h1" ] && [ -n "$h2" ] \
   && [ "$h1" -gt "${h0:-0}" ] && [ "$h2" -gt "$h1" ] 2>/dev/null; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream jar GETs ${h0:-?} -> ${h1:-?} -> ${h2:-?} (no new GET = answered from the cache)"
fi

begin_test "control: a .nupkg whose .nuspec declares another version is withheld under fail_closed (423 scan_pending)"
nh0=$(hits "/nuget/v3-flatcontainer/${NUG_LIAR}")
pull "${N}/${NUG}/v3/flatcontainer/${NUG_LIAR}"
nh1=$(hits "/nuget/v3-flatcontainer/${NUG_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ]; then
  pass
else
  fail "status=${ST} body=$(snippet)"
fi
settle

begin_test "FIX #4514: the withheld .nupkg is not cached, and a re-pull fetches it from the upstream again (423)"
c=$(cache_rows "$NUG" "dtf.scanliar.2.0.0.nupkg")
pull "${N}/${NUG}/v3/flatcontainer/${NUG_LIAR}"
nh2=$(hits "/nuget/v3-flatcontainer/${NUG_LIAR}")
if [ "$c" = "0" ] && [ "$ST" = "423" ] && [ -n "$nh1" ] && [ -n "$nh2" ] && [ "$nh2" -gt "$nh1" ] 2>/dev/null; then
  pass
else
  fail "catalog rows=${c} second=${ST} upstream GETs ${nh0:-?} -> ${nh1:-?} -> ${nh2:-?}"
fi

begin_test "FIX #4514: a Go module zip that is not the requested version is withheld (423), not cached, and re-fetched on the next pull"
gh0=$(hits "/goproxy/${GO_LIAR}")
pull "${G}/${GO}/${GO_LIAR}"; s1="$ST/$(body_err)"
settle
c=$(cache_rows "$GO" "v2.0.0.zip")
gh1=$(hits "/goproxy/${GO_LIAR}")
pull "${G}/${GO}/${GO_LIAR}"; s2="$ST/$(body_err)"
gh2=$(hits "/goproxy/${GO_LIAR}")
if [ "$s1" = "423/scan_pending" ] && [ "$s2" = "423/scan_pending" ] && [ "$c" = "0" ] \
   && [ -n "$gh2" ] && [ "$gh1" -gt "${gh0:-0}" ] && [ "$gh2" -gt "$gh1" ] 2>/dev/null; then
  pass
else
  fail "first=${s1} second=${s2} catalog rows=${c} upstream GETs ${gh0:-?} -> ${gh1:-?} -> ${gh2:-?}"
fi

# ---------------------------------------------------------------------------
# Vulnerable: 403, stays cached and listed, refused again from the verdict
# ---------------------------------------------------------------------------
begin_test "control: log4j-core-2.14.1.jar through the fail_closed Remote is 403 scan_blocked with a 'vulnerable' verdict"
vh0=$(file_hits "/maven2/${LOG4J}")
pull "${M}/${MVN}/${LOG4J}"
D=$(golden_sha "maven2/${LOG4J}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$D")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$D")'"
fi
settle
vh1=$(file_hits "/maven2/${LOG4J}")

begin_test "control: the vulnerable jar stays in the proxy cache (one catalog row with its digest)"
c=$(psql_q "SELECT count(*) FROM proxy_cache_artifacts p JOIN repositories r ON r.id=p.repository_id
            WHERE r.key='${MVN}' AND p.path LIKE '%log4j-core-2.14.1.jar' AND p.checksum_sha256='${D}'")
if [ "$c" = "1" ]; then pass; else fail "catalog rows with the jar's digest: '${c}'"; fi

begin_test "control: a re-pull of the vulnerable jar is 403 again, refused from the stored verdict without an upstream fetch"
pull "${M}/${MVN}/${LOG4J}"
vh2=$(file_hits "/maven2/${LOG4J}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ -n "$vh2" ] && [ "$vh2" = "$vh1" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream jar GETs ${vh0:-?} -> ${vh1:-?} -> ${vh2:-?}"
fi

begin_test "1.12.0 #4777, kept by #4514: GET /api/v1/security/proxy-blocked lists the cached vulnerable jar (endpoint absent on 1.11.x)"
got=$(api_get "/api/v1/security/proxy-blocked?repository=${MVN}" 2>/dev/null \
  | jq -r --arg d "$D" '[(.items // [])[] | select(.checksum_sha256==$d)][0].path // empty' 2>/dev/null || true)
if [ "$got" = "$LOG4J" ]; then pass; else fail "proxy-blocked item path='${got}'"; fi

begin_test "1.12.0 #4510, kept by #4514: GET /api/v1/admin/holds/policy-blocks lists the cached vulnerable jar as a proxy-cache block (endpoint absent on 1.11.x)"
got=$(api_get "/api/v1/admin/holds/policy-blocks?repository_key=${MVN}" 2>/dev/null \
  | jq -r --arg d "$D" '[(.items // [])[] | select(.checksum_sha256==$d)][0] | [.source, .path] | join("|")' 2>/dev/null || true)
if [ "$got" = "proxy-cache|${LOG4J}" ]; then pass; else fail "policy-blocks item '${got}'"; fi

end_suite
