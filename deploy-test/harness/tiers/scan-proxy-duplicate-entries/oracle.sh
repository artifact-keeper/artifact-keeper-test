#!/usr/bin/env bash
# =============================================================================
# tiers/scan-proxy-duplicate-entries/oracle.sh - a proxied package archive
# with two entries at its manifest's path is not established by the
# scan-on-proxy gate
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-dup-entries` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (mock_dup_entries.py), per format: `dtf-dup` 1.0.0 carries its
# manifest twice, one copy naming dtf-dup 1.0.0 and the other another package;
# `dtf-single` 1.0.0 carries it once.
#
# Green: the fixed main and 1.11.x line images. Red: ak-backend:1.11.8 (every
# FIX case; every control passes on both).
# =============================================================================
set -uo pipefail
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scan-proxy-duplicate-entries"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.73"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

NPM="spd-npm-${SUF}"
MVN="spd-mvn-${SUF}"
NUG="spd-nug-${SUF}"
CRG="spd-crg-${SUF}"
CND="spd-cnd-${SUF}"

cleanup() {
  local k
  for k in "$NPM" "$MVN" "$NUG" "$CRG" "$CND"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
rows_for() { psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='$1'"; }

BODY="${WORK_DIR}/body"
pull() {
  local hdr="${WORK_DIR}/hdr"
  ST=$(curl -s -D "$hdr" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }

scan_cfg() { # key -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed"}' 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

# Format table: label | repo | format | upstream base | client path prefix |
# dup path (client) | dup path (mock) | single path (client) | single (mock)
CASES=(
  "npm|${NPM}|npm|${UP}/npm|/npm/${NPM}|dtf-dup/-/dtf-dup-1.0.0.tgz|npm/dtf-dup/-/dtf-dup-1.0.0.tgz|dtf-single/-/dtf-single-1.0.0.tgz|npm/dtf-single/-/dtf-single-1.0.0.tgz"
  "maven|${MVN}|maven|${UP}/maven2|/maven/${MVN}|org/dtf/dup/dtf-dup/1.0.0/dtf-dup-1.0.0.jar|maven2/org/dtf/dup/dtf-dup/1.0.0/dtf-dup-1.0.0.jar|org/dtf/dup/dtf-single/1.0.0/dtf-single-1.0.0.jar|maven2/org/dtf/dup/dtf-single/1.0.0/dtf-single-1.0.0.jar"
  "nuget|${NUG}|nuget|${UP}/nuget/v3/index.json|/nuget/${NUG}/v3/flatcontainer|dtf.dup/1.0.0/dtf.dup.1.0.0.nupkg|nuget/v3-flatcontainer/dtf.dup/1.0.0/dtf.dup.1.0.0.nupkg|dtf.single/1.0.0/dtf.single.1.0.0.nupkg|nuget/v3-flatcontainer/dtf.single/1.0.0/dtf.single.1.0.0.nupkg"
  "cargo|${CRG}|cargo|${UP}/cargo|/cargo/${CRG}|api/v1/crates/dtf-dup/1.0.0/download|cargo/api/v1/crates/dtf-dup/1.0.0/download|api/v1/crates/dtf-single/1.0.0/download|cargo/api/v1/crates/dtf-single/1.0.0/download"
  "conda|${CND}|conda|${UP}/conda|/conda/${CND}|noarch/dtf-dup-1.0.0-0.tar.bz2|conda/noarch/dtf-dup-1.0.0-0.tar.bz2|noarch/dtf-single-1.0.0-0.tar.bz2|conda/noarch/dtf-single-1.0.0-0.tar.bz2"
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and fixtures present"
missing=""
for c in "${CASES[@]}"; do
  IFS='|' read -r label _ _ _ _ _ dup_m _ single_m <<<"$c"
  [ -n "$(golden_sha "$dup_m")" ] && [ -n "$(golden_sha "$single_m")" ] || missing+="${label} "
done
if [ -z "$missing" ]; then
  pass
else
  infra_fail "mock control endpoint ${MOCK} is missing fixtures" "$missing"
  end_suite
fi

begin_test "Setup: one fail_closed scan-on-proxy Remote per format"
err=""
for c in "${CASES[@]}"; do
  IFS='|' read -r label repo fmt up _ _ _ _ _ <<<"$c"
  create_repo "$repo" "$fmt" "remote" "$up" || err+="create ${label}; "
  [ "$(scan_cfg "$repo")" = "fail_closed" ] || err+="scan config ${label}; "
done
if [ -z "$err" ]; then
  pass
else
  infra_fail "repository setup failed" "$err"
  end_suite
fi

# ---------------------------------------------------------------------------
# Per format: control, then the duplicated manifest
# ---------------------------------------------------------------------------
for c in "${CASES[@]}"; do
  IFS='|' read -r label repo _ _ prefix dup_c dup_m single_c single_m <<<"$c"

  begin_test "control (${label}): the package with one manifest is graded and served (200, X-AK-Scan: clean)"
  pull "${BASE_URL}${prefix}/${single_c}"
  want=$(golden_sha "$single_m")
  if [ "$ST" = "200" ] && [ "$SCAN" = "clean" ] && [ "$BSHA" = "$want" ]; then
    pass
  else
    fail "status=${ST} scan='${SCAN}' body=$(snippet)"
  fi

  begin_test "FIX (${label}): a package with two entries at its manifest path is withheld under fail_closed (423 scan_pending)"
  pull "${BASE_URL}${prefix}/${dup_c}"
  if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ]; then
    pass
  else
    fail "status=${ST} scan='${SCAN}' body=$(snippet) (200 clean means the gate graded one copy of the manifest and served the other)"
  fi

  begin_test "FIX (${label}): nothing is scanned or recorded for that package's digest"
  d=$(golden_sha "$dup_m")
  n=$(rows_for "$d")
  if [ "$n" = "0" ]; then
    pass
  else
    fail "digest ${d}: ${n:-?} proxy_scan_results rows"
  fi
done

end_suite
