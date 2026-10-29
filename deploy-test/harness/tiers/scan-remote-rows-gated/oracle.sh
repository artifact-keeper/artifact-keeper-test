#!/usr/bin/env bash
# =============================================================================
# tiers/scan-remote-rows-gated/oracle.sh - artifacts rows a scanning Remote
# holds go through the scan gate on the Go, RubyGems, Composer, Pub,
# CocoaPods and Swift routes
# =============================================================================
# artifact-keeper 1.12.0: #4514 plan item A3 (backend PR #5071). A Remote can
# hold `artifacts` rows of its own. The format routes look a row up first and,
# when one exists, serve it from storage; before #5071 they did so without
# the scan gate, even when the Remote scans on proxy under fail_closed. Now
# proxy_helpers::open_stored_row / serve_local_artifact_gated run the stored
# bytes through gate_proxy_scan_serve with the format's own identity rule.
#
# Seeding. For each format an unscanned seed Remote pulls the fixtures from
# the mock, so their blobs land in the proxy cache. The oracle then records
# an artifacts row per fixture in two target Remotes:
#   T_*  scan_on_proxy, fail_closed
#   O_*  no scanning (control)
# pointing at the cached blob (`proxy-cache/...` keys resolve at the shared
# storage root, so any repository's storage handle reads them). Both target
# Remotes have an upstream the mock does not serve (`/dtf-rows-none/...`);
# the oracle asserts the mock saw no request there, so each answer is the
# stored row's, not a proxied fetch.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Green: an image carrying #5071. Red: ak-backend:1.11.9 (every FIX case;
# the controls pass on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

begin_suite "scan-remote-rows-gated"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
NONE="/dtf-rows-none"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
REF="0123456789abcdef0123456789abcdef01234567"

# One line per fixture:
#   id|format|route|upstream dir|golden path (mock)|request path|name|version|row path|row checksum override
SPECS=(
  "go-vuln|go|go|goproxy|goproxy/example.com/dtfscan/vulnmod/@v/v1.0.0.zip|example.com/dtfscan/vulnmod/@v/v1.0.0.zip|example.com/dtfscan/vulnmod|v1.0.0|example.com/dtfscan/vulnmod/@v/v1.0.0.zip|"
  "go-clean|go|go|goproxy|goproxy/example.com/dtfscan/cleanmod/@v/v1.0.0.zip|example.com/dtfscan/cleanmod/@v/v1.0.0.zip|example.com/dtfscan/cleanmod|v1.0.0|example.com/dtfscan/cleanmod/@v/v1.0.0.zip|"
  "go-liar|go|go|goproxy|goproxy/example.com/dtfscan/liarmod/@v/v2.0.0.zip|example.com/dtfscan/liarmod/@v/v2.0.0.zip|example.com/dtfscan/liarmod|v2.0.0|example.com/dtfscan/liarmod/@v/v2.0.0.zip|"
  "gem-vuln|rubygems|gems|rubygems|rubygems/gems/rack-2.0.7.gem|gems/rack-2.0.7.gem|rack|2.0.7|gems/rack-2.0.7.gem|"
  "gem-clean|rubygems|gems|rubygems|rubygems/gems/dtf-scanclean-1.0.0.gem|gems/dtf-scanclean-1.0.0.gem|dtf-scanclean|1.0.0|gems/dtf-scanclean-1.0.0.gem|"
  "gem-liar|rubygems|gems|rubygems|rubygems/gems/dtf-scanliar-2.0.0.gem|gems/dtf-scanliar-2.0.0.gem|dtf-scanliar|2.0.0|gems/dtf-scanliar-2.0.0.gem|"
  "cmp-vuln|composer|composer|composer|composer/zipball/vulnpkg.zip|dist/dtf/vulnpkg/1.0.0/${REF}.zip|dtf/vulnpkg|1.0.0|dist/dtf/vulnpkg/1.0.0/${REF}.zip|${REF}"
  "cmp-clean|composer|composer|composer|composer/zipball/cleanpkg.zip|dist/dtf/cleanpkg/1.0.0/${REF}.zip|dtf/cleanpkg|1.0.0|dist/dtf/cleanpkg/1.0.0/${REF}.zip|${REF}"
  "pub-vuln|pub|pub|pub|pub/packages/http/versions/0.12.0.tar.gz|packages/http/versions/0.12.0.tar.gz|http|0.12.0|packages/http/versions/0.12.0.tar.gz|"
  "pub-clean|pub|pub|pub|pub/packages/dtf_scanclean/versions/1.0.0.tar.gz|packages/dtf_scanclean/versions/1.0.0.tar.gz|dtf_scanclean|1.0.0|packages/dtf_scanclean/versions/1.0.0.tar.gz|"
  "pod-vuln|cocoapods|cocoapods|cocoapods|cocoapods/pods/DtfVulnPod-1.0.0.tar.gz|pods/DtfVulnPod-1.0.0.tar.gz|DtfVulnPod|1.0.0|pods/DtfVulnPod-1.0.0.tar.gz|"
  "pod-clean|cocoapods|cocoapods|cocoapods|cocoapods/pods/DtfCleanPod-1.0.0.tar.gz|pods/DtfCleanPod-1.0.0.tar.gz|DtfCleanPod|1.0.0|pods/DtfCleanPod-1.0.0.tar.gz|"
  "sw-vuln|swift|swift|swift|swift/dtf/vulnpkg/1.0.0.zip|dtf/vulnpkg/1.0.0.zip|dtf.vulnpkg|1.0.0|dtf/vulnpkg/1.0.0.zip|"
  "sw-clean|swift|swift|swift|swift/dtf/cleanpkg/1.0.0.zip|dtf/cleanpkg/1.0.0.zip|dtf.cleanpkg|1.0.0|dtf/cleanpkg/1.0.0.zip|"
)
FORMATS="go rubygems composer pub cocoapods swift"

short() { case "$1" in rubygems) echo gem;; composer) echo cmp;; cocoapods) echo pod;; swift) echo sw;; *) echo "$1";; esac; }
seed_key() { echo "srg-s$(short "$1")-${SUF}"; }
gate_key() { echo "srg-t$(short "$1")-${SUF}"; }
off_key()  { echo "srg-o$(short "$1")-${SUF}"; }

cleanup() {
  local f
  for f in $FORMATS; do
    for k in "$(seed_key "$f")" "$(gate_key "$f")" "$(off_key "$f")"; do
      api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
    done
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$1" | jq -r '.count // empty' 2>/dev/null; }

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 160 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}
spec() { # id -> sets S_FMT S_ROUTE S_UPDIR S_GOLD S_REQ S_NAME S_VER S_PATH S_SUM
  local line
  for line in "${SPECS[@]}"; do
    if [ "${line%%|*}" = "$1" ]; then
      IFS='|' read -r _ S_FMT S_ROUTE S_UPDIR S_GOLD S_REQ S_NAME S_VER S_PATH S_SUM <<<"$line"
      return 0
    fi
  done
  return 1
}
# gate_pull id -> pulls the fixture's coordinate through the fail_closed target
gate_pull() { spec "$1"; pull "${BASE_URL}/${S_ROUTE}/$(gate_key "$S_FMT")/${S_REQ}"; }
off_pull()  { spec "$1"; pull "${BASE_URL}/${S_ROUTE}/$(off_key "$S_FMT")/${S_REQ}"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and every fixture present"
missing=""
for line in "${SPECS[@]}"; do
  spec "${line%%|*}"
  [ -n "$(golden_sha "$S_GOLD")" ] || missing="${missing} ${S_GOLD}"
done
if [ -z "$missing" ]; then
  pass
else
  infra_fail "mock control endpoint ${MOCK} did not answer for:${missing}"
  end_suite
fi

begin_test "Setup: per format an unscanned seed Remote, a fail_closed target Remote and an unscanned target Remote"
ok=1; acts=""
for f in $FORMATS; do
  spec "$(short "$f")-vuln"
  create_repo "$(seed_key "$f")" "$f" remote "${UP}/${S_UPDIR}" || ok=0
  create_repo "$(gate_key "$f")" "$f" remote "${UP}${NONE}/${S_UPDIR}" || ok=0
  create_repo "$(off_key "$f")" "$f" remote "${UP}${NONE}/${S_UPDIR}" || ok=0
  acts="${acts}$(scan_cfg "$(gate_key "$f")" fail_closed) "
done
if [ "$ok" = 1 ] && [ "$acts" = "fail_closed fail_closed fail_closed fail_closed fail_closed fail_closed " ]; then
  pass
else
  infra_fail "repo setup failed (ok=${ok}) or actions not persisted: '${acts}'"
  end_suite
fi

begin_test "Setup: each fixture pulled through its seed Remote and recorded as an artifacts row in both target Remotes"
err=""
for line in "${SPECS[@]}"; do
  id="${line%%|*}"; spec "$id"
  pull "${BASE_URL}/${S_ROUTE}/$(seed_key "$S_FMT")/${S_REQ}"
  gold=$(golden_sha "$S_GOLD")
  if [ "$ST" != "200" ] || [ "$BSHA" != "$gold" ]; then err="${err} seed-pull:${id}:${ST}"; continue; fi
  ck=""
  for _ in $(seq 1 10); do
    ck=$(psql_q "SELECT p.storage_key||'|'||p.size_bytes FROM proxy_cache_artifacts p JOIN repositories r ON r.id=p.repository_id
                 WHERE r.key='$(seed_key "$S_FMT")' AND p.checksum_sha256='${gold}' LIMIT 1")
    [ -n "$ck" ] && break
    sleep 1
  done
  [ -n "$ck" ] || { err="${err} no-cache-row:${id}"; continue; }
  skey="${ck%|*}"; size="${ck##*|}"
  sum="${S_SUM:-$gold}"
  for tk in "$(gate_key "$S_FMT")" "$(off_key "$S_FMT")"; do
    rid=$(psql_q "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key)
                  SELECT id, '${S_PATH}', '${S_NAME}', '${S_VER}', ${size}, '${sum}', 'application/octet-stream', '${skey}'
                  FROM repositories WHERE key='${tk}' RETURNING id")
    [ -n "$rid" ] || err="${err} insert:${id}:${tk}"
  done
done
NONE_H0=$(hits "$NONE")
if [ -z "$err" ]; then
  pass
else
  infra_fail "seeding failed:${err}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: the unscanned target Remotes serve every seeded row from storage (200, fixture bytes, no X-AK-Scan)"
bad=""
for line in "${SPECS[@]}"; do
  id="${line%%|*}"; off_pull "$id"
  [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$(golden_sha "$S_GOLD")" ] || bad="${bad} ${id}=${ST}/${SCAN}"
done
if [ -z "$bad" ]; then pass; else fail "rows not served as stored:${bad}"; fi

begin_test "control: a clean row is served through the fail_closed Remotes (200, fixture bytes) on all six routes"
bad=""
for f in $FORMATS; do
  id="$(short "$f")-clean"; gate_pull "$id"
  [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "$S_GOLD")" ] || bad="${bad} ${id}=${ST}:$(snippet)"
done
if [ -z "$bad" ]; then pass; else fail "clean rows not served:${bad}"; fi

# ---------------------------------------------------------------------------
# #5071: the stored rows go through the gate
# ---------------------------------------------------------------------------
for f in $FORMATS; do
  id="$(short "$f")-vuln"
  begin_test "FIX #4514: a vulnerable ${f} row in the fail_closed Remote is 403 scan_blocked with a 'vulnerable' verdict (was 200 unscanned)"
  gate_pull "$id"
  d=$(golden_sha "$S_GOLD")
  if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
    pass
  else
    fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
  fi
done

begin_test "FIX #4514: the clean rows are graded and served with X-AK-Scan: clean on all six routes (was no header)"
bad=""
for f in $FORMATS; do
  id="$(short "$f")-clean"; gate_pull "$id"
  d=$(golden_sha "$S_GOLD")
  [ "$ST/$SCAN" = "200/clean" ] && [ "$(verdict_of "$d")" = "clean" ] || bad="${bad} ${id}=${ST}/${SCAN}/verdict:$(verdict_of "$d")"
done
if [ -z "$bad" ]; then pass; else fail "${bad}"; fi

begin_test "FIX #4514: a second pull of a vulnerable row is refused again from the stored verdict (403, one verdict row)"
gate_pull "go-vuln"
d=$(golden_sha "$S_GOLD")
n=$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='${d}'")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$n" = "1" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict rows=${n}"
fi

for id in go-liar gem-liar; do
  spec "$id"
  begin_test "FIX #4514: a ${S_FMT} row whose archive declares another version is withheld under fail_closed (423, no verdict row)"
  gate_pull "$id"
  d=$(golden_sha "$S_GOLD")
  if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
    pass
  else
    fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
  fi
done

begin_test "control: the target Remotes' upstream got no request (every answer above came from the stored row)"
NONE_H1=$(hits "$NONE")
if [ -n "$NONE_H1" ] && [ "$NONE_H1" = "${NONE_H0:-x}" ] && [ "$NONE_H1" = "0" ]; then
  pass
else
  fail "GETs under ${NONE}: ${NONE_H0:-?} -> ${NONE_H1:-?}"
fi

end_suite
