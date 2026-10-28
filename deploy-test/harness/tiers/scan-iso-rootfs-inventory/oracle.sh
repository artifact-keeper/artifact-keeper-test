#!/usr/bin/env bash
# =============================================================================
# tiers/scan-iso-rootfs-inventory/oracle.sh - package inventory of ISO live
# media, and an explicit not_cataloged for an ISO whose rootfs is unreadable
# =============================================================================
# artifact-keeper 1.12.0:
#   #1966  an ISO9660 image is detected by its volume descriptor, its embedded
#          squashfs rootfs is located (Rock Ridge names), the rootfs package
#          database is extracted with unsquashfs under the scan-workspace
#          ceilings, and the scan inventories and grades it. An image whose
#          rootfs cannot be read is not_cataloged, inventory_status 'partial',
#          never a clean grade.
#
# run.sh has stood up `storage.filesystem` and exported BASE_URL, ADMIN_PASS,
# RUN_ID, DTF_SLOT, DB_CONTAINER, COMMON_SH. The two ISOs are written by
# fixtures/make_fixtures.py. Scans run the backend image's bundled Grype.
#
# Green: an image carrying #1966. Red: ak-backend:1.11.7 (every FIX case;
# the controls pass on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "scan-iso-rootfs-inventory"
auth_admin
setup_workdir
require_cmd python3

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
FX="${WORK_DIR}/fx"

R_LIVE="iso-live-${SUF}"
R_BAD="iso-bad-${SUF}"
P_LIVE="media/debian-live-${SUF}.iso"
P_BAD="media/broken-live-${SUF}.iso"

cleanup() {
  local k
  for k in "$R_LIVE" "$R_BAD"; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
put() {
  curl -s -o "${WORK_DIR}/put.out" -w '%{http_code}' --max-time 120 -X PUT -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" --data-binary "@$1" "$2" 2>/dev/null || echo 000
}
# The newest completed grype row of REPO_KEY/PATH: its id, completeness,
# reason and inventory status, '|'-separated.
grype_row() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT s.id || '|' || coalesce(s.scan_completeness,'') || '|' || coalesce(s.scan_completeness_reason,'')
            || '|' || coalesce(s.inventory_status,'') || '|' || s.findings_count
     FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id JOIN repositories r ON r.id = a.repository_id
     WHERE r.key = '$1' AND a.path = '$2' AND s.scan_type = 'grype' AND s.status = 'completed'
     ORDER BY s.completed_at DESC LIMIT 1" 2>/dev/null | head -1 || true
}
has_grype_row() { [ -n "$(grype_row "$1" "$2")" ]; }
field() { cut -d'|' -f"$2" <<<"$1"; }
score_of() { # REPO_KEY -> "grade has_uncataloged_scan"
  api_get "/api/v1/repositories/$1/security" 2>/dev/null \
    | jq -r '(.score // {}) | "\(.grade // "none") \(.has_uncataloged_scan)"' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: build the ISO fixtures, create generic repos with scan_enabled + scan_on_upload"
mkdir -p "$FX"
python3 -I "${HERE}/fixtures/make_fixtures.py" "$FX" "$SUF" > "${WORK_DIR}/sizes.json" 2>"${WORK_DIR}/mk.err" || true
ok=1
for k in "$R_LIVE" "$R_BAD"; do
  create_repo "$k" generic local || ok=0
  [ "$(api_put "/api/v1/repositories/${k}/security" '{"scan_enabled":true,"scan_on_upload":true}' 2>/dev/null \
      | jq -r '.scan_on_upload' 2>/dev/null || true)" = "true" ] || ok=0
done
if [ "$ok" = 1 ] && [ -s "${FX}/live.iso" ] && [ -s "${FX}/corrupt.iso" ]; then
  pass
else
  fail "setup ok=${ok} $(head -c 300 "${WORK_DIR}/mk.err" 2>/dev/null)"
fi

begin_test "control: both ISO uploads are accepted and scanned on upload (completed Grype rows)"
s1=$(put "${FX}/live.iso" "${BASE_URL}/api/v1/repositories/${R_LIVE}/artifacts/${P_LIVE}")
s2=$(put "${FX}/corrupt.iso" "${BASE_URL}/api/v1/repositories/${R_BAD}/artifacts/${P_BAD}")
wait_until "live ISO grype row" 180 has_grype_row "$R_LIVE" "$P_LIVE" || true
wait_until "corrupt ISO grype row" 120 has_grype_row "$R_BAD" "$P_BAD" || true
LIVE_ROW=$(grype_row "$R_LIVE" "$P_LIVE")
BAD_ROW=$(grype_row "$R_BAD" "$P_BAD")
if [[ "$s1" =~ ^20[01]$ && "$s2" =~ ^20[01]$ ]] && [ -n "$LIVE_ROW" ] && [ -n "$BAD_ROW" ]; then
  pass
else
  fail "uploads live=${s1} corrupt=${s2}; grype rows live='${LIVE_ROW}' corrupt='${BAD_ROW}'"
fi
LIVE_SCAN=$(field "$LIVE_ROW" 1)

# ---------------------------------------------------------------------------
# #1966: the live ISO's rootfs is inventoried and graded
# ---------------------------------------------------------------------------
begin_test "FIX #1966: the live ISO's scan persists the rootfs packages (scan_packages > 0, openssl 3.0.11-1~deb12u2 among them)"
n_pkgs=$(psql_q "SELECT count(*) FROM scan_packages WHERE scan_result_id = '${LIVE_SCAN:-00000000-0000-0000-0000-000000000000}'")
openssl=$(psql_q "SELECT count(*) FROM scan_packages WHERE scan_result_id = '${LIVE_SCAN:-00000000-0000-0000-0000-000000000000}'
                  AND name = 'openssl' AND version = '3.0.11-1~deb12u2'")
if [ "${n_pkgs:-0}" -gt 0 ] 2>/dev/null && [ "${openssl:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "scan ${LIVE_SCAN:-none}: ${n_pkgs:-0} scan_packages rows, openssl rows ${openssl:-0} (pre-fix: the ISO is one opaque file, 0 packages)"
fi

begin_test "FIX #1966: the openssl vulnerability is a finding of the live ISO's scan"
n_find=$(psql_q "SELECT count(*) FROM scan_findings WHERE scan_result_id = '${LIVE_SCAN:-00000000-0000-0000-0000-000000000000}'
                 AND affected_component = 'openssl' AND cve_id IS NOT NULL")
if [ "${n_find:-0}" -ge 1 ] 2>/dev/null && [ "$(field "$LIVE_ROW" 5)" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "openssl findings ${n_find:-0}, grype row '${LIVE_ROW}', score '$(score_of "$R_LIVE")' (pre-fix: 0 findings, grade A)"
fi

begin_test "control: the live ISO's scan is complete (it was inventoried)"
if [ "$(field "$LIVE_ROW" 2)" = "complete" ]; then pass; else fail "grype row '${LIVE_ROW}'"; fi

# ---------------------------------------------------------------------------
# #1966: an unreadable rootfs is not_cataloged, never clean
# ---------------------------------------------------------------------------
begin_test "FIX #1966: the ISO with a corrupt squashfs is not_cataloged with a reason and inventory_status partial, not a clean scan"
if [ "$(field "$BAD_ROW" 2)" = "not_cataloged" ] && [ -n "$(field "$BAD_ROW" 3)" ] \
   && [ "$(field "$BAD_ROW" 4)" = "partial" ] && [ "$(field "$BAD_ROW" 5)" = "0" ]; then
  pass
else
  fail "grype row (id|completeness|reason|inventory|findings) '${BAD_ROW}' (pre-fix: complete|''|complete|0, read as clean)"
fi

begin_test "FIX #1966: the corrupt ISO flags its repository (has_uncataloged_scan) instead of reading clean"
sc=$(score_of "$R_BAD")
if [ "${sc#* }" = "true" ]; then
  pass
else
  fail "score '${sc}' (pre-fix: 'A false')"
fi

end_suite
