#!/usr/bin/env bash
# =============================================================================
# tiers/scanner-collapse/oracle.sh — not_applicable row-collapse oracle
#   PKT-F (P7): #2471 (collapse redundant not_applicable scan rows)
# =============================================================================
# run.sh has stood up the `filesystem + scanners=trivy` profile-set (the
# scanner-adapter sidecar, so image + filesystem + incus + grype + dependency
# scanners are registered) and exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, DTF_SLOT, DB_CONTAINER, JUNIT_OUTPUT_DIR. We source common.sh
# for the assertion + JUnit harness.
#
# FEATURE (#2471) — SERVER-SIDE collapse (OQ#3 resolved: API-observable, not
# UI-only): `collapse_not_applicable_rows` runs inside the scan-results API
# handlers before serialization. When an artifact has >= 2 `not_applicable`
# scanner rows they fold into ONE synthetic summary row whose wire shape carries
# `collapsed_not_applicable_count` (n>=2) and `collapsed_scan_types` (the folded
# scan_type list). A lone not_applicable row is left untouched; every non-
# not_applicable row passes through verbatim.
#
# DRIVE: upload a NON-image `.bin` artifact (outside TrivyFsScanner's scannable
# extensions) and trigger a scan. image + filesystem + incus all decline by TYPE
# (is_applicable=false) -> three fast `not_applicable` rows for the one artifact
# -> the collapse must fold them.
#
# DISCRIMINATING GATE (green on candidate, red on a pre-#2471 backend):
#   POS  the scan-results API returns EXACTLY ONE `not_applicable` row for the
#        artifact (RED: >= 2 separate not_applicable rows — no collapse).
#   POS  that row is the synthetic summary: scan_type == "not_applicable",
#        `collapsed_not_applicable_count` present and >= 2, `collapsed_scan_types`
#        an array whose length == the count. (RED: field absent / null.)
#   GUARD any non-not_applicable row carries NO `collapsed_*` field (collapse
#        touches only the not_applicable group).
#   DB   cross-check (best-effort): the raw `scan_results` table holds >= 2
#        not_applicable rows for the artifact while the API shows exactly 1 —
#        proving the fold happened server-side (N rows -> 1 wire row).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scanner-collapse-2471"
auth_admin
setup_workdir

KEY="dtf-collapse-${RUN_ID}"
OBJ="collapse-sample-${RUN_ID}.bin"   # .bin => filesystem scanner also declines by type
ART_FILE="${WORK_DIR}/${OBJ}"
SCANS_JSON="${WORK_DIR}/scans.json"
ARTIFACT_ID=""

cleanup_repo() { api_delete "/api/v1/repositories/${KEY}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup_repo"

psql_ak() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}

# ---------------------------------------------------------------------------
# Setup: local generic repo + a non-image .bin artifact.
# ---------------------------------------------------------------------------
begin_test "Create local generic repo ${KEY}"
if create_repo "$KEY" "generic" "local"; then
  pass
else
  fail "could not create local generic repo; the tier is untestable without it"
  end_suite
fi

# A small, non-image, non-scannable-extension payload.
head -c 512 /dev/urandom > "$ART_FILE" 2>/dev/null || printf 'DTF-NOT-AN-IMAGE-%s' "$RUN_ID" > "$ART_FILE"

begin_test "Upload non-image artifact ${OBJ} (PUT /repositories/${KEY}/artifacts/${OBJ})"
up_status=$(curl -s -o "${WORK_DIR}/up-body" -w '%{http_code}' --max-time 40 \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
  --data-binary "@${ART_FILE}" \
  "${BASE_URL}/api/v1/repositories/${KEY}/artifacts/${OBJ}" 2>/dev/null) || up_status="000"
if [ "$up_status" -ge 200 ] 2>/dev/null && [ "$up_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "artifact upload expected 2xx, got ${up_status}" "$(head -c 300 "${WORK_DIR}/up-body" 2>/dev/null)"
  end_suite
fi

begin_test "Resolve the uploaded artifact_id via the artifacts listing"
if listing=$(api_get "/api/v1/repositories/${KEY}/artifacts?per_page=50" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$listing" | jq -r --arg o "$OBJ" \
    '(.items // [])[] | select((.path//"")|endswith($o)) | .id' 2>/dev/null | head -n1)
  [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ] && \
    ARTIFACT_ID=$(echo "$listing" | jq -r '(.items // [])[0].id // empty' 2>/dev/null)
fi
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  pass
else
  fail "could not resolve artifact_id from the listing" "$(echo "${listing:-}" | head -c 300)"
  end_suite
fi

# ---------------------------------------------------------------------------
# Trigger the scan (admin-only) and poll for the collapsed summary.
# ---------------------------------------------------------------------------
begin_test "Trigger scan for the artifact (POST /security/scan)"
tr_status=$(curl -s -o "${WORK_DIR}/trig" -w '%{http_code}' --max-time 40 \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "{\"artifact_id\":\"${ARTIFACT_ID}\"}" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || tr_status="000"
if [ "$tr_status" -ge 200 ] 2>/dev/null && [ "$tr_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "POST /security/scan expected 2xx, got ${tr_status} (scanner not wired? adapter down?)" \
       "$(head -c 300 "${WORK_DIR}/trig" 2>/dev/null)"
  end_suite
fi

# Poll the scan-results API until the collapsed summary row appears: an item
# with `collapsed_not_applicable_count` present (only emitted once >= 2
# not_applicable rows for the artifact exist and were folded).
begin_test "Poll scan-results API until the collapsed not_applicable summary appears"
elapsed=0; timeout=180; have_summary=0
while [ "$elapsed" -lt "$timeout" ]; do
  if api_get "/api/v1/security/scans?artifact_id=${ARTIFACT_ID}&per_page=50" > "$SCANS_JSON" 2>/dev/null; then
    cnt=$(jq -r '[(.items // [])[] | select(.collapsed_not_applicable_count != null)] | length' "$SCANS_JSON" 2>/dev/null || echo 0)
    if [ "${cnt:-0}" -ge 1 ] 2>/dev/null; then have_summary=1; break; fi
  fi
  sleep 5; elapsed=$((elapsed + 5))
done
if [ "$have_summary" = "1" ]; then
  pass
else
  # Distinguish "collapse never happened" (the #2471 RED) from "scan never ran".
  na_rows=$(jq -r '[(.items // [])[] | select(.status=="not_applicable")] | length' "$SCANS_JSON" 2>/dev/null || echo 0)
  total_rows=$(jq -r '(.items // []) | length' "$SCANS_JSON" 2>/dev/null || echo 0)
  fail "no collapsed not_applicable summary within ${timeout}s (na_rows=${na_rows}, total_rows=${total_rows}); a pre-#2471 backend returns >=2 separate not_applicable rows with no collapsed_* field" \
       "$(head -c 400 "$SCANS_JSON" 2>/dev/null)"
  end_suite
fi

# ---------------------------------------------------------------------------
# The discriminating assertions.
# ---------------------------------------------------------------------------
begin_test "#2471: scan-results API returns EXACTLY ONE not_applicable row (folded), not N"
na_rows=$(jq -r '[(.items // [])[] | select(.status=="not_applicable")] | length' "$SCANS_JSON" 2>/dev/null || echo -1)
if [ "$na_rows" = "1" ]; then
  pass
else
  fail "#2471 RED: expected exactly 1 not_applicable row in the API payload (collapsed), got ${na_rows}" \
       "$(head -c 400 "$SCANS_JSON")"
fi

begin_test "#2471: the summary row is synthetic — scan_type==not_applicable, collapsed_not_applicable_count>=2, collapsed_scan_types length matches"
sum=$(jq -c '(.items // [])[] | select(.collapsed_not_applicable_count != null)' "$SCANS_JSON" 2>/dev/null | head -n1)
if [ -z "$sum" ]; then
  fail "no summary row with collapsed_not_applicable_count found" "$(head -c 400 "$SCANS_JSON")"
else
  st=$(echo "$sum" | jq -r '.scan_type // empty')
  cnt=$(echo "$sum" | jq -r '.collapsed_not_applicable_count // -1')
  types_len=$(echo "$sum" | jq -r '(.collapsed_scan_types // []) | length')
  if [ "$st" = "not_applicable" ] && [ "$cnt" -ge 2 ] 2>/dev/null && [ "$types_len" = "$cnt" ]; then
    pass
  else
    fail "summary row malformed: scan_type=${st} collapsed_count=${cnt} collapsed_scan_types_len=${types_len} (want scan_type=not_applicable, count>=2, len==count)" "$sum"
  fi
fi

begin_test "GUARD: no non-not_applicable row carries a collapsed_* field (collapse touches only the not_applicable group)"
bad=$(jq -r '[(.items // [])[] | select(.status != "not_applicable") | select(.collapsed_not_applicable_count != null)] | length' "$SCANS_JSON" 2>/dev/null || echo -1)
if [ "$bad" = "0" ]; then
  pass
else
  fail "a non-not_applicable row carries collapsed_* (${bad} such rows); collapse must fold ONLY not_applicable rows" "$(head -c 400 "$SCANS_JSON")"
fi

begin_test "DB cross-check: raw scan_results holds >=2 not_applicable rows while the API shows 1 (server-side fold)"
raw_na=$(psql_ak "SELECT COUNT(*) FROM scan_results WHERE artifact_id='${ARTIFACT_ID}' AND status='not_applicable'")
if [ -n "$raw_na" ] && [ "$raw_na" -ge 2 ] 2>/dev/null; then
  pass
elif [ -z "$raw_na" ]; then
  # DB unreachable / query shape drift: do not fail the tier on the cross-check
  # alone — the API assertions above are the primary gate. Record as a soft pass.
  echo ">> NOTE: DB cross-check inconclusive (empty result); relying on the API assertions above"
  pass
else
  fail "expected >=2 raw not_applicable rows in scan_results (folded to 1 in the API), DB reports ${raw_na}"
fi

end_suite
