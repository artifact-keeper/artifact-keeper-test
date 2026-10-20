#!/usr/bin/env bash
# =============================================================================
# tiers/migration-items-filters/oracle.sh - the migration items listing honours
#          its filters, and a migrated .deb is filed under its deb.component
#          (artifact-keeper#4787 / #4778, #4797 / #4740; backend 1.11.3)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-artifactory-items`
# with RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, DTF_SLOT,
# DTF_DIR, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH.
#
# ONE migration job moves two source repositories:
#   dtfmi-debian  three real .debs whose Artifactory properties name their
#                 component (main / contrib / non-free) and architecture, plus
#                 a phantom pool/main/Packages.gz the source lists but never
#                 serves (the importer SKIPS it with an item row: a Debian
#                 index path that 404s is cache metadata, eligible on a re-run;
#                 anything under dists/ is dropped before an item row exists);
#   dtfmi-gen     two good files and one whose advertised digest is wrong (the
#                 checksum-verifying importer FAILS it).
# So the job has 7 artifact items: 5 completed, 1 failed, 1 skipped.
#
# THE BUGS.
#   #4778 `GET /api/v1/migrations/{id}/items?status=&item_type=` ignored both
#         filters: every call returned the whole job and pagination.total
#         counted every item.
#   #4740 a migrated .deb ignored its source `deb.component`: the flat
#         pool/dtfcontrib_1.0_amd64.deb landed in `main`, and
#         pool/n/nfpkg/nfpkg_2.0_arm64.deb in a component named `n`.
#
# An API-driven migration only ever writes item_type=artifact rows (the worker's
# user/group/permission migrators are not called from the job runner), so the
# second item type is two `repository` rows seeded into the same job with psql,
# after every assertion on the real run.
#
# --path-as-is on every curl, per the harness convention.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
read -r -a CURLF <<< "--path-as-is ${CURL_TIMEOUT}"
TIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK="ak-dtf${SLOT}-mock-artifactory"

# Source repository keys; the destinations take the same keys. Fixed because
# the mock's MOCK_REPOS is fixed (profile); each slot owns its own mock and
# Postgres, so they cannot collide across slots.
DEB="dtfmi-debian"
GEN="dtfmi-gen"
SRC_ITEMS=7        # 3 .deb + phantom Packages.gz + 3 generic files
WANT_COMPLETED=5   # 3 .deb + ok-1 + ok-2
WANT_FAILED=1      # broken.bin (wrong advertised digest)
WANT_SKIPPED=1     # pool/main/Packages.gz (listed, 404, Debian index path)

DEB_MAIN_SRC="pool/dtfmain_1.0_amd64.deb"
DEB_MAIN_DST="pool/main/dtfmain_1.0_amd64.deb"          # same on both images
DEB_CONTRIB_SRC="pool/dtfcontrib_1.0_amd64.deb"
DEB_CONTRIB_DST="pool/contrib/dtfcontrib_1.0_amd64.deb" # #4797
DEB_NF_SRC="pool/n/nfpkg/nfpkg_2.0_arm64.deb"
DEB_NF_DST="pool/non-free/n/nfpkg/nfpkg_2.0_arm64.deb"  # #4797

WORK="$(mktemp -d -t dtf-migitems-XXXXXX)"
add_exit_handler "rm -rf '${WORK}'"

# --- REST helpers ------------------------------------------------------------
aj() { # METHOD PATH [BODY] -> response body (never fails the shell)
  local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then
    curl -s "${CURLF[@]}" -X "$m" "${BASE_URL}${p}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
      -d "$b" 2>/dev/null || true
  else
    curl -s "${CURLF[@]}" -X "$m" "${BASE_URL}${p}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true
  fi
}
ac() { # METHOD PATH -> http code only (body to ${WORK}/last.body)
  curl -s -o "${WORK}/last.body" -w '%{http_code}' "${CURLF[@]}" -X "$1" \
    "${BASE_URL}${2}" -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000
}
fetch() { # PATH OUTFILE -> http code (body to OUTFILE)
  curl -s -o "$2" -w '%{http_code}' "${CURLF[@]}" "${BASE_URL}${1}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000
}
jqf() { # JSON FILTER DEFAULT
  echo "$1" | jq -r "$2" 2>/dev/null || echo "$3"
}
psql_ak() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" \
    2>/dev/null | tr -d '[:space:]' || echo "?"
}
psql_rows() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

job_row() { aj GET "/api/v1/migrations/${1}"; }

wait_terminal() { # JOB_ID DEADLINE_SECONDS -> prints the status reached
  local id="$1" budget="$2" st="" i
  for ((i = 0; i < budget; i++)); do
    st="$(jqf "$(job_row "$id")" '.status // empty' '')"
    case "$st" in completed|completed_with_errors|failed|cancelled) echo "$st"; return 0 ;; esac
    sleep 1
  done
  echo "${st:-unknown}"
  return 1
}

live_paths() { # REPO_KEY -> live artifact paths, sorted
  psql_rows "SELECT a.path FROM artifacts a JOIN repositories r ON r.id = a.repository_id
    WHERE r.key = '${1}' AND a.is_deleted = false ORDER BY 1;"
}
# Packages index for a component/arch -> http code (body to OUTFILE)
packages_index() { fetch "/debian/${DEB}/dists/stable/${1}/binary-${2}/Packages" "$3"; }
stanza() { # FILE PACKAGE -> the package's stanza, or ""
  awk -v p="$2" 'BEGIN{RS=""} $0 ~ "(^|\n)Package: " p "(\n|$)" {print; exit}' "$1" 2>/dev/null
}
field() { # STANZA FIELD -> value
  echo "$1" | sed -n "s/^${2}: //p" | head -n1
}

# items QUERY -> body of GET .../items?per_page=100&QUERY into ${WORK}/items.json,
# echoes the HTTP code.
items() {
  curl -s -o "${WORK}/items.json" -w '%{http_code}' "${CURLF[@]}" \
    "${BASE_URL}/api/v1/migrations/${JOB}/items?per_page=100${1:+&$1}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000
}
items_total() { jq -r '.pagination.total // "null"' "${WORK}/items.json" 2>/dev/null || echo "?"; }
items_count() { jq -r '.items | length' "${WORK}/items.json" 2>/dev/null || echo "?"; }
# distinct values of FIELD over the returned rows, comma-joined
items_values() { jq -r "[.items[].${1}] | unique | join(\",\")" "${WORK}/items.json" 2>/dev/null || echo "?"; }
items_summary() {
  jq -c '{total: .pagination.total, rows: [.items[] | "\(.item_type)/\(.status) \(.source_path)"]}' \
    "${WORK}/items.json" 2>/dev/null | head -c 900
}

# assert_filter NAME QUERY WANT_COUNT WANT_STATUSES WANT_TYPES
#   WANT_STATUSES / WANT_TYPES: the comma-joined distinct values every returned
#   row must carry ("" when the answer must be empty).
assert_filter() {
  local name="$1" q="$2" n="$3" ws="$4" wt="$5" code got_total got_rows got_s got_t
  begin_test "$name"
  code="$(items "$q")"
  got_total="$(items_total)"; got_rows="$(items_count)"
  got_s="$(items_values status)"; got_t="$(items_values item_type)"
  if [ "$code" = "200" ] && [ "$got_total" = "$n" ] && [ "$got_rows" = "$n" ] \
     && [ "$got_s" = "$ws" ] && [ "$got_t" = "$wt" ]; then
    pass
  else
    fail "GET /api/v1/migrations/{id}/items?${q} -> HTTP ${code}, ${got_rows} rows, pagination.total=${got_total}, \
statuses=[${got_s}] types=[${got_t}]; want ${n} rows and total ${n}, statuses=[${ws}] types=[${wt}]. \
The handler parsed status/item_type and never bound them, so the filter is ignored (#4778)." \
      "$(items_summary)"
  fi
}

begin_suite "migration-items-filters"

# ===========================================================================
# SETUP - build the source, load it into the mock, run ONE migration job
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

SRC="${WORK}/source"
if ! python3 -I "${TIER_DIR}/fixtures/build_fixtures.py" "$SRC" 2>"${WORK}/build.err"; then
  begin_test "setup: build the source files"
  infra_fail "fixtures/build_fixtures.py failed" "$(cat "${WORK}/build.err")"
  end_suite
fi
if ! docker cp "${SRC}/." "${MOCK}:/srv/catalog/" >"${WORK}/cp.err" 2>&1; then
  begin_test "setup: copy the source files into the mock Artifactory"
  infra_fail "docker cp into ${MOCK} failed" "$(cat "${WORK}/cp.err")"
  end_suite
fi

CONN="$(aj POST /api/v1/migrations/connections "$(jq -nc --arg n "dtf-migitems-${SUF}" '{
  name: $n, url: "http://mock-artifactory", auth_type: "basic_auth",
  source_type: "artifactory", credentials: {username: "dtf", password: "dtf"}
}')")"
CONN_ID="$(jqf "$CONN" '.id // empty' '')"
if [ -z "$CONN_ID" ]; then
  begin_test "setup: create the migration source connection"
  infra_fail "POST /api/v1/migrations/connections returned no id (the overlay must set \
AK_SSRF_ALLOW_PRIVATE_CIDRS + ALLOW_HTTP_INTEGRATIONS)" "$(echo "$CONN" | head -c 500)"
  end_suite
fi
CONN_TEST="$(aj POST "/api/v1/migrations/connections/${CONN_ID}/test")"
if [ "$(jqf "$CONN_TEST" '.success // false' 'false')" != "true" ]; then
  begin_test "setup: the backend can reach the migration source"
  infra_fail "connection test did not succeed" "$(echo "$CONN_TEST" | head -c 500)"
  end_suite
fi
# The mock serves the properties the #4740 fix reads (proves the fixture, not the backend).
PROP_CHECK="$(docker exec "$MOCK" python3 -c "import urllib.request,sys; \
print(urllib.request.urlopen('http://127.0.0.1/api/storage/${DEB}/${DEB_CONTRIB_SRC}?properties').read().decode())" 2>&1)"
if ! echo "$PROP_CHECK" | jq -e '.properties["deb.component"][0] == "contrib"' >/dev/null 2>&1; then
  begin_test "setup: the mock source serves deb.component properties"
  infra_fail "GET /api/storage/${DEB}/${DEB_CONTRIB_SRC}?properties on the mock did not return deb.component=contrib" \
    "$(echo "$PROP_CHECK" | head -c 500)"
  end_suite
fi

JOB="$(jqf "$(aj POST /api/v1/migrations "$(jq -nc --arg cid "$CONN_ID" --arg d "$DEB" --arg g "$GEN" '{
  source_connection_id: $cid, job_type: "full",
  config: { include_repos: [$d, $g], dry_run: false,
            conflict_resolution: "overwrite", verify_checksums: true,
            include_users: false, include_groups: false, include_permissions: false,
            concurrent_transfers: 1, throttle_delay_ms: 0 }
}')")" '.id // empty' '')"
START_CODE="$( [ -n "$JOB" ] && ac POST "/api/v1/migrations/${JOB}/start" || echo none)"
if [ -z "$JOB" ] || [ "$START_CODE" != "200" ]; then
  begin_test "setup: create and start the migration"
  infra_fail "job=${JOB:-<none>} start=${START_CODE}" "$(head -c 400 "${WORK}/last.body" 2>/dev/null)"
  end_suite
fi
JOB_ST="$(wait_terminal "$JOB" 180)"
JOB_ROW="$(job_row "$JOB")"
J_T="$(jqf "$JOB_ROW" '.total_items // 0' 0)"
J_C="$(jqf "$JOB_ROW" '.completed_items // 0' 0)"
J_F="$(jqf "$JOB_ROW" '.failed_items // 0' 0)"
J_S="$(jqf "$JOB_ROW" '.skipped_items // 0' 0)"
echo "  [observe] job ${JOB}: status=${JOB_ST} total=${J_T} completed=${J_C} failed=${J_F} skipped=${J_S}"

# ===========================================================================
# CONTROLS on the real run (both images)
# ===========================================================================
begin_test "CONTROL: the job ends with 5 completed, 1 failed (bad digest), 1 skipped (phantom Packages.gz)"
if [ "$J_C" = "$WANT_COMPLETED" ] && [ "$J_F" = "$WANT_FAILED" ] && [ "$J_S" = "$WANT_SKIPPED" ]; then
  pass
else
  fail "job status=${JOB_ST} completed=${J_C} failed=${J_F} skipped=${J_S} total=${J_T}; want completed ${WANT_COMPLETED}, \
failed ${WANT_FAILED}, skipped ${WANT_SKIPPED}. The fixture did not produce the item mix every filter case relies on." \
    "$(echo "$JOB_ROW" | jq -c '{status,total_items,completed_items,failed_items,skipped_items,error_message}' 2>/dev/null)
$(aj GET "/api/v1/migrations/${JOB}/items?per_page=100" | jq -c '[.items[]? | "\(.status) \(.source_path) \(.error_message // "")"]' 2>/dev/null | head -c 1200)"
fi

begin_test "CONTROL: the unfiltered items list holds all 7 artifact items, total 7, in the job's status mix"
code="$(items "")"
UNF_MIX="$(jq -r '[.items[].status] | group_by(.) | map("\(.[0])=\(length)") | join(",")' "${WORK}/items.json" 2>/dev/null)"
if [ "$code" = "200" ] && [ "$(items_total)" = "$SRC_ITEMS" ] && [ "$(items_count)" = "$SRC_ITEMS" ] \
   && [ "$(items_values item_type)" = "artifact" ] \
   && [ "$UNF_MIX" = "completed=${WANT_COMPLETED},failed=${WANT_FAILED},skipped=${WANT_SKIPPED}" ]; then
  pass
else
  fail "GET .../items -> HTTP ${code}, rows=$(items_count) total=$(items_total) types=[$(items_values item_type)] mix=[${UNF_MIX}]; \
want ${SRC_ITEMS} artifact rows, completed=${WANT_COMPLETED},failed=${WANT_FAILED},skipped=${WANT_SKIPPED}" "$(items_summary)"
fi

begin_test "CONTROL: the report's per-type summary counts match the items (artifacts 7 / 5 migrated / 1 failed / 1 skipped)"
REP_CODE="$(ac GET "/api/v1/migrations/${JOB}/report")"
REP_ART="$(jq -c '.summary.artifacts // null' "${WORK}/last.body" 2>/dev/null)"
if [ "$REP_CODE" = "200" ] \
   && [ "$(echo "$REP_ART" | jq -r '"\(.total)/\(.migrated)/\(.failed)/\(.skipped)"' 2>/dev/null)" \
        = "${SRC_ITEMS}/${WANT_COMPLETED}/${WANT_FAILED}/${WANT_SKIPPED}" ]; then
  pass
else
  fail "GET /api/v1/migrations/{id}/report -> ${REP_CODE}, summary.artifacts=${REP_ART}" \
    "$(head -c 800 "${WORK}/last.body" 2>/dev/null)"
fi

# ===========================================================================
# FIX #4778 - the items filters, on the real run
# ===========================================================================
assert_filter "FIX #4778: ?status=completed returns only the 5 completed items" \
  "status=completed" "$WANT_COMPLETED" "completed" "artifact"
assert_filter "FIX #4778: ?status=failed returns only the bad-digest item" \
  "status=failed" "$WANT_FAILED" "failed" "artifact"
begin_test "FIX #4778: the ?status=failed row is broken.bin with its checksum error"
F_PATH="$(jq -r '[.items[].source_path] | join(",")' "${WORK}/items.json" 2>/dev/null)"
F_ERR="$(jq -r '.items[0].error_message // ""' "${WORK}/items.json" 2>/dev/null)"
case "$F_PATH" in
  *files/broken.bin) if [ -n "$F_ERR" ]; then pass; else fail "the failed row carries no error_message" "$(items_summary)"; fi ;;
  *) fail "?status=failed returned [${F_PATH}], want exactly the ${GEN} files/broken.bin item" "$(items_summary)" ;;
esac
assert_filter "FIX #4778: ?status=skipped returns only the phantom Packages.gz" \
  "status=skipped" "$WANT_SKIPPED" "skipped" "artifact"
assert_filter "FIX #4778: ?status=failed&item_type=artifact intersects (1 row)" \
  "status=failed&item_type=artifact" "$WANT_FAILED" "failed" "artifact"
assert_filter "FIX #4778: ?item_type=user matches nothing in an artifact-only job" \
  "item_type=user" 0 "" ""
assert_filter "FIX #4778: an unknown ?status=bogus matches nothing (the handler does not validate; it filters)" \
  "status=bogus" 0 "" ""

# ===========================================================================
# FIX #4778 - two item types: seed two `repository` rows into the same job
# ===========================================================================
psql_ak "INSERT INTO migration_items (job_id, item_type, source_path, status, error_message) VALUES
  ('${JOB}', 'repository', 'repo:dtfmi-seed-ok', 'completed', NULL),
  ('${JOB}', 'repository', 'repo:dtfmi-seed-bad', 'failed', 'dtf seeded failure');" >/dev/null
SEEDED="$(psql_ak "SELECT count(*) FROM migration_items WHERE job_id='${JOB}' AND item_type='repository';")"
if [ "$SEEDED" != "2" ]; then
  begin_test "setup: seed two repository items into the job"
  infra_fail "could not seed migration_items (repository rows=${SEEDED})"
else
  assert_filter "FIX #4778: ?item_type=repository returns only the 2 repository items" \
    "item_type=repository" 2 "completed,failed" "repository"
  assert_filter "FIX #4778: ?item_type=artifact returns only the 7 artifact items" \
    "item_type=artifact" "$SRC_ITEMS" "completed,failed,skipped" "artifact"
  assert_filter "FIX #4778: ?status=failed spans both types (2 rows)" \
    "status=failed" 2 "failed" "artifact,repository"
  assert_filter "FIX #4778: ?status=failed&item_type=repository intersects (1 row)" \
    "status=failed&item_type=repository" 1 "failed" "repository"
  assert_filter "FIX #4778: ?status=skipped&item_type=repository is empty" \
    "status=skipped&item_type=repository" 0 "" ""
  begin_test "CONTROL: the unfiltered list now totals 9 (7 artifact + 2 repository)"
  code="$(items "")"
  if [ "$code" = "200" ] && [ "$(items_total)" = "$((SRC_ITEMS + 2))" ] && [ "$(items_count)" = "$((SRC_ITEMS + 2))" ]; then
    pass
  else
    fail "GET .../items -> HTTP ${code}, rows=$(items_count) total=$(items_total); want $((SRC_ITEMS + 2))" "$(items_summary)"
  fi
fi

# ===========================================================================
# #4740 - each .deb under its own deb.component
# ===========================================================================
D_PATHS="$(live_paths "$DEB")"
D_FMT="$(psql_ak "SELECT format::text FROM repositories WHERE key='${DEB}';")"
IDX_MAIN_AMD="${WORK}/main-amd64"; IDX_CON_AMD="${WORK}/contrib-amd64"
IDX_NF_ARM="${WORK}/nonfree-arm64"; IDX_MAIN_ARM="${WORK}/main-arm64"; IDX_N_ARM="${WORK}/n-arm64"
C_MAIN_AMD="$(packages_index main amd64 "$IDX_MAIN_AMD")"
C_CON_AMD="$(packages_index contrib amd64 "$IDX_CON_AMD")"
C_NF_ARM="$(packages_index non-free arm64 "$IDX_NF_ARM")"
C_MAIN_ARM="$(packages_index main arm64 "$IDX_MAIN_ARM")"
C_N_ARM="$(packages_index n arm64 "$IDX_N_ARM")"
REL_CODE="$(fetch "/debian/${DEB}/dists/stable/Release" "${WORK}/Release")"
REL_COMPONENTS="$(sed -n 's/^Components: //p' "${WORK}/Release" 2>/dev/null | tr ' ' '\n' | sort | paste -sd' ')"
echo "  [observe] ${DEB} live rows: $(echo "$D_PATHS" | paste -sd' ')"
echo "  [observe] Release (HTTP ${REL_CODE}) Components: ${REL_COMPONENTS}"

ST_MAIN="$(stanza "$IDX_MAIN_AMD" dtfmain)"
begin_test "CONTROL: the main/binary-amd64 Packages index parses and lists dtfmain (deb.component=main) with its SHA256"
if [ "$D_FMT" = "debian" ] && [ "$C_MAIN_AMD" = "200" ] \
   && [ "$(field "$ST_MAIN" Filename)" = "$DEB_MAIN_DST" ] \
   && [ "$(field "$ST_MAIN" SHA256)" = "$(sha "${SRC}/${DEB}/${DEB_MAIN_SRC}")" ]; then
  pass
else
  fail "destination format=${D_FMT}; dists/stable/main/binary-amd64/Packages HTTP ${C_MAIN_AMD}; dtfmain stanza \
Filename=$(field "$ST_MAIN" Filename) SHA256=$(field "$ST_MAIN" SHA256); want ${DEB_MAIN_DST} and the source digest" \
    "live rows:
${D_PATHS}
--- index ---
$(head -c 1200 "$IDX_MAIN_AMD" 2>/dev/null)"
fi

begin_test "CONTROL: each migrated .deb downloads byte-identical from the Filename its index advertises"
dl_bad=""
for spec in "dtfcontrib:${DEB_CONTRIB_SRC}" "nfpkg:${DEB_NF_SRC}" "dtfmain:${DEB_MAIN_SRC}"; do
  pkg="${spec%%:*}"; src="${spec#*:}"
  fname="$(grep -h -A20 "^Package: ${pkg}$" "${WORK}"/main-amd64 "${WORK}"/contrib-amd64 "${WORK}"/nonfree-arm64 \
    "${WORK}"/main-arm64 "${WORK}"/n-arm64 2>/dev/null | sed -n 's/^Filename: //p' | head -n1)"
  if [ -z "$fname" ]; then dl_bad="${dl_bad} ${pkg}:not-indexed-anywhere"; continue; fi
  c="$(fetch "/debian/${DEB}/${fname}" "${WORK}/${pkg}.deb")"
  if [ "$c" != "200" ] || [ "$(sha "${WORK}/${pkg}.deb")" != "$(sha "${SRC}/${DEB}/${src}")" ]; then
    dl_bad="${dl_bad} ${pkg}:${fname}:HTTP${c}"
  fi
done
if [ -z "$dl_bad" ]; then pass; else fail "download/digest mismatch:${dl_bad}" "live rows:
${D_PATHS}"; fi

ST_CON="$(stanza "$IDX_CON_AMD" dtfcontrib)"
begin_test "FIX #4740: dtfcontrib (deb.component=contrib) is stored and indexed under pool/contrib/"
if echo "$D_PATHS" | grep -qxF "$DEB_CONTRIB_DST" && [ "$C_CON_AMD" = "200" ] \
   && [ "$(field "$ST_CON" Filename)" = "$DEB_CONTRIB_DST" ] \
   && [ "$(field "$ST_CON" SHA256)" = "$(sha "${SRC}/${DEB}/${DEB_CONTRIB_SRC}")" ]; then
  pass
else
  fail "MIGRATED .deb IGNORES deb.component (#4740): want artifact row ${DEB_CONTRIB_DST} and a \
dists/stable/contrib/binary-amd64/Packages stanza for it (HTTP ${C_CON_AMD}, Filename=$(field "$ST_CON" Filename)). \
The importer filed the flat source path under the default component instead." \
    "live rows:
${D_PATHS}"
fi

begin_test "FIX #4740: main/binary-amd64 does NOT list dtfcontrib"
if [ "$C_MAIN_AMD" = "200" ] && [ -z "$(stanza "$IDX_MAIN_AMD" dtfcontrib)" ]; then
  pass
else
  fail "dists/stable/main/binary-amd64/Packages (HTTP ${C_MAIN_AMD}) lists dtfcontrib, whose source deb.component is \
contrib: apt with only 'main' enabled would install it" "$(stanza "$IDX_MAIN_AMD" dtfcontrib)"
fi

ST_NF="$(stanza "$IDX_NF_ARM" nfpkg)"
begin_test "FIX #4740: nfpkg (pool/n/nfpkg/ layout, deb.component=non-free) is stored and indexed under pool/non-free/"
if echo "$D_PATHS" | grep -qxF "$DEB_NF_DST" && [ "$C_NF_ARM" = "200" ] \
   && [ "$(field "$ST_NF" Filename)" = "$DEB_NF_DST" ] \
   && [ "$(field "$ST_NF" Architecture)" = "arm64" ]; then
  pass
else
  fail "want artifact row ${DEB_NF_DST} and a dists/stable/non-free/binary-arm64/Packages stanza for it \
(HTTP ${C_NF_ARM}, Filename=$(field "$ST_NF" Filename)). Before #4797 the pool prefix letter 'n' became the component." \
    "live rows:
${D_PATHS}"
fi

begin_test "FIX #4740: neither main/binary-arm64 nor a bogus 'n' component lists nfpkg"
if [ -z "$(stanza "$IDX_MAIN_ARM" nfpkg)" ] && [ -z "$(stanza "$IDX_N_ARM" nfpkg)" ]; then
  pass
else
  fail "nfpkg is listed in main/binary-arm64 (HTTP ${C_MAIN_ARM}) or n/binary-arm64 (HTTP ${C_N_ARM})" \
    "main: $(stanza "$IDX_MAIN_ARM" nfpkg)
n: $(stanza "$IDX_N_ARM" nfpkg)"
fi

begin_test "FIX #4740: the Release file advertises exactly the source components (contrib main non-free)"
if [ "$REL_CODE" = "200" ] && [ "$REL_COMPONENTS" = "contrib main non-free" ]; then
  pass
else
  fail "dists/stable/Release (HTTP ${REL_CODE}) Components: [${REL_COMPONENTS}], want [contrib main non-free]" \
    "$(head -c 800 "${WORK}/Release" 2>/dev/null)"
fi

end_suite
