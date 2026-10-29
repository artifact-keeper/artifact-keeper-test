#!/usr/bin/env bash
# =============================================================================
# tiers/migration-package-catalog/oracle.sh — a migrated Maven or Debian
#          repository must show its packages like a native upload does
#          (artifact-keeper#4691 / #4735, #4657 / #4741)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-artifactory-catalog`
# with RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, DTF_SLOT,
# DTF_DIR, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH.
#
# THE BUGS.
#   #4691 `migration_catalog_entry` returned None for the whole Maven family,
#         so a migrated Maven repository stored every file and listed no
#         packages (`GET /api/v1/packages?repository_key=` empty).
#   #4657 the importer copied `.deb` files without registering them: no
#         catalog row, no `debian` control document (so `Packages` fell back
#         to the file name and lost the control file's fields), and a `.deb`
#         outside `pool/<component>/` was stored where no `Packages` query
#         looks.
#
# SOURCE FIDELITY (the audit's `migration-source-fidelity` cases, added to this
# tier because they need the same source):
#   #3927 a migrated Maven GA serves `maven-metadata.xml` (generated from the
#         coordinates the importer now records; was 404).
#   #3928 the pre-migration assessment counts every source artifact and says
#         the count is exact (was at most 1 per repository).
#   #3925 a migrated RPM repository's `primary.xml` carries each header's
#         summary and `<rpm:requires>` (was synthesised from the file name).
#   #3926 an artifact whose body takes longer than 30 s to stream migrates
#         (was "error decoding response body" under a whole-request timeout).
#   #4797/#4740 (1.11.3) a `.deb` in the Nexus `pool/<letter>/<name>/` layout
#         is filed under `pool/main/`, one whose Artifactory `deb.component`
#         property says `universe` under `pool/universe/`; a re-run moves a
#         package an earlier run misfiled and retires the old row.
#   #2525 an Artifactory `cran` repository migrates into a native CRAN
#         repository listed in `src/contrib/PACKAGES`; the source's own
#         `PACKAGES` file is skipped.
# Red images: everything above except #4797/#4740 is a 1.11.0 fix (red on
# 1.10.0); #4797/#4740 is red on 1.11.2. #4691/#4657 (1.11.2) are red on
# 1.11.1.
#
# The source files are real (a jar with its pom, sidecars and
# maven-metadata.xml; `.deb` ar archives; the #3801 fixture RPMs; an R source
# tarball), built on the host by fixtures/build_catalog.py and copied into the
# mock after the stack is up.
#
# --path-as-is on every curl, per the harness convention.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
# Every curl: the harness convention (--path-as-is) plus common.sh's timeouts,
# split into words once here so no call site relies on unquoted expansion.
read -r -a CURLF <<< "--path-as-is ${CURL_TIMEOUT}"
TIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK="ak-dtf${SLOT}-mock-artifactory"

# Source repository keys; the destination repositories take the same keys.
# Fixed because the mock's MOCK_REPOS is fixed (profile); each slot owns its
# own mock and Postgres, so they cannot collide across slots.
MVN="dtfcat-mvn"
DEB="dtfcat-deb"
MVN_SOURCE_FILES=6   # jar, jar.sha1, jar.md5, pom, pom.sha1, maven-metadata.xml
DEB_SOURCE_FILES=2   # the pooled .deb and the flat-layout .deb
MVN_JAR="com/dtf/demo/1.0.0/demo-1.0.0.jar"
DEB_POOLED="pool/main/d/dtfpkg/dtfpkg_1.0_amd64.deb"
DEB_FLAT_SRC="pool/dtfflat_2.0_all.deb"
DEB_FLAT_DST="pool/main/dtfflat_2.0_all.deb"   # where #4741 files it
DEB_POOLED_DESC="DTF pooled fixture for artifact-keeper 4657"
DEB_FLAT_DESC="DTF flat-layout fixture for artifact-keeper 4657"
# Source-fidelity repositories (see the profile's MOCK_REPOS).
RPM="dtfcat-rpm"
DEBC="dtfcat-debc"
CRAN="dtfcat-cran"
SLOW="dtfcat-slow"
DEBC_LETTER_SRC="pool/d/dtfletter/dtfletter_1.0_amd64.deb"
DEBC_LETTER_DST="pool/main/d/dtfletter/dtfletter_1.0_amd64.deb"
DEBC_UNIV_DST="pool/universe/d/dtfuniv/dtfuniv_1.0_amd64.deb"
SLOW_FILE="slow-blob.bin"

WORK="$(mktemp -d -t dtf-migcat-XXXXXX)"
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
ac() { # METHOD PATH [BODY] -> http code only
  local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then
    curl -s -o "${WORK}/last.body" -w '%{http_code}' "${CURLF[@]}" -X "$m" \
      "${BASE_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H 'Content-Type: application/json' -d "$b" 2>/dev/null || echo 000
  else
    curl -s -o "${WORK}/last.body" -w '%{http_code}' "${CURLF[@]}" -X "$m" \
      "${BASE_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000
  fi
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
psql_rows() { # SQL -> rows as-is (one per line)
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

job_row() { aj GET "/api/v1/migrations/${1}"; }
job_field() { jqf "$(job_row "$1")" ".${2} // empty" ""; }

make_job() { # SRC_REPO -> prints the job id
  local body
  body="$(jq -nc --arg cid "$CONN_ID" --arg repo "$1" '{
    source_connection_id: $cid, job_type: "full",
    config: { include_repos: [$repo], dry_run: false,
              conflict_resolution: "overwrite", verify_checksums: true,
              include_users: false, include_groups: false, include_permissions: false,
              concurrent_transfers: 1, throttle_delay_ms: 0 }
  }')"
  jqf "$(aj POST /api/v1/migrations "$body")" '.id // empty' ""
}

wait_status() { # JOB_ID DEADLINE_SECONDS STATUS... -> prints the status reached
  local id="$1" budget="$2"; shift 2
  local want=" $* " st="" i
  for ((i = 0; i < budget; i++)); do
    st="$(job_field "$id" status)"
    case "$want" in *" ${st} "*) echo "$st"; return 0 ;; esac
    sleep 1
  done
  echo "${st:-unknown}"
  return 1
}

run_job() { # SRC_REPO -> prints the job id once it is terminal ("" on setup failure)
  local id code
  id="$(make_job "$1")"
  [ -n "$id" ] || return 0
  code="$(ac POST "/api/v1/migrations/${id}/start")"
  [ "$code" = "200" ] || { echo "start-${code}"; return 0; }
  wait_status "$id" 120 completed completed_with_errors failed cancelled >/dev/null || true
  echo "$id"
}

catalog() { # REPO_KEY -> "name version" lines from the Packages-tab API, sorted
  aj GET "/api/v1/packages?repository_key=${1}&per_page=100" \
    | jq -r '.items[]? | "\(.name) \(.version)"' 2>/dev/null | sort
}
catalog_db() { # REPO_KEY -> "name version" lines from packages x package_versions
  psql_rows "SELECT p.name || ' ' || pv.version FROM packages p
    JOIN package_versions pv ON pv.package_id = p.id
    JOIN repositories r ON r.id = p.repository_id
    WHERE r.key = '${1}' ORDER BY 1;"
}
live_paths() { # REPO_KEY -> live artifact paths
  psql_rows "SELECT a.path FROM artifacts a JOIN repositories r ON r.id = a.repository_id
    WHERE r.key = '${1}' AND a.is_deleted = false ORDER BY 1;"
}
packages_index() { # REPO_KEY ARCH OUTFILE -> http code
  fetch "/debian/${1}/dists/stable/main/binary-${2}/Packages" "$3"
}
# The Packages stanza for one package name (blank-line separated), or "".
stanza() { # FILE PACKAGE
  awk -v p="$2" 'BEGIN{RS=""} $0 ~ "(^|\n)Package: " p "(\n|$)" {print; exit}' "$1" 2>/dev/null
}

begin_suite "migration-package-catalog"

# ===========================================================================
# SETUP — build the real source files and load them into the mock
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

SRC="${WORK}/catalog"
if ! python3 -I "${TIER_DIR}/fixtures/build_catalog.py" "$SRC" "${DTF_DIR}/fixtures/rpm" 2>"${WORK}/build.err"; then
  begin_test "setup: build the Maven and Debian source files"
  infra_fail "fixtures/build_catalog.py failed" "$(cat "${WORK}/build.err")"
  end_suite
fi
if ! docker cp "${SRC}/." "${MOCK}:/srv/catalog/" >"${WORK}/cp.err" 2>&1; then
  begin_test "setup: copy the source files into the mock Artifactory"
  infra_fail "docker cp into ${MOCK} failed" "$(cat "${WORK}/cp.err")"
  end_suite
fi

CONN="$(aj POST /api/v1/migrations/connections "$(jq -nc --arg n "dtf-migcat-${SUF}" '{
  name: $n, url: "http://mock-artifactory", auth_type: "basic_auth",
  source_type: "artifactory", credentials: {username: "dtf", password: "dtf"}
}')")"
CONN_ID="$(jqf "$CONN" '.id // empty' '')"
if [ -z "$CONN_ID" ]; then
  begin_test "setup: create the migration source connection"
  infra_fail "POST /api/v1/migrations/connections returned no id; the mock source needs \
AK_SSRF_ALLOW_PRIVATE_CIDRS + ALLOW_HTTP_INTEGRATIONS from the upstreams.mock-artifactory-catalog overlay" \
    "$(echo "$CONN" | head -c 500)"
  end_suite
fi
CONN_TEST="$(aj POST "/api/v1/migrations/connections/${CONN_ID}/test")"
if [ "$(jqf "$CONN_TEST" '.success // false' 'false')" != "true" ]; then
  begin_test "setup: the backend can reach the migration source"
  infra_fail "connection test did not succeed" "$(echo "$CONN_TEST" | head -c 500)"
  end_suite
fi
SRC_LIST="$(aj GET "/api/v1/migrations/connections/${CONN_ID}/repositories")"
for r in "$MVN" "$DEB" "$RPM" "$DEBC" "$CRAN" "$SLOW"; do
  if ! echo "$SRC_LIST" | jq -e --arg k "$r" '[.items[]?.key] | index($k)' >/dev/null 2>&1; then
    begin_test "setup: the mock source advertises the fixture repositories"
    infra_fail "the source does not list '${r}' (MOCK_REPOS in the overlay must match this oracle)" \
      "$(echo "$SRC_LIST" | head -c 500)"
    end_suite
  fi
done

# #3926: start the slow-source job first. The mock streams its one file over
# ~36 s; the other migrations run meanwhile and the result is read at the end.
JOB_SLOW="$(make_job "$SLOW")"
SLOW_START_CODE="000"
[ -n "$JOB_SLOW" ] && SLOW_START_CODE="$(ac POST "/api/v1/migrations/${JOB_SLOW}/start")"

# ===========================================================================
# MAVEN (#4691)
# ===========================================================================
JOB_MVN="$(run_job "$MVN")"
case "$JOB_MVN" in ""|start-*)
  begin_test "setup: create and start the Maven migration"
  infra_fail "the Maven job could not be created/started (${JOB_MVN:-no id})" "$(cat "${WORK}/last.body" 2>/dev/null | head -c 400)"
  end_suite ;;
esac
MVN_ROW="$(job_row "$JOB_MVN")"
M_ST="$(jqf "$MVN_ROW" '.status // "?"' '?')"
M_T="$(jqf "$MVN_ROW" '.total_items // 0' 0)"
M_C="$(jqf "$MVN_ROW" '.completed_items // 0' 0)"
M_F="$(jqf "$MVN_ROW" '.failed_items // 0' 0)"
M_LIVE="$(live_paths "$MVN" | grep -c . || true)"
M_FMT="$(psql_ak "SELECT format::text FROM repositories WHERE key='${MVN}';")"

begin_test "CONTROL: the Maven migration completes and moves every source file into a maven repository"
if [ "$M_ST" = "completed" ] && [ "${M_T:-0}" -eq "$MVN_SOURCE_FILES" ] \
   && [ "${M_C:-0}" -eq "$MVN_SOURCE_FILES" ] && [ "${M_F:-0}" -eq 0 ] && [ "$M_FMT" = "maven" ]; then
  pass
else
  fail "Maven migration: status=${M_ST} completed=${M_C}/${M_T} failed=${M_F} (want completed ${MVN_SOURCE_FILES}/${MVN_SOURCE_FILES}, 0 failed); destination format=${M_FMT} (want maven)" \
    "$(echo "$MVN_ROW" | jq -c '{status,total_items,completed_items,failed_items,skipped_items,error_message}' 2>/dev/null)
live artifact rows (${M_LIVE}):
$(live_paths "$MVN")"
fi

begin_test "CONTROL: the migrated jar downloads byte-identical through the Maven route"
JAR_CODE="$(fetch "/maven/${MVN}/${MVN_JAR}" "${WORK}/demo.jar")"
if [ "$JAR_CODE" = "200" ] && [ "$(sha "${WORK}/demo.jar")" = "$(sha "${SRC}/${MVN}/${MVN_JAR}")" ]; then
  pass
else
  fail "GET /maven/${MVN}/${MVN_JAR} -> ${JAR_CODE}, sha256 $(sha "${WORK}/demo.jar") (want 200 and the source's $(sha "${SRC}/${MVN}/${MVN_JAR}"))"
fi

MVN_API="$(catalog "$MVN")"
MVN_DB="$(catalog_db "$MVN")"
begin_test "FIX #4691: the Packages-tab API lists the migrated module as com.dtf:demo 1.0.0, and nothing else"
if [ "$MVN_API" = "com.dtf:demo 1.0.0" ]; then
  pass
else
  fail "MIGRATED MAVEN REPOSITORY HAS NO PACKAGES (#4691): GET /api/v1/packages?repository_key=${MVN} returned \
[$(echo "$MVN_API" | paste -sd, -)], want exactly [com.dtf:demo 1.0.0]. The files are stored (${M_LIVE} live rows) \
but migration_catalog_entry skipped the Maven family, so the Packages tab is empty. Sidecars and \
maven-metadata.xml must not appear as packages." \
    "$(aj GET "/api/v1/packages?repository_key=${MVN}" | head -c 600)"
fi

begin_test "FIX #4691: package_versions holds the groupId:artifactId row at the directory version"
if [ "$MVN_DB" = "com.dtf:demo 1.0.0" ]; then
  pass
else
  fail "packages x package_versions for ${MVN} = [$(echo "$MVN_DB" | paste -sd, -)], want [com.dtf:demo 1.0.0]"
fi

MM_CODE="$(fetch "/maven/${MVN}/com/dtf/demo/maven-metadata.xml" "${WORK}/maven-metadata.xml")"
begin_test "FIX #3927: the migrated GA serves maven-metadata.xml naming 1.0.0 as <latest> and <release>"
if [ "$MM_CODE" = "200" ] \
   && grep -q '<artifactId>demo</artifactId>' "${WORK}/maven-metadata.xml" \
   && grep -q '<latest>1.0.0</latest>' "${WORK}/maven-metadata.xml" \
   && grep -q '<release>1.0.0</release>' "${WORK}/maven-metadata.xml" \
   && grep -q '<version>1.0.0</version>' "${WORK}/maven-metadata.xml"; then
  pass
else
  fail "GET /maven/${MVN}/com/dtf/demo/maven-metadata.xml -> ${MM_CODE}; want 200 listing 1.0.0 as <latest>/<release>. \
maven-metadata.xml is generated from 'maven' artifact_metadata rows, which the importer did not write, so \
LATEST/RELEASE resolution of a migrated GA fell through to another repository (#3927)." \
    "$(head -c 800 "${WORK}/maven-metadata.xml" 2>/dev/null)
maven metadata rows: $(psql_ak "SELECT count(*) FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id
  JOIN repositories r ON r.id = a.repository_id WHERE r.key='${MVN}' AND am.format='maven';")"
fi

# ===========================================================================
# DEBIAN (#4657)
# ===========================================================================
JOB_DEB="$(run_job "$DEB")"
case "$JOB_DEB" in ""|start-*)
  begin_test "setup: create and start the Debian migration"
  infra_fail "the Debian job could not be created/started (${JOB_DEB:-no id})" "$(cat "${WORK}/last.body" 2>/dev/null | head -c 400)"
  end_suite ;;
esac
DEB_ROW="$(job_row "$JOB_DEB")"
D_ST="$(jqf "$DEB_ROW" '.status // "?"' '?')"
D_T="$(jqf "$DEB_ROW" '.total_items // 0' 0)"
D_C="$(jqf "$DEB_ROW" '.completed_items // 0' 0)"
D_F="$(jqf "$DEB_ROW" '.failed_items // 0' 0)"
D_FMT="$(psql_ak "SELECT format::text FROM repositories WHERE key='${DEB}';")"
D_PATHS="$(live_paths "$DEB")"

begin_test "CONTROL: the Debian migration completes and moves every source file into a debian repository"
if [ "$D_ST" = "completed" ] && [ "${D_T:-0}" -eq "$DEB_SOURCE_FILES" ] \
   && [ "${D_C:-0}" -eq "$DEB_SOURCE_FILES" ] && [ "${D_F:-0}" -eq 0 ] && [ "$D_FMT" = "debian" ]; then
  pass
else
  fail "Debian migration: status=${D_ST} completed=${D_C}/${D_T} failed=${D_F} (want completed ${DEB_SOURCE_FILES}/${DEB_SOURCE_FILES}, 0 failed); destination format=${D_FMT} (want debian)" \
    "$(echo "$DEB_ROW" | jq -c '{status,total_items,completed_items,failed_items,skipped_items,error_message}' 2>/dev/null)
live artifact rows:
${D_PATHS}"
fi

begin_test "CONTROL: the pooled .deb downloads byte-identical from its pool path"
P_CODE="$(fetch "/debian/${DEB}/${DEB_POOLED}" "${WORK}/pooled.deb")"
if [ "$P_CODE" = "200" ] && [ "$(sha "${WORK}/pooled.deb")" = "$(sha "${SRC}/${DEB}/${DEB_POOLED}")" ]; then
  pass
else
  fail "GET /debian/${DEB}/${DEB_POOLED} -> ${P_CODE}, sha256 $(sha "${WORK}/pooled.deb") (want 200 and $(sha "${SRC}/${DEB}/${DEB_POOLED}"))" \
    "live artifact rows:
${D_PATHS}"
fi

DEB_API="$(catalog "$DEB")"
begin_test "FIX #4657: the Packages-tab API lists both migrated .debs (dtfpkg 1.0, dtfflat 2.0)"
if [ "$DEB_API" = "$(printf 'dtfflat 2.0\ndtfpkg 1.0')" ]; then
  pass
else
  fail "MIGRATED DEBIAN PACKAGES NOT REGISTERED (#4657): GET /api/v1/packages?repository_key=${DEB} returned \
[$(echo "$DEB_API" | paste -sd, -)], want [dtfflat 2.0, dtfpkg 1.0]. The importer had no Debian name/version \
parser, so no catalog row was written." \
    "$(aj GET "/api/v1/packages?repository_key=${DEB}" | head -c 600)
package_versions: $(catalog_db "$DEB" | paste -sd, -)"
fi

IDX_CODE="$(packages_index "$DEB" amd64 "${WORK}/Packages")"
ST_POOLED="$(stanza "${WORK}/Packages" dtfpkg)"
ST_FLAT="$(stanza "${WORK}/Packages" dtfflat)"
begin_test "FIX #4657: the pooled .deb is indexed from its control file (Description present, digest matches)"
if [ "$IDX_CODE" = "200" ] \
   && echo "$ST_POOLED" | grep -qxF "Description: ${DEB_POOLED_DESC}" \
   && echo "$ST_POOLED" | grep -qxF "Filename: ${DEB_POOLED}" \
   && echo "$ST_POOLED" | grep -qxF "SHA256: $(sha "${SRC}/${DEB}/${DEB_POOLED}")"; then
  pass
else
  fail "dists/stable/main/binary-amd64/Packages (HTTP ${IDX_CODE}) does not carry dtfpkg's control file: want \
'Description: ${DEB_POOLED_DESC}', 'Filename: ${DEB_POOLED}' and its SHA256. Without the 'debian' control \
document the migration never wrote, the index is synthesised from the file name and every control field \
(Description, Maintainer, Depends...) is lost." \
    "dtfpkg stanza:
${ST_POOLED:-<absent>}
--- whole index ---
$(head -c 1500 "${WORK}/Packages" 2>/dev/null)"
fi

begin_test "FIX #4657: a .deb from Artifactory's flat pool/<file>.deb layout is filed under pool/main/ and indexed"
if [ "$IDX_CODE" = "200" ] \
   && echo "$ST_FLAT" | grep -qxF "Filename: ${DEB_FLAT_DST}" \
   && echo "$ST_FLAT" | grep -qxF "Description: ${DEB_FLAT_DESC}"; then
  pass
else
  fail "the flat-layout package is missing from main/binary-amd64/Packages (want Filename: ${DEB_FLAT_DST} with \
its control Description). A .deb stored at ${DEB_FLAT_SRC} sits outside pool/<component>/, where the Packages \
query never looks, so apt cannot see it." \
    "dtfflat stanza: ${ST_FLAT:-<absent>}
live artifact rows:
${D_PATHS}"
fi

begin_test "FIX #4657: the flat-layout .deb downloads from the pool path the index advertises"
F_CODE="$(fetch "/debian/${DEB}/${DEB_FLAT_DST}" "${WORK}/flat.deb")"
if [ "$F_CODE" = "200" ] && [ "$(sha "${WORK}/flat.deb")" = "$(sha "${SRC}/${DEB}/${DEB_FLAT_SRC}")" ]; then
  pass
else
  fail "GET /debian/${DEB}/${DEB_FLAT_DST} -> ${F_CODE} (want 200 and the source bytes)" \
    "live artifact rows:
${D_PATHS}"
fi

# ===========================================================================
# RECOVERY — an already-migrated repository whose catalog is empty
# ===========================================================================
# Maven: the brief for this tier expected the #1570 storage reindex to rebuild
# the catalog. #4735 documents that it cannot (it only registers objects with
# NO artifacts row and never touches the catalog); the tool it names is the
# #3659 catalog backfill. Both are exercised: the reindex as a CONTROL that it
# leaves an indexed repository alone, the backfill as the recovery assertion.
MVN_REPO_ID="$(psql_ak "SELECT id FROM repositories WHERE key='${MVN}';")"
LIVE_BEFORE="$(live_paths "$MVN" | grep -c . || true)"
psql_ak "DELETE FROM packages WHERE repository_id='${MVN_REPO_ID}';" >/dev/null
EMPTIED="$(catalog_db "$MVN" | grep -c . || true)"

RX_CODE="$(ac POST "/api/v1/admin/repositories/${MVN}/reindex-storage" '{"dry_run":false}')"
RX_BODY="$(cat "${WORK}/last.body" 2>/dev/null)"
RX_REG="$(jqf "$RX_BODY" '.registered // -1' -1)"
AFTER_RX_CATALOG="$(catalog_db "$MVN" | paste -sd, -)"
LIVE_AFTER_RX="$(live_paths "$MVN" | grep -c . || true)"
echo "  [observe] reindex-storage on ${MVN}: HTTP ${RX_CODE} registered=${RX_REG}; catalog afterwards=[${AFTER_RX_CATALOG}]"

begin_test "CONTROL: reindex-storage leaves a fully indexed migrated Maven repository alone (registers nothing)"
if [ "${EMPTIED:-1}" -ne 0 ]; then
  infra_fail "could not empty the catalog for ${MVN} to stage the recovery (still ${EMPTIED} rows)"
elif [ "$RX_CODE" = "200" ] && [ "$RX_REG" = "0" ] && [ "$LIVE_AFTER_RX" = "$LIVE_BEFORE" ]; then
  pass
else
  fail "POST /api/v1/admin/repositories/${MVN}/reindex-storage -> ${RX_CODE} registered=${RX_REG}; live rows ${LIVE_BEFORE} -> ${LIVE_AFTER_RX}. \
Every migrated object already has a row, so the #1570 reindex must register nothing and duplicate nothing." \
    "$(echo "$RX_BODY" | head -c 600)"
fi

BF_CODE="$(ac POST "/api/v1/admin/packages/backfill?repository_key=${MVN}")"
BF_BODY="$(cat "${WORK}/last.body" 2>/dev/null)"
begin_test "RECOVERY (pre-existing #3659 tool, both images): the admin catalog backfill rebuilds a migrated Maven repository's catalog"
AFTER_BF="$(catalog "$MVN")"
if [ "$BF_CODE" = "200" ] && [ "$AFTER_BF" = "com.dtf:demo 1.0.0" ]; then
  pass
else
  fail "POST /api/v1/admin/packages/backfill?repository_key=${MVN} -> ${BF_CODE}; catalog afterwards \
[$(echo "$AFTER_BF" | paste -sd, -)], want [com.dtf:demo 1.0.0] (the recovery #4735's changelog documents)" \
    "$(echo "$BF_BODY" | head -c 600)"
fi

# Debian: #4741 documents that the reindex is Maven-only and the catalog
# backfill does not cover debian; its recovery is to RE-RUN the migration,
# which re-imports any pooled .deb that lacks its `debian` control document.
# Reproduce a pre-fix import (rows kept, control documents and catalog gone)
# and re-run.
DEB_REPO_ID="$(psql_ak "SELECT id FROM repositories WHERE key='${DEB}';")"
DRX_CODE="$(ac POST "/api/v1/admin/repositories/${DEB}/reindex-storage" '{"dry_run":false}')"
echo "  [observe] reindex-storage on ${DEB}: HTTP ${DRX_CODE} $(head -c 200 "${WORK}/last.body" 2>/dev/null)"
psql_ak "DELETE FROM packages WHERE repository_id='${DEB_REPO_ID}';" >/dev/null
psql_ak "DELETE FROM artifact_metadata WHERE format='debian' AND artifact_id IN
  (SELECT id FROM artifacts WHERE repository_id='${DEB_REPO_ID}');" >/dev/null
STRIPPED="$(psql_ak "SELECT count(*) FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id
  WHERE a.repository_id='${DEB_REPO_ID}' AND am.format='debian';")"
JOB_DEB2="$(run_job "$DEB")"
D2_ST="$(job_field "$JOB_DEB2" status)"
DEB2_API="$(catalog "$DEB")"
packages_index "$DEB" amd64 "${WORK}/Packages2" >/dev/null
ST2_POOLED="$(stanza "${WORK}/Packages2" dtfpkg)"
D2_LIVE="$(live_paths "$DEB" | grep -c . || true)"

begin_test "RECOVERY #4657: re-running the migration re-registers .debs an earlier import left unregistered"
if [ "${STRIPPED:-1}" != "0" ] || [ -z "$JOB_DEB2" ]; then
  infra_fail "could not stage the pre-fix state (debian control documents left=${STRIPPED}) or re-run the job (${JOB_DEB2:-no id})"
elif [ "$D2_ST" = "completed" ] && [ "$DEB2_API" = "$(printf 'dtfflat 2.0\ndtfpkg 1.0')" ] \
     && echo "$ST2_POOLED" | grep -qxF "Description: ${DEB_POOLED_DESC}" \
     && [ "$D2_LIVE" = "$DEB_SOURCE_FILES" ]; then
  pass
else
  fail "after stripping the control documents and catalog and re-running the migration: status=${D2_ST}, \
catalog=[$(echo "$DEB2_API" | paste -sd, -)] (want dtfflat 2.0, dtfpkg 1.0), dtfpkg Description present=\
$(echo "$ST2_POOLED" | grep -cxF "Description: ${DEB_POOLED_DESC}"), live rows=${D2_LIVE} (want ${DEB_SOURCE_FILES}). \
#4741's documented recovery is the re-run: an already-imported .deb with no 'debian' control document must be \
re-imported in place, not skipped as a duplicate." \
    "$(job_row "$JOB_DEB2" | jq -c '{status,total_items,completed_items,skipped_items,failed_items}' 2>/dev/null)
live rows:
$(live_paths "$DEB")"
fi

# ===========================================================================
# ASSESSMENT (#3928)
# ===========================================================================
# The seeded count, per source repository, straight from the files the mock
# serves (the __props tree is not a repository).
declare -A SEEDED=()
SEEDED_TOTAL=0
for r in "$MVN" "$DEB" "$RPM" "$DEBC" "$CRAN" "$SLOW"; do
  SEEDED[$r]="$(find "${SRC}/${r}" -type f | grep -c . || true)"
  SEEDED_TOTAL=$((SEEDED_TOTAL + SEEDED[$r]))
done
AS_JOB="$(jqf "$(aj POST /api/v1/migrations "$(jq -nc --arg cid "$CONN_ID" \
  '{source_connection_id: $cid, job_type: "assessment", config: {}}')")" '.id // empty' '')"
AS_CODE="000"; AS_BODY=""
if [ -n "$AS_JOB" ]; then
  AS_CODE="$(ac POST "/api/v1/migrations/${AS_JOB}/assess")"
  for _ in $(seq 1 30); do
    AS_BODY="$(aj GET "/api/v1/migrations/${AS_JOB}/assessment")"
    # The handler answers zeros with status "assessing" until the worker saves.
    case "$(jqf "$AS_BODY" '.status // empty' '')" in ready|failed|completed) break ;; esac
    sleep 1
  done
fi
AS_TOTAL="$(jqf "$AS_BODY" '.total_artifacts // "absent"' 'absent')"
AS_EXACT="$(jqf "$AS_BODY" '.total_artifacts_exact | tostring' 'absent')"
AS_REPOS="$(jqf "$AS_BODY" '[.repositories[]? | "\(.key)=\(.artifact_count)/\(.artifact_count_exact)"] | sort | join(",")' '')"
WANT_REPOS="$(for r in "${!SEEDED[@]}"; do echo "${r}=${SEEDED[$r]}/true"; done | sort | paste -sd, -)"
begin_test "FIX #3928: the assessment counts all ${SEEDED_TOTAL} source artifacts, per repository, and flags the counts exact"
if [ -z "$AS_JOB" ] || [ "$AS_CODE" != "202" ]; then
  fail "could not run the assessment: job=${AS_JOB:-none} POST /assess -> ${AS_CODE}" "$(head -c 400 "${WORK}/last.body" 2>/dev/null)"
elif [ "$AS_TOTAL" = "$SEEDED_TOTAL" ] && [ "$AS_EXACT" = "true" ] && [ "$AS_REPOS" = "$WANT_REPOS" ]; then
  pass
else
  fail "assessment (status $(jqf "$AS_BODY" '.status // "?"' '?')) total_artifacts=${AS_TOTAL} total_artifacts_exact=${AS_EXACT} (want ${SEEDED_TOTAL}, true); \
per repository [${AS_REPOS}] (want [${WANT_REPOS}]). The assessment read a one-row listing page's range.total \
as the repository size, so every repository counted as at most one artifact (#3928)." \
    "$(echo "$AS_BODY" | head -c 800)"
fi

# ===========================================================================
# RPM (#3925)
# ===========================================================================
JOB_RPM="$(run_job "$RPM")"
RPM_ROW="$(job_row "$JOB_RPM")"
R_ST="$(jqf "$RPM_ROW" '.status // "?"' '?')"
R_C="$(jqf "$RPM_ROW" '.completed_items // 0' 0)"
R_T="$(jqf "$RPM_ROW" '.total_items // 0' 0)"
R_FMT="$(psql_ak "SELECT format::text FROM repositories WHERE key='${RPM}';")"
begin_test "CONTROL: the RPM migration completes and moves both source packages"
if [ "$R_ST" = "completed" ] && [ "$R_C" = "${SEEDED[$RPM]}" ] && [ "$R_T" = "${SEEDED[$RPM]}" ]; then
  pass
else
  fail "RPM migration: status=${R_ST} completed=${R_C}/${R_T} (want ${SEEDED[$RPM]})" \
    "$(echo "$RPM_ROW" | jq -c '{status,total_items,completed_items,failed_items,error_message}' 2>/dev/null)"
fi

begin_test "FIX #3925: the RPM source lands in a native rpm repository and the package downloads byte-identical from it"
RPM_DL="$(fetch "/rpm/${RPM}/packages/akdep-app-2.0-1.noarch.rpm" "${WORK}/app.rpm")"
if [ "$R_FMT" = "rpm" ] && [ "$RPM_DL" = "200" ] \
   && [ "$(sha "${WORK}/app.rpm")" = "$(sha "${SRC}/${RPM}/akdep-app-2.0-1.noarch.rpm")" ]; then
  pass
else
  fail "destination format=${R_FMT} (want rpm); GET /rpm/${RPM}/packages/akdep-app-2.0-1.noarch.rpm -> ${RPM_DL}. \
Before #3925 RPM was a file-copy-only format and the migration provisioned a generic repository."
fi

# Since 1.12.0 hosted RPM repodata is precomputed in the background a few
# seconds after the last write (artifact-keeper#4544). Ask for the build and
# wait for it, so the read below sees every migrated package. Best effort:
# an image without the endpoint (404) renders repodata on request, which is
# already current.
RB_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${CURLF[@]}" --max-time 330 -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${RPM}/rpm/repodata/rebuild?wait=true" 2>/dev/null || echo 000)"
echo "  rpm repodata rebuild?wait=true -> HTTP ${RB_CODE} (404 on images without precomputed repodata)"
PRIM_CODE="$(fetch "/rpm/${RPM}/repodata/primary.xml.gz" "${WORK}/primary.xml.gz")"
gunzip -c "${WORK}/primary.xml.gz" > "${WORK}/primary.xml" 2>/dev/null || true
# The akdep-app <package> block alone.
APP_PKG="$(awk '/<package /{b=""} {b=b $0 "\n"} /<\/package>/{ if (b ~ /<name>akdep-app<\/name>/) printf "%s", b }' "${WORK}/primary.xml" 2>/dev/null)"
begin_test "FIX #3925: the migrated RPM's primary.xml carries its header summary and <rpm:requires> akdep-libfoo"
if [ "$PRIM_CODE" = "200" ] \
   && echo "$APP_PKG" | grep -qF '<summary>artifact-keeper E2E dependency fixture (consumer)</summary>' \
   && echo "$APP_PKG" | grep -qF '<rpm:requires>' \
   && echo "$APP_PKG" | grep -qE '<rpm:entry name="akdep-libfoo" flags="GE"[^>]*ver="1.0"'; then
  pass
else
  fail "repodata/primary.xml.gz (HTTP ${PRIM_CODE}) for the migrated ${RPM}: the akdep-app package has no header \
summary or no <rpm:requires> akdep-libfoo >= 1.0. The importer copied .rpm files without recording their header \
metadata, so repodata was synthesised from the file name and dnf cannot resolve dependencies (#3925)." \
    "akdep-app block:
${APP_PKG:-<absent>}
--- head of primary.xml ---
$(head -c 1200 "${WORK}/primary.xml" 2>/dev/null)"
fi

# ===========================================================================
# DEBIAN COMPONENT (#4797 / #4740, 1.11.3)
# ===========================================================================
JOB_DEBC="$(run_job "$DEBC")"
DC_ST="$(job_field "$JOB_DEBC" status)"
DC_PATHS="$(live_paths "$DEBC")"
fetch "/debian/${DEBC}/dists/stable/main/binary-amd64/Packages" "${WORK}/debc-main" >/dev/null
fetch "/debian/${DEBC}/dists/stable/universe/binary-amd64/Packages" "${WORK}/debc-univ" >/dev/null
ST_LETTER="$(stanza "${WORK}/debc-main" dtfletter)"
ST_UNIV_MAIN="$(stanza "${WORK}/debc-main" dtfuniv)"
ST_UNIV="$(stanza "${WORK}/debc-univ" dtfuniv)"

begin_test "CONTROL: the Debian component migration completes and both packages are stored"
if [ "$DC_ST" = "completed" ] && [ "$(echo "$DC_PATHS" | grep -c '\.deb$' || true)" = "2" ]; then
  pass
else
  fail "migration of ${DEBC}: status=${DC_ST}, live .deb rows:
${DC_PATHS}" "$(job_row "$JOB_DEBC" | jq -c '{status,total_items,completed_items,failed_items}' 2>/dev/null)"
fi

begin_test "FIX #4740: a .deb in the Nexus pool/<letter>/<name>/ layout is filed under pool/main/ and listed in dists/stable/main"
if echo "$ST_LETTER" | grep -qxF "Filename: ${DEBC_LETTER_DST}" \
   && echo "$DC_PATHS" | grep -qxF "$DEBC_LETTER_DST"; then
  pass
else
  fail "dtfletter is not in dists/stable/main/binary-amd64/Packages at Filename: ${DEBC_LETTER_DST}. A .deb kept at \
${DEBC_LETTER_SRC} takes the letter 'd' as its component, so apt pointed at 'main' never sees it (#4740)." \
    "dtfletter stanza in main: ${ST_LETTER:-<absent>}
live rows:
${DC_PATHS}"
fi

begin_test "FIX #4740: a .deb whose deb.component property is 'universe' is filed under pool/universe/ and listed there, not in main"
if echo "$ST_UNIV" | grep -qxF "Filename: ${DEBC_UNIV_DST}" && [ -z "$ST_UNIV_MAIN" ]; then
  pass
else
  fail "dtfuniv (Artifactory property deb.component=universe): universe stanza Filename present=\
$(echo "$ST_UNIV" | grep -cxF "Filename: ${DEBC_UNIV_DST}"), listed in main=$([ -n "$ST_UNIV_MAIN" ] && echo yes || echo no). \
The migration must read the item's deb.component property (#4740)." \
    "universe stanza: ${ST_UNIV:-<absent>}
live rows:
${DC_PATHS}"
fi

# Stage what a pre-#4740 run left behind: the letter package's row at its
# source path (the content is addressed by digest, so moving the row is all
# an older import differs by), then re-run the job.
DEBC_REPO_ID="$(psql_ak "SELECT id FROM repositories WHERE key='${DEBC}';")"
MOVED="$(psql_ak "WITH m AS (UPDATE artifacts SET path='${DEBC_LETTER_SRC}' WHERE repository_id='${DEBC_REPO_ID}'
  AND path='${DEBC_LETTER_DST}' AND is_deleted=false RETURNING 1) SELECT count(*) FROM m;")"
JOB_DEBC2="$(run_job "$DEBC")"
DC2_ST="$(job_field "$JOB_DEBC2" status)"
DC2_PATHS="$(live_paths "$DEBC")"
OLD_LIVE="$(psql_ak "SELECT count(*) FROM artifacts WHERE repository_id='${DEBC_REPO_ID}'
  AND path='${DEBC_LETTER_SRC}' AND is_deleted=false;")"
fetch "/debian/${DEBC}/dists/stable/main/binary-amd64/Packages" "${WORK}/debc-main2" >/dev/null
begin_test "FIX #4740: re-running the job moves a package an earlier run misfiled and retires the old row"
if [ "$MOVED" != "1" ]; then
  if echo "$DC_PATHS" | grep -qxF "$DEBC_LETTER_DST"; then
    infra_fail "could not stage the misfiled row (UPDATE returned '${MOVED}')"
  else
    fail "the first run never filed dtfletter under ${DEBC_LETTER_DST}, so there is nothing to move (see the case above)" \
      "live rows:
${DC_PATHS}"
  fi
elif [ "$DC2_ST" = "completed" ] && echo "$DC2_PATHS" | grep -qxF "$DEBC_LETTER_DST" && [ "$OLD_LIVE" = "0" ] \
     && stanza "${WORK}/debc-main2" dtfletter | grep -qxF "Filename: ${DEBC_LETTER_DST}"; then
  pass
else
  fail "after moving dtfletter's row back to ${DEBC_LETTER_SRC} and re-running: status=${DC2_ST}, row at the old path \
still live=${OLD_LIVE} (want 0), live rows:
${DC2_PATHS}" "$(job_row "$JOB_DEBC2" | jq -c '{status,total_items,completed_items,skipped_items,failed_items}' 2>/dev/null)"
fi

# ===========================================================================
# CRAN (#2525)
# ===========================================================================
JOB_CRAN="$(run_job "$CRAN")"
CR_ROW="$(job_row "$JOB_CRAN")"
CR_ST="$(jqf "$CR_ROW" '.status // "?"' '?')"
CR_FMT="$(psql_ak "SELECT format::text FROM repositories WHERE key='${CRAN}';")"
CR_IDX="$(fetch "/cran/${CRAN}/src/contrib/PACKAGES" "${WORK}/cran-PACKAGES")"
CR_DL="$(fetch "/cran/${CRAN}/src/contrib/dtfr_1.0.tar.gz" "${WORK}/dtfr.tar.gz")"
ST_DTFR="$(stanza "${WORK}/cran-PACKAGES" dtfr)"
begin_test "FIX #2525: an Artifactory cran repository migrates into a native CRAN repository and its source package downloads"
if [ "$CR_ST" = "completed" ] && [ "$CR_FMT" = "cran" ] && [ "$CR_DL" = "200" ] \
   && [ "$(sha "${WORK}/dtfr.tar.gz")" = "$(sha "${SRC}/${CRAN}/src/contrib/dtfr_1.0.tar.gz")" ]; then
  pass
else
  fail "CRAN migration: status=${CR_ST}, destination format=${CR_FMT} (want cran), \
GET /cran/${CRAN}/src/contrib/dtfr_1.0.tar.gz -> ${CR_DL} (want 200 and the source bytes)" \
    "$(echo "$CR_ROW" | jq -c '{status,total_items,completed_items,skipped_items,failed_items,error_message}' 2>/dev/null)
live rows:
$(live_paths "$CRAN")"
fi

begin_test "FIX #2525: src/contrib/PACKAGES lists dtfr 1.0 and not the source's own PACKAGES file or its entries"
if [ "$CR_IDX" = "200" ] && echo "$ST_DTFR" | grep -qxF "Version: 1.0" \
   && ! grep -qE '^Package: (PACKAGES|dtfsourceonly)$' "${WORK}/cran-PACKAGES"; then
  pass
else
  fail "GET /cran/${CRAN}/src/contrib/PACKAGES -> ${CR_IDX}; want a 'Package: dtfr' stanza with 'Version: 1.0' and no \
'Package: PACKAGES' / 'Package: dtfsourceonly' (the source's index must be skipped, #2525)." \
    "$(head -c 800 "${WORK}/cran-PACKAGES" 2>/dev/null)"
fi

# ===========================================================================
# SLOW SOURCE BODY (#3926)
# ===========================================================================
[ -n "$JOB_SLOW" ] && wait_status "$JOB_SLOW" 150 completed completed_with_errors failed cancelled >/dev/null
SLOW_ROW="$(job_row "$JOB_SLOW")"
SL_ST="$(jqf "$SLOW_ROW" '.status // "?"' '?')"
SL_C="$(jqf "$SLOW_ROW" '.completed_items // 0' 0)"
SL_F="$(jqf "$SLOW_ROW" '.failed_items // 0' 0)"
SL_ERR="$(aj GET "/api/v1/migrations/${JOB_SLOW}/items" | jq -r '[.items[]?.error_message // empty] | join("; ")' 2>/dev/null)"
SL_SHA="$(psql_ak "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id
  WHERE r.key='${SLOW}' AND a.path='${SLOW_FILE}' AND a.is_deleted=false;")"
SL_SECS="$(psql_ak "SELECT GREATEST(0, EXTRACT(EPOCH FROM (MAX(i.completed_at) - MIN(i.started_at)))::int)
  FROM migration_items i WHERE i.job_id='${JOB_SLOW}';")"
MOCK_SLOW_HITS="$(docker exec "$MOCK" cat /tmp/mock-requests.log 2>/dev/null | grep -c "GET /${SLOW}/${SLOW_FILE} " || true)"
begin_test "CONTROL: the mock source served ${SLOW_FILE} (the slow leg ran)"
if [ "$SLOW_START_CODE" = "200" ] && [ "${MOCK_SLOW_HITS:-0}" -ge 1 ]; then
  pass
else
  fail "slow job ${JOB_SLOW:-none}: POST /start -> ${SLOW_START_CODE}, source GETs of ${SLOW_FILE}=${MOCK_SLOW_HITS}"
fi
begin_test "FIX #3926: an artifact whose body streams for ~36 s migrates intact (no 30 s whole-request timeout)"
if [ "$SL_ST" = "completed" ] && [ "$SL_C" = "1" ] && [ "$SL_F" = "0" ] \
   && [ "$SL_SHA" = "$(sha "${SRC}/${SLOW}/${SLOW_FILE}")" ]; then
  pass
else
  fail "slow-source migration: status=${SL_ST} completed=${SL_C} failed=${SL_F}, stored sha256=${SL_SHA:-none} \
(want completed 1, 0 failed, sha $(sha "${SRC}/${SLOW}/${SLOW_FILE}")); item errors: ${SL_ERR:-none}. \
The Artifactory client's 30 s whole-request timeout covered the response body, so any artifact needing more \
than 30 s of source bandwidth failed with 'error decoding response body' (#3926)." \
    "$(echo "$SLOW_ROW" | jq -c '{status,total_items,completed_items,failed_items,error_message}' 2>/dev/null)
item transfer window: ${SL_SECS:-?} s"
fi

end_suite
