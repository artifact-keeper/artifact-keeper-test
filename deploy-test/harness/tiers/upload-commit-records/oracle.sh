#!/usr/bin/env bash
# =============================================================================
# tiers/upload-commit-records/oracle.sh: an upload's format metadata and
#   revision commit with its artifact row, and its catalog row is written once
#   (artifact-keeper#6383, #6346, #6318)
# =============================================================================
# run.sh has stood up filesystem/single with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Primitives (see the manifest): a switchable fault trigger on
# artifact_metadata / artifact_versions for rows naming `dtfw13ufault`, and
# row-write counting triggers on packages / package_versions. Both live only
# in this slot's Postgres and are dropped on exit.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq
require_cmd python3

SUF="$(printf '%s' "${RUN_ID:-x}" | tr -cd '[:alnum:]' | tail -c 8 | tr '[:upper:]' '[:lower:]')"
SLOT="${DTF_SLOT:-x}"
R_PYPI="ucr-pypi-${SLOT}-${SUF}"
R_NUGET="ucr-nuget-${SLOT}-${SUF}"
R_RPM="ucr-rpm-${SLOT}-${SUF}"
R_VERS="ucr-vers-${SLOT}-${SUF}"
MARK="dtfw13ufault"
W="$(mktemp -d -t dtf-ucr-XXXXXX)"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>&1 | tr -d '[:space:]'; }
psql_x() { docker exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U registry -d artifact_registry -q 2>&1; }

cleanup() {
  psql_x >/dev/null <<'SQL' || true
DROP TRIGGER IF EXISTS dtf_ucr_fault ON artifact_metadata;
DROP TRIGGER IF EXISTS dtf_ucr_fault ON artifact_versions;
DROP TRIGGER IF EXISTS dtf_ucr_count ON packages;
DROP TRIGGER IF EXISTS dtf_ucr_count ON package_versions;
DROP FUNCTION IF EXISTS dtf_ucr_fault();
DROP FUNCTION IF EXISTS dtf_ucr_fault_rev();
DROP FUNCTION IF EXISTS dtf_ucr_count();
DROP TABLE IF EXISTS dtf_ucr_switch;
DROP TABLE IF EXISTS dtf_ucr_writes;
SQL
  rm -rf "$W"
}
trap cleanup EXIT

fault_on() { psql_q "INSERT INTO dtf_ucr_switch VALUES (true) ON CONFLICT DO NOTHING" >/dev/null; }
fault_off() { psql_q "DELETE FROM dtf_ucr_switch" >/dev/null; }
# writes <table> <package name> -> row writes the counting trigger logged
writes() { psql_q "SELECT COUNT(*) FROM dtf_ucr_writes WHERE tbl = '$1' AND lower(name) = lower('$2')"; }

# code <curl args...> -> HTTP status; the body lands in $W/body
code() { curl -s -o "$W/body" -w '%{http_code}' --max-time 120 "$@" 2>/dev/null || echo 000; }
body() { head -c 300 "$W/body" 2>/dev/null; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
BASIC="Authorization: Basic $(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64 | tr -d '\n')"

# live_row <repo key> <path>      -> id of the live artifact row ('' if none)
live_row() {
  psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id
          WHERE r.key = '$1' AND a.path = '$2' AND NOT a.is_deleted"
}
# live_name_row <repo key> <name> -> id of a live artifact row with that name
live_name_row() {
  psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id
          WHERE r.key = '$1' AND lower(a.name) = lower('$2') AND NOT a.is_deleted LIMIT 1"
}
has_metadata() { [ "$(psql_q "SELECT COUNT(*) FROM artifact_metadata WHERE artifact_id = '$1'")" = "1" ]; }

# --- fixtures -----------------------------------------------------------------
# wheel <project> <version> <summary> -> path of a minimal valid wheel
wheel() {
  python3 - "$W" "$1" "$2" "$3" <<'PY'
import sys, zipfile
out, name, version, summary = sys.argv[1:5]
dist = name.replace("-", "_")
path = f"{out}/{dist}-{version}-py3-none-any.whl"
with zipfile.ZipFile(path, "w") as z:
    z.writestr(f"{dist}/__init__.py", f"# {name} {version}\n")
    z.writestr(f"{dist}-{version}.dist-info/METADATA",
               f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: {summary}\n"
               "Requires-Python: >=3.8\n")
    z.writestr(f"{dist}-{version}.dist-info/WHEEL",
               "Wheel-Version: 1.0\nGenerator: dtf\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    z.writestr(f"{dist}-{version}.dist-info/RECORD", "")
print(path)
PY
}
# nupkg <id> <version> <description> -> path of a minimal .nupkg
nupkg() {
  python3 - "$W" "$1" "$2" "$3" <<'PY'
import sys, zipfile
out, pid, version, desc = sys.argv[1:5]
path = f"{out}/{pid}.{version}.nupkg"
with zipfile.ZipFile(path, "w") as z:
    z.writestr(f"{pid}.nuspec",
               '<?xml version="1.0"?><package><metadata>'
               f"<id>{pid}</id><version>{version}</version><authors>DTF</authors>"
               f"<description>{desc}</description></metadata></package>")
print(path)
PY
}
# twine_upload <repo> <project> <version> <summary> <wheel> -> HTTP status
twine_upload() {
  local sha
  sha="$(sha256sum "$5" | cut -d' ' -f1)"
  code -X POST -H "$BASIC" "${BASE_URL}/pypi/$1/" \
    -F ":action=file_upload" -F "protocol_version=1" -F "metadata_version=2.1" \
    -F "name=$2" -F "version=$3" -F "summary=$4" -F "requires_python=>=3.8" \
    -F "filetype=bdist_wheel" -F "pyversion=py3" -F "sha256_digest=${sha}" \
    -F "content=@$5;type=application/octet-stream"
}
gput() { # <repo> <path> <file> -> HTTP status of a generic PUT
  code -X PUT -H "$(auth_header)" -H 'Content-Type: application/octet-stream' \
    --data-binary @"$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2"
}

begin_suite "upload-commit-records"
auth_admin

begin_test "SETUP: repositories, fault and write-counting triggers"
SETUP_ERR=""
for spec in "${R_PYPI}:pypi" "${R_NUGET}:nuget" "${R_RPM}:rpm"; do
  create_local_repo "${spec%%:*}" "${spec##*:}" || SETUP_ERR="${SETUP_ERR} create ${spec};"
done
c="$(code -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${R_VERS}\",\"name\":\"${R_VERS}\",\"format\":\"generic\",\"repo_type\":\"local\",\"versioning_enabled\":true}" \
  "${BASE_URL}/api/v1/repositories")"
is_2xx "$c" || SETUP_ERR="${SETUP_ERR} create ${R_VERS}: HTTP ${c} $(body);"
trig_out="$(psql_x <<SQL
CREATE TABLE IF NOT EXISTS dtf_ucr_switch (on_ boolean PRIMARY KEY);
CREATE TABLE IF NOT EXISTS dtf_ucr_writes (tbl text, name text, op text);
CREATE OR REPLACE FUNCTION dtf_ucr_fault() RETURNS trigger LANGUAGE plpgsql AS \$f\$
BEGIN
  IF EXISTS (SELECT 1 FROM dtf_ucr_switch) AND NEW.metadata::text ILIKE '%${MARK}%' THEN
    RAISE EXCEPTION 'dtf injected artifact_metadata write fault';
  END IF;
  RETURN NEW;
END \$f\$;
CREATE OR REPLACE FUNCTION dtf_ucr_fault_rev() RETURNS trigger LANGUAGE plpgsql AS \$f\$
BEGIN
  IF EXISTS (SELECT 1 FROM dtf_ucr_switch) AND NEW.path ILIKE '%${MARK}%' THEN
    RAISE EXCEPTION 'dtf injected artifact_versions write fault';
  END IF;
  RETURN NEW;
END \$f\$;
CREATE OR REPLACE FUNCTION dtf_ucr_count() RETURNS trigger LANGUAGE plpgsql AS \$f\$
BEGIN
  IF TG_TABLE_NAME = 'packages' THEN
    INSERT INTO dtf_ucr_writes VALUES ('packages', NEW.name, TG_OP);
  ELSE
    INSERT INTO dtf_ucr_writes
      SELECT 'package_versions', p.name, TG_OP FROM packages p WHERE p.id = NEW.package_id;
  END IF;
  RETURN NULL;
END \$f\$;
DROP TRIGGER IF EXISTS dtf_ucr_fault ON artifact_metadata;
CREATE TRIGGER dtf_ucr_fault BEFORE INSERT OR UPDATE ON artifact_metadata
  FOR EACH ROW EXECUTE FUNCTION dtf_ucr_fault();
DROP TRIGGER IF EXISTS dtf_ucr_fault ON artifact_versions;
CREATE TRIGGER dtf_ucr_fault BEFORE INSERT OR UPDATE ON artifact_versions
  FOR EACH ROW EXECUTE FUNCTION dtf_ucr_fault_rev();
DROP TRIGGER IF EXISTS dtf_ucr_count ON packages;
CREATE TRIGGER dtf_ucr_count AFTER INSERT OR UPDATE ON packages
  FOR EACH ROW EXECUTE FUNCTION dtf_ucr_count();
DROP TRIGGER IF EXISTS dtf_ucr_count ON package_versions;
CREATE TRIGGER dtf_ucr_count AFTER INSERT OR UPDATE ON package_versions
  FOR EACH ROW EXECUTE FUNCTION dtf_ucr_count();
SQL
)" || SETUP_ERR="${SETUP_ERR} triggers: ${trig_out};"
if [ -z "$SETUP_ERR" ]; then pass; else fail_fatal "setup failed:${SETUP_ERR}"; fi

# =============================================================================
# #6346 / #6318: one upload writes its catalog row once
# =============================================================================
P1="ucr-twine-${SUF}"
WHL1="$(wheel "$P1" 1.0.0 "dtf twine summary ${SUF}")"
c="$(twine_upload "$R_PYPI" "$P1" 1.0.0 "dtf twine summary ${SUF}" "$WHL1")"

begin_test "CONTROL: a twine-style PyPI upload is 200 and listed in the simple index"
c_idx="$(code -H "$BASIC" "${BASE_URL}/pypi/${R_PYPI}/simple/${P1}/")"
if [ "$c" = "200" ] && [ "$c_idx" = "200" ] && grep -q "$(basename "$WHL1")" "$W/body"; then
  pass
else
  fail "upload HTTP ${c}, simple index HTTP ${c_idx}" "$(body)"
fi

begin_test "CONTROL: the catalog row carries the upload's summary"
desc="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT p.description FROM packages p JOIN repositories r ON r.id = p.repository_id
   WHERE r.key = '${R_PYPI}' AND p.name = '${P1}'" 2>&1 | head -1)"
if [ "$desc" = "dtf twine summary ${SUF}" ]; then pass; else fail "description '${desc}'"; fi

begin_test "FIX #6346: a PyPI upload writes its packages row twice (insert, update) and package_versions once"
pw="$(writes packages "$P1")"; vw="$(writes package_versions "$P1")"
echo "  packages writes ${pw}, package_versions writes ${vw}"
if [ "$pw" = "2" ] && [ "$vw" = "1" ]; then
  pass
else
  fail "packages writes ${pw} (want 2), package_versions writes ${vw} (want 1): the catalog row was upserted more than once"
fi

N1="DtfUcrPush${SUF}"
NUP1="$(nupkg "$N1" 1.0.0 "dtf nuget description")"
c="$(code -X PUT -H "$BASIC" -H 'Content-Type: application/octet-stream' --data-binary @"$NUP1" \
  "${BASE_URL}/nuget/${R_NUGET}/api/v2/package")"
begin_test "FIX #6346: a NuGet push is 201 and writes its packages row twice and package_versions once"
pw="$(writes packages "$N1")"; vw="$(writes package_versions "$N1")"
echo "  push HTTP ${c}; packages writes ${pw}, package_versions writes ${vw}"
if [ "$c" = "201" ] && [ "$pw" = "2" ] && [ "$vw" = "1" ]; then
  pass
else
  fail "push HTTP ${c}; packages writes ${pw} (want 2), package_versions writes ${vw} (want 1)" "$(body)"
fi

P2="ucr-gput-${SUF}"
WHL2="$(wheel "$P2" 1.0.0 "dtf generic put summary")"
c="$(gput "$R_PYPI" "${P2}/1.0.0/$(basename "$WHL2")" "$WHL2")"
begin_test "FIX #6318: a generic PUT of a wheel into a PyPI repository is 201 and writes the catalog once"
pw="$(writes packages "$P2")"; vw="$(writes package_versions "$P2")"
echo "  PUT HTTP ${c}; packages writes ${pw}, package_versions writes ${vw}"
if [ "$c" = "201" ] && [ "$pw" = "2" ] && [ "$vw" = "1" ]; then
  pass
else
  fail "PUT HTTP ${c}; packages writes ${pw} (want 2), package_versions writes ${vw} (want 1)" "$(body)"
fi

# =============================================================================
# #6383: the metadata commits with the row
# =============================================================================
# fault_case <label> <upload fn> <row fn> : runs the upload with the metadata
# write failing, then again with the fault cleared.
P3="${MARK}-gput-${SUF}"
WHL3="$(wheel "$P3" 1.0.0 "dtf fault wheel")"
GPATH3="${P3}/1.0.0/$(basename "$WHL3")"
N3="DtfW13uFault${SUF}"
NUP3="$(nupkg "$N3" 1.0.0 "dtf fault nuget")"
RPM3="${MARK}-${SUF}-1.0-1.noarch.rpm"
printf 'dtf upload-commit-records rpm %s\n' "$SUF" > "$W/$RPM3"

up_gput() { gput "$R_PYPI" "$GPATH3" "$WHL3"; }
row_gput() { live_row "$R_PYPI" "$GPATH3"; }
up_nuget() {
  code -X PUT -H "$BASIC" -H 'Content-Type: application/octet-stream' --data-binary @"$NUP3" \
    "${BASE_URL}/nuget/${R_NUGET}/api/v2/package"
}
row_nuget() { live_name_row "$R_NUGET" "$N3"; }
up_rpm() {
  code -X PUT -H "$BASIC" -H 'Content-Type: application/x-rpm' --data-binary @"$W/$RPM3" \
    "${BASE_URL}/rpm/${R_RPM}/packages/${RPM3}"
}
row_rpm() { live_name_row "$R_RPM" "${MARK}-${SUF}"; }

for kind in gput:"a generic PUT of a wheel into a PyPI repository" \
            nuget:"a NuGet push" rpm:"a native RPM upload"; do
  k="${kind%%:*}"; label="${kind#*:}"
  fault_on
  c="$("up_${k}")"; b="$(body)"
  id="$("row_${k}")"
  begin_test "FIX #6383: ${label} whose metadata write fails leaves no stored package without its metadata"
  echo "  HTTP ${c}; live row '${id}'"
  if [ -n "$id" ] && ! has_metadata "$id"; then
    fail "HTTP ${c} and a live artifact row ${id} with no artifact_metadata row: the metadata was written after the commit" "$b"
  elif is_2xx "$c"; then
    fail "HTTP ${c} although the metadata write failed" "$b"
  else
    pass
  fi
  fault_off
  c="$("up_${k}")"; id="$("row_${k}")"
  begin_test "FIX #6383: ${label}, retried once the fault clears, is stored with its metadata"
  echo "  HTTP ${c}; live row '${id}'"
  if is_2xx "$c" && [ -n "$id" ] && has_metadata "$id"; then
    pass
  else
    fail "retry HTTP ${c}, live row '${id}'" "$(body)"
  fi
done

# A versioning-enabled generic repository: the revision commits with the HEAD.
VPATH="${MARK}/1.0/blob-${SUF}.bin"
printf 'dtf revision one %s\n' "$SUF" > "$W/v1.bin"
printf 'dtf revision two %s\n' "$SUF" > "$W/v2.bin"
c1="$(gput "$R_VERS" "$VPATH" "$W/v1.bin")"
fault_on
c2="$(gput "$R_VERS" "$VPATH" "$W/v2.bin")"; b2="$(body)"
fault_off
code -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${R_VERS}/download/${VPATH}" >/dev/null
begin_test "FIX #6383: a versioned replacement whose revision write fails leaves the HEAD serving the previous bytes"
echo "  first PUT HTTP ${c1}; faulted PUT HTTP ${c2}"
if ! is_2xx "$c1"; then
  fail "the first upload failed: HTTP ${c1}"
elif cmp -s "$W/body" "$W/v1.bin" && ! is_2xx "$c2"; then
  pass
else
  fail "faulted PUT HTTP ${c2}; HEAD now serves: $(body)" "$b2"
fi
c3="$(gput "$R_VERS" "$VPATH" "$W/v2.bin")"
revs="$(psql_q "SELECT COUNT(*) FROM artifact_versions v JOIN repositories r ON r.id = v.repository_id
               WHERE r.key = '${R_VERS}' AND v.path = '${VPATH}'")"
begin_test "FIX #6383: the versioned replacement, retried once the fault clears, lands as revision 2"
echo "  retry HTTP ${c3}; revisions ${revs}"
if is_2xx "$c3" && [ "$revs" = "2" ]; then pass; else fail "retry HTTP ${c3}, ${revs} revisions (want 2)" "$(body)"; fi

end_suite
