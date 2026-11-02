#!/usr/bin/env bash
# =============================================================================
# tiers/rpm-repodata-large-root-memory/oracle.sh: a cold repodata render of a
# large hosted RPM root completes under a 2 GiB memory limit (#4544).
# =============================================================================
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH, DTF_SLOT.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="rpm-large-${DTF_SLOT:-x}-${SUF}"
BACKEND="ak-dtf${DTF_SLOT}-backend"
PACKAGES="${RPM_LARGE_PACKAGES:-2000}"
FILES_PER_PACKAGE="${RPM_LARGE_FILES:-8000}"
CHUNK=50
MEMORY_LIMIT="${RPM_LARGE_MEMORY:-2g}"
WD="$(mktemp -d)"
trap 'rm -rf "$WD"' EXIT

PSQL() { docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAq "$@"; }

begin_suite "rpm-repodata-large-root-memory"
auth_admin

begin_test "Setup: ${PACKAGES} synthetic packages with ${FILES_PER_PACKAGE} files each in one root"
code=$(curl -s -o "$WD/create.json" -w '%{http_code}' -X POST "${BASE_URL}/api/v1/repositories" \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"rpm\",\"repo_type\":\"local\",\"is_public\":true}")
if [ "$code" != "200" ] && [ "$code" != "201" ]; then
  infra_fail "create repository returned HTTP ${code}: $(head -c 300 "$WD/create.json")"; end_suite
fi
started=$(date +%s)
for first in $(seq 1 "$CHUNK" "$PACKAGES"); do
  last=$((first + CHUNK - 1)); [ "$last" -gt "$PACKAGES" ] && last="$PACKAGES"
  # Rows straight into Postgres: the render reads artifacts and
  # artifact_metadata, never package bytes. A current repodata block (v=1)
  # keeps the render from trying to heal the rows from storage.
  if ! PSQL >/dev/null <<SQL; then
WITH ins AS (
  INSERT INTO artifacts (repository_id, path, name, version, size_bytes,
                         checksum_sha256, content_type, storage_key, uploaded_by)
  SELECT r.id,
         'packages/dtf-large-' || lpad(g::text, 5, '0') || '-1.0-1.x86_64.rpm',
         'dtf-large-' || lpad(g::text, 5, '0'), '1.0-1', 65536,
         encode(sha256(('dtf-large-' || g)::bytea), 'hex'),
         'application/x-rpm',
         'rpm/${REPO}/dtf-large-' || g || '.rpm',
         (SELECT id FROM users WHERE username = 'admin')
  FROM repositories r, generate_series(${first}, ${last}) g
  WHERE r.key = '${REPO}'
  RETURNING id, name
)
INSERT INTO artifact_metadata (artifact_id, format, metadata)
SELECT ins.id, 'rpm', jsonb_build_object(
         'name', ins.name, 'version', '1.0', 'release', '1', 'arch', 'x86_64',
         'summary', 'DTF synthetic package with a long file list',
         'repodata', jsonb_build_object('v', 1, 'header_start', 280, 'header_end', 60000,
           'files', (SELECT jsonb_agg(jsonb_build_object('path',
                       '/usr/share/' || ins.name || '/data/file-' || lpad(f::text, 6, '0') || '.dat'))
                     FROM generate_series(1, ${FILES_PER_PACKAGE}) f)))
FROM ins;
SQL
    infra_fail "seeding packages ${first}..${last} failed"; end_suite
  fi
done
n="$(PSQL -c "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}'")"
meta_mb="$(PSQL -c "SELECT sum(octet_length(m.metadata::text)) / 1048576 FROM artifact_metadata m JOIN artifacts a ON a.id = m.artifact_id JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}'")"
if [ "$n" != "$PACKAGES" ]; then
  infra_fail "expected ${PACKAGES} seeded rows, found '${n}'"; end_suite
fi
pass "seeded ${n} packages, ${meta_mb} MiB of metadata JSON, in $(( $(date +%s) - started ))s"

begin_test "Backend capped at ${MEMORY_LIMIT} with no swap"
if ! docker update --memory "$MEMORY_LIMIT" --memory-swap "$MEMORY_LIMIT" "$BACKEND" >/dev/null 2>&1; then
  infra_fail "could not set a memory limit on ${BACKEND}"; end_suite
fi
limit="$(docker exec "$BACKEND" cat /sys/fs/cgroup/memory.max 2>/dev/null)"
pass "memory.max=${limit}"

begin_test "Cold repomd.xml of the large root answers 200 under the limit (#4544)"
started=$(date +%s)
code=$(curl -s --max-time 900 -o "$WD/repomd.xml" -w '%{http_code}' \
  "${BASE_URL}/rpm/${REPO}/repodata/repomd.xml" 2>/dev/null) || true
elapsed=$(( $(date +%s) - started ))
state="$(docker inspect "$BACKEND" --format 'running={{.State.Running}} oomkilled={{.State.OOMKilled}} exit={{.State.ExitCode}}' 2>/dev/null)"
peak="$(docker exec "$BACKEND" cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo n/a)"
echo "-- HTTP ${code:-000} after ${elapsed}s; ${state}; memory.peak=${peak}"
if [ "${code:-000}" != "200" ]; then
  fail "cold repomd.xml answered HTTP ${code:-000} after ${elapsed}s (${state}): the render did not fit in ${MEMORY_LIMIT}"
  end_suite
fi
case "$state" in
  *running=true*oomkilled=false*) pass "200 in ${elapsed}s, ${state}, memory.peak=${peak}" ;;
  *) fail "repomd.xml answered 200 but the backend is not healthy afterwards (${state})" ;;
esac

begin_test "primary.xml.gz and filelists.xml.gz describe all ${PACKAGES} packages and match repomd.xml"
ok=1
for doc in primary filelists; do
  code=$(curl -s --max-time 300 -o "$WD/$doc.xml.gz" -w '%{http_code}' \
    "${BASE_URL}/rpm/${REPO}/repodata/$doc.xml.gz" 2>/dev/null) || true
  sha="$(sha256sum "$WD/$doc.xml.gz" | awk '{print $1}')"
  advertised="$(grep -A3 "<data type=\"$doc\">" "$WD/repomd.xml" | grep -o '<checksum type="sha256">[0-9a-f]*' | sed 's/.*>//')"
  count="$(gzip -dc "$WD/$doc.xml.gz" 2>/dev/null | grep -c '<package ')"
  echo "-- ${doc}: HTTP ${code} sha=${sha:0:16} advertised=${advertised:0:16} packages=${count}"
  if [ "$code" != "200" ] || [ "$sha" != "$advertised" ] || [ "$count" != "$PACKAGES" ]; then ok=0; fi
done
files="$(gzip -dc "$WD/filelists.xml.gz" 2>/dev/null | grep -c '<file>')"
expected_files=$((PACKAGES * FILES_PER_PACKAGE))
if [ "$ok" = "1" ] && [ "$files" = "$expected_files" ]; then
  pass "both documents list ${PACKAGES} packages, ${files} files, checksums match repomd.xml"
else
  fail "documents incomplete or incoherent (files ${files}/${expected_files}; see the lines above)"
fi

end_suite
