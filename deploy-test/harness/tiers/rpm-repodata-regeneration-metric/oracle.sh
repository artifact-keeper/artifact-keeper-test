#!/usr/bin/env bash
# =============================================================================
# tiers/rpm-repodata-regeneration-metric/oracle.sh: one regeneration per
# repository state for hosted RPM repodata, reported through the shared
# metadata revision cache metrics (#4174).
# =============================================================================
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH, DTF_SLOT.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="rpm-regen-${DTF_SLOT:-x}-${SUF}"
CLIENT="ak-dtf${DTF_SLOT}-client-dnf"
PACKAGES=300
BURST=20
WD="$(mktemp -d)"
trap 'rm -rf "$WD"' EXIT

PSQL() { docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAq "$@"; }

# regenerations: the rpm sample of ak_repo_metadata_regenerations_total, or
# "absent" when the backend does not export it.
regenerations() {
  local v
  v="$(curl -s --max-time 10 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null \
    | grep '^ak_repo_metadata_regenerations_total{' | grep 'format="rpm"' \
    | awk '{s += $NF} END {if (NR) printf "%d", s}')"
  echo "${v:-absent}"
}
cache_hits() {
  local v
  v="$(curl -s --max-time 10 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null \
    | grep '^ak_repo_metadata_cache_requests_total{' | grep 'format="rpm"' | grep 'result="hit"' \
    | awk '{s += $NF} END {if (NR) printf "%d", s}')"
  echo "${v:-0}"
}

# seed_packages <first> <last>: synthetic live .rpm rows with a current
# repodata block (so the render never tries to heal them from storage).
seed_packages() {
  PSQL <<SQL
INSERT INTO artifacts (repository_id, path, name, version, size_bytes,
                       checksum_sha256, content_type, storage_key, uploaded_by)
SELECT r.id,
       'packages/dtf-synth-' || g || '-1.0-1.noarch.rpm',
       'dtf-synth-' || g, '1.0-1', 4096,
       encode(sha256(('dtf-synth-' || g)::bytea), 'hex'),
       'application/x-rpm',
       'rpm/${REPO}/dtf-synth-' || g || '-1.0-1.noarch.rpm',
       (SELECT id FROM users WHERE username = 'admin')
FROM repositories r, generate_series($1, $2) g
WHERE r.key = '${REPO}';
INSERT INTO artifact_metadata (artifact_id, format, metadata)
SELECT a.id, 'rpm', jsonb_build_object(
         'name', a.name, 'version', '1.0', 'release', '1', 'arch', 'noarch',
         'summary', 'DTF synthetic package',
         'repodata', jsonb_build_object('v', 1, 'header_start', 280, 'header_end', 4000,
           'files', jsonb_build_array(jsonb_build_object('path', '/usr/share/' || a.name || '/README'))))
FROM artifacts a JOIN repositories r ON r.id = a.repository_id
WHERE r.key = '${REPO}'
  AND NOT EXISTS (SELECT 1 FROM artifact_metadata m WHERE m.artifact_id = a.id);
SQL
}

begin_suite "rpm-repodata-regeneration-metric"
auth_admin

begin_test "Setup: hosted RPM repository with ${PACKAGES} synthetic packages"
code=$(curl -s -o "$WD/create.json" -w '%{http_code}' -X POST "${BASE_URL}/api/v1/repositories" \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"rpm\",\"repo_type\":\"local\",\"is_public\":true}")
if [ "$code" != "200" ] && [ "$code" != "201" ]; then
  infra_fail "create repository returned HTTP ${code}: $(head -c 300 "$WD/create.json")"; end_suite; exit $?
fi
if ! seed_packages 1 "$PACKAGES" >/dev/null; then
  infra_fail "seeding ${PACKAGES} synthetic rows failed"; end_suite; exit $?
fi
n="$(PSQL -c "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}'")"
if [ "$n" != "$PACKAGES" ]; then
  infra_fail "expected ${PACKAGES} seeded rows, found '${n}'"; end_suite; exit $?
fi
pass "seeded ${n} packages into ${REPO}"

begin_test "${BURST} concurrent cold repomd.xml GETs: one body, exactly one rpm regeneration sample"
before="$(regenerations)"
for i in $(seq 1 "$BURST"); do
  curl -s --max-time 120 -o "$WD/repomd.$i" -w '%{http_code}\n' \
    "${BASE_URL}/rpm/${REPO}/repodata/repomd.xml" >"$WD/code.$i" &
done
wait
codes="$(cat "$WD"/code.* | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
bodies="$(sha256sum "$WD"/repomd.* | awk '{print $1}' | sort -u | wc -l)"
after="$(regenerations)"
echo "-- codes: ${codes} distinct bodies: ${bodies} regenerations: ${before} -> ${after}"
if [ "$(cat "$WD"/code.* | grep -vc '^200$')" != "0" ]; then
  fail "not every burst GET answered 200 (${codes})"
elif [ "$bodies" != "1" ]; then
  fail "the burst saw ${bodies} distinct repomd.xml bodies for one repository state"
elif [ "$after" = "absent" ]; then
  fail "ak_repo_metadata_regenerations_total{format=\"rpm\"} is not exported: renders are not observable (#4174)"
elif [ $((after - ${before/absent/0})) -ne 1 ]; then
  fail "the burst produced regenerations ${before} -> ${after}; expected exactly one"
else
  pass "${BURST} GETs, one body, regenerations ${before} -> ${after}"
fi
REPOMD_V1="$(sha256sum "$WD/repomd.1" | awk '{print $1}')"

begin_test "Warm repeats are cache hits and do not regenerate"
regen0="$(regenerations)"; hits0="$(cache_hits)"
for i in 1 2 3 4 5; do
  curl -s --max-time 60 -o /dev/null "${BASE_URL}/rpm/${REPO}/repodata/repomd.xml"
  curl -s --max-time 60 -o /dev/null "${BASE_URL}/rpm/${REPO}/repodata/primary.xml.gz"
done
regen1="$(regenerations)"; hits1="$(cache_hits)"
echo "-- regenerations ${regen0} -> ${regen1}, hits ${hits0} -> ${hits1}"
if [ "$regen1" = "absent" ] || [ "$regen0" != "$regen1" ]; then
  fail "warm requests regenerated (${regen0} -> ${regen1})"
elif [ $((hits1 - hits0)) -lt 10 ]; then
  fail "10 warm requests recorded $((hits1 - hits0)) cache hits"
else
  pass "10 warm requests: $((hits1 - hits0)) hits, no regeneration"
fi

begin_test "One more package: the next read serves a new revision, one more regeneration"
seed_packages $((PACKAGES + 1)) $((PACKAGES + 1)) >/dev/null
regen0="$(regenerations)"
code=$(curl -s --max-time 120 -o "$WD/repomd.after" -w '%{http_code}' "${BASE_URL}/rpm/${REPO}/repodata/repomd.xml")
curl -s --max-time 120 -o "$WD/primary.after" "${BASE_URL}/rpm/${REPO}/repodata/primary.xml.gz"
regen1="$(regenerations)"
pkgs="$(gzip -dc "$WD/primary.after" 2>/dev/null | grep -o 'packages="[0-9]*"' | head -1)"
echo "-- HTTP ${code}, ${pkgs}, regenerations ${regen0} -> ${regen1}"
if [ "$code" != "200" ] || [ "$(sha256sum "$WD/repomd.after" | awk '{print $1}')" = "$REPOMD_V1" ]; then
  fail "after a publish repomd.xml did not change (HTTP ${code})"
elif [ "$pkgs" != "packages=\"$((PACKAGES + 1))\"" ]; then
  fail "primary.xml.gz lists ${pkgs:-nothing}; expected $((PACKAGES + 1))"
elif [ "$regen1" = "absent" ] || [ "$regen0" = "absent" ] || [ $((regen1 - regen0)) -ne 1 ]; then
  fail "a publish moved regenerations ${regen0} -> ${regen1}; expected exactly one"
else
  pass "new revision with ${pkgs}, regenerations ${regen0} -> ${regen1}"
fi

begin_test "dnf makecache accepts the served repodata"
docker exec "$CLIENT" sh -c "cat > /etc/yum.repos.d/dtf.repo <<REPO
[dtf]
name=dtf
baseurl=http://backend:8080/rpm/${REPO}/
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO" >/dev/null 2>&1
if docker exec "$CLIENT" dnf -q --disablerepo='*' --enablerepo=dtf makecache >"$WD/dnf.log" 2>&1 \
   && docker exec "$CLIENT" dnf -q --disablerepo='*' --enablerepo=dtf list --available 'dtf-synth-*' 2>/dev/null \
      | grep -c '^dtf-synth-' >"$WD/dnf.count"; then
  listed="$(cat "$WD/dnf.count")"
  if [ "$listed" = "$((PACKAGES + 1))" ]; then
    pass "dnf makecache succeeded and lists ${listed} packages"
  else
    fail "dnf lists ${listed} packages; expected $((PACKAGES + 1))"
  fi
else
  fail "dnf makecache failed: $(tail -5 "$WD/dnf.log")"
fi

end_suite
