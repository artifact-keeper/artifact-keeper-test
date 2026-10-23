#!/usr/bin/env bash
# =============================================================================
# tiers/maven-upload-tx-and-quality-s3/oracle.sh
#   #3587/#3814 a Maven hosted upload commits the artifact row and its
#               artifact_metadata row in one transaction: a metadata write
#               that fails leaves no live artifact behind, and (#4837) no
#               stored object the download path would still serve
#   #3736       quality checks read the artifact from the repository's
#               configured storage backend (here S3/MinIO)
# See the manifest for THE BUGS, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here is judged, never fatal.
set +e

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
ADMIN="${ADMIN_USER:-admin}"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>&1 | tr -d '[:space:]' || true; }
BASIC="Basic $(printf '%s:%s' "$ADMIN" "$ADMIN_PASS" | base64 | tr -d '\n')"

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mput(){ # <path> <file> -> code
  curl -s --max-time 60 -o "$W/mput.out" -w '%{http_code}' -X PUT -H "Authorization: ${BASIC}" \
    --data-binary "@$2" "$BASE/maven/${REPO}/$1" || true
}
mget(){ curl -s --max-time 60 -o "$2" -w '%{http_code}' -H "Authorization: ${BASIC}" "$BASE/maven/${REPO}/$1" || true; }
live_rows(){ psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}' AND a.path = '$1' AND a.is_deleted = false"; }
rows_without_meta(){ psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}' AND a.path = '$1' AND a.is_deleted = false AND NOT EXISTS (SELECT 1 FROM artifact_metadata m WHERE m.artifact_id = a.id)"; }
# The object store is the ground truth for "were the failed upload's bytes
# removed" (#4837). mc runs on the slot network against the profile's MinIO.
mc_exists(){ # <key> -> yes | no | unknown(...)
  local out
  out="$(docker run --rm --network "ak-dtf${DTF_SLOT}-net" --entrypoint sh \
    ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z -c \
    "mc alias set l http://minio:9000 minioadmin minioadmin >/dev/null 2>&1; if mc stat 'l/ak-artifacts/$1' >/dev/null 2>&1; then echo yes; else echo no; fi" 2>/dev/null || true)"
  case "$out" in *yes*) echo yes ;; *no*) echo no ;; *) echo "unknown(${out})" ;; esac
}
key_of(){ psql_q "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}' AND a.path = '$1' AND a.is_deleted = false LIMIT 1"; }
artifact_id_of(){ psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}' AND a.path = '$1' AND a.is_deleted = false LIMIT 1"; }

# =============================================================================
begin_suite "maven-upload-tx-and-quality-s3"

begin_test "setup: admin login, a local Maven repository on S3 storage"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN}\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}"
REPO="mvns3-${SUF}"
body="$(jq -n --arg k "$REPO" '{key:$k,name:$k,format:"maven",repo_type:"local",is_public:false}')"
curl -s -o "$W/repo.json" -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$body" >/dev/null
[ "$(jqr '.key // empty' < "$W/repo.json")" = "$REPO" ] || { infra_fail "could not create ${REPO}" "$(head -c 300 "$W/repo.json")"; end_suite; }
REPO_ID="$(jqr '.id' < "$W/repo.json")"
sb="$(psql_q "SELECT storage_backend FROM repositories WHERE key = '${REPO}'")"
echo "-- repo ${REPO} (${REPO_ID}), storage_backend=${sb}"
[ "$sb" = "s3" ] || { infra_fail "repository storage_backend is '${sb}', expected s3 (profiles/storage.s3.yml)"; end_suite; }
pass

GAV="com/dtf/tx${SUF}"

begin_test "CONTROL: a Maven release uploads to S3, reads back byte-for-byte, and is listed in maven-metadata.xml"
reset_case
head -c 4096 /dev/urandom > "$W/rel.jar"
c="$(mput "${GAV}/lib/1.0/lib-1.0.jar" "$W/rel.jar")"
note "PUT lib-1.0.jar: ${c}"
case "$c" in 2*) ;; *) fail_g "release upload answered ${c}: $(head -c 160 "$W/mput.out")";; esac
c="$(mget "${GAV}/lib/1.0/lib-1.0.jar" "$W/rel.got")"
{ [ "$c" = "200" ] && cmp -s "$W/rel.jar" "$W/rel.got"; } || fail_g "the S3-stored jar does not read back (HTTP ${c})"
mget "${GAV}/lib/maven-metadata.xml" "$W/md.xml" >/dev/null
grep -q '<version>1.0</version>' "$W/md.xml" || fail_g "maven-metadata.xml does not list 1.0: $(head -c 200 "$W/md.xml")"
[ "$(rows_without_meta "${GAV}/lib/1.0/lib-1.0.jar")" = "0" ] || fail_g "the release row has no artifact_metadata"
finish_case "S3 Maven upload control failed"

begin_test "CONTROL: 8 concurrent republishes of one SNAPSHOT path all succeed and leave one row with its metadata"
reset_case
P="${GAV}/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar"
for i in 1 2 3 4 5 6 7 8; do head -c 2048 /dev/urandom > "$W/snap.$i"; done
for i in 1 2 3 4 5 6 7 8; do
  ( curl -s --max-time 60 -o /dev/null -w '%{http_code}\n' -X PUT -H "Authorization: ${BASIC}" \
      --data-binary "@$W/snap.$i" "$BASE/maven/${REPO}/${P}" > "$W/race.$i" 2>/dev/null ) &
done
wait
codes="$(cat "$W"/race.* | tr '\n' ' ')"
note "racer status codes: ${codes}"
for i in 1 2 3 4 5 6 7 8; do
  case "$(tr -d '[:space:]' < "$W/race.$i")" in 2*) ;; *) fail_g "racer ${i} answered $(cat "$W/race.$i")";; esac
done
lr="$(live_rows "$P")"; nm="$(rows_without_meta "$P")"
note "live rows for the path: ${lr}; rows without artifact_metadata: ${nm}"
[ "$lr" = "1" ] || fail_g "${lr} live rows for one path, expected 1"
[ "$nm" = "0" ] || fail_g "${nm} live row(s) without Maven metadata"
mget "$P" "$W/snap.got" >/dev/null
won=0; for i in 1 2 3 4 5 6 7 8; do cmp -s "$W/snap.$i" "$W/snap.got" && won=$i; done
note "served bytes match racer ${won}"
[ "$won" != 0 ] || fail_g "the served SNAPSHOT bytes match none of the racers"
finish_case "concurrent SNAPSHOT republish control failed"

begin_test "FIX #3587/#3814/#4837: an artifact_metadata write that fails leaves no live artifact row and no downloadable bytes behind"
reset_case
# Fault injection: a trigger that refuses the artifact_metadata row of one
# artifactId only. The upload's metadata INSERT fails after the artifact row
# was written; in one transaction that row must roll back with it.
TX_AID="dtftxfail${SUF}"
inst="$(docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -qc "
CREATE OR REPLACE FUNCTION dtf_fail_meta_${SUF}() RETURNS trigger LANGUAGE plpgsql AS \$\$
BEGIN
  IF NEW.metadata::text LIKE '%${TX_AID}%' THEN
    RAISE EXCEPTION 'dtf injected artifact_metadata failure';
  END IF;
  RETURN NEW;
END \$\$;
CREATE TRIGGER dtf_fail_meta_${SUF} BEFORE INSERT OR UPDATE ON artifact_metadata
  FOR EACH ROW EXECUTE FUNCTION dtf_fail_meta_${SUF}();" 2>&1)"; irc=$?
if [ "$irc" -ne 0 ]; then
  infra_fail "could not install the artifact_metadata fault trigger" "$inst"
else
  TP="${GAV}/${TX_AID}/2.0/${TX_AID}-2.0.jar"
  head -c 1024 /dev/urandom > "$W/tx.jar"
  c="$(mput "$TP" "$W/tx.jar")"
  lr="$(live_rows "$TP")"; nm="$(rows_without_meta "$TP")"
  g="$(mget "$TP" "$W/tx.got")"
  note "PUT with the metadata write failing: ${c} $(head -c 120 "$W/mput.out"); live rows ${lr}; rows without metadata ${nm}"
  case "$c" in 2*) fail_g "the upload reported success (${c}) although its metadata was not written";; esac
  [ "$lr" = "0" ] || fail_g "${lr} live artifact row(s) left behind by an upload whose metadata write failed"
  # artifact-keeper#4837: the object written to the repo-scoped S3 key
  # before the transaction must not outlive the failed upload, and the hosted
  # download's repo-scoped fallback must not serve it with no row (404).
  orphan="no"; [ "$g" = "200" ] && cmp -s "$W/tx.jar" "$W/tx.got" && orphan="yes"
  note "#4837: GET after the failed upload: ${g}; serves the failed upload's bytes: ${orphan}"
  [ "$g" = "404" ] || fail_g "#4837: GET of the failed upload's path answered ${g} (serves its bytes: ${orphan}), expected 404"
  # The stored object itself. The release jar's row names the scoped key
  # layout (maven/<repo id>/<path>); its object is the positive control that
  # keeps the absence check from passing vacuously.
  RK="$(key_of "${GAV}/lib/1.0/lib-1.0.jar")"
  if [ "$RK" = "maven/${REPO_ID}/${GAV}/lib/1.0/lib-1.0.jar" ] && [ "$(mc_exists "$RK")" = "yes" ]; then
    ob="$(mc_exists "maven/${REPO_ID}/${TP}")"
    note "#4837: object maven/${REPO_ID}/${TP} after the failed upload: ${ob}"
    [ "$ob" = "no" ] || fail_g "#4837: the failed upload's object is still in the bucket (${ob})"
  else
    fail_g "#4837: cannot observe the scoped key in MinIO (release row key '${RK}', object $(mc_exists "$RK"))"
  fi
  docker exec "$DBC" psql -U registry -d artifact_registry -qc \
    "DROP TRIGGER IF EXISTS dtf_fail_meta_${SUF} ON artifact_metadata; DROP FUNCTION IF EXISTS dtf_fail_meta_${SUF}();" >/dev/null 2>&1
  c="$(mput "$TP" "$W/tx.jar")"
  lr="$(live_rows "$TP")"; nm="$(rows_without_meta "$TP")"
  note "retry with the fault removed: ${c}; live rows ${lr}; rows without metadata ${nm}"
  case "$c" in 2*) ;; *) fail_g "the retry after the fault answered ${c}";; esac
  [ "$lr" = "1" ] && [ "$nm" = "0" ] || fail_g "the retry did not leave exactly one row with its metadata"
fi
finish_case "#3587/#3814/#4837 failed upload left state behind"

begin_test "CONTROL: a failed first publish that overlaps a successful one of the same coordinate does not take the winner's bytes"
reset_case
# The #4837 cleanup deletes the failed upload's object when no committed row
# names its key. Two PUTs of one new release coordinate share that key: if the
# first fails while the second has stored its bytes but not yet committed, the
# cleanup must not delete the bytes the second one publishes. The fault
# trigger serialises it deterministically: a sequence (non-transactional)
# numbers the metadata writes for one artifactId; write 1 sleeps 3 s and
# raises, write 2 sleeps 3 s and succeeds. PUT 2 starts 1 s after PUT 1, so it
# stores its bytes while PUT 1 holds the row, then commits about 3 s after
# PUT 1 has rolled back and run its cleanup.
RC_AID="dtfrace${SUF}"
inst="$(docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -qc "
CREATE SEQUENCE dtf_race_seq_${SUF};
CREATE OR REPLACE FUNCTION dtf_race_meta_${SUF}() RETURNS trigger LANGUAGE plpgsql AS \$\$
DECLARE n bigint;
BEGIN
  IF NEW.metadata::text LIKE '%${RC_AID}%' THEN
    n := nextval('dtf_race_seq_${SUF}');
    IF n = 1 THEN
      PERFORM pg_sleep(3);
      RAISE EXCEPTION 'dtf injected artifact_metadata failure (first publisher)';
    ELSIF n = 2 THEN
      PERFORM pg_sleep(3);
    END IF;
  END IF;
  RETURN NEW;
END \$\$;
CREATE TRIGGER dtf_race_meta_${SUF} BEFORE INSERT OR UPDATE ON artifact_metadata
  FOR EACH ROW EXECUTE FUNCTION dtf_race_meta_${SUF}();" 2>&1)"; irc=$?
if [ "$irc" -ne 0 ]; then
  infra_fail "could not install the race fault trigger" "$inst"
else
  RP="${GAV}/${RC_AID}/1.0/${RC_AID}-1.0.jar"
  head -c 1024 /dev/urandom > "$W/race1.jar"; head -c 1024 /dev/urandom > "$W/race2.jar"
  ( curl -s --max-time 60 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: ${BASIC}" \
      --data-binary "@$W/race1.jar" "$BASE/maven/${REPO}/${RP}" > "$W/rc1.code" 2>/dev/null ) &
  sleep 1
  ( curl -s --max-time 60 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: ${BASIC}" \
      --data-binary "@$W/race2.jar" "$BASE/maven/${REPO}/${RP}" > "$W/rc2.code" 2>/dev/null ) &
  wait
  c1="$(cat "$W/rc1.code")"; c2="$(cat "$W/rc2.code")"
  docker exec "$DBC" psql -U registry -d artifact_registry -qc \
    "DROP TRIGGER IF EXISTS dtf_race_meta_${SUF} ON artifact_metadata; DROP FUNCTION IF EXISTS dtf_race_meta_${SUF}(); DROP SEQUENCE IF EXISTS dtf_race_seq_${SUF};" >/dev/null 2>&1
  lr="$(live_rows "$RP")"
  g="$(mget "$RP" "$W/race.got")"
  same="no"; cmp -s "$W/race2.jar" "$W/race.got" && same="yes"
  ob="$(mc_exists "maven/${REPO_ID}/${RP}")"
  note "PUT 1 (fails): ${c1}; PUT 2 (wins): ${c2}; live rows ${lr}; GET ${g}, serves PUT 2's bytes: ${same}; object in the bucket: ${ob}"
  case "$c1" in 2*) fail_g "the first publisher reported success (${c1}) although its metadata write failed";; esac
  case "$c2" in 2*) ;; *) fail_g "the second publisher answered ${c2}, expected 2xx";; esac
  [ "$lr" = "1" ] || fail_g "${lr} live rows for the coordinate, expected the winner's 1"
  { [ "$g" = "200" ] && [ "$same" = "yes" ]; } || fail_g "the published coordinate does not serve the winner's bytes (GET ${g}, object ${ob}): the failed publisher's cleanup deleted them"
fi
finish_case "a failed overlapping publish destroyed the winner's bytes"

begin_test "FIX #3736: quality checks triggered for an S3-stored artifact read it and record a result"
reset_case
QP="${GAV}/lib/1.0/lib-1.0.jar"
AID="$(artifact_id_of "$QP")"
before="$(psql_q "SELECT count(*) FROM quality_check_results WHERE artifact_id = '${AID}'")"
c="$(curl -s --max-time 30 -o "$W/trig.json" -w '%{http_code}' -X POST "$BASE/api/v1/quality/checks/trigger" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "{\"artifact_id\":\"${AID}\"}" || true)"
note "trigger for artifact ${AID}: ${c} $(head -c 120 "$W/trig.json"); result rows before ${before}"
[ "$c" = "200" ] || fail_g "the trigger answered ${c}"
n=0
for _i in $(seq 1 30); do
  n="$(psql_q "SELECT count(*) FROM quality_check_results WHERE artifact_id = '${AID}'")"
  [ "${n:-0}" -gt "${before:-0}" ] 2>/dev/null && break
  sleep 1
done
curl -s --max-time 30 -o "$W/checks.json" -H "Authorization: Bearer $TOK" "$BASE/api/v1/quality/checks?artifact_id=${AID}" || true
st="$(jqr '[.[] | "\(.check_type)=\(.status)"] | join(",")' < "$W/checks.json")"
note "quality_check_results rows now ${n}; GET /quality/checks: [${st}]"
[ "${n:-0}" -gt "${before:-0}" ] 2>/dev/null || fail_g "no quality check result was recorded for the S3-stored artifact within 30 s"
echo "$st" | grep -q 'metadata_completeness=completed' || fail_g "no completed metadata_completeness check is listed (${st})"
echo "$st" | grep -q '=failed' && fail_g "a quality check is listed as failed (${st})"
finish_case "#3736 quality checks on S3 failed"

end_suite
