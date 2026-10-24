#!/usr/bin/env bash
# =============================================================================
# tiers/upload-staging-object-store-single-put/oracle.sh
#   #3916 single PUTs into an object-storage repository need no local scratch:
#   generic (control) and Maven (fix), with the scratch volume read-only.
# See the manifest for the gap and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh enables errexit; every probe below is judged by its assertion.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
MINIO_CTR="ak-dtf${SLOT}-minio"
BACKEND_CTR="ak-dtf${SLOT}-backend"
BUCKET="ak-artifacts"
MC_IMAGE="${USSP_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
MIB=1048576
R_GEN="ussp-gen-${SLOT}-${SUF}"; R_MVN="ussp-mvn-${SLOT}-${SUF}"
W="$(mktemp -d -t dtf-ussp-XXXXXX)"
trap 'rm -rf "$W"' EXIT

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>/dev/null; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 300 "$@" 2>/dev/null || echo 000; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
mcx() {
  docker run --rm -i --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}
mk_repo() {
  local body
  body="$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  code -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' -d "$body" "${BASE_URL}/api/v1/repositories"
}

begin_suite "upload-staging-object-store-single-put"
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

begin_test "setup: S3-backed generic and Maven repositories, read-only scratch, fixtures"
SF=""
c="$(mk_repo "$R_GEN" generic)"; is_2xx "$c" || SF="${SF} create-generic=${c}"
c="$(mk_repo "$R_MVN" maven)"; is_2xx "$c" || SF="${SF} create-maven=${c}"
[ "$(psqlq "SELECT string_agg(DISTINCT storage_backend, ',') FROM repositories WHERE key IN ('${R_GEN}','${R_MVN}')")" = "s3" ] || SF="${SF} not-s3"
# The scratch volume really is read-only for the backend.
RO="$(docker exec "$BACKEND_CTR" sh -c 'touch /scratch-ro/probe 2>&1 && echo writable || echo read-only' 2>/dev/null)"
case "$RO" in *read-only*|"") ;; *) SF="${SF} scratch-writable" ;; esac
head -c $((40 * MIB)) /dev/urandom > "$W/big.bin"
cp "$W/big.bin" "$W/big.jar"
G="com/acme/ussp${SLOT}"; A="big"; V="4.0"
printf '<?xml version="1.0"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><description>streamed to object storage</description></project>\n' \
  "${G//\//.}" "$A" "$V" > "$W/big.pom"
sha1sum "$W/big.jar" | cut -d' ' -f1 | tr -d '\n' > "$W/big.jar.sha1"
if [ -n "$SF" ]; then infra_fail "setup failed:${SF}" "$(head -c 300 "$W/last" 2>/dev/null)"; end_suite; fi
pass

begin_test "CONTROL: a 40 MiB generic PUT into the S3 repository answers 201 and reads back byte-identical"
c="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/big.bin" "${BASE_URL}/api/v1/repositories/${R_GEN}/artifacts/tool/1.0/big.bin")"
d="$(curl -s -o "$W/big.dl" -w '%{http_code}' --max-time 300 "${AUTHZ[@]}" "${BASE_URL}/api/v1/repositories/${R_GEN}/download/tool/1.0/big.bin" 2>/dev/null)"
if [ "$c" = 201 ] && [ "$d" = 200 ] && [ "$(sha "$W/big.dl")" = "$(sha "$W/big.bin")" ]; then
  pass
else
  fail "generic PUT HTTP ${c} ($(head -c 160 "$W/last")), download HTTP ${d}"
fi

begin_test "#3916 a 40 MiB Maven jar, its POM and .sha1 PUT through the Maven route answer 201 and read back"
cj="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/big.jar" "${BASE_URL}/maven/${R_MVN}/${G}/${A}/${V}/${A}-${V}.jar")"; bj="$(head -c 160 "$W/last")"
cp="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/big.pom" "${BASE_URL}/maven/${R_MVN}/${G}/${A}/${V}/${A}-${V}.pom")"
cs="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/big.jar.sha1" "${BASE_URL}/maven/${R_MVN}/${G}/${A}/${V}/${A}-${V}.jar.sha1")"
dj="$(curl -s -o "$W/jar.dl" -w '%{http_code}' --max-time 300 "${AUTHZ[@]}" "${BASE_URL}/maven/${R_MVN}/${G}/${A}/${V}/${A}-${V}.jar" 2>/dev/null)"
ds="$(curl -s -o "$W/sha1.dl" -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" "${BASE_URL}/maven/${R_MVN}/${G}/${A}/${V}/${A}-${V}.jar.sha1" 2>/dev/null)"
DESC="$(psqlq "SELECT am.metadata->>'description' FROM artifacts a JOIN repositories r ON r.id = a.repository_id JOIN artifact_metadata am ON am.artifact_id = a.id WHERE r.key = '${R_MVN}' AND a.path LIKE '%.pom'")"
if [ "$cj" = 201 ] && [ "$cp" = 201 ] && [ "$cs" = 201 ] && [ "$dj" = 200 ] \
   && [ "$(sha "$W/jar.dl")" = "$(sha "$W/big.jar")" ] && [ "$ds" = 200 ] \
   && [ "$(tr -d ' \n' < "$W/sha1.dl" | cut -c1-40)" = "$(cat "$W/big.jar.sha1")" ] \
   && [ "$DESC" = "streamed to object storage" ]; then
  pass
else
  fail "jar PUT ${cj} (${bj}), pom PUT ${cp}, sha1 PUT ${cs}; jar GET ${dj}, sha1 GET ${ds}; POM description '${DESC}'"
fi

begin_test "#3916 no staging object or tracking row is left behind"
LEFT=""; ROWS=""
for _ in $(seq 1 20); do
  LEFT="$(mcx "mc find local/${BUCKET} --name '*'" 2>/dev/null | grep -c 'generic-upload-staging/')"
  ROWS="$(psqlq "SELECT count(*) FROM generic_upload_staging")"
  [ "$LEFT" = 0 ] && [ "$ROWS" = 0 ] && break
  sleep 1
done
if [ "$LEFT" = 0 ] && [ "$ROWS" = 0 ]; then pass; else fail "${LEFT} staging objects and ${ROWS} tracking rows remain"; fi

end_suite
