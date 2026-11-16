#!/usr/bin/env bash
# =============================================================================
# tiers/azure-default-backend/oracle.sh
#   Azure as the default storage backend: concurrent identical uploads both
#   succeed (artifact-keeper#3920) and remote repositories no longer stop the
#   backend from starting (#3923).
# =============================================================================
# run.sh has stood up `storage.azurite upstreams.mock-static` with
# RATE_LIMIT_ENABLED=false and UPSTREAM_ALLOW_PRIVATE_IPS=true, and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# S3_PORT (Azurite's published blob port), TRIVY_PORT (the mock's control
# port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest.
#
# Azurite is listed from the host through fixtures/azurite_blob.py (Shared Key,
# throwaway TLS, so no verification). The backend's /data volume is read
# through a transient container with --volumes-from (no shell in the image).
# The restart case runs LAST: on the unfixed image the backend does not come
# back.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${S3_PORT:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it.
set +e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
BACKEND_CTR="ak-dtf${SLOT}-backend"
FS_HELPER_IMAGE="${ADB_FS_HELPER_IMAGE:-postgres:16-alpine}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${SLOT}.70/"
export AZURITE_URL="https://127.0.0.1:${S3_PORT}/dtfaccount"
export AZURITE_CONTAINER="ak-artifacts"
MIB=1048576
NPAR="${ADB_PARALLEL:-6}"
RACE_ROUNDS="${ADB_RACE_ROUNDS:-8}"

RPM_REPO="adb-rpm-${SLOT}-${SUF}"
GEN_REPO="adb-gen-${SLOT}-${SUF}"
REMOTE="adb-remote-${SLOT}-${SUF}"
REMOTE_AZ="adb-remote-az-${SLOT}-${SUF}"

WORK="$(mktemp -d -t dtf-adb-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>&1; }
blobs() { python3 -I "${HERE}/fixtures/azurite_blob.py" list "${1:-}" 2>/dev/null; }
fsx() { docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null; }
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
cas_key() { local s; s="$(sha_of "$1")"; echo "${s:0:2}/${s:2:2}/${s}"; }
race_logs() { docker logs "$BACKEND_CTR" 2>&1 | grep -c 'lost a race to a concurrent writer of identical content'; }
mock_count() { curl -s --max-time 5 "${MOCK}/__requests?path=/f/$1" | jq -r '.count // empty' 2>/dev/null; }
AUTHZ=()

mk_repo() { # KEY FORMAT TYPE [extra-json] -> code; body in $WORK/mk-KEY.json
  local body extra="${4:-}"
  [ -n "$extra" ] || extra='{}'
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "$UPSTREAM" --argjson x "$extra" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $t == "remote" then {upstream_url:$u} else {} end) + $x')"
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-$1.json" -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/json' -d "$body"
}

begin_suite "azure-default-backend"

# =============================================================================
# SETUP
# =============================================================================
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
SF=""
c="$(mk_repo "$RPM_REPO" rpm local)"; is_2xx "$c" || SF="${SF} rpm-repo=${c}"
c="$(mk_repo "$GEN_REPO" generic local)"; is_2xx "$c" || SF="${SF} generic-repo=${c}"
for r in "$RPM_REPO" "$GEN_REPO"; do
  b="$(psqlq "SELECT storage_backend FROM repositories WHERE key='${r}'")"
  [ "$b" = "azure" ] || SF="${SF} ${r}-backend=${b}"
done
blobs >/dev/null || SF="${SF} azurite-list"
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || SF="${SF} mock-static"
if [ -n "$SF" ]; then
  begin_test "setup: Azure-backed repositories, Azurite listing, mock upstream"
  infra_fail "setup failed:${SF}" "$(head -c 300 "${WORK}/mk-${RPM_REPO}.json" 2>/dev/null)"
  end_suite
fi
head -c $((5 * MIB)) /dev/urandom > "${WORK}/single.bin"
head -c $((2 * MIB)) /dev/urandom > "${WORK}/chunked.bin"

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: one 5 MiB upload to an *.rpm path of an Azure-backed RPM repository is 201, downloads byte-exact, and its content-addressed blob is in Azurite"
c="$(code_to_file "${BASE_URL}/api/v1/repositories/${RPM_REPO}/artifacts/single/dtf-single-1.0-1.noarch.rpm" "${WORK}/single.put" \
      -X PUT "${AUTHZ[@]}" -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/single.bin")"
d="$(code_to_file "${BASE_URL}/api/v1/repositories/${RPM_REPO}/download/single/dtf-single-1.0-1.noarch.rpm" "${WORK}/single.out" "${AUTHZ[@]}" -L)"
K="$(cas_key "${WORK}/single.bin")"
if [ "$c" = "201" ] && [ "$d" = "200" ] && cmp -s "${WORK}/single.out" "${WORK}/single.bin" && blobs "$K" | grep -qx "$K"; then pass; else
  fail "PUT=${c} download=${d} byte-exact=$(cmp -s "${WORK}/single.out" "${WORK}/single.bin" && echo yes || echo no) blob ${K} in Azurite=$(blobs "$K" | grep -cx "$K")" \
    "$(head -c 300 "${WORK}/single.put" 2>/dev/null)"
fi

begin_test "CONTROL: a two-chunk session into the Azure-backed generic repository completes and downloads byte-exact"
SHA="$(sha_of "${WORK}/chunked.bin")"
SID="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
  -d "{\"repository_key\":\"${GEN_REPO}\",\"artifact_path\":\"chunked/c-${SUF}.bin\",\"total_size\":$((2 * MIB)),\"chunk_size\":${MIB},\"checksum_sha256\":\"${SHA}\"}" \
  "${BASE_URL}/api/v1/uploads" | jq -r '.session_id // empty')"
PC=""
for i in 0 1; do
  tail -c +$((i * MIB + 1)) "${WORK}/chunked.bin" | head -c "$MIB" > "${WORK}/part"
  PC="${PC} $(code_to_file "${BASE_URL}/api/v1/uploads/${SID}" /dev/null -X PATCH "${AUTHZ[@]}" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes $((i * MIB))-$(((i + 1) * MIB - 1))/$((2 * MIB))" --data-binary "@${WORK}/part")"
done
cc="$(code_to_file "${BASE_URL}/api/v1/uploads/${SID}/complete" "${WORK}/complete.json" -X PUT "${AUTHZ[@]}" -H 'Content-Type: application/json')"
d="$(code_to_file "${BASE_URL}/api/v1/repositories/${GEN_REPO}/download/chunked/c-${SUF}.bin" "${WORK}/chunked.out" "${AUTHZ[@]}" -L)"
if [ -n "$SID" ] && [ "$PC" = " 200 200" ] && is_2xx "$cc" && [ "$d" = "200" ] && cmp -s "${WORK}/chunked.out" "${WORK}/chunked.bin"; then pass; else
  fail "session='${SID}' patches:${PC} complete=${cc} download=${d} byte-exact=$(cmp -s "${WORK}/chunked.out" "${WORK}/chunked.bin" && echo yes || echo no)" \
    "$(head -c 300 "${WORK}/complete.json" 2>/dev/null)"
fi

# =============================================================================
# #3920: concurrent identical uploads
# =============================================================================
begin_test "#3920: rounds of ${NPAR} parallel uploads of one fresh 12 MiB body to an Azure-backed repository all answer 201 and every path downloads byte-exact"
# Whether the uploads overlap closely enough for one Put Block List to lose
# is up to the scheduler: on an idle or fast runner a single round can
# serialise and the race is never reached. So the round repeats (each with a
# fresh body, so it is never deduplicated against an already committed blob)
# until the backend logs the race, up to ADB_RACE_ROUNDS. EVERY round must be
# all-201 and byte-exact; the first round that is not fails the tier at once.
# Whether the race was reached is judged in its own case at the end of the
# suite (INFRA, not a product verdict, when no round reached it).
R0="$(race_logs)"; RACES=0; ROUND=0; RACE_PRODUCT_FAIL=""
WANT_CODES="$(for _ in $(seq 1 "$NPAR"); do printf ' 201'; done)"
WANT_DL="$(for _ in $(seq 1 "$NPAR"); do printf ' ok'; done)"
ROUND_LOG=""
while [ "$ROUND" -lt "$RACE_ROUNDS" ] && [ "$RACES" -lt 1 ]; do
  ROUND=$(( ROUND + 1 ))
  head -c $((12 * MIB)) /dev/urandom > "${WORK}/race.bin"
  for i in $(seq 1 "$NPAR"); do
    curl -s -o "${WORK}/race-${i}.body" -w '%{http_code}' --max-time 120 -X PUT "${AUTHZ[@]}" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/race.bin" \
      "${BASE_URL}/api/v1/repositories/${RPM_REPO}/artifacts/race${ROUND}-${i}/dtf-race-1.0-${ROUND}${i}.noarch.rpm" > "${WORK}/race-${i}.code" 2>/dev/null &
  done
  wait
  CODES=""; DL=""; BAD_BODY=""
  for i in $(seq 1 "$NPAR"); do
    ci="$(cat "${WORK}/race-${i}.code" 2>/dev/null)"; CODES="${CODES} ${ci:-000}"
    [ "$ci" = "201" ] || BAD_BODY="$(head -c 200 "${WORK}/race-${i}.body" 2>/dev/null)"
    di="$(code_to_file "${BASE_URL}/api/v1/repositories/${RPM_REPO}/download/race${ROUND}-${i}/dtf-race-1.0-${ROUND}${i}.noarch.rpm" "${WORK}/race-${i}.out" "${AUTHZ[@]}" -L)"
    if [ "$di" = "200" ] && cmp -s "${WORK}/race-${i}.out" "${WORK}/race.bin"; then DL="${DL} ok"; else DL="${DL} ${di}"; fi
  done
  RACES=$(( $(race_logs) - R0 ))
  ROUND_LOG="${ROUND_LOG} r${ROUND}:races=${RACES}"
  echo "  round ${ROUND}/${RACE_ROUNDS}: upload codes:${CODES}; downloads:${DL}; '#3920 lost a race' log lines so far: ${RACES}"
  if [ "$CODES" != "$WANT_CODES" ] || [ "$DL" != "$WANT_DL" ]; then
    RACE_PRODUCT_FAIL="round ${ROUND}: upload codes:${CODES} (want all 201); downloads:${DL} (want all ok)"
    break
  fi
done
if [ -z "$RACE_PRODUCT_FAIL" ]; then pass; else
  fail "${RACE_PRODUCT_FAIL}. Pre-#3920 the loser's Put Block List got 400 InvalidBlockList and the upload 500 STORAGE_ERROR" \
    "${BAD_BODY}"
fi

# =============================================================================
# #3923: remote repositories on an Azure default
# =============================================================================
begin_test "#3923: a remote repository created without storage_backend lands on 'filesystem' (the proxy cache's backend), not the Azure default"
c="$(mk_repo "$REMOTE" generic remote)"
RB="$(psqlq "SELECT storage_backend FROM repositories WHERE key='${REMOTE}'")"
AB="$(jq -r '.storage_backend // "null"' "${WORK}/mk-${REMOTE}.json" 2>/dev/null)"
if is_2xx "$c" && [ "$RB" = "filesystem" ] && [ "$AB" = "filesystem" ]; then pass; else
  fail "create=${c} repositories.storage_backend='${RB}' response storage_backend='${AB}' (want filesystem in both). Pre-#3923 a remote inherited the Azure default, which the proxy cache cannot serve" \
    "$(head -c 300 "${WORK}/mk-${REMOTE}.json" 2>/dev/null)"
fi

begin_test "#3923: a remote repository with an explicit storage_backend 'azure' is refused 400 VALIDATION_ERROR naming 'filesystem', and no row is created"
c="$(mk_repo "$REMOTE_AZ" generic remote '{"storage_backend":"azure"}')"
CODE="$(jq -r '.code // empty' "${WORK}/mk-${REMOTE_AZ}.json" 2>/dev/null)"
MSG="$(jq -r '.message // empty' "${WORK}/mk-${REMOTE_AZ}.json" 2>/dev/null)"
ROW="$(psqlq "SELECT count(*) FROM repositories WHERE key='${REMOTE_AZ}'")"
if [ "$c" = "400" ] && [ "$CODE" = "VALIDATION_ERROR" ] && printf '%s' "$MSG" | grep -q '"storage_backend": "filesystem"' && [ "$ROW" = "0" ]; then pass; else
  fail "create=${c} code='${CODE}' rows=${ROW} message='${MSG:0:200}' (want 400 VALIDATION_ERROR telling the operator to use \"storage_backend\": \"filesystem\")"
fi

begin_test "#3923: with that remote present the backend restarts and comes back healthy (no 'Refusing to start')"
docker restart "$BACKEND_CTR" >/dev/null 2>&1
STATE=""; HEALTHY=no
for _ in $(seq 1 60); do
  STATE="$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' "$BACKEND_CTR" 2>/dev/null)"
  if curl -sf --max-time 3 "${BASE_URL}/health" >/dev/null 2>&1; then HEALTHY=yes; break; fi
  case "$STATE" in exited*|dead*) break ;; esac
  sleep 2
done
REFUSE="$(docker logs "$BACKEND_CTR" 2>&1 | grep -m1 -o 'cannot serve remote/proxy repositories.*Refusing to start' | head -c 200)"
if [ "$HEALTHY" = "yes" ] && [ -z "$REFUSE" ]; then pass; else
  fail "after docker restart: healthy=${HEALTHY} state='${STATE}' startup error='${REFUSE}'. Pre-#3923 a remote repository on an Azure default stopped the next startup"
fi

begin_test "#3923: after the restart the remote serves through the local proxy cache: 200 byte-exact from the upstream, entry under /data/storage/proxy-cache, the second GET is a cache hit"
[ "$HEALTHY" = "yes" ] && auth_admin >/dev/null 2>&1 && AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
NAME="adb-${SUF}.bin"
curl -s --max-time 10 -o "${WORK}/golden" "${MOCK}/__golden/${NAME}"
g1="$(code_to_file "${BASE_URL}/api/v1/repositories/${REMOTE}/download/f/${NAME}" "${WORK}/remote1.out" "${AUTHZ[@]}")"
g2="$(code_to_file "${BASE_URL}/api/v1/repositories/${REMOTE}/download/f/${NAME}" "${WORK}/remote2.out" "${AUTHZ[@]}")"
UP="$(mock_count "$NAME")"
ENTRY="$(fsx "ls -d /data/storage/proxy-cache/*/${REMOTE}/f/${NAME}/__content__ 2>/dev/null" | head -1)"
if [ "$g1" = "200" ] && [ "$g2" = "200" ] && [ -s "${WORK}/golden" ] && cmp -s "${WORK}/remote1.out" "${WORK}/golden" \
   && cmp -s "${WORK}/remote2.out" "${WORK}/golden" && [ "$UP" = "1" ] && [ -n "$ENTRY" ]; then pass; else
  fail "GET1=${g1} GET2=${g2} byte-exact=$(cmp -s "${WORK}/remote1.out" "${WORK}/golden" && echo yes || echo no) upstream GETs=${UP:-?} (want 1) cache entry='${ENTRY}' (want a __content__ under /data/storage/proxy-cache)"
fi

# =============================================================================
# #3920: was the race reached? (judged last so it never masks a product FAIL)
# =============================================================================
# common.sh lets an INFRA case take precedence over FAILs in the exit code, so
# INFRA is only recorded when nothing else failed; otherwise this case is a
# plain FAIL next to the real one.
begin_test "#3920: the concurrent Put Block List race was reached (backend logged '#3920 lost a race' at least once in ${RACE_ROUNDS} rounds)"
if [ "$RACES" -ge 1 ]; then pass
elif [ -n "$RACE_PRODUCT_FAIL" ] || [ "${_FAIL_COUNT:-0}" -gt 0 ]; then
  fail "race not reached in ${ROUND} round(s) (${ROUND_LOG# }); not judged as INFRA because another case failed"
else
  infra_fail "race not reached: ${ROUND} round(s) of ${NPAR} parallel identical uploads, all 201 and byte-exact, but '#3920 lost a race' log lines: 0 (${ROUND_LOG# }). The tier did not exercise the #3920 fix; this is NOT a pass. Raise ADB_RACE_ROUNDS or ADB_PARALLEL"
fi

end_suite
