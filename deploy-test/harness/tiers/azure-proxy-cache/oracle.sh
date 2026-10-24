#!/usr/bin/env bash
# =============================================================================
# tiers/azure-proxy-cache/oracle.sh
#   #4320 the proxy cache of remote repositories on Azure Blob storage
# See the manifest for the gap and the gates.
#
# run.sh has stood up `storage.azurite storage.azurite-proxy-cache
# upstreams.mock-static`, exporting BASE_URL, DB_CONTAINER, DTF_SLOT, S3_PORT
# (Azurite's blob port on the host), TRIVY_PORT (the mock's control port),
# RUN_ID, COMMON_SH.
#
# Azurite is listed from the host through the azure-default-backend fixture
# azurite_blob.py (Shared Key, throwaway TLS, so no verification). The
# backend's /data volume is read through a transient container with
# --volumes-from (no shell in the image).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${S3_PORT:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it.
set +e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOB_PY="${HERE}/../azure-default-backend/fixtures/azurite_blob.py"
SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
BACKEND_CTR="ak-dtf${SLOT}-backend"
FS_HELPER_IMAGE="${APC_FS_HELPER_IMAGE:-postgres:16-alpine}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${SLOT}.70/"
export AZURITE_URL="https://127.0.0.1:${S3_PORT}/dtfaccount"
export AZURITE_CONTAINER="ak-artifacts"

REMOTE="apc-remote-${SLOT}-${SUF}"
REMOTE_AZ="apc-remote-az-${SLOT}-${SUF}"

WORK="$(mktemp -d -t dtf-apc-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>&1; }
blobs() { python3 -I "$BLOB_PY" list "${1:-}" 2>/dev/null; }
fsx() { docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null; }
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' --max-time 60 "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
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

begin_suite "azure-proxy-cache"

auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
SF=""
blobs >/dev/null || SF="${SF} azurite-list"
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || SF="${SF} mock-static"
if [ -n "$SF" ]; then
  begin_test "setup: Azurite listing, mock upstream"
  infra_fail "setup failed:${SF}"
  end_suite
fi

# =============================================================================
begin_test "FIX #4320: a remote repository created without storage_backend lands on 'azure'"
c="$(mk_repo "$REMOTE" generic remote)"
RB="$(psqlq "SELECT storage_backend FROM repositories WHERE key='${REMOTE}'")"
if [ "$c" = "201" ] || [ "$c" = "200" ]; then
  if [ "$RB" = "azure" ]; then pass; else
    fail "create=${c} repositories.storage_backend='${RB}' (want azure; 1.11 keeps a remote on filesystem because the proxy cache cannot use Azure)"
  fi
else
  infra_fail "create of ${REMOTE} answered ${c}: $(head -c 300 "${WORK}/mk-${REMOTE}.json")"
  end_suite
fi

begin_test "FIX #4320: a remote repository with an explicit storage_backend 'azure' is created"
c="$(mk_repo "$REMOTE_AZ" generic remote '{"storage_backend":"azure"}')"
if [ "$c" = "201" ] || [ "$c" = "200" ]; then pass; else
  fail "create=${c} $(jq -r '.message // .error // empty' "${WORK}/mk-${REMOTE_AZ}.json" 2>/dev/null | head -c 200) (1.11 refuses it: the proxy cache has no Azure support)"
fi

# =============================================================================
NAME="apc-${SUF}.bin"
curl -s --max-time 10 -o "${WORK}/golden" "${MOCK}/__golden/${NAME}"
g1="$(code_to_file "${BASE_URL}/api/v1/repositories/${REMOTE}/download/f/${NAME}" "${WORK}/r1.out" "${AUTHZ[@]}")"
# Let the tee's publish (staging write, server-side copy, sidecar) finish.
CONTENT=""; SIDECAR=""
for _ in $(seq 1 20); do
  LIST="$(blobs "proxy-cache/")"
  CONTENT="$(printf '%s\n' "$LIST" | grep -m1 "/${REMOTE}/f/${NAME}/__content__\$")"
  SIDECAR="$(printf '%s\n' "$LIST" | grep -m1 "/${REMOTE}/f/${NAME}/__cache_meta__.json\$")"
  [ -n "$CONTENT" ] && [ -n "$SIDECAR" ] && break
  sleep 0.5
done
g2="$(code_to_file "${BASE_URL}/api/v1/repositories/${REMOTE}/download/f/${NAME}" "${WORK}/r2.out" "${AUTHZ[@]}")"
UP="$(mock_count "$NAME")"
LOCAL="$(fsx "ls -d /data/storage/proxy-cache/*/${REMOTE}/f/${NAME}/__content__ /data/storage/proxy-cache/${REMOTE}/f/${NAME}/__content__ 2>/dev/null" | head -1)"

begin_test "CONTROL: the remote serves the upstream bytes on both GETs"
if [ "$g1" = "200" ] && [ "$g2" = "200" ] && [ -s "${WORK}/golden" ] \
   && cmp -s "${WORK}/r1.out" "${WORK}/golden" && cmp -s "${WORK}/r2.out" "${WORK}/golden"; then pass; else
  fail "GET1=${g1} GET2=${g2} byte-exact1=$(cmp -s "${WORK}/r1.out" "${WORK}/golden" && echo yes || echo no) byte-exact2=$(cmp -s "${WORK}/r2.out" "${WORK}/golden" && echo yes || echo no)"
fi

begin_test "FIX #4320: the cache entry is committed in Azure (content and sidecar blobs), not under /data/storage/proxy-cache, and the second GET is a hit"
if [ -n "$CONTENT" ] && [ -n "$SIDECAR" ] && [ -z "$LOCAL" ] && [ "$UP" = "1" ]; then pass; else
  fail "azure content blob='${CONTENT}' sidecar blob='${SIDECAR}' local entry='${LOCAL}' upstream GETs=${UP:-?} (want both blobs, no local entry, 1 upstream GET; 1.11 caches under STORAGE_PATH)"
fi

begin_test "FIX #4320: POST cache/invalidate deletes the Azure blobs and the next GET refetches from upstream"
INV="$(curl -s --max-time 30 -X POST "${AUTHZ[@]}" \
  "${BASE_URL}/api/v1/repositories/${REMOTE}/cache/invalidate?path=f/${NAME}" | jq -r '.invalidated // empty' 2>/dev/null)"
LEFT="$(blobs "proxy-cache/" | grep -c "/${REMOTE}/f/${NAME}/")"
g3="$(code_to_file "${BASE_URL}/api/v1/repositories/${REMOTE}/download/f/${NAME}" "${WORK}/r3.out" "${AUTHZ[@]}")"
UP3="$(mock_count "$NAME")"
if [ "$INV" = "true" ] && [ "$LEFT" = "0" ] && [ "$g3" = "200" ] && cmp -s "${WORK}/r3.out" "${WORK}/golden" \
   && [ "$UP3" = "2" ] && [ -n "$CONTENT" ]; then pass; else
  fail "invalidated='${INV}' azure blobs left=${LEFT} GET3=${g3} upstream GETs=${UP3:-?} (want true, 0, 200, 2) content blob before='${CONTENT}'"
fi

end_suite
