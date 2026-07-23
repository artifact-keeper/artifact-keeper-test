#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-upstream-url/assert.sh -- the #2822 ORACLE (proxy -> remote+url)
# =============================================================================
# run.sh has stood up backend+postgres+nexus on this slot and exported BASE_URL,
# DB_CONTAINER, BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS; nexus_seed.sh has
# put a maven `proxy` repo into Nexus. This drives a REAL AK migration of it and
# asserts the #2822 fix: the proxy source is NOT skipped -- an AK `remote` repo
# is provisioned with `upstream_url` populated from the proxy remoteUrl, and the
# job completes (not Failed).
#
# POSITIVE oracle (NON-ZERO-WHILE-BUG): exit = number of FAILED checks; a fully
# fixed image exits 0. Pre-#2822 the create_repository INSERT omits upstream_url,
# the remote row violates check_upstream_url (SQLSTATE 23514), the repo is
# skipped and (as the only requested repo) the job reports Failed -- so every
# check below fails and the oracle is discriminating.
#
#   P1  the AK repository row EXISTS (not skipped)
#   P2  repo_type='remote' (Nexus proxy maps to AK remote)
#   P3  upstream_url is populated with the proxy remoteUrl
#   P4  migration status is Completed / CompletedWithErrors (not Failed)
#
# Requires (exported by run.sh + nexus_lib.sh): BASE_URL, DB_CONTAINER,
# BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS; fixtures seeded.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${BACKEND_IMAGE:?}"
AK_ADMIN_USER="${ADMIN_USER:-admin}"
AK_ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
AK_BASE="${BASE_URL}"
DB_CTR="${DB_CONTAINER}"
PXU_FIXTURES_FILE="${NEXUS_STATE_DIR}/proxyupstream_fixtures.json"

[ -f "${PXU_FIXTURES_FILE}" ] || die "no fixtures at ${PXU_FIXTURES_FILE} -- run nexus_seed.sh first"
nexus_is_up || die "Nexus not up -- profile/run.sh problem"

FX="${PXU_FIXTURES_FILE}"
PROXY_REPO=$(jq -r '.proxy.repo' "$FX")
REMOTE_URL=$(jq -r '.proxy.remote_url' "$FX")
# Host+path fragment used for a normalization-tolerant upstream_url match
# (Nexus / AK may add or strip a trailing slash).
URL_FRAG="$(echo "$REMOTE_URL" | sed -E 's#^https?://##; s#/+$##')"
log "Fixtures: proxy=${PROXY_REPO} remoteUrl=${REMOTE_URL} (match-fragment '${URL_FRAG}')"
log "Slot ${DTF_SLOT}: AK=${AK_BASE}  DB=${DB_CTR}  image=${BACKEND_IMAGE}"

# --- AK REST helpers ----------------------------------------------------------
ak_login() {
  curl -s -X POST "${AK_BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$AK_ADMIN_USER" --arg p "$AK_ADMIN_PASS" '{username:$u,password:$p}')" \
    | jq -r '.access_token // empty'
}
TOK="$(ak_login)"; [ -n "$TOK" ] || die "AK admin login failed on ${AK_BASE}"
akj() { local m="$1" p="$2" b="${3:-}"; if [ -n "$b" ]; then
    curl -s -X "$m" "${AK_BASE}$p" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$b";
  else curl -s -X "$m" "${AK_BASE}$p" -H "Authorization: Bearer $TOK"; fi; }
psql_ak() { docker exec "${DB_CTR}" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# --- 1. connection ------------------------------------------------------------
log "Creating Nexus source connection (${NEXUS_API_INTERNAL}) ..."
conn_body=$(jq -nc --arg url "${NEXUS_API_INTERNAL}" --arg u "${NEXUS_ADMIN_USER}" --arg p "$(nx_pass)" '{
  name:"dtf-proxyupstream-nexus-source", url:$url, auth_type:"basic_auth", source_type:"nexus",
  credentials:{username:$u, password:$p}
}')
conn=$(akj POST /api/v1/migrations/connections "$conn_body")
CONN_ID=$(echo "$conn" | jq -r '.id // empty')
[ -n "$CONN_ID" ] || die "connection create failed: $conn"
log "connection test: $(akj POST "/api/v1/migrations/connections/${CONN_ID}/test" | jq -c '{success,message}')"

# --- 2. migrate the proxy repo ------------------------------------------------
# include_artifacts=false: the discriminator is the repository row's
# upstream_url; a fresh proxy has nothing cached to transfer, and the provision
# pre-pass (create_repository) is where #2822 fails.
job_body=$(jq -nc --arg cid "${CONN_ID}" --arg p "${PROXY_REPO}" '{
  source_connection_id:$cid, job_type:"full",
  config:{ include_repos:[$p], conflict_resolution:"overwrite", verify_checksums:false,
           include_artifacts:false, include_users:false, include_groups:false, include_permissions:false }
}')
job=$(akj POST /api/v1/migrations "$job_body")
JOB_ID=$(echo "$job" | jq -r '.id // empty')
[ -n "$JOB_ID" ] || die "job create failed: $job"
log "job id=${JOB_ID}"

akj POST "/api/v1/migrations/${JOB_ID}/assess" >/dev/null 2>&1 || true
adl=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$adl" ]; do
  st=$(akj GET "/api/v1/migrations/${JOB_ID}" | jq -r '.status'); [ "$st" = "assessing" ] || break; sleep 3
done
log "Starting migration ..."
akj POST "/api/v1/migrations/${JOB_ID}/start" >/dev/null 2>&1 || true
status=""; deadline=$(( $(date +%s) + 240 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  jr=$(akj GET "/api/v1/migrations/${JOB_ID}"); status=$(echo "$jr" | jq -r '.status')
  case "$status" in completed|completed_with_errors|failed|cancelled) break;; esac; sleep 4
done
jr=$(akj GET "/api/v1/migrations/${JOB_ID}")
log "final job status=${status}  counters=$(echo "$jr" | jq -c '{total_items,completed_items,failed_items,skipped_items}')  error_summary=$(echo "$jr" | jq -r '.error_summary // ""')"

# Diagnostic: surface the pre-#2822 23514 skip line from the worker log.
ROOT=$(docker logs "ak-dtf${DTF_SLOT}-backend" 2>&1 | grep -iE "check_upstream_url|23514|Failed to create destination repository" | sed 's/\x1b\[[0-9;]*m//g' | tail -3)
[ -n "$ROOT" ] && echo "[ROOT] worker log tail:" >&2 && echo "$ROOT" | sed 's/^/    /' >&2

echo "================ #2822 POSITIVE ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE}) ================" >&2
FAILS=0

# --- P1: repository row exists (not skipped) ---------------------------------
exists=$(psql_ak "SELECT count(*) FROM repositories WHERE key='${PROXY_REPO}';")
echo "[P1] repositories '${PROXY_REPO}' exists=${exists:-0} (want 1; pre-#2822 the proxy is skipped, 23514)" >&2
if [ "${exists:-0}" = "1" ]; then echo "     => P1 OK (proxy provisioned, not skipped)" >&2
else FAILS=$((FAILS+1)); echo "     => P1 FAIL (proxy source skipped -- create_repository omitted upstream_url and hit check_upstream_url)" >&2; fi

# --- P2: repo_type='remote' ---------------------------------------------------
rtype=$(psql_ak "SELECT repo_type::text FROM repositories WHERE key='${PROXY_REPO}';")
echo "[P2] repositories '${PROXY_REPO}' repo_type='${rtype:-<none>}' (want remote)" >&2
if [ "$rtype" = "remote" ]; then echo "     => P2 OK" >&2
else FAILS=$((FAILS+1)); echo "     => P2 FAIL (proxy not mapped to an AK remote repo)" >&2; fi

# --- P3: upstream_url populated with the proxy remoteUrl ----------------------
uurl=$(psql_ak "SELECT coalesce(upstream_url,'') FROM repositories WHERE key='${PROXY_REPO}';")
echo "[P3] repositories '${PROXY_REPO}' upstream_url='${uurl:-<none>}' (want populated, contains '${URL_FRAG}')" >&2
if [ -n "${uurl}" ] && echo "${uurl}" | grep -qF "${URL_FRAG}"; then echo "     => P3 OK (upstream_url captured from proxy remoteUrl)" >&2
else FAILS=$((FAILS+1)); echo "     => P3 FAIL (upstream_url missing/empty/mismatched -- #2822 remoteUrl capture gap)" >&2; fi

# --- P4: job did not Fail -----------------------------------------------------
echo "[P4] migration job status='${status}' (want completed / completed_with_errors, NOT failed)" >&2
case "$status" in
  completed|completed_with_errors) echo "     => P4 OK (job did not fail on the skipped proxy)" >&2 ;;
  *) FAILS=$((FAILS+1)); echo "     => P4 FAIL (job status '${status}'; pre-#2822 the skipped proxy failed the only requested repo -> Failed)" >&2 ;;
esac

echo "===============================================================================================" >&2
echo "POSITIVE_CHECKS_FAILED=${FAILS}" >&2
if [ "${FAILS}" -gt 0 ]; then
  err "#2822 NOT satisfied: ${FAILS} positive check(s) failed -> exit ${FAILS}"
  exit "${FAILS}"
fi
log "GREEN: proxy provisioned as an AK remote repo with upstream_url set; job did not fail -> exit 0"
exit 0
