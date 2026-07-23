#!/usr/bin/env bash
# =============================================================================
# tiers/nexus-go-apt/assert.sh — the #2784 ORACLE (Go + apt Nexus migration)
# =============================================================================
# run.sh has stood up backend+postgres+nexus on this slot and exported BASE_URL,
# DB_CONTAINER, BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS; nexus_seed.sh has
# put a go-hosted (Go module) + apt-hosted (.deb) source into Nexus. This drives
# a REAL AK migration of those two repos (source connection -> assess -> start ->
# poll to terminal) and asserts the #2784 fixed behaviour.
#
# POSITIVE oracle (NON-ZERO-WHILE-BUG): exit = number of FAILED positive checks;
# a fully-fixed image exits 0. Pre-#2784 the Go deps never reach
# Artifacts/Packages/search and the apt repo is rejected as an unsupported
# format, so every check below fails -> discriminating.
#
#   GO  G1  go source migrates to an AK repo with format='go', repo_type='local'
#       G2  the Go module lands in `artifacts` with name=<module> AND version set
#           (the module-proxy parser threaded name+version)
#       G3  Packages API: GET /go/<repo>/<module>/@v/list returns <version>
#       G4  search is index-backed: /api/v1/search/advanced?format=go returns it
#   APT A1  apt source is NOT rejected: an AK repo exists, repo_type='local'
#       A2  the .deb lands in `artifacts` for that repo
#       (diagnostic) the migrated apt format (debian ideal; Partial->generic
#        is the current behaviour) is logged, not gated.
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
GOAPT_FIXTURES_FILE="${NEXUS_STATE_DIR}/goapt_fixtures.json"

[ -f "${GOAPT_FIXTURES_FILE}" ] || die "no fixtures at ${GOAPT_FIXTURES_FILE} — run nexus_seed.sh first"
nexus_is_up || die "Nexus not up — profile/run.sh problem"

FX="${GOAPT_FIXTURES_FILE}"
GO_REPO=$(jq -r '.go.repo' "$FX");     GO_MODULE=$(jq -r '.go.module' "$FX")
GO_VERSION=$(jq -r '.go.version' "$FX")
APT_REPO=$(jq -r '.apt.repo' "$FX");   DEB_NAME=$(jq -r '.apt.deb_name' "$FX")
log "Fixtures: go=${GO_REPO} ${GO_MODULE}@${GO_VERSION}  apt=${APT_REPO} deb=${DEB_NAME}"
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

# --- 1. create + test source connection ---------------------------------------
log "Creating Nexus source connection (${NEXUS_API_INTERNAL}) ..."
conn_body=$(jq -nc --arg url "${NEXUS_API_INTERNAL}" --arg u "${NEXUS_ADMIN_USER}" --arg p "$(nx_pass)" '{
  name:"dtf-goapt-nexus-source", url:$url, auth_type:"basic_auth", source_type:"nexus",
  credentials:{username:$u, password:$p}
}')
conn=$(akj POST /api/v1/migrations/connections "$conn_body")
CONN_ID=$(echo "$conn" | jq -r '.id // empty')
[ -n "$CONN_ID" ] || die "connection create failed: $conn"
log "connection test: $(akj POST "/api/v1/migrations/connections/${CONN_ID}/test" | jq -c '{success,message}')"

# --- 2. create + assess + start migration of the two hosted repos -------------
job_body=$(jq -nc --arg cid "${CONN_ID}" --arg go "${GO_REPO}" --arg apt "${APT_REPO}" '{
  source_connection_id:$cid, job_type:"full",
  config:{ include_repos:[$go,$apt], conflict_resolution:"overwrite", verify_checksums:true,
           include_users:false, include_groups:false, include_permissions:false }
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
assess=$(akj GET "/api/v1/migrations/${JOB_ID}/assessment")
log "assessment: $(echo "$assess" | jq -c '{total_repositories,total_artifacts}' 2>/dev/null || echo "$assess" | head -c 200)"

log "Starting migration ..."
akj POST "/api/v1/migrations/${JOB_ID}/start" >/dev/null 2>&1 || true
status=""; deadline=$(( $(date +%s) + 240 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  jr=$(akj GET "/api/v1/migrations/${JOB_ID}"); status=$(echo "$jr" | jq -r '.status')
  case "$status" in completed|completed_with_errors|failed|cancelled) break;; esac; sleep 4
done
jr=$(akj GET "/api/v1/migrations/${JOB_ID}")
log "final job status=${status}  counters=$(echo "$jr" | jq -c '{total_items,completed_items,failed_items,skipped_items}')  error_summary=$(echo "$jr" | jq -r '.error_summary // ""')"
ROOT=$(docker logs "ak-dtf${DTF_SLOT}-backend" 2>&1 | grep -iE "Unknown repository type|not supported for migration|Failed to create destination|Migration worker failed" | sed 's/\x1b\[[0-9;]*m//g' | tail -3)
[ -n "$ROOT" ] && echo "[ROOT] worker log tail:" >&2 && echo "$ROOT" | sed 's/^/    /' >&2

echo "================ #2784 POSITIVE ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE}) ================" >&2
FAILS=0

# ---------------- GO leg ----------------
go_fmt=$(psql_ak "SELECT format::text FROM repositories WHERE key='${GO_REPO}';")
go_type=$(psql_ak "SELECT repo_type::text FROM repositories WHERE key='${GO_REPO}';")
echo "[G1] repositories '${GO_REPO}': format='${go_fmt:-<none>}' repo_type='${go_type:-<none>}' (want go/local)" >&2
if [ "$go_fmt" = "go" ] && [ "$go_type" = "local" ]; then echo "     => G1 OK" >&2
else FAILS=$((FAILS+1)); echo "     => G1 FAIL (go source not migrated as a local go repo)" >&2; fi

go_art=$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${GO_REPO}' AND a.name='${GO_MODULE}' AND a.version='${GO_VERSION}' AND a.is_deleted=false;")
echo "[G2] artifacts(${GO_REPO}, name=${GO_MODULE}, version=${GO_VERSION}) = ${go_art:-0} (want >=1)" >&2
if [ "${go_art:-0}" -ge 1 ]; then echo "     => G2 OK (module parsed into name+version)" >&2
else FAILS=$((FAILS+1)); echo "     => G2 FAIL (Go module deps absent from artifacts — #2784 module-proxy parser gap)" >&2; fi

list_out=$(curl -s -u "${AK_ADMIN_USER}:${AK_ADMIN_PASS}" "${AK_BASE}/go/${GO_REPO}/${GO_MODULE}/@v/list")
echo "[G3] GET /go/${GO_REPO}/${GO_MODULE}/@v/list -> '$(echo "$list_out" | tr '\n' ',' | head -c 80)' (want contains ${GO_VERSION})" >&2
if echo "$list_out" | grep -qx "${GO_VERSION}"; then echo "     => G3 OK (Packages API queryable)" >&2
else FAILS=$((FAILS+1)); echo "     => G3 FAIL (module not queryable via Go Packages API)" >&2; fi

srch_n=$(akj GET "/api/v1/search/advanced?format=go&limit=50" | jq '[.items[]?|select(.name=="'"${GO_MODULE}"'")]|length' 2>/dev/null || echo 0)
echo "[G4] /api/v1/search/advanced?format=go matching ${GO_MODULE} = ${srch_n:-0} (want >=1)" >&2
if [ "${srch_n:-0}" -ge 1 ]; then echo "     => G4 OK (index-backed search returns the module)" >&2
else FAILS=$((FAILS+1)); echo "     => G4 FAIL (module not indexed/searchable — #2784 index_artifact threading gap)" >&2; fi

# ---------------- APT leg ----------------
apt_exists=$(psql_ak "SELECT count(*) FROM repositories WHERE key='${APT_REPO}';")
apt_type=$(psql_ak "SELECT repo_type::text FROM repositories WHERE key='${APT_REPO}';")
apt_fmt=$(psql_ak "SELECT format::text FROM repositories WHERE key='${APT_REPO}';")
echo "[A1] repositories '${APT_REPO}': exists=${apt_exists:-0} repo_type='${apt_type:-<none>}' format='${apt_fmt:-<none>}' (want exists=1/local; pre-#2784 apt is rejected as unsupported)" >&2
if [ "${apt_exists:-0}" = "1" ] && [ "$apt_type" = "local" ]; then echo "     => A1 OK (apt not rejected — format recognized + provisioned)" >&2
else FAILS=$((FAILS+1)); echo "     => A1 FAIL (apt source rejected/not provisioned — #2784 apt->debian mapping gap)" >&2; fi

apt_art=$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${APT_REPO}' AND a.name='${DEB_NAME}' AND a.is_deleted=false;")
echo "[A2] artifacts(${APT_REPO}, name=${DEB_NAME}) = ${apt_art:-0} (want >=1)" >&2
if [ "${apt_art:-0}" -ge 1 ]; then echo "     => A2 OK (.deb transferred)" >&2
else FAILS=$((FAILS+1)); echo "     => A2 FAIL (.deb not transferred)" >&2; fi

# diagnostic (non-gating): the ideal migrated apt format is 'debian'; the
# Partial-compat path currently stores it as 'generic'. Log, do not gate.
if [ "$apt_fmt" = "debian" ]; then echo "[A-info] apt migrated with the ideal format 'debian'." >&2
else echo "[A-info] apt migrated as format='${apt_fmt:-<none>}' (Partial-compat -> generic; debian is the aspirational target)." >&2; fi

echo "===============================================================================================" >&2
echo "POSITIVE_CHECKS_FAILED=${FAILS}" >&2
if [ "${FAILS}" -gt 0 ]; then
  err "#2784 NOT fully satisfied: ${FAILS} positive check(s) failed -> exit ${FAILS}"
  exit "${FAILS}"
fi
log "GREEN: Go module migrated (format=go, artifacts+Packages+search) AND apt migrated (not rejected, .deb present) -> exit 0"
exit 0
