#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-upstream-url/nexus_seed.sh -- seed the #2822 maven-proxy fixture
# =============================================================================
# Seeds a single maven `proxy` source repo whose proxy.remoteUrl points at Maven
# Central:
#
#   maven-proxy-central  (maven2 proxy)  remoteUrl = https://repo1.maven.org/maven2/
#
# A proxy repo is the fixture that reproduces #2822: it maps to an AK `remote`
# repo, and AK's create_repository must persist `upstream_url` or the row
# violates the repositories.check_upstream_url constraint (SQLSTATE 23514).
#
# Maven proxy has a first-class Nexus REST recipe
# (POST /service/rest/v1/repositories/maven/proxy), so no Groovy scripting is
# needed -- the REST call is the "equivalent" of the createMavenProxy scripting
# helper. No components are uploaded: the discriminator is the repository row's
# `upstream_url`, which comes from the proxy config, not from any cached content
# (a fresh proxy caches nothing until something is pulled through it).
#
# Records the repo key + the remoteUrl to the per-run state file so assert.sh can
# drive the migration and compare `upstream_url`. Idempotent (run.sh gives a
# fresh `down -v` Nexus per run, but --keep re-runs must not double-fail).
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

PROXY_REPO="${PROXY_REPO:-maven-proxy-central}"
REMOTE_URL="${REMOTE_URL:-https://repo1.maven.org/maven2/}"
PXU_FIXTURES_FILE="${NEXUS_STATE_DIR}/proxyupstream_fixtures.json"

nexus_is_up || die "Nexus is not running -- run nexus_bootstrap.sh first."
[ -f "${NEXUS_PASS_FILE}" ] || die "No resolved admin password -- run nexus_bootstrap.sh first."

repo_exists() {
  nx_curl GET "/service/rest/v1/repositories" \
    | jq -e --arg n "$1" '.[]|select(.name==$n)' >/dev/null 2>&1
}

# --- 1. create the maven proxy repo (first-class REST recipe) ----------------
if repo_exists "${PROXY_REPO}"; then
  log "proxy repo '${PROXY_REPO}' already present."
else
  body=$(jq -nc --arg n "${PROXY_REPO}" --arg url "${REMOTE_URL}" '{
    name:$n, online:true,
    storage:{blobStoreName:"default", strictContentTypeValidation:true},
    proxy:{remoteUrl:$url, contentMaxAge:1440, metadataMaxAge:1440},
    negativeCache:{enabled:true, timeToLive:1440},
    httpClient:{blocked:false, autoBlock:true},
    maven:{versionPolicy:"RELEASE", layoutPolicy:"STRICT", contentDisposition:"INLINE"}
  }')
  code=$(nx_curl POST "/service/rest/v1/repositories/maven/proxy" \
    -H 'Content-Type: application/json' --data "$body" -o /dev/null -w '%{http_code}')
  log "create maven/proxy '${PROXY_REPO}' (remoteUrl ${REMOTE_URL}) -> HTTP ${code}"
  [ "$code" = "201" ] || warn "unexpected proxy create status ${code}"
fi

# --- 2. confirm the proxy exists + its remoteUrl is what we seeded ------------
sleep 2
repo_json=$(nx_curl GET "/service/rest/v1/repositories" | jq -c --arg n "${PROXY_REPO}" '.[]|select(.name==$n)')
[ -n "$repo_json" ] || die "proxy repo '${PROXY_REPO}' missing after seed"
seeded_type=$(echo "$repo_json" | jq -r '.type // "<none>"')
seeded_url=$(echo "$repo_json" | jq -r '.attributes.proxy.remoteUrl // .url // "<none>"')
log "Nexus reports '${PROXY_REPO}': type=${seeded_type} remoteUrl=${seeded_url}"
[ "$seeded_type" = "proxy" ] || warn "Nexus type for '${PROXY_REPO}' is '${seeded_type}', expected 'proxy'"

jq -n \
  --arg proxy_repo "${PROXY_REPO}" --arg remote_url "${REMOTE_URL}" \
  '{proxy:{repo:$proxy_repo, remote_url:$remote_url}}' \
  > "${PXU_FIXTURES_FILE}"
log "Fixtures recorded at ${PXU_FIXTURES_FILE}:"
cat "${PXU_FIXTURES_FILE}" >&2
echo "${PXU_FIXTURES_FILE}"
