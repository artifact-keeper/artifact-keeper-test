#!/usr/bin/env bash
# =============================================================================
# tiers/curation-multiformat-enforce/oracle.sh — cross-format curation (#2930)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP flow against the backend.
#
# Gate: a curation `block` rule blocks a PROXY PULL on npm and docker, exactly
# as PyPI already did. The block returns 403 curation_blocked BEFORE any
# outbound upstream fetch, so the discriminator is hermetic (no live internet):
#   Fixed (#2930): blocked npm tarball / docker manifest -> 403 curation_blocked.
#   Pre-#2930:     the enforcement seam is absent -> the request falls through to
#                  the upstream proxy path -> NOT 403 -> FAIL.
# A NON-blocked package on the same repo must NOT be 403 (curation is scoped to
# the ruled package, legitimate pulls are unaffected).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
NPM_REPO="cme-npm-${DTF_SLOT:-x}-${SUF}"
DOCKER_REPO="cme-docker-${DTF_SLOT:-x}-${SUF}"

begin_suite "curation-multiformat-enforce-2930"

auth_admin   # sets ADMIN_TOKEN

# api_call METHOD PATH [BODY] -> sets API_STATUS + API_BODY (no subshell)
api_call() {
  local method="$1" path="$2" body="${3:-}" tmp
  tmp=$(mktemp)
  if [ -n "$body" ]; then
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  else
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  fi
  API_BODY="$(cat "$tmp")"; rm -f "$tmp"
}

# repo_id KEY -> echoes the repository id (via the REST GET)
repo_id() {
  api_call GET "/api/v1/repositories/$1"
  echo "$API_BODY" | jq -r '.id // empty' 2>/dev/null || true
}

# add_block_rule REPO_ID PATTERN
add_block_rule() {
  api_call POST /api/v1/curation/rules \
    "{\"staging_repo_id\":\"$1\",\"package_pattern\":\"$2\",\"action\":\"block\",\"reason\":\"#2930 tier block\",\"priority\":5}"
}

RULE_IDS=()
record_rule() { local id; id="$(echo "$API_BODY" | jq -r '.id // empty' 2>/dev/null)"; [ -n "$id" ] && RULE_IDS+=("$id"); }

# =============================================================================
# NPM half
# =============================================================================
begin_test "npm: create remote curated repo + block rule (left-pad)"
NPM_OK=1
if ! create_repo "$NPM_REPO" "npm" "remote" "https://registry.npmjs.org"; then
  NPM_OK=0; fail "could not create remote npm repo ${NPM_REPO}"
else
  api_call PATCH "/api/v1/repositories/${NPM_REPO}" \
    '{"curation_enabled":true,"curation_default_action":"allow"}'
  NPM_ID="$(repo_id "$NPM_REPO")"
  add_block_rule "$NPM_ID" "left-pad"; record_rule
  if [ "$API_STATUS" = "201" ] && [ -n "$NPM_ID" ]; then pass; else
    NPM_OK=0; fail "npm curation setup failed: rule_status=${API_STATUS} repo_id=${NPM_ID}" "resp=${API_BODY}"
  fi
fi

begin_test "npm: BLOCKED package tarball pull -> 403 curation_blocked (#2930)"
if [ "$NPM_OK" != "1" ]; then
  fail "skipped: npm setup failed"
else
  tmp=$(mktemp)
  st=$(curl -s -o "$tmp" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/npm/${NPM_REPO}/left-pad/-/left-pad-1.3.0.tgz" 2>/dev/null) || st=000
  body="$(head -c 300 "$tmp")"; rm -f "$tmp"
  err="$(echo "$body" | jq -r '.error // empty' 2>/dev/null || true)"
  if [ "$st" = "403" ] && [ "$err" = "curation_blocked" ]; then
    pass
  else
    fail "npm block rule did NOT block the pull: status=${st} error='${err}' (pre-#2930 the tarball streams / 404s from upstream, never 403)" "body=${body}"
  fi
fi

begin_test "npm: NON-blocked package pull is NOT curation-blocked (scoped)"
if [ "$NPM_OK" != "1" ]; then
  fail "skipped: npm setup failed"
else
  st=$(curl -s -o /dev/null -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/npm/${NPM_REPO}/is-odd/-/is-odd-3.0.1.tgz" 2>/dev/null) || st=000
  # A non-blocked pull may 200 (upstream reachable) or 404/502 (offline) — the
  # invariant is only that curation must not 403 it.
  if [ "$st" != "403" ]; then pass; else
    fail "curation over-blocked a non-ruled package: is-odd returned 403"
  fi
fi

# =============================================================================
# Docker / OCI half
# =============================================================================
begin_test "docker: create remote curated repo (public+anon) + block rule (library/hello-world)"
DOCKER_OK=1
if ! create_repo "$DOCKER_REPO" "docker" "remote" "https://registry-1.docker.io"; then
  DOCKER_OK=0; fail "could not create remote docker repo ${DOCKER_REPO}"
else
  api_call PATCH "/api/v1/repositories/${DOCKER_REPO}" \
    '{"curation_enabled":true,"curation_default_action":"allow","is_public":true,"allow_anonymous_access":true}'
  DOCKER_ID="$(repo_id "$DOCKER_REPO")"
  add_block_rule "$DOCKER_ID" "library/hello-world"; record_rule
  if [ "$API_STATUS" = "201" ] && [ -n "$DOCKER_ID" ]; then pass; else
    DOCKER_OK=0; fail "docker curation setup failed: rule_status=${API_STATUS} repo_id=${DOCKER_ID}" "resp=${API_BODY}"
  fi
fi

# oci_token IMAGE -> echoes an anonymous OCI bearer token for a pull scope
oci_token() {
  curl -s "${BASE_URL}/v2/token?service=artifact-keeper&scope=repository:${DOCKER_REPO}/$1:pull" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
OCI_ACCEPT='application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json'

begin_test "docker: BLOCKED image GET manifest -> 403 curation_blocked (#2930)"
if [ "$DOCKER_OK" != "1" ]; then
  fail "skipped: docker setup failed"
else
  DTOK="$(oci_token library/hello-world)"
  tmp=$(mktemp)
  st=$(curl -s -o "$tmp" -w '%{http_code}' -H "Authorization: Bearer ${DTOK}" -H "Accept: ${OCI_ACCEPT}" \
    "${BASE_URL}/v2/${DOCKER_REPO}/library/hello-world/manifests/latest" 2>/dev/null) || st=000
  body="$(head -c 300 "$tmp")"; rm -f "$tmp"
  err="$(echo "$body" | jq -r '.error // empty' 2>/dev/null || true)"
  if [ "$st" = "403" ] && [ "$err" = "curation_blocked" ]; then
    pass
  else
    fail "docker block rule did NOT block GET manifest: status=${st} error='${err}' (pre-#2930 falls through to the upstream registry, never 403)" "body=${body}"
  fi
fi

begin_test "docker: BLOCKED image HEAD manifest -> 403 (#2930)"
if [ "$DOCKER_OK" != "1" ]; then
  fail "skipped: docker setup failed"
else
  DTOK="$(oci_token library/hello-world)"
  st=$(curl -s -I -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${DTOK}" -H "Accept: ${OCI_ACCEPT}" \
    "${BASE_URL}/v2/${DOCKER_REPO}/library/hello-world/manifests/latest" 2>/dev/null) || st=000
  if [ "$st" = "403" ]; then pass; else
    fail "docker block rule did NOT block HEAD manifest: status=${st}"
  fi
fi

begin_test "docker: NON-blocked image manifest is NOT curation-blocked (scoped)"
if [ "$DOCKER_OK" != "1" ]; then
  fail "skipped: docker setup failed"
else
  ATOK="$(oci_token library/alpine)"
  st=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${ATOK}" -H "Accept: ${OCI_ACCEPT}" \
    "${BASE_URL}/v2/${DOCKER_REPO}/library/alpine/manifests/latest" 2>/dev/null) || st=000
  if [ "$st" != "403" ]; then pass; else
    fail "curation over-blocked a non-ruled image: library/alpine returned 403"
  fi
fi

# =============================================================================
# cleanup
# =============================================================================
for rid in "${RULE_IDS[@]:-}"; do
  [ -n "$rid" ] && api_call DELETE "/api/v1/curation/rules/${rid}"
done
api_call DELETE "/api/v1/repositories/${NPM_REPO}" 2>/dev/null
api_call DELETE "/api/v1/repositories/${DOCKER_REPO}" 2>/dev/null

end_suite
