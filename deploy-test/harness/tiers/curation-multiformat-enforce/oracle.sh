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

# =============================================================================
# Curation-block body shapes  (verdict = #2930, wire shape = #3110)
# =============================================================================
# What this tier guards is the block VERDICT: pre-#2930 a blocked docker pull
# was never 403'd at all, it fell through to the upstream registry. The SHAPE
# the verdict is reported in is a separate contract, and on the /v2 surface it
# changed in artifact-keeper#3110 (PR #3274):
#
#   REST shape — every proxy format, and /v2 before #3110:
#     {"error":"curation_blocked","package":"…","reason":"…"}
#
#   OCI error envelope — /v2 from #3110 on. The distribution-spec "Error
#   Codes" section makes it a MUST ("If the response body is in JSON format,
#   it MUST have the following format": {"errors":[{"code","message","detail"}]})
#   so a REST-shaped 4XX JSON body on /v2 was a spec violation and docker
#   clients could not render it:
#     {"errors":[{"code":"DENIED",
#                 "message":"curation_blocked: pull of <image> is blocked by
#                            this repository's curation policy: <reason>",
#                 "detail":{"package":"<image>","reason":"<reason>"}}]}
#   `DENIED` is registered code-12; the `curation_blocked` marker stays in the
#   message, and the rule `reason` moves into the spec's `detail` member
#   ("OPTIONAL and MAY contain arbitrary JSON data providing information the
#   client can use to resolve the issue") so /v2 keeps the which-rule-fired
#   parity every other format has.
#
# Both arms below are jq FIELD lookups, never a substring match on the raw
# body: the REST body carries the literal `curation_blocked` AND the reason at
# the top level, so a whole-body grep would pass on either shape and could not
# tell a conforming envelope from the shape #3110 removed.
#
# The npm arm is deliberately untouched — #3110 re-shaped /v2 only, and npm's
# REST body is pinned by a backend unit test (proxy_helpers
# `curation_block_rest_body_is_unchanged`).
# =============================================================================

# Backend version that first emits the OCI envelope on /v2 (artifact-keeper
# #3110 / PR #3274, milestone 1.7.2). At or above this the envelope is
# REQUIRED — a regression back to the REST shape fails the tier. Below it,
# either shape passes: this same oracle runs at `@main` against every tag the
# release gate is pointed at, including 1.7.x cuts that predate the fix and
# `dev` images built from main before the version bump. Keep this in step with
# the release the fix actually ships in.
CURATION_OCI_ENVELOPE_MIN_VERSION="1.7.2"

# curation_block_rest_ok BODY -> 0 if BODY is the shared REST block body.
curation_block_rest_ok() {
  local err
  err="$(printf '%s' "$1" | jq -r '.error // empty' 2>/dev/null || true)"
  [ "$err" = "curation_blocked" ]
}

# curation_block_oci_ok BODY -> 0 if BODY is the OCI error envelope for a
# curation block: registered code, the curation_blocked marker in `message`,
# and the rule reason carried structurally in `detail`.
curation_block_oci_ok() {
  local body="$1" code msg reason
  code="$(printf '%s' "$body"   | jq -r '.errors[0].code // empty'          2>/dev/null || true)"
  msg="$(printf '%s' "$body"    | jq -r '.errors[0].message // empty'       2>/dev/null || true)"
  reason="$(printf '%s' "$body" | jq -r '.errors[0].detail.reason // empty' 2>/dev/null || true)"
  [ "$code" = "DENIED" ] || return 1
  printf '%s' "$msg" | grep -q 'curation_blocked' || return 1
  [ -n "$reason" ] || return 1
}

# curation_block_body_ok BODY -> 0 if BODY reports a curation block in the
# shape the DEPLOYED backend contracts to. Sets CURATION_BLOCK_SHAPE for the
# failure message.
CURATION_BLOCK_SHAPE="none"
curation_block_body_ok() {
  local body="$1" ver
  ver="$(get_backend_version)"
  if [ "$ver" != "unknown" ] && version_ge "$ver" "$CURATION_OCI_ENVELOPE_MIN_VERSION"; then
    if curation_block_oci_ok "$body"; then
      CURATION_BLOCK_SHAPE="oci-envelope"
      return 0
    fi
    CURATION_BLOCK_SHAPE="not-an-oci-envelope (required at backend ${ver} >= ${CURATION_OCI_ENVELOPE_MIN_VERSION})"
    return 1
  fi
  # Below the floor, or an undiscoverable version: accept either shape. Both
  # checks stay structural, so the #2930 verdict is still fully asserted.
  if curation_block_oci_ok "$body"; then CURATION_BLOCK_SHAPE="oci-envelope"; return 0; fi
  if curation_block_rest_ok "$body"; then CURATION_BLOCK_SHAPE="rest"; return 0; fi
  CURATION_BLOCK_SHAPE="neither rest nor oci-envelope (backend ${ver})"
  return 1
}

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
  # 2000, not 300: the OCI envelope carries the image name and the operator's
  # rule `reason` twice (message + detail), and truncating mid-body would make
  # every jq lookup below yield empty — a parse failure that reads as a real
  # regression.
  body="$(head -c 2000 "$tmp")"; rm -f "$tmp"
  if [ "$st" = "403" ] && curation_block_body_ok "$body"; then
    pass
  else
    fail "docker block rule did NOT block GET manifest: status=${st} shape='${CURATION_BLOCK_SHAPE}' (pre-#2930 falls through to the upstream registry, never 403)" "body=${body}"
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
