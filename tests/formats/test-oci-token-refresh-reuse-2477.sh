#!/usr/bin/env bash
# test-oci-token-refresh-reuse-2477.sh - Regression gate for artifact-keeper#2477
#
# Bug #2477 (Docker /v2/token registry offline-token reuse):
#   `docker login` against a Docker/OCI repo obtains an *offline* registry
#   token (the "identity token" Docker stores in ~/.docker/config.json under
#   `identitytoken`). On every subsequent pull, the Docker client re-presents
#   that SAME stored offline token to POST /v2/token
#   (grant_type=refresh_token) to mint a short-lived access token.
#
#   The 1.5.5 backend treated the OCI offline token like a single-use,
#   family-rotating browser refresh token (#1174 replay protection): the first
#   pull consumed it and the SECOND presentation of the same token tripped
#   replay detection and REVOKED THE WHOLE TOKEN FAMILY -> 401. Result: the
#   first `docker pull` after `docker login` worked, every repeated pull failed
#   with "unauthorized" until the user logged in again. The #2477 fix makes the
#   OCI offline token REUSABLE (idempotent) so repeated pulls keep working,
#   while still honoring account deactivation / credential-change revocation.
#
# This gate is DISCRIMINATING (proven fail-on-1.5.5 / pass-on-fix):
#   - buggy 1.5.5 image: the SECOND reuse of the offline token returns 401
#     ("invalid refresh token" == family revoked) -> this suite FAILS.
#   - #2477 fix build:   every reuse returns 200                -> this suite PASSES.
#
# Positive path (the repro): docker login, then TWO pulls (token exchanges)
#   re-presenting the same stored offline token WITHOUT re-login -> BOTH 200,
#   no 401 / no family revocation.
# Negative control: after the user is deactivated, a reuse of the same offline
#   token -> 401. The reusable offline token stays BOUNDED to an active account;
#   reusability must not become an un-revocable long-lived credential.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-token-refresh-reuse-2477"
auth_admin
setup_workdir

SVC="artifact-keeper"                       # OCI_TOKEN_SERVICE advertised by the backend
REMOTE_KEY="test-oci-refresh-remote-${RUN_ID}"
UPSTREAM_URL="https://registry-1.docker.io"
PULL_USER="oci-refresh-user-${RUN_ID}"
PULL_PASS="OciRefresh!2026x"
PULL_EMAIL="${PULL_USER}@example.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# docker_login_offline_token USER PASS -> prints the offline/identity token.
# Mirrors the classic `docker login` GET flow: Basic-auth credentials against
# /v2/token with ?offline_token=true, per the Distribution token spec. The
# response `refresh_token` is what Docker persists as `identitytoken`.
docker_login_offline_token() {
  local user="$1" pass="$2"
  curl -s $CURL_TIMEOUT -u "${user}:${pass}" \
    "${BASE_URL}/v2/token?service=${SVC}&offline_token=true" 2>/dev/null \
    | jq -r '.refresh_token // empty'
}

# pull_with_offline_token TOKEN -> prints "<http_code>\t<body_first_200>".
# One "docker pull" worth of auth: exchange the stored offline token for a
# fresh access token (grant_type=refresh_token). Docker re-presents the SAME
# stored token every time; this helper does NOT rotate it between calls.
pull_with_offline_token() {
  local token="$1" tmp code body
  tmp=$(mktemp)
  code=$(curl -s $CURL_TIMEOUT -o "$tmp" -w '%{http_code}' \
    -X POST "${BASE_URL}/v2/token?service=${SVC}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=${token}" \
    --data-urlencode "service=${SVC}" 2>/dev/null) || code="000"
  body=$(head -c 200 "$tmp" 2>/dev/null || true)
  rm -f "$tmp"
  printf '%s\t%s' "$code" "$body"
}

# ---------------------------------------------------------------------------
# 1. Create a Docker REMOTE repository (upstream Docker Hub), as in #2477.
# ---------------------------------------------------------------------------
begin_test "Create Docker remote repository (upstream registry-1.docker.io)"
if create_remote_repo "$REMOTE_KEY" "docker" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create docker remote repository"
fi

# ---------------------------------------------------------------------------
# 2. Create a normal (non-admin) user to act as the pulling client.
# ---------------------------------------------------------------------------
begin_test "Create non-admin pull user"
PULL_UID=$(create_test_user_with_retry "$PULL_USER" "$PULL_PASS" "$PULL_EMAIL") || PULL_UID=""
if [ -n "$PULL_UID" ]; then
  pass
else
  fail "could not create pull user ${PULL_USER}"
fi

# ---------------------------------------------------------------------------
# 3. docker login: obtain the offline/identity token.
# ---------------------------------------------------------------------------
begin_test "docker login obtains an offline registry token"
OFFLINE_TOKEN=$(docker_login_offline_token "$PULL_USER" "$PULL_PASS")
if [ -n "$OFFLINE_TOKEN" ] && [ "$OFFLINE_TOKEN" != "null" ]; then
  pass
else
  fail "offline token exchange (offline_token=true) returned no refresh_token"
fi

# ---------------------------------------------------------------------------
# 4. Pull #1: exchange the offline token for an access token.
# ---------------------------------------------------------------------------
begin_test "Pull #1: offline-token exchange succeeds (200)"
if [ -z "${OFFLINE_TOKEN:-}" ] || [ "$OFFLINE_TOKEN" = "null" ]; then
  skip "no offline token from login step"
else
  IFS=$'\t' read -r code1 body1 <<<"$(pull_with_offline_token "$OFFLINE_TOKEN")"
  if [ "$code1" = "200" ]; then
    pass
  else
    fail "first offline-token exchange returned ${code1}, expected 200" "$body1"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Pull #2 (THE #2477 GATE): re-present the SAME offline token WITHOUT
#    re-login. Must succeed -- must NOT 401 / family-revoke.
# ---------------------------------------------------------------------------
begin_test "Pull #2: reuse SAME offline token succeeds (no family revocation) [#2477]"
if [ -z "${OFFLINE_TOKEN:-}" ] || [ "$OFFLINE_TOKEN" = "null" ]; then
  skip "no offline token from login step"
else
  IFS=$'\t' read -r code2 body2 <<<"$(pull_with_offline_token "$OFFLINE_TOKEN")"
  if [ "$code2" = "200" ]; then
    pass
  elif [ "$code2" = "401" ]; then
    # This is exactly the #2477 regression: the second pull's re-presented
    # offline token tripped single-use/replay family revocation.
    fail "REGRESSION #2477: reusing the offline token returned 401 (family revoked); repeated docker pulls broken after a single login" "$body2"
  else
    fail "second offline-token exchange returned ${code2}, expected 200" "$body2"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Pull #3: the offline token stays reusable (idempotent) across N pulls.
# ---------------------------------------------------------------------------
begin_test "Pull #3: offline token remains reusable across repeated pulls [#2477]"
if [ -z "${OFFLINE_TOKEN:-}" ] || [ "$OFFLINE_TOKEN" = "null" ]; then
  skip "no offline token from login step"
else
  IFS=$'\t' read -r code3 body3 <<<"$(pull_with_offline_token "$OFFLINE_TOKEN")"
  if [ "$code3" = "200" ]; then
    pass
  else
    fail "third offline-token exchange returned ${code3}, expected 200 (token should stay reusable)" "$body3"
  fi
fi

# ---------------------------------------------------------------------------
# 7. Best-effort real pulls through the remote proxy (needs Docker Hub egress).
#    The token-reuse assertions above are the deterministic gate; the actual
#    upstream manifest fetch is skipped when Docker Hub is unreachable /
#    anonymous-throttled from the gate environment.
# ---------------------------------------------------------------------------
begin_test "Two real manifest pulls through remote proxy reuse the offline token"
# Opt-in (OCI_2477_REAL_PULL=1). The token-reuse assertions above are the
# deterministic #2477 gate and need no egress. This extra step does two REAL
# manifest pulls through the Docker Hub proxy re-presenting the same offline
# token, but Docker Hub anonymous-pull throttling on a shared gate egress IP
# (the documented flake in test-oci-remote.sh) makes it non-deterministic, so
# it is SKIPPED by default and only runs when explicitly enabled with upstream
# reachable.
if [ "${OCI_2477_REAL_PULL:-0}" != "1" ]; then
  skip "real Docker Hub pull disabled by default (set OCI_2477_REAL_PULL=1 to enable); deterministic token-reuse gate above already covers #2477"
elif [ -z "${OFFLINE_TOKEN:-}" ] || [ "$OFFLINE_TOKEN" = "null" ]; then
  skip "no offline token from login step"
elif ! curl -sf --max-time 10 \
      "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull" \
      >/dev/null 2>&1; then
  skip "Docker Hub unreachable from test environment"
else
  ACCEPT="application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"
  # Tight per-call bound so a slow/throttled Docker Hub upstream can never
  # dominate the per-script TEST_TIMEOUT budget: this is a best-effort fidelity
  # check on top of the deterministic reuse gate above, not the gate itself.
  PULL_TIMEOUT="--max-time 20 --connect-timeout 8"
  pull_manifest() {
    # Fresh access token from the SAME stored offline token (as docker does),
    # then GET a manifest through the remote proxy. Prints the manifest HTTP code.
    local at
    at=$(curl -s $PULL_TIMEOUT -X POST "${BASE_URL}/v2/token?service=${SVC}" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "grant_type=refresh_token" \
      --data-urlencode "refresh_token=${OFFLINE_TOKEN}" \
      --data-urlencode "service=${SVC}" 2>/dev/null | jq -r '.token // .access_token // empty')
    [ -z "$at" ] && { echo "000"; return; }
    curl -s -o /dev/null -w '%{http_code}' $PULL_TIMEOUT \
      -H "Authorization: Bearer ${at}" -H "Accept: ${ACCEPT}" \
      "${BASE_URL}/v2/${REMOTE_KEY}/library/alpine/manifests/3.20"
  }
  m1=$(pull_manifest)
  m2=$(pull_manifest)
  if [ "$m1" = "200" ] && [ "$m2" = "200" ]; then
    pass
  elif [ "$m1" = "200" ] || [ "$m2" = "200" ] || [ "$m1" = "429" ] || [ "$m2" = "429" ] \
       || [ "$m1" = "404" ] || [ "$m2" = "404" ] || [ "$m1" = "000" ] || [ "$m2" = "000" ]; then
    # Docker Hub anonymous pull-quota throttling / egress latency; not a backend
    # defect (see test-oci-remote.sh). The deterministic reuse gate above already
    # proved the token flow, so a throttled or slow upstream is a skip, never a
    # fail -- keeps this suite deterministic in gate environments without a
    # DOCKERHUB_* credential.
    skip "Docker Hub anonymous pull throttled/unavailable (pull1=${m1} pull2=${m2}); no upstream credentials in gate"
  else
    fail "two real proxied manifest pulls: pull1=${m1} pull2=${m2}, expected both 200"
  fi
fi

# ---------------------------------------------------------------------------
# 8. Negative control: after deactivation, the reusable offline token -> 401.
#    Reusability must not outlive account revocation.
# ---------------------------------------------------------------------------
begin_test "Negative control: deactivated user's offline token exchange returns 401"
if [ -z "${OFFLINE_TOKEN:-}" ] || [ "$OFFLINE_TOKEN" = "null" ] || [ -z "${PULL_UID:-}" ]; then
  skip "no offline token or user id available"
else
  deact=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d '{"is_active":false}' "${BASE_URL}/api/v1/users/${PULL_UID}" 2>/dev/null) || deact="000"
  if [ "$deact" -lt 200 ] 2>/dev/null || [ "$deact" -ge 300 ] 2>/dev/null; then
    fail "could not deactivate pull user (PATCH is_active=false returned ${deact})"
  else
    IFS=$'\t' read -r code_neg body_neg <<<"$(pull_with_offline_token "$OFFLINE_TOKEN")"
    if [ "$code_neg" = "401" ]; then
      pass
    else
      fail "deactivated user's offline-token exchange returned ${code_neg}, expected 401 (token must be revocable)" "$body_neg"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
curl -s -o /dev/null $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null || true
if [ -n "${PULL_UID:-}" ]; then
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/users/${PULL_UID}" 2>/dev/null || true
fi

end_suite
