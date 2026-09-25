#!/usr/bin/env bash
# test-quarantine-proxy-release-window.sh -- the Package Age Policy on the
# proxy STREAMING path honours its release-date window, and held proxied
# content has a releasable identity (#3912).
#
# Before the fix, a remote repository with quarantine enabled refused every
# uncached streaming download outright (409 before the upstream open), forever:
# the release-date window was never evaluated and there was no release path.
# After the fix:
#   * a held fetch is cached under its hold and answered 409 until the window
#     elapses (then served from cache, no upstream re-fetch);
#   * POST /api/v1/quarantine/proxy-cache/{repo}/release releases one held
#     entry immediately, keyed on repo + path.
#
# AK-to-AK topology (the Python mock upstream binds RFC1918 and the backend's
# SSRF guard rejects it — see test-cache-hit-no-refetch.sh):
#   U  = local generic repo we publish one file to.
#   R1 = remote repo proxying U, quarantine window 60 min (release-path leg).
#   R2 = remote repo proxying U, quarantine window 1 min (window-elapse leg).
#
# Fails against the unfixed backend: the release endpoint does not exist
# (404), and the window-leg refetch still answers 409.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "quarantine-proxy-release-window"
auth_admin
setup_workdir

U_KEY="qwin-upstream-${RUN_ID}"
R1_KEY="qwin-release-${RUN_ID}"
R2_KEY="qwin-window-${RUN_ID}"
PKG_PATH="pkg/w3912-${RUN_ID}.bin"
PAYLOAD="quarantine-window-${RUN_ID}"

# fetch_through REPO_KEY -> "STATUS<TAB>BODY"
fetch_through() {
  curl -s $CURL_TIMEOUT -w $'\t%{http_code}' \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/$1/download/${PKG_PATH}" 2>/dev/null
}

enable_quarantine() { # REPO_KEY MINUTES
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "{\"quarantine_enabled\":true,\"quarantine_duration_minutes\":$2}" \
    "${BASE_URL}/api/v1/repositories/$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create upstream U and publish the package"
echo "$PAYLOAD" > "${WORK_DIR}/pkg.bin"
if create_local_repo "$U_KEY" "generic" && \
   api_upload "/api/v1/repositories/${U_KEY}/artifacts/${PKG_PATH}" "${WORK_DIR}/pkg.bin"; then
  pass
else
  fail "could not create upstream repo or publish"
fi

begin_test "Create quarantined remote R1 (window 60m)"
UPSTREAM_URL="${BASE_URL}/api/v1/repositories/${U_KEY}/download"
if create_remote_repo "$R1_KEY" "generic" "$UPSTREAM_URL"; then
  status=$(enable_quarantine "$R1_KEY" 60)
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "enabling quarantine on a remote repo must succeed, got HTTP ${status}"
  fi
else
  fail "could not create R1"
fi

# ---------------------------------------------------------------------------
# Both behaviours agree on the first leg: a fresh uncached fetch is held.
# ---------------------------------------------------------------------------

begin_test "First fetch through R1 is held (409)"
out=$(fetch_through "$R1_KEY") || true
status=$(echo "$out" | awk -F'\t' '{print $NF}')
if [ "$status" = "409" ]; then
  pass
else
  fail "expected 409 for a package inside the hold window, got HTTP ${status}" "$out"
fi

# ---------------------------------------------------------------------------
# THE FIX (leg 1): the held entry can be released without touching the repo's
# policy, then serves immediately.
# ---------------------------------------------------------------------------

begin_test "Release the held cache entry via the quarantine API"
status=$(curl -s -o "${WORK_DIR}/release.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"${PKG_PATH}\"}" \
  "${BASE_URL}/api/v1/quarantine/proxy-cache/${R1_KEY}/release" 2>/dev/null) || status="000"
if [ "$status" = "200" ]; then
  pass
else
  fail "release endpoint must answer 200, got HTTP ${status}" "$(cat "${WORK_DIR}/release.json" 2>/dev/null)"
fi

begin_test "The released entry serves immediately (bytes match upstream)"
out=$(fetch_through "$R1_KEY") || true
status=$(echo "$out" | awk -F'\t' '{print $NF}')
body=$(echo "$out" | sed 's/\t[0-9]*$//')
if [ "$status" = "200" ] && [ "$body" = "$PAYLOAD" ]; then
  pass
else
  fail "released entry must serve 200 with upstream bytes, got HTTP ${status}" "$body"
fi

# ---------------------------------------------------------------------------
# THE FIX (leg 2): the window elapses on the streaming path. R2 holds for
# 1 minute; the first fetch caches-but-holds, the second (after the window)
# is served from the cache — without any second upstream fetch.
# ---------------------------------------------------------------------------

begin_test "Create quarantined remote R2 (window 1m)"
if create_remote_repo "$R2_KEY" "generic" "$UPSTREAM_URL"; then
  status=$(enable_quarantine "$R2_KEY" 1)
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "enabling quarantine on R2 failed (HTTP ${status})"
  fi
else
  fail "could not create R2"
fi

begin_test "First fetch through R2 is held (409)"
out=$(fetch_through "$R2_KEY") || true
status=$(echo "$out" | awk -F'\t' '{print $NF}')
if [ "$status" = "409" ]; then
  pass
else
  fail "expected 409 inside R2's hold window, got HTTP ${status}" "$out"
fi

begin_test "After the 1-minute window the held entry serves from cache"
sleep 70
out=$(fetch_through "$R2_KEY") || true
status=$(echo "$out" | awk -F'\t' '{print $NF}')
body=$(echo "$out" | sed 's/\t[0-9]*$//')
if [ "$status" = "200" ] && [ "$body" = "$PAYLOAD" ]; then
  pass
else
  fail "a package past its hold window must be served, got HTTP ${status}" "$body"
fi

# Each remote's first (held) fetch downloaded from U exactly once; the
# post-release and post-window fetches are cache hits. Two remotes -> two
# upstream downloads, never more.
begin_test "Upstream was fetched exactly once per remote (cache-but-hold, no re-fetch per poll)"
U_ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${U_KEY}/artifacts" 2>/dev/null); then
  U_ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // .[0].artifact_id // empty
    elif .items then .items[0].id // .items[0].artifact_id // empty
    else .id // .artifact_id // empty
    end' 2>/dev/null) || true
fi
if [ -z "${U_ARTIFACT_ID:-}" ] || [ "$U_ARTIFACT_ID" = "null" ]; then
  skip "could not resolve upstream artifact id"
elif resp=$(api_get "/api/v1/artifacts/${U_ARTIFACT_ID}/stats" 2>/dev/null); then
  count=$(echo "$resp" | jq -r '.download_count // 0')
  if [ "$count" = "2" ]; then
    pass
  else
    fail "expected exactly 2 upstream downloads (one per remote), got ${count}" "$resp"
  fi
else
  fail "could not read upstream download stats"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${R2_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${R1_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${U_KEY}" > /dev/null 2>&1 || true

end_suite
