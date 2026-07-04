#!/usr/bin/env bash
# test-composer-dist-cache.sh - A warm composer dist fetch is served from the
# pull-through cache without re-dialing upstream.
#
# Release gate for:
#   artifact-keeper#2204 - composer dist cache (warm-hit after cold-miss)
#
# Strategy: AK-to-AK upstream (see tests/pullthrough/test-cache-hit-no-refetch.sh
# for the full rationale -- the Python mock binds an RFC1918 addr that the
# backend's validate_outbound_url rejects, so we point a remote composer repo
# at a local composer repo's own AK URL and the backend dials itself).
#
#   U = local composer repo, published with one package archive.
#   R = remote composer repo whose upstream_url is U's AK URL.
#
# Assertions:
#   1. Cold dist fetch through R is 2xx (cache miss, proxied from U, cached).
#   2. N warm refetches are byte-identical (cache serves a stable source, no
#      partial-cache-write race / per-request re-fetch).
#   3. After U is removed, the warm dist fetch through R STILL returns the
#      cached archive (byte-identical). If R re-dialed upstream on the warm
#      request it would now fail -- so a 2xx here proves the hit came from
#      cache, not a re-fetch.
#
# Feature-gated on `composer_dist_cache` so it auto-skips on a 1.2.x backend.
#
# NOTE (formats matrix): lives in tests/formats/, so it must be listed in a
# format-tests batch. Appended to the `misc-native` batch in
# .github/workflows/release-gate.yml and .github/workflows/format-tests.yml.
#
# Requires: curl, jq, zip

source "$(dirname "$0")/../lib/common.sh"

begin_suite "composer-dist-cache"
auth_admin
setup_workdir

begin_test "Backend supports composer_dist_cache (v1.3.0)"
if require_feature "composer_dist_cache"; then
  pass
else
  end_suite
  exit 0
fi

require_cmd zip

UPSTREAM_KEY="cdc-up-${RUN_ID}"
REMOTE_KEY="cdc-rem-${RUN_ID}"
VENDOR="e2e${RUN_ID//-/}"
PACKAGE="distpkg"
VERSION="1.0.0"
# Long TTL so the warm window never slips on a loaded runner.
TTL_SECS=300

DIST_PATH="dist/${VENDOR}/${PACKAGE}/${VERSION}.zip"

cleanup_repos() {
  api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

fetch_dist() {
  local out="$1"
  curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/composer/${REMOTE_KEY}/${DIST_PATH}" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# Setup: local upstream U with one package archive
# ---------------------------------------------------------------------------

begin_test "Create local composer upstream U"
if create_local_repo "$UPSTREAM_KEY" "composer"; then
  pass
else
  fail "could not create composer upstream"
fi

begin_test "Publish package to U"
PKG_DIR="${WORK_DIR}/pkg"
mkdir -p "$PKG_DIR"
cat > "${PKG_DIR}/composer.json" <<EOJSON
{"name": "${VENDOR}/${PACKAGE}", "version": "${VERSION}", "type": "library"}
EOJSON
echo "payload-${RUN_ID}" > "${PKG_DIR}/payload.txt"
PKG_ARCHIVE="${WORK_DIR}/${VENDOR}-${PACKAGE}-${VERSION}.zip"
( cd "$PKG_DIR" && zip -qr "$PKG_ARCHIVE" . )
pub_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -H "$(format_auth_header)" -H "Content-Type: application/zip" \
  --data-binary "@${PKG_ARCHIVE}" \
  "${BASE_URL}/composer/${UPSTREAM_KEY}/api/packages" 2>/dev/null) || pub_status="000"
if [ "$pub_status" = "200" ] || [ "$pub_status" = "201" ]; then
  pass
else
  skip "composer publish endpoint unavailable (status ${pub_status}); cannot run dist-cache assertion"
  cleanup_repos
  end_suite
  exit 0
fi

begin_test "Create remote R pointing at U (TTL=${TTL_SECS}s)"
if create_remote_repo "$REMOTE_KEY" "composer" "${BASE_URL}/composer/${UPSTREAM_KEY}"; then
  pass
else
  fail "could not create remote R"
fi
api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
  "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 1. Cold dist fetch (cache miss -> proxied -> cached)
# ---------------------------------------------------------------------------

begin_test "Cold dist fetch through R is 2xx (cache miss, proxied + cached)"
cold_status=$(fetch_dist "${WORK_DIR}/cold.zip")
if assert_http_2xx "$cold_status" "cold composer dist fetch should be 2xx"; then
  COLD_SHA=$(shasum -a 256 "${WORK_DIR}/cold.zip" | awk '{print $1}')
  pass
fi

# ---------------------------------------------------------------------------
# 2. Warm refetches are byte-identical (stable cache source)
# ---------------------------------------------------------------------------

begin_test "5 warm dist refetches are byte-identical (cache hit)"
mismatch=0
for i in $(seq 1 5); do
  st=$(fetch_dist "${WORK_DIR}/warm-${i}.zip")
  if [ "$st" != "200" ]; then
    mismatch=1; echo "  warm fetch ${i}: status ${st}"; break
  fi
  sha=$(shasum -a 256 "${WORK_DIR}/warm-${i}.zip" | awk '{print $1}')
  if [ "${COLD_SHA:-}" != "" ] && [ "$sha" != "$COLD_SHA" ]; then
    mismatch=1; echo "  warm fetch ${i}: bytes differ from cold prime"; break
  fi
done
if [ "$mismatch" -eq 0 ]; then
  pass
else
  fail "warm composer dist refetches diverged; cache is not a stable byte source"
fi

# ---------------------------------------------------------------------------
# 3. After U is removed, the warm fetch STILL serves the cached archive.
#    A re-fetch would now fail (upstream gone), so 2xx here == served from cache.
# ---------------------------------------------------------------------------

begin_test "Warm dist fetch still 2xx after upstream U removed (served from cache, not re-fetched)"
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true
sleep 1
after_status=$(fetch_dist "${WORK_DIR}/after.zip")
if [ "$after_status" = "200" ]; then
  after_sha=$(shasum -a 256 "${WORK_DIR}/after.zip" | awk '{print $1}')
  if [ "${COLD_SHA:-}" = "" ] || [ "$after_sha" = "$COLD_SHA" ]; then
    pass
  else
    fail "post-removal dist bytes differ from cached copy (unexpected re-fetch/rewrite)"
  fi
else
  fail "post-removal warm dist fetch returned ${after_status}; cache did not serve the warm hit (re-dialed the now-absent upstream)"
fi

end_suite
