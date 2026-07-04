#!/usr/bin/env bash
# test-npm-packument-swr.sh - npm packument is served from cache (no upstream
# re-fetch) within the TTL window.
#
# Release gate for:
#   artifact-keeper#2166 - npm packument stale-while-revalidate cache
#
# Strategy: AK-to-AK upstream (identical rationale to
# tests/pullthrough/test-cache-hit-no-refetch.sh -- the Python mock binds an
# RFC1918 address the backend's validate_outbound_url rejects, so a remote npm
# repo points at a local npm repo's own AK URL and the backend dials itself).
#
#   U = local npm repo we publish to.
#   R = remote npm repo whose upstream_url is U's AK URL.
#
# Assertions (count-axis, same technique as the pypi cache-hit test):
#   1. Cold packument fetch through R primes the cache (v1 present).
#   2. N warm refetches are byte-identical -- a stable cache source, not a
#      per-request upstream re-fetch or a partial-cache-write race.
#   3. After a NEW version lands on U, the packument on R still serves the
#      cached (v1-only) document within the long TTL window. If the proxy
#      re-fetched upstream on every call we would already see v2 here; a
#      packument that still lacks v2 within TTL proves the warm hit was
#      served from cache (the SWR "serve stale" property).
#
# Feature-gated on `npm_packument_swr` so it auto-skips on a 1.2.x backend.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm-packument-swr"
auth_admin
setup_workdir

begin_test "Backend supports npm_packument_swr (v1.3.0)"
if require_feature "npm_packument_swr"; then
  pass
else
  end_suite
  exit 0
fi

UPSTREAM_KEY="nps-up-${RUN_ID}"
REMOTE_KEY="nps-rem-${RUN_ID}"
PKG_NAME="npspkg${RUN_ID//-/}"
PKG_V1="1.0.0"
PKG_V2="2.0.0"
# Long TTL so no test step can slip past it on a loaded runner.
TTL_SECS=60
HIT_FETCHES=5

cleanup_repos() {
  api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

# Publish PKG_NAME@<version> to the local upstream U via the npm _attachments
# PUT payload shape (same as tests/formats/test-npm.sh curl fallback).
publish_to_upstream() {
  local version="$1"
  local pkgdir="${WORK_DIR}/pub-${version}"
  mkdir -p "$pkgdir"
  printf '{"name":"%s","version":"%s"}\n' "$PKG_NAME" "$version" > "${pkgdir}/package.json"
  printf 'module.exports = "%s";\n' "$version" > "${pkgdir}/index.js"
  local tgz="${WORK_DIR}/${PKG_NAME}-${version}.tgz"
  tar czf "$tgz" -C "$pkgdir" .
  base64 < "$tgz" | tr -d '\n' > "${WORK_DIR}/b64-${version}.txt"
  local size
  size=$(wc -c < "$tgz" | tr -d ' ')
  jq -n \
    --arg name "$PKG_NAME" --arg version "$version" \
    --arg tarball "${BASE_URL}/npm/${UPSTREAM_KEY}/${PKG_NAME}/-/${PKG_NAME}-${version}.tgz" \
    --rawfile data "${WORK_DIR}/b64-${version}.txt" \
    --argjson length "$size" \
    '{name: $name, versions: {($version): {name: $name, version: $version, dist: {tarball: $tarball}}},
      "_attachments": {("\($name)-\($version).tgz"): {content_type: "application/octet-stream", data: $data, length: $length}}}' \
    > "${WORK_DIR}/publish-${version}.json"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/json" \
    --data-binary "@${WORK_DIR}/publish-${version}.json" \
    "${BASE_URL}/npm/${UPSTREAM_KEY}/${PKG_NAME}" 2>/dev/null) || status="000"
  echo "$status"
}

fetch_packument() {
  curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${REMOTE_KEY}/${PKG_NAME}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create local npm upstream U"
if create_local_repo "$UPSTREAM_KEY" "npm"; then
  pass
else
  fail "could not create npm upstream"
fi

begin_test "Publish ${PKG_NAME}@${PKG_V1} to U"
st=$(publish_to_upstream "$PKG_V1")
if [ "$st" = "200" ] || [ "$st" = "201" ]; then
  pass
else
  skip "npm publish endpoint unavailable (status ${st}); cannot run packument SWR assertion"
  cleanup_repos
  end_suite
  exit 0
fi

# Wait for U to surface v1 in its own packument.
deadline=$(( $(date +%s) + 10 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/npm/${UPSTREAM_KEY}/${PKG_NAME}" 2>/dev/null \
      | grep -q "\"${PKG_V1}\"" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Create remote R pointing at U (TTL=${TTL_SECS}s)"
if create_remote_repo "$REMOTE_KEY" "npm" "${BASE_URL}/npm/${UPSTREAM_KEY}"; then
  pass
else
  fail "could not create remote R"
fi
api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
  "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 1. Prime the packument cache
# ---------------------------------------------------------------------------

begin_test "Prime cache: first packument fetch through R contains v${PKG_V1}"
PRIMED=$(fetch_packument) || PRIMED=""
if [ -n "$PRIMED" ] && echo "$PRIMED" | grep -q "\"${PKG_V1}\""; then
  pass
else
  fail "primed packument missing v${PKG_V1}; SWR test cannot proceed (got: ${PRIMED:0:200})"
fi
PRIME_TS=$(date +%s)

# ---------------------------------------------------------------------------
# 2. N tight-loop refetches must return byte-identical bodies (cache hit)
# ---------------------------------------------------------------------------

begin_test "${HIT_FETCHES} consecutive packument refetches are byte-identical (cache hit)"
mismatch=0
last="$PRIMED"
for i in $(seq 1 $HIT_FETCHES); do
  body=$(fetch_packument) || body=""
  if [ -z "$body" ]; then
    mismatch=1; echo "  fetch ${i}: empty body"; break
  fi
  if [ "$body" != "$last" ]; then
    mismatch=1; echo "  fetch ${i}: body differs from previous (cache miss or partial write)"; break
  fi
  last="$body"
done
if [ "$mismatch" -eq 0 ]; then
  pass
else
  fail "consecutive packument refetches diverged; cache is not serving hits as a stable byte source"
fi

# ---------------------------------------------------------------------------
# 3. Publish v2 to U; within the TTL window R still serves the cached
#    v1-only packument (SWR serve-stale, no per-call upstream re-fetch).
# ---------------------------------------------------------------------------

begin_test "Publish ${PKG_NAME}@${PKG_V2} to upstream U (cache still primed)"
st=$(publish_to_upstream "$PKG_V2")
if [ "$st" = "200" ] || [ "$st" = "201" ]; then
  pass
else
  fail "could not publish v${PKG_V2} to U (status ${st})"
fi

# Confirm U itself now sees v2 (sanity).
deadline=$(( $(date +%s) + 10 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/npm/${UPSTREAM_KEY}/${PKG_NAME}" 2>/dev/null \
      | grep -q "\"${PKG_V2}\"" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Within-TTL packument refetch still serves cached v${PKG_V1}-only (no upstream re-fetch)"
NOW=$(date +%s)
ELAPSED=$(( NOW - PRIME_TS ))
if [ "$ELAPSED" -ge "$TTL_SECS" ]; then
  skip "scheduling slipped past TTL window (elapsed=${ELAPSED}s, ttl=${TTL_SECS}s)"
else
  BODY=$(fetch_packument) || BODY=""
  if [ -z "$BODY" ]; then
    fail "within-TTL packument refetch returned empty"
  elif echo "$BODY" | grep -q "\"${PKG_V2}\""; then
    fail "CACHE BYPASSED: within-TTL packument already shows v${PKG_V2}; proxy re-fetched upstream every call (SWR serve-stale violated)"
  elif echo "$BODY" | grep -q "\"${PKG_V1}\""; then
    pass
  else
    fail "within-TTL packument refetch returned unexpected body: ${BODY:0:200}"
  fi
fi

end_suite
