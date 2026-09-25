#!/usr/bin/env bash
# test-virtual-nested-members.sh - Nested virtual repositories aggregate leaf
# content, and npm writes addressed at a virtual land in its hosted member.
#
# Release gate for:
#   artifact-keeper#3840 - virtual repository member expansion was a
#     single-level join, so a virtual whose member was itself a virtual
#     listed and resolved nothing (0 rows through the intermediate node).
#   artifact-keeper#968  - a publish addressed at a virtual repository was
#     rejected with 400 "Cannot publish to a virtual repository", so the
#     single-entry-point layout (one virtual in front of the hosted repo)
#     was impossible for writers.
#
# Layout:
#   LEAF = local npm repo (the content-owning publish target).
#   MID  = virtual npm repo containing LEAF (priority 1).
#   TOP  = virtual npm repo containing MID (priority 1).
#
# Assertions:
#   1. A version published directly to LEAF is served by TOP's packument and
#      appears in TOP's artifact listing -- the recursive member walk. Both
#      fail against an unfixed backend, where the nested virtual contributes
#      zero members.
#   2. `npm publish` addressed at TOP returns 2xx and the version lands in
#      LEAF (the deployment-target routing), then TOP's own packument serves
#      it -- which also exercises the recursive ancestor cache-invalidation
#      walk. The publish returns 400 on an unfixed backend.
#   3. The write-time cycle guard keeps refusing MID -> TOP (TOP already
#      reaches MID): the recursive read walk stays cycle-free by
#      construction. Green on fixed and unfixed backends; pins the invariant.
#
# Feature-gated on `virtual_nested_members` (floor 1.11.0) so the suite
# auto-skips on older backends.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-nested-members"
auth_admin
setup_workdir

begin_test "Backend supports virtual_nested_members (v1.11.0)"
if require_feature "virtual_nested_members"; then
  pass
else
  end_suite
  exit 0
fi

LEAF_KEY="vn-leaf-${RUN_ID}"
MID_KEY="vn-mid-${RUN_ID}"
TOP_KEY="vn-top-${RUN_ID}"
PKG_NAME="vnpkg${RUN_ID//-/}"
PKG_V1="1.0.0"
PKG_V2="2.0.0"

cleanup_repos() {
  api_delete "/api/v1/repositories/${TOP_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${MID_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${LEAF_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

# Publish PKG_NAME@<version> to repo <key> via the npm _attachments PUT
# payload shape (same as tests/pullthrough/test-npm-packument-swr.sh).
npm_publish() {
  local repo_key="$1"
  local version="$2"
  local pkgdir="${WORK_DIR}/pub-${repo_key}-${version}"
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
    --arg tarball "${BASE_URL}/npm/${repo_key}/${PKG_NAME}/-/${PKG_NAME}-${version}.tgz" \
    --rawfile data "${WORK_DIR}/b64-${version}.txt" \
    --argjson length "$size" \
    '{name: $name, versions: {($version): {name: $name, version: $version, dist: {tarball: $tarball}}},
      "_attachments": {("\($name)-\($version).tgz"): {content_type: "application/octet-stream", data: $data, length: $length}}}' \
    > "${WORK_DIR}/publish-${repo_key}-${version}.json"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/json" \
    --data-binary "@${WORK_DIR}/publish-${repo_key}-${version}.json" \
    "${BASE_URL}/npm/${repo_key}/${PKG_NAME}" 2>/dev/null) || status="000"
  echo "$status"
}

fetch_packument() {
  local repo_key="$1"
  curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${repo_key}/${PKG_NAME}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup: LEAF local, MID virtual {LEAF}, TOP virtual {MID}
# ---------------------------------------------------------------------------

begin_test "Create local npm repo LEAF"
if create_local_repo "$LEAF_KEY" "npm"; then
  pass
else
  fail "could not create local npm repo"
fi

begin_test "Create virtual npm repo MID containing LEAF"
if create_virtual_repo "$MID_KEY" "npm" "$LEAF_KEY"; then
  pass
else
  fail "could not create MID with LEAF as member"
fi

begin_test "Create virtual npm repo TOP containing MID"
if create_virtual_repo "$TOP_KEY" "npm" "$MID_KEY"; then
  pass
else
  fail "could not create TOP with MID as member"
fi

begin_test "Publish ${PKG_NAME}@${PKG_V1} directly to LEAF"
st=$(npm_publish "$LEAF_KEY" "$PKG_V1")
if [ "$st" = "200" ] || [ "$st" = "201" ]; then
  pass
else
  skip "npm publish endpoint unavailable (status ${st}); cannot run nested-virtual assertions"
  cleanup_repos
  end_suite
  exit 0
fi

# Wait for LEAF to surface v1 in its own packument before probing through TOP.
deadline=$(( $(date +%s) + 10 ))
until fetch_packument "$LEAF_KEY" | grep -q "\"${PKG_V1}\"" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

# ---------------------------------------------------------------------------
# 1. Recursive member expansion (#3840)
# ---------------------------------------------------------------------------

begin_test "Nested virtual TOP serves LEAF's packument (#3840)"
PACK=$(fetch_packument "$TOP_KEY") || PACK=""
if [ -n "$PACK" ] && echo "$PACK" | grep -q "\"${PKG_V1}\""; then
  pass
else
  fail "TOP (virtual containing a virtual) does not serve LEAF's version; \
single-level member expansion strikes again (got: $(echo "$PACK" | head -c 200))"
fi

begin_test "Nested virtual TOP lists LEAF's artifact (#3840)"
LIST=$(api_get "/api/v1/repositories/${TOP_KEY}/artifacts" 2>/dev/null) || LIST=""
if [ -n "$LIST" ] && echo "$LIST" | grep -q "$PKG_NAME"; then
  pass
else
  fail "TOP's artifact listing is empty though LEAF holds ${PKG_NAME}; \
the flat listing still expands members single-level (got: $(echo "$LIST" | head -c 200))"
fi

# ---------------------------------------------------------------------------
# 2. Publish through the virtual (#968)
# ---------------------------------------------------------------------------

begin_test "npm publish addressed at TOP succeeds (#968)"
st=$(npm_publish "$TOP_KEY" "$PKG_V2")
if [ "$st" = "200" ] || [ "$st" = "201" ]; then
  pass
else
  fail "publish through TOP returned ${st}; expected 200/201 (unfixed backends answer 400)"
fi

begin_test "Through-TOP publish landed in LEAF (#968)"
LEAF_PACK=""
deadline=$(( $(date +%s) + 10 ))
until LEAF_PACK=$(fetch_packument "$LEAF_KEY") && echo "$LEAF_PACK" | grep -q "\"${PKG_V2}\"" \
      || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done
if [ -n "$LEAF_PACK" ] && echo "$LEAF_PACK" | grep -q "\"${PKG_V2}\""; then
  pass
else
  fail "LEAF does not carry ${PKG_V2} after publishing through TOP; \
the write did not route to the hosted member"
fi

begin_test "TOP serves the through-TOP version immediately (#968 invalidation)"
TOP_PACK=""
deadline=$(( $(date +%s) + 15 ))
until TOP_PACK=$(fetch_packument "$TOP_KEY") && echo "$TOP_PACK" | grep -q "\"${PKG_V2}\"" \
      || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.5
done
if [ -n "$TOP_PACK" ] && echo "$TOP_PACK" | grep -q "\"${PKG_V2}\""; then
  pass
else
  fail "TOP does not serve ${PKG_V2} right after the through-TOP publish; \
the ancestor-virtual packument invalidation did not reach TOP"
fi

# ---------------------------------------------------------------------------
# 3. Cycle guard invariant (write-time guard keeps the read walk acyclic)
# ---------------------------------------------------------------------------

begin_test "Cycle guard refuses to close MID -> TOP"
cycle_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
  -H "$(format_auth_header)" -H "Content-Type: application/json" \
  -d "{\"member_key\":\"${TOP_KEY}\"}" \
  "${BASE_URL}/api/v1/repositories/${MID_KEY}/members" 2>/dev/null) || cycle_status="000"
if [ "$cycle_status" = "400" ]; then
  pass
else
  fail "adding TOP as a member of MID returned ${cycle_status}; the write-time \
cycle guard must answer 400 or the recursive read walk would loop"
fi

end_suite
