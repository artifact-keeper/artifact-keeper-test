#!/usr/bin/env bash
# test-agentplugins-conformance.sh - Agent Plugins repository conformance
#
# Pins the wire contract of the agentplugins format (artifact-keeper#5251)
# beyond the happy path in test-agentplugins.sh:
#
#   1. claude-marketplace.json obeys the rules Claude Code enforces when it
#      loads a marketplace from a URL: the marketplace `name` and every entry
#      `name` match ^[A-Za-z0-9][A-Za-z0-9._-]*$ and contain no "..",
#      `owner.name` is present, no entry uses a relative-path source (only
#      `archive` sources work for a hosted marketplace), and each entry's
#      `version` equals the version in its archive path.
#   2. Publishes the backend must refuse with 400: no manifest, a manifest
#      `name` that differs from the slug, a manifest `version` that differs
#      from the path, a `../` entry, a non-SemVer version, a filename that is
#      not {name}-{version}.zip, and an uppercase slug. None of them may
#      appear in an index afterwards.
#   3. A virtual agentplugins repository is refused (400, not supported yet),
#      a remote one is accepted (artifact-keeper#5289: a Remote proxies
#      another Artifact Keeper's hosted repository), and a repository keyed
#      `t`, which would shadow the token route, is refused.
#   4. A private repository is readable through the token-in-path prefix
#      /agentplugins/t/{token}/{repo}/..., archive URLs keep that prefix and
#      download with no Authorization header, and the plain URL without
#      credentials is refused.
#   5. Index documents carry an ETag, answer If-None-Match with 304 and are
#      Cache-Control: no-cache; token-route responses are private, no-store,
#      and a bogus path token is 401.
#   6. A deleted version can only come back with identical bytes (different
#      bytes 409, an empty body 400), SemVer build metadata is refused, a
#      generic REST upload is neither indexed nor served natively, and a
#      rename onto the reserved key `t` is refused.
#
# AK_EXTERNAL_URL is not asserted (it depends on the deployment), so archive
# URLs are compared by path only and downloaded from BASE_URL.
#
# Capability gate: as in test-agentplugins.sh, a backend that answers
# repository creation with `400 Invalid format: agentplugins` does not ship
# the format, and the suite stands down through skip_suite and the
# agentplugins_format row of _CAPABILITY_EXEMPTIONS.
#
# Requires: curl, jq, zip, python3, sha256sum

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "agentplugins-conformance"
auth_admin
setup_workdir
require_cmd jq
require_cmd zip
require_cmd python3
require_cmd sha256sum

REPO_KEY="test-ap-conf-${RUN_ID}"
PRIVATE_KEY="test-ap-priv-${RUN_ID}"
REMOTE_KEY="test-ap-remote-${RUN_ID}"
VIRTUAL_KEY="test-ap-virtual-${RUN_ID}"
GATE_REASON="repository format 'agentplugins' is not known to this backend (POST /api/v1/repositories: 400 Invalid format: agentplugins); Agent Plugins format not shipped"
NAME_RE='^[A-Za-z0-9][A-Za-z0-9._-]*$'

PLUGIN="conf-plugin"
PLUGIN_VERSION="1.2.3"
PRIV_PLUGIN="priv-plugin"
PRIV_VERSION="0.1.0"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

url_path() {
  printf '%s' "$1" | sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://[^/]+##'
}

sha_of() {
  sha256sum "$1" | cut -d' ' -f1
}

# create_ap_repo KEY IS_PUBLIC: create an agentplugins local repository.
# Stands the suite down when the backend does not know the format. Echoes
# nothing; returns 0 on 2xx.
create_ap_repo() {
  local key="$1" is_public="$2" out="${WORK_DIR}/create-${1}.json" status="000"
  for _ in 1 2 3 4; do
    status=$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
      -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
      -d "{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"agentplugins\",\"repo_type\":\"local\",\"is_public\":${is_public}}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"
    case "$status" in
      000|401|429|503) sleep 2 ;;
      *) break ;;
    esac
  done
  if [ "$status" = "400" ] && grep -q 'Invalid format: agentplugins' "$out" 2>/dev/null; then
    skip_suite "$GATE_REASON"
  fi
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"${BASE_URL}/api/v1/repositories/${key}\" || true"
    return 0
  fi
  CREATE_ERROR="HTTP ${status}: $(head -c 300 "$out" 2>/dev/null)"
  return 1
}

# ap_put REPO ZIP PATH: PUT ZIP to /agentplugins/REPO/PATH. Sets PUT_STATUS
# and PUT_BODY.
ap_put() {
  local repo="$1" zip="$2" path="$3" out="${WORK_DIR}/put-resp.txt"
  PUT_STATUS=$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X PUT -H "$(format_auth_header)" -H "Content-Type: application/zip" \
    --data-binary "@${zip}" \
    "${BASE_URL}/agentplugins/${repo}/${path}" 2>/dev/null) || PUT_STATUS="000"
  PUT_BODY=$(cat "$out" 2>/dev/null || true)
}

# header_value FILE NAME: the value of header NAME in a curl -D dump.
header_value() {
  grep -i "^${2}:" "$1" 2>/dev/null | head -1 | cut -d: -f2- | sed -e 's/^ *//' -e 's/\r$//' || true
}

# claude_manifest DIR NAME VERSION: write DIR/.claude-plugin/plugin.json plus
# one skill. An empty NAME or VERSION omits that field.
claude_manifest() {
  local dir="$1" name="$2" version="$3"
  mkdir -p "${dir}/.claude-plugin" "${dir}/skills/check"
  jq -n --arg name "$name" --arg version "$version" '
    {description: "Agent Plugins conformance fixture", author: {name: "Artifact Keeper Release Gate"}}
    + (if $name == "" then {} else {name: $name} end)
    + (if $version == "" then {} else {version: $version} end)' \
    > "${dir}/.claude-plugin/plugin.json"
  cat > "${dir}/skills/check/SKILL.md" <<'EOF'
---
name: check
description: Conformance fixture skill.
---

Run the conformance check.
EOF
}

# build_zip NAME MANIFEST_NAME MANIFEST_VERSION: a Claude-layout zip at
# WORK_DIR/NAME.zip, echoes its path.
build_zip() {
  local label="$1" dir="${WORK_DIR}/src-${1}"
  rm -rf "$dir"
  claude_manifest "$dir" "$2" "$3"
  rm -f "${WORK_DIR}/${label}.zip"
  (cd "$dir" && zip -qrX "${WORK_DIR}/${label}.zip" .)
  echo "${WORK_DIR}/${label}.zip"
}

# expect_400 DESCRIPTION ZIP PATH
expect_400() {
  local description="$1" zip="$2" path="$3"
  begin_test "Publish refused with 400: ${description}"
  ap_put "$REPO_KEY" "$zip" "$path"
  if assert_eq "$PUT_STATUS" "400" "PUT ${path} returned HTTP ${PUT_STATUS}, expected 400 (${description})"; then
    pass
  else
    echo "    body: ${PUT_BODY:0:300}"
  fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create agentplugins local repository"
if create_ap_repo "$REPO_KEY" true; then
  pass
else
  fail_fatal "could not create agentplugins repository: ${CREATE_ERROR}"
fi

begin_test "Publish a valid Claude-layout plugin"
GOOD_ZIP=$(build_zip "good" "$PLUGIN" "$PLUGIN_VERSION")
GOOD_SHA=$(sha_of "$GOOD_ZIP")
ap_put "$REPO_KEY" "$GOOD_ZIP" "${PLUGIN}/${PLUGIN_VERSION}/${PLUGIN}-${PLUGIN_VERSION}.zip"
if [ "$PUT_STATUS" = "201" ]; then
  PUBLISH_MP_NAME=$(printf '%s' "$PUT_BODY" | jq -r '.marketplace_name // empty' 2>/dev/null) || PUBLISH_MP_NAME=""
  pass
else
  fail_fatal "valid publish returned HTTP ${PUT_STATUS}, expected 201" "${PUT_BODY:0:600}"
fi

# ---------------------------------------------------------------------------
# 1. Claude Code marketplace schema rules
# ---------------------------------------------------------------------------

CLAUDE_DOC="${WORK_DIR}/claude-marketplace.json"
CLAUDE_HDR="${WORK_DIR}/claude-marketplace.headers"
CLAUDE_STATUS=$(curl -s -D "$CLAUDE_HDR" -o "$CLAUDE_DOC" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -H "$(format_auth_header)" \
  "${BASE_URL}/agentplugins/${REPO_KEY}/claude-marketplace.json" 2>/dev/null) || CLAUDE_STATUS="000"

begin_test "claude-marketplace.json is served as JSON"
if [ "$CLAUDE_STATUS" != "200" ]; then
  fail "GET claude-marketplace.json returned HTTP ${CLAUDE_STATUS}" "$(head -c 400 "$CLAUDE_DOC" 2>/dev/null)"
elif ! jq -e '.plugins | type == "array"' "$CLAUDE_DOC" >/dev/null 2>&1; then
  fail "claude-marketplace.json has no plugins array" "$(head -c 600 "$CLAUDE_DOC")"
else
  pass
fi

begin_test "Marketplace name is a valid Claude Code marketplace name"
MP_NAME=$(jq -r '.name // empty' "$CLAUDE_DOC" 2>/dev/null) || MP_NAME=""
if [[ ! "$MP_NAME" =~ $NAME_RE ]]; then
  fail "marketplace name '${MP_NAME}' does not match ${NAME_RE}"
elif [[ "$MP_NAME" == *..* ]]; then
  fail "marketplace name '${MP_NAME}' contains '..'"
else
  pass
fi

begin_test "Publish response marketplace_name is the document's name"
if assert_eq "$PUBLISH_MP_NAME" "$MP_NAME" "publish response marketplace_name '${PUBLISH_MP_NAME}', claude-marketplace.json name '${MP_NAME}'"; then
  pass
fi

begin_test "Marketplace owner.name is present"
OWNER=$(jq -r '.owner.name // empty' "$CLAUDE_DOC" 2>/dev/null) || OWNER=""
if [ -n "$OWNER" ]; then
  pass
else
  fail "owner.name is missing" "$(jq -c '.owner' "$CLAUDE_DOC" 2>/dev/null)"
fi

begin_test "Every entry has a valid name, an archive source and the path version"
PROBLEMS=""
COUNT=$(jq '.plugins | length' "$CLAUDE_DOC" 2>/dev/null) || COUNT=0
for (( i = 0; i < COUNT; i++ )); do
  e_name=$(jq -r ".plugins[$i].name // empty" "$CLAUDE_DOC")
  e_type=$(jq -r ".plugins[$i].source | type" "$CLAUDE_DOC")
  e_kind=$(jq -r ".plugins[$i].source.source? // empty" "$CLAUDE_DOC")
  e_sha=$(jq -r ".plugins[$i].source.sha256? // empty" "$CLAUDE_DOC")
  e_url=$(jq -r ".plugins[$i].source.url? // empty" "$CLAUDE_DOC")
  e_version=$(jq -r ".plugins[$i].version // empty" "$CLAUDE_DOC")
  if [[ ! "$e_name" =~ $NAME_RE ]] || [[ "$e_name" == *..* ]]; then
    PROBLEMS="${PROBLEMS}entry ${i}: name '${e_name}' is not a valid plugin name; "
  fi
  # A string source is a relative path inside a git-hosted marketplace;
  # Claude Code cannot resolve one from a URL marketplace.
  if [ "$e_type" != "object" ]; then
    PROBLEMS="${PROBLEMS}${e_name}: source is a ${e_type} (relative path), not an object; "
    continue
  fi
  if [ "$e_kind" != "archive" ]; then
    PROBLEMS="${PROBLEMS}${e_name}: source.source=${e_kind:-<none>}, expected archive; "
  fi
  if ! [[ "$e_sha" =~ ^[0-9a-f]{64}$ ]]; then
    PROBLEMS="${PROBLEMS}${e_name}: source.sha256 '${e_sha}' is not 64 lowercase hex; "
  fi
  e_path=$(url_path "$e_url")
  # .../{name}/{version}/{name}-{version}.zip: the version is the next-to-last segment.
  path_version=$(printf '%s' "$e_path" | awk -F/ '{print $(NF-1)}')
  if [ "$e_path" != "/agentplugins/${REPO_KEY}/${e_name}/${path_version}/${e_name}-${path_version}.zip" ]; then
    PROBLEMS="${PROBLEMS}${e_name}: source.url '${e_url}' is not {name}/{version}/{name}-{version}.zip; "
  elif [ "$e_version" != "$path_version" ]; then
    PROBLEMS="${PROBLEMS}${e_name}: version ${e_version} differs from path version ${path_version}; "
  fi
done
if [ "$COUNT" -lt 1 ]; then
  fail "claude-marketplace.json has no entries after a valid publish"
elif [ -n "$PROBLEMS" ]; then
  fail "$PROBLEMS" "$(head -c 1200 "$CLAUDE_DOC")"
else
  pass
fi

begin_test "Entry sha256 matches the archive bytes and the published zip"
E_URL=$(jq -r --arg n "$PLUGIN" '.plugins[] | select(.name == $n) | .source.url' "$CLAUDE_DOC" 2>/dev/null) || E_URL=""
E_SHA=$(jq -r --arg n "$PLUGIN" '.plugins[] | select(.name == $n) | .source.sha256' "$CLAUDE_DOC" 2>/dev/null) || E_SHA=""
E_VER=$(jq -r --arg n "$PLUGIN" '.plugins[] | select(.name == $n) | .version' "$CLAUDE_DOC" 2>/dev/null) || E_VER=""
DL="${WORK_DIR}/entry.zip"
if [ -z "$E_URL" ]; then
  fail "${PLUGIN} is not in claude-marketplace.json" "$(head -c 800 "$CLAUDE_DOC")"
elif ! curl -sf -o "$DL" "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" "${BASE_URL}$(url_path "$E_URL")"; then
  fail "archive ${E_URL} did not download"
elif assert_eq "$(sha_of "$DL")" "$E_SHA" "downloaded archive hashes to $(sha_of "$DL"), entry says ${E_SHA}" && \
     assert_eq "$E_SHA" "$GOOD_SHA" "entry sha256 ${E_SHA} is not the published zip's ${GOOD_SHA}" && \
     assert_eq "$E_VER" "$PLUGIN_VERSION" "entry version ${E_VER}, published ${PLUGIN_VERSION}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 2. Publishes the backend must refuse
# ---------------------------------------------------------------------------

NEG_NONE="${WORK_DIR}/neg-none.zip"
mkdir -p "${WORK_DIR}/src-neg-none/docs"
echo "not a plugin" > "${WORK_DIR}/src-neg-none/docs/README.md"
(cd "${WORK_DIR}/src-neg-none" && zip -qrX "$NEG_NONE" .)
expect_400 "zip without any plugin manifest" "$NEG_NONE" "neg-none/1.0.0/neg-none-1.0.0.zip"

NEG_NAME=$(build_zip "neg-name" "some-other-name" "1.0.0")
expect_400 "manifest name differs from the slug" "$NEG_NAME" "neg-name/1.0.0/neg-name-1.0.0.zip"

NEG_VERSION=$(build_zip "neg-version" "neg-version" "9.9.9")
expect_400 "manifest version differs from the path version" "$NEG_VERSION" "neg-version/1.0.0/neg-version-1.0.0.zip"

# zip(1) normalises "../" away, so write the traversal entry with zipfile.
NEG_TRAVERSAL="${WORK_DIR}/neg-traversal.zip"
python3 -I - "$NEG_TRAVERSAL" <<'EOF'
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr(".claude-plugin/plugin.json",
               json.dumps({"name": "neg-traversal", "version": "1.0.0"}))
    z.writestr("skills/check/SKILL.md", "---\nname: check\ndescription: x\n---\n")
    z.writestr("../escape.txt", "escaped")
EOF
expect_400 "entry named ../escape.txt" "$NEG_TRAVERSAL" "neg-traversal/1.0.0/neg-traversal-1.0.0.zip"

NEG_SEMVER=$(build_zip "neg-semver" "neg-semver" "")
expect_400 "non-SemVer version v1" "$NEG_SEMVER" "neg-semver/v1/neg-semver-v1.zip"

NEG_FILE=$(build_zip "neg-file" "neg-file" "1.0.0")
expect_400 "filename is not {name}-{version}.zip" "$NEG_FILE" "neg-file/1.0.0/something-else-1.0.0.zip"

NEG_UPPER=$(build_zip "neg-upper" "" "1.0.0")
expect_400 "uppercase slug" "$NEG_UPPER" "Neg-Upper/1.0.0/Neg-Upper-1.0.0.zip"

begin_test "Refused publishes do not appear in marketplace.json"
ALL_DOC="${WORK_DIR}/marketplace.json"
ALL_STATUS=$(curl -s -o "$ALL_DOC" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" \
  "${BASE_URL}/agentplugins/${REPO_KEY}/marketplace.json" 2>/dev/null) || ALL_STATUS="000"
ALL_NAMES=$(jq -r '[.plugins[].name] | sort | join(",")' "$ALL_DOC" 2>/dev/null) || ALL_NAMES=""
if [ "$ALL_STATUS" != "200" ]; then
  fail "GET marketplace.json returned HTTP ${ALL_STATUS}"
elif assert_eq "$ALL_NAMES" "$PLUGIN" "marketplace.json lists [${ALL_NAMES}], expected only [${PLUGIN}]"; then
  pass
fi

# ---------------------------------------------------------------------------
# 3. Repository types: hosted and remote, not virtual (artifact-keeper#5289)
# ---------------------------------------------------------------------------

begin_test "Creating a virtual agentplugins repository is refused with 400"
VIRTUAL_OUT="${WORK_DIR}/virtual.json"
VIRTUAL_STATUS=$(curl -s -o "$VIRTUAL_OUT" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "{\"key\":\"${VIRTUAL_KEY}\",\"name\":\"${VIRTUAL_KEY}\",\"format\":\"agentplugins\",\"repo_type\":\"virtual\",\"is_public\":true}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || VIRTUAL_STATUS="000"
if [ "$VIRTUAL_STATUS" -ge 200 ] 2>/dev/null && [ "$VIRTUAL_STATUS" -lt 300 ] 2>/dev/null; then
  api_delete "/api/v1/repositories/${VIRTUAL_KEY}" >/dev/null 2>&1 || true
fi
if ! assert_eq "$VIRTUAL_STATUS" "400" "virtual repository creation returned HTTP ${VIRTUAL_STATUS}, expected 400"; then
  echo "    body: $(head -c 300 "$VIRTUAL_OUT" 2>/dev/null)"
elif ! grep -q 'virtual repositories are not supported yet' "$VIRTUAL_OUT" 2>/dev/null; then
  fail "virtual refusal does not say virtual repositories are not supported yet: $(head -c 300 "$VIRTUAL_OUT" 2>/dev/null)"
else
  pass
fi

begin_test "Creating a remote agentplugins repository succeeds (2xx)"
REMOTE_OUT="${WORK_DIR}/remote.json"
REMOTE_STATUS=$(curl -s -o "$REMOTE_OUT" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "{\"key\":\"${REMOTE_KEY}\",\"name\":\"${REMOTE_KEY}\",\"format\":\"agentplugins\",\"repo_type\":\"remote\",\"upstream_url\":\"https://example.com/agentplugins/plugins\",\"is_public\":true}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || REMOTE_STATUS="000"
if [ "$REMOTE_STATUS" -ge 200 ] 2>/dev/null && [ "$REMOTE_STATUS" -lt 300 ] 2>/dev/null; then
  api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
  pass
else
  fail "remote repository creation returned HTTP ${REMOTE_STATUS}, expected 2xx: $(head -c 300 "$REMOTE_OUT" 2>/dev/null)"
fi

begin_test "An agentplugins repository keyed 't' is refused with 400 (it would shadow /agentplugins/t/)"
T_OUT="${WORK_DIR}/t-repo.json"
T_STATUS=$(curl -s -o "$T_OUT" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d '{"key":"t","name":"t","format":"agentplugins","repo_type":"local","is_public":true}' \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || T_STATUS="000"
if [ "$T_STATUS" -ge 200 ] 2>/dev/null && [ "$T_STATUS" -lt 300 ] 2>/dev/null; then
  api_delete "/api/v1/repositories/t" >/dev/null 2>&1 || true
fi
if assert_eq "$T_STATUS" "400" "creating agentplugins repository 't' returned HTTP ${T_STATUS}, expected 400"; then
  pass
else
  echo "    body: $(head -c 300 "$T_OUT" 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# 4. Private repository through the token-in-path prefix
# ---------------------------------------------------------------------------

READ_TOKEN=""
READ_TOKEN_ID=""

begin_test "Create a private agentplugins repository"
if create_ap_repo "$PRIVATE_KEY" false; then
  PRIVATE_READY=true
  pass
else
  PRIVATE_READY=false
  fail "could not create private agentplugins repository: ${CREATE_ERROR}"
fi

begin_test "Mint a repository-scoped read token"
if [ "$PRIVATE_READY" = true ]; then
  MINT_OUT="${WORK_DIR}/mint.json"
  MINT_STATUS=$(curl -s -o "$MINT_OUT" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-agentplugins-read-${RUN_ID}\",\"scopes\":[\"read:artifacts\"],\"expires_in_days\":1}" \
    "${BASE_URL}/api/v1/repositories/${PRIVATE_KEY}/tokens" 2>/dev/null) || MINT_STATUS="000"
  READ_TOKEN=$(jq -r '.token // empty' "$MINT_OUT" 2>/dev/null) || READ_TOKEN=""
  READ_TOKEN_ID=$(jq -r '.id // empty' "$MINT_OUT" 2>/dev/null) || READ_TOKEN_ID=""
  if [ -n "$READ_TOKEN" ]; then
    if [ -n "$READ_TOKEN_ID" ]; then
      add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"${BASE_URL}/api/v1/repositories/${PRIVATE_KEY}/tokens/${READ_TOKEN_ID}\" || true"
    fi
    pass
  else
    fail "token mint returned HTTP ${MINT_STATUS}" "$(head -c 400 "$MINT_OUT" 2>/dev/null)"
  fi
else
  fail "no private repository"
fi

begin_test "Publish a plugin to the private repository"
PRIV_ZIP=$(build_zip "priv" "$PRIV_PLUGIN" "$PRIV_VERSION")
PRIV_SHA=$(sha_of "$PRIV_ZIP")
PRIV_PUBLISHED=false
if [ "$PRIVATE_READY" = true ]; then
  ap_put "$PRIVATE_KEY" "$PRIV_ZIP" "${PRIV_PLUGIN}/${PRIV_VERSION}/${PRIV_PLUGIN}-${PRIV_VERSION}.zip"
  if assert_eq "$PUT_STATUS" "201" "private publish returned HTTP ${PUT_STATUS}, expected 201: ${PUT_BODY:0:300}"; then
    PRIV_PUBLISHED=true
    pass
  fi
else
  fail "no private repository"
fi

TOKEN_PREFIX="/agentplugins/t/${READ_TOKEN}/"
TOKEN_DOC="${WORK_DIR}/token-claude.json"

begin_test "Token-in-path claude-marketplace.json is 200 without an Authorization header"
TOKEN_STATUS="000"
if [ -n "$READ_TOKEN" ] && [ "$PRIV_PUBLISHED" = true ]; then
  TOKEN_STATUS=$(curl -s -D "${WORK_DIR}/token.headers" -o "$TOKEN_DOC" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    "${BASE_URL}${TOKEN_PREFIX}${PRIVATE_KEY}/claude-marketplace.json" 2>/dev/null) || TOKEN_STATUS="000"
  if assert_eq "$TOKEN_STATUS" "200" "token-in-path marketplace returned HTTP ${TOKEN_STATUS}, expected 200"; then
    pass
  fi
else
  fail "needs the read token and the private publish"
fi

begin_test "Token-in-path responses are Cache-Control: private, no-store"
TOKEN_CC=$(header_value "${WORK_DIR}/token.headers" "cache-control")
if [ "$TOKEN_STATUS" != "200" ]; then
  fail "needs the token-in-path marketplace"
elif assert_contains "$TOKEN_CC" "private" "token route Cache-Control '${TOKEN_CC}' lacks private" && \
     assert_contains "$TOKEN_CC" "no-store" "token route Cache-Control '${TOKEN_CC}' lacks no-store"; then
  pass
fi

begin_test "A bogus token in the path is refused with 401"
BOGUS_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  "${BASE_URL}/agentplugins/t/not-a-real-token-${RUN_ID}/${PRIVATE_KEY}/claude-marketplace.json" 2>/dev/null) || BOGUS_STATUS="000"
if assert_eq "$BOGUS_STATUS" "401" "bogus token returned HTTP ${BOGUS_STATUS}, expected 401"; then
  pass
fi

begin_test "Token-in-path archive URLs keep the /agentplugins/t/{token}/ prefix"
TOKEN_URL=$(jq -r '.plugins[0].source.url // empty' "$TOKEN_DOC" 2>/dev/null) || TOKEN_URL=""
if [ "$TOKEN_STATUS" != "200" ]; then
  fail "needs the token-in-path marketplace"
elif assert_contains "$TOKEN_URL" "$TOKEN_PREFIX" "plugins[0].source.url '${TOKEN_URL}' does not contain ${TOKEN_PREFIX}"; then
  pass
fi

begin_test "Token-in-path archive downloads with no Authorization header"
TOKEN_DL="${WORK_DIR}/token-dl.zip"
if [ -z "$TOKEN_URL" ]; then
  fail "no archive URL in the token-in-path marketplace"
else
  DL_STATUS=$(curl -s -o "$TOKEN_DL" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    "${BASE_URL}$(url_path "$TOKEN_URL")" 2>/dev/null) || DL_STATUS="000"
  if assert_eq "$DL_STATUS" "200" "token-in-path archive returned HTTP ${DL_STATUS}, expected 200" && \
     assert_eq "$(sha_of "$TOKEN_DL")" "$PRIV_SHA" "token-in-path archive bytes differ from the published zip"; then
    pass
  fi
fi

begin_test "Private claude-marketplace.json without credentials is refused"
if [ "$PRIV_PUBLISHED" = true ]; then
  ANON_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    "${BASE_URL}/agentplugins/${PRIVATE_KEY}/claude-marketplace.json" 2>/dev/null) || ANON_STATUS="000"
  # 401 when the visibility middleware asks for credentials, 404 when it
  # hides the repository's existence; both are documented outcomes (design
  # section 11). Anything else, 200 above all, is a leak.
  case "$ANON_STATUS" in
    401|404) pass ;;
    *) fail "anonymous GET of a private marketplace returned HTTP ${ANON_STATUS}, expected 401 or 404" ;;
  esac
else
  fail "needs the private publish"
fi

begin_test "Private archive without credentials is refused"
if [ "$PRIV_PUBLISHED" = true ]; then
  ANON_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    "${BASE_URL}/agentplugins/${PRIVATE_KEY}/${PRIV_PLUGIN}/${PRIV_VERSION}/${PRIV_PLUGIN}-${PRIV_VERSION}.zip" 2>/dev/null) || ANON_STATUS="000"
  case "$ANON_STATUS" in
    401|404) pass ;;
    *) fail "anonymous GET of a private archive returned HTTP ${ANON_STATUS}, expected 401 or 404" ;;
  esac
else
  fail "needs the private publish"
fi

# ---------------------------------------------------------------------------
# 6. Lifecycle: immutability after delete, native rows only, reserved key
# ---------------------------------------------------------------------------

LIFE="hello"
LIFE_VERSION="1.0.0"
LIFE_PATH="${LIFE}/${LIFE_VERSION}/${LIFE}-${LIFE_VERSION}.zip"
LIFE_ZIP=$(build_zip "life" "$LIFE" "$LIFE_VERSION")
# Same manifest, one extra file: a different archive for the same version.
LIFE_OTHER="${WORK_DIR}/life-other.zip"
cp "$LIFE_ZIP" "$LIFE_OTHER"
mkdir -p "${WORK_DIR}/src-life-extra"
echo "different bytes" > "${WORK_DIR}/src-life-extra/EXTRA.md"
(cd "${WORK_DIR}/src-life-extra" && zip -qX "$LIFE_OTHER" EXTRA.md)

# life_versions: the comma-separated versions hello/index.json lists, or
# "<HTTP status>" when the document is not served.
life_versions() {
  local out="${WORK_DIR}/life-index.json" status
  status=$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" \
    "${BASE_URL}/agentplugins/${REPO_KEY}/${LIFE}/index.json" 2>/dev/null) || status="000"
  if [ "$status" = "200" ]; then
    jq -r '[.versions[].version] | join(",")' "$out" 2>/dev/null
  else
    echo "<HTTP ${status}>"
  fi
}

begin_test "Publish ${LIFE} ${LIFE_VERSION} and delete it through the REST artifacts API"
ap_put "$REPO_KEY" "$LIFE_ZIP" "$LIFE_PATH"
LIFE_DELETED=false
if [ "$PUT_STATUS" != "201" ]; then
  fail "publish returned HTTP ${PUT_STATUS}, expected 201" "${PUT_BODY:0:300}"
else
  DEL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${LIFE_PATH}" 2>/dev/null) || DEL_STATUS="000"
  if [ "$DEL_STATUS" -ge 200 ] 2>/dev/null && [ "$DEL_STATUS" -lt 300 ] 2>/dev/null; then
    LIFE_DELETED=true
    pass
  else
    fail "REST delete returned HTTP ${DEL_STATUS}"
  fi
fi

begin_test "Empty-body PUT to a deleted version is refused with 400"
EMPTY_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X PUT -H "$(format_auth_header)" -H "Content-Type: application/zip" --data-binary "" \
  "${BASE_URL}/agentplugins/${REPO_KEY}/${LIFE_PATH}" 2>/dev/null) || EMPTY_STATUS="000"
if [ "$LIFE_DELETED" != true ]; then
  fail "needs the deleted version"
elif assert_eq "$EMPTY_STATUS" "400" "empty-body PUT returned HTTP ${EMPTY_STATUS}, expected 400"; then
  pass
fi

begin_test "Re-publishing a deleted version with different bytes is refused with 409"
ap_put "$REPO_KEY" "$LIFE_OTHER" "$LIFE_PATH"
if [ "$LIFE_DELETED" != true ]; then
  fail "needs the deleted version"
elif assert_eq "$PUT_STATUS" "409" "re-publish with different bytes returned HTTP ${PUT_STATUS}, expected 409 (a version is immutable even after delete)"; then
  pass
fi

begin_test "Re-publishing a deleted version with identical bytes restores it (201) and re-indexes it"
ap_put "$REPO_KEY" "$LIFE_ZIP" "$LIFE_PATH"
if [ "$LIFE_DELETED" != true ]; then
  fail "needs the deleted version"
elif assert_eq "$PUT_STATUS" "201" "re-publish with identical bytes returned HTTP ${PUT_STATUS}, expected 201: ${PUT_BODY:0:300}" && \
     assert_eq "$(life_versions)" "$LIFE_VERSION" "${LIFE}/index.json lists [$(life_versions)] after the restore, expected [${LIFE_VERSION}]"; then
  pass
fi

BUILD_ZIP=$(build_zip "neg-build" "$LIFE" "")
expect_400 "SemVer build metadata (1.0.0+hotfix)" "$BUILD_ZIP" "${LIFE}/1.0.0+hotfix/${LIFE}-1.0.0+hotfix.zip"

begin_test "A generic REST upload into the repository is stored but not indexed or served"
GEN_PATH="${LIFE}/9.0.0/${LIFE}-9.0.0.zip"
GEN_ZIP=$(build_zip "generic-9" "$LIFE" "9.0.0")
# Push replication delivers through this route, so it stays open; only rows a
# native publish wrote may reach an index or the download route.
GEN_STATUS=$(curl -s -o "${WORK_DIR}/gen.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/zip" --data-binary "@${GEN_ZIP}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${GEN_PATH}" 2>/dev/null) || GEN_STATUS="000"
GEN_DL=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" \
  "${BASE_URL}/agentplugins/${REPO_KEY}/${GEN_PATH}" 2>/dev/null) || GEN_DL="000"
GEN_VERSIONS=$(life_versions)
if assert_eq "$GEN_STATUS" "201" "generic REST PUT returned HTTP ${GEN_STATUS}, expected 201: $(head -c 300 "${WORK_DIR}/gen.json" 2>/dev/null)" && \
   assert_eq "$GEN_VERSIONS" "$LIFE_VERSION" "${LIFE}/index.json lists [${GEN_VERSIONS}], expected only [${LIFE_VERSION}] (9.0.0 came from a generic upload)" && \
   assert_eq "$GEN_DL" "404" "native GET of the generic upload returned HTTP ${GEN_DL}, expected 404"; then
  pass
fi

begin_test "Renaming an agentplugins repository to 't' is refused with 400 and the key is kept"
RENAME_STATUS=$(curl -s -o "${WORK_DIR}/rename.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X PATCH -H "$(auth_header)" -H "Content-Type: application/json" -d '{"key":"t"}' \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || RENAME_STATUS="000"
KEPT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || KEPT_STATUS="000"
if [ "$RENAME_STATUS" -ge 200 ] 2>/dev/null && [ "$RENAME_STATUS" -lt 300 ] 2>/dev/null; then
  # Put it back so the rest of the suite and the exit cleanup still work.
  curl -s -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" -X PATCH -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"key\":\"${REPO_KEY}\"}" "${BASE_URL}/api/v1/repositories/t" 2>/dev/null || true
fi
if assert_eq "$RENAME_STATUS" "400" "PATCH key=t returned HTTP ${RENAME_STATUS}, expected 400: $(head -c 300 "${WORK_DIR}/rename.json" 2>/dev/null)" && \
   assert_eq "$KEPT_STATUS" "200" "GET of the original key returned HTTP ${KEPT_STATUS} after the refused rename"; then
  pass
fi

# ---------------------------------------------------------------------------
# 5. ETag and conditional GET
# ---------------------------------------------------------------------------

begin_test "claude-marketplace.json carries an ETag and If-None-Match yields 304"
curl -s -D "$CLAUDE_HDR" -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" \
  "${BASE_URL}/agentplugins/${REPO_KEY}/claude-marketplace.json" 2>/dev/null || true
ETAG=$(header_value "$CLAUDE_HDR" "etag")
if [ -z "$ETAG" ]; then
  fail "no ETag header on claude-marketplace.json" "$(cat "$CLAUDE_HDR" 2>/dev/null)"
else
  COND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -H "$(format_auth_header)" -H "If-None-Match: ${ETAG}" \
    "${BASE_URL}/agentplugins/${REPO_KEY}/claude-marketplace.json" 2>/dev/null) || COND_STATUS="000"
  if assert_eq "$COND_STATUS" "304" "If-None-Match: ${ETAG} returned HTTP ${COND_STATUS}, expected 304"; then
    pass
  fi
fi

begin_test "Index documents are Cache-Control: no-cache"
INDEX_CC=$(header_value "$CLAUDE_HDR" "cache-control")
if assert_contains "$INDEX_CC" "no-cache" "claude-marketplace.json Cache-Control '${INDEX_CC}' lacks no-cache"; then
  pass
fi

end_suite
