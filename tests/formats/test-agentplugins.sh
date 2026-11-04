#!/usr/bin/env bash
# test-agentplugins.sh - Agent Plugins repository E2E test
#
# Hosted repositories of AI coding-agent plugin bundles (Claude Code, Cursor,
# Codex, Copilot / VS Code, Agent Plugins Standard), artifact-keeper#5251.
# One zip per plugin version is published to
#
#   PUT /agentplugins/{repo}/{name}/{version}/{name}-{version}.zip
#
# and the backend generates the marketplace documents on request:
#
#   GET /agentplugins/{repo}/marketplace.json           every plugin
#   GET /agentplugins/{repo}/claude-marketplace.json    claude or standard
#   GET /agentplugins/{repo}/cursor-marketplace.json    cursor or standard
#   GET /agentplugins/{repo}/codex-marketplace.json     codex or standard
#   GET /agentplugins/{repo}/vscode-marketplace.json    standard
#   GET /agentplugins/{repo}/{name}/index.json          every version of one plugin
#
# Each marketplace entry carries only the latest SemVer version, as a Claude
# Code `archive` source ({"source":"archive","url":...,"sha256":...}).
#
# Three fixtures, built with `zip`, cover the three bundle shapes:
#   hello-claude   Claude layout at the zip root (.claude-plugin/plugin.json,
#                  skills/hello/SKILL.md, commands/hi.md)
#   std-tools      Agent Plugins Standard layout at the zip root (plugin.json
#                  with the agent-plugins.org $schema, skills/, mcp.json)
#   multi-bundle   .claude-plugin/, .cursor-plugin/ and .codex-plugin/
#                  manifests wrapped in one top-level directory
#
# Then: 409 on re-publish, byte and checksum equality on download, every index
# document asserted with jq, a second version and latest selection,
# {name}/index.json, removal through the REST artifact delete and the index
# falling back to the older version, and a plugin whose newest version is
# Cursor only staying in claude-marketplace.json at its newest Claude
# version. The `ak agent plugins` steps run only when an `ak` with that
# command group is on PATH (or AK_BIN names one).
#
# Capability gate: a backend without the format answers repository creation
# with `400 Invalid format: agentplugins`. That is the candidate saying the
# format is not in this release, so the suite stands down through skip_suite
# and the agentplugins_format row of _CAPABILITY_EXEMPTIONS. A version floor
# cannot express this: main reports crate version 1.11.3 while the
# release/1.11.x maintenance line reports 1.11.11, so no floor separates them.
#
# Requires: curl, jq, zip, sha256sum

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "agentplugins"
auth_admin
setup_workdir
require_cmd jq
require_cmd zip
require_cmd sha256sum

REPO_KEY="test-agentplugins-${RUN_ID}"
AP_URL="${BASE_URL}/agentplugins/${REPO_KEY}"
STANDARD_SCHEMA="https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
GATE_REASON="repository format 'agentplugins' is not known to this backend (POST /api/v1/repositories: 400 Invalid format: agentplugins); Agent Plugins format not shipped"

CLAUDE_SLUG="hello-claude"
CLAUDE_V1="1.0.0"
CLAUDE_V2="1.1.0"
STD_SLUG="std-tools"
STD_VERSION="0.3.0"
MULTI_SLUG="multi-bundle"
MULTI_VERSION="2.0.0"

# Expected latest version and sha256 per plugin, kept current as the suite
# publishes and deletes.
declare -A LATEST_VERSION=()
declare -A LATEST_SHA=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# url_path URL: the path of an absolute URL. Index documents carry absolute
# URLs built from the request's base URL (or AK_EXTERNAL_URL, which this suite
# does not assume), so downloads go to BASE_URL plus the path.
url_path() {
  printf '%s' "$1" | sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://[^/]+##'
}

sha_of() {
  sha256sum "$1" | cut -d' ' -f1
}

# ap_put ZIP PATH: PUT a zip to /agentplugins/{repo}/PATH with Basic auth.
# Sets PUT_STATUS and PUT_BODY.
ap_put() {
  local zip="$1" path="$2" out="${WORK_DIR}/put-resp.json"
  PUT_STATUS=$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/zip" \
    --data-binary "@${zip}" \
    "${AP_URL}/${path}" 2>/dev/null) || PUT_STATUS="000"
  PUT_BODY=$(cat "$out" 2>/dev/null || true)
}

# ap_get PATH OUT: GET /agentplugins/{repo}/PATH into OUT. Echoes the status.
ap_get() {
  local path="$1" out="$2"
  curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -H "$(format_auth_header)" \
    "${AP_URL}/${path}" 2>/dev/null || echo "000"
}

# zip_dir DIR OUT: zip the contents of DIR (dotfiles included) into OUT.
zip_dir() {
  local dir="$1" out="$2"
  rm -f "$out"
  (cd "$dir" && zip -qrX "$out" .)
}

write_skill() {
  local dir="$1" name="$2"
  mkdir -p "${dir}/skills/${name}"
  cat > "${dir}/skills/${name}/SKILL.md" <<EOF
---
name: ${name}
description: Release-gate fixture skill ${name}.
---

Say hello from the Artifact Keeper release gate.
EOF
}

build_claude_plugin() {
  local version="$1" out="$2"
  local dir="${WORK_DIR}/src-${CLAUDE_SLUG}-${version}"
  rm -rf "$dir"
  mkdir -p "${dir}/.claude-plugin" "${dir}/commands"
  cat > "${dir}/.claude-plugin/plugin.json" <<EOF
{
  "name": "${CLAUDE_SLUG}",
  "version": "${version}",
  "description": "Claude layout fixture for the Artifact Keeper release gate",
  "author": { "name": "Artifact Keeper Release Gate" },
  "license": "MIT",
  "keywords": ["release-gate", "fixture"]
}
EOF
  write_skill "$dir" "hello"
  cat > "${dir}/commands/hi.md" <<'EOF'
---
description: Greet the user.
---

Reply with a short greeting.
EOF
  zip_dir "$dir" "$out"
}

build_standard_plugin() {
  local out="$1"
  local dir="${WORK_DIR}/src-${STD_SLUG}"
  rm -rf "$dir"
  mkdir -p "$dir"
  cat > "${dir}/plugin.json" <<EOF
{
  "\$schema": "${STANDARD_SCHEMA}",
  "name": "${STD_SLUG}",
  "version": "${STD_VERSION}",
  "description": "Agent Plugins Standard fixture for the Artifact Keeper release gate"
}
EOF
  write_skill "$dir" "greet"
  cat > "${dir}/mcp.json" <<'EOF'
{
  "mcpServers": {
    "echo": { "command": "echo", "args": ["release-gate"] }
  }
}
EOF
  zip_dir "$dir" "$out"
}

build_multi_plugin() {
  local out="$1"
  local parent="${WORK_DIR}/src-${MULTI_SLUG}"
  local dir="${parent}/${MULTI_SLUG}"
  local harness
  rm -rf "$parent"
  for harness in claude cursor codex; do
    mkdir -p "${dir}/.${harness}-plugin"
    cat > "${dir}/.${harness}-plugin/plugin.json" <<EOF
{
  "name": "${MULTI_SLUG}",
  "version": "${MULTI_VERSION}",
  "description": "Multi-harness fixture for the Artifact Keeper release gate (${harness})"
}
EOF
  done
  write_skill "$dir" "multi"
  rm -f "$out"
  (cd "$parent" && zip -qrX "$out" "$MULTI_SLUG")
}

# publish_and_check NAME VERSION ZIP EXPECTED_HARNESSES
# EXPECTED_HARNESSES is a sorted, comma-separated list.
publish_and_check() {
  local name="$1" version="$2" zip="$3" harnesses="$4"
  local path="${name}/${version}/${name}-${version}.zip"
  local sha
  sha=$(sha_of "$zip")
  begin_test "Publish ${name} ${version} returns 201 with the publish response"
  ap_put "$zip" "$path"
  if [ "$PUT_STATUS" != "201" ]; then
    fail "PUT ${path} returned HTTP ${PUT_STATUS}, expected 201" "${PUT_BODY:0:600}"
    return 1
  fi
  local problems
  problems=$(printf '%s' "$PUT_BODY" | jq -r \
    --arg name "$name" --arg version "$version" --arg sha "$sha" \
    --arg harnesses "$harnesses" --arg dl "/agentplugins/${REPO_KEY}/${path}" \
    --arg claude "/agentplugins/${REPO_KEY}/claude-marketplace.json" '
      [ (if .name != $name then "name=\(.name)" else empty end),
        (if .version != $version then "version=\(.version)" else empty end),
        (if .sha256 != $sha then "sha256=\(.sha256)" else empty end),
        (if ((.harnesses // []) | sort | join(",")) != $harnesses
           then "harnesses=\(.harnesses)" else empty end),
        (if ((.download_url // "") | endswith($dl)) | not
           then "download_url=\(.download_url)" else empty end),
        (if ((.marketplaces.claude // "") | endswith($claude)) | not
           then "marketplaces.claude=\(.marketplaces.claude)" else empty end)
      ] | join("; ")' 2>&1) || problems="response is not JSON"
  if [ -n "$problems" ]; then
    fail "publish response mismatch: ${problems}" "${PUT_BODY:0:600}"
    return 1
  fi
  LATEST_VERSION[$name]="$version"
  LATEST_SHA[$name]="$sha"
  pass
}

# check_index DOC EXPECTED_NAMES
# Fetch DOC, assert the sorted entry names equal EXPECTED_NAMES and that every
# entry is an archive source whose sha256 and version are the latest published
# ones and whose archive downloads to bytes with that sha256.
check_index() {
  local doc="$1" expected="$2"
  local out="${WORK_DIR}/idx-${doc}"
  begin_test "${doc} lists ${expected:-no plugins} with archive sources"
  local status
  status=$(ap_get "$doc" "$out")
  if [ "$status" != "200" ]; then
    fail "GET ${doc} returned HTTP ${status}" "$(head -c 600 "$out" 2>/dev/null)"
    return 1
  fi
  local names
  if ! names=$(jq -r '[.plugins[].name] | sort | join(",")' "$out" 2>/dev/null); then
    fail "${doc} is not a marketplace document" "$(head -c 600 "$out")"
    return 1
  fi
  if [ "$names" != "$expected" ]; then
    fail "${doc} lists [${names}], expected [${expected}]" "$(head -c 1200 "$out")"
    return 1
  fi
  local n count name source_kind sha version url dl problems=""
  count=$(jq '.plugins | length' "$out")
  for (( n = 0; n < count; n++ )); do
    name=$(jq -r ".plugins[$n].name" "$out")
    source_kind=$(jq -r ".plugins[$n].source.source // empty" "$out")
    sha=$(jq -r ".plugins[$n].source.sha256 // empty" "$out")
    version=$(jq -r ".plugins[$n].version // empty" "$out")
    url=$(jq -r ".plugins[$n].source.url // empty" "$out")
    if [ "$source_kind" != "archive" ]; then
      problems="${problems}${name}: source.source=${source_kind:-<none>}; "
      continue
    fi
    if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
      problems="${problems}${name}: source.sha256 '${sha}' is not 64 hex; "
      continue
    fi
    if [ "$version" != "${LATEST_VERSION[$name]:-}" ]; then
      problems="${problems}${name}: version ${version}, expected ${LATEST_VERSION[$name]:-?}; "
    fi
    if [ "$sha" != "${LATEST_SHA[$name]:-}" ]; then
      problems="${problems}${name}: sha256 differs from the published zip; "
    fi
    if [ "$(url_path "$url")" != "/agentplugins/${REPO_KEY}/${name}/${version}/${name}-${version}.zip" ]; then
      problems="${problems}${name}: source.url ${url} is not the archive path; "
      continue
    fi
    dl="${WORK_DIR}/idx-dl-${name}.zip"
    if curl -sf -o "$dl" "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" "${BASE_URL}$(url_path "$url")"; then
      if [ "$(sha_of "$dl")" != "$sha" ]; then
        problems="${problems}${name}: downloaded archive does not hash to source.sha256; "
      fi
    else
      problems="${problems}${name}: source.url did not download; "
    fi
  done
  if [ -n "$problems" ]; then
    fail "${doc}: ${problems}" "$(head -c 1200 "$out")"
    return 1
  fi
  pass
}

# ---------------------------------------------------------------------------
# Create repository (capability gate)
# ---------------------------------------------------------------------------

begin_test "Create agentplugins local repository"
CREATE_BODY="${WORK_DIR}/create-resp.json"
CREATE_STATUS="000"
for _ in 1 2 3 4; do
  CREATE_STATUS=$(curl -s -o "$CREATE_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"agentplugins\",\"repo_type\":\"local\",\"is_public\":true}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || CREATE_STATUS="000"
  case "$CREATE_STATUS" in
    000|401|429|503) sleep 2 ;;
    *) break ;;
  esac
done
if [ "$CREATE_STATUS" = "400" ] && grep -q 'Invalid format: agentplugins' "$CREATE_BODY" 2>/dev/null; then
  skip_suite "$GATE_REASON"
fi
if [ "$CREATE_STATUS" -ge 200 ] 2>/dev/null && [ "$CREATE_STATUS" -lt 300 ] 2>/dev/null; then
  add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"${BASE_URL}/api/v1/repositories/${REPO_KEY}\" || true"
  pass
else
  fail_fatal "could not create agentplugins repository: HTTP ${CREATE_STATUS}" "$(head -c 400 "$CREATE_BODY" 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# Build fixtures
# ---------------------------------------------------------------------------

CLAUDE_ZIP_V1="${WORK_DIR}/${CLAUDE_SLUG}-${CLAUDE_V1}.zip"
CLAUDE_ZIP_V2="${WORK_DIR}/${CLAUDE_SLUG}-${CLAUDE_V2}.zip"
STD_ZIP="${WORK_DIR}/${STD_SLUG}-${STD_VERSION}.zip"
MULTI_ZIP="${WORK_DIR}/${MULTI_SLUG}-${MULTI_VERSION}.zip"

begin_test "Build plugin fixtures"
if build_claude_plugin "$CLAUDE_V1" "$CLAUDE_ZIP_V1" && \
   build_claude_plugin "$CLAUDE_V2" "$CLAUDE_ZIP_V2" && \
   build_standard_plugin "$STD_ZIP" && \
   build_multi_plugin "$MULTI_ZIP"; then
  pass
else
  fail_fatal "could not build the plugin zips"
fi

# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------

publish_and_check "$CLAUDE_SLUG" "$CLAUDE_V1" "$CLAUDE_ZIP_V1" "claude" || true
publish_and_check "$STD_SLUG" "$STD_VERSION" "$STD_ZIP" "standard" || true
publish_and_check "$MULTI_SLUG" "$MULTI_VERSION" "$MULTI_ZIP" "claude,codex,cursor" || true

begin_test "Re-publishing an existing version returns 409"
ap_put "$CLAUDE_ZIP_V1" "${CLAUDE_SLUG}/${CLAUDE_V1}/${CLAUDE_SLUG}-${CLAUDE_V1}.zip"
if assert_eq "$PUT_STATUS" "409" "re-PUT of ${CLAUDE_SLUG} ${CLAUDE_V1} returned HTTP ${PUT_STATUS}, expected 409 (versions are immutable)"; then
  pass
fi

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

for _fixture in "${CLAUDE_SLUG}|${CLAUDE_V1}|${CLAUDE_ZIP_V1}" \
                "${STD_SLUG}|${STD_VERSION}|${STD_ZIP}" \
                "${MULTI_SLUG}|${MULTI_VERSION}|${MULTI_ZIP}"; do
  IFS='|' read -r _name _version _zip <<< "$_fixture"
  begin_test "Download ${_name} ${_version}: same bytes, X-Checksum-Sha256 matches"
  _dl="${WORK_DIR}/dl-${_name}-${_version}.zip"
  _hdr="${WORK_DIR}/dl-${_name}-${_version}.headers"
  _status=$(curl -s -D "$_hdr" -o "$_dl" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -H "$(format_auth_header)" \
    "${AP_URL}/${_name}/${_version}/${_name}-${_version}.zip" 2>/dev/null) || _status="000"
  _hdr_sha=$(grep -i '^x-checksum-sha256:' "$_hdr" 2>/dev/null | head -1 | cut -d: -f2- | tr -d ' \r') || _hdr_sha=""
  if [ "$_status" != "200" ]; then
    fail "download returned HTTP ${_status}"
  elif ! cmp -s "$_zip" "$_dl"; then
    fail "downloaded bytes differ from the published zip"
  elif [ "$_hdr_sha" != "$(sha_of "$_dl")" ]; then
    fail "X-Checksum-Sha256 '${_hdr_sha}' does not equal sha256sum of the body ($(sha_of "$_dl"))"
  else
    pass
  fi
done

# ---------------------------------------------------------------------------
# Index documents (membership per design section 5)
# ---------------------------------------------------------------------------

check_index "marketplace.json"        "${CLAUDE_SLUG},${MULTI_SLUG},${STD_SLUG}" || true
check_index "claude-marketplace.json" "${CLAUDE_SLUG},${MULTI_SLUG},${STD_SLUG}" || true
check_index "cursor-marketplace.json" "${MULTI_SLUG},${STD_SLUG}" || true
check_index "codex-marketplace.json"  "${MULTI_SLUG},${STD_SLUG}" || true
check_index "vscode-marketplace.json" "${STD_SLUG}" || true

begin_test "marketplace.json records harnesses per plugin"
_status=$(ap_get "marketplace.json" "${WORK_DIR}/all.json")
_got=$(jq -r '[.plugins[] | "\(.name)=\((.metadata.harnesses // []) | sort | join("+"))"] | sort | join(",")' "${WORK_DIR}/all.json" 2>/dev/null) || _got=""
_want="${CLAUDE_SLUG}=claude,${MULTI_SLUG}=claude+codex+cursor,${STD_SLUG}=standard"
if [ "$_status" != "200" ]; then
  fail "GET marketplace.json returned HTTP ${_status}"
elif assert_eq "$_got" "$_want" "metadata.harnesses: got [${_got}], expected [${_want}]"; then
  pass
fi

# ---------------------------------------------------------------------------
# Second version and latest selection
# ---------------------------------------------------------------------------

publish_and_check "$CLAUDE_SLUG" "$CLAUDE_V2" "$CLAUDE_ZIP_V2" "claude" || true

# LATEST_* now say CLAUDE_V2, so check_index also proves the entry moved.
check_index "claude-marketplace.json" "${CLAUDE_SLUG},${MULTI_SLUG},${STD_SLUG}" || true

# check_versions LATEST VERSIONS: {name}/index.json names LATEST and lists
# exactly VERSIONS (comma-separated, newest first).
check_versions() {
  local latest="$1" versions="$2"
  local out="${WORK_DIR}/versions.json" status got_latest got_versions
  status=$(ap_get "${CLAUDE_SLUG}/index.json" "$out")
  got_latest=$(jq -r '.latest // empty' "$out" 2>/dev/null) || got_latest=""
  got_versions=$(jq -r '[.versions[].version] | join(",")' "$out" 2>/dev/null) || got_versions=""
  if [ "$status" != "200" ]; then
    fail "GET ${CLAUDE_SLUG}/index.json returned HTTP ${status}" "$(head -c 400 "$out" 2>/dev/null)"
  elif [ "$got_latest" != "$latest" ] || [ "$got_versions" != "$versions" ]; then
    fail "index.json latest=${got_latest} versions=[${got_versions}], expected latest=${latest} versions=[${versions}]" "$(head -c 800 "$out")"
  else
    pass
  fi
}

begin_test "${CLAUDE_SLUG}/index.json lists both versions, newest first, with latest"
check_versions "$CLAUDE_V2" "${CLAUDE_V2},${CLAUDE_V1}"

# ---------------------------------------------------------------------------
# REST delete and re-index
# ---------------------------------------------------------------------------

begin_test "Delete ${CLAUDE_SLUG} ${CLAUDE_V2} through the REST artifacts API"
_del_path="${CLAUDE_SLUG}/${CLAUDE_V2}/${CLAUDE_SLUG}-${CLAUDE_V2}.zip"
_del_status=$(curl -s -o "${WORK_DIR}/del.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${_del_path}" 2>/dev/null) || _del_status="000"
if [ "$_del_status" -ge 200 ] 2>/dev/null && [ "$_del_status" -lt 300 ] 2>/dev/null; then
  LATEST_VERSION[$CLAUDE_SLUG]="$CLAUDE_V1"
  LATEST_SHA[$CLAUDE_SLUG]="$(sha_of "$CLAUDE_ZIP_V1")"
  pass
else
  fail "DELETE /api/v1/repositories/${REPO_KEY}/artifacts/${_del_path} returned HTTP ${_del_status}" "$(head -c 400 "${WORK_DIR}/del.json" 2>/dev/null)"
fi

check_index "claude-marketplace.json" "${CLAUDE_SLUG},${MULTI_SLUG},${STD_SLUG}" || true

begin_test "${CLAUDE_SLUG}/index.json falls back to ${CLAUDE_V1} after the delete"
check_versions "$CLAUDE_V1" "$CLAUDE_V1"

begin_test "Deleted version no longer downloads"
_status=$(ap_get "$_del_path" "${WORK_DIR}/deleted.zip")
if assert_eq "$_status" "404" "GET of the deleted version returned HTTP ${_status}, expected 404"; then
  pass
fi

# ---------------------------------------------------------------------------
# Per-document latest: a newest version that drops a harness
# ---------------------------------------------------------------------------
#
# mixed 1.0.0 is Claude layout, mixed 2.0.0 is Cursor only. Each document
# picks its latest among the versions it may list, so Claude Code keeps
# seeing 1.0.0 while Cursor and the unified index move to 2.0.0.

MIXED_SLUG="mixed"
MIXED_V1_ZIP="${WORK_DIR}/${MIXED_SLUG}-1.0.0.zip"
MIXED_V2_ZIP="${WORK_DIR}/${MIXED_SLUG}-2.0.0.zip"

begin_test "Build the mixed fixtures (1.0.0 Claude layout, 2.0.0 Cursor only)"
_mdir="${WORK_DIR}/src-${MIXED_SLUG}-1.0.0"
mkdir -p "${_mdir}/.claude-plugin"
printf '{"name":"%s","version":"1.0.0","description":"Claude layout"}\n' "$MIXED_SLUG" > "${_mdir}/.claude-plugin/plugin.json"
write_skill "$_mdir" "mixed"
zip_dir "$_mdir" "$MIXED_V1_ZIP"
_mdir="${WORK_DIR}/src-${MIXED_SLUG}-2.0.0"
mkdir -p "${_mdir}/.cursor-plugin"
printf '{"name":"%s","version":"2.0.0","description":"Cursor only"}\n' "$MIXED_SLUG" > "${_mdir}/.cursor-plugin/plugin.json"
write_skill "$_mdir" "mixed"
zip_dir "$_mdir" "$MIXED_V2_ZIP"
if [ -s "$MIXED_V1_ZIP" ] && [ -s "$MIXED_V2_ZIP" ]; then
  pass
else
  fail "could not build the mixed zips"
fi

publish_and_check "$MIXED_SLUG" "1.0.0" "$MIXED_V1_ZIP" "claude" || true
publish_and_check "$MIXED_SLUG" "2.0.0" "$MIXED_V2_ZIP" "cursor" || true

# mixed_entry DOC: "<version> <sha256>" of the mixed entry in DOC, or
# "<HTTP status>" / "absent".
mixed_entry() {
  local doc="$1" out="${WORK_DIR}/mixed-${1}" status
  status=$(ap_get "$doc" "$out")
  if [ "$status" != "200" ]; then
    echo "<HTTP ${status}>"
    return
  fi
  jq -r --arg n "$MIXED_SLUG" \
    '[.plugins[] | select(.name == $n) | "\(.version) \(.source.sha256)"] | if length == 0 then "absent" else join(" | ") end' \
    "$out" 2>/dev/null || echo "unparseable"
}

for _expect in "claude-marketplace.json|1.0.0|${MIXED_V1_ZIP}" \
               "cursor-marketplace.json|2.0.0|${MIXED_V2_ZIP}" \
               "marketplace.json|2.0.0|${MIXED_V2_ZIP}"; do
  IFS='|' read -r _doc _ver _zip <<< "$_expect"
  begin_test "${_doc} lists ${MIXED_SLUG} at ${_ver}, its newest version that document may list"
  _got=$(mixed_entry "$_doc")
  if assert_eq "$_got" "${_ver} $(sha_of "$_zip")" "${_doc} ${MIXED_SLUG} entry is '${_got}', expected '${_ver} <sha256 of ${MIXED_SLUG}-${_ver}.zip>'"; then
    pass
  fi
done

# ---------------------------------------------------------------------------
# Optional: the ak CLI (ak agent plugins publish --dry-run / install --path)
# ---------------------------------------------------------------------------
#
# The gate installs the released ak in the cli-smoke job only, and released
# CLIs predate `ak agent plugins`, so these steps skip until a CLI release
# carries the command group. AK_BIN points at a specific binary.

AK="${AK_BIN:-$(command -v ak 2>/dev/null || true)}"
AK_REASON=""
if [ -z "$AK" ]; then
  AK_REASON="ak CLI not on PATH (set AK_BIN to run the ak agent plugins steps)"
elif ! "$AK" agent plugins --help >/dev/null 2>&1; then
  AK_REASON="installed ak ($("$AK" --version 2>/dev/null | head -1)) has no 'agent plugins' command group"
fi

begin_test "ak agent plugins publish --dry-run"
if [ -n "$AK_REASON" ]; then
  skip "$AK_REASON"
else
  # Isolate ak's config the way tests/release-gate/test-cli-smoke.sh does.
  export HOME="${WORK_DIR}/home"
  export AK_CONFIG_DIR="${HOME}/ak"
  export XDG_CONFIG_HOME="${HOME}/.config"
  export AK_CREDENTIAL_STORE=file
  export AK_NO_INPUT=true
  export NO_COLOR=1
  export AK_ALLOW_INSECURE_HTTP=1
  export AK_TOKEN="$ADMIN_TOKEN"
  mkdir -p "$AK_CONFIG_DIR"
  AK_OUT="${WORK_DIR}/ak-out.txt"
  if ! "$AK" instance add gate "$BASE_URL" > "$AK_OUT" 2>&1; then
    fail "ak instance add failed: $(tail -5 "$AK_OUT")"
  elif "$AK" agent plugins publish "${WORK_DIR}/src-${CLAUDE_SLUG}-${CLAUDE_V2}" \
       --repo "$REPO_KEY" --dry-run > "$AK_OUT" 2>&1; then
    if grep -q '.claude-plugin/plugin.json' "$AK_OUT"; then
      pass
    else
      fail "dry-run output does not list .claude-plugin/plugin.json" "$(head -c 800 "$AK_OUT")"
    fi
  else
    fail "ak agent plugins publish --dry-run failed" "$(tail -20 "$AK_OUT")"
  fi
fi

begin_test "ak agent plugins install --path writes .ak/plugin-info.json"
if [ -n "$AK_REASON" ]; then
  skip "$AK_REASON"
else
  INSTALL_DIR="${WORK_DIR}/install"
  if "$AK" agent plugins install "$CLAUDE_SLUG" --repo "$REPO_KEY" --harness claude \
       --path "$INSTALL_DIR" --version "$CLAUDE_V1" > "$AK_OUT" 2>&1; then
    INFO="${INSTALL_DIR}/${CLAUDE_SLUG}/.ak/plugin-info.json"
    if [ ! -f "$INFO" ]; then
      fail "${INFO} not written" "$(tail -20 "$AK_OUT")"
    elif assert_eq "$(jq -r '.version // empty' "$INFO")" "$CLAUDE_V1" \
         "plugin-info.json version is $(jq -c '.version' "$INFO"), expected ${CLAUDE_V1}" && \
         assert_eq "$(jq -r '.sha256 // empty' "$INFO")" "$(sha_of "$CLAUDE_ZIP_V1")" \
         "plugin-info.json sha256 does not match the published zip" && \
         assert_eq "$([ -f "${INSTALL_DIR}/${CLAUDE_SLUG}/.claude-plugin/plugin.json" ] && echo yes)" "yes" \
         "installed plugin has no .claude-plugin/plugin.json"; then
      pass
    fi
  else
    fail "ak agent plugins install failed" "$(tail -20 "$AK_OUT")"
  fi
fi

end_suite
