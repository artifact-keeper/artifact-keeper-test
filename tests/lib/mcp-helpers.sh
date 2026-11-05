#!/usr/bin/env bash
# mcp-helpers.sh - shared helpers for the MCP Registry suites
# (artifact-keeper#5253).
#
# Source AFTER tests/lib/common.sh:
#
#   source "$(dirname "$0")/../lib/common.sh"
#   source "$(dirname "$0")/../lib/mcp-helpers.sh"
#
# What lives here:
#   - the registry API prefix (MCP_API_VERSION, the prefix-drift canary) and
#     URL helpers (mcp_base, mcp_encode_name)
#   - capability gates: mcp_require_registry (feature flag + floor),
#     mcp_create_repo (format probe -> skip_suite + the mcp_registry_format
#     exemption), mcp_create_proxy_repo (Remote/Virtual probe ->
#     skip_suite + the mcp_registry_proxy exemption), mcp_probe_route
#   - request helpers that capture status, body and headers (mcp_req,
#     mcp_publish, mcp_get, mcp_patch_status) and problem+json assertions
#   - the Remote management API (/api/v1/repositories/{key}/mcp/...):
#     mcp_mgmt_url, mcp_remote_sync, mcp_remote_mounted, mcp_catalog_load,
#     mcp_catalog_item, mcp_catalog_decide
#   - backing packages: mcp_create_backing_repos, mcp_publish_echo_package
#     (zero-dependency npm package from tests/fixtures/mcp/echo-server),
#     mcp_artifact_id, mcp_quarantine / mcp_release
#   - the real publisher: install_mcp_publisher (pinned version + sha256),
#     mcp_write_publisher_token, mcp_publisher
#   - fixtures: start_mock_mcp_upstream (tests/lib/mock-mcp-upstream.py),
#     start_mock_mcp_http (tests/lib/mock-mcp-http-server.py), mcp_client
#     (tests/lib/mcp-stdio-client.py)
#
# Every refusal on the /mcp/ surface is application/problem+json with
# Cache-Control: no-store, and a held version answers a reader exactly what an
# unknown name answers (404, MCP_NOT_FOUND_BODY). The helpers assert that
# shape rather than any 451/403: see docs/mcp-registry.md "What a client
# sees" in artifact-keeper.

# shellcheck disable=SC2034 # several globals are consumed by sourcing scripts

_MCP_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_FIXTURES_DIR="$(cd "${_MCP_LIB_DIR}/../fixtures/mcp" && pwd)"

# The registry API prefix. One constant so an upstream prefix change (it was
# /v0 before /v0.1) is a one-line bump; the backend also serves /v0.
MCP_API_VERSION="${MCP_API_VERSION:-v0.1}"
MCP_SCHEMA_URL="https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"

# The byte-exact unknown-name answer (formats/mcp.rs NOT_FOUND_BODY).
MCP_NOT_FOUND_BODY='{"detail":"Server not found","status":404,"title":"Not Found","type":"about:blank"}'

# Headers that legitimately differ between two otherwise identical answers.
MCP_VOLATILE_HEADERS='^(date|x-correlation-id|x-request-id|content-length|connection|keep-alive):'

# mcp-publisher, pinned. Bump all three together; the checksums are the
# release's own registry_<ver>_checksums.txt entries for these tarballs.
MCP_PUBLISHER_VERSION="${MCP_PUBLISHER_VERSION:-1.8.7}"
MCP_PUBLISHER_SHA256_LINUX_AMD64="00b21004149a4ce66f0782508ae4a2bce67d1bea395a8da0bd8028159fb59579"
MCP_PUBLISHER_SHA256_LINUX_ARM64="653ecba7556f4ff7f9c88251400a9ddcb22f7534de497874296b41d0586febea"

# skip_suite reasons, each matched by a _CAPABILITY_EXEMPTIONS row in
# common.sh. A backend that ships the capability cannot produce the probe
# answer that leads here, so the rows cannot hide a broken handler.
MCP_FORMAT_GATE_REASON="repository format 'mcp' is not known to this backend (POST /api/v1/repositories: 400 Invalid format: mcp); MCP Registry format not shipped"
MCP_PROXY_GATE_REASON="MCP Remote/Virtual repositories are refused by this backend (POST /api/v1/repositories: 400 MCP registries support Local and Staging repositories in this release); MCP Registry proxy not shipped"

# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

# mcp_root REPO: the registry URL a client is configured with.
mcp_root() {
  printf '%s/mcp/%s' "$BASE_URL" "$1"
}

# mcp_base REPO: the API base, ${BASE_URL}/mcp/REPO/v0.1
mcp_base() {
  printf '%s/mcp/%s/%s' "$BASE_URL" "$1" "$MCP_API_VERSION"
}

# mcp_encode_name NAME: URL-encode a server name for a path segment
# (io.github.a/b -> io.github.a%2Fb).
mcp_encode_name() {
  jq -rn --arg v "$1" '$v|@uri'
}

# mcp_version_path NAME VERSION: servers/<enc>/versions/<version>
mcp_version_path() {
  printf 'servers/%s/versions/%s' "$(mcp_encode_name "$1")" "$(jq -rn --arg v "$2" '$v|@uri')"
}

# url_path URL: the path (and query) of URL, scheme and host dropped.
mcp_url_path() {
  printf '%s' "$1" | sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://[^/]+##'
}

# ---------------------------------------------------------------------------
# Requests. Every helper sets MCP_STATUS, MCP_BODY (file), MCP_HDRS (file).
# ---------------------------------------------------------------------------

_mcp_resp_seq=0
_mcp_new_resp() {
  _mcp_resp_seq=$(( _mcp_resp_seq + 1 ))
  MCP_BODY="${WORK_DIR:?setup_workdir first}/mcp-resp-${_mcp_resp_seq}.body"
  MCP_HDRS="${WORK_DIR}/mcp-resp-${_mcp_resp_seq}.hdrs"
  : > "$MCP_BODY"
  : > "$MCP_HDRS"
}

# mcp_req METHOD URL [AUTH] [curl args...]
#   AUTH: "admin" (default) uses $(auth_header); "anon" sends none; any other
#   value is used as a bearer token.
mcp_req() {
  local method="$1" url="$2" auth="${3:-admin}"
  shift 2
  [ $# -gt 0 ] && shift
  _mcp_new_resp
  local -a hdr=()
  case "$auth" in
    admin) hdr=(-H "$(auth_header)") ;;
    anon) hdr=() ;;
    *) hdr=(-H "Authorization: Bearer ${auth}") ;;
  esac
  MCP_STATUS=$(curl -s -o "$MCP_BODY" -D "$MCP_HDRS" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X "$method" "${hdr[@]}" "$@" "$url" 2>/dev/null) || MCP_STATUS="000"
}

# mcp_get REPO TAIL [AUTH]: GET $(mcp_base REPO)/TAIL
mcp_get() {
  mcp_req GET "$(mcp_base "$1")/$2" "${3:-admin}"
}

# mcp_publish REPO FILE [AUTH]: POST a server.json file to /publish.
mcp_publish() {
  mcp_req POST "$(mcp_base "$1")/publish" "${3:-admin}" \
    -H "Content-Type: application/json" --data-binary "@$2"
}

# mcp_patch_status REPO NAME VERSION STATUS [MESSAGE] [AUTH]
#   VERSION "" patches every version (PATCH servers/<enc>/status).
mcp_patch_status() {
  local repo="$1" name="$2" version="$3" status="$4" message="${5:-}" auth="${6:-admin}" url body
  if [ -n "$version" ]; then
    url="$(mcp_base "$repo")/$(mcp_version_path "$name" "$version")/status"
  else
    url="$(mcp_base "$repo")/servers/$(mcp_encode_name "$name")/status"
  fi
  if [ -n "$message" ]; then
    body=$(jq -cn --arg s "$status" --arg m "$message" '{status:$s,statusMessage:$m}')
  else
    body=$(jq -cn --arg s "$status" '{status:$s}')
  fi
  mcp_req PATCH "$url" "$auth" -H "Content-Type: application/json" -d "$body"
}

# mcp_header NAME [FILE]: the value of header NAME in FILE (default MCP_HDRS).
mcp_header() {
  grep -i "^${1}:" "${2:-$MCP_HDRS}" 2>/dev/null | tail -1 | cut -d: -f2- | sed -e 's/^ *//' -e 's/\r$//' || true
}

# mcp_json FILTER: jq -r FILTER over MCP_BODY ("" on non-JSON).
mcp_json() {
  jq -r "$1" "$MCP_BODY" 2>/dev/null || true
}

# mcp_snip: the first 400 bytes of MCP_BODY, for failure messages.
mcp_snip() {
  head -c 400 "$MCP_BODY" 2>/dev/null || true
}

# mcp_is_problem: 0 when the last answer is problem+json with no-store.
mcp_is_problem() {
  case "$(mcp_header content-type)" in
    application/problem+json*) ;;
    *) return 1 ;;
  esac
  [ "$(mcp_header cache-control)" = "no-store" ]
}

# mcp_check_problem STATUS ERROR_CODE: 0 when the last answer is STATUS,
# problem+json, Cache-Control: no-store and carries .error == ERROR_CODE
# (ERROR_CODE "" skips the code check). Prints the mismatch on failure.
mcp_check_problem() {
  local want="$1" code="$2"
  if [ "$MCP_STATUS" != "$want" ]; then
    echo "expected HTTP ${want}, got ${MCP_STATUS}: $(mcp_snip)"
    return 1
  fi
  if ! mcp_is_problem; then
    echo "HTTP ${want} is not problem+json with no-store (content-type='$(mcp_header content-type)' cache-control='$(mcp_header cache-control)')"
    return 1
  fi
  if [ -n "$code" ] && [ "$(mcp_json '.error // empty')" != "$code" ]; then
    echo "expected error '${code}', got '$(mcp_json '.error // empty')': $(mcp_snip)"
    return 1
  fi
  return 0
}

# mcp_check_plain_404: 0 when the last answer is byte for byte the
# unknown-name answer (body), problem+json, no-store.
mcp_check_plain_404() {
  local why
  why=$(mcp_check_problem 404 "") || { echo "$why"; return 1; }
  if [ "$(cat "$MCP_BODY")" != "$MCP_NOT_FOUND_BODY" ]; then
    echo "404 body is not the unknown-name body: $(mcp_snip)"
    return 1
  fi
  return 0
}

# mcp_stable_headers FILE: the header block minus volatile headers, lower
# cased and sorted, for byte comparison of two answers.
mcp_stable_headers() {
  tr -d '\r' < "$1" | grep -v '^HTTP/' | grep -v '^$' \
    | awk -F: '{ printf "%s:%s\n", tolower($1), substr($0, index($0, ":") + 1) }' \
    | grep -viE "$MCP_VOLATILE_HEADERS" | sort
}

# ---------------------------------------------------------------------------
# Capability gates
# ---------------------------------------------------------------------------

# mcp_require_registry: stand the suite down when the feature flag layer says
# the MCP registry is not in this candidate. Call right after begin_suite /
# auth_admin. The format probe in mcp_create_repo is the second, definitive
# gate (a version floor cannot tell main 1.11.3 from release/1.11.x 1.11.11).
mcp_require_registry() {
  _TEST_NAME="preflight: mcp_registry"
  _TEST_START=$(date +%s)
  if ! require_feature "${1:-mcp_registry}"; then
    end_suite
    exit 0
  fi
}

# mcp_require_feature FLAG: per-test gate for a later-phase capability.
# Returns 1 (and records the skip) when the flag layer says it is absent.
mcp_require_feature() {
  require_feature "$1"
}

# mcp_create_repo KEY [EXTRA_JSON] [IS_PUBLIC]: create a Local mcp
# repository. EXTRA_JSON is merged into the create body
# ('{"mcp_package_policy":"open"}'). Stands the suite down when the backend
# does not know the format. Registers deletion on exit. Sets
# MCP_CREATE_STATUS / MCP_CREATE_BODY; returns 0 on 2xx.
mcp_create_repo() {
  local key="$1" extra="${2:-}" is_public="${3:-true}" body
  [ -n "$extra" ] || extra='{}'
  body=$(jq -cn --arg k "$key" --argjson pub "$is_public" --argjson x "$extra" \
    '{key:$k,name:$k,format:"mcp",repo_type:"local",is_public:$pub} + $x')
  _mcp_create "$key" "$body"
  if [ "$MCP_CREATE_STATUS" = "400" ] && grep -q 'Invalid format: mcp' "$MCP_CREATE_BODY" 2>/dev/null; then
    skip_suite "$MCP_FORMAT_GATE_REASON"
  fi
  _mcp_create_ok
}

# mcp_create_proxy_repo KEY TYPE UPSTREAM_OR_MEMBERS [EXTRA_JSON]
#   TYPE remote: UPSTREAM_OR_MEMBERS is the upstream_url.
#   TYPE virtual: a comma-separated member key list (members are attached
#   after creation through PUT /api/v1/repositories/KEY/members).
# Stands the suite down (MCP_PROXY_GATE_REASON) while the backend refuses
# Remote/Virtual mcp repositories with its Phase 1 message.
mcp_create_proxy_repo() {
  local key="$1" type="$2" arg="$3" extra="${4:-}" body
  [ -n "$extra" ] || extra='{}'
  if [ "$type" = "remote" ]; then
    body=$(jq -cn --arg k "$key" --arg u "$arg" --argjson x "$extra" \
      '{key:$k,name:$k,format:"mcp",repo_type:"remote",upstream_url:$u,is_public:true} + $x')
  else
    body=$(jq -cn --arg k "$key" --argjson x "$extra" \
      '{key:$k,name:$k,format:"mcp",repo_type:"virtual",is_public:true} + $x')
  fi
  _mcp_create "$key" "$body"
  if [ "$MCP_CREATE_STATUS" = "400" ] && grep -q 'Invalid format: mcp' "$MCP_CREATE_BODY" 2>/dev/null; then
    skip_suite "$MCP_FORMAT_GATE_REASON"
  fi
  if [ "$MCP_CREATE_STATUS" = "400" ] && grep -q 'support Local and Staging repositories in this release' "$MCP_CREATE_BODY" 2>/dev/null; then
    skip_suite "$MCP_PROXY_GATE_REASON"
  fi
  _mcp_create_ok || return 1
  if [ "$type" = "virtual" ] && [ -n "$arg" ]; then
    mcp_set_virtual_members "$key" "$arg" || return 1
  fi
  return 0
}

# mcp_set_virtual_members VIRTUAL CSV_MEMBERS: full-set replace, priority in
# list order.
mcp_set_virtual_members() {
  local key="$1" csv="$2" members
  members=$(printf '%s' "$csv" | jq -Rc 'split(",") | to_entries | map({member_key: .value, priority: (.key + 1)})')
  _mcp_new_resp
  MCP_STATUS=$(curl -s -o "$MCP_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"members\":${members}}" "${BASE_URL}/api/v1/repositories/${key}/members" 2>/dev/null) || MCP_STATUS="000"
  if [ "${MCP_STATUS:0:1}" != "2" ]; then
    # Older contract: one POST per member.
    local m prio=1 ok=0
    for m in ${csv//,/ }; do
      MCP_STATUS=$(curl -s -o "$MCP_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X POST \
        -H "$(auth_header)" -H "Content-Type: application/json" \
        -d "{\"member_key\":\"${m}\",\"priority\":${prio}}" \
        "${BASE_URL}/api/v1/repositories/${key}/members" 2>/dev/null) || MCP_STATUS="000"
      [ "${MCP_STATUS:0:1}" = "2" ] || ok=1
      prio=$(( prio + 1 ))
    done
    return "$ok"
  fi
}

_mcp_create() {
  local key="$1" body="$2"
  MCP_CREATE_BODY="${WORK_DIR:?setup_workdir first}/create-${key}.json"
  MCP_CREATE_STATUS="000"
  local _
  for _ in 1 2 3 4; do
    MCP_CREATE_STATUS=$(curl -s -o "$MCP_CREATE_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
      -X POST -H "$(auth_header)" -H "Content-Type: application/json" -d "$body" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || MCP_CREATE_STATUS="000"
    case "$MCP_CREATE_STATUS" in
      000|401|429|503) sleep 2 ;;
      *) break ;;
    esac
  done
  _MCP_CREATE_KEY="$key"
}

_mcp_create_ok() {
  if [ "${MCP_CREATE_STATUS:0:1}" = "2" ]; then
    mcp_delete_repo_on_exit "$_MCP_CREATE_KEY"
    return 0
  fi
  MCP_CREATE_ERROR="HTTP ${MCP_CREATE_STATUS}: $(head -c 300 "$MCP_CREATE_BODY" 2>/dev/null)"
  return 1
}

# mcp_delete_repo_on_exit KEY
mcp_delete_repo_on_exit() {
  add_exit_handler "curl -s -o /dev/null --max-time 30 -X DELETE -H \"\$(auth_header)\" \"${BASE_URL}/api/v1/repositories/$1\" || true"
}

# mcp_patch_repo KEY JSON: PATCH repository settings (mcp_* keys included).
mcp_patch_repo() {
  _mcp_new_resp
  MCP_STATUS=$(curl -s -o "$MCP_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PATCH \
    -H "$(auth_header)" -H "Content-Type: application/json" -d "$2" \
    "${BASE_URL}/api/v1/repositories/$1" 2>/dev/null) || MCP_STATUS="000"
  [ "${MCP_STATUS:0:1}" = "2" ]
}

# mcp_repo_id KEY: the repository UUID.
mcp_repo_id() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/$1" 2>/dev/null \
    | jq -r '.id // empty' 2>/dev/null || true
}

# mcp_probe_route METHOD URL [BODY]: 0 when the route exists, 1 when the
# backend answers it with the router fallback (404 with the unknown-name body
# on a fresh repository, or 405 mcp_method_not_allowed). Used to gate
# later-phase endpoints (POST /validate, .../capabilities, holds) that a
# Phase 1 backend does not mount.
mcp_probe_route() {
  local method="$1" url="$2" body="${3:-}"
  if [ -n "$body" ]; then
    mcp_req "$method" "$url" admin -H "Content-Type: application/json" -d "$body"
  else
    mcp_req "$method" "$url" admin
  fi
  case "$MCP_STATUS" in
    405) [ "$(mcp_json '.error // empty')" = "mcp_method_not_allowed" ] && return 1 ;;
    404) [ "$(cat "$MCP_BODY")" = "$MCP_NOT_FOUND_BODY" ] && return 1 ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# Remote MCP management API (docs/mcp-registry.md "Management API"):
# /api/v1/repositories/{key}/mcp/{catalog,sync}. Remote MCP repositories
# only; any other key answers 404. Errors are the API's {"code","message"}.
# ---------------------------------------------------------------------------

# mcp_mgmt_url KEY [TAIL]: ${BASE_URL}/api/v1/repositories/KEY/mcp[/TAIL]
mcp_mgmt_url() {
  printf '%s/api/v1/repositories/%s/mcp%s' "$BASE_URL" "$1" "${2:+/$2}"
}

# mcp_remote_sync KEY [AUTH]: POST .../mcp/sync, which runs one pass
# synchronously and answers 200 {repository, summary: SyncSummary}, 409 while
# another pass runs, 502 when the first upstream page is unreadable. Sets
# MCP_STATUS / MCP_BODY and MCP_SYNC_STATUS. A backend without the management
# API answers the router's 404 for a Remote (mcp_remote_mounted).
mcp_remote_sync() {
  local _try
  for _try in 1 2 3 4 5; do
    mcp_req POST "$(mcp_mgmt_url "$1" sync)" "${2:-admin}"
    [ "$MCP_STATUS" = "409" ] || break
    sleep 2
  done
  MCP_SYNC_STATUS="$MCP_STATUS"
  [ "$MCP_STATUS" = "200" ]
}

# mcp_remote_mounted: 0 unless the last management call answered as an
# unmounted route would (404 or 405 on a key that is a Remote MCP repository).
mcp_remote_mounted() {
  case "$MCP_STATUS" in
    404|405|000) return 1 ;;
  esac
  return 0
}

# mcp_catalog_load KEY OUT [AUTH] [QUERY]: walk GET .../mcp/catalog (limit
# 200, every page) and write the CatalogItem objects to OUT as one JSON
# array. QUERY is extra query text ("status=review&"). Returns 1 (OUT = [])
# when a page is not 200; MCP_STATUS is that page's status.
mcp_catalog_load() {
  local key="$1" out="$2" auth="${3:-admin}" query="${4:-}" cursor="" url pages=0 acc
  acc="${out}.acc"
  echo '[]' > "$acc"
  while :; do
    url="$(mcp_mgmt_url "$key" catalog)?${query}limit=200"
    [ -n "$cursor" ] && url="${url}&cursor=$(jq -rn --arg c "$cursor" '$c|@uri')"
    mcp_req GET "$url" "$auth"
    if [ "$MCP_STATUS" != "200" ] || ! jq -e '.items | type == "array"' "$MCP_BODY" >/dev/null 2>&1; then
      echo '[]' > "$out"
      rm -f "$acc"
      return 1
    fi
    jq -s '.[0] + .[1].items' "$acc" "$MCP_BODY" > "${acc}.tmp" && mv "${acc}.tmp" "$acc"
    cursor=$(mcp_json '.nextCursor // empty')
    pages=$(( pages + 1 ))
    if [ -z "$cursor" ] || [ "$pages" -ge 50 ]; then
      break
    fi
  done
  mv "$acc" "$out"
}

# mcp_catalog_item FILE NAME: the CatalogItem of NAME in a loaded catalog
# ("" when absent).
mcp_catalog_item() {
  jq -c --arg n "$2" 'map(select(.name == $n))[0] // empty' "$1" 2>/dev/null || true
}

# mcp_catalog_decide KEY ID DECISION [AUTH] [REASON]: POST
# .../catalog/{id}/{approve|block|reopen} {reason}; 200 DecisionResult
# {item, ingestError}. An approval ingests the name before it answers.
mcp_catalog_decide() {
  mcp_req POST "$(mcp_mgmt_url "$1" "catalog/$2/$3")" "${4:-admin}" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn --arg r "${5:-release-gate ${3}}" '{reason:$r}')"
  [ "$MCP_STATUS" = "200" ]
}

# ---------------------------------------------------------------------------
# server.json documents
# ---------------------------------------------------------------------------

# mcp_server_json NAME VERSION [PACKAGES_JSON] [REMOTES_JSON] [DESCRIPTION]
# prints a server.json. Empty PACKAGES/REMOTES omit the key.
mcp_server_json() {
  local name="$1" version="$2" pkgs="${3:-}" remotes="${4:-}" desc="${5:-Release-gate MCP fixture server}"
  jq -cn --arg s "$MCP_SCHEMA_URL" --arg n "$name" --arg v "$version" --arg d "$desc" \
    --argjson p "${pkgs:-null}" --argjson r "${remotes:-null}" \
    '{"$schema":$s,name:$n,description:$d,version:$v}
     + (if $p == null then {} else {packages:$p} end)
     + (if $r == null then {} else {remotes:$r} end)'
}

# mcp_remote_json URL [TYPE]: a one-entry remotes[] array.
mcp_remote_json() {
  jq -cn --arg u "$1" --arg t "${2:-streamable-http}" '[{type:$t,url:$u}]'
}

# mcp_npm_package_json IDENTIFIER VERSION [REGISTRY_BASE_URL]: a one-entry
# packages[] array for a stdio npm server. An empty base URL omits
# registryBaseUrl (own-repos then fills it in with the backing repository).
mcp_npm_package_json() {
  jq -cn --arg i "$1" --arg v "$2" --arg b "${3:-}" \
    '[{registryType:"npm",identifier:$i,version:$v,runtimeHint:"npx",transport:{type:"stdio"}}
      + (if $b == "" then {} else {registryBaseUrl:$b} end)]'
}

# mcp_oci_package_json IDENTIFIER: a one-entry packages[] array for OCI.
mcp_oci_package_json() {
  jq -cn --arg i "$1" '[{registryType:"oci",identifier:$i,runtimeHint:"docker",transport:{type:"stdio"}}]'
}

# mcp_render_fixture SRC OUT [KEY=VALUE...]: copy a corpus file replacing
# __KEY__ placeholders (__SLUG__, __AK_BASE__, __NPM_PKG__, __OCI_REF__).
mcp_render_fixture() {
  local src="$1" out="$2" kv k v
  shift 2
  cp "$src" "$out"
  for kv in "$@"; do
    k="${kv%%=*}"
    v="${kv#*=}"
    K="$k" V="$v" python3 -c '
import os, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read().replace("__%s__" % os.environ["K"], os.environ["V"])
open(p, "w", encoding="utf-8").write(s)
' "$out"
  done
}

# ---------------------------------------------------------------------------
# Backing packages
# ---------------------------------------------------------------------------

# mcp_create_backing_repos PREFIX [WITH_OCI]: create an npm Local
# (MCP_NPM_KEY) and, when WITH_OCI is "oci", a docker Local (MCP_OCI_KEY).
mcp_create_backing_repos() {
  MCP_NPM_KEY="${1}-npm"
  create_local_repo "$MCP_NPM_KEY" npm || return 1
  mcp_delete_repo_on_exit "$MCP_NPM_KEY"
  if [ "${2:-}" = "oci" ]; then
    MCP_OCI_KEY="${1}-oci"
    create_local_repo "$MCP_OCI_KEY" docker || return 1
    mcp_delete_repo_on_exit "$MCP_OCI_KEY"
  fi
}

# mcp_package_repos_json: {"npm": MCP_NPM_KEY[, "oci": MCP_OCI_KEY]}
mcp_package_repos_json() {
  jq -cn --arg n "${MCP_NPM_KEY:-}" --arg o "${MCP_OCI_KEY:-}" \
    '{} + (if $n == "" then {} else {npm:$n} end) + (if $o == "" then {} else {oci:$o} end)'
}

# mcp_render_echo_package OUT_DIR NAME VERSION MCP_NAME: render the
# zero-dependency echo server into OUT_DIR/package (npm tarball layout).
mcp_render_echo_package() {
  local out="$1" name="$2" version="$3" mcp_name="$4"
  rm -rf "${out}/package"
  mkdir -p "${out}/package/bin"
  cp "${MCP_FIXTURES_DIR}/echo-server/bin/server.js" "${out}/package/bin/server.js"
  chmod +x "${out}/package/bin/server.js"
  sed -e "s|__NAME__|${name}|" -e "s|__VERSION__|${version}|" -e "s|__MCP_NAME__|${mcp_name}|" \
    "${MCP_FIXTURES_DIR}/echo-server/package.json.tmpl" > "${out}/package/package.json"
}

# mcp_publish_echo_package NPM_KEY NAME VERSION MCP_NAME: build the echo
# server tarball and publish it to the npm repository with the npm PUT wire
# body (no npm client needed, so the security suites can use it too). Sets
# MCP_ECHO_TARBALL and MCP_STATUS; returns 0 on 2xx.
mcp_publish_echo_package() {
  local key="$1" name="$2" version="$3" mcp_name="$4" dir tarball registry
  dir="${WORK_DIR}/echo-${name//[^A-Za-z0-9._-]/_}-${version}"
  mkdir -p "$dir"
  mcp_render_echo_package "$dir" "$name" "$version" "$mcp_name"
  tarball="${dir}/${name##*/}-${version}.tgz"
  tar -czf "$tarball" -C "$dir" package
  MCP_ECHO_TARBALL="$tarball"
  registry="${BASE_URL}/npm/${key}/"
  local payload="${dir}/publish.json"
  python3 - "$name" "$version" "$tarball" "${dir}/package/package.json" "$registry" > "$payload" <<'PY'
import base64, hashlib, json, sys
name, version, tarball, pkgjson, registry = sys.argv[1:6]
data = open(tarball, "rb").read()
meta = json.load(open(pkgjson))
base = name.split("/")[-1]
meta["dist"] = {
    "tarball": "%s%s/-/%s-%s.tgz" % (registry, name, base, version),
    "shasum": hashlib.sha1(data).hexdigest(),
    "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
}
meta["_id"] = "%s@%s" % (name, version)
print(json.dumps({
    "_id": name, "name": name, "description": meta.get("description", ""),
    "dist-tags": {"latest": version},
    "versions": {version: meta},
    "_attachments": {"%s-%s.tgz" % (base, version): {
        "content_type": "application/octet-stream",
        "data": base64.b64encode(data).decode(), "length": len(data)}},
}))
PY
  local enc
  enc=$(printf '%s' "$name" | sed 's#/#%2f#')
  _mcp_new_resp
  MCP_STATUS=$(curl -s -o "$MCP_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/json" --data-binary "@${payload}" \
    "${registry}${enc}" 2>/dev/null) || MCP_STATUS="000"
  [ "${MCP_STATUS:0:1}" = "2" ]
}

# mcp_artifact_id REPO PATH_REGEX: the id of the first artifact whose path
# matches PATH_REGEX (jq test()).
mcp_artifact_id() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/$1/artifacts?per_page=200" 2>/dev/null \
    | jq -r --arg re "$2" '[(.items // .artifacts // .data // .)[]? | select((.path // "") | test($re))][0].id // empty' 2>/dev/null || true
}

# mcp_quarantine ARTIFACT_ID [REASON] / mcp_release ARTIFACT_ID: the admin
# quarantine routes. Set MCP_STATUS; return 0 on 2xx.
mcp_quarantine() {
  mcp_req POST "${BASE_URL}/api/v1/quarantine/$1/quarantine" admin \
    -H "Content-Type: application/json" -d "$(jq -cn --arg r "${2:-release-gate MCP hold}" '{reason:$r}')"
  [ "${MCP_STATUS:0:1}" = "2" ]
}
mcp_release() {
  mcp_req POST "${BASE_URL}/api/v1/quarantine/$1/release" admin -H "Content-Type: application/json" -d '{}'
  [ "${MCP_STATUS:0:1}" = "2" ]
}

# ---------------------------------------------------------------------------
# Users and grants (repository holder vs plain reader)
# ---------------------------------------------------------------------------

# mcp_make_user NAME: create a user (password MCP_USER_PASS) and echo its
# token. Sets MCP_USER_ID and registers the user's deletion, so call it in
# the current shell with stdout redirected (mcp_make_user u > "$WORK_DIR/tok"),
# never as TOKEN=$(mcp_make_user u): a subshell loses both.
MCP_USER_PASS="${MCP_USER_PASS:-McpGate!2026secure}"
mcp_make_user() {
  local name="$1"
  MCP_USER_ID=$(create_test_user_with_retry "$name" "$MCP_USER_PASS" "${name}@example.invalid") || return 1
  add_exit_handler "curl -s -o /dev/null --max-time 30 -X DELETE -H \"\$(auth_header)\" \"${BASE_URL}/api/v1/users/${MCP_USER_ID}\" || true"
  login_as "$name" "$MCP_USER_PASS"
}

# mcp_grant USER_ID REPO ACTIONS_JSON: a repository permission
# ('["read"]', '["read","write"]').
mcp_grant() {
  local repo_id
  repo_id=$(mcp_repo_id "$2")
  [ -n "$repo_id" ] || return 1
  _mcp_new_resp
  MCP_STATUS=$(curl -s -o "$MCP_BODY" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X POST \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"principal_type\":\"user\",\"principal_id\":\"$1\",\"target_type\":\"repository\",\"target_id\":\"${repo_id}\",\"actions\":$3}" \
    "${BASE_URL}/api/v1/permissions" 2>/dev/null) || MCP_STATUS="000"
  [ "${MCP_STATUS:0:1}" = "2" ]
}

# mcp_mint_token TOKEN_OF_OWNER NAME SCOPES_JSON: an API token, echoed.
mcp_mint_token() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST -H "Authorization: Bearer $1" -H "Content-Type: application/json" \
    -d "$(jq -cn --arg n "$2" --argjson s "$3" '{name:$n,scopes:$s}')" \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null | jq -r '.token // empty' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# mcp-publisher (pinned + checksummed)
# ---------------------------------------------------------------------------

# install_mcp_publisher: download the pinned release once per runner into
# ${XDG_CACHE_HOME:-$HOME/.cache}/ak-e2e/mcp-publisher-<ver>/, verify the
# tarball sha256, and set MCP_PUBLISHER to the binary. Returns 1 (with
# MCP_PUBLISHER_ERROR) on a download failure and 2 on a checksum mismatch;
# the caller reports either through infra_fail (a harness problem, not a
# product verdict). MCP_PUBLISHER_BIN overrides the download entirely.
install_mcp_publisher() {
  MCP_PUBLISHER_ERROR=""
  if [ -n "${MCP_PUBLISHER_BIN:-}" ]; then
    MCP_PUBLISHER="$MCP_PUBLISHER_BIN"
    return 0
  fi
  local arch sha
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64; sha="$MCP_PUBLISHER_SHA256_LINUX_AMD64" ;;
    aarch64|arm64) arch=arm64; sha="$MCP_PUBLISHER_SHA256_LINUX_ARM64" ;;
    *) MCP_PUBLISHER_ERROR="unsupported architecture $(uname -m)"; return 1 ;;
  esac
  local cache="${XDG_CACHE_HOME:-${HOME}/.cache}/ak-e2e/mcp-publisher-${MCP_PUBLISHER_VERSION}-${arch}"
  if [ -x "${cache}/mcp-publisher" ] && [ -f "${cache}/.sha256" ] && [ "$(cat "${cache}/.sha256")" = "$sha" ]; then
    MCP_PUBLISHER="${cache}/mcp-publisher"
    return 0
  fi
  mkdir -p "$cache"
  local tgz="${cache}/mcp-publisher.tar.gz.part"
  local url="https://github.com/modelcontextprotocol/registry/releases/download/v${MCP_PUBLISHER_VERSION}/mcp-publisher_linux_${arch}.tar.gz"
  if ! curl -fsSL --max-time 120 --retry 3 -o "$tgz" "$url"; then
    MCP_PUBLISHER_ERROR="download failed: ${url}"
    rm -f "$tgz"
    return 1
  fi
  local got
  got=$(sha256sum "$tgz" | cut -d' ' -f1)
  if [ "$got" != "$sha" ]; then
    MCP_PUBLISHER_ERROR="sha256 mismatch for ${url}: expected ${sha}, got ${got}"
    rm -f "$tgz"
    return 2
  fi
  local x="${cache}/x"
  rm -rf "$x"
  mkdir -p "$x"
  tar -xzf "$tgz" -C "$x" mcp-publisher || { MCP_PUBLISHER_ERROR="extract failed"; return 1; }
  mv "${x}/mcp-publisher" "${cache}/mcp-publisher"
  chmod +x "${cache}/mcp-publisher"
  rm -rf "$x" "$tgz"
  printf '%s' "$sha" > "${cache}/.sha256"
  MCP_PUBLISHER="${cache}/mcp-publisher"
}

# mcp_write_publisher_token HOME_DIR REGISTRY_URL TOKEN: what
# `mcp-publisher login` would write, with an Artifact Keeper token. The
# caller points HOME at HOME_DIR so parallel scripts never share it.
mcp_write_publisher_token() {
  mkdir -p "${1}/.config/mcp-publisher"
  jq -n --arg t "$3" --arg r "$2" '{token:$t,method:"none",registry:$r}' > "${1}/.config/mcp-publisher/token.json"
  chmod 600 "${1}/.config/mcp-publisher/token.json"
}

# mcp_publisher HOME_DIR ARGS...: run the publisher with HOME=HOME_DIR in
# the current directory; output to MCP_PUBLISHER_OUT (file), exit code
# returned.
mcp_publisher() {
  local home="$1"
  shift
  MCP_PUBLISHER_OUT="${WORK_DIR}/mcp-publisher-$(( ++_mcp_resp_seq )).out"
  HOME="$home" timeout 60 "$MCP_PUBLISHER" "$@" > "$MCP_PUBLISHER_OUT" 2>&1
}

# ---------------------------------------------------------------------------
# MCP client
# ---------------------------------------------------------------------------

# mcp_client ARGS...: tests/lib/mcp-stdio-client.py; JSON on stdout.
mcp_client() {
  python3 "${_MCP_LIB_DIR}/mcp-stdio-client.py" "$@"
}

# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------

# mcp_mock_host: the address the backend dials the runner on.
mcp_mock_host() {
  printf '%s' "${MOCK_UPSTREAM_HOSTNAME:-127.0.0.1}"
}

# start_mock_mcp_upstream STATE_DIR [FIXTURE_SERVERS_DIR]: boot
# mock-mcp-upstream.py (seeded from FIXTURE_SERVERS_DIR, default
# tests/fixtures/mcp/upstream/servers). Sets MCP_MOCK_PID, MCP_MOCK_PORT,
# MCP_MOCK_STATE_DIR, MCP_MOCK_BASE_URL (backend-facing), MCP_MOCK_LOCAL_URL.
# Also exports MOCK_STATE_DIR so mock_counter_key / wait_for_counter_stable
# read this mock's counters.
start_mock_mcp_upstream() {
  MCP_MOCK_STATE_DIR="$1"
  local seed="${2:-${MCP_FIXTURES_DIR}/upstream/servers}"
  mkdir -p "${MCP_MOCK_STATE_DIR}/servers"
  cp "$seed"/*.json "${MCP_MOCK_STATE_DIR}/servers/" 2>/dev/null || true
  MCP_MOCK_PORT="$(_pick_mock_port)"
  MOCK_STATE_DIR="$MCP_MOCK_STATE_DIR" MOCK_PORT="$MCP_MOCK_PORT" \
    python3 "${_MCP_LIB_DIR}/mock-mcp-upstream.py" \
    > "${WORK_DIR}/mock-mcp-upstream.out" 2> "${WORK_DIR}/mock-mcp-upstream.err" &
  MCP_MOCK_PID=$!
  disown "$MCP_MOCK_PID" 2>/dev/null || true
  add_exit_handler "kill ${MCP_MOCK_PID} 2>/dev/null || true"
  MOCK_STATE_DIR="$MCP_MOCK_STATE_DIR"
  MCP_MOCK_LOCAL_URL="http://127.0.0.1:${MCP_MOCK_PORT}"
  MCP_MOCK_BASE_URL="http://$(mcp_mock_host):${MCP_MOCK_PORT}"
  _mcp_wait_ready "$MCP_MOCK_PID" "${MCP_MOCK_LOCAL_URL}/__readyz" "${WORK_DIR}/mock-mcp-upstream.err"
}

# start_mock_mcp_http STATE_DIR [SSE]: boot mock-mcp-http-server.py. Sets
# MCP_HTTP_PID, MCP_HTTP_PORT, MCP_HTTP_STATE_DIR, MCP_HTTP_URL
# (backend-facing /mcp endpoint, what a server.json names) and
# MCP_HTTP_LOCAL_URL (what the runner's client calls).
start_mock_mcp_http() {
  MCP_HTTP_STATE_DIR="$1"
  mkdir -p "$MCP_HTTP_STATE_DIR"
  MCP_HTTP_PORT="$(_pick_mock_port)"
  MCP_HTTP_STATE_DIR="$MCP_HTTP_STATE_DIR" MCP_HTTP_PORT="$MCP_HTTP_PORT" MCP_HTTP_SSE="${2:-0}" \
    python3 "${_MCP_LIB_DIR}/mock-mcp-http-server.py" \
    > "${WORK_DIR}/mock-mcp-http.out" 2> "${WORK_DIR}/mock-mcp-http.err" &
  MCP_HTTP_PID=$!
  disown "$MCP_HTTP_PID" 2>/dev/null || true
  add_exit_handler "kill ${MCP_HTTP_PID} 2>/dev/null || true"
  MCP_HTTP_URL="http://$(mcp_mock_host):${MCP_HTTP_PORT}/mcp"
  MCP_HTTP_LOCAL_URL="http://127.0.0.1:${MCP_HTTP_PORT}/mcp"
  _mcp_wait_ready "$MCP_HTTP_PID" "http://127.0.0.1:${MCP_HTTP_PORT}/__readyz" "${WORK_DIR}/mock-mcp-http.err"
}

# mcp_http_count [NAME]: request-count (default) or foreign-count of the
# HTTP mock.
mcp_http_count() {
  cat "${MCP_HTTP_STATE_DIR}/${1:-request-count}" 2>/dev/null || echo 0
}

# mcp_mock_count KEY: a mock-mcp-upstream counter ("" = total).
mcp_mock_count() {
  local f="${MCP_MOCK_STATE_DIR}/request-count${1:+.$1}"
  cat "$f" 2>/dev/null || echo 0
}

_mcp_wait_ready() {
  local pid="$1" url="$2" err="$3" code _
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "mock died during boot: $(head -c 400 "$err" 2>/dev/null)" >&2
      return 1
    fi
    code=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null) || code="000"
    [ "$code" = "200" ] && return 0
    sleep 0.5
  done
  echo "mock not ready at ${url} after 10s" >&2
  return 1
}

# mcp_require_dialback: the backend must be able to reach the runner for a
# mock upstream. Off-cluster local runs set MOCK_UPSTREAM_HOSTNAME to a
# non-loopback address of this host; the gate's "Resolve runner pod address"
# step sets it to the pod IP.
mcp_require_dialback() {
  if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
    skip_suite "MOCK_UPSTREAM_HOSTNAME not set; the backend cannot dial the runner-hosted MCP mock"
  fi
}

# mcp_skip_later_phase CAPABILITY PROBE_DESCRIPTION: stand the suite down
# because a probe proved a Phase 2/3 capability absent. The reason matches
# the mcp_registry_later_phase row of _CAPABILITY_EXEMPTIONS; call it only
# after a discriminating probe (mcp_probe_route, a setting the backend did
# not echo back), never on an ordinary failure.
mcp_skip_later_phase() {
  skip_suite "MCP Registry later-phase capability not shipped by this backend (probe: ${2}); capability ${1}"
}
