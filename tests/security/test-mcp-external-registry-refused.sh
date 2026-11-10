#!/usr/bin/env bash
# test-mcp-external-registry-refused.sh - the own-repos package policy refuses
# servers whose packages live outside this instance (artifact-keeper#5253;
# docs/mcp-registry.md "Package policy").
#
# Contract under test:
#   - own-repos (the default) refuses with 422 mcp_external_registry, one
#     `detail` line naming packages[0]: a registryBaseUrl of a public
#     registry, of an attacker host, or of another AK npm repository than the
#     mapped one; a registryType with no mcp_package_repos mapping (pypi);
#     an OCI entry when there is no `oci` mapping. An mcpb entry without
#     registryBaseUrl is resolved by its fileSha256 against uploaded bundles
#     and the mcpb mapping, so one matching nothing is 422
#     mcp_package_not_found (docs "MCPB bundles"). Nothing is contacted to
#     decide (publish is a database lookup).
#   - an `open` repository (npm mapped) accepts the foreign npm coordinates
#     only because the package resolves in the mapped npm repository: it is
#     pinned, served at its Artifact Keeper coordinates (registryBaseUrl
#     /npm/<mapped>) with the pin warning foreign_coordinates_replaced, and
#     labelled _meta["com.artifactkeeper.registry/source"].packagePolicy
#     "open" (artifact-keeper#5452). Nothing else is relaxed: the unmapped
#     pypi and oci entries stay 422 mcp_external_registry and the unmatched
#     mcpb entry stays 422 mcp_package_not_found.
#   - switching a repository open -> own-repos does not change what was
#     published under open: those versions keep their pins and are served
#     (200) to a reader and to the administrator.
#   - mcp_package_repos must name an existing repository whose format serves
#     the registry type and that the caller can read; create and PATCH refuse
#     anything else with 400, and a repository the caller cannot read gets
#     the same message as one that does not exist.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-external-registry-refused"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd tar
mcp_require_registry

PREFIX="sec-mcpext-${RUN_ID}"
OWN_KEY="${PREFIX}-own"
OPEN_KEY="${PREFIX}-open"
OTHER_NPM="${PREFIX}-npm2"
PYPI_KEY="${PREFIX}-pypi"
PRIV_NPM="${PREFIX}-npmpriv"
NPM_PKG="@ak-e2e/ext-${RUN_ID}"
OWN_DIR="${MCP_FIXTURES_DIR}/server-json/own-repos"

expect_problem() {
  local why
  if why=$(mcp_check_problem "$1" "$2"); then
    pass
  else
    fail "$3: ${why}"
  fi
}

begin_test "Create backing repositories (mapped npm, a second npm, pypi, private npm)"
ok=true
mcp_create_backing_repos "$PREFIX" || ok=false
create_local_repo "$OTHER_NPM" npm || ok=false
mcp_delete_repo_on_exit "$OTHER_NPM"
create_local_repo "$PYPI_KEY" pypi || ok=false
mcp_delete_repo_on_exit "$PYPI_KEY"
st=$(curl -s -o "${WORK_DIR}/privnpm.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X POST \
  -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$(jq -cn --arg k "$PRIV_NPM" '{key:$k,name:$k,format:"npm",repo_type:"local",is_public:false}')" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || st="000"
[ "${st:0:1}" = "2" ] || ok=false
mcp_delete_repo_on_exit "$PRIV_NPM"
if $ok; then pass; else fail_fatal "backing repository setup failed (private npm HTTP ${st})"; fi

begin_test "Create own-repos and open MCP repositories (both npm mapped)"
if mcp_create_repo "$OWN_KEY" "$(jq -cn --arg n "$MCP_NPM_KEY" '{mcp_package_repos:{npm:$n}}')" \
  && mcp_create_repo "$OPEN_KEY" "$(jq -cn --arg n "$MCP_NPM_KEY" '{mcp_package_policy:"open",mcp_package_repos:{npm:$n}}')"; then
  pass
else
  fail_fatal "MCP repository creation failed: ${MCP_CREATE_ERROR:-}"
fi

begin_test "GET /api/v1/repositories/{key} echoes the package policies"
own_pol=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${OWN_KEY}" | jq -r '.mcp_package_policy // empty')
open_pol=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${OPEN_KEY}" | jq -r '.mcp_package_policy // empty')
if [ "$own_pol" = "own-repos" ] && [ "$open_pol" = "open" ]; then
  pass
else
  fail "mcp_package_policy echoed as own='${own_pol}' open='${open_pol}'"
fi

begin_test "Publish the echo package to the mapped npm and to the second npm repository"
if mcp_publish_echo_package "$MCP_NPM_KEY" "$NPM_PKG" 1.0.0 "io.github.ak-e2e/ext-${RUN_ID}" \
  && mcp_publish_echo_package "$OTHER_NPM" "$NPM_PKG" 1.0.0 "io.github.ak-e2e/ext-${RUN_ID}"; then
  pass
else
  fail_fatal "npm publish of the echo package failed: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# own-repos refusals and their open twins
# ---------------------------------------------------------------------------

# own-repos fixture[:expected error, default mcp_external_registry]. The
# open repository pins the npm cases from the mapped npm repository and
# refuses the others with the same error as own-repos.
CASES=(npm-external-registry npm-evil-registry npm-other-ak-repo pypi-unmapped mcpb-bundle:mcp_package_not_found oci-foreign-host)
for spec in "${CASES[@]}"; do
  c="${spec%%:*}"
  want_err="mcp_external_registry"
  [ "$spec" = "$c" ] || want_err="${spec#*:}"
  out="${WORK_DIR}/${c}.json"
  mcp_render_fixture "${OWN_DIR}/${c}.json" "$out" SLUG="ext-${c}-${RUN_ID}" AK_BASE="$BASE_URL" NPM_PKG="$NPM_PKG"

  begin_test "own-repos refuses ${c}: 422 ${want_err} naming packages[0]"
  mcp_publish "$OWN_KEY" "$out"
  if why=$(mcp_check_problem 422 "$want_err"); then
    if mcp_json '.detail' | grep -q '^packages\[0\]'; then
      pass
    else
      fail "${c}: detail does not name packages[0]: $(mcp_json '.detail')"
    fi
  else
    fail "${c}: ${why}"
  fi

  case "$c" in
    npm-*)
      begin_test "open pins ${c} from the mapped npm repository (200, foreign_coordinates_replaced, packagePolicy open)"
      mcp_publish "$OPEN_KEY" "$out"
      base=$(mcp_json '.server.packages[0].registryBaseUrl')
      warned=$(mcp_json '.server.packages[0]._meta["com.artifactkeeper/resolved"].warnings // [] | index("foreign_coordinates_replaced") != null')
      label=$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')
      if [ "$MCP_STATUS" != "200" ]; then
        fail "open publish of ${c}: HTTP ${MCP_STATUS}: $(mcp_snip)"
      elif [ "$(mcp_url_path "$base")" != "/npm/${MCP_NPM_KEY}" ]; then
        fail "open served registryBaseUrl '${base}' for ${c}, expected the mapped /npm/${MCP_NPM_KEY}"
      elif [ "$warned" != "true" ]; then
        fail "open pin of ${c} does not carry foreign_coordinates_replaced: $(mcp_json '.server.packages[0]._meta' | head -c 300)"
      elif [ "$label" != "open" ]; then
        fail "open publish of ${c} labelled packagePolicy '${label}'"
      else
        pass
      fi
      ;;
    *)
      begin_test "open refuses ${c} as own-repos does: 422 ${want_err}"
      mcp_publish "$OPEN_KEY" "$out"
      if why=$(mcp_check_problem 422 "$want_err"); then
        pass
      else
        fail "open publish of ${c}: ${why}"
      fi
      ;;
  esac
done

# The fixture npm-other-ak-repo names a key that does not exist; this one is a
# real AK npm repository holding the same package, just not the mapped one.
begin_test "own-repos refuses a registryBaseUrl of another real AK npm repository (422)"
mcp_server_json "io.github.ak-e2e/ext-real-other-${RUN_ID}" 1.0.0 \
  "$(mcp_npm_package_json "$NPM_PKG" 1.0.0 "${BASE_URL}/npm/${OTHER_NPM}")" > "${WORK_DIR}/real-other.json"
mcp_publish "$OWN_KEY" "${WORK_DIR}/real-other.json"
if why=$(mcp_check_problem 422 mcp_external_registry) && mcp_json '.detail' | grep -q '^packages\[0\]'; then
  pass
else
  [ -n "$why" ] || why="detail \"$(mcp_json '.detail')\" does not name packages[0]"
  fail "another real AK npm repository: ${why}"
fi

begin_test "Control: own-repos accepts the mapped npm repository and serves its coordinates"
mcp_server_json "io.github.ak-e2e/ext-ok-${RUN_ID}" 1.0.0 "$(mcp_npm_package_json "$NPM_PKG" 1.0.0)" > "${WORK_DIR}/ok.json"
mcp_publish "$OWN_KEY" "${WORK_DIR}/ok.json"
base=$(mcp_json '.server.packages[0].registryBaseUrl')
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_url_path "$base")" = "/npm/${MCP_NPM_KEY}" ]; then
  pass
else
  fail "own-repos publish of the mapped package: HTTP ${MCP_STATUS}, registryBaseUrl '${base}': $(mcp_snip)"
fi

begin_test "None of the refused documents reached the own-repos listing"
mcp_get "$OWN_KEY" "servers?limit=100"
names=$(mcp_json '[.servers[].server.name] | join(",")')
if [ "$MCP_STATUS" = "200" ] && [ "$names" = "io.github.ak-e2e/ext-ok-${RUN_ID}" ]; then
  pass
else
  fail "own-repos listing: HTTP ${MCP_STATUS}, names '${names}'"
fi

# ---------------------------------------------------------------------------
# open -> own-repos: open-era versions keep their pins (docs/mcp-registry.md
# "Switching a repository between open and own-repos does not change versions
# already published")
# ---------------------------------------------------------------------------

SWITCH_NAME="io.github.ak-e2e/ext-npm-external-registry-${RUN_ID}"
SWITCH_PATH="$(mcp_version_path "$SWITCH_NAME" 1.0.0)"
begin_test "Switch the open repository to own-repos (PATCH accepted)"
if mcp_patch_repo "$OPEN_KEY" "$(jq -cn --arg n "$MCP_NPM_KEY" '{mcp_package_policy:"own-repos",mcp_package_repos:{npm:$n}}')"; then
  pass
else
  fail "PATCH to own-repos: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

for who in anon admin; do
  begin_test "After the switch an open-era version is still served to ${who} (200, pinned coordinates)"
  mcp_get "$OPEN_KEY" "$SWITCH_PATH" "$who"
  base=$(mcp_json '.server.packages[0].registryBaseUrl')
  if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.name')" = "$SWITCH_NAME" ] \
    && [ "$(mcp_url_path "$base")" = "/npm/${MCP_NPM_KEY}" ]; then
    pass
  else
    fail "open-era version after the switch (${who}): HTTP ${MCP_STATUS}, registryBaseUrl '${base}': $(mcp_snip)"
  fi
done

begin_test "After the switch the three pinned open-era versions are still listed"
mcp_get "$OPEN_KEY" "servers?limit=100" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.servers | length')" = "3" ]; then
  pass
else
  fail "listing after the switch: HTTP ${MCP_STATUS}, $(mcp_json '.servers | length') entries (want the 3 npm cases): $(mcp_json '[.servers[].server.name] | join(",")')"
fi

# ---------------------------------------------------------------------------
# mcp_package_repos validation
# ---------------------------------------------------------------------------

begin_test "mcp_package_repos naming a pypi repository for npm is refused at PATCH (400)"
mcp_patch_repo "$OWN_KEY" "$(jq -cn --arg n "$PYPI_KEY" '{mcp_package_repos:{npm:$n}}')" || true
if [ "$MCP_STATUS" = "400" ] && grep -q "$PYPI_KEY" "$MCP_BODY"; then
  pass
else
  fail "wrong-format mapping: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "mcp_package_repos naming a pypi repository for npm is refused at create (400)"
if mcp_create_repo "${PREFIX}-c1" "$(jq -cn --arg n "$PYPI_KEY" '{mcp_package_repos:{npm:$n}}')"; then
  fail "an mcp repository mapping npm to a pypi repository was created"
elif [ "$MCP_CREATE_STATUS" = "400" ]; then
  pass
else
  fail "wrong-format mapping at create: ${MCP_CREATE_ERROR:-}"
fi

MISSING="${PREFIX}-absent"
begin_test "mcp_package_repos naming a missing repository is refused at create and PATCH (400)"
mcp_create_repo "${PREFIX}-c2" "$(jq -cn --arg n "$MISSING" '{mcp_package_repos:{npm:$n}}')" || true
create_status="$MCP_CREATE_STATUS"
mcp_patch_repo "$OWN_KEY" "$(jq -cn --arg n "$MISSING" '{mcp_package_repos:{npm:$n}}')" || true
if [ "$create_status" = "400" ] && [ "$MCP_STATUS" = "400" ]; then
  pass
else
  fail "missing repository mapping: create HTTP ${create_status}, PATCH HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "A repository-admin user: unreadable and missing repositories get the same message"
if mcp_make_user "mcpext-adm-${RUN_ID}" > "${WORK_DIR}/tok-adm" \
  && mcp_grant "$MCP_USER_ID" "$OWN_KEY" '["read","write","admin"]'; then
  TOK_ADM=$(cat "${WORK_DIR}/tok-adm")
  user_patch() {
    curl -s -o "${WORK_DIR}/up-$1.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PATCH \
      -H "Authorization: Bearer ${TOK_ADM}" -H "Content-Type: application/json" \
      -d "$(jq -cn --arg n "$1" '{mcp_package_repos:{npm:$n}}')" \
      "${BASE_URL}/api/v1/repositories/${OWN_KEY}" 2>/dev/null || echo 000
  }
  st_priv=$(user_patch "$PRIV_NPM")
  st_miss=$(user_patch "$MISSING")
  msg_priv=$(jq -r '.message // .detail // empty' "${WORK_DIR}/up-${PRIV_NPM}.json" 2>/dev/null | sed "s/${PRIV_NPM}/KEY/g")
  msg_miss=$(jq -r '.message // .detail // empty' "${WORK_DIR}/up-${MISSING}.json" 2>/dev/null | sed "s/${MISSING}/KEY/g")
  st_ok=$(user_patch "$OTHER_NPM")
  if [ "$st_priv" != "400" ] || [ "$st_miss" != "400" ]; then
    fail "user PATCH naming a private repository: ${st_priv}; naming a missing one: ${st_miss} (expected 400 both)"
  elif [ "$msg_priv" != "$msg_miss" ] || [ -z "$msg_priv" ]; then
    fail "unreadable and missing repositories answer differently: '${msg_priv}' vs '${msg_miss}'" \
      "docs/mcp-registry.md: a repository the caller cannot read is refused with the same message as one that does not exist."
  elif [ "${st_ok:0:1}" != "2" ]; then
    fail "control: the same user mapping a readable public npm repository got HTTP ${st_ok}: $(head -c 300 "${WORK_DIR}/up-${OTHER_NPM}.json")"
  else
    pass
  fi
else
  fail "could not create the repository-admin user: $(mcp_snip)"
fi

end_suite
