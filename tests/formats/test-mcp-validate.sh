#!/usr/bin/env bash
# test-mcp-validate.sh - POST /validate dry run (artifact-keeper#5253 Phase 2,
# issue 4.2 "POST /validate", 8 Phase 2 item 5).
#
# Audit lane. POST /mcp/{repo}/v0.1/validate (and the /v0 alias the
# publisher uses) runs the same parse and policy checks as /publish without
# writing: a good document is valid, a bad one returns the issues list, and
# nothing is stored or pinned. `mcp-publisher validate` sends no token
# (tests/fixtures/mcp/publisher-wire.txt), so the dry run must answer an
# anonymous caller on a public repository.
#
# Gate: mcp_require_registry mcp_validate, then mcp_probe_route POST
# .../v0.1/validate with a valid document: the router fallback (404 with the
# unknown-name body) -> mcp_skip_later_phase mcp_validate.
#
# Response shape (docs/mcp-registry.md "POST /validate"): always 200 for a
# document, valid or not (413 mcp_too_large over the cap), with upstream's
# ValidationResult plus packages: {"valid": bool, "issues": [{type, path,
# message, severity, reference}], "packages": [...]}. Validation stops at the
# first error: an invalid document has exactly one `error` issue whose
# `reference` is the code the publish would answer. The version-taken check
# (mcp_version_exists) is made only for a repository holder, so an anonymous
# caller learns nothing a read would not tell it.
#
# Requires: curl, jq. mcp-publisher is optional (install_mcp_publisher);
# without it the publisher test skips.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-validate"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
mcp_require_registry mcp_validate

# --- Contract (docs/mcp-registry.md "POST /validate") ----------------------
VALID_FIELD="valid"
ISSUES_FIELD="issues"

REPO="mcp-validate-${RUN_ID}"
SLUG="validate-${RUN_ID}"
NAME="io.github.ak-e2e/${SLUG}"
CORPUS="${MCP_FIXTURES_DIR}/server-json"

validate_as() {
  # validate_as AUTH FILE [API_VERSION]
  mcp_req POST "$(mcp_root "$REPO")/${3:-$MCP_API_VERSION}/validate" "$1" \
    -H "Content-Type: application/json" --data-binary "@$2"
}

# is_valid_answer: 200, valid true, no `error` issue.
is_valid_answer() {
  [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json ".${VALID_FIELD}")" = "true" ] \
    && [ "$(mcp_json "[.${ISSUES_FIELD}[]? | select(.severity == \"error\")] | length")" = "0" ]
}

# invalid_why REFERENCE [PATH]: "" when the last answer is 200, valid false,
# with exactly one `error` issue {type, path, message, severity, reference}
# whose reference is REFERENCE (and path PATH when given); else why not.
invalid_why() {
  local got
  if [ "$MCP_STATUS" != "200" ]; then
    echo "HTTP ${MCP_STATUS} (want 200 for any document): $(mcp_snip)"
    return
  fi
  got=$(mcp_json "[.${ISSUES_FIELD}[]? | select(.severity == \"error\")] | if length == 1 then .[0] | \"\(.type)|\(.path)|\(.reference)|\(.message | length > 0)\" else \"\(length) error issues\" end")
  if [ "$(mcp_json ".${VALID_FIELD}")" != "false" ]; then
    echo "valid is '$(mcp_json ".${VALID_FIELD}")', want false: $(mcp_snip)"
  elif ! printf '%s' "$got" | grep -qE "^(schema|semantic)\|${2:-[^|]*}\|${1}\|true$"; then
    echo "error issue type|path|reference|has-message is '${got}', want reference ${1}${2:+ at path ${2}}: $(mcp_snip)"
  fi
}

begin_test "Setup: mcp repository and fixtures"
if ! mcp_create_repo "$REPO"; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
mcp_render_fixture "${CORPUS}/valid/minimal-remote.json" "${WORK_DIR}/good.json" "SLUG=${SLUG}"
mcp_render_fixture "${CORPUS}/invalid/description-101.json" "${WORK_DIR}/bad.json" "SLUG=${SLUG}-bad"
mcp_render_fixture "${CORPUS}/invalid/name-two-slashes.json" "${WORK_DIR}/bad-name.json" "SLUG=${SLUG}-bad2"
pass

if ! mcp_probe_route POST "$(mcp_base "$REPO")/validate" "$(cat "${WORK_DIR}/good.json")"; then
  mcp_skip_later_phase mcp_validate "POST $(mcp_url_path "$(mcp_base "$REPO")")/validate answered ${MCP_STATUS} with the router fallback"
fi

begin_test "A valid document is valid (anonymous, ${MCP_API_VERSION} and /v0)"
validate_as anon "${WORK_DIR}/good.json"
v01="$MCP_STATUS:$(mcp_json ".${VALID_FIELD}")"
ok01=0
is_valid_answer && ok01=1
validate_as anon "${WORK_DIR}/good.json" v0
v0="$MCP_STATUS:$(mcp_json ".${VALID_FIELD}")"
if [ "$ok01" = "1" ] && is_valid_answer; then
  pass
else
  fail "valid document: ${MCP_API_VERSION} ${v01}, v0 ${v0} (want 200 ${VALID_FIELD}=true)" "$(mcp_snip)"
fi

begin_test "A bad document is 200 valid=false with one error issue naming the field"
validate_as anon "${WORK_DIR}/bad.json"
why=$(invalid_why mcp_invalid_server_json description)
if [ -z "$why" ]; then
  validate_as anon "${WORK_DIR}/bad-name.json"
  why=$(invalid_why mcp_invalid_server_json)
  if [ -z "$why" ]; then
    pass
  else
    fail "bad name: ${why}"
  fi
else
  fail "101-character description: ${why}"
fi

begin_test "Validate is a dry run: nothing stored"
mcp_get "$REPO" "$(mcp_version_path "$NAME" 1.0.0)" admin
st="$MCP_STATUS"
mcp_get "$REPO" "servers?search=${SLUG}" admin
n=$(mcp_json '.servers | length')
if [ "$st" = "404" ] && [ "$n" = "0" ] && [ -z "$(mcp_artifact_id "$REPO" "${SLUG}")" ]; then
  # And the version is still publishable afterwards.
  mcp_publish "$REPO" "${WORK_DIR}/good.json"
  if [ "$MCP_STATUS" = "200" ]; then
    pass
  else
    fail "publish after validate answered ${MCP_STATUS}: $(mcp_snip)"
  fi
else
  fail "validate stored something: detail ${st}, listed ${n}"
fi

begin_test "A taken name@version is reported to a repository holder only"
validate_as admin "${WORK_DIR}/good.json"
holder_why=$(invalid_why mcp_version_exists version)
validate_as anon "${WORK_DIR}/good.json"
anon_ok=0
is_valid_answer && anon_ok=1
if [ -n "$holder_why" ]; then
  fail "admin validate of the published ${NAME}@1.0.0: ${holder_why}"
elif [ "$anon_ok" != "1" ]; then
  fail "anonymous validate of a taken version must not reveal it (want 200 valid=true): HTTP ${MCP_STATUS} $(mcp_snip)"
else
  pass
fi

begin_test "Validate applies publish policy: a reserved namespace is reported"
mcp_render_fixture "${CORPUS}/invalid/reserved-namespace.json" "${WORK_DIR}/reserved.json" "SLUG=${SLUG}-r"
validate_as anon "${WORK_DIR}/reserved.json"
why=$(invalid_why mcp_namespace_reserved name)
if [ -z "$why" ]; then
  pass
else
  fail "reserved namespace: ${why}"
fi

begin_test "mcp-publisher validate: valid document exits 0, bad document lists the issue"
rc=0
install_mcp_publisher || rc=$?
if [ "$rc" != "0" ]; then
  skip "mcp-publisher unavailable: ${MCP_PUBLISHER_ERROR}"
else
  PUB_HOME="${WORK_DIR}/pubhome"
  OLDPWD_SUITE="$PWD"
  # validate sends no token; method none with an empty token is what a
  # never-logged-in publisher pointed at this registry has.
  mcp_write_publisher_token "$PUB_HOME" "$(mcp_root "$REPO")" ""
  mkdir -p "${WORK_DIR}/pubgood" "${WORK_DIR}/pubbad"
  mcp_render_fixture "${CORPUS}/valid/minimal-remote.json" "${WORK_DIR}/pubgood/server.json" "SLUG=${SLUG}-pub"
  cp "${WORK_DIR}/bad.json" "${WORK_DIR}/pubbad/server.json"
  cd "${WORK_DIR}/pubgood" || fail_fatal "cd pubgood"
  good_rc=0
  mcp_publisher "$PUB_HOME" validate || good_rc=$?
  good_out="$MCP_PUBLISHER_OUT"
  cd "${WORK_DIR}/pubbad" || fail_fatal "cd pubbad"
  bad_rc=0
  mcp_publisher "$PUB_HOME" validate || bad_rc=$?
  bad_out="$MCP_PUBLISHER_OUT"
  cd "$OLDPWD_SUITE" || true
  if [ "$good_rc" != "0" ]; then
    fail "validate of a good document exited ${good_rc}" "$(head -c 600 "$good_out" 2>/dev/null)"
  elif [ "$bad_rc" = "0" ]; then
    fail "validate of a bad document exited 0" "$(head -c 600 "$bad_out" 2>/dev/null)"
  elif ! grep -qi 'description' "$bad_out" 2>/dev/null; then
    fail "the publisher output does not name the description issue" "$(head -c 600 "$bad_out" 2>/dev/null)"
  else
    pass
  fi
fi

end_suite
