#!/usr/bin/env bash
# test-mcp-namespace-squatting.sh - who may publish under which server name
# (artifact-keeper#5253 threats T1/T2; docs/mcp-registry.md "Authentication
# and publishing" and "Repository settings (Phase 2 and 3)").
#
# Phase 1:
#   - io.modelcontextprotocol and every sub-namespace (including
#     io.modelcontextprotocol.anonymous) are reserved: 403
#     mcp_namespace_reserved, also for an administrator.
#   - mcp_namespace_allow is a prefix list on namespace boundaries:
#     "com.acme" admits com.acme/x and com.acme.team/x, not com.acmecorp/x;
#     anything else is 403 mcp_namespace_not_allowed. Lookalikes are not
#     normalised into the allowlist: an ASCII lookalike (rn for m) is simply a
#     different namespace (403), a Unicode confusable fails the name regex
#     (400 mcp_invalid_server_json).
#   - a repository without the allowlist accepts the same names (the
#     discriminating control: the 403s above come from the allowlist, not
#     from the names), the allowlist is echoed on the repository API, and a
#     PATCH is honoured by the next publish.
#
# Later phases, gated on behaviour (the settings are echoed by the scaffold
# even before enforcement lands, so an echo proves nothing):
#   - mcp_server_deny (Phase 2): a denied name is refused on publish (403
#     mcp_server_denied) and hidden on serve. Probe: publish a denied name;
#     200 means the deny list is not enforced here and those tests record a
#     plain skip.
#   - mcp_require_namespace_grant (Phase 3): plain repository write is not
#     enough (403 mcp_namespace_not_granted), a permission rule whose
#     conditions carry mcp_namespaces is (docs "Namespace grants"; the rule
#     is updated with PUT /api/v1/permissions/{id}, whose body is the full
#     create body). A pattern without `/` means that namespace's servers
#     (com.acme = com.acme/*), so it covers neither com.acme.team/x nor
#     another namespace. Probe: a write-grant user publishes with the setting
#     on; 200 means enforcement is absent and those tests record a plain skip.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-namespace-squatting"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
mcp_require_registry

ALLOW_KEY="sec-mcpns-${RUN_ID}"
OPEN_KEY="sec-mcpns-ctl-${RUN_ID}"
ACME="com.acme-${RUN_ID}"
REMOTE='[{"type":"streamable-http","url":"https://mcp.example.invalid/mcp"}]'

_doc_seq=0
remote_doc() {
  _doc_seq=$(( _doc_seq + 1 ))
  local f="${WORK_DIR}/doc-${_doc_seq}.json"
  mcp_server_json "$1" "${2:-1.0.0}" "" "$REMOTE" > "$f"
  echo "$f"
}

expect_problem() {
  local why
  if why=$(mcp_check_problem "$1" "$2"); then
    pass
  else
    fail "$3: ${why}"
  fi
}

# publish_expect REPO NAME STATUS [CODE] [AUTH]
publish_expect() {
  mcp_publish "$1" "$(remote_doc "$2")" "${5:-admin}"
  if [ "$3" = "200" ]; then
    if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.name')" = "$2" ]; then
      pass
    else
      fail "publish ${2} to ${1}: expected 200, got ${MCP_STATUS}: $(mcp_snip)"
    fi
  else
    expect_problem "$3" "${4:-}" "publish ${2} to ${1}"
  fi
}

repo_field() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/$1" 2>/dev/null \
    | jq -c "$2" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

begin_test "Create an allowlisted MCP repository and a control without the allowlist"
if mcp_create_repo "$ALLOW_KEY" "$(jq -cn --arg a "$ACME" '{mcp_namespace_allow:[$a]}')" \
  && mcp_create_repo "$OPEN_KEY"; then
  pass
else
  fail_fatal "MCP repository creation failed: ${MCP_CREATE_ERROR:-}"
fi

begin_test "GET /api/v1/repositories/{key} echoes mcp_namespace_allow"
got=$(repo_field "$ALLOW_KEY" '.mcp_namespace_allow')
want=$(jq -cn --arg a "$ACME" '[$a]')
if [ "$got" = "$want" ]; then
  pass
else
  fail "mcp_namespace_allow echoed as '${got}', expected '${want}'"
fi

# ---------------------------------------------------------------------------
# Reserved namespaces (both repositories: the reservation is not a setting)
# ---------------------------------------------------------------------------

for key in "$OPEN_KEY" "$ALLOW_KEY"; do
  for name in "io.modelcontextprotocol/x-${RUN_ID}" \
              "io.modelcontextprotocol.anonymous/x-${RUN_ID}" \
              "io.modelcontextprotocol.registry/x-${RUN_ID}" \
              "IO.ModelContextProtocol/x-${RUN_ID}"; do
    begin_test "Reserved: ${name%%/*} is refused on ${key} (403 mcp_namespace_reserved)"
    publish_expect "$key" "$name" 403 mcp_namespace_reserved
  done
done

begin_test "Reserved refusal holds for a write-grant user too"
if mcp_make_user "mcpns-w-${RUN_ID}" > "${WORK_DIR}/tok-w" && mcp_grant "$MCP_USER_ID" "$OPEN_KEY" '["read","write"]'; then
  TOK_W=$(cat "${WORK_DIR}/tok-w")
  publish_expect "$OPEN_KEY" "io.modelcontextprotocol/u-${RUN_ID}" 403 mcp_namespace_reserved "$TOK_W"
else
  TOK_W=""
  fail "could not create the write-grant user: $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Allowlist prefix matching
# ---------------------------------------------------------------------------

begin_test "Allowlist admits the exact namespace ${ACME}/x"
publish_expect "$ALLOW_KEY" "${ACME}/x" 200

begin_test "Allowlist admits a sub-namespace ${ACME}.team/x"
publish_expect "$ALLOW_KEY" "${ACME}.team/x" 200

LOOKALIKES=("${ACME}corp/x" "com.acrne-${RUN_ID}/x" "com.acme-${RUN_ID}-evil/x" "evil.${ACME}/x" "com.acm-${RUN_ID}/x")
for name in "${LOOKALIKES[@]}"; do
  begin_test "Allowlist refuses ${name%%/*} (403 mcp_namespace_not_allowed)"
  publish_expect "$ALLOW_KEY" "$name" 403 mcp_namespace_not_allowed
done

# Cyrillic a (U+0430) in place of the Latin a: the name regex is ASCII only.
CONFUSABLE="com.$(printf '\xd0\xb0')cme-${RUN_ID}/x"
begin_test "A Unicode confusable of the allowed namespace fails the name regex (400)"
publish_expect "$ALLOW_KEY" "$CONFUSABLE" 400 mcp_invalid_server_json

begin_test "Control: the repository without an allowlist accepts the same names"
ctl_bad=""
for name in "${LOOKALIKES[@]}"; do
  mcp_publish "$OPEN_KEY" "$(remote_doc "$name")"
  [ "$MCP_STATUS" = "200" ] || ctl_bad="${ctl_bad} ${name}=${MCP_STATUS}"
done
if [ -z "$ctl_bad" ]; then
  pass
else
  fail "the control repository refused names the allowlist test relies on:${ctl_bad}" \
    "Without this control the 403s above could come from the names themselves rather than from mcp_namespace_allow."
fi

begin_test "Control: the confusable is refused without an allowlist too (regex, not allowlist)"
publish_expect "$OPEN_KEY" "$CONFUSABLE" 400 mcp_invalid_server_json

# ---------------------------------------------------------------------------
# PATCH is honoured on the next publish
# ---------------------------------------------------------------------------

OTHER_NS="org.other-${RUN_ID}"
begin_test "PATCH mcp_namespace_allow to [${OTHER_NS}] is accepted and echoed"
if mcp_patch_repo "$ALLOW_KEY" "$(jq -cn --arg a "$OTHER_NS" '{mcp_namespace_allow:[$a]}')"; then
  got=$(repo_field "$ALLOW_KEY" '.mcp_namespace_allow')
  if [ "$got" = "$(jq -cn --arg a "$OTHER_NS" '[$a]')" ]; then
    pass
  else
    fail "after PATCH mcp_namespace_allow echoes '${got}'"
  fi
else
  fail "PATCH mcp_namespace_allow: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "After the PATCH the old namespace is refused (403)"
publish_expect "$ALLOW_KEY" "${ACME}/after-patch" 403 mcp_namespace_not_allowed

begin_test "After the PATCH the new namespace is admitted (200)"
publish_expect "$ALLOW_KEY" "${OTHER_NS}/after-patch" 200

begin_test "Versions published under the old allowlist are still served"
mcp_get "$ALLOW_KEY" "$(mcp_version_path "${ACME}/x" 1.0.0)" anon
if [ "$MCP_STATUS" = "200" ]; then
  pass
else
  fail "${ACME}/x after the allowlist change: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# mcp_server_deny (Phase 2): behaviour probe, per-test skip when absent
# ---------------------------------------------------------------------------

DENY_KEY="sec-mcpns-deny-${RUN_ID}"
DENY_GLOB="com.deny-${RUN_ID}/*"
DENY_DEFER=""
begin_test "mcp_server_deny: fixture repository with an already published name"
if mcp_create_repo "$DENY_KEY"; then
  mcp_publish "$DENY_KEY" "$(remote_doc "com.deny-${RUN_ID}/existing")"
  if [ "$MCP_STATUS" = "200" ]; then
    pass
  else
    fail "seed publish before the deny list: HTTP ${MCP_STATUS}: $(mcp_snip)"
  fi
else
  fail "deny fixture repository: ${MCP_CREATE_ERROR:-}"
fi

begin_test "mcp_server_deny: a denied name is refused on publish (403)"
if ! mcp_patch_repo "$DENY_KEY" "$(jq -cn --arg g "$DENY_GLOB" '{mcp_server_deny:[$g]}')"; then
  DENY_DEFER="PATCH mcp_server_deny answered HTTP ${MCP_STATUS}"
else
  mcp_publish "$DENY_KEY" "$(remote_doc "COM.Deny-${RUN_ID}/New")"
  if [ "$MCP_STATUS" = "200" ]; then
    DENY_DEFER="a name matching mcp_server_deny ${DENY_GLOB} (case-folded) published with 200"
  fi
fi
if [ -n "$DENY_DEFER" ]; then
  skip "mcp_server_deny not enforced by this backend (${DENY_DEFER}); Phase 2 capability"
else
  expect_problem 403 mcp_server_denied "publish of a denied name"
fi

begin_test "mcp_server_deny: an earlier version of a denied name is hidden from readers"
if [ -n "$DENY_DEFER" ]; then
  skip "mcp_server_deny not enforced by this backend (${DENY_DEFER}); Phase 2 capability"
else
  mcp_get "$DENY_KEY" "$(mcp_version_path "com.deny-${RUN_ID}/existing" 1.0.0)" anon
  if why=$(mcp_check_plain_404); then
    pass
  else
    fail "denied name still served: ${why}"
  fi
fi

# ---------------------------------------------------------------------------
# mcp_require_namespace_grant (Phase 3): behaviour probe, per-test skip
# ---------------------------------------------------------------------------

GRANT_KEY="sec-mcpns-grant-${RUN_ID}"
GRANT_DEFER=""
G_TOK=""
begin_test "Namespace grants: fixture repository, write-grant user, setting on"
if mcp_require_feature mcp_namespace_grants; then
  if mcp_create_repo "$GRANT_KEY" \
    && mcp_make_user "mcpns-g-${RUN_ID}" > "${WORK_DIR}/tok-g" \
    && mcp_grant "$MCP_USER_ID" "$GRANT_KEY" '["read","write"]'; then
    G_TOK=$(cat "${WORK_DIR}/tok-g")
    G_USER_ID="$MCP_USER_ID"
    G_PERM_ID=$(mcp_json '.id // empty')
    if mcp_patch_repo "$GRANT_KEY" '{"mcp_require_namespace_grant":true}'; then
      echoed=$(repo_field "$GRANT_KEY" '.mcp_require_namespace_grant')
      echo "  mcp_require_namespace_grant echoed as: ${echoed:-<absent>}"
      pass
    else
      GRANT_DEFER="PATCH mcp_require_namespace_grant answered HTTP ${MCP_STATUS}"
      skip "mcp_require_namespace_grant not accepted by this backend (${GRANT_DEFER}); Phase 3 capability"
    fi
  else
    fail "namespace-grant fixtures failed: ${MCP_CREATE_ERROR:-} $(mcp_snip)"
    GRANT_DEFER="fixture failure"
  fi
else
  GRANT_DEFER="feature flag layer says mcp_namespace_grants is absent"
fi

begin_test "Namespace grants: plain repository write is not enough (403)"
if [ -n "$GRANT_DEFER" ]; then
  skip "mcp_require_namespace_grant not testable here (${GRANT_DEFER}); Phase 3 capability"
else
  mcp_publish "$GRANT_KEY" "$(remote_doc "${ACME}/plain-write")" "$G_TOK"
  if [ "$MCP_STATUS" = "200" ]; then
    GRANT_DEFER="with mcp_require_namespace_grant=true a plain write grant published ${ACME}/plain-write with 200"
    skip "mcp_require_namespace_grant not enforced by this backend (${GRANT_DEFER}); Phase 3 capability"
  else
    expect_problem 403 mcp_namespace_not_granted "publish with plain write under mcp_require_namespace_grant"
  fi
fi

begin_test "Namespace grants: a grant conditioned on mcp_namespaces [${ACME}] admits that namespace (200)"
if [ -n "$GRANT_DEFER" ]; then
  skip "mcp_require_namespace_grant not testable here (${GRANT_DEFER}); Phase 3 capability"
else
  # PUT takes the full create body (CreatePermissionRequest).
  body=$(jq -cn --arg u "$G_USER_ID" --arg r "$(mcp_repo_id "$GRANT_KEY")" --arg a "$ACME" \
    '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,
      actions:["read","write"],conditions:{mcp_namespaces:[$a]}}')
  mcp_req PUT "${BASE_URL}/api/v1/permissions/${G_PERM_ID}" admin -H "Content-Type: application/json" -d "$body"
  if [ "${MCP_STATUS:0:1}" != "2" ]; then
    fail "PUT /api/v1/permissions/{id} with conditions.mcp_namespaces: HTTP ${MCP_STATUS}: $(mcp_snip)"
  else
    mcp_publish "$GRANT_KEY" "$(remote_doc "${ACME}/granted")" "$G_TOK"
    if [ "$MCP_STATUS" = "200" ]; then
      pass
    else
      fail "namespace-conditioned grant publish of ${ACME}/granted: HTTP ${MCP_STATUS}: $(mcp_snip)"
    fi
  fi
fi

begin_test "Namespace grants: [${ACME}] covers neither a sub-namespace nor another namespace (403)"
if [ -n "$GRANT_DEFER" ]; then
  skip "mcp_require_namespace_grant not testable here (${GRANT_DEFER}); Phase 3 capability"
else
  mcp_publish "$GRANT_KEY" "$(remote_doc "${ACME}.team/x")" "$G_TOK"
  sub_why=$(mcp_check_problem 403 mcp_namespace_not_granted) || true
  mcp_publish "$GRANT_KEY" "$(remote_doc "org.elsewhere-${RUN_ID}/x")" "$G_TOK"
  other_why=$(mcp_check_problem 403 mcp_namespace_not_granted) || true
  if [ -z "$sub_why" ] && [ -z "$other_why" ]; then
    pass
  else
    fail "namespace-conditioned grant outside its namespace: sub-namespace ${ACME}.team/x: ${sub_why:-ok}; org.elsewhere: ${other_why:-ok}"
  fi
fi

end_suite
