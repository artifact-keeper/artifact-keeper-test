#!/usr/bin/env bash
# test-go-virtual-untagged-list.sh -- Go virtual @v/list for a module with no
# tagged version.
#
# Companion E2E for backend issue artifact-keeper#6211. A Go module that exists
# but has no tagged version has an empty version list: the upstream answers
# `GET <module>/@v/list` with 200 and an empty body, and `go` then resolves the
# module through `@latest` (a pseudo-version). A Remote repository forwards
# that answer. A Virtual repository over the Remote answered `404 module not
# found` for the same request, so `go list -m -versions <module>@latest` and
# `go install <module>@latest` failed through the Virtual while they worked
# through its member.
#
# The Remote member's "upstream" is this suite's controllable mock
# (tests/lib/mock-upstream.py), so the empty list is deliberate and does not
# depend on a public module staying untagged:
#
#   example.com/ak-e2e/untagged   @v/list is 200 with an empty body, @latest
#                                 names a pseudo-version
#   example.com/ak-e2e/tagged     @v/list names v1.0.0 (control: a non-empty
#                                 list is unchanged)
#   example.com/ak-e2e/absent     not served (control: 404 stays 404)
#
# Requires: curl, jq. MOCK_UPSTREAM_HOSTNAME must name the runner pod for the
# backend (see tests/security/test-cache-poisoning.sh).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "go-virtual-untagged-list"

if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; CI must set this to a name the backend can resolve to the test runner pod"
fi

auth_admin
setup_workdir

REMOTE_KEY="gvu-remote-${RUN_ID}"
VIRTUAL_KEY="gvu-virt-${RUN_ID}"

UNTAGGED="example.com/ak-e2e/untagged"
TAGGED="example.com/ak-e2e/tagged"
ABSENT="example.com/ak-e2e/absent"
PSEUDO_VERSION="v0.0.0-20260101000000-0123456789ab"

# list_status_and_size REPO_KEY MODULE -- prints "<http status> <body bytes>".
list_status_and_size() {
  curl -s $CURL_TIMEOUT -o /dev/null -w '%{http_code} %{size_download}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/$1/$2/@v/list" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Boot the mock upstream and seed the three modules
# ---------------------------------------------------------------------------

begin_test "Mock upstream starts with an untagged and a tagged module"
if start_mock_upstream "${WORK_DIR}/mock-state"; then
  FILES="${MOCK_STATE_DIR}/files"
  mkdir -p "${FILES}/${UNTAGGED}/@v" "${FILES}/${TAGGED}/@v"
  : > "${FILES}/${UNTAGGED}/@v/list"
  jq -cn --arg v "$PSEUDO_VERSION" '{Version: $v, Time: "2026-01-01T00:00:00Z"}' \
    > "${FILES}/${UNTAGGED}/@latest"
  printf 'v1.0.0\n' > "${FILES}/${TAGGED}/@v/list"
  pass
else
  fail "mock upstream did not boot"
  end_suite
fi

begin_test "Mock serves the untagged module's list as 200 with an empty body"
mock_answer=$(curl -s --max-time 10 -o /dev/null -w '%{http_code} %{size_download}' \
  "${MOCK_LOCAL_URL}/${UNTAGGED}/@v/list" 2>/dev/null || true)
if assert_eq "$mock_answer" "200 0" "the mock must answer 200 with 0 bytes, got '${mock_answer}'"; then
  pass
fi

# ---------------------------------------------------------------------------
# Repositories: a Remote member over the mock, a Virtual over the Remote
# ---------------------------------------------------------------------------

begin_test "Create remote member pointing at the mock upstream"
if create_remote_repo "$REMOTE_KEY" "go" "$MOCK_BASE_URL"; then
  pass
else
  fail "could not create remote go repo ${REMOTE_KEY}"
  end_suite
fi

begin_test "Create virtual repository over the remote member"
if create_virtual_repo "$VIRTUAL_KEY" "go" "$REMOTE_KEY"; then
  pass
else
  fail "could not create virtual go repo ${VIRTUAL_KEY}"
  end_suite
fi

# ---------------------------------------------------------------------------
# The member's answer is the reference
# ---------------------------------------------------------------------------

begin_test "Remote member lists the untagged module as 200 with an empty body"
answer=$(list_status_and_size "$REMOTE_KEY" "$UNTAGGED")
if assert_eq "$answer" "200 0" "remote @v/list for an untagged module: expected '200 0', got '${answer}'"; then
  pass
fi

# ---------------------------------------------------------------------------
# FIX #6211: the Virtual answers as its member does
# ---------------------------------------------------------------------------

begin_test "FIX #6211: virtual lists the untagged module as 200 with an empty body"
answer=$(list_status_and_size "$VIRTUAL_KEY" "$UNTAGGED")
if assert_eq "$answer" "200 0" "virtual @v/list for an untagged module: expected '200 0' as on the member, got '${answer}'"; then
  pass
fi

begin_test "Virtual resolves the untagged module's @latest to the pseudo-version"
if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${VIRTUAL_KEY}/${UNTAGGED}/@latest" 2>/dev/null); then
  if assert_contains "$resp" "$PSEUDO_VERSION"; then
    pass
  fi
else
  fail "@latest through the virtual returned an error for the untagged module"
fi

# ---------------------------------------------------------------------------
# Controls: a tagged module and an absent module are unchanged
# ---------------------------------------------------------------------------

begin_test "Virtual lists the tagged module's version"
if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/${VIRTUAL_KEY}/${TAGGED}/@v/list" 2>/dev/null); then
  if assert_contains "$resp" "v1.0.0"; then
    pass
  fi
else
  fail "virtual @v/list returned an error for the tagged module"
fi

begin_test "Virtual answers 404 for a module no member knows"
answer=$(list_status_and_size "$VIRTUAL_KEY" "$ABSENT")
status="${answer%% *}"
if assert_eq "$status" "404" "virtual @v/list for an absent module: expected 404, got '${status}'"; then
  pass
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
