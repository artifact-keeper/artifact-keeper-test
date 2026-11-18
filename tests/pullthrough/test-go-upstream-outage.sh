#!/usr/bin/env bash
# test-go-upstream-outage.sh -- Go metadata routes when the upstream cannot
# answer.
#
# Companion E2E for backend issue artifact-keeper#6214. When a Go Remote cannot
# get an answer from its upstream (5xx, 429, or no connection at all), `.mod`
# and `.zip` answer 502/503, but `@v/list`, `@latest` and `.info` answered 404,
# on the Remote and through a Virtual over it. `go` reads 404 and 410 as "this
# proxy does not have the module" and moves on to the next GOPROXY entry, so an
# outage turned into a fetch from `direct`, or into a "not found" build failure
# when the repository is the only entry.
#
# Expected, per the issue: the three routes answer like `.mod` on a Remote (502
# or 503) and 503 with Retry-After through a Virtual. 404 stays for an upstream
# that answered 404 or 410.
#
# The Remote's "upstream" is this suite's controllable mock
# (tests/lib/mock-upstream.py), which answers a fixed status per module:
#
#   example.com/ak-e2e/down500   500 on every route
#   example.com/ak-e2e/down429   429 on every route
#   example.com/ak-e2e/gone410   410 on every route (control: stays 404)
#   example.com/ak-e2e/absent    not served, 404 (control: stays 404)
#   example.com/ak-e2e/tagged    served (control: 200)
#
# A second Remote points at a host name that does not resolve, for the
# no-connection case.
#
# Requires: curl, jq. MOCK_UPSTREAM_HOSTNAME must name the runner pod for the
# backend (see tests/security/test-cache-poisoning.sh).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "go-upstream-outage"

if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; CI must set this to a name the backend can resolve to the test runner pod"
fi

auth_admin
setup_workdir

REMOTE_KEY="gou-remote-${RUN_ID}"
VIRTUAL_KEY="gou-virt-${RUN_ID}"
DEAD_REMOTE_KEY="gou-dead-${RUN_ID}"
DEAD_VIRTUAL_KEY="gou-dead-virt-${RUN_ID}"

# RFC 6761 reserves .invalid: the name never resolves, so the fetch fails
# before any connection.
DEAD_UPSTREAM="https://go-proxy.ak-e2e.invalid"

PREFIX="example.com/ak-e2e"
VERSION="v1.0.0"

# The three metadata routes under test, as path suffixes after the module.
METADATA_ROUTES="@v/list @latest @v/${VERSION}.info"

# route_status REPO_KEY MODULE SUFFIX -- prints the HTTP status.
route_status() {
  curl -s $CURL_TIMEOUT -o /dev/null -w '%{http_code}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/$1/$2/$3" 2>/dev/null || true
}

# route_status_and_retry_after REPO_KEY MODULE SUFFIX -- prints
# "<http status> <Retry-After value or 'none'>".
route_status_and_retry_after() {
  local headers status retry
  headers=$(curl -s $CURL_TIMEOUT -o /dev/null -D - \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/go/$1/$2/$3" 2>/dev/null || true)
  status=$(printf '%s\n' "$headers" | awk 'NR==1 {print $2}')
  retry=$(printf '%s\n' "$headers" | tr -d '\r' \
    | awk -F': *' 'tolower($1)=="retry-after" {print $2; exit}')
  echo "${status:-000} ${retry:-none}"
}

# assert_remote_outage REPO_KEY MODULE LABEL -- one test per metadata route:
# it must answer what `.mod` answers for the same module, and that must be a
# 502 or a 503.
assert_remote_outage() {
  local repo="$1" module="$2" label="$3" mod_status suffix status
  mod_status=$(route_status "$repo" "$module" "@v/${VERSION}.mod")

  begin_test "Remote, ${label}: .mod answers 502 or 503"
  case "$mod_status" in
    502|503) pass ;;
    *) fail "remote .mod for ${label}: expected 502 or 503, got '${mod_status}'" ;;
  esac

  for suffix in $METADATA_ROUTES; do
    begin_test "FIX #6214: remote, ${label}: ${suffix} answers like .mod"
    status=$(route_status "$repo" "$module" "$suffix")
    case "$status" in
      502|503)
        if assert_eq "$status" "$mod_status" "remote ${suffix} for ${label}: expected '${mod_status}' as on .mod, got '${status}'"; then
          pass
        fi
        ;;
      *) fail "remote ${suffix} for ${label}: expected '${mod_status}' as on .mod, got '${status}'" ;;
    esac
  done
}

# assert_virtual_outage REPO_KEY MODULE LABEL -- one test per route: 503 with
# a Retry-After header. `.mod` is the control, it already answered that way.
assert_virtual_outage() {
  local repo="$1" module="$2" label="$3" suffix answer status retry name
  for suffix in "@v/${VERSION}.mod" $METADATA_ROUTES; do
    name="FIX #6214: virtual, ${label}: ${suffix} answers 503 with Retry-After"
    [ "$suffix" = "@v/${VERSION}.mod" ] && name="Virtual, ${label}: .mod answers 503 with Retry-After"
    begin_test "$name"
    answer=$(route_status_and_retry_after "$repo" "$module" "$suffix")
    status="${answer%% *}"
    retry="${answer#* }"
    if [ "$status" != "503" ]; then
      fail "virtual ${suffix} for ${label}: expected 503, got '${status}'"
    elif [ "$retry" = "none" ]; then
      fail "virtual ${suffix} for ${label}: 503 without a Retry-After header"
    else
      pass
    fi
  done
}

# assert_still_404 REPO_KEY MODULE LABEL -- one test per metadata route.
assert_still_404() {
  local repo="$1" module="$2" label="$3" suffix status
  for suffix in $METADATA_ROUTES; do
    begin_test "${label}: ${suffix} answers 404"
    status=$(route_status "$repo" "$module" "$suffix")
    if assert_eq "$status" "404" "${label} ${suffix}: expected 404, got '${status}'"; then
      pass
    fi
  done
}

# ---------------------------------------------------------------------------
# Boot the mock upstream: one served module, a fixed status for the others
# ---------------------------------------------------------------------------

begin_test "Mock upstream starts with one served module and three failing ones"
if start_mock_upstream "${WORK_DIR}/mock-state"; then
  FILES="${MOCK_STATE_DIR}/files"
  mkdir -p "${FILES}/${PREFIX}/tagged/@v"
  printf '%s\n' "$VERSION" > "${FILES}/${PREFIX}/tagged/@v/list"
  jq -cn --arg v "$VERSION" '{Version: $v, Time: "2026-01-01T00:00:00Z"}' \
    | tee "${FILES}/${PREFIX}/tagged/@latest" > "${FILES}/${PREFIX}/tagged/@v/${VERSION}.info"
  printf 'module %s/tagged\n' "$PREFIX" > "${FILES}/${PREFIX}/tagged/@v/${VERSION}.mod"
  {
    echo "/${PREFIX}/down500/ 500"
    echo "/${PREFIX}/down429/ 429"
    echo "/${PREFIX}/gone410/ 410"
  } > "${MOCK_STATE_DIR}/status-prefixes"
  pass
else
  fail "mock upstream did not boot"
  end_suite
fi

begin_test "Mock answers 500, 429, 410 and 404 for the four unserved modules"
mock_answers=""
for module in down500 down429 gone410 absent; do
  mock_answers="${mock_answers} $(curl -s --max-time 10 -o /dev/null -w '%{http_code}' \
    "${MOCK_LOCAL_URL}/${PREFIX}/${module}/@v/list" 2>/dev/null || true)"
done
if assert_eq "$mock_answers" " 500 429 410 404" "the mock must answer 500, 429, 410 and 404, got '${mock_answers}'"; then
  pass
fi

# ---------------------------------------------------------------------------
# Repositories: a Remote over the mock, a Remote over a dead host, and a
# Virtual over each
# ---------------------------------------------------------------------------

begin_test "Create remote over the mock upstream and a virtual over it"
if create_remote_repo "$REMOTE_KEY" "go" "$MOCK_BASE_URL" \
    && create_virtual_repo "$VIRTUAL_KEY" "go" "$REMOTE_KEY"; then
  pass
else
  fail "could not create ${REMOTE_KEY} and ${VIRTUAL_KEY}"
  end_suite
fi

begin_test "Create remote over an unreachable upstream and a virtual over it"
if create_remote_repo "$DEAD_REMOTE_KEY" "go" "$DEAD_UPSTREAM" \
    && create_virtual_repo "$DEAD_VIRTUAL_KEY" "go" "$DEAD_REMOTE_KEY"; then
  pass
else
  fail "could not create ${DEAD_REMOTE_KEY} and ${DEAD_VIRTUAL_KEY}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Control: a module the upstream serves answers 200 on every route
# ---------------------------------------------------------------------------

for repo in "$REMOTE_KEY" "$VIRTUAL_KEY"; do
  begin_test "Served module answers 200 on the metadata routes through ${repo%-"${RUN_ID}"}"
  statuses=""
  for suffix in $METADATA_ROUTES; do
    statuses="${statuses} $(route_status "$repo" "${PREFIX}/tagged" "$suffix")"
  done
  if assert_eq "$statuses" " 200 200 200" "served module through ${repo}: expected 200 on @v/list, @latest and .info, got '${statuses}'"; then
    pass
  fi
done

# ---------------------------------------------------------------------------
# FIX #6214: an upstream that cannot answer is not a missing module
# ---------------------------------------------------------------------------

assert_remote_outage "$REMOTE_KEY" "${PREFIX}/down500" "upstream 500"
assert_remote_outage "$REMOTE_KEY" "${PREFIX}/down429" "upstream 429"
assert_remote_outage "$DEAD_REMOTE_KEY" "${PREFIX}/tagged" "upstream unreachable"

assert_virtual_outage "$VIRTUAL_KEY" "${PREFIX}/down500" "member upstream 500"
assert_virtual_outage "$VIRTUAL_KEY" "${PREFIX}/down429" "member upstream 429"
assert_virtual_outage "$DEAD_VIRTUAL_KEY" "${PREFIX}/tagged" "member upstream unreachable"

# ---------------------------------------------------------------------------
# Controls: an upstream that answered 404 or 410 is still a missing module
# ---------------------------------------------------------------------------

assert_still_404 "$REMOTE_KEY" "${PREFIX}/absent" "Remote, upstream 404"
assert_still_404 "$REMOTE_KEY" "${PREFIX}/gone410" "Remote, upstream 410"
assert_still_404 "$VIRTUAL_KEY" "${PREFIX}/absent" "Virtual, member upstream 404"
assert_still_404 "$VIRTUAL_KEY" "${PREFIX}/gone410" "Virtual, member upstream 410"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${DEAD_VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${DEAD_REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
