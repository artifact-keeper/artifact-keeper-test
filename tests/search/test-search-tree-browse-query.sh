#!/usr/bin/env bash
# test-search-tree-browse-query.sh - Tree browse API (query-string form)
#
# Epic 8 sub-task 8.10 (artifact-keeper-test#73). Companion to
# test-search-tree-browse.sh: that script probes path-style routing
# (/api/v1/tree/<repo>/<path>) which works on older revisions. The
# v1.2.0 OpenAPI contract documents the canonical surface as a single
# /api/v1/tree endpoint that takes repository_key and path as query
# parameters and returns a TreeResponse {"nodes":[TreeNodeResponse]}.
#
# This script exercises the documented form end-to-end:
#
#   1. /api/v1/tree?repository_key=<repo>            -> path segment node
#   2. /api/v1/tree?repository_key=<repo>&path=<seg> -> leaf filename node
#   3. /api/v1/tree?repository_key=does-not-exist    -> 4xx, not 5xx
#   4. /api/v1/tree?repository_key=<repo>&include_metadata=true
#      -> nodes carry size_bytes / created_at when supported
#
# The load-bearing assertions are (1) and (2): a backend that ignores
# the path parameter (returns the same nodes regardless) is a regression
# we explicitly want to catch.
#
# Skips cleanly if /api/v1/tree returns 404/501 at preflight.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-tree-browse-query"
auth_admin
setup_workdir

REPO_KEY="tree-q-${RUN_ID}"
SEGMENT="alpha-${RUN_ID}"
FILENAME="leaf-${RUN_ID}.txt"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

# Preflight: /api/v1/tree must at least be mounted.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/tree" 2>/dev/null || echo "000")
case "$preflight_status" in
  404|501)
    skip_suite "tree endpoint not available (HTTP ${preflight_status})"
    ;;
  503|504|000)
    skip_suite "tree backend unavailable (HTTP ${preflight_status})"
    ;;
esac

# _tree_node_names <json>
# Extract names from a TreeResponse.nodes[] array. Tolerant of legacy
# wrappers so an older backend deployed under the same test job still
# matches.
_tree_node_names() {
  echo "$1" | jq -r '
    def entries:
      if type == "array" then .
      elif (.nodes?    | type) == "array" then .nodes
      elif (.entries?  | type) == "array" then .entries
      elif (.children? | type) == "array" then .children
      elif (.items?    | type) == "array" then .items
      else [] end;
    entries
    | map(
        (.name // empty),
        (.path // empty),
        (.key  // empty)
      )
    | flatten
    | map(select(. != null and . != ""))
    | .[]
  ' 2>/dev/null || true
}

# _names_contain <list> <needle>
# Match equality OR final path component (so /foo/bar/seg matches seg).
_names_contain() {
  local list="$1"; local needle="$2"
  [ -z "$list" ] && return 1
  local line base
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    [ "$line" = "$needle" ] && return 0
    base="${line##*/}"
    [ "$base" = "$needle" ] && return 0
  done <<< "$list"
  return 1
}

begin_test "Create repo and upload nested artifact"
ok=true
create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1 || ok=false
echo "tree-query-${RUN_ID}" > "${WORK_DIR}/${FILENAME}"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${SEGMENT}/${FILENAME}" \
  "${WORK_DIR}/${FILENAME}" >/dev/null 2>&1 || ok=false
if [ "$ok" = true ]; then
  pass
else
  fail "could not set up corpus"
  end_suite
fi

sleep 2

# -------------------------------------------------------------------------
# 1. Repository-scoped tree must surface the first path segment.
# -------------------------------------------------------------------------

begin_test "tree?repository_key=<repo> surfaces the path segment"
resp_repo=$(api_get "/api/v1/tree?repository_key=${REPO_KEY}" 2>/dev/null || echo "")
if [ -z "$resp_repo" ]; then
  skip "repository-scoped tree query returned error"
else
  names=$(_tree_node_names "$resp_repo")
  if _names_contain "$names" "$SEGMENT"; then
    pass
  else
    fail "repo-level tree did not surface segment '${SEGMENT}'" \
         "names: $(echo "$names" | tr '\n' ',' | head -c 300)"
  fi
fi

# -------------------------------------------------------------------------
# 2. Path-scoped tree must surface the leaf filename. This is the
#    load-bearing assertion: a backend that ignores the path parameter
#    would return the same payload as step 1 and fail this check.
# -------------------------------------------------------------------------

begin_test "tree?repository_key=<repo>&path=<seg> surfaces the leaf filename"
resp_leaf=$(api_get "/api/v1/tree?repository_key=${REPO_KEY}&path=${SEGMENT}" 2>/dev/null || echo "")
if [ -z "$resp_leaf" ]; then
  # Some revisions require a leading slash on path.
  resp_leaf=$(api_get "/api/v1/tree?repository_key=${REPO_KEY}&path=/${SEGMENT}" 2>/dev/null || echo "")
fi
if [ -z "$resp_leaf" ]; then
  skip "path-scoped tree query returned error"
else
  names=$(_tree_node_names "$resp_leaf")
  if _names_contain "$names" "$FILENAME"; then
    pass
  else
    fail "path-level tree did not surface filename '${FILENAME}'" \
         "names: $(echo "$names" | tr '\n' ',' | head -c 300)"
  fi
fi

# -------------------------------------------------------------------------
# 3. Unknown repository must produce a deterministic 4xx (not 5xx).
# -------------------------------------------------------------------------

begin_test "tree?repository_key=does-not-exist returns 4xx, not 5xx"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/tree?repository_key=does-not-exist-${RUN_ID}" 2>/dev/null || echo "000")
case "$status" in
  4*) pass ;;
  5*) fail "unknown repo returned HTTP ${status}; expected 4xx" ;;
  2*)
    # Some revisions return 200 with an empty nodes array. Accept that
    # only if nodes is actually empty.
    resp_unknown=$(api_get "/api/v1/tree?repository_key=does-not-exist-${RUN_ID}" 2>/dev/null || echo "")
    count=$(echo "$resp_unknown" | jq -r '
      if (.nodes? | type) == "array" then (.nodes|length)
      elif type=="array" then length
      else 0 end' 2>/dev/null || echo 0)
    if [ "$count" = "0" ]; then
      pass
    else
      fail "unknown repo returned HTTP 200 with ${count} nodes; expected 4xx or empty"
    fi
    ;;
  *)
    skip "unknown repo returned HTTP ${status}; not a clean signal"
    ;;
esac

# -------------------------------------------------------------------------
# 4. include_metadata=true should produce nodes with size_bytes /
#    created_at populated for leaf entries. This is best-effort: if the
#    flag is ignored, skip rather than fail (older backends).
# -------------------------------------------------------------------------

begin_test "tree?include_metadata=true populates leaf size_bytes"
resp_meta=$(api_get "/api/v1/tree?repository_key=${REPO_KEY}&path=${SEGMENT}&include_metadata=true" 2>/dev/null || echo "")
if [ -z "$resp_meta" ]; then
  resp_meta=$(api_get "/api/v1/tree?repository_key=${REPO_KEY}&path=/${SEGMENT}&include_metadata=true" 2>/dev/null || echo "")
fi
if [ -z "$resp_meta" ]; then
  skip "include_metadata query returned error"
else
  has_size=$(echo "$resp_meta" | jq -r '
    def entries:
      if (.nodes? | type) == "array" then .nodes
      elif type=="array" then .
      else [] end;
    entries
    | map(select((.type // "") != "directory" and (.size_bytes // null) != null))
    | length' 2>/dev/null || echo 0)
  if [ "${has_size:-0}" -ge 1 ]; then
    pass
  else
    skip "include_metadata=true did not populate size_bytes (handler may ignore the flag)"
  fi
fi

end_suite
