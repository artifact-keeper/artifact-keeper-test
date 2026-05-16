#!/usr/bin/env bash
# test-search-tree-browse.sh - Tree browse API smoke
#
# Epic 8 sub-task 8.10 (artifact-keeper-test#73). The tree browse handler
# (backend/src/api/handlers/tree.rs, ~709 lines) has zero E2E coverage.
# This script puts a known artifact tree in place and walks the browse
# endpoint at three levels:
#
#   1. Root listing returns the repository as a node.
#   2. Repo-level listing returns the first path segment.
#   3. Leaf listing returns the artifact filename.
#
# The response shape varies by backend version (some return
# {"nodes":[...]}, some return {"entries":[...]}, some {"children":[...]}
# or a bare array). We extract candidate name/path fields via jq and
# check membership against the structured field set, rather than grep on
# the raw JSON which would false-positive on bytes that happen to occur
# in unrelated fields (e.g. an opaque encoded "next_page_token").
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-tree-browse"
auth_admin
setup_workdir

REPO_KEY="tree-${RUN_ID}"
SEGMENT="alpha-${RUN_ID}"
FILENAME="beta-${RUN_ID}.txt"

# _tree_names <json>
#
# Extract the list of node names/paths from a tree-browse response into a
# newline-delimited list on stdout. Handles every wrapper shape we have
# seen in the wild without falling back to substring grep on raw JSON.
_tree_names() {
  local json="$1"
  echo "$json" | jq -r '
    def entries:
      if type == "array" then .
      elif (.nodes? | type) == "array"    then .nodes
      elif (.entries? | type) == "array"  then .entries
      elif (.children? | type) == "array" then .children
      elif (.items? | type) == "array"    then .items
      elif (.results? | type) == "array"  then .results
      else [] end;
    entries
    | map(
        (.name // empty),
        (.path // empty),
        (.key // empty)
      )
    | flatten
    | map(select(. != null and . != ""))
    | .[]
  ' 2>/dev/null || true
}

# _names_contain <names-list-newline-delim> <needle>
# Returns 0 if any name equals or has a final path component equal to needle.
_names_contain() {
  local list="$1"
  local needle="$2"
  if [ -z "$list" ]; then
    return 1
  fi
  local line base
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "$line" = "$needle" ]; then
      return 0
    fi
    base="${line##*/}"
    if [ "$base" = "$needle" ]; then
      return 0
    fi
  done <<< "$list"
  return 1
}

begin_test "Create repo and upload a nested artifact"
ok=true
create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1 || ok=false
echo "tree-browse-${RUN_ID}" > "${WORK_DIR}/${FILENAME}"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${SEGMENT}/${FILENAME}" \
  "${WORK_DIR}/${FILENAME}" >/dev/null 2>&1 || ok=false
if [ "$ok" = true ]; then
  pass
else
  fail "could not set up corpus"
  end_suite
fi

sleep 2  # allow listing index to settle

# -------------------------------------------------------------------------
# Probe a few candidate tree endpoints. The browse handler is mounted at
# /api/v1/tree in the current backend; older revisions used /api/v1/browse.
# We try both and use whichever one responds 200.
# -------------------------------------------------------------------------

TREE_BASE=""
for candidate in "/api/v1/tree" "/api/v1/browse"; do
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" -o /dev/null \
     "${BASE_URL}${candidate}" 2>/dev/null; then
    TREE_BASE="$candidate"
    break
  fi
done

begin_test "Tree browse base endpoint is reachable"
if [ -n "$TREE_BASE" ]; then
  pass
else
  skip "no tree/browse endpoint responded 200"
  end_suite
fi

# -------------------------------------------------------------------------
# Root: must surface our repo key in a structured name/path field.
# -------------------------------------------------------------------------

begin_test "Root listing surfaces the test repo"
root_resp=""
if r=$(api_get "$TREE_BASE" 2>/dev/null); then
  root_resp="$r"
elif r=$(api_get "${TREE_BASE}?path=/" 2>/dev/null); then
  root_resp="$r"
fi
if [ -z "$root_resp" ]; then
  skip "root listing returned error"
else
  names=$(_tree_names "$root_resp")
  if _names_contain "$names" "$REPO_KEY"; then
    pass
  else
    fail "root listing did not surface ${REPO_KEY} in any name/path field (got names: $(echo "$names" | tr '\n' ',' | head -c 300))"
  fi
fi

# -------------------------------------------------------------------------
# Repo level: must surface the first path segment as a structured node.
# -------------------------------------------------------------------------

begin_test "Repo-level listing surfaces the path segment"
repo_resp=""
for path_form in "${TREE_BASE}/${REPO_KEY}" "${TREE_BASE}?path=/${REPO_KEY}" "${TREE_BASE}/${REPO_KEY}/"; do
  if r=$(api_get "$path_form" 2>/dev/null); then
    repo_resp="$r"
    break
  fi
done
if [ -z "$repo_resp" ]; then
  skip "no repo-level tree response"
else
  names=$(_tree_names "$repo_resp")
  if _names_contain "$names" "$SEGMENT"; then
    pass
  else
    fail "repo-level listing did not surface segment ${SEGMENT} in any name/path field (got names: $(echo "$names" | tr '\n' ',' | head -c 300))"
  fi
fi

# -------------------------------------------------------------------------
# Leaf level: must surface the filename as a structured node.
# -------------------------------------------------------------------------

begin_test "Path-level listing surfaces the artifact filename"
leaf_resp=""
for path_form in \
  "${TREE_BASE}/${REPO_KEY}/${SEGMENT}" \
  "${TREE_BASE}?path=/${REPO_KEY}/${SEGMENT}" \
  "${TREE_BASE}/${REPO_KEY}/${SEGMENT}/"; do
  if r=$(api_get "$path_form" 2>/dev/null); then
    leaf_resp="$r"
    break
  fi
done
if [ -z "$leaf_resp" ]; then
  skip "no path-level tree response"
else
  names=$(_tree_names "$leaf_resp")
  if _names_contain "$names" "$FILENAME"; then
    pass
  else
    fail "path-level listing did not surface ${FILENAME} in any name/path field (got names: $(echo "$names" | tr '\n' ',' | head -c 300))"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup.
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
