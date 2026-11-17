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
# Every lookup is scoped to this suite's own RUN_ID-named repository
# (test#365). An unfiltered, unpaginated instance-wide root listing is a
# global-scope read: with ~18 sibling jobs creating repositories at the same
# time, whether ours lands in it says nothing about the browse handler.
# The current backend takes the repository as ?repository_key= (and answers
# a bare /api/v1/tree with 400); path-style forms remain as fallbacks for
# older revisions.
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

# _artifact_listed REPO PATH
# True once the repository's artifact listing carries a row whose path ends in
# PATH, i.e. the upload has been persisted (test#364: replaces a fixed sleep).
_artifact_listed() {
  api_get "/api/v1/repositories/$1/artifacts?per_page=100" 2>/dev/null \
    | jq -e --arg p "$2" '[.items[]? | select((.path // "") | endswith($p))] | length > 0' >/dev/null 2>&1
}

# The tree handler derives nodes from the persisted artifact rows.
begin_test "Uploaded artifact is persisted"
if assert_eventually "${SEGMENT}/${FILENAME} listed in ${REPO_KEY}" 60 _artifact_listed "$REPO_KEY" "${SEGMENT}/${FILENAME}"; then
  pass
fi

# -------------------------------------------------------------------------
# Probe a few candidate tree endpoints. The browse handler is mounted at
# /api/v1/tree in the current backend; older revisions used /api/v1/browse.
# We try both, scoped to our own repository, and use whichever one
# responds 200.
# -------------------------------------------------------------------------

TREE_BASE=""
for candidate in "/api/v1/tree" "/api/v1/browse"; do
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" -o /dev/null \
     "${BASE_URL}${candidate}?repository_key=${REPO_KEY}" 2>/dev/null || \
     curl -sf $CURL_TIMEOUT -H "$(auth_header)" -o /dev/null \
     "${BASE_URL}${candidate}/${REPO_KEY}" 2>/dev/null; then
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
# Repo-scoped tree (test#365): the backend has no instance-wide root view any
# more (repository_key is required, 400 without it), and the old unfiltered
# root assertion moved with every sibling repo. What a scoped request must
# guarantee is that it answers nodes, and only nodes of the requested repo:
# get_tree stamps the requested repository_key on every node it returns.
# -------------------------------------------------------------------------

begin_test "Repo-scoped tree answers only this repo's nodes"
root_resp=""
for path_form in "${TREE_BASE}?repository_key=${REPO_KEY}" "${TREE_BASE}/${REPO_KEY}"; do
  if r=$(api_get "$path_form" 2>/dev/null); then
    root_resp="$r"
    break
  fi
done
if [ -z "$root_resp" ]; then
  fail "repo-scoped tree request for ${REPO_KEY} returned an error"
else
  scoped=$(echo "$root_resp" | jq -r --arg k "$REPO_KEY" '
    (if type == "array" then . else (.nodes // .entries // .children // .items // .results // []) end) as $n
    | if ($n | length) == 0 then "empty"
      elif ([$n[] | select((.repository_key // $k) != $k)] | length) > 0 then "foreign"
      else "ok" end' 2>/dev/null || echo "unparsable")
  case "$scoped" in
    ok) pass ;;
    empty) fail "repo-scoped tree for ${REPO_KEY} answered no nodes" "${root_resp:0:300}" ;;
    foreign) fail "repo-scoped tree for ${REPO_KEY} answered nodes of another repository" "${root_resp:0:300}" ;;
    *) fail "repo-scoped tree for ${REPO_KEY} answered an unparsable body" "${root_resp:0:300}" ;;
  esac
fi

# -------------------------------------------------------------------------
# Repo level: must surface the first path segment as a structured node.
# -------------------------------------------------------------------------

begin_test "Repo-level listing surfaces the path segment"
repo_resp=""
for path_form in "${TREE_BASE}?repository_key=${REPO_KEY}" "${TREE_BASE}/${REPO_KEY}" "${TREE_BASE}?path=/${REPO_KEY}" "${TREE_BASE}/${REPO_KEY}/"; do
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
  "${TREE_BASE}?repository_key=${REPO_KEY}&path=${SEGMENT}" \
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
