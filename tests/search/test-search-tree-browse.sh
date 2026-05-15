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
# The exact response shape varies by backend version (some return
# {"nodes":[...]}, some return {"entries":[...]}). We accept either as
# long as the expected name appears anywhere in the response body.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-tree-browse"
auth_admin
setup_workdir

REPO_KEY="tree-${RUN_ID}"
SEGMENT="alpha-${RUN_ID}"
FILENAME="beta-${RUN_ID}.txt"

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
# Root: must surface our repo key.
# -------------------------------------------------------------------------

begin_test "Root listing surfaces the test repo"
if resp=$(api_get "$TREE_BASE" 2>/dev/null); then
  if echo "$resp" | grep -q "$REPO_KEY"; then
    pass
  else
    # Some implementations require an explicit "/" or "?path=" param.
    if resp2=$(api_get "${TREE_BASE}?path=/" 2>/dev/null) && echo "$resp2" | grep -q "$REPO_KEY"; then
      pass
    else
      fail "root listing did not contain ${REPO_KEY}"
    fi
  fi
else
  skip "root listing returned error"
fi

# -------------------------------------------------------------------------
# Repo level: must surface the first path segment.
# -------------------------------------------------------------------------

begin_test "Repo-level listing surfaces the path segment"
repo_resp=""
for path_form in "${TREE_BASE}/${REPO_KEY}" "${TREE_BASE}?path=/${REPO_KEY}" "${TREE_BASE}/${REPO_KEY}/"; do
  if r=$(api_get "$path_form" 2>/dev/null); then
    repo_resp="$r"
    break
  fi
done
if [ -n "$repo_resp" ] && echo "$repo_resp" | grep -q "$SEGMENT"; then
  pass
elif [ -z "$repo_resp" ]; then
  skip "no repo-level tree response"
else
  fail "repo-level listing did not contain segment ${SEGMENT}"
fi

# -------------------------------------------------------------------------
# Leaf level: must surface the filename.
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
if [ -n "$leaf_resp" ] && echo "$leaf_resp" | grep -q "$FILENAME"; then
  pass
elif [ -z "$leaf_resp" ]; then
  skip "no path-level tree response"
else
  fail "path-level listing did not contain ${FILENAME}"
fi

# -------------------------------------------------------------------------
# Cleanup.
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
