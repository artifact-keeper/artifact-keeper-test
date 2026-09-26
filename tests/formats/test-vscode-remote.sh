#!/usr/bin/env bash
# test-vscode-remote.sh - VS Code/Open VSX gallery gateway E2E test
#
# Contract tests for the experimental Open VSX pull-through gateway: a
# public VS Code Remote repository whose upstream_url is an Open VSX gallery
# adapter root (e.g. https://open-vsx.org/vscode/gallery). Ported from the
# disposable dogfood harness's `probe` subcommand (artifact-keeper PR #3253,
# scripts/dogfood-vscode-openvsx.sh, docs/vscode-openvsx-gateway.md) so the
# release gate exercises the manifest / gallery-query / latest-lookup /
# AK-asset-URL-rewrite contract headlessly, without a real VSCodium or
# code-server install.
#
# Ported behavior:
#   - GET  {gallery}/manifest names AK's extensionquery + latest endpoints
#   - POST {gallery}/extensionquery, with the exact VS Code client request
#     body shape, resolves the reviewed extension and rewrites every asset
#     URL onto AK
#   - GET  {gallery}/{publisher}/{name}/latest resolves the same way
#   - GET  {gallery}/vscode/{publisher}/{name}/latest (the code-server
#     compatibility alias) resolves the same way
#
# NOT ported: the dogfood script's vscodium-ui, code-server-ui, install-*,
# update-*, and TRACE_NETWORK subcommands drive a real VS Code-family client
# against an isolated profile. That doesn't fit a headless, 120s-per-script
# release-gate suite, and per-suite the gate deploy also has no VSCodium/
# code-server binary on PATH.
#
# Known bug fixed while porting: the dogfood script's own inline jq asset-
# URL assertions built `[.assetUri?, .fallbackAssetUri?, (.files[]?.source?)]`
# without filtering nulls before `all(startswith($prefix))`. The `?` suffix
# suppresses jq TYPE errors, not missing keys -- a version object lacking
# `fallbackAssetUri` still yields `null` for that slot, and `null |
# startswith(_)` is a jq runtime error. That aborts the whole `jq -e` with a
# non-zero exit, which the caller reads as "retains a non-AK asset URL" --
# the opposite of the truth. Every assertion below null-filters first (see
# _assert_asset_urls_ak_owned), matching the shape of the dogfood script's
# OWN fixed assert_ak_urls helper rather than its buggy inline duplicates.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "vscode-remote"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq

REPO_KEY="test-vscode-remote-${RUN_ID}"
UPSTREAM_URL="https://open-vsx.org/vscode/gallery"
GALLERY_URL="${BASE_URL}/vscode/${REPO_KEY}/gallery"
AK_PREFIX="${BASE_URL}/vscode/${REPO_KEY}/"

# A small, stable, popular extension -- the same reviewed dogfood candidate
# the upstream harness restricts itself to (accidental arbitrary-install
# prevention lives in the dogfood script; irrelevant here since we only GET/
# POST gallery metadata, never install anything).
EXTENSION_PUBLISHER="redhat"
EXTENSION_NAME="vscode-yaml"
EXTENSION_ID="${EXTENSION_PUBLISHER}.${EXTENSION_NAME}"

# ---------------------------------------------------------------------------
# Helper: null-filtered "every asset URL is AK-owned" assertion
#
# Usage:
#   _assert_asset_urls_ak_owned FILE VERSIONS_JQ_EXPR PREFIX
#
# VERSIONS_JQ_EXPR is a jq expression (evaluated against FILE's root) that
# produces a stream of version objects, e.g. '.versions[]' for a /latest
# response or '.results[].extensions[].versions[]?' for an extensionquery
# response. Checks .assetUri, .fallbackAssetUri, and every .files[].source
# across that stream all start with PREFIX.
# ---------------------------------------------------------------------------
_assert_asset_urls_ak_owned() {
  local file="$1"
  local versions_expr="$2"
  local prefix="$3"
  local jq_program
  jq_program='
    [
      '"${versions_expr}"' |
      .assetUri?, .fallbackAssetUri?, (.files[]?.source?)
    ]
    | map(select(. != null))
    | length > 0 and all(startswith($prefix))
  '
  jq -e --arg prefix "$prefix" "$jq_program" "$file" >/dev/null 2>&1
}

# =========================================================================
# Setup: create the public gateway repository
# =========================================================================

begin_test "Create remote vscode gallery repository"
if create_remote_repo "$REPO_KEY" "vscode" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote vscode repo"
fi

# -------------------------------------------------------------------------
# Check upstream reachability before running gallery-gateway tests
# -------------------------------------------------------------------------

begin_test "Verify upstream reachability"
if curl -sf --max-time 10 "https://open-vsx.org" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "open-vsx.org unreachable from test environment"
fi

# =========================================================================
# Test 1: Gallery manifest names AK's own query/latest endpoints
# =========================================================================

begin_test "Gallery manifest names AK's extensionquery and latest endpoints"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  MANIFEST_FILE="${WORK_DIR}/manifest.json"
  if curl -sf $CURL_TIMEOUT -o "$MANIFEST_FILE" "${GALLERY_URL}/manifest" 2>/dev/null; then
    if jq -e --arg gallery "$GALLERY_URL" '
        .resources
        | any(.type == "ExtensionQueryService" and .id == ($gallery + "/extensionquery"))
          and any(.type == "ExtensionLatestVersionUriTemplate" and .id == ($gallery + "/{publisher}/{name}/latest"))
      ' "$MANIFEST_FILE" >/dev/null 2>&1; then
      pass
    else
      fail "manifest does not name AK's gallery query/latest endpoints" \
        "$(head -c 2000 "$MANIFEST_FILE" 2>/dev/null)"
    fi
  else
    fail "GET ${GALLERY_URL}/manifest returned error"
  fi
fi

# =========================================================================
# Test 2: Gallery extensionquery resolves the reviewed extension, with the
# exact VS Code client request body shape
# =========================================================================

begin_test "Gallery extensionquery resolves ${EXTENSION_ID}"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  QUERY_BODY=$(jq -n --arg id "$EXTENSION_ID" '{
    filters: [{
      criteria: [{filterType: 7, value: $id}],
      pageNumber: 1,
      pageSize: 10,
      sortBy: 0,
      sortOrder: 0
    }],
    flags: 511
  }') || true
  PROBE_FILE="${WORK_DIR}/probe.json"
  if [ -n "$QUERY_BODY" ] && echo "$QUERY_BODY" | curl -sf $CURL_TIMEOUT \
      -H 'accept: application/json;api-version=3.0-preview.1' \
      -H 'content-type: application/json' \
      --data-binary @- -o "$PROBE_FILE" \
      "${GALLERY_URL}/extensionquery" 2>/dev/null; then
    if jq -e --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" '
        .results[].extensions[]
        | select(.publisher.publisherName == $publisher and .extensionName == $name)
        | .versions | length > 0
      ' "$PROBE_FILE" >/dev/null 2>&1; then
      pass
    else
      fail "AK did not resolve ${EXTENSION_ID} via extensionquery" \
        "$(head -c 2000 "$PROBE_FILE" 2>/dev/null)"
    fi
  else
    fail "POST ${GALLERY_URL}/extensionquery returned error"
  fi
fi

# =========================================================================
# Test 3: extensionquery response asset URLs are all AK-owned
# =========================================================================

begin_test "Gallery extensionquery response asset URLs are AK-owned"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ ! -s "${PROBE_FILE:-}" ]; then
  skip "no extensionquery response captured (previous step failed)"
else
  if _assert_asset_urls_ak_owned "$PROBE_FILE" '.results[].extensions[].versions[]?' "$AK_PREFIX"; then
    pass
  else
    fail "extensionquery response retains a non-AK asset URL" \
      "$(head -c 2000 "$PROBE_FILE" 2>/dev/null)"
  fi
fi

# =========================================================================
# Test 4: {publisher}/{name}/latest resolves the reviewed extension
# =========================================================================

begin_test "Gallery latest lookup resolves ${EXTENSION_ID}"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  LATEST_FILE="${WORK_DIR}/latest.json"
  if curl -sf $CURL_TIMEOUT -o "$LATEST_FILE" \
      "${GALLERY_URL}/${EXTENSION_PUBLISHER}/${EXTENSION_NAME}/latest" 2>/dev/null; then
    if jq -e --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" '
        .publisher.publisherName == $publisher
        and .extensionName == $name
        and (.versions | length > 0)
      ' "$LATEST_FILE" >/dev/null 2>&1; then
      pass
    else
      fail "AK latest lookup did not return ${EXTENSION_ID}" \
        "$(head -c 2000 "$LATEST_FILE" 2>/dev/null)"
    fi
  else
    fail "GET ${GALLERY_URL}/${EXTENSION_PUBLISHER}/${EXTENSION_NAME}/latest returned error"
  fi
fi

# =========================================================================
# Test 5: latest response asset URLs are all AK-owned
# =========================================================================

begin_test "Gallery latest response asset URLs are AK-owned"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ ! -s "${LATEST_FILE:-}" ]; then
  skip "no latest response captured (previous step failed)"
else
  if _assert_asset_urls_ak_owned "$LATEST_FILE" '.versions[]' "$AK_PREFIX"; then
    pass
  else
    fail "latest response retains a non-AK asset URL" \
      "$(head -c 2000 "$LATEST_FILE" 2>/dev/null)"
  fi
fi

# =========================================================================
# Test 6: code-server's compatibility alias
# (/vscode/{publisher}/{name}/latest, derived by code-server from serviceUrl)
# resolves the reviewed extension. Kept as a direct probe -- not derived
# from the manifest-only checks above -- so a regression in this alias
# specifically cannot hide behind the primary latest-lookup passing.
# =========================================================================

begin_test "code-server latest alias resolves ${EXTENSION_ID}"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  CS_LATEST_FILE="${WORK_DIR}/latest-code-server.json"
  if curl -sf $CURL_TIMEOUT -o "$CS_LATEST_FILE" \
      "${GALLERY_URL}/vscode/${EXTENSION_PUBLISHER}/${EXTENSION_NAME}/latest" 2>/dev/null; then
    if jq -e --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" '
        .publisher.publisherName == $publisher
        and .extensionName == $name
        and (.versions | length > 0)
      ' "$CS_LATEST_FILE" >/dev/null 2>&1; then
      pass
    else
      fail "code-server latest alias did not return ${EXTENSION_ID}" \
        "$(head -c 2000 "$CS_LATEST_FILE" 2>/dev/null)"
    fi
  else
    fail "GET ${GALLERY_URL}/vscode/${EXTENSION_PUBLISHER}/${EXTENSION_NAME}/latest returned error"
  fi
fi

# =========================================================================
# Test 7: code-server alias response asset URLs are all AK-owned
# =========================================================================

begin_test "code-server latest alias asset URLs are AK-owned"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ ! -s "${CS_LATEST_FILE:-}" ]; then
  skip "no code-server latest alias response captured (previous step failed)"
else
  if _assert_asset_urls_ak_owned "$CS_LATEST_FILE" '.versions[]' "$AK_PREFIX"; then
    pass
  else
    fail "code-server latest alias response retains a non-AK asset URL" \
      "$(head -c 2000 "$CS_LATEST_FILE" 2>/dev/null)"
  fi
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
