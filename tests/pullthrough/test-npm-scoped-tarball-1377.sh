#!/usr/bin/env bash
# test-npm-scoped-tarball-1377.sh - NPM Remote scoped package + tarball against npmjs.org
#
# E2E reproducer for artifact-keeper#1377 assertion (c): a Remote npm
# repo backed by https://registry.npmjs.org must serve scoped package
# metadata AND the tarball for that package without leaking the @scope
# encoding or routing to the unscoped path.
#
# Closing PR: artifact-keeper#1391 (merged at 172508c0).
#
# Per #1391, the production code path that encodes @scope/pkg as
# @scope%2Fpkg when proxying to upstream was already correct. The PR
# adds a wiremock-backed Rust regression test
#
#   backend/src/api/handlers/npm::tests::
#     test_remote_proxy_download_scoped_tarball_hits_encoded_upstream_path
#
# This bash test is the externally-visible E2E counterpart: it points
# a Remote at the real npm registry and walks the client-facing wire
# (metadata -> tarball) so a future refactor that drops %2F encoding
# or mis-routes scoped paths to the unscoped fallback fails the gate.
#
# Package choice: @types/node
#   * Stable, dependency-free, ubiquitous, and large enough that an
#     empty response is unambiguous.
#   * The metadata document advertises many versions and each version's
#     `dist.tarball` URL is publicly resolvable.
#   * We don't pin a specific tarball version up front; instead we
#     parse the metadata, pull a tarball URL out of it, rewrite to the
#     local Remote path, and assert the tarball downloads with non-zero
#     bytes. This avoids breakage when upstream rotates versions.
#
# What this test asserts:
#   1. /npm/<remote>/@types/node returns HTTP 200 with valid JSON whose
#      .name == "@types/node" (i.e. the Remote proxy + %2F encoding for
#      the upstream metadata request is correct).
#   2. The metadata document advertises at least one version with a
#      .dist.tarball URL.
#   3. GET /npm/<remote>/@types/node/-/node-<version>.tgz returns 200
#      with a non-empty body (the binary tarball). This is the exact
#      assertion from #1377 -- "the tarball downloads (200, non-empty
#      bytes)" -- against a real upstream.
#
# Skip behaviour:
#   If registry.npmjs.org is unreachable, the suite skips gracefully.
#   The reachability gate is the first test.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm-scoped-tarball-1377"
auth_admin
setup_workdir

REMOTE_KEY="test-npm-scoped-1377-${RUN_ID}"
UPSTREAM_URL="https://registry.npmjs.org"
SCOPE="@types"
PKG_SHORT="node"
SCOPED_NAME="${SCOPE}/${PKG_SHORT}"

UPSTREAM_REACHABLE=false

# -------------------------------------------------------------------------
# Reachability gate. Probe registry.npmjs.org for the @types/node
# document before touching the API so an offline runner produces a
# clean "skip" rather than a cascade of failures.
# -------------------------------------------------------------------------

begin_test "Probe upstream registry.npmjs.org reachability"
if curl -sf --max-time 10 "${UPSTREAM_URL}/@types%2Fnode" -o /dev/null 2>/dev/null; then
  UPSTREAM_REACHABLE=true
  pass
else
  skip "registry.npmjs.org unreachable from test environment"
fi

# -------------------------------------------------------------------------
# Create Remote npm repo.
# -------------------------------------------------------------------------

begin_test "Create Remote npm repo against registry.npmjs.org"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif create_remote_repo "$REMOTE_KEY" "npm" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create Remote npm repo against ${UPSTREAM_URL}"
fi

sleep 2

# -------------------------------------------------------------------------
# Assertion (c) part 1: scoped metadata fetches end-to-end.
#
# Client GET path is the un-encoded @scope/pkg form. The handler must
# encode the upstream request as @scope%2Fpkg internally. Pre-fix
# regressions would route to the unscoped fallback or 404; we assert
# 200 + .name == "@types/node".
# -------------------------------------------------------------------------

METADATA_JSON=""

begin_test "GET scoped metadata via Remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  meta_tmp="${WORK_DIR}/metadata.json"
  meta_status=$(curl -s -o "$meta_tmp" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${REMOTE_KEY}/${SCOPED_NAME}" 2>/dev/null) || meta_status="000"
  METADATA_JSON=$(cat "$meta_tmp" 2>/dev/null || echo "")
  if [ "$meta_status" != "200" ]; then
    fail "expected HTTP 200 for scoped metadata, got ${meta_status}" "${METADATA_JSON:0:500}"
  else
    fetched_name=$(echo "$METADATA_JSON" | jq -r '.name // empty' 2>/dev/null) || fetched_name=""
    if [ "$fetched_name" = "${SCOPED_NAME}" ]; then
      pass
    else
      fail "metadata .name='${fetched_name}', expected '${SCOPED_NAME}'" "${METADATA_JSON:0:500}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Assertion (c) part 2: extract a published version + its tarball URL
# from the metadata. We pick the latest version advertised in
# .dist-tags.latest so the version we attempt to download is one the
# registry actually serves right now.
# -------------------------------------------------------------------------

TARBALL_VERSION=""
TARBALL_FILENAME=""

begin_test "Metadata advertises at least one version with dist.tarball"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -z "$METADATA_JSON" ]; then
  fail "no metadata to parse"
else
  TARBALL_VERSION=$(echo "$METADATA_JSON" | jq -r '."dist-tags".latest // empty' 2>/dev/null) || TARBALL_VERSION=""
  if [ -z "$TARBALL_VERSION" ] || [ "$TARBALL_VERSION" = "null" ]; then
    # Fall back to the first version key. .versions is an object keyed
    # by version string; .versions | keys[0] is the first by jq's
    # lexicographic ordering, which is fine for "any one version".
    TARBALL_VERSION=$(echo "$METADATA_JSON" | jq -r '.versions | keys[0] // empty' 2>/dev/null) || TARBALL_VERSION=""
  fi

  if [ -z "$TARBALL_VERSION" ] || [ "$TARBALL_VERSION" = "null" ]; then
    fail "no version advertised in metadata document" "${METADATA_JSON:0:500}"
  else
    upstream_tarball=$(echo "$METADATA_JSON" | jq -r --arg v "$TARBALL_VERSION" '.versions[$v].dist.tarball // empty' 2>/dev/null) || upstream_tarball=""
    if [ -z "$upstream_tarball" ] || [ "$upstream_tarball" = "null" ]; then
      fail "version ${TARBALL_VERSION} has no dist.tarball" "${METADATA_JSON:0:500}"
    else
      # Tarballs in the npm registry use a stable URL shape:
      #   https://registry.npmjs.org/@types/node/-/node-20.x.x.tgz
      # We need just the filename for the local Remote path.
      TARBALL_FILENAME=$(basename "$upstream_tarball")
      if [ -z "$TARBALL_FILENAME" ]; then
        fail "could not extract tarball filename from ${upstream_tarball}"
      else
        pass
      fi
    fi
  fi
fi

# -------------------------------------------------------------------------
# Assertion (c) part 3: GET the tarball through the Remote proxy.
#
# Client URL is /npm/<remote>/@scope/pkg/-/<filename>. The backend must
# encode @scope/pkg as @scope%2Fpkg when calling upstream. Pre-fix
# regressions surface as either a 404 (unscoped fallback path) or a
# zero-byte response (encoding dropped). We assert HTTP 200 AND
# non-zero file size.
# -------------------------------------------------------------------------

begin_test "Download scoped tarball via Remote proxy (200 + non-empty)"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -z "$TARBALL_FILENAME" ]; then
  fail "no tarball filename from previous step"
else
  out_file="${WORK_DIR}/remote-scoped.tgz"
  tar_status=$(curl -s -o "$out_file" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${REMOTE_KEY}/${SCOPED_NAME}/-/${TARBALL_FILENAME}" 2>/dev/null) || tar_status="000"

  if [ "$tar_status" != "200" ]; then
    body_snip=""
    if [ -f "$out_file" ]; then
      body_snip=$(head -c 200 "$out_file" 2>/dev/null || echo "")
    fi
    fail "expected HTTP 200 downloading tarball, got ${tar_status}" "$body_snip"
  elif [ ! -s "$out_file" ]; then
    fail "tarball downloaded (200) but file is empty"
  else
    file_size=$(wc -c < "$out_file" | tr -d ' ')
    # Real @types/node tarballs are >>1KB; anything under a few hundred
    # bytes is likely an error page misclassified by curl, so we
    # require a meaningful minimum.
    if [ "${file_size:-0}" -lt 256 ]; then
      fail "tarball is suspiciously small (${file_size} bytes), likely not a real tarball"
    else
      pass
    fi
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
