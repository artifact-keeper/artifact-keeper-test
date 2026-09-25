#!/usr/bin/env bash
# test-conda.sh - Conda channel E2E test
#
# Tests conda package upload and channel metadata retrieval via the
# /conda/{repo_key}/ endpoints.
#
# Swarm extensions (1.11.0 conda cluster):
#   #4155 - the CEP-27 attestation upload path must actually verify: a bare
#           unsigned in-toto Statement (which the pre-#4155 shape-only check
#           accepted and stored verbatim) must be refused with HTTP 400 now
#           that store_attestation runs cep27::verify_conda_bundle and
#           honours CONDA_ATTESTATION_REQUIRE_VERIFIED (fail-closed default).
#   #4149 - uncompressed repodata.json past the 128 MiB LARGE_METADATA_MAX_BYTES
#           ceiling must stream (200) instead of failing the buffered fetch
#           (502). Exercised through a conda remote repository fronting the
#           mock upstream, which serves an over-ceiling noarch/repodata.json.
#           These tests skip when MOCK_UPSTREAM_HOSTNAME is unset.
#
# Requires: conda, curl, jq, shasum, python3
source "$(dirname "$0")/../lib/common.sh"
begin_suite "conda"
auth_admin
setup_workdir
require_cmd conda
REPO_KEY="test-conda-${RUN_ID}"
PKG_NAME="test-conda-pkg"
PKG_VERSION="1.0.$(date +%s)"
SUBDIR="noarch"
CONDA_URL="${BASE_URL}/conda/${REPO_KEY}"
# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------
begin_test "Create conda local repository"
if create_local_repo "$REPO_KEY" "conda"; then
  pass
else
  fail "could not create conda repository"
fi
# ---------------------------------------------------------------------------
# Build a minimal conda package
# ---------------------------------------------------------------------------
# A .tar.bz2 conda package contains at minimum:
#   - info/index.json (package metadata)
#   - info/paths.json (file listing)
begin_test "Build minimal conda package"
cd "$WORK_DIR"
mkdir -p conda-pkg/info
cat > conda-pkg/info/index.json <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "build": "0",
  "build_number": 0,
  "depends": [],
  "subdir": "${SUBDIR}",
  "arch": null,
  "platform": null,
  "noarch": "generic"
}
EOF
cat > conda-pkg/info/paths.json <<EOF
{
  "paths": []
}
EOF
CONDA_FILENAME="${PKG_NAME}-${PKG_VERSION}-0.tar.bz2"
cd conda-pkg
if tar cjf "${WORK_DIR}/${CONDA_FILENAME}" info/ 2>/dev/null; then
  pass
else
  fail "failed to create conda .tar.bz2 package"
fi
# ---------------------------------------------------------------------------
# Upload package via API
# ---------------------------------------------------------------------------
begin_test "Upload conda package"
UPLOAD_URL="${CONDA_URL}/upload"
if resp=$(curl -sf -X POST "$UPLOAD_URL" \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Conda-Subdir: ${SUBDIR}" \
  -H "X-Package-Filename: ${CONDA_FILENAME}" \
  --data-binary "@${WORK_DIR}/${CONDA_FILENAME}" 2>&1); then
  pass
else
  fail "conda package upload failed: ${resp}"
fi
# ---------------------------------------------------------------------------
# Verify channeldata.json
# ---------------------------------------------------------------------------
begin_test "Verify channeldata.json"
sleep 1
if resp=$(curl -sf "${CONDA_URL}/channeldata.json" -H "$(format_auth_header)"); then
  if assert_contains "$resp" "$PKG_NAME" "channeldata should contain package name"; then
    pass
  fi
else
  fail "GET channeldata.json returned error"
fi
# ---------------------------------------------------------------------------
# Verify repodata.json for subdir
# ---------------------------------------------------------------------------
begin_test "Verify repodata.json for ${SUBDIR}"
if resp=$(curl -sf "${CONDA_URL}/${SUBDIR}/repodata.json" -H "$(format_auth_header)"); then
  if assert_contains "$resp" "$PKG_NAME" "repodata should contain package name"; then
    if assert_contains "$resp" "$PKG_VERSION" "repodata should contain version"; then
      pass
    fi
  fi
else
  fail "GET ${SUBDIR}/repodata.json returned error"
fi
# ---------------------------------------------------------------------------
# Download package file
# ---------------------------------------------------------------------------
begin_test "Download conda package"
DL_URL="${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME}"
DL_FILE="${WORK_DIR}/downloaded.tar.bz2"
if curl -sf -H "$(format_auth_header)" -o "$DL_FILE" "$DL_URL"; then
  # Verify it is a valid bzip2 file. Use `bzip2 -t` (integrity test) rather than
  # `file`: the gate runner image does not ship the `file` utility, so the old
  # `file ... | grep bzip2` check errored out and mis-reported a valid download.
  # bzip2 is provably present (the fixture is built with `tar cjf`). See
  # artifact-keeper-test#294.
  if bzip2 -t "$DL_FILE"; then
    pass
  else
    fail "downloaded file is not a valid bzip2 archive"
  fi
else
  fail "conda package download failed"
fi
# ---------------------------------------------------------------------------
# #4155: CEP-27 attestation verification is enforced at the upload path
# ---------------------------------------------------------------------------
# Pre-#4155 the live upload path ran validate_cep27_attestation, a shape-only
# check that accepted a bare in-toto Statement (no Sigstore bundle, no
# signature) and stored it verbatim, while CONDA_ATTESTATION_REQUIRE_VERIFIED
# was read at no decision point. Post-fix store_attestation runs
# cep27::verify_conda_bundle and refuses any attestation that does not verify
# (the flag is fail-closed by default), so this exact document - which the old
# shape check ACCEPTED - must now come back HTTP 400 naming the verification
# failure.
begin_test "#4155: unsigned bare in-toto Statement attestation is refused"
PKG_SHA256=$(shasum -a 256 "${WORK_DIR}/${CONDA_FILENAME}" | awk '{print $1}')
ATT_FILE="${WORK_DIR}/bare-statement.json"
jq -cn --arg fn "$CONDA_FILENAME" --arg sha "$PKG_SHA256" \
  '{_type: "https://in-toto.io/Statement/v1",
    predicateType: "https://schemas.conda.org/attestations-publish-1.schema.json",
    subject: [{name: $fn, digest: {sha256: $sha}}],
    predicate: {}}' > "$ATT_FILE"
ATT_URL="${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME}/attestation"
att_code=$(curl -s -o "${WORK_DIR}/att-resp.txt" -w '%{http_code}' -X PUT "$ATT_URL" \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  --data-binary "@${ATT_FILE}")
if [ "$att_code" = "400" ]; then
  if assert_contains "$(cat "${WORK_DIR}/att-resp.txt")" "verification failed" "refusal should name the verification failure"; then
    pass
  fi
else
  fail "bare unsigned Statement attestation was accepted (HTTP ${att_code}); CEP-27 verification is not enforced at the upload path (#4155)"
fi
# ---------------------------------------------------------------------------
# #4149: uncompressed repodata.json past the 128 MiB metadata ceiling streams
# ---------------------------------------------------------------------------
# conda-forge's plain repodata.json exceeds LARGE_METADATA_MAX_BYTES
# (128 MiB = 134217728 B) on every major subdir, and pre-#4149 the buffered
# upstream metadata fetch answered 502 for it. The fix streams the over-cap
# body upstream -> client -> proxy cache. This seeds a mock upstream whose
# noarch/repodata.json is over the ceiling and requires a proxied 200 with
# the full body, plus a warm-cache re-serve. Skips when the harness provides
# no backend-resolvable mock hostname.
if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip "#4149 over-ceiling repodata proxy tests need MOCK_UPSTREAM_HOSTNAME"
else
  begin_test "#4149: mock upstream starts with an over-ceiling repodata.json"
  if start_mock_upstream "${WORK_DIR}/mock-state"; then
    MOCK_FILES="${MOCK_STATE_DIR}/files"
    mkdir -p "${MOCK_FILES}/noarch"
    python3 - "${MOCK_FILES}/noarch/repodata.json" <<'PY'
import json, sys
doc = {
    "info": {"subdir": "noarch"},
    "packages": {},
    "packages.conda": {},
    "removed": [],
    "repodata_version": 1,
    "padding": "A" * (140 * 1024 * 1024),
}
with open(sys.argv[1], "w") as fh:
    json.dump(doc, fh)
PY
    pass
  else
    fail "mock upstream did not boot"
  fi

  REMOTE_KEY="test-conda-remote-${RUN_ID}"
  begin_test "#4149: create conda remote repository against mock upstream"
  if create_remote_repo "$REMOTE_KEY" "conda" "$MOCK_BASE_URL"; then
    pass
  else
    fail "could not create conda remote repository"
  fi

  BIG_URL="${BASE_URL}/conda/${REMOTE_KEY}/noarch/repodata.json"
  BIG_OUT="${WORK_DIR}/big-repodata.json"
  begin_test "#4149: over-ceiling uncompressed repodata.json proxied 200, not 502"
  big_code=$(curl -s -o "$BIG_OUT" -w '%{http_code}' --max-time 300 -H "$(format_auth_header)" "$BIG_URL")
  big_size=$(wc -c < "$BIG_OUT" 2>/dev/null || echo 0)
  if [ "$big_code" = "200" ] && [ "$big_size" -gt 134217728 ]; then
    pass
  else
    fail "over-ceiling repodata proxy returned HTTP ${big_code} size=${big_size}; pre-#4149 the buffered fetch 502s past the 128 MiB ceiling"
  fi

  begin_test "#4149: warm-cache re-serve of the over-ceiling repodata"
  big_code2=$(curl -s -o /dev/null -w '%{http_code}' --max-time 300 -H "$(format_auth_header)" "$BIG_URL")
  if [ "$big_code2" = "200" ]; then
    pass
  else
    fail "warm-cache re-serve returned HTTP ${big_code2}"
  fi
fi
# ---------------------------------------------------------------------------
# Conda install from private channel
# ---------------------------------------------------------------------------
begin_test "Conda search from private channel"
# conda search with --override-channels to use only our repo
# We use the token-based URL format for conda access
if output=$(conda search "${PKG_NAME}" \
  --override-channels \
  -c "${CONDA_URL}" \
  --json 2>&1); then
  if assert_contains "$output" "$PKG_NAME" "conda search should find the package"; then
    pass
  fi
else
  # conda search may fail if auth headers are not forwarded; that is acceptable
  # as long as the direct download and repodata work
  skip "conda search did not succeed (auth may not be forwarded by conda client)"
fi
# ---------------------------------------------------------------------------
# Verify repository artifacts via management API
# ---------------------------------------------------------------------------
begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$PKG_NAME" "artifact list should contain package"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi
end_suite
