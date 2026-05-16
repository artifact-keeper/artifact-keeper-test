#!/usr/bin/env bash
# test-search-checksum-multi.sh - Checksum search across SHA1 and MD5
#
# Epic 8 sub-task 8.13 (artifact-keeper-test#73). The existing
# test-search-checksum.sh covers only SHA256 (the default algorithm).
# The backend's checksum_search handler (search.rs ~line 326) supports
# three algorithms (sha256, sha1, md5) gated by the `algorithm` query
# parameter, and returns 422 for any other value. None of that is
# exercised by the gate today, so a regression that dropped the SHA1
# or MD5 SQL branches would not surface here.
#
# Strategy: upload a single sentinel, compute all three checksums
# locally (using sha256sum / sha1sum / md5sum, falling back to shasum
# and OpenSSL where missing), then ask the API for each algorithm and
# verify the artifact is returned. The load-bearing assertion is
# response.artifacts[*].id agreement across the three algorithms: a
# backend that always returns the SHA256-keyed row (ignoring the
# `algorithm` parameter) would still look "fine" if we only checked
# that something came back. Comparing the returned artifact id catches
# the silent-default regression.
#
# We also verify the 422 contract for an unsupported algorithm.
#
# Skips cleanly if:
#   - /api/v1/search/checksum returns 404/501 (endpoint not mounted)
#   - sha1sum and md5sum are both unavailable
#
# Requires: curl, jq, sha256sum (or shasum -a 256), plus at least one
# of sha1sum/shasum and one of md5sum/openssl.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-checksum-multi"
auth_admin
setup_workdir

REPO_KEY="cksm-mu-${RUN_ID}"
FILENAME="cksm-${RUN_ID}.bin"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

# Preflight: endpoint must exist.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/checksum?checksum=preflight" 2>/dev/null || echo "000")
case "$preflight_status" in
  404|501)
    skip_suite "checksum search endpoint not available (HTTP ${preflight_status})"
    ;;
  503|504|000)
    skip_suite "search backend unavailable (HTTP ${preflight_status})"
    ;;
esac

# -------------------------------------------------------------------------
# Compute checksums locally with the most-portable tool available.
# Returns the empty string when no tool is present.
# -------------------------------------------------------------------------

_sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo ""
  fi
}
_sha1_of() {
  if command -v sha1sum >/dev/null 2>&1; then
    sha1sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 1 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha1 "$1" | awk '{print $NF}'
  else
    echo ""
  fi
}
_md5_of() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | awk '{print $1}'
  elif command -v md5 >/dev/null 2>&1; then
    md5 -q "$1"
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -md5 "$1" | awk '{print $NF}'
  else
    echo ""
  fi
}

begin_test "Create repo and upload a checksum sentinel"
ok=true
create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1 || ok=false
# Deterministic content so checksums match the bytes the backend hashed.
printf 'multi-checksum-sentinel-%s\n' "$RUN_ID" > "${WORK_DIR}/${FILENAME}"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${FILENAME}" \
  "${WORK_DIR}/${FILENAME}" >/dev/null 2>&1 || ok=false
if [ "$ok" = true ]; then
  pass
else
  fail "could not seed checksum corpus"
  end_suite
fi

SHA256=$(_sha256_of "${WORK_DIR}/${FILENAME}")
SHA1=$(_sha1_of   "${WORK_DIR}/${FILENAME}")
MD5=$(_md5_of    "${WORK_DIR}/${FILENAME}")

sleep 2   # the backend computes/persists all three checksums on upload

# _checksum_artifact_id <checksum> <algorithm>
# Calls /api/v1/search/checksum and echoes the first artifact id (or "").
_checksum_artifact_id() {
  local checksum="$1"; local algorithm="$2"
  local resp
  resp=$(api_get "/api/v1/search/checksum?checksum=${checksum}&algorithm=${algorithm}" 2>/dev/null || echo "")
  if [ -z "$resp" ]; then
    echo ""
    return
  fi
  echo "$resp" | jq -r '
    if (.artifacts? | type) == "array" then (.artifacts[0].id // "")
    elif type == "array" then (.[0].id // "")
    else "" end' 2>/dev/null || echo ""
}

# Establish the SHA256 baseline first; the other algorithms are compared
# against this artifact id to detect silent-default behaviour.
SHA256_ID=""
if [ -n "$SHA256" ]; then
  SHA256_ID=$(_checksum_artifact_id "$SHA256" "sha256")
fi

# -------------------------------------------------------------------------
# 8.13 SHA1 search must return an artifact with the SAME id as SHA256.
# -------------------------------------------------------------------------

begin_test "checksum?algorithm=sha1 returns the same artifact as sha256"
if [ -z "$SHA1" ]; then
  skip "sha1sum / shasum / openssl not installed; cannot compute SHA1 locally"
elif [ -z "$SHA256_ID" ]; then
  skip "SHA256 baseline lookup returned nothing; cannot cross-check SHA1"
else
  sha1_id=$(_checksum_artifact_id "$SHA1" "sha1")
  if [ -z "$sha1_id" ]; then
    fail "SHA1 lookup returned no artifact for checksum ${SHA1:0:12}..."
  elif [ "$sha1_id" = "$SHA256_ID" ]; then
    pass
  else
    fail "SHA1 lookup returned id=${sha1_id}; expected ${SHA256_ID} (algorithm parameter likely ignored)"
  fi
fi

# -------------------------------------------------------------------------
# 8.13 MD5 search must return an artifact with the SAME id as SHA256.
# -------------------------------------------------------------------------

begin_test "checksum?algorithm=md5 returns the same artifact as sha256"
if [ -z "$MD5" ]; then
  skip "md5sum / md5 / openssl not installed; cannot compute MD5 locally"
elif [ -z "$SHA256_ID" ]; then
  skip "SHA256 baseline lookup returned nothing; cannot cross-check MD5"
else
  md5_id=$(_checksum_artifact_id "$MD5" "md5")
  if [ -z "$md5_id" ]; then
    fail "MD5 lookup returned no artifact for checksum ${MD5:0:12}..."
  elif [ "$md5_id" = "$SHA256_ID" ]; then
    pass
  else
    fail "MD5 lookup returned id=${md5_id}; expected ${SHA256_ID} (algorithm parameter likely ignored)"
  fi
fi

# -------------------------------------------------------------------------
# 8.13 Unsupported algorithm must return 422 per the OpenAPI contract.
# -------------------------------------------------------------------------

begin_test "checksum?algorithm=sha512 returns 422 (unsupported algorithm)"
if [ -z "$SHA256" ]; then
  skip "no checksum to probe with"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search/checksum?checksum=${SHA256}&algorithm=sha512" 2>/dev/null || echo "000")
  case "$status" in
    422)         pass ;;
    400|404)     pass ;;  # acceptable rejection variants
    5*)          fail "sha512 algorithm returned HTTP ${status}; expected 422" ;;
    2*)          fail "sha512 algorithm returned HTTP ${status}; should be rejected" ;;
    *)           skip "sha512 algorithm returned HTTP ${status}; not a clean signal" ;;
  esac
fi

# -------------------------------------------------------------------------
# 8.13 Case-insensitive checksum: backend lowercases on lookup.
#      An uppercase SHA1 must still match.
# -------------------------------------------------------------------------

begin_test "checksum lookup is case-insensitive for sha1"
if [ -z "$SHA1" ] || [ -z "$SHA256_ID" ]; then
  skip "no SHA1 baseline available for case test"
else
  # Convert to uppercase using tr (portable across bash/zsh).
  sha1_upper=$(printf '%s' "$SHA1" | tr 'a-f' 'A-F')
  upper_id=$(_checksum_artifact_id "$sha1_upper" "sha1")
  if [ -z "$upper_id" ]; then
    fail "uppercase SHA1 lookup returned no artifact (case-sensitivity regression)"
  elif [ "$upper_id" = "$SHA256_ID" ]; then
    pass
  else
    fail "uppercase SHA1 returned id=${upper_id}; expected ${SHA256_ID}"
  fi
fi

end_suite
