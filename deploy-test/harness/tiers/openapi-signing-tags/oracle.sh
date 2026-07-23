#!/usr/bin/env bash
# =============================================================================
# tiers/openapi-signing-tags/oracle.sh — served OpenAPI operation-tags gate
# (#2721 / PR #2836), filesystem storage.
# =============================================================================
# Discriminating oracle for the untagged signing operation.
#
# Background (handlers/signing.rs::sign_artifact): the utoipa path macro for
# POST /api/v1/signing/artifacts/{artifact_id}/sign omitted `tag = "signing"`,
# so the merged OpenAPI document served at /api/v1/openapi.json carried an empty
# `tags` array for that operation. Spectral's error-severity `operation-tags`
# rule fails the SDK-generation pipeline on any untagged operation.
#
# Asserts (against the RUNNING instance's served spec):
#   * /api/v1/openapi.json is reachable and parses as JSON.
#   * the operation object at
#       paths./api/v1/signing/artifacts/{artifact_id}/sign.post
#     exists AND its `tags` array has length > 0.
#     Pre-#2721: tags == []  -> length 0 -> FAIL (non-zero exit).
#     Fixed:     tags == ["signing"] -> length 1 -> PASS.
#
# run.sh has stood up the filesystem profile-set and exported BASE_URL,
# DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SIGN_PATH='/api/v1/signing/artifacts/{artifact_id}/sign'

begin_suite "openapi-signing-tags"

# ---------------------------------------------------------------------------
begin_test "Served OpenAPI /api/v1/openapi.json is reachable and parses as JSON"
SPEC_FILE="$(mktemp)"
HTTP=$(curl -s -o "$SPEC_FILE" -w '%{http_code}' "$BASE/api/v1/openapi.json")
echo "-- GET /api/v1/openapi.json -> HTTP $HTTP ($(wc -c <"$SPEC_FILE") bytes)"
SPEC_OK=1
if [ "$HTTP" != "200" ]; then
  SPEC_OK=0
  fail "openapi.json not served (HTTP $HTTP); the spec route must be mounted for this gate"
elif ! jq -e . "$SPEC_FILE" >/dev/null 2>&1; then
  SPEC_OK=0
  fail "openapi.json did not parse as JSON"
else
  pass
fi

# ---------------------------------------------------------------------------
begin_test "POST $SIGN_PATH operation declares a non-empty tags array (#2721)"
if [ "$SPEC_OK" != "1" ]; then
  fail "skipped: openapi.json was not retrievable"
else
  # Confirm the operation is actually present (guards against a spec that
  # silently dropped the path, which would make a length check vacuously pass).
  OP_PRESENT=$(jq -r --arg p "$SIGN_PATH" '.paths[$p].post != null' "$SPEC_FILE" 2>/dev/null)
  TAGS_LEN=$(jq -r --arg p "$SIGN_PATH" '(.paths[$p].post.tags // []) | length' "$SPEC_FILE" 2>/dev/null)
  TAGS_VAL=$(jq -c --arg p "$SIGN_PATH" '.paths[$p].post.tags // []' "$SPEC_FILE" 2>/dev/null)
  echo "-- operation present: $OP_PRESENT   tags: $TAGS_VAL   length: $TAGS_LEN"
  if [ "$OP_PRESENT" != "true" ]; then
    fail "sign operation missing from served spec at path '$SIGN_PATH' (cannot evaluate #2721)"
  elif [ "${TAGS_LEN:-0}" -gt 0 ] 2>/dev/null; then
    pass
  else
    fail "sign operation has an EMPTY tags array (#2721); Spectral operation-tags fails the SDK pipeline on this. Pre-fix tags == []"
  fi
fi

rm -f "$SPEC_FILE"
end_suite
