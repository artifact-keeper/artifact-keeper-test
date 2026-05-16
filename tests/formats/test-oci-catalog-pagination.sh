#!/usr/bin/env bash
# test-oci-catalog-pagination.sh - OCI _catalog cursor edges (#72.2)
#
# Existing coverage:
#   tests/formats/test-oci-conformance.sh:498 - basic GET /v2/_catalog only.
#   No assertions on `?n=` / `?last=` pagination, no Link-header check, no
#   empty-cursor edge.
#
# This suite extends that to the cursor edges the OCI Distribution Spec
# requires:
#   1. ?n=2 returns at most 2 repositories AND a Link header whose rel is
#      `next` (when there are more results available)
#   2. ?last=<X>&n=2 advances past X: the first item in the response must
#      sort strictly after X, and X itself must not be in the response
#   3. ?last=zzz...&n=10 with a cursor past every name returns the empty
#      repositories array (no error, no 500)
#
# The Link header check is the load-bearing assertion: a registry that
# truncates results without advertising the next-page cursor breaks
# every spec-compliant OCI client (containerd, skopeo, crane).
#
# Requires: curl, jq.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-catalog-pagination"
auth_admin
setup_workdir

# Use three distinct repos so _catalog has >=3 entries owned by this run.
REPO_KEYS=(
  "test-oci-pag-aaa-${RUN_ID}"
  "test-oci-pag-mmm-${RUN_ID}"
  "test-oci-pag-zzz-${RUN_ID}"
)
IMAGE="catpag"

# ---------------------------------------------------------------------------
# Get a registry token (same shape as test-oci-conformance.sh).
# ---------------------------------------------------------------------------

TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi
if [ -z "$TOKEN" ]; then
  skip_suite "could not obtain /v2/token; cannot run catalog pagination tests"
fi

# ---------------------------------------------------------------------------
# Helper: push a tiny, valid OCI manifest into a repo so the repo
# actually surfaces in _catalog. A registry that only lists repos with
# at least one manifest (the spec-correct behaviour) would otherwise
# hide our 3 freshly-created repos.
# ---------------------------------------------------------------------------

push_min_manifest() {
  local repo="$1"
  local config='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]},"config":{}}'
  local config_digest="sha256:$(printf '%s' "$config" | shasum -a 256 | awk '{print $1}')"
  local config_size=${#config}

  # Upload the config blob (monolithic).
  local hdr="${WORK_DIR}/${repo}.init.hdr"
  curl -s -D "$hdr" -o /dev/null -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${repo}/${IMAGE}/blobs/uploads/" >/dev/null 2>&1 || return 1
  local loc
  loc=$(grep -i '^location:' "$hdr" | tr -d '\r' | sed 's/^[Ll]ocation: *//')
  [ -z "$loc" ] && return 1
  [[ "$loc" != http* ]] && loc="${BASE_URL}${loc}"
  if [[ "$loc" == *"?"* ]]; then
    loc="${loc}&digest=${config_digest}"
  else
    loc="${loc}?digest=${config_digest}"
  fi
  curl -s -o /dev/null -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    -d "$config" \
    "$loc" >/dev/null 2>&1 || return 1

  # Push a manifest referencing only the config (no layers needed).
  local manifest
  manifest=$(cat <<EOFM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${config_digest}",
    "size": ${config_size}
  },
  "layers": []
}
EOFM
)
  curl -s -o /dev/null -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    -d "$manifest" \
    "${BASE_URL}/v2/${repo}/${IMAGE}/manifests/v1" >/dev/null 2>&1 || return 1

  return 0
}

# ---------------------------------------------------------------------------
# 1. Set up three repos with one manifest each.
# ---------------------------------------------------------------------------

begin_test "Create 3 docker repositories for pagination"
created=0
for k in "${REPO_KEYS[@]}"; do
  if create_local_repo "$k" "docker"; then
    created=$(( created + 1 ))
  fi
done
if [ "$created" -eq 3 ]; then
  pass
else
  fail "expected 3 repos created, got ${created}"
  end_suite
fi

begin_test "Push minimal manifest into each repo"
pushed=0
for k in "${REPO_KEYS[@]}"; do
  if push_min_manifest "$k"; then
    pushed=$(( pushed + 1 ))
  fi
done
if [ "$pushed" -eq 3 ]; then
  pass
else
  fail "expected 3 manifest pushes, got ${pushed}"
  end_suite
fi

# Give the catalog index a moment in case it's eventually-consistent.
sleep 1

# ---------------------------------------------------------------------------
# 2. ?n=2 returns at most 2 repos AND advertises a Link: next page header.
# ---------------------------------------------------------------------------

begin_test "GET /v2/_catalog?n=2 limits results AND emits Link rel=next"
CAT_HDR="${WORK_DIR}/cat-n2.hdr"
CAT_BODY="${WORK_DIR}/cat-n2.json"
CAT_STATUS=$(curl -s -D "$CAT_HDR" -o "$CAT_BODY" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/_catalog?n=2") || CAT_STATUS="000"

if [ "$CAT_STATUS" = "404" ] || [ "$CAT_STATUS" = "501" ]; then
  skip_suite "_catalog endpoint not implemented (HTTP ${CAT_STATUS})"
elif [ "$CAT_STATUS" -lt 200 ] 2>/dev/null || [ "$CAT_STATUS" -ge 300 ] 2>/dev/null; then
  fail "GET /v2/_catalog?n=2 returned HTTP ${CAT_STATUS}"
else
  N2_COUNT=$(jq '.repositories | length' "$CAT_BODY" 2>/dev/null) || N2_COUNT="?"
  LINK_HDR=$(grep -i '^link:' "$CAT_HDR" | tr -d '\r' || true)

  # Must respect n=2 (some registries are lenient and return <=2).
  if [ "$N2_COUNT" != "2" ]; then
    fail "?n=2 should return exactly 2 repositories, got ${N2_COUNT}" \
         "$(head -c 400 "$CAT_BODY")"
  elif [ -z "$LINK_HDR" ]; then
    # Without a Link header the client can't paginate. This is the bug
    # we want to catch on regression.
    fail "?n=2 truncated results to 2 but emitted no Link header; clients cannot paginate" \
         "$(head -c 400 "$CAT_HDR")"
  elif ! echo "$LINK_HDR" | grep -qi 'rel="next"\|rel=next'; then
    fail "Link header present but rel is not next" "${LINK_HDR}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 3. ?last=<first>&n=2 advances the cursor.
# ---------------------------------------------------------------------------

begin_test "?last=<X>&n=2 advances past X and does not echo X back"
if [ ! -s "$CAT_BODY" ]; then
  skip "no page-1 body to read cursor from"
else
  LAST_ITEM=$(jq -r '.repositories[-1] // empty' "$CAT_BODY" 2>/dev/null)
  if [ -z "$LAST_ITEM" ]; then
    skip "page 1 had no last item to use as cursor"
  else
    P2_BODY="${WORK_DIR}/cat-p2.json"
    # URL-encode the cursor: repository names can contain `/` (e.g.
    # "test-oci-pag-aaa-RUNID/catpag") which would otherwise terminate
    # the query value early on strict servers.
    LAST_ENC=$(printf '%s' "$LAST_ITEM" | jq -sRr @uri)
    P2_STATUS=$(curl -s -o "$P2_BODY" -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" \
        "${BASE_URL}/v2/_catalog?last=${LAST_ENC}&n=2") || P2_STATUS="000"

    if [ "$P2_STATUS" -lt 200 ] 2>/dev/null || [ "$P2_STATUS" -ge 300 ] 2>/dev/null; then
      fail "page-2 GET returned HTTP ${P2_STATUS}"
    else
      # Cursor semantics: ?last=X means "start strictly AFTER X". The
      # response must NOT contain X, and every entry must sort > X.
      P2_REPOS_JSON=$(jq -c '.repositories // []' "$P2_BODY" 2>/dev/null) || P2_REPOS_JSON="[]"
      contains_last=$(jq --arg x "$LAST_ITEM" '[.repositories[]? | select(. == $x)] | length' "$P2_BODY" 2>/dev/null) || contains_last=0
      bad_order=$(jq --arg x "$LAST_ITEM" '[.repositories[]? | select(. <= $x)] | length' "$P2_BODY" 2>/dev/null) || bad_order=0

      if [ "${contains_last:-0}" -ne 0 ]; then
        fail "page 2 echoes the cursor item back (last=${LAST_ITEM})" \
             "page2=${P2_REPOS_JSON}"
      elif [ "${bad_order:-0}" -ne 0 ]; then
        fail "page 2 contains items <= cursor (last=${LAST_ITEM})" \
             "page2=${P2_REPOS_JSON}"
      else
        pass
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 4. Empty-cursor edge: ?last=zzz_past_everything&n=10 returns an empty
#    repositories array (length 0) with HTTP 200 and no Link rel=next.
# ---------------------------------------------------------------------------

begin_test "?last=<past-end>&n=10 returns empty repositories array (no Link next)"
END_HDR="${WORK_DIR}/cat-end.hdr"
END_BODY="${WORK_DIR}/cat-end.json"
# A cursor that sorts after any plausible repo key. Concatenating ~,zzz,RUN_ID
# yields a string with the highest-sorting printable ASCII prefix that no
# real key would have.
END_CURSOR="~zzzzzz-past-everything-${RUN_ID}"
END_ENC=$(printf '%s' "$END_CURSOR" | jq -sRr @uri)
END_STATUS=$(curl -s -D "$END_HDR" -o "$END_BODY" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/_catalog?last=${END_ENC}&n=10") || END_STATUS="000"

if [ "$END_STATUS" -lt 200 ] 2>/dev/null || [ "$END_STATUS" -ge 300 ] 2>/dev/null; then
  fail "past-end cursor returned HTTP ${END_STATUS}, expected 200 with empty array" \
       "$(head -c 200 "$END_BODY")"
else
  END_COUNT=$(jq '.repositories | length' "$END_BODY" 2>/dev/null) || END_COUNT="?"
  END_LINK=$(grep -i '^link:' "$END_HDR" | tr -d '\r' || true)
  if [ "$END_COUNT" != "0" ]; then
    fail "past-end cursor should return 0 repos, got ${END_COUNT}" \
         "$(head -c 400 "$END_BODY")"
  elif [ -n "$END_LINK" ] && echo "$END_LINK" | grep -qi 'rel="next"\|rel=next'; then
    fail "past-end cursor returned 0 repos but still emitted Link rel=next" \
         "${END_LINK}"
  else
    pass
  fi
fi

end_suite
