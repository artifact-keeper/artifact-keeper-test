#!/usr/bin/env bash
# test-nuget-search-freshness.sh - NuGet v3 search index freshness SLA
#
# After a package is pushed, the NuGet v3 search service (/v3/search?q=...)
# must reflect it within a small SLA window. The 1.1.x backend documents an
# indexing lag bounded by NUGET_SEARCH_INDEX_FRESHNESS_SECONDS; this suite
# defaults to 60s (long enough to absorb a single index flush cycle, short
# enough that a regression won't pass).
#
# Distinct from test-nuget-conformance.sh:261 which only asserts the search
# endpoint responds; this suite specifically targets freshness/SLA.
#
# Covers issue #68 subtask 3.10.
#
# Requires: curl, jq, zip

source "$(dirname "$0")/../lib/common.sh"

begin_suite "nuget-search-freshness"
auth_admin
setup_workdir
require_cmd zip

REPO_KEY="test-nuget-fresh-${RUN_ID}"
NUGET_BASE="${BASE_URL}/nuget/${REPO_KEY}"

# Unique enough that the search query can't match anything pre-existing.
PACKAGE_ID="FreshSearch${RUN_ID//-/}"
PACKAGE_ID_LOWER=$(echo "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')
PACKAGE_VERSION="1.0.$(date +%s)"

# SLA budget in seconds. Override via env to tune for slow clusters.
SLA_SECONDS="${NUGET_SEARCH_FRESHNESS_SLA:-60}"
POLL_INTERVAL="${NUGET_SEARCH_FRESHNESS_POLL:-3}"

# ---------------------------------------------------------------------------
# Create repo
# ---------------------------------------------------------------------------

begin_test "Create NuGet repository"
if create_local_repo "$REPO_KEY" "nuget"; then
  pass
else
  fail "could not create nuget repository"
fi

# ---------------------------------------------------------------------------
# Build a minimal .nupkg with a unique ID
# ---------------------------------------------------------------------------

begin_test "Build minimal .nupkg"
PKG_DIR="${WORK_DIR}/nupkg-build"
mkdir -p "${PKG_DIR}/lib/net8.0" "${PKG_DIR}/_rels"

cat > "${PKG_DIR}/${PACKAGE_ID}.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${PACKAGE_ID}</id>
    <version>${PACKAGE_VERSION}</version>
    <authors>artifact-keeper-test</authors>
    <description>search freshness fixture for ${RUN_ID}</description>
    <license type="expression">MIT</license>
  </metadata>
</package>
EOF

echo "dll-${RUN_ID}" > "${PKG_DIR}/lib/net8.0/${PACKAGE_ID}.dll"

cat > "${PKG_DIR}/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/xml" />
  <Default Extension="dll" ContentType="application/octet-stream" />
</Types>
EOF

cat > "${PKG_DIR}/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${PACKAGE_ID}.nuspec" Id="R1" />
</Relationships>
EOF

NUPKG_FILE="${WORK_DIR}/${PACKAGE_ID}.${PACKAGE_VERSION}.nupkg"
( cd "$PKG_DIR" && zip -qr "$NUPKG_FILE" . )
if [ -s "$NUPKG_FILE" ]; then pass; else fail "nupkg build empty"; fi

# ---------------------------------------------------------------------------
# Snapshot search index BEFORE push so we know the ID is novel
# ---------------------------------------------------------------------------

begin_test "Pre-push search returns 0 hits for unique ID"
pre_resp=$(curl -s -o "${WORK_DIR}/pre.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NUGET_BASE}/v3/search?q=${PACKAGE_ID}") || pre_resp="000"

if [ "$pre_resp" = "404" ] || [ "$pre_resp" = "501" ]; then
  skip_suite "nuget search endpoint not implemented (HTTP ${pre_resp})"
elif [ "$pre_resp" != "200" ]; then
  fail "pre-push search returned HTTP ${pre_resp}" "$(head -c 400 "${WORK_DIR}/pre.json" 2>/dev/null)"
else
  pre_hits=$(jq -r '.totalHits // 0' "${WORK_DIR}/pre.json" 2>/dev/null) || pre_hits="0"
  if [ "$pre_hits" = "0" ] || [ "$pre_hits" = "null" ]; then
    pass
  else
    fail "pre-push search has ${pre_hits} hits for unique ID ${PACKAGE_ID}; ID is not novel" \
         "$(head -c 400 "${WORK_DIR}/pre.json")"
  fi
fi

# ---------------------------------------------------------------------------
# Push the package, then poll search until either it appears or SLA expires
# ---------------------------------------------------------------------------

begin_test "Push package"
push_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -F "package=@${NUPKG_FILE};type=application/octet-stream" \
  "${NUGET_BASE}/api/v2/package") || push_status="000"

if [ "$push_status" = "200" ] || [ "$push_status" = "201" ]; then
  pass
elif [ "$push_status" = "404" ] || [ "$push_status" = "501" ]; then
  skip_suite "nuget push not supported (HTTP ${push_status})"
else
  fail "package push returned HTTP ${push_status}"
fi

# Record push completion timestamp so the freshness window is measured
# from push acknowledgement, not from suite start.
PUSH_DONE_AT=$(date +%s)

begin_test "Package appears in search index within ${SLA_SECONDS}s SLA"
DEADLINE=$(( PUSH_DONE_AT + SLA_SECONDS ))
ATTEMPTS=0
SAW_HIT="false"
LAST_BODY=""
LAST_STATUS="000"
ELAPSED_AT_HIT=""

while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  ATTEMPTS=$(( ATTEMPTS + 1 ))
  LAST_STATUS=$(curl -s -o "${WORK_DIR}/search.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/search?q=${PACKAGE_ID}") || LAST_STATUS="000"

  if [ "$LAST_STATUS" = "200" ]; then
    hit_count=$(jq -r --arg id "$PACKAGE_ID" \
      '[.data[]? | select((.id // "") | ascii_downcase == ($id | ascii_downcase))] | length' \
      "${WORK_DIR}/search.json" 2>/dev/null) || hit_count="0"

    if [ "$hit_count" != "0" ] && [ "$hit_count" != "null" ] && [ -n "$hit_count" ]; then
      SAW_HIT="true"
      ELAPSED_AT_HIT=$(( $(date +%s) - PUSH_DONE_AT ))
      break
    fi
  fi

  LAST_BODY=$(head -c 200 "${WORK_DIR}/search.json" 2>/dev/null || true)
  sleep "$POLL_INTERVAL"
done

if [ "$SAW_HIT" = "true" ]; then
  echo "  indexed after ${ELAPSED_AT_HIT}s (${ATTEMPTS} polls, SLA=${SLA_SECONDS}s)"
  pass
else
  fail "package did not surface in /v3/search within ${SLA_SECONDS}s SLA" \
       "attempts=${ATTEMPTS} last_status=${LAST_STATUS} last_body=${LAST_BODY}"
fi

# ---------------------------------------------------------------------------
# Confirm the search result carries the right version and totalHits>=1
# ---------------------------------------------------------------------------

begin_test "Search result reflects pushed version and totalHits>=1"
if [ "$SAW_HIT" != "true" ]; then
  skip "previous step did not observe the package; cannot verify result shape"
else
  total=$(jq -r '.totalHits // 0' "${WORK_DIR}/search.json" 2>/dev/null) || total="0"
  ver=$(jq -r --arg id "$PACKAGE_ID" \
    '.data[]? | select((.id // "") | ascii_downcase == ($id | ascii_downcase)) | .version' \
    "${WORK_DIR}/search.json" 2>/dev/null | head -n1) || ver=""

  if [ "$total" -ge 1 ] 2>/dev/null && [ "$ver" = "$PACKAGE_VERSION" ]; then
    pass
  elif [ "$total" -ge 1 ] 2>/dev/null; then
    # Backend may normalize the version (e.g. strip trailing .0). Accept any
    # non-empty version that starts with our prefix.
    case "$ver" in
      "${PACKAGE_VERSION%.*}"*) pass ;;
      *) fail "search hit has unexpected version '${ver}' (expected '${PACKAGE_VERSION}')" ;;
    esac
  else
    fail "totalHits=${total} but expected >= 1"
  fi
fi

end_suite
