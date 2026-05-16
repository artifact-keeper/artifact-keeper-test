#!/usr/bin/env bash
# test-nuget-symbol-packages.sh - NuGet symbol package (.snupkg) lifecycle
#
# NuGet supports a companion symbol package format (.snupkg) for shipping
# PDBs alongside a .nupkg. Push uses the same /api/v2/symbolpackage endpoint
# in the v3 push protocol (or /api/v2/package when content-typed as snupkg).
# Symbol packages have their own URL space; they must be downloadable
# without colliding with the primary nupkg.
#
# Covers issue #68 subtask 3.8.
#
# Requires: curl, zip

source "$(dirname "$0")/../lib/common.sh"

begin_suite "nuget-symbol-packages"
auth_admin
setup_workdir
require_cmd zip

REPO_KEY="test-nuget-snupkg-${RUN_ID}"
NUGET_BASE="${BASE_URL}/nuget/${REPO_KEY}"
PACKAGE_ID="E2ESym.Hello"
PACKAGE_ID_LOWER=$(echo "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')
PACKAGE_VERSION="1.0.$(date +%s)"

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
# Build the primary .nupkg
# ---------------------------------------------------------------------------

begin_test "Build primary .nupkg"
PKG_DIR="${WORK_DIR}/nupkg-build"
mkdir -p "${PKG_DIR}/lib/net8.0" "${PKG_DIR}/_rels"

cat > "${PKG_DIR}/${PACKAGE_ID}.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${PACKAGE_ID}</id>
    <version>${PACKAGE_VERSION}</version>
    <authors>artifact-keeper-test</authors>
    <description>E2E symbol package companion fixture</description>
    <license type="expression">MIT</license>
  </metadata>
</package>
EOF

echo "primary-dll-bytes-${RUN_ID}" > "${PKG_DIR}/lib/net8.0/${PACKAGE_ID}.dll"

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
# Build the companion .snupkg (snupkg has packageTypes=SymbolsPackage)
# ---------------------------------------------------------------------------

begin_test "Build companion .snupkg"
SYM_DIR="${WORK_DIR}/snupkg-build"
mkdir -p "${SYM_DIR}/lib/net8.0" "${SYM_DIR}/_rels"

# Snupkg nuspec must declare packageTypes containing SymbolsPackage.
cat > "${SYM_DIR}/${PACKAGE_ID}.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${PACKAGE_ID}</id>
    <version>${PACKAGE_VERSION}</version>
    <authors>artifact-keeper-test</authors>
    <description>Symbols for ${PACKAGE_ID}</description>
    <packageTypes>
      <packageType name="SymbolsPackage" />
    </packageTypes>
  </metadata>
</package>
EOF

# Placeholder PDB.
echo "pdb-bytes-${RUN_ID}" > "${SYM_DIR}/lib/net8.0/${PACKAGE_ID}.pdb"

cat > "${SYM_DIR}/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/xml" />
  <Default Extension="pdb" ContentType="application/octet-stream" />
</Types>
EOF

cat > "${SYM_DIR}/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${PACKAGE_ID}.nuspec" Id="R1" />
</Relationships>
EOF

SNUPKG_FILE="${WORK_DIR}/${PACKAGE_ID}.${PACKAGE_VERSION}.snupkg"
( cd "$SYM_DIR" && zip -qr "$SNUPKG_FILE" . )
if [ -s "$SNUPKG_FILE" ]; then pass; else fail "snupkg build empty"; fi

NUPKG_SHA=$(shasum -a 256 "$NUPKG_FILE"  | awk '{print $1}')
SNUPKG_SHA=$(shasum -a 256 "$SNUPKG_FILE" | awk '{print $1}')

# Sanity: the two packages must have different bytes or the rest of the
# suite is meaningless.
begin_test "snupkg bytes differ from nupkg bytes"
if [ "$NUPKG_SHA" != "$SNUPKG_SHA" ]; then
  pass
else
  fail "nupkg and snupkg fixtures hashed to the same value; symbol-vs-primary test would be vacuous"
fi

# ---------------------------------------------------------------------------
# Push the primary .nupkg first
# ---------------------------------------------------------------------------

begin_test "Push primary .nupkg"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -F "package=@${NUPKG_FILE};type=application/octet-stream" \
  "${NUGET_BASE}/api/v2/package") || status="000"

if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
elif [ "$status" = "404" ] || [ "$status" = "501" ]; then
  skip_suite "nuget push not supported (HTTP ${status})"
else
  fail "primary push returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# Push the companion .snupkg via the symbolpackage endpoint
# ---------------------------------------------------------------------------

begin_test "Push companion .snupkg via /api/v2/symbolpackage"
SYM_STATUS=""
SYM_DETAIL=""

# 1. /api/v2/symbolpackage (v3 symbol push)
sym_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -F "package=@${SNUPKG_FILE};type=application/octet-stream" \
  "${NUGET_BASE}/api/v2/symbolpackage") || sym_status="000"
SYM_DETAIL="${SYM_DETAIL}symbolpackage multipart -> ${sym_status}; "
if [ "$sym_status" = "200" ] || [ "$sym_status" = "201" ]; then
  SYM_STATUS="ok"
fi

# 2. Same endpoint with raw body
if [ -z "$SYM_STATUS" ]; then
  sym_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${SNUPKG_FILE}" \
    "${NUGET_BASE}/api/v2/symbolpackage") || sym_status="000"
  SYM_DETAIL="${SYM_DETAIL}symbolpackage raw -> ${sym_status}; "
  if [ "$sym_status" = "200" ] || [ "$sym_status" = "201" ]; then
    SYM_STATUS="ok"
  fi
fi

# 3. Fallback: some backends accept snupkg on the regular /api/v2/package
#    endpoint and dispatch by inspecting packageTypes inside the nuspec.
if [ -z "$SYM_STATUS" ]; then
  sym_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -F "package=@${SNUPKG_FILE};type=application/octet-stream" \
    "${NUGET_BASE}/api/v2/package") || sym_status="000"
  SYM_DETAIL="${SYM_DETAIL}package (fallback) -> ${sym_status}; "
  if [ "$sym_status" = "200" ] || [ "$sym_status" = "201" ]; then
    SYM_STATUS="ok-fallback"
  fi
fi

if [ -n "$SYM_STATUS" ]; then
  pass
elif echo "$SYM_DETAIL" | grep -qE '\b(404|501)\b'; then
  skip "snupkg push endpoint not implemented; tried: ${SYM_DETAIL}"
else
  fail "snupkg push failed on all endpoints" "$SYM_DETAIL"
fi

sleep 2

# ---------------------------------------------------------------------------
# Retrieve the .snupkg back, separate from the .nupkg
# ---------------------------------------------------------------------------

begin_test "Symbol package retrievable separately from .nupkg"
if [ -z "$SYM_STATUS" ]; then
  skip "snupkg push did not succeed; cannot verify retrieval"
else
  # NuGet symbol packages live under flatcontainer with .snupkg extension.
  SNUPKG_OUT="${WORK_DIR}/downloaded.snupkg"
  SNUPKG_URL="${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.snupkg"

  dl_status=$(curl -s -o "$SNUPKG_OUT" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "$SNUPKG_URL") || dl_status="000"

  if [ "$dl_status" = "404" ]; then
    skip "snupkg download URL not implemented (HTTP 404 from ${SNUPKG_URL})"
  elif [ "$dl_status" != "200" ]; then
    fail "snupkg download returned HTTP ${dl_status} from ${SNUPKG_URL}"
  elif [ ! -s "$SNUPKG_OUT" ]; then
    fail "snupkg download returned empty body"
  else
    DL_SHA=$(shasum -a 256 "$SNUPKG_OUT" | awk '{print $1}')
    if [ "$DL_SHA" = "$SNUPKG_SHA" ]; then
      pass
    elif [ "$DL_SHA" = "$NUPKG_SHA" ]; then
      fail "snupkg URL served nupkg bytes (URL space collision)" \
           "downloaded sha=${DL_SHA} matches nupkg sha=${NUPKG_SHA}, expected snupkg sha=${SNUPKG_SHA}"
    else
      # Backend may re-zip / normalize; accept any non-colliding response
      # whose first bytes are a ZIP magic.
      magic=$(head -c 4 "$SNUPKG_OUT" | od -An -c | tr -d ' \n' | head -c 4)
      if [ "$magic" = "PK^C^D" ] || head -c 2 "$SNUPKG_OUT" | grep -q 'PK'; then
        echo "  note: snupkg sha differs from upload (${DL_SHA} vs ${SNUPKG_SHA}); backend likely re-packed"
        pass
      else
        fail "snupkg download is not a ZIP and does not match upload hash"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Confirm the primary .nupkg is still independently retrievable
# ---------------------------------------------------------------------------

begin_test "Primary .nupkg still independently retrievable after symbol push"
NUPKG_OUT="${WORK_DIR}/downloaded.nupkg"
NUPKG_URL="${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg"

dl_status=$(curl -s -o "$NUPKG_OUT" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "$NUPKG_URL") || dl_status="000"

if [ "$dl_status" != "200" ]; then
  fail "primary nupkg download returned HTTP ${dl_status}"
elif [ ! -s "$NUPKG_OUT" ]; then
  fail "primary nupkg download returned empty body"
else
  DL_SHA=$(shasum -a 256 "$NUPKG_OUT" | awk '{print $1}')
  if [ "$DL_SHA" = "$NUPKG_SHA" ]; then
    pass
  elif [ "$DL_SHA" = "$SNUPKG_SHA" ]; then
    fail "nupkg URL served snupkg bytes (symbol push overwrote primary)" \
         "downloaded sha=${DL_SHA} matches snupkg sha=${SNUPKG_SHA}"
  else
    # Re-pack is acceptable as long as it's not the snupkg.
    if head -c 2 "$NUPKG_OUT" | grep -q 'PK'; then
      pass
    else
      fail "nupkg download is not a ZIP"
    fi
  fi
fi

end_suite
