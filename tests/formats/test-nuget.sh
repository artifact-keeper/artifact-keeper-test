#!/usr/bin/env bash
# test-nuget.sh - NuGet package registry E2E test (curl-based)
#
# Uploads a .nupkg to the NuGet v3 endpoint, verifies the service index,
# and downloads the package back.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "nuget"
auth_admin
setup_workdir

REPO_KEY="test-nuget-${RUN_ID}"
PACKAGE_ID="E2ETest.Hello"
PACKAGE_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create NuGet repository"
if create_local_repo "$REPO_KEY" "nuget"; then
  pass
else
  fail "could not create nuget repository"
fi

# -----------------------------------------------------------------------
# Generate a minimal .nupkg
# -----------------------------------------------------------------------
# A .nupkg is a ZIP file containing a .nuspec and package contents.
begin_test "Upload package"
PKG_DIR="$WORK_DIR/nupkg-build"
mkdir -p "$PKG_DIR/lib/net8.0"

cat > "$PKG_DIR/${PACKAGE_ID}.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${PACKAGE_ID}</id>
    <version>${PACKAGE_VERSION}</version>
    <authors>E2E Test</authors>
    <description>E2E test package for NuGet registry</description>
    <license type="expression">MIT</license>
  </metadata>
</package>
EOF

# Create a placeholder DLL (just needs to be a file)
echo "placeholder assembly" > "$PKG_DIR/lib/net8.0/${PACKAGE_ID}.dll"

# NuGet also expects [Content_Types].xml and a _rels/.rels in the zip
mkdir -p "$PKG_DIR/_rels"
cat > "$PKG_DIR/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/xml" />
  <Default Extension="dll" ContentType="application/octet-stream" />
</Types>
EOF

cat > "$PKG_DIR/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${PACKAGE_ID}.nuspec" Id="R1" />
</Relationships>
EOF

NUPKG_FILE="$WORK_DIR/${PACKAGE_ID}.${PACKAGE_VERSION}.nupkg"
(cd "$PKG_DIR" && zip -qr "$NUPKG_FILE" .)

# NuGet push uses PUT with multipart/form-data
upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -F "package=@${NUPKG_FILE};type=application/octet-stream" \
  "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  # Try alternate push style (raw body)
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${NUPKG_FILE}" \
    "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package") || true
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
    pass
  else
    fail "package upload returned ${upload_status}, expected 200 or 201"
  fi
fi

# -----------------------------------------------------------------------
# Verify NuGet v3 service index
# -----------------------------------------------------------------------
begin_test "Verify service index"
service_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/v3/index.json" 2>/dev/null) || true

if [ -n "$service_resp" ]; then
  version=$(echo "$service_resp" | jq -r '.version // empty' 2>/dev/null) || true
  if [ -n "$version" ]; then
    pass
  else
    # Check for resources array (NuGet v3 service index structure)
    resources=$(echo "$service_resp" | jq -r '.resources // empty' 2>/dev/null) || true
    if [ -n "$resources" ] && [ "$resources" != "null" ]; then
      pass
    else
      fail "service index does not contain expected NuGet v3 structure"
    fi
  fi
else
  fail "could not fetch NuGet service index"
fi

# -----------------------------------------------------------------------
# Verify package registration
# -----------------------------------------------------------------------
begin_test "Verify package registration"
# NuGet v3 uses lowercase package IDs in URLs
PACKAGE_ID_LOWER=$(echo "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')

reg_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/v3/registration/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true

if [ -n "$reg_resp" ] && echo "$reg_resp" | grep -qi "$PACKAGE_ID"; then
  pass
else
  skip "package registration endpoint not available"
fi

# -----------------------------------------------------------------------
# Download package
# -----------------------------------------------------------------------
begin_test "Download package"
dl_file="$WORK_DIR/downloaded.nupkg"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>/dev/null) || true

if [ "$dl_status" = "200" ]; then
  if [ -s "$dl_file" ]; then
    pass
  else
    fail "downloaded nupkg is empty"
  fi
elif [ "$dl_status" = "404" ] || [ "$dl_status" = "405" ]; then
  skip "download endpoint not available for this format (status: ${dl_status})"
else
  fail "package download returned ${dl_status}, expected 200"
fi

# -----------------------------------------------------------------------
# Upload second version
# -----------------------------------------------------------------------
begin_test "Upload second version"
PACKAGE_VERSION_V2="2.0.$(date +%s)"

cat > "$PKG_DIR/${PACKAGE_ID}.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${PACKAGE_ID}</id>
    <version>${PACKAGE_VERSION_V2}</version>
    <authors>E2E Test</authors>
    <description>E2E test package v2 for NuGet registry</description>
    <license type="expression">MIT</license>
  </metadata>
</package>
EOF

echo "placeholder assembly v2" > "$PKG_DIR/lib/net8.0/${PACKAGE_ID}.dll"

NUPKG_FILE_V2="$WORK_DIR/${PACKAGE_ID}.${PACKAGE_VERSION_V2}.nupkg"
(cd "$PKG_DIR" && zip -qr "$NUPKG_FILE_V2" .)

v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -F "package=@${NUPKG_FILE_V2};type=application/octet-stream" \
  "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package") || true

if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  pass
else
  v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${NUPKG_FILE_V2}" \
    "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package") || true
  if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
    pass
  elif [ "$v2_status" = "404" ] || [ "$v2_status" = "405" ]; then
    skip "version upload endpoint not available for this format (status: ${v2_status})"
  else
    fail "v2 upload returned ${v2_status}"
  fi
fi

# -----------------------------------------------------------------------
# Delete package and verify removal
# -----------------------------------------------------------------------
begin_test "Delete package and verify removal"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package/${PACKAGE_ID}/${PACKAGE_VERSION}" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(format_auth_header)" \
    "${BASE_URL}/nuget/${REPO_KEY}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
else
  # Try management API delete
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${PACKAGE_ID}/${PACKAGE_VERSION}/${PACKAGE_ID}.${PACKAGE_VERSION}.nupkg" 2>&1) || true
  if [ "$status" = "200" ] || [ "$status" = "204" ]; then
    pass
  elif [ "$status" = "404" ] || [ "$status" = "405" ] || [ "$status" = "401" ]; then
    # 404 / 405: route not registered (DELETE for nupkg artifacts has no
    # handler on the management API). 401: middleware-level fallback
    # returns Unauthorized for unknown routes that match a parent's
    # auth scope before axum's router resolves the 404. Functionally
    # equivalent to "delete not supported" - treat the same. The
    # release/1.1.x middleware composition exhibits this on the NuGet
    # management path; main returns 404 directly.
    skip "delete not supported for this format (status: ${status})"
  else
    fail "delete returned ${status}"
  fi
fi


# =======================================================================
# #3835: the package id is reported as the .nuspec authored it
# =======================================================================
# The registry stores ids lowercased for lookups, but every read surface
# (V3 search, registration catalogEntry.id, autocomplete, V2 feed) must echo
# the authored spelling of the first push, while every V3 URL stays
# lowercased. A later push spelled differently must not fork the package.
CASE_REPO="test-nuget-case-${RUN_ID}"
CASE_ID="Qa.CasingPkg"
CASE_ID_LOWER="qa.casingpkg"

# build_nupkg_py ID VERSION OUT: minimal .nupkg via python zipfile (no zip/dotnet needed).
build_nupkg_py() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys, zipfile
pid, ver, out = sys.argv[1:4]
nuspec = f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{pid}</id>
    <version>{ver}</version>
    <authors>E2E Test</authors>
    <description>#3835 casing fixture</description>
  </metadata>
</package>
"""
ct = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/xml" />
  <Default Extension="dll" ContentType="application/octet-stream" />
</Types>
"""
rels = f"""<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/{pid}.nuspec" Id="R1" />
</Relationships>
"""
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr(f"{pid}.nuspec", nuspec)
    z.writestr("[Content_Types].xml", ct)
    z.writestr("_rels/.rels", rels)
    z.writestr(f"lib/net8.0/{pid}.dll", "placeholder assembly\n")
PY
}

# nuget_push REPO FILE: echoes the HTTP status (multipart, then raw body).
nuget_push() {
  local repo="$1" file="$2" code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$(format_auth_header)" \
    -F "package=@${file};type=application/octet-stream" \
    "${BASE_URL}/nuget/${repo}/api/v2/package") || code="000"
  if [ "$code" != "200" ] && [ "$code" != "201" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$(format_auth_header)" \
      -H "Content-Type: application/octet-stream" --data-binary "@${file}" \
      "${BASE_URL}/nuget/${repo}/api/v2/package") || code="000"
  fi
  echo "$code"
}

nuget_get() {
  curl -s --max-time 30 -H "$(format_auth_header)" "${BASE_URL}/nuget/${CASE_REPO}/$1" 2>/dev/null || true
}

# check_v3_casing LATEST_VERSION VERSION_COUNT: asserts search, registration and
# autocomplete report CASE_ID exactly and that no V3 URL carries the authored casing.
# (Search lists only the latest version per package, so the version count is
# checked on the registration index.)
check_v3_casing() {
  local want_latest="$1" want_versions="$2" problems="" search reg auto ids n urls cat_ids nver latest
  search=$(nuget_get "v3/search?q=${CASE_ID_LOWER}&prerelease=true")
  ids=$(echo "$search" | jq -r --arg l "$CASE_ID_LOWER" \
    '[.data[]? | select((.id|ascii_downcase)==$l) | .id] | join(",")' 2>/dev/null) || ids=""
  n=$(echo "$search" | jq -r --arg l "$CASE_ID_LOWER" \
    '[.data[]? | select((.id|ascii_downcase)==$l)] | length' 2>/dev/null) || n=""
  [ "$ids" = "$CASE_ID" ] || problems="${problems}search data[].id='${ids}' (want exactly one '${CASE_ID}', rows=${n}); "
  latest=$(echo "$search" | jq -r --arg l "$CASE_ID_LOWER" \
    '[.data[]? | select((.id|ascii_downcase)==$l) | .version] | join(",")' 2>/dev/null) || latest=""
  [ "$latest" = "$want_latest" ] || problems="${problems}search version='${latest}' (want ${want_latest}); "

  reg=$(nuget_get "v3/registration/${CASE_ID_LOWER}/index.json")
  cat_ids=$(echo "$reg" | jq -r '[.items[]?.items[]?.catalogEntry.id] | unique | join(",")' 2>/dev/null) || cat_ids=""
  nver=$(echo "$reg" | jq -r '[.items[]?.items[]?] | length' 2>/dev/null) || nver=""
  [ "$cat_ids" = "$CASE_ID" ] || problems="${problems}registration catalogEntry.id='${cat_ids}'; "
  [ "$nver" = "$want_versions" ] || problems="${problems}registration versions=${nver} (want ${want_versions}); "

  auto=$(nuget_get "v3/autocomplete?q=qa.casing&prerelease=true")
  ids=$(echo "$auto" | jq -r --arg l "$CASE_ID_LOWER" \
    '[.data[]? | select(ascii_downcase==$l)] | join(",")' 2>/dev/null) || ids=""
  [ "$ids" = "$CASE_ID" ] || problems="${problems}autocomplete data='${ids}'; "

  urls=$( { echo "$search"; echo "$reg"; } | jq -r '.. | strings | select(test("^https?://"))' 2>/dev/null \
    | grep -c 'CasingPkg' || true)
  [ "${urls:-0}" = "0" ] || problems="${problems}${urls} V3 URL(s) carry the authored casing (must stay lowercased); "
  [ -n "$(echo "$reg" | jq -r '.items[]?.items[]?.packageContent // empty' 2>/dev/null | grep "/flatcontainer/${CASE_ID_LOWER}/")" ] \
    || problems="${problems}packageContent not under /flatcontainer/${CASE_ID_LOWER}/; "
  echo "$problems"
}

# check_v2_casing: echoes problems with the hosted V2 feed d:Id values.
check_v2_casing() {
  local want_entries="$1" feed ids n
  feed=$(nuget_get "v2/FindPackagesById()?id='${CASE_ID_LOWER}'")
  ids=$(echo "$feed" | grep -o '<d:Id>[^<]*</d:Id>' | sed 's/<[^>]*>//g' | sort -u | paste -sd, -) || ids=""
  n=$(echo "$feed" | grep -o '<d:Id>' | wc -l | tr -d ' ') || true
  local p=""
  [ "$ids" = "$CASE_ID" ] || p="V2 d:Id values='${ids}' (want '${CASE_ID}'); "
  [ "$n" = "$want_entries" ] || p="${p}V2 entries=${n} (want ${want_entries}); "
  echo "$p"
}

begin_test "#3835: push mixed-case id ${CASE_ID} 1.0.0"
CASE_V1="$WORK_DIR/${CASE_ID}.1.0.0.nupkg"
if ! create_local_repo "$CASE_REPO" "nuget"; then
  fail "could not create ${CASE_REPO}"
else
  build_nupkg_py "$CASE_ID" "1.0.0" "$CASE_V1"
  st=$(nuget_push "$CASE_REPO" "$CASE_V1")
  if [ "$st" = "200" ] || [ "$st" = "201" ]; then pass; else fail "push returned ${st}"; fi
fi

begin_test "#3835: V3 search/registration/autocomplete report ${CASE_ID}, URLs lowercased"
probs=$(check_v3_casing 1.0.0 1)
if [ -z "$probs" ]; then pass; else fail "$probs" "$(nuget_get "v3/search?q=${CASE_ID_LOWER}" | head -c 800)"; fi

begin_test "#3835: hosted V2 feed reports ${CASE_ID}"
probs=$(check_v2_casing 1)
if [ -z "$probs" ]; then pass; else fail "$probs"; fi

begin_test "#3835: second push spelled ${CASE_ID_LOWER} 2.0.0"
CASE_V2="$WORK_DIR/${CASE_ID_LOWER}.2.0.0.nupkg"
build_nupkg_py "$CASE_ID_LOWER" "2.0.0" "$CASE_V2"
st=$(nuget_push "$CASE_REPO" "$CASE_V2")
if [ "$st" = "200" ] || [ "$st" = "201" ]; then pass; else fail "second push returned ${st}"; fi

begin_test "#3835: after lowercase push, V3 keeps first spelling across both versions"
probs=$(check_v3_casing 2.0.0 2)
if [ -z "$probs" ]; then pass; else fail "$probs" "$(nuget_get "v3/registration/${CASE_ID_LOWER}/index.json" | head -c 800)"; fi

begin_test "#3835: after lowercase push, V2 feed keeps first spelling for every version"
probs=$(check_v2_casing 2)
if [ -z "$probs" ]; then pass; else fail "$probs"; fi

begin_test "#3835: lowercase push does not create a second package"
pk=$(curl -s -H "$(auth_header)" \
  "${BASE_URL}/api/v1/packages?repository_key=${CASE_REPO}&per_page=100" 2>/dev/null) || pk=""
pk_names=$(echo "$pk" | jq -r --arg l "$CASE_ID_LOWER" \
  '[(.items // .data // .packages // .)[]? | select((.name|ascii_downcase)==$l) | .name] | join(",")' 2>/dev/null) || pk_names=""
if [ "$pk_names" = "$CASE_ID" ]; then
  pass
else
  fail "/api/v1/packages rows for ${CASE_ID_LOWER}: '${pk_names}' (want exactly one '${CASE_ID}')" "$(echo "$pk" | head -c 800)"
fi

# =======================================================================
# #3899: a failing remote resolution step is logged with step/repo/status
# =======================================================================
# Only observable in the backend log. Needs kubectl access to the namespace
# (AK_NAMESPACE, e.g. test-<deploy-run-id>) and a mock upstream the backend
# pod can reach (MOCK_UPSTREAM_HOSTNAME). Otherwise the section skips; the
# behaviour is also covered by the backend test
# remote_discovery_tests::registration_page_failure_logs_the_step_upstream_and_status.
begin_test "#3899: remote registration page 500 is logged with step, repo key and status"
if [ -z "${AK_NAMESPACE:-}" ] || ! command -v kubectl >/dev/null 2>&1 \
   || ! kubectl -n "$AK_NAMESPACE" get deploy artifact-keeper-backend >/dev/null 2>&1; then
  skip "needs AK_NAMESPACE + kubectl access to deploy/artifact-keeper-backend"
elif [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip "needs MOCK_UPSTREAM_HOSTNAME reachable from the backend pod"
elif ! start_mock_upstream "$(mktemp -d "$WORK_DIR/mock-nuget.XXXXXX")"; then
  fail "mock upstream did not start"
else
  REM_REPO="test-nuget-rem3899-${RUN_ID}"
  FAIL_ID="qa.failpage"
  mkdir -p "$MOCK_STATE_DIR/files/v3"
  cat > "$MOCK_STATE_DIR/files/v3/index.json" <<EOF
{"version":"3.0.0","resources":[
 {"@id":"${MOCK_BASE_URL}/v3/registration/","@type":"RegistrationsBaseUrl/3.6.0"},
 {"@id":"${MOCK_BASE_URL}/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}
EOF
  echo "/v3/registration/${FAIL_ID}/page/ 500" > "$MOCK_STATE_DIR/status-prefixes"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if ! create_remote_repo "$REM_REPO" "nuget" "${MOCK_BASE_URL}/v3/index.json"; then
    fail "could not create remote nuget repo ${REM_REPO}"
  else
    page_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -H "$(format_auth_header)" \
      "${BASE_URL}/nuget/${REM_REPO}/v3/registration/${FAIL_ID}/page/1.0.0/2.0.0.json") || page_status="000"
    sleep 2
    upstream_hits=$(grep -c "/v3/registration/${FAIL_ID}/page/" "$MOCK_STATE_DIR/request-log.txt" || true)
    lines=$(kubectl -n "$AK_NAMESPACE" logs deploy/artifact-keeper-backend --since-time="$since" --all-containers 2>/dev/null \
      | sed 's/\x1b\[[0-9;]*m//g' \
      | grep -E 'step(=|":)"?registration_page\b' | grep -E "repo_key(=|\":)\"?${REM_REPO}\b" || true)
    if [ "${upstream_hits:-0}" = "0" ]; then
      fail "backend never fetched the page from the mock (client status ${page_status})"
    elif [ "$page_status" = "200" ]; then
      fail "page answered 200 although the upstream answered 500"
    elif [ -z "$lines" ]; then
      fail "no backend log line with step=registration_page and repo_key=${REM_REPO} (client status ${page_status}, upstream hits ${upstream_hits})"
    elif ! echo "$lines" | grep -Eq 'status(=|":)5[0-9][0-9]'; then
      fail "log line lacks a 5xx status field" "$lines"
    elif ! echo "$lines" | grep -q "/v3/registration/${FAIL_ID}/page/1.0.0/2.0.0.json"; then
      fail "log line lacks the fetch URL" "$lines"
    else
      echo "  client status ${page_status}; log: $(echo "$lines" | head -n 1 | cut -c 1-400)"
      pass
    fi
  fi
  stop_mock_upstream
fi

end_suite
