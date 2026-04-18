#!/usr/bin/env bash
# test-conan-stress.sh - Conan v2 stress and concurrency E2E tests
#
# Exercises the Conan v2 REST API under load: rapid sequential uploads,
# concurrent writes, concurrent reads, large file handling, revision churn,
# and mixed read/write workloads. All operations use the Conan v2 wire
# protocol at /conan/{repo_key}/v2/conans/...
#
# Requires: curl, jq, md5sum (or md5 on macOS)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-stress"
auth_admin
setup_workdir

REPO_KEY="test-conan-stress-${RUN_ID}"
CONAN_BASE="${BASE_URL}/conan/${REPO_KEY}/v2/conans"

# ---------------------------------------------------------------------------
# Helper: compute md5 portably (Linux md5sum vs macOS md5)
# ---------------------------------------------------------------------------
portable_md5() {
  local file="$1"
  if command -v md5sum &>/dev/null; then
    md5sum "$file" | cut -d' ' -f1
  else
    md5 -q "$file"
  fi
}

# ---------------------------------------------------------------------------
# Helper: generate a revision hash from a string
# ---------------------------------------------------------------------------
make_rev() {
  if command -v md5sum &>/dev/null; then
    echo -n "$1" | md5sum | cut -d' ' -f1
  else
    echo -n "$1" | md5 -q
  fi
}

# ---------------------------------------------------------------------------
# Helper: upload a conanfile.py to a recipe and return the HTTP status
# ---------------------------------------------------------------------------
conan_upload_recipe() {
  local name="$1" version="$2" revision="$3" filepath="$4"
  curl -s -o /dev/null -w '%{http_code}' -X PUT \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${filepath}" \
    "${CONAN_BASE}/${name}/${version}/_/_/revisions/${revision}/files/conanfile.py"
}

# ---------------------------------------------------------------------------
# Helper: download a recipe file and return the HTTP status
# ---------------------------------------------------------------------------
conan_download_recipe() {
  local name="$1" version="$2" revision="$3" filename="$4" dest="$5"
  curl -s -o "$dest" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONAN_BASE}/${name}/${version}/_/_/revisions/${revision}/files/${filename}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: generate a minimal conanfile.py for a given name and version
# ---------------------------------------------------------------------------
gen_conanfile() {
  local name="$1" version="$2" outfile="$3"
  cat > "$outfile" <<PYEOF
from conan import ConanFile

class ${name}Conan(ConanFile):
    name = "${name}"
    version = "${version}"
    license = "MIT"
    description = "Stress test recipe ${name}/${version}"
    settings = "os", "compiler", "build_type", "arch"
PYEOF
}

# =========================================================================
# 1. Create local Conan repository
# =========================================================================
begin_test "Create local Conan repository"
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repo"
fi

# =========================================================================
# 2. Rapid sequential uploads: 20 recipe versions
# =========================================================================
begin_test "Upload 20 recipe versions rapidly"

upload_failures=0
for i in $(seq 0 19); do
  version="1.0.${i}"
  rev=$(make_rev "stresslib-${version}-content")
  gen_conanfile "stresslib" "$version" "${WORK_DIR}/stresslib-${i}.py"

  status=$(conan_upload_recipe "stresslib" "$version" "$rev" "${WORK_DIR}/stresslib-${i}.py") || true
  if [ "$status" -lt 200 ] 2>/dev/null || [ "$status" -ge 300 ] 2>/dev/null; then
    echo "  stresslib/1.0.${i}: HTTP ${status}"
    upload_failures=$((upload_failures + 1))
  fi
done

if [ "$upload_failures" -eq 0 ]; then
  pass
else
  fail "${upload_failures}/20 rapid uploads failed"
fi

# =========================================================================
# 3. Search for stresslib* and verify all 20 versions appear
# =========================================================================
begin_test "Search stresslib* returns all 20 versions"

# Brief pause to let indexing settle
sleep 1

search_resp=$(curl -s $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/search?q=stresslib*") || true

if [ -z "$search_resp" ]; then
  fail "search returned empty response"
else
  missing=0
  for i in $(seq 0 19); do
    if [[ "$search_resp" != *"stresslib/1.0.${i}"* ]]; then
      echo "  missing: stresslib/1.0.${i}"
      missing=$((missing + 1))
    fi
  done

  if [ "$missing" -eq 0 ]; then
    pass
  else
    fail "${missing}/20 versions missing from search results"
  fi
fi

# =========================================================================
# 4. Concurrent uploads: 10 different recipes in parallel
# =========================================================================
begin_test "Concurrent uploads of 10 different recipes"

mkdir -p "${WORK_DIR}/concurrent-results"

for i in $(seq 0 9); do
  (
    name="concurrent-${i}"
    rev=$(make_rev "${name}-1.0.0-content")
    gen_conanfile "$name" "1.0.0" "${WORK_DIR}/${name}.py"
    status=$(conan_upload_recipe "$name" "1.0.0" "$rev" "${WORK_DIR}/${name}.py") || true
    echo "$status" > "${WORK_DIR}/concurrent-results/${name}.status"
  ) &
done

wait

concurrent_ok=0
concurrent_fail=0
for i in $(seq 0 9); do
  sf="${WORK_DIR}/concurrent-results/concurrent-${i}.status"
  if [ -f "$sf" ]; then
    code=$(cat "$sf")
    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 300 ] 2>/dev/null; then
      concurrent_ok=$((concurrent_ok + 1))
    else
      concurrent_fail=$((concurrent_fail + 1))
      echo "  concurrent-${i}: HTTP ${code}"
    fi
  else
    concurrent_fail=$((concurrent_fail + 1))
    echo "  concurrent-${i}: no status file"
  fi
done

echo "  ${concurrent_ok}/10 concurrent uploads succeeded"
if [ "$concurrent_ok" -ge 9 ]; then
  pass
else
  fail "only ${concurrent_ok}/10 concurrent uploads succeeded, expected at least 9"
fi

# =========================================================================
# 5. Concurrent reads: upload one recipe, then 20 parallel downloads
# =========================================================================
begin_test "Concurrent reads: 20 parallel downloads of one recipe"

# Upload a recipe to read from
READER_REV=$(make_rev "reader-recipe-1.0.0")
gen_conanfile "readerlib" "1.0.0" "${WORK_DIR}/readerlib.py"
upload_status=$(conan_upload_recipe "readerlib" "1.0.0" "$READER_REV" "${WORK_DIR}/readerlib.py") || true

if [ "$upload_status" -lt 200 ] 2>/dev/null || [ "$upload_status" -ge 300 ] 2>/dev/null; then
  fail "could not upload reader recipe (HTTP ${upload_status})"
else
  mkdir -p "${WORK_DIR}/read-results"

  for i in $(seq 1 20); do
    (
      status=$(curl -s -o /dev/null -w '%{http_code}' \
        $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        "${CONAN_BASE}/readerlib/1.0.0/_/_/revisions/${READER_REV}/files/conanfile.py") || true
      echo "$status" > "${WORK_DIR}/read-results/read-${i}.status"
    ) &
  done

  wait

  read_ok=0
  read_fail=0
  for i in $(seq 1 20); do
    sf="${WORK_DIR}/read-results/read-${i}.status"
    if [ -f "$sf" ]; then
      code=$(cat "$sf")
      if [ "$code" = "200" ]; then
        read_ok=$((read_ok + 1))
      else
        read_fail=$((read_fail + 1))
        echo "  read-${i}: HTTP ${code}"
      fi
    else
      read_fail=$((read_fail + 1))
      echo "  read-${i}: no status file"
    fi
  done

  echo "  ${read_ok}/20 concurrent reads returned 200"
  if [ "$read_ok" -ge 19 ]; then
    pass
  else
    fail "only ${read_ok}/20 concurrent reads succeeded, expected at least 19"
  fi
fi

# =========================================================================
# 6. Large recipe file upload: 5MB conanfile.py
# =========================================================================
begin_test "Upload and download 5MB conanfile.py"

large_file="${WORK_DIR}/large-conanfile.py"
{
  cat <<'PYEOF'
from conan import ConanFile

class LargeLibConan(ConanFile):
    name = "largelib"
    version = "1.0.0"
    license = "MIT"
    description = "Large recipe stress test"
    settings = "os", "compiler", "build_type", "arch"
PYEOF
  # Pad the file to approximately 5MB with Python comments
  for j in $(seq 1 65000); do
    echo "# padding line ${j}: this line exists to inflate the recipe to stress-test large file handling"
  done
} > "$large_file"

large_size=$(wc -c < "$large_file" | tr -d ' ')
echo "  generated file: ${large_size} bytes"

LARGE_REV=$(make_rev "largelib-1.0.0-large-content")
upload_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  --max-time 120 --connect-timeout 10 \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${large_file}" \
  "${CONAN_BASE}/largelib/1.0.0/_/_/revisions/${LARGE_REV}/files/conanfile.py") || true

if [ "$upload_status" -lt 200 ] 2>/dev/null || [ "$upload_status" -ge 300 ] 2>/dev/null; then
  fail "large recipe upload returned HTTP ${upload_status}"
else
  # Download and verify size matches
  dl_file="${WORK_DIR}/dl-large-conanfile.py"
  dl_status=$(curl -s -o "$dl_file" -w '%{http_code}' \
    --max-time 120 --connect-timeout 10 \
    -H "$(format_auth_header)" \
    "${CONAN_BASE}/largelib/1.0.0/_/_/revisions/${LARGE_REV}/files/conanfile.py" 2>/dev/null) || true

  if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
    dl_size=$(wc -c < "$dl_file" | tr -d ' ')
    if assert_eq "$dl_size" "$large_size" "downloaded size ${dl_size} does not match uploaded size ${large_size}"; then
      pass
    fi
  else
    fail "large recipe download failed (HTTP ${dl_status})"
  fi
fi

# =========================================================================
# 7. Large package tarball: 10MB conan_package.tgz
# =========================================================================
begin_test "Upload and download 10MB package tarball"

# First upload a recipe revision for the package to belong to
PKG_RECIPE_REV=$(make_rev "bigpkg-1.0.0-recipe")
gen_conanfile "bigpkg" "1.0.0" "${WORK_DIR}/bigpkg.py"
conan_upload_recipe "bigpkg" "1.0.0" "$PKG_RECIPE_REV" "${WORK_DIR}/bigpkg.py" > /dev/null 2>&1 || true

# Create a 10MB tarball
mkdir -p "${WORK_DIR}/bigpkg-staging/lib"
dd if=/dev/urandom of="${WORK_DIR}/bigpkg-staging/lib/libbigpkg.a" bs=1024 count=10240 2>/dev/null
tar czf "${WORK_DIR}/big_package.tgz" -C "${WORK_DIR}/bigpkg-staging" lib

big_size=$(wc -c < "${WORK_DIR}/big_package.tgz" | tr -d ' ')
echo "  generated tarball: ${big_size} bytes"

PKG_ID="da39a3ee5e6b4b0d3255bfef95601890afd80709"
PKG_REV=$(make_rev "bigpkg-pkgrev-1")
PKG_FILE_URL="${CONAN_BASE}/bigpkg/1.0.0/_/_/revisions/${PKG_RECIPE_REV}/packages/${PKG_ID}/revisions/${PKG_REV}/files/conan_package.tgz"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  --max-time 180 --connect-timeout 10 \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/big_package.tgz" \
  "$PKG_FILE_URL") || true

if [ "$upload_status" -lt 200 ] 2>/dev/null || [ "$upload_status" -ge 300 ] 2>/dev/null; then
  fail "10MB tarball upload returned HTTP ${upload_status}"
else
  dl_pkg="${WORK_DIR}/dl-big-package.tgz"
  dl_status=$(curl -s -o "$dl_pkg" -w '%{http_code}' \
    --max-time 180 --connect-timeout 10 \
    -H "$(format_auth_header)" \
    "$PKG_FILE_URL" 2>/dev/null) || true

  if [ "$dl_status" = "200" ] && [ -s "$dl_pkg" ]; then
    dl_size=$(wc -c < "$dl_pkg" | tr -d ' ')
    if assert_eq "$dl_size" "$big_size" "downloaded tarball size ${dl_size} does not match uploaded size ${big_size}"; then
      pass
    fi
  else
    fail "10MB tarball download failed (HTTP ${dl_status})"
  fi
fi

# =========================================================================
# 8. Rapid revision churn: 10 revisions of the same recipe
# =========================================================================
begin_test "Rapid revision churn: 10 revisions of one recipe"

CHURN_NAME="churnlib"
last_rev=""

for i in $(seq 1 10); do
  rev=$(make_rev "churnlib-rev-${i}")
  last_rev="$rev"

  cat > "${WORK_DIR}/churnlib-r${i}.py" <<PYEOF
from conan import ConanFile

class ChurnLibConan(ConanFile):
    name = "churnlib"
    version = "1.0.0"
    license = "MIT"
    description = "Revision ${i} of churnlib"
    settings = "os", "compiler", "build_type", "arch"
PYEOF

  status=$(conan_upload_recipe "$CHURN_NAME" "1.0.0" "$rev" "${WORK_DIR}/churnlib-r${i}.py") || true
  if [ "$status" -lt 200 ] 2>/dev/null || [ "$status" -ge 300 ] 2>/dev/null; then
    fail "churnlib revision ${i} upload returned HTTP ${status}"
    last_rev=""
    break
  fi
done

if [ -n "$last_rev" ]; then
  # Verify that latest points to the final revision
  latest_resp=$(curl -sf \
    -H "$(format_auth_header)" \
    $CURL_TIMEOUT \
    "${CONAN_BASE}/${CHURN_NAME}/1.0.0/_/_/latest") || true

  if [ -z "$latest_resp" ]; then
    fail "latest revision returned empty response after 10 revisions"
  else
    latest_rev=$(echo "$latest_resp" | jq -r '.revision // empty')
    if assert_eq "$latest_rev" "$last_rev" "latest revision should be the 10th upload, got ${latest_rev}"; then
      pass
    fi
  fi
fi

# =========================================================================
# 9. Search performance: q=* returns results within timeout
# =========================================================================
begin_test "Search q=* returns results within timeout"

search_start=$(date +%s)
search_resp=$(curl -s -w '\n%{http_code}' \
  --max-time 30 --connect-timeout 10 \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/search?q=*") || true
search_end=$(date +%s)
search_duration=$((search_end - search_start))

# Split body and status
search_status=$(echo "$search_resp" | tail -1)
search_body=$(echo "$search_resp" | sed '$d')

echo "  search completed in ${search_duration}s (HTTP ${search_status})"

if [ "$search_status" = "200" ]; then
  # Verify we got a non-empty result set
  result_count=$(echo "$search_body" | jq '.results | length' 2>/dev/null) || result_count="0"
  echo "  search returned ${result_count} results"
  if [ "$result_count" -gt 0 ] 2>/dev/null; then
    if [ "$search_duration" -le 30 ]; then
      pass
    else
      fail "search took ${search_duration}s, exceeds 30s timeout"
    fi
  else
    fail "search returned 0 results despite uploaded recipes"
  fi
else
  fail "search returned HTTP ${search_status}"
fi

# =========================================================================
# 10. Mixed concurrent read/write workload
# =========================================================================
begin_test "Mixed concurrent read/write workload"

mkdir -p "${WORK_DIR}/mixed-results"

# Writers: upload 5 new recipes
for i in $(seq 0 4); do
  (
    name="mixwrite-${i}"
    rev=$(make_rev "${name}-1.0.0-mixed")
    gen_conanfile "$name" "1.0.0" "${WORK_DIR}/${name}.py"
    status=$(conan_upload_recipe "$name" "1.0.0" "$rev" "${WORK_DIR}/${name}.py") || true
    echo "$status" > "${WORK_DIR}/mixed-results/write-${i}.status"
  ) &
done

# Readers: download the readerlib recipe uploaded in test 5 (10 concurrent reads)
for i in $(seq 0 9); do
  (
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${CONAN_BASE}/readerlib/1.0.0/_/_/revisions/${READER_REV}/files/conanfile.py") || true
    echo "$status" > "${WORK_DIR}/mixed-results/read-${i}.status"
  ) &
done

wait

write_ok=0
write_fail=0
for i in $(seq 0 4); do
  sf="${WORK_DIR}/mixed-results/write-${i}.status"
  if [ -f "$sf" ]; then
    code=$(cat "$sf")
    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 300 ] 2>/dev/null; then
      write_ok=$((write_ok + 1))
    else
      write_fail=$((write_fail + 1))
      echo "  mixwrite-${i}: HTTP ${code}"
    fi
  else
    write_fail=$((write_fail + 1))
    echo "  mixwrite-${i}: no status file"
  fi
done

read_ok=0
read_fail=0
for i in $(seq 0 9); do
  sf="${WORK_DIR}/mixed-results/read-${i}.status"
  if [ -f "$sf" ]; then
    code=$(cat "$sf")
    if [ "$code" = "200" ]; then
      read_ok=$((read_ok + 1))
    else
      read_fail=$((read_fail + 1))
      echo "  mixread-${i}: HTTP ${code}"
    fi
  else
    read_fail=$((read_fail + 1))
    echo "  mixread-${i}: no status file"
  fi
done

echo "  writes: ${write_ok}/5 succeeded, reads: ${read_ok}/10 succeeded"

if [ "$write_ok" -ge 4 ] && [ "$read_ok" -ge 9 ]; then
  pass
else
  fail "mixed workload: ${write_ok}/5 writes and ${read_ok}/10 reads succeeded, expected at least 4 writes and 9 reads"
fi

# =========================================================================
# Cleanup
# =========================================================================
echo ""
echo "Cleaning up repository ${REPO_KEY}..."
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
