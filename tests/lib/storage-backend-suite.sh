# storage-backend-suite.sh - Shared object-storage backend E2E suite
#
# Runs the same artifact round-trip contract against a named storage backend
# (s3, azure, gcs). Sourced by the thin per-backend wrappers in
# tests/platform/test-storage-backend-*.sh.
#
# The suite probes GET /api/v1/admin/storage-backends first and skips every
# test when the backend is not registered, so the gate stays green on
# deployments without the storage emulators (values-test.yaml) and on
# backends that cannot run against an emulator yet (gcs until
# artifact-keeper#2646 ships an endpoint override, azure until
# artifact-keeper#2649 fixes path-style Shared Key signing).
#
# Contract exercised per backend:
#   1. Repository creation with an explicit storage_backend override
#   2. Small artifact round-trip with checksum verification
#   3. Multi-MiB artifact round-trip (exercises multipart/resumable upload
#      paths and streaming downloads through the real HTTP client)
#   4. Nested path upload
#   5. Artifact delete reaches the object store (GET returns 404 after)
#
# Requires: curl, jq, shasum or sha256sum

# Portable sha256 (mirrors test-maven-s3.sh).
_sb_sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# run_storage_backend_suite <backend-name>
run_storage_backend_suite() {
  local backend="$1"

  begin_suite "storage-backend-${backend}"
  auth_admin
  setup_workdir

  local repo_key="test-storage-${backend}-${RUN_ID}"

  # -------------------------------------------------------------------------
  # Backend availability probe
  # -------------------------------------------------------------------------

  begin_test "Backend '${backend}' is registered"
  local resp
  if resp=$(api_get "/api/v1/admin/storage-backends" 2>/dev/null); then
    if echo "$resp" | jq -e --arg b "$backend" '
        (if type == "array" then . elif (.backends | type == "array") then .backends
         elif (.items | type == "array") then .items else [] end)
        | map(if type == "string" then . else (.name // .key // .backend_type // "") end)
        | index($b) != null' > /dev/null 2>&1; then
      pass
    else
      # The capability is genuinely not provisioned. Route through skip_suite
      # so the _CAPABILITY_EXEMPTIONS allowlist decides the outcome, rather
      # than emitting per-test skips that leave the suite certifying nothing
      # while still exiting 0 (test#339 / test#347). The reason carries the
      # backend NAME on purpose: only gcs and azure are exempt, so if s3 --
      # which is provisioned and passing -- ever stops registering, this
      # hard-fails instead of being silently excused.
      skip_suite "storage backend '${backend}' not registered on this deployment"
    fi
  else
    # Deliberately NOT exempt. If the probe itself cannot run we have learned
    # nothing about the candidate, which under RELEASE_GATE=1 must fail rather
    # than skip.
    skip_suite "admin storage-backends endpoint unavailable; cannot probe '${backend}'"
  fi

  # -------------------------------------------------------------------------
  # 1. Repository with explicit storage_backend
  # -------------------------------------------------------------------------

  begin_test "Create generic repository on ${backend}"
  local payload="{\"key\":\"${repo_key}\",\"name\":\"${repo_key}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true,\"storage_backend\":\"${backend}\"}"
  local http_code
  http_code=$(curl -s -o "${WORK_DIR}/create-repo.json" -w "%{http_code}" $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/repositories")
  if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
    pass
  else
    fail "repo create with storage_backend=${backend} returned ${http_code}: $(head -c 200 "${WORK_DIR}/create-repo.json")"
    end_suite
    return 1
  fi

  # -------------------------------------------------------------------------
  # 2. Small artifact round-trip
  # -------------------------------------------------------------------------

  begin_test "Small artifact round-trip on ${backend}"
  echo "storage backend ${backend} round-trip ${RUN_ID}" > "${WORK_DIR}/small.txt"
  local small_sha
  small_sha=$(_sb_sha256 "${WORK_DIR}/small.txt")
  if api_upload "/api/v1/repositories/${repo_key}/artifacts/roundtrip/small.txt" \
      "${WORK_DIR}/small.txt" "text/plain" > /dev/null \
     && curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
          -o "${WORK_DIR}/small.down" \
          "${BASE_URL}/api/v1/repositories/${repo_key}/download/roundtrip/small.txt" \
     && [ "$(_sb_sha256 "${WORK_DIR}/small.down")" = "$small_sha" ]; then
    pass
  else
    fail "small artifact upload/download/checksum failed on ${backend}"
  fi

  # -------------------------------------------------------------------------
  # 3. Multi-MiB artifact round-trip (multipart / resumable upload paths)
  # -------------------------------------------------------------------------

  begin_test "Multi-MiB artifact round-trip on ${backend}"
  # 16 MiB of random (incompressible) data: large enough to cross chunked
  # upload thresholds, small enough for the per-test timeout budget.
  head -c $((16 * 1024 * 1024)) /dev/urandom > "${WORK_DIR}/large.bin"
  local large_sha
  large_sha=$(_sb_sha256 "${WORK_DIR}/large.bin")
  if api_upload "/api/v1/repositories/${repo_key}/artifacts/roundtrip/large.bin" \
      "${WORK_DIR}/large.bin" "application/octet-stream" > /dev/null \
     && curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
          -o "${WORK_DIR}/large.down" \
          "${BASE_URL}/api/v1/repositories/${repo_key}/download/roundtrip/large.bin" \
     && [ "$(_sb_sha256 "${WORK_DIR}/large.down")" = "$large_sha" ]; then
    pass
  else
    fail "16MiB artifact upload/download/checksum failed on ${backend}"
  fi

  # -------------------------------------------------------------------------
  # 4. Nested path upload
  # -------------------------------------------------------------------------

  begin_test "Nested path upload on ${backend}"
  echo "nested ${backend} ${RUN_ID}" > "${WORK_DIR}/nested.txt"
  if api_upload "/api/v1/repositories/${repo_key}/artifacts/a/b/c/d/nested.txt" \
      "${WORK_DIR}/nested.txt" "text/plain" > /dev/null \
     && curl -sf $CURL_TIMEOUT -H "$(auth_header)" -o /dev/null \
          "${BASE_URL}/api/v1/repositories/${repo_key}/download/a/b/c/d/nested.txt"; then
    pass
  else
    fail "nested path upload/download failed on ${backend}"
  fi

  # -------------------------------------------------------------------------
  # 5. Delete reaches the object store
  # -------------------------------------------------------------------------

  begin_test "Artifact delete on ${backend}"
  local del_code get_code
  del_code=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${repo_key}/artifacts/roundtrip/small.txt")
  get_code=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${repo_key}/download/roundtrip/small.txt")
  if [ "$del_code" = "200" ] || [ "$del_code" = "204" ]; then
    if [ "$get_code" = "404" ] || [ "$get_code" = "410" ]; then
      pass
    else
      fail "deleted artifact still downloadable (GET ${get_code}) on ${backend}"
    fi
  else
    fail "artifact delete returned ${del_code} on ${backend}"
  fi

  # Cleanup (best effort)
  api_delete "/api/v1/repositories/${repo_key}" > /dev/null 2>&1 || true

  end_suite
}
