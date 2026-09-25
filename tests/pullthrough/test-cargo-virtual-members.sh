#!/usr/bin/env bash
# test-cargo-virtual-members.sh -- Cargo virtual-repository member resolution.
#
# Companion E2E for backend issues #3952, #3953 and #3937 (cluster
# cargo-virtual). All three defects live on the cargo Virtual repo paths and
# share one fixture shape: a virtual repo aggregating a local member and a
# remote member whose "upstream" is this suite's controllable mock
# (tests/lib/mock-upstream.py), so every byte the upstream serves is
# deliberate.
#
#   #3952 -- the Virtual download route never resolved the member's
#     config.json `dl` template, so it asked the member's INDEX host for the
#     crate body. The mock's config.json names a DIFFERENT path for downloads
#     (`/dl-crates/...`) than the canonical `/api/v1/crates/...` path, and the
#     crate body exists only at the `dl` path -- the download can only
#     succeed if the backend resolved the template. On the unfixed backend
#     this section fails with a 404 (and the mock's request log shows the
#     `/api/v1/crates/...` hit the fix must not make).
#
#   #3953 -- the Virtual download ownership guard fired on the crate NAME
#     alone, so a local member holding `virtcrate@1.0.0` shadowed the
#     upstream-only `virtcrate@2.0.0` that the merged sparse index still
#     advertised. The suite publishes 1.0.0 locally, serves 1.0.0 + 2.0.0
#     from the mock, and asserts 2.0.0 resolves through the virtual (404 on
#     the unfixed backend) while 1.0.0 still serves the LOCAL bytes (the
#     dependency-confusion shadowing defence, unchanged).
#
#   #3937 -- the ungated Virtual member index fetch was coding-blind, so a
#     member body stored content-encoded contributed zero NDJSON lines. The
#     mock serves `gzipcrate`'s index document gzip-coded; the merged index
#     must still list its version (empty aggregation -> 404 on the unfixed
#     backend).
#
# Requires: curl, jq, gzip. MOCK_UPSTREAM_HOSTNAME must name the runner pod
# for the backend (see tests/security/test-cache-poisoning.sh).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cargo-virtual-members"

if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; CI must set this to a name the backend can resolve to the test runner pod"
fi

auth_admin
setup_workdir

LOCAL_KEY="cv-local-${RUN_ID}"
REMOTE_KEY="cv-remote-${RUN_ID}"
VIRTUAL_KEY="cv-virt-${RUN_ID}"

# The local member owns virtcrate@1.0.0 (distinct bytes from upstream).
LOCAL_V1_BODY="local-owned-virtcrate-1.0.0-${RUN_ID}"
UPSTREAM_V1_BODY="upstream-virtcrate-1.0.0-${RUN_ID}"
UPSTREAM_V2_BODY="upstream-virtcrate-2.0.0-${RUN_ID}"
UPSTREAM_DLCRATE_BODY="upstream-dlcrate-1.0.0-${RUN_ID}"
GZIPCRATE_VERSION="3.1.0"

index_line() {
  # index_line NAME VERS CKSUM -- one sparse-index NDJSON line.
  jq -cn --arg name "$1" --arg vers "$2" --arg cksum "$3" \
    '{name: $name, vers: $vers, deps: [], cksum: $cksum, features: {}, yanked: false}'
}

# ---------------------------------------------------------------------------
# Boot the mock upstream and seed every document it serves
# ---------------------------------------------------------------------------

begin_test "Mock upstream starts with seeded cargo registry state"
if start_mock_upstream "${WORK_DIR}/mock-state"; then
  FILES="${MOCK_STATE_DIR}/files"
  mkdir -p "${FILES}/vi/rt" "${FILES}/dl/cr" "${FILES}/gz/ip" \
    "${FILES}/dl-crates/virtcrate/1.0.0" \
    "${FILES}/dl-crates/virtcrate/2.0.0" \
    "${FILES}/dl-crates/dlcrate/1.0.0"

  printf '%s' "$UPSTREAM_V1_BODY" > "${FILES}/dl-crates/virtcrate/1.0.0/download"
  printf '%s' "$UPSTREAM_V2_BODY" > "${FILES}/dl-crates/virtcrate/2.0.0/download"
  printf '%s' "$UPSTREAM_DLCRATE_BODY" > "${FILES}/dl-crates/dlcrate/1.0.0/download"
  V1_SUM=$(shasum -a 256 "${FILES}/dl-crates/virtcrate/1.0.0/download" | awk '{print $1}')
  V2_SUM=$(shasum -a 256 "${FILES}/dl-crates/virtcrate/2.0.0/download" | awk '{print $1}')
  DL_SUM=$(shasum -a 256 "${FILES}/dl-crates/dlcrate/1.0.0/download" | awk '{print $1}')

  # config.json: the `dl` template names a DIFFERENT path than the canonical
  # /api/v1/crates/... the pre-#3952 virtual route built. The crate bodies
  # above exist ONLY at the dl path, so downloads prove template resolution.
  jq -cn --arg dl "${MOCK_BASE_URL}/dl-crates/{crate}/{version}/download" \
    --arg api "${MOCK_BASE_URL}" \
    '{dl: $dl, api: $api}' > "${FILES}/config.json"

  # Sparse-index documents (virtcrate: both versions upstream; dlcrate:
  # upstream-only; gzipcrate: served gzip-coded below).
  index_line "virtcrate" "1.0.0" "$V1_SUM" > "${FILES}/vi/rt/virtcrate"
  index_line "virtcrate" "2.0.0" "$V2_SUM" >> "${FILES}/vi/rt/virtcrate"
  index_line "dlcrate" "1.0.0" "$DL_SUM" > "${FILES}/dl/cr/dlcrate"

  # #3937: a member index body STORED content-encoded. The mock replays the
  # declared Content-Encoding regardless of the request, exactly like an
  # object store serving a stored-coded object.
  GZ_SUM=$(printf '%s' "gzipcrate-bytes" | shasum -a 256 | awk '{print $1}')
  index_line "gzipcrate" "$GZIPCRATE_VERSION" "$GZ_SUM" | gzip -c > "${FILES}/gz/ip/gzipcrate"
  printf 'Content-Encoding: gzip\n' > "${FILES}/gz/ip/gzipcrate.headers"
  pass
else
  fail "mock upstream did not boot"
  end_suite
fi

# ---------------------------------------------------------------------------
# Repositories: local member (seeded), remote member (mock), virtual over both
# ---------------------------------------------------------------------------

begin_test "Create local member and seed virtcrate@1.0.0 with local bytes"
if create_local_repo "$LOCAL_KEY" "cargo" && \
   printf '%s' "$LOCAL_V1_BODY" > "${WORK_DIR}/virtcrate-1.0.0.crate" && \
   api_upload "/api/v1/repositories/${LOCAL_KEY}/artifacts/virtcrate/1.0.0/virtcrate-1.0.0.crate" \
     "${WORK_DIR}/virtcrate-1.0.0.crate" "application/x-tar" > /dev/null; then
  pass
else
  fail "could not create/seed local cargo repo ${LOCAL_KEY}"
  end_suite
fi

begin_test "Create remote member pointing at the mock upstream"
if create_remote_repo "$REMOTE_KEY" "cargo" "$MOCK_BASE_URL"; then
  pass
else
  fail "could not create remote cargo repo ${REMOTE_KEY}"
  end_suite
fi

begin_test "Create virtual repo aggregating local (p1) and remote (p2)"
if create_virtual_repo "$VIRTUAL_KEY" "cargo" "${LOCAL_KEY},${REMOTE_KEY}"; then
  pass
else
  fail "could not create virtual cargo repo ${VIRTUAL_KEY}"
  end_suite
fi

# ---------------------------------------------------------------------------
# #3952: a crate that exists ONLY upstream, served ONLY at the dl path.
# The unfixed virtual asks for /api/v1/crates/dlcrate/1.0.0/download and gets
# the mock's 404; the fixed virtual resolves config.json's dl template first.
# ---------------------------------------------------------------------------

begin_test "#3952: virtual download resolves the member's dl template"
dl_status=$(curl -s -o "${WORK_DIR}/dlcrate.crate" -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/cargo/${VIRTUAL_KEY}/api/v1/crates/dlcrate/1.0.0/download") || dl_status="000"
if [ "$dl_status" = "200" ] && \
   [ "$(cat "${WORK_DIR}/dlcrate.crate")" = "$UPSTREAM_DLCRATE_BODY" ]; then
  pass
else
  fail "expected 200 with dl-host bytes, got HTTP ${dl_status}: $(head -c 200 "${WORK_DIR}/dlcrate.crate" 2>/dev/null)"
fi

begin_test "#3952: the backend fetched the dl path, never the canonical index-host path"
if grep -q "GET /dl-crates/dlcrate/1.0.0/download" "${MOCK_STATE_DIR}/request-log.txt" && \
   ! grep -q "GET /api/v1/crates/" "${MOCK_STATE_DIR}/request-log.txt"; then
  pass
else
  fail "mock request log disagrees: $(grep -E 'dl-crates|api/v1/crates' "${MOCK_STATE_DIR}/request-log.txt" || echo '<none>')"
fi

# ---------------------------------------------------------------------------
# #3953: the local member owns virtcrate@1.0.0 only. The upstream-only 2.0.0
# must resolve through the virtual (the name-only guard 404'd it), while the
# owned 1.0.0 still serves the local member's bytes (shadowing defence).
# ---------------------------------------------------------------------------

begin_test "#3953: upstream-only virtcrate@2.0.0 resolves through the virtual"
v2_status=$(curl -s -o "${WORK_DIR}/virtcrate-2.crate" -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/cargo/${VIRTUAL_KEY}/api/v1/crates/virtcrate/2.0.0/download") || v2_status="000"
if [ "$v2_status" = "200" ] && \
   [ "$(cat "${WORK_DIR}/virtcrate-2.crate")" = "$UPSTREAM_V2_BODY" ]; then
  pass
else
  fail "expected 200 with upstream 2.0.0 bytes, got HTTP ${v2_status}: $(head -c 200 "${WORK_DIR}/virtcrate-2.crate" 2>/dev/null)"
fi

begin_test "#3953: locally-owned virtcrate@1.0.0 still serves the local bytes"
v1_status=$(curl -s -o "${WORK_DIR}/virtcrate-1.crate" -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/cargo/${VIRTUAL_KEY}/api/v1/crates/virtcrate/1.0.0/download") || v1_status="000"
if [ "$v1_status" = "200" ] && \
   [ "$(cat "${WORK_DIR}/virtcrate-1.crate")" = "$LOCAL_V1_BODY" ]; then
  pass
else
  fail "expected 200 with LOCAL 1.0.0 bytes (shadowing defence), got HTTP ${v1_status}: $(head -c 200 "${WORK_DIR}/virtcrate-1.crate" 2>/dev/null)"
fi

begin_test "#3953: the merged sparse index advertises local and upstream versions"
merged=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/cargo/${VIRTUAL_KEY}/index/vi/rt/virtcrate" 2>/dev/null) || merged=""
if echo "$merged" | grep -q '"vers":"1.0.0"' && echo "$merged" | grep -q '"vers":"2.0.0"'; then
  pass
else
  fail "merged index must list 1.0.0 (local) and 2.0.0 (upstream): $(echo "$merged" | head -c 300)"
fi

# ---------------------------------------------------------------------------
# #3937: gzipcrate's member index body is stored gzip-coded. The merged index
# must still list its version; the coding-blind fetch aggregated zero lines
# and the virtual answered 404.
# ---------------------------------------------------------------------------

begin_test "#3937: a gzip-stored member index body still contributes its versions"
gz_status=$(curl -s -o "${WORK_DIR}/gzipcrate-index" -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/cargo/${VIRTUAL_KEY}/index/gz/ip/gzipcrate") || gz_status="000"
if [ "$gz_status" = "200" ] && grep -q "\"vers\":\"${GZIPCRATE_VERSION}\"" "${WORK_DIR}/gzipcrate-index"; then
  pass
else
  fail "expected 200 listing ${GZIPCRATE_VERSION}, got HTTP ${gz_status}: $(head -c 300 "${WORK_DIR}/gzipcrate-index" 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true

end_suite
