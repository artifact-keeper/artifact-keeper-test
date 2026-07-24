#!/usr/bin/env bash
# test-oci-gc-mark-sweep.sh - OCI GC reclaims an unreferenced blob and leaves
# no dangling manifest reference.
#
# Release gate for:
#   artifact-keeper#1660 - OCI GC two-phase mark-sweep
#
# The registry tracks manifest -> blob references (manifest_blob_refs). When a
# manifest is deleted its layer blobs become unreferenced; the GC sweep must
# reclaim a genuinely unreferenced blob after the grace window, WITHOUT
# sweeping any blob still referenced by a live manifest (which would create a
# dangling reference / 500 on pull).
#
# This gate:
#   1. Pushes image A (layer blob B1) and image B (layer blob B2), each tagged.
#   2. Deletes image A's manifest so B1 is genuinely unreferenced.
#   3. Triggers GC (POST /api/v1/admin/storage-gc {"dry_run":false}) a few times
#      to run the sweep.
#   4. RECLAIM (B1 GET -> 404) is NOT assertable at the gate and is SKIPPED: the
#      backend enforces a compile-time MIN_BLOB_AGE_SECS = 24h shield on blob
#      deletion (storage_gc_service.rs:123), so a blob pushed this session can
#      never be swept during the run. Tracked for an env-configurable age shield
#      in artifact-keeper#2906 (see artifact-keeper-test#292).
#   5. Asserts NO DANGLING: image B's manifest still resolves (200) and its
#      referenced blob B2 still resolves (200) -- GC did not sweep a live blob.
#
# Resurrection sub-case (a blob re-adopted between mark and sweep must survive)
# is intentionally SKIPPED: it requires the GC endpoint to expose mark and
# sweep as separately triggerable phases (or a pinned, timeable grace). The
# current endpoint is a single atomic run_gc call, so the race cannot be driven
# deterministically at the gate layer. See v130-test-gates-plan.md G3.
#
# Target-capability note: the deploy overlay must set BLOB_GC_ENABLED=true and a
# short BLOB_GC_SWEEP_GRACE_SECS (the backend default grace is 3600s and blob GC
# is opt-in) for the reclaim assertion to complete inside the gate timeout.
#
# Feature-gated on `oci_gc_two_phase` so it auto-skips on a 1.2.x backend
# (which does not run the manifest-dereference blob sweep) instead of hard-failing.
#
# Requires: curl, jq, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-gc-mark-sweep"
auth_admin
setup_workdir

begin_test "Backend supports oci_gc_two_phase (v1.3.0)"
if require_feature "oci_gc_two_phase"; then
  pass
else
  end_suite
  exit 0
fi

REPO_KEY="e2e-ocigc-${RUN_ID}"
IMG_A="gc-image-a"
IMG_B="gc-image-b"
TAG="v1"

cleanup() {
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

TOKEN=""
# Push a monolithic blob; echoes the pushed HTTP status. Digest is computed by
# the caller (content-addressed).
push_blob() {
  local image="$1" content_file="$2" digest="$3"
  curl -s -D "${WORK_DIR}/upl.hdr" -o /dev/null -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL}/v2/${REPO_KEY}/${image}/blobs/uploads/" >/dev/null 2>&1 || true
  local loc base put_url
  loc=$(grep -i '^location:' "${WORK_DIR}/upl.hdr" 2>/dev/null | tr -d '\r' | awk '{print $2}') || true
  [ -z "$loc" ] && { echo "000"; return 1; }
  if [[ "$loc" == http* ]]; then base="$loc"; else base="${BASE_URL}${loc}"; fi
  if [[ "$loc" == *"?"* ]]; then put_url="${base}&digest=${digest}"; else put_url="${base}?digest=${digest}"; fi
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${content_file}" "$put_url" 2>/dev/null || echo "000"
}

blob_status() {
  local image="$1" digest="$2"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL}/v2/${REPO_KEY}/${image}/blobs/${digest}" 2>/dev/null || echo "000"
}

# Push a config blob + a layer blob, then a manifest referencing them. Echoes
# the manifest PUT status. Runs in a command-substitution subshell at every
# call site, so it exports nothing to the parent; callers recompute the layer
# digest themselves with the same formula used below.
push_image() {
  local image="$1" layer_file="$2" tag="$3"
  local cfg='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
  local cfg_file="${WORK_DIR}/${image}-config.json"
  printf '%s' "$cfg" > "$cfg_file"
  local cfg_digest cfg_size layer_digest layer_size
  cfg_digest="sha256:$(shasum -a 256 "$cfg_file" | awk '{print $1}')"
  cfg_size=$(wc -c < "$cfg_file" | tr -d ' ')
  layer_digest="sha256:$(shasum -a 256 "$layer_file" | awk '{print $1}')"
  layer_size=$(wc -c < "$layer_file" | tr -d ' ')

  push_blob "$image" "$cfg_file" "$cfg_digest" >/dev/null
  push_blob "$image" "$layer_file" "$layer_digest" >/dev/null

  local manifest="${WORK_DIR}/${image}-manifest.json"
  cat > "$manifest" <<EOM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "${cfg_digest}", "size": ${cfg_size}},
  "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "${layer_digest}", "size": ${layer_size}}]
}
EOM
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    --data-binary "@${manifest}" \
    "${BASE_URL}/v2/${REPO_KEY}/${image}/manifests/${tag}" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create docker repository"
if create_local_repo "$REPO_KEY" "docker"; then
  pass
else
  fail "could not create docker repo"
fi

begin_test "Obtain registry token"
TOKEN=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null | jq -r '.token // empty') || true
if [ -n "$TOKEN" ]; then
  pass
else
  skip "could not obtain /v2/token; OCI GC gate cannot proceed"
  cleanup
  end_suite
  exit 0
fi

# Unique layer contents so B1 and B2 are distinct, content-addressed blobs.
printf 'gc-layer-b1-%s\n' "$RUN_ID" > "${WORK_DIR}/layer-b1.bin"
printf 'gc-layer-b2-%s\n' "$RUN_ID" > "${WORK_DIR}/layer-b2.bin"

begin_test "Push image A (layer B1)"
st=$(push_image "$IMG_A" "${WORK_DIR}/layer-b1.bin" "$TAG")
# push_image runs in a command-substitution subshell, so the LAYER_DIGEST it
# sets never reaches this parent shell. Recompute B1's digest here in the
# parent using the same formula push_image uses, so it is defined under set -u.
B1_DIGEST="sha256:$(shasum -a 256 "${WORK_DIR}/layer-b1.bin" | awk '{print $1}')"
if [ "$st" = "201" ] || [ "$st" = "200" ]; then
  pass
else
  skip "image A manifest PUT returned ${st}; OCI push not available"
  cleanup
  end_suite
  exit 0
fi

begin_test "Push image B (layer B2, stays referenced)"
st=$(push_image "$IMG_B" "${WORK_DIR}/layer-b2.bin" "$TAG")
# Same subshell caveat as B1: recompute B2's digest in the parent shell.
B2_DIGEST="sha256:$(shasum -a 256 "${WORK_DIR}/layer-b2.bin" | awk '{print $1}')"
if [ "$st" = "201" ] || [ "$st" = "200" ]; then
  pass
else
  fail "image B manifest PUT returned ${st}, expected 201/200"
fi

begin_test "Blob B1 is present before GC"
st=$(blob_status "$IMG_A" "$B1_DIGEST")
if [ "$st" = "200" ]; then
  pass
else
  fail "blob B1 GET returned ${st} before GC, expected 200"
fi

# ---------------------------------------------------------------------------
# Delete image A's manifest -> B1 becomes unreferenced
# ---------------------------------------------------------------------------

begin_test "Delete image A manifest (B1 becomes unreferenced)"
del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X DELETE \
  -H "Authorization: Bearer ${TOKEN}" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMG_A}/manifests/${TAG}" 2>/dev/null) || del_status="000"
if [ "$del_status" = "202" ] || [ "$del_status" = "200" ]; then
  pass
elif [ "$del_status" = "404" ]; then
  skip "manifest DELETE returned 404 (delete-by-tag unsupported); cannot unreference B1"
  cleanup
  end_suite
  exit 0
else
  fail "manifest DELETE returned ${del_status}, expected 202/200"
fi

# ---------------------------------------------------------------------------
# Trigger GC. We still RUN the sweep so the no-dangling-ref checks below prove
# it does not touch a live blob, but the B1 reclaim itself is NOT assertable at
# the gate: the backend enforces a compile-time MIN_BLOB_AGE_SECS = 24h shield
# on blob deletion (storage_gc_service.rs:123) that protects in-flight pushes,
# so a blob pushed this session can never be swept during the run no matter how
# short BLOB_GC_SWEEP_GRACE_SECS is. This is the same "not drivable at the gate
# layer" situation as the resurrection sub-test below; it is skipped pending an
# env-configurable age shield (backend artifact-keeper#2906).
# ---------------------------------------------------------------------------

begin_test "GC reclaims unreferenced blob B1 (GET -> 404)"
for _attempt in $(seq 1 3); do
  api_post "/api/v1/admin/storage-gc" '{"dry_run":false}' >/dev/null 2>&1 || true
  sleep 2
done
skip "same-session blob reclaim is untestable at the gate: backend MIN_BLOB_AGE_SECS is a compile-time 24h shield for in-flight pushes (storage_gc_service.rs:123); tracked for an env-configurable age shield in artifact-keeper#2906 (artifact-keeper-test#292)"

# ---------------------------------------------------------------------------
# No dangling reference: image B's manifest + referenced blob survive
# ---------------------------------------------------------------------------

begin_test "No dangling ref: image B manifest still resolves (200) after GC"
mb_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMG_B}/manifests/${TAG}" 2>/dev/null) || mb_status="000"
if [ "$mb_status" = "200" ]; then
  pass
else
  fail "image B manifest GET returned ${mb_status} after GC, expected 200 (GC broke a live manifest)"
fi

begin_test "No dangling ref: referenced blob B2 survives GC (GET -> 200)"
st=$(blob_status "$IMG_B" "$B2_DIGEST")
if [ "$st" = "200" ]; then
  pass
else
  fail "referenced blob B2 GET returned ${st} after GC, expected 200 (GC swept a referenced blob -> dangling ref)"
fi

# ---------------------------------------------------------------------------
# Resurrection sub-case: not drivable at the gate layer (single atomic GC)
# ---------------------------------------------------------------------------

begin_test "Resurrection (re-adopt during mark->sweep window) survives"
skip "GC endpoint exposes no separately-triggerable mark/sweep phases (single atomic run_gc); resurrection race cannot be driven at the gate layer -- tracked for a backend phase-control hook (v130 plan G3)"

end_suite
