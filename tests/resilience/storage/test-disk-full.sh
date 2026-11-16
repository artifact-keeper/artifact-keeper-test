#!/usr/bin/env bash
# test-disk-full.sh - Verify clean error handling when storage is full
#
# Makes the backend's storage path a full filesystem, proves the kernel now
# refuses writes there (ENOSPC), verifies that uploads fail with clean errors
# and the server stays up, frees the space, proves writes work again, and
# verifies uploads and the pre-fill artifact.
#
# How the disk is filled (artifact-keeper-test#842): the gate's PVCs are
# local-path, host directories with no quota, so filling the real volume
# would fill the node's disk, and that node also runs production. Instead the
# fault-fs container that tests/lib/k8s.sh attaches to the backend pod mounts
# a small fixed-size tmpfs over the storage path INSIDE the backend
# container's mount namespace and fills it. The backend's writes to its
# storage path then hit a real ENOSPC. While the fault is on, the volume
# underneath is hidden (not changed); unmounting the tmpfs brings it back
# intact. A fill that cannot be applied or verified is INFRA (exit 11),
# never a skip.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"
source "$(dirname "$0")/../../lib/k8s.sh"

begin_suite "storage-disk-full"
require_cmd kubectl
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="store-full-${RUN_ID}"
FULL_SIZE="16m"

begin_test "Attach fault injector to the backend pod"
k8s_fault_injector_attach BACKEND_POD
echo "  Storage mount (${AK_STORAGE_MOUNT}) as the backend sees it:"
k8s_fault_storage_mountline "$BACKEND_POD" 2>&1 | sed 's/^/    /'
pass

auth_admin

# Never leave the storage path shadowed, whatever happens below.
add_exit_handler 'k8s_fault_cleanup_full "$BACKEND_POD"'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload artifact before filling disk"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/prefill.bin" 2>/dev/null
PREFILL_SHA=$(shasum -a 256 "${WORK_DIR}/prefill.bin" | awk '{print $1}')
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/prefill.bin" \
    "${WORK_DIR}/prefill.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "pre-fill upload failed"
fi

# ---------------------------------------------------------------------------
# Fill the storage path
# ---------------------------------------------------------------------------

begin_test "Fill the backend's storage path (${FULL_SIZE} tmpfs, filled)"
if ! fill_out=$(k8s_fault_storage_fill "$BACKEND_POD" "$FULL_SIZE" 2>&1); then
  _k8s_fault_abort "could not mount the disk-full tmpfs over ${AK_STORAGE_MOUNT} in the backend's mount namespace" "$fill_out"
fi
full_line=$(k8s_fault_storage_mountline "$BACKEND_POD" 2>&1)
avail=$(k8s_fault_storage_avail_kb "$BACKEND_POD" 2>/dev/null || true)
echo "  mountinfo: ${full_line}"
echo "  Available on ${AK_STORAGE_MOUNT}: ${avail:-?} KiB"
probe_err=$(k8s_fault_storage_write_probe "$BACKEND_POD" 2>&1) && probe_rc=0 || probe_rc=$?
echo "  write probe: rc=${probe_rc} ${probe_err}"
case "$probe_err" in
  *"No space left on device"*)
    if [ -n "$avail" ] && [ "$avail" -lt 64 ]; then
      pass
    else
      _k8s_fault_abort "a write failed with ENOSPC but the storage path still reports ${avail:-unknown} KiB free" \
        "mountinfo: ${full_line}"
    fi ;;
  *) _k8s_fault_abort "the storage path was filled but a write did not fail with ENOSPC" \
       "probe rc=${probe_rc}: ${probe_err}
available: ${avail} KiB
mountinfo: ${full_line}" ;;
esac

# ---------------------------------------------------------------------------
# Verify uploads fail with clean errors
# ---------------------------------------------------------------------------

begin_test "Upload fails cleanly when disk is full"
dd if=/dev/urandom bs=1024 count=64 of="${WORK_DIR}/should-fail.bin" 2>/dev/null
full_status=$(curl -s -o "${WORK_DIR}/full-response.txt" -w '%{http_code}' -X PUT \
  --max-time 60 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/should-fail.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/should-fail.bin" 2>/dev/null || true)
full_status="${full_status:-000}"
echo "  Upload status when disk full: ${full_status}"
echo "  Response: $(head -c 300 "${WORK_DIR}/full-response.txt" 2>/dev/null)"
if [ "$full_status" -ge 200 ] 2>/dev/null && [ "$full_status" -lt 300 ] 2>/dev/null; then
  fail "upload returned ${full_status} while the storage path was full (ENOSPC)" \
    "$(head -c 2000 "${WORK_DIR}/full-response.txt" 2>/dev/null)"
elif [ "$full_status" = "000" ]; then
  fail "no HTTP response to an upload on a full disk (connection dropped or hung for 60s)"
else
  error_body=$(cat "${WORK_DIR}/full-response.txt" 2>/dev/null)
  if assert_not_contains "$error_body" "panic" "response should not contain panic"; then
    echo "  Error response is clean"
    pass
  fi
fi

# Check server is still responding (not crashed)
begin_test "Server still responds after disk-full error"
health_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE_URL}/health" 2>/dev/null || true)
# Accept 503 since /health may report unhealthy optional services
if [ "$health_status" = "200" ] || [ "$health_status" = "503" ]; then
  pass
else
  fail "server not responding after disk-full error (status: ${health_status:-000})"
fi

# ---------------------------------------------------------------------------
# Free the space
# ---------------------------------------------------------------------------

begin_test "Free the storage path"
if ! unfill_out=$(k8s_fault_storage_unfill "$BACKEND_POD" 2>&1); then
  _k8s_fault_abort "could not unmount the disk-full tmpfs from ${AK_STORAGE_MOUNT}" "$unfill_out"
fi
after_line=$(k8s_fault_storage_mountline "$BACKEND_POD" 2>&1)
echo "  mountinfo: ${after_line}"
case "$after_line" in
  *" - tmpfs ${K8S_FAULT_FULL_SOURCE} "*)
    _k8s_fault_abort "the disk-full tmpfs is still mounted over ${AK_STORAGE_MOUNT}" "$after_line" ;;
esac
if ! probe_err=$(k8s_fault_storage_write_probe "$BACKEND_POD" 2>&1); then
  _k8s_fault_abort "the storage path was freed but a write still fails" "$probe_err"
fi
echo "  Available on ${AK_STORAGE_MOUNT}: $(k8s_fault_storage_avail_kb "$BACKEND_POD" 2>/dev/null || echo '?') KiB; write probe succeeded"
pass

# ---------------------------------------------------------------------------
# Verify uploads work again
# ---------------------------------------------------------------------------

begin_test "Upload works after freeing space"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/after-free.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/after-free.bin" \
    "${WORK_DIR}/after-free.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after freeing disk space failed"
fi

begin_test "Verify pre-fill artifact still accessible and intact"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/dl-prefill.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/prefill.bin"; then
  if assert_eq "$(shasum -a 256 "${WORK_DIR}/dl-prefill.bin" | awk '{print $1}')" "$PREFILL_SHA" \
      "pre-fill artifact checksum mismatch"; then
    pass
  fi
else
  fail "could not download the pre-fill artifact after freeing space"
fi

end_suite
