#!/usr/bin/env bash
# test-storage-readonly.sh - Verify clean error handling with read-only storage
#
# Remounts the backend's storage path read-only inside the backend
# container's own mount namespace, proves the kernel now refuses writes there
# (EROFS), verifies that uploads fail with clean errors while existing
# artifacts stay readable, restores the mount read-write, proves writes work
# again, and verifies uploads and the pre-existing artifact.
#
# The backend image has no mount or sh, so the remount runs from the fault-fs
# container that tests/lib/k8s.sh attaches to the backend pod: it nsenters the
# backend's mount namespace (artifact-keeper-test#842). Only that one mount in
# that one namespace changes; the volume and the node are untouched. A
# remount that cannot be applied or verified is INFRA (exit 11), never a skip.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"
source "$(dirname "$0")/../../lib/k8s.sh"

begin_suite "storage-readonly"
require_cmd kubectl
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="store-ro-${RUN_ID}"

begin_test "Attach fault injector to the backend pod"
k8s_fault_injector_attach BACKEND_POD
echo "  Storage mount (${AK_STORAGE_MOUNT}) as the backend sees it:"
k8s_fault_storage_mountline "$BACKEND_POD" 2>&1 | sed 's/^/    /'
pass

auth_admin

# Never leave the storage read-only, whatever happens below.
add_exit_handler 'k8s_fault_cleanup_readonly "$BACKEND_POD"'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload artifact before making storage read-only"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/before-ro.bin" 2>/dev/null
BEFORE_SHA=$(shasum -a 256 "${WORK_DIR}/before-ro.bin" | awk '{print $1}')
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/before-ro.bin" \
    "${WORK_DIR}/before-ro.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "pre-readonly upload failed"
fi

# ---------------------------------------------------------------------------
# Make storage read-only
# ---------------------------------------------------------------------------

begin_test "Remount storage read-only in the backend's mount namespace"
# Not in a $(...) subshell: the helper records the mount's flags in
# K8S_FAULT_STORAGE_OPTS, which the restore and the exit handler need. It
# refuses unless the path is a bind of a subdirectory of a read-write
# filesystem, and it checks that only the bind became read-only, never the
# filesystem underneath (on local-path that is the node's root filesystem).
if ! k8s_fault_storage_readonly "$BACKEND_POD" > "${WORK_DIR}/remount-ro.out" 2>&1; then
  if grep -q 'SUPERBLOCK' "${WORK_DIR}/remount-ro.out"; then
    echo "::error::ak-fault: the read-only remount reached the filesystem under ${AK_STORAGE_MOUNT} (on local-path, the node's root filesystem); it was restored at once, check the node. $(grep 'superblock now' "${WORK_DIR}/remount-ro.out")"
  fi
  _k8s_fault_abort "could not remount ${AK_STORAGE_MOUNT} read-only in the backend's mount namespace" \
    "$(cat "${WORK_DIR}/remount-ro.out")"
fi
sed 's/^/  /' "${WORK_DIR}/remount-ro.out"
echo "  original flags: ${K8S_FAULT_STORAGE_OPTS}"
ro_line=$(k8s_fault_storage_mountline "$BACKEND_POD" 2>&1)
echo "  mountinfo: ${ro_line}"
probe_err=$(k8s_fault_storage_write_probe "$BACKEND_POD" 2>&1) && probe_rc=0 || probe_rc=$?
echo "  write probe: rc=${probe_rc} ${probe_err}"
case "$probe_err" in
  *"Read-only file system"*) pass ;;
  *) _k8s_fault_abort "remount reported success but a write to ${AK_STORAGE_MOUNT} did not fail with EROFS" \
       "probe rc=${probe_rc}: ${probe_err}
mountinfo: ${ro_line}" ;;
esac

# ---------------------------------------------------------------------------
# Attempt uploads (should fail cleanly)
# ---------------------------------------------------------------------------

begin_test "Upload fails cleanly with read-only storage"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/ro-test.bin" 2>/dev/null
ro_status=$(curl -s -o "${WORK_DIR}/ro-response.txt" -w '%{http_code}' -X PUT \
  --max-time 60 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/ro-test.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/ro-test.bin" 2>/dev/null || true)
ro_status="${ro_status:-000}"
echo "  Upload status with read-only storage: ${ro_status}"
echo "  Response: $(head -c 300 "${WORK_DIR}/ro-response.txt" 2>/dev/null)"
if [ "$ro_status" -ge 200 ] 2>/dev/null && [ "$ro_status" -lt 300 ] 2>/dev/null; then
  fail "upload returned ${ro_status} while the storage path refused writes (EROFS)" \
    "$(head -c 2000 "${WORK_DIR}/ro-response.txt" 2>/dev/null)"
elif [ "$ro_status" = "000" ]; then
  fail "no HTTP response to an upload on read-only storage (connection dropped or hung for 60s)"
else
  error_body=$(cat "${WORK_DIR}/ro-response.txt" 2>/dev/null)
  if assert_not_contains "$error_body" "panic" "response should not contain panic"; then
    if assert_not_contains "$error_body" "RUST_BACKTRACE" "response should not expose backtrace env"; then
      pass
    fi
  fi
fi

begin_test "Existing artifact still downloadable while storage is read-only"
if curl -sf --max-time 60 -H "$(auth_header)" \
    -o "${WORK_DIR}/dl-during-ro.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/before-ro.bin"; then
  if assert_eq "$(shasum -a 256 "${WORK_DIR}/dl-during-ro.bin" | awk '{print $1}')" "$BEFORE_SHA" \
      "checksum mismatch reading from read-only storage"; then
    pass
  fi
else
  fail "could not read an existing artifact while storage was read-only"
fi

begin_test "Server still healthy after read-only error"
health_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE_URL}/health" 2>/dev/null || true)
# Accept 503 since /health may report unhealthy optional services
if [ "$health_status" = "200" ] || [ "$health_status" = "503" ]; then
  pass
else
  fail "server not responding after read-only error (status: ${health_status:-000})"
fi

# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

begin_test "Remount storage read-write"
if ! rw_out=$(k8s_fault_storage_restore "$BACKEND_POD" 2>&1); then
  _k8s_fault_abort "could not remount ${AK_STORAGE_MOUNT} read-write" "$rw_out"
fi
echo "  mountinfo: $(k8s_fault_storage_mountline "$BACKEND_POD" 2>&1)"
if ! probe_err=$(k8s_fault_storage_write_probe "$BACKEND_POD" 2>&1); then
  _k8s_fault_abort "storage was remounted read-write but a write still fails" "$probe_err"
fi
K8S_FAULT_STORAGE_OPTS=""
echo "  write probe succeeded"
pass

# ---------------------------------------------------------------------------
# Verify uploads work again
# ---------------------------------------------------------------------------

begin_test "Upload works after restoring write access"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/after-ro.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/after-ro.bin" \
    "${WORK_DIR}/after-ro.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after restoring write access failed"
fi

begin_test "Verify pre-existing artifact still accessible"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/dl-before-ro.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/before-ro.bin"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/dl-before-ro.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$BEFORE_SHA" "pre-readonly artifact checksum mismatch"; then
    pass
  fi
else
  fail "could not download pre-readonly artifact"
fi

end_suite
