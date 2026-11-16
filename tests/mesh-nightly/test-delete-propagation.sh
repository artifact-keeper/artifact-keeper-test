#!/usr/bin/env bash
# test-delete-propagation.sh - a delete on the hub reaches every push peer
# (artifact-keeper/artifact-keeper#6120)
#
# Topology: SRC_URL (the instance that owns the repo) pushes to every URL in
# DST_URLS (space-separated). The nightly mesh lane runs it as hub -> peer1 +
# peer2, and for the mixed-version tier as hub -> legacy and legacy -> hub.
#
# What it proves, on real instances with their own databases and storage:
#   1. a push subscription replicates two artifacts to every peer (same bytes);
#   2. deleting one on SRC queues a `delete` sync task per peer
#      (artifact_service ENQUEUE_DELETE_SYNC_TASKS_SQL) and every peer drops it;
#   3. the delete is scoped: the sibling artifact stays on every peer;
#   4. the freed path takes a NEW upload with different bytes, and every peer
#      ends with the new bytes (the push waits for the delete, #5699).
#
# Requires: SRC_URL, DST_URLS (or MAIN_URL + PEER1_URL [+ PEER2_URL]).

source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/mesh.sh"

SRC_URL="${SRC_URL:-${MAIN_URL:-}}"
DST_URLS="${DST_URLS:-${PEER1_URL:-} ${PEER2_URL:-}}"
export BASE_URL="${SRC_URL:-$BASE_URL}"

begin_suite "mesh-delete-propagation"
setup_workdir

if [ -z "${SRC_URL}" ] || [ -z "${DST_URLS// /}" ]; then
  skip_suite "SRC_URL and DST_URLS (or MAIN_URL and PEER1_URL) are required: multi-instance mesh only"
fi

SYNC_WAIT="${SYNC_WAIT:-100}"
# Four phases (two initial artifacts, the delete, the re-upload), each with
# ONE deadline shared by every peer (mesh_wait_all), so the total does not
# grow with the number of peers.
read -r -a DSTS <<< "$DST_URLS"
require_wait_budget $(( 4 * SYNC_WAIT )) "initial-sync, delete and re-upload waits (SYNC_WAIT=${SYNC_WAIT}s per phase, shared by all peers)"

mesh_init "$SRC_URL" "${DSTS[@]}"

TAG=$(mesh_tag)
REPO="mesh-del-${TAG}"
KEEP="del/keep.bin"
GONE="del/gone.bin"

begin_test "Create repo ${REPO} on the source and on every peer"
ok=true
for u in "$SRC_URL" "${DSTS[@]}"; do
  mesh_on "$u" create_local_repo "$REPO" generic || { ok=false; echo "  create on ${u} failed"; }
done
if $ok; then pass; else fail_fatal "could not create the repository on every instance"; fi

begin_test "Register every peer on the source with a key minted on that peer, and subscribe it (push)"
PEER_IDS=()
ok=true
for i in "${!DSTS[@]}"; do
  if id=$(mesh_link "$SRC_URL" "${DSTS[$i]}" "del-${TAG}-${i}") && \
     mesh_subscribe "$SRC_URL" "$id" "$REPO" push >/dev/null; then
    PEER_IDS+=("$id")
  else
    ok=false
  fi
done
if $ok; then pass; else fail_fatal "peer registration or subscription failed"; fi

dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/keep.bin" 2>/dev/null
dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/gone.bin" 2>/dev/null
dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/gone2.bin" 2>/dev/null
KEEP_SHA=$(sha256sum "${WORK_DIR}/keep.bin" | awk '{print $1}')
GONE_SHA=$(sha256sum "${WORK_DIR}/gone.bin" | awk '{print $1}')
GONE2_SHA=$(sha256sum "${WORK_DIR}/gone2.bin" | awk '{print $1}')

begin_test "Upload two artifacts on the source"
if mesh_upload "$SRC_URL" "$REPO" "$KEEP" "${WORK_DIR}/keep.bin" && \
   mesh_upload "$SRC_URL" "$REPO" "$GONE" "${WORK_DIR}/gone.bin"; then
  pass
else
  fail_fatal "upload on the source failed"
fi

begin_test "Both artifacts replicate to every peer with the same bytes"
ok=true
mesh_wait_all "$SYNC_WAIT" present "$REPO" "$KEEP" "${DSTS[@]}" || ok=false
mesh_wait_all "$SYNC_WAIT" present "$REPO" "$GONE" "${DSTS[@]}" || ok=false
for u in "${DSTS[@]}"; do
  $ok || break
  [ "$(mesh_download_sha "$u" "$REPO" "$KEEP")" = "$KEEP_SHA" ] || { ok=false; echo "  ${KEEP} on ${u}: checksum mismatch"; }
  [ "$(mesh_download_sha "$u" "$REPO" "$GONE")" = "$GONE_SHA" ] || { ok=false; echo "  ${GONE} on ${u}: checksum mismatch"; }
done
if $ok; then pass; else fail_fatal "replication did not reach every peer; the delete checks below would prove nothing"; fi

begin_test "Delete ${GONE} on the source"
if mesh_on "$SRC_URL" api_delete "/api/v1/repositories/${REPO}/artifacts/${GONE}" >/dev/null; then
  pass
else
  fail_fatal "DELETE on the source failed"
fi

begin_test "The delete propagates to every peer (a definite 404, not an error)"
if mesh_wait_all "$SYNC_WAIT" absent "$REPO" "$GONE" "${DSTS[@]}"; then
  pass
else
  fail "delete did not propagate to every peer within ${SYNC_WAIT}s"
fi

begin_test "The delete is scoped: ${KEEP} is still on every peer"
ok=true
for u in "${DSTS[@]}"; do
  mesh_has_artifact "$u" "$REPO" "$KEEP" || { ok=false; echo "  ${KEEP} missing on ${u}"; }
done
if $ok; then pass; else fail "a sibling artifact disappeared from a peer"; fi

begin_test "A new upload at the freed path reaches every peer with the new bytes"
if ! mesh_upload "$SRC_URL" "$REPO" "$GONE" "${WORK_DIR}/gone2.bin"; then
  fail "re-upload at ${GONE} on the source failed"
else
  ok=true
  deadline=$(( $(date +%s) + SYNC_WAIT ))
  for u in "${DSTS[@]}"; do
    got=""
    while :; do
      if mesh_has_artifact "$u" "$REPO" "$GONE"; then
        got=$(mesh_download_sha "$u" "$REPO" "$GONE" || true)
        [ "$got" = "$GONE2_SHA" ] && break
      fi
      [ "$(date +%s)" -ge "$deadline" ] && break
      sleep 3
    done
    if [ "$got" != "$GONE2_SHA" ]; then
      ok=false; echo "  ${u}: ${GONE} sha '${got:-absent}', wanted the re-uploaded ${GONE2_SHA}"
    fi
  done
  if $ok; then pass; else fail "re-upload after delete did not converge on every peer"; fi
fi

end_suite
