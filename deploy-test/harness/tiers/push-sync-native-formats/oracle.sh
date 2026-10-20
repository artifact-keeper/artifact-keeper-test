#!/usr/bin/env bash
# =============================================================================
# tiers/push-sync-native-formats/oracle.sh
#   #4725 a native-format client upload to a push-subscribed hosted repo
#         queues a push sync task, and the sync worker delivers it to the peer
# See the manifest for THE BUG, THE PEER and the gates.
#
# run.sh exported BASE_URL (instance A), DB_CONTAINER (A's postgres),
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (instance B's published
# HTTP port, profiles/peer.second-instance.yml), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
: "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_DB="ak-dtf${SLOT}-peer-db"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"

R_BZ="psbazel-${SLOT}-${SUF}"     # bazel        PUT  /bazel/{repo}/{path}
R_LFS="pslfs-${SLOT}-${SUF}"      # gitlfs       PUT  /lfs/{repo}/objects/{oid}
R_HF="pshf-${SLOT}-${SUF}"        # huggingface  POST /huggingface/{repo}/api/models/{m}/upload/{rev}
R_GEN="psgen-${SLOT}-${SUF}"      # generic      PUT  /api/v1/repositories/{repo}/artifacts/{path} (control)

# How long the oracle waits for the worker after the generic control landed
# on B. The worker ticks every 10 s and claims every pending task of a peer in
# the same tick, so on the fixed image the native rows complete together with
# the generic one; the grace covers a native row queued a tick later.
GRACE_SECS=25

W="$(mktemp -d -t dtf-pushsync-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# HTTP code of a request; the body goes to $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }

repo_create() { # base key format -> id
  local body
  body="$(jq -nc --arg k "$2" --arg f "$3" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}

# "<status>|<rows>" of the push rows on A for one live artifact path.
push_state() { # repo path
  psql_a "SELECT coalesce(max(st.status::text),'none') || '|' || count(st.id) \
          FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          LEFT JOIN sync_tasks st ON st.artifact_id = a.id AND st.task_type = 'push' \
               AND st.peer_instance_id = '${PEER_ID:-00000000-0000-0000-0000-000000000000}' \
          WHERE r.key = '$1' AND a.path = '$2' AND a.is_deleted = false"
}
# sha256 of the live artifact row on A / on B (empty when there is none).
sha_a() { psql_a "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '$1' AND a.path = '$2' AND a.is_deleted = false"; }
sha_b() { psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '$1' AND a.path = '$2' AND a.is_deleted = false"; }
# sha256 of the bytes B serves at a URL ("<http>:<sha>").
served_b() {
  local c
  c="$(curl -s -o "$W/servedb" -w '%{http_code}' --max-time 60 -u "$AUTH" "$1" 2>/dev/null || echo 000)"
  echo "${c}:$(sha256sum "$W/servedb" 2>/dev/null | cut -d' ' -f1)"
}

begin_suite "push-sync-native-formats"
auth_admin

# =============================================================================
# SETUP: the same four repos on A and B, a push peer A -> B
# =============================================================================
begin_test "SETUP: instance B is up, same repos on A and B, B registered on A as a push peer"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
declare -A RID=()
for spec in "$R_BZ:bazel" "$R_LFS:gitlfs" "$R_HF:huggingface" "$R_GEN:generic"; do
  IFS=: read -r k f <<<"$spec"
  RID[$k]="$(repo_create "$A" "$k" "$f")"
  [ -n "${RID[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on A failed;"
  [ -n "$(repo_create "$B" "$k" "$f")" ] || SETUP_ERR="${SETUP_ERR} create ${k} on B failed;"
done
# The sync worker authenticates to B with this key (Bearer) for both the
# heartbeat probe (GET /api/v1/peers) and the transfer PUT.
B_KEY="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-peer-a-${SUF}\",\"scopes\":[\"*\"]}" "${B}/api/v1/auth/tokens" 2>/dev/null \
  | jq -r '.token // empty' 2>/dev/null || true)"
[ -n "$B_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint an API key on B;"
PEER_ID="$(curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-peer-b-${SLOT}-${SUF}\",\"endpoint_url\":\"http://peer-backend:8080\",\"api_key\":\"${B_KEY}\"}" \
  "${A}/api/v1/peers" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
if [ -z "$PEER_ID" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration on A failed;"
else
  # Online now rather than at the next heartbeat probe (up to 60 s); B
  # answers the probe, so the worker keeps it online.
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_ID}'" >/dev/null
  for k in "$R_BZ" "$R_LFS" "$R_HF" "$R_GEN"; do
    c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
      -d "{\"repository_id\":\"${RID[$k]:-x}\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
      "${A}/api/v1/peers/${PEER_ID}/repositories")"
    [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe ${k} -> ${c};"
  done
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# Uploads on A: three native protocols, one replication-tagged native upload,
# one generic REST upload (the control).
# =============================================================================
BZ_PATH="modules/dtfsync/1.0.0/MODULE.bazel"
printf "module(name = \"dtfsync\", version = \"1.0.0\")  # %s\n" "$SUF" > "$W/bz"
BZ_REPL_PATH="modules/dtfsync/2.0.0/MODULE.bazel"
printf "module(name = \"dtfsync\", version = \"2.0.0\")  # %s\n" "$SUF" > "$W/bzrepl"
printf 'dtf lfs object %s\n' "$SUF" > "$W/lfs"
LFS_OID="$(sha256sum "$W/lfs" | cut -d' ' -f1)"
LFS_PATH="lfs/objects/${LFS_OID:0:2}/${LFS_OID}"
head -c 4096 /dev/urandom > "$W/hf"
HF_PATH="dtfmodel/main/model.bin"
printf 'dtf generic %s\n' "$SUF" > "$W/gen"
GEN_PATH="dtf/${SUF}/control.txt"

begin_test "CONTROL: native uploads on A succeed (bazel PUT, Git LFS PUT, Hugging Face POST) and a generic REST PUT succeeds"
c_bz="$(code -u "$AUTH" -X PUT --data-binary @"$W/bz" "${A}/bazel/${R_BZ}/${BZ_PATH}")"
c_lfs="$(code -u "$AUTH" -X PUT --data-binary @"$W/lfs" "${A}/lfs/${R_LFS}/objects/${LFS_OID}")"
c_hf="$(code -u "$AUTH" -X POST -H 'x-filename: model.bin' --data-binary @"$W/hf" \
  "${A}/huggingface/${R_HF}/api/models/dtfmodel/upload/main")"
c_gen="$(code -u "$AUTH" -X PUT --data-binary @"$W/gen" "${A}/api/v1/repositories/${R_GEN}/artifacts/${GEN_PATH}")"
s_bz="$(sha_a "$R_BZ" "$BZ_PATH")"; s_lfs="$(sha_a "$R_LFS" "$LFS_PATH")"
s_hf="$(sha_a "$R_HF" "$HF_PATH")"; s_gen="$(sha_a "$R_GEN" "$GEN_PATH")"
if [[ "$c_bz" == 20? && "$c_lfs" == 20? && "$c_hf" == 20? && "$c_gen" == 20? ]] \
   && [ "$s_bz" = "$(sha256sum "$W/bz" | cut -d' ' -f1)" ] && [ "$s_lfs" = "$LFS_OID" ] \
   && [ "$s_hf" = "$(sha256sum "$W/hf" | cut -d' ' -f1)" ] && [ "$s_gen" = "$(sha256sum "$W/gen" | cut -d' ' -f1)" ]; then
  pass
else
  infra_fail "upload precondition failed: bazel=${c_bz} lfs=${c_lfs} hf=${c_hf} generic=${c_gen}; A rows sha bazel=${s_bz:-none} lfs=${s_lfs:-none} hf=${s_hf:-none} generic=${s_gen:-none}"
  end_suite; exit $?
fi
# A native upload as the sync worker sends it (replication marker) must store
# but never fan out again, on either image.
c_repl="$(code -u "$AUTH" -X PUT -H 'X-Artifact-Keeper-Replication: true' --data-binary @"$W/bzrepl" \
  "${A}/bazel/${R_BZ}/${BZ_REPL_PATH}")"

# --- the queue on A, read straight after the uploads (before any worker tick
# can complete a row, a completed row also counts as queued) --------------------
begin_test "CONTROL: the generic REST upload queued a push sync task for peer B on A"
st="$(push_state "$R_GEN" "$GEN_PATH")"
if [[ "$st" =~ ^(pending|in_progress|completed)\|1$ ]]; then pass; else
  fail "generic upload ${GEN_PATH} -> push rows ${st} (want one row). The peer wiring itself is broken."
fi

begin_test "CONTROL: a bazel upload carrying X-Artifact-Keeper-Replication stores but queues no push task"
st="$(push_state "$R_BZ" "$BZ_REPL_PATH")"
if [[ "$c_repl" == 20? ]] && [ "$st" = "none|0" ]; then pass; else
  fail "replicated bazel PUT -> ${c_repl}, push rows ${st} (want 2xx and none|0): a replicated write must not be pushed back out"
fi

for spec in "bazel PUT:${R_BZ}:${BZ_PATH}" "Git LFS PUT:${R_LFS}:${LFS_PATH}" "Hugging Face POST:${R_HF}:${HF_PATH}"; do
  IFS=: read -r label repo path <<<"$spec"
  begin_test "FIX(#4725): the ${label} upload queued a push sync task for peer B on A"
  st="$(push_state "$repo" "$path")"
  if [[ "$st" =~ ^(pending|in_progress|completed)\|1$ ]]; then pass; else
    fail "${label} ${repo}/${path} -> push rows ${st} (want exactly one). The native upload never enqueued a sync task, so the peer never receives it."
  fi
done

# --- delivery: wait for the generic control to land on B, then a grace ---------
begin_test "CONTROL: the sync worker delivers the generic upload to B (row on B, same sha256, served bytes equal)"
want_gen="$(sha256sum "$W/gen" | cut -d' ' -f1)"
deadline=$(( $(date +%s) + 90 ))
while [ "$(sha_b "$R_GEN" "$GEN_PATH")" != "$want_gen" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 3; done
got="$(served_b "${B}/api/v1/repositories/${R_GEN}/download/${GEN_PATH}")"
st="$(push_state "$R_GEN" "$GEN_PATH")"
if [ "$(sha_b "$R_GEN" "$GEN_PATH")" = "$want_gen" ] && [ "$got" = "200:${want_gen}" ] && [ "$st" = "completed|1" ]; then pass; else
  fail "generic upload never reached B within 90 s: B row sha=$(sha_b "$R_GEN" "$GEN_PATH"), B GET=${got}, A push row=${st}" \
       "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}'")"
fi
sleep "$GRACE_SECS"

check_delivery() { # label repo path native_url want_sha
  local label="$1" repo="$2" path="$3" url="$4" want="$5" rowb got st
  rowb="$(sha_b "$repo" "$path")"
  got="$(served_b "$url")"
  st="$(push_state "$repo" "$path")"
  if [ "$rowb" = "$want" ] && [ "$got" = "200:${want}" ] && [ "$st" = "completed|1" ]; then pass; else
    fail "${label} upload not on B $((GRACE_SECS)) s after the generic control landed: B row sha=${rowb:-none} (want ${want}), B native GET=${got}, A push row=${st}"
  fi
}
begin_test "FIX(#4725): the bazel upload reaches B (row on B, sha256 equal, B serves the bytes at the bazel path)"
check_delivery "bazel" "$R_BZ" "$BZ_PATH" "${B}/bazel/${R_BZ}/${BZ_PATH}" "$(sha256sum "$W/bz" | cut -d' ' -f1)"
begin_test "FIX(#4725): the Git LFS upload reaches B (row on B, sha256 equal, B serves the object by oid)"
check_delivery "Git LFS" "$R_LFS" "$LFS_PATH" "${B}/lfs/${R_LFS}/objects/${LFS_OID}" "$LFS_OID"
begin_test "FIX(#4725): the Hugging Face upload reaches B (row on B, sha256 equal, B serves the bytes)"
check_delivery "Hugging Face" "$R_HF" "$HF_PATH" "${B}/api/v1/repositories/${R_HF}/download/${HF_PATH}" "$(sha256sum "$W/hf" | cut -d' ' -f1)"

begin_test "CONTROL: the replication-tagged bazel upload never reached B"
if [ -z "$(sha_b "$R_BZ" "$BZ_REPL_PATH")" ]; then pass; else
  fail "B has ${R_BZ}/${BZ_REPL_PATH}: a replication-tagged write on A was pushed back out"
fi

# --- A's own view of the peer -------------------------------------------------
begin_test "FIX(#4725): A's sync status for peer B: no pending task left, every push row completed, last_sync_at set"
pending="$(curl -s --max-time 30 -u "$AUTH" "${A}/api/v1/peers/${PEER_ID}/sync/tasks" 2>/dev/null | jq -r 'length' 2>/dev/null || echo '?')"
peer="$(curl -s --max-time 30 -u "$AUTH" "${A}/api/v1/peers/${PEER_ID}" 2>/dev/null)"
pstatus="$(jq -r '.status // empty' <<<"$peer" 2>/dev/null)"; plast="$(jq -r '.last_sync_at // empty' <<<"$peer" 2>/dev/null)"
rows="$(psql_a "SELECT count(*) FILTER (WHERE status = 'completed') || '/' || count(*) FROM sync_tasks \
                WHERE peer_instance_id = '${PEER_ID}' AND task_type = 'push'")"
# generic + bazel + Git LFS + Hugging Face = 4 completed push rows.
if [ "$pending" = "0" ] && [ "$pstatus" = "online" ] && [ -n "$plast" ] && [ "$rows" = "4/4" ]; then pass; else
  fail "GET /api/v1/peers/${PEER_ID}/sync/tasks -> ${pending} pending; peer status=${pstatus:-?} last_sync_at=${plast:-null}; push rows completed/total=${rows} (want 4/4: generic + three native uploads)"
fi

end_suite
