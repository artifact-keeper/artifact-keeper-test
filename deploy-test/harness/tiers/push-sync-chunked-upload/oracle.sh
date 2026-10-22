#!/usr/bin/env bash
# =============================================================================
# tiers/push-sync-chunked-upload/oracle.sh
#   #4791 a generic artifact finished through the upload-session API
#         (/api/v1/uploads) is pushed to a subscribed push peer, and a peer
#         write through the same API is not pushed back out
# See the manifest for THE BUG, THE PEERS and the gates.
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
NIL="00000000-0000-0000-0000-000000000000"
MIB=1048576

R_GEN="psechunk-${SLOT}-${SUF}"

W="$(mktemp -d -t dtf-pushchunk-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# HTTP code of a request; the body goes to $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }

repo_create() { # base key -> id
  local body
  body="$(jq -nc --arg k "$2" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}
mint_key() { # base -> token
  curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"dtf-chunk-${SUF}-$RANDOM\",\"scopes\":[\"*\"]}" "$1/api/v1/auth/tokens" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
register_peer() { # base name endpoint key -> id (the response body lands in $W/peer-$2)
  curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\",\"endpoint_url\":\"$3\",\"api_key\":\"$4\"}" \
    "$1/api/v1/peers" 2>/dev/null | tee "$W/peer-$2" | jq -r '.id // empty' 2>/dev/null || true
}
subscribe() { # base peer repo_id -> http code
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"repository_id\":\"$3\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
    "$1/api/v1/peers/$2/repositories"
}

# "<status>|<rows>" of the push rows on one side for one live artifact path.
push_rows() { # a|b peer path
  local q="SELECT coalesce(max(st.status::text),'none') || '|' || count(st.id) \
          FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          LEFT JOIN sync_tasks st ON st.artifact_id = a.id AND st.task_type = 'push' \
               AND st.peer_instance_id = '${2:-$NIL}' \
          WHERE r.key = '${R_GEN}' AND a.path = '$3' AND a.is_deleted = false"
  if [ "$1" = a ]; then psql_a "$q"; else psql_b "$q"; fi
}
# Every push row on B for peer A (any artifact).
b_rows_for_a() { psql_b "SELECT count(*) FROM sync_tasks WHERE task_type = 'push' AND peer_instance_id = '${PEER_A_ON_B:-$NIL}'"; }
sha_a() { psql_a "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '${R_GEN}' AND a.path = '$1' AND a.is_deleted = false"; }
sha_b() { psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '${R_GEN}' AND a.path = '$1' AND a.is_deleted = false"; }
rows_b() { psql_b "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                   WHERE r.key = '${R_GEN}' AND a.path = '$1' AND a.is_deleted = false"; }
# "<http>:<sha256>" of what a base serves for a path of the generic repo.
served() { # base path
  local c
  c="$(curl -s -o "$W/served" -w '%{http_code}' --max-time 60 -u "$AUTH" \
    "$1/api/v1/repositories/${R_GEN}/download/$2" 2>/dev/null || echo 000)"
  echo "${c}:$(sha256sum "$W/served" 2>/dev/null | cut -d' ' -f1)"
}
wait_sha_b() { # path want secs
  local deadline=$(( $(date +%s) + $3 ))
  while [ "$(sha_b "$1")" != "$2" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 3; done
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# session_upload <base> <path> <file> <chunk_size> [replication]
# Drives the whole upload-session protocol: POST /api/v1/uploads, one PATCH
# per chunk with Content-Range, PUT .../complete. With `replication` every
# request carries X-Artifact-Keeper-Replication: true (a peer write). Echoes
# "<create>/<chunk codes joined by +>/<complete>"; the complete body lands in
# $W/complete.
session_upload() {
  local base="$1" path="$2" src="$3" csz="$4" rep="${5:-}"
  local size csum sess body c_create c_chunk chunks="" c_done off end
  local -a hdr=(-u "$AUTH")
  [ -n "$rep" ] && hdr+=(-H 'X-Artifact-Keeper-Replication: true')
  size="$(wc -c <"$src" | tr -d ' ')"; csum="$(sha "$src")"
  body="$(jq -nc --arg r "$R_GEN" --arg p "$path" --arg c "$csum" --argjson s "$size" --argjson z "$csz" \
    '{repository_key:$r,artifact_path:$p,total_size:$s,checksum_sha256:$c,chunk_size:$z}')"
  c_create="$(curl -s -o "$W/create" -w '%{http_code}' --max-time 60 "${hdr[@]}" -X POST \
    -H 'Content-Type: application/json' -d "$body" "${base}/api/v1/uploads" 2>/dev/null || echo 000)"
  sess="$(jq -r '.session_id // empty' "$W/create" 2>/dev/null)"
  if [ -z "$sess" ]; then echo "${c_create}/-/-"; return; fi
  off=0
  while [ "$off" -lt "$size" ]; do
    end=$(( off + csz - 1 )); [ "$end" -ge "$size" ] && end=$(( size - 1 ))
    tail -c "+$(( off + 1 ))" "$src" | head -c "$(( end - off + 1 ))" > "$W/chunk"
    c_chunk="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 "${hdr[@]}" -X PATCH \
      -H 'Content-Type: application/octet-stream' -H "Content-Range: bytes ${off}-${end}/${size}" \
      --data-binary @"$W/chunk" "${base}/api/v1/uploads/${sess}" 2>/dev/null || echo 000)"
    chunks="${chunks:+${chunks}+}${c_chunk}"
    off=$(( end + 1 ))
  done
  c_done="$(curl -s -o "$W/complete" -w '%{http_code}' --max-time 60 "${hdr[@]}" -X PUT \
    -H 'Content-Type: application/json' "${base}/api/v1/uploads/${sess}/complete" 2>/dev/null || echo 000)"
  echo "${c_create}/${chunks}/${c_done}"
}
all_2xx() { [[ "$1" =~ ^20[0-9](/20[0-9](\+20[0-9])*)?/20[0-9]$ ]]; }

begin_suite "push-sync-chunked-upload"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: B up, the same generic repo on A and B, B a push peer of A and A a push peer of B"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"

# Fixtures, random bytes made now: a REST control, a three-chunk upload
# (2.5 MiB at the 1 MiB minimum chunk size), a one-chunk upload and the
# three-chunk peer write to B.
REST_F="$W/rest.bin";   head -c 4096 /dev/urandom > "$REST_F"
MULTI_F="$W/multi.bin"; head -c $(( 5 * MIB / 2 )) /dev/urandom > "$MULTI_F"
ONE_F="$W/one.bin";     head -c 70000 /dev/urandom > "$ONE_F"
PEER_F="$W/peer.bin";   head -c $(( 5 * MIB / 2 )) /dev/urandom > "$PEER_F"

RID_A="$(repo_create "$A" "$R_GEN")"; RID_B="$(repo_create "$B" "$R_GEN")"
[ -n "$RID_A" ] || SETUP_ERR="${SETUP_ERR} create ${R_GEN} on A failed;"
[ -n "$RID_B" ] || SETUP_ERR="${SETUP_ERR} create ${R_GEN} on B failed;"

B_KEY="$(mint_key "$B")"; A_KEY="$(mint_key "$A")"
[ -n "$B_KEY" ] && [ -n "$A_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint API keys;"
PEER_B_ON_A="$(register_peer "$A" "dtf-chunk-b-${SLOT}-${SUF}" "http://peer-backend:8080" "$B_KEY")"
# B reaches A by its container name: the bare `backend` service alias is on
# the peer endpoint host blocklist (an internal name), the container name is not.
PEER_A_ON_B="$(register_peer "$B" "dtf-chunk-a-${SLOT}-${SUF}" "http://ak-dtf${SLOT}-backend:8080" "$A_KEY")"
if [ -z "$PEER_B_ON_A" ] || [ -z "$PEER_A_ON_B" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration failed (B on A '${PEER_B_ON_A}', A on B '${PEER_A_ON_B}': $(cat "$W"/peer-* 2>/dev/null | tr '\n' ' ' | cut -c1-300));"
else
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_B_ON_A}'" >/dev/null
  psql_b "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_A_ON_B}'" >/dev/null
  c="$(subscribe "$A" "$PEER_B_ON_A" "${RID_A:-x}")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe B to ${R_GEN} on A -> ${c};"
  # The return path an echo would travel: B pushes the same repo to A.
  c="$(subscribe "$B" "$PEER_A_ON_B" "${RID_B:-x}")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe A to ${R_GEN} on B -> ${c};"
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

REST_P="ctl/rest-${SUF}.bin"
MULTI_P="chunked/multi-${SUF}.bin"
ONE_P="chunked/one-${SUF}.bin"
PEER_P="chunked/peer-${SUF}.bin"

# =============================================================================
# CONTROL: the peer wiring works for a plain REST upload (both images)
# =============================================================================
begin_test "CONTROL: a REST PUT of a generic artifact on A queues one push row and reaches B (sha256 equal, B serves it)"
c_rest="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$REST_F" \
  "${A}/api/v1/repositories/${R_GEN}/artifacts/${REST_P}")"
st_rest_q="$(push_rows a "$PEER_B_ON_A" "$REST_P")"
wait_sha_b "$REST_P" "$(sha "$REST_F")" 90
got="$(served "$B" "$REST_P")"
if [[ "$c_rest" == 20? ]] && [[ "$st_rest_q" =~ ^(pending|in_progress|completed)\|1$ ]] \
   && [ "$(sha_b "$REST_P")" = "$(sha "$REST_F")" ] && [ "$got" = "200:$(sha "$REST_F")" ]; then
  pass
else
  infra_fail "the peer wiring itself does not deliver: REST PUT on A -> ${c_rest}, push row ${st_rest_q}, B sha=$(sha_b "$REST_P") GET=${got}" \
    "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_B_ON_A}'")"
  end_suite; exit $?
fi

# =============================================================================
# Upload sessions on A: three chunks and one chunk
# =============================================================================
r_multi="$(session_upload "$A" "$MULTI_P" "$MULTI_F" "$MIB")"
r_one="$(session_upload "$A" "$ONE_P" "$ONE_F" "$MIB")"
st_multi_q="$(push_rows a "$PEER_B_ON_A" "$MULTI_P")"
st_one_q="$(push_rows a "$PEER_B_ON_A" "$ONE_P")"

begin_test "CONTROL: a three-chunk and a one-chunk upload session on A complete and A serves the bytes"
g_multi="$(served "$A" "$MULTI_P")"; g_one="$(served "$A" "$ONE_P")"
if all_2xx "$r_multi" && all_2xx "$r_one" && [[ "$r_multi" == */*+*+*/* ]] \
   && [ "$g_multi" = "200:$(sha "$MULTI_F")" ] && [ "$g_one" = "200:$(sha "$ONE_F")" ]; then
  pass
else
  infra_fail "upload sessions on A: three-chunk create/chunks/complete=${r_multi} GET=${g_multi}; one-chunk=${r_one} GET=${g_one}" \
    "$(head -c 300 "$W/complete" 2>/dev/null)"
  end_suite; exit $?
fi

wait_sha_b "$MULTI_P" "$(sha "$MULTI_F")" 90
wait_sha_b "$ONE_P" "$(sha "$ONE_F")" 30

begin_test "FIX(#4791): a three-chunk upload session on A queues one push row and reaches B (sha256 equal, B serves it, row completed)"
gb="$(served "$B" "$MULTI_P")"; st="$(push_rows a "$PEER_B_ON_A" "$MULTI_P")"
if [[ "$st_multi_q" =~ ^(pending|in_progress|completed)\|1$ ]] && [ "$(rows_b "$MULTI_P")" = "1" ] \
   && [ "$(sha_b "$MULTI_P")" = "$(sha "$MULTI_F")" ] && [ "$gb" = "200:$(sha "$MULTI_F")" ] && [ "$st" = "completed|1" ]; then
  pass
else
  fail "the chunked upload never reached the push peer: A push row right after complete=${st_multi_q} now=${st}; B rows=$(rows_b "$MULTI_P") sha=$(sha_b "$MULTI_P") GET=${gb} (want a row, then completed|1 and 200:<sha>)" \
    "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_B_ON_A}'")"
fi

begin_test "FIX(#4791): a one-chunk upload session on A queues one push row and reaches B (sha256 equal, B serves it, row completed)"
gb="$(served "$B" "$ONE_P")"; st="$(push_rows a "$PEER_B_ON_A" "$ONE_P")"
if [[ "$st_one_q" =~ ^(pending|in_progress|completed)\|1$ ]] && [ "$(rows_b "$ONE_P")" = "1" ] \
   && [ "$(sha_b "$ONE_P")" = "$(sha "$ONE_F")" ] && [ "$gb" = "200:$(sha "$ONE_F")" ] && [ "$st" = "completed|1" ]; then
  pass
else
  fail "the single-chunk upload never reached the push peer: A push row right after complete=${st_one_q} now=${st}; B rows=$(rows_b "$ONE_P") sha=$(sha_b "$ONE_P") GET=${gb}" \
    "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_B_ON_A}'")"
fi

# =============================================================================
# GUARD: a peer write through the upload-session API on B is not echoed
# =============================================================================
r_peer="$(session_upload "$B" "$PEER_P" "$PEER_F" "$MIB" replication)"
st_peer_q="$(push_rows b "$PEER_A_ON_B" "$PEER_P")"

begin_test "GUARD(#4791): a three-chunk upload session on B carrying the replication header stores and queues no push row back to A"
gb="$(served "$B" "$PEER_P")"
if all_2xx "$r_peer" && [ "$gb" = "200:$(sha "$PEER_F")" ] && [ "$st_peer_q" = "none|0" ]; then
  pass
else
  fail "peer-write session on B: create/chunks/complete=${r_peer}, B GET=${gb}, B push rows for A=${st_peer_q} (want 2xx, 200:<sha>, none|0): a replicated write was queued again" \
    "$(head -c 300 "$W/complete" 2>/dev/null)"
fi

# --- settle (two worker ticks), then the echo end state ----------------------
sleep 25
begin_test "GUARD(#4791): nothing B received or stored was pushed back to A (no push row on B for A, A has no copy of the peer write)"
n="$(b_rows_for_a)"; a_peer="$(sha_a "$PEER_P")"
if [ "$n" = "0" ] && [ -z "$a_peer" ]; then pass; else
  fail "B push rows for A=${n}; A row for the peer write=${a_peer:-none} (want 0 and none): a replicated write was pushed back out" \
    "$(psql_b "SELECT st.status || ' ' || a.path FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id WHERE st.peer_instance_id = '${PEER_A_ON_B}'")"
fi

end_suite
