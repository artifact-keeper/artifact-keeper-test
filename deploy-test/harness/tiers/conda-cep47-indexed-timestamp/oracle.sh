#!/usr/bin/env bash
# =============================================================================
# tiers/conda-cep47-indexed-timestamp/oracle.sh
#   #6525 indexed_timestamp is when a package became visible (hold release,
#         scan policy lifted, trash restore), in repodata.json and the shard
#   #6527 a push peer keeps the source's indexed_timestamp
#   #6529 a future builder timestamp is flagged at upload
# See the manifest for the bugs.
#
# run.sh exported BASE_URL (instance A), DB_CONTAINER (A's postgres),
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, TRIVY_PORT (instance B's
# published HTTP port), RELEASE_GATE=1, COMMON_SH.
#
# Shards are decoded by harness/tiers/conda-sharded-remote-virtual/fixtures/
# cep16.py in a throwaway python:3.14-slim container, as the other CEP-16 tiers
# do.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
: "${DTF_DIR:?}"; : "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh enables errexit; every probe guards its own failure.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_DB="ak-dtf${SLOT}-peer-db"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
DECODER_IMAGE="docker.io/library/python:3.14-slim"
BUILD="${DTF_DIR}/fixtures/conda/build.sh"

R_Q="ixq-${SLOT}-${SUF}"     # upload quarantine (hold -> release)
R_P="ixp-${SLOT}-${SUF}"     # scan policy (block -> lift)
R_T="ixt-${SLOT}-${SUF}"     # trash (delete -> restore)
R_S="ixs-${SLOT}-${SUF}"     # push-replicated to B
R_F="ixf-${SLOT}-${SUF}"     # future builder timestamp
R_U="ixu-${SLOT}-${SUF}"     # generic PUT with the replication time header

FN_Q="dtfix-held-1.0-0.tar.bz2"
FN_P="dtfix-pol-1.0-0.tar.bz2"
FN_T="dtfix-trash-1.0-0.tar.bz2"
FN_S="dtfix-sync-1.0-0.tar.bz2"
FN_F="dtfix-future-1.0-0.tar.bz2"
FN_N="dtfix-now-1.0-0.tar.bz2"
FN_L="dtfix-legacy-1.0-0.tar.bz2"
FN_U1="dtfix-hdr-untrusted-1.0-0.tar.bz2"
FN_U2="dtfix-hdr-trusted-1.0-0.tar.bz2"
# The time a trusted replication PUT carries (and its milliseconds).
HDR_AT="2026-01-02T03:04:05.678901Z"
HDR_MS=1767323045678

# Time between an upload and the event that makes it visible, so the upload
# time and the visibility time cannot fall in the same millisecond.
GAP_SECS=3

W="$(mktemp -d -t dtf-cep47-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
db_now_ms() { psql_a "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint"; }

# HTTP code of a request; the body goes to $W/last, headers to $W/last.hdr.
code() { curl -s -D "$W/last.hdr" -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }
hdr() { grep -i "^$1:" "$W/last.hdr" 2>/dev/null | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }

repo_create() { # base key -> id
  local body
  body="$(jq -nc --arg k "$2" '{key:$k,name:$k,format:"conda",repo_type:"local",is_public:false}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}
build_pkg() { # name [timestamp_ms]
  CONDA_PKG_TIMESTAMP="${2:-}" bash "$BUILD" "$W" "$1" 1.0 0 noarch >/dev/null 2>&1
}
conda_put() { # base repo filename -> status (headers in $W/last.hdr)
  code -u "$AUTH" -X PUT --data-binary "@$W/$3" "$1/conda/$2/noarch/$3"
}
artifact_id() { # repo filename (on A)
  psql_a "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE r.key = '$1' AND a.path = 'noarch/$2' ORDER BY a.created_at DESC LIMIT 1"
}
created_ms() { # psql-fn repo filename
  "$1" "SELECT (EXTRACT(EPOCH FROM a.created_at) * 1000)::bigint FROM artifacts a \
        JOIN repositories r ON r.id = a.repository_id \
        WHERE r.key = '$2' AND a.path = 'noarch/$3' AND a.is_deleted = false"
}

# indexed_timestamp of FILENAME in BASE's repodata.json ("none" when absent).
rd_ts() { # base repo filename
  local c
  c="$(code -u "$AUTH" "$1/conda/$2/noarch/repodata.json")"
  [ "$c" = "200" ] || { echo "http-$c"; return; }
  jq -r --arg f "$3" '((.packages // {})[$f] // (."packages.conda" // {})[$f] // {}).indexed_timestamp // "none"' \
    "$W/last" 2>/dev/null || echo "bad-json"
}
decode() { # file -> file.json
  docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
    "$DECODER_IMAGE" python3 -I /app/cep16.py < "$1" > "$1.json" 2>/dev/null \
    && jq -e 'has("doc")' "$1.json" >/dev/null 2>&1
}
# indexed_timestamp of FILENAME in the CEP-16 shard of package NAME at BASE
# ("none" when the index does not list the name).
shard_ts() { # base repo name filename
  local c addr
  c="$(curl -s -o "$W/idx" -w '%{http_code}' --max-time 60 -u "$AUTH" \
        "$1/conda/$2/noarch/repodata_shards.msgpack.zst" 2>/dev/null || echo 000)"
  [ "$c" = "200" ] || { echo "idx-http-$c"; return; }
  decode "$W/idx" || { echo "idx-undecodable"; return; }
  addr="$(jq -r --arg n "$3" '.doc.shards[$n] // empty | if type == "object" then .bin else . end' "$W/idx.json")"
  [ -n "$addr" ] || { echo "none"; return; }
  c="$(curl -s -o "$W/shard" -w '%{http_code}' --max-time 60 -u "$AUTH" \
        "$1/conda/$2/noarch/shards/${addr}.msgpack.zst" 2>/dev/null || echo 000)"
  [ "$c" = "200" ] || { echo "shard-http-$c"; return; }
  decode "$W/shard" || { echo "shard-undecodable"; return; }
  jq -r --arg f "$4" '((.doc.packages // {})[$f] // (.doc."packages.conda" // {})[$f] // {}).indexed_timestamp // "none"' \
    "$W/shard.json"
}
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
# sha256 of the live row for FILENAME in REPO on B (empty when there is none).
sha_b_of() { psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                     WHERE r.key = '$1' AND a.path = 'noarch/$2' AND a.is_deleted = false"; }
wait_b_row() { # repo filename -> 0 when B holds a live row within ~90 s
  local _
  for _ in $(seq 1 30); do [ -n "$(sha_b_of "$1" "$2")" ] && return 0; sleep 3; done
  return 1
}

begin_suite "conda-cep47-indexed-timestamp (#6525 #6527 #6529)"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: instance B up, five hosted channels on A (one also on B), packages built, B a push peer of A"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
docker image inspect "$DECODER_IMAGE" >/dev/null 2>&1 || docker pull -q "$DECODER_IMAGE" >/dev/null 2>&1 \
  || SETUP_ERR="${SETUP_ERR} decoder image unavailable;"
declare -A RID=()
for k in "$R_Q" "$R_P" "$R_T" "$R_S" "$R_F" "$R_U"; do
  RID[$k]="$(repo_create "$A" "$k")"
  [ -n "${RID[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on A failed;"
done
for k in "$R_S" "$R_Q"; do
  [ -n "$(repo_create "$B" "$k")" ] || SETUP_ERR="${SETUP_ERR} create ${k} on B failed;"
done
c="$(code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' \
  -d '{"quarantine_enabled":true,"quarantine_duration_minutes":60}' "${A}/api/v1/repositories/${R_Q}")"
[[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} enable quarantine on ${R_Q} -> ${c};"
for n in held pol trash sync now legacy hdr-untrusted hdr-trusted; do
  build_pkg "dtfix-$n" || SETUP_ERR="${SETUP_ERR} build dtfix-$n;"
done
NOW_MS="$(date +%s%3N)"
build_pkg dtfix-now "$NOW_MS" || SETUP_ERR="${SETUP_ERR} build dtfix-now;"
FUTURE_MS=$((NOW_MS + 86400000))
build_pkg dtfix-future "$FUTURE_MS" || SETUP_ERR="${SETUP_ERR} build dtfix-future;"
B_KEY="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-cep47-a-${SUF}\",\"scopes\":[\"*\"]}" "${B}/api/v1/auth/tokens" 2>/dev/null \
  | jq -r '.token // empty' 2>/dev/null || true)"
[ -n "$B_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint an API key on B;"
PEER_ID="$(curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-cep47-b-${SLOT}-${SUF}\",\"endpoint_url\":\"http://peer-backend:8080\",\"api_key\":\"${B_KEY}\"}" \
  "${A}/api/v1/peers" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
if [ -z "$PEER_ID" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration on A failed;"
else
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_ID}'" >/dev/null
  for k in "$R_S" "$R_Q"; do
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
# #6525 (1/3): upload quarantine hold -> admin release
# =============================================================================
begin_test "CONTROL: an upload under the quarantine hold is stored, refused 409 and not listed"
c_up="$(conda_put "$A" "$R_Q" "$FN_Q")"
Q_ID="$(artifact_id "$R_Q" "$FN_Q")"
c_dl="$(code -u "$AUTH" "${A}/conda/${R_Q}/noarch/${FN_Q}")"
q_rd="$(rd_ts "$A" "$R_Q" "$FN_Q")"; q_sh="$(shard_ts "$A" "$R_Q" dtfix-held "$FN_Q")"
if [[ "$c_up" == 20? ]] && [ -n "$Q_ID" ] && [ "$c_dl" = "409" ] && [ "$q_rd" = "none" ] && [ "$q_sh" = "none" ]; then
  pass
else
  infra_fail "the hold precondition does not hold" "upload ${c_up}, id ${Q_ID:-none}, download ${c_dl}, repodata ${q_rd}, shard ${q_sh}"
fi

# Long enough for A's sync worker (10 s tick) to have pushed the held package
# had it been willing to (#6527).
sleep 25
Q_B_WHILE_HELD="$(sha_b_of "$R_Q" "$FN_Q")"
Q_RELEASE_MS="$(db_now_ms)"
c_rel="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d '{}' "${A}/api/v1/quarantine/${Q_ID:-x}/release")"
Q_CREATED_MS="$(created_ms psql_a "$R_Q" "$FN_Q")"
q_rd="$(rd_ts "$A" "$R_Q" "$FN_Q")"; q_sh="$(shard_ts "$A" "$R_Q" dtfix-held "$FN_Q")"

begin_test "CONTROL: after the release the package is listed in repodata.json and its shard"
if [[ "$c_rel" == 20? ]] && is_int "$q_rd" && is_int "$q_sh"; then
  pass
else
  fail "the released package is not listed" "release ${c_rel}: $(head -c 200 "$W/last"); repodata ${q_rd}, shard ${q_sh}"
fi

begin_test "FIX #6525: the released package's indexed_timestamp is at or after its release, not its upload, in repodata.json and the shard"
if is_int "$q_rd" && is_int "$q_sh" && [ "$q_rd" -ge "$Q_RELEASE_MS" ] && [ "$q_sh" = "$q_rd" ]; then
  pass
else
  fail "indexed_timestamp predates the release (the hold's wait counts toward a client cooldown)" \
    "repodata ${q_rd}, shard ${q_sh}, released at ${Q_RELEASE_MS}, uploaded at ${Q_CREATED_MS:-?}"
fi
Q_FIRST="$q_rd"

begin_test "FIX #6527: a held package is not pushed while held; after the release B reports A's indexed_timestamp, in repodata.json and the shard"
wait_b_row "$R_Q" "$FN_Q"
qb_rd="$(rd_ts "$B" "$R_Q" "$FN_Q")"; qb_sh="$(shard_ts "$B" "$R_Q" dtfix-held "$FN_Q")"
if [ -z "$Q_B_WHILE_HELD" ] && is_int "$Q_FIRST" && [ "$qb_rd" = "$Q_FIRST" ] && [ "$qb_sh" = "$Q_FIRST" ]; then
  pass
else
  fail "the peer got the held package early or with its own time" \
    "on B while held: [${Q_B_WHILE_HELD:-none}]; A ${Q_FIRST}; B repodata ${qb_rd}, shard ${qb_sh}"
fi

# =============================================================================
# #6525 (2/3): scan policy refuses the upload -> policy deleted
# =============================================================================
pol_body="$(jq -nc --arg n "ix-pol-${SUF}" --arg r "${RID[$R_P]}" \
  '{name:$n, repository_id:$r, max_severity:"critical", block_unscanned:false, block_on_fail:false,
    predicates:{conda:{min_attestation_state:"verified"}}}')"
c_pol="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d "$pol_body" "${A}/api/v1/security/policies")"
POL_ID="$(jq -r '.id // empty' "$W/last" 2>/dev/null)"

begin_test "CONTROL: under a policy that refuses unattested packages the upload is stored and not listed"
c_up="$(conda_put "$A" "$R_P" "$FN_P")"
p_rd="$(rd_ts "$A" "$R_P" "$FN_P")"; p_sh="$(shard_ts "$A" "$R_P" dtfix-pol "$FN_P")"
if [[ "$c_pol" == 20? ]] && [ -n "$POL_ID" ] && [[ "$c_up" == 20? ]] && [ "$p_rd" = "none" ] && [ "$p_sh" = "none" ]; then
  pass
else
  infra_fail "the policy precondition does not hold" "policy ${c_pol} id ${POL_ID:-none}, upload ${c_up}, repodata ${p_rd}, shard ${p_sh}"
fi

sleep "$GAP_SECS"
P_LIFT_MS="$(db_now_ms)"
c_del="$(code -u "$AUTH" -X DELETE "${A}/api/v1/security/policies/${POL_ID:-x}")"
# The shard first, as a sharded client (pixi, rattler) asks; then repodata.json.
p_sh="$(shard_ts "$A" "$R_P" dtfix-pol "$FN_P")"
for _ in 1 2 3 4 5; do
  is_int "$p_sh" && break
  sleep 1; p_sh="$(shard_ts "$A" "$R_P" dtfix-pol "$FN_P")"
done
p_rd="$(rd_ts "$A" "$R_P" "$FN_P")"

begin_test "CONTROL: once the policy is deleted the package is listed in its shard and repodata.json"
if [[ "$c_del" == 20? ]] && is_int "$p_rd" && is_int "$p_sh"; then
  pass
else
  fail "the package is not listed after the policy was deleted" "delete ${c_del}; repodata ${p_rd}, shard ${p_sh}"
fi

begin_test "FIX #6525: the policy-cleared package's indexed_timestamp is at or after the policy was lifted, in the shard and repodata.json"
if is_int "$p_rd" && is_int "$p_sh" && [ "$p_sh" -ge "$P_LIFT_MS" ] && [ "$p_rd" = "$p_sh" ]; then
  pass
else
  fail "indexed_timestamp predates the policy lifting" \
    "shard ${p_sh}, repodata ${p_rd}, lifted at ${P_LIFT_MS}, uploaded at $(created_ms psql_a "$R_P" "$FN_P")"
fi

# =============================================================================
# #6525 (3/3): delete -> trash restore
# =============================================================================
begin_test "CONTROL: an uploaded package is listed, then gone after a delete"
c_up="$(conda_put "$A" "$R_T" "$FN_T")"
t_before="$(rd_ts "$A" "$R_T" "$FN_T")"
T_ID="$(artifact_id "$R_T" "$FN_T")"
sleep "$GAP_SECS"
c_del="$(code -u "$AUTH" -X DELETE "${A}/api/v1/repositories/${R_T}/artifacts/noarch/${FN_T}")"
t_gone="$(rd_ts "$A" "$R_T" "$FN_T")"
if [[ "$c_up" == 20? ]] && is_int "$t_before" && [[ "$c_del" == 20? ]] && [ "$t_gone" = "none" ]; then
  pass
else
  infra_fail "the trash precondition does not hold" "upload ${c_up}, listed ${t_before}, delete ${c_del}, after delete ${t_gone}"
fi

T_RESTORE_MS="$(db_now_ms)"
c_rst="$(code -u "$AUTH" -X POST "${A}/api/v1/admin/trash/${T_ID:-x}/restore")"
t_rd="$(rd_ts "$A" "$R_T" "$FN_T")"; t_sh="$(shard_ts "$A" "$R_T" dtfix-trash "$FN_T")"

begin_test "CONTROL: a restored package that was listed before keeps its indexed_timestamp (the same bytes; clients saw that value)"
if [[ "$c_rst" == 20? ]] && is_int "$t_rd" && [ "$t_rd" = "$t_before" ] && [ "$t_sh" = "$t_rd" ]; then
  pass
else
  fail "the restored package's value moved or it is not listed" "restore ${c_rst}: $(head -c 200 "$W/last"); before ${t_before}, repodata ${t_rd}, shard ${t_sh}"
fi

# A package from before the indexed_at column: dated by its creation, long ago.
c_up="$(conda_put "$A" "$R_T" "$FN_L")"
L_ID="$(artifact_id "$R_T" "$FN_L")"
psql_a "UPDATE artifacts SET created_at = NOW() - INTERVAL '30 days' WHERE id = '${L_ID:-00000000-0000-0000-0000-000000000000}'" >/dev/null
psql_a "UPDATE artifacts SET indexed_at = NULL WHERE id = '${L_ID:-00000000-0000-0000-0000-000000000000}'" >/dev/null
c_del="$(code -u "$AUTH" -X DELETE "${A}/api/v1/repositories/${R_T}/artifacts/noarch/${FN_L}")"
L_RESTORE_MS="$(db_now_ms)"
c_rst="$(code -u "$AUTH" -X POST "${A}/api/v1/admin/trash/${L_ID:-x}/restore")"
l_rd="$(rd_ts "$A" "$R_T" "$FN_L")"; l_sh="$(shard_ts "$A" "$R_T" dtfix-legacy "$FN_L")"

begin_test "FIX #6525: a restored package that was never dated is indexed at its restore, not its 30-day-old upload, in repodata.json and the shard"
if [[ "$c_up" == 20? ]] && [[ "$c_del" == 20? ]] && [[ "$c_rst" == 20? ]] \
   && is_int "$l_rd" && [ "$l_rd" -ge "$L_RESTORE_MS" ] && [ "$l_sh" = "$l_rd" ]; then
  pass
else
  fail "a restored package reports its old upload time, as if it had been visible all along" \
    "upload ${c_up}, delete ${c_del}, restore ${c_rst}; repodata ${l_rd}, shard ${l_sh}, restored at ${L_RESTORE_MS}"
fi

begin_test "CONTROL: indexed_timestamp is stable: the released package reports the same value after other writes rebuilt the channel"
conda_put "$A" "$R_Q" "$FN_N" >/dev/null   # a write to the held channel; held itself, which is fine
c_up="$(conda_put "$A" "$R_Q" "$FN_T")"     # another package in the same subdir
q_again="$(rd_ts "$A" "$R_Q" "$FN_Q")"; q_sh_again="$(shard_ts "$A" "$R_Q" dtfix-held "$FN_Q")"
if [ "$q_again" = "$Q_FIRST" ] && [ "$q_sh_again" = "$Q_FIRST" ]; then
  pass
else
  fail "indexed_timestamp moved across rebuilds" "first ${Q_FIRST}, now repodata ${q_again} shard ${q_sh_again} (upload ${c_up})"
fi

# =============================================================================
# #6527: the X-Artifact-Indexed-At header of a single-request replication PUT
# =============================================================================
U_START_MS="$(db_now_ms)"
c_u1="$(code -u "$AUTH" -X PUT -H "X-Artifact-Indexed-At: ${HDR_AT}" --data-binary "@$W/$FN_U1" \
  "${A}/api/v1/repositories/${R_U}/artifacts/noarch/${FN_U1}")"
u1="$(rd_ts "$A" "$R_U" "$FN_U1")"

begin_test "CONTROL: the header on a write that is not a peer replication is ignored"
if [[ "$c_u1" == 20? ]] && is_int "$u1" && [ "$u1" != "$HDR_MS" ] && [ "$u1" -ge "$((U_START_MS - 1000))" ]; then
  pass
else
  fail "a caller set its own indexed_timestamp" "PUT ${c_u1}: $(head -c 200 "$W/last"); served ${u1}, header ${HDR_MS}"
fi

c_u2="$(code -u "$AUTH" -X PUT -H "X-Artifact-Keeper-Replication: true" -H "X-Artifact-Indexed-At: ${HDR_AT}" \
  --data-binary "@$W/$FN_U2" "${A}/api/v1/repositories/${R_U}/artifacts/noarch/${FN_U2}")"
# A generic PUT records no conda metadata, so the shard is keyed by the
# row's own name, whatever the generic route derived from the path.
U2_NAME="$(psql_a "SELECT a.name FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                   WHERE r.key = '${R_U}' AND a.path = 'noarch/${FN_U2}' AND a.is_deleted = false")"
u2="$(rd_ts "$A" "$R_U" "$FN_U2")"; u2_sh="$(shard_ts "$A" "$R_U" "${U2_NAME:-x}" "$FN_U2")"

begin_test "FIX #6527: a trusted single-request replication PUT keeps the source's time from X-Artifact-Indexed-At, in repodata.json and the shard"
if [[ "$c_u2" == 20? ]] && [ "$u2" = "$HDR_MS" ] && [ "$u2_sh" = "$HDR_MS" ]; then
  pass
else
  fail "the replicated row was dated by the receiver" "PUT ${c_u2}: $(head -c 200 "$W/last"); repodata ${u2}, shard ${u2_sh}, header ${HDR_MS}"
fi

# =============================================================================
# #6529: future builder timestamp at upload (default action: warn)
# =============================================================================
begin_test "CONTROL: a package whose builder timestamp is now uploads without a timestamp warning"
c_now="$(conda_put "$A" "$R_F" "$FN_N")"
w_now="$(hdr X-Conda-Timestamp-Warning)"
if [[ "$c_now" == 20? ]] && [ -z "$w_now" ]; then
  pass
else
  fail "a normal upload was affected" "HTTP ${c_now}, warning [${w_now}]: $(head -c 200 "$W/last")"
fi

c_fut="$(conda_put "$A" "$R_F" "$FN_F")"
w_fut="$(hdr X-Conda-Timestamp-Warning)"

begin_test "CONTROL: by default a package whose builder timestamp is a day ahead is still accepted and listed with that timestamp"
f_ts="$(code -u "$AUTH" "${A}/conda/${R_F}/noarch/repodata.json" >/dev/null; \
        jq -r --arg f "$FN_F" '(.packages // {})[$f].timestamp // "none"' "$W/last" 2>/dev/null)"
if [[ "$c_fut" == 20? ]] && [ "$f_ts" = "$FUTURE_MS" ]; then
  pass
else
  fail "the default must not refuse existing publishers" "HTTP ${c_fut}: $(head -c 200 "$W/last"); listed timestamp ${f_ts}"
fi

begin_test "FIX #6529: the future-dated upload is flagged: X-Conda-Timestamp-Warning on the 201 and package.future_timestamp in its audit row"
audit_n=0
for _ in 1 2 3 4 5 6; do
  audit_n="$(psql_a "SELECT count(*) FROM audit_log WHERE action = 'ARTIFACT_UPLOADED' \
             AND details->'package'->>'filename' = '${FN_F}' \
             AND details->'repository' #>> '{}' = '${R_F}' \
             AND (details->'package'->'future_timestamp'->>'timestamp_ms')::bigint = ${FUTURE_MS}")"
  [ "${audit_n:-0}" -ge 1 ] && break
  sleep 1
done
if [ -n "$w_fut" ] && [[ "$w_fut" == *"in the future"* ]] && [ "${audit_n:-0}" -ge 1 ]; then
  pass
else
  fail "a future builder timestamp was stored unflagged" "warning header [${w_fut}], audit rows ${audit_n:-0}"
fi

# =============================================================================
# #6527: push replication keeps the source's indexed_timestamp
# =============================================================================
begin_test "CONTROL: a package uploaded to A reaches B through the push peer"
c_up="$(conda_put "$A" "$R_S" "$FN_S")"
sha_a="$(psql_a "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                 WHERE r.key = '${R_S}' AND a.path = 'noarch/${FN_S}' AND a.is_deleted = false")"
sha_b=""
for _ in $(seq 1 30); do
  sha_b="$(psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                   WHERE r.key = '${R_S}' AND a.path = 'noarch/${FN_S}' AND a.is_deleted = false")"
  [ -n "$sha_b" ] && break
  sleep 3
done
if [[ "$c_up" == 20? ]] && [ -n "$sha_a" ] && [ "$sha_a" = "$sha_b" ]; then
  pass
else
  fail "replication to B did not complete" "upload ${c_up}; A ${sha_a:-none}; B ${sha_b:-none}; tasks: $(psql_a "SELECT status || ':' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' ORDER BY created_at DESC LIMIT 3")"
fi

s_a_rd="$(rd_ts "$A" "$R_S" "$FN_S")"; s_a_sh="$(shard_ts "$A" "$R_S" dtfix-sync "$FN_S")"
s_b_rd="$(rd_ts "$B" "$R_S" "$FN_S")"; s_b_sh="$(shard_ts "$B" "$R_S" dtfix-sync "$FN_S")"
S_A_CREATED="$(created_ms psql_a "$R_S" "$FN_S")"; S_B_CREATED="$(created_ms psql_b "$R_S" "$FN_S")"

begin_test "CONTROL: both peers list the package, and B received it later than A stored it"
if is_int "$s_a_rd" && is_int "$s_b_rd" && is_int "${S_A_CREATED:-x}" && is_int "${S_B_CREATED:-x}" \
   && [ "$S_B_CREATED" -gt "$S_A_CREATED" ]; then
  pass
else
  fail "precondition" "A repodata ${s_a_rd}, B repodata ${s_b_rd}, A created ${S_A_CREATED:-?}, B created ${S_B_CREATED:-?}"
fi

begin_test "FIX #6527: A and B report the same indexed_timestamp, in repodata.json and the shard"
if is_int "$s_a_rd" && [ "$s_b_rd" = "$s_a_rd" ] && [ "$s_a_sh" = "$s_a_rd" ] && [ "$s_b_sh" = "$s_a_rd" ]; then
  pass
else
  fail "the replicas disagree on indexed_timestamp (B stamped its receipt time)" \
    "A repodata ${s_a_rd} shard ${s_a_sh}; B repodata ${s_b_rd} shard ${s_b_sh}"
fi

end_suite
