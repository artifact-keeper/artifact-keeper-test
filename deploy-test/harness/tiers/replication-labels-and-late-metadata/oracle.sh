#!/usr/bin/env bash
# =============================================================================
# tiers/replication-labels-and-late-metadata/oracle.sh
#   #4889 a protobuf `_labels` move reaches a push peer (and a later move is
#         re-delivered), and NuGet nuspec metadata written after the push was
#         queued still reaches the peer; peer writes are still not echoed
#   #4921 a protobuf commit uploaded after the peer subscribed reaches it
# See the manifest for THE BUGS, THE PEERS, THE PRIMITIVE and the gates.
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
SUFN="${RUN_ID##*-}$$"; SUFN="${SUFN//[^0-9a-z]/}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_DB="ak-dtf${SLOT}-peer-db"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
NIL="00000000-0000-0000-0000-000000000000"

R_PB="rlpb-${SLOT}-${SUF}"
R_NU="rlnu-${SLOT}-${SUF}"
OWNER="dtf"; MOD="labels${SUFN}"; MOD_ECHO="echo${SUFN}"
LBL_PATH="modules/${OWNER}/${MOD}/_labels"
NU_ID="DtfLate${SUFN}"; NU_ID_LC="dtflate${SUFN}"
NU_DESC="dtf late metadata ${SUFN}"
NU_PATH="${NU_ID_LC}/1.0.0/${NU_ID_LC}.1.0.0.nupkg"
NU_ECHO_PATH="${NU_ID_LC}/2.0.0/${NU_ID_LC}.2.0.0.nupkg"

W="$(mktemp -d -t dtf-rlabels-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# HTTP code of a request; the body goes to $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 90 "$@" 2>/dev/null || echo 000; }

repo_create() { # base key format -> id
  local body
  body="$(jq -nc --arg k "$2" --arg f "$3" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}
mint_key() { # base -> token
  curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"dtf-rlabels-${SUF}-$RANDOM\",\"scopes\":[\"*\"]}" "$1/api/v1/auth/tokens" 2>/dev/null \
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
push_rows() { # a|b peer repo path
  local q="SELECT coalesce(max(st.status::text),'none') || '|' || count(st.id) \
          FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          LEFT JOIN sync_tasks st ON st.artifact_id = a.id AND st.task_type = 'push' \
               AND st.peer_instance_id = '${2:-$NIL}' \
          WHERE r.key = '$3' AND a.path = '$4' AND a.is_deleted = false"
  if [ "$1" = a ]; then psql_a "$q"; else psql_b "$q"; fi
}
b_rows_for_a() { psql_b "SELECT count(*) FROM sync_tasks WHERE task_type = 'push' AND peer_instance_id = '${PEER_A_ON_B:-$NIL}'"; }
sha_of() { # a|b repo path -> sha256 of the live row
  local q="SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
           WHERE r.key = '$2' AND a.path = '$3' AND a.is_deleted = false"
  if [ "$1" = a ]; then psql_a "$q"; else psql_b "$q"; fi
}
rows_of() { # a|b repo path -> live row count
  local q="SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
           WHERE r.key = '$2' AND a.path = '$3' AND a.is_deleted = false"
  if [ "$1" = a ]; then psql_a "$q"; else psql_b "$q"; fi
}
meta_of() { # a|b repo path -> compact metadata JSON (or empty)
  local q="SELECT am.metadata::text FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
           JOIN artifact_metadata am ON am.artifact_id = a.id \
           WHERE r.key = '$2' AND a.path = '$3' AND a.is_deleted = false"
  if [ "$1" = a ]; then psql_a "$q"; else psql_b "$q"; fi
}
# "<http>:<sha256>" of what B serves at a URL.
served_b() {
  local c
  c="$(curl -s -o "$W/servedb" -w '%{http_code}' --max-time 60 -u "$AUTH" "$1" 2>/dev/null || echo 000)"
  echo "${c}:$(sha256sum "$W/servedb" 2>/dev/null | cut -d' ' -f1)"
}

# Connect JSON call: base repo method body [extra curl args...] -> http code, body in $W/last
rpc() {
  local base="$1" repo="$2" m="$3" body="$4"; shift 4
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' \
    "$@" -d "$body" "${base}/proto/${repo}/${m}"
}
UPLOAD="buf.registry.module.v1beta1.UploadService/Upload"
GETLBL="buf.registry.module.v1.LabelService/GetLabels"
SETLBL="buf.registry.module.v1.LabelService/CreateOrUpdateLabels"
upload_body() { # module proto-text [label] -> Connect JSON
  local b64; b64="$(printf '%s' "$2" | base64 | tr -d '\n')"
  jq -nc --arg o "$OWNER" --arg m "$1" --arg p "${OWNER}/$1/v1/x.proto" --arg c "$b64" --arg l "${3:-}" \
    '{contents:[{moduleRef:{owner:$o,module:$m},files:[{path:$p,content:$c}]} + (if $l == "" then {} else {labelRefs:[{name:$l}]} end)]}'
}
# The commit digest a label resolves to on one side ("" when unknown).
label_on() { # base label
  rpc "$1" "$R_PB" "$GETLBL" "$(jq -nc --arg o "$OWNER" --arg m "$MOD" --arg l "$2" '{labelRefs:[{owner:$o,module:$m,label:$l}]}')" >/dev/null
  jq -r '.labels[0].commitId // empty' < "$W/last" 2>/dev/null || true
}
wait_label_b() { # label want secs -> last seen
  local deadline=$(( $(date +%s) + $3 )) got
  got="$(label_on "$B" "$1")"
  while [ "$got" != "$2" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 3; got="$(label_on "$B" "$1")"; done
  echo "$got"
}
wait_sha_b() { # repo path want secs
  local deadline=$(( $(date +%s) + $4 ))
  while [ "$(sha_of b "$1" "$2")" != "$3" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 3; done
}

nupkg() { # out id version description
  python3 -I - "$@" <<'PY'
import sys, zipfile
out, pid, ver, desc = sys.argv[1:5]
nuspec = ('<?xml version="1.0" encoding="utf-8"?>\n'
          '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>'
          f'<id>{pid}</id><version>{ver}</version><authors>DTF</authors>'
          f'<description>{desc}</description></metadata></package>\n')
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr(f"{pid}.nuspec", nuspec)
    z.writestr("lib/net8.0/placeholder.txt", f"dtf {pid} {ver}\n")
PY
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

begin_suite "replication-labels-and-late-metadata"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: B up, fixtures built, protobuf and nuget repos on A and B, each instance a push peer of the other"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
nupkg "$W/late.nupkg" "$NU_ID" 1.0.0 "$NU_DESC"
nupkg "$W/echo.nupkg" "$NU_ID" 2.0.0 "dtf echo ${SUFN}"
[ -s "$W/late.nupkg" ] && [ -s "$W/echo.nupkg" ] || SETUP_ERR="${SETUP_ERR} nupkg fixtures not built (python3);"

declare -A RID_A=() RID_B=()
for spec in "$R_PB:protobuf" "$R_NU:nuget"; do
  IFS=: read -r k f <<<"$spec"
  RID_A[$k]="$(repo_create "$A" "$k" "$f")"
  RID_B[$k]="$(repo_create "$B" "$k" "$f")"
  [ -n "${RID_A[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on A failed;"
  [ -n "${RID_B[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on B failed;"
done

B_KEY="$(mint_key "$B")"; A_KEY="$(mint_key "$A")"
[ -n "$B_KEY" ] && [ -n "$A_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint API keys;"
PEER_B_ON_A="$(register_peer "$A" "dtf-peer-b-${SLOT}-${SUF}" "http://peer-backend:8080" "$B_KEY")"
# B reaches A by its container name: the bare `backend` service alias is on
# the peer endpoint host blocklist (an internal name), the container name is not.
PEER_A_ON_B="$(register_peer "$B" "dtf-peer-a-${SLOT}-${SUF}" "http://ak-dtf${SLOT}-backend:8080" "$A_KEY")"
if [ -z "$PEER_B_ON_A" ] || [ -z "$PEER_A_ON_B" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration failed (B on A '${PEER_B_ON_A}', A on B '${PEER_A_ON_B}': $(cat "$W"/peer-* 2>/dev/null | tr '\n' ' ' | cut -c1-300));"
else
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_B_ON_A}'" >/dev/null
  psql_b "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_A_ON_B}'" >/dev/null
  # B subscribes to A's protobuf repo only after the commits exist (below).
  c="$(subscribe "$A" "$PEER_B_ON_A" "${RID_A[$R_NU]:-x}")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe B to ${R_NU} on A -> ${c};"
  for k in "$R_PB" "$R_NU"; do
    # The return path an echo would travel: B pushes the same repos to A.
    c="$(subscribe "$B" "$PEER_A_ON_B" "${RID_B[$k]:-x}")"
    [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe A to ${k} on B -> ${c};"
  done
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# NuGet: hold the nuspec metadata write open, watch A's push row
# =============================================================================
inst="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -qc "
CREATE SEQUENCE dtf_late_seq_${SUFN};
CREATE TABLE dtf_late_release_${SUFN} (x int);
CREATE OR REPLACE FUNCTION dtf_late_meta_${SUFN}() RETURNS trigger LANGUAGE plpgsql AS \$\$
BEGIN
  IF NEW.metadata::text LIKE '%${NU_DESC}%' THEN
    PERFORM nextval('dtf_late_seq_${SUFN}');
    FOR i IN 1..240 LOOP
      EXIT WHEN EXISTS (SELECT 1 FROM dtf_late_release_${SUFN});
      PERFORM pg_sleep(0.25);
    END LOOP;
  END IF;
  RETURN NEW;
END \$\$;
CREATE TRIGGER dtf_late_meta_${SUFN} BEFORE INSERT OR UPDATE ON artifact_metadata
  FOR EACH ROW EXECUTE FUNCTION dtf_late_meta_${SUFN}();" 2>&1)"; irc=$?

begin_test "CONTROL: a NuGet push on A succeeds while its nuspec metadata write is held open, and reaches B (row, sha256, bytes)"
if [ "$irc" -ne 0 ]; then
  infra_fail "could not install the artifact_metadata hold trigger" "$inst"; end_suite; exit $?
fi
( curl -s --max-time 120 -o "$W/nupush.out" -w '%{http_code}' -u "$AUTH" -X PUT \
    -F "package=@$W/late.nupkg;type=application/octet-stream" "${A}/nuget/${R_NU}/api/v2/package" \
    > "$W/nupush.code" 2>/dev/null ) &
NU_PID=$!
held="no"
for _i in $(seq 1 80); do
  [ "$(psql_a "SELECT is_called FROM dtf_late_seq_${SUFN}")" = "t" ] && { held="yes"; break; }
  sleep 0.25
done
# While the document is held: did A already queue (and deliver) the package?
st_held="none|0"
deadline=$(( $(date +%s) + 25 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  st_held="$(push_rows a "$PEER_B_ON_A" "$R_NU" "$NU_PATH")"
  [ "$st_held" = "completed|1" ] && break
  sleep 1
done
psql_a "INSERT INTO dtf_late_release_${SUFN} VALUES (1)" >/dev/null
wait "$NU_PID"
c_nu="$(cat "$W/nupush.code" 2>/dev/null)"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qc \
  "DROP TRIGGER IF EXISTS dtf_late_meta_${SUFN} ON artifact_metadata; DROP FUNCTION IF EXISTS dtf_late_meta_${SUFN}(); \
   DROP TABLE IF EXISTS dtf_late_release_${SUFN}; DROP SEQUENCE IF EXISTS dtf_late_seq_${SUFN};" >/dev/null 2>&1
echo "   metadata write held: ${held}; A push row while held: ${st_held}; push -> ${c_nu}"
want_nu="$(sha "$W/late.nupkg")"
wait_sha_b "$R_NU" "$NU_PATH" "$want_nu" 60
got_nu="$(served_b "${B}/api/v1/repositories/${R_NU}/download/${NU_PATH}")"
if [ "$held" = "yes" ] && [[ "$c_nu" == 20? ]] && [ "$(sha_of a "$R_NU" "$NU_PATH")" = "$want_nu" ] \
   && [ "$(sha_of b "$R_NU" "$NU_PATH")" = "$want_nu" ] && [ "$got_nu" = "200:${want_nu}" ]; then
  pass
else
  fail "held=${held} push=${c_nu} $(head -c 160 "$W/nupush.out"); A sha=$(sha_of a "$R_NU" "$NU_PATH") B sha=$(sha_of b "$R_NU" "$NU_PATH") B GET=${got_nu} (want ${want_nu})"
fi

# =============================================================================
# #4889-1: the protobuf `_labels` index reaches B, and a later move is re-delivered
# =============================================================================
# The two commits are uploaded BEFORE B subscribes to A's protobuf repo, so
# only label writes are queued for B and the label gates time only the label
# deliveries. Before #4921 every commit push failed and backed the whole peer
# off, which would have starved them. The commit push itself is covered by the
# #4921 gates at the end, with a commit uploaded after B subscribed.
begin_test "CONTROL: two buf Uploads on A (main -> commit 1, dev -> commit 2) before B subscribes; nothing is queued for B"
c1="$(rpc "$A" "$R_PB" "$UPLOAD" "$(upload_body "$MOD" "syntax = \"proto3\"; // dtf c1 ${SUFN}")")"
D1="$(jq -r '.commits[0].digest.value // empty' < "$W/last" 2>/dev/null)"
c2="$(rpc "$A" "$R_PB" "$UPLOAD" "$(upload_body "$MOD" "syntax = \"proto3\"; // dtf c2 ${SUFN}" dev)")"
D2="$(jq -r '.commits[0].digest.value // empty' < "$W/last" 2>/dev/null)"
a_main="$(label_on "$A" main)"; a_dev="$(label_on "$A" dev)"
n_pb="$(psql_a "SELECT count(*) FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id WHERE a.repository_id = '${RID_A[$R_PB]}'")"
if [ "$c1" = "200" ] && [ "$c2" = "200" ] && [ -n "$D1" ] && [ -n "$D2" ] && [ "$D1" != "$D2" ] \
   && [ "$a_main" = "$D1" ] && [ "$a_dev" = "$D2" ] && [ "$n_pb" = "0" ]; then
  pass
else
  infra_fail "buf Uploads on A -> ${c1}/${c2} digests '${D1}' '${D2}'; A main -> '${a_main}', dev -> '${a_dev}'; protobuf sync rows on A ${n_pb}"
  end_suite; exit $?
fi
c="$(subscribe "$A" "$PEER_B_ON_A" "${RID_A[$R_PB]:-x}")"
[ "$c" = "200" ] || { infra_fail "subscribe B to ${R_PB} on A -> ${c}"; end_suite; exit $?; }

move_main() { # digest -> http code (A's CreateOrUpdateLabels)
  rpc "$A" "$R_PB" "$SETLBL" "$(jq -nc --arg o "$OWNER" --arg m "$MOD" --arg d "$1" '{values:[{owner:$o,module:$m,name:"main",commitId:$d}]}')"
}
wait_push_a() { # repo path want secs -> last seen
  local deadline=$(( $(date +%s) + $4 )) got
  got="$(push_rows a "$PEER_B_ON_A" "$1" "$2")"
  while [ "$got" != "$3" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 2; got="$(push_rows a "$PEER_B_ON_A" "$1" "$2")"; done
  echo "$got"
}

c="$(move_main "$D2")"; a_main="$(label_on "$A" main)"
begin_test "FIX(#4889): moving main on A (CreateOrUpdateLabels) pushes the label index: B resolves main and dev to commit 2, one _labels row with A's sha256, no package version for it"
b_main="$(wait_label_b main "$D2" 60)"; b_dev="$(label_on "$B" dev)"
st_l="$(wait_push_a "$R_PB" "$LBL_PATH" "completed|1" 20)"
a_lsha="$(sha_of a "$R_PB" "$LBL_PATH")"; b_lsha="$(sha_of b "$R_PB" "$LBL_PATH")"
b_lrows="$(rows_of b "$R_PB" "$LBL_PATH")"
b_pv="$(psql_b "SELECT count(*) FROM package_versions pv JOIN packages p ON p.id = pv.package_id \
               WHERE p.repository_id = '${RID_B[$R_PB]}' AND pv.version = '_labels'")"
echo "   A move -> ${c}, A main -> ${a_main}; B main -> '${b_main}', dev -> '${b_dev}'; A _labels push row ${st_l}; _labels sha A ${a_lsha} B ${b_lsha}"
if [ "$c" = "200" ] && [ "$a_main" = "$D2" ] && [ "$b_main" = "$D2" ] && [ "$b_dev" = "$D2" ] && [ "$b_lrows" = "1" ] \
   && [ -n "$a_lsha" ] && [ "$a_lsha" = "$b_lsha" ] && [ "${b_pv:-x}" = "0" ] && [ "$st_l" = "completed|1" ]; then
  pass
else
  fail "B main -> '${b_main}', dev -> '${b_dev}' (want ${D2} both); _labels rows on B ${b_lrows}, sha A '${a_lsha}' B '${b_lsha}'; B package versions named _labels ${b_pv}; A _labels push row ${st_l} (want completed|1)" \
       "$(psql_a "SELECT a.path || ' ' || st.status || ' ' || coalesce(st.error_message,'') FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id WHERE st.peer_instance_id = '${PEER_B_ON_A}'")"
fi

# The first label push is finished; a second move must re-arm that same row.
c="$(move_main "$D1")"; a_main="$(label_on "$A" main)"
begin_test "FIX(#4889): moving main back after the first push finished is re-delivered: B resolves main to commit 1 within 60 s, through A's single _labels push row"
b_main="$(wait_label_b main "$D1" 60)"; b_dev="$(label_on "$B" dev)"
st_l="$(wait_push_a "$R_PB" "$LBL_PATH" "completed|1" 20)"
a_lsha="$(sha_of a "$R_PB" "$LBL_PATH")"; b_lsha="$(sha_of b "$R_PB" "$LBL_PATH")"
echo "   A move -> ${c}, A main -> ${a_main}; B main -> '${b_main}', dev -> '${b_dev}'; A _labels push row ${st_l}; _labels sha A ${a_lsha} B ${b_lsha}"
if [ "$c" = "200" ] && [ "$a_main" = "$D1" ] && [ "$b_main" = "$D1" ] && [ "$b_dev" = "$D2" ] && [ "$a_lsha" = "$b_lsha" ] \
   && [ "$(rows_of b "$R_PB" "$LBL_PATH")" = "1" ] && [ "$st_l" = "completed|1" ]; then
  pass
else
  fail "CreateOrUpdateLabels on A -> ${c}; A main -> '${a_main}'; B main -> '${b_main}' (want ${D1}), dev -> '${b_dev}' (want ${D2}); _labels sha A '${a_lsha}' B '${b_lsha}'; A _labels push row ${st_l} (want completed|1)"
fi

# =============================================================================
# #4889-2: the NuGet metadata that landed after the push
# =============================================================================
begin_test "FIX(#4889): the NuGet package's nuspec metadata written on A after its push was queued is on B (id, version, description)"
want_meta="$(meta_of a "$R_NU" "$NU_PATH" | jq -c '{id,version,description}' 2>/dev/null)"
deadline=$(( $(date +%s) + 60 ))
got_meta="$(meta_of b "$R_NU" "$NU_PATH" | jq -c '{id,version,description}' 2>/dev/null)"
while [ "$got_meta" != "$want_meta" ] && [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 3; got_meta="$(meta_of b "$R_NU" "$NU_PATH" | jq -c '{id,version,description}' 2>/dev/null)"
done
reg="$(code -u "$AUTH" "${B}/nuget/${R_NU}/v3/registration/${NU_ID_LC}/index.json")"
reg_desc="$(jq -r '[.items[]?.items[]?.catalogEntry.description] | first // empty' < "$W/last" 2>/dev/null)"
echo "   A metadata ${want_meta}; B metadata ${got_meta:-none}; B v3 registration ${reg} description '${reg_desc}'"
if [ -n "$want_meta" ] && [ "$want_meta" != "null" ] && [ "$got_meta" = "$want_meta" ]; then
  pass
else
  fail "B holds metadata '${got_meta:-none}' for ${NU_PATH}, want A's ${want_meta} (A push row while the write was held: ${st_held}, now $(push_rows a "$PEER_B_ON_A" "$R_NU" "$NU_PATH")); B v3 registration ${reg} description '${reg_desc}'"
fi

# =============================================================================
# Echo control: peer writes on B's native routes queue nothing back to A
# =============================================================================
c_nu2="$(code -u "$AUTH" -X PUT -H 'X-Artifact-Keeper-Replication: true' \
  -F "package=@$W/echo.nupkg;type=application/octet-stream" "${B}/nuget/${R_NU}/api/v2/package")"
c_pb2="$(rpc "$B" "$R_PB" "$UPLOAD" "$(upload_body "$MOD_ECHO" "syntax = \"proto3\"; // dtf echo ${SUFN}")" \
  -H 'X-Artifact-Keeper-Replication: true')"
DE="$(jq -r '.commits[0].digest.value // empty' < "$W/last" 2>/dev/null)"
st_nu2="$(push_rows b "$PEER_A_ON_B" "$R_NU" "$NU_ECHO_PATH")"
st_pb2="$(push_rows b "$PEER_A_ON_B" "$R_PB" "modules/${OWNER}/${MOD_ECHO}/commits/${DE}")"
st_pbl="$(push_rows b "$PEER_A_ON_B" "$R_PB" "modules/${OWNER}/${MOD_ECHO}/_labels")"
begin_test "CONTROL: a NuGet push and a buf Upload arriving at B as peer writes store and queue no push row back to A"
if [[ "$c_nu2" == 20? ]] && [ "$c_pb2" = "200" ] && [ "$st_nu2" = "none|0" ] && [ "$st_pb2" = "none|0" ] && [ "$st_pbl" = "none|0" ]; then
  pass
else
  fail "peer NuGet push on B -> ${c_nu2} (push rows for A ${st_nu2}); peer buf Upload on B -> ${c_pb2} (commit rows for A ${st_pb2}, _labels rows for A ${st_pbl}); want 2xx and none|0 each"
fi

sleep 25
begin_test "CONTROL: after settling B holds no push row for A (A's deliveries, the _labels refreshes and the peer writes were not echoed) and A never got the peer writes"
n="$(b_rows_for_a)"
a_nu2="$(sha_of a "$R_NU" "$NU_ECHO_PATH")"; a_pb2="$(rows_of a "$R_PB" "modules/${OWNER}/${MOD_ECHO}/commits/${DE}")"
if [ "$n" = "0" ] && [ -z "$a_nu2" ] && [ "$a_pb2" = "0" ]; then pass; else
  fail "B push rows for A=${n}; A rows for the peer writes: nuget=${a_nu2:-none} protobuf=${a_pb2} (want 0, none, 0)" \
       "$(psql_b "SELECT a.path || ' ' || st.status FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id WHERE st.peer_instance_id = '${PEER_A_ON_B}'")"
fi

begin_test "CONTROL: A's push rows for B end completed, one per artifact"
rows="$(psql_a "SELECT count(*) FILTER (WHERE status = 'completed') || '/' || count(*) || '/' || count(DISTINCT artifact_id) FROM sync_tasks \
                WHERE peer_instance_id = '${PEER_B_ON_A}' AND task_type = 'push'")"
IFS=/ read -r done_n all_n dist_n <<<"$rows"
if [ -n "$all_n" ] && [ "$all_n" -ge 1 ] 2>/dev/null && [ "$done_n" = "$all_n" ] && [ "$dist_n" = "$all_n" ]; then pass; else
  fail "A push rows for B completed/total/distinct artifacts=${rows} (want every row completed, one per artifact: the package and, once #4889 is in, the _labels index)" \
       "$(psql_a "SELECT a.path || ' ' || st.status || ' ' || coalesce(st.error_message,'') FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id WHERE st.peer_instance_id = '${PEER_B_ON_A}'")"
fi

# =============================================================================
# #4921: a protobuf commit uploaded after B subscribed reaches B
# =============================================================================
# Before #4921 the commit row's checksum_sha256 was the commit digest (sha256
# over each file's path and content), not the sha256 of the stored bundle, so
# B's chunked-upload complete refused every commit push with "checksum
# mismatch" and the commit never landed. These gates run last: on an image
# without the fix the failed push also backs the whole peer off.
C3_TEXT="syntax = \"proto3\"; // dtf c3 ${SUFN}"
c="$(rpc "$A" "$R_PB" "$UPLOAD" "$(upload_body "$MOD" "$C3_TEXT" pin)")"
D3="$(jq -r '.commits[0].digest.value // empty' < "$W/last" 2>/dev/null)"
C3_PATH="modules/${OWNER}/${MOD}/commits/${D3}"
begin_test "FIX(#4921): a commit uploaded to A after B subscribed is pushed: A's push row completes and B holds the commit with A's sha256, which is the sha256 of the bundle A serves"
st_c3="$(wait_push_a "$R_PB" "$C3_PATH" "completed|1" 60)"
a_c3="$(sha_of a "$R_PB" "$C3_PATH")"
wait_sha_b "$R_PB" "$C3_PATH" "$a_c3" 20
b_c3="$(sha_of b "$R_PB" "$C3_PATH")"; b_c3n="$(rows_of b "$R_PB" "$C3_PATH")"
a_served="$(curl -s -o "$W/c3a" -w '%{http_code}' --max-time 60 -u "$AUTH" \
  "${A}/api/v1/repositories/${R_PB}/download/${C3_PATH}" 2>/dev/null || echo 000):$(sha "$W/c3a")"
err="$(psql_a "SELECT st.status || ' ' || coalesce(st.error_message,'') FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id \
               WHERE st.peer_instance_id = '${PEER_B_ON_A}' AND a.path = '${C3_PATH}'")"
echo "   Upload 3 on A -> ${c} (${D3}); A push row ${st_c3} '${err}'; sha A ${a_c3} B ${b_c3:-none} (rows ${b_c3n}); A serves ${a_served}"
if [ "$c" = "200" ] && [ -n "$D3" ] && [ "$st_c3" = "completed|1" ] && [ "$b_c3n" = "1" ] \
   && [ -n "$a_c3" ] && [ "$b_c3" = "$a_c3" ] && [ "$a_served" = "200:${a_c3}" ]; then
  pass
else
  fail "Upload ${c}; A commit push row ${st_c3} '${err:-none}' (want completed|1); B rows ${b_c3n} sha '${b_c3:-none}' (want 1, A's '${a_c3}'); A serves ${a_served} (want 200:${a_c3})"
fi

begin_test "FIX(#4921): B serves that commit to buf: the pin label resolves to it and a Download on B by commit id returns the uploaded file"
b_pin="$(wait_label_b pin "$D3" 30)"
dl="$(rpc "$B" "$R_PB" "buf.registry.module.v1beta1.DownloadService/Download" \
  "$(jq -nc --arg o "$OWNER" --arg m "$MOD" --arg d "$D3" '{values:[{resourceRef:{owner:$o,module:$m,id:$d}}]}')")"
dl_text="$(jq -r '.contents[0].files[0].content // empty' < "$W/last" 2>/dev/null | base64 -d 2>/dev/null)"
dl_id="$(jq -r '.contents[0].commit.digest.value // empty' < "$W/last" 2>/dev/null)"
echo "   B pin -> '${b_pin}'; B Download -> ${dl}, commit '${dl_id}', file '${dl_text}'"
if [ "$b_pin" = "$D3" ] && [ "$dl" = "200" ] && [ "$dl_id" = "$D3" ] && [ "$dl_text" = "$C3_TEXT" ]; then
  pass
else
  fail "B pin -> '${b_pin}' (want ${D3}); B Download -> ${dl} commit '${dl_id}' file '${dl_text}' (want 200, ${D3}, '${C3_TEXT}'): $(head -c 200 "$W/last")"
fi

end_suite
