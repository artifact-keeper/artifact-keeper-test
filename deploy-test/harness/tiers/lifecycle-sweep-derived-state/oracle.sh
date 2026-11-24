#!/usr/bin/env bash
# =============================================================================
# tiers/lifecycle-sweep-derived-state/oracle.sh: a lifecycle sweep updates
# each format's derived state the way a single delete does (artifact-keeper
# #6469, the #6333 audit). See the manifest for the bug and the gates.
#
# run.sh exports BASE_URL, DB_CONTAINER, ADMIN_PASS, DTF_SLOT, RUN_ID,
# TRIVY_PORT, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
SFX="${SFX//[^a-zA-Z0-9]/}"
MOCK_IN="http://172.16.${DTF_SLOT}.78"
OS_CTR="ak-dtf${DTF_SLOT}-mock-opensearch"
setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

req(){
  local m="$1" p="$2" d="${3:-}"
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$m" -H "Authorization: Bearer ${TOK}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}${p}" 2>/dev/null)"; [ -n "$CODE" ] || CODE=000
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
put_bytes(){ # <path> <body> -> CODE
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
    --data-binary "$2" "${BASE}$1")"
}
get_body(){ curl -s --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}$1"; }
mkrepo(){ # <key> <format> [repo_type] -> id
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "${3:-local}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:true}')"
  jqr '.id // empty' <<<"$BODY"
}
# sweep <repo id> <label>: a max_age_days 30 policy on that repository, run
# once; sets REMOVED and EX_CODE.
sweep(){
  req POST /api/v1/admin/lifecycle "$(jq -nc --arg n "lsd-$2-${SFX}" --arg r "$1" \
    '{name:$n,policy_type:"max_age_days",config:{days:30},repository_ids:[$r],enabled:true}')"
  local id; id="$(jqr '.id // empty' <<<"$BODY")"
  req POST "/api/v1/admin/lifecycle/${id}/execute"
  EX_CODE="$CODE"; REMOVED="$(jqr '.artifacts_removed // empty' <<<"$BODY")"
  note "policy ${id:-none}: execute ${EX_CODE} removed=${REMOVED}"
  req DELETE "/api/v1/admin/lifecycle/${id}"
}
age(){ # <repo id> <path LIKE> -> rows aged
  psql_q "WITH u AS (UPDATE artifacts SET created_at = NOW() - INTERVAL '60 days' WHERE repository_id = '$1' AND path LIKE '$2' AND is_deleted = false RETURNING 1) SELECT count(*) FROM u"
}
id_of(){ psql_q "SELECT id FROM artifacts WHERE repository_id = '$1' AND path = '$2'"; }

begin_suite "lifecycle-sweep-derived-state"

begin_test "setup: admin login, repositories, peer, webhook"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
[ -n "$TOK" ] || { infra_fail "admin login failed at $BASE"; end_suite; exit 1; }
M="lsdm${SFX}"; C="lsdc${SFX}"; CV="lsdcv${SFX}"; G="lsdg${SFX}"
M_ID="$(mkrepo "$M" maven)"; C_ID="$(mkrepo "$C" cargo)"; G_ID="$(mkrepo "$G" generic)"
CV_ID="$(mkrepo "$CV" cargo virtual)"
req POST "/api/v1/repositories/${CV}/members" "$(jq -nc --arg k "$C" '{member_key:$k,priority:1}')"
MEM_CODE="$CODE"
PEER_ID="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "INSERT INTO peer_instances (name, endpoint_url, region, cache_size_bytes, api_key) \
   VALUES ('lsd-peer-${SFX}', 'http://127.0.0.1:9', 'dtf', 1024, 'k') RETURNING id" 2>/dev/null | head -n1 | tr -d '[:space:]')"
SUB="$(psql_q "WITH i AS (INSERT INTO peer_repo_subscriptions (peer_instance_id, repository_id, sync_enabled, replication_mode) VALUES ('${PEER_ID}', '${G_ID}', true, 'push') RETURNING 1) SELECT count(*) FROM i")"
req POST /api/v1/webhooks "$(jq -nc --arg u "${MOCK_IN}/hook/lsd-${SFX}" --arg r "$G_ID" \
  '{name:"lsd-deleted",url:$u,events:["artifact_deleted"],repository_id:$r}')"
WH_CODE="$CODE"; WH_ID="$(jqr '.id // empty' <<<"$BODY")"
echo "-- maven ${M_ID:-?} cargo ${C_ID:-?} virtual ${CV_ID:-?} (member ${MEM_CODE}) generic ${G_ID:-?} peer ${PEER_ID:-?} (sub ${SUB}) webhook ${WH_ID:-?} (${WH_CODE})"
if [ -z "$M_ID" ] || [ -z "$C_ID" ] || [ -z "$CV_ID" ] || [ -z "$G_ID" ] || [ -z "$PEER_ID" ] || [ "$SUB" != "1" ] || [ -z "$WH_ID" ] || ! is_2xx "$MEM_CODE"; then
  infra_fail "setup incomplete"; end_suite; exit 1
fi
docker exec "$OS_CTR" true >/dev/null 2>&1 || { infra_fail "mock OpenSearch container ${OS_CTR} not found (profile search.mock-opensearch)"; end_suite; exit 1; }
pass

# =============================================================================
# Maven: stored maven-metadata.xml (GA and SNAPSHOT level)
# =============================================================================
GP="com/example/lsd${SFX}"; GID="com.example.lsd${SFX}"; A="demo"
pom(){ printf '<project><modelVersion>4.0.0</modelVersion><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></project>' "$GID" "$A" "$1"; }
for V in 1.0.0 2.0.0; do
  put_bytes "/maven/${M}/${GP}/${A}/${V}/${A}-${V}.pom" "$(pom "$V")"; echo "   PUT ${V} pom: ${CODE}"
  put_bytes "/maven/${M}/${GP}/${A}/${V}/${A}-${V}.jar" "jar-${V}"; echo "   PUT ${V} jar: ${CODE}"
done
SV="3.0-SNAPSHOT"; B1="3.0-20260101.110000-1"; B2="3.0-20260101.120000-2"
for B in "$B1" "$B2"; do
  put_bytes "/maven/${M}/${GP}/${A}/${SV}/${A}-${B}.pom" "$(pom "$SV")"; echo "   PUT ${B} pom: ${CODE}"
  put_bytes "/maven/${M}/${GP}/${A}/${SV}/${A}-${B}.jar" "jar-${B}"; echo "   PUT ${B} jar: ${CODE}"
done
put_bytes "/maven/${M}/${GP}/${A}/maven-metadata.xml" "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata><groupId>${GID}</groupId><artifactId>${A}</artifactId><versioning><latest>2.0.0</latest><release>2.0.0</release><versions><version>1.0.0</version><version>2.0.0</version><version>${SV}</version></versions><lastUpdated>20260101120000</lastUpdated></versioning></metadata>"
GA_PUT="$CODE"
put_bytes "/maven/${M}/${GP}/${A}/${SV}/maven-metadata.xml" "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata><groupId>${GID}</groupId><artifactId>${A}</artifactId><version>${SV}</version><versioning><snapshot><timestamp>20260101.120000</timestamp><buildNumber>2</buildNumber></snapshot><lastUpdated>20260101120000</lastUpdated><snapshotVersions><snapshotVersion><extension>jar</extension><value>${B2}</value><updated>20260101120000</updated></snapshotVersion><snapshotVersion><extension>pom</extension><value>${B2}</value><updated>20260101120000</updated></snapshotVersion></snapshotVersions></versioning></metadata>"
SV_PUT="$CODE"
GA_BEFORE="$(get_body "/maven/${M}/${GP}/${A}/maven-metadata.xml")"
SV_BEFORE="$(get_body "/maven/${M}/${GP}/${A}/${SV}/maven-metadata.xml")"
AGED_M=$(( $(age "$M_ID" "${GP}/${A}/2.0.0/%") + $(age "$M_ID" "${GP}/${A}/${SV}/${A}-${B2}.%") ))
sweep "$M_ID" maven; M_REMOVED="$REMOVED"; M_EX="$EX_CODE"
GA_AFTER="$(get_body "/maven/${M}/${GP}/${A}/maven-metadata.xml")"
SV_AFTER="$(get_body "/maven/${M}/${GP}/${A}/${SV}/maven-metadata.xml")"

begin_test "CONTROL: the stored Maven documents are served, and the sweep removes exactly the four aged files"
reset_case
note "PUT GA doc ${GA_PUT}, SNAPSHOT doc ${SV_PUT}; aged ${AGED_M}; execute ${M_EX} removed ${M_REMOVED}"
{ [ "$GA_PUT" = 201 ] && [ "$SV_PUT" = 201 ]; } || fail_g "stored metadata PUT answered ${GA_PUT}/${SV_PUT}"
grep -q "<release>2.0.0</release>" <<<"$GA_BEFORE" || fail_g "the GA document before the sweep is not the stored one: ${GA_BEFORE:0:300}"
grep -q "<value>${B2}</value>" <<<"$SV_BEFORE" || fail_g "the SNAPSHOT document before the sweep does not name ${B2}: ${SV_BEFORE:0:300}"
[ "$AGED_M" = 4 ] || fail_g "aging touched ${AGED_M} rows, want 4"
{ is_2xx "$M_EX" && [ "$M_REMOVED" = 4 ]; } || fail_g "the sweep answered ${M_EX}, removed '${M_REMOVED}' (want 4)"
finish_case "the Maven fixture or sweep is not as expected"

begin_test "FIX #6469: after the sweep, the GA maven-metadata.xml no longer lists the swept 2.0.0 and <release> is 1.0.0"
reset_case
note "GA document after: $(tr -d '\n' <<<"$GA_AFTER" | head -c 400)"
grep -q "<version>2.0.0</version>" <<<"$GA_AFTER" && fail_g "the swept 2.0.0 is still listed (the stored document was not cleared)"
grep -q "<release>2.0.0</release>" <<<"$GA_AFTER" && fail_g "<release> still names the swept 2.0.0"
grep -q "<version>1.0.0</version>" <<<"$GA_AFTER" || fail_g "the surviving 1.0.0 is not listed"
grep -q "<release>1.0.0</release>" <<<"$GA_AFTER" || fail_g "<release> is not the surviving 1.0.0"
finish_case "a sweep leaves the stored GA maven-metadata.xml advertising a removed version"

begin_test "FIX #6469: after the sweep, the SNAPSHOT maven-metadata.xml no longer names the swept build ${B2}"
reset_case
note "SNAPSHOT document after: $(tr -d '\n' <<<"$SV_AFTER" | head -c 400)"
grep -q "${B2}" <<<"$SV_AFTER" && fail_g "the swept build ${B2} is still named (the stored document was not cleared)"
grep -q "${B1}" <<<"$SV_AFTER" || fail_g "the surviving build ${B1} is not named"
finish_case "a sweep leaves the stored SNAPSHOT maven-metadata.xml naming a removed build"

# =============================================================================
# Cargo: the cached sparse-index file (Local and Virtual), sweep and REST delete
# =============================================================================
CR="lsdcrate"; IDX="ls/dc/${CR}"
publish_crate(){ # <version> -> CODE
  local v="$1" d="$W/c/${CR}-$1"
  mkdir -p "$d/src"; printf '[package]\nname = "%s"\nversion = "%s"\n' "$CR" "$v" >"$d/Cargo.toml"; : >"$d/src/lib.rs"
  tar -czf "$W/${CR}-$v.crate" -C "$W/c" "${CR}-$v"
  python3 -I - "$W/${CR}-$v.crate" "$W/${CR}-$v.pay" "$CR" "$v" <<'PY'
import json, struct, sys
m = json.dumps({"name": sys.argv[3], "vers": sys.argv[4], "deps": [], "features": {},
                "authors": ["dtf"], "description": "d", "license": "MIT"}).encode()
c = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(struct.pack("<I", len(m)) + m + struct.pack("<I", len(c)) + c)
PY
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
    --data-binary "@$W/${CR}-$v.pay" "${BASE}/cargo/${C}/api/v1/crates/new")"
}
vers_of(){ get_body "/cargo/$1/${IDX}" | jq -r '.vers' 2>/dev/null | sort -V | tr '\n' ' ' | sed 's/ $//'; }
for v in 0.1.0 0.2.0; do publish_crate "$v"; echo "   publish ${CR} ${v}: ${CODE}"; done
L_BEFORE="$(vers_of "$C")"; V_BEFORE="$(vers_of "$CV")"     # warms both caches
AGED_C="$(age "$C_ID" "${CR}/0.2.0/%")"
sweep "$C_ID" cargo; C_REMOVED="$REMOVED"; C_EX="$EX_CODE"
L_AFTER="$(vers_of "$C")"; V_AFTER="$(vers_of "$CV")"
publish_crate 0.3.0; P3="$CODE"
L_PRE_DEL="$(vers_of "$C")"; V_PRE_DEL="$(vers_of "$CV")"
DEL3="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer ${TOK}" \
  "${BASE}/api/v1/repositories/${C}/artifacts/${CR}/0.3.0/${CR}-0.3.0.crate")"
L_DEL="$(vers_of "$C")"; V_DEL="$(vers_of "$CV")"

begin_test "CONTROL: the Cargo index lists both versions before the sweep, and the sweep removes the aged one"
reset_case
note "index before: local [${L_BEFORE}] virtual [${V_BEFORE}]; aged ${AGED_C}; execute ${C_EX} removed ${C_REMOVED}"
[ "$L_BEFORE" = "0.1.0 0.2.0" ] || fail_g "local index before is [${L_BEFORE}]"
[ "$V_BEFORE" = "0.1.0 0.2.0" ] || fail_g "virtual index before is [${V_BEFORE}]"
{ [ "$AGED_C" = 1 ] && is_2xx "$C_EX" && [ "$C_REMOVED" = 1 ]; } || fail_g "aged ${AGED_C}, sweep ${C_EX} removed '${C_REMOVED}' (want 1/1)"
finish_case "the Cargo fixture or sweep is not as expected"

begin_test "FIX #6469: after the sweep, the cached sparse index stops listing the swept 0.2.0, on the Local and the Virtual"
reset_case
note "index after the sweep: local [${L_AFTER}] virtual [${V_AFTER}]"
[ "$L_AFTER" = "0.1.0" ] || fail_g "the local index is [${L_AFTER}], want [0.1.0] (cached entry not dropped)"
[ "$V_AFTER" = "0.1.0" ] || fail_g "the virtual index is [${V_AFTER}], want [0.1.0] (cached entry not dropped)"
finish_case "a sweep leaves the Cargo sparse index listing a removed version"

begin_test "FIX #6469: after a REST delete, the cached sparse index stops listing the deleted 0.3.0"
reset_case
note "publish 0.3.0 ${P3}; before delete local [${L_PRE_DEL}] virtual [${V_PRE_DEL}]; DELETE ${DEL3}; after local [${L_DEL}] virtual [${V_DEL}]"
{ is_2xx "$P3" && [ "$L_PRE_DEL" = "0.1.0 0.3.0" ] && [ "$V_PRE_DEL" = "0.1.0 0.3.0" ]; } || fail_g "0.3.0 was not published and indexed"
is_2xx "$DEL3" || fail_g "the REST delete answered ${DEL3}"
[ "$L_DEL" = "0.1.0" ] || fail_g "the local index is [${L_DEL}], want [0.1.0]"
[ "$V_DEL" = "0.1.0" ] || fail_g "the virtual index is [${V_DEL}], want [0.1.0]"
finish_case "a REST delete leaves the Cargo sparse index listing a removed version"

# =============================================================================
# generic: peers, audit, artifact.deleted, search documents
# =============================================================================
for p in g/1.0/g.bin g/2.0/g.bin g/3.0/g.bin; do
  put_bytes "/api/v1/repositories/${G}/artifacts/${p}" "bytes-${p}"; echo "   PUT ${p}: ${CODE}"
done
SWEPT="$(id_of "$G_ID" g/1.0/g.bin)"; LIVE="$(id_of "$G_ID" g/2.0/g.bin)"; RESTD="$(id_of "$G_ID" g/3.0/g.bin)"
AGED_G="$(age "$G_ID" "g/1.0/%")"
sweep "$G_ID" generic; G_REMOVED="$REMOVED"; G_EX="$EX_CODE"
RDEL="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer ${TOK}" \
  "${BASE}/api/v1/repositories/${G}/artifacts/g/3.0/g.bin")"
tasks_for(){ psql_q "SELECT count(*) FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' AND task_type = 'delete' AND artifact_id = '$1'"; }
audit_for(){ psql_q "SELECT count(*) FROM audit_log WHERE action = 'ARTIFACT_DELETED' AND resource_id = '$1'"; }
hooks_for(){ psql_q "SELECT count(*) FROM webhook_deliveries WHERE webhook_id = '${WH_ID}' AND event = 'artifact_deleted' AND payload->>'entity_id' = '$1'"; }
search_for(){ # <id> -> "<bulk deletes> <single DELETEs>"
  local log; log="$(docker exec "$OS_CTR" cat /tmp/os/requests.log 2>/dev/null)"
  echo "$(grep -c "^BULK delete .* $1\$" <<<"$log") $(grep -c "^DELETE /.*/_doc/$1 " <<<"$log")"
}
# The webhook producer and the audit write are asynchronous: wait for the
# REST delete's (the control) and give the sweep's the same time.
for _ in $(seq 1 30); do
  [ "$(hooks_for "$RESTD")" -ge 1 ] 2>/dev/null && [ "$(audit_for "$RESTD")" -ge 1 ] 2>/dev/null && break; sleep 1
done
sleep 2
read -r S_BULK S_ONE <<<"$(search_for "$SWEPT")"; read -r L_BULK L_ONE <<<"$(search_for "$LIVE")"; read -r R_BULK R_ONE <<<"$(search_for "$RESTD")"

begin_test "CONTROL: the sweep removes the aged artifact only; a REST delete is observed by every probe (delete task, audit, webhook, search DELETE)"
reset_case
note "ids: swept ${SWEPT} live ${LIVE} rest-deleted ${RESTD}; aged ${AGED_G}; execute ${G_EX} removed ${G_REMOVED}; REST DELETE ${RDEL}"
note "rest-deleted: task $(tasks_for "$RESTD") audit $(audit_for "$RESTD") webhook $(hooks_for "$RESTD") search bulk ${R_BULK} single ${R_ONE}"
{ [ "$AGED_G" = 1 ] && is_2xx "$G_EX" && [ "$G_REMOVED" = 1 ]; } || fail_g "aged ${AGED_G}, sweep ${G_EX} removed '${G_REMOVED}' (want 1/1)"
is_2xx "$RDEL" || fail_g "the REST delete answered ${RDEL}"
[ "$(tasks_for "$RESTD")" = 1 ] || fail_g "the REST delete enqueued no delete task"
[ "$(audit_for "$RESTD")" = 1 ] || fail_g "the REST delete wrote no audit row"
[ "$(hooks_for "$RESTD")" -ge 1 ] 2>/dev/null || fail_g "the REST delete produced no artifact_deleted delivery"
[ "$((R_BULK + R_ONE))" -ge 1 ] || fail_g "the REST delete sent no search delete"
finish_case "the generic fixture, sweep or probes are not as expected"

begin_test "CONTROL: the surviving artifact gets no delete task, audit row, webhook delivery or search delete"
reset_case
note "live: task $(tasks_for "$LIVE") audit $(audit_for "$LIVE") webhook $(hooks_for "$LIVE") search ${L_BULK}/${L_ONE}"
[ "$(tasks_for "$LIVE")$(audit_for "$LIVE")$(hooks_for "$LIVE")${L_BULK}${L_ONE}" = "00000" ] || fail_g "the surviving artifact was treated as deleted"
finish_case "the sweep touched the derived state of a live artifact"

begin_test "FIX #6469: the sweep enqueues a delete sync task for the push peer"
reset_case
note "swept: delete tasks $(tasks_for "$SWEPT")"
[ "$(tasks_for "$SWEPT")" = 1 ] || fail_g "no delete task for the swept artifact; the peer keeps advertising it"
finish_case "a sweep does not tell peers to delete"

begin_test "FIX #6469: the sweep writes an ARTIFACT_DELETED audit row"
reset_case
note "swept: audit rows $(audit_for "$SWEPT")"
[ "$(audit_for "$SWEPT")" = 1 ] || fail_g "no audit row for the swept artifact"
finish_case "a sweep leaves no audit trail"

begin_test "FIX #6469: the sweep emits artifact.deleted (a webhook delivery for the swept artifact)"
reset_case
note "swept: deliveries $(hooks_for "$SWEPT")"
[ "$(hooks_for "$SWEPT")" -ge 1 ] 2>/dev/null || fail_g "no artifact_deleted delivery for the swept artifact"
finish_case "a sweep emits no artifact.deleted"

begin_test "FIX #6469: the sweep removes the swept document from the search index (one _bulk delete)"
reset_case
note "swept: bulk deletes ${S_BULK}, single DELETEs ${S_ONE}"
[ "$((S_BULK + S_ONE))" -ge 1 ] || fail_g "the swept artifact's search document was never deleted"
finish_case "a sweep leaves swept artifacts in the search index"

end_suite
