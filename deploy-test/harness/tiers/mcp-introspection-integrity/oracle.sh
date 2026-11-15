#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/mcp-introspection-integrity/oracle.sh
#   MCP introspection completion integrity of 1.12.0: one winner per claim
#   (#5461), lease expiry at completion (#5462), freshness-ordered current
#   selection (#5464) and result metadata validation (#5466). The oracle acts
#   as the introspection worker. See the manifest.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, DB_CONTAINER,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
: "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SFX="$(printf '%s' "${DTF_SLOT}-${RUN_ID##*-}-$$" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
iso(){ date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

login(){ curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" | jqr '.access_token // empty'; }

# api METHOD PATH [JSON] [TOKEN]: admin (or TOKEN) request; sets CODE, R (file).
R="${W}/resp.json"
api(){
  local tok="${4:-$TOK}"
  : >"$R"
  if [ -n "${3:-}" ]; then
    CODE="$(curl -s -o "$R" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${tok}" \
      -H 'Content-Type: application/json' -d "$3" "${BASE}$2")"
  else
    CODE="$(curl -s -o "$R" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${tok}" "${BASE}$2")"
  fi
}

begin_suite "mcp-introspection-integrity"

begin_test "setup: admin session, an mcp repository probing hosted remotes and an mcp:introspect worker token"
TOK="$(login admin "$ADMIN_PASS")"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(psql_q 'SELECT 1')" = "1" ] || { infra_fail "no psql in ${DBC}"; end_suite; }
REPO="l6-mii-${SFX}"
api POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"mcp",repo_type:"local",is_public:true}')"
case "$CODE" in 2??) ;; *) infra_fail "creating the mcp repository answered ${CODE}" "$(head -c 300 "$R")"; end_suite ;; esac
add_exit_handler "curl -s -o /dev/null --max-time 30 -X DELETE -H 'Authorization: Bearer ${TOK}' '${BASE}/api/v1/repositories/${REPO}' || true"
api PATCH "/api/v1/repositories/${REPO}" '{"mcp_probe_remotes":"hosted_only"}'
[ "$(jqr '.mcp_probe_remotes // empty' "$R")" = "hosted_only" ] \
  || { infra_fail "PATCH mcp_probe_remotes=hosted_only answered ${CODE}" "$(head -c 300 "$R")"; end_suite; }
api POST /api/v1/service-accounts "$(jq -nc --arg n "l6mii${SFX//-/}" '{name:$n}')"
SA="$(jqr '.id // empty' "$R")"
[ -n "$SA" ] || { infra_fail "creating the service account answered ${CODE}" "$(head -c 300 "$R")"; end_suite; }
add_exit_handler "curl -s -o /dev/null --max-time 30 -X DELETE -H 'Authorization: Bearer ${TOK}' '${BASE}/api/v1/service-accounts/${SA}' || true"
api POST "/api/v1/service-accounts/${SA}/tokens" "$(jq -nc --arg n "l6-mii-worker-${SFX}" '{name:$n,scopes:["mcp:introspect"]}')"
WTOK="$(jqr '.token // empty' "$R")"
[ -n "$WTOK" ] || { infra_fail "minting the mcp:introspect token answered ${CODE}" "$(head -c 300 "$R")"; end_suite; }
echo "-- repository ${REPO}, worker service account ${SA}"
pass

NS="io.github.ak-dtf"

# publish SLUG VERSION: publish a server version with one streamable-http
# remote; mcp_probe_remotes=hosted_only queues its remote_probe job.
publish(){
  jq -nc --arg n "${NS}/$1-${SFX}" --arg v "$2" \
    '{"$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
      name:$n, description:"DTF introspection fixture", version:$v,
      remotes:[{type:"streamable-http", url:"https://mcp.example.invalid/mcp"}]}' > "${W}/srv.json"
  CODE="$(curl -s -o "$R" -w '%{http_code}' --max-time 30 -X POST -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' --data-binary "@${W}/srv.json" "${BASE}/mcp/${REPO}/v0.1/publish")"
  [ "$CODE" = "200" ] || fail_g "publishing $1@$2 answered ${CODE}: $(head -c 200 "$R")"
}

vpath(){ printf '/mcp/%s/v0.1/servers/%s%%2F%s-%s/versions/%s' "$REPO" "$NS" "$1" "$SFX" "$2"; }

# probe SLUG VERSION: queue another remote_probe job (POST .../capabilities/probe).
probe(){
  api POST "$(vpath "$1" "$2")/capabilities/probe"
  [ "$CODE" = "202" ] || fail_g "capabilities/probe of $1@$2 answered ${CODE}: $(head -c 200 "$R")"
}

# claim SLUG VERSION: claim the due job of that version; sets JOB, CTOK.
# A due job of another version (none is expected) is kept claimed and skipped.
claim(){
  local i want="${NS}/$1-${SFX}|$2"
  JOB=""; CTOK=""
  for i in 1 2 3 4 5; do
    api POST /api/v1/mcp/introspection/jobs/claim '{"kinds":["remote_probe"],"workerId":"l6-dtf"}' "$WTOK"
    if [ "$CODE" != "200" ]; then
      fail_g "claim for $1@$2 answered ${CODE}: $(head -c 200 "$R")"; return 1
    fi
    if [ "$(jqr '"\(.server.name)|\(.server.version)"' "$R")" = "$want" ]; then
      JOB="$(jqr '.jobId' "$R")"; CTOK="$(jqr '.claimToken' "$R")"; return 0
    fi
    note "claim ${i} handed out $(jqr '"\(.server.name)@\(.server.version)"' "$R"), not $1@$2"
  done
  fail_g "no claim of $1@$2 within 5 claims"; return 1
}

# result OUTCOME [EXTRA_JSON] [TOOL]: a worker result body for $CTOK.
result(){
  local extra="${2:-}"; [ -n "$extra" ] || extra='{}'
  if [ "$1" = "ok" ]; then
    jq -nc --arg c "$CTOK" --arg t "${3:-tool}" --argjson x "$extra" \
      '{claimToken:$c, outcome:"ok", authState:"none", protocolVersion:"2025-06-18",
        tools:[{name:$t, description:"DTF tool", inputSchema:{type:"object"}}],
        resources:[], prompts:[], instructions:null, workerVersion:"l6-dtf-worker/1"} + $x'
  else
    jq -nc --arg c "$CTOK" --arg o "$1" --argjson x "$extra" \
      '{claimToken:$c, outcome:$o, error:"DTF synthetic \($o)", workerVersion:"l6-dtf-worker/1"} + $x'
  fi
}

# complete BODY [OUT]: POST /jobs/$JOB/complete; sets CODE (and OUT file).
complete(){
  local out="${2:-$R}"
  CODE="$(curl -s -o "$out" -w '%{http_code}' --max-time 60 -X POST -H "Authorization: Bearer ${WTOK}" \
    -H 'Content-Type: application/json' -d "$1" "${BASE}/api/v1/mcp/introspection/jobs/${JOB}/complete")"
}

# caps SLUG VERSION: read capabilities into ${W}/caps.json; sets CUR (current
# tool name or "-"), NSNAP (remote_probe snapshots), NOK (ok ones), JST (job
# $JOB status).
caps(){
  curl -s -o "${W}/caps.json" --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}$(vpath "$1" "$2")/capabilities"
  CUR="$(jqr '.current.tools[0].name // "-"' "${W}/caps.json")"
  NSNAP="$(jqr '[.snapshots[]? | select(.source == "remote_probe")] | length' "${W}/caps.json")"
  NOK="$(jqr '[.snapshots[]? | select(.source == "remote_probe" and .outcome == "ok")] | length' "${W}/caps.json")"
  JST="$(jqr --arg j "$JOB" '[.introspection.jobs[]? | select(.id == $j) | .status][0] // "-"' "${W}/caps.json")"
}

# The row lock: a psql session in the DB container takes job $JOB's row FOR
# NO KEY UPDATE and sleeps, so completions sent meanwhile queue on the row (or,
# before the fix, on the claim update). release_row cancels the sleep, which
# aborts that transaction and lets the queue go. HOLD_SQL marks the session.
HOLD_SQL="FOR NO KEY UPDATE; SELECT pg_sleep"

# hold_row: start the holder in the background (the caller's `wait` reaps
# it) and return once it holds the row (it is sleeping), at most 30 s.
hold_row(){
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "BEGIN; SELECT 1 FROM mcp_introspection_jobs WHERE id = '${JOB}' ${HOLD_SQL}(60); COMMIT;" \
    >/dev/null 2>&1 &
  local end=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$end" ]; do
    [ "$(psql_q "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'PgSleep' AND query LIKE '%${HOLD_SQL}%' AND pid <> pg_backend_pid()")" = "1" ] && return 0
    sleep 0.2
  done
  fail_g "the row lock holder did not start within 30 s"
}

# release_row: cancel the holder's sleep; its transaction aborts.
release_row(){
  psql_q "SELECT count(pg_cancel_backend(pid)) FROM pg_stat_activity WHERE datname = current_database() AND query LIKE '%${HOLD_SQL}%' AND pid <> pg_backend_pid()" >/dev/null
}

# wait_waiters N: poll until N backends wait on a lock, at most 30 s.
wait_waiters(){
  local n=0 end=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$end" ]; do
    n="$(psql_q "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'")"
    [ "${n:-0}" -ge "$1" ] 2>/dev/null && break
    sleep 0.2
  done
  note "${n:-0} completion(s) queued on the held job row"
  [ "${n:-0}" -ge "$1" ] 2>/dev/null || fail_g "only ${n:-0} of $1 completion(s) queued on the held job row within 30 s: the race was not set up"
}

# =============================================================================
# Controls
# =============================================================================
begin_test "CONTROL: a live claim's ok result is stored and current; a sequential replay answers 409 mcp_claim_invalid"
reset_case
publish ctl 1.0.0
if claim ctl 1.0.0; then
  complete "$(result ok '{"ttlMs":2592000000,"cacheScope":"public"}' ctl_tool)"
  note "complete: ${CODE} $(jqr -c '{status,error}' "$R")"
  { [ "$CODE" = "200" ] && [ "$(jqr '.status' "$R")" = "stored" ]; } || fail_g "a live claim's ok result answered ${CODE}: $(head -c 200 "$R")"
  complete "$(result ok '{}' ctl_replay)"
  note "replay: ${CODE} $(jqr '.error // empty' "$R")"
  { [ "$CODE" = "409" ] && [ "$(jqr '.error' "$R")" = "mcp_claim_invalid" ]; } || fail_g "a replay of a completed claim answered ${CODE} $(head -c 200 "$R"), expected 409 mcp_claim_invalid"
  caps ctl 1.0.0
  note "capabilities: current=${CUR} remote_probe snapshots=${NSNAP} job=${JST} ttlMs=$(jqr '.current.ttlMs' "${W}/caps.json") cacheScope=$(jqr '.current.cacheScope' "${W}/caps.json")"
  [ "$CUR" = "ctl_tool" ] || fail_g "current tool is ${CUR}, expected ctl_tool"
  [ "$NSNAP" = "1" ] || fail_g "${NSNAP} remote_probe snapshots, expected 1"
  [ "$JST" = "completed" ] || fail_g "job status ${JST}, expected completed"
fi
finish_case "introspection completion baseline is broken"

begin_test "CONTROL: a timeout result on attempt 1 answers retry and the job goes back to pending with no snapshot"
reset_case
publish retry 1.0.0
if claim retry 1.0.0; then
  complete "$(result timeout)"
  note "complete timeout: ${CODE} $(jqr -c '{status,notBefore,error}' "$R")"
  { [ "$CODE" = "200" ] && [ "$(jqr '.status' "$R")" = "retry" ]; } || fail_g "a timeout on attempt 1 answered ${CODE}: $(head -c 200 "$R"), expected 200 retry"
  caps retry 1.0.0
  note "capabilities: current=${CUR} remote_probe snapshots=${NSNAP} job=${JST}"
  [ "$JST" = "pending" ] || fail_g "job status ${JST}, expected pending"
  [ "$NSNAP" = "0" ] || fail_g "${NSNAP} remote_probe snapshots after a retry, expected 0"
fi
finish_case "introspection retry baseline is broken"

begin_test "CONTROL: a fresher observation replaces an older current one"
reset_case
publish fresh 1.0.0
if claim fresh 1.0.0; then
  complete "$(result ok "$(jq -nc --arg o "$(iso '-30 seconds')" '{observedAt:$o}')" first_tool)"
  note "first (observed 30 s ago): ${CODE} $(jqr -c '{status,error}' "$R")"
  [ "$CODE" = "200" ] || fail_g "the first result answered ${CODE}: $(head -c 200 "$R")"
fi
probe fresh 1.0.0
if claim fresh 1.0.0; then
  complete "$(result ok '{"ttlMs":0,"cacheScope":"private"}' second_tool)"
  note "second (observed now, ttlMs 0, cacheScope private): ${CODE} $(jqr -c '{status,current,error}' "$R")"
  [ "$CODE" = "200" ] || fail_g "the second result answered ${CODE}: $(head -c 200 "$R")"
  caps fresh 1.0.0
  note "capabilities: current=${CUR} remote_probe snapshots=${NSNAP}"
  [ "$CUR" = "second_tool" ] || fail_g "current tool is ${CUR}, expected second_tool (the fresher observation)"
  [ "$NSNAP" = "2" ] || fail_g "${NSNAP} remote_probe snapshots, expected 2"
fi
finish_case "a fresher observation does not become current"

# =============================================================================
# #5461 one winner per claim
# =============================================================================
begin_test "FIX #5461: concurrent completions of one claim, and a retry racing an ok result, have exactly one winner"
reset_case
publish race 1.0.0
if claim race 1.0.0; then
  hold_row
  for i in 1 2 3 4; do
    complete "$(result ok '{}' "race_tool_${i}")" "${W}/race-${i}.json" &
  done
  wait_waiters 4
  release_row
  wait
  stored=0; lost=0
  for i in 1 2 3 4; do
    st="$(jqr '.status // empty' "${W}/race-${i}.json")"; er="$(jqr '.error // empty' "${W}/race-${i}.json")"
    note "completion ${i}: status=${st} error=${er}"
    [ "$st" = "stored" ] && stored=$((stored+1))
    [ "$er" = "mcp_claim_invalid" ] && lost=$((lost+1))
  done
  caps race 1.0.0
  note "capabilities: current=${CUR} remote_probe snapshots=${NSNAP} job=${JST}"
  [ "$stored" = "1" ] || fail_g "${stored} of 4 concurrent completions answered stored, expected exactly 1"
  [ "$lost" = "3" ] || fail_g "${lost} of 4 concurrent completions answered 409 mcp_claim_invalid, expected 3"
  [ "$NSNAP" = "1" ] || fail_g "${NSNAP} remote_probe snapshots after 4 concurrent completions of one claim, expected 1"
fi
publish race-retry 1.0.0
if claim race-retry 1.0.0; then
  hold_row
  complete "$(result timeout)" "${W}/rr-retry.json" &
  wait_waiters 1
  complete "$(result ok '{}' rr_tool)" "${W}/rr-ok.json" &
  wait_waiters 2
  release_row
  wait
  rs="$(jqr '.status // .error // empty' "${W}/rr-retry.json")"; os="$(jqr '.status // .error // empty' "${W}/rr-ok.json")"
  caps race-retry 1.0.0
  note "retry: ${rs}; ok: ${os}; job=${JST} ok snapshots=${NOK}"
  wins=0
  case "$rs" in retry) wins=$((wins+1)) ;; esac
  case "$os" in stored) wins=$((wins+1)) ;; esac
  [ "$wins" = "1" ] || fail_g "the retry answered '${rs}' and the ok result '${os}': ${wins} winners, expected exactly 1"
  if [ "$JST" = "pending" ] && [ "$NOK" != "0" ]; then
    fail_g "the job is pending with ${NOK} stored ok snapshot(s): a snapshot was left behind a pending job"
  fi
  if [ "$JST" = "completed" ] && [ "$NOK" != "1" ]; then
    fail_g "the job is completed with ${NOK} ok snapshots, expected 1"
  fi
fi
finish_case "introspection completion is not one-winner atomic"

# =============================================================================
# #5462 an expired lease cannot complete
# =============================================================================
begin_test "FIX #5462: a claim whose lease expired (reaper not yet run) answers 409 mcp_claim_invalid and stores nothing"
reset_case
publish lease 1.0.0
if claim lease 1.0.0; then
  moved="$(psql_q "UPDATE mcp_introspection_jobs SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = '${JOB}' AND status = 'claimed' RETURNING status")"
  case "$moved" in claimed*) ;; *) note "moving the lease answered '${moved}'" ;; esac
  complete "$(result ok '{}' expired_tool)"
  note "complete after lease expiry: ${CODE} $(jqr -c '{status,error}' "$R")"
  { [ "$CODE" = "409" ] && [ "$(jqr '.error' "$R")" = "mcp_claim_invalid" ]; } \
    || fail_g "an expired claim's result answered ${CODE} $(jqr 'if (.status|type) == "string" then .status else .error end' "$R"), expected 409 mcp_claim_invalid"
  caps lease 1.0.0
  note "capabilities: current=${CUR} remote_probe snapshots=${NSNAP} job=${JST}"
  [ "$NSNAP" = "0" ] || fail_g "${NSNAP} remote_probe snapshots stored from an expired claim, expected 0"
  [ "$CUR" = "-" ] || fail_g "current is ${CUR} from an expired claim, expected none"
fi
finish_case "an expired introspection claim still completes"

# =============================================================================
# #5464 freshness, not arrival, picks current
# =============================================================================
begin_test "FIX #5464: a later result observed 3 minutes earlier stays history, and an observedAt before the claim answers 400"
reset_case
publish stale 1.0.0
if claim stale 1.0.0; then
  complete "$(result ok '{}' fresh_tool)"
  note "fresh (observed now): ${CODE} $(jqr -c '{status,current,error}' "$R")"
  [ "$CODE" = "200" ] || fail_g "the fresh result answered ${CODE}: $(head -c 200 "$R")"
fi
probe stale 1.0.0
if claim stale 1.0.0; then
  complete "$(result ok "$(jq -nc --arg o "$(iso '-180 seconds')" '{observedAt:$o}')" stale_tool)"
  note "stale (observed 3 min ago, arrives later): ${CODE} $(jqr -c '{status,current,error}' "$R")"
  [ "$CODE" = "200" ] || fail_g "the stale result answered ${CODE}: $(head -c 200 "$R"), expected 200 stored as history"
  [ "$(jqr '.current' "$R")" = "true" ] && fail_g "the stale result answered current: true"
  caps stale 1.0.0
  note "capabilities: current=${CUR} remote_probe snapshots=${NSNAP}"
  [ "$CUR" = "fresh_tool" ] || fail_g "current tool is ${CUR}, expected fresh_tool: a stale observation replaced a fresher current one"
fi
probe stale 1.0.0
if claim stale 1.0.0; then
  complete "$(result ok "$(jq -nc --arg o "$(iso '-1 hour')" '{observedAt:$o}')" ancient_tool)"
  note "observedAt an hour before the claim: ${CODE} $(jqr -c '{status,error,field}' "$R")"
  { [ "$CODE" = "400" ] && [ "$(jqr '.field' "$R")" = "observedAt" ]; } \
    || fail_g "an observedAt an hour before the claim answered ${CODE} $(jqr 'if (.status|type) == "string" then .status else .error end' "$R"), expected 400 naming observedAt"
  caps stale 1.0.0
  note "capabilities: current=${CUR}"
  [ "$CUR" = "fresh_tool" ] || fail_g "current tool is ${CUR} after the pre-claim result, expected fresh_tool"
fi
finish_case "a stale introspection observation replaces a fresher current one"

# =============================================================================
# #5466 result metadata validation
# =============================================================================
begin_test "FIX #5466: ttlMs -1, cacheScope shared and an observedAt an hour ahead each answer 400 mcp_invalid_result_metadata and leave the claim live"
reset_case
v=0
for spec in 'ttlMs|{"ttlMs":-1}' 'cacheScope|{"cacheScope":"shared"}' "observedAt|$(jq -nc --arg o "$(iso '+1 hour')" '{observedAt:$o}')"; do
  field="${spec%%|*}"; extra="${spec#*|}"
  v=$((v+1)); ver="1.0.${v}"
  publish meta "$ver"
  claim meta "$ver" || continue
  complete "$(result ok "$extra" "bad_${field}")"
  note "${extra}: ${CODE} $(jqr -c '{status,error,field}' "$R")"
  { [ "$CODE" = "400" ] && [ "$(jqr '.error' "$R")" = "mcp_invalid_result_metadata" ] && [ "$(jqr '.field' "$R")" = "$field" ]; } \
    || fail_g "${extra} answered ${CODE} $(jqr 'if (.status|type) == "string" then .status else .error end' "$R"), expected 400 mcp_invalid_result_metadata naming ${field}"
  caps meta "$ver"
  [ "$NSNAP" = "0" ] || fail_g "${NSNAP} snapshot(s) stored from ${extra}, expected 0"
  complete "$(result ok '{}' "good_${field}")"
  note "   corrected result on the same claim: ${CODE} $(jqr -c '{status,error}' "$R")"
  { [ "$CODE" = "200" ] && [ "$(jqr '.status' "$R")" = "stored" ]; } \
    || fail_g "the corrected result after ${extra} answered ${CODE} $(jqr 'if (.status|type) == "string" then .status else .error end' "$R"), expected 200 stored (a refusal leaves the claim live)"
done
finish_case "introspection completion accepts invalid result metadata"

end_suite
