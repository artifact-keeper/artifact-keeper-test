#!/usr/bin/env bash
# =============================================================================
# tiers/conda-age-gate/oracle.sh: the age gate (cooldown) on conda Remote and
# Virtual channels (artifact-keeper#6526). See the manifest for the gates.
# =============================================================================
# run.sh exported BASE_URL, DB_CONTAINER, RUN_ID, DTF_SLOT, DTF_DIR, COMMON_SH.
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${DTF_SLOT}x${RUN_ID##*-}"
R="dtf-cgate-r-${SUF}"
V="dtf-cgate-v-${SUF}"
UPSTREAM="http://172.16.${DTF_SLOT}.70/gate/"
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-conda"
TIER_DIR="${DTF_DIR}/harness/tiers/conda-age-gate"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
PY_IMAGE="docker.io/library/python:3.14-slim"
OLD="dtfgate-old-1.0-0.tar.bz2"
YOUNG="dtfgate-young-1.0-0.tar.bz2"
NOIDX="dtfgate-noidx-1.0-0.tar.bz2"
LATER="dtfgate-later-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-cgate-XXXXXX)"
cleanup() {
  api_delete "/api/v1/repositories/${V}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${R}" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
jqr() { jq -r "$1" 2>/dev/null || true; }
# get TAG PATH -> HTTP status; body in $WORK/TAG, headers in $WORK/TAG.hdr
get() {
  curl -s --max-time 120 -D "$WORK/$1.hdr" -o "$WORK/$1" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}$2" 2>/dev/null || echo 000
}
hdr() { { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r ' ; }
# records TAG ENC -> {"records":{fn: indexed_timestamp|null}}
records() {
  docker run --rm -i --security-opt label=disable -v "${TIER_DIR}/fixtures:/fx:ro" "$PY_IMAGE" \
    python3 -I /fx/repodata_records.py "$2" < "$WORK/$1" 2>/dev/null || echo '{"records":{},"error":"decoder did not run"}'
}
listed() { records "$1" "$2" | jq -c '.records | keys' 2>/dev/null || echo null; }
upstream_ts() { docker exec "$MOCK_CTR" python3 -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1/gate/noarch/repodata.json'))['packages']['$1'].get('indexed_timestamp'))" 2>/dev/null; }
mock_bytes() { docker exec "$MOCK_CTR" python3 -c "import sys,urllib.request; sys.stdout.buffer.write(urllib.request.urlopen('http://127.0.0.1/gate/noarch/$1').read())" > "$WORK/$1.mock" 2>/dev/null; }
gatelog() { docker exec "$MOCK_CTR" python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/__gatelog').read().decode())" 2>/dev/null || true; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

begin_suite "conda-age-gate (#6526)"

begin_test "setup: remote over the mock /gate/ channel, virtual over it, decoder image"
auth_admin
setup_err=""
create_repo "$R" conda remote "$UPSTREAM" >/dev/null 2>&1 || setup_err+="create R; "
create_repo "$V" conda virtual >/dev/null 2>&1 || setup_err+="create V; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\",\"priority\":1}" >/dev/null 2>&1 || setup_err+="add member; "
RID="$(psql_q "SELECT id FROM repositories WHERE key='${R}'")"
[ -n "$RID" ] || setup_err+="no remote id; "
psql_q "INSERT INTO repository_config (repository_id, key, value) VALUES ('${RID}', 'cache_ttl_secs', '2')" >/dev/null
docker image inspect "$PY_IMAGE" >/dev/null 2>&1 || docker pull -q "$PY_IMAGE" >/dev/null 2>&1 || setup_err+="pull python; "
if [ -n "$setup_err" ]; then infra_fail "setup did not complete" "$setup_err"; end_suite; fi
pass

begin_test "setup: enable the age gate on the remote (7 days, upstream_publish_time)"
put_st="$(curl -s -o "$WORK/put" -w '%{http_code}' --max-time 30 -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}' \
  "${BASE_URL}/api/v1/repositories/${R}/age-gate" 2>/dev/null || echo 000)"
GATE_VIA=api
if [ "$put_st" != "200" ]; then
  # main refuses the config for conda: switch it on in the database so the red
  # run shows what a gated conda remote served before #6526.
  echo "  age-gate PUT HTTP ${put_st} ($(head -c 160 "$WORK/put")); enabling it in the database"
  psql_q "UPDATE repositories SET age_gate_enabled=true, age_gate_min_age_days=7, age_gate_mode='upstream_publish_time' WHERE key='${R}'" >/dev/null
  GATE_VIA=db
  sleep 61   # the repository row cache keeps the old columns for up to 60 s
fi
got="$(psql_q "SELECT age_gate_enabled::text||'|'||age_gate_min_age_days||'|'||age_gate_mode FROM repositories WHERE key='${R}'")"
if [ "$got" = "true|7|upstream_publish_time" ]; then pass
else infra_fail "age gate not configured (via ${GATE_VIA}: ${got})" "$(head -c 300 "$WORK/put")"; end_suite; fi

OLD_TS="$(upstream_ts "$OLD")"

# ---------------------------------------------------------------------------
# Remote: every document
# ---------------------------------------------------------------------------
for enc in json bz2 zst; do
  case "$enc" in json) file=repodata.json ;; *) file="repodata.json.${enc}" ;; esac
  st="$(get "r.${enc}" "/conda/${R}/noarch/${file}")"
  got="$(listed "r.${enc}" "$enc")"
  begin_test "FIX #6526: the remote's noarch/${file} lists only ${OLD}"
  if [ "$st" = "200" ] && [ "$got" = "[\"${OLD}\"]" ]; then pass
  else fail "#6526: ${file} HTTP ${st} lists ${got}; the young records reach the solver" "$(head -c 300 "$WORK/r.${enc}")"; fi
done

begin_test "CONTROL: ${OLD} keeps the upstream indexed_timestamp (${OLD_TS}) in repodata.json"
got="$(records r.json json | jq -r --arg f "$OLD" '.records[$f] // "absent"')"
if [ -n "$OLD_TS" ] && [ "$got" = "$OLD_TS" ]; then pass
else fail "old record indexed_timestamp ${got}, upstream ${OLD_TS:-none}"; fi

begin_test "FIX #6526: the gated repodata.json names the withheld count (x-ak-age-gate-withheld: 3)"
w="$(hdr r.json x-ak-age-gate-withheld)"
if [ "$w" = "3" ]; then pass; else fail "#6526: x-ak-age-gate-withheld '${w:-absent}'"; fi

st="$(get r.cur "/conda/${R}/noarch/current_repodata.json")"
got="$(listed r.cur json)"
begin_test "FIX #6526: the remote's current_repodata.json lists only ${OLD}"
if [ "$st" = "200" ] && [ "$got" = "[\"${OLD}\"]" ]; then pass
else fail "#6526: current_repodata.json HTTP ${st} lists ${got}" "$(head -c 300 "$WORK/r.cur")"; fi

st="$(get r.idx "/conda/${R}/noarch/repodata_shards.msgpack.zst")"
names="$(docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" "$PY_IMAGE" \
  python3 -I /app/cep16.py < "$WORK/r.idx" 2>/dev/null | jq -c '.doc.shards | keys' 2>/dev/null || echo null)"
begin_test "FIX #6526: the remote's CEP-16 shard index names only dtfgate-old"
if [ "$st" = "200" ] && [ "$names" = '["dtfgate-old"]' ]; then pass
else fail "#6526: shard index HTTP ${st} names ${names}"; fi

st="$(get r.young "/conda/${R}/noarch/${YOUNG}")"
begin_test "FIX #6526: the young package answers 451 age_gate_blocked naming dtfgate-young 1.0"
if [ "$st" = "451" ] && [ "$(jqr .error < "$WORK/r.young")" = "age_gate_blocked" ] \
   && [ "$(jqr .package < "$WORK/r.young")" = "dtfgate-young" ] && [ "$(jqr .version < "$WORK/r.young")" = "1.0" ]; then pass
else fail "#6526: young package HTTP ${st}" "$(head -c 300 "$WORK/r.young")"; fi

begin_test "FIX #6526: the refused young package was never fetched upstream"
if gatelog | grep -qx "/gate/noarch/${YOUNG}"; then fail "#6526: the backend fetched ${YOUNG} upstream" "$(gatelog | head -c 600)"
else pass; fi

begin_test "FIX #6526: the refusal recorded one pending review for dtfgate-young 1.0"
n="$(psql_q "SELECT count(*) FROM age_gate_reviews WHERE repository_id='${RID}' AND package_name='dtfgate-young' AND package_version='1.0' AND status='pending'")"
if [ "${n:-0}" = "1" ]; then pass; else fail "#6526: ${n:-0} pending reviews"; fi

begin_test "CONTROL: ${OLD} downloads from the remote with the upstream bytes"
st="$(get r.old "/conda/${R}/noarch/${OLD}")"; mock_bytes "$OLD"
if [ "$st" = "200" ] && [ -s "$WORK/${OLD}.mock" ] && [ "$(sha "$WORK/r.old")" = "$(sha "$WORK/${OLD}.mock")" ]; then pass
else fail "old package HTTP ${st}"; fi

# ---------------------------------------------------------------------------
# Virtual
# ---------------------------------------------------------------------------
st="$(get v.json "/conda/${V}/noarch/repodata.json")"
got="$(listed v.json json)"
begin_test "FIX #6526: the virtual's repodata.json lists only ${OLD} from the gated member"
if [ "$st" = "200" ] && [ "$got" = "[\"${OLD}\"]" ]; then pass
else fail "#6526: virtual repodata HTTP ${st} lists ${got}"; fi

st="$(get v.young "/conda/${V}/noarch/${YOUNG}")"
begin_test "FIX #6526: through the virtual the young package answers 451 age_gate_blocked"
if [ "$st" = "451" ] && [ "$(jqr .error < "$WORK/v.young")" = "age_gate_blocked" ]; then pass
else fail "#6526: virtual young package HTTP ${st}" "$(head -c 300 "$WORK/v.young")"; fi

begin_test "CONTROL: ${OLD} downloads through the virtual"
st="$(get v.old "/conda/${V}/noarch/${OLD}")"
if [ "$st" = "200" ] && [ "$(sha "$WORK/v.old")" = "$(sha "$WORK/${OLD}.mock")" ]; then pass
else fail "virtual old package HTTP ${st}"; fi

# ---------------------------------------------------------------------------
# First sightings, aging, decisions
# ---------------------------------------------------------------------------
begin_test "FIX #6526: the first sightings of the unindexed files are stored"
n="$(psql_q "SELECT count(*) FROM conda_record_first_seen s JOIN conda_first_seen_channels c ON c.id=s.channel_id WHERE c.repository_id='${RID}' AND c.subdir='noarch'")"
if [ "${n:-0}" -ge 2 ] 2>/dev/null; then pass; else fail "#6526: ${n:-none} first-sighting rows"; fi

psql_q "UPDATE conda_record_first_seen s SET first_seen_at = first_seen_at - interval '8 days' FROM conda_first_seen_channels c WHERE c.id=s.channel_id AND c.repository_id='${RID}' AND s.filename='${NOIDX}'" >/dev/null
got=""
for _ in $(seq 1 20); do
  sleep 3
  get r.aged "/conda/${R}/noarch/repodata.json" >/dev/null
  got="$(listed r.aged json)"
  [ "$got" = "[\"${NOIDX}\",\"${OLD}\"]" ] && break
done
begin_test "FIX #6526: once its first sighting is 8 days old, ${NOIDX} is served and ${LATER} is still withheld"
if [ "$got" = "[\"${NOIDX}\",\"${OLD}\"]" ]; then pass
else fail "#6526: after aging the remote lists ${got}"; fi

begin_test "CONTROL #6526: the aged record carries no indexed_timestamp (a first sighting is never injected)"
ts="$(records r.aged json | jq -r --arg f "$NOIDX" '.records | if has($f) then (.[$f] // "null") else "absent" end')"
if [ "$ts" = "null" ]; then pass; else fail "#6526: ${NOIDX} indexed_timestamp ${ts}"; fi

rv="$(psql_q "SELECT id FROM age_gate_reviews WHERE repository_id='${RID}' AND package_name='dtfgate-young' AND package_version='1.0' LIMIT 1")"
ap="000"
[ -n "$rv" ] && ap="$(curl -s -o "$WORK/ap" -w '%{http_code}' --max-time 30 -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d '{"reason":"dtf conda-age-gate approve"}' \
  "${BASE_URL}/api/v1/admin/age-gate/reviews/${rv}/approve" 2>/dev/null || echo 000)"
st="$(get r.appr "/conda/${R}/noarch/repodata.json")"
got="$(listed r.appr json)"
begin_test "FIX #6526: right after its review is approved the remote lists dtfgate-young"
if [ "$ap" = "200" ] && echo "$got" | jq -e --arg f "$YOUNG" 'index($f) != null' >/dev/null 2>&1; then pass
else fail "#6526: approve HTTP ${ap}, repodata lists ${got}"; fi

begin_test "CONTROL #6526: the approved young package downloads with the upstream bytes"
st="$(get r.young2 "/conda/${R}/noarch/${YOUNG}")"; mock_bytes "$YOUNG"
if [ "$st" = "200" ] && [ "$(sha "$WORK/r.young2")" = "$(sha "$WORK/${YOUNG}.mock")" ]; then pass
else fail "#6526: approved young package HTTP ${st}" "$(head -c 300 "$WORK/r.young2")"; fi

end_suite
