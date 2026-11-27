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
R="dtf-cgate-r-${SUF}"     # gated remote
R2="dtf-cgate-u-${SUF}"    # ungated remote over the same upstream
V="dtf-cgate-v-${SUF}"     # virtual over R
V2="dtf-cgate-m-${SUF}"    # virtual over R2 (first) and R
UPSTREAM="http://172.16.${DTF_SLOT}.70/gate/"
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-conda"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
PIXI_CTR="ak-dtf${DTF_SLOT}-cgate-pixi"
TIER_DIR="${DTF_DIR}/harness/tiers/conda-age-gate"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
PY_IMAGE="docker.io/library/python:3.14-slim"
PIXI_IMAGE="ghcr.io/prefix-dev/pixi:0.81.0"
f() { echo "dtfgate-$1-1.0-0.tar.bz2"; }
SERVED='["dtfgate-noidx-1.0-0.tar.bz2","dtfgate-old-1.0-0.tar.bz2","dtfgate-rej-1.0-0.tar.bz2"]'
SERVED_NAMES='["dtfgate-noidx","dtfgate-old","dtfgate-rej"]'

WORK="$(mktemp -d -t dtf-cgate-XXXXXX)"
cleanup() {
  docker rm -f "$PIXI_CTR" >/dev/null 2>&1 || true
  for k in "$V2" "$V" "$R2" "$R"; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
jqr() { jq -r "$1" 2>/dev/null || true; }
# get TAG PATH -> HTTP status; body in $WORK/TAG, headers in $WORK/TAG.hdr
get() {
  curl -s --max-time 120 -D "$WORK/$1.hdr" -o "$WORK/$1" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}$2" 2>/dev/null || echo 000
}
hdr() { { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r ' ; }
records() {
  docker run --rm -i --security-opt label=disable -v "${TIER_DIR}/fixtures:/fx:ro" "$PY_IMAGE" \
    python3 -I /fx/repodata_records.py "$2" < "$WORK/$1" 2>/dev/null || echo '{"records":{},"error":"decoder did not run"}'
}
listed() { records "$1" "$2" | jq -c '.records | keys' 2>/dev/null || echo null; }
shard_names() { # REPO -> the shard index's names
  get "idx.$1" "/conda/$1/noarch/repodata_shards.msgpack.zst" >/dev/null
  docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" "$PY_IMAGE" \
    python3 -I /app/cep16.py < "$WORK/idx.$1" 2>/dev/null | jq -c '.doc.shards | keys' 2>/dev/null || echo null
}
mock() { docker exec "$MOCK_CTR" python3 -c "import sys,urllib.request; sys.stdout.buffer.write(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1$1', method='$2')).read())" 2>/dev/null; }
upstream_ts() { mock /gate/noarch/repodata.json GET | jq -r --arg f "$1" '.packages[$f].indexed_timestamp // empty'; }
gatelog() { mock /__gatelog GET || true; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
withheld_json() { # -> the admin lookup's withheld list ([] or null on error)
  get lookup "/api/v1/repositories/${R}/age-gate/conda/withheld?subdir=noarch" >/dev/null
  jq -c '.withheld // null' "$WORK/lookup" 2>/dev/null || echo null
}
lookup_field() { withheld_json | jq -r --arg f "$1" --arg k "$2" '(map(select(.filename == $f)) | .[0][$k]) // "absent" | tostring'; }
# poll: wait up to 60 s for `eval "$1"` to print `$2`; prints the last value.
poll() { local got=""; for _ in $(seq 1 20); do got="$(eval "$1")"; [ "$got" = "$2" ] && break; sleep 3; done; echo "$got"; }
assert_451() { # TAG STATUS WANT_PACKAGE WANT_REASON
  if [ "$2" = "451" ] && [ "$(jqr .error < "$WORK/$1")" = "age_gate_blocked" ] \
     && [ "$(jqr .package < "$WORK/$1")" = "$3" ] && [ "$(jqr .reason < "$WORK/$1")" = "$4" ]; then pass
  else fail "#6526: HTTP $2 (want 451 age_gate_blocked for $3, reason $4)" "$(head -c 300 "$WORK/$1")"; fi
}

begin_suite "conda-age-gate (#6526)"

begin_test "setup: gated and ungated remotes over the mock /gate/ channel, two virtuals, images"
auth_admin
setup_err=""
create_repo "$R" conda remote "$UPSTREAM" >/dev/null 2>&1 || setup_err+="create R; "
create_repo "$R2" conda remote "$UPSTREAM" >/dev/null 2>&1 || setup_err+="create R2; "
create_repo "$V" conda virtual >/dev/null 2>&1 || setup_err+="create V; "
create_repo "$V2" conda virtual >/dev/null 2>&1 || setup_err+="create V2; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\",\"priority\":1}" >/dev/null 2>&1 || setup_err+="V member; "
api_post "/api/v1/repositories/${V2}/members" "{\"member_key\":\"${R2}\",\"priority\":1}" >/dev/null 2>&1 || setup_err+="V2 member R2; "
api_post "/api/v1/repositories/${V2}/members" "{\"member_key\":\"${R}\",\"priority\":2}" >/dev/null 2>&1 || setup_err+="V2 member R; "
RID="$(psql_q "SELECT id FROM repositories WHERE key='${R}'")"
R2ID="$(psql_q "SELECT id FROM repositories WHERE key='${R2}'")"
[ -n "$RID" ] && [ -n "$R2ID" ] || setup_err+="no remote id; "
for id in "$RID" "$R2ID"; do
  psql_q "INSERT INTO repository_config (repository_id, key, value) VALUES ('${id}', 'cache_ttl_secs', '2')" >/dev/null
done
for img in "$PY_IMAGE" "$PIXI_IMAGE"; do docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null 2>&1 || setup_err+="pull ${img}; "; done
docker rm -f "$PIXI_CTR" >/dev/null 2>&1 || true
docker run -d --name "$PIXI_CTR" --network "container:${BACKEND_CTR}" --entrypoint sleep "$PIXI_IMAGE" infinity >/dev/null 2>&1 || setup_err+="start pixi; "
if [ -n "$setup_err" ]; then infra_fail "setup did not complete" "$setup_err"; end_suite; fi
pass

begin_test "setup: enable the age gate on the gated remote (7 days, upstream_publish_time)"
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

# ---------------------------------------------------------------------------
# Baseline on first enable, every document of the remote
# ---------------------------------------------------------------------------
for enc in json bz2 zst; do
  case "$enc" in json) file=repodata.json ;; *) file="repodata.json.${enc}" ;; esac
  st="$(get "r.${enc}" "/conda/${R}/noarch/${file}")"
  got="$(listed "r.${enc}" "$enc")"
  begin_test "FIX #6526: on first enable the remote's ${file} keeps the old baseline records and holds the rest"
  if [ "$st" = "200" ] && [ "$got" = "$SERVED" ]; then pass
  else fail "#6526: ${file} HTTP ${st} lists ${got} (want ${SERVED})" "$(head -c 300 "$WORK/r.${enc}")"; fi
done

begin_test "FIX #6526: the gated repodata.json names the withheld count (x-ak-age-gate-withheld: 4)"
w="$(hdr r.json x-ak-age-gate-withheld)"
if [ "$w" = "4" ]; then pass; else fail "#6526: x-ak-age-gate-withheld '${w:-absent}'"; fi

begin_test "FIX #6526: the baseline is recorded for the subdir, with a sighting for every file"
b="$(psql_q "SELECT (baseline_at IS NOT NULL)::text||'|'||(SELECT count(*) FROM conda_record_first_seen s WHERE s.channel_id = c.id AND s.in_baseline) FROM conda_first_seen_channels c WHERE c.repository_id='${RID}' AND c.subdir='noarch'")"
if [ "$b" = "true|7" ]; then pass; else fail "#6526: baseline|rows = '${b:-none}' (want true|7)"; fi

OLD_TS="$(upstream_ts "$(f old)")"
begin_test "CONTROL: dtfgate-old keeps the upstream indexed_timestamp (${OLD_TS})"
got="$(records r.json json | jq -r --arg f "$(f old)" '.records[$f] // "absent"')"
if [ -n "$OLD_TS" ] && [ "$got" = "$OLD_TS" ]; then pass; else fail "indexed_timestamp ${got}, upstream ${OLD_TS:-none}"; fi

st="$(get r.cur "/conda/${R}/noarch/current_repodata.json")"; got="$(listed r.cur json)"
begin_test "FIX #6526: the remote's current_repodata.json lists only the served records"
if [ "$st" = "200" ] && [ "$got" = "$SERVED" ]; then pass; else fail "#6526: current_repodata HTTP ${st} lists ${got}"; fi

got="$(shard_names "$R")"
begin_test "FIX #6526: the remote's CEP-16 shard index names only the served packages"
if [ "$got" = "$SERVED_NAMES" ]; then pass; else fail "#6526: shard index names ${got}"; fi

st="$(get r.sig "/conda/${R}/noarch/repodata.json.sig")"
begin_test "FIX #6526: the gated remote's repodata.json.sig answers 404 (the upstream signature no longer covers it)"
if [ "$st" = "404" ]; then pass; else fail "#6526: repodata.json.sig HTTP ${st}" "$(head -c 200 "$WORK/r.sig")"; fi

st="$(get r.young "/conda/${R}/noarch/$(f young)")"
begin_test "FIX #6526: the young package answers 451 age_gate_blocked (too_young)"
assert_451 r.young "$st" dtfgate-young too_young
begin_test "FIX #6526: the 451 names the age basis (baseline) and the date it becomes available"
if [ "$(jqr .age_basis < "$WORK/r.young")" = "baseline" ] && [ -n "$(jqr '.available_at // empty' < "$WORK/r.young")" ]; then pass
else fail "#6526: age_basis $(jqr .age_basis < "$WORK/r.young"), available_at $(jqr .available_at < "$WORK/r.young")"; fi

st="$(get r.fut "/conda/${R}/noarch/$(f futurets)")"
begin_test "FIX #6526: a record with a future builder timestamp answers 451 (timestamp_in_future)"
assert_451 r.fut "$st" dtfgate-futurets timestamp_in_future
st="$(get r.ord "/conda/${R}/noarch/$(f badorder)")"
begin_test "FIX #6526: a record indexed before it was built answers 451 (indexed_before_built)"
assert_451 r.ord "$st" dtfgate-badorder indexed_before_built

st="$(get r.unl "/conda/${R}/noarch/$(f unlisted)")"
begin_test "FIX #6526: a file the upstream index does not list answers 404 age_gate_unlisted"
if [ "$st" = "404" ] && [ "$(jqr .error < "$WORK/r.unl")" = "age_gate_unlisted" ]; then pass
else fail "#6526: unlisted file HTTP ${st}" "$(head -c 200 "$WORK/r.unl")"; fi

begin_test "FIX #6526: the refused young and unlisted files were never fetched upstream"
if gatelog | grep -qxE "/gate/noarch/($(f young)|$(f unlisted))"; then fail "#6526: fetched upstream" "$(gatelog | head -c 600)"
else pass; fi

begin_test "FIX #6526: the young refusal recorded one pending review"
n="$(psql_q "SELECT count(*) FROM age_gate_reviews WHERE repository_id='${RID}' AND package_name='dtfgate-young' AND status='pending'")"
if [ "${n:-0}" = "1" ]; then pass; else fail "#6526: ${n:-0} pending reviews"; fi

begin_test "CONTROL: dtfgate-old downloads from the remote with the upstream bytes"
st="$(get r.old "/conda/${R}/noarch/$(f old)")"; mock "/gate/noarch/$(f old)" GET > "$WORK/old.mock"
if [ "$st" = "200" ] && [ -s "$WORK/old.mock" ] && [ "$(sha "$WORK/r.old")" = "$(sha "$WORK/old.mock")" ]; then pass
else fail "old package HTTP ${st}"; fi

# ---------------------------------------------------------------------------
# Virtuals: the gated member alone, and mixed with an ungated member
# ---------------------------------------------------------------------------
for enc in json zst; do
  case "$enc" in json) file=repodata.json ;; *) file="repodata.json.${enc}" ;; esac
  st="$(get "v.${enc}" "/conda/${V}/noarch/${file}")"; got="$(listed "v.${enc}" "$enc")"
  begin_test "FIX #6526: the virtual's ${file} lists only the gated member's served records"
  if [ "$st" = "200" ] && [ "$got" = "$SERVED" ]; then pass; else fail "#6526: virtual ${file} HTTP ${st} lists ${got}"; fi
done
got="$(shard_names "$V")"
begin_test "FIX #6526: the virtual's shard index names only the served packages"
if [ "$got" = "$SERVED_NAMES" ]; then pass; else fail "#6526: virtual shard index names ${got}"; fi
st="$(get v.young "/conda/${V}/noarch/$(f young)")"
begin_test "FIX #6526: through the virtual the young package answers 451"
if [ "$st" = "451" ] && [ "$(jqr .error < "$WORK/v.young")" = "age_gate_blocked" ]; then pass; else fail "#6526: HTTP ${st}" "$(head -c 300 "$WORK/v.young")"; fi
st="$(get v.unl "/conda/${V}/noarch/$(f unlisted)")"
begin_test "FIX #6526: through the virtual the unlisted file is not fetched from the gated member"
if [ "$st" = "404" ]; then pass; else fail "#6526: virtual unlisted file HTTP ${st}"; fi

st="$(get m.json "/conda/${V2}/noarch/repodata.json")"; got="$(listed m.json json)"
begin_test "FIX #6526: a virtual with an ungated member first still leaves out every file the gated member withholds"
if [ "$st" = "200" ] && ! echo "$got" | jq -e --arg y "$(f young)" 'index($y)' >/dev/null 2>&1 \
   && echo "$got" | jq -e --arg o "$(f old)" 'index($o)' >/dev/null 2>&1; then pass
else fail "#6526: mixed virtual repodata HTTP ${st} lists ${got}"; fi
got="$(shard_names "$V2")"
begin_test "FIX #6526: the mixed virtual's shard index lists no withheld package (filtered as repodata is)"
if echo "$got" | jq -e 'index("dtfgate-old") and (index("dtfgate-young") | not) and (index("dtfgate-futurets") | not)' >/dev/null 2>&1; then pass
else fail "#6526: mixed virtual shard index names ${got}"; fi
st="$(get m.young "/conda/${V2}/noarch/$(f young)")"
begin_test "FIX #6526: through the mixed virtual the young package answers 451"
if [ "$st" = "451" ]; then pass; else fail "#6526: mixed virtual young HTTP ${st}"; fi

# ---------------------------------------------------------------------------
# A real client: pixi solves against the gated remote
# ---------------------------------------------------------------------------
pixi_lock() { # TAG SPEC -> pixi's exit status
  docker exec "$PIXI_CTR" sh -c "rm -rf /w-$1 && mkdir -p /w-$1 && printf '%s\n' '[workspace]' 'name = \"cgate\"' 'channels = [\"http://127.0.0.1:8080/conda/${R}\"]' 'platforms = [\"linux-64\"]' '' '[dependencies]' '$2 = \"*\"' > /w-$1/pixi.toml && cd /w-$1 && PIXI_CACHE_DIR=/tmp/pc-$1 RATTLER_CACHE_DIR=/tmp/pc-$1 pixi lock" > "$WORK/pixi.$1" 2>&1
  echo $?
}
echo "  client: $(docker exec "$PIXI_CTR" pixi --version 2>&1 | tail -1)"
c_old="$(pixi_lock old dtfgate-old)"; c_young="$(pixi_lock young dtfgate-young)"
begin_test "CONTROL: pixi locks dtfgate-old from the gated remote"
if [ "$c_old" = "0" ]; then pass; else fail "pixi lock dtfgate-old exit ${c_old}" "$(tail -c 500 "$WORK/pixi.old")"; fi
begin_test "FIX #6526: pixi cannot lock dtfgate-young from the gated remote (the gate withholds it)"
if [ "$c_young" != "0" ]; then pass; else fail "#6526: pixi locked the young package" "$(tail -c 500 "$WORK/pixi.young")"; fi

# ---------------------------------------------------------------------------
# Decisions and the admin lookup
# ---------------------------------------------------------------------------
ADMIN_ID="$(psql_q "SELECT id FROM users WHERE username='${ADMIN_USER:-admin}' LIMIT 1")"
psql_q "INSERT INTO age_gate_reviews (repository_id, package_name, package_version, status, reviewed_by, reviewed_at, review_reason) VALUES ('${RID}', 'dtfgate-rej', '1.0', 'rejected', '${ADMIN_ID}', NOW(), 'dtf reject')" >/dev/null
st="$(get r.rj "/conda/${R}/noarch/repodata.json")"; got="$(listed r.rj json)"
begin_test "FIX #6526: right after an old version is rejected the remote stops listing it"
if [ "$st" = "200" ] && ! echo "$got" | jq -e --arg r "$(f rej)" 'index($r)' >/dev/null 2>&1; then pass
else fail "#6526: after the rejection repodata lists ${got}"; fi
st="$(get r.rjd "/conda/${R}/noarch/$(f rej)")"
begin_test "FIX #6526: the rejected version's file answers 451 (rejected)"
assert_451 r.rjd "$st" dtfgate-rej rejected

begin_test "FIX #6526: the admin lookup names why each file is withheld"
wj="$(withheld_json)"
if echo "$wj" | jq -e --arg y "$(f young)" --arg u "$(f futurets)" \
     'any(.[]; .filename == $y and .age_basis == "baseline" and .reason == "too_young" and .available_at != null)
      and any(.[]; .filename == $u and .reason == "timestamp_in_future")' >/dev/null 2>&1; then pass
else fail "#6526: lookup ${wj:0:400}" "$(head -c 300 "$WORK/lookup")"; fi

rv="$(psql_q "SELECT id FROM age_gate_reviews WHERE repository_id='${RID}' AND package_name='dtfgate-young' LIMIT 1")"
ap="000"
[ -n "$rv" ] && ap="$(curl -s -o "$WORK/ap" -w '%{http_code}' --max-time 30 -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d '{"reason":"dtf conda-age-gate approve"}' \
  "${BASE_URL}/api/v1/admin/age-gate/reviews/${rv}/approve" 2>/dev/null || echo 000)"
st="$(get r.appr "/conda/${R}/noarch/repodata.json")"; got="$(listed r.appr json)"
begin_test "FIX #6526: right after its review is approved the remote lists dtfgate-young"
if [ "$ap" = "200" ] && echo "$got" | jq -e --arg f "$(f young)" 'index($f) != null' >/dev/null 2>&1; then pass
else fail "#6526: approve HTTP ${ap}, repodata lists ${got}"; fi
begin_test "CONTROL: the approved young package downloads with the upstream bytes"
st="$(get r.young2 "/conda/${R}/noarch/$(f young)")"; mock "/gate/noarch/$(f young)" GET > "$WORK/young.mock"
if [ "$st" = "200" ] && [ "$(sha "$WORK/r.young2")" = "$(sha "$WORK/young.mock")" ]; then pass
else fail "approved young package HTTP ${st}" "$(head -c 300 "$WORK/r.young2")"; fi

# ---------------------------------------------------------------------------
# After the baseline: a backdated newcomer, aging, an in-place swap
# ---------------------------------------------------------------------------
mock "/__gate/add?name=dtfgate-fresh&indexed_days_ago=30" POST >/dev/null
got="$(poll "lookup_field $(f fresh) backdated_indexed_timestamp" true)"
begin_test "FIX #6526: a file listed after the baseline with an indexed_timestamp 30 days old is held and flagged as backdated"
st="$(get r.fr "/conda/${R}/noarch/repodata.json")"; lst="$(listed r.fr json)"
if [ "$got" = "true" ] && [ "$(lookup_field "$(f fresh)" age_basis)" = "first_seen" ] \
   && ! echo "$lst" | jq -e --arg f "$(f fresh)" 'index($f)' >/dev/null 2>&1; then pass
else fail "#6526: backdated newcomer: lookup backdated=${got}, repodata lists ${lst}"; fi

psql_q "UPDATE conda_record_first_seen s SET first_seen_at = first_seen_at - interval '8 days', prev_fetch_at = prev_fetch_at - interval '8 days' FROM conda_first_seen_channels c WHERE c.id = s.channel_id AND c.repository_id='${RID}' AND s.filename='$(f fresh)'" >/dev/null
aged_listed() { get r.ag "/conda/${R}/noarch/repodata.json" >/dev/null; listed r.ag json | jq -r --arg f "$(f fresh)" 'index($f) != null'; }
got="$(poll aged_listed true)"
begin_test "CONTROL #6526: once its sighting is 8 days old the newcomer is served"
if [ "$got" = "true" ]; then pass; else fail "#6526: the aged newcomer is still withheld"; fi

mock "/__gate/swap?name=dtfgate-noidx" POST >/dev/null
got="$(poll "lookup_field $(f noidx) age_basis" first_seen)"
begin_test "FIX #6526: new bytes under a published filename are a new sighting and are held"
get r.sw "/conda/${R}/noarch/repodata.json" >/dev/null; lst="$(listed r.sw json)"
if [ "$got" = "first_seen" ] && ! echo "$lst" | jq -e --arg f "$(f noidx)" 'index($f)' >/dev/null 2>&1; then pass
else fail "#6526: swapped file: lookup age_basis=${got}, repodata lists ${lst}"; fi

# ---------------------------------------------------------------------------
# Re-baselining is an explicit, audited action
# ---------------------------------------------------------------------------
rb="$(curl -s -o "$WORK/rb" -w '%{http_code}' --max-time 30 -X POST -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${R}/age-gate/conda/rebaseline" 2>/dev/null || echo 000)"
begin_test "FIX #6526: re-baselining is an explicit action and is audited (AGE_GATE_REBASELINED)"
n="$(psql_q "SELECT count(*) FROM audit_log WHERE action='AGE_GATE_REBASELINED' AND resource_id='${RID}'")"
if [ "$rb" = "200" ] && [ "$(jqr .channels_reset < "$WORK/rb")" -ge 1 ] 2>/dev/null && [ "${n:-0}" -ge 1 ] 2>/dev/null; then pass
else fail "#6526: rebaseline HTTP ${rb} ($(head -c 200 "$WORK/rb")), audit rows ${n:-0}"; fi

end_suite
