#!/usr/bin/env bash
# =============================================================================
# tiers/bounded-download-dispatch/oracle.sh -- #2522 bounded side-effect oracle
# =============================================================================
# run.sh has stood up filesystem/single and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1, COMMON_SH, JUNIT_OUTPUT_DIR, DTF_SLOT.
#
# THREAT/REGRESSION (#2522 bounded half): the download epilogue's stats/audit
# writes were per-request `tokio::spawn`s -- unbounded task + pool-connection
# growth under a flood with a slow event store. The fix routes both through a
# bounded queue + a FIXED flush-worker pool (batch INSERT, shed on overflow).
# This oracle makes the event store slow (pg_sleep trigger on
# download_statistics), floods the real maven GET path, and asserts:
#   (1) byte plane unaffected: every GET returns 200 + exact bytes, promptly;
#   (2) BOUNDED: concurrent `INSERT INTO download_statistics` backends sampled
#       from pg_stat_activity during the flood never exceed the worker bound;
#   (3) rows still eventually land once the sink recovers; HEAD lands none.
# On the unbounded image, (2) climbs toward min(FLOOD, pool_max=50) -> RED.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-${DTF_SLOT:-x}-$$"
REPO="bdd2522-${SUF}"
COORD="com/example/lib/1.0/lib-1.0-${SUF}.jar"
CONTENT="bounded-download-dispatch-2522-${SUF}"
FLOOD=80              # concurrent GETs, >> worker bound, > default worker count
SINK_SLEEP="0.3"      # per-row pg_sleep in the injected trigger (slow sink)
WORKER_BOUND=4        # fixed flush workers = 2; assert <= 4 for margin
SAMPLES=90            # pg_stat_activity samples over ~ the flood window

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# Concurrent backends actively running a download_statistics INSERT (excludes
# our own sampling backend). Matches both the per-row and the batched form.
active_stat_inserts() {
  psql_q "SELECT COUNT(*) FROM pg_stat_activity
          WHERE state = 'active'
            AND query ILIKE '%INSERT INTO download_statistics%'
            AND pid <> pg_backend_pid();"
}

dl_rows() {
  psql_q "SELECT COUNT(*) FROM download_statistics ds
          JOIN artifacts a ON a.id = ds.artifact_id
          WHERE a.repository_id = (SELECT id FROM repositories WHERE key='${REPO}');"
}

# Poll dl_rows until it reaches $1 or the budget (~60s: batch flush through the
# still-draining slow trigger takes seconds-per-batch) is exhausted.
poll_dl_rows() {
  local want="$1" last="-1" i
  for i in $(seq 1 120); do
    last="$(dl_rows)"
    [[ "$last" =~ ^[0-9]+$ ]] && [ "$last" -ge "$want" ] && { echo "$last"; return 0; }
    sleep 0.5
  done
  echo "$last"
}

begin_suite "bounded-download-dispatch-2522"

# --- setup: repo + one hosted artifact ---------------------------------------
auth_admin

begin_test "setup: create a local maven repo and upload one hosted artifact"
setup_ok=1
api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}" \
  >/dev/null 2>&1 || setup_ok=0
up_code="$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" --data-binary "$CONTENT" \
  "${BASE_URL}/maven/${REPO}/${COORD}" 2>/dev/null || echo 000)"
art_id="$(psql_q "SELECT id FROM artifacts
          WHERE repository_id=(SELECT id FROM repositories WHERE key='${REPO}') AND is_deleted=false LIMIT 1;")"
if [ "$setup_ok" = "1" ] && [ "$up_code" = "201" ] && [ -n "$art_id" ]; then
  pass "repo created, artifact uploaded (HTTP ${up_code}, id=${art_id})"
else
  fail "setup failed (repo_ok=${setup_ok} upload=${up_code} art_id='${art_id}')"
  end_suite
fi

# --- inject the slow event-store sink ----------------------------------------
begin_test "inject slow sink: BEFORE INSERT pg_sleep(${SINK_SLEEP}) trigger on download_statistics"
trig_ok=1
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -q -c "
  CREATE OR REPLACE FUNCTION dtf_slow_dl_2522() RETURNS trigger AS \$\$
  BEGIN PERFORM pg_sleep(${SINK_SLEEP}); RETURN NEW; END \$\$ LANGUAGE plpgsql;
  DROP TRIGGER IF EXISTS dtf_slow_dl_2522_trg ON download_statistics;
  CREATE TRIGGER dtf_slow_dl_2522_trg BEFORE INSERT ON download_statistics
    FOR EACH ROW EXECUTE FUNCTION dtf_slow_dl_2522();" >/dev/null 2>&1 || trig_ok=0
if [ "$trig_ok" = "1" ]; then pass "slow-sink trigger installed"; else
  fail "could not install the slow-sink trigger"; end_suite; fi

# --- flood + sample: byte plane fast AND side-effect concurrency bounded -----
begin_test "flood ${FLOOD} GETs vs slow sink: all 200 + exact bytes, promptly"
FLOOD_DIR="$(mktemp -d)"
for i in $(seq 1 "$FLOOD"); do
  ( code="$(curl -s -o "${FLOOD_DIR}/body.$i" -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}/maven/${REPO}/${COORD}" 2>/dev/null || echo 000)"
    echo "$code" > "${FLOOD_DIR}/code.$i" ) &
done

# Sample the bounded property WHILE the flood (and its deferred flushes) runs.
max_seen=0
for _ in $(seq 1 "$SAMPLES"); do
  now="$(active_stat_inserts)"
  [[ "$now" =~ ^[0-9]+$ ]] && [ "$now" -gt "$max_seen" ] && max_seen="$now"
  sleep 0.1
done
wait

flood_bad=0
for i in $(seq 1 "$FLOOD"); do
  code="$(cat "${FLOOD_DIR}/code.$i" 2>/dev/null || echo 000)"
  body="$(cat "${FLOOD_DIR}/body.$i" 2>/dev/null || echo '')"
  { [ "$code" = "200" ] && [ "$body" = "$CONTENT" ]; } || flood_bad=$((flood_bad + 1))
done
rm -rf "$FLOOD_DIR"
if [ "$flood_bad" = "0" ]; then
  pass "all ${FLOOD} floods served 200 with exact bytes despite the slow sink"
else
  fail "${flood_bad}/${FLOOD} flood downloads failed or returned wrong bytes"
fi

begin_test "BOUNDED: concurrent download_statistics INSERT backends <= ${WORKER_BOUND} during the flood"
if [ "$max_seen" -le "$WORKER_BOUND" ]; then
  pass "max concurrent stats-INSERT backends = ${max_seen} (bound ${WORKER_BOUND}; unbounded image climbs toward pool_max=50)"
else
  fail "side-effect concurrency is UNBOUNDED: ${max_seen} concurrent stats-INSERT backends (> ${WORKER_BOUND}) -- per-request spawn regression (#2522)"
fi

# --- sink recovers: rows eventually land; HEAD lands none --------------------
begin_test "sink recovered: every flood row eventually lands (batched, polled)"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -q -c \
  "DROP TRIGGER IF EXISTS dtf_slow_dl_2522_trg ON download_statistics;" >/dev/null 2>&1
final="$(poll_dl_rows "$FLOOD")"
if [[ "$final" =~ ^[0-9]+$ ]] && [ "$final" -ge "$FLOOD" ]; then
  pass "download_statistics reached ${final} rows (>= ${FLOOD}) after recovery"
else
  fail "rows never landed: ${final}/${FLOOD} after the poll budget (writes lost, not just deferred)"
fi

begin_test "HEAD still records nothing (no body => no row, #2260)"
before="$(dl_rows)"
head_code="$(curl -s -I -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/maven/${REPO}/${COORD}" 2>/dev/null || echo 000)"
sleep 2
after="$(dl_rows)"
if [ "$head_code" = "200" ] && [ "$after" = "$before" ]; then
  pass "HEAD returned 200 and added no download_statistics row (${before} -> ${after})"
else
  fail "HEAD contract broken (code=${head_code} rows ${before} -> ${after})"
fi

# --- batching must not amplify loss (red-team follow-up findings) ------------
# Finding 1: an oversized User-Agent (601 chars vs VARCHAR(512)) used to fail
# the whole batched INSERT (SQLSTATE 22001), silently dropping every co-batched
# legit row. Fixed by clamping the UA to the column width (capture + insert
# build). All co-batched rows AND the long-UA row (truncated) must persist.
begin_test "poison UA: 601-char User-Agent co-batched with legit GETs loses NOTHING"
base_rows="$(dl_rows)"
LONG_UA="$(printf 'P%.0s' $(seq 1 601))"
for i in $(seq 1 10); do
  ( curl -s -o /dev/null --max-time 10 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}/maven/${REPO}/${COORD}" >/dev/null 2>&1 ) &
done
curl -s -o /dev/null --max-time 10 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -A "$LONG_UA" "${BASE_URL}/maven/${REPO}/${COORD}" >/dev/null 2>&1 &
wait
want=$((base_rows + 11))
got="$(poll_dl_rows "$want")"
ua_len="$(psql_q "SELECT MAX(LENGTH(user_agent)) FROM download_statistics ds
        JOIN artifacts a ON a.id = ds.artifact_id
        WHERE a.repository_id = (SELECT id FROM repositories WHERE key='${REPO}');")"
if [[ "$got" =~ ^[0-9]+$ ]] && [ "$got" -ge "$want" ] && [ "$ua_len" = "512" ]; then
  pass "all 11 rows persisted (${base_rows} -> ${got}); oversized UA stored clamped to 512"
else
  fail "poison UA amplified loss or was not clamped (rows ${base_rows} -> ${got}, want ${want}; max ua_len=${ua_len}, want 512)"
fi

# Finding 2: rows the DB rejects at flush time must leave a metric trace and
# must not take co-batched neighbors with them. Inject a row-level poison the
# clamp cannot prevent (a trigger that RAISEs for one marker UA), co-batch it
# with legit GETs, and assert: neighbors persist (split-batch fallback), and
# ak_download_events_dropped_total{reason="flush_failed"} counts the loss.
begin_test "flush-failure: poison row loses only itself and is COUNTED (flush_failed metric)"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -q -c "
  CREATE OR REPLACE FUNCTION dtf_poison_dl_2522() RETURNS trigger AS \$\$
  BEGIN
    IF NEW.user_agent = 'dtf-poison-2522' THEN RAISE EXCEPTION 'dtf poison row'; END IF;
    RETURN NEW;
  END \$\$ LANGUAGE plpgsql;
  DROP TRIGGER IF EXISTS dtf_poison_dl_2522_trg ON download_statistics;
  CREATE TRIGGER dtf_poison_dl_2522_trg BEFORE INSERT ON download_statistics
    FOR EACH ROW EXECUTE FUNCTION dtf_poison_dl_2522();" >/dev/null 2>&1
base_rows="$(dl_rows)"
for i in $(seq 1 10); do
  ( curl -s -o /dev/null --max-time 10 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}/maven/${REPO}/${COORD}" >/dev/null 2>&1 ) &
done
curl -s -o /dev/null --max-time 10 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -A "dtf-poison-2522" "${BASE_URL}/maven/${REPO}/${COORD}" >/dev/null 2>&1 &
wait
want=$((base_rows + 10))   # the 10 innocents; the poison row is lost by design
got="$(poll_dl_rows "$want")"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -q -c \
  "DROP TRIGGER IF EXISTS dtf_poison_dl_2522_trg ON download_statistics;" >/dev/null 2>&1
flush_failed="$(curl -s --max-time 10 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null \
  | grep 'ak_download_events_dropped_total' | grep 'reason="flush_failed"' \
  | grep -oE '[0-9]+$' | head -1)"
if [[ "$got" =~ ^[0-9]+$ ]] && [ "$got" -ge "$want" ] \
   && [[ "$flush_failed" =~ ^[0-9]+$ ]] && [ "$flush_failed" -ge 1 ]; then
  pass "10/10 innocent co-batched rows persisted (${base_rows} -> ${got}); flush_failed metric = ${flush_failed}"
else
  fail "poison row took neighbors or left no trace (rows ${base_rows} -> ${got}, want ${want}; flush_failed='${flush_failed}')"
fi

end_suite
