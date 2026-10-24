#!/usr/bin/env bash
# =============================================================================
# tiers/storage-gc-bounded-deletes/oracle.sh
#   artifact-keeper#2524 (1.12.0): storage GC claims an orphan key in a short
#   transaction and deletes the object only after it committed, and a pass
#   honours STORAGE_GC_MAX_KEYS_PER_RUN (budget_exhausted in the result).
# See the manifest for the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SLOT_PREFIX="${DB_CONTAINER%-db}"
MINIO_CTR="${SLOT_PREFIX}-minio"
SHIM_CTR="${SLOT_PREFIX}-s3-slow-delete"
MC_IMAGE="ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z"   # pulled by storage.s3.yml
BUCKET="ak-artifacts"

BUDGET=500          # STORAGE_GC_MAX_KEYS_PER_RUN in profiles/gc.storage-budget.yml
SEEDED=2000         # orphan keys written with SQL
REAL=3              # orphan keys uploaded through the API, then deleted
HELD=8              # deletes the shim holds at the start of the first pass
HOLD_SECS=1.5       # how long each held delete waits
IDLE_MS=100         # an "idle in transaction" session older than this counts
SAMPLES=500         # pg_stat_activity samples, one every ~50 ms

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec -i "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -q >/dev/null 2>"$W/psql.err"; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
shim(){ docker exec "$SHIM_CTR" python3 -c "import urllib.request,sys; print(urllib.request.urlopen('http://127.0.0.1:9000/__shim/'+sys.argv[1], timeout=5).read().decode())" "$1" 2>/dev/null || true; }
# MinIO's root credentials are read from its container at run time.
MC_USER=""; MC_PASS=""
mcx(){ docker run --rm -i --network "container:$MINIO_CTR" --entrypoint sh "$MC_IMAGE" -c \
  "mc alias set local http://localhost:9000 '$MC_USER' '$MC_PASS' >/dev/null 2>&1 && $1" 2>/dev/null || true; }
obj_exists(){ # <storage key> -> yes | no
  mcx "mc stat 'local/${BUCKET}/$1' >/dev/null 2>&1 && echo yes || echo no" | tr -d '[:space:]'
}

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# http <method> <path> <outfile> [curl args...] -> HTTP code (admin bearer)
http(){
  local m="$1" u="$2" o="$3"
  shift 3
  rm -f "$o"
  curl -s --max-time 600 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $TOK" "$@" "$BASE$u" || true
  [ -f "$o" ] || : > "$o"
}
body(){ head -c 400 "$1" 2>/dev/null | tr -d '\n' || true; }
gc_pass(){ # <outfile> <true|false> -> HTTP code
  http POST /api/v1/admin/storage-gc "$1" -H 'Content-Type: application/json' -d "{\"dry_run\":$2}"
}
gen_put(){ http PUT "/api/v1/repositories/$1/artifacts/$2" "$W/o" -H 'Content-Type: application/octet-stream' --data-binary "@$3"; }
gen_get(){ http GET "/api/v1/repositories/$1/download/$2" "$3"; }
trashed_rows(){ psql_q "SELECT count(*) FROM artifacts WHERE repository_id='${REPO_ID}' AND is_deleted;"; }

# =============================================================================
begin_suite "storage-gc-bounded-deletes"

begin_test "setup: admin login, a hosted generic repository, ${REAL} uploaded-then-deleted artifacts, one live artifact, ${SEEDED} soft-deleted rows seeded with SQL"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(shim readyz)" != "ok" ]; then infra_fail "the slow-delete shim ${SHIM_CTR} is not answering (profiles/storage.s3-slow-delete.yml)"; end_suite; fi
MC_USER="$(docker exec "$MINIO_CTR" printenv MINIO_ROOT_USER 2>/dev/null || true)"
MC_PASS="$(docker exec "$MINIO_CTR" printenv MINIO_ROOT_PASSWORD 2>/dev/null || true)"
[ -n "$MC_USER" ] && [ -n "$MC_PASS" ] || { infra_fail "could not read the MinIO credentials from ${MINIO_CTR}"; end_suite; }
SUF="${RUN_ID##*-}-$$"
REPO="gcb-${DTF_SLOT}-${SUF}"
REPO_ID="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')" | jqr '.id // empty')"
[ -n "$REPO_ID" ] || { infra_fail "could not create the generic repository ${REPO}"; end_suite; }
# Real objects: uploaded through the API (content-addressed keys, hex, so they
# sort before every seeded key and are claimed by the first pass), then
# deleted through the API (soft delete).
REAL_KEYS=()
for i in $(seq 1 "$REAL"); do
  head -c $((4096 + i)) /dev/urandom > "$W/r$i.bin"
  c="$(gen_put "$REPO" "gone/r$i.bin" "$W/r$i.bin")"
  [ "$c" = "201" ] || { infra_fail "upload gone/r$i.bin was HTTP ${c}: $(body "$W/o")"; end_suite; }
  REAL_KEYS+=("$(psql_q "SELECT storage_key FROM artifacts WHERE repository_id='${REPO_ID}' AND path='gone/r$i.bin';")")
  c="$(http DELETE "/api/v1/repositories/${REPO}/artifacts/gone/r$i.bin" "$W/o")"
  case "$c" in 200|204) ;; *) infra_fail "delete gone/r$i.bin was HTTP ${c}"; end_suite;; esac
done
head -c 8192 /dev/urandom > "$W/live.bin"
c="$(gen_put "$REPO" keep/live.bin "$W/live.bin")"
[ "$c" = "201" ] || { infra_fail "upload keep/live.bin was HTTP ${c}"; end_suite; }
LIVE_KEY="$(psql_q "SELECT storage_key FROM artifacts WHERE repository_id='${REPO_ID}' AND path='keep/live.bin';")"
# The bulk: soft-deleted rows, one distinct storage key each, deleted two days
# ago, with no object behind them (a delete of a missing key succeeds on S3).
psql_x <<SQL
INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
SELECT '${REPO_ID}', 'seed/' || lpad(g::text, 5, '0') || '.bin', lpad(g::text, 5, '0') || '.bin', 1024,
       lpad(to_hex(g), 64, '0'), 'application/octet-stream',
       'zz-dtf-gc-${SUF}/' || lpad(g::text, 5, '0'), true
FROM generate_series(1, ${SEEDED}) g;
UPDATE artifacts SET deleted_at = NOW() - interval '2 days' WHERE repository_id = '${REPO_ID}' AND is_deleted;
SQL
TOTAL="$(trashed_rows)"
note "repo ${REPO}: ${TOTAL} soft-deleted rows; real keys ${REAL_KEYS[*]}; live key ${LIVE_KEY}"
real_present=0; for k in "${REAL_KEYS[@]}"; do [ "$(obj_exists "$k")" = "yes" ] && real_present=$((real_present+1)); done
[ "$TOTAL" = "$((SEEDED + REAL))" ] || { infra_fail "seeding left ${TOTAL:-?} soft-deleted rows, expected $((SEEDED + REAL)): $(head -c 300 "$W/psql.err")"; end_suite; }
[ "$real_present" = "$REAL" ] || { infra_fail "only ${real_present} of ${REAL} uploaded objects are in MinIO before GC"; end_suite; }
pass

# =============================================================================
# (e) A dry run applies the budget: it reports at most one pass's worth and
# deletes nothing. RED before #2524: it reports every orphan key.
# =============================================================================
begin_test "FIX #2524: a dry-run pass reports at most STORAGE_GC_MAX_KEYS_PER_RUN=${BUDGET} keys and deletes nothing"
reset_case
c="$(gc_pass "$W/dry" true)"
dk="$(jqr '.storage_keys_deleted' < "$W/dry")"
note "dry run: HTTP ${c} $(jq -c '{dry_run,storage_keys_deleted,artifacts_removed,budget_exhausted}' < "$W/dry" 2>/dev/null || body "$W/dry"); rows after $(trashed_rows)"
[ "$c" = "200" ] || fail_g "dry run was HTTP ${c}"
[ "${dk:-0}" -gt 0 ] 2>/dev/null && [ "$dk" -le "$BUDGET" ] || fail_g "the dry run reports storage_keys_deleted=${dk}, expected 1..${BUDGET} (the whole orphan set without a budget)"
[ "$(trashed_rows)" = "$TOTAL" ] || fail_g "the dry run changed the soft-deleted row count ($(trashed_rows), was ${TOTAL})"
finish_case "#2524: a dry run ignores the per-pass key budget"

# =============================================================================
# The first live pass, with the first ${HELD} object deletes held for
# ${HOLD_SECS} s each by the shim, while pg_stat_activity is sampled.
# =============================================================================
shim "arm?n=${HELD}&delay=${HOLD_SECS}" >/dev/null
# One psql session runs every sample (each its own autocommit statement, so
# each reads a fresh pg_stat_activity snapshot) and prints
# <epoch>|<idle-in-transaction sessions older than IDLE_MS>|<their queries>.
{
  for _ in $(seq 1 "$SAMPLES"); do
    cat <<SQL
SELECT extract(epoch FROM clock_timestamp())::numeric(16,3) || '|' || count(*) || '|' ||
       coalesce(string_agg(pid || ':' || (extract(epoch FROM clock_timestamp() - state_change) * 1000)::int || 'ms:' ||
                           regexp_replace(left(query, 70), '\s+', ' ', 'g'), ' ; '), '')
FROM pg_stat_activity
WHERE datname = 'artifact_registry' AND pid <> pg_backend_pid()
  AND state = 'idle in transaction'
  AND clock_timestamp() - state_change > interval '${IDLE_MS} milliseconds';
SQL
    echo "SELECT pg_sleep(0.05);"
  done
} > "$W/sampler.sql"
docker exec -i "$DBC" psql -U registry -d artifact_registry -tAq < "$W/sampler.sql" > "$W/samples.txt" 2>/dev/null &
SAMPLER=$!
sleep 1
P1_T0="$(date +%s)"
c1="$(gc_pass "$W/p1" false)"
P1_SECS=$(( $(date +%s) - P1_T0 ))
wait "$SAMPLER" 2>/dev/null || true
STATS="$(shim stats)"
held="$(jqr '.delayed' <<<"$STATS")"; w0="$(jqr '.first_delay_at // 0' <<<"$STATS")"; w1="$(jqr '.last_delay_end // 0' <<<"$STATS")"
grep -a '|' "$W/samples.txt" > "$W/s.txt" || true
in_win="$(awk -F'|' -v a="$w0" -v b="$w1" '$1+0 >= a+0 && $1+0 <= b+0' "$W/s.txt" | wc -l | tr -d ' ')"
hit_win="$(awk -F'|' -v a="$w0" -v b="$w1" '$1+0 >= a+0 && $1+0 <= b+0 && $2+0 > 0' "$W/s.txt" | wc -l | tr -d ' ')"
hit_all="$(awk -F'|' '$2+0 > 0' "$W/s.txt" | wc -l | tr -d ' ')"
D1="$(jqr '.storage_keys_deleted' < "$W/p1")"; X1="$(jqr '.budget_exhausted // "null"' < "$W/p1")"
LEFT1="$(trashed_rows)"

begin_test "FIX #2524: no GC session sits idle in transaction while an object delete is held by the store"
reset_case
note "pass 1: HTTP ${c1} in ${P1_SECS}s; shim held ${held:-?} deletes (max $(jqr '.max_delayed_in_flight' <<<"$STATS") at once), window $(awk -v a="$w0" -v b="$w1" 'BEGIN{printf "%.1f", b-a}') s"
note "samples: $(wc -l < "$W/s.txt" | tr -d ' ') taken, ${in_win} inside the held-delete window; idle-in-transaction (>${IDLE_MS} ms) in ${hit_win} of them (${hit_all} over the whole pass)"
ex="$(awk -F'|' '$2+0 > 0 {print $3}' "$W/s.txt" 2>/dev/null | head -2 || true)"
[ -n "$ex" ] && note "e.g. ${ex}"
[ "$c1" = "200" ] || fail_g "the GC pass was HTTP ${c1}: $(body "$W/p1")"
if [ "${held:-0}" -lt "$HELD" ] 2>/dev/null || [ "${in_win:-0}" -lt 10 ]; then
  infra_fail "the shim held ${held:-0} of ${HELD} deletes and ${in_win:-0} samples fell inside the window: the pass did not go through the shim as set up" "$DETAIL"
else
  [ "$hit_win" = "0" ] || fail_g "${hit_win} of ${in_win} samples inside the held-delete window show a session idle in transaction (the object delete runs inside the per-key FOR UPDATE transaction)"
  finish_case "#2524: storage GC holds a transaction open across the object-store delete"
fi

begin_test "FIX #2524: the first pass claims at most ${BUDGET} keys, reports budget_exhausted=keys, and leaves the rest soft-deleted"
reset_case
note "pass 1: $(jq -c '{storage_keys_deleted,artifacts_removed,bytes_freed,budget_exhausted,errors:(.errors|length)}' < "$W/p1" 2>/dev/null || body "$W/p1"); soft-deleted rows ${TOTAL} -> ${LEFT1}"
[ "${D1:-0}" -gt 0 ] 2>/dev/null && [ "$D1" -le "$BUDGET" ] || fail_g "pass 1 reclaimed storage_keys_deleted=${D1}, expected 1..${BUDGET} (one pass reclaims every orphan without the budget)"
[ "$X1" = "keys" ] || fail_g "budget_exhausted is ${X1}, expected \"keys\""
B1="$(jqr '.bytes_freed' < "$W/p1")"
[ "${B1:-0}" -ge $(( ${D1:-0} * 1024 )) ] 2>/dev/null && [ "${B1:-0}" -gt 0 ] || fail_g "bytes_freed is ${B1}, expected at least 1024 per reclaimed key (every reclaimed row has size_bytes >= 1024)"
[ "${LEFT1:-0}" -eq $(( TOTAL - ${D1:-0} )) ] 2>/dev/null || fail_g "soft-deleted rows left ${LEFT1}, expected ${TOTAL} - ${D1} (one row per key)"
[ "${LEFT1:-0}" -ge $(( TOTAL - BUDGET )) ] 2>/dev/null || fail_g "only ${LEFT1} soft-deleted rows remain, expected about $(( TOTAL - BUDGET ))"
finish_case "#2524: storage GC ignores STORAGE_GC_MAX_KEYS_PER_RUN"

# (d) The real objects were claimed by pass 1 (their keys sort first): they
# are gone from MinIO and their rows are gone. The live artifact is untouched.
begin_test "CONTROL: the uploaded-then-deleted objects are gone from MinIO after their pass; the live artifact downloads byte-exact"
reset_case
gone=0; rows=0
for k in "${REAL_KEYS[@]}"; do
  [ "$(obj_exists "$k")" = "no" ] && gone=$((gone+1))
  n="$(psql_q "SELECT count(*) FROM artifacts WHERE storage_key='$k';")"
  rows=$(( rows + ${n:-1} ))
done
c="$(gen_get "$REPO" keep/live.bin "$W/live.get")"
note "real objects gone ${gone}/${REAL}, rows left ${rows}; live object $(obj_exists "$LIVE_KEY"), download HTTP ${c}"
[ "$gone" = "$REAL" ] || fail_g "$(( REAL - gone )) reclaimed objects are still in MinIO"
[ "$rows" = "0" ] || fail_g "${rows} rows of the reclaimed keys remain"
[ "$c" = "200" ] && [ "$(sha_of "$W/live.get")" = "$(sha_of "$W/live.bin")" ] || fail_g "the live artifact does not download byte-exact (HTTP ${c})"
finish_case "storage GC reclaimed the wrong objects"

# (c) The next pass reclaims the next budget's worth.
begin_test "FIX #2524: a second pass reclaims the next <= ${BUDGET} keys"
reset_case
c="$(gc_pass "$W/p2" false)"
D2="$(jqr '.storage_keys_deleted' < "$W/p2")"; X2="$(jqr '.budget_exhausted // "null"' < "$W/p2")"
LEFT2="$(trashed_rows)"
note "pass 2: HTTP ${c} $(jq -c '{storage_keys_deleted,budget_exhausted,errors:(.errors|length)}' < "$W/p2" 2>/dev/null || body "$W/p2"); rows ${LEFT1} -> ${LEFT2}"
[ "$c" = "200" ] || fail_g "pass 2 was HTTP ${c}"
[ "${D2:-0}" -gt 0 ] 2>/dev/null && [ "$D2" -le "$BUDGET" ] || fail_g "pass 2 reclaimed storage_keys_deleted=${D2}, expected 1..${BUDGET} (nothing is left once one pass took everything)"
[ "$X2" = "keys" ] || fail_g "pass 2 budget_exhausted is ${X2}, expected \"keys\""
[ "${LEFT2:-0}" -eq $(( LEFT1 - ${D2:-0} )) ] 2>/dev/null || fail_g "rows left ${LEFT2}, expected ${LEFT1} - ${D2}"
c="$(gen_get "$REPO" keep/live.bin "$W/live.get")"
[ "$c" = "200" ] && [ "$(sha_of "$W/live.get")" = "$(sha_of "$W/live.bin")" ] || fail_g "the live artifact no longer downloads byte-exact after pass 2 (HTTP ${c})"
finish_case "#2524: a later pass does not resume the budgeted backlog"

# (f) The budget stop is counted.
begin_test "FIX #2524: ak_storage_gc_budget_stops_total{budget=\"keys\"} counts the budgeted passes"
reset_case
curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/metrics" > "$W/metrics" || true
stops="$(awk '/^ak_storage_gc_budget_stops_total\{/ && /budget="keys"/ {print $NF}' "$W/metrics" | tail -1 || true)"
objs="$(awk '/^ak_storage_gc_objects_deleted_total\{/ && /orphan_keys/ {print $NF}' "$W/metrics" | tail -1 || true)"
note "ak_storage_gc_budget_stops_total{budget=\"keys\"}=${stops:-absent}; ak_storage_gc_objects_deleted_total{sweep=\"orphan_keys\"}=${objs:-absent}"
awk -v v="${stops:-0}" 'BEGIN{exit !(v >= 1)}' || fail_g "no ak_storage_gc_budget_stops_total{budget=\"keys\"} sample >= 1"
finish_case "#2524: budget stops are not counted"

end_suite
