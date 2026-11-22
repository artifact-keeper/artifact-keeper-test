#!/usr/bin/env bash
# =============================================================================
# tiers/ledger-triggers-authoritative/oracle.sh — usage-ledger authority gate
# (#2992), filesystem storage.
# =============================================================================
# Discriminating oracle: after EVERY mutation of the three usage source tables
# (artifacts / proxy_cache_artifacts / oci_blobs) the repository_usage_ledger
# counters must equal the authoritative live sums — the invariant migration 183
# enforces with row-level in-transaction triggers.
#
# Background: pre-183 only the background reconciler trued the ledger up; the
# format handlers (every `INSERT INTO artifacts` upload path), the proxy-cache
# catalog and the OCI blob writers never touched it, and the scattered
# soft/hard delete sites never decremented it. So a Maven upload through the
# handler leaves hosted_bytes stale (RED leg 1), and deletes can strand or
# phantom-free bytes. With 183 the trigger charges/decrements the exact
# contribution in the mutation's own transaction, so the invariant holds after
# every step.
#
#   Fixed (183):  ledger == live SUM after every mutation      -> PASS.
#   Pre-#2992:    ledger absent/0 after the handler upload     -> FAIL.
#
# Regression leg (same result on both images): quota admission is unchanged —
# under-quota enforced upload 201, over-quota refused (507 on the 1.11 line,
# 403 QUOTA_EXCEEDED from 1.12.0, backend #5915).
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SUF="$RANDOM$RANDOM"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

begin_suite "ledger-triggers-authoritative-2992"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

mkrepo(){ # <key> <format>
  curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"local\"}" \
    | jqr '.key // empty'
}
repo_id(){ psql_q "SELECT id FROM repositories WHERE key='$1';" | tr -d '[:space:]'; }

# The authoritative hosted sum (the reconciler / migration-171 rule).
live_hosted(){ psql_q "SELECT COALESCE(SUM(size_bytes),0) FROM artifacts \
  WHERE repository_id='$1' AND is_deleted=false AND storage_key NOT LIKE 'proxy-cache/%';" | tr -d '[:space:]'; }
ledger_hosted(){ psql_q "SELECT COALESCE((SELECT hosted_bytes FROM repository_usage_ledger \
  WHERE repository_id='$1'),0);" | tr -d '[:space:]'; }
ledger_proxy(){ psql_q "SELECT COALESCE((SELECT proxy_bytes FROM repository_usage_ledger \
  WHERE repository_id='$1'),0);" | tr -d '[:space:]'; }
ledger_oci(){ psql_q "SELECT COALESCE((SELECT oci_bytes FROM repository_usage_ledger \
  WHERE repository_id='$1'),0);" | tr -d '[:space:]'; }

# ---------------------------------------------------------------------------
# Leg 1 (F1, discriminator): a format-handler upload that bypasses the
# enforced admission path must still move the ledger, in its own transaction.
# ---------------------------------------------------------------------------
begin_test "handler (maven) upload charges hosted_bytes in-tx (#2992 F1)"

MREPO="ledgerbf$SUF"
mkrepo "$MREPO" maven >/dev/null
MRID=$(repo_id "$MREPO")
if [ -z "$MRID" ]; then
  fail "maven repo $MREPO was not created"; end_suite; exit 1
fi

head -c 4096 /dev/urandom >"/tmp/ledgerbf-$SUF.jar"
UP=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "${AUTH[@]}" \
  -H 'Content-Type: application/java-archive' \
  --data-binary "@/tmp/ledgerbf-$SUF.jar" \
  "$BASE/maven/$MREPO/com/example/lb/1.0/lb-1.0.jar")
rm -f "/tmp/ledgerbf-$SUF.jar"
echo "-- maven PUT -> HTTP $UP"

SUM=$(live_hosted "$MRID"); LED=$(ledger_hosted "$MRID")
echo "-- live hosted SUM=$SUM  ledger hosted_bytes=$LED"
if { [ "$UP" = "200" ] || [ "$UP" = "201" ]; } \
   && [ "${SUM:-0}" -ge 4096 ] && [ "$LED" = "$SUM" ]; then
  pass
else
  fail "handler upload left the ledger stale (HTTP $UP, live=$SUM ledger=$LED). Pre-#2992 nothing but the reconciler maintains hosted_bytes."
fi

# ---------------------------------------------------------------------------
# Leg 2 (F1/F2): raw catalog mutations — insert, soft-delete, hard delete —
# each keep ledger == live SUM exactly, and the counter never goes negative.
# ---------------------------------------------------------------------------
begin_test "raw insert/soft-delete/hard-delete keep ledger exact (#2992 F2)"

BASE_LED=$(ledger_hosted "$MRID")
psql_q "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
        VALUES (gen_random_uuid(), '$MRID', 'raw/f2-$SUF', 'f2', 600, repeat('a',64), 'application/octet-stream', 'cas/f2-$SUF', false);" >/dev/null
L1=$(ledger_hosted "$MRID"); S1=$(live_hosted "$MRID")
psql_q "UPDATE artifacts SET is_deleted=true WHERE repository_id='$MRID' AND path='raw/f2-$SUF';" >/dev/null
L2=$(ledger_hosted "$MRID"); S2=$(live_hosted "$MRID")
psql_q "DELETE FROM artifacts WHERE repository_id='$MRID' AND path='raw/f2-$SUF';" >/dev/null
L3=$(ledger_hosted "$MRID"); S3=$(live_hosted "$MRID")
echo "-- after insert: ledger=$L1 live=$S1 | after soft-delete: ledger=$L2 live=$S2 | after hard-delete: ledger=$L3 live=$S3 (baseline $BASE_LED)"

if [ "$L1" = "$S1" ] && [ "$L1" = "$((BASE_LED + 600))" ] \
   && [ "$L2" = "$S2" ] && [ "$L2" = "$BASE_LED" ] \
   && [ "$L3" = "$S3" ] && [ "$L3" = "$BASE_LED" ] && [ "$L3" -ge 0 ]; then
  pass
else
  fail "ledger drifted from the live sum across insert/soft-delete/hard-delete (insert $L1/$S1, soft $L2/$S2, hard $L3/$S3, baseline $BASE_LED): uncharged writes or phantom decrements survive."
fi

# ---------------------------------------------------------------------------
# Leg 3: proxy_cache_artifacts and oci_blobs charge their own components.
# ---------------------------------------------------------------------------
begin_test "proxy_cache_artifacts / oci_blobs charge proxy/oci components (#2992)"

psql_q "INSERT INTO proxy_cache_artifacts (id, repository_id, path, storage_key, metadata_key, size_bytes)
        VALUES (gen_random_uuid(), '$MRID', 'p/$SUF', 'proxy-cache/$MREPO/p-$SUF/__content__', 'proxy-cache/$MREPO/p-$SUF/__cache_meta__.json', 2500);" >/dev/null
psql_q "INSERT INTO oci_blobs (id, repository_id, digest, size_bytes, storage_key)
        VALUES (gen_random_uuid(), '$MRID', 'sha256:$SUF', 4000, 'oci-blobs/$SUF');" >/dev/null
LP=$(ledger_proxy "$MRID"); LO=$(ledger_oci "$MRID")
psql_q "DELETE FROM proxy_cache_artifacts WHERE repository_id='$MRID';" >/dev/null
psql_q "DELETE FROM oci_blobs WHERE repository_id='$MRID';" >/dev/null
LP2=$(ledger_proxy "$MRID"); LO2=$(ledger_oci "$MRID")
echo "-- charged proxy=$LP oci=$LO ; after delete proxy=$LP2 oci=$LO2"

if [ "$LP" = "2500" ] && [ "$LO" = "4000" ] && [ "$LP2" = "0" ] && [ "$LO2" = "0" ]; then
  pass
else
  fail "component charging wrong (proxy $LP->$LP2 expected 2500->0, oci $LO->$LO2 expected 4000->0)"
fi

# ---------------------------------------------------------------------------
# #3094: /admin/stats reported four counts with a COUNT(*) over the whole of
# artifacts, proxy_cache_artifacts, download_statistics and
# proxy_download_statistics on every call, so its cost grew with the
# catalogue and the download history. From 1.13.0 triggers keep those counts
# exact in row_count_deltas (migration 414).
#
# Deterministic proxy for "the endpoint no longer scans those tables": hold
# an ACCESS EXCLUSIVE lock on all four and ask for the stats. An endpoint that
# reads any of them waits for the lock (the request times out); one that
# reads only the trigger-kept counts answers at once. Request time is not
# measured; whether the request needs the locked tables at all is.
# CONTROL (both images): the counts equal the live COUNT(*) figures, before
# and after writes of every kind.
# ---------------------------------------------------------------------------
stats_counts(){ # -> "artifacts proxy downloads proxy_downloads" as /admin/stats reports them
  curl -s --max-time 30 "${AUTH[@]}" "$BASE/api/v1/admin/stats" \
    | jqr '"\(.total_artifacts) \(.proxy_artifact_count) \(.total_downloads - .proxy_download_count) \(.proxy_download_count)"' || true
}
live_counts(){
  psql_q "SELECT (SELECT COUNT(*) FROM artifacts WHERE is_deleted = false) || ' ' ||
    (SELECT COUNT(*) FROM proxy_cache_artifacts) || ' ' || (SELECT COUNT(*) FROM download_statistics) || ' ' ||
    (SELECT COUNT(*) FROM proxy_download_statistics);" || true
}
# The backend seeds its counts shortly after startup; an image without
# migration 414 has no seeds table, and the wait ends at once.
# common.sh may run under `set -e`: every probe below swallows its own failure
# and the assertion that reads the (possibly empty) value judges it.
seeds="-1"
if [ "$(psql_q "SELECT to_regclass('row_count_seeds') IS NOT NULL;" | tr -d '[:space:]' || true)" = "t" ]; then
  for _ in $(seq 1 60); do
    seeds=$(psql_q "SELECT count(*) FROM row_count_seeds;" | tr -d '[:space:]' || true)
    [ "${seeds:-0}" -ge 4 ] && break
    sleep 1
  done
fi
echo "-- row_count_seeds: ${seeds:-?} (-1 = no migration 414)"

begin_test "CONTROL: /admin/stats counts equal the live COUNT(*) figures through inserts, soft deletes, restores, hard deletes and downloads"
CR="ledgerstats$SUF"
mkrepo "$CR" generic >/dev/null
CRID=$(repo_id "$CR" || true)
S0=$(stats_counts); L0=$(live_counts)
psql_q "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
        SELECT '$CRID', 'st/' || g, 'st' || g, 10, repeat('c',64), 'application/octet-stream', 'cas/st-$SUF-' || g, g = 5
          FROM generate_series(1, 5) g;" >/dev/null || true
psql_q "UPDATE artifacts SET is_deleted = true WHERE repository_id = '$CRID' AND path IN ('st/1', 'st/2');" >/dev/null || true
psql_q "UPDATE artifacts SET is_deleted = false WHERE repository_id = '$CRID' AND path = 'st/2';" >/dev/null || true
psql_q "INSERT INTO download_statistics (artifact_id) SELECT id FROM artifacts WHERE repository_id = '$CRID';" >/dev/null || true
psql_q "DELETE FROM artifacts WHERE repository_id = '$CRID' AND path IN ('st/3', 'st/5');" >/dev/null || true
psql_q "INSERT INTO proxy_cache_artifacts (repository_id, path, storage_key, metadata_key, size_bytes)
        VALUES ('$CRID', 'pc/$SUF', 'proxy-cache/$CR/pc/__content__', 'proxy-cache/$CR/pc/__cache_meta__.json', 7);" >/dev/null || true
psql_q "INSERT INTO proxy_download_statistics (repository_id, path) VALUES ('$CRID', 'pc/$SUF');" >/dev/null || true
S1=$(stats_counts); L1=$(live_counts)
echo "-- before: stats [$S0] live [$L0]; after: stats [$S1] live [$L1]"
if [ -n "$S0" ] && [ "$S0" = "$L0" ] && [ "$S1" = "$L1" ] && [ "$S1" != "$S0" ]; then
  pass
else
  fail "/admin/stats counts differ from the live COUNT(*) figures (before stats [$S0] live [$L0]; after stats [$S1] live [$L1])"
fi

begin_test "FIX #3094: /admin/stats answers while artifacts, proxy_cache_artifacts, download_statistics and proxy_download_statistics are locked (it reads none of them)"
LOCK_TABLES="artifacts, proxy_cache_artifacts, download_statistics, proxy_download_statistics"
docker exec -e PGAPPNAME=dtf3094lock "$DBC" psql -U registry -d artifact_registry -q \
  -c "BEGIN; LOCK TABLE ${LOCK_TABLES} IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60); COMMIT;" \
  >/dev/null 2>&1 &
LOCKER=$!
held=""
for _ in $(seq 1 40); do
  held=$(psql_q "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
                  WHERE a.application_name = 'dtf3094lock' AND l.granted AND l.mode = 'AccessExclusiveLock'
                    AND l.relation IN ('artifacts'::regclass, 'proxy_cache_artifacts'::regclass,
                                       'download_statistics'::regclass, 'proxy_download_statistics'::regclass);" | tr -d '[:space:]' || true)
  [ "${held:-0}" = "4" ] && break
  sleep 0.5
done
W_STATS="$(mktemp)"
CODE=$(curl -s -o "$W_STATS" -w '%{http_code}' --max-time 8 "${AUTH[@]}" "$BASE/api/v1/admin/stats" || true)
GOT=$(jq -r '"\(.total_artifacts) \(.proxy_artifact_count)"' < "$W_STATS" 2>/dev/null || true)
rm -f "$W_STATS"
psql_q "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'dtf3094lock';" >/dev/null || true
wait "$LOCKER" 2>/dev/null || true
echo "-- locks held on ${held:-?}/4 tables; /admin/stats -> HTTP ${CODE} [${GOT}]"
if [ "${held:-0}" != "4" ]; then
  fail "could not take the four table locks (held ${held:-?}/4); the case did not run"
elif [ "$CODE" = "200" ] && [ -n "$GOT" ]; then
  pass
else
  fail "/admin/stats did not answer within 8 s while the four large tables were locked (HTTP ${CODE}): it still reads them with COUNT(*) on every call (#3094)"
fi

# ---------------------------------------------------------------------------
# Regression leg (same on both images): quota admission behaviour unchanged —
# under-quota enforced upload 201, over-quota refused: 507 on the 1.11 line,
# 403 {"code":"QUOTA_EXCEEDED"} from 1.12.0 (artifact-keeper#5915). A 403
# with any other code is an authorization refusal and fails.
# ---------------------------------------------------------------------------
begin_test "regression: enforced quota admission unchanged (201 under, 507 or 403 QUOTA_EXCEEDED over)"

QREPO="ledgerq$SUF"
mkrepo "$QREPO" generic >/dev/null
QRID=$(repo_id "$QREPO")
psql_q "UPDATE repositories SET quota_bytes=1000 WHERE id='$QRID';" >/dev/null

put_generic(){ # <path> <nbytes> -> http code; body in $W_QBODY
  head -c "$2" /dev/zero | tr '\0' 'x' | \
    curl -s -o "$W_QBODY" -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$QREPO/artifacts/$1" \
      "${AUTH[@]}" -H 'Content-Type: application/octet-stream' --data-binary @-
}
W_QBODY="$(mktemp)"
C1=$(put_generic "ok.bin" 600)
C2=$(put_generic "over.bin" 600)
C2_CODE=$(jq -r '.code // empty' < "$W_QBODY" 2>/dev/null || true)
rm -f "$W_QBODY"
echo "-- under-quota PUT -> $C1 ; over-quota PUT -> $C2 ${C2_CODE}"

if { [ "$C1" = "200" ] || [ "$C1" = "201" ]; } && \
   { [ "$C2" = "507" ] || { [ "$C2" = "403" ] && [ "$C2_CODE" = "QUOTA_EXCEEDED" ]; }; }; then
  pass
else
  fail "quota admission behaviour changed (under=$C1 expected 201, over=$C2 ${C2_CODE} expected 507 or 403 QUOTA_EXCEEDED)"
fi

end_suite
