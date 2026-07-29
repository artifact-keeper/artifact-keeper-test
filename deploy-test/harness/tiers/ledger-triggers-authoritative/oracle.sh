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
# under-quota enforced upload 201, over-quota 507.
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
# Regression leg (same on both images): quota admission behaviour unchanged —
# under-quota enforced upload 201, over-quota 507.
# ---------------------------------------------------------------------------
begin_test "regression: enforced quota admission unchanged (201 under, 507 over)"

QREPO="ledgerq$SUF"
mkrepo "$QREPO" generic >/dev/null
QRID=$(repo_id "$QREPO")
psql_q "UPDATE repositories SET quota_bytes=1000 WHERE id='$QRID';" >/dev/null

put_generic(){ # <path> <nbytes> -> http code
  head -c "$2" /dev/zero | tr '\0' 'x' | \
    curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$QREPO/artifacts/$1" \
      "${AUTH[@]}" -H 'Content-Type: application/octet-stream' --data-binary @-
}
C1=$(put_generic "ok.bin" 600)
C2=$(put_generic "over.bin" 600)
echo "-- under-quota PUT -> $C1 ; over-quota PUT -> $C2"

if { [ "$C1" = "200" ] || [ "$C1" = "201" ]; } && [ "$C2" = "507" ]; then
  pass
else
  fail "quota admission behaviour changed (under=$C1 expected 201, over=$C2 expected 507)"
fi

end_suite
