#!/usr/bin/env bash
# =============================================================================
# tiers/repo-delete-reclaims-storage/oracle.sh -- #4833 discriminating oracle
# =============================================================================
# 1. Repos A, B, C, D (generic/local). The same random payload goes to A and
#    B; a unique payload to A only. Another shared payload goes to C and D.
# 2. DELETE repo A. Gate: nothing left under A's storage path (RED on 1.11.3:
#    the shared payload's file stays). Controls: A's unique file is gone, B
#    downloads the shared payload byte-exact and its file is on disk.
# 3. Storage GC dry run reports nothing to reclaim, live run leaves A's tree
#    empty (on 1.11.3 GC cannot see the leaked file, so it stays).
# 4. Trash C's copy (DELETE artifact), run storage GC. Gate: C's file is gone
#    from C's tree (RED on 1.11.3: D's live row shielded it). Control: D's
#    file is on disk and downloads byte-exact.
# 5. DELETE B (last holder of the first payload): B's tree is empty (both).
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, COMMON_SH, RUN_ID.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
BC="${DB_CONTAINER%-db}-backend"
SFX="${RUN_ID:-$$}"
SFX="$(printf '%s' "$SFX" | tr -cd 'a-z0-9' | tail -c 8)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

jqr(){ jq -r "$1" 2>/dev/null; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }
files_under(){ docker exec "$BC" /usr/bin/find "$1" -type f 2>/dev/null | sort; }
count_under(){ files_under "$1" | grep -c . ; }
indent(){ sed "s/^/     $1/"; }

begin_suite "repo-delete-reclaims-storage"

TOK=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u admin --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" \
  | jqr '.access_token // .token // empty')
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; exit 1; fi
AH="Authorization: Bearer $TOK"

mkrepo(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories" -H "$AH" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$1" '{key:$k,name:$k,format:"generic",repo_type:"local"}')"; }
upload(){ curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$1/artifacts/$2" \
  -H "$AH" -H 'Content-Type: application/octet-stream' --data-binary @"$3"; }
download(){ curl -s -o "$3" -w '%{http_code}' "$BASE/api/v1/repositories/$1/download/$2" -H "$AH"; }
storage_path(){ psql_q "SELECT storage_path FROM repositories WHERE key='$1'" | tr -d '[:space:]'; }
gc(){ curl -s -X POST "$BASE/api/v1/admin/storage-gc" -H "$AH" -H 'Content-Type: application/json' \
  -d "{\"dry_run\":$1}"; }

A="rdr-a-$SFX"; B="rdr-b-$SFX"; C="rdr-c-$SFX"; D="rdr-d-$SFX"
head -c 2097152 /dev/urandom > "$WORK/shared.bin"
head -c 524288 /dev/urandom > "$WORK/only-a.bin"
head -c 1048576 /dev/urandom > "$WORK/pair.bin"
SH=$(sha256sum "$WORK/shared.bin" | cut -c1-64)
OA=$(sha256sum "$WORK/only-a.bin" | cut -c1-64)
PR=$(sha256sum "$WORK/pair.bin" | cut -c1-64)

# ---------------------------------------------------------------------------
begin_test "Setup: four generic repositories, shared and unique payloads on disk"
F=0
for r in "$A" "$B" "$C" "$D"; do
  code=$(mkrepo "$r"); [ "$code" = "200" ] || [ "$code" = "201" ] || { echo "   create $r -> $code"; F=1; }
done
put_ok(){
  local code; code=$(upload "$1" "$2" "$WORK/$2")
  [ "$code" = "200" ] || [ "$code" = "201" ] || { echo "   upload $1/$2 -> $code"; F=1; }
}
put_ok "$A" shared.bin; put_ok "$B" shared.bin; put_ok "$A" only-a.bin
put_ok "$C" pair.bin; put_ok "$D" pair.bin
PA=$(storage_path "$A"); PB=$(storage_path "$B"); PC=$(storage_path "$C"); PD=$(storage_path "$D")
echo "-- storage paths: A=$PA B=$PB C=$PC D=$PD"
echo "-- files under A before delete:"; files_under "$PA" | indent ""
NA=$(count_under "$PA"); NB=$(count_under "$PB")
[ "$NA" = "2" ] || { echo "   expected 2 files under A, got $NA"; F=1; }
[ "$NB" = "1" ] || { echo "   expected 1 file under B, got $NB"; F=1; }
[ -n "$PA" ] && [ "$PA" != "$PB" ] || { echo "   A and B must have distinct storage paths"; F=1; }
if [ "$F" -eq 0 ]; then pass; else fail_fatal "setup failed"; exit 1; fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: deleting repo A purges its unique file and leaves repo B's copy served"
F=0
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/v1/repositories/$A" -H "$AH")
echo "-- DELETE $A -> $code"
[ "$code" = "200" ] || [ "$code" = "204" ] || F=1
# The purge runs in a background task after the DB delete.
for _ in $(seq 1 20); do
  files_under "$PA" | grep -q "$OA" || break
  sleep 1
done
files_under "$PA" | grep -q "$OA" && { echo "   A's unique file still on disk"; F=1; }
code=$(download "$B" shared.bin "$WORK/b.out")
cmp -s "$WORK/b.out" "$WORK/shared.bin" || { echo "   B download -> $code, not byte-exact"; F=1; }
files_under "$PB" | grep -q "$SH" || { echo "   B's copy is missing from $PB"; F=1; }
if [ "$F" -eq 0 ]; then pass; else fail "repo delete control failed"; fi

# ---------------------------------------------------------------------------
begin_test "FIX #4833: no file is left under deleted repo A's storage path"
sleep 2
LEFT=$(files_under "$PA")
if [ -z "$LEFT" ]; then
  pass
else
  printf '%s\n' "$LEFT" | indent "leaked: "
  fail "repository delete left the shared payload's file under $PA (#4833)" "leaked=$(echo "$LEFT" | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
begin_test "FIX #4833: storage GC has nothing left to find, and A's tree stays empty after a live pass"
F=0
DRY=$(gc true); echo "-- dry run: $DRY"
DK=$(echo "$DRY" | jqr '.storage_keys_deleted // empty')
[ "$DK" = "0" ] || { echo "   dry run reports $DK keys to delete (expected 0)"; F=1; }
LIVE=$(gc false); echo "-- live run: $LIVE"
echo "$LIVE" | jq -e '.errors | length == 0' >/dev/null 2>&1 || { echo "   GC reported errors"; F=1; }
LEFT=$(files_under "$PA")
[ -z "$LEFT" ] || { printf '%s\n' "$LEFT" | indent "still on disk: "; F=1; }
files_under "$PB" | grep -q "$SH" || { echo "   GC removed B's live copy"; F=1; }
if [ "$F" -eq 0 ]; then pass; else fail "storage GC does not account for the deleted repository's file (#4833)"; fi

# ---------------------------------------------------------------------------
begin_test "FIX #4833 (GC): a trashed copy is reclaimed from repo C while repo D serves its own copy"
F=0
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/v1/repositories/$C/artifacts/pair.bin" -H "$AH")
echo "-- DELETE $C/pair.bin -> $code"
DEL=$(psql_q "SELECT is_deleted FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$C' AND a.path='pair.bin'" | tr -d '[:space:]')
echo "-- C row is_deleted='$DEL' (t = trashed, empty = hard-deleted)"
LIVE=$(gc false); echo "-- live run: $LIVE"
LEFT=$(files_under "$PC")
[ -z "$LEFT" ] || { printf '%s\n' "$LEFT" | indent "still on disk: "; F=1; }
if [ "$F" -eq 0 ]; then pass; else fail "storage GC kept a trashed filesystem copy because another repository holds the same key (#4833)"; fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: repo D's copy of the shared key is on disk and served byte-exact"
F=0
files_under "$PD" | grep -q "$PR" || { echo "   D's file is missing"; F=1; }
code=$(download "$D" pair.bin "$WORK/d.out")
cmp -s "$WORK/d.out" "$WORK/pair.bin" || { echo "   D download -> $code, not byte-exact"; F=1; }
if [ "$F" -eq 0 ]; then pass; else fail "GC over-deleted repo D's copy"; fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: deleting repo B (last holder) empties its tree"
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/v1/repositories/$B" -H "$AH")
for _ in $(seq 1 20); do [ -z "$(files_under "$PB")" ] && break; sleep 1; done
LEFT=$(files_under "$PB")
if [ "$code" = "200" ] && [ -z "$LEFT" ]; then pass; else fail "DELETE $B -> $code, left: $LEFT"; fi

for r in "$C" "$D"; do
  curl -s -o /dev/null -X DELETE "$BASE/api/v1/repositories/$r" -H "$AH"
done

end_suite
