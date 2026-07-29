#!/usr/bin/env bash
# =============================================================================
# tiers/storage-prefix-rollup/oracle.sh — per-prefix storage rollup gate (#2601)
# =============================================================================
# Discriminating oracle for the folder/path-tree usage rollup (epic #2056 P2).
#
# Feature under test:
#   * `repository_path_storage_stats` — materialized per-(repo, path-prefix)
#     rollup (logical/physical/file/blob per folder node), refreshed by the
#     storage-stats pass. #2601 also makes the admin-triggered
#     POST /api/v1/admin/storage-gc refresh the materializations (previously
#     only the *scheduled* GC pass did), which this oracle uses as its
#     deterministic refresh trigger.
#   * `GET /api/v1/repositories/{key}/storage/tree?prefix=&depth=` — reads the
#     cache only; returns the rooted node + descendant folder nodes.
#
# RED  (pre-fix image): the /storage/tree route does not exist -> 404.
# GREEN (fixed image):  200 + correct nested-prefix totals + dedup-aware
#                       physical figures.
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

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

begin_suite "storage-prefix-rollup"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"
  fail "admin login failed at $BASE"
  end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

mkrepo(){ # <key>
  curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" \
    | jqr '.key // empty'
}
upload(){ # <repo> <path> <nbytes>
  head -c "$3" /dev/zero | tr '\0' 'x' | \
    curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$1/artifacts/$2" \
      "${AUTH[@]}" -H 'Content-Type: application/octet-stream' --data-binary @-
}
# The fix wires the admin GC endpoint to refresh the materialized stats.
refresh_stats(){
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/admin/storage-gc" \
    "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"dry_run":false}'
}
tree(){ # <repo> [query]
  curl -s "${AUTH[@]}" "$BASE/api/v1/repositories/$1/storage/tree${2:+?$2}"
}
tree_status(){ # <repo> [query]
  curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/api/v1/repositories/$1/storage/tree${2:+?$2}"
}

# $RANDOM-based (a /dev/urandom|head pipe dies of SIGPIPE under pipefail).
RAND="$(( RANDOM % 90000 + 10000 ))$$"
REPO1="ptree-nested-$RAND"
REPO2="ptree-dedup-$RAND"

# ---------------------------------------------------------------------------
begin_test "GET /storage/tree exists and reports correct nested per-prefix rollup (#2601)"
FAILS=0
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); }

K=$(mkrepo "$REPO1")
[ "$K" = "$REPO1" ] || { fail "repo create failed for $REPO1"; end_suite; exit 1; }

# Nested layout: libs/app{100,50} + libs/core{25} + a root-level file {10}.
for spec in "libs/app/a.bin 100" "libs/app/b.bin 50" "libs/core/c.bin 25" "top.bin 10"; do
  P="${spec% *}"; N="${spec#* }"
  RC=$(upload "$REPO1" "$P" "$N")
  echo "-- upload $P ($N bytes): HTTP $RC"
  case "$RC" in 2*) : ;; *) fail_g "upload $P failed (HTTP $RC)";; esac
done

RC=$(refresh_stats)
echo "-- POST /admin/storage-gc (stats refresh trigger): HTTP $RC"
[ "$RC" = "200" ] || fail_g "admin storage-gc failed (HTTP $RC)"

ST=$(tree_status "$REPO1")
echo "-- GET /repositories/$REPO1/storage/tree: HTTP $ST"
if [ "$ST" != "200" ]; then
  fail_g "storage/tree endpoint missing or failing (HTTP $ST) — pre-#2601 image?"
else
  ROOT=$(tree "$REPO1")
  echo "-- root node: $(echo "$ROOT" | jq -c '.node' 2>/dev/null)"
  RL=$(echo "$ROOT" | jqr '.node.logical_bytes'); RF=$(echo "$ROOT" | jqr '.node.file_count')
  CAT=$(echo "$ROOT" | jqr '.computed_at')
  [ "$RL" = "185" ] || fail_g "root logical_bytes=$RL (want 185)"
  [ "$RF" = "4" ]   || fail_g "root file_count=$RF (want 4)"
  [ -n "$CAT" ] && [ "$CAT" != "null" ] || fail_g "computed_at is null after the GC-triggered refresh"
  # Immediate children of the root must include libs (175).
  LIBS_CHILD=$(echo "$ROOT" | jq -r '.children[] | select(.prefix=="libs") | .logical_bytes' 2>/dev/null)
  [ "$LIBS_CHILD" = "175" ] || fail_g "root child 'libs' logical=$LIBS_CHILD (want 175)"

  SUB=$(tree "$REPO1" "prefix=libs")
  SL=$(echo "$SUB" | jqr '.node.logical_bytes')
  [ "$SL" = "175" ] || fail_g "prefix=libs logical=$SL (want 175)"
  APP=$(echo "$SUB" | jq -r '.children[] | select(.prefix=="libs/app") | .logical_bytes' 2>/dev/null)
  CORE=$(echo "$SUB" | jq -r '.children[] | select(.prefix=="libs/core") | .logical_bytes' 2>/dev/null)
  echo "-- libs children: app=$APP core=$CORE"
  [ "$APP" = "150" ] || fail_g "libs/app logical=$APP (want 150)"
  [ "$CORE" = "25" ] || fail_g "libs/core logical=$CORE (want 25)"
  # Off-root listings must not carry the root-only unattributed figure.
  UB=$(echo "$SUB" | jq 'has("unattributed_bytes")' 2>/dev/null)
  [ "$UB" = "false" ] || fail_g "unattributed_bytes leaked on a non-root listing"
fi

if [ "$FAILS" -eq 0 ]; then pass; else fail "per-prefix rollup missing or wrong (see GATE-FAILs)"; fi

# ---------------------------------------------------------------------------
begin_test "Dedup: shared object counts once per node; children can exceed parent physical"
FAILS=0

K=$(mkrepo "$REPO2")
[ "$K" = "$REPO2" ] || { fail "repo create failed for $REPO2"; end_suite; exit 1; }

RID=$(psql_q "SELECT id FROM repositories WHERE key='$REPO2';" | tr -d '[:space:]')
echo "-- repo2 id: $RID"
if [ -z "$RID" ]; then
  fail "cannot resolve repository id for $REPO2"
else
  # One CAS object (same storage_key, 1000 bytes) referenced from two sibling
  # subtrees: x/ twice, y/ once — inserted at catalog level exactly as the
  # content-addressed write path stores it.
  CASKEY="cas/aa/bb/dedup-$RAND"
  for p in "x/one.bin" "x/two.bin" "y/three.bin"; do
    psql_q "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
            VALUES (gen_random_uuid(), '$RID', '$p', '$p', 1000, repeat('a',64), 'application/octet-stream', '$CASKEY', false);" >/dev/null
  done
  NROWS=$(psql_q "SELECT count(*) FROM artifacts WHERE repository_id='$RID';" | tr -d '[:space:]')
  echo "-- seeded artifact rows: $NROWS (want 3)"
  [ "$NROWS" = "3" ] || fail_g "seeding failed (rows=$NROWS)"

  RC=$(refresh_stats)
  [ "$RC" = "200" ] || fail_g "admin storage-gc failed (HTTP $RC)"

  ROOT=$(tree "$REPO2" "depth=2")
  echo "-- dedup root: $(echo "$ROOT" | jq -c '{node, children}' 2>/dev/null)"
  RL=$(echo "$ROOT" | jqr '.node.logical_bytes'); RP=$(echo "$ROOT" | jqr '.node.physical_bytes')
  RB=$(echo "$ROOT" | jqr '.node.blob_count')
  [ "$RL" = "3000" ] || fail_g "root logical=$RL (want 3000 = 3 refs x 1000)"
  [ "$RP" = "1000" ] || fail_g "root physical=$RP (want 1000: shared object counted ONCE)"
  [ "$RB" = "1" ]    || fail_g "root blob_count=$RB (want 1)"
  XP=$(echo "$ROOT" | jq -r '.children[] | select(.prefix=="x") | .physical_bytes' 2>/dev/null)
  XL=$(echo "$ROOT" | jq -r '.children[] | select(.prefix=="x") | .logical_bytes' 2>/dev/null)
  YP=$(echo "$ROOT" | jq -r '.children[] | select(.prefix=="y") | .physical_bytes' 2>/dev/null)
  echo "-- x: logical=$XL physical=$XP ; y: physical=$YP"
  [ "$XL" = "2000" ] || fail_g "x logical=$XL (want 2000)"
  [ "$XP" = "1000" ] || fail_g "x physical=$XP (want 1000: dedup within subtree)"
  [ "$YP" = "1000" ] || fail_g "y physical=$YP (want 1000)"
  # The dedup-savings signal: sum(children.physical) > parent.physical.
  if [ -n "$XP" ] && [ -n "$YP" ] && [ -n "$RP" ]; then
    [ $((XP + YP)) -gt "$RP" ] || fail_g "expected sum(children.physical)=$((XP+YP)) > root.physical=$RP"
  fi
fi

if [ "$FAILS" -eq 0 ]; then pass; else fail "dedup-aware per-prefix physical figures are wrong (see GATE-FAILs)"; fi

# ---------------------------------------------------------------------------
begin_test "Regression: repo-level /storage endpoint (#2559 P1) and artifact download still work"
FAILS=0

ST=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/api/v1/repositories/$REPO1/storage")
echo "-- GET /repositories/$REPO1/storage: HTTP $ST"
[ "$ST" = "200" ] || fail_g "repo-level storage endpoint broke (HTTP $ST)"

DL=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/api/v1/repositories/$REPO1/download/libs/app/a.bin")
echo "-- download libs/app/a.bin: HTTP $DL"
[ "$DL" = "200" ] || fail_g "artifact download regressed (HTTP $DL)"

if [ "$FAILS" -eq 0 ]; then pass; else fail "P1 storage endpoint or download path regressed"; fi

end_suite
