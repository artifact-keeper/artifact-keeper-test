#!/usr/bin/env bash
# =============================================================================
# tiers/maven-grouped-name-keyset/oracle.sh — Maven grouped listing keyset gate
# (#2723), filesystem storage.
# =============================================================================
# Discriminating oracle for the hosted/virtual Maven grouped LISTING path.
#
# Background (repositories.rs::list_artifacts_grouped_by_maven_component): the
# hosted/virtual `group_by=maven_component` listing used to fetch up to
# MAX_FETCH artifacts and group them in memory, paginating with page/per_page
# and advertising NO keyset cursor. #2723 routes that listing through the
# package-catalog SQL keyset (the same mechanism the remote/proxy branch uses):
# ordered `(name, version)` component keys come from `packages ⋈
# package_versions` (name == "groupId:artifactId"), and each page carries an
# opaque `next_cursor`.
#
# Fixture: a maven/local repo with two artifacts under distinct
# groupId:artifactId (`com.example:aaa…` and `com.example:zzz…`), each pushed
# via a real generic chunked upload.
#
# Asserts (walk the grouped listing one component per page via ?cursor=):
#   * page 1 component key == "com.example:aaa…"  (ascending order)
#   * page 1 emits a non-empty `next_cursor` and `has_more == true`   [FIXED]
#   * following that cursor returns the SECOND, DISTINCT component
#     "com.example:zzz…"                                              [FIXED]
#   Pre-#2723 listing: no `next_cursor` is emitted and `?cursor=` is ignored,
#   so page 2 repeats the first component -> FAIL.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SUF="$RANDOM$RANDOM"
REPO="mgnk$SUF"
GROUP="com.example"
GDIR="com/example"
VER="1.0.0"
AID1="aaa$SUF"                      # sorts before zzz… regardless of suffix
AID2="zzz$SUF"
GN1="$GROUP:$AID1"                  # expected page-1 grouped key
GN2="$GROUP:$AID2"                  # expected page-2 grouped key

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }

if command -v sha256sum >/dev/null 2>&1; then sha(){ sha256sum "$1" | awk '{print $1}'; }
else sha(){ shasum -a 256 "$1" | awk '{print $1}'; }; fi

# generic_chunked_upload <token> <repo_key> <artifact_path> <version> <file>
# POST /uploads -> PATCH chunk -> PUT complete. Echoes the finalize HTTP code.
generic_chunked_upload(){
  local tok="$1" repo="$2" path="$3" ver="$4" src="$5"
  local size csum sess body last
  size=$(wc -c <"$src"); csum=$(sha "$src")
  body=$(curl -s -X POST "$BASE/api/v1/uploads" -H "Authorization: Bearer $tok" \
    -H 'Content-Type: application/json' -d "{
      \"repository_key\":\"$repo\",
      \"artifact_path\":\"$path\",
      \"artifact_version\":\"$ver\",
      \"total_size\":$size,
      \"checksum_sha256\":\"$csum\",
      \"chunk_size\":1048576
    }")
  sess=$(echo "$body" | jqr '.session_id // .id // empty')
  if [ -z "$sess" ]; then echo "SESSION-FAIL: $body" >&2; echo "000"; return; fi
  last=$((size-1))
  curl -s -o /dev/null -X PATCH "$BASE/api/v1/uploads/$sess" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes 0-$last/$size" --data-binary "@$src" >/dev/null
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/uploads/$sess/complete" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json'
}

# grouped_page <token> <repo> [cursor] -> prints JSON body
grouped_page(){
  local tok="$1" repo="$2" cursor="${3:-}"
  local url="$BASE/api/v1/repositories/$repo/artifacts?group_by=maven_component&per_page=1"
  [ -n "$cursor" ] && url="$url&cursor=$cursor"
  curl -s "$url" -H "Authorization: Bearer $tok"
}

begin_suite "maven-grouped-name-keyset-filesystem"

begin_test "Hosted Maven grouped listing pages by catalog keyset, keyed on groupId:artifactId in stable order (#2723)"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then fail "admin login failed at $BASE"; end_suite; exit 1; fi

curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null

# minimal but structurally-valid jar (an empty ZIP: PK end-of-central-directory)
JAR="$(mktemp)"
printf 'PK\005\006\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' >"$JAR"

for spec in "$AID1" "$AID2"; do
  APATH="$GDIR/$spec/$VER/$spec-$VER.jar"
  FIN=$(generic_chunked_upload "$TOK" "$REPO" "$APATH" "$VER" "$JAR")
  echo "-- upload $spec -> HTTP $FIN"
  if [ "$FIN" != "200" ] && [ "$FIN" != "201" ]; then
    fail "upload of $spec did not finalize (HTTP $FIN); cannot evaluate keyset gate"
    rm -f "$JAR"; end_suite; exit 1
  fi
done
rm -f "$JAR"

# --- Page 1 (no cursor) ------------------------------------------------------
P1=$(grouped_page "$TOK" "$REPO")
K1=$(echo "$P1" | jqr '.components[0] | (.group_id + ":" + .artifact_id)')
CUR=$(echo "$P1" | jqr '.next_cursor // empty')
MORE=$(echo "$P1" | jqr '.has_more // empty')
echo "-- page1 key='${K1:-<none>}' has_more='${MORE:-<none>}' next_cursor='${CUR:0:16}...'"

if [ "$K1" != "$GN1" ]; then
  fail "page-1 grouped key is '${K1:-<none>}'; expected '$GN1' (groupId:artifactId, ascending)"
  end_suite; exit 1
fi

# PRIMARY discriminator: the keyset listing advertises a cursor. The pre-#2723
# in-memory path omits next_cursor entirely.
if [ -z "$CUR" ]; then
  fail "grouped listing emitted no next_cursor (pre-#2723 in-memory path); keyset paging is not active"
  end_suite; exit 1
fi

# --- Page 2 (follow the cursor) ---------------------------------------------
P2=$(grouped_page "$TOK" "$REPO" "$CUR")
K2=$(echo "$P2" | jqr '.components[0] | (.group_id + ":" + .artifact_id)')
echo "-- page2 key='${K2:-<none>}' (expect '$GN2', distinct from page1)"

if [ "$K2" = "$K1" ]; then
  fail "cursor page repeated the first component '$K2' (?cursor= ignored -> pre-#2723 in-memory path)"
  end_suite; exit 1
fi
if [ "$K2" != "$GN2" ]; then
  fail "cursor page returned '${K2:-<none>}'; expected the second grouped component '$GN2' in stable order"
  end_suite; exit 1
fi

pass

end_suite
