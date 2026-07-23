#!/usr/bin/env bash
# =============================================================================
# tiers/maven-grouped-name/oracle.sh — Maven grouped catalog name gate
# (#2723 / PR #2837), filesystem storage.
# =============================================================================
# Discriminating oracle for the Maven/Gradle grouped `packages.name`.
#
# Background (upload.rs::completed_package_catalog_entry): a Maven artifact
# pushed through the generic chunked-upload flow carries no replicated POM
# metadata, so the catalog `packages` row was keyed on the bare artifact
# name/filename. Grouped hosted/virtual listings key on `groupId:artifactId`, so
# the bare-named row split the component. #2723 derives the grouped name from
# the GAV path for Maven/Gradle repos.
#
# Fixture: create a maven/local repo and drive a real generic chunked upload of
# a small .jar at a GAV path `com/example/<artifactId>/<version>/<file>.jar`,
# then read the created `packages` row's `name`.
#
# Asserts:
#   * packages.name == "com.example:<artifactId>"   (fixed, #2723)
#     Pre-#2723: name == "<artifactId>-<version>.jar" (bare filename) -> FAIL.
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
REPO="mgn$SUF"
AID="mylib$SUF"                                  # artifactId (no separators)
VER="1.0.0"
FILE="$AID-$VER.jar"
APATH="com/example/$AID/$VER/$FILE"              # GAV layout
GROUPED="com.example:$AID"                       # expected grouped name
BARE="$FILE"                                     # pre-fix bare name

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

# sha256 helper
if command -v sha256sum >/dev/null 2>&1; then sha(){ sha256sum "$1" | awk '{print $1}'; }
else sha(){ shasum -a 256 "$1" | awk '{print $1}'; }; fi

# generic_chunked_upload <token> <repo_key> <artifact_path> <version> <file>
# Drives POST /uploads -> PATCH chunk -> PUT complete. Echoes the finalize HTTP
# code on the last line. Single-chunk (payload is tiny).
generic_chunked_upload(){
  local tok="$1" repo="$2" path="$3" ver="$4" src="$5"
  local size csum sess
  size=$(wc -c <"$src"); csum=$(sha "$src")
  local body
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
  local last=$((size-1))
  curl -s -o /dev/null -X PATCH "$BASE/api/v1/uploads/$sess" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes 0-$last/$size" --data-binary "@$src" >/dev/null
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/uploads/$sess/complete" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json'
}

begin_suite "maven-grouped-name-filesystem"

begin_test "Generic chunked upload of a Maven jar lists under the grouped groupId:artifactId catalog name (#2723)"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then fail "admin login failed at $BASE"; end_suite; exit 1; fi

# maven/local repo
curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null

# minimal but structurally-valid jar (an empty ZIP: PK end-of-central-directory)
JAR="$(mktemp)"
printf 'PK\005\006\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' >"$JAR"

FIN=$(generic_chunked_upload "$TOK" "$REPO" "$APATH" "$VER" "$JAR")
echo "-- generic chunked upload finalize -> HTTP $FIN"
if [ "$FIN" != "200" ] && [ "$FIN" != "201" ]; then
  fail "generic chunked upload did not finalize (HTTP $FIN); cannot evaluate the grouped-name gate"
  rm -f "$JAR"; end_suite; exit 1
fi
rm -f "$JAR"

# Read the catalog row name for this repo.
NAME=$(psql_q "SELECT p.name FROM packages p JOIN repositories r ON r.id=p.repository_id WHERE r.key='$REPO' ORDER BY p.created_at DESC LIMIT 1;" | tr -d '[:space:]')
echo "-- packages.name for $REPO: '${NAME:-<none>}'  (expect grouped '$GROUPED', pre-fix bare '$BARE')"

if [ "$NAME" = "$GROUPED" ]; then
  pass
elif [ "$NAME" = "$BARE" ]; then
  fail "catalog name is the bare filename '$NAME' (pre-#2723); expected grouped '$GROUPED'"
elif [ -z "$NAME" ]; then
  fail "no packages row was created for repo '$REPO' after the generic upload"
else
  fail "catalog name '$NAME' is neither the grouped '$GROUPED' nor the bare '$BARE'"
fi

end_suite
