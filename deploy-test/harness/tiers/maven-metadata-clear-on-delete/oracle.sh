#!/usr/bin/env bash
# =============================================================================
# tiers/maven-metadata-clear-on-delete/oracle.sh — Maven metadata refresh on
# artifact delete (#2845), filesystem storage.
# =============================================================================
# Discriminating oracle for the group/artifact `maven-metadata.xml` after a
# version is deleted.
#
# Background (api/handlers/maven.rs::fetch_maven_metadata_bytes): `mvn deploy`
# uploads a verbatim group/artifact `maven-metadata.xml`; the download path
# serves that stored document in preference to dynamic generation. The delete
# handler (repositories.rs::delete_artifact) soft-deletes the artifact rows but,
# pre-#2845, left the stored `maven-metadata.xml` in place — so the served
# metadata kept advertising the removed version. #2845 clears the stored
# document on delete, so the next GET regenerates the list from the live rows.
#
# Fixture: create a maven/local repo, publish versions 1.0.0 and 2.0.0 (pom +
# jar via the Maven PUT handler) plus the verbatim maven-metadata.xml listing
# both, then delete every stored file of 2.0.0 via the artifact delete API.
#
# Asserts (GET /maven/<repo>/<group>/<artifact>/maven-metadata.xml):
#   * BASELINE (before delete): both 1.0.0 and 2.0.0 are listed.
#   * FIXED (#2845): 2.0.0 is ABSENT from <versions>, 1.0.0 is present, and
#     <latest>/<release> == 1.0.0.
#     Pre-#2845: 2.0.0 is STILL listed (and still <latest>/<release>) -> FAIL.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SUF="$RANDOM$RANDOM"
REPO="mmd$SUF"
GID="com/example/del$SUF"                         # group path (slashes)
AID="demo"                                        # artifactId
GPATH="$GID/$AID"                                 # group/artifact base path
METAPATH="$GPATH/maven-metadata.xml"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }

# maven_put <token> <path> <body> -> echoes HTTP code
maven_put(){
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$REPO/$1" \
    -H "Authorization: Bearer $2" --data-binary "$3"
}

pom(){ printf '<project><modelVersion>4.0.0</modelVersion><groupId>com.example.del%s</groupId><artifactId>%s</artifactId><version>%s</version></project>' "$SUF" "$AID" "$1"; }

begin_suite "maven-metadata-clear-on-delete-filesystem"

begin_test "Deleting a Maven version refreshes maven-metadata.xml so the removed version is no longer advertised (#2845)"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then fail "admin login failed at $BASE"; end_suite; exit 1; fi

# maven/local repo
curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null

# Publish 1.0.0 and 2.0.0 (pom + jar).
for V in 1.0.0 2.0.0; do
  c=$(maven_put "$GPATH/$V/$AID-$V.pom" "$TOK" "$(pom "$V")")
  [ "$c" = "201" ] || { fail "PUT pom $V returned HTTP $c (expected 201)"; end_suite; exit 1; }
  c=$(maven_put "$GPATH/$V/$AID-$V.jar" "$TOK" "jarbytes-$V")
  [ "$c" = "201" ] || { fail "PUT jar $V returned HTTP $c (expected 201)"; end_suite; exit 1; }
done

# Publish the verbatim maven-metadata.xml listing both, as the deploy plugin does.
STORED='<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example.del'"$SUF"'</groupId>
  <artifactId>'"$AID"'</artifactId>
  <versioning>
    <latest>2.0.0</latest>
    <release>2.0.0</release>
    <versions>
      <version>1.0.0</version>
      <version>2.0.0</version>
    </versions>
    <lastUpdated>20260101000000</lastUpdated>
  </versioning>
</metadata>'
c=$(maven_put "$METAPATH" "$TOK" "$STORED")
[ "$c" = "201" ] || { fail "PUT maven-metadata.xml returned HTTP $c (expected 201)"; end_suite; exit 1; }

# Baseline: the stored document is served and lists both versions.
BEFORE=$(curl -s "$BASE/maven/$REPO/$METAPATH" -H "Authorization: Bearer $TOK")
if ! echo "$BEFORE" | grep -q "<version>2.0.0</version>" || ! echo "$BEFORE" | grep -q "<version>1.0.0</version>"; then
  fail "baseline maven-metadata.xml did not list both versions; got: $BEFORE"; end_suite; exit 1
fi
echo "-- baseline lists 1.0.0 and 2.0.0 (ok)"

# Delete every stored file of 2.0.0 via the artifact delete API (web-UI path).
for F in "$AID-2.0.0.pom" "$AID-2.0.0.jar"; do
  c=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    "$BASE/api/v1/repositories/$REPO/artifacts/$GPATH/2.0.0/$F" \
    -H "Authorization: Bearer $TOK")
  [ "$c" = "200" ] || [ "$c" = "204" ] || { fail "DELETE $F returned HTTP $c (expected 200/204)"; end_suite; exit 1; }
done
echo "-- deleted 2.0.0 pom + jar"

# The discriminating GET: after delete, 2.0.0 must be gone and latest/release
# must fall back to the surviving 1.0.0.
AFTER=$(curl -s "$BASE/maven/$REPO/$METAPATH" -H "Authorization: Bearer $TOK")
echo "-- maven-metadata.xml after delete:"
echo "$AFTER" | sed 's/^/     /'

if echo "$AFTER" | grep -q "<version>2.0.0</version>"; then
  fail "deleted version 2.0.0 is STILL advertised in maven-metadata.xml (pre-#2845)"
elif ! echo "$AFTER" | grep -q "<version>1.0.0</version>"; then
  fail "surviving version 1.0.0 disappeared from maven-metadata.xml after delete"
elif ! echo "$AFTER" | grep -q "<latest>1.0.0</latest>"; then
  fail "<latest> was not refreshed to the surviving 1.0.0 (still advertises the deleted version)"
elif ! echo "$AFTER" | grep -q "<release>1.0.0</release>"; then
  fail "<release> was not refreshed to the surviving 1.0.0 (still advertises the deleted version)"
else
  pass
fi

end_suite
