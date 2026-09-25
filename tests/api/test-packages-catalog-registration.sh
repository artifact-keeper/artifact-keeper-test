#!/usr/bin/env bash
# test-packages-catalog-registration.sh -- catalog registration correctness
#
# Companions for artifact-keeper#4197 and #3931 (cluster fix/packages-catalog,
# upstream PR: artifact-keeper/artifact-keeper fix/packages-catalog).
#
#   #4197 -- the generic upload/finalize path parsed `maven-metadata.xml` (and
#   checksum/signature sidecars) as package coordinates, registering a bogus
#   packages row (artifactId directory read as the version). Pre-fix this
#   script's metadata uploads produce a bogus row; post-fix no row is
#   registered and the real asset still registers groupId:artifactId.
#
#   #3931 -- two concurrent publishes of the same (name, version) raced the
#   catalog upsert CTE into a packages.size_bytes NOT NULL violation (23502),
#   leaving NO catalog row. This script fires 20 parallel identical uploads;
#   pre-fix the row is often missing (and the backend logs 23502), post-fix
#   all uploads succeed and the row exists.
#
#   #4191 (go backfill sidecar size) is deliberately NOT covered here: its
#   precondition is legacy artifact rows with no catalog rows, which no public
#   API can create; it is covered by pure unit tests on
#   backfill_catalog_coordinates plus a DB-backed backfill test in the
#   backend suite.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "packages-catalog-registration"
auth_admin

MVN_REPO="e2e-cat-mvn-${RUN_ID}"
GEN_REPO="e2e-cat-gen-${RUN_ID}"
WORK_DIR="$(mktemp -d)"

begin_test "Setup: create maven + generic local repos"
if create_local_repo "$MVN_REPO" "maven" && create_local_repo "$GEN_REPO" "generic"; then
  pass
else
  fail "could not create local repos"
fi

# -------------------------------------------------------------------------
# #4197: metadata + sidecar uploads must not register catalog rows
# -------------------------------------------------------------------------

printf 'jar-bytes' > "$WORK_DIR/widget-1.2.3.jar"
printf '<metadata/>' > "$WORK_DIR/maven-metadata.xml"
printf 'deadbeef' > "$WORK_DIR/widget-1.2.3.jar.sha1"

begin_test "#4197: upload real maven asset (control)"
if api_upload "/api/v1/repositories/${MVN_REPO}/artifacts/com/acme/widget/1.2.3/widget-1.2.3.jar" \
    "$WORK_DIR/widget-1.2.3.jar" "application/java-archive" >/dev/null; then
  pass
else
  fail "could not upload widget-1.2.3.jar"
fi

begin_test "#4197: upload maven-metadata.xml + .sha1 sidecar"
if api_upload "/api/v1/repositories/${MVN_REPO}/artifacts/com/acme/widget/maven-metadata.xml" \
    "$WORK_DIR/maven-metadata.xml" "text/xml" >/dev/null \
  && api_upload "/api/v1/repositories/${MVN_REPO}/artifacts/com/acme/widget/1.2.3/widget-1.2.3.jar.sha1" \
    "$WORK_DIR/widget-1.2.3.jar.sha1" "text/plain" >/dev/null; then
  pass
else
  fail "metadata/sidecar uploads failed"
fi

begin_test "#4197: catalog shows only the real GAV row"
resp=$(curl -s $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/packages?q=widget" 2>/dev/null)
bogus=$(echo "$resp" | jq '[.items[]? // empty | select(.repository_key == "${MVN_REPO}" and (.name == "maven-metadata.xml" or .name == "widget-1.2.3.jar.sha1" or .version == "widget"))] | length' 2>/dev/null || echo "-1")
real=$(echo "$resp" | jq '[.items[]? // empty | select(.repository_key == "${MVN_REPO}" and .name == "com.acme:widget" and .version == "1.2.3")] | length' 2>/dev/null || echo "-1")
if [ "$bogus" = "0" ] && [ "$real" = "1" ]; then
  pass
else
  fail "catalog rows wrong: bogus=$bogus (want 0) real=$real (want 1); body=$(echo "$resp" | head -c 400)"
fi

# -------------------------------------------------------------------------
# #3931: concurrent identical publishes never lose the catalog row
# -------------------------------------------------------------------------

# Warm the path once so the burst measures the catalog race, not cold-start
# connection churn.
api_upload "/api/v1/repositories/${GEN_REPO}/artifacts/race-pkg/1.0.0/race.bin" \
  "$WORK_DIR/race.bin" "application/octet-stream" >/dev/null || true

begin_test "#3931: 20 parallel identical uploads all succeed"
printf 'race-payload' > "$WORK_DIR/race.bin"
pids=""
for i in $(seq 1 20); do
  api_upload "/api/v1/repositories/${GEN_REPO}/artifacts/race-pkg/1.0.0/race.bin" \
    "$WORK_DIR/race.bin" "application/octet-stream" >/dev/null 2>&1 &
  pids="$pids $!"
done
rc=0
for p in $pids; do wait "$p" || rc=1; done
if [ "$rc" = "0" ]; then
  pass
else
  fail "one or more parallel uploads failed"
fi

begin_test "#3931: catalog row exists after the race"
resp=$(curl -s $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/packages?q=race-pkg" 2>/dev/null)
if echo "$resp" | jq -e '[.items[]? // empty | select(.repository_key == "${GEN_REPO}" and .name == "race-pkg")] | length >= 1' >/dev/null 2>&1; then
  pass
else
  fail "no catalog row for race-pkg after concurrent publishes; body=$(echo "$resp" | head -c 400)"
fi

rm -rf "$WORK_DIR"
end_suite
