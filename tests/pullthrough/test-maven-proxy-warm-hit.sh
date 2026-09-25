#!/usr/bin/env bash
# test-maven-proxy-warm-hit.sh -- Maven proxy warm-cache-hit companion for
# artifact-keeper#3982 (sequential .sha1 sidecar + content round-trips, now
# overlapped/deferred) and artifact-keeper#3778 (synchronous PostgreSQL I/O
# on every warm hit: repo resolution + download telemetry, now
# cached/deferred).
#
# Strategy: AK-to-AK upstream (same rationale as
# test-cache-hit-no-refetch.sh -- the Python mock fixture binds an RFC1918
# address that validate_outbound_url rejects, so the "remote" repo proxies
# a LOCAL Maven repo on the same backend):
#
#   U  = "upstream" -- a local Maven repo we PUT a release jar into.
#   R  = "remote"   -- a remote Maven repo whose upstream_url is U. The
#                      backend dials itself; U serves a GENERATED .sha1
#                      sidecar, so R exercises the #3982 sidecar-gated arm.
#
# What this script asserts (in order)
# -----------------------------------
# 1. U serves a generated .sha1 sidecar matching the jar (fixture sanity:
#    without it, the sidecar-gated code path under test is never reached).
# 2. Cold GET of the jar through R returns 200 and byte-identical content
#    (cache prime).
# 3. Cold GET of the jar's .sha1 through R returns the digest of the jar
#    (the sidecar rides the proxy cache, exactly what a mvn/gradle client
#    does).
# 4. WARM HIT CONTRACT: N consecutive warm GETs of the jar through R each
#    return 200 with byte-identical content, and U's download_count for the
#    jar does not move -- a warm hit must not re-contact upstream at all
#    (neither for the content nor for the .sha1 sidecar).
# 5. #3778 regression pin: proxy download telemetry is still recorded for
#    R even though record_proxy_download moved off the response path
#    (record_proxy_download_deferred). Polled, because the write is now
#    asynchronous.
#
# Negative-control caveat (documented per the swarm plan): the #3982/#3778
# latency delta is NOT robustly observable at the cluster level. The old
# code resolved the sidecar THROUGH the proxy cache, so old warm hits also
# produce zero upstream traffic (the sidecar rides a warm/negative cache
# entry) -- assertion 4 passes on the unfixed image too. The old-vs-new
# difference is two sequential in-process cache/DB round-trips vs one,
# which is sub-millisecond on cluster-local storage and cannot be gated on
# without flaking. The failing-before evidence for the latency fix itself
# is carried by the unit gate
# (maven::tests::test_remote_warm_hit_does_not_refetch_sha1_sidecar_3982,
# test_resolve_maven_repo_cache_hit_never_touches_db_3778). Warm GET
# durations are printed as informational log evidence.
#
# Requires: curl, jq, python3, sha1sum, sha256sum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-proxy-warm-hit"
auth_admin
setup_workdir

UPSTREAM_KEY="mpwh-upstream-${RUN_ID}"
REMOTE_KEY="mpwh-remote-${RUN_ID}"
GROUP_ID="com.test.mpwh"
ARTIFACT_ID="mpwh${RUN_ID//-/}"
VERSION="1.0.0"
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
JAR_NAME="${ARTIFACT_ID}-${VERSION}.jar"
JAR_PATH="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}/${JAR_NAME}"
# Long enough that no test step can plausibly slip past the cache window on
# a loaded runner (same bound as test-cache-hit-no-refetch.sh).
TTL_SECS=60
WARM_FETCHES=3

UPSTREAM_MAVEN_URL="${BASE_URL}/maven/${UPSTREAM_KEY}"
REMOTE_MAVEN_URL="${BASE_URL}/maven/${REMOTE_KEY}"

# U's download_count for the jar (empty string if the row is not visible).
u_jar_dl_count() {
  api_get "/api/v1/repositories/${UPSTREAM_KEY}/artifacts?per_page=100" 2>/dev/null \
    | jq -r --arg p "$JAR_PATH" '(.items // .)[]? | select(.path == $p) | .download_count' \
    | head -n1
}

# R's download_count for the proxied jar (empty string if not listed).
r_jar_dl_count() {
  api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts?per_page=100" 2>/dev/null \
    | jq -r --arg p "$JAR_PATH" '(.items // .)[]? | select(.path == $p) | .download_count' \
    | head -n1
}

# ---------------------------------------------------------------------------
# Setup: upstream U with a release jar
# ---------------------------------------------------------------------------

begin_test "Create local Maven upstream U"
if create_local_repo "$UPSTREAM_KEY" "maven"; then
  pass
else
  fail "could not create Maven upstream"
fi

begin_test "Build and PUT release jar to U"
cd "$WORK_DIR"
mkdir -p jar-content/META-INF
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
Implementation-Title: ${ARTIFACT_ID}
Implementation-Version: ${VERSION}
EOF
echo "warm-hit probe ${RUN_ID}" > jar-content/payload.txt
JAR_FILE="${WORK_DIR}/${JAR_NAME}"
python3 - "$JAR_FILE" <<'PYZIP'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.write("jar-content/META-INF/MANIFEST.MF", "META-INF/MANIFEST.MF")
    z.write("jar-content/payload.txt", "payload.txt")
PYZIP
ORIG_SHA256=$(sha256sum "$JAR_FILE" | awk '{print $1}')
ORIG_SHA1=$(sha1sum "$JAR_FILE" | awk '{print $1}')
if curl -sf $CURL_TIMEOUT -X PUT "${UPSTREAM_MAVEN_URL}/${JAR_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT jar to upstream failed"
fi

begin_test "U serves a generated .sha1 sidecar matching the jar (fixture sanity)"
SIDE_BODY=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${UPSTREAM_MAVEN_URL}/${JAR_PATH}.sha1" 2>/dev/null) || SIDE_BODY=""
SIDE_BODY=$(printf '%s' "$SIDE_BODY" | tr -d '[:space:]' | cut -c1-40)
if [ -z "$SIDE_BODY" ]; then
  fail "upstream returned no .sha1 sidecar; the #3982 sidecar-gated path is not exercised by this fixture"
elif [ "$SIDE_BODY" != "$ORIG_SHA1" ]; then
  fail "upstream .sha1 (${SIDE_BODY}) does not match jar sha1 (${ORIG_SHA1})"
else
  pass
fi

begin_test "Create remote R pointing at U with TTL=${TTL_SECS}s"
if create_remote_repo "$REMOTE_KEY" "maven" "$UPSTREAM_MAVEN_URL"; then
  pass
else
  fail "could not create remote R"
fi
api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
    "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Cold path: prime the cache (content + sidecar)
# ---------------------------------------------------------------------------

begin_test "Cold GET jar through R returns 200 with byte-identical content (cache prime)"
DL_FILE="${WORK_DIR}/cold.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" -o "$DL_FILE" \
    "${REMOTE_MAVEN_URL}/${JAR_PATH}"; then
  DL_SHA256=$(sha256sum "$DL_FILE" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "cold GET sha256 mismatch"; then
    pass
  fi
else
  fail "cold GET through R failed; cannot proceed"
fi

begin_test "Cold GET jar.sha1 through R returns the jar digest"
R_SIDE=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${REMOTE_MAVEN_URL}/${JAR_PATH}.sha1" 2>/dev/null) || R_SIDE=""
R_SIDE=$(printf '%s' "$R_SIDE" | tr -d '[:space:]' | cut -c1-40)
if [ -z "$R_SIDE" ]; then
  fail "remote returned no .sha1 sidecar"
elif [ "$R_SIDE" != "$ORIG_SHA1" ]; then
  fail "remote .sha1 (${R_SIDE}) does not match jar sha1 (${ORIG_SHA1})"
else
  pass
fi

# Let U's download telemetry settle before snapshotting the counter.
sleep 2
U_COUNT_BEFORE=$(u_jar_dl_count)

# ---------------------------------------------------------------------------
# Warm path: N consecutive hits -- 200, byte-identical, zero upstream
# re-contact (neither content nor .sha1 sidecar may be re-fetched).
# ---------------------------------------------------------------------------

begin_test "${WARM_FETCHES} warm GETs through R return 200 with byte-identical content"
mismatch=0
durations=""
for i in $(seq 1 $WARM_FETCHES); do
  out=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -o "${WORK_DIR}/warm-${i}.jar" -w '%{time_total}' \
        "${REMOTE_MAVEN_URL}/${JAR_PATH}") || { mismatch=1; echo "  warm fetch ${i}: HTTP error"; break; }
  durations="${durations} ${out}s"
  wsha=$(sha256sum "${WORK_DIR}/warm-${i}.jar" | awk '{print $1}')
  if [ "$wsha" != "$ORIG_SHA256" ]; then
    mismatch=1
    echo "  warm fetch ${i}: sha256 mismatch (${wsha} != ${ORIG_SHA256})"
    break
  fi
done
echo "  warm GET durations (informational, #3982/#3778 latency evidence):${durations}"
if [ "$mismatch" -eq 0 ]; then
  pass
else
  fail "warm GETs did not all return the cached bytes"
fi

begin_test "Warm hits do not re-contact upstream U (content or .sha1 sidecar)"
if [ -z "$U_COUNT_BEFORE" ]; then
  skip "U download_count not observable via artifacts list; upstream-contact assertion unobservable"
else
  sleep 2
  U_COUNT_AFTER=$(u_jar_dl_count)
  if [ -z "$U_COUNT_AFTER" ]; then
    skip "U download_count disappeared from artifacts list; upstream-contact assertion unobservable"
  elif [ "$U_COUNT_AFTER" != "$U_COUNT_BEFORE" ]; then
    fail "warm hits re-fetched upstream: U jar download_count moved ${U_COUNT_BEFORE} -> ${U_COUNT_AFTER} across ${WARM_FETCHES} warm GETs"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# #3778 regression pin: deferred proxy-download telemetry must still land.
# ---------------------------------------------------------------------------

begin_test "Proxy download telemetry is recorded for R despite deferred recording (#3778)"
R_COUNT=""
deadline=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  R_COUNT=$(r_jar_dl_count)
  if [ -n "$R_COUNT" ] && [ "$R_COUNT" -ge 1 ] 2>/dev/null; then
    break
  fi
  sleep 1
done
R_LISTING=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts?per_page=100" 2>/dev/null || true)
if printf '%s' "$R_LISTING" | jq -e --arg p "$JAR_PATH" '(.items // .)[]? | select(.path == $p)' >/dev/null 2>&1; then
  if [ -n "$R_COUNT" ] && [ "$R_COUNT" -ge 1 ] 2>/dev/null; then
    pass
  else
    fail "R lists the proxied jar but download_count stayed at ${R_COUNT:-0} after $((WARM_FETCHES + 1)) GETs; deferred telemetry was lost" "$R_LISTING"
  fi
else
  skip "proxied jar not surfaced in R artifacts list; telemetry count unobservable via this endpoint"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
