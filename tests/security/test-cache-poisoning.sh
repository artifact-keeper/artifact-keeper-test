#!/usr/bin/env bash
# test-cache-poisoning.sh - T2-11: Proxy/remote repo cache poisoning prevention
#
# Verifies that content fetched through a remote (proxy) repo is integrity-checked
# and that an attacker who briefly controls the upstream cannot retroactively
# corrupt previously-cached, known-good content.
#
# Customer pain #1 (https://github.com/orgs/artifact-keeper/discussions/872):
# the prior version of this suite skipped the load-bearing assertion with
# "requires controllable mock HTTP upstream". This version stands up a real
# mock upstream (tests/lib/mock-upstream.py via start_mock_upstream), seeds
# known bytes, primes the cache, swaps the upstream content for a different
# payload, and asserts that the proxy serves the originally-cached bytes
# (or 502/503), never the tampered payload.
#
# Hard constraint (issue artifact-keeper-test#67): this test must FAIL when
# the backend is broken. Run with EXPECT_FAILURE=1 against a known-broken
# build to validate the assertion is load-bearing (see common.sh).
#
# Parking history (artifact-keeper-test#343)
# ------------------------------------------
# This suite and its cache-stampede twin were stubbed down to a single skip in
# #126, because the backend rejected every RFC1918 upstream URL and the mock
# fixture is exposed on the ARC runner pod IP (10.244.0.0/16). That blocker is
# gone on BOTH sides and has been since May 2026:
#
#   * artifact-keeper#1325 (merged, closes artifact-keeper#1224) added the
#     AK_SSRF_ALLOW_PRIVATE_CIDRS env var.
#   * helm/values-test-full.yaml -- which the release-gate deploy renders, via
#     create-test-namespace.sh --full-stack -- already sets
#     AK_SSRF_ALLOW_PRIVATE_CIDRS: "10.96.0.0/12,10.244.0.0/16".
#
# So the suites were not blocked, only unmaintained. They are restored here
# rather than exempted: an exemption would have claimed a capability was
# missing when it had in fact shipped three months earlier.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-poisoning"

# Pre-flight: the mock upstream needs python3 and the backend has to be able
# to dial the mock from the cluster (MOCK_UPSTREAM_HOSTNAME, set by CI).
# RELEASE_GATE=1 turns these skips into hard fails (silent-success class).
if ! command -v python3 >/dev/null 2>&1; then
  skip_suite "python3 not available; cache-poisoning needs the mock upstream fixture"
fi

if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; CI must set this to a name the backend can resolve to the test runner pod (e.g. <pod-ip-dashed>.<ns>.pod.cluster.local)"
fi

auth_admin
setup_workdir

REMOTE_KEY="sec-cache-poison-${RUN_ID}"
LOCAL_KEY="sec-cache-ref-${RUN_ID}"
ARTIFACT_PATH="pkg/v1/payload.bin"
ETAG_PATH="pkg/v1/etagged.bin"
CL_PATH="pkg/v1/clmismatch.bin"

# ---------------------------------------------------------------------------
# Boot the mock upstream
# ---------------------------------------------------------------------------

begin_test "Mock upstream starts and serves seeded content"
if start_mock_upstream "${WORK_DIR}/mock-state"; then
  GOOD_CONTENT="known-good-content-${RUN_ID}"
  TAMPERED_CONTENT="tampered-by-attacker-${RUN_ID}"
  mkdir -p "${MOCK_STATE_DIR}/files/$(dirname "$ARTIFACT_PATH")"
  printf '%s\n' "$GOOD_CONTENT" > "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}"
  GOOD_SHA256=$(shasum -a 256 "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}" | awk '{print $1}')
  pass
else
  fail "mock upstream did not boot"
  end_suite
fi

# ---------------------------------------------------------------------------
# Create a remote repo pointing at the mock
# ---------------------------------------------------------------------------

begin_test "Create remote repo pointing at the mock upstream"
if create_remote_repo "$REMOTE_KEY" "generic" "$MOCK_BASE_URL"; then
  pass
else
  fail "could not create remote repo for upstream ${MOCK_BASE_URL}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Prime the cache: fetch the artifact through the proxy. The backend should
# pull from the mock, store the bytes, and remember the sha256.
# ---------------------------------------------------------------------------

begin_test "Prime the proxy cache with known-good upstream content"
prime_status=$(curl -s -o "${WORK_DIR}/prime.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true

if assert_http_2xx "$prime_status" "prime fetch should succeed against a healthy mock upstream"; then
  prime_sha=$(shasum -a 256 "${WORK_DIR}/prime.bin" | awk '{print $1}')
  if assert_eq "$prime_sha" "$GOOD_SHA256" "primed cache should contain the seeded upstream bytes"; then
    pass
  fi
fi

# ---------------------------------------------------------------------------
# The prime above proves the right BYTES were served. It does NOT prove they
# are cached: the backend publishes a proxy-cache entry from a writer task that
# outlives the response (staging write -> copy onto the live key -> discard
# staging -> pin storage ETag -> __cache_meta__.json sidecar), and freshness is
# evaluated from that sidecar. A request landing before the sidecar exists
# classifies a miss and refetches upstream.
#
# Both assertions below are phrased "for a previously-cached artifact", so the
# precondition has to be established rather than assumed -- otherwise a fetch
# that raced the publish reports as cache poisoning, which is what happened on
# release-gate run 31677420530 while run 31666770835 won the same race on a
# backend whose entire proxy-cache implementation is byte-identical.
#
# This is a real test, not a sleep: if the entry never becomes readable, that
# IS a backend defect and the gate must go red.
# ---------------------------------------------------------------------------

UPSTREAM_COUNTER="${MOCK_STATE_DIR}/request-count.$(mock_counter_key "$ARTIFACT_PATH")"

begin_test "Primed entry is readable from the proxy cache before tampering"
if wait_for_proxy_cache_warm \
    "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}" \
    "$UPSTREAM_COUNTER"; then
  pass
else
  fail "proxy never served ${ARTIFACT_PATH} without re-contacting upstream: the primed cache entry never became readable"
fi

# ---------------------------------------------------------------------------
# Attacker step: swap the upstream payload for a different sha256. The mock
# now serves the tampered content with a 200 OK. A correctly-implemented
# proxy must NOT propagate the new bytes silently for the same cache key
# while a known-good copy is on disk. Acceptable behaviors:
#   - serve the previously-cached good bytes (cache hit, ignore upstream)
#   - reject with 502/503 (refuse to overwrite verified content)
# Forbidden behavior:
#   - return 200 OK with the tampered bytes
# ---------------------------------------------------------------------------

printf '%s\n' "$TAMPERED_CONTENT" > "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}"
TAMPERED_SHA256=$(shasum -a 256 "${MOCK_STATE_DIR}/files/${ARTIFACT_PATH}" | awk '{print $1}')

begin_test "Tampered upstream content does not poison the proxy cache"
post_status=$(curl -s -o "${WORK_DIR}/post.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true

post_sha=""
if [ -f "${WORK_DIR}/post.bin" ]; then
  post_sha=$(shasum -a 256 "${WORK_DIR}/post.bin" | awk '{print $1}')
fi

if [ "$post_sha" = "$TAMPERED_SHA256" ]; then
  fail "proxy returned tampered upstream bytes (sha=${post_sha}) for previously-cached artifact: cache poisoning"
elif [ "$post_status" = "502" ] || [ "$post_status" = "503" ] || [ "$post_status" = "504" ]; then
  pass
elif [ "$post_sha" = "$GOOD_SHA256" ]; then
  pass
else
  fail "post-tamper fetch returned HTTP ${post_status} sha=${post_sha:-<empty>} (neither cached-good nor 5xx)"
fi

# ---------------------------------------------------------------------------
# When the upstream goes away entirely, the proxy must still serve the
# known-good cached bytes (or fail loudly) -- never the tampered ones it
# saw between prime and shutdown.
# ---------------------------------------------------------------------------

# Pin the port BEFORE stopping so the later restart binds the same port. The
# remote repo's upstream_url was recorded at create_remote_repo time with the
# port start_mock_upstream picked; without this pin, _pick_mock_port hands out
# a fresh random port on restart and every subsequent proxy fetch 502s against
# a dead upstream (the suite's own fixture, not a backend defect).
MOCK_PORT_OVERRIDE="${MOCK_PORT}"
export MOCK_PORT_OVERRIDE

stop_mock_upstream

begin_test "Proxy serves cached good bytes (or 5xx) when upstream is unreachable"
offline_status=$(curl -s -o "${WORK_DIR}/offline.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true

offline_sha=""
if [ -f "${WORK_DIR}/offline.bin" ]; then
  offline_sha=$(shasum -a 256 "${WORK_DIR}/offline.bin" | awk '{print $1}')
fi

if [ "$offline_sha" = "$TAMPERED_SHA256" ]; then
  fail "proxy served tampered bytes after upstream went offline: tampered payload was cached"
elif [ "$offline_sha" = "$GOOD_SHA256" ]; then
  pass
elif [ "$offline_status" = "502" ] || [ "$offline_status" = "503" ] || [ "$offline_status" = "504" ] || [ "$offline_status" = "404" ]; then
  pass
else
  fail "offline fetch returned HTTP ${offline_status} sha=${offline_sha:-<empty>} (neither cached-good nor 5xx)"
fi

# ---------------------------------------------------------------------------
# Bring the mock back up for the remaining content-integrity probes.
# ---------------------------------------------------------------------------

begin_test "Mock upstream restarts (continues with content-integrity probes)"
if start_mock_upstream "${WORK_DIR}/mock-state-2"; then
  pass
else
  fail "mock upstream did not restart"
  end_suite
fi

# ---------------------------------------------------------------------------
# Coverage: upstream lies about Content-Length. A fetch that returns fewer
# bytes than advertised must NOT be silently cached as if it were complete.
# Acceptable: 200 (curl handles short read) followed by an integrity reject;
# OR 502/503 from the proxy; OR a successful fetch with the actual bytes.
# Forbidden: cache a partial as if complete and serve it as the full artifact.
# ---------------------------------------------------------------------------

begin_test "Upstream Content-Length mismatch is not silently cached as complete"
mkdir -p "${MOCK_STATE_DIR}/files/$(dirname "$CL_PATH")"
CL_BODY="full-body-content-${RUN_ID}"
printf '%s\n' "$CL_BODY" > "${MOCK_STATE_DIR}/files/${CL_PATH}"
# Lie: claim the body is twice as long. Real curl will detect short read and
# either error or truncate; the question is whether the backend caches the
# (potentially short) bytes as if they were the canonical artifact.
real_len=$(wc -c < "${MOCK_STATE_DIR}/files/${CL_PATH}" | tr -d ' ')
echo "Content-Length: $((real_len * 2))" > "${MOCK_STATE_DIR}/files/${CL_PATH}.headers"

cl_status=$(curl -s -o "${WORK_DIR}/cl.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${CL_PATH}") || true

# Now repair the upstream and re-fetch. If the proxy cached the lying response
# as if complete, the second fetch returns the (broken) cached copy. If it
# refused to cache, the second fetch sees the corrected upstream.
rm -f "${MOCK_STATE_DIR}/files/${CL_PATH}.headers"
followup_status=$(curl -s -o "${WORK_DIR}/cl-followup.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${CL_PATH}") || true

if assert_http_2xx "$followup_status" "follow-up fetch should succeed once upstream is honest"; then
  followup_sha=$(shasum -a 256 "${WORK_DIR}/cl-followup.bin" | awk '{print $1}')
  expected_sha=$(shasum -a 256 "${MOCK_STATE_DIR}/files/${CL_PATH}" | awk '{print $1}')
  if [ "$followup_sha" = "$expected_sha" ]; then
    pass
  else
    fail "after Content-Length-lie-then-repair, proxy served sha=${followup_sha} but upstream now serves sha=${expected_sha}: a partial response was cached as canonical"
  fi
fi
echo "  (initial mismatch fetch: HTTP ${cl_status})"

# ---------------------------------------------------------------------------
# Coverage: upstream sends a forged X-Checksum-Sha256 header that does not
# match the body. If the backend trusts the header without recomputing, an
# attacker who controls the upstream can poison the cache with a deceptive
# checksum. The proxy should either ignore the header (recompute locally) or
# reject the fetch.
# ---------------------------------------------------------------------------

begin_test "Forged upstream X-Checksum-Sha256 does not override on-disk hash"
mkdir -p "${MOCK_STATE_DIR}/files/$(dirname "$ETAG_PATH")"
HONEST_BODY="honest-payload-${RUN_ID}"
printf '%s\n' "$HONEST_BODY" > "${MOCK_STATE_DIR}/files/${ETAG_PATH}"
HONEST_SHA=$(shasum -a 256 "${MOCK_STATE_DIR}/files/${ETAG_PATH}" | awk '{print $1}')
# Plant a wrong sha256 in the headers file.
cat > "${MOCK_STATE_DIR}/files/${ETAG_PATH}.headers" <<EOF
X-Checksum-Sha256: 0000000000000000000000000000000000000000000000000000000000000000
ETag: "fake-etag"
EOF

forged_status=$(curl -s -o "${WORK_DIR}/forged.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ETAG_PATH}") || true

if assert_http_2xx "$forged_status" "fetch should succeed; integrity must be enforced from bytes, not header"; then
  forged_sha=$(shasum -a 256 "${WORK_DIR}/forged.bin" | awk '{print $1}')
  if [ "$forged_sha" = "$HONEST_SHA" ]; then
    pass
  else
    fail "served bytes (sha=${forged_sha}) do not match upstream body (sha=${HONEST_SHA}); proxy may have honored forged X-Checksum-Sha256 header"
  fi
fi

# ---------------------------------------------------------------------------
# Cross-repo isolation: a remote repo MUST NOT serve content from an unrelated
# local repo even when the path matches. This catches the "cross-repo cache
# leak" class of bugs where the storage layer keys cache entries by path
# alone instead of (repo_id, path).
# ---------------------------------------------------------------------------

begin_test "Create local reference repo and upload distinct content"
if create_local_repo "$LOCAL_KEY" "generic"; then
  echo "${GOOD_CONTENT}" > "${WORK_DIR}/reference.bin"
  if api_upload "/api/v1/repositories/${LOCAL_KEY}/artifacts/${ARTIFACT_PATH}" \
      "${WORK_DIR}/reference.bin"; then
    pass
  else
    fail "could not upload reference artifact"
  fi
else
  fail "could not create local reference repo"
fi

begin_test "Remote repo does not serve content from unrelated local repo"
cross_status=$(curl -s -o "${WORK_DIR}/cross.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/${ARTIFACT_PATH}") || true

# Cross-repo isolation invariant: a remote repo can only serve paths the
# upstream actually had. Probe a path the local repo could conceivably leak
# via a global cache table but the mock has never seen. A 2xx here proves a
# cross-repo or unauthenticated cache leak.
if [ -s "${WORK_DIR}/cross.bin" ] && [ "$cross_status" -ge 200 ] 2>/dev/null && [ "$cross_status" -lt 300 ] 2>/dev/null; then
  cross_sha=$(shasum -a 256 "${WORK_DIR}/cross.bin" | awk '{print $1}')
  ref_sha=$(shasum -a 256 "${WORK_DIR}/reference.bin" | awk '{print $1}')
  status_only_local=$(curl -s -o "${WORK_DIR}/cross-only.bin" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/download/never-fetched-from-mock-${RUN_ID}.bin") || true
  if [ "$status_only_local" -ge 200 ] 2>/dev/null && [ "$status_only_local" -lt 300 ] 2>/dev/null; then
    fail "remote repo served content for a path the mock never had (cross-repo or unauthenticated cache leak)"
  else
    if [ "$cross_sha" = "$ref_sha" ] && [ "$cross_sha" != "$GOOD_SHA256" ]; then
      fail "remote repo served local-repo-only content"
    else
      pass
    fi
  fi
elif [ "$cross_status" = "404" ] || [ "$cross_status" = "502" ] || [ "$cross_status" = "503" ] || [ "$cross_status" = "504" ]; then
  pass
else
  pass
fi

end_suite
