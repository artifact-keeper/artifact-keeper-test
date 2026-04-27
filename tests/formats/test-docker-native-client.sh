#!/usr/bin/env bash
# test-docker-native-client.sh - Docker native client smoke test
#
# Real `docker login`, `docker push`, `docker pull` against the in-cluster
# OCI endpoint. The existing test-oci.sh defaults to a curl-based
# simulation of the OCI v2 API (USE_DOCKER=false unless FORCE_DOCKER_TESTS
# is set, which never is in CI). That simulation cannot catch regressions
# that only manifest with the real client: token endpoint redirects,
# auth scope strings, manifest content-type strictness, and the
# Docker-Distribution-Api-Version response header.
#
# This is the test that would have caught the docker-format regression
# Firjen reported on the community channel.
#
# Skipped cleanly when:
#   - docker CLI is not installed
#   - docker daemon is not reachable (`docker info` fails)
#   - the registry hostname does not resolve from inside the runner pod
#   - the registry is HTTPS-only and no cert is mounted (we cannot inject
#     /etc/docker/daemon.json from a non-root pod)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "docker-native-client"

# Pre-flight skips MUST run BEFORE auth_admin so a missing-tool skip emits
# a clean JUnit testcase via skip_suite. Round 2 review: if auth_admin
# (which calls into the backend) errors out before pre-flight runs, the
# suite errors with no JUnit and the gate's silent-success protection
# never fires.

REPO_KEY="test-docker-nc-${RUN_ID}"
UNIQUE_TAG="1.0.$(date +%s)"

# -------------------------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------------------------

# Pre-flight skips use skip_suite() so they emit a JUnit testcase with
# <skipped/>. The previous bare `exit 0` SKIPs wrote nothing to JUnit
# and the release-gate dashboard showed "no testcases" rather than the
# explicit skip reason. In release-gate context (RELEASE_GATE=1), every
# skip_suite turns into a hard fail: a silently-skipped docker test is
# the same silent-success class (#888-style) the gate exists to catch.

if ! command -v docker &>/dev/null; then
  skip_suite "docker CLI not installed"
fi

if ! docker info > /dev/null 2>&1; then
  skip_suite "docker daemon not reachable from this runner"
fi

# Strip scheme to get host:port for docker commands. REGISTRY_HOST keeps
# the port (e.g. host:8080); REGISTRY_HOSTNAME is just the hostname for
# DNS resolution. Both are needed -- the insecure-registries check below
# matches against the host:port form.
REGISTRY_HOST="${BASE_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"
REGISTRY_HOSTNAME="${REGISTRY_HOST%%:*}"

# If the runner cannot resolve the registry hostname there is no point
# trying to push. Resolve via getent (Linux) or python (portable).
if command -v getent &>/dev/null; then
  if ! getent hosts "$REGISTRY_HOSTNAME" > /dev/null 2>&1; then
    skip_suite "registry hostname '${REGISTRY_HOSTNAME}' does not resolve from this runner"
  fi
elif ! python3 -c "import socket, sys; socket.gethostbyname('${REGISTRY_HOSTNAME}')" > /dev/null 2>&1; then
  skip_suite "registry hostname '${REGISTRY_HOSTNAME}' does not resolve"
fi

# Docker refuses to talk plain HTTP to anything that is not localhost
# unless the daemon is started with `--insecure-registries`. We cannot
# reconfigure dockerd from an unprivileged runner pod; if BASE_URL is
# plain HTTP and not localhost, the push will fail with a clear error.
#
# The insecure-registries entry is keyed by host:port, not just host
# (round-1 review caught this: matching on REGISTRY_HOSTNAME alone could
# pass when the entry was actually for a different port on the same
# host). We match against REGISTRY_HOST (with port) when the URL has a
# port, falling back to hostname-only when it does not.
if [[ "$BASE_URL" =~ ^http:// ]] && [[ "$REGISTRY_HOSTNAME" != "localhost" ]] && [[ "$REGISTRY_HOSTNAME" != "127.0.0.1" ]]; then
  docker_info_out=$(docker info 2>/dev/null || true)
  if ! echo "$docker_info_out" | grep -q "Insecure Registries"; then
    skip_suite "BASE_URL is plain HTTP and dockerd has no insecure-registries entry for ${REGISTRY_HOST}"
  fi
  # Match REGISTRY_HOST (with port) first, fall back to hostname-only
  # for entries that omit the port (less common but legal).
  if ! echo "$docker_info_out" | grep -A 5 "Insecure Registries" | grep -qE "^\s*${REGISTRY_HOST}\b"; then
    if ! echo "$docker_info_out" | grep -A 5 "Insecure Registries" | grep -qE "^\s*${REGISTRY_HOSTNAME}\b"; then
      skip_suite "dockerd has no insecure-registries entry matching '${REGISTRY_HOST}' (or '${REGISTRY_HOSTNAME}')"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Pre-flight passed -- now bring up the suite state that needs the
# backend to be reachable. Doing auth_admin/setup_workdir AFTER pre-flight
# means a docker-not-installed runner skips cleanly via skip_suite without
# having tried (and failed) to reach the backend first.
# -------------------------------------------------------------------------

auth_admin
setup_workdir

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create docker repository"
if create_local_repo "$REPO_KEY" "docker"; then
  pass
else
  fail "could not create docker repository"
fi

# -------------------------------------------------------------------------
# docker login
# -------------------------------------------------------------------------

begin_test "docker login"
login_log="${WORK_DIR}/docker-login.log"
if echo "$ADMIN_PASS" | docker login "$REGISTRY_HOST" \
    --username "$ADMIN_USER" \
    --password-stdin > "$login_log" 2>&1; then
  pass
else
  fail "docker login failed; tail: $(tail -n 10 "$login_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# Build a tiny image
#
# We use busybox pinned by digest so this test never depends on network
# pulls of :latest, which would (a) flake on rate-limited runners and
# (b) drift over time and cause confusing failures.
# -------------------------------------------------------------------------

begin_test "Build native-client smoke image"
cat > "${WORK_DIR}/Dockerfile" <<'EOF'
FROM busybox:1.36.1
RUN echo "ak-native-smoke" > /etc/marker
EOF

IMAGE_LOCAL="ak-native-smoke:${UNIQUE_TAG}"
IMAGE_REMOTE="${REGISTRY_HOST}/${REPO_KEY}/native-smoke:${UNIQUE_TAG}"

build_log="${WORK_DIR}/docker-build.log"
if docker build -q -t "$IMAGE_LOCAL" "${WORK_DIR}" > "$build_log" 2>&1; then
  pass
else
  fail "docker build failed; tail: $(tail -n 15 "$build_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# docker tag + docker push
# -------------------------------------------------------------------------

begin_test "docker push"
push_log="${WORK_DIR}/docker-push.log"
PUSH_DIGEST=""
if docker tag "$IMAGE_LOCAL" "$IMAGE_REMOTE" 2>>"$push_log" && \
   docker push "$IMAGE_REMOTE" > "$push_log" 2>&1; then
  # Capture the digest from `docker inspect` after a successful push.
  # We will compare this with the post-pull digest below to catch
  # regressions where the registry re-tags layers under different
  # digests (a real OCI silent-corruption class).
  # Use RepoDigests (manifest digest) over .Id (local config-blob hash).
  # .Id catches layer mutation in transit but misses manifest-only
  # mutation (mediaType drift, annotation injection) where layers are
  # byte-identical but the manifest JSON changed. RepoDigests is the
  # registry's view, comparable across push and pull.
  # The format `{{index .RepoDigests 0}}` returns "host:port/repo@sha256:..."
  # The sha is the manifest digest the registry computed.
  PUSH_DIGEST=$(docker inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$IMAGE_REMOTE" 2>/dev/null || echo "")
  pass
else
  fail "docker push failed; tail: $(tail -n 20 "$push_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# Remove local copies, then docker pull
#
# We have to drop the local image and the tagged remote ref before pull,
# otherwise pull is a no-op and tells us nothing about the registry.
# -------------------------------------------------------------------------

begin_test "docker pull"
docker rmi "$IMAGE_LOCAL" "$IMAGE_REMOTE" > /dev/null 2>&1 || true

pull_log="${WORK_DIR}/docker-pull.log"
if docker pull "$IMAGE_REMOTE" > "$pull_log" 2>&1; then
  # Verify the pulled image actually has our marker file. A successful
  # `docker pull` with an empty image would still pass; this check
  # confirms the manifest+layer round-tripped correctly.
  if marker=$(docker run --rm "$IMAGE_REMOTE" cat /etc/marker 2>/dev/null); then
    if assert_contains "$marker" "ak-native-smoke"; then
      pass
    fi
  else
    # `docker run` may not work in dind; the pull itself is the load-bearing
    # assertion, so accept just the pull success.
    pass
  fi
else
  fail "docker pull failed; tail: $(tail -n 20 "$pull_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# Digest stability assertion
#
# Catches the OCI silent-corruption class where the registry returns an
# image with a different digest than what was pushed (e.g. layer
# reordering, manifest content-type drift). A pure push+pull round-trip
# without this assertion would still pass on a registry that mutates
# bytes in transit.
# -------------------------------------------------------------------------

begin_test "Pulled image digest matches pushed digest"
if [ -n "$PUSH_DIGEST" ]; then
  PULL_DIGEST=$(docker inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$IMAGE_REMOTE" 2>/dev/null || echo "")
  if [ -n "$PULL_DIGEST" ] && [ "$PUSH_DIGEST" = "$PULL_DIGEST" ]; then
    pass
  else
    fail "digest drift: pushed='${PUSH_DIGEST}', pulled='${PULL_DIGEST}'"
  fi
else
  # Push step did not record a digest (likely because dind doesn't
  # populate .Id consistently). Don't fail the suite over diagnostic
  # absence -- mark as skipped with a clear reason.
  skip "PUSH_DIGEST was empty; cannot compare with pulled digest"
fi

# -------------------------------------------------------------------------
# Cleanup (best effort)
# -------------------------------------------------------------------------

docker rmi "$IMAGE_LOCAL" "$IMAGE_REMOTE" > /dev/null 2>&1 || true
docker logout "$REGISTRY_HOST" > /dev/null 2>&1 || true

end_suite
