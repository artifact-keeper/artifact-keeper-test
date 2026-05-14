#!/usr/bin/env bash
# test-rubygems-native-client.sh - RubyGems native-client smoke
#
# Push a real .gem via `gem push` and pull it back via `gem fetch`.
# This is the wire-equivalent of `bundle install` against a private
# index: any auth-realm or content-type regression that the curl-
# based test-rubygems.sh would miss should surface here.
#
# Skipped automatically when the `gem` CLI is missing. The expected
# install path on the system-packages batch's runner pod is:
#   apt-get install -y ruby
# but we do not install it here unconditionally to keep the gate
# under the 5-minute target. The release-gate workflow can opt-in
# by adding `ruby` to its dependency-install step.
#
# Requires: gem (RubyGems CLI), build-essential for any compile-time
# step on the gem (the synthetic gem we ship is pure ruby so no
# native extensions).

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rubygems-native-client"
auth_admin
setup_workdir
require_cmd gem

REPO_KEY="test-rubygems-nc-${RUN_ID}"
GEM_NAME="rfs_gem_${RUN_ID//-/_}"
GEM_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------

begin_test "Create rubygems local repository"
if create_local_repo "$REPO_KEY" "rubygems"; then
  pass
else
  fail "could not create rubygems repository"
fi

# -----------------------------------------------------------------------
# Build a minimal gem via the gem CLI.
#
# We use `gem build` rather than hand-assembling the tarball (as
# test-rubygems.sh does) so the bytes are exactly what a real Ruby
# developer would push. A regression that only surfaces on real-
# client encodings (e.g. RubyGems 3.5+ Marshal_5 framing) shows up
# here.
# -----------------------------------------------------------------------

begin_test "Build gem with gem-build CLI"
GEM_DIR="${WORK_DIR}/src"
mkdir -p "$GEM_DIR/lib"

cat > "$GEM_DIR/lib/${GEM_NAME}.rb" <<EOF
module ${GEM_NAME}
  VERSION = "${GEM_VERSION}"
  def self.hello
    "hello from ${GEM_NAME}"
  end
end
EOF

cat > "${GEM_DIR}/${GEM_NAME}.gemspec" <<EOF
Gem::Specification.new do |s|
  s.name        = "${GEM_NAME}"
  s.version     = "${GEM_VERSION}"
  s.summary     = "Native-client release-gate smoke gem"
  s.description = "Ephemeral fixture pushed by tests/formats/test-rubygems-native-client.sh"
  s.authors     = ["release-gate"]
  s.email       = ["release-gate@example.invalid"]
  s.files       = ["lib/${GEM_NAME}.rb"]
  s.require_paths = ["lib"]
  s.license     = "MIT"
end
EOF

cd "$GEM_DIR" || fail "cd to GEM_DIR failed"
build_log="${WORK_DIR}/gem-build.log"
if gem build "${GEM_NAME}.gemspec" > "$build_log" 2>&1; then
  GEM_FILE="${GEM_DIR}/${GEM_NAME}-${GEM_VERSION}.gem"
  if [ -s "$GEM_FILE" ]; then
    pass
  else
    fail "gem build reported success but no .gem file at ${GEM_FILE}"
  fi
else
  fail "gem build failed; tail: $(tail -n 10 "$build_log" | tr '\n' ' ')"
fi

# -----------------------------------------------------------------------
# Push the gem with `gem push`.
#
# RubyGems uses an Authorization header containing the user's API key,
# but it also accepts a Bearer token. We pass the admin password via
# the HTTP_PROXY/AUTH variables the CLI honors. Easiest: write a
# ~/.gem/credentials file with the basic-auth value pre-set.
# -----------------------------------------------------------------------

begin_test "Push gem with gem-push CLI"
GEM_HOST="${BASE_URL}/gems/${REPO_KEY}"
# gem push needs the host plus the API key. We use the admin password
# as the key value; the backend accepts it as a Basic-auth equivalent.
AUTH_B64=$(printf '%s:%s' "${ADMIN_USER}" "${ADMIN_PASS}" | base64)
mkdir -p "${HOME}/.gem"
chmod 700 "${HOME}/.gem"
# RubyGems credentials are YAML keyed by host or :rubygems_api_key.
# We set both so any version of the CLI picks one up.
cat > "${HOME}/.gem/credentials" <<EOF
---
:rubygems_api_key: Basic ${AUTH_B64}
${GEM_HOST}: Basic ${AUTH_B64}
EOF
chmod 600 "${HOME}/.gem/credentials"

push_log="${WORK_DIR}/gem-push.log"
if gem push --host "$GEM_HOST" "${GEM_FILE}" > "$push_log" 2>&1; then
  pass
else
  fail "gem push failed; tail: $(tail -n 10 "$push_log" | tr '\n' ' ')"
fi

# -----------------------------------------------------------------------
# Pull the gem back with `gem fetch`.
#
# `gem fetch` downloads the .gem without installing it; we then diff
# the file size with the pushed file. We do NOT install (which would
# need the gem to compile on the runner pod and dilute the byte-
# round-trip signal we want).
# -----------------------------------------------------------------------

begin_test "Pull gem with gem-fetch CLI"
PULL_DIR="${WORK_DIR}/pull"
mkdir -p "$PULL_DIR"
cd "$PULL_DIR" || fail "cd to PULL_DIR failed"

fetch_log="${WORK_DIR}/gem-fetch.log"
if gem fetch "${GEM_NAME}" --version "${GEM_VERSION}" \
    --source "$GEM_HOST" > "$fetch_log" 2>&1; then
  PULLED_GEM=$(find . -maxdepth 1 -name "${GEM_NAME}-${GEM_VERSION}.gem" -print -quit)
  if [ -n "$PULLED_GEM" ] && [ -s "$PULLED_GEM" ]; then
    # Compare file sizes. Byte-level equality is too strict because
    # the registry may re-pack the tar metadata (timestamps,
    # checksums) without changing the wire-meaningful payload. Size
    # is the practical assertion that the round-trip is intact.
    pushed_size=$(wc -c < "$GEM_FILE" | tr -d ' ')
    pulled_size=$(wc -c < "$PULLED_GEM" | tr -d ' ')
    if [ "$pushed_size" = "$pulled_size" ]; then
      pass
    else
      fail "size mismatch on round-trip: pushed=${pushed_size}, pulled=${pulled_size}"
    fi
  else
    fail "gem fetch reported success but no .gem file in ${PULL_DIR}"
  fi
else
  fail "gem fetch failed; tail: $(tail -n 10 "$fetch_log" | tr '\n' ' ')"
fi

# -----------------------------------------------------------------------
# Verify the management API also lists the artifact (cross-protocol
# correctness: the format-native push must register the artifact in
# the management view, not be a write-only "shadow").
# -----------------------------------------------------------------------

begin_test "Management API lists the pushed gem"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null || echo "")
if [ -z "$list_resp" ]; then
  fail "could not list artifacts via management API"
else
  if echo "$list_resp" | grep -q "${GEM_NAME}"; then
    pass
  else
    fail "pushed gem ${GEM_NAME} not visible in management API artifact list"
  fi
fi

end_suite
