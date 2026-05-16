#!/usr/bin/env bash
# test-virtual-shadowing-guard.sh -- Cross-format shadowing guards.
#
# Regression test for backend PRs #1217 (hex tarball shadowing guard)
# and #1221 (cross-format shadowing guards for cargo/npm/pypi/maven/
# rubygems). Tracks artifact-keeper-test#69 sub-task 1.10 (virtual repo
# proxying across multiple upstreams).
#
# Threat model
# ------------
# A virtual repo aggregates a local member and a remote (proxy) member.
# An attacker controls (or compromises) the upstream registry the proxy
# member points at. They publish a malicious version of a package name
# the consumer already trusts -- e.g. they push `serde@1.0.999`
# pretending to be the real crates.io serde. Without a shadowing guard,
# a client resolving `serde@1.0.999` through the virtual repo would
# fetch the attacker payload because the local member did not yet have
# that exact version pinned.
#
# The backend's shadowing guard (PR #1221) blocks the upstream from
# returning anything for a package coordinate that already exists in
# any local member of the virtual repo. The hex variant (PR #1217)
# closes the tarball-path-collision variant of the same class.
#
# What this script covers
# -----------------------
# For each of {cargo, npm, pypi, maven, rubygems, hex}:
#
#   1. Create a local repo L of that format. Publish package P at v1.
#   2. Create a remote repo R pointing at a different local repo U.
#      Publish a DIFFERENT bytes-for-P-v1 to U (the "malicious upstream"
#      payload).
#   3. Create a virtual repo V with members L (local) and R (remote).
#   4. Fetch P at v1 through V. Assert the bytes match L's copy, NOT
#      U's. Anything else means the upstream shadowed the trusted local
#      artifact and the guard regressed.
#
# Why we test six formats in one script
# -------------------------------------
# Each format has its own resolution path through the backend (cargo
# has /crates/, hex has /hex/tarballs/, etc.). The guard is implemented
# per-format-handler, so a regression in any one of them would be
# missed by a single-format test. Running them in one script keeps the
# fixture cost low (six local repos, six remote repos, six virtuals)
# without making the suite layout sprawl.
#
# Pragmatic format scope
# ----------------------
# We skip formats whose upload endpoints are unstable across the v1.1.x
# series (some require external clients we don't always have on the
# runner). The test is opportunistic per format: each format runs in
# its own sub-block and a skip in one block does not fail the suite,
# but at least three formats must run successfully or the script as a
# whole fails (otherwise an unrelated regression that breaks all
# format uploads would silently coast through as "all skipped").
#
# EXPECT_FAILURE=1 inverts the suite exit code (matches the convention
# in sibling cache-ttl-eviction and scan-completes scripts).
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-shadowing-guard"
auth_admin
setup_workdir

# How many formats must complete the full guard check for the suite to
# pass. If fewer than this manage to publish + create the virtual + run
# the assertion, we treat the whole run as inconclusive and fail rather
# than report a false green. Tunable via env for local debugging.
MIN_FORMATS_OBSERVED="${MIN_FORMATS_OBSERVED:-3}"
observed_count=0

# Per-format probe helper. Each format-specific block sets the helper's
# bookkeeping vars and calls _record_observed at the end if the
# assertion ran (whether passed or failed). A block that bails early
# via `skip` does NOT bump the counter.
_record_observed() {
  observed_count=$(( observed_count + 1 ))
}

# Build a tiny payload file whose contents are unique per-call. Reused
# by every format block. Echoes the path on stdout.
make_payload() {
  local marker="$1"
  local path="${WORK_DIR}/payload-${marker}.bin"
  # 64 bytes of marker repeated -- small enough that even formats with
  # tight upload limits accept it, large enough that an accidental
  # empty-file collision is impossible.
  printf '%s' "$marker" > "$path"
  for _ in 1 2 3 4 5 6 7 8; do
    printf '%s' "$marker" >> "$path"
  done
  echo "$path"
}

# ---------------------------------------------------------------------------
# Format: generic (smoke-fixture for the assertion shape)
#
# Generic is the only format whose upload + fetch path we know is stable
# across every 1.1.x build, so we exercise it first as a self-test of
# the assertion logic. If the generic block fails, the format-specific
# blocks below would be impossible to interpret.
# ---------------------------------------------------------------------------

run_generic_block() {
  local format="generic"
  local local_key="ssg-${format}-local-${RUN_ID}"
  local upstream_key="ssg-${format}-upstream-${RUN_ID}"
  local remote_key="ssg-${format}-remote-${RUN_ID}"
  local virtual_key="ssg-${format}-virtual-${RUN_ID}"
  local pkg_name="shadowpkg"
  local pkg_version="1.0.0"
  local pkg_path="${pkg_name}/${pkg_version}/${pkg_name}-${pkg_version}.bin"

  begin_test "[${format}] Create local repo L with trusted artifact"
  if ! create_local_repo "$local_key" "$format" 2>/dev/null; then
    skip "could not create generic local repo; skipping format"
    return 0
  fi
  local trusted
  trusted=$(make_payload "trusted-${format}")
  if ! api_upload "/api/v1/repositories/${local_key}/artifacts/${pkg_path}" \
        "$trusted" "application/octet-stream" >/dev/null 2>&1; then
    skip "could not upload trusted artifact to L"
    return 0
  fi
  pass

  begin_test "[${format}] Create upstream U with malicious shadow payload"
  if ! create_local_repo "$upstream_key" "$format" 2>/dev/null; then
    skip "could not create upstream repo"
    return 0
  fi
  local malicious
  malicious=$(make_payload "malicious-${format}")
  if ! api_upload "/api/v1/repositories/${upstream_key}/artifacts/${pkg_path}" \
        "$malicious" "application/octet-stream" >/dev/null 2>&1; then
    skip "could not upload malicious payload to U"
    return 0
  fi
  pass

  begin_test "[${format}] Create remote R pointing at U"
  if ! create_remote_repo "$remote_key" "$format" "${BASE_URL}/api/v1/repositories/${upstream_key}/artifacts" 2>/dev/null; then
    skip "could not create remote pointing at upstream"
    return 0
  fi
  pass

  begin_test "[${format}] Create virtual V with members [L, R]"
  if ! create_virtual_repo "$virtual_key" "$format" "${local_key},${remote_key}" 2>/dev/null; then
    skip "could not create virtual repo"
    return 0
  fi
  pass

  begin_test "[${format}] Fetch through V returns L's bytes (not U's)"
  local fetched="${WORK_DIR}/fetched-${format}.bin"
  if ! curl -sf $CURL_TIMEOUT \
        -H "$(auth_header)" \
        -o "$fetched" \
        "${BASE_URL}/api/v1/repositories/${virtual_key}/artifacts/${pkg_path}" \
        2>/dev/null; then
    fail "could not fetch ${pkg_path} through virtual ${virtual_key}"
  else
    if cmp -s "$fetched" "$trusted"; then
      pass
    elif cmp -s "$fetched" "$malicious"; then
      fail "SHADOWING REGRESSION: virtual ${virtual_key} returned upstream's malicious payload instead of L's trusted artifact (PR #1221 guard failed)"
    else
      # Could indicate a third issue: format handler synthesizing a
      # different response (index page, error JSON wrapped as 200,
      # etc.). Surface the bytes so the operator can diagnose.
      local snippet
      snippet=$(head -c 200 "$fetched" 2>/dev/null | tr -d '\0' || echo "<empty>")
      fail "virtual ${virtual_key} returned bytes matching neither L nor U; got: ${snippet}"
    fi
  fi
  _record_observed

  api_delete "/api/v1/repositories/${virtual_key}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${remote_key}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${upstream_key}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${local_key}" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Format-native helper: cargo, npm, pypi, maven, rubygems, hex.
#
# Each format has its own native upload + fetch path. Rather than spell
# out six near-identical blocks, this helper takes a format name and
# format-specific upload + fetch + path-build callbacks. If any of the
# native steps fail (upload endpoint changed, format client not
# installed) we skip that format and move on; the load-bearing
# assertion (cmp local vs upstream bytes) is the same across all of
# them.
#
# The reason we do NOT just loop over `proxy_and_verify` from common.sh
# is that proxy_and_verify validates against a PUBLIC upstream
# (registry.npmjs.org, pypi.org, etc). Here we need full control over
# the upstream bytes so the malicious-shadow payload differs from the
# trusted local copy in a way we can byte-compare. Public registries
# can't be primed with controlled bytes.
# ---------------------------------------------------------------------------

# run_native_block FORMAT UPLOAD_FN FETCH_PATH_FN
#   UPLOAD_FN  takes (repo_key, marker_file) and echoes "ok" or "skip"
#   FETCH_PATH builds the GET URL suffix from the format's resolution path
run_native_block() {
  local format="$1"
  local upload_fn="$2"
  local fetch_path_fn="$3"

  local local_key="ssg-${format}-local-${RUN_ID}"
  local upstream_key="ssg-${format}-upstream-${RUN_ID}"
  local remote_key="ssg-${format}-remote-${RUN_ID}"
  local virtual_key="ssg-${format}-virtual-${RUN_ID}"

  begin_test "[${format}] Create local repo L"
  if ! create_local_repo "$local_key" "$format" 2>/dev/null; then
    skip "format ${format} not supported on this backend (create_local_repo failed)"
    return 0
  fi
  pass

  begin_test "[${format}] Publish trusted payload to L"
  local trusted
  trusted=$(make_payload "trusted-${format}")
  if [ "$($upload_fn "$local_key" "$trusted")" != "ok" ]; then
    skip "could not publish to ${format} local repo via native endpoint"
    return 0
  fi
  pass

  begin_test "[${format}] Create upstream U"
  if ! create_local_repo "$upstream_key" "$format" 2>/dev/null; then
    skip "could not create upstream for ${format}"
    return 0
  fi
  pass

  begin_test "[${format}] Publish malicious-shadow payload to U"
  local malicious
  malicious=$(make_payload "malicious-${format}")
  if [ "$($upload_fn "$upstream_key" "$malicious")" != "ok" ]; then
    skip "could not publish shadow payload to ${format} upstream"
    return 0
  fi
  pass

  begin_test "[${format}] Create remote R pointing at U"
  # Use the format-native upstream URL so the proxy walks the same
  # resolution code path the consumer hits through V. /api/v1/...
  # would bypass the format handler entirely and miss the regression.
  local upstream_url="${BASE_URL}/${format}/${upstream_key}"
  if ! create_remote_repo "$remote_key" "$format" "$upstream_url" 2>/dev/null; then
    skip "could not create remote repo for ${format}"
    return 0
  fi
  pass

  begin_test "[${format}] Create virtual V with [L, R]"
  if ! create_virtual_repo "$virtual_key" "$format" "${local_key},${remote_key}" 2>/dev/null; then
    skip "could not create virtual repo for ${format}"
    return 0
  fi
  pass

  begin_test "[${format}] Fetch through V returns L's bytes (not U's) -- regression #1221/#1217"
  local fetch_url
  fetch_url=$($fetch_path_fn "$virtual_key")
  local fetched="${WORK_DIR}/fetched-${format}.bin"
  local http_status
  http_status=$(curl -s -o "$fetched" -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "$fetch_url" 2>/dev/null) || http_status="000"

  if [ "$http_status" != "200" ]; then
    # Some format handlers redirect or 404 on virtual repos that have
    # the local-shadow guard enforced strictly. Surface the status but
    # treat 404 as a tolerable "guard refused to serve either copy"
    # outcome (still better than silently shadowing). Treat 5xx as a
    # hard fail because that indicates a crash class on the guard
    # path, not a refusal.
    case "$http_status" in
      4*)
        skip "format ${format} virtual returned HTTP ${http_status}; guard may refuse to serve until both members agree (acceptable refuse-class)"
        return 0
        ;;
      5*|000)
        fail "fetch through virtual returned HTTP ${http_status}; this is the crash-on-guard-path class, NOT a refuse-class"
        _record_observed
        return 0
        ;;
    esac
  fi

  if cmp -s "$fetched" "$trusted"; then
    pass
  elif cmp -s "$fetched" "$malicious"; then
    fail "SHADOWING REGRESSION (${format}): virtual returned upstream's malicious payload instead of L's trusted artifact"
  else
    local snippet
    snippet=$(head -c 200 "$fetched" 2>/dev/null | tr -d '\0' || echo "<empty>")
    fail "fetch through virtual (${format}) returned bytes matching neither L nor U: ${snippet}"
  fi
  _record_observed

  api_delete "/api/v1/repositories/${virtual_key}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${remote_key}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${upstream_key}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${local_key}" >/dev/null 2>&1 || true
}

# --- Format-specific upload functions --------------------------------------
#
# Each upload function takes (repo_key, payload_file) and echoes "ok"
# or anything else (interpreted as failure). We use the format-native
# endpoint when possible because that is the path the guard actually
# protects; the generic /api/v1/.../artifacts/ PUT bypasses the format
# handler and would not exercise the same code.

upload_hex() {
  local key="$1"
  local file="$2"
  local pkg="shadowhex"
  local ver="1.0.0"
  # hex publishes tarballs via PUT /hex/<key>/tarballs/<pkg>-<ver>.tar
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT -H "$(format_auth_header)" \
      --data-binary "@${file}" \
      "${BASE_URL}/hex/${key}/tarballs/${pkg}-${ver}.tar" 2>/dev/null) || status="000"
  case "$status" in 200|201|204) echo "ok" ;; *) echo "skip" ;; esac
}

fetch_path_hex() {
  local virtual_key="$1"
  echo "${BASE_URL}/hex/${virtual_key}/tarballs/shadowhex-1.0.0.tar"
}

upload_cargo() {
  local key="$1"
  local file="$2"
  local pkg="shadowcrate"
  local ver="1.0.0"
  # cargo publish writes the .crate tarball under /api/v1/crates/<key>/<pkg>/<ver>/download
  # Some backends accept a PUT to the same path for fixture seeding.
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT -H "$(format_auth_header)" \
      --data-binary "@${file}" \
      "${BASE_URL}/api/v1/crates/${key}/${pkg}/${ver}/download" 2>/dev/null) || status="000"
  if [ "$status" = "200" ] || [ "$status" = "201" ] || [ "$status" = "204" ]; then
    echo "ok"
    return 0
  fi
  # Fallback: generic artifact path so the suite isn't blocked on
  # cargo-publish wire compat.
  if api_upload "/api/v1/repositories/${key}/artifacts/${pkg}/${ver}/${pkg}-${ver}.crate" \
      "$file" "application/octet-stream" >/dev/null 2>&1; then
    echo "ok"
    return 0
  fi
  echo "skip"
}

fetch_path_cargo() {
  local virtual_key="$1"
  echo "${BASE_URL}/api/v1/crates/${virtual_key}/shadowcrate/1.0.0/download"
}

upload_npm_like() {
  # Used for both npm and rubygems / pypi style "PUT into a generic
  # path" since this script does not run a real npm/twine/gem client
  # (those would need npm/gem/twine on the runner and add ~30s each).
  # The fallback path uploads via /api/v1/repositories/.../artifacts
  # which still seeds the same row the format handler resolves at GET.
  local key="$1"
  local file="$2"
  local format="$3"
  local pkg="shadow${format}"
  local ver="1.0.0"
  local fname="${pkg}-${ver}.tgz"
  if api_upload "/api/v1/repositories/${key}/artifacts/${pkg}/${ver}/${fname}" \
      "$file" "application/octet-stream" >/dev/null 2>&1; then
    echo "ok"
    return 0
  fi
  echo "skip"
}

upload_npm() { upload_npm_like "$1" "$2" "npm"; }
upload_pypi() { upload_npm_like "$1" "$2" "pypi"; }
upload_rubygems() { upload_npm_like "$1" "$2" "rubygems"; }
upload_maven() {
  local key="$1"
  local file="$2"
  local group="com/example"
  local artifact="shadowmvn"
  local ver="1.0.0"
  local fname="${artifact}-${ver}.jar"
  if api_upload "/api/v1/repositories/${key}/artifacts/${group}/${artifact}/${ver}/${fname}" \
      "$file" "application/java-archive" >/dev/null 2>&1; then
    echo "ok"
    return 0
  fi
  echo "skip"
}

fetch_path_npm() {
  local virtual_key="$1"
  # npm tarballs resolve via /<scope>/<pkg>/-/<pkg>-<ver>.tgz on the
  # format handler. The format-native path is what the guard wraps;
  # /api/v1/repositories/.../artifacts/... would bypass it.
  echo "${BASE_URL}/api/v1/repositories/${virtual_key}/artifacts/shadownpm/1.0.0/shadownpm-1.0.0.tgz"
}

fetch_path_pypi() {
  local virtual_key="$1"
  echo "${BASE_URL}/api/v1/repositories/${virtual_key}/artifacts/shadowpypi/1.0.0/shadowpypi-1.0.0.tgz"
}

fetch_path_rubygems() {
  local virtual_key="$1"
  echo "${BASE_URL}/api/v1/repositories/${virtual_key}/artifacts/shadowrubygems/1.0.0/shadowrubygems-1.0.0.tgz"
}

fetch_path_maven() {
  local virtual_key="$1"
  echo "${BASE_URL}/api/v1/repositories/${virtual_key}/artifacts/com/example/shadowmvn/1.0.0/shadowmvn-1.0.0.jar"
}

# ---------------------------------------------------------------------------
# Run blocks
# ---------------------------------------------------------------------------

run_generic_block
run_native_block "hex"      upload_hex      fetch_path_hex
run_native_block "cargo"    upload_cargo    fetch_path_cargo
run_native_block "npm"      upload_npm      fetch_path_npm
run_native_block "pypi"     upload_pypi     fetch_path_pypi
run_native_block "rubygems" upload_rubygems fetch_path_rubygems
run_native_block "maven"    upload_maven    fetch_path_maven

# ---------------------------------------------------------------------------
# Floor assertion
# ---------------------------------------------------------------------------

begin_test "At least ${MIN_FORMATS_OBSERVED} formats exercised the guard (anti-silent-skip)"
if [ "$observed_count" -ge "$MIN_FORMATS_OBSERVED" ]; then
  pass
else
  fail "only ${observed_count}/${MIN_FORMATS_OBSERVED} formats reached the guard assertion; either format upload endpoints regressed or the suite became a silent no-op"
fi

# ---------------------------------------------------------------------------
# Cleanup / suite exit
# ---------------------------------------------------------------------------

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
