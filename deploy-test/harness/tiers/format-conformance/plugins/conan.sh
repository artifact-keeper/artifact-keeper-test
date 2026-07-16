# =============================================================================
# plugins/conan.sh — format-conformance plugin
# FC_FORMAT: conan
# FC_MOUNT: conan
# FC_REPO_FORMAT: conan
# FC_PROFILE: client.conan
# FC_SERVICE: client-conan
# FC_ENABLED: 1
# =============================================================================
# Conan 2 hosted publish->consume conformance. Routes (handlers/conan.rs): nest
# /conan; ping /:repo/v{1,2}/ping; authenticate /:repo/v2/users/authenticate;
# search /:repo/v2/conans/search; recipe latest
# /:repo/v2/conans/:name/:version/:user/:channel/latest; revisions + files list
# + file download/upload; package-level latest/revisions/files. A reference with
# no user/channel uses the `_/_` placeholders.
#
# The REAL client is Conan 2 (installed via pip in python:3.12-slim — arm64-safe;
# conanio/* images are amd64-history, the brick-4 trap). fc_publish builds the
# fixture recipe with `conan create` (a settings-dependent package_id) and
# `conan upload`s recipe + binary to AK. fc_consume then, with an EMPTY cache,
# runs `conan install --requires=dtf-marker/1.0 -r dtf --build=never`: the
# pre-built binary MUST be resolved via /latest -> revisions -> files and
# fetched from AK, and `--build=never` forbids any local rebuild (the
# discriminator). fc_assert proves the marker file was unpacked client-side.
# =============================================================================
FC_CASES="two_revisions search_remote package_id_binary"

CONAN_NAME="dtf-marker"
CONAN_VER="1.0"
CONAN_REF="${CONAN_NAME}/${CONAN_VER}"
CONAN_MARKER="DTF-CONAN-INSTALLED-1.0"
CONAN_RECIPE="${DTF_DIR}/fixtures/conan/conanfile.py"

# Every conan invocation gets a stable HOME/CONAN_HOME and non-interactive mode.
# `set -o pipefail` so a failed `conan ...` piped to `tail` is NOT masked by
# tail's exit 0 (the whole point is that create/upload/install failures fail the
# hook, and that a missing-binary install genuinely returns non-zero).
_conan_env() { echo 'set -o pipefail; export HOME=/root CONAN_HOME=/root/.conan2 CONAN_NON_INTERACTIVE=1;'; }

# ---------------------------------------------------------------------------
# fc_publish — install conan (once), write compiler-less profiles, `conan
# create` the fixture, then authenticate + upload recipe+binary to AK.
# (In-container publish via the real client; the discriminating value is the
# empty-cache CONSUME below.)
# ---------------------------------------------------------------------------
fc_publish() {
  # tooling: Conan 2 via pip (arch-neutral). Idempotent; fc_publish runs first
  # so every later hook in this subshell sees conan.
  nc_exec -t 360 "$(_conan_env)
pip install --quiet --disable-pip-version-check --no-input 'conan>=2,<3' 2>&1 | tail -2
conan --version" || { echo "conan pip install failed"; return 1; }

  # Compiler-less default + an 'alt' profile (different arch/build_type) so the
  # package_id_binary edge case can force a distinct, un-built package_id. No
  # gcc on the image, but nothing is compiled (the marker is written in
  # package()), so a hand-written profile avoids `conan profile detect`'s
  # compiler probe entirely.
  nc_exec "$(_conan_env)
mkdir -p \$CONAN_HOME/profiles
cat > \$CONAN_HOME/profiles/default <<'EOF'
[settings]
os=Linux
arch=armv8
build_type=Release
compiler=gcc
compiler.version=12
compiler.cppstd=gnu17
compiler.libcxx=libstdc++11
EOF
cat > \$CONAN_HOME/profiles/alt <<'EOF'
[settings]
os=Linux
arch=x86_64
build_type=Debug
compiler=gcc
compiler.version=12
compiler.cppstd=gnu17
compiler.libcxx=libstdc++11
EOF
echo profiles-written" || return 1

  nc_exec "mkdir -p /work/recipe" || return 1
  nc_copy_to_ctr "$CONAN_RECIPE" /work/recipe/conanfile.py \
    || { echo "copy conanfile.py failed"; return 1; }

  # Build the binary package for the default profile into the local cache.
  nc_exec -t 240 "$(_conan_env) cd /work/recipe && conan create . 2>&1 | tail -15" \
    || { echo "conan create failed"; return 1; }

  # Register the AK remote, authenticate, upload recipe + binary.
  nc_exec -t 240 "$(_conan_env)
conan remote add dtf '${FC_INT_URL}' --force
conan remote login dtf '${ADMIN_USER}' -p '${ADMIN_PASS}'
conan upload '${CONAN_REF}' -r dtf -c 2>&1 | tail -20" \
    || { echo "conan upload failed"; return 1; }

  # The advertised /latest must now resolve.
  nc_expect_code 200 "${FC_URL}/v2/conans/${CONAN_NAME}/${CONAN_VER}/_/_/latest" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real client is present and the dtf remote points
# ONLY at $FC_INT_URL (no other remote / no conancenter default).
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec "$(_conan_env)
conan --version >/dev/null || exit 1
conan remote list
conan remote list | grep -E '^dtf:' | grep -qF '${FC_INT_URL}'" \
    || { echo "conan client / dtf remote not configured to ${FC_INT_URL}"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client, EMPTY cache. `conan install --build=never`
# resolves the recipe via /latest -> revisions -> files, then fetches the
# pre-built binary package from AK. --build=never forbids any local rebuild, so
# a missing/unservable advertised binary would FAIL here (the #2580 path).
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "$(_conan_env)
conan remove '*' -c
conan install --requires='${CONAN_REF}' -r dtf --build=never 2>&1 | tail -25" \
    || { echo "conan install --build=never failed (binary not fetched from AK)"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker file was UNPACKED from the fetched
# binary into the conan package cache (not merely that /latest listed a rev).
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "$(_conan_env)
f=\$(find \$CONAN_HOME -path '*share/dtf-marker/marker.txt' 2>/dev/null | head -1)
test -n \"\$f\" && grep -q '${CONAN_MARKER}' \"\$f\" && echo \"marker unpacked at \$f\"" \
    || { echo "marker not found in conan cache after install"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2247/#2580 discriminator. /latest advertises a
# recipe revision; its files listing includes conanfile.py + conanmanifest.txt,
# each resolving 200; a bogus revision's file path 404s (positive + negative).
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local rev
  rev="$(nc_advertised "${FC_URL}/v2/conans/${CONAN_NAME}/${CONAN_VER}/_/_/latest" \
    "jq -r '.revision // empty'")" || return 1
  echo "  recipe revision=${rev}"
  local files="${FC_URL}/v2/conans/${CONAN_NAME}/${CONAN_VER}/_/_/revisions/${rev}/files"
  local list="${WORK_DIR}/conan-files.json"
  nc_fetch "$files" "$list" || return 1
  jq -e '.files["conanfile.py"] and .files["conanmanifest.txt"]' "$list" >/dev/null \
    || { echo "files listing missing conanfile.py/conanmanifest.txt: $(cat "$list")"; return 1; }
  # each advertised file resolves (the #2247 conanfile.py-missing class)
  nc_expect_code 200 "${files}/conanfile.py" || return 1
  nc_expect_code 200 "${files}/conanmanifest.txt" || return 1
  # negative: a bogus recipe revision must NOT resolve a real file
  nc_expect_code 404 \
    "${FC_URL}/v2/conans/${CONAN_NAME}/${CONAN_VER}/_/_/revisions/deadbeefdeadbeef/files/conanfile.py" \
    || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# two_revisions — modify + re-create/upload; `latest` must advance to the NEWER
# recipe revision and an empty-cache install must fetch it.
# Bug class: stale /latest (a consumer pinned to an old revision).
fc_case_two_revisions() {
  local rev1 rev2
  rev1="$(curl -s -H "$(format_auth_header)" \
    "${FC_URL}/v2/conans/${CONAN_NAME}/${CONAN_VER}/_/_/latest" | jq -r '.revision // empty')"
  # Changing conanfile.py content changes the recipe revision (hash of exports).
  nc_exec -t 240 "$(_conan_env)
printf '\n# rev2 marker %s\n' '${RUN_ID}' >> /work/recipe/conanfile.py
cd /work/recipe && conan create . 2>&1 | tail -5
conan upload '${CONAN_REF}' -r dtf -c 2>&1 | tail -8" || return 1
  rev2="$(curl -s -H "$(format_auth_header)" \
    "${FC_URL}/v2/conans/${CONAN_NAME}/${CONAN_VER}/_/_/latest" | jq -r '.revision // empty')"
  echo "  rev1=${rev1} rev2=${rev2}"
  [ -n "$rev2" ] && [ "$rev2" != "$rev1" ] \
    || { echo "latest did not advance to a new revision"; return 1; }
  # empty-cache install must resolve + fetch the newer revision
  nc_exec -t 180 "$(_conan_env)
conan remove '*' -c
conan install --requires='${CONAN_REF}' -r dtf --build=never 2>&1 | tail -8" || return 1
  nc_exec "$(_conan_env) conan list '${CONAN_REF}#*' -c 2>&1 | grep -qF '${rev2}'" \
    || { echo "installed recipe revision is not the newer rev2 (${rev2})"; return 1; }
}

# search_remote — `/v2/conans/search?q=dtf-*` (and the real `conan search`) must
# return the published recipe.
# Bug class: search index not populated / not consulted (#2058 sibling).
fc_case_search_remote() {
  local out
  out="$(curl -s -H "$(format_auth_header)" "${FC_URL}/v2/conans/search?q=dtf-%2A")"
  echo "  search results: ${out}"
  echo "$out" | jq -e '(.results // []) | map(startswith("dtf-marker/")) | any' >/dev/null \
    || { echo "conan search API did not return dtf-marker"; return 1; }
  nc_exec "$(_conan_env) conan search 'dtf-*' -r dtf 2>&1 | tail -15 | grep -q 'dtf-marker'" \
    || { echo "real 'conan search -r dtf' did not find dtf-marker"; return 1; }
}

# package_id_binary — install under a DIFFERENT profile with --build=never MUST
# fail missing-binary: the binary for that package_id was never built/uploaded.
# Proves package_id resolution consults the real revisions tree, not a wildcard.
# Bug class: package_id over-match (serving any binary regardless of settings).
fc_case_package_id_binary() {
  local out rc
  out="$(nc_exec -t 150 "$(_conan_env)
conan remove '*' -c
conan install --requires='${CONAN_REF}' -r dtf -pr:h alt -pr:b alt --build=never 2>&1 | tail -20")"
  rc=$?
  echo "$out"
  if [ "$rc" -eq 0 ]; then
    echo "expected missing-binary failure under alt profile, but install SUCCEEDED (over-match)"
    return 1
  fi
  echo "$out" | grep -qiE 'missing|no binary|not built|--build|cannot find' \
    || { echo "install failed but not with a missing-binary diagnostic"; return 1; }
  # positive control: the default profile still resolves the binary from AK
  nc_exec -t 150 "$(_conan_env)
conan remove '*' -c
conan install --requires='${CONAN_REF}' -r dtf --build=never 2>&1 | tail -5" \
    || { echo "default-profile install regressed"; return 1; }
}
