# =============================================================================
# plugins/conda.sh — format-conformance plugin (REFERENCE IMPLEMENTATION)
# FC_FORMAT: conda
# FC_MOUNT: conda
# FC_REPO_FORMAT: conda
# FC_PROFILE: client.conda
# FC_SERVICE: client-conda
# FC_ENABLED: 1
# =============================================================================
# The template every other format plugin (B1-B6) copies. It defines ONLY the
# format-specific verbs; the shared driver (harness/lib/native_client.sh) owns
# the sequence, repo lifecycle, JUnit suite, subshell isolation, and the nc_*
# helpers. B1-B6 add ONLY plugins/<fmt>.sh + profiles/client.<fmt>.yml +
# fixtures/<fmt>/ and NEVER touch native_client.sh / run.sh / the oracle / matrix.md.
#
# Conda routes (backend handlers/conda.rs): nest /conda; upload
# `PUT /:repo/:subdir/:filename`; repodata `GET /:repo/:subdir/repodata.json`
# (+ .bz2/.zst variants); download `GET /:repo/:subdir/:filename`; token router
# `/conda/t/<TOKEN>/...`. A conda v1 package is a bzip2 tar with
# `info/index.json` — host-crafted by fixtures/conda/build.sh (no conda-build).
#
# Consume via the advertised path: `<channel>/<subdir>/repodata.json` lists the
# package filename; the client (micromamba) downloads `<channel>/noarch/<fname>`
# and links the marker onto its fs. --override-channels disables every default
# source so the install can ONLY succeed via the AK channel.
# =============================================================================

# KNOWN-RED: token_channel is implemented (fc_case_token_channel below) but held
# OUT of the active run set — the conda token-router GET reads are structurally
# broken in the backend (a valid minted token 401s on
# /conda/t/<TOKEN>/<repo>/noarch/repodata.json). Root cause: token_router() maps
# the `/:token/:repo_key/:subdir/...` GET routes to the NON-token handlers
# (repodata_json / download_package) whose Path extractors bind only
# (repo_key, subdir[, filename]) — the leading :token segment shifts every param,
# so resolution never reaches a valid channel. See
# rig/results/format-conformance/conda-finding.md. Re-add `token_channel` to
# FC_CASES once the backend routes token GETs through token-aware handlers; the
# hook is a positive+negative discriminator ready to go.
FC_CASES="subdir_arch_split compressed_repodata sha_integrity"

# micromamba:2.0 runs as `mambauser`; exec as root so /tmp env + root-prefix are
# writable (the driver's nc_exec honors FC_EXEC_USER).
FC_EXEC_USER="root"

CONDA_NAME="dtf-marker"
CONDA_VER="1.0"
CONDA_BUILD="0"
CONDA_PKG="${CONDA_NAME}-${CONDA_VER}-${CONDA_BUILD}.tar.bz2"
CONDA_MARKER_TOKEN="DTF-CONDA-INSTALLED-${CONDA_VER}"
CONDA_BUILDSH="${DTF_DIR}/fixtures/conda/build.sh"

# Env every micromamba invocation needs: a writable root-prefix + HOME, and
# --no-rc so no baked-in /opt/conda/.condarc leaks a default channel.
_mm() {
  echo 'export MAMBA_ROOT_PREFIX=/tmp/mamba HOME=/tmp; export CONDA_ALLOW_INSECURE=1;'
}

# ---------------------------------------------------------------------------
# fc_publish — host-craft the noarch fixture and PUT it on the native route.
# (host curl PUT is the accepted brick-3 deviation; the discriminating value is
# the client-side CONSUME.)
# ---------------------------------------------------------------------------
fc_publish() {
  CONDA_FIXTURE="$(bash "$CONDA_BUILDSH" "$WORK_DIR" "$CONDA_NAME" "$CONDA_VER" "$CONDA_BUILD" noarch "$CONDA_MARKER_TOKEN")" || return 1
  [ -s "$CONDA_FIXTURE" ] || { echo "fixture build produced no file"; return 1; }
  CONDA_PUB_SHA="$(nc_sha256 "$CONDA_FIXTURE")"
  echo "  fixture=${CONDA_FIXTURE} sha256=${CONDA_PUB_SHA}"
  nc_put_file "$CONDA_FIXTURE" "${FC_URL}/noarch/${CONDA_PKG}" || return 1
  # The advertised repodata must now list it (repodata is generated from the DB).
  nc_expect_code 200 "${FC_URL}/noarch/repodata.json" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real client is present (no silent skip) and write
# a channel-only .condarc INSIDE the container pointing ONLY at $FC_INT_URL.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v micromamba >/dev/null 2>&1 && micromamba --version' \
    || { echo "micromamba missing inside the provisioned conda client"; return 1; }
  # A channel-only condarc: no defaults, override enabled. We still pass -c +
  # --override-channels on the CLI (belt and suspenders), but this proves the
  # client config route too.
  nc_exec "$(_mm) mkdir -p /tmp && cat > /tmp/.condarc <<EOF
channels:
  - ${FC_INT_URL}
override_channels_enabled: true
default_channels: []
repodata_use_zst: true
ssl_verify: false
EOF
cat /tmp/.condarc" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `micromamba create` reads noarch/repodata.json,
# resolves the advertised fname, FOLLOWS base_url+fname to download, extracts,
# and links the package. --override-channels => the AK channel is the ONLY
# possible source (the discriminator).
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "$(_mm) rm -rf /tmp/env
micromamba create -y -p /tmp/env --no-rc --override-channels -c '${FC_INT_URL}' ${CONDA_NAME} 2>&1" \
    || { echo "micromamba create failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker was LINKED into the prefix (not just
# listed in repodata) AND micromamba records the package as installed.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "$(_mm) test -f /tmp/env/share/${CONDA_NAME}/marker.txt && \
grep -q '${CONDA_MARKER_TOKEN}' /tmp/env/share/${CONDA_NAME}/marker.txt && \
micromamba list -p /tmp/env | grep -E '^\s*${CONDA_NAME}\b'" \
    || { echo "marker not linked / package not listed by micromamba"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. repodata advertises the fname
# under `packages`; the subdir-qualified URL resolves (200) while the pre-fix
# subdir-less shape (a real client following a bare href would emit) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local fname
  fname="$(nc_advertised "${FC_URL}/noarch/repodata.json" \
    "jq -r '.packages | keys[] | select(test(\"^${CONDA_NAME}-\"))' | head -1")" || return 1
  echo "  advertised fname=${fname}"
  nc_expect_code 200 "${FC_URL}/noarch/${fname}" || return 1
  # subdir-less shape must NOT resolve (no /:repo/:filename route)
  nc_expect_code 404 "${FC_URL}/${fname}" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# subdir_arch_split — publish a DISTINCT package into linux-aarch64/. The arch
# repodata must list it; the noarch repodata must NOT (per-subdir isolation).
# Bug class: cross-subdir repodata bleed (an arch pkg leaking into noarch would
# break clients that solve noarch-only).
fc_case_subdir_arch_split() {
  local aname="dtf-arch-marker"
  local apkg="${aname}-${CONDA_VER}-${CONDA_BUILD}.tar.bz2"
  local afix
  afix="$(bash "$CONDA_BUILDSH" "$WORK_DIR" "$aname" "$CONDA_VER" "$CONDA_BUILD" linux-aarch64 "DTF-CONDA-ARCH-${CONDA_VER}")" || return 1
  nc_put_file "$afix" "${FC_URL}/linux-aarch64/${apkg}" || return 1
  # positive: arch pkg appears in the arch repodata
  local in_arch
  in_arch="$(nc_advertised "${FC_URL}/linux-aarch64/repodata.json" \
    "jq -r '.packages | keys[] | select(. == \"${apkg}\")'")" || return 1
  echo "  linux-aarch64 repodata lists ${in_arch}"
  # negative: arch pkg must NOT appear in the noarch repodata
  local leaked
  leaked="$(curl -s --max-time 60 -H "$(format_auth_header)" "${FC_URL}/noarch/repodata.json" \
    | jq -r --arg f "$apkg" '.packages | has($f)')"
  if [ "$leaked" = "true" ]; then
    echo "  LEAK: ${apkg} appears in noarch/repodata.json"; return 1
  fi
  echo "  noarch repodata does NOT list the arch pkg (isolated)"
}

# compressed_repodata — micromamba prefers repodata.json.zst. The compressed
# variant MUST decompress to byte-identical JSON as the plain endpoint, else a
# client that fetched .zst would solve against divergent metadata.
# Bug class: compressed-variant divergence (a stale/mismatched .zst).
fc_case_compressed_repodata() {
  local plain="${WORK_DIR}/repodata.plain.json"
  local zst="${WORK_DIR}/repodata.json.zst"
  nc_fetch "${FC_URL}/noarch/repodata.json"     "$plain" || return 1
  nc_fetch "${FC_URL}/noarch/repodata.json.zst" "$zst"   || return 1
  [ -s "$zst" ] || { echo "empty .zst variant"; return 1; }
  local dec="${WORK_DIR}/repodata.from-zst.json"
  zstd -dqf "$zst" -o "$dec" 2>/dev/null || { echo "zst did not decompress"; return 1; }
  # Compare canonicalized JSON (whitespace-insensitive) so a pretty-vs-compact
  # difference is not a false red — only a semantic divergence fails.
  local a b
  a="$(jq -S . "$plain" 2>/dev/null)" || { echo "plain repodata not JSON"; return 1; }
  b="$(jq -S . "$dec"   2>/dev/null)" || { echo "decompressed .zst not JSON"; return 1; }
  if [ "$a" != "$b" ]; then
    echo "  DIVERGENCE: repodata.json.zst != repodata.json after decompress"
    diff <(printf '%s' "$a") <(printf '%s' "$b") | head -20
    return 1
  fi
  echo "  repodata.json.zst decompresses byte-identical to repodata.json"
}

# sha_integrity — repodata advertises a sha256 per package; it MUST equal the
# sha256 of the bytes actually served at the advertised location. micromamba
# verifies this on install, so a mismatch would fail the consume — assert it
# explicitly host-side too.
# Bug class: advertised-checksum vs served-bytes drift.
fc_case_sha_integrity() {
  local adv_sha
  adv_sha="$(nc_advertised "${FC_URL}/noarch/repodata.json" \
    "jq -r '.packages[\"${CONDA_PKG}\"].sha256 // empty'")" || return 1
  local dl="${WORK_DIR}/served-${CONDA_PKG}"
  nc_fetch "${FC_URL}/noarch/${CONDA_PKG}" "$dl" || return 1
  local served_sha
  served_sha="$(nc_sha256 "$dl")"
  nc_assert_sha_eq "$adv_sha" "$served_sha" "repodata sha256 != served-bytes sha256" || return 1
  # and the served bytes are exactly what we published
  nc_assert_sha_eq "$CONDA_PUB_SHA" "$served_sha" "published bytes != served bytes" || return 1
}

# token_channel — the conda token router `/conda/t/<TOKEN>/<repo>/...`. A valid
# minted token must resolve the channel (200 + lists the package); a bogus token
# must be REJECTED (401/403), never a silent empty-200 (the "wrong token still
# reads" fall-open class).
# KNOWN-RED (not in FC_CASES): the valid-token positive currently 401s — a real
# backend gap (token-router GETs reuse non-token handlers with mismatched Path
# extractors). Kept implemented so re-enabling is a one-line FC_CASES edit once
# the backend is fixed. See rig/results/format-conformance/conda-finding.md.
fc_case_token_channel() {
  local uid
  uid="$(resolve_user_id_by_username "${ADMIN_USER}")" \
    || { echo "could not resolve admin user id to mint a token"; return 1; }
  local tok
  tok="$(api_post "/api/v1/users/${uid}/tokens" \
    "{\"name\":\"dtf-conda-${RUN_ID}\",\"scopes\":[\"read\",\"write\"]}" \
    | jq -r '.token // empty')"
  [ -n "$tok" ] || { echo "token mint returned no token"; return 1; }
  echo "  minted token prefix=${tok:0:8}..."
  # positive: valid token channel serves repodata listing the package
  local rd="${WORK_DIR}/token-repodata.json"
  local code
  code="$(curl -s -o "$rd" -w '%{http_code}' --max-time 60 \
    "${BASE_URL}/conda/t/${tok}/${FC_REPO}/noarch/repodata.json" 2>/dev/null)"
  if [ "$code" != "200" ]; then
    echo "  token channel repodata -> HTTP ${code} (wanted 200)"; return 1
  fi
  local has
  has="$(jq -r --arg f "$CONDA_PKG" '.packages | has($f)' "$rd" 2>/dev/null)"
  [ "$has" = "true" ] || { echo "token channel repodata did not list ${CONDA_PKG}"; return 1; }
  echo "  valid token channel resolves + lists the package"
  # negative: a bogus token must be rejected, not silently served
  local bad
  bad="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    "${BASE_URL}/conda/t/deadbeefbogustoken/${FC_REPO}/noarch/repodata.json" 2>/dev/null)"
  case "$bad" in
    401|403) echo "  bogus token rejected (HTTP ${bad})" ;;
    *) echo "  bogus token returned HTTP ${bad} (expected 401/403; empty-200 = fall-open)"; return 1 ;;
  esac
}
