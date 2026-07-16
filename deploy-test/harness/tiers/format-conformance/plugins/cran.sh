# =============================================================================
# plugins/cran.sh — format-conformance plugin (CRAN / R)
# FC_FORMAT: cran
# FC_MOUNT: cran
# FC_REPO_FORMAT: cran
# FC_PROFILE: client.cran
# FC_SERVICE: client-cran
# FC_ENABLED: 1
# =============================================================================
# CRAN routes (backend handlers/cran.rs): nest /cran; source index
# `GET /:repo/src/contrib/PACKAGES` (+ `.gz`); source pkg download/upload
# `GET|PUT /:repo/src/contrib/:filename`. The PACKAGES index is a DCF text
# document generated from the DB (one `Package:/Version:` record per artifact).
#
# A CRAN source package is "just an archive with metadata" — a gzipped tar whose
# top-level dir is the package name and which carries DESCRIPTION + R sources.
# Host-crafted by fixtures/cran/build.sh (no R toolchain needed to BUILD it).
#
# Consume via the advertised path: R's `install.packages(type="source")` reads
# `<repos>/src/contrib/PACKAGES`, resolves the highest advertised version,
# FOLLOWS it to `src/contrib/<name>_<version>.tar.gz`, downloads + installs, and
# we then CALL the package's exported marker function. `repos=<AK-only>` is the
# discriminator: the install can succeed ONLY via the AK repo (no default CRAN).
# =============================================================================
FC_CASES="packages_gz_parity available_packages version_upgrade"

# rocker/r-ver runs as root by default; keep it explicit so the temp lib and
# site-library are writable.
FC_EXEC_USER="root"

CRAN_NAME="dtf.marker"
CRAN_VER="1.0"
CRAN_VER2="1.1"
CRAN_TARBALL="${CRAN_NAME}_${CRAN_VER}.tar.gz"
CRAN_MARKER_TOKEN="DTF-CRAN-INSTALLED-${CRAN_VER}"
CRAN_BUILDSH="${DTF_DIR}/fixtures/cran/build.sh"

# ---------------------------------------------------------------------------
# fc_publish — host-craft the source tarball and PUT it on the native route.
# (host curl PUT is the accepted brick-3 deviation; the discriminating value is
# the client-side CONSUME.)
# ---------------------------------------------------------------------------
fc_publish() {
  CRAN_FIXTURE="$(bash "$CRAN_BUILDSH" "$WORK_DIR" "$CRAN_NAME" "$CRAN_VER" "$CRAN_MARKER_TOKEN")" || return 1
  [ -s "$CRAN_FIXTURE" ] || { echo "fixture build produced no file"; return 1; }
  CRAN_PUB_SHA="$(nc_sha256 "$CRAN_FIXTURE")"
  echo "  fixture=${CRAN_FIXTURE} sha256=${CRAN_PUB_SHA}"
  nc_put_file "$CRAN_FIXTURE" "${FC_URL}/src/contrib/${CRAN_TARBALL}" || return 1
  # The advertised index must now list it (PACKAGES is generated from the DB).
  nc_expect_code 200 "${FC_URL}/src/contrib/PACKAGES" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real client (Rscript) is present (no silent skip)
# and write a repos-only Rprofile INSIDE the container pointing ONLY at the AK
# repo, so a fallback to a default CRAN mirror cannot mask a broken AK repo.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v Rscript >/dev/null 2>&1 && Rscript --version' \
    || { echo "Rscript missing inside the provisioned cran client"; return 1; }
  # A repos-only site Rprofile: the ONLY configured repository is the AK repo.
  nc_exec "mkdir -p /tmp/rlib && cat > /tmp/dtf.Rprofile <<EOF
options(repos = c(DTF = '${FC_INT_URL}'))
options(pkgType = 'source')
.libPaths('/tmp/rlib')
EOF
cat /tmp/dtf.Rprofile" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. install.packages reads src/contrib/PACKAGES,
# resolves the advertised tarball, FOLLOWS it to src/contrib/<name>_<ver>.tar.gz,
# downloads + installs into /tmp/rlib. repos=<AK-only> => the AK repo is the
# ONLY possible source (the discriminator). We requireNamespace afterwards so a
# failed install (warning-only in R) becomes a hard non-zero exit.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "R_PROFILE_USER=/tmp/dtf.Rprofile Rscript -e '
    .libPaths(\"/tmp/rlib\")
    install.packages(\"${CRAN_NAME}\", repos=\"${FC_INT_URL}\", type=\"source\", lib=\"/tmp/rlib\")
    if (!requireNamespace(\"${CRAN_NAME}\", quietly=TRUE, lib.loc=\"/tmp/rlib\")) {
      cat(\"INSTALL FAILED: ${CRAN_NAME} not available after install.packages\\n\")
      quit(status=1)
    }
    cat(\"INSTALLED ${CRAN_NAME}\", as.character(packageVersion(\"${CRAN_NAME}\", lib.loc=\"/tmp/rlib\")), \"\\n\")
  '" || { echo "install.packages failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the package is loadable AND its exported marker
# function returns the grep-able token (not merely that PACKAGES listed it).
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "Rscript -e '
    .libPaths(\"/tmp/rlib\")
    library(${CRAN_NAME}, lib.loc=\"/tmp/rlib\")
    cat(dtf_marker_ping(), \"\\n\")
  ' | grep -q '${CRAN_MARKER_TOKEN}'" \
    || { echo "marker function did not return the token"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. PACKAGES advertises the package
# (Package/Version); the src/contrib-qualified tarball URL resolves (200) while
# the repo-root shape (a client following a bare filename) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  # Positive: PACKAGES advertises the package name + version.
  local pkg
  pkg="$(nc_advertised "${FC_URL}/src/contrib/PACKAGES" \
    "awk '/^Package: ${CRAN_NAME}\$/{p=1} p&&/^Version:/{print \$2; exit}'")" || return 1
  echo "  PACKAGES advertises ${CRAN_NAME} version=${pkg}"
  [ "$pkg" = "$CRAN_VER" ] || { echo "advertised version ${pkg} != ${CRAN_VER}"; return 1; }
  # Positive: the advertised src/contrib tarball resolves.
  nc_expect_code 200 "${FC_URL}/src/contrib/${CRAN_TARBALL}" || return 1
  # Negative: the repo-root (src/contrib-less) shape must NOT resolve.
  nc_expect_code 404 "${FC_URL}/${CRAN_TARBALL}" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# packages_gz_parity — R prefers the compressed PACKAGES.gz. It MUST gunzip to
# byte-identical content as the plain PACKAGES endpoint, else a client that
# fetched .gz would resolve against divergent metadata.
# Bug class: compressed-index divergence (a stale/mismatched PACKAGES.gz).
fc_case_packages_gz_parity() {
  local plain="${WORK_DIR}/cran-PACKAGES"
  local gz="${WORK_DIR}/cran-PACKAGES.gz"
  nc_fetch "${FC_URL}/src/contrib/PACKAGES"    "$plain" || return 1
  nc_fetch "${FC_URL}/src/contrib/PACKAGES.gz" "$gz"    || return 1
  [ -s "$plain" ] || { echo "empty PACKAGES"; return 1; }
  [ -s "$gz" ]    || { echo "empty PACKAGES.gz"; return 1; }
  local dec="${WORK_DIR}/cran-PACKAGES.from-gz"
  gunzip -c "$gz" > "$dec" 2>/dev/null || { echo "PACKAGES.gz did not decompress"; return 1; }
  if ! cmp -s "$plain" "$dec"; then
    echo "  DIVERGENCE: PACKAGES.gz != PACKAGES after gunzip"
    diff "$plain" "$dec" | head -20
    return 1
  fi
  echo "  PACKAGES.gz gunzips byte-identical to PACKAGES"
}

# available_packages — the R client's `available.packages()` (the real API
# install.packages resolves through) must return EXACTLY the published set for
# this repo (only dtf.marker), at the published version.
# Bug class: index bleed / phantom entries (a repo advertising more than it holds).
fc_case_available_packages() {
  local out="${WORK_DIR}/cran-available.txt"
  nc_exec "Rscript -e '
    ap <- available.packages(repos=\"${FC_INT_URL}\", type=\"source\")
    cat(paste(rownames(ap), ap[,\"Version\"], sep=\"@\"), sep=\"\\n\")
  '" > "$out" 2>&1 || { echo "available.packages failed"; cat "$out"; return 1; }
  # Positive: exactly one package, and it is dtf.marker@1.0.
  local rows
  rows="$(grep -c '@' "$out" || true)"
  echo "  available.packages returned ${rows} row(s):"; sed 's/^/    /' "$out"
  grep -qx "${CRAN_NAME}@${CRAN_VER}" "$out" || { echo "expected ${CRAN_NAME}@${CRAN_VER} in available set"; return 1; }
  # Negative: no phantom packages (this repo only holds dtf.marker at this point).
  [ "$rows" = "1" ] || { echo "expected exactly 1 available package, got ${rows}"; return 1; }
}

# version_upgrade — publish 1.1; the client must resolve the NEWER version, and
# the OLD tarball must still be fetchable (immutable history).
# Bug class: stale index / lost-old-version on upgrade.
fc_case_version_upgrade() {
  local fix2 tarball2="${CRAN_NAME}_${CRAN_VER2}.tar.gz"
  fix2="$(bash "$CRAN_BUILDSH" "$WORK_DIR" "$CRAN_NAME" "$CRAN_VER2" "DTF-CRAN-INSTALLED-${CRAN_VER2}")" || return 1
  nc_put_file "$fix2" "${FC_URL}/src/contrib/${tarball2}" || return 1
  # Positive: available.packages now resolves 1.1 (R picks the highest version).
  local resolved
  resolved="$(nc_exec "Rscript -e '
    ap <- available.packages(repos=\"${FC_INT_URL}\", type=\"source\")
    cat(ap[\"${CRAN_NAME}\", \"Version\"])
  '" 2>/dev/null | tr -d '[:space:]')"
  echo "  available.packages resolves ${CRAN_NAME} -> ${resolved}"
  [ "$resolved" = "$CRAN_VER2" ] || { echo "expected resolved version ${CRAN_VER2}, got ${resolved}"; return 1; }
  # Positive: a fresh install picks up 1.1.
  nc_exec -t 240 "Rscript -e '
    .libPaths(\"/tmp/rlib2\"); dir.create(\"/tmp/rlib2\", showWarnings=FALSE)
    install.packages(\"${CRAN_NAME}\", repos=\"${FC_INT_URL}\", type=\"source\", lib=\"/tmp/rlib2\")
    v <- as.character(packageVersion(\"${CRAN_NAME}\", lib.loc=\"/tmp/rlib2\"))
    if (v != \"${CRAN_VER2}\") { cat(\"got version\", v, \"\\n\"); quit(status=1) }
    cat(\"UPGRADED to\", v, \"\\n\")
  '" || { echo "fresh install did not resolve ${CRAN_VER2}"; return 1; }
  # Negative/immutable: the OLD tarball is still fetchable at its advertised path.
  nc_expect_code 200 "${FC_URL}/src/contrib/${CRAN_TARBALL}" || return 1
}
