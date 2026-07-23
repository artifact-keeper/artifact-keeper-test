#!/usr/bin/env bash
# =============================================================================
# tiers/nexus-go-apt/nexus_seed.sh — seed the #2784 Go + apt fixtures into Nexus
# =============================================================================
# Seeds two HOSTED source repos so the AK migration maps them to *local* repos
# (a Nexus proxy/group maps to an AK `remote`/`virtual` repo, and the migration's
# create_repository does not populate upstream_url, so a proxy source fails the
# repositories.check_upstream_url constraint — hosted is the only source shape
# whose artifacts actually transfer):
#
#   1. go-hosted  (format go)  — Nexus has NO REST recipe for a Go *hosted*
#      repo (only proxy/group), so it is created through the Nexus Groovy
#      scripting API (`repository.createGolangHosted`, enabled on the profile via
#      -Dnexus.scripts.allowCreation=true). A byte-exact Go module zip is built
#      on the host with fixtures/go/build.sh (no Go toolchain needed) and PUT to
#      the Go module-proxy path `/<module>/@v/<version>.zip`; Nexus derives the
#      .info/.mod from it. Internally Nexus calls the format "Golang" — the very
#      name #2784 had to map to AK's `go`.
#
#   2. apt-hosted (format apt) — an apt hosted repo needs a signing keypair; the
#      REST API rejects an empty one (400), but the Groovy `createAptHosted`
#      accepts an empty pgpPrivateKey, so no GPG material is required on the
#      host. A minimal .deb is built on the host (dpkg-deb, or an `ar`+`tar`
#      fallback) and uploaded via the components API (`apt.asset`).
#
# Records the fixture identity (repo keys, module path/version, deb filename) to
# the per-run state file so assert.sh can drive the migration and assert exact
# rows/paths. All steps idempotent (run.sh gives a fresh `down -v` Nexus per run,
# but --keep re-runs must not double-fail).
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

GO_REPO="${GO_REPO:-go-hosted}"
APT_REPO="${APT_REPO:-apt-hosted}"
GO_MODULE="${GO_MODULE:-example.com/dtf/marker}"
GO_VERSION="${GO_VERSION:-v1.0.0}"
DEB_PKG="${DEB_PKG:-dtf-hello}"
DEB_VER="${DEB_VER:-1.0.0}"
DEB_ARCH="${DEB_ARCH:-amd64}"
GOAPT_FIXTURES_FILE="${NEXUS_STATE_DIR}/goapt_fixtures.json"

nexus_is_up || die "Nexus is not running — run nexus_bootstrap.sh first."
[ -f "${NEXUS_PASS_FILE}" ] || die "No resolved admin password — run nexus_bootstrap.sh first."

# --- Groovy scripting helper (create-or-update, then run) --------------------
nx_groovy() {  # $1=script-name  $2=groovy-body  -> echoes the "result" string
  local name="$1" body="$2" payload
  payload=$(jq -nc --arg n "$name" --arg c "$body" '{name:$n,type:"groovy",content:$c}')
  nx_curl POST "/service/rest/v1/script" -H 'Content-Type: application/json' \
    --data "$payload" -o /dev/null 2>/dev/null || true
  nx_curl PUT "/service/rest/v1/script/${name}" -H 'Content-Type: application/json' \
    --data "$payload" -o /dev/null 2>/dev/null || true
  nx_curl POST "/service/rest/v1/script/${name}/run" -H 'Content-Type: text/plain' \
    | jq -r '.result // empty'
}

repo_exists() {
  nx_curl GET "/service/rest/v1/repositories" \
    | jq -e --arg n "$1" '.[]|select(.name==$n)' >/dev/null 2>&1
}

# --- 1. create go-hosted via Groovy (no REST recipe for Go hosted) -----------
if repo_exists "${GO_REPO}"; then
  log "go repo '${GO_REPO}' already present."
else
  log "Creating Go hosted repo '${GO_REPO}' via Groovy (createGolangHosted) ..."
  res=$(nx_groovy dtf_mk_go "import org.sonatype.nexus.repository.config.WritePolicy; repository.createGolangHosted('${GO_REPO}','default',true,WritePolicy.ALLOW); return 'go-created'")
  log "  createGolangHosted -> ${res:-<no result>}"
  repo_exists "${GO_REPO}" || die "go repo '${GO_REPO}' was not created (Groovy scripting disabled? check -Dnexus.scripts.allowCreation)"
fi

# --- 2. create apt-hosted via Groovy (empty pgp key -> no GPG needed) ---------
if repo_exists "${APT_REPO}"; then
  log "apt repo '${APT_REPO}' already present."
else
  log "Creating apt hosted repo '${APT_REPO}' via Groovy (createAptHosted, empty key) ..."
  res=$(nx_groovy dtf_mk_apt "import org.sonatype.nexus.repository.config.WritePolicy; repository.createAptHosted('${APT_REPO}','bookworm','','','default',WritePolicy.ALLOW,false); return 'apt-created'")
  log "  createAptHosted -> ${res:-<no result>}"
  repo_exists "${APT_REPO}" || die "apt repo '${APT_REPO}' was not created"
fi

# --- 3. build + PUT the Go module zip ----------------------------------------
GO_WORK="${NEXUS_STATE_DIR}/gomod"
mkdir -p "${GO_WORK}"
BUILD_GO="${DTF_DIR}/fixtures/go/build.sh"
[ -f "${BUILD_GO}" ] || die "missing Go fixture builder ${BUILD_GO}"
log "Building Go module zip ${GO_MODULE}@${GO_VERSION} (host-side, no toolchain) ..."
GO_ZIP=$(bash "${BUILD_GO}" "${GO_WORK}" "${GO_MODULE}" "${GO_VERSION}" 2>/dev/null) \
  || die "fixtures/go/build.sh failed (python3 available?)"
[ -f "${GO_ZIP}" ] || die "Go module zip not produced at ${GO_ZIP}"

# Nexus Go hosted accepts the module zip on the module-proxy path; it derives
# .mod/.info from the zip (a direct .mod PUT is 404 — the zip is the unit).
put_code=$(nx_curl PUT "/repository/${GO_REPO}/${GO_MODULE}/@v/${GO_VERSION}.zip" \
  --data-binary @"${GO_ZIP}" -o /dev/null -w '%{http_code}')
log "  PUT ${GO_MODULE}/@v/${GO_VERSION}.zip -> HTTP ${put_code}"
[ "$put_code" = "201" ] || [ "$put_code" = "200" ] || warn "unexpected Go zip PUT status ${put_code}"

# --- 4. build + upload the .deb ----------------------------------------------
APT_WORK="${NEXUS_STATE_DIR}/aptpkg"
DEB_FILE="${APT_WORK}/${DEB_PKG}_${DEB_VER}_${DEB_ARCH}.deb"
build_deb() {
  local root="${APT_WORK}/pkgroot"
  rm -rf "${APT_WORK}"; mkdir -p "${root}/DEBIAN" "${root}/usr/share/${DEB_PKG}"
  cat > "${root}/DEBIAN/control" <<EOF
Package: ${DEB_PKG}
Version: ${DEB_VER}
Architecture: ${DEB_ARCH}
Maintainer: DTF <dtf@example.com>
Description: DTF migration marker package for the nexus-go-apt tier (#2784)
EOF
  printf 'DTF-APT-MARKER\n' > "${root}/usr/share/${DEB_PKG}/marker.txt"
  if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build "${root}" "${DEB_FILE}" >/dev/null 2>&1 && return 0
  fi
  # Portable fallback: a .deb is an `ar` archive of debian-binary +
  # control.tar.gz + data.tar.gz (member order matters; debian-binary first).
  command -v ar >/dev/null 2>&1 || return 1
  ( cd "${root}" \
    && printf '2.0\n' > "${APT_WORK}/debian-binary" \
    && tar -C "${root}/DEBIAN" -czf "${APT_WORK}/control.tar.gz" ./control \
    && tar -C "${root}" --exclude=./DEBIAN -czf "${APT_WORK}/data.tar.gz" . \
    && ar rc "${DEB_FILE}" "${APT_WORK}/debian-binary" "${APT_WORK}/control.tar.gz" "${APT_WORK}/data.tar.gz" )
}
log "Building .deb ${DEB_PKG}_${DEB_VER}_${DEB_ARCH} ..."
build_deb || die "could not build a .deb (need dpkg-deb, or ar+tar)"
[ -f "${DEB_FILE}" ] || die ".deb not produced at ${DEB_FILE}"

log "Uploading .deb to '${APT_REPO}' via components API ..."
up_code=$(nx_curl POST "/service/rest/v1/components?repository=${APT_REPO}" \
  -F "apt.asset=@${DEB_FILE}" -o /dev/null -w '%{http_code}')
log "  components upload -> HTTP ${up_code}"
[ "$up_code" = "204" ] || [ "$up_code" = "200" ] || warn "unexpected .deb upload status ${up_code}"

# --- 5. confirm components landed + record fixture state ----------------------
sleep 2
go_n=$(nx_curl GET "/service/rest/v1/components?repository=${GO_REPO}" | jq '[.items[]?]|length' 2>/dev/null || echo 0)
apt_n=$(nx_curl GET "/service/rest/v1/components?repository=${APT_REPO}" | jq '[.items[]?]|length' 2>/dev/null || echo 0)
log "Nexus components after seed: ${GO_REPO}=${go_n}  ${APT_REPO}=${apt_n}"
[ "${go_n:-0}" -ge 1 ] || die "go repo has no components after seed"
[ "${apt_n:-0}" -ge 1 ] || die "apt repo has no components after seed"

jq -n \
  --arg go_repo "${GO_REPO}" --arg go_module "${GO_MODULE}" --arg go_version "${GO_VERSION}" \
  --arg apt_repo "${APT_REPO}" --arg deb_name "$(basename "${DEB_FILE}")" \
  --arg deb_pkg "${DEB_PKG}" --arg deb_ver "${DEB_VER}" \
  '{go:{repo:$go_repo, module:$go_module, version:$go_version},
    apt:{repo:$apt_repo, deb_name:$deb_name, package:$deb_pkg, version:$deb_ver}}' \
  > "${GOAPT_FIXTURES_FILE}"
log "Fixtures recorded at ${GOAPT_FIXTURES_FILE}:"
cat "${GOAPT_FIXTURES_FILE}" >&2
echo "${GOAPT_FIXTURES_FILE}"
