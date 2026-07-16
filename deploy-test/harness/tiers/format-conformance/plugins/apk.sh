# =============================================================================
# plugins/apk.sh — format-conformance plugin (Alpine / apk)
# FC_FORMAT: apk
# FC_MOUNT: alpine
# FC_REPO_FORMAT: alpine
# FC_PROFILE: client.apk
# FC_SERVICE: client-apk
# FC_ENABLED: 0
# =============================================================================
# Alpine routes (backend handlers/alpine.rs): nest /alpine; APKINDEX `GET
# /:repo/:branch/:repository/:arch/APKINDEX.tar.gz`; package GET/PUT
# `/:repo/:branch/:repository/:arch/:filename`; signing key `GET
# /:repo/:branch/keys/artifact-keeper.rsa.pub`.
#
# The dnf/apt clone for Alpine: build a dependency-free marker apk in-container
# via `abuild -F`, publish it, then point /etc/apk/repositories ONLY at the AK
# repo and run a REAL `apk add dtf-marker` that reads the AK-generated
# APKINDEX.tar.gz and FOLLOWS the advertised package location to fetch + install
# it (the #2580 path).
#
# KNOWN-RED (FC_ENABLED: 0 — the CORE consume is blocked by a real backend gap):
# AK's generated APKINDEX emits the package checksum as a BARE HEX SHA256 in the
# `C:` field (`generate_apkindex_text`: `C:{checksum_sha256}`), whereas a real
# apk client requires the apk-native `Q1`+base64(SHA1) form (e.g.
# `C:Q1O3f05G1QIlK5QBrIDIGE0gDWKs4=`). apk-tools 2.14 therefore rejects the whole
# index with "BAD signature" and CANNOT install ANY package from a hosted AK
# alpine repo — even with --allow-untrusted (that flag skips index *signature*
# trust, not the per-entry checksum parse). Proven: a local `apk index`-built
# tarball of the SAME .apk installs cleanly, while AK's tarball is rejected. The
# curl-based corpus test-alpine.sh only asserts the index decompresses, so it
# never surfaced this. See rig/results/format-conformance/apk-finding.md.
#
# The plugin below is fully implemented and left registered so flipping
# FC_ENABLED: 1 re-tests the whole real-client flow the moment the backend emits
# apk-conformant `C:` checksums.
#
# Secondary KNOWN-RED: `signed_index` (held out of FC_CASES) — a fresh hosted
# repo has no signing key, so `.../keys/artifact-keeper.rsa.pub` 404s and the
# index is unsigned; re-add it to FC_CASES once hosted repos emit a verifiable
# signed index. (This is downstream of the C: gap above.)
# =============================================================================
FC_CASES="arch_isolation index_regen_on_upgrade"

APK_BRANCH="v3.21"
APK_REPOSITORY="main"
APK_ARCH="aarch64"
APK_NAME="dtf-marker"
APK_MARKER="DTF-APK-INSTALLED"

# Path under which apk expects <arch>/APKINDEX.tar.gz (host + in-ctr views).
_apk_repo_url()     { echo "${FC_URL}/${APK_BRANCH}/${APK_REPOSITORY}"; }
_apk_repo_int_url() { echo "${FC_INT_URL}/${APK_BRANCH}/${APK_REPOSITORY}"; }

# One-time build-toolchain + non-root builder + signing keypair (abuild refuses
# to run as root). Idempotent; the default Alpine repos are still present here
# (fc_client_setup rewrites /etc/apk/repositories only AFTER publish).
_apk_build_setup() {
  nc_exec -t 300 'set -e
if [ ! -f /home/builder/.abuild/.setup-done ]; then
  apk add --no-cache alpine-sdk sudo >/dev/null
  adduser -D builder 2>/dev/null || true
  addgroup builder abuild 2>/dev/null || true
  echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder
  mkdir -p /home/builder/aports/main
  chown -R builder:builder /home/builder
  su builder -c "abuild-keygen -a -n" >/dev/null 2>&1
  # Trust the freshly minted pubkey so abuild can sign+index the LOCAL repo
  # without an UNTRUSTED-signature error (unrelated to the AK-served index).
  cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/ 2>/dev/null || true
  touch /home/builder/.abuild/.setup-done
fi
ls /home/builder/.abuild/*.rsa.pub >/dev/null'
}

# Build a marker apk at pkgver=$1; echoes the in-ctr .apk path on success.
# The gate is the produced .apk FILE (abuild's own exit code also covers a
# post-build local-index step that is irrelevant to the AK-served index).
_apk_build() {
  local ver="$1"
  local out="/home/builder/packages/main/${APK_ARCH}/${APK_NAME}-${ver}-r0.apk"
  nc_exec -t 240 "d=/home/builder/aports/main/${APK_NAME}
mkdir -p \$d && chown -R builder:builder /home/builder/aports
cat > \$d/APKBUILD <<EOF
# Maintainer: dtf <dtf@example.com>
pkgname=${APK_NAME}
pkgver=${ver}
pkgrel=0
pkgdesc=\"DTF format-conformance marker\"
url=\"https://example.com\"
arch=\"all\"
license=\"MIT\"
options=\"!check !tracedeps\"
package() {
	mkdir -p \\\$pkgdir/usr/share/${APK_NAME}
	echo \"${APK_MARKER}-${ver}\" > \\\$pkgdir/usr/share/${APK_NAME}/marker.txt
}
EOF
chown builder:builder \$d/APKBUILD
su builder -c \"cd \$d && abuild -F\" >/dev/null 2>&1 || true
test -f ${out}" >/dev/null || return 1
  echo "$out"
}

# ---------------------------------------------------------------------------
# fc_publish — abuild the v1.0 marker apk, copy it out for the byte proof, and
# PUT it on the native arch-qualified route.
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v apk >/dev/null && apk --version' \
    || { echo "apk missing inside the provisioned alpine client"; return 1; }
  _apk_build_setup || { echo "abuild toolchain setup failed"; return 1; }
  local ctr_apk
  ctr_apk="$(_apk_build 1.0)" || { echo "abuild of the marker apk failed"; return 1; }
  APK_FILE="${APK_NAME}-1.0-r0.apk"
  nc_copy_from_ctr "$ctr_apk" "${WORK_DIR}/${APK_FILE}" || return 1
  APK_PUB_SHA="$(nc_sha256 "${WORK_DIR}/${APK_FILE}")"
  echo "  apk=${APK_FILE} sha256=${APK_PUB_SHA}"
  nc_put_file "${WORK_DIR}/${APK_FILE}" "$(_apk_repo_url)/${APK_ARCH}/${APK_FILE}" || return 1
  nc_expect_code 200 "$(_apk_repo_url)/${APK_ARCH}/APKINDEX.tar.gz" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — point /etc/apk/repositories ONLY at the AK repo (no default
# Alpine mirror), so `apk add` can ONLY succeed via the AK APKINDEX.
# ---------------------------------------------------------------------------
fc_client_setup() {
  # AK's /alpine routes require auth (repo_visibility_middleware); a real apk
  # client carries HTTP basic creds in the repository URL. url-encode the
  # password so shell/special chars (e.g. '!') survive apk's libfetch parser.
  local encpw
  encpw="$(printf '%s' "$ADMIN_PASS" | jq -sRr @uri)"
  local repo_url="http://${ADMIN_USER}:${encpw}@backend:8080/alpine/${FC_REPO}/${APK_BRANCH}/${APK_REPOSITORY}"
  nc_exec "echo '${repo_url}' > /etc/apk/repositories && sed 's/:[^@]*@/:***@/' /etc/apk/repositories" \
    || { echo "could not rewrite /etc/apk/repositories"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `apk update` fetches the AK APKINDEX; `apk add`
# resolves dtf-marker and FOLLOWS the advertised package location to install it.
# --allow-untrusted: the base hosted repo is unsigned (see signed_index KNOWN-RED).
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 120 "set -e
apk update
apk add --allow-untrusted ${APK_NAME}" \
    || { echo "apk add (following the APKINDEX) failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker file was installed AND apk records
# the package as explicitly installed.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "test -f /usr/share/${APK_NAME}/marker.txt && \
grep -q '${APK_MARKER}' /usr/share/${APK_NAME}/marker.txt && \
apk info -e ${APK_NAME}" \
    || { echo "marker not installed / package not recorded by apk"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. APKINDEX lists P:dtf-marker;
# the package URL under the SAME branch/repository/arch 200s while the wrong-arch
# path (never uploaded there) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local idx="${WORK_DIR}/APKINDEX.tar.gz"
  nc_fetch "$(_apk_repo_url)/${APK_ARCH}/APKINDEX.tar.gz" "$idx" || return 1
  if tar xzOf "$idx" APKINDEX 2>/dev/null | grep -qE "^P:${APK_NAME}$"; then
    echo "  APKINDEX advertises P:${APK_NAME}"
  else
    echo "  APKINDEX does not advertise P:${APK_NAME}"
    tar xzOf "$idx" APKINDEX 2>/dev/null | head; return 1
  fi
  nc_expect_code 200 "$(_apk_repo_url)/${APK_ARCH}/${APK_FILE}" || return 1
  # wrong-arch path must NOT resolve (package was only PUT under aarch64)
  nc_expect_code 404 "${FC_URL}/${APK_BRANCH}/${APK_REPOSITORY}/x86_64/${APK_FILE}" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# arch_isolation — publish an x86_64-only package; the aarch64 APKINDEX must NOT
# list it and `apk add` on the aarch64 client must not find it. Bug class:
# cross-arch index bleed (an x86_64 pkg leaking into the aarch64 view).
fc_case_arch_isolation() {
  local xname="dtf-x86only"
  local xfile="${xname}-1.0-r0.apk"
  # A minimal apk is a gzipped tar with .PKGINFO; AK derives the index P: name
  # from the filename/metadata, so this need not be a fully installable apk — it
  # only has to be visible to the index generator under the x86_64 path.
  local xdir="${WORK_DIR}/x86pkg"
  mkdir -p "$xdir"
  cat > "$xdir/.PKGINFO" <<EOF
pkgname = ${xname}
pkgver = 1.0-r0
pkgdesc = x86_64-only marker
arch = x86_64
size = 32
EOF
  ( cd "$xdir" && tar czf "${WORK_DIR}/${xfile}" .PKGINFO ) || return 1
  nc_put_file "${WORK_DIR}/${xfile}" "${FC_URL}/${APK_BRANCH}/${APK_REPOSITORY}/x86_64/${xfile}" || return 1
  # positive: x86_64 index lists it
  local xidx="${WORK_DIR}/APKINDEX.x86.tar.gz"
  nc_fetch "${FC_URL}/${APK_BRANCH}/${APK_REPOSITORY}/x86_64/APKINDEX.tar.gz" "$xidx" || return 1
  tar xzOf "$xidx" APKINDEX 2>/dev/null | grep -qE "^P:${xname}$" \
    || { echo "x86_64 APKINDEX does not list ${xname}"; return 1; }
  echo "  x86_64 APKINDEX lists ${xname}"
  # negative: aarch64 index must NOT list it
  local aidx="${WORK_DIR}/APKINDEX.aarch64.tar.gz"
  nc_fetch "$(_apk_repo_url)/${APK_ARCH}/APKINDEX.tar.gz" "$aidx" || return 1
  if tar xzOf "$aidx" APKINDEX 2>/dev/null | grep -qE "^P:${xname}$"; then
    echo "  LEAK: ${xname} appears in the aarch64 APKINDEX"; return 1
  fi
  # and the aarch64 client cannot resolve it
  if nc_exec "apk update >/dev/null 2>&1; apk info ${xname} >/dev/null 2>&1"; then
    echo "  LEAK: aarch64 apk can see ${xname}"; return 1
  fi
  echo "  aarch64 view isolated from the x86_64-only package"
}

# index_regen_on_upgrade — publish 1.1-r0; after `apk update` an `apk upgrade`
# must pick up the newer version (the APKINDEX is regenerated, not stale). Bug
# class: stale index after a new upload.
fc_case_index_regen_on_upgrade() {
  local ctr_apk
  ctr_apk="$(_apk_build 1.1)" || { echo "abuild of 1.1 failed"; return 1; }
  local newfile="${APK_NAME}-1.1-r0.apk"
  nc_copy_from_ctr "$ctr_apk" "${WORK_DIR}/${newfile}" || return 1
  nc_put_file "${WORK_DIR}/${newfile}" "$(_apk_repo_url)/${APK_ARCH}/${newfile}" || return 1
  # positive: the regenerated index advertises 1.1 and upgrade installs it
  nc_exec -t 120 "set -e
apk update
apk upgrade --allow-untrusted ${APK_NAME}
apk info -e ${APK_NAME}
grep -q '${APK_MARKER}-1.1' /usr/share/${APK_NAME}/marker.txt" \
    || { echo "apk upgrade did not pick up the regenerated 1.1 index"; return 1; }
  # negative: apk must report the installed version as 1.1, not the old 1.0
  local ver
  ver="$(nc_exec "apk version ${APK_NAME} 2>/dev/null | tail -n1")"
  echo "  post-upgrade: ${ver}"
  nc_exec "apk info ${APK_NAME} | grep -qE '${APK_NAME}-1\\.1'" \
    || { echo "installed version is not 1.1 after upgrade"; return 1; }
  echo "  index regenerated on upload; upgrade -> 1.1"
}

# ---------------------------------------------------------------------------
# signed_index — HELD OUT of FC_CASES (KNOWN-RED, see header). Install the repo
# public key and `apk add` WITHOUT --allow-untrusted: a backend-signed APKINDEX
# must verify. A fresh hosted repo has no signing key, so the pubkey endpoint
# 404s and verification cannot succeed. Kept implemented so re-enabling is a
# one-line FC_CASES edit once hosted repos emit a verifiable signed index.
# ---------------------------------------------------------------------------
fc_case_signed_index() {
  # positive precondition: the advertised signing key must be served
  local key="${WORK_DIR}/artifact-keeper.rsa.pub"
  local code
  code="$(curl -s -o "$key" -w '%{http_code}' --max-time 60 \
    -H "$(format_auth_header)" \
    "${FC_URL}/${APK_BRANCH}/keys/artifact-keeper.rsa.pub" 2>/dev/null)"
  if [ "$code" != "200" ] || [ ! -s "$key" ]; then
    echo "  no signing key served for a hosted repo (HTTP ${code}) — APKINDEX is unsigned"
    return 1
  fi
  nc_copy_to_ctr "$key" "/etc/apk/keys/artifact-keeper.rsa.pub" || return 1
  # WITHOUT --allow-untrusted: the signed index must verify
  nc_exec -t 120 "set -e
apk update
apk add ${APK_NAME}" \
    || { echo "signature verification failed (unsigned or mismatched index)"; return 1; }
  echo "  signed APKINDEX verified without --allow-untrusted"
}
