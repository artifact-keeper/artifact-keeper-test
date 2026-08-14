#!/usr/bin/env bash
# =============================================================================
# tiers/signing/oracle.sh — do real clients actually VERIFY AK's signatures?
#                           (#72 Epic 4: format signing & verification)
# =============================================================================
# run.sh has stood up `filesystem + client.apt + client.dnf + client.apk +
# client.helm` on this slot and exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, DTF_SLOT, JUNIT_OUTPUT_DIR. We source the corpus common.sh for
# the assertion + JUnit harness (DTF rule: the corpus IS the assertion library).
#
# THE POINT OF THIS TIER
# ----------------------
# Every other real-client leg we own runs with signature verification DISABLED:
#   * tiers/native-client/oracle.sh LEG B:  deb [trusted=yes] ...
#   * plugins/apk.sh fc_consume:            apk add --allow-untrusted
#   * tiers/native-client/oracle.sh LEG A:  gpgcheck=0 / repo_gpgcheck=0
# So we drive real clients down the advertised route and then tell them not to
# check who signed it. This tier flips every one of those switches ON. It is the
# productized, gate-wired form of four corpus scripts that previously ran
# NOWHERE (0 hits in release-gate.yml): test-debian-gpg-chain.sh (LEG A) and
# test-helm-provenance-verify.sh (LEG D) are ported here as real-client legs;
# test-maven-snapshot-metadata.sh and test-pypi-yanking.sh are lifecycle (not
# signing) and land as FC plugin cases in plugins/maven.sh + plugins/pypi.sh.
#
# THE PORT IS NOT A COPY (why the dark scripts could never have passed)
# --------------------------------------------------------------------
# test-debian-gpg-chain.sh attaches the signing key with
# `PUT /api/v1/repositories/{key}/signing`. That endpoint DOES NOT EXIST. The
# real contract is `POST /api/v1/signing/repositories/{repo_UUID}/config`
# {"signing_key_id":...,"sign_metadata":true} (signing.rs:30-33) — a different
# verb, path, id-space (UUID not key) and body. The script's 404 fell into
# `skip_suite "per-repo signing config endpoint not available"`, so had anyone
# ever wired it, it would have GREEN-SKIPPED past the entire chain it exists to
# test. It also asks for `key_type:"rsa"`, which yields an X.509 SPKI PEM that
# `gpg --import` rejects; the OpenPGP chain needs `key_type:"gpg"`. Both bugs
# are fixed in this port and both are load-bearing.
#
# STANDING GREEN REGRESSION GATE (history: this tier began as a pinned-red tier)
# ------------------------------------------------------------------------------
# When first written (against ak-backend:v158-4fix) three of the four formats
# were broken and their failures were pinned as KNOWN-RED. The backend fixes
# have since merged, so every leg is now a PLAIN GREEN assertion and this tier
# is the standing regression gate for those fixes:
#   A  apt   — was green from day one; verification ON, unsigned REFUSED,
#              tampered Release = BAD signature
#   B  rpm   — #2645 (repodata signed with real OpenPGP so dnf can verify) +
#              #2679 (non-OpenPGP key_type for Debian/RPM rejected at config
#              time, instead of failing every anonymous metadata poll later)
#   C  apk   — #2634 (APKINDEX C: field in apk's native Q1+base64(SHA1) form) +
#              #2677 (fail closed when APKINDEX signing fails)
#   D  helm  — #2640 (store + serve <chart>.tgz.prov) + #2680 (proxy .prov)
# If any of these assertions goes red, one of those fixes has regressed.
# Each leg keeps its DISCRIMINATION control (unsigned repo refused, tampered
# metadata rejected, verification-OFF control install) proving a future red is
# signature-specific and not plumbing.
#
# ONE pin remains: C4 (real `apk add` end-to-end verify) is still KNOWN-RED —
# the served .SIGN.RSA signature itself is not apk-verifiable on current main
# (see the LEG C header for the root cause). It keeps the original pin
# semantics: documented failure shape -> PASS + loud banner; correct behavior
# -> FAIL "remove the pin".
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "signing-verification-72"
auth_admin
setup_workdir

SLOT="${DTF_SLOT}"
CAPT="ak-dtf${SLOT}-client-apt"
CDNF="ak-dtf${SLOT}-client-dnf"
CAPK="ak-dtf${SLOT}-client-apk"
CHELM="ak-dtf${SLOT}-client-helm"
BACKEND_INTERNAL="http://backend:8080"

DEB_REPO="dtf-sign-deb-${RUN_ID}"
DEB_UNSIGNED_REPO="dtf-sign-deb-unsigned-${RUN_ID}"
RPM_REPO="dtf-sign-rpm-${RUN_ID}"
APK_REPO="dtf-sign-apk-${RUN_ID}"
HELM_REPO="dtf-sign-helm-${RUN_ID}"

APK_BRANCH="v3.21"
APK_REPOSITORY="main"
# Derive the client arch at runtime so the tier runs unchanged on arm64 AND
# amd64 runners (apk --print-arch: aarch64 / x86_64 — the same strings abuild
# uses for its output dirs).
APK_ARCH="$(docker exec "$CAPK" apk --print-arch 2>/dev/null | tr -d '[:space:]' || true)"
[ -n "$APK_ARCH" ] || APK_ARCH="$(uname -m)"

CREATED_KEYS=()

# Per-suite GNUPGHOME so we never touch the host's real keyring.
export GNUPGHOME="${WORK_DIR}/gpghome"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

cleanup() {
  local r k
  for r in "$DEB_REPO" "$DEB_UNSIGNED_REPO" "$RPM_REPO" "$APK_REPO" "$HELM_REPO"; do
    api_delete "/api/v1/repositories/${r}" >/dev/null 2>&1 || true
  done
  for k in "${CREATED_KEYS[@]:-}"; do
    [ -n "$k" ] && api_delete "/api/v1/signing/keys/${k}" >/dev/null 2>&1 || true
  done
  gpgconf --kill gpg-agent >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

hcode() { curl -s -o /dev/null -w '%{http_code}' --max-time 40 "$@"; }

# ---------------------------------------------------------------------------
# green_step <label> <regression-ref> <fn>
#   Run a regression check as a PLAIN GREEN assertion. <fn> returns 0 iff the
#   correct (verified) behavior is observed. A non-zero return means the named
#   backend fix has REGRESSED — the step fails hard and quotes the log.
#   (Historical note: these steps were `kr_step` KNOWN-RED pins while the
#   backend bugs were open; the fixes merged, so the pins are gone — except
#   the single remaining C4 pin, inlined at its call site in LEG C.)
# ---------------------------------------------------------------------------
green_step() {
  local label="$1" ref="$2" fn="$3"
  begin_test "$label"
  local log="${WORK_DIR}/green-${fn}.log"
  if "$fn" >"$log" 2>&1; then
    sed -n '1,12p' "$log" 2>/dev/null
    pass
  else
    fail "${label} FAILED — regression of ${ref}" \
         "$(tail -n 40 "$log" 2>/dev/null)"
  fi
}

# sign_create_key <name> <key_type> -> echoes key id
sign_create_key() {
  local name="$1" ktype="$2" resp id
  resp="$(api_post "/api/v1/signing/keys" \
    "{\"name\":\"${name}\",\"key_type\":\"${ktype}\",\"algorithm\":\"rsa4096\"}" 2>/dev/null)" || return 1
  id="$(printf '%s' "$resp" | jq -r '.id // empty')"
  [ -n "$id" ] || { echo "no key id in: $(printf '%s' "$resp" | head -c 200)" >&2; return 1; }
  CREATED_KEYS+=("$id")
  echo "$id"
}

# sign_repo_uuid <repo_key> -> echoes the repository UUID
sign_repo_uuid() {
  curl -s --max-time 30 -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/$1" 2>/dev/null \
    | jq -r '.id // empty'
}

# sign_attach_key <repo_key> <key_id>  (the REAL contract; see header)
sign_attach_key() {
  local rkey="$1" kid="$2" ruuid code
  ruuid="$(sign_repo_uuid "$rkey")"
  [ -n "$ruuid" ] || { echo "could not resolve repo uuid for ${rkey}" >&2; return 1; }
  code="$(hcode -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"signing_key_id\":\"${kid}\",\"sign_metadata\":true}" \
    "${BASE_URL}/api/v1/signing/repositories/${ruuid}/config")"
  [ "$code" = "200" ] || { echo "attach signing config -> HTTP ${code}" >&2; return 1; }
  echo "  attached key ${kid} to ${rkey} (uuid ${ruuid}) -> sign_metadata=true"
}

# ---------------------------------------------------------------------------
# Preflight: gpg is a hard requirement of this tier (LEG A crypto + LEG D key).
# A signing tier that skips when its crypto tool is missing is an unfailable
# test — fail loudly instead (DTF rule §5.4).
# ---------------------------------------------------------------------------
begin_test "preflight: gpg available on the harness host (hard requirement, never skipped)"
if command -v gpg >/dev/null 2>&1; then
  echo "  $(gpg --version | head -1)"
  pass
else
  fail "gpg is not installed on the harness host; the signing tier cannot verify anything. Install gnupg (this is a hard failure by design — see manifest)."
fi

# ===========================================================================
# LEG A — apt / apt-secure. THE GREEN ONE. Verification ON, no [trusted=yes].
# Ports tests/security/test-debian-gpg-chain.sh (which ran nowhere) and adds
# the real-client half it never had.
# ===========================================================================

A_OK=1
DEB_ARCH=""
DEB_FILE=""

begin_test "A0: hosted debian repo + OpenPGP (key_type=gpg) signing key attached via the REAL config route"
DEB_KEY_ID=""
if ! create_repo "$DEB_REPO" debian local; then
  A_OK=0; fail "could not create hosted debian repo ${DEB_REPO}"
elif ! DEB_KEY_ID="$(sign_create_key "dtf-deb-${RUN_ID}" gpg)"; then
  A_OK=0; fail "could not create an OpenPGP signing key (POST /api/v1/signing/keys key_type=gpg)"
elif ! sign_attach_key "$DEB_REPO" "$DEB_KEY_ID"; then
  A_OK=0; fail "could not attach the signing key to ${DEB_REPO} via POST /api/v1/signing/repositories/{uuid}/config"
else
  pass
fi

begin_test "A1: build + publish a dependency-free marker .deb into the signed repo"
if [ "$A_OK" = "1" ]; then
  # NOTE: common.sh runs `set -euo pipefail`, so every command that is ALLOWED
  # to fail below is explicitly guarded with `|| true`. The green_step hooks
  # are exempt: bash suppresses errexit for the whole dynamic extent of an `if`
  # condition, which is how they are invoked.
  DEB_ARCH="$(docker exec "$CAPT" dpkg --print-architecture 2>/dev/null | tr -d '[:space:]' || true)"
  if [ -z "$DEB_ARCH" ]; then
    case "$(uname -m)" in x86_64) DEB_ARCH="amd64" ;; *) DEB_ARCH="arm64" ;; esac
  fi
  DEB_FILE="dtf-signed_1.0_${DEB_ARCH}.deb"
  # umask 0022 + the explicit chmod are LOAD-BEARING: dpkg-deb refuses a
  # control directory outside 0755-0775, and an exec session under a
  # docker-in-docker daemon (the CI runner) inherits umask 0000, so a plain
  # `mkdir -p` produces 0777 and the build dies. Same bug the native-client
  # tier's deb leg hit in the release gate; fixed here before this tier is
  # ever promoted into CI.
  build_deb='
set -e
umask 0022
rm -rf /tmp/dtf-signed
mkdir -p /tmp/dtf-signed/DEBIAN /tmp/dtf-signed/usr/share/dtf-signed
chmod 0755 /tmp/dtf-signed/DEBIAN
cat > /tmp/dtf-signed/DEBIAN/control <<CTRL
Package: dtf-signed
Version: 1.0
Architecture: '"$DEB_ARCH"'
Maintainer: DTF <dtf@example.com>
Description: DTF signing-tier marker
 A dependency-free marker package for the DTF signing tier.
CTRL
echo "DTF-DEB-SIGNED-INSTALLED-1.0" > /tmp/dtf-signed/usr/share/dtf-signed/marker.txt
dpkg-deb --root-owner-group --build /tmp/dtf-signed "/tmp/'"$DEB_FILE"'"
test -f "/tmp/'"$DEB_FILE"'"
'
  if deb_build_out=$(timeout 120 docker exec "$CAPT" bash -c "$build_deb" 2>&1) \
     && docker cp "${CAPT}:/tmp/${DEB_FILE}" "${WORK_DIR}/${DEB_FILE}" >/dev/null 2>&1 \
     && [ -s "${WORK_DIR}/${DEB_FILE}" ]; then
    up=$(hcode -X PUT -H "$(format_auth_header)" --upload-file "${WORK_DIR}/${DEB_FILE}" \
          "${BASE_URL}/debian/${DEB_REPO}/pool/main/d/dtf-signed/${DEB_FILE}" || true)
    if [ "$up" = "200" ] || [ "$up" = "201" ]; then pass; else
      A_OK=0; fail "deb upload returned HTTP ${up} (expected 201)"
    fi
  else
    A_OK=0
    infra_fail "dpkg-deb build/copy failed inside the Debian client (${CAPT}) — fixture build, NOT a candidate assertion" \
               "$(printf '%s\n' "${deb_build_out:-}" | tail -n 40)"
  fi
else
  fail "skipped: prior step failed"
fi

sleep 2   # allow the async re-sign of Release after the pool upload

begin_test "A2: the apt-secure chain is served as REAL OpenPGP (InRelease clearsigned + Release.gpg detached + gpg-key.asc)"
if [ "$A_OK" = "1" ]; then
  for f in InRelease Release Release.gpg gpg-key.asc; do
    curl -s --max-time 30 -H "$(format_auth_header)" \
      -o "${WORK_DIR}/${f}" "${BASE_URL}/debian/${DEB_REPO}/dists/stable/${f}" 2>/dev/null || true
  done
  a2_err=""
  grep -q "BEGIN PGP SIGNED MESSAGE" "${WORK_DIR}/InRelease" 2>/dev/null \
    || a2_err="${a2_err}InRelease is not a clearsigned PGP message; "
  grep -q "BEGIN PGP SIGNATURE" "${WORK_DIR}/Release.gpg" 2>/dev/null \
    || a2_err="${a2_err}Release.gpg is not a PGP signature; "
  grep -q "^Suite: stable" "${WORK_DIR}/Release" 2>/dev/null \
    || a2_err="${a2_err}Release lacks 'Suite: stable'; "
  # An X.509 SPKI PEM here is the RPM bug (LEG B); apt/gpg cannot import it.
  if grep -q "BEGIN PUBLIC KEY" "${WORK_DIR}/gpg-key.asc" 2>/dev/null; then
    a2_err="${a2_err}gpg-key.asc served an X.509 SPKI PEM ('BEGIN PUBLIC KEY') which gpg --import rejects; "
  elif ! grep -q "BEGIN PGP PUBLIC KEY" "${WORK_DIR}/gpg-key.asc" 2>/dev/null; then
    a2_err="${a2_err}gpg-key.asc is not an OpenPGP public key block; "
  fi
  if [ -z "$a2_err" ]; then
    echo "  InRelease=clearsigned  Release.gpg=detached PGP  gpg-key.asc=OpenPGP public key block"
    pass
  else
    A_OK=0; fail "apt-secure chain malformed: ${a2_err}" \
      "$(head -c 300 "${WORK_DIR}/gpg-key.asc" 2>/dev/null)"
  fi
else
  fail "skipped: prior step failed"
fi

begin_test "A3: crypto discrimination — gpg --verify PASSES on the served pair and FAILS on a tampered Release"
if [ "$A_OK" = "1" ]; then
  gpg --batch --import "${WORK_DIR}/gpg-key.asc" >"${WORK_DIR}/gpg-import.log" 2>&1 || true
  if ! gpg --batch --verify "${WORK_DIR}/Release.gpg" "${WORK_DIR}/Release" >"${WORK_DIR}/gpg-verify.log" 2>&1; then
    A_OK=0
    fail "gpg --verify FAILED on the untampered Release/Release.gpg pair; the apt-secure chain is broken" \
         "$(head -c 600 "${WORK_DIR}/gpg-verify.log")"
  else
    # NEGATIVE: a tampered Release must NOT verify. Without this, a backend
    # serving a static self-consistent stub would still pass the positive.
    cp "${WORK_DIR}/Release" "${WORK_DIR}/Release.tampered"
    printf 'X' >> "${WORK_DIR}/Release.tampered"
    if gpg --batch --verify "${WORK_DIR}/Release.gpg" "${WORK_DIR}/Release.tampered" \
         >"${WORK_DIR}/gpg-verify-neg.log" 2>&1; then
      fail "a TAMPERED Release was accepted by gpg --verify; the signature is not binding the content" \
           "$(head -c 600 "${WORK_DIR}/gpg-verify-neg.log")"
    else
      echo "  untampered -> Good signature; tampered -> rejected"
      grep -E 'Good signature|BAD signature' "${WORK_DIR}/gpg-verify.log" "${WORK_DIR}/gpg-verify-neg.log" 2>/dev/null | sed 's/^/    /'
      pass
    fi
  fi
else
  fail "skipped: prior step failed"
fi

begin_test "A4: REAL \`apt-get install\` with signature verification ON (signed-by=, NO [trusted=yes]) installs the package"
if [ "$A_OK" = "1" ]; then
  # The client image has no gpg/curl once the default sources are stripped, so
  # the oracle hands it the advertised key. apt >= 2.4 accepts an ASCII-armored
  # key at signed-by=, so the .asc is used verbatim — exactly the bytes AK
  # advertises at dists/<suite>/gpg-key.asc.
  docker exec "$CAPT" mkdir -p /etc/apt/keyrings >/dev/null 2>&1 || true
  docker cp "${WORK_DIR}/gpg-key.asc" "${CAPT}:/etc/apt/keyrings/dtf-ak.asc" >/dev/null 2>&1 || true
  install_signed='
set -e
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list
rm -rf /etc/apt/sources.list.d/*
# NOTE: signed-by= and NO [trusted=yes] -> apt MUST verify the InRelease
# signature against the AK-advertised key or refuse the repo outright.
echo "deb [signed-by=/etc/apt/keyrings/dtf-ak.asc] '"${BACKEND_INTERNAL}/debian/${DEB_REPO}"' stable main" \
  > /etc/apt/sources.list.d/dtf-ak.list
apt-get -o Acquire::Check-Valid-Until=false update >/tmp/apt.log 2>&1
apt-get -y install dtf-signed >>/tmp/apt.log 2>&1
test -f /usr/share/dtf-signed/marker.txt
grep -q DTF-DEB-SIGNED-INSTALLED /usr/share/dtf-signed/marker.txt
dpkg -s dtf-signed >/dev/null 2>&1
'
  if timeout 240 docker exec "$CAPT" bash -c "$install_signed"; then
    echo "  apt verified the AK-signed InRelease chain and installed dtf-signed (verification ON)"
    pass
  else
    aptlog=$(docker exec "$CAPT" sh -c 'tail -n 40 /tmp/apt.log 2>/dev/null' 2>/dev/null || true)
    fail "REAL apt-get install FAILED with signature verification ON; AK's signed Debian chain is not trusted by apt" "$aptlog"
  fi
else
  fail "skipped: prior step failed"
fi

begin_test "A5: client discrimination — an UNSIGNED repo is REFUSED by the same apt client with verification ON"
if [ "$A_OK" = "1" ]; then
  if ! create_repo "$DEB_UNSIGNED_REPO" debian local; then
    fail "could not create the unsigned control repo ${DEB_UNSIGNED_REPO}"
  else
    up=$(hcode -X PUT -H "$(format_auth_header)" --upload-file "${WORK_DIR}/${DEB_FILE}" \
          "${BASE_URL}/debian/${DEB_UNSIGNED_REPO}/pool/main/d/dtf-signed/${DEB_FILE}" || true)
    # Same package, same client, same flags — ONLY the signing key is absent.
    refuse='
export DEBIAN_FRONTEND=noninteractive
rm -rf /etc/apt/sources.list.d/*
echo "deb [signed-by=/etc/apt/keyrings/dtf-ak.asc] '"${BACKEND_INTERNAL}/debian/${DEB_UNSIGNED_REPO}"' stable main" \
  > /etc/apt/sources.list.d/dtf-unsigned.list
apt-get -o Acquire::Check-Valid-Until=false update >/tmp/apt-unsigned.log 2>&1
'
    # apt-get update EXITS 100 on an unsigned repo — that is the expected
    # outcome here, so it must not abort the oracle under errexit.
    timeout 120 docker exec "$CAPT" bash -c "$refuse" >/dev/null 2>&1 || true
    ulog=$(docker exec "$CAPT" sh -c 'cat /tmp/apt-unsigned.log 2>/dev/null' 2>/dev/null || true)
    if printf '%s' "$ulog" | grep -qiE 'is not signed|NO_PUBKEY|not have a Release file'; then
      echo "  unsigned repo (pool upload HTTP ${up}) -> apt refused it:"
      printf '%s\n' "$ulog" | grep -iE '^E:|is not signed' | head -3 | sed 's/^/    /'
      pass
    else
      fail "an UNSIGNED repo was ACCEPTED by apt with verification ON — the A4 green is not signature-discriminating" "$ulog"
    fi
  fi
else
  fail "skipped: prior step failed"
fi

# ===========================================================================
# LEG B — rpm / dnf. GREEN: regression gate for #2645 + #2679.
# ===========================================================================
# HISTORY (the defect this leg now gates against): before #2645,
#   handlers/rpm.rs repomd_xml_asc() signed with raw PKCS#1 RSA bytes wrapped
#   in hand-rolled "BEGIN PGP SIGNATURE" markers (no OpenPGP packet framing,
#   no CRC24) and repomd_xml_key() served an X.509 SPKI PEM — "GPG signature
#   theater": no key_type yielded a chain real dnf could verify. #2645 routes
#   RPM through the same sign_openpgp_* path Debian always used, so the served
#   chain is real OpenPGP. #2679 closes the companion config trap: a Debian/RPM
#   repo can only ever be served by a key_type='gpg' key, so attaching an
#   rsa/ed25519 key is now REJECTED at config time (400) instead of booting
#   green and failing every anonymous apt/dnf metadata poll at request time.
# This leg asserts both fixes with the real client: key_type=gpg signs a chain
# dnf verifies end-to-end (B1-B3), and key_type=rsa is refused up front (B5).
# ===========================================================================

B_OK=1
RPM_FILE="dtf-signed-1.0-1.noarch.rpm"

begin_test "B0: hosted rpm repo + OpenPGP (key_type=gpg) signing key attached + marker RPM published"
RPM_KEY_ID=""
if ! create_repo "$RPM_REPO" rpm local; then
  B_OK=0; fail "could not create hosted rpm repo ${RPM_REPO}"
elif ! RPM_KEY_ID="$(sign_create_key "dtf-rpm-${RUN_ID}" gpg)"; then
  B_OK=0; fail "could not create an OpenPGP signing key (POST /api/v1/signing/keys key_type=gpg)"
elif ! sign_attach_key "$RPM_REPO" "$RPM_KEY_ID"; then
  B_OK=0; fail "could not attach the signing key to ${RPM_REPO}"
else
  build_rpm='
set -e
rpm -q rpm-build >/dev/null 2>&1 || dnf -y install rpm-build >/dev/null 2>&1
mkdir -p /root/rpmbuild/{SPECS,BUILD,RPMS,SOURCES,SRPMS}
cat > /root/rpmbuild/SPECS/dtf-signed.spec <<SPEC
Name: dtf-signed
Version: 1.0
Release: 1
Summary: DTF signing-tier marker
License: MIT
BuildArch: noarch
%description
DTF signing-tier RPM marker package.
%install
mkdir -p %{buildroot}/usr/share/dtf-signed
echo "DTF-RPM-SIGNED-INSTALLED-%{version}" > %{buildroot}/usr/share/dtf-signed/marker.txt
%files
/usr/share/dtf-signed/marker.txt
SPEC
rpmbuild -bb /root/rpmbuild/SPECS/dtf-signed.spec >/dev/null 2>&1
test -f /root/rpmbuild/RPMS/noarch/'"$RPM_FILE"'
'
  if timeout 420 docker exec "$CDNF" bash -c "$build_rpm" \
     && docker cp "${CDNF}:/root/rpmbuild/RPMS/noarch/${RPM_FILE}" "${WORK_DIR}/${RPM_FILE}" >/dev/null 2>&1 \
     && [ -s "${WORK_DIR}/${RPM_FILE}" ]; then
    up=$(hcode -X PUT -H "$(format_auth_header)" --upload-file "${WORK_DIR}/${RPM_FILE}" \
          "${BASE_URL}/rpm/${RPM_REPO}/packages/${RPM_FILE}" || true)
    if [ "$up" = "200" ] || [ "$up" = "201" ]; then pass; else
      B_OK=0; fail "RPM upload returned HTTP ${up}"
    fi
  else
    B_OK=0; fail "rpmbuild failed inside the Fedora client"
  fi
fi

# --- B1: the advertised gpgkey must be importable OpenPGP -------------------
_b1_key_importable() {
  [ "$B_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  local code
  code="$(curl -s -o "${WORK_DIR}/repomd.xml.key" -w '%{http_code}' --max-time 30 \
    -H "$(format_auth_header)" "${BASE_URL}/rpm/${RPM_REPO}/repodata/repomd.xml.key")"
  echo "  GET repodata/repomd.xml.key -> HTTP ${code}"
  echo "  first line: $(head -1 "${WORK_DIR}/repomd.xml.key" 2>/dev/null)"
  [ "$code" = "200" ] || { echo "  key endpoint did not serve a key"; return 1; }
  if grep -q "BEGIN PUBLIC KEY" "${WORK_DIR}/repomd.xml.key" 2>/dev/null; then
    # This is the pre-#2645 defect shape: an X.509 SPKI PEM where OpenPGP is
    # required. dnf/rpm --import and gpg --import both reject it.
    echo "  -> X.509 SubjectPublicKeyInfo PEM served where OpenPGP is required (pre-#2645 defect shape)"
    return 1
  fi
  local kh="${WORK_DIR}/gpghome-rpm"; rm -rf "$kh"; mkdir -p "$kh"; chmod 700 "$kh"
  GNUPGHOME="$kh" gpg --batch --import "${WORK_DIR}/repomd.xml.key" >"${WORK_DIR}/rpm-key-import.log" 2>&1
  local rc=$?
  cat "${WORK_DIR}/rpm-key-import.log" | sed 's/^/  gpg: /'
  GNUPGHOME="$kh" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  return $rc
}
green_step "B1: the advertised gpgkey (repodata/repomd.xml.key) is an importable OpenPGP key" \
           "#2645 (real OpenPGP repodata signing)" \
           _b1_key_importable

# --- B2: repomd.xml.asc must be a verifiable OpenPGP signature --------------
_b2_asc_verifies() {
  [ "$B_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  local code
  code="$(curl -s -o "${WORK_DIR}/repomd.xml.asc" -w '%{http_code}' --max-time 30 \
    -H "$(format_auth_header)" "${BASE_URL}/rpm/${RPM_REPO}/repodata/repomd.xml.asc")"
  curl -s --max-time 30 -H "$(format_auth_header)" \
    -o "${WORK_DIR}/repomd.xml" "${BASE_URL}/rpm/${RPM_REPO}/repodata/repomd.xml" 2>/dev/null
  echo "  GET repodata/repomd.xml.asc -> HTTP ${code} ($(wc -c < "${WORK_DIR}/repomd.xml.asc" 2>/dev/null) bytes)"
  echo "  first line: $(head -1 "${WORK_DIR}/repomd.xml.asc" 2>/dev/null)"
  [ "$code" = "200" ] || { echo "  no detached signature served"; return 1; }
  # A real PGP armor block carries a CRC24 checksum line ("=XXXX") before END.
  # Its absence was the pre-#2645 defect shape (hand-rolled markers around
  # base64'd raw RSA bytes) — flag it, it will fail the verify below anyway.
  if ! grep -qE '^=[A-Za-z0-9+/]{4}$' "${WORK_DIR}/repomd.xml.asc" 2>/dev/null; then
    echo "  -> armor has NO CRC24 checksum line: hand-rolled markers around base64, not real OpenPGP armor"
  fi
  echo "  --- gpg --verify repomd.xml.asc repomd.xml ---"
  GNUPGHOME="${WORK_DIR}/gpghome-rpm" gpg --batch --verify \
    "${WORK_DIR}/repomd.xml.asc" "${WORK_DIR}/repomd.xml" >"${WORK_DIR}/rpm-verify.log" 2>&1
  local rc=$?
  sed -n '1,4p' "${WORK_DIR}/rpm-verify.log" | sed 's/^/    /'
  if [ "$rc" -ne 0 ]; then
    GNUPGHOME="${WORK_DIR}/gpghome-rpm" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    return "$rc"
  fi
  # NEGATIVE: a tampered repomd.xml must NOT verify against the served .asc —
  # same binding check LEG A applies to the Debian Release (A3).
  cp "${WORK_DIR}/repomd.xml" "${WORK_DIR}/repomd.xml.tampered"
  printf 'X' >> "${WORK_DIR}/repomd.xml.tampered"
  if GNUPGHOME="${WORK_DIR}/gpghome-rpm" gpg --batch --verify \
       "${WORK_DIR}/repomd.xml.asc" "${WORK_DIR}/repomd.xml.tampered" \
       >"${WORK_DIR}/rpm-verify-neg.log" 2>&1; then
    echo "  -> a TAMPERED repomd.xml was accepted by gpg --verify; the signature is not binding the content"
    rc=1
  else
    echo "  untampered -> Good signature; tampered -> rejected"
  fi
  GNUPGHOME="${WORK_DIR}/gpghome-rpm" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  return $rc
}
green_step "B2: repodata/repomd.xml.asc is a gpg-verifiable detached OpenPGP signature (tampered repomd rejected)" \
           "#2645 (real OpenPGP repodata signing)" \
           _b2_asc_verifies

# --- B3: the real client, verification ON ----------------------------------
_b3_dnf_repo_gpgcheck() {
  [ "$B_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  # repo_gpgcheck=1 makes dnf verify repomd.xml against repomd.xml.asc using the
  # key it fetches from gpgkey=. This is the shipped, documented RPM trust path.
  local script='
set -e
cat > /etc/yum.repos.d/dtf-signed.repo <<REPO
[dtf-signed]
name=DTF AK signed RPM repo
baseurl='"${BACKEND_INTERNAL}/rpm/${RPM_REPO}/"'
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey='"${BACKEND_INTERNAL}/rpm/${RPM_REPO}/repodata/repomd.xml.key"'
REPO
rm -f /etc/yum.repos.d/dtf-nogpg.repo
dnf -y --disablerepo="*" --enablerepo=dtf-signed --refresh install dtf-signed >/tmp/dnf-signed.log 2>&1
test -f /usr/share/dtf-signed/marker.txt
'
  timeout 240 docker exec "$CDNF" bash -c "$script"
  local rc=$?
  docker exec "$CDNF" sh -c 'tail -n 6 /tmp/dnf-signed.log 2>/dev/null' 2>/dev/null | sed 's/^/    dnf: /'
  return $rc
}
green_step "B3: REAL \`dnf install\` with repo_gpgcheck=1 + the AK-advertised gpgkey verifies and installs" \
           "#2645 (real OpenPGP repodata signing; pre-fix dnf said 'Error during parsing OpenPGP packets')" \
           _b3_dnf_repo_gpgcheck

begin_test "B4: control — the SAME repo/package/client also installs with repo_gpgcheck=0 (plumbing sanity; keeps a future B3 red attributable to the SIGNATURE)"
if [ "$B_OK" = "1" ]; then
  ctrl='
set -e
dnf -y remove dtf-signed >/dev/null 2>&1 || true
rm -rf /var/cache/dnf/* || true
cat > /etc/yum.repos.d/dtf-nogpg.repo <<REPO
[dtf-nogpg]
name=DTF AK rpm repo (verification OFF - control)
baseurl='"${BACKEND_INTERNAL}/rpm/${RPM_REPO}/"'
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
rm -f /etc/yum.repos.d/dtf-signed.repo
dnf -y --disablerepo="*" --enablerepo=dtf-nogpg --refresh install dtf-signed >/tmp/dnf-nogpg.log 2>&1
test -f /usr/share/dtf-signed/marker.txt
grep -q DTF-RPM-SIGNED-INSTALLED /usr/share/dtf-signed/marker.txt
'
  if timeout 240 docker exec "$CDNF" bash -c "$ctrl"; then
    echo "  repo_gpgcheck=0 also installs -> the publish/serve plumbing is sound. If B3 ever goes red while this stays green, the regression is signature verification."
    pass
  else
    dlog=$(docker exec "$CDNF" sh -c 'tail -n 20 /tmp/dnf-nogpg.log 2>/dev/null' 2>/dev/null || true)
    fail "the control install (verification OFF) failed — a future B3 red could not be attributed to signing; fix the plumbing first" "$dlog"
  fi
else
  fail "skipped: prior step failed"
fi

# --- B5: #2679 — a non-OpenPGP key for an RPM repo is refused at CONFIG time -
# Before #2679 an rsa key attached cleanly (200) and the repo then failed every
# anonymous dnf metadata poll at request time (a fail-open config trap; the
# signing error was swallowed into a misleading 404 'No signing key
# configured'). The guard lives in POST /api/v1/signing/keys when the payload
# carries a repository_id: a repo-scoped key whose key_type can never sign the
# repo's metadata format must be a 400 naming the supported key_type.
_b5_rsa_keytype_rejected() {
  [ "$B_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  local ruuid code body
  ruuid="$(sign_repo_uuid "$RPM_REPO")"
  [ -n "$ruuid" ] || { echo "could not resolve repo uuid for ${RPM_REPO}"; return 1; }
  body="$(curl -s --max-time 30 -o - -w '\n%{http_code}' \
    -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"name\":\"dtf-rpm-rsa-reject-${RUN_ID}\",\"key_type\":\"rsa\",\"algorithm\":\"rsa4096\",\"repository_id\":\"${ruuid}\"}" \
    "${BASE_URL}/api/v1/signing/keys")"
  code="$(printf '%s' "$body" | tail -n1)"
  body="$(printf '%s' "$body" | sed '$d')"
  echo "  POST /api/v1/signing/keys {key_type:rsa, repository_id:<rpm repo>} -> HTTP ${code}"
  echo "  body: $(printf '%s' "$body" | head -c 200)"
  if [ "$code" != "400" ]; then
    echo "  -> expected a 400 Validation rejection (pre-#2679 this was accepted and the repo failed at request time)"
    return 1
  fi
  # The rejection must be actionable: it names the offending and supported types.
  printf '%s' "$body" | grep -q "gpg" || {
    echo "  -> the 400 does not name the supported key_type (gpg)"; return 1; }
  return 0
}
green_step "B5: attaching key_type=rsa to an RPM repo is REJECTED at config time with an actionable 400" \
           "#2679 (reject non-OpenPGP key_type for Debian/RPM at config time)" \
           _b5_rsa_keytype_rejected

# ===========================================================================
# LEG C — apk. GREEN gate for #2634 + #2677; ONE remaining KNOWN-RED pin (C4).
# ===========================================================================
# HISTORY: before #2634, AK's generate_apkindex_text emitted
# `C:{checksum_sha256}` — a bare hex SHA256 — where apk-tools requires its
# native Q1+base64(SHA1) form (e.g. `C:Q1O3f05G1QIlK5QBrIDIGE0gDWKs4=`), so
# apk rejected the whole index at the PARSE, before index trust was even
# decided. #2634 emits the native form; #2677 makes the index endpoint fail
# CLOSED when signing fails (no silently-unsigned index). C1-C3 gate those as
# plain green assertions.
#
# STILL OPEN (the C4 pin): with the parse fixed, real apk now reaches the
# TRUST decision and rejects AK's index signature itself: "BAD signature".
# Root cause (read at source, current main): alpine.rs signs via
# SigningService::sign_data = RSA-PKCS#1v1.5-**SHA256** over the UNCOMPRESSED
# APKINDEX text, and packs `.SIGN.RSA.artifact-keeper.rsa.pub` + APKINDEX into
# a SINGLE gzip stream. apk-tools' contract for `.SIGN.RSA` is **SHA1** over
# the COMPRESSED data segment, with the signature segment as its own leading
# gzip stream (`.SIGN.RSA256` for SHA256). Three independent mismatches, so no
# key material can make the served index verify. The pin's discrimination:
# C5 proves the byte-identical .apk installs from an abuild index, and C6
# proves removing the key flips BAD->UNTRUSTED (the trust mapping works —
# the defect is the signature bytes).
# ===========================================================================

C_OK=1
APK_FILE="dtf-signed-1.0-r0.apk"

begin_test "C0: hosted alpine repo + rsa signing key attached + marker apk built and published"
APK_KEY_ID=""
if ! create_repo "$APK_REPO" alpine local; then
  C_OK=0; fail "could not create hosted alpine repo ${APK_REPO}"
elif ! APK_KEY_ID="$(sign_create_key "dtf-apk-${RUN_ID}" rsa)"; then
  C_OK=0; fail "could not create an rsa signing key"
elif ! sign_attach_key "$APK_REPO" "$APK_KEY_ID"; then
  C_OK=0; fail "could not attach the signing key to ${APK_REPO}"
else
  build_apk='
set -e
if [ ! -f /home/builder/.abuild/.dtf-done ]; then
  apk add --no-cache alpine-sdk sudo >/dev/null 2>&1
  adduser -D builder 2>/dev/null || true
  addgroup builder abuild 2>/dev/null || true
  echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder
  mkdir -p /home/builder/aports/main
  chown -R builder:builder /home/builder
  su builder -c "abuild-keygen -a -n" >/dev/null 2>&1
  cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/ 2>/dev/null || true
  touch /home/builder/.abuild/.dtf-done
fi
d=/home/builder/aports/main/dtf-signed
mkdir -p $d
cat > $d/APKBUILD <<EOF
pkgname=dtf-signed
pkgver=1.0
pkgrel=0
pkgdesc="DTF signing-tier marker"
url="https://example.com"
arch="all"
license="MIT"
options="!check !tracedeps"
package() {
	mkdir -p \$pkgdir/usr/share/dtf-signed
	echo "DTF-APK-SIGNED-INSTALLED" > \$pkgdir/usr/share/dtf-signed/marker.txt
}
EOF
chown -R builder:builder /home/builder/aports
su builder -c "cd $d && abuild -F" >/dev/null 2>&1 || true
test -f /home/builder/packages/main/'"${APK_ARCH}"'/'"${APK_FILE}"'
'
  if timeout 420 docker exec "$CAPK" sh -c "$build_apk" \
     && docker cp "${CAPK}:/home/builder/packages/main/${APK_ARCH}/${APK_FILE}" "${WORK_DIR}/${APK_FILE}" >/dev/null 2>&1 \
     && [ -s "${WORK_DIR}/${APK_FILE}" ]; then
    up=$(hcode -X PUT -H "$(format_auth_header)" --upload-file "${WORK_DIR}/${APK_FILE}" \
          "${BASE_URL}/alpine/${APK_REPO}/${APK_BRANCH}/${APK_REPOSITORY}/${APK_ARCH}/${APK_FILE}" || true)
    if [ "$up" = "200" ] || [ "$up" = "201" ]; then pass; else
      C_OK=0; fail "apk upload returned HTTP ${up}"
    fi
  else
    C_OK=0; fail "abuild of the marker apk failed inside the Alpine client"
  fi
fi

begin_test "C1: the advertised apk signing key endpoint serves an apk-shaped RSA public key (this half WORKS)"
if [ "$C_OK" = "1" ]; then
  code="$(curl -s -o "${WORK_DIR}/artifact-keeper.rsa.pub" -w '%{http_code}' --max-time 30 \
    -H "$(format_auth_header)" "${BASE_URL}/alpine/${APK_REPO}/${APK_BRANCH}/keys/artifact-keeper.rsa.pub" || true)"
  echo "  GET /${APK_BRANCH}/keys/artifact-keeper.rsa.pub -> HTTP ${code}: $(head -1 "${WORK_DIR}/artifact-keeper.rsa.pub" 2>/dev/null)"
  # apk consumes an OpenSSL RSA public key PEM, so 'BEGIN PUBLIC KEY' is CORRECT
  # here (unlike RPM/Debian, which need OpenPGP). This endpoint is not the bug.
  if [ "$code" = "200" ] && grep -q "BEGIN PUBLIC KEY" "${WORK_DIR}/artifact-keeper.rsa.pub" 2>/dev/null; then
    pass
  else
    C_OK=0; fail "the alpine signing-key endpoint did not serve an RSA public-key PEM (HTTP ${code})" \
      "$(head -c 200 "${WORK_DIR}/artifact-keeper.rsa.pub" 2>/dev/null)"
  fi
else
  fail "skipped: prior step failed"
fi

begin_test "C2: the served APKINDEX.tar.gz carries a .SIGN.RSA member (signing IS attempted)"
if [ "$C_OK" = "1" ]; then
  curl -s --max-time 30 -H "$(format_auth_header)" -o "${WORK_DIR}/APKINDEX.tar.gz" \
    "${BASE_URL}/alpine/${APK_REPO}/${APK_BRANCH}/${APK_REPOSITORY}/${APK_ARCH}/APKINDEX.tar.gz" 2>/dev/null
  entries="$(tar tzf "${WORK_DIR}/APKINDEX.tar.gz" 2>/dev/null | tr '\n' ' ' || true)"
  echo "  tar members: ${entries}"
  if printf '%s' "$entries" | grep -q '.SIGN.RSA'; then pass; else
    fail "the AK-served APKINDEX has no .SIGN.RSA member; the index is unsigned despite an attached key" "$entries"
  fi
else
  fail "skipped: prior step failed"
fi

# --- C3: the C: checksum encoding ------------------------------------------
_c3_index_checksum_form() {
  [ "$C_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  local cfield
  cfield="$(tar xzOf "${WORK_DIR}/APKINDEX.tar.gz" APKINDEX 2>/dev/null | grep -m1 '^C:')"
  echo "  AK APKINDEX:  ${cfield}"
  local ground
  ground="$(docker exec "$CAPK" sh -c "tar xzOf /home/builder/packages/main/${APK_ARCH}/APKINDEX.tar.gz APKINDEX 2>/dev/null | grep -m1 '^C:'" 2>/dev/null)"
  echo "  abuild (ground truth): ${ground}"
  if printf '%s' "$cfield" | grep -qE '^C:Q1[A-Za-z0-9+/]+=*$'; then
    echo "  -> apk-native Q1+base64(SHA1) form. Correct."
    return 0
  fi
  echo "  -> bare hex SHA256, not apk's Q1+base64(SHA1) form (the pre-#2634 defect shape). apk-tools cannot parse this entry."
  return 1
}
green_step "C3: the APKINDEX C: checksum uses apk's native Q1+base64(SHA1) form" \
           "#2634 (native C: checksum form; pre-fix apk said 'BAD signature' at the parse, before trust)" \
           _c3_index_checksum_form

# --- C4: the real client, verification ON ----------------------------------
_c4_apk_trusted_add() {
  [ "$C_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  # Install the AK-advertised key into /etc/apk/keys and `apk add` with NO
  # --allow-untrusted: the signed index must verify against the served key.
  docker cp "${WORK_DIR}/artifact-keeper.rsa.pub" \
    "${CAPK}:/etc/apk/keys/artifact-keeper.rsa.pub" >/dev/null 2>&1
  local script='
set -e
echo "'"${BACKEND_INTERNAL}/alpine/${APK_REPO}/${APK_BRANCH}/${APK_REPOSITORY}"'" > /etc/apk/repositories
apk update 2>&1 | tail -3
apk add dtf-signed 2>&1 | tail -3
test -f /usr/share/dtf-signed/marker.txt
'
  timeout 180 docker exec "$CAPK" sh -c "$script"
}
# C4 — the ONE remaining KNOWN-RED pin (see the LEG C header for the root
# cause). Pin semantics: the exact documented failure shape (apk "BAD
# signature" at the trust decision) -> PASS + loud banner; any OTHER failure
# shape -> FAIL (the failure mode moved); correct behavior -> FAIL ("remove
# the pin") so the fix cannot land silently un-gated.
begin_test "C4 [KNOWN-RED pin]: REAL \`apk add\` WITHOUT --allow-untrusted — index signature is not apk-verifiable yet (.SIGN.RSA digest/framing)"
c4log="${WORK_DIR}/c4-apk-verify.log"
if _c4_apk_trusted_add >"$c4log" 2>&1; then
  fail "KNOWN-RED pin now PASSES — the backend's APKINDEX signature looks apk-verifiable. Remove this pin and make C4 a plain green assertion (green_step)." \
       "$(tail -n 15 "$c4log" 2>/dev/null)"
elif grep -qi "BAD signature" "$c4log"; then
  echo "    !! ================= KNOWN-RED ================="
  echo "    !! C4: apk rejects AK's index signature: BAD signature"
  echo "    !! .SIGN.RSA is RSA-SHA256 over the uncompressed index text in a"
  echo "    !! single gzip stream; apk expects SHA1 over the compressed data"
  echo "    !! segment with a separate signature stream (see LEG C header)."
  grep -i "BAD signature" "$c4log" | head -1 | sed 's/^/    !!   /'
  echo "    !! ============================================="
  pass
else
  fail "C4 failed with an UNPINNED shape (expected apk 'BAD signature' at the trust decision) — the failure mode moved; re-triage" \
       "$(tail -n 15 "$c4log" 2>/dev/null)"
fi

begin_test "C5: control — the SAME .apk installs from a correctly-formed local index (plumbing sanity; keeps a future C4 red attributable to AK's INDEX)"
if [ "$C_OK" = "1" ]; then
  ctrl='
set -e
apk del dtf-signed >/dev/null 2>&1 || true
mkdir -p /tmp/dtf-localrepo
cp /home/builder/packages/main/'"${APK_ARCH}"'/'"${APK_FILE}"' /tmp/dtf-localrepo/ 2>/dev/null || true
cp /home/builder/packages/main/'"${APK_ARCH}"'/APKINDEX.tar.gz /tmp/dtf-localrepo/ 2>/dev/null || true
mkdir -p /tmp/dtf-localrepo/'"${APK_ARCH}"'
cp /home/builder/packages/main/'"${APK_ARCH}"'/'"${APK_FILE}"' /tmp/dtf-localrepo/'"${APK_ARCH}"'/
cp /home/builder/packages/main/'"${APK_ARCH}"'/APKINDEX.tar.gz /tmp/dtf-localrepo/'"${APK_ARCH}"'/
echo "/tmp/dtf-localrepo" > /etc/apk/repositories
apk update 2>&1 | tail -2
apk add dtf-signed 2>&1 | tail -2
test -f /usr/share/dtf-signed/marker.txt
grep -q DTF-APK-SIGNED-INSTALLED /usr/share/dtf-signed/marker.txt
'
  if timeout 180 docker exec "$CAPK" sh -c "$ctrl"; then
    echo "  identical .apk + an abuild-generated index -> installs. If C4 ever goes red while this stays green, the regression is AK's index."
    pass
  else
    fail "the control install from a locally-built index failed — a future C4 red could not be attributed to AK's index" \
         "$(docker exec "$CAPK" sh -c 'apk update 2>&1 | tail -5' 2>/dev/null || true)"
  fi
else
  fail "skipped: prior step failed"
fi

begin_test "C6: client discrimination — WITHOUT the advertised key the AK index flips BAD->UNTRUSTED (the trust mapping works; C4's red is the signature bytes)"
if [ "$C_OK" = "1" ]; then
  neg='
set -e
apk del dtf-signed >/dev/null 2>&1 || true
mv /etc/apk/keys/artifact-keeper.rsa.pub /tmp/dtf-ak-key.stash
echo "'"${BACKEND_INTERNAL}/alpine/${APK_REPO}/${APK_BRANCH}/${APK_REPOSITORY}"'" > /etc/apk/repositories
out=$(apk update 2>&1; apk add dtf-signed 2>&1) || true
mv /tmp/dtf-ak-key.stash /etc/apk/keys/artifact-keeper.rsa.pub
echo "$out" | grep -iE "UNTRUSTED signature|unable to select packages|No such package" >/dev/null || {
  echo "$out" | tail -5
  exit 1
}
echo "$out" | grep -i "UNTRUSTED signature" | head -1
if [ -f /usr/share/dtf-signed/marker.txt ]; then exit 1; fi
'
  if timeout 180 docker exec "$CAPK" sh -c "$neg" >"${WORK_DIR}/apk-neg.log" 2>&1; then
    echo "  key removed -> UNTRUSTED signature, install refused; key restored."
    sed -n '1,3p' "${WORK_DIR}/apk-neg.log" | sed 's/^/    /'
    pass
  else
    fail "with the advertised key REMOVED, apk still accepted the AK index/package — the trust decision is not bound to the advertised key" \
         "$(tail -n 10 "${WORK_DIR}/apk-neg.log" 2>/dev/null)"
  fi
else
  fail "skipped: prior step failed"
fi

# ===========================================================================
# LEG D — helm provenance. GREEN: regression gate for #2640 + #2680.
# Ports test-helm-provenance-verify.sh.
# ===========================================================================
# HISTORY (the defect this leg now gates against): before #2640, handlers/
# helm.rs had four routes and the string "prov" appeared NOWHERE — the
# ChartMuseum multipart upload accepted a `prov` part, answered 201
# {"saved":true}, then dropped it, and no route served <chart>.tgz.prov, so
# `helm pull --verify` could never succeed against an AK helm repo. #2640
# stores the .prov and serves it at the helm-conventional URL (#2680 extends
# that to remote/proxy repos). This leg signs a chart client-side, uploads
# chart+prov, and asserts the .prov round-trips (D2) and that a real
# `helm pull --verify` succeeds (D3).
# ===========================================================================

D_OK=1
HELM_CHART="dtf-provchart"
HELM_VER="0.1.0"

begin_test "D0: helm client keyring + a chart signed with \`helm package --sign\` (verifies locally BEFORE any AK round-trip)"
prep_helm='
set -e
command -v gpg >/dev/null 2>&1 || apk add --no-cache gnupg >/dev/null 2>&1
export GNUPGHOME=/tmp/dtf-gh
rm -rf $GNUPGHOME /tmp/dtf-out /tmp/dtf-chart
mkdir -p $GNUPGHOME; chmod 700 $GNUPGHOME
cat > /tmp/dtf-batch <<EOF
%no-protection
Key-Type: RSA
Key-Length: 3072
Name-Real: dtf-helm-prov
Name-Email: dtf@example.com
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key /tmp/dtf-batch >/dev/null 2>&1
gpg --batch --export --output /tmp/dtf-pub.gpg dtf@example.com
gpg --batch --export-secret-keys --output /tmp/dtf-sec.gpg dtf@example.com
mkdir -p /tmp/dtf-chart/'"$HELM_CHART"'/templates /tmp/dtf-out
cat > /tmp/dtf-chart/'"$HELM_CHART"'/Chart.yaml <<EOF
apiVersion: v2
name: '"$HELM_CHART"'
version: '"$HELM_VER"'
description: DTF signing-tier provenance chart
type: application
appVersion: "1.0.0"
EOF
echo "replicaCount: 1" > /tmp/dtf-chart/'"$HELM_CHART"'/values.yaml
helm package /tmp/dtf-chart/'"$HELM_CHART"' --destination /tmp/dtf-out \
  --sign --key dtf@example.com --keyring /tmp/dtf-sec.gpg >/dev/null 2>&1
test -s /tmp/dtf-out/'"$HELM_CHART"'-'"$HELM_VER"'.tgz
test -s /tmp/dtf-out/'"$HELM_CHART"'-'"$HELM_VER"'.tgz.prov
# The .prov is provably valid before AK ever sees it -> any later verify failure
# is attributable to AK, not to the fixture.
helm verify /tmp/dtf-out/'"$HELM_CHART"'-'"$HELM_VER"'.tgz --keyring /tmp/dtf-pub.gpg
'
if timeout 300 docker exec "$CHELM" sh -c "$prep_helm" >"${WORK_DIR}/helm-prep.log" 2>&1; then
  grep -E 'Signed by:|Chart Hash Verified:' "${WORK_DIR}/helm-prep.log" 2>/dev/null | sed 's/^/    /'
  pass
else
  D_OK=0; fail "could not build/sign a chart in the helm client (or local helm verify failed)" \
    "$(tail -n 20 "${WORK_DIR}/helm-prep.log" 2>/dev/null)"
fi

begin_test "D1: hosted helm repo + chart.tgz AND .prov uploaded via the ChartMuseum multipart API (both parts accepted)"
if [ "$D_OK" = "1" ]; then
  if ! create_repo "$HELM_REPO" helm local; then
    D_OK=0; fail "could not create hosted helm repo ${HELM_REPO}"
  else
    upl='
curl -s -o /tmp/dtf-up.log -w "%{http_code}" \
  -u "'"${ADMIN_USER}:${ADMIN_PASS}"'" \
  -F "chart=@/tmp/dtf-out/'"$HELM_CHART"'-'"$HELM_VER"'.tgz" \
  -F "prov=@/tmp/dtf-out/'"$HELM_CHART"'-'"$HELM_VER"'.tgz.prov" \
  '"${BACKEND_INTERNAL}/helm/${HELM_REPO}/api/charts"'
echo ""
cat /tmp/dtf-up.log
'
    out="$(timeout 120 docker exec "$CHELM" sh -c "$upl" 2>&1 || true)"
    echo "  POST /api/charts (chart + prov) -> ${out}"
    if printf '%s' "$out" | grep -qE '^(200|201)'; then pass; else
      D_OK=0; fail "chart+prov multipart upload failed: ${out}"
    fi
  fi
else
  fail "skipped: prior step failed"
fi

sleep 2

# --- D2: the .prov must be served back --------------------------------------
_d2_prov_served() {
  [ "$D_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  local url="${BASE_URL}/helm/${HELM_REPO}/charts/${HELM_CHART}-${HELM_VER}.tgz"
  local tgz prov
  tgz="$(hcode -H "$(format_auth_header)" "$url")"
  prov="$(curl -s -o "${WORK_DIR}/served.prov" -w '%{http_code}' --max-time 30 \
    -H "$(format_auth_header)" "${url}.prov")"
  echo "  GET charts/${HELM_CHART}-${HELM_VER}.tgz      -> HTTP ${tgz}"
  echo "  GET charts/${HELM_CHART}-${HELM_VER}.tgz.prov -> HTTP ${prov}  $(head -c 40 "${WORK_DIR}/served.prov" 2>/dev/null)"
  if [ "$prov" != "200" ]; then
    echo "  -> pre-#2640 defect shape: the upload answered {\"saved\":true} for a prov part the backend never stored/served."
    return 1
  fi
  grep -q "BEGIN PGP SIGNED MESSAGE" "${WORK_DIR}/served.prov" 2>/dev/null
}
green_step "D2: the uploaded .prov is retrievable at <chart>.tgz.prov (helm's provenance URL)" \
           "#2640 (store + serve .prov; pre-fix it was accepted then silently discarded)" \
           _d2_prov_served

# --- D3: the real client, verification ON -----------------------------------
_d3_helm_pull_verify() {
  [ "$D_OK" = "1" ] || { echo "skipped: prior step failed"; return 1; }
  local script='
set -e
export HELM_CACHE_HOME=/tmp/dtf-h/c HELM_CONFIG_HOME=/tmp/dtf-h/g HELM_DATA_HOME=/tmp/dtf-h/d
rm -rf /tmp/dtf-h /tmp/dtf-pulled; mkdir -p /tmp/dtf-h/c /tmp/dtf-h/g /tmp/dtf-h/d /tmp/dtf-pulled
helm repo add dtfsign '"${BACKEND_INTERNAL}/helm/${HELM_REPO}"' \
  --username "'"$ADMIN_USER"'" --password "'"$ADMIN_PASS"'" >/dev/null 2>&1
helm repo update dtfsign >/dev/null 2>&1
helm pull dtfsign/'"$HELM_CHART"' --version '"$HELM_VER"' --verify \
  --keyring /tmp/dtf-pub.gpg --destination /tmp/dtf-pulled
'
  timeout 180 docker exec "$CHELM" sh -c "$script"
}
green_step "D3: REAL \`helm pull --verify\` against the AK repo verifies the chart's provenance" \
           "#2640/#2680 (.prov stored + served; pre-fix helm said 'failed to fetch provenance .../<chart>.tgz.prov')" \
           _d3_helm_pull_verify

begin_test "D4: control — the SAME chart also pulls WITHOUT --verify (plumbing sanity; keeps a future D3 red attributable to PROVENANCE)"
if [ "$D_OK" = "1" ]; then
  ctrl='
set -e
export HELM_CACHE_HOME=/tmp/dtf-h/c HELM_CONFIG_HOME=/tmp/dtf-h/g HELM_DATA_HOME=/tmp/dtf-h/d
rm -rf /tmp/dtf-pulled2; mkdir -p /tmp/dtf-pulled2
helm pull dtfsign/'"$HELM_CHART"' --version '"$HELM_VER"' --destination /tmp/dtf-pulled2
test -s /tmp/dtf-pulled2/'"$HELM_CHART"'-'"$HELM_VER"'.tgz
'
  if timeout 120 docker exec "$CHELM" sh -c "$ctrl" >"${WORK_DIR}/helm-ctrl.log" 2>&1; then
    echo "  helm pull (no --verify) also succeeds -> repo/chart plumbing is sound. If D3 ever goes red while this stays green, the regression is the .prov."
    pass
  else
    fail "the control pull (no --verify) failed — a future D3 red could not be attributed to provenance" \
         "$(tail -n 20 "${WORK_DIR}/helm-ctrl.log" 2>/dev/null)"
  fi
else
  fail "skipped: prior step failed"
fi

# ---------------------------------------------------------------------------
# Summary banner
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " signing tier summary — standing GREEN regression gate"
echo "   LEG A apt   : verification ON, no [trusted=yes]; unsigned refused, tamper BAD"
echo "   LEG B rpm   : repo_gpgcheck=1 verifies       (gates #2645 + #2679)"
echo "   LEG C apk   : index parse/signing/fail-closed (gates #2634 + #2677)"
echo "                 C4 end-to-end verify = the ONE remaining KNOWN-RED pin"
echo "                 (.SIGN.RSA digest/framing not apk-verifiable yet)"
echo "   LEG D helm  : pull --verify verifies         (gates #2640 + #2680)"
echo "   any other red means a merged backend fix has regressed."
echo "============================================================"

end_suite
