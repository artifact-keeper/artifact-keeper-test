#!/usr/bin/env bash
# test-debian-gpg-chain.sh - Debian GPG signature chain end-to-end test (#72.4)
#
# Validates the full apt-secure trust chain on a signing-enabled Debian
# repository:
#
#   1. Create a Debian repo, attach a signing key, upload a .deb
#   2. Fetch dists/<suite>/InRelease and assert it has a PGP signed block
#   3. Fetch dists/<suite>/Release and dists/<suite>/Release.gpg (detached)
#   4. Fetch the repo's GPG public key (/key endpoint, format-native scope)
#      and import it into a throwaway GNUPGHOME
#   5. Run `gpg --verify Release.gpg Release` and assert PASS
#   6. Negative control: flip one byte in Release, re-run gpg --verify, and
#      assert it FAILS (signature must reject tampered content)
#
# This is the first E2E test of the Debian signing-chain endpoints (4.4),
# which had no test-deb*.sh coverage before issue #72. The /key endpoint
# and Release.gpg endpoint exist in the 1.1.x backend but were never
# exercised by an apt-secure-style verification flow.
#
# Requires: curl, gpg (gnupg pre-installed on Ubuntu runners), ar (binutils),
# tar, gzip, jq.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "debian-gpg-chain"
auth_admin
setup_workdir

# Per-suite GNUPGHOME so we never touch the runner's real keyring.
GNUPGHOME_DIR="${WORK_DIR}/gpghome"
mkdir -p "$GNUPGHOME_DIR"
chmod 700 "$GNUPGHOME_DIR"
export GNUPGHOME="$GNUPGHOME_DIR"
# Best-effort kill of any gpg-agent we spawn so a parallel suite doesn't
# inherit a stuck socket. Registered before any gpg call.
add_exit_handler 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true'

REPO_KEY="test-deb-gpg-${RUN_ID}"
KEY_NAME="deb-gpg-chain-key-${RUN_ID}"
DISTRIBUTION="stable"
COMPONENT="main"
PKG_NAME="gpgchain"
PKG_VERSION="1.0.0"
PKG_ARCH="amd64"
DEB_FILE="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

# ---------------------------------------------------------------------------
# Tool preflight: gpg is the only non-stock dep. binutils-ar is already in
# the system-packages batch install (see release-gate.yml). If gpg is
# missing we skip the whole suite rather than fail a release gate on a
# runner gap.
# ---------------------------------------------------------------------------
if ! command -v gpg >/dev/null 2>&1; then
  skip_suite "gpg not available on runner; cannot exercise apt-secure trust chain"
fi
if ! command -v ar >/dev/null 2>&1; then
  skip_suite "ar (binutils) not available; cannot assemble .deb fixture"
fi

# ---------------------------------------------------------------------------
# Helper: build a minimal .deb. Same shape as the helper in
# test-debian-conformance.sh, kept inline so this suite is self-contained.
# ---------------------------------------------------------------------------
build_deb() {
  local name="$1"
  local version="$2"
  local arch="$3"
  local outfile="$4"

  local build_dir="${WORK_DIR}/deb-build-${name}-${version}-${arch}"
  mkdir -p "${build_dir}"
  echo "2.0" > "${build_dir}/debian-binary"

  local ctrl_dir="${build_dir}/control-root"
  mkdir -p "${ctrl_dir}"
  cat > "${ctrl_dir}/control" <<CTRL
Package: ${name}
Version: ${version}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: CI <ci@example.com>
Description: GPG-chain test package (${name} ${version} ${arch})
CTRL
  tar czf "${build_dir}/control.tar.gz" -C "${ctrl_dir}" ./control

  local data_dir="${build_dir}/data-root"
  mkdir -p "${data_dir}/usr/share/doc/${name}"
  echo "${name} ${version}" > "${data_dir}/usr/share/doc/${name}/README"
  tar czf "${build_dir}/data.tar.gz" -C "${data_dir}" .

  (cd "${build_dir}" && ar rcs "${outfile}" debian-binary control.tar.gz data.tar.gz 2>/dev/null)
}

# ---------------------------------------------------------------------------
# 1. Create signing key (RSA 4096). If the signing API is not present on
#    this backend, the whole suite skips: the chain we want to exercise
#    does not exist without a key.
# ---------------------------------------------------------------------------

begin_test "Create RSA signing key for Debian repo"
KEY_RESP=""
if KEY_RESP=$(api_post "/api/v1/signing/keys" \
    "{\"name\":\"${KEY_NAME}\",\"key_type\":\"rsa\",\"algorithm\":\"rsa4096\"}" 2>/dev/null); then
  KEY_ID=$(echo "$KEY_RESP" | jq -r '.id // .key_id // empty')
  if [ -n "$KEY_ID" ] && [ "$KEY_ID" != "null" ]; then
    pass
    # Clean the key up at suite exit so re-runs don't leak.
    add_exit_handler "curl -sf -X DELETE -H \"\$(auth_header)\" \"\${BASE_URL}/api/v1/signing/keys/${KEY_ID}\" >/dev/null 2>&1 || true"
  else
    skip "signing key created but response had no id"
    end_suite
  fi
else
  # 404/501 means the feature isn't shipped on this backend; clean-skip
  # rather than fail (#72 targets a backend that ships it).
  skip_suite "signing API not available (POST /api/v1/signing/keys returned non-2xx)"
fi

# ---------------------------------------------------------------------------
# 2. Create the repo and attach the signing key.
# ---------------------------------------------------------------------------

begin_test "Create Debian repo"
if create_local_repo "$REPO_KEY" "debian"; then
  pass
  # Clean the repo up at suite exit so throwaway repos don't accumulate
  # across re-runs. Mirrors the signing-key cleanup above.
  add_exit_handler "curl -s -X DELETE -H \"\$(auth_header)\" \"\${BASE_URL}/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"
else
  fail "could not create debian repo"
  end_suite
fi

begin_test "Attach signing key to repo (enable=true)"
SIGN_STATUS=$(curl -s -o "${WORK_DIR}/sign-cfg.json" -w '%{http_code}' \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "{\"key_id\":\"${KEY_ID}\",\"enabled\":true}" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/signing") || SIGN_STATUS="000"

if [ "$SIGN_STATUS" -ge 200 ] 2>/dev/null && [ "$SIGN_STATUS" -lt 300 ] 2>/dev/null; then
  pass
elif [ "$SIGN_STATUS" = "404" ] || [ "$SIGN_STATUS" = "501" ]; then
  skip_suite "per-repo signing config endpoint not available (HTTP ${SIGN_STATUS})"
else
  fail "PUT /repositories/${REPO_KEY}/signing returned ${SIGN_STATUS}"
  end_suite
fi

# ---------------------------------------------------------------------------
# 3. Upload one .deb so the repo has Release content to sign.
# ---------------------------------------------------------------------------

DEB_PATH="${WORK_DIR}/${DEB_FILE}"
build_deb "$PKG_NAME" "$PKG_VERSION" "$PKG_ARCH" "$DEB_PATH"

begin_test "Upload .deb into signed repo"
UP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@${DEB_PATH}" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/${DEB_FILE}") || UP_STATUS="000"

if [ "$UP_STATUS" -ge 200 ] 2>/dev/null && [ "$UP_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "pool PUT returned HTTP ${UP_STATUS}, expected 2xx"
  end_suite
fi

# Allow async re-sign of Release after the upload.
sleep 2

# ---------------------------------------------------------------------------
# 4. Fetch and validate InRelease (inline-signed Release).
# ---------------------------------------------------------------------------

begin_test "InRelease contains PGP SIGNED MESSAGE block"
INREL_STATUS=$(curl -s -o "${WORK_DIR}/InRelease" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/InRelease") || INREL_STATUS="000"

if [ "$INREL_STATUS" = "404" ] || [ "$INREL_STATUS" = "501" ]; then
  skip "InRelease endpoint not available (HTTP ${INREL_STATUS})"
elif [ "$INREL_STATUS" -ge 200 ] 2>/dev/null && [ "$INREL_STATUS" -lt 300 ] 2>/dev/null; then
  if grep -q "BEGIN PGP SIGNED MESSAGE" "${WORK_DIR}/InRelease" \
     && grep -q "BEGIN PGP SIGNATURE" "${WORK_DIR}/InRelease"; then
    pass
  else
    fail "InRelease lacks PGP markers; signing chain did not produce inline-signed Release" \
         "$(head -c 400 "${WORK_DIR}/InRelease")"
  fi
else
  fail "InRelease GET returned HTTP ${INREL_STATUS}"
fi

# ---------------------------------------------------------------------------
# 5. Fetch detached pair: Release + Release.gpg.
# ---------------------------------------------------------------------------

begin_test "Release endpoint returns plain Release file"
REL_STATUS=$(curl -s -o "${WORK_DIR}/Release" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/Release") || REL_STATUS="000"

if [ "$REL_STATUS" -ge 200 ] 2>/dev/null && [ "$REL_STATUS" -lt 300 ] 2>/dev/null \
   && [ -s "${WORK_DIR}/Release" ]; then
  if grep -q "^Suite: ${DISTRIBUTION}" "${WORK_DIR}/Release"; then
    pass
  else
    fail "Release file missing Suite: ${DISTRIBUTION}" \
         "$(head -c 400 "${WORK_DIR}/Release")"
  fi
else
  fail "Release GET returned HTTP ${REL_STATUS} (body empty=$([ ! -s "${WORK_DIR}/Release" ] && echo yes || echo no))"
fi

begin_test "Release.gpg endpoint returns detached PGP signature"
RELGPG_STATUS=$(curl -s -o "${WORK_DIR}/Release.gpg" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/Release.gpg") || RELGPG_STATUS="000"

if [ "$RELGPG_STATUS" = "404" ] || [ "$RELGPG_STATUS" = "501" ]; then
  skip "Release.gpg endpoint not implemented (HTTP ${RELGPG_STATUS})"
elif [ "$RELGPG_STATUS" -ge 200 ] 2>/dev/null && [ "$RELGPG_STATUS" -lt 300 ] 2>/dev/null \
     && [ -s "${WORK_DIR}/Release.gpg" ]; then
  # A detached sig is either PGP-armored ("BEGIN PGP SIGNATURE") or binary
  # OpenPGP. Accept either; we'll prove validity in the gpg --verify step.
  if grep -q "BEGIN PGP SIGNATURE" "${WORK_DIR}/Release.gpg" 2>/dev/null \
     || file "${WORK_DIR}/Release.gpg" 2>/dev/null | grep -qi "PGP" \
     || [ "$(wc -c < "${WORK_DIR}/Release.gpg")" -gt 64 ]; then
    pass
  else
    fail "Release.gpg body does not look like a PGP signature" \
         "head: $(head -c 200 "${WORK_DIR}/Release.gpg" | od -c | head -3)"
  fi
else
  fail "Release.gpg GET returned HTTP ${RELGPG_STATUS}"
fi

# ---------------------------------------------------------------------------
# 6. Fetch the repo's GPG public key. The Debian handler exposes this at
#    /debian/<repo>/dists/<distribution>/gpg-key.asc (debian.rs:61). That
#    is the format-native, OpenPGP-armored route apt clients use. We do
#    NOT fall back to /api/v1/signing/keys/<id>/public here because that
#    platform endpoint returns an X.509 SubjectPublicKeyInfo PEM
#    ("BEGIN PUBLIC KEY"), which gpg --import rejects, breaking the
#    entire trust chain we are trying to verify.
# ---------------------------------------------------------------------------

begin_test "Fetch repo GPG public key (dists/<dist>/gpg-key.asc)"
PUBKEY_FILE="${WORK_DIR}/repo.pub.asc"
PK_STATUS=$(curl -s -o "$PUBKEY_FILE" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/gpg-key.asc") || PK_STATUS="000"

if [ "$PK_STATUS" = "404" ] || [ "$PK_STATUS" = "501" ]; then
  skip_suite "OpenPGP public-key endpoint not available (HTTP ${PK_STATUS} at /debian/${REPO_KEY}/dists/${DISTRIBUTION}/gpg-key.asc); cannot exercise apt-secure trust chain"
elif [ "$PK_STATUS" -ge 200 ] 2>/dev/null && [ "$PK_STATUS" -lt 300 ] 2>/dev/null \
     && [ -s "$PUBKEY_FILE" ]; then
  # The route serves an OpenPGP public key. Accept ASCII-armored
  # ("BEGIN PGP PUBLIC KEY") or a binary OpenPGP packet blob. Reject
  # an X.509 PEM, which gpg --import will not accept.
  if grep -q "BEGIN PUBLIC KEY" "$PUBKEY_FILE"; then
    fail "gpg-key.asc returned an X.509 PEM ('BEGIN PUBLIC KEY'), not OpenPGP; gpg --import will reject it" \
         "$(head -c 200 "$PUBKEY_FILE")"
  elif grep -q "BEGIN PGP PUBLIC KEY" "$PUBKEY_FILE"; then
    pass
  elif [ "$(wc -c < "$PUBKEY_FILE")" -gt 100 ]; then
    # Binary OpenPGP packets are valid; gpg --import will validate below.
    pass
  else
    fail "public key body too small (${PK_STATUS}, $(wc -c < "$PUBKEY_FILE") bytes)"
  fi
else
  fail "GET ${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/gpg-key.asc returned HTTP ${PK_STATUS}"
fi

# ---------------------------------------------------------------------------
# 7. apt-secure verification: import the key into a throwaway GNUPGHOME,
#    then `gpg --verify Release.gpg Release` and assert PASS.
# ---------------------------------------------------------------------------

begin_test "gpg --import accepts repo public key"
if [ ! -s "$PUBKEY_FILE" ]; then
  skip "no public key to import"
else
  IMPORT_LOG="${WORK_DIR}/gpg-import.log"
  if gpg --batch --import "$PUBKEY_FILE" >"$IMPORT_LOG" 2>&1; then
    pass
  else
    fail "gpg --import failed" "$(head -c 600 "$IMPORT_LOG")"
  fi
fi

begin_test "apt-secure trust chain: gpg --verify Release.gpg Release PASSES"
if [ ! -s "${WORK_DIR}/Release.gpg" ] || [ ! -s "${WORK_DIR}/Release" ] \
   || [ ! -s "$PUBKEY_FILE" ]; then
  skip "missing artefacts (Release, Release.gpg, or public key) - upstream tests already failed"
else
  VERIFY_LOG="${WORK_DIR}/gpg-verify.log"
  if gpg --batch --verify "${WORK_DIR}/Release.gpg" "${WORK_DIR}/Release" >"$VERIFY_LOG" 2>&1; then
    pass
  else
    fail "gpg --verify on untampered pair failed; apt-secure trust chain broken" \
         "$(head -c 800 "$VERIFY_LOG")"
  fi
fi

# ---------------------------------------------------------------------------
# 8. Negative control: tamper one byte in Release and assert gpg --verify
#    FAILS. Without this, a backend that hands out a self-consistent but
#    static stub would still pass test 7.
# ---------------------------------------------------------------------------

begin_test "Negative control: tampered Release FAILS gpg --verify"
if [ ! -s "${WORK_DIR}/Release.gpg" ] || [ ! -s "${WORK_DIR}/Release" ] \
   || [ ! -s "$PUBKEY_FILE" ]; then
  skip "missing artefacts; cannot run negative control"
else
  TAMPERED="${WORK_DIR}/Release.tampered"
  cp "${WORK_DIR}/Release" "$TAMPERED"
  # Flip a printable byte well inside the body. We append a single 'X' to
  # avoid edge cases where the very first/last byte is part of trailing
  # whitespace that some normalizers strip.
  printf 'X' >> "$TAMPERED"

  NEG_LOG="${WORK_DIR}/gpg-verify-neg.log"
  if gpg --batch --verify "${WORK_DIR}/Release.gpg" "$TAMPERED" >"$NEG_LOG" 2>&1; then
    fail "tampered Release was accepted by gpg --verify; signature is not enforcing integrity" \
         "$(head -c 800 "$NEG_LOG")"
  else
    pass
  fi
fi

end_suite
