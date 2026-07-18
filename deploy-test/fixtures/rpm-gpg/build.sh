#!/usr/bin/env bash
# =============================================================================
# fixtures/rpm-gpg/build.sh — signed RPM curation upstream fixture (PKT-E, #2568)
# =============================================================================
# Bakes a mock RPM upstream tree + a REAL OpenPGP keypair that the backend's
# `signing_service::verify_detached` (pgp / rPGP 0.14 crate) accepts, so the
# rpm-curation-gpg tier can drive the fail-closed curation GPG gate end to end.
#
# RUN ON THE HOST at fixture-authoring time (needs `gpg`, which the nginx:alpine
# upstream container does NOT ship and cannot apk-add offline on the rig). The
# profile bind-mounts the baked `tree/` into the upstream webroot READ-ONLY, and
# the oracle reads the exported public keys from `keys/`. Re-runnable + idempotent
# (wipes and regenerates keys+tree together so the signature and the pubkey the
# oracle configures are ALWAYS consistent — never commit a stale asc/key pair).
#
# What it produces under this dir:
#   keys/correct.pub.asc   ASCII-armored PUBLIC key A  (configured as trusted_gpg_key on the POSITIVE + missing-asc remotes)
#   keys/wrong.pub.asc     ASCII-armored PUBLIC key B  (unrelated; configured on the WRONG-KEY remote — verify must fail)
#   tree/signed/repodata/repomd.xml           minimal repomd pinning primary.xml.gz by sha256 (compressed + open)
#   tree/signed/repodata/repomd.xml.asc       DETACHED signature over repomd.xml, made by key A (RSA, SHA256 — the flavor rPGP verifies)
#   tree/signed/repodata/primary.xml.gz       gzip of primary.xml; its sha256 == repomd <checksum> (primary_gz_pinned_by_repomd chain)
#   tree/signed/pool/<marker>.rpm             placeholder pool object at the primary <location href> (sync never fetches it; realism only)
#   tree/unsigned/repodata/{repomd.xml,primary.xml.gz}   SAME tree but NO repomd.xml.asc (drives the missing-.asc fail-closed leg)
#
# The GPG flavor is chosen to mirror the backend's own signer
# (signing_service::sign_openpgp_detached_blocking: SignatureType::Binary, RSA,
# SHA2_256) — the same way the SSO tier mirrors the backend's bergshamra verifier.
# `gpg --detach-sign` produces exactly a binary document signature; forcing an RSA
# key + SHA256 digest keeps it inside what pgp 0.14's StandaloneSignature::verify
# accepts. verify_detached is validated for real by running the tier against the
# candidate image (the POSITIVE leg must ingest > 0), not assumed here.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${HERE}/keys"
TREE_DIR="${HERE}/tree"
MARKER_NAME="ak-dtf-gpg-marker"
MARKER_NVRA="${MARKER_NAME}-1.0.0-1.noarch.rpm"

command -v gpg >/dev/null || { echo "!! gpg not found on host; cannot bake GPG fixture" >&2; exit 1; }
command -v gzip >/dev/null || { echo "!! gzip not found" >&2; exit 1; }

echo ">> rpm-gpg fixture: regenerating keys + tree (consistent asc/pubkey pair)"
rm -rf "$KEYS_DIR" "$TREE_DIR"
mkdir -p "$KEYS_DIR" "$TREE_DIR/signed/repodata" "$TREE_DIR/signed/pool" "$TREE_DIR/unsigned/repodata" "$TREE_DIR/unsigned/pool"

# --- 1. Generate two independent RSA keypairs (A = trusted, B = wrong) --------
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
chmod 700 "$GNUPGHOME"
cleanup() { rm -rf "$GNUPGHOME"; }
trap cleanup EXIT

gen_key() { # gen_key <realname> <email>  -> prints fingerprint
  local name="$1" email="$2"
  cat > "$GNUPGHOME/keyparams" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 3072
Key-Usage: sign
Name-Real: $name
Name-Email: $email
Expire-Date: 0
%commit
EOF
  gpg --batch --quiet --gen-key "$GNUPGHOME/keyparams" >/dev/null 2>&1
  # Latest fingerprint for this email.
  gpg --batch --with-colons --list-keys "$email" 2>/dev/null \
    | awk -F: '/^fpr:/{print $10; exit}'
}

echo ">>   generating trusted key A + unrelated wrong key B (RSA-3072)..."
FPR_A="$(gen_key 'DTF Curation Trusted Key' 'dtf-trusted@example.test')"
FPR_B="$(gen_key 'DTF Curation Wrong Key'   'dtf-wrong@example.test')"
[ -n "$FPR_A" ] && [ -n "$FPR_B" ] || { echo "!! key generation failed (A=$FPR_A B=$FPR_B)" >&2; exit 1; }
echo ">>   trusted A fpr=${FPR_A}"
echo ">>   wrong   B fpr=${FPR_B}"

gpg --batch --armor --export "$FPR_A" > "$KEYS_DIR/correct.pub.asc"
gpg --batch --armor --export "$FPR_B" > "$KEYS_DIR/wrong.pub.asc"
[ -s "$KEYS_DIR/correct.pub.asc" ] && [ -s "$KEYS_DIR/wrong.pub.asc" ] || { echo "!! pubkey export empty" >&2; exit 1; }

# --- 2. Build primary.xml (one marker package the sync parser will ingest) ----
# parse_rpm_primary_xml requires a non-empty <name> and version ver="" attr; the
# per-package <checksum> is the rpm pkgid (arbitrary hex, stored verbatim).
PKGID_SHA="$(printf 'dtf-marker-pkgid' | sha256sum | cut -d' ' -f1)"
PRIMARY_XML="$TREE_DIR/signed/repodata/primary.xml"
cat > "$PRIMARY_XML" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm">
  <name>${MARKER_NAME}</name>
  <arch>noarch</arch>
  <version epoch="0" ver="1.0.0" rel="1"/>
  <checksum type="sha256" pkgid="YES">${PKGID_SHA}</checksum>
  <summary>DTF PKT-E RPM curation GPG marker</summary>
  <description>DTF-CURATION-GPG-MARKER</description>
  <packager>DTF</packager>
  <url>http://example.test</url>
  <location href="pool/${MARKER_NVRA}"/>
</package>
</metadata>
EOF

# Placeholder pool object at the advertised href (sync never fetches it).
printf 'DTF-CURATION-GPG-MARKER placeholder rpm (not a real package)\n' > "$TREE_DIR/signed/pool/${MARKER_NVRA}"

# --- 3. Compute the repomd checksum chain from the ACTUAL bytes ---------------
OPEN_SHA="$(sha256sum "$PRIMARY_XML" | cut -d' ' -f1)"
OPEN_SIZE="$(wc -c < "$PRIMARY_XML" | tr -d ' ')"
# gzip -n: drop name/mtime so the archive bytes are stable across runs.
gzip -9 -n -c "$PRIMARY_XML" > "$TREE_DIR/signed/repodata/primary.xml.gz"
rm -f "$PRIMARY_XML"   # only the .gz is served (the href points at primary.xml.gz)
GZ_SHA="$(sha256sum "$TREE_DIR/signed/repodata/primary.xml.gz" | cut -d' ' -f1)"
GZ_SIZE="$(wc -c < "$TREE_DIR/signed/repodata/primary.xml.gz" | tr -d ' ')"
TS="$(date +%s)"

# --- 4. repomd.xml pinning primary.xml.gz by BOTH compressed + open checksum --
# extract_primary_data reads: <location href>, <checksum type> (over the .gz),
# <open-checksum type> (over the decompressed xml). primary_gz_pinned_by_repomd
# then enforces sha256(primary.xml.gz) == <checksum> on the verified path.
REPOMD="$TREE_DIR/signed/repodata/repomd.xml"
cat > "$REPOMD" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>${TS}</revision>
  <data type="primary">
    <checksum type="sha256">${GZ_SHA}</checksum>
    <open-checksum type="sha256">${OPEN_SHA}</open-checksum>
    <location href="repodata/primary.xml.gz"/>
    <timestamp>${TS}</timestamp>
    <size>${GZ_SIZE}</size>
    <open-size>${OPEN_SIZE}</open-size>
  </data>
</repomd>
EOF

# --- 5. Detached signature over repomd.xml by key A (RSA + SHA256) ------------
gpg --batch --yes --quiet --local-user "$FPR_A" \
    --digest-algo SHA256 --detach-sign --armor \
    --output "$REPOMD.asc" "$REPOMD"
[ -s "$REPOMD.asc" ] || { echo "!! detached signature not produced" >&2; exit 1; }

# Sanity: the signature must verify with key A under gpg itself (a real OpenPGP
# signature). rPGP acceptance is proven by the live POSITIVE leg of the tier.
if ! gpg --batch --quiet --verify "$REPOMD.asc" "$REPOMD" 2>/dev/null; then
  echo "!! self-verify of repomd.xml.asc with the generating key failed" >&2
  exit 1
fi

# --- 6. Unsigned tree: identical repomd + primary, but NO .asc ----------------
cp "$REPOMD" "$TREE_DIR/unsigned/repodata/repomd.xml"
cp "$TREE_DIR/signed/repodata/primary.xml.gz" "$TREE_DIR/unsigned/repodata/primary.xml.gz"
cp "$TREE_DIR/signed/pool/${MARKER_NVRA}" "$TREE_DIR/unsigned/pool/${MARKER_NVRA}"
# (deliberately no repomd.xml.asc under unsigned/ -> drives the missing-asc leg)

echo ">> rpm-gpg fixture baked:"
echo "   trusted pubkey : ${KEYS_DIR}/correct.pub.asc"
echo "   wrong   pubkey : ${KEYS_DIR}/wrong.pub.asc"
echo "   signed tree    : ${TREE_DIR}/signed   (repomd.xml + .asc + primary.xml.gz sha=${GZ_SHA})"
echo "   unsigned tree  : ${TREE_DIR}/unsigned (no repomd.xml.asc)"
echo "   marker package : ${MARKER_NAME} 1.0.0-1 noarch"
