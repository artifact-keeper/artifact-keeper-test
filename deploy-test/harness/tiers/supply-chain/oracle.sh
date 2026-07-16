#!/usr/bin/env bash
# =============================================================================
# tiers/supply-chain/oracle.sh — scanner-efficacy discriminating oracle (#2088)
# =============================================================================
# run.sh has already stood up the `filesystem + trivy` profile-set (backend with
# TRIVY_ADAPTER_URL pointed at the in-house scanner-adapter sidecar) and exported
# BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT,
# JUNIT_OUTPUT_DIR, AK_TEST_ROOT. We reuse the corpus PER-SCANNER image-scan
# efficacy gate tests/release-gate/test-pinned-cve-image.sh verbatim — it is the
# oracle that already models the ONE thing that works correctly per the #2088
# forensics: a DIGEST-PINNED known-vulnerable image is scanned and EACH wired
# image scanner must independently reach `completed` with findings_count >= a
# FLOOR. A scanner that completes with 0 findings on the vulnerable canary (the
# #2088 false-clean: trivy CLI dropped in #2059 -> scan_type=image completed/0),
# or is ABSENT (adapter down / not dispatched), is a HARD FAIL. An aggregate
# "total findings > 0" would PASS that bug (a peer scanner covers for the dead
# one); this gate refuses that by asserting PER SCANNER.
#
# Scanner set for THIS profile: only the Trivy adapter is wired (scanners=trivy),
# so the required per-scanner list is `image` (the Trivy container-image scan) —
# NOT the corpus default "image grype", because no grype sidecar is stood up in
# this tier. Requiring `image` alone is exactly the #2088 regression surface.
#
# WASM PLUGIN SIGNING (matrix row 8): NOT covered here. Standing up a real
# signed/tampered-plugin reject test needs a plugin-signing keypair + a plugin
# load endpoint fixture that this profile does not provision, and faking it would
# violate the no-unfailable-test rule. Row 8 stays GAP (see MATRIX-ROW.md); this
# oracle deliberately does not claim it.
# =============================================================================
set -uo pipefail
: "${AK_TEST_ROOT:?}"; : "${BASE_URL:?}"

SUITE="${AK_TEST_ROOT}/tests/release-gate/test-pinned-cve-image.sh"
if [ ! -f "$SUITE" ]; then
  echo "!! corpus scanner-efficacy suite not found: ${SUITE}" >&2
  exit 1
fi

# Only the Trivy image scanner is wired in this profile; require it explicitly.
# (Override REQUIRED_IMAGE_SCANNERS to add grype once a grype sidecar profile
# exists.) FINDINGS_FLOOR default 10: the alpine:3.4 canary yields dozens of
# OS-package CVEs across the trivy DB, comfortably above the floor.
export REQUIRED_IMAGE_SCANNERS="${REQUIRED_IMAGE_SCANNERS:-image}"
export FINDINGS_FLOOR="${FINDINGS_FLOOR:-10}"
# First scan pays the trivy vuln-DB download (cached thereafter in the adapter
# volume); give the poll a generous budget.
export SCAN_TIMEOUT="${SCAN_TIMEOUT:-420}"
# A release gate must never silently skip an unavailable scanner (the #2088
# false-clean class). The suite already refuses ALLOW_SCANNER_SKIP=1; be explicit.
export ALLOW_SCANNER_SKIP=0

# ---------------------------------------------------------------------------
# Pre-warm the trivy vuln DB in the adapter BEFORE the corpus test triggers its
# one scan. The very first scan otherwise pays the ~100 MiB DB download inline,
# and a transient upstream token hiccup during that download makes trivy exit
# non-zero -> the scan row is `failed` (an infra fault mis-scored as a #2088
# false-clean). Pre-warming (with retries) moves the download out of the
# measured scan and caches it in dtf_trivycache, so the scan itself hits a warm
# DB. This is the design's "cache the Trivy DB so first-run download doesn't
# dominate". Best-effort: if it can't warm after retries we still run the gate
# (which then fails closed, correctly, on a genuinely unreachable DB).
TRIVY_CONTAINER="ak-dtf${DTF_SLOT:?}-trivy"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$TRIVY_CONTAINER"; then
  echo ">> pre-warming trivy vuln DB in ${TRIVY_CONTAINER} ..."
  warmed=0
  for attempt in 1 2 3 4 5; do
    if docker exec "$TRIVY_CONTAINER" sh -c \
        'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' \
        >/dev/null 2>&1; then
      echo ">>   trivy DB warm (attempt ${attempt})"
      warmed=1
      break
    fi
    echo ">>   DB warm attempt ${attempt}/5 failed; retrying in 5s ..."
    sleep 5
  done
  [ "$warmed" = "1" ] || echo "!! WARN: could not pre-warm trivy DB after 5 attempts; the gate will fail closed if the DB is genuinely unreachable" >&2
else
  echo "!! WARN: trivy adapter container ${TRIVY_CONTAINER} not found; scanner may be unavailable" >&2
fi

echo ">> supply-chain oracle -> ${SUITE}"
echo ">>   REQUIRED_IMAGE_SCANNERS=${REQUIRED_IMAGE_SCANNERS}  FINDINGS_FLOOR=${FINDINGS_FLOOR}  SCAN_TIMEOUT=${SCAN_TIMEOUT}"
bash "$SUITE"
