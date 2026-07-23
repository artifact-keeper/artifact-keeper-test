#!/usr/bin/env bash
# =============================================================================
# tiers/nexus-go-apt/oracle.sh — nexus-go-apt tier (upstreams=nexus, #2784)
# =============================================================================
# run.sh has brought backend+postgres+nexus up on this slot (health-gated
# `up -d --wait`, so the 2-3 min Nexus boot is already absorbed) and exported
# BASE_URL, DB_CONTAINER, ADMIN_PASS, BACKEND_IMAGE, DTF_SLOT + the port block,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR.
#
# Steps (each a JUnit test):
#   1. nexus_bootstrap.sh  — EULA accept + admin password rotation (idempotent)
#   2. nexus_seed.sh       — seed a go-hosted (Go module) + apt-hosted (.deb)
#   3. assert.sh           — real AK migration, then the #2784 positive checks:
#                            exit 0 on a fixed image, exit = failed-check count
#                            on a pre-#2784 image (non-zero-while-bug).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "nexus-go-apt-2784"

SETUP_OK=1

begin_test "Nexus source bootstrap (EULA accept + admin rotation, per-slot instance)"
if bash "${HERE}/nexus_bootstrap.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_bootstrap.sh failed on slot ${DTF_SLOT} (see stdout above)"
fi

begin_test "Seed Go + apt fixtures into Nexus: go-hosted (module zip) + apt-hosted (.deb)"
if [ "$SETUP_OK" = "1" ] && bash "${HERE}/nexus_seed.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_seed.sh failed (or bootstrap already failed) on slot ${DTF_SLOT}"
fi

begin_test "#2784 migrate -> assert: Go module in artifacts+Packages+search (format=go), apt provisioned (not rejected) with its .deb"
if [ "$SETUP_OK" = "1" ]; then
  rc=0; bash "${HERE}/assert.sh" || rc=$?
  if [ "$rc" -eq 0 ]; then
    pass
  else
    fail "nexus-go-apt oracle reported ${rc} failed #2784 positive check(s) on ${BASE_URL} (Go deps absent from Artifacts/Packages/search, or apt rejected); see stdout above"
  fi
else
  fail "skipped: Nexus setup failed earlier in the suite"
fi

end_suite
