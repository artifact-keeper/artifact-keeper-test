#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-upstream-url/oracle.sh -- proxy-upstream-url tier (#2822)
# =============================================================================
# run.sh has brought backend+postgres+nexus up on this slot (health-gated
# `up -d --wait`, so the 2-3 min Nexus boot is already absorbed) and exported
# BASE_URL, DB_CONTAINER, ADMIN_PASS, BACKEND_IMAGE, DTF_SLOT + the port block,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR.
#
# Steps (each a JUnit test):
#   1. nexus_bootstrap.sh  -- EULA accept + admin password rotation (idempotent)
#   2. nexus_seed.sh       -- seed a maven `proxy` repo (proxy.remoteUrl set)
#   3. assert.sh           -- real AK migration of the proxy, then the #2822
#                            checks: the proxy provisions as an AK remote repo
#                            with upstream_url set and the job does not fail.
#                            exit 0 on a fixed image, exit = failed-check count
#                            on a pre-#2822 image (non-zero-while-bug).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-upstream-url-2822"

SETUP_OK=1

begin_test "Nexus source bootstrap (EULA accept + admin rotation, per-slot instance)"
if bash "${HERE}/nexus_bootstrap.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_bootstrap.sh failed on slot ${DTF_SLOT} (see stdout above)"
fi

begin_test "Seed a maven proxy repo into Nexus (proxy.remoteUrl = Maven Central)"
if [ "$SETUP_OK" = "1" ] && bash "${HERE}/nexus_seed.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_seed.sh failed (or bootstrap already failed) on slot ${DTF_SLOT}"
fi

begin_test "#2822 migrate -> assert: proxy provisioned as an AK remote repo with upstream_url set (not skipped by check_upstream_url 23514) and the job did not fail"
if [ "$SETUP_OK" = "1" ]; then
  rc=0; bash "${HERE}/assert.sh" || rc=$?
  if [ "$rc" -eq 0 ]; then
    pass
  else
    fail "proxy-upstream-url oracle reported ${rc} failed #2822 positive check(s) on ${BASE_URL} (proxy skipped/absent or upstream_url missing; pre-#2822 create_repository omitted upstream_url -> check_upstream_url 23514 -> job Failed); see stdout above"
  fi
else
  fail "skipped: Nexus setup failed earlier in the suite"
fi

end_suite
