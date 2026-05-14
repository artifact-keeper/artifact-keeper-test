#!/usr/bin/env bash
# test-cache-stampede.sh - T2-12: Cache stampede / thundering-herd prevention
#
# STUBBED: same backend dependency as test-cache-poisoning.sh.
#
# The mock-upstream fixture exposes itself on the ARC runner pod IP
# (10.244.0.0/16, RFC1918). The backend's validate_outbound_url rejects every
# RFC1918 address via Ipv4Addr::is_private(), so POST /api/v1/repositories
# with that upstream_url returns HTTP 400.
#
# Backend dependency: artifact-keeper#1224 (add AK_SSRF_ALLOW_PRIVATE_CIDRS
# env var so the test overlay can allowlist 10.244.0.0/16). Once that ships,
# helm/values-test.yaml sets the env var and this file drops the skip.
#
# Full rationale and rejected alternatives: see test-cache-poisoning.sh.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-stampede"
begin_test "Cache-stampede suite skipped pending backend SSRF allowlist"
skip "Blocked on artifact-keeper#1224 (backend AK_SSRF_ALLOW_PRIVATE_CIDRS env var). Tracking: artifact-keeper-test#122."
end_suite
