#!/usr/bin/env bash
# test-cache-stampede.sh - T2-12: Cache stampede / thundering-herd prevention
#
# STUBBED: Same mock-upstream fixture issue as test-cache-poisoning.sh.
# Mock deploys at runner pod IP (RFC1918), backend's SSRF guard correctly
# rejects. Tracked in artifact-keeper-test#122 (Service-DNS-based mock).
#
# Until #122 lands, this test emits a clean per-test skip so release-gate
# does not silent-success-fail.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-stampede"
begin_test "Cache-stampede suite skipped pending fixture refactor"
skip "Mock-upstream fixture refactor blocked on artifact-keeper-test#122 (Service-DNS-based mock to bypass SSRF guard for cluster-internal fixtures)"
end_suite
