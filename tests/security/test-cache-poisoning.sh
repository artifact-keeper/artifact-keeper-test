#!/usr/bin/env bash
# test-cache-poisoning.sh - T2-11: Proxy/remote repo cache poisoning prevention
#
# STUBBED: blocked on a backend change.
#
# Why this is stubbed
# -------------------
# The fixture (tests/lib/mock-upstream.py, booted by start_mock_upstream in
# tests/lib/common.sh) runs the mock inside the ARC runner pod and exposes
# it on the pod IP. In our K8s cluster the pod CIDR is 10.244.0.0/16, which
# is RFC1918. The backend's validate_outbound_url (backend/src/api/validation.rs)
# rejects every RFC1918 address via Rust's Ipv4Addr::is_private(). The
# release-gate workflow sets MOCK_UPSTREAM_HOSTNAME to the runner pod IP,
# so POST /api/v1/repositories with that upstream_url returns:
#
#   HTTP 400 "IP '10.244.0.x' is not allowed (private/internal network)"
#
# This is correct production behavior; what's missing is a test-only opt-out.
#
# Backend dependency
# ------------------
# Tracked as artifact-keeper#1224: add AK_SSRF_ALLOW_PRIVATE_CIDRS env var so
# the test overlay can allowlist 10.244.0.0/16 for the test namespace. Once
# that ships:
#   1. helm/values-test.yaml sets backend.env.AK_SSRF_ALLOW_PRIVATE_CIDRS=10.244.0.0/16
#   2. this file drops the skip and runs against ${MOCK_BASE_URL}
#
# Other approaches that were considered and rejected as out-of-scope for #122:
#   - Service-DNS mock: deploy mock-upstream.py as a K8s Service. Validator
#     passes (hostname, not an IP literal), but the fixture would need to
#     pivot from "exec a Python process on the runner" to "deploy a pod that
#     shares a state dir with the runner", which breaks the current
#     filesystem-shared mock-state model.
#   - NodePort + node IP: same DNS/fixture problem at a different layer.
#
# The cross-cutting concern (this fixture, the cache-stampede twin, and any
# future test that needs the backend to dial a runner-local upstream) is
# what justifies a single env var on the backend rather than a per-test
# workaround.
#
# Coverage gap mitigation
# -----------------------
# tests/security/test-ssrf-prevention.sh continues to assert the blocklist
# from the other direction, so the security property "backend rejects
# private-CIDR upstreams" stays under test even while this suite is dark.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-poisoning"
begin_test "Cache-poisoning suite skipped pending backend SSRF allowlist"
skip "Blocked on artifact-keeper#1224 (backend AK_SSRF_ALLOW_PRIVATE_CIDRS env var). Tracking: artifact-keeper-test#122."
end_suite
