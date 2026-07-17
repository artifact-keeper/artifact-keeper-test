#!/usr/bin/env bash
# test-storage-backend-azure.sh - Azure Blob backend E2E (Azurite emulator)
#
# Runs the shared storage-backend round-trip contract against the "azure"
# backend registered from AZURE_STORAGE_* env vars. In the full-stack test
# deploy the backend points at the in-namespace Azurite (well-known
# devstoreaccount1 account) from helm/storage-emulators.yaml. Skips cleanly
# when no azure backend is registered.
#
# Currently skipping in the gate: Shared Key signing is wrong for path-style
# (Azurite) endpoints (artifact-keeper#2649), so the AZURE_* env in
# values-test-full.yaml stays commented out until that fix ships. Verified
# locally: with the env set, registration succeeds and uploads 403.
#
# Real-cloud auth (RBAC, SAS signatures) stays covered by the
# credential-gated live tests in the main repo (azure_*_live_test.rs).
#
# Requires: curl, jq, shasum (or sha256sum)
source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/storage-backend-suite.sh"

run_storage_backend_suite "azure"
