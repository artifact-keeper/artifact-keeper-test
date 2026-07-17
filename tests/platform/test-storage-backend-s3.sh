#!/usr/bin/env bash
# test-storage-backend-s3.sh - S3 object-storage backend E2E (MinIO emulator)
#
# Runs the shared storage-backend round-trip contract against the "s3"
# backend registered from S3_* env vars. In the full-stack test deploy the
# backend points at the in-namespace MinIO from helm/storage-emulators.yaml.
# Skips cleanly when no s3 backend is registered.
#
# Requires: curl, jq, shasum (or sha256sum)
source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/storage-backend-suite.sh"

run_storage_backend_suite "s3"
