#!/usr/bin/env bash
# test-storage-backend-gcs.sh - GCS backend E2E (fake-gcs-server emulator)
#
# Runs the shared storage-backend round-trip contract against the "gcs"
# backend. Currently the backend cannot register a gcs backend against an
# emulator (no endpoint override; artifact-keeper#2646), so this suite
# reports every section as skipped. Once #2646 ships and
# helm/storage-emulators.yaml grows a fake-gcs-server deployment plus GCS_*
# env in values-test-full.yaml, this suite starts running with no further
# changes here.
#
# Requires: curl, jq, shasum (or sha256sum)
source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/storage-backend-suite.sh"

run_storage_backend_suite "gcs"
