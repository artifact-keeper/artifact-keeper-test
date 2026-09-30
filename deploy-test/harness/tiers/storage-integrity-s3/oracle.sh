#!/usr/bin/env bash
# =============================================================================
# tiers/storage-integrity-s3/oracle.sh: S3 (MinIO) run of the storage-integrity
# oracle (#3919, #3910, #1570). All assertions live in
# tiers/storage-integrity/oracle.sh; SI_STORAGE=s3 switches its tamper helpers
# from the filesystem volume to the `ak-artifacts` bucket.
# =============================================================================
set -uo pipefail
export SI_STORAGE=s3
exec bash "$(dirname "${BASH_SOURCE[0]}")/../storage-integrity/oracle.sh"
