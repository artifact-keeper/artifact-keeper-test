# CLAUDE.md

## Project Overview

This is the release-gate test infrastructure for Artifact Keeper. It contains E2E test scripts, Helm value overlays, and GitHub Actions workflows that validate releases before tagging.

## Repository Structure

- `tests/` - Test scripts organized by suite (formats, stress, resilience, mesh, security, compatibility)
- `tests/lib/` - Shared shell helpers (auth, assertions, JUnit output)
- `helm/` - Thin Helm value overlays referencing the chart in artifact-keeper-iac
- `scripts/` - Namespace lifecycle (create, teardown, run-suite orchestrator)
- `.github/workflows/` - Release coordinator and reusable test workflows

## Running Tests Locally

Tests require a running Artifact Keeper instance. Set these env vars:

```bash
export BASE_URL="http://localhost:8080"
export ADMIN_USER="admin"
export ADMIN_PASS="admin123"
export RUN_ID="local-$(date +%s)"
```

Then run any test directly:

```bash
source tests/lib/common.sh
bash tests/formats/test-npm.sh
```

## Test Script Contract

Every script in `tests/` must:
1. Source `tests/lib/common.sh`
2. Use `RUN_ID` in all resource names to avoid collisions
3. Print PASS/FAIL per test section
4. Produce JUnit XML output to `$JUNIT_OUTPUT_DIR/`
5. Exit 0 on all-pass, non-zero on any failure

## Key Commands

```bash
# Deploy a test namespace (requires kubectl access)
./scripts/create-test-namespace.sh --run-id test-123 --backend-tag dev --web-tag dev

# Run a single format test
bash tests/formats/test-npm.sh

# Run a full suite
./scripts/run-suite.sh --suite formats --run-id test-123

# Tear down
./scripts/teardown-test-namespace.sh --run-id test-123
```

## Helm Chart Reference

Tests deploy using the Helm chart from `artifact-keeper-iac` (git source, not a registry). The chart is cloned at deploy time and overlaid with `helm/values-test.yaml`.

## Writing Style

Follow the same conventions as the main artifact-keeper repos: no em-dashes, no emoji in docs, no ChatGPT-isms. Be direct and technical.
