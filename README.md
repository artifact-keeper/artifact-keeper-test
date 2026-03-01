# artifact-keeper-test

Release gate test infrastructure for [Artifact Keeper](https://github.com/artifact-keeper/artifact-keeper). Every release candidate must pass this full test suite before a version tag is cut.

## How It Works

A release workflow in any Artifact Keeper repo calls into this repository's `release-gate.yml` workflow. That workflow deploys the candidate build into an isolated Kubernetes namespace on the self-hosted rocky cluster, runs the full test suite, collects results, and tears everything down.

```
artifact-keeper release workflow
        │
        ▼
┌─────────────────────────────────────────────┐
│         release-gate.yml (this repo)        │
│                                             │
│  1. Deploy candidate build to test-<run-id> │
│  2. Run test suites                         │
│  3. Collect JUnit XML results               │
│  4. Teardown namespace                      │
│                                             │
│  Pass ──► Release proceeds                  │
│  Fail ──► Release blocked                   │
└─────────────────────────────────────────────┘
```

## Test Pipeline

Tests run in a dependency chain. Earlier suites validate basic functionality before later suites stress the system.

```
deploy-test-env
    │
    ├── format-tests (8 parallel batches, 38 formats)
    ├── security-tests
    └── compatibility-tests
    │
    ▼ (all pass)
stress-tests
    │
    ▼ (passes)
resilience-tests (5 parallel categories)
    │
    ▼ (all pass)
deploy-mesh-env (4 instances) ──► mesh-tests
    │
    ▼ (all pass)
collect-results ──► teardown
```

## Test Suites

### Format Tests (38 scripts)

Each of the 38 package format handlers gets an E2E test that creates a repository, publishes a package using the native protocol, consumes it, and verifies metadata through the REST API.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Format Test Batches                         │
├──────────────────┬──────────────────────────────────────────────────┤
│ Node             │ npm, vscode                                     │
│ Python           │ pypi, conda, huggingface, mlmodel               │
│ JVM              │ maven, sbt                                      │
│ Rust/Go/Swift    │ cargo, go, swift, pub                           │
│ System Packages  │ debian, rpm, alpine, opkg                       │
│ Containers       │ oci, helm, incus                                │
│ Misc Native      │ terraform, composer, hex, rubygems, nuget,      │
│                  │ cocoapods, cran                                  │
│ Generic/Protocol │ generic, gitlfs, protobuf, bazel, conan,        │
│                  │ ansible, p2, jetbrains, vagrant, wasm,           │
│                  │ puppet, chef                                     │
└──────────────────┴──────────────────────────────────────────────────┘
```

### Resilience Tests (18 scripts)

These tests verify that Artifact Keeper handles infrastructure failures gracefully: no data loss, no corruption, clean error messages, and recovery within 30 seconds.

```
resilience/
├── crash/          SIGKILL, OOM kill, graceful shutdown
├── restart/        Rolling restart, pod reschedule, full reboot, DB restart
├── network/        Latency injection, packet loss, upstream timeout,
│                   DNS failure, partition + heal
├── storage/        Disk full, read-only mount, PVC remount
└── data/           Concurrent writes, large artifacts (100MB), corrupt uploads
```

### Stress Tests

- **Concurrent uploads**: 20 parallel uploads, assert 95%+ success rate
- **Throughput**: Sequential upload/download of 10MB files, assert > 1 MB/s

### Security Tests

- **Trivy scan**: Upload an OCI image, verify vulnerability scan results appear
- **Quality gate**: Create a gate with `max_critical_issues: 0`, verify enforcement

### Mesh Tests (5 scripts)

Deployed as 4 separate instances (main + 3 peers), each with its own backend, database, and search engine. Tests validate the mesh replication protocol.

```
┌──────────┐     sync      ┌──────────┐
│   main   │◄────────────►│  peer-1  │
└────┬─────┘               └──────────┘
     │
     │  sync
     │
┌────▼─────┐               ┌──────────┐
│  peer-2  │               │  peer-3  │
└──────────┘               └──────────┘

Tests: peer registration, sync policies, artifact replication,
       retroactive sync, heartbeat signaling
```

## Namespace Lifecycle

Each test run gets a fully isolated Kubernetes namespace. No shared state between runs.

```
create-test-namespace.sh
    │
    ├── kubectl create namespace test-<run-id>
    ├── Create image pull secret (ghcr-creds)
    ├── Apply ResourceQuota (CPU/memory caps)
    ├── helm install with candidate image tags
    └── wait-for-ready.sh (poll /health, 3-min timeout)
    │
    ▼
    ... tests run ...
    │
    ▼
teardown-test-namespace.sh
    │
    ├── Collect pod logs (saved as workflow artifacts)
    ├── helm uninstall
    └── kubectl delete namespace (cascading)
```

Resource limits are configured as GitHub Actions repository variables, not hardcoded:

| Variable | Default | Purpose |
|---|---|---|
| `TEST_MAX_CPU` | 8000m | Total CPU cap across all test namespaces |
| `TEST_MAX_MEMORY` | 16Gi | Total memory cap |
| `TEST_MAX_NAMESPACES` | 2 | Max concurrent test runs |
| `TEST_NAMESPACE_CPU` | 4000m | ResourceQuota CPU per namespace |
| `TEST_NAMESPACE_MEMORY` | 8Gi | ResourceQuota memory per namespace |

## Running Tests Locally

Tests can run against any Artifact Keeper instance. Set these environment variables and run any script directly:

```bash
export BASE_URL="http://localhost:8080"
export ADMIN_USER="admin"
export ADMIN_PASS="admin123"
export RUN_ID="local-$(date +%s)"

# Single format test
bash tests/formats/test-npm.sh

# Full format suite
./scripts/run-suite.sh --suite formats --run-id "$RUN_ID"
```

For resilience and mesh tests, you also need `kubectl` access and the appropriate environment variables (`NAMESPACE`, `MAIN_URL`, `PEER1_URL`, etc.).

## Calling from a Release Workflow

Add this to your release workflow in any Artifact Keeper repo:

```yaml
jobs:
  release-gate:
    uses: artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main
    with:
      backend_tag: ${{ github.ref_name }}
    secrets: inherit
```

The release gate will block the release if any test fails.

## Repository Structure

```
artifact-keeper-test/
├── .github/workflows/
│   ├── release-gate.yml           Unified release coordinator
│   ├── format-tests.yml           Reusable: 38 format E2E tests
│   ├── stress-tests.yml           Reusable: concurrent uploads, throughput
│   ├── resilience-tests.yml       Reusable: crash, restart, network, storage, data
│   └── mesh-tests.yml             Reusable: peer replication suite
├── helm/
│   ├── values-test.yaml           Single-instance test overlay
│   └── values-test-mesh.yaml      Mesh topology overlay (4 instances)
├── tests/
│   ├── lib/
│   │   ├── common.sh              Auth, API helpers, assertions, JUnit output
│   │   └── wait-for-ready.sh      Health endpoint poller
│   ├── formats/                   38 format test scripts
│   ├── security/                  Trivy scan, quality gate enforcement
│   ├── stress/                    Concurrent uploads, throughput
│   ├── resilience/
│   │   ├── crash/                 SIGKILL, OOM, graceful shutdown
│   │   ├── restart/               Rolling, reschedule, reboot, DB restart
│   │   ├── network/               Latency, packet loss, timeout, partition
│   │   ├── storage/               Disk full, read-only, PVC remount
│   │   └── data/                  Concurrent writes, large files, corruption
│   ├── mesh/                      Peer registration, sync, heartbeat
│   └── compatibility/             API version compatibility
├── scripts/
│   ├── create-test-namespace.sh   Namespace + Helm install
│   ├── teardown-test-namespace.sh Log collection + cleanup
│   └── run-suite.sh               Suite orchestrator with timeout
└── docs/plans/                    Design documents
```
