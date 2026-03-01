# artifact-keeper-test: Release Gate Test Infrastructure

**Date:** 2026-02-28
**Status:** Approved

## Purpose

A dedicated test repository that gates releases for Artifact Keeper. Before any release tag is cut (backend, web, mobile), the full test suite must pass against the candidate build deployed to an isolated Kubernetes environment on the self-hosted rocky cluster.

## Repository

- **Name:** `artifact-keeper/artifact-keeper-test`
- **Visibility:** Public
- **Language:** Shell scripts (tests), YAML (workflows, Helm values)

## Architecture Decisions

- **Monolithic test repo:** All test scripts, workflows, and Helm overlays live in one place. Tests are purpose-built for this repo rather than scattered across backend/web repos.
- **Dynamic namespaces:** Each test run gets isolated Kubernetes namespaces (`test-<run-id>`). No shared state between runs. Concurrent runs are supported up to a configurable limit.
- **GitHub Actions on ARC runners:** The existing self-hosted ARC runner scale set on rocky provides in-cluster access. No external CI compute needed.
- **Unified release coordinator:** A single workflow accepts version inputs for all components and runs the appropriate test tier. Backend is the primary gate (full suite); web/mobile are lighter gates (compatibility + UI E2E).

## Repository Structure

```
artifact-keeper-test/
├── .github/
│   └── workflows/
│       ├── release-gate.yml          # Unified release coordinator
│       ├── format-tests.yml          # Reusable: all 38 format E2E tests
│       ├── stress-tests.yml          # Reusable: concurrent uploads, throughput
│       ├── resilience-tests.yml      # Reusable: crash, restart, network, storage, data
│       ├── mesh-tests.yml            # Reusable: peer replication suite
│       └── web-e2e-tests.yml         # Reusable: Playwright UI tests
│
├── helm/
│   ├── values-test.yaml              # Base test environment values
│   └── values-test-mesh.yaml         # Mesh topology test values (4 instances)
│
├── tests/
│   ├── lib/
│   │   ├── common.sh                 # Auth, API helpers, assertions, JUnit output
│   │   ├── format-helpers.sh         # Repo creation, package upload/download helpers
│   │   └── wait-for-ready.sh         # Poll health endpoints until stack is up
│   │
│   ├── formats/                      # One script per format handler (38 total)
│   │   ├── test-alpine.sh
│   │   ├── test-ansible.sh
│   │   ├── ... (one per handler)
│   │   └── test-wasm.sh
│   │
│   ├── security/
│   │   ├── test-trivy-scan.sh
│   │   ├── test-dependency-track.sh
│   │   └── test-quality-gate-enforcement.sh
│   │
│   ├── compatibility/
│   │   └── test-api-version-compat.sh
│   │
│   ├── stress/
│   │   ├── test-concurrent-uploads.sh
│   │   └── test-throughput.sh
│   │
│   ├── resilience/
│   │   ├── crash/
│   │   │   ├── test-backend-kill.sh       # SIGKILL mid-upload
│   │   │   ├── test-backend-oom.sh        # OOM kill recovery
│   │   │   └── test-graceful-shutdown.sh  # SIGTERM drain behavior
│   │   ├── restart/
│   │   │   ├── test-rolling-restart.sh    # Rollout restart during active uploads
│   │   │   ├── test-pod-reschedule.sh     # Pod delete + reschedule, data intact
│   │   │   ├── test-full-reboot.sh        # Scale to 0, scale back, verify state
│   │   │   └── test-postgres-restart.sh   # DB kill + reconnect + flush
│   │   ├── network/
│   │   │   ├── test-latency-injection.sh  # 500ms latency via tc netem
│   │   │   ├── test-packet-loss.sh        # 10% packet loss backend<->postgres
│   │   │   ├── test-upstream-timeout.sh   # Proxy repo with slow/dead upstream
│   │   │   ├── test-dns-failure.sh        # Brief CoreDNS outage
│   │   │   └── test-partition-heal.sh     # Network partition + restore
│   │   ├── storage/
│   │   │   ├── test-disk-full.sh          # PVC quota hit, clean error
│   │   │   ├── test-storage-readonly.sh   # Read-only mount, writes fail gracefully
│   │   │   └── test-pvc-remount.sh        # PVC detach/reattach
│   │   └── data/
│   │       ├── test-concurrent-writes.sh  # Same version from 2 clients
│   │       ├── test-large-artifact.sh     # 2GB+ streaming upload
│   │       └── test-corrupt-upload.sh     # Malformed package rejection
│   │
│   └── mesh/
│       ├── test-peer-registration.sh
│       ├── test-sync-policy.sh
│       ├── test-artifact-sync.sh
│       ├── test-retroactive-sync.sh
│       └── test-heartbeat.sh
│
├── scripts/
│   ├── create-test-namespace.sh      # Create ns, RBAC, ResourceQuota, Helm install
│   ├── teardown-test-namespace.sh    # Collect logs, Helm uninstall, delete ns
│   └── run-suite.sh                  # Orchestrator: run suite with retries + JUnit
│
├── docs/
│   └── plans/
├── CLAUDE.md
└── README.md
```

## Namespace Lifecycle

### Creation (`scripts/create-test-namespace.sh`)

1. Create namespace `test-<run-id>`
2. Create `ghcr-creds` image pull secret (from GitHub Actions secret)
3. Apply ResourceQuota (CPU/memory limits from GitHub Actions variables)
4. `helm install` using the IAC chart with `values-test.yaml` overlay, passing candidate image tags via `--set`
5. Run `wait-for-ready.sh`: poll `/health` on backend and web (2-min timeout, 5s interval)
6. For mesh tests: repeat for 4 namespaces using `values-test-mesh.yaml`

### Teardown (`scripts/teardown-test-namespace.sh`)

1. Collect logs from all pods, save as workflow artifacts
2. `helm uninstall` the release
3. `kubectl delete namespace test-<run-id>` (cascading delete)
4. Always runs, even on test failure (`if: always()`)
5. Skippable via `skip_teardown: true` for debugging

### Resource Limits

Configured as GitHub Actions repository variables (not in code):

| Variable | Default | Purpose |
|---|---|---|
| `TEST_MAX_CPU` | `8000m` | Total CPU request cap across all test namespaces |
| `TEST_MAX_MEMORY` | `16Gi` | Total memory request cap across all test namespaces |
| `TEST_MAX_NAMESPACES` | `2` | Max concurrent test runs |
| `TEST_NAMESPACE_CPU` | `4000m` | ResourceQuota CPU per namespace |
| `TEST_NAMESPACE_MEMORY` | `8Gi` | ResourceQuota memory per namespace |

Rocky cluster specs (as of 2026-02-28): 56 vCPU, 156Gi RAM. Existing workloads use ~10 CPU requests and ~22Gi memory requests, leaving ample headroom.

## Release Coordinator Workflow

### Inputs

```yaml
inputs:
  backend_tag:    # Required. Image tag to test
  web_tag:        # Optional. Defaults to "latest"
  test_suite:     # all | formats | stress | resilience | mesh | security | compatibility
  skip_teardown:  # Default: false
```

### Job Graph

```
deploy-test-env
    ├── format-tests (matrix: 8 parallel batches by client tooling)
    ├── security-tests
    └── compatibility-tests
    │
    ▼ (all pass)
stress-tests
    │
    ▼ (passes)
resilience-tests (matrix: [crash, restart, network, storage, data])
    │
    ▼ (all pass)
deploy-mesh-env ──► mesh-tests
    │
    ▼ (all pass)
collect-results ──► teardown
```

### Calling from a Backend Release

```yaml
# In artifact-keeper/.github/workflows/release.yml
jobs:
  release-gate:
    uses: artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main
    with:
      backend_tag: ${{ github.ref_name }}
    secrets: inherit
```

## Format Test Conventions

### Script Contract

Every script in `tests/formats/` follows the same pattern:

1. Source `tests/lib/common.sh`
2. Create a local repo with key `test-<format>-<RUN_ID>`
3. Publish a package using the native client
4. Consume/install the package using the native client
5. Verify metadata via the REST API
6. If the format supports proxying: create a remote repo, fetch from upstream, verify cache
7. Cleanup handled by namespace teardown

### Environment Variables (provided by orchestrator)

| Variable | Purpose |
|---|---|
| `BASE_URL` | In-cluster backend URL |
| `RUN_ID` | Unique per run, used in repo keys to avoid collisions |
| `ADMIN_TOKEN` | Pre-authenticated admin JWT |
| `TEST_TIMEOUT` | Per-test timeout in seconds |

### Parallel Batches

| Batch | Formats | Tooling |
|---|---|---|
| 1 - Node | npm, vscode_extensions | node, npm |
| 2 - Python | pypi, conda, huggingface, mlmodel | pip, conda |
| 3 - JVM | maven, sbt | mvn, sbt |
| 4 - Rust/Go/Swift | cargo, go, swift, pub | cargo, go, swift |
| 5 - System packages | debian, rpm, alpine, opkg | dpkg, rpm, apk |
| 6 - Containers/OCI | oci, helm, incus | docker, helm |
| 7 - Misc native | terraform, vagrant, composer, hex, rubygems, nuget, cocoapods, puppet, chef, cran | Mixed CLI tools |
| 8 - Generic/protocol | generic, gitlfs, protobuf, bazel, conan, ansible, p2, jetbrains_plugins, wasm | curl-based |

### Output

Each script produces JUnit XML via the shared library. The orchestrator aggregates all XML and publishes as a GitHub Actions test summary.

## Resilience Testing

### Network Tests

Use `tc netem` from a sidecar/init container with `NET_ADMIN` capability scoped to the test namespace. For upstream timeout tests, deploy a tiny nginx acting as a broken upstream registry.

### Restart Tests

Use `kubectl` from the ARC runner pod. Scale deployments, delete pods, watch recovery. Key assertions:
- No data loss (artifact count before == after)
- No corruption (checksums match)
- Clients get retryable errors, not garbage
- Recovery within SLA (30 seconds default)

### Storage Tests

Use ResourceQuota limits and `kubectl exec` to manipulate mount permissions within test pods.

## Mesh Test Topology

Deployed as 4 namespaces: `test-<run-id>-mesh-main`, `test-<run-id>-mesh-peer{1,2,3}`. Each gets a full backend + postgres + meilisearch stack. Tests validate peer registration, sync policies, artifact replication, retroactive sync, and heartbeat signaling.
