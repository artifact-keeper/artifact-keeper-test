# Tier 1: Foundation Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the CI pipeline, backend health checks, graceful shutdown, metrics middleware, and Helm configuration so that test results can be trusted.

**Architecture:** 11 items across 3 repos (artifact-keeper-test, artifact-keeper, artifact-keeper-iac). CI fixes in the test repo ensure failures are not silently swallowed. Backend code fixes ensure health endpoints report truthfully and the server shuts down cleanly. Helm fixes ensure Kubernetes probes use the correct endpoints.

**Tech Stack:** Rust (Axum, Tonic, SQLx), GitHub Actions YAML, Helm templates, Bash

**Spec:** `docs/superpowers/specs/2026-03-20-release-gate-organization-design.md`

---

## File Structure

### artifact-keeper-test (CI + framework fixes)
- Modify: `.github/workflows/release-gate.yml` (resilience runner, mesh job, collect-results)
- Modify: `tests/lib/common.sh` (status code assertion fix)

### artifact-keeper (backend code fixes)
- Modify: `backend/src/api/handlers/health.rs` (overall status, S3/GCS probe)
- Modify: `backend/src/main.rs` (graceful shutdown for HTTP + gRPC)
- Modify: `backend/src/api/middleware/metrics.rs` (implement metrics middleware)
- Create: `backend/src/api/middleware/metrics_tests.rs` (if tests are co-located) or add to existing test modules

### artifact-keeper-iac (Helm fixes)
- Modify: `charts/artifact-keeper/templates/backend-deployment.yaml` (probes, secrets)
- Modify: `charts/artifact-keeper/values.yaml` (default probe paths)

---

## Tasks

### Task 1: T1-01 - Remove || true from resilience test runner [artifact-keeper-test]

**Files:**
- Modify: `.github/workflows/release-gate.yml`

- [ ] **Step 1: Read the current resilience runner block**

Read `.github/workflows/release-gate.yml` and find the resilience test runner (around lines 575-595). Identify the `bash "$script" || true` pattern.

- [ ] **Step 2: Replace || true with exit code tracking**

Change the resilience test runner from:
```yaml
- name: Run ${{ matrix.category }} resilience tests
  run: |
    mkdir -p "$JUNIT_OUTPUT_DIR"
    FAILED=0
    for script in tests/resilience/${{ matrix.category }}/test-*.sh; do
      [ -f "$script" ] || continue
      echo "=== Running ${script} ==="
      bash "$script" || true
    done
```

To:
```yaml
- name: Run ${{ matrix.category }} resilience tests
  run: |
    mkdir -p "$JUNIT_OUTPUT_DIR"
    FAILED=0
    for script in tests/resilience/${{ matrix.category }}/test-*.sh; do
      [ -f "$script" ] || continue
      echo "=== Running ${script} ==="
      if ! bash "$script"; then
        echo "FAILED: ${script}"
        FAILED=$((FAILED + 1))
      fi
    done
    if [ "$FAILED" -gt 0 ]; then
      echo "::error::${FAILED} resilience test(s) failed in ${{ matrix.category }}"
      exit 1
    fi
```

- [ ] **Step 3: Verify the change by reviewing the diff**

Run: `cd /Users/khan/ak/artifact-keeper-test && git diff .github/workflows/release-gate.yml`

Confirm only the resilience runner block changed and || true is gone.

- [ ] **Step 4: Commit**

```bash
cd /Users/khan/ak/artifact-keeper-test
git add .github/workflows/release-gate.yml
git commit -m "fix(ci): track resilience test failures instead of swallowing with || true"
```

---

### Task 2: T1-09 - Remove continue-on-error from mesh tests [artifact-keeper-test]

**Files:**
- Modify: `.github/workflows/release-gate.yml`

- [ ] **Step 1: Find and remove continue-on-error on mesh-tests job**

Search for `continue-on-error: true` in the mesh-tests job (around line 602). Remove the line entirely.

- [ ] **Step 2: Verify the change**

Run: `cd /Users/khan/ak/artifact-keeper-test && grep -n "continue-on-error" .github/workflows/release-gate.yml`

Expected: No matches (or only matches on jobs that intentionally allow failure like teardown).

- [ ] **Step 3: Commit**

```bash
cd /Users/khan/ak/artifact-keeper-test
git add .github/workflows/release-gate.yml
git commit -m "fix(ci): make mesh test failures block the release gate"
```

---

### Task 3: T1-10 - Add gate-check step to collect-results [artifact-keeper-test]

**Files:**
- Modify: `.github/workflows/release-gate.yml`

- [ ] **Step 1: Read the collect-results job**

Read the collect-results job in release-gate.yml (around lines 686-738). Understand how it aggregates results.

- [ ] **Step 2: Add gate-check step**

After the existing summary steps in the collect-results job, add a new step that checks all required job results:

```yaml
- name: Gate check - fail if any suite failed
  run: |
    echo "Checking all suite results..."
    GATE_FAILED=0

    # Check each required job result via needs context
    for job in format-batch-1 format-batch-2 format-batch-3 format-batch-4 \
               format-batch-5 format-batch-6 format-batch-7 format-batch-8 \
               security-tests compatibility-tests repo-tests promotion-tests \
               rbac-tests lifecycle-tests webhooks-tests search-tests \
               platform-tests auth-tests stress-tests resilience-tests \
               mesh-tests; do
      # Read result from needs context (passed via outputs or checked via if)
      echo "  $job: checking..."
    done

    # The actual mechanism: this step should use needs.<job>.result
    # Since we can't loop over needs in bash, use the if: condition approach
    echo "Gate check complete"
```

Note: The exact implementation depends on how the workflow passes job results. The simplest approach is to add `if: failure()` logic or use the `needs` context. Read the exact job names from the workflow and construct the check.

A more robust approach: add this as the final step in collect-results which already has `needs: [all jobs]`:

```yaml
- name: Gate check
  if: >-
    contains(needs.*.result, 'failure') ||
    contains(needs.*.result, 'cancelled')
  run: |
    echo "::error::Release gate FAILED - one or more test suites did not pass"
    echo "Review the workflow summary above for details"
    exit 1
```

- [ ] **Step 3: Verify the collect-results job has needs dependencies on all test jobs**

Confirm the `needs:` array on collect-results includes all test suite jobs.

- [ ] **Step 4: Commit**

```bash
cd /Users/khan/ak/artifact-keeper-test
git add .github/workflows/release-gate.yml
git commit -m "fix(ci): add gate-check step that fails workflow when any suite fails"
```

---

### Task 4: T1-11 - Fix inconsistent HTTP status code assertions [artifact-keeper-test]

**Files:**
- Modify: `tests/lib/common.sh`

- [ ] **Step 1: Read common.sh assertion functions**

Read `tests/lib/common.sh` and find the `assert_http_status` function. Check if there is any logic that treats 401/403/404 as interchangeable.

- [ ] **Step 2: Audit test scripts for loose status checks**

Search across all test scripts for patterns like:
```bash
grep -rn '"401" || "403"' tests/
grep -rn '"403" || "404"' tests/
grep -rn 'status.*40[134]' tests/
```

- [ ] **Step 3: Add assert_http_exact_status helper if needed**

If `assert_http_status` already checks exact codes, the issue is in the test scripts themselves. Add a comment to common.sh documenting the correct usage:

```bash
# assert_http_status checks for EXACT status code match.
# Use specific codes:
#   401 = Unauthenticated (no valid credentials provided)
#   403 = Forbidden (authenticated but insufficient permissions)
#   404 = Not Found (resource does not exist)
# Do NOT use "401 or 403" checks - pick the correct one for the scenario.
```

- [ ] **Step 4: Fix any test scripts that use loose checks**

For each file found in Step 2, change the loose checks to exact status code assertions. For example, if a test checks "401 or 403" for an unauthenticated request, it should check 401 specifically. If it checks "401 or 403" for a non-admin user, it should check 403 specifically.

- [ ] **Step 5: Commit**

```bash
cd /Users/khan/ak/artifact-keeper-test
git add tests/lib/common.sh tests/
git commit -m "fix(framework): enforce exact HTTP status code assertions, document 401 vs 403 vs 404"
```

---

### Task 5: T1-02 - Health endpoint includes storage and search in overall status [artifact-keeper]

**Files:**
- Modify: `backend/src/api/handlers/health.rs`

- [ ] **Step 1: Read the health_check function**

Read `backend/src/api/handlers/health.rs` around line 177. Find where `overall_status` is determined. Currently it only checks `db_check.status == "healthy"`.

- [ ] **Step 2: Write a unit test for the new behavior**

Find the existing test module in health.rs (or create one). Add a test that verifies overall_status is "unhealthy" when storage is unhealthy:

```rust
#[cfg(test)]
mod tests {
    // Test that overall status reflects storage health
    #[test]
    fn test_overall_status_includes_storage() {
        // When storage is unhealthy, overall should be unhealthy
        // Implementation depends on existing test patterns
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --lib test_overall_status_includes_storage`
Expected: FAIL

- [ ] **Step 4: Modify overall_status logic**

Change the `overall_status` determination (around line 177) to factor in storage and Meilisearch status:

```rust
// Before:
let overall_status = if db_check.status == "healthy" {
    "healthy"
} else {
    "unhealthy"
};

// After:
let overall_status = if db_check.status == "healthy"
    && storage_check.status == "healthy"
    && (meilisearch_check.is_none() || meilisearch_check.as_ref().map_or(true, |m| m.status == "healthy"))
{
    "healthy"
} else {
    "unhealthy"
};
```

Also update the HTTP status code to return 503 when unhealthy:

```rust
let http_status = if overall_status == "healthy" {
    StatusCode::OK
} else {
    StatusCode::SERVICE_UNAVAILABLE
};
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --lib test_overall_status_includes_storage`
Expected: PASS

- [ ] **Step 6: Run all health-related tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --lib health`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/handlers/health.rs
git commit -m "fix(health): include storage and search status in overall health determination"
```

---

### Task 6: T1-05 - S3/GCS health check performs real connectivity probe [artifact-keeper]

**Files:**
- Modify: `backend/src/api/handlers/health.rs`

- [ ] **Step 1: Read check_storage_health function**

Read `backend/src/api/handlers/health.rs` around lines 377-408. The filesystem backend does a real write/read probe. The S3 and GCS backends only check if the bucket name is configured.

- [ ] **Step 2: Add a real probe for S3**

For S3, add a HeadBucket or PutObject/GetObject probe to a test key (e.g., `.health-check`):

```rust
// For S3: attempt a HeadBucket call
StorageBackend::S3 { client, bucket, .. } => {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => StorageHealthCheck {
            status: "healthy".to_string(),
            backend: "s3".to_string(),
            details: Some(format!("bucket: {}", bucket)),
        },
        Err(e) => StorageHealthCheck {
            status: "unhealthy".to_string(),
            backend: "s3".to_string(),
            details: Some(format!("bucket: {}, error: {}", bucket, e)),
        },
    }
}
```

For GCS, apply the same pattern with a bucket metadata check.

- [ ] **Step 3: Run existing tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --lib health`
Expected: All PASS (existing tests should still work since they use filesystem backend)

- [ ] **Step 4: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/handlers/health.rs
git commit -m "fix(health): S3/GCS health checks perform real connectivity probes"
```

---

### Task 7: T1-03 + T1-04 - Implement graceful shutdown for HTTP and gRPC [artifact-keeper]

**Files:**
- Modify: `backend/src/main.rs`

- [ ] **Step 1: Read the server startup code**

Read `backend/src/main.rs` around lines 451-496. Understand how HTTP (Axum) and gRPC (Tonic) servers are started.

- [ ] **Step 2: Add shutdown signal handler**

Create a shared shutdown signal that both servers listen to:

```rust
use tokio::signal;

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("Ctrl+C received, starting graceful shutdown"); },
        _ = terminate => { tracing::info!("SIGTERM received, starting graceful shutdown"); },
    }
}
```

- [ ] **Step 3: Wire shutdown to HTTP server**

Change the Axum server startup from:

```rust
axum::serve(listener, app).await?;
```

To:

```rust
axum::serve(listener, app)
    .with_graceful_shutdown(shutdown_signal())
    .await?;
```

- [ ] **Step 4: Wire shutdown to gRPC server**

Add a `tokio::sync::watch` channel or `CancellationToken` that the gRPC server task also listens to for shutdown. The gRPC server should use Tonic's graceful shutdown:

```rust
let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

// In gRPC task:
let grpc_handle = tokio::spawn(async move {
    tonic::transport::Server::builder()
        // ... services ...
        .serve_with_shutdown(grpc_addr, async move {
            let _ = shutdown_rx.changed().await;
        })
        .await
});
```

- [ ] **Step 5: Run cargo check**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check`
Expected: No errors

- [ ] **Step 6: Run unit tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/main.rs
git commit -m "feat(server): implement graceful shutdown for HTTP and gRPC servers

Wire SIGTERM and Ctrl+C to axum's with_graceful_shutdown and tonic's
serve_with_shutdown. In-flight requests complete before the process exits."
```

---

### Task 8: T1-06 - Implement metrics middleware [artifact-keeper]

**Files:**
- Modify: `backend/src/api/middleware/metrics.rs`

- [ ] **Step 1: Read the current metrics.rs file**

Read `backend/src/api/middleware/metrics.rs`. Confirm it is an empty TODO.

- [ ] **Step 2: Read how metrics_service is initialized**

Search for `metrics` in `backend/src/main.rs` and `backend/src/services/` to understand how the metrics service is set up and what metrics registry is used (likely prometheus crate or metrics crate).

- [ ] **Step 3: Implement the middleware**

Implement an Axum middleware layer that records:
- `http_requests_total` counter (labels: method, path, status)
- `http_request_duration_seconds` histogram (labels: method, path)

Follow existing middleware patterns in the codebase. The implementation will depend on which metrics library is used.

```rust
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;

pub async fn metrics_middleware(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = Instant::now();

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    // Record metrics using the project's metrics approach
    // metrics::counter!("http_requests_total", "method" => method, "status" => status).increment(1);
    // metrics::histogram!("http_request_duration_seconds", "method" => method).record(duration);

    response
}
```

- [ ] **Step 4: Run cargo check**

Run: `cd /Users/khan/ak/artifact-keeper && cargo check`
Expected: No errors

- [ ] **Step 5: Run unit tests**

Run: `cd /Users/khan/ak/artifact-keeper && cargo test --workspace --lib`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
cd /Users/khan/ak/artifact-keeper
git add backend/src/api/middleware/metrics.rs
git commit -m "feat(metrics): implement HTTP request metrics middleware

Records http_requests_total counter and http_request_duration_seconds
histogram with method, path, and status labels."
```

---

### Task 9: T1-07 - Fix Helm probe endpoints [artifact-keeper-iac]

**Files:**
- Modify: `charts/artifact-keeper/templates/backend-deployment.yaml`

- [ ] **Step 1: Read the current probe configuration**

Read `charts/artifact-keeper/templates/backend-deployment.yaml` around lines 198-213. Find the livenessProbe and readinessProbe configuration.

- [ ] **Step 2: Change probe endpoints**

Change:
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: http
readinessProbe:
  httpGet:
    path: /health
    port: http
```

To:
```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: http
readinessProbe:
  httpGet:
    path: /readyz
    port: http
startupProbe:
  httpGet:
    path: /readyz
    port: http
  failureThreshold: 30
  periodSeconds: 5
```

Remove `initialDelaySeconds` from readiness and liveness probes since the startup probe gates them.

- [ ] **Step 3: Run helm lint**

Run: `cd /Users/khan/ak/artifact-keeper-iac && helm lint charts/artifact-keeper/`
Expected: No errors

- [ ] **Step 4: Run helm template to verify**

Run: `cd /Users/khan/ak/artifact-keeper-iac && helm template test charts/artifact-keeper/ -f charts/artifact-keeper/values.yaml | grep -A5 "Probe"`
Expected: Shows /readyz for readiness, /livez for liveness, /readyz for startup

- [ ] **Step 5: Commit**

```bash
cd /Users/khan/ak/artifact-keeper-iac
git add charts/artifact-keeper/templates/backend-deployment.yaml
git commit -m "fix(helm): use /readyz for readiness, /livez for liveness, add startup probe

Readiness probe now only checks critical deps (DB, migrations) via /readyz.
Liveness probe uses /livez for basic alive check.
Startup probe gates readiness/liveness with 150s max startup time."
```

---

### Task 10: T1-08 - Use secretKeyRef for Meilisearch API key [artifact-keeper-iac]

**Files:**
- Modify: `charts/artifact-keeper/templates/backend-deployment.yaml`

- [ ] **Step 1: Read the current Meilisearch env var configuration**

Read `charts/artifact-keeper/templates/backend-deployment.yaml` around lines 178-182. Find the Meilisearch API key env var.

- [ ] **Step 2: Change from value to secretKeyRef**

Change:
```yaml
- name: MEILISEARCH_API_KEY
  value: {{ .Values.meilisearch.apiKey }}
```

To:
```yaml
- name: MEILISEARCH_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "artifact-keeper.fullname" . }}-meilisearch
      key: api-key
```

Also add a Secret template or update the existing secrets template to include the Meilisearch API key.

- [ ] **Step 3: Run helm lint and template**

Run: `cd /Users/khan/ak/artifact-keeper-iac && helm lint charts/artifact-keeper/ && helm template test charts/artifact-keeper/ | grep -B2 -A5 MEILISEARCH`
Expected: Shows secretKeyRef instead of direct value

- [ ] **Step 4: Update test values overlay**

Update `artifact-keeper-test/helm/values-test.yaml` if it references the Meilisearch API key to match the new secret-based approach.

- [ ] **Step 5: Commit**

```bash
cd /Users/khan/ak/artifact-keeper-iac
git add charts/artifact-keeper/
git commit -m "fix(helm): use secretKeyRef for Meilisearch API key instead of plaintext env var"
```

---

### Task 11: Verification - Run the full test suite locally

- [ ] **Step 1: Verify CI fixes**

```bash
cd /Users/khan/ak/artifact-keeper-test
grep -n '|| true' .github/workflows/release-gate.yml
grep -n 'continue-on-error' .github/workflows/release-gate.yml
```

Expected: No `|| true` in resilience runner. No `continue-on-error` on mesh-tests. Only acceptable `|| true` should be in teardown jobs.

- [ ] **Step 2: Verify backend compiles**

```bash
cd /Users/khan/ak/artifact-keeper
cargo check
cargo test --workspace --lib
```

Expected: All compile, all tests pass.

- [ ] **Step 3: Verify Helm chart**

```bash
cd /Users/khan/ak/artifact-keeper-iac
helm lint charts/artifact-keeper/
```

Expected: No errors.

- [ ] **Step 4: Create tracking issues for each PR**

Use `gh` CLI to create PRs in each repo for the Tier 1 changes:
- artifact-keeper-test: CI fixes + framework fix
- artifact-keeper: health endpoint + graceful shutdown + metrics
- artifact-keeper-iac: Helm probe + secret fixes
