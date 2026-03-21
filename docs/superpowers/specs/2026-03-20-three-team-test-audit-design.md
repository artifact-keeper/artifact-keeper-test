# Three-Team Test Audit Design

**Date:** 2026-03-20
**Status:** Approved
**Scope:** Full system audit of artifact-keeper-test coverage

## Goal

Three specialized agent teams (Test, Security, DevOps) perform a full audit of the Artifact Keeper test suite. Each team analyzes the entire system from their unique lens, identifies coverage gaps, and produces prioritized recommendations. A coordination agent merges findings into a unified report.

## Architecture

```
Coordination Agent (orchestrator)
  |
  +-- Test Team Agent      -> correctness, edge cases, error paths
  |
  +-- Security Team Agent  -> attack vectors, vulnerability probing
  |
  +-- DevOps Team Agent    -> infra failures, CI gaps, deployment issues
  |
  +-- Coordinator merges results
      -> deduplicates overlapping findings
      -> prioritizes by severity/impact
      -> produces unified audit report
```

All three teams run in parallel. The coordinator waits for all three to complete before merging.

## Current State

The `artifact-keeper-test` repo contains 107 test scripts across 14 suites:

- **Formats** (38 scripts) - 8 parallel batches covering 45+ package formats
- **Resilience** (23 scripts) - crash, restart, network, storage, data failure scenarios
- **Repositories** (9 scripts) - virtual, remote, proxy, CRUD operations
- **Platform** (9 scripts) - signing, SBOM, curation, labels, audit, backup, analytics
- **RBAC** (6 scripts) - users, groups, permissions, service accounts, tokens
- **Promotion** (4 scripts) - staging to release, rules, approvals, bulk
- **Stress** (5 scripts) - concurrent uploads, throughput, auth saturation, sustained load
- **Auth** (4 scripts) - token lifecycle, TOTP 2FA, SSO breakglass, rate limiting
- **Mesh** (5 scripts) - peer registration, sync, policies, retroactive sync, heartbeat
- **Search** (2 scripts) - full-text search, checksum lookup
- **Webhooks** (2 scripts) - CRUD, delivery
- **Lifecycle** (2 scripts) - policies, garbage collection
- **Security** (2 scripts) - Trivy scan, quality gates
- **Compatibility** (1 script) - API version compatibility

The backend repo (`artifact-keeper/`) has additional test infrastructure not yet migrated:
- 15 red team security scripts
- 3 failure injection tests (crash, DB disconnect, storage failure)
- 5 SSO E2E tests
- 5 mesh E2E tests

## Team Mandates

### Test Team - Correctness Lens

**Focus areas:**
1. Gap analysis across all 14 suites: which endpoints/features have no tests?
2. Edge cases in existing tests: boundary values, empty inputs, large payloads, unicode, special characters
3. Error path coverage: what happens when operations fail gracefully? Are error responses validated?
4. Missing assertions: tests that check "it didn't crash" but not "it returned the right data"
5. Migration candidates from `artifact-keeper/scripts/` not yet in `artifact-keeper-test/`
6. Cross-format consistency: do all format tests follow the same depth of verification?
7. Negative testing: operations that should fail (invalid packages, wrong permissions, bad checksums)

**Inputs to analyze:**
- All 107 test scripts in `artifact-keeper-test/tests/`
- Test framework library (`tests/lib/common.sh`)
- Backend API handlers (`artifact-keeper/backend/src/api/handlers/`)
- Backend services (`artifact-keeper/backend/src/services/`)
- Backend format handlers (`artifact-keeper/backend/src/formats/`)
- Existing backend test scripts (`artifact-keeper/scripts/native-tests/`)

### Security Team - Attack Surface Lens

**Focus areas:**
1. OWASP Top 10 coverage gap analysis against existing security + red team tests
2. Auth/authz gaps: token handling, permission escalation, session fixation, JWT manipulation
3. Input validation across all 45+ format handlers: path traversal, injection, oversized uploads
4. API security: rate limiting effectiveness, CORS, SSRF, header injection
5. Secrets/credential exposure in test infrastructure
6. Dependency chain attacks: what if a proxied upstream serves malicious content?
7. gRPC security: unauthenticated access, message size limits, reflection
8. WASM plugin sandbox escapes

**Inputs to analyze:**
- Existing security tests in `artifact-keeper-test/tests/security/`
- Backend red team scripts (`artifact-keeper/scripts/redteam/`)
- Backend auth middleware (`artifact-keeper/backend/src/middleware/`)
- Backend auth handlers and services
- API handler input validation patterns
- Helm chart security configuration

### DevOps Team - Infrastructure Lens

**Focus areas:**
1. Resilience test gaps: which failure modes are not covered? (e.g., certificate expiry, config hot-reload, log rotation under pressure)
2. CI pipeline robustness: flaky test detection, timeout coverage, resource limit accuracy
3. Deployment edge cases: rolling updates mid-upload, config changes during traffic, certificate rotation
4. Health probe accuracy: do health endpoints actually test critical paths or just return 200?
5. Resource exhaustion: what happens when disk fills, connections exhaust, memory pressure hits?
6. Mesh replication under adverse conditions: network partitions, clock skew, split-brain
7. Backup/restore verification: do restore tests actually verify data integrity?
8. Monitoring gaps: are the right metrics exposed? Would failures actually trigger alerts?

**Inputs to analyze:**
- Resilience tests in `artifact-keeper-test/tests/resilience/`
- Stress tests in `artifact-keeper-test/tests/stress/`
- CI workflows (`.github/workflows/`)
- Helm chart and test value overlays (`helm/`)
- Backend failure injection scripts (`artifact-keeper/scripts/failure/`)
- Backend health check implementation
- Docker compose test infrastructure

## Output Format

Each team produces findings in this structure:

```
### [CATEGORY] Finding Title

**Severity:** critical | high | medium | low
**Suite:** which test suite this belongs in
**Gap type:** missing test | weak assertion | untested error path | missing edge case | migration candidate
**Description:** What is missing and why it matters
**Recommendation:** What test to write, including endpoint/scenario details
**References:** Which existing files/code informed this finding
```

## Coordination Agent Responsibilities

1. Dispatch all three teams in parallel with full context
2. Wait for all teams to complete
3. Merge findings, removing duplicates (same gap found by multiple teams)
4. When teams disagree on severity, use the higher rating
5. Group findings by suite (where the test would live)
6. Produce final report sorted by severity within each suite group
7. Save unified report to `artifact-keeper-test/docs/audit/2026-03-20-full-system-audit.md`

## Deliverable

Analysis-only report with prioritized findings and recommendations. No test scripts written in this phase. The report serves as the backlog for future implementation work.
