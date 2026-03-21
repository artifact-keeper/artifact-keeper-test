# Artifact Keeper Test Suite: Full System Audit

**Date:** 2026-03-20
**Teams:** Test Team (3 analysts), Security Team (3 analysts), DevOps Team (3 analysts)
**Scope:** Full audit of all 14 test suites against backend API surface, security posture, and infrastructure resilience
**Method:** 12 agents across 3 teams analyzed code in `artifact-keeper-test/` and `artifact-keeper/` repos

## Executive Summary

Three specialized teams audited the entire Artifact Keeper test suite. After deduplication across 6 report sources (261 raw findings), this document presents **142 unique findings** organized by priority and category.

**API endpoint coverage is approximately 31%** (~103 of 329+ endpoints tested). The largest gaps are in backup/restore, security scanning, migration, plugin management, and RBAC endpoints.

**Critical systemic issues:**
1. The 15 red team security scripts run outside the release-gate pipeline, meaning security regressions do not block releases
2. The `/health` endpoint ignores storage and search failures, so Kubernetes marks broken nodes as healthy
3. Resilience test failures are silently swallowed in CI (`|| true`)
4. Backup/restore tests do not verify data integrity after restore
5. No decompression bomb protection across 6+ format handlers
6. Graceful shutdown is not implemented in the HTTP or gRPC servers

---

## Findings by Priority

### P0: Critical (13 findings)

These represent the highest-risk gaps, either direct security vulnerabilities or systemic test infrastructure failures that undermine all other testing.

#### C-01: Red team security suite not in release gate
**Source:** Test Team, Security Team (both)
**Suite:** security
**Description:** 15 red team scripts (auth bypass, path traversal, SQL injection, SSRF, CORS, default credentials, gRPC unauth, info disclosure, metrics auth) exist in `artifact-keeper/scripts/redteam/` but none are in the release-gate pipeline. A security regression introduced in any release would not be caught.
**Recommendation:** Migrate all 15 scripts to `artifact-keeper-test/tests/security/redteam/` and add to release-gate.yml.

#### C-02: Health endpoint ignores storage and search failures
**Source:** DevOps Team (both)
**Suite:** resilience
**Description:** `health_check` in health.rs determines `overall_status` based solely on DB status. If storage is down or Meilisearch is unreachable, `/health` still returns 200. Kubernetes probes mark the node ready, and it receives traffic that fails with 500 errors.
**Recommendation:** Test that `/health` returns 503 when storage is read-only or Meilisearch is down. Fix backend to include storage+search in overall status.

#### C-03: CI resilience tests silently swallowed
**Source:** DevOps Team (both)
**Suite:** CI
**Description:** In release-gate.yml, resilience test scripts run with `|| true`, meaning individual failures never fail the CI job. The release gate passes regardless of resilience test outcomes.
**Recommendation:** Remove `|| true` from resilience script invocations. Use the same failure-tracking pattern as format tests.

#### C-04: Backup/restore test does not verify data integrity
**Source:** DevOps Team (both)
**Suite:** platform
**Description:** test-backup-restore.sh only tests backup creation and listing. It never creates test data, performs a restore, or verifies data survived the cycle. A corrupted backup would pass.
**Recommendation:** Rewrite to: upload artifacts with known checksums, create backup, delete data, restore, verify all data intact.

#### C-05: SSO authentication tests completely missing
**Source:** Test Team (both)
**Suite:** auth
**Description:** Backend has OIDC, LDAP, and SAML integration with 20+ SSO admin endpoints. The SSO E2E suite (Keycloak, OpenLDAP) exists in the backend repo but is not migrated. Zero SSO tests in the release gate.
**Recommendation:** Migrate `artifact-keeper/scripts/sso-e2e/` and add SSO admin CRUD tests.

#### C-06: Dependency confusion via virtual repository shadowing
**Source:** Security Team (both)
**Suite:** security
**Description:** Virtual repos iterate members by priority with no conflict detection. An attacker controlling a lower-priority upstream can inject a malicious package that shadows a legitimate internal one. This is the primary supply chain attack vector for a package registry.
**Recommendation:** Test: create local package v1.0, upstream has same name v2.0, virtual repo should serve local v1.0. Test for npm, PyPI, Maven.

#### C-07: Artifact integrity/checksum enforcement untested
**Source:** Security solo agent
**Suite:** security
**Description:** No test verifies the backend enforces checksum validation on uploads. For formats with checksums (Maven SHA-1, npm integrity, PyPI digests), no test uploads an artifact with a mismatched checksum to verify rejection.
**Recommendation:** Upload Maven JAR with incorrect SHA-1, npm package with tampered integrity field. Assert rejection.

#### C-08: IDOR - cross-user resource access untested
**Source:** Security solo agent, Security Team
**Suite:** rbac
**Description:** No test verifies User A cannot access User B's tokens, profile, or settings by manipulating IDs in API paths. The most basic access control check is missing.
**Recommendation:** Login as User A, attempt GET/DELETE on `/api/v1/users/{UserB_ID}/tokens`. Assert 403.

#### C-09: Privilege escalation - non-admin to admin untested
**Source:** Security solo agent, Test Team, Security Team
**Suite:** rbac
**Description:** No test verifies a non-admin cannot elevate privileges by sending `{"is_admin": true}` in a PATCH, crafting a JWT with is_admin=true, or creating admin users. Tests only check positive cases.
**Recommendation:** Non-admin PATCH self with is_admin=true (assert 403 or ignored). Non-admin hits all `/api/v1/admin/*` endpoints (assert 403).

#### C-10: SSRF tests not in release gate
**Source:** Security solo agent
**Suite:** security
**Description:** Red team script 13 (SSRF prevention) thoroughly tests webhook URLs with private IPs, AWS metadata, Docker names. Not in the release gate. A regression in URL validation is undetectable.
**Recommendation:** Migrate SSRF tests. Also add tests for remote repo upstream URLs and plugin Git install URLs.

#### C-11: Connection pool exhaustion under load untested
**Source:** DevOps Team (both)
**Suite:** stress
**Description:** DB pool has max_connections=20, acquire_timeout=30s. No test stresses these limits. Under concurrent load, pool starvation would cause requests to hang for 30s before timing out. No test validates the backend returns clean 503 errors.
**Recommendation:** Launch 50+ concurrent large uploads, monitor pool stats, assert timely error responses.

#### C-12: Helm upgrade under active traffic untested
**Source:** DevOps Team
**Suite:** resilience/deployment
**Description:** No test performs a Helm chart upgrade while the system serves requests. Schema migrations, config propagation, and pod replacement during traffic are all untested. Every production upgrade is flying blind.
**Recommendation:** Start sustained background reads/writes, trigger helm upgrade, monitor for errors, verify data integrity after rollout.

#### C-13: Schema migration during running traffic untested
**Source:** DevOps Team (both)
**Suite:** resilience
**Description:** No test verifies DB migrations work while the system handles active traffic. Concurrent queries against partially-migrated tables can deadlock or corrupt data.
**Recommendation:** Start background reads/writes, trigger migration, verify no deadlocks, check for errors.

---

### P1: High (45 findings)

#### Security - Authentication & Authorization

| ID | Finding | Suite |
|----|---------|-------|
| H-01 | JWT algorithm confusion (alg=none) untested | auth |
| H-02 | API key scope enforcement untested (read-only token can write) | rbac |
| H-03 | Repository-scoped token cross-repo access untested | rbac |
| H-04 | Admin endpoint protection not systematically tested | rbac |
| H-05 | Token revocation has 5-min cache window, test skips assertion | auth |
| H-06 | Expired token rejection has no integration test | auth |
| H-07 | Refresh token reuse not tested (single-use enforcement) | auth |
| H-08 | TOTP 2FA only tests setup, never enable/verify/bypass | auth |
| H-09 | OIDC state parameter (CSRF) validation untested | auth |
| H-10 | SAML signature validation untested | auth |
| H-11 | Default credentials test not in release gate | security |
| H-12 | Rogue mesh peer registration untested | security |

#### Security - Input Validation & Injection

| ID | Finding | Suite |
|----|---------|-------|
| H-13 | Decompression bomb protection missing across 6+ format handlers | security |
| H-14 | SQL injection tests not in release gate | security |
| H-15 | Path traversal tests not in release gate | security |
| H-16 | Cache poisoning via proxy (no checksum verification) | security |
| H-17 | Unsigned artifact acceptance (no enforcement) | security |
| H-18 | gRPC reflection enabled unconditionally (unauthenticated) | security |
| H-19 | WASM sandbox memory/CPU limits untested | security |
| H-20 | Malicious upstream content through proxy repos untested | security |
| H-21 | WASM plugin filesystem escape untested | security |
| H-22 | Mesh peer data integrity (tampered artifact sync) untested | security |
| H-23 | Zip bomb / decompression bomb for format handlers | security |
| H-24 | Audit log completeness untested (30+ action types) | security |

#### Test Quality

| ID | Finding | Suite |
|----|---------|-------|
| H-25 | 11 format tests are shallow (no download, delete, or versioning) | formats |
| H-26 | No format tests verify duplicate upload behavior (409 conflict) | formats |
| H-27 | No format tests upload empty/malformed/truncated packages | formats |
| H-28 | Lifecycle policies created+previewed but never executed | lifecycle |
| H-29 | Signing keys created but never used to sign artifacts | platform |
| H-30 | Curation rules created but enforcement never tested | platform |
| H-31 | Webhook delivery skips instead of fails on zero deliveries | webhooks |
| H-32 | Analytics test has 1 test, no assertions, covers 1 of 7 endpoints | platform |
| H-33 | Upstream proxy failure handling untested (timeout, 404, wrong creds) | repos |

#### Missing API Coverage

| ID | Finding | Suite |
|----|---------|-------|
| H-34 | Builds API completely untested (6 endpoints) | platform |
| H-35 | Packages API completely untested (3 endpoints) | platform |
| H-36 | WASM plugin API untested (14 endpoints) + 4 backend scripts not migrated | platform |
| H-37 | Security scanning advanced features (15 endpoints) untested | security |
| H-38 | Quality gate evaluation/health dashboard (10 endpoints) untested | platform |
| H-39 | User roles/password management untested | rbac |
| H-40 | Group management untested (5 endpoints) | rbac |
| H-41 | Permission CRUD untested (5 endpoints) | rbac |
| H-42 | Dependency-Track integration untested (7 endpoints) | platform |

#### Infrastructure & Resilience

| ID | Finding | Suite |
|----|---------|-------|
| H-43 | Meilisearch has zero resilience testing | resilience |
| H-44 | S3/GCS health check is config-only (no connectivity probe) | resilience |
| H-45 | Graceful shutdown not implemented in HTTP or gRPC servers | resilience |

---

### P2: Medium (60 findings)

#### Security (22 medium)
- LDAP injection payloads untested
- Header injection via CRLF in package names untested
- SQL injection against format-specific endpoints untested
- ReDoS via user-supplied glob patterns
- Symlink following in archives untested
- XXE payloads for Maven POM / NuGet nuspec untested
- Content-type confusion / file upload polyglots
- JWT claims validation (wrong sub, missing claims) untested
- Cookie security attributes (HttpOnly, Secure, SameSite) untested
- Brute force protection (per-user vs per-IP) untested
- Refresh token type confusion (used as access token) untested
- Basic auth edge cases (wrong password, empty fields) untested
- Session fixation after password change untested
- Credential stuffing protection beyond rate limiting untested
- Account lockout after failed attempts untested
- Concurrent upload race condition (TOCTOU) untested
- XSS via artifact metadata (stored) untested
- Audit log tampering protection untested
- gRPC stream auth not enforced per-message
- Sensitive data in proxy error logs
- SSRF gaps (DNS rebinding, IPv6-mapped, authority confusion)
- Metrics endpoint rate limiting

#### Test Quality (19 medium)
- No format tests verify native install/consume operations
- Weak HTTP status assertions (accept 200-299 range instead of exact codes)
- Inconsistent status code assertions (401/403/404 interchangeable)
- Virtual repo priority resolution not tested with conflicting artifacts
- Search tests skip instead of fail when Meilisearch is down
- Weak search assertions (string contains vs exact match)
- Missing concurrent write conflict tests (same path)
- Repository CRUD missing constraint violations (duplicate key, type change)
- Quality gate tests don't verify actual gate blocking
- Missing version string edge cases (pre-release, build metadata, unicode)
- Format tests missing metadata query operations
- SBOM output format not validated structurally
- Missing common.sh assert_json_field helper
- Promotion to non-existent/wrong-format repo untested
- Promotion reject endpoint untested
- Approval workflow history untested
- Rate limit recovery timing not verified
- Webhook SSRF validation (internal IPs) untested
- Audit log test entirely skipped ("endpoint not exposed")

#### Missing API Coverage (9 medium)
- Migration connections/assessment API (9 endpoints)
- Monitoring/alerting API (4 endpoints)
- Remote instances API (7 endpoints)
- Tree browser API (2 endpoints)
- Event stream SSE API (1 endpoint)
- Search advanced features (trending, recent, filters)
- Repository cache TTL endpoints
- User profile operations
- Signing key advanced operations (rotate, revoke, export)

#### Infrastructure (10 medium)
- TLS/certificate rotation testing absent
- File descriptor exhaustion untested
- Config hot-reload under load untested
- Database migration failure recovery untested
- Mesh peer rejoin after extended outage untested
- Mesh split-brain scenario untested
- Network partition between mesh peers untested
- No startup probe for slow initialization
- Health probes don't verify DB connection pool state
- Prometheus metrics endpoint untested

#### CI Pipeline (8 medium)
- No flaky test detection or retry mechanism
- No per-test timeout in resilience CI jobs
- Parallel namespace naming collision possible
- Stale namespace cleanup not automated
- Test result aggregation doesn't fail workflow on test failures
- Parallel job output directory interference possible
- No deploy job timeout (can hang for 6 hours)
- Cache invalidation timing not tested

---

### P3: Low (24 findings)

- Telemetry/crash reporting API untested (7 endpoints)
- Download ticket API untested
- Profile access token API untested
- Webhook redeliver/enable endpoints untested
- Tree browser API untested
- Repository cache TTL untested
- Unicode/special characters in package names untested
- SBOM output format not structurally validated
- Rate limit recovery timing not verified
- Slowloris upload protection
- Pod security context (runAsNonRoot at container level)
- Health endpoint exposes DB pool stats unauthenticated
- Log injection payloads untested
- Password complexity enforcement untested
- CI artifact retention policy not configured
- CI failure notification mechanism absent
- CI workflow-level timeout not set
- Helm rollback after failed upgrade untested
- Probe timeout configuration inconsistent
- Trivy/scanner unavailability untested
- Meilisearch disk exhaustion untested
- Sync queue overflow untested
- Background service failure degradation untested
- Log format consistency untested

---

## Migration Candidates (Priority Order)

Scripts in `artifact-keeper/scripts/` not yet in `artifact-keeper-test/`:

| Priority | Source | Target | Scripts |
|----------|--------|--------|---------|
| Critical | `scripts/redteam/` | `tests/security/redteam/` | 15 scripts + lib.sh + payloads/ |
| Critical | `scripts/sso-e2e/` | `tests/auth/sso/` | 6 scripts (OIDC, LDAP, SAML) |
| High | `scripts/native-tests/test-wasm-plugin*.sh` | `tests/platform/` | 4 scripts (763 lines) |
| High | `scripts/failure/test-db-disconnect.sh` | `tests/resilience/restart/` | 1 script |
| High | `scripts/failure/test-server-crash.sh` | `tests/resilience/crash/` | 1 script |
| High | `scripts/native-tests/test-tag-replication.sh` | `tests/mesh/` | 1 script |
| High | `scripts/native-tests/test-proxy-virtual.sh` | `tests/repos/` | 1 script (696 lines) |
| High | `scripts/native-tests/test-curation.sh` | `tests/platform/` | 1 script (23KB) |
| Medium | `scripts/native-tests/test-grpc-sbom.sh` | `tests/platform/` | 1 script (215 lines) |
| Medium | `scripts/native-tests/test-health-probes.sh` | `tests/platform/` | 1 script (263 lines) |
| Medium | `scripts/native-tests/test-docker.sh` | merge into `tests/formats/test-oci.sh` | 1 script (203 lines) |
| Medium | `scripts/native-tests/test-s3-redirect.sh` | `tests/platform/` | 1 script |
| Medium | `scripts/native-tests/test-azure-redirect.sh` | `tests/platform/` | 1 script |
| Medium | `scripts/native-tests/test-gcs-redirect.sh` | `tests/platform/` | 1 script |
| Medium | `scripts/native-tests/test-s3-sts-rotation.sh` | `tests/platform/` | 1 script (944 lines) |
| Medium | `scripts/migration-e2e/` | `tests/platform/` | Migration pipeline tests |
| Medium | `scripts/stress/validate-results.sh` | integrate into `tests/stress/` | 1 script |

---

## Recommended New Test Suites

| Suite Path | Focus | Finding Count |
|---|---|---|
| `tests/security/redteam/` | Migrated red team scripts (auth bypass, injection, SSRF, etc.) | 15 scripts |
| `tests/security/decompression/` | Zip bombs, tar bombs, nested archives | 2 |
| `tests/security/injection/` | SQL, LDAP, ReDoS, XXE, header injection | 5 |
| `tests/security/archive/` | Symlinks, polyglots, path traversal in archives | 3 |
| `tests/security/supply-chain/` | Cache poisoning, dependency confusion, unsigned artifacts | 4 |
| `tests/auth/jwt-manipulation/` | alg=none, claims validation, expiry, type confusion | 5 |
| `tests/auth/sso/` | OIDC state, SAML signatures, LDAP injection | 3+ SSO migration |
| `tests/auth/mfa/` | TOTP replay, backup codes, enable/disable flow | 2 |
| `tests/rbac/scope-enforcement/` | API key scopes, repo restrictions, admin gate | 4 |
| `tests/platform/builds/` | Build CRUD, artifact association, diffs | 3 |
| `tests/platform/packages/` | Cross-repo package aggregation | 2 |
| `tests/platform/monitoring/` | Health log, alerts, metrics, SLO validation | 4 |
| `tests/platform/migration/` | Connection CRUD, assessment, migration jobs | 3 |
| `tests/infrastructure/grpc/` | Reflection, stream auth, unauthenticated access | 3 |
| `tests/infrastructure/wasm/` | Sandbox limits, memory, CPU, filesystem, network | 3 |

---

## Backend Code Issues Discovered During Audit

These are not test gaps but actual code issues the teams flagged:

1. **Graceful shutdown not implemented** - HTTP server (main.rs:495) does not wire SIGTERM to axum's with_graceful_shutdown. gRPC server has no shutdown signal. test-graceful-shutdown.sh exists but tests a feature that is not implemented.

2. **Metrics middleware is a TODO** - api/middleware/metrics.rs is empty. No request-level metrics (counts, latencies, histograms) are being collected. Blocks all production monitoring capability.

3. **Health endpoint ignores storage status** - overall_status in health.rs:177 only checks db_check.status. Storage and Meilisearch failures are reported but don't affect the overall status or HTTP response code.

4. **S3/GCS health check is config-only** - check_storage_health (health.rs:377-408) verifies bucket name is configured but performs no actual connectivity probe. Filesystem backend does a real read/write test.

5. **Helm readiness probe uses wrong endpoint** - Readiness probe uses `/health` (full rich check) instead of `/readyz` (critical deps only). A Meilisearch misconfiguration causes readiness failure even though the API can serve traffic.

6. **gRPC reflection unconditionally enabled** - No environment variable to disable in production. Unauthenticated service enumeration on port 9090.

7. **Meilisearch API key in plaintext env var** - Helm template uses direct value instead of secretKeyRef.

---

## Implementation Priority Roadmap

### Phase 1: Immediate (blocks release confidence)
1. Fix CI: Remove `|| true` from resilience test runner
2. Migrate red team scripts to release gate
3. Fix health endpoint to include storage/search in overall status
4. Add backup/restore data integrity verification

### Phase 2: Short-term (next 2 sprints)
1. Add decompression bomb protection tests
2. Add RBAC negative tests (admin protection, scope enforcement, IDOR)
3. Add JWT manipulation tests (alg=none, expiry)
4. Add Meilisearch resilience test
5. Add connection pool exhaustion test
6. Migrate SSO tests
7. Implement graceful shutdown in backend
8. Migrate WASM plugin test scripts

### Phase 3: Medium-term (next quarter)
1. Deepen shallow format tests (11 formats need download/delete/version tests)
2. Add supply chain tests (dependency confusion, cache poisoning)
3. Add mesh partition and split-brain tests
4. Add Helm upgrade-under-load test
5. Add schema migration during traffic test
6. Add deployment edge case tests
7. Expand platform suite (builds, packages, monitoring, migration APIs)
8. Implement metrics middleware in backend

### Phase 4: Ongoing
1. Add remaining API endpoint coverage (currently 31%, target 80%)
2. Native client consumption tests for all major formats
3. SLO validation and latency distribution in stress tests
4. Certificate rotation testing
5. Flaky test detection and retry mechanism in CI

---

## Audit Methodology

**Sources merged (261 raw findings -> 142 unique):**

| Source | Agent Type | Findings | Duplicates Removed |
|--------|-----------|----------|-------------------|
| Test Team (3 analysts) | Team-based | 60 | 20 (overlap with solo) |
| Security Team (3 analysts) | Team-based | 41 | 15 (overlap with solo) |
| DevOps Team (3 analysts) | Team-based | 53 | 18 (overlap with solo) |
| Test solo agent | Background | 40 | 16 (overlap with team) |
| Security solo agent | Background | 35 | 17 (overlap with team) |
| DevOps solo agent | Background | 32 | 13 (overlap with team + others) |

**Deduplication rules:**
- Same gap found by multiple teams: merged, severity kept at highest rating
- Overlapping findings (e.g., "red team not migrated" found by test + security teams): merged into single finding
- Related but distinct findings kept separate (e.g., SSRF in webhooks vs SSRF in proxy repos)

**Severity criteria:**
- **Critical:** Direct security vulnerability exploitable without privileged access, or systemic test infrastructure failure that undermines all testing
- **High:** Security gap requiring some access to exploit, or missing coverage for core functionality
- **Medium:** Defense-in-depth gap, quality improvement, or missing coverage for secondary functionality
- **Low:** Nice-to-have, edge case, or cosmetic improvement
