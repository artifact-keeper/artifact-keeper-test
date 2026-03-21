# 1.1.0 Release Gate Organization

**Date:** 2026-03-20
**Status:** Approved
**Context:** Full system audit produced 142 findings. This spec defines what blocks the 1.1.0 release vs. what ships as known issues for 1.1.1.

## Principles

1. **Two gates:** Hard gate (release blocker) and soft gate (known issues, tracked publicly)
2. **Full advertised feature set:** If the docs say it works, the release gate tests it
3. **Code fixes are release blockers:** Backend bugs that undermine advertised functionality must be fixed, not documented around
4. **Security-first within the hard gate:** Nothing ships exploitable
5. **Tiered execution:** Foundation first, security second, feature coverage third

## Hard Gate: Release Blockers

Every item here must pass before 1.1.0 ships. Organized in dependency order.

### Tier 1: Fix the Foundation

These are backend code fixes and CI corrections. Without these, test results cannot be trusted.

| ID | Type | Description | Repo |
|----|------|-------------|------|
| T1-01 | CI fix | Remove `|| true` from resilience test runner in release-gate.yml | artifact-keeper-test |
| T1-02 | Code fix | Health endpoint must include storage and search status in overall determination (health.rs:177) | artifact-keeper |
| T1-03 | Code fix | Implement graceful shutdown in HTTP server using tokio::signal + axum with_graceful_shutdown (main.rs:495) | artifact-keeper |
| T1-04 | Code fix | Implement graceful shutdown in gRPC server (main.rs:451-484) | artifact-keeper |
| T1-05 | Code fix | S3/GCS health check must perform actual connectivity probe, not just config check (health.rs:377-408) | artifact-keeper |
| T1-06 | Code fix | Implement metrics middleware (api/middleware/metrics.rs is an empty TODO) | artifact-keeper |
| T1-07 | Helm fix | Change readiness probe from /health to /readyz, liveness from /health to /livez | artifact-keeper-iac |
| T1-08 | Helm fix | Use secretKeyRef for Meilisearch API key instead of plaintext env var | artifact-keeper-iac |
| T1-09 | CI fix | Remove `continue-on-error: true` from mesh-tests job in release-gate.yml | artifact-keeper-test |
| T1-10 | CI fix | Add gate-check step to collect-results job that fails the workflow if any non-skipped job result is not `success` | artifact-keeper-test |
| T1-11 | Framework fix | Fix inconsistent HTTP status code assertions in common.sh (401/403/404 must not be interchangeable; assert exact codes) | artifact-keeper-test |

**Pass criteria:** All code fixes merged to their respective repos. CI fixes verified by: (1) running the gate with a deliberately failing resilience test and confirming the workflow fails, (2) running the gate with a deliberately failing mesh test and confirming the workflow fails, (3) collect-results job exits non-zero when any suite job fails.

### Tier 2: Security

No exploitable vulnerability may ship. These are new tests in artifact-keeper-test, plus the red team migration.

| ID | Type | Description | Suite |
|----|------|-------------|-------|
| T2-01 | Migration | Migrate 15 red team scripts to release gate (auth bypass, path traversal, SQLi, SSRF, CORS, default creds, gRPC unauth, info disclosure, metrics auth, OCI DoS, WASM plugin, API key exposure) | security/redteam |
| T2-02 | New test | IDOR: User A cannot access User B's tokens, profile, settings via ID manipulation | rbac |
| T2-03 | New test | Privilege escalation: non-admin cannot elevate via PATCH is_admin, JWT manipulation, or user creation | rbac |
| T2-04 | New test | Admin endpoint protection: non-admin systematically denied on all /api/v1/admin/* endpoints | rbac |
| T2-05 | New test | API key scope enforcement: read-only token cannot write, repo-scoped token cannot cross repos | rbac |
| T2-06 | New test | JWT algorithm confusion: tokens with alg=none are rejected | auth |
| T2-07 | New test | Dependency confusion: virtual repo serves local package over higher-versioned upstream (npm, PyPI, Maven) | security |
| T2-08 | New test | Artifact integrity: upload with mismatched checksum is rejected (Maven SHA-1, npm integrity, PyPI digests) | security |
| T2-09 | New test | Decompression bomb protection: small archive expanding to huge size is rejected across format handlers | security |
| T2-10 | New test | WASM sandbox: plugins exceeding memory/CPU/fuel limits are terminated without crashing backend | security |
| T2-11 | New test | Cache poisoning: proxy repo verifies upstream content checksums before caching | security |
| T2-12 | New test | SSRF: webhook, proxy upstream, and plugin git URLs reject private IPs, cloud metadata, localhost | security |
| T2-13 | New test | Default credentials: common credential pairs rejected in production-like test config | security |
| T2-14 | New test | Path traversal: URL-encoded and double-encoded ../../../ payloads rejected across format endpoints | security |
| T2-15 | New test | SQL injection: parameterized query enforcement on search, repository listing, format-specific paths | security |
| T2-16 | New test | gRPC: reflection disabled or requires auth, unauthenticated method calls rejected | security |
| T2-17 | New test | Token expiry: expired access tokens return 401, expired refresh tokens cannot generate new tokens | auth |
| T2-18 | New test | Token revocation: revoked tokens rejected (test within and beyond 5-min cache window) | auth |
| T2-19 | New test | Rogue mesh peer: registration with wrong API key rejected, sync operations require valid peer auth | security |
| T2-20 | New test | Stored XSS: upload artifacts with `<script>` tags in metadata fields (name, description, author), verify API responses are safe for rendering | security |
| T2-21 | New test | XXE: upload Maven POM and NuGet nuspec with `<!DOCTYPE ... ENTITY xxe SYSTEM "file:///etc/passwd">`, verify rejection | security |
| T2-22 | New test | TOCTOU race: two simultaneous uploads of same package/version with different content, verify atomic resolution (one wins, no corruption) | security |
| T2-23 | New test | Session invalidation: after password change or admin role revocation, existing JWT tokens must be rejected | auth |

**Pass criteria:** All 23 items pass. Zero high/critical security findings remain open.

**Note on T2-01 vs T2-12/T2-14/T2-15:** The red team migration (T2-01) brings in existing scripts that test these attack vectors against specific endpoints. The new test items (T2-12 for SSRF, T2-14 for path traversal, T2-15 for SQL injection) cover additional endpoints and scenarios not in the red team scripts. No overlap: the red team scripts are ported as-is, the new tests fill remaining gaps.

### Tier 3: Advertised Feature Coverage

Every feature claimed in docs/marketing must have meaningful tests (not just CRUD or HTTP 200 checks).

| ID | Feature | What must be tested | Suite |
|----|---------|--------------------|-------|
| T3-01 | 45 package formats | Deepen all format tests to include download verification, delete, and second version upload. 11 tests have no download at all; the remaining ~19 need delete and version tests added. Target: all 38 format tests include download+verify+delete+version | formats |
| T3-02 | Backup & restore | Upload known data, backup, delete, restore, verify data integrity with checksums | platform |
| T3-03 | SSO (OIDC/LDAP/SAML) | Migrate SSO E2E tests; at minimum test SSO admin CRUD for all 3 providers | auth |
| T3-04 | RBAC | Non-admin blocked from admin operations, role assignment/revocation changes access, group membership works | rbac |
| T3-05 | Artifact signing | Create key, configure repo, upload artifact, verify it gets signed, validate with public key | platform |
| T3-06 | Curation policies | Create block rule, attempt to download matching package, verify it is blocked | platform |
| T3-07 | Lifecycle policies | Create policy with max_versions=2, upload 5 versions, execute (not just preview), verify only 2 remain | lifecycle |
| T3-08 | Quality gates | Create gate with threshold, inject finding exceeding threshold, evaluate, verify gate fails artifact | security |
| T3-09 | Promotion | Test full flow: staging to release, approval, rejection, invalid promotion errors | promotion |
| T3-10 | Search | Test advanced search with filters, trending, recent, and checksum lookup | search |
| T3-11 | Webhooks | Fix skip-on-failure to fail-on-failure, verify delivery payload contains artifact ID and event type | webhooks |
| T3-12 | Mesh replication | All 5 capabilities with real assertions: peer registration, sync, policies, retroactive sync, heartbeat | mesh |
| T3-13 | WASM plugins | Migrate 4 plugin test scripts: install (local/git/zip), enable/disable, hot-reload, lifecycle | platform |
| T3-14 | Security scanning | Test scan trigger, findings listing, finding acknowledgment, security dashboard | security |
| T3-15 | Analytics | Expand from 1 test to cover storage breakdown, download trends, growth summary (3 of 7 endpoints) | platform |
| T3-16 | Builds | Create build, add artifacts, list builds, get build by ID | platform |
| T3-17 | Packages | Upload to multiple repos, query packages API for aggregated results | platform |
| T3-18 | TOTP 2FA | Test full flow: setup, enable, login with code, invalid code rejected, disable | auth |
| T3-19 | Meilisearch resilience | Kill Meilisearch, verify uploads still work (search degrades gracefully), verify recovery after restart | resilience |
| T3-20 | Audit logging | Security-relevant actions (login, permission changes, artifact deletion) produce audit log entries with user, action, timestamp, resource | platform |
| T3-21 | SBOM generation | Generate SBOM, verify output contains valid CycloneDX structure (bomFormat, specVersion, components), test SPDX format | platform |

**Pass criteria:** All 21 items pass. Every advertised feature has at least one test that exercises the actual behavior, not just the API surface. "Exercises actual behavior" means: at least one assertion on response body content or resulting system state (not just HTTP status code).

## Soft Gate: Known Issues (Target 1.1.1)

These are tracked publicly, do not block the 1.1.0 release, and are prioritized for 1.1.1.

### Priority 1: Security hardening (medium severity)
- LDAP injection payload testing
- Header injection via CRLF in package names
- ReDoS via user-supplied glob patterns
- Symlink following in archives
- Content-type confusion / file upload polyglots
- JWT claims validation (wrong sub, missing claims)
- Cookie security attributes (HttpOnly, Secure, SameSite)
- Brute force protection granularity (per-user vs per-IP)
- Refresh token type confusion
- Basic auth edge cases
- Account lockout after failed attempts
- Audit log tampering protection
- gRPC stream auth per-message enforcement
- Credential scrubbing in proxy error logs
- SSRF advanced bypass (DNS rebinding, IPv6-mapped, authority confusion)
- Connection pool exhaustion stress test (50+ concurrent, verify clean 503)

### Priority 2: Deployment and infrastructure
- Helm upgrade under active traffic
- Schema migration during running traffic
- Blue-green / canary deployment validation
- Certificate rotation during operation
- PVC expansion under load
- Init container ordering validation
- NetworkPolicy enforcement testing
- Rollback after failed upgrade
- Helm chart value validation (helm lint step)

### Priority 3: CI pipeline improvements
- Flaky test detection and retry mechanism
- Per-test timeout in resilience CI jobs
- Namespace naming collision fix (use GITHUB_RUN_ID)
- Stale namespace cleanup cron job
- Test result aggregation fails workflow on failures
- Parallel job output isolation
- Deploy job timeout
- Artifact retention policy (14 days)
- Failure notification (Slack/GitHub issue)

### Priority 4: Test depth and coverage expansion
- Remaining API endpoint coverage: migration (15 endpoints), remote instances (7), telemetry (7), monitoring (4), tree browser (2), events SSE (1), download tickets, profile tokens
- Format native client consumption tests (cargo install, helm pull, apt-get)
- Duplicate upload behavior (409 conflict) for all formats
- Empty/malformed package upload rejection
- Unicode/special characters in package names
- Version string edge cases (pre-release, build metadata)
- Virtual repo priority resolution with conflicting artifacts
- Webhook redeliver and enable endpoints
- Promotion reject endpoint
- Approval workflow history
- Repository cache TTL endpoints
- SLO validation and latency percentile measurement
- Mesh adversarial scenarios (split-brain, partition, clock skew, peer rejoin, sync queue overflow)

### Priority 5: Remaining migration candidates
- gRPC SBOM test (215 lines)
- Health probes test (263 lines)
- Docker native test enhancements (203 lines)
- S3/Azure/GCS redirect tests (4 scripts, ~1,748 lines)
- Migration E2E (Artifactory/Nexus import)
- Failure injection enhancements (truncated/empty file uploads)
- Stress test result validation script

### Priority 6: Test framework improvements
- Add assert_json_field helper to common.sh
- Fix inconsistent HTTP status code assertions (401/403/404 interchangeable)
- Change search test skip-on-error to fail-on-error
- Standardize error response assertions (JSON body with error + message fields)

## Release Workflow

```
1. Tier 1 code fixes merged to artifact-keeper, artifact-keeper-iac
2. Tier 1 CI fixes applied to release-gate.yml: remove || true, remove continue-on-error, add gate-check step, fix status code assertions
3. Tier 2 security tests written in artifact-keeper-test
4. Tier 3 feature tests written in artifact-keeper-test
5. release-gate.yml updated with new test suites and jobs
6. RC build triggers release gate
7. Hard gate passes (all jobs green, gate-check confirms) -> 1.1.0 tagged
8. Soft gate items filed as GitHub issues, milestoned to 1.1.1
```

## Metrics

| Metric | Current | After Hard Gate |
|--------|---------|----------------|
| API endpoint coverage | ~31% (103/329) | ~55% (180/329) |
| Security test scripts in release gate | 2 | 40 |
| Format tests with download+delete+version | ~8 of 38 | 38 of 38 |
| Features with enforcement testing | ~3 of 12 | 12 of 12 |
| Backend code issues | 6 open | 0 open |
| Red team scripts in release gate | 0 of 15 | 15 of 15 |

## Hard Gate Item Count

| Tier | Items | Type |
|------|-------|------|
| Tier 1: Foundation | 11 | Code/CI/Helm/framework fixes |
| Tier 2: Security | 23 | New tests + migration |
| Tier 3: Features | 21 | New + enhanced tests |
| **Total hard gate** | **55** | |
| Soft gate (1.1.1) | ~87 | Tracked as known issues |
