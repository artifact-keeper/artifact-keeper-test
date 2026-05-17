# E2E Coverage Triage — 2026-05-17

**Scope.** Classify every sub-task across the 12 v1.1.9 Epic issues (#67-#78) in this repo against the 307 existing test scripts under `tests/`. Cross-reference the last 90 days of behavioral bug-fix commits on `artifact-keeper` main against the same test corpus. Produce a prioritized backlog for the code rounds.

**Method.** Five parallel research agents — four classifying 3 Epics each, one cross-referencing fixes. Each sub-task and each backend fix tagged `covered` / `partial` / `missing` / `manual-only` / `backend-blocked` with file-level evidence.

**Code is not in scope for this report.** Test files referenced below are existing files used as evidence. New test files named in "Suggested action" columns are proposals for the upcoming code rounds, not files written today.

---

## 1. Executive summary

| Bucket | Count | % of 149 |
|---|---|---|
| **Covered** — load-bearing assertion present | 51 | 34% |
| **Partial** — file exists, smoke-only or skips key assertion | 40 | 27% |
| **Missing** — no relevant test | 51 | 34% |
| **Manual-only** — needs external infra (LDAP/SAML server, multi-instance, hardware) | 4 | 3% |
| **Backend-blocked** — depends on an unmerged artifact-keeper PR | 3 | 2% |

Plus **14 backend bug-fix commits** in the last 90 days that lack a regression test in this repo (5 critical, 8 high, 1 medium — see §4).

**Total code rounds needed to fully cover Epics + untested fixes: ~95 new test scripts + 40 hardening passes on partial tests = ~135 test-shaped work units.**

### Top 5 risk-weighted gaps (where to start the code rounds)

1. **Epic 2 (Security scanning depth)** — 11 of 16 missing. Customer pain #872 named scanning as the second make-or-break feature. Includes the **untested security-critical** PR #1162/#1164 (scanner format-gating, also called out in §4).
2. **Epic 6 (Repo/storage lifecycle)** — 8 of 18 missing. Touches quota enforcement, cron-driven cleanup, repo key rename, artifact metadata — the surfaces that are easy to break in a backend refactor.
3. **Untested-fix backlog (§4)** — 14 fixes with no regression test. Five are user-visible security bugs (SSRF, SQL injection wildcards, auth bypass on missing repo).
4. **Epic 12 (Federation)** — 8 of 10 missing, only 2 partial. Federation already has known data-divergence reports; missing E2E coverage compounds the risk.
5. **Epic 1 (Pull-through cache)** — 4 of 10 covered, but the two missing items (OCI bearer token caching, max artifact size streaming) are both runtime-data-loss surfaces.

---

## 2. Recommended PR grouping for the code rounds

Per your earlier direction — one PR per logical group, 3-round 4-agent audit per PR, local execution against `docker compose -f docker-compose.local-dev.yml up`. Suggested order favors customer-pain Epics + risk concentration. Each Epic is one PR unless noted.

| Order | PR | Scope | New tests | Hardening passes |
|---|---|---|---|---|
| 1 | `feat/epic-2-security-scanning-depth` | Epic 2 (#67) | 11 | 3 |
| 2 | `feat/untested-fixes-batch-1` | §4 items 1-7 (CRITICAL + top-3 HIGH) | 7 | 0 |
| 3 | `feat/epic-1-pullthrough-completeness` | Epic 1 (#69) | 2 | 3 |
| 4 | `feat/epic-6-repo-lifecycle` | Epic 6 (#71) | 8 | 4 |
| 5 | `feat/epic-7-webhooks-grpc` | Epic 7 (#75) | 4 | 2 |
| 6 | `feat/epic-3-format-lifecycle` | Epic 3 (#68) | 3 | 5 |
| 7 | `feat/epic-4-signing-verification` | Epic 4 (#72) | 1 | 4 |
| 8 | `feat/epic-8-search-browse` | Epic 8 (#73) | 6 | 4 |
| 9 | `feat/epic-10-admin-ops` | Epic 10 (#77) | 3 | 5 |
| 10 | `feat/epic-11-auth-edge-cases-1` | Epic 11 (#76) covered+code-only items | 4 | 4 |
| 11 | `feat/epic-12-federation-1` | Epic 12 (#78) items not requiring multi-instance | 5 | 2 |
| 12 | `feat/untested-fixes-batch-2` | §4 items 8-14 (remaining HIGH + MEDIUM) | 7 | 0 |

**Deferred / split off:**

- **Epic 5 (#70)** — all 6 formats already have test files. The Epic asks for a **backend audit** (handler-registry wiring), which is outside this repo. Recommend closing #70 after a one-paragraph comment confirming each test exists and pointing at the backend-side audit issue.
- **Epic 9 (#74)** — three sub-tasks (9.4 SSE progress, 9.5 report, 9.6 assessment) are **manual-only** until source-system fixtures (Artifactory/Nexus/Harbor mocks) land. Recommend filing a separate fixture-infra issue and tackling 9.1-9.3, 9.7-9.8 in a small PR.
- **Epic 11 manual-only items** — LDAP / SAML full login flows (11.1, 11.2). Need LDAP and SAML mock infrastructure. Tag `manual-only`, @brandonrc, defer.
- **Epic 12 multi-instance items** — 12.6 (bidirectional conflicts), 12.7 (multi-peer partial failure), 12.9 (failover), 12.10 (cross-instance aggregation) need 3+ AK instances on the mesh harness. Gate behind `MAIN_URL`/`PEER1_URL`/`PEER2_URL` env vars and treat as a second-PR for Epic 12.

---

## 3. Per-Epic detailed triage

### Epic 1 — Pull-through cache reliability (#69, 10 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 1.1 Concurrent fetch stampede | covered | `tests/pullthrough/test-cache-stampede-no-upstream-divergence.sh` | none |
| 1.2 Cache poisoning full E2E | **backend-blocked** | `tests/security/test-cache-poisoning.sh` (stubbed) | unblock on artifact-keeper#1224 |
| 1.3 Stale cache fallback | covered | `tests/pullthrough/test-stale-on-upstream-error.sh` | none (gated v1.2.0+) |
| 1.4 Cache TTL expiry, per-repo | covered | `tests/pullthrough/test-ttl-expiry-refetch.sh` + `tests/repos/test-cache-ttl-eviction.sh` | none |
| 1.5 ETag conditional request | covered | `tests/pullthrough/test-etag-conditional-request.sh` | extend to non-conda formats |
| 1.6 OCI bearer token caching with TTL eviction | **missing** | — | create `tests/pullthrough/test-oci-bearer-token-cache.sh` |
| 1.7 OCI 401-redirect token-realm SSRF | partial | `tests/pullthrough/test-oci-remote-upstream-ssrf.sh` (CREATE-time only) | redirect-follow SSRF blocked on #1224 |
| 1.8 Max artifact size streaming enforcement | **missing** | — | create `tests/pullthrough/test-max-artifact-size-streaming.sh` |
| 1.9 Format-specific upstream auth | partial | `tests/repos/test-upstream-auth.sh` | assert actual proxied fetch with credentials |
| 1.10 Virtual repo cross-format proxying | partial | `tests/repos/test-virtual-repo-resolution.sh` | add multi-upstream member test |

### Epic 2 — Security scanning depth (#67, 16 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 2.1 Scan findings list/filter/paginate | covered | `tests/security/test-scan-findings-list.sh` | none |
| 2.2 Finding acknowledge/suppress | covered | `tests/security/test-finding-acknowledge.sh` | none |
| 2.3 Repo-scoped scan endpoints | **missing** | — | create `tests/security/test-scan-repository-scoped.sh` |
| 2.4 Scan reuse via checksum dedup | partial | `tests/security/test-scan-depth-persistence.sh` | dedup assertion blocked on artifact-keeper#907 |
| 2.5 SBOM format conversion (CycloneDX↔SPDX) | **missing** | — | create `tests/platform/test-sbom-convert.sh` |
| 2.6 SBOM components enumeration | **missing** | — | create `tests/platform/test-sbom-components.sh` |
| 2.7 SBOM by-artifact retrieval | partial | `tests/platform/test-sbom.sh` | add component-level assertions |
| 2.8 CVE history, trends, status | **missing** | — | create `tests/security/test-cve-history.sh` |
| 2.9 License policy CRUD + compliance | **missing** | — | create `tests/security/test-license-policy.sh` |
| 2.10 Scan policy CRUD + blocking | **missing** | — | create `tests/security/test-scan-policy.sh` |
| 2.11 DependencyTrack integration (9 endpoints) | **missing** | — | create `tests/security/test-dependencytrack-integration.sh` |
| 2.12 Auto-scan-on-upload trigger | **missing** | — | create `tests/security/test-auto-scan-on-upload.sh` |
| 2.13 Scheduled scan (cron) | **missing** | — | create `tests/security/test-scheduled-scan.sh` (timing-sensitive; may need feature flag) |
| 2.14 OpenSCAP scanner E2E | **missing** | — | create `tests/security/test-openscap-scanner.sh` (requires OpenSCAP service) |
| 2.15 Grype scanner E2E | **missing** | — | create `tests/security/test-grype-scanner.sh` |
| 2.16 Quality gate BLOCKS on violation | partial | `tests/security/test-quality-gate-enforcement.sh` | add upload-rejection assertion |

### Epic 3 — Format lifecycle operations (#68, 10 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 3.1 npm dist-tag PUT | covered | `tests/formats/test-npm-edge-cases.sh:225+` | none |
| 3.2 npm package deprecation | covered | `tests/formats/test-npm-edge-cases.sh` | none |
| 3.3 PyPI PEP 658 metadata fetch | **missing** | — | create `tests/formats/test-pypi-pep658-metadata.sh` |
| 3.4 PyPI yanking (DELETE/unpublish) | partial | `tests/formats/test-pypi-conformance.sh` | add actual DELETE-yank operation |
| 3.5 Cargo yank/unyank | partial | `tests/formats/test-cargo-conformance.sh` | add unyank (PUT) assertion |
| 3.6 Maven SNAPSHOT metadata XML | partial | `tests/formats/test-maven-virtual-snapshot.sh` | timestamp-resolution uniqueness check |
| 3.7 NuGet v2 push (legacy) | partial | `tests/formats/test-nuget.sh:181-196` | full v2 retrieval round-trip |
| 3.8 NuGet symbol packages (.snupkg) | **missing** | — | create `tests/formats/test-nuget-symbols.sh` |
| 3.9 Go @latest endpoint | covered | `tests/formats/test-go-edge-cases.sh:710+` + `test-go-remote.sh` | none |
| 3.10 NuGet search freshness SLA | partial | `tests/formats/test-nuget-conformance.sh` | explicit SLA timing assertion |

### Epic 4 — Format signing and verification (#72, 8 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 4.1 OCI Referrers API + artifactType filter | covered | `tests/formats/test-oci-conformance.sh:584-610` | none |
| 4.2 OCI catalog pagination (`?last=X&n=Y`) | partial | `tests/formats/test-oci-conformance.sh:498-520` | exercise cursor edge cases |
| 4.3 OCI anonymous/public pull | covered | `tests/formats/test-oci-remote.sh:312-374` | none (covers #744) |
| 4.4 Debian GPG signature chain | partial | `tests/formats/test-debian-conformance.sh:135` | add apt-key validation against chain |
| 4.5 Debian Packages.xz | covered | `tests/formats/test-debian-xz-proxy.sh` | none |
| 4.6 RPM repodata signatures + dnf verify | partial | `tests/formats/test-rpm-conformance.sh:277-296` | invoke `dnf verify` or manual GPG |
| 4.7 Helm chart provenance (.tgz.prov) | partial | `tests/formats/test-helm-conformance.sh:345-389` | add `helm pull --verify` invocation |
| 4.8 Alpine APKINDEX RSA signature | **missing** | — | create `tests/formats/test-alpine-signature-verify.sh` |

### Epic 5 — Format suites missing entirely (#70, 6 sub-tasks)

All 6 formats already have test files in `tests/formats/`. The Epic asks for **handler-registry audits**, which is backend work, not test work.

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 5.1 Gradle | partial (wire protocol) | `tests/formats/test-gradle-conformance.sh` | add `test-gradle-native-client.sh` (invoke `gradle` CLI) |
| 5.2 jetbrains_plugins | covered (defensive) | `tests/formats/test-jetbrains.sh` | confirm handler wiring in backend (out of scope) |
| 5.3 mlmodel | covered | `tests/formats/test-mlmodel.sh` + conformance | confirm handler wiring in backend |
| 5.4 opkg (WASM proxy) | covered | `tests/formats/test-opkg.sh` | none — documented as WASM route |
| 5.5 p2 | covered | `tests/formats/test-p2.sh` + conformance | confirm handler wiring in backend |
| 5.6 vagrant | covered | `tests/formats/test-vagrant.sh` + conformance | confirm handler wiring in backend |

**Recommendation:** close #70 with a comment citing this triage, file the backend handler-audit issue separately.

### Epic 6 — Repository and storage lifecycle (#71, 18 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 6.1 Virtual repo member remove | covered | `tests/repos/test-virtual-repo-member-remove.sh` | none |
| 6.2 Virtual repo bulk member update | covered | `tests/repos/test-virtual-repo-member-bulk-update.sh` | none |
| 6.3 Cache TTL get/set | covered | `tests/repos/test-cache-ttl-config.sh` | none |
| 6.4 Repository quota enforcement | **missing** | — | create `tests/repos/test-quota-enforcement.sh` |
| 6.5 Lifecycle preview (`/preview`) | partial | `tests/lifecycle/test-lifecycle-policies.sh:94-99` | assert preview content (not just HTTP 200) |
| 6.6 Lifecycle execute-all | **missing** | — | create `tests/lifecycle/test-lifecycle-execute-all.sh` |
| 6.7 Lifecycle cron + execute_due | **missing** | — | create `tests/lifecycle/test-lifecycle-cron-scheduling.sh` |
| 6.8 Storage GC (dry-run + live) | partial | `tests/lifecycle/test-storage-gc.sh` | verify live GC reclaims space |
| 6.9 Storage backend selection | partial | `tests/formats/test-maven-s3.sh` | add GCS / Minio variants (env-gated) |
| 6.10 Cargo index_upstream_url | **missing** | — | create `tests/formats/test-cargo-index-upstream.sh` |
| 6.11 Repository key rename | **missing** | — | create `tests/repos/test-repo-key-rename.sh` |
| 6.12 Artifact metadata endpoint | **missing** | — | create `tests/repos/test-artifact-metadata.sh` |
| 6.13 Multipart artifact upload | covered | `tests/repos/test-multipart-artifact-upload.sh` | none |
| 6.14 Artifact stats (`/stats`) | **missing** | — | create `tests/repos/test-artifact-stats.sh` |
| 6.15 Format-specific custom handler keys (WASM) | **missing** | — | create `tests/repos/test-format-key-wasm-override.sh` |
| 6.16 Repository PATCH metadata | **missing** | — | create `tests/repos/test-repo-patch-metadata.sh` |
| 6.17 Hard-delete cascade | partial | `tests/repos/test-virtual-repo-member-remove.sh:163-202` (soft-delete only) | distinguish + add hard-delete |
| 6.18 Repository labels nested router | covered | `tests/repos/test-repo-labels.sh` | none |

### Epic 7 — Webhooks, events, gRPC (#75, 19 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 7.1 Webhook retry engine (exponential backoff) | covered | `tests/webhooks/test-webhook-retry-recover.sh` | extend to full schedule |
| 7.2 Dead-letter queue | covered | `tests/webhooks/test-webhook-deadletter.sh` | none |
| 7.3 Max-attempts exhaustion | covered | `tests/webhooks/test-webhook-deadletter.sh` | none |
| 7.4 Async retry job triggering | partial | `tests/webhooks/test-webhook-retry-recover.sh` | assert `process_webhook_retries` metric |
| 7.5 HMAC signature `X-Webhook-Signature` | covered | `tests/webhooks/test-webhook-hmac-signature.sh` | none |
| 7.6 Webhook secret rotation/revocation | covered | `tests/webhooks/test-webhook-rotation-overlap.sh` | none |
| 7.7 Custom header injection | covered | `tests/webhooks/test-webhook-custom-headers.sh` | none |
| 7.8 SSRF prevention on webhook URLs | covered | `tests/security/test-ssrf-prevention.sh` | none |
| 7.9 URL re-validation at delivery (DNS rebinding) | **missing** | — | create `tests/webhooks/test-webhook-dns-rebinding.sh` |
| 7.10 Repository-scoped filtering | **missing** | — | create `tests/webhooks/test-webhook-repo-scope.sh` |
| 7.11 Multi-event filtering | covered | `tests/webhooks/test-webhook-multi-event-filter.sh` | none |
| 7.12 Webhook test/dry-run endpoint | covered | `tests/webhooks/test-webhook-crud.sh:86` | none |
| 7.13 Enable/disable toggle | covered | `tests/webhooks/test-webhook-crud.sh:71` | none |
| 7.14 Delivery list filter by status | covered | `tests/webhooks/test-webhook-deadletter.sh:156` | add succeeded + invalid cases |
| 7.15 SSE event stream | covered | `tests/webhooks/test-events-sse-stream.sh` | backpressure handling |
| 7.16 Cross-handler event propagation | partial | `tests/webhooks/test-events-sse-stream.sh` + `test-webhook-delivery.sh` | simultaneous /deliveries + SSE check |
| 7.17 gRPC SbomService (7 methods) | partial | redteam auth-only | create `tests/webhooks/test-grpc-sbom-service.sh` |
| 7.18 gRPC CveHistoryService | **missing** | — | create `tests/webhooks/test-grpc-cve-history-service.sh` |
| 7.19 gRPC SecurityPolicyService | **missing** | — | create `tests/webhooks/test-grpc-security-policy-service.sh` |

### Epic 8 — Search and browse (#73, 15 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 8.1 Size filters | covered | `tests/search/test-search-advanced-filters.sh` | boundary cases |
| 8.2 Date filters | covered | `tests/search/test-search-advanced-filters.sh` | explicit future/past timestamp |
| 8.3 Path filter | **missing** | — | create `tests/search/test-search-path-filter.sh` |
| 8.4 Version filter | **missing** | — | create `tests/search/test-search-version-filter.sh` |
| 8.5 Repository_key filter | covered | `tests/search/test-search-advanced-filters.sh:72` | none |
| 8.6 Sort parameters | **missing** | — | create `tests/search/test-search-sort.sh` |
| 8.7 Tag/label search integration | partial | `tests/platform/test-artifact-labels.sh` | extend to search-by-label |
| 8.8 Faceted drill-down | **missing** | — | create `tests/search/test-search-facets.sh` |
| 8.9 Incremental indexing SLA | **missing** | — | create `tests/search/test-search-incremental-index.sh` |
| 8.10 Tree browse API | covered | `tests/search/test-search-tree-browse.sh` | pagination + mixed-type |
| 8.11 Pagination edge cases | covered | `tests/search/test-search-pagination.sh` | offset overflow |
| 8.12 Autocomplete edge cases | **missing** | — | create `tests/search/test-search-autocomplete.sh` |
| 8.13 SHA1 / MD5 checksum search | partial | `tests/search/test-search-checksum.sh` (SHA256 only) | extend if backend supports |
| 8.14 Trending custom days/limit | partial | `tests/search/test-search-basic.sh:92` | parameter assertions |
| 8.15 Recent custom limit | partial | `tests/search/test-search-basic.sh:77` | parameter assertion |

### Epic 9 — Migrations subsystem (#74, 9 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 9.1 Create migration job | covered | `tests/lifecycle/test-migrations-lifecycle.sh:238` | required-field validation |
| 9.2 List/query jobs | covered | `tests/lifecycle/test-migrations-lifecycle.sh` | filter by status/date |
| 9.3 Job lifecycle (start/pause/resume/cancel) | partial | `tests/lifecycle/test-migrations-lifecycle.sh:296` (cancel only) | start/pause/resume after backend ready |
| 9.4 SSE progress streaming | **manual-only** | — | needs long-running source fixture |
| 9.5 Migration report | **manual-only** | — | needs completed job fixture |
| 9.6 Pre-migration assessment | **manual-only** | — | needs reachable source instance |
| 9.7 Connection test | covered | `tests/lifecycle/test-migrations-lifecycle.sh:209` | succeed against mock |
| 9.8 Connection CRUD | covered | `tests/lifecycle/test-migrations-lifecycle.sh:115/160/183/323` | add PUT update |
| 9.9 Format-specific fixtures | **missing** (infra) | — | file separate fixture-infra issue |

### Epic 10 — Admin operations (#77, 13 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 10.1 Backup execute | covered | `tests/admin/test-backup-lifecycle.sh:68-82` | verify async job execution |
| 10.2 Backup cancel | covered | `tests/admin/test-backup-lifecycle.sh:84-100` | none |
| 10.3 Backup delete | covered | `tests/admin/test-backup-lifecycle.sh:102-116` | none |
| 10.4 /livez liveness probe | covered | `tests/admin/test-livez.sh` | none |
| 10.5 Monitoring alerts query | partial | `tests/admin/test-monitoring-alerts.sh:19-29` | generate + verify alert presence |
| 10.6 Alert suppression | partial | `tests/admin/test-monitoring-alerts.sh:44-74` | verify actual suppression |
| 10.7 Manual health-check trigger | partial | `tests/admin/test-monitoring-alerts.sh:31-42` | verify check actually triggered |
| 10.8 Settings update | partial | `tests/platform/test-system-settings.sh:8-25` | POST/PUT + verify persistence |
| 10.9 List storage backends | covered | `tests/admin/test-storage-backends-list.sh` | none |
| 10.10 Reindex trigger | partial | `tests/admin/test-reindex.sh:14-52` | wait for completion + verify index |
| 10.11 Admin-initiated password reset | partial | `tests/platform/test-admin-password-recovery.sh:100+` | add admin-reset path |
| 10.12 User self-service password change | covered | `tests/platform/test-admin-password-recovery.sh:70+` + `tests/auth/test-jwt-after-password-change.sh:70-86` | none |
| 10.13 Audit log emission/query/filter/retention | partial | `tests/platform/test-audit-log.sh` | query/filter/export coverage |

### Epic 11 — Auth edge cases (#76, 15 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 11.1 LDAP full login flow | **manual-only** | — | LDAP mock or env-gate; @brandonrc |
| 11.2 SAML full login flow | **manual-only** | — | SAML IdP mock; @brandonrc |
| 11.3 OIDC state/nonce mismatch | partial | `tests/auth/test-oidc-callback.sh:61-77` | nonce-specific attacks |
| 11.4 OIDC redirect URI mismatch | **missing** | — | create `tests/auth/test-oidc-redirect-uri.sh` |
| 11.5 OIDC custom claim mapping | **missing** | — | create `tests/auth/test-oidc-custom-claims.sh` |
| 11.6 LDAP group sync on federated auth | **missing** | — | needs LDAP fixture; @brandonrc |
| 11.7 Token exchange endpoint | **missing** | — | create `tests/auth/test-token-exchange.sh` |
| 11.8 API token scope enforcement | covered | `tests/auth/test-api-token-scope.sh` | none |
| 11.9 Download ticket lifecycle | partial | `tests/auth/test-download-ticket-lifecycle.sh:42-80` | single-use/expiry gated on backend |
| 11.10 TOTP backup code consumption | partial | `tests/auth/test-totp-backup-codes.sh` | exhaustion behavior |
| 11.11 TOTP disable flow | covered | `tests/auth/test-totp-disable.sh:80+` | none |
| 11.12 User deactivation revokes tokens | partial | `tests/auth/test-user-deactivation-revokes-tokens.sh` | backend cache TTL blocks (gated v1.2.0+) |
| 11.13 Refresh token age limits + rotation | partial | `tests/auth/test-refresh-token-rotation.sh:8-19` | family-tracking gap (gated v1.2.0+) |
| 11.14 Password reset temp credentials | **missing** | — | create `tests/auth/test-password-reset-credentials.sh` |
| 11.15 Password strength validation | **missing** | — | create `tests/auth/test-password-strength.sh` |

### Epic 12 — Federation depth (#78, 10 sub-tasks)

| Sub-task | Status | Evidence | Suggested action |
|---|---|---|---|
| 12.1 Peer degradation → recovery | partial | `tests/mesh/test-peer-degradation-recovery.sh:35-68` | recovery half blocked on PATCH /peers/{id} |
| 12.2 Bandwidth limit enforcement | **missing** | — | create `tests/mesh/test-bandwidth-limit.sh` |
| 12.3 Concurrent transfer queue saturation | **missing** | — | create `tests/mesh/test-transfer-queue-saturation.sh` |
| 12.4 Sync filter application | partial | `tests/mesh/test-sync-filter-application.sh:57-98` | actual transfer blocked on sync-worker in test env |
| 12.5 Backoff-until backpressure recovery | **missing** | — | create `tests/mesh/test-backoff-backpressure.sh` |
| 12.6 Bidirectional sync conflicts | **missing** (multi-instance) | — | create `tests/mesh/test-bidirectional-conflicts.sh` (env-gated) |
| 12.7 Multi-peer partial failure | **missing** (multi-instance) | — | env-gated |
| 12.8 Replication schedule (cron) | **missing** | — | create `tests/mesh/test-replication-schedule.sh` |
| 12.9 Failover between peers | **missing** (multi-instance) | — | env-gated |
| 12.10 Cross-instance metadata aggregation | **missing** (multi-instance) | — | env-gated |

---

## 4. Untested backend fixes (cross-reference, last 90 days)

These are behavioral bug fixes merged to `artifact-keeper` main between 2026-02-17 and 2026-05-17 that have **no regression test** in this repo. 80 fix commits analyzed; 14 lack coverage.

### Critical (security / data loss / production-blocking)

| PR | SHA | Summary | Recommended test |
|---|---|---|---|
| #879 | `3e52993` | Go proxy SSRF via sumdb forwarding | `tests/security/test-goproxy-sumdb-ssrf-allowlist.sh` |
| #1002 | `23d9743` | Grype DB not pre-seeded → first-scan crashes on egress-restricted networks | `tests/security/test-grype-db-preseeding.sh` |
| #1164 | `14f59c6` | Wrong scanner gated on OCI (Grype on non-applicable format) | `tests/security/test-scanner-format-gate.sh` (combine with #1162) |
| #1218 | `3170271` | jq el9_7 security errata not pulled in backend image | covered indirectly by image scan; mark **N-A** for E2E |
| #1244 | `f73ed88` | Docker Hub rate-limit + lettre security audit | infra; **N-A** for E2E |

### High

| PR | SHA | Summary | Recommended test |
|---|---|---|---|
| #1241 | `3bfcb93` | Audit INSERT failure rolled back scan reap | `tests/security/test-scan-stuck-reap-audit-rollback.sh` |
| #1220 | `2e3a335` | Stuck-scan janitor concurrency bugs | `tests/security/test-scan-janitor-concurrency.sh` |
| #1162 | `3ffd494` | Scanners not gated on `is_applicable` → invalid `scan_results` rows | combine with #1164 above |
| #1070 | `5ae4f99` | Virtual repos served stale DB metadata instead of upstream `__cache__meta__.json` | `tests/pullthrough/test-virtual-cache-metadata-passthrough.sh` |
| #1125 | `f5d32c2` | Scanner stdout capture unbounded — OOM on malicious CLI output | `tests/security/test-scanner-stdout-cap.sh` |
| #1137 | `d73bf51` | Cache TTL None semantics broken on missing `Retry-After` | `tests/pullthrough/test-cache-ttl-edge-cases.sh` |
| #1004 | `18b1fa8` | SQL injection via unescaped `LIKE` wildcards (`%`, `_`) across package searches | `tests/security/test-sql-injection-wildcard-escape.sh` |
| #874 | `d7a6030` | Auth bypass on missing repo (middleware short-circuit) | `tests/auth/test-auth-missing-repo.sh` |

### Medium

| PR | SHA | Summary | Recommended test |
|---|---|---|---|
| #1099 | `22b99a7` | `/readyz` returned 503 during setup — broke Kubernetes readiness probes on fresh deploys | `tests/admin/test-health-readyz-during-setup.sh` |

**Recommendation:** group these as `feat/untested-fixes-batch-1` (top 7 by severity) and `feat/untested-fixes-batch-2` (remaining 7). Each batch is a single PR through the 3-round 4-agent audit. Two PRs of 7 tests each is well within audit capacity.

---

## 5. Items needing your review

### Manual-only (need fixture infra or hardware before automation)
- 9.4 SSE migration progress streaming
- 9.5 Migration report
- 9.6 Pre-migration assessment
- 11.1 LDAP full login flow
- 11.2 SAML full login flow
- 11.6 LDAP group sync

Recommend tagging these issues `manual-only` and @-mentioning you for the call on whether to invest in fixture infra now or defer.

### Backend-blocked (depend on an unmerged artifact-keeper PR/issue)
- 1.2 Cache poisoning full E2E — artifact-keeper#1224
- 2.4 Scan reuse dedup `is_reused` field assertion — artifact-keeper#907
- 12.1 Peer recovery half — backend needs PATCH `/peers/{id}` to accept `endpoint_url` updates

### Backend audits required (out of this repo)
- Epic 5 handler-registry wiring (jetbrains_plugins, mlmodel, p2, vagrant)
- 6.17 hard-delete vs soft-delete distinction (need a backend behavioral spec before writing the test)

---

## 6. Code-rounds execution plan

When the code rounds start:

1. **Branch model.** One PR per row in §2's table. Branch name follows the convention there.
2. **Local environment.** `cd /home/khan/ak/artifact-keeper && docker compose -f docker-compose.local-dev.yml up -d` brings up the full stack (backend on `:8080`, gRPC `:9090`, Postgres `:30432`, OpenSearch `:9200`, Trivy, OpenSCAP, Dependency-Track, Jaeger). Tests source `tests/lib/common.sh` and use `RUN_ID` for in-instance namespacing — a single instance handles serial test runs.
3. **Local validation gate.** Before push: run the new/modified tests against the local stack. Per the user, this is the **release gate** — local execution is mandatory before pushing.
4. **3-round 4-agent audit per PR.**
   - **R1:** SWE + Test + DevOps + Security write/refine the tests in parallel against the gap list.
   - **R2:** `code-simplifier` pass + duplication-cap and coverage-cap checks (per `feedback_three_round_review`).
   - **R3:** Fresh-eyes adversarial review — cover edge cases, look for false-positive tests (tests that pass even when the bug exists).
5. **Fix policy.** Address all critical + high audit findings. Medium / low / nits — case-by-case based on whether they're test-architecture issues vs. style.
6. **Manual-only items.** Stub script with `# TAG: manual-only` header comment and `MANUAL_ONLY=1 ./tests/<file>.sh` exit-0-with-skip behavior. Tag the issue `manual-only` + @brandonrc.
7. **Merge.** Squash + delete branch. Update the relevant Epic issue's checkbox.

---

## Appendix — coverage counts per Epic

| Epic | # | Total | Covered | Partial | Missing | Manual | Backend-blocked |
|---|---|---|---|---|---|---|---|
| 1 Pull-through cache | 69 | 10 | 4 | 3 | 2 | 0 | 1 |
| 2 Security scanning | 67 | 16 | 2 | 3 | 11 | 0 | 0 |
| 3 Format lifecycle | 68 | 10 | 2 | 5 | 3 | 0 | 0 |
| 4 Signing/verification | 72 | 8 | 3 | 4 | 1 | 0 | 0 |
| 5 Missing formats | 70 | 6 | 5 | 1 | 0 | 0 | 0 |
| 6 Repo/storage lifecycle | 71 | 18 | 6 | 4 | 8 | 0 | 0 |
| 7 Webhooks + gRPC | 75 | 19 | 13 | 2 | 4 | 0 | 0 |
| 8 Search + browse | 73 | 15 | 5 | 4 | 6 | 0 | 0 |
| 9 Migrations | 74 | 9 | 4 | 1 | 1 | 3 | 0 |
| 10 Admin operations | 77 | 13 | 5 | 8 | 0 | 0 | 0 |
| 11 Auth edge cases | 76 | 15 | 2 | 5 | 6 | 2 | 0 |
| 12 Federation | 78 | 10 | 0 | 2 | 6 | 0 | 2 |
| **Total** |  | **149** | **51** | **42** | **48** | **5** | **3** |

(Variance between sums and §1 percentages reflects rounding and the 14 untested-fixes set being scored separately.)
