# Tier 3: Advertised Feature Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every feature advertised in Artifact Keeper documentation has meaningful tests that exercise actual behavior, not just API surface availability.

**Architecture:** 21 items enhancing or creating tests in `artifact-keeper-test/`. Most tasks modify existing test scripts to add deeper assertions. Some create new test scripts for previously untested features. All follow the common.sh test framework pattern.

**Tech Stack:** Bash, curl, jq, common.sh test framework

**Spec:** `docs/superpowers/specs/2026-03-20-release-gate-organization-design.md` (Tier 3 section)

**Depends on:** Tier 1 (foundation) and Tier 2 (security) must be complete

---

## File Structure

### Modified files (deepening existing tests)
- `tests/formats/test-ansible.sh`, `test-chef.sh`, `test-composer.sh`, `test-hex.sh`, `test-puppet.sh`, `test-cocoapods.sh`, `test-conan.sh`, `test-cran.sh`, `test-nuget.sh`, `test-rubygems.sh`, `test-terraform.sh` - Add download, delete, version tests
- `tests/formats/` remaining 19 format tests - Add delete and version tests where missing
- `tests/platform/test-backup-restore.sh` - Full rewrite with data integrity verification
- `tests/platform/test-signing.sh` - Add actual signing operations
- `tests/platform/test-sbom.sh` - Add structural validation
- `tests/lifecycle/test-lifecycle-policies.sh` - Add execution and verification
- `tests/security/test-quality-gate-enforcement.sh` - Add actual blocking behavior
- `tests/webhooks/test-webhook-delivery.sh` - Fix skip-on-failure, add payload checks
- `tests/platform/test-analytics.sh` - Expand to cover 3 of 7 endpoints
- `tests/search/test-search-basic.sh` - Add advanced search, trending, recent
- `tests/platform/test-curation.sh` - Add enforcement verification
- `tests/auth/test-totp-2fa.sh` - Full enable/verify/disable flow
- `tests/platform/test-audit-log.sh` - Rewrite with actual assertions

### New files
- `tests/platform/test-builds.sh` - Builds API
- `tests/platform/test-packages.sh` - Packages API
- `tests/platform/test-wasm-plugins.sh` - WASM plugin lifecycle (migrated + adapted)
- `tests/security/test-security-scanning.sh` - Scan trigger, findings, dashboard
- `tests/resilience/restart/test-meilisearch-restart.sh` - Meilisearch resilience
- `tests/rbac/test-role-management.sh` - Role assignment/revocation
- `tests/rbac/test-group-membership.sh` - Group CRUD and membership
- `tests/auth/test-sso-admin.sh` - SSO provider CRUD

---

## Tasks

### Task 1: T3-01 - Deepen 11 shallow format tests

**Files:**
- Modify: 11 format test scripts in `tests/formats/`

- [ ] **Step 1: Identify the 11 shallow format tests**

These are the tests with only 4-5 tests (no download, delete, or versioning):
`test-ansible.sh`, `test-chef.sh`, `test-composer.sh`, `test-hex.sh`, `test-puppet.sh`, `test-cocoapods.sh`, `test-conan.sh`, `test-cran.sh`, `test-nuget.sh`, `test-rubygems.sh`, `test-terraform.sh`

- [ ] **Step 2: Add 3 tests to each shallow format test**

For each, append before `end_suite`:

```bash
begin_test "Download uploaded artifact"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/download.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/download.bin" | awk '{print $1}')
  ORIG_SHA=$(shasum -a 256 "${WORK_DIR}/upload.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$ORIG_SHA" "checksum mismatch"; then
    pass
  fi
else
  fail "download failed"
fi

begin_test "Upload second version"
# Create a slightly different artifact for v2
echo "version-2-${RUN_ID}" > "${WORK_DIR}/v2.txt"
# Upload using the format-specific method with a new version
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${V2_PATH}" "${WORK_DIR}/v2.txt"; then
  pass
else
  fail "v2 upload failed"
fi

begin_test "Delete artifact"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  # Verify it's gone
  get_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>&1) || true
  if [ "$get_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete, got ${get_status}"
  fi
else
  fail "delete returned ${status}"
fi
```

Adapt the paths and upload methods for each format's specific API structure.

- [ ] **Step 3: Also check remaining 19 format tests for missing delete/version tests**

For format tests that already have download but lack delete or version tests, add those.

- [ ] **Step 4: Run one test locally to verify the pattern works**

```bash
bash tests/formats/test-npm.sh
```

- [ ] **Step 5: Commit**

```bash
git add tests/formats/
git commit -m "test(formats): deepen all format tests with download verification, delete, and versioning"
```

---

### Task 2: T3-02 - Backup & restore with data integrity verification

**Files:**
- Modify: `tests/platform/test-backup-restore.sh`

- [ ] **Step 1: Rewrite the test**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "platform-backup-restore"
auth_admin
setup_workdir

REPO_KEY="backup-test-${RUN_ID}"

begin_test "Create test repo"
if create_local_repo "$REPO_KEY" "generic"; then pass; else fail "create repo failed"; fi

begin_test "Upload artifacts with known checksums"
for i in 1 2 3; do
  dd if=/dev/urandom bs=1024 count=$((i * 10)) of="${WORK_DIR}/artifact-${i}.bin" 2>/dev/null
  eval "SHA_${i}=$(shasum -a 256 "${WORK_DIR}/artifact-${i}.bin" | awk '{print $1}')"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/file-${i}.bin" "${WORK_DIR}/artifact-${i}.bin" "application/octet-stream" > /dev/null
done
pass

begin_test "Create backup"
resp=$(api_post "/api/v1/admin/backups" '{"type":"full"}')
BACKUP_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$BACKUP_ID" ]; then pass; else skip "backup API not available"; fi

begin_test "Wait for backup completion"
elapsed=0
while [ "$elapsed" -lt 60 ]; do
  status_resp=$(api_get "/api/v1/admin/backups/${BACKUP_ID}")
  backup_status=$(echo "$status_resp" | jq -r '.status // empty')
  if [ "$backup_status" = "completed" ]; then break; fi
  sleep 3
  elapsed=$((elapsed + 3))
done
if [ "$backup_status" = "completed" ]; then pass; else fail "backup did not complete in 60s"; fi

begin_test "Delete all artifacts"
for i in 1 2 3; do
  curl -sf -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/file-${i}.bin" > /dev/null 2>&1 || true
done
# Verify deletion
status=$(curl -s -o /dev/null -w "%{http_code}" -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/file-1.bin" 2>&1) || true
if [ "$status" = "404" ]; then pass; else fail "artifacts not deleted"; fi

begin_test "Restore from backup"
resp=$(api_post "/api/v1/admin/backups/${BACKUP_ID}/restore" '{}')
restore_status=$(echo "$resp" | jq -r '.status // empty')
if [ -n "$restore_status" ]; then pass; else fail "restore failed"; fi

begin_test "Wait for restore completion"
elapsed=0
while [ "$elapsed" -lt 60 ]; do
  sleep 3
  elapsed=$((elapsed + 3))
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/file-1.bin" 2>&1) || true
  if [ "$status" = "200" ]; then break; fi
done
if [ "$status" = "200" ]; then pass; else fail "artifacts not restored in 60s"; fi

begin_test "Verify restored data integrity"
ALL_MATCH=true
for i in 1 2 3; do
  curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/restored-${i}.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/file-${i}.bin" 2>&1 || true
  RESTORED_SHA=$(shasum -a 256 "${WORK_DIR}/restored-${i}.bin" | awk '{print $1}')
  eval "ORIG_SHA=\$SHA_${i}"
  if [ "$RESTORED_SHA" != "$ORIG_SHA" ]; then
    ALL_MATCH=false
    fail "checksum mismatch for file-${i}.bin: expected ${ORIG_SHA}, got ${RESTORED_SHA}"
  fi
done
if [ "$ALL_MATCH" = true ]; then pass; fi

end_suite
```

- [ ] **Step 2: Commit**

```bash
git add tests/platform/test-backup-restore.sh
git commit -m "test(platform): rewrite backup/restore test with full data integrity verification"
```

---

### Task 3: T3-03 - SSO admin CRUD tests

**Files:**
- Create: `tests/auth/test-sso-admin.sh`

- [ ] **Step 1: Write SSO admin CRUD test**

Test OIDC, LDAP, and SAML provider create/list/update/delete through the admin API. These don't require a running IdP since they test configuration management.

- [ ] **Step 2: Commit**

---

### Task 4: T3-04 - RBAC role management and group membership

**Files:**
- Create: `tests/rbac/test-role-management.sh`
- Create: `tests/rbac/test-group-membership.sh`

- [ ] **Step 1: Write role management test**

Assign admin role to user, verify admin access. Revoke role, verify access denied.

- [ ] **Step 2: Write group membership test**

Create group, add members, verify group permissions apply. Remove member, verify access revoked.

- [ ] **Step 3: Commit each**

---

### Task 5: T3-05 - Signing operations test

**Files:**
- Modify: `tests/platform/test-signing.sh`

- [ ] **Step 1: Extend signing test with actual operations**

After key creation, add:
- Configure repo to use the signing key
- Upload an artifact
- Retrieve the signature/public key
- Verify the signature is valid (if possible with available tools)
- Delete the key and verify signing stops

- [ ] **Step 2: Commit**

---

### Task 6: T3-06 - Curation enforcement test

**Files:**
- Modify: `tests/platform/test-curation.sh`

- [ ] **Step 1: Add enforcement verification**

After creating the block rule for "malicious-*", attempt to download a package matching that pattern and assert it is blocked (403 or 451). Also verify non-matching packages still work.

- [ ] **Step 2: Commit**

---

### Task 7: T3-07 - Lifecycle policy execution test

**Files:**
- Modify: `tests/lifecycle/test-lifecycle-policies.sh`

- [ ] **Step 1: Add actual execution and verification**

```bash
begin_test "Upload 5 versions"
for i in 1 2 3 4 5; do
  echo "version-${i}-${RUN_ID}" > "${WORK_DIR}/v${i}.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/pkg/v${i}/file.txt" \
    "${WORK_DIR}/v${i}.txt" "application/octet-stream" > /dev/null
done
pass

begin_test "Execute lifecycle policy"
resp=$(api_post "/api/v1/admin/lifecycle-policies/${POLICY_ID}/execute" '{}')
if [ $? -eq 0 ]; then pass; else fail "execution failed"; fi

begin_test "Wait for cleanup and verify only 2 versions remain"
sleep 5
resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts")
count=$(echo "$resp" | jq '[.[] | select(.path | contains("pkg/v"))] | length' 2>/dev/null || echo "0")
if assert_eq "$count" "2" "expected 2 versions after cleanup"; then
  pass
fi
```

- [ ] **Step 2: Commit**

---

### Task 8: T3-08 - Quality gate blocking test

**Files:**
- Modify: `tests/security/test-quality-gate-enforcement.sh`

- [ ] **Step 1: Add actual gate failure test**

After creating a quality gate, trigger a scan that produces findings exceeding the threshold. Evaluate the gate and verify it returns a "failed" status.

- [ ] **Step 2: Commit**

---

### Task 9: T3-09 - Promotion full flow including rejection

**Files:**
- Modify: `tests/promotion/test-promotion-flow.sh` or `test-approval-workflow.sh`

- [ ] **Step 1: Add rejection test**

Submit an approval request, reject it, verify the artifact is NOT promoted and the rejection appears in history.

- [ ] **Step 2: Add invalid promotion test**

Attempt to promote to a non-existent repo (assert 404), to a wrong-format repo (assert 400).

- [ ] **Step 3: Commit**

---

### Task 10: T3-10 - Search advanced features

**Files:**
- Modify: `tests/search/test-search-basic.sh`

- [ ] **Step 1: Add advanced search test**

```bash
begin_test "Advanced search with format filter"
resp=$(api_get "/api/v1/search/advanced?q=${PKG_NAME}&format=generic")
if assert_contains "$resp" "$PKG_NAME"; then pass; else fail "advanced search returned no results"; fi

begin_test "Trending artifacts"
resp=$(api_get "/api/v1/search/trending")
if [ $? -eq 0 ]; then pass; else skip "trending endpoint not available"; fi

begin_test "Recent artifacts"
resp=$(api_get "/api/v1/search/recent")
if assert_contains "$resp" "$PKG_NAME"; then pass; else fail "recently uploaded artifact not in recent"; fi
```

- [ ] **Step 2: Change skip-on-error to fail-on-error for search tests**

- [ ] **Step 3: Commit**

---

### Task 11: T3-11 - Webhook delivery assertions

**Files:**
- Modify: `tests/webhooks/test-webhook-delivery.sh`

- [ ] **Step 1: Change skip to fail for zero deliveries**

- [ ] **Step 2: Add payload content verification**

After receiving a delivery, check that the payload contains the artifact ID and event type.

- [ ] **Step 3: Commit**

---

### Task 12: T3-12 - Mesh replication assertions

**Files:**
- Modify: `tests/mesh/test-*.sh` (all 5 mesh test scripts)

- [ ] **Step 1: Strengthen assertions in each mesh test**

Replace weak assertions (status code only) with content verification: verify artifact checksums match across peers, verify sync timestamps are populated, verify heartbeat contains expected fields.

- [ ] **Step 2: Commit**

---

### Task 13: T3-13 - WASM plugin lifecycle (migration)

**Files:**
- Create: `tests/platform/test-wasm-plugins.sh`

- [ ] **Step 1: Migrate and adapt from backend repo**

Adapt the 4 WASM plugin test scripts from `artifact-keeper/scripts/native-tests/test-wasm-plugin*.sh` into a single comprehensive test in the common.sh framework.

- [ ] **Step 2: Commit**

---

### Task 14: T3-14 - Security scanning dashboard and findings

**Files:**
- Create: `tests/security/test-security-scanning.sh`

- [ ] **Step 1: Write security scanning test**

Test scan trigger, findings listing, finding acknowledgment, and security dashboard endpoint.

- [ ] **Step 2: Commit**

---

### Task 15: T3-15 - Analytics expansion

**Files:**
- Modify: `tests/platform/test-analytics.sh`

- [ ] **Step 1: Add storage breakdown, download trends, growth summary tests**

For each endpoint, verify the response contains expected JSON structure (not just 200 status).

- [ ] **Step 2: Commit**

---

### Task 16: T3-16 + T3-17 - Builds API and Packages API

**Files:**
- Create: `tests/platform/test-builds.sh`
- Create: `tests/platform/test-packages.sh`

- [ ] **Step 1: Write builds test**

Create build, add artifacts, list builds, get build by ID, verify build diff.

- [ ] **Step 2: Write packages test**

Upload to multiple repos, query packages API, verify cross-repo aggregation.

- [ ] **Step 3: Commit each**

---

### Task 17: T3-18 - TOTP 2FA full flow

**Files:**
- Modify: `tests/auth/test-totp-2fa.sh`

- [ ] **Step 1: Rewrite with full flow**

Setup TOTP, extract secret, enable, login requiring TOTP code (use oathtool if available), verify invalid code rejected, disable TOTP, verify login works without code again.

- [ ] **Step 2: Commit**

---

### Task 18: T3-19 - Meilisearch resilience

**Files:**
- Create: `tests/resilience/restart/test-meilisearch-restart.sh`

- [ ] **Step 1: Write the test**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../../lib/common.sh"

begin_suite "resilience-meilisearch-restart"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="meili-test-${RUN_ID}"

begin_test "Create repo and upload baseline"
create_local_repo "$REPO_KEY" "generic"
echo "searchable-content-${RUN_ID}" > "${WORK_DIR}/test.txt"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/search-test.txt" "${WORK_DIR}/test.txt" > /dev/null
pass

begin_test "Verify search works before kill"
sleep 3  # Allow indexing
resp=$(api_get "/api/v1/search?q=searchable-content-${RUN_ID}")
if assert_contains "$resp" "search-test"; then pass; else skip "search not returning results yet"; fi

begin_test "Kill Meilisearch pod"
kubectl delete pod -l app.kubernetes.io/name=meilisearch -n "${NAMESPACE}" --force 2>&1 || true
pass

begin_test "Verify uploads still work without Meilisearch"
echo "uploaded-during-outage-${RUN_ID}" > "${WORK_DIR}/during-outage.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/outage-test.txt" "${WORK_DIR}/during-outage.txt" > /dev/null; then
  pass
else
  fail "uploads failed when Meilisearch is down"
fi

begin_test "Wait for Meilisearch recovery"
elapsed=0
meili_ready=false
while [ "$elapsed" -lt 90 ]; do
  ready=$(kubectl get pods -l app.kubernetes.io/name=meilisearch \
    -n "${NAMESPACE}" -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" = "true" ]; then meili_ready=true; break; fi
  sleep 5
  elapsed=$((elapsed + 5))
done
if [ "$meili_ready" = true ]; then pass; else fail "Meilisearch did not recover in 90s"; fi

begin_test "Verify search recovers"
sleep 10  # Allow reindex
resp=$(api_get "/api/v1/search?q=searchable-content-${RUN_ID}")
if assert_contains "$resp" "search-test"; then
  pass
else
  fail "search did not recover after Meilisearch restart"
fi

end_suite
```

- [ ] **Step 2: Commit**

```bash
git add tests/resilience/restart/test-meilisearch-restart.sh
git commit -m "test(resilience): add Meilisearch restart test - uploads work during outage, search recovers"
```

---

### Task 19: T3-20 - Audit logging verification

**Files:**
- Modify: `tests/platform/test-audit-log.sh`

- [ ] **Step 1: Rewrite with actual assertions**

Remove the skip. Perform actions (login, create user, upload artifact), then query the audit log endpoint and verify entries exist.

- [ ] **Step 2: Commit**

---

### Task 20: T3-21 - SBOM structural validation

**Files:**
- Modify: `tests/platform/test-sbom.sh`

- [ ] **Step 1: Add structural validation**

After generating SBOM, fetch it and verify:
- `bomFormat` equals "CycloneDX"
- `specVersion` is present
- `components` array exists and has entries

- [ ] **Step 2: Commit**

---

### Task 21: Update release-gate.yml with all new/modified jobs

**Files:**
- Modify: `.github/workflows/release-gate.yml`

- [ ] **Step 1: Verify all new test files are discovered by their respective suite runners**

Check that `run-suite.sh` globs include all new files in their subdirectories.

- [ ] **Step 2: Add any new suite jobs if needed**

If new suites were created (e.g., `tests/platform/builds/`), add corresponding jobs.

- [ ] **Step 3: Add the new resilience test to the resilience matrix**

Ensure `test-meilisearch-restart.sh` is picked up by the restart category.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release-gate.yml
git commit -m "ci(release-gate): add all Tier 3 test scripts to workflow"
```
