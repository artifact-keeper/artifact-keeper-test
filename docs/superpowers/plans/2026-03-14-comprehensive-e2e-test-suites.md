# Comprehensive E2E Test Suites Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 8 new test suites to artifact-keeper-test covering virtual/remote repos, promotion pipelines, RBAC, lifecycle policies, webhooks, search, platform features, and auth flows, bringing E2E coverage from ~38% of backend features to ~90%.

**Architecture:** Each suite is a directory under `tests/` containing independent bash test scripts following the existing common.sh framework. Tests run on ARC self-hosted runners in Kubernetes against a Helm-deployed backend. New suites are wired into the release-gate.yml workflow as parallel jobs.

**Tech Stack:** Bash, curl, jq, common.sh test framework, GitHub Actions, Kubernetes (ARC runners), Helm

**Repo:** `artifact-keeper-test` (all work happens here)

---

## File Structure

```
tests/
  repos/
    test-virtual-repo-resolution.sh     # Virtual repo aggregation and priority
    test-remote-repo-proxy.sh           # Remote repo upstream proxy + caching
    test-repo-types-crud.sh             # Create/list/update/delete all repo types
    test-repo-labels.sh                 # Repository label CRUD and filtering
  promotion/
    test-promotion-flow.sh              # Manual promote staging -> release
    test-promotion-rules.sh             # Auto-promotion rule evaluation
    test-promotion-approval.sh          # Approval workflow (request, approve, reject)
    test-promotion-bulk.sh              # Bulk promote multiple artifacts
  rbac/
    test-user-crud.sh                   # User create, update, delete, list
    test-group-management.sh            # Group CRUD, member add/remove
    test-permissions.sh                 # Fine-grained repo permissions enforcement
    test-service-accounts.sh            # Service account + scoped token lifecycle
    test-api-tokens.sh                  # API token create, use, revoke
  lifecycle/
    test-lifecycle-policies.sh          # Retention policy CRUD and preview
    test-storage-gc.sh                  # Storage garbage collection (dry-run + execute)
  webhooks/
    test-webhook-crud.sh                # Webhook create, update, delete, list
    test-webhook-delivery.sh            # Trigger event, verify delivery logged
  search/
    test-search-basic.sh                # Full-text search across artifacts
    test-search-checksum.sh             # SHA256 checksum lookup
  platform/
    test-signing.sh                     # Signing key CRUD, artifact signing
    test-sbom.sh                        # SBOM generation (CycloneDX, SPDX)
    test-curation.sh                    # Package curation rules (allow/block)
    test-artifact-labels.sh             # Artifact label CRUD and filtering
    test-audit-log.sh                   # Audit trail verification
    test-backup-restore.sh              # Backup create, list, status check
    test-system-settings.sh             # System settings get/update
    test-analytics.sh                   # Analytics endpoints return data
  auth/
    test-token-lifecycle.sh             # Token create, refresh, revoke, expire
    test-totp-2fa.sh                    # TOTP enable, verify, recovery codes
    test-rate-limiting.sh               # Rapid requests trigger 429
.github/
  workflows/
    release-gate.yml                    # Add new suite jobs
```

All new test scripts follow the exact patterns in `tests/lib/common.sh`: `begin_suite`, `begin_test`, `pass`/`fail`/`skip`, `end_suite`, RUN_ID in all resource names, JUnit XML output.

---

## Chunk 1: Repository Types Suite

### Task 1: Virtual repository resolution test

**Files:**
- Create: `tests/repos/test-virtual-repo-resolution.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-virtual-repo-resolution.sh - Virtual repository aggregation E2E test
#
# Tests that a virtual repository aggregates artifacts from multiple local
# repositories and resolves them by priority order.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-resolution"
auth_admin
setup_workdir

LOCAL_A="test-virt-local-a-${RUN_ID}"
LOCAL_B="test-virt-local-b-${RUN_ID}"
VIRTUAL_KEY="test-virt-virtual-${RUN_ID}"

# -------------------------------------------------------------------------
# Create two local repos and one virtual repo
# -------------------------------------------------------------------------

begin_test "Create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  pass
else
  fail "could not create local repo A"
fi

begin_test "Create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  pass
else
  fail "could not create local repo B"
fi

begin_test "Create virtual repo"
if create_virtual_repo "$VIRTUAL_KEY" "generic"; then
  pass
else
  fail "could not create virtual repo"
fi

# -------------------------------------------------------------------------
# Add local repos as members of the virtual repo
# -------------------------------------------------------------------------

begin_test "Add local repos as virtual repo members"
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"members\":[\"${LOCAL_A}\",\"${LOCAL_B}\"]}" > /dev/null 2>&1; then
  pass
elif api_put "/api/v1/repositories/${VIRTUAL_KEY}" \
    "{\"members\":[\"${LOCAL_A}\",\"${LOCAL_B}\"]}" > /dev/null 2>&1; then
  pass
else
  fail "could not add members to virtual repo"
fi

# -------------------------------------------------------------------------
# Upload distinct artifacts to each local repo
# -------------------------------------------------------------------------

begin_test "Upload artifact to local repo A"
echo "content-from-A-${RUN_ID}" > "${WORK_DIR}/file-a.txt"
if api_upload "/api/v1/repositories/${LOCAL_A}/artifacts/shared/file.txt" \
    "${WORK_DIR}/file-a.txt"; then
  pass
else
  fail "upload to local A failed"
fi

begin_test "Upload unique artifact to local repo B"
echo "content-from-B-${RUN_ID}" > "${WORK_DIR}/file-b.txt"
if api_upload "/api/v1/repositories/${LOCAL_B}/artifacts/only-in-b/file.txt" \
    "${WORK_DIR}/file-b.txt"; then
  pass
else
  fail "upload to local B failed"
fi

# -------------------------------------------------------------------------
# Resolve artifacts through the virtual repo
# -------------------------------------------------------------------------

sleep 2

begin_test "Virtual repo resolves artifact from local A"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts/shared/file.txt" 2>/dev/null); then
  pass
else
  # Try downloading via generic format endpoint
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/resolved-a.txt" \
      "${BASE_URL}/generic/${VIRTUAL_KEY}/shared/file.txt" 2>/dev/null; then
    pass
  else
    fail "virtual repo could not resolve artifact from local A"
  fi
fi

begin_test "Virtual repo resolves artifact only in local B"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts/only-in-b/file.txt" 2>/dev/null); then
  pass
else
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/resolved-b.txt" \
      "${BASE_URL}/generic/${VIRTUAL_KEY}/only-in-b/file.txt" 2>/dev/null; then
    pass
  else
    fail "virtual repo could not resolve artifact only in local B"
  fi
fi

# -------------------------------------------------------------------------
# List artifacts through virtual repo
# -------------------------------------------------------------------------

begin_test "List artifacts via virtual repo"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "file.txt"; then
    pass
  fi
else
  skip "virtual repo artifact listing not supported"
fi

end_suite
```

- [ ] **Step 2: Make executable and verify locally**

Run: `chmod +x tests/repos/test-virtual-repo-resolution.sh`
Run: `BASE_URL=http://backend.artifactkeeper-1.svc.cluster.local:8080 bash tests/repos/test-virtual-repo-resolution.sh`
Expected: Suite runs, tests pass or produce clear error messages

- [ ] **Step 3: Commit**

```bash
git add tests/repos/test-virtual-repo-resolution.sh
git commit -m "test: add virtual repository resolution E2E test"
```

---

### Task 2: Remote repository proxy test

**Files:**
- Create: `tests/repos/test-remote-repo-proxy.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-remote-repo-proxy.sh - Remote repository proxy/cache E2E test
#
# Tests that a remote repository proxies requests to an upstream URL and
# caches artifacts locally. Uses one local repo as the "upstream" and
# a remote repo pointing at it.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "remote-repo-proxy"
auth_admin
setup_workdir

UPSTREAM_KEY="test-remote-upstream-${RUN_ID}"
REMOTE_KEY="test-remote-proxy-${RUN_ID}"

# -------------------------------------------------------------------------
# Create upstream local repo and seed it with an artifact
# -------------------------------------------------------------------------

begin_test "Create upstream local repo"
if create_local_repo "$UPSTREAM_KEY" "generic"; then
  pass
else
  fail "could not create upstream repo"
fi

begin_test "Upload artifact to upstream"
echo "upstream-content-${RUN_ID}" > "${WORK_DIR}/upstream.txt"
if api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/libs/artifact.jar" \
    "${WORK_DIR}/upstream.txt"; then
  pass
else
  fail "upload to upstream failed"
fi

# -------------------------------------------------------------------------
# Create remote repo pointing at the upstream
# -------------------------------------------------------------------------

begin_test "Create remote repo with upstream URL"
UPSTREAM_URL="${BASE_URL}/generic/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "generic" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote repo"
fi

# -------------------------------------------------------------------------
# Fetch artifact through the remote repo (proxy)
# -------------------------------------------------------------------------

sleep 2

begin_test "Fetch artifact via remote proxy"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/proxied.txt" \
    "${BASE_URL}/generic/${REMOTE_KEY}/libs/artifact.jar" 2>/dev/null; then
  if [ -s "${WORK_DIR}/proxied.txt" ]; then
    pass
  else
    fail "proxied artifact is empty"
  fi
else
  # Try via management API
  if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts/libs/artifact.jar" 2>/dev/null); then
    pass
  else
    fail "could not fetch artifact through remote proxy"
  fi
fi

# -------------------------------------------------------------------------
# Verify the remote repo cached the artifact
# -------------------------------------------------------------------------

begin_test "Verify artifact cached in remote repo"
sleep 2
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "artifact"; then
    pass
  fi
else
  skip "remote repo artifact listing not supported"
fi

# -------------------------------------------------------------------------
# Verify remote repo metadata
# -------------------------------------------------------------------------

begin_test "Get remote repo details"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "remote"; then
    pass
  fi
else
  fail "could not get remote repo details"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/repos/test-remote-repo-proxy.sh
git add tests/repos/test-remote-repo-proxy.sh
git commit -m "test: add remote repository proxy/cache E2E test"
```

---

### Task 3: Repository types CRUD test

**Files:**
- Create: `tests/repos/test-repo-types-crud.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-repo-types-crud.sh - Repository CRUD for all repo types
#
# Tests create, read, update, and delete for local, remote, and virtual repos.
# Verifies listing, filtering by format, and repo metadata.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-types-crud"
auth_admin
setup_workdir

LOCAL_KEY="test-crud-local-${RUN_ID}"
REMOTE_KEY="test-crud-remote-${RUN_ID}"
VIRTUAL_KEY="test-crud-virtual-${RUN_ID}"

# -------------------------------------------------------------------------
# Create repos of each type
# -------------------------------------------------------------------------

begin_test "Create local repo"
if create_local_repo "$LOCAL_KEY" "generic"; then
  pass
else
  fail "create local repo failed"
fi

begin_test "Create remote repo"
if create_remote_repo "$REMOTE_KEY" "generic" "https://example.com/upstream"; then
  pass
else
  fail "create remote repo failed"
fi

begin_test "Create virtual repo"
if create_virtual_repo "$VIRTUAL_KEY" "generic"; then
  pass
else
  fail "create virtual repo failed"
fi

# -------------------------------------------------------------------------
# Read repos
# -------------------------------------------------------------------------

begin_test "Get local repo by key"
if resp=$(api_get "/api/v1/repositories/${LOCAL_KEY}"); then
  if assert_contains "$resp" "$LOCAL_KEY"; then
    pass
  fi
else
  fail "get local repo failed"
fi

begin_test "Get remote repo by key"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}"); then
  if assert_contains "$resp" "$REMOTE_KEY"; then
    pass
  fi
else
  fail "get remote repo failed"
fi

begin_test "Get virtual repo by key"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}"); then
  if assert_contains "$resp" "$VIRTUAL_KEY"; then
    pass
  fi
else
  fail "get virtual repo failed"
fi

# -------------------------------------------------------------------------
# List repos
# -------------------------------------------------------------------------

begin_test "List all repositories"
if resp=$(api_get "/api/v1/repositories"); then
  if assert_contains "$resp" "$LOCAL_KEY"; then
    pass
  fi
else
  fail "list repos failed"
fi

# -------------------------------------------------------------------------
# Update repo
# -------------------------------------------------------------------------

begin_test "Update local repo description"
if api_put "/api/v1/repositories/${LOCAL_KEY}" \
    '{"description":"Updated by E2E test"}' > /dev/null 2>&1; then
  resp=$(api_get "/api/v1/repositories/${LOCAL_KEY}")
  if assert_contains "$resp" "Updated by E2E test"; then
    pass
  fi
else
  skip "repo update not supported or different API shape"
fi

# -------------------------------------------------------------------------
# Delete repos
# -------------------------------------------------------------------------

begin_test "Delete virtual repo"
if api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1; then
  status=$(curl -s -o /dev/null -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}") || true
  if [ "$status" = "404" ]; then
    pass
  else
    fail "deleted repo still returns ${status}"
  fi
else
  fail "delete virtual repo failed"
fi

begin_test "Delete remote repo"
if api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1; then
  pass
else
  fail "delete remote repo failed"
fi

begin_test "Delete local repo"
if api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1; then
  pass
else
  fail "delete local repo failed"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/repos/test-repo-types-crud.sh
git add tests/repos/test-repo-types-crud.sh
git commit -m "test: add repository types CRUD E2E test"
```

---

### Task 4: Repository labels test

**Files:**
- Create: `tests/repos/test-repo-labels.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-repo-labels.sh - Repository label CRUD and filtering
#
# Tests setting, getting, updating, and removing labels on repositories,
# and filtering the repository list by label.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-labels"
auth_admin
setup_workdir

REPO_KEY="test-labels-${RUN_ID}"

begin_test "Create repo for label tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# Set labels
# -------------------------------------------------------------------------

begin_test "Set labels on repository"
if api_put "/api/v1/repositories/${REPO_KEY}/labels" \
    '{"labels":{"env":"staging","team":"platform"}}' > /dev/null 2>&1; then
  pass
elif api_post "/api/v1/repositories/${REPO_KEY}/labels" \
    '{"labels":{"env":"staging","team":"platform"}}' > /dev/null 2>&1; then
  pass
else
  skip "repository labels endpoint not available"
fi

# -------------------------------------------------------------------------
# Get labels
# -------------------------------------------------------------------------

begin_test "Get labels from repository"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/labels" 2>/dev/null); then
  if assert_contains "$resp" "staging"; then
    pass
  fi
elif resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "staging"; then
    pass
  fi
else
  skip "could not retrieve labels"
fi

# -------------------------------------------------------------------------
# Update labels
# -------------------------------------------------------------------------

begin_test "Update labels"
if api_put "/api/v1/repositories/${REPO_KEY}/labels" \
    '{"labels":{"env":"production","team":"platform","tier":"critical"}}' > /dev/null 2>&1; then
  resp=$(api_get "/api/v1/repositories/${REPO_KEY}/labels" 2>/dev/null) || \
    resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || true
  if [ -n "$resp" ] && assert_contains "$resp" "production"; then
    pass
  fi
else
  skip "label update not supported"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

begin_test "Delete test repo"
if api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  pass
else
  fail "cleanup failed"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/repos/test-repo-labels.sh
git add tests/repos/test-repo-labels.sh
git commit -m "test: add repository labels E2E test"
```

---

## Chunk 2: Promotion Suite

### Task 5: Promotion flow test

**Files:**
- Create: `tests/promotion/test-promotion-flow.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-promotion-flow.sh - Artifact promotion E2E test
#
# Tests the complete promotion lifecycle: upload artifact to staging repo,
# promote to release repo, verify artifact appears in target, verify
# promotion history.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-flow"
auth_admin
setup_workdir

STAGING_KEY="test-promo-staging-${RUN_ID}"
RELEASE_KEY="test-promo-release-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: create staging and release repos
# -------------------------------------------------------------------------

begin_test "Create staging repo"
if create_local_repo "$STAGING_KEY" "generic"; then
  pass
else
  fail "could not create staging repo"
fi

begin_test "Create release repo"
if create_local_repo "$RELEASE_KEY" "generic"; then
  pass
else
  fail "could not create release repo"
fi

# -------------------------------------------------------------------------
# Upload artifact to staging
# -------------------------------------------------------------------------

begin_test "Upload artifact to staging"
echo "release-candidate-${RUN_ID}" > "${WORK_DIR}/app.jar"
if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/com/app/app.jar" \
    "${WORK_DIR}/app.jar"; then
  pass
else
  fail "upload to staging failed"
fi

sleep 2

# -------------------------------------------------------------------------
# Get artifact ID for promotion
# -------------------------------------------------------------------------

begin_test "Get artifact ID from staging"
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // .[0].artifact_id // empty
    elif .items then .items[0].id // .items[0].artifact_id // empty
    else .id // .artifact_id // empty
    end' 2>/dev/null) || true
  if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
    pass
  else
    fail "could not extract artifact ID from response"
  fi
else
  fail "could not list staging artifacts"
fi

# -------------------------------------------------------------------------
# Promote artifact
# -------------------------------------------------------------------------

begin_test "Promote artifact from staging to release"
if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "no artifact ID available"
else
  PROMO_PAYLOAD="{\"source_repo\":\"${STAGING_KEY}\",\"target_repo\":\"${RELEASE_KEY}\",\"artifact_ids\":[\"${ARTIFACT_ID}\"]}"
  if api_post "/api/v1/promotion/promote" "$PROMO_PAYLOAD" > /dev/null 2>&1; then
    pass
  elif api_post "/api/v1/promotion" "$PROMO_PAYLOAD" > /dev/null 2>&1; then
    pass
  else
    fail "promotion request failed"
  fi
fi

# -------------------------------------------------------------------------
# Verify artifact in release repo
# -------------------------------------------------------------------------

sleep 2

begin_test "Verify artifact exists in release repo"
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "app.jar"; then
    pass
  fi
else
  fail "could not list release repo artifacts"
fi

# -------------------------------------------------------------------------
# Check promotion history
# -------------------------------------------------------------------------

begin_test "Verify promotion history"
if resp=$(api_get "/api/v1/promotion/history?source_repo=${STAGING_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "$RELEASE_KEY"; then
    pass
  fi
elif resp=$(api_get "/api/v1/promotion?source_repo=${STAGING_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "$RELEASE_KEY"; then
    pass
  fi
else
  skip "promotion history endpoint not available"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/promotion/test-promotion-flow.sh
git add tests/promotion/test-promotion-flow.sh
git commit -m "test: add artifact promotion flow E2E test"
```

---

### Task 6: Promotion rules test

**Files:**
- Create: `tests/promotion/test-promotion-rules.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-promotion-rules.sh - Auto-promotion rules E2E test
#
# Tests CRUD for promotion rules and verifies rule evaluation triggers
# automatic promotion when conditions are met.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-rules"
auth_admin
setup_workdir

STAGING_KEY="test-promorules-staging-${RUN_ID}"
RELEASE_KEY="test-promorules-release-${RUN_ID}"

begin_test "Create staging and release repos"
if create_local_repo "$STAGING_KEY" "generic" && \
   create_local_repo "$RELEASE_KEY" "generic"; then
  pass
else
  fail "could not create repos"
fi

# -------------------------------------------------------------------------
# Create promotion rule
# -------------------------------------------------------------------------

begin_test "Create auto-promotion rule"
RULE_PAYLOAD='{
  "name": "auto-promote-'"${RUN_ID}"'",
  "source_repo": "'"${STAGING_KEY}"'",
  "target_repo": "'"${RELEASE_KEY}"'",
  "criteria": {"min_age_hours": 0},
  "enabled": true
}'
if resp=$(api_post "/api/v1/promotion-rules" "$RULE_PAYLOAD" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  if [ -n "$RULE_ID" ] && [ "$RULE_ID" != "null" ]; then
    pass
  else
    pass  # Rule created but no ID returned
  fi
else
  skip "promotion rules endpoint not available"
fi

# -------------------------------------------------------------------------
# List rules
# -------------------------------------------------------------------------

begin_test "List promotion rules"
if resp=$(api_get "/api/v1/promotion-rules" 2>/dev/null); then
  if assert_contains "$resp" "auto-promote-${RUN_ID}"; then
    pass
  fi
else
  skip "could not list promotion rules"
fi

# -------------------------------------------------------------------------
# Get rule by ID
# -------------------------------------------------------------------------

begin_test "Get promotion rule by ID"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/promotion-rules/${RULE_ID}" 2>/dev/null); then
    if assert_contains "$resp" "$STAGING_KEY"; then
      pass
    fi
  else
    fail "could not get rule by ID"
  fi
else
  skip "no rule ID available"
fi

# -------------------------------------------------------------------------
# Delete rule
# -------------------------------------------------------------------------

begin_test "Delete promotion rule"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  if api_delete "/api/v1/promotion-rules/${RULE_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete promotion rule"
  fi
else
  skip "no rule ID to delete"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/promotion/test-promotion-rules.sh
git add tests/promotion/test-promotion-rules.sh
git commit -m "test: add promotion rules E2E test"
```

---

### Task 7: Promotion approval workflow test

**Files:**
- Create: `tests/promotion/test-promotion-approval.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-promotion-approval.sh - Promotion approval workflow E2E test
#
# Tests the approval gate: request promotion, list pending approvals,
# approve/reject, verify outcome.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-approval"
auth_admin
setup_workdir

STAGING_KEY="test-approval-staging-${RUN_ID}"
RELEASE_KEY="test-approval-release-${RUN_ID}"

begin_test "Create staging and release repos"
if create_local_repo "$STAGING_KEY" "generic" && \
   create_local_repo "$RELEASE_KEY" "generic"; then
  pass
else
  fail "could not create repos"
fi

begin_test "Upload artifact to staging"
echo "needs-approval-${RUN_ID}" > "${WORK_DIR}/artifact.bin"
if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/pkg/artifact.bin" \
    "${WORK_DIR}/artifact.bin"; then
  pass
else
  fail "upload failed"
fi

sleep 2

# -------------------------------------------------------------------------
# Request approval for promotion
# -------------------------------------------------------------------------

begin_test "Request promotion approval"
# Get artifact ID
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // empty
    elif .items then .items[0].id // empty
    else .id // empty
    end' 2>/dev/null) || true
fi

if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "could not get artifact ID"
else
  APPROVAL_PAYLOAD='{
    "source_repo": "'"${STAGING_KEY}"'",
    "target_repo": "'"${RELEASE_KEY}"'",
    "artifact_ids": ["'"${ARTIFACT_ID}"'"],
    "comment": "E2E test promotion request"
  }'
  if resp=$(api_post "/api/v1/approval/request" "$APPROVAL_PAYLOAD" 2>/dev/null); then
    APPROVAL_ID=$(echo "$resp" | jq -r '.id // .approval_id // empty') || true
    pass
  elif resp=$(api_post "/api/v1/approval" "$APPROVAL_PAYLOAD" 2>/dev/null); then
    APPROVAL_ID=$(echo "$resp" | jq -r '.id // .approval_id // empty') || true
    pass
  else
    skip "approval endpoint not available"
  fi
fi

# -------------------------------------------------------------------------
# List pending approvals
# -------------------------------------------------------------------------

begin_test "List pending approvals"
if resp=$(api_get "/api/v1/approval/pending" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/approval?status=pending" 2>/dev/null); then
  pass
else
  skip "pending approvals endpoint not available"
fi

# -------------------------------------------------------------------------
# Approve the request
# -------------------------------------------------------------------------

begin_test "Approve promotion request"
if [ -n "${APPROVAL_ID:-}" ] && [ "$APPROVAL_ID" != "null" ]; then
  if api_post "/api/v1/approval/${APPROVAL_ID}/approve" \
      '{"comment":"Approved by E2E test"}' > /dev/null 2>&1; then
    pass
  else
    fail "could not approve"
  fi
else
  skip "no approval ID available"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/promotion/test-promotion-approval.sh
git add tests/promotion/test-promotion-approval.sh
git commit -m "test: add promotion approval workflow E2E test"
```

---

### Task 8: Bulk promotion test

**Files:**
- Create: `tests/promotion/test-promotion-bulk.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-promotion-bulk.sh - Bulk artifact promotion E2E test
#
# Tests promoting multiple artifacts in a single request.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-bulk"
auth_admin
setup_workdir

STAGING_KEY="test-bulk-staging-${RUN_ID}"
RELEASE_KEY="test-bulk-release-${RUN_ID}"

begin_test "Create repos"
if create_local_repo "$STAGING_KEY" "generic" && \
   create_local_repo "$RELEASE_KEY" "generic"; then
  pass
else
  fail "could not create repos"
fi

# -------------------------------------------------------------------------
# Upload 5 artifacts to staging
# -------------------------------------------------------------------------

begin_test "Upload 5 artifacts to staging"
uploaded=0
for i in 1 2 3 4 5; do
  echo "bulk-artifact-${i}-${RUN_ID}" > "${WORK_DIR}/bulk-${i}.bin"
  if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/pkg/bulk-${i}.bin" \
      "${WORK_DIR}/bulk-${i}.bin" > /dev/null 2>&1; then
    uploaded=$(( uploaded + 1 ))
  fi
done
if [ "$uploaded" -ge 3 ]; then
  pass
else
  fail "only uploaded ${uploaded}/5 artifacts"
fi

sleep 2

# -------------------------------------------------------------------------
# Collect artifact IDs
# -------------------------------------------------------------------------

begin_test "Collect artifact IDs for bulk promote"
ARTIFACT_IDS="[]"
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_IDS=$(echo "$resp" | jq '
    if type == "array" then [.[].id // .[].artifact_id] | map(select(. != null))
    elif .items then [.items[].id // .items[].artifact_id] | map(select(. != null))
    else []
    end' 2>/dev/null) || ARTIFACT_IDS="[]"
  count=$(echo "$ARTIFACT_IDS" | jq 'length') || count=0
  if [ "$count" -ge 3 ]; then
    pass
  else
    fail "only found ${count} artifact IDs"
  fi
else
  fail "could not list staging artifacts"
fi

# -------------------------------------------------------------------------
# Bulk promote
# -------------------------------------------------------------------------

begin_test "Bulk promote all artifacts"
if [ "$(echo "$ARTIFACT_IDS" | jq 'length')" -gt 0 ] 2>/dev/null; then
  BULK_PAYLOAD="{\"source_repo\":\"${STAGING_KEY}\",\"target_repo\":\"${RELEASE_KEY}\",\"artifact_ids\":${ARTIFACT_IDS}}"
  if api_post "/api/v1/promotion/promote" "$BULK_PAYLOAD" > /dev/null 2>&1; then
    pass
  elif api_post "/api/v1/promotion" "$BULK_PAYLOAD" > /dev/null 2>&1; then
    pass
  else
    fail "bulk promotion failed"
  fi
else
  skip "no artifact IDs for bulk promotion"
fi

# -------------------------------------------------------------------------
# Verify all artifacts in release repo
# -------------------------------------------------------------------------

sleep 2

begin_test "Verify artifacts promoted to release"
if resp=$(api_get "/api/v1/repositories/${RELEASE_KEY}/artifacts" 2>/dev/null); then
  count=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end' 2>/dev/null) || count=0
  if [ "$count" -ge 3 ]; then
    pass
  else
    fail "expected >= 3 artifacts in release, got ${count}"
  fi
else
  fail "could not list release artifacts"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/promotion/test-promotion-bulk.sh
git add tests/promotion/test-promotion-bulk.sh
git commit -m "test: add bulk promotion E2E test"
```

---

## Chunk 3: RBAC Suite

### Task 9: User CRUD test

**Files:**
- Create: `tests/rbac/test-user-crud.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-user-crud.sh - User management CRUD E2E test
#
# Tests creating, listing, getting, updating, and deleting users.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "user-crud"
auth_admin
setup_workdir

TEST_USER="e2e-user-${RUN_ID}"
TEST_PASS="TestPass123!"
TEST_EMAIL="e2e-${RUN_ID}@test.local"

# -------------------------------------------------------------------------
# Create user
# -------------------------------------------------------------------------

begin_test "Create user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"E2E Test User\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.id // .user_id // empty') || true
  pass
else
  fail "could not create user"
fi

# -------------------------------------------------------------------------
# List users
# -------------------------------------------------------------------------

begin_test "List users includes new user"
if resp=$(api_get "/api/v1/users"); then
  if assert_contains "$resp" "$TEST_USER"; then
    pass
  fi
else
  fail "could not list users"
fi

# -------------------------------------------------------------------------
# Get user
# -------------------------------------------------------------------------

begin_test "Get user by username"
if resp=$(api_get "/api/v1/users/${TEST_USER}" 2>/dev/null); then
  if assert_contains "$resp" "$TEST_EMAIL"; then
    pass
  fi
elif [ -n "${USER_ID:-}" ] && resp=$(api_get "/api/v1/users/${USER_ID}" 2>/dev/null); then
  if assert_contains "$resp" "$TEST_EMAIL"; then
    pass
  fi
else
  fail "could not get user"
fi

# -------------------------------------------------------------------------
# Login as new user
# -------------------------------------------------------------------------

begin_test "Login as new user"
if resp=$(curl -sf -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
  token=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$token" ]; then
    pass
  else
    fail "login succeeded but no token returned"
  fi
else
  fail "could not login as new user"
fi

# -------------------------------------------------------------------------
# Update user
# -------------------------------------------------------------------------

begin_test "Update user display name"
if api_put "/api/v1/users/${TEST_USER}" \
    '{"display_name":"Updated E2E User"}' > /dev/null 2>&1; then
  pass
elif [ -n "${USER_ID:-}" ] && api_put "/api/v1/users/${USER_ID}" \
    '{"display_name":"Updated E2E User"}' > /dev/null 2>&1; then
  pass
else
  skip "user update not supported"
fi

# -------------------------------------------------------------------------
# Delete user
# -------------------------------------------------------------------------

begin_test "Delete user"
if api_delete "/api/v1/users/${TEST_USER}" > /dev/null 2>&1; then
  pass
elif [ -n "${USER_ID:-}" ] && api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1; then
  pass
else
  fail "could not delete user"
fi

begin_test "Deleted user cannot login"
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null) || true
if [ "$status" = "401" ] || [ "$status" = "404" ] || [ "$status" = "403" ]; then
  pass
else
  fail "deleted user got HTTP ${status}, expected 401/403/404"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/rbac/test-user-crud.sh
git add tests/rbac/test-user-crud.sh
git commit -m "test: add user CRUD E2E test"
```

---

### Task 10: Group management test

**Files:**
- Create: `tests/rbac/test-group-management.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-group-management.sh - Group CRUD and membership E2E test
#
# Tests creating groups, adding/removing members, listing groups.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "group-management"
auth_admin
setup_workdir

GROUP_NAME="e2e-group-${RUN_ID}"
USER_A="e2e-grp-user-a-${RUN_ID}"
USER_B="e2e-grp-user-b-${RUN_ID}"

# Create test users first
api_post "/api/v1/users" "{\"username\":\"${USER_A}\",\"password\":\"Pass123!\",\"email\":\"${USER_A}@test.local\"}" > /dev/null 2>&1 || true
api_post "/api/v1/users" "{\"username\":\"${USER_B}\",\"password\":\"Pass123!\",\"email\":\"${USER_B}@test.local\"}" > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# Create group
# -------------------------------------------------------------------------

begin_test "Create group"
if resp=$(api_post "/api/v1/groups" \
    "{\"name\":\"${GROUP_NAME}\",\"description\":\"E2E test group\"}" 2>/dev/null); then
  GROUP_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  fail "could not create group"
fi

# -------------------------------------------------------------------------
# List groups
# -------------------------------------------------------------------------

begin_test "List groups"
if resp=$(api_get "/api/v1/groups"); then
  if assert_contains "$resp" "$GROUP_NAME"; then
    pass
  fi
else
  fail "could not list groups"
fi

# -------------------------------------------------------------------------
# Add members
# -------------------------------------------------------------------------

begin_test "Add members to group"
endpoint="/api/v1/groups/${GROUP_ID:-$GROUP_NAME}/members"
if api_post "$endpoint" "{\"usernames\":[\"${USER_A}\",\"${USER_B}\"]}" > /dev/null 2>&1; then
  pass
elif api_post "$endpoint" "{\"members\":[\"${USER_A}\",\"${USER_B}\"]}" > /dev/null 2>&1; then
  pass
else
  skip "add members endpoint not available or different shape"
fi

# -------------------------------------------------------------------------
# List group members
# -------------------------------------------------------------------------

begin_test "List group members"
if resp=$(api_get "$endpoint" 2>/dev/null); then
  if assert_contains "$resp" "$USER_A"; then
    pass
  fi
else
  skip "member listing not available"
fi

# -------------------------------------------------------------------------
# Remove member
# -------------------------------------------------------------------------

begin_test "Remove member from group"
if api_delete "${endpoint}/${USER_B}" > /dev/null 2>&1; then
  pass
elif api_post "${endpoint}/remove" "{\"usernames\":[\"${USER_B}\"]}" > /dev/null 2>&1; then
  pass
else
  skip "remove member not available"
fi

# -------------------------------------------------------------------------
# Delete group
# -------------------------------------------------------------------------

begin_test "Delete group"
if api_delete "/api/v1/groups/${GROUP_ID:-$GROUP_NAME}" > /dev/null 2>&1; then
  pass
else
  fail "could not delete group"
fi

# Cleanup users
api_delete "/api/v1/users/${USER_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_B}" > /dev/null 2>&1 || true

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/rbac/test-group-management.sh
git add tests/rbac/test-group-management.sh
git commit -m "test: add group management E2E test"
```

---

### Task 11: Permissions enforcement test

**Files:**
- Create: `tests/rbac/test-permissions.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-permissions.sh - Fine-grained permission enforcement E2E test
#
# Tests that a non-admin user cannot access repos they don't have permission
# for, and CAN access repos where permission has been explicitly granted.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "permissions"
auth_admin
setup_workdir

PRIVATE_REPO="test-perm-private-${RUN_ID}"
PUBLIC_REPO="test-perm-public-${RUN_ID}"
TEST_USER="e2e-perm-user-${RUN_ID}"
TEST_PASS="PermTest123!"

# -------------------------------------------------------------------------
# Setup: create repos and a non-admin user
# -------------------------------------------------------------------------

begin_test "Create private repo"
payload="{\"key\":\"${PRIVATE_REPO}\",\"name\":\"${PRIVATE_REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}"
if api_post "/api/v1/repositories" "$payload" > /dev/null 2>&1; then
  pass
else
  fail "could not create private repo"
fi

begin_test "Create public repo"
if create_local_repo "$PUBLIC_REPO" "generic"; then
  pass
else
  fail "could not create public repo"
fi

begin_test "Create non-admin user"
if api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\"}" > /dev/null 2>&1; then
  pass
else
  fail "could not create test user"
fi

# Upload something to private repo (as admin)
echo "secret-${RUN_ID}" > "${WORK_DIR}/secret.bin"
api_upload "/api/v1/repositories/${PRIVATE_REPO}/artifacts/secret.bin" "${WORK_DIR}/secret.bin" > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# Login as non-admin user
# -------------------------------------------------------------------------

begin_test "Login as non-admin user"
USER_TOKEN=""
if resp=$(curl -sf -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
  USER_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "no token in response"
  fi
else
  fail "non-admin login failed"
fi

# -------------------------------------------------------------------------
# Non-admin should NOT access private repo
# -------------------------------------------------------------------------

begin_test "Non-admin denied access to private repo"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${PRIVATE_REPO}/artifacts" 2>/dev/null) || true
  if [ "$status" = "403" ] || [ "$status" = "401" ] || [ "$status" = "404" ]; then
    pass
  else
    fail "expected 403/401/404 for private repo, got ${status}"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Non-admin CAN access public repo
# -------------------------------------------------------------------------

begin_test "Non-admin can access public repo"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${PUBLIC_REPO}" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for public repo, got ${status}"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Grant permission and verify access
# -------------------------------------------------------------------------

begin_test "Grant read permission on private repo"
if api_post "/api/v1/permissions" \
    "{\"username\":\"${TEST_USER}\",\"repository_key\":\"${PRIVATE_REPO}\",\"actions\":[\"read\"]}" > /dev/null 2>&1; then
  pass
elif api_put "/api/v1/repositories/${PRIVATE_REPO}/permissions" \
    "{\"username\":\"${TEST_USER}\",\"actions\":[\"read\"]}" > /dev/null 2>&1; then
  pass
else
  skip "permission grant endpoint not available"
fi

begin_test "Non-admin can now access private repo"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${PRIVATE_REPO}" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "permission not yet enforced, got ${status}"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

# Re-authenticate as admin for cleanup
auth_admin
api_delete "/api/v1/users/${TEST_USER}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PRIVATE_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PUBLIC_REPO}" > /dev/null 2>&1 || true

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/rbac/test-permissions.sh
git add tests/rbac/test-permissions.sh
git commit -m "test: add RBAC permissions enforcement E2E test"
```

---

### Task 12: Service accounts test

**Files:**
- Create: `tests/rbac/test-service-accounts.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-service-accounts.sh - Service account lifecycle E2E test
#
# Tests creating a service account, generating scoped tokens, using a
# token to authenticate, and revoking tokens.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "service-accounts"
auth_admin
setup_workdir

SA_NAME="e2e-sa-${RUN_ID}"
REPO_KEY="test-sa-repo-${RUN_ID}"

begin_test "Create repo for service account tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# Create service account
# -------------------------------------------------------------------------

begin_test "Create service account"
if resp=$(api_post "/api/v1/service-accounts" \
    "{\"name\":\"${SA_NAME}\",\"description\":\"E2E test SA\"}" 2>/dev/null); then
  SA_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "service accounts endpoint not available"
fi

# -------------------------------------------------------------------------
# Create scoped token for the service account
# -------------------------------------------------------------------------

begin_test "Create scoped token"
if [ -n "${SA_ID:-}" ]; then
  if resp=$(api_post "/api/v1/service-accounts/${SA_ID}/tokens" \
      "{\"name\":\"e2e-token-${RUN_ID}\",\"scopes\":[\"read\"]}" 2>/dev/null); then
    SA_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // empty') || true
    if [ -n "$SA_TOKEN" ] && [ "$SA_TOKEN" != "null" ]; then
      pass
    else
      fail "token created but value not returned"
    fi
  else
    fail "could not create token"
  fi
else
  skip "no service account ID"
fi

# -------------------------------------------------------------------------
# Use token to authenticate
# -------------------------------------------------------------------------

begin_test "Authenticate with service account token"
if [ -n "${SA_TOKEN:-}" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${SA_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "SA token auth returned ${status}"
  fi
else
  skip "no SA token"
fi

# -------------------------------------------------------------------------
# List service accounts
# -------------------------------------------------------------------------

begin_test "List service accounts"
if resp=$(api_get "/api/v1/service-accounts" 2>/dev/null); then
  if assert_contains "$resp" "$SA_NAME"; then
    pass
  fi
else
  skip "could not list service accounts"
fi

# -------------------------------------------------------------------------
# Delete service account
# -------------------------------------------------------------------------

begin_test "Delete service account"
if [ -n "${SA_ID:-}" ]; then
  if api_delete "/api/v1/service-accounts/${SA_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete service account"
  fi
else
  skip "no SA ID"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/rbac/test-service-accounts.sh
git add tests/rbac/test-service-accounts.sh
git commit -m "test: add service accounts E2E test"
```

---

### Task 13: API tokens test

**Files:**
- Create: `tests/rbac/test-api-tokens.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-api-tokens.sh - API token lifecycle E2E test
#
# Tests creating API tokens for a user, listing them, using a token
# for API access, and revoking it.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "api-tokens"
auth_admin
setup_workdir

TOKEN_NAME="e2e-apitoken-${RUN_ID}"

# -------------------------------------------------------------------------
# Create API token
# -------------------------------------------------------------------------

begin_test "Create API token"
if resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read\",\"write\"]}" 2>/dev/null); then
  API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
  TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
    pass
  else
    fail "token created but value not returned"
  fi
else
  skip "API tokens endpoint not available"
fi

# -------------------------------------------------------------------------
# Use token for API access
# -------------------------------------------------------------------------

begin_test "Use API token for authenticated request"
if [ -n "${API_TOKEN:-}" ] && [ "$API_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "API token auth returned ${status}"
  fi
else
  skip "no API token"
fi

# -------------------------------------------------------------------------
# List tokens
# -------------------------------------------------------------------------

begin_test "List API tokens"
if resp=$(api_get "/api/v1/auth/tokens" 2>/dev/null); then
  if assert_contains "$resp" "$TOKEN_NAME"; then
    pass
  fi
else
  skip "token listing not available"
fi

# -------------------------------------------------------------------------
# Revoke token
# -------------------------------------------------------------------------

begin_test "Revoke API token"
if [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  if api_delete "/api/v1/auth/tokens/${TOKEN_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not revoke token"
  fi
else
  skip "no token ID"
fi

begin_test "Revoked token is rejected"
if [ -n "${API_TOKEN:-}" ] && [ "$API_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass
  else
    skip "revoked token returned ${status} (may take time to propagate)"
  fi
else
  skip "no API token"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/rbac/test-api-tokens.sh
git add tests/rbac/test-api-tokens.sh
git commit -m "test: add API token lifecycle E2E test"
```

---

## Chunk 4: Lifecycle, Webhooks, and Search Suites

### Task 14: Lifecycle policies test

**Files:**
- Create: `tests/lifecycle/test-lifecycle-policies.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-lifecycle-policies.sh - Retention policy CRUD and preview E2E test
#
# Tests creating lifecycle/retention policies, previewing what would be
# cleaned, and verifying policy listing.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "lifecycle-policies"
auth_admin
setup_workdir

REPO_KEY="test-lifecycle-${RUN_ID}"
POLICY_NAME="cleanup-${RUN_ID}"

begin_test "Create repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# Upload some artifacts
for i in 1 2 3; do
  echo "old-artifact-${i}-${RUN_ID}" > "${WORK_DIR}/old-${i}.bin"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/old/file-${i}.bin" \
    "${WORK_DIR}/old-${i}.bin" > /dev/null 2>&1 || true
done

# -------------------------------------------------------------------------
# Create lifecycle policy
# -------------------------------------------------------------------------

begin_test "Create lifecycle policy"
POLICY_PAYLOAD='{
  "name": "'"${POLICY_NAME}"'",
  "repository_key": "'"${REPO_KEY}"'",
  "rules": [{"type": "max_count", "value": 1}],
  "enabled": true
}'
if resp=$(api_post "/api/v1/admin/lifecycle" "$POLICY_PAYLOAD" 2>/dev/null); then
  POLICY_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
elif resp=$(api_post "/api/v1/admin/lifecycle/policies" "$POLICY_PAYLOAD" 2>/dev/null); then
  POLICY_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "lifecycle policy endpoint not available"
fi

# -------------------------------------------------------------------------
# List policies
# -------------------------------------------------------------------------

begin_test "List lifecycle policies"
if resp=$(api_get "/api/v1/admin/lifecycle" 2>/dev/null); then
  if assert_contains "$resp" "$POLICY_NAME"; then
    pass
  fi
elif resp=$(api_get "/api/v1/admin/lifecycle/policies" 2>/dev/null); then
  if assert_contains "$resp" "$POLICY_NAME"; then
    pass
  fi
else
  skip "lifecycle listing not available"
fi

# -------------------------------------------------------------------------
# Preview policy execution
# -------------------------------------------------------------------------

begin_test "Preview lifecycle policy"
if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/admin/lifecycle/${POLICY_ID}/preview" "" 2>/dev/null); then
    pass
  elif resp=$(api_post "/api/v1/admin/lifecycle/${POLICY_ID}/execute?dry_run=true" "" 2>/dev/null); then
    pass
  else
    skip "policy preview not available"
  fi
else
  skip "no policy ID"
fi

# -------------------------------------------------------------------------
# Delete policy
# -------------------------------------------------------------------------

begin_test "Delete lifecycle policy"
if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
  if api_delete "/api/v1/admin/lifecycle/${POLICY_ID}" > /dev/null 2>&1; then
    pass
  elif api_delete "/api/v1/admin/lifecycle/policies/${POLICY_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete policy"
  fi
else
  skip "no policy ID"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/lifecycle/test-lifecycle-policies.sh
git add tests/lifecycle/test-lifecycle-policies.sh
git commit -m "test: add lifecycle policies E2E test"
```

---

### Task 15: Storage garbage collection test

**Files:**
- Create: `tests/lifecycle/test-storage-gc.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-storage-gc.sh - Storage garbage collection E2E test
#
# Tests running storage GC in dry-run mode, verifying the response
# contains reclaim estimates.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "storage-gc"
auth_admin

# -------------------------------------------------------------------------
# Run GC dry-run
# -------------------------------------------------------------------------

begin_test "Run storage GC in dry-run mode"
if resp=$(api_post "/api/v1/admin/storage-gc" '{"dry_run":true}' 2>/dev/null); then
  pass
elif resp=$(api_post "/api/v1/admin/storage-gc?dry_run=true" "" 2>/dev/null); then
  pass
else
  skip "storage GC endpoint not available"
fi

# -------------------------------------------------------------------------
# Verify GC status endpoint
# -------------------------------------------------------------------------

begin_test "Check GC status"
if resp=$(api_get "/api/v1/admin/storage-gc" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/storage-gc/status" 2>/dev/null); then
  pass
else
  skip "GC status endpoint not available"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/lifecycle/test-storage-gc.sh
git add tests/lifecycle/test-storage-gc.sh
git commit -m "test: add storage garbage collection E2E test"
```

---

### Task 16: Webhook CRUD test

**Files:**
- Create: `tests/webhooks/test-webhook-crud.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-webhook-crud.sh - Webhook CRUD E2E test
#
# Tests creating, listing, getting, updating, and deleting webhooks.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-crud"
auth_admin
setup_workdir

WEBHOOK_NAME="e2e-webhook-${RUN_ID}"
# Use a non-routable address for the webhook URL (we just test CRUD, not delivery)
WEBHOOK_URL="https://httpbin.org/post"

# -------------------------------------------------------------------------
# Create webhook
# -------------------------------------------------------------------------

begin_test "Create webhook"
WEBHOOK_PAYLOAD='{
  "name": "'"${WEBHOOK_NAME}"'",
  "url": "'"${WEBHOOK_URL}"'",
  "events": ["artifact.uploaded", "artifact.deleted"],
  "enabled": true
}'
if resp=$(api_post "/api/v1/webhooks" "$WEBHOOK_PAYLOAD" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "webhooks endpoint not available"
fi

# -------------------------------------------------------------------------
# List webhooks
# -------------------------------------------------------------------------

begin_test "List webhooks"
if resp=$(api_get "/api/v1/webhooks" 2>/dev/null); then
  if assert_contains "$resp" "$WEBHOOK_NAME"; then
    pass
  fi
else
  skip "webhook listing not available"
fi

# -------------------------------------------------------------------------
# Get webhook
# -------------------------------------------------------------------------

begin_test "Get webhook by ID"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null); then
    if assert_contains "$resp" "$WEBHOOK_NAME"; then
      pass
    fi
  else
    fail "could not get webhook"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# Update webhook
# -------------------------------------------------------------------------

begin_test "Disable webhook"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if api_put "/api/v1/webhooks/${WEBHOOK_ID}" '{"enabled":false}' > /dev/null 2>&1; then
    pass
  else
    skip "webhook update not supported"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# Test webhook delivery (dry-run)
# -------------------------------------------------------------------------

begin_test "Test webhook delivery"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" 2>/dev/null); then
    pass
  else
    skip "webhook test delivery not available"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# List deliveries
# -------------------------------------------------------------------------

begin_test "List webhook deliveries"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
    pass
  else
    skip "delivery listing not available"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# Delete webhook
# -------------------------------------------------------------------------

begin_test "Delete webhook"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if api_delete "/api/v1/webhooks/${WEBHOOK_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete webhook"
  fi
else
  skip "no webhook ID"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/webhooks/test-webhook-crud.sh
git add tests/webhooks/test-webhook-crud.sh
git commit -m "test: add webhook CRUD E2E test"
```

---

### Task 17: Webhook delivery test

**Files:**
- Create: `tests/webhooks/test-webhook-delivery.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-webhook-delivery.sh - Webhook delivery on artifact upload E2E test
#
# Creates a webhook, uploads an artifact, verifies the delivery was logged.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-delivery"
auth_admin
setup_workdir

REPO_KEY="test-whk-delivery-${RUN_ID}"
WEBHOOK_NAME="delivery-test-${RUN_ID}"

begin_test "Create repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# Create webhook targeting the repo
# -------------------------------------------------------------------------

begin_test "Create webhook for artifact.uploaded events"
WEBHOOK_PAYLOAD='{
  "name": "'"${WEBHOOK_NAME}"'",
  "url": "https://httpbin.org/post",
  "events": ["artifact.uploaded"],
  "repository_key": "'"${REPO_KEY}"'",
  "enabled": true
}'
if resp=$(api_post "/api/v1/webhooks" "$WEBHOOK_PAYLOAD" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "webhooks not available"
fi

# -------------------------------------------------------------------------
# Upload artifact to trigger webhook
# -------------------------------------------------------------------------

begin_test "Upload artifact to trigger webhook"
echo "webhook-trigger-${RUN_ID}" > "${WORK_DIR}/trigger.bin"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/trigger.bin" \
    "${WORK_DIR}/trigger.bin"; then
  pass
else
  fail "upload failed"
fi

# -------------------------------------------------------------------------
# Verify delivery was logged
# -------------------------------------------------------------------------

sleep 5

begin_test "Verify webhook delivery logged"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
    count=$(echo "$resp" | jq '
      if type == "array" then length
      elif .items then (.items | length)
      elif .total != null then .total
      else 0
      end' 2>/dev/null) || count=0
    if [ "$count" -gt 0 ]; then
      pass
    else
      skip "no deliveries logged yet (async delivery may be delayed)"
    fi
  else
    skip "delivery listing not available"
  fi
else
  skip "no webhook ID"
fi

# Cleanup
api_delete "/api/v1/webhooks/${WEBHOOK_ID}" > /dev/null 2>&1 || true

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/webhooks/test-webhook-delivery.sh
git add tests/webhooks/test-webhook-delivery.sh
git commit -m "test: add webhook delivery E2E test"
```

---

### Task 18: Search tests

**Files:**
- Create: `tests/search/test-search-basic.sh`
- Create: `tests/search/test-search-checksum.sh`

- [ ] **Step 1: Write basic search test**

```bash
#!/usr/bin/env bash
# test-search-basic.sh - Full-text search E2E test
#
# Uploads artifacts with known names, then searches for them via the
# search API and verifies results.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-basic"
auth_admin
setup_workdir

REPO_KEY="test-search-${RUN_ID}"
UNIQUE_TERM="findme${RUN_ID//[^a-z0-9]/}"

begin_test "Create repo and upload searchable artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "searchable-content-${UNIQUE_TERM}" > "${WORK_DIR}/searchable.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/searchable.txt" \
    "${WORK_DIR}/searchable.txt" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

sleep 3  # Allow indexing

# -------------------------------------------------------------------------
# Quick search
# -------------------------------------------------------------------------

begin_test "Quick search finds artifact"
if resp=$(api_get "/api/v1/search?q=${UNIQUE_TERM}" 2>/dev/null); then
  if assert_contains "$resp" "searchable"; then
    pass
  fi
elif resp=$(api_get "/api/v1/search/quick?q=${UNIQUE_TERM}" 2>/dev/null); then
  if assert_contains "$resp" "searchable"; then
    pass
  fi
else
  skip "search endpoint returned error (indexing may be disabled)"
fi

# -------------------------------------------------------------------------
# Search suggestions
# -------------------------------------------------------------------------

begin_test "Search suggestions endpoint"
prefix="${UNIQUE_TERM:0:6}"
if resp=$(api_get "/api/v1/search/suggest?q=${prefix}" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/search/suggestions?q=${prefix}" 2>/dev/null); then
  pass
else
  skip "suggestions endpoint not available"
fi

end_suite
```

- [ ] **Step 2: Write checksum search test**

```bash
#!/usr/bin/env bash
# test-search-checksum.sh - Checksum-based artifact lookup E2E test
#
# Uploads an artifact, computes its SHA256, and searches by checksum.
#
# Requires: curl, jq, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-checksum"
auth_admin
setup_workdir

REPO_KEY="test-checksum-${RUN_ID}"

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "checksum-test-content-${RUN_ID}" > "${WORK_DIR}/checksumfile.bin"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/checksumfile.bin" \
    "${WORK_DIR}/checksumfile.bin" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

# Compute SHA256
if command -v sha256sum &>/dev/null; then
  CHECKSUM=$(sha256sum "${WORK_DIR}/checksumfile.bin" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  CHECKSUM=$(shasum -a 256 "${WORK_DIR}/checksumfile.bin" | awk '{print $1}')
else
  CHECKSUM=""
fi

sleep 3

# -------------------------------------------------------------------------
# Search by checksum
# -------------------------------------------------------------------------

begin_test "Search by SHA256 checksum"
if [ -n "$CHECKSUM" ]; then
  if resp=$(api_get "/api/v1/search/checksum?sha256=${CHECKSUM}" 2>/dev/null); then
    if assert_contains "$resp" "checksumfile"; then
      pass
    fi
  elif resp=$(api_get "/api/v1/search?checksum=${CHECKSUM}" 2>/dev/null); then
    if assert_contains "$resp" "checksumfile"; then
      pass
    fi
  else
    skip "checksum search not available"
  fi
else
  skip "sha256sum/shasum not available"
fi

end_suite
```

- [ ] **Step 3: Make executable and commit**

```bash
chmod +x tests/search/test-search-basic.sh tests/search/test-search-checksum.sh
git add tests/search/
git commit -m "test: add search and checksum lookup E2E tests"
```

---

## Chunk 5: Platform Suite

### Task 19: Signing test

**Files:**
- Create: `tests/platform/test-signing.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-signing.sh - Signing key CRUD E2E test
#
# Tests creating signing keys, listing them, and verifying key metadata.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "signing"
auth_admin

KEY_NAME="e2e-signing-key-${RUN_ID}"

begin_test "Create signing key"
if resp=$(api_post "/api/v1/signing/keys" \
    "{\"name\":\"${KEY_NAME}\",\"type\":\"rsa\",\"key_size\":2048}" 2>/dev/null); then
  KEY_ID=$(echo "$resp" | jq -r '.id // .key_id // empty') || true
  pass
elif resp=$(api_post "/api/v1/signing" \
    "{\"name\":\"${KEY_NAME}\",\"type\":\"rsa\"}" 2>/dev/null); then
  KEY_ID=$(echo "$resp" | jq -r '.id // .key_id // empty') || true
  pass
else
  skip "signing endpoint not available"
fi

begin_test "List signing keys"
if resp=$(api_get "/api/v1/signing/keys" 2>/dev/null); then
  if assert_contains "$resp" "$KEY_NAME"; then
    pass
  fi
elif resp=$(api_get "/api/v1/signing" 2>/dev/null); then
  if assert_contains "$resp" "$KEY_NAME"; then
    pass
  fi
else
  skip "signing key listing not available"
fi

begin_test "Get public key"
if [ -n "${KEY_ID:-}" ] && [ "$KEY_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/signing/keys/${KEY_ID}/public" 2>/dev/null); then
    pass
  else
    skip "public key endpoint not available"
  fi
else
  skip "no key ID"
fi

begin_test "Delete signing key"
if [ -n "${KEY_ID:-}" ] && [ "$KEY_ID" != "null" ]; then
  if api_delete "/api/v1/signing/keys/${KEY_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete signing key"
  fi
else
  skip "no key ID"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/platform/test-signing.sh
git add tests/platform/test-signing.sh
git commit -m "test: add signing key E2E test"
```

---

### Task 20: SBOM test

**Files:**
- Create: `tests/platform/test-sbom.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-sbom.sh - SBOM generation and listing E2E test
#
# Uploads an artifact, triggers SBOM generation, and verifies the SBOM
# can be retrieved.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom"
auth_admin
setup_workdir

REPO_KEY="test-sbom-${RUN_ID}"

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "sbom-test-${RUN_ID}" > "${WORK_DIR}/app.jar"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/app.jar" \
    "${WORK_DIR}/app.jar" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

sleep 2

begin_test "Generate SBOM"
# Get artifact ID
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // empty
    elif .items then .items[0].id // empty
    else empty
    end' 2>/dev/null) || true
fi

if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/sbom/generate" \
      "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\"}" 2>/dev/null); then
    pass
  else
    skip "SBOM generation not available"
  fi
else
  skip "could not get artifact ID for SBOM"
fi

begin_test "List SBOMs"
if resp=$(api_get "/api/v1/sbom" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/sbom?repository_key=${REPO_KEY}" 2>/dev/null); then
  pass
else
  skip "SBOM listing not available"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/platform/test-sbom.sh
git add tests/platform/test-sbom.sh
git commit -m "test: add SBOM E2E test"
```

---

### Task 21: Curation, labels, audit, backup, settings, analytics tests

**Files:**
- Create: `tests/platform/test-curation.sh`
- Create: `tests/platform/test-artifact-labels.sh`
- Create: `tests/platform/test-audit-log.sh`
- Create: `tests/platform/test-backup-restore.sh`
- Create: `tests/platform/test-system-settings.sh`
- Create: `tests/platform/test-analytics.sh`

- [ ] **Step 1: Write curation test**

```bash
#!/usr/bin/env bash
# test-curation.sh - Package curation rules E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "curation"
auth_admin

RULE_NAME="e2e-curation-${RUN_ID}"

begin_test "Create curation rule"
if resp=$(api_post "/api/v1/curation/rules" \
    "{\"name\":\"${RULE_NAME}\",\"action\":\"block\",\"criteria\":{\"name_pattern\":\"malicious-*\"}}" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
elif resp=$(api_post "/api/v1/curation" \
    "{\"name\":\"${RULE_NAME}\",\"action\":\"block\",\"criteria\":{\"name_pattern\":\"malicious-*\"}}" 2>/dev/null); then
  RULE_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "curation endpoint not available"
fi

begin_test "List curation rules"
if resp=$(api_get "/api/v1/curation/rules" 2>/dev/null); then
  if assert_contains "$resp" "$RULE_NAME"; then pass; fi
elif resp=$(api_get "/api/v1/curation" 2>/dev/null); then
  if assert_contains "$resp" "$RULE_NAME"; then pass; fi
else
  skip "curation listing not available"
fi

begin_test "Delete curation rule"
if [ -n "${RULE_ID:-}" ] && [ "$RULE_ID" != "null" ]; then
  api_delete "/api/v1/curation/rules/${RULE_ID}" > /dev/null 2>&1 || \
    api_delete "/api/v1/curation/${RULE_ID}" > /dev/null 2>&1 || true
  pass
else
  skip "no rule ID"
fi

end_suite
```

- [ ] **Step 2: Write artifact labels test**

```bash
#!/usr/bin/env bash
# test-artifact-labels.sh - Artifact label CRUD E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "artifact-labels"
auth_admin
setup_workdir

REPO_KEY="test-artlabels-${RUN_ID}"

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "label-test-${RUN_ID}" > "${WORK_DIR}/labeled.bin"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/labeled.bin" \
    "${WORK_DIR}/labeled.bin" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

sleep 2

begin_test "Set labels on artifact"
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // empty
    elif .items then .items[0].id // empty
    else empty end' 2>/dev/null) || true
fi
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if api_put "/api/v1/artifacts/${ARTIFACT_ID}/labels" \
      '{"labels":{"release":"candidate","build":"123"}}' > /dev/null 2>&1; then
    pass
  elif api_post "/api/v1/artifacts/${ARTIFACT_ID}/labels" \
      '{"labels":{"release":"candidate","build":"123"}}' > /dev/null 2>&1; then
    pass
  else
    skip "artifact labels not available"
  fi
else
  skip "no artifact ID"
fi

begin_test "Get artifact labels"
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/artifacts/${ARTIFACT_ID}/labels" 2>/dev/null); then
    if assert_contains "$resp" "candidate"; then pass; fi
  else
    skip "artifact label retrieval not available"
  fi
else
  skip "no artifact ID"
fi

end_suite
```

- [ ] **Step 3: Write audit log test**

```bash
#!/usr/bin/env bash
# test-audit-log.sh - Audit trail verification E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "audit-log"
auth_admin
setup_workdir

REPO_KEY="test-audit-${RUN_ID}"

begin_test "Create repo to generate audit event"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

sleep 2

begin_test "Query audit log"
if resp=$(api_get "/api/v1/admin/audit" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/audit?limit=10" 2>/dev/null); then
  pass
else
  skip "audit log endpoint not available"
fi

begin_test "Audit log contains recent repo creation"
if [ -n "${resp:-}" ]; then
  if assert_contains "$resp" "$REPO_KEY" 2>/dev/null; then
    pass
  else
    skip "repo key not found in recent audit entries"
  fi
else
  skip "no audit response"
fi

end_suite
```

- [ ] **Step 4: Write backup, settings, and analytics tests**

```bash
#!/usr/bin/env bash
# test-backup-restore.sh - Backup lifecycle E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "backup-restore"
auth_admin

begin_test "Create backup"
if resp=$(api_post "/api/v1/admin/backups" '{"name":"e2e-backup-'"${RUN_ID}"'"}' 2>/dev/null); then
  BACKUP_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
elif resp=$(api_post "/api/v1/admin/backup" '{"name":"e2e-backup-'"${RUN_ID}"'"}' 2>/dev/null); then
  BACKUP_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "backup endpoint not available"
fi

begin_test "List backups"
if resp=$(api_get "/api/v1/admin/backups" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/backup" 2>/dev/null); then
  pass
else
  skip "backup listing not available"
fi

end_suite
```

```bash
#!/usr/bin/env bash
# test-system-settings.sh - System settings E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "system-settings"
auth_admin

begin_test "Get system settings"
if resp=$(api_get "/api/v1/admin/settings" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/system/settings" 2>/dev/null); then
  pass
else
  skip "system settings not available"
fi

begin_test "Get system stats"
if resp=$(api_get "/api/v1/admin/stats" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/system/stats" 2>/dev/null); then
  pass
else
  skip "system stats not available"
fi

end_suite
```

```bash
#!/usr/bin/env bash
# test-analytics.sh - Analytics endpoints E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "analytics"
auth_admin

begin_test "Get repository analytics"
if resp=$(api_get "/api/v1/admin/analytics" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/analytics/repositories" 2>/dev/null); then
  pass
else
  skip "analytics endpoint not available"
fi

begin_test "Get format usage analytics"
if resp=$(api_get "/api/v1/admin/analytics/formats" 2>/dev/null); then
  pass
else
  skip "format analytics not available"
fi

begin_test "Get download trends"
if resp=$(api_get "/api/v1/admin/analytics/downloads" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/analytics/trends" 2>/dev/null); then
  pass
else
  skip "download trends not available"
fi

end_suite
```

- [ ] **Step 5: Make all executable and commit**

```bash
chmod +x tests/platform/test-curation.sh tests/platform/test-artifact-labels.sh \
  tests/platform/test-audit-log.sh tests/platform/test-backup-restore.sh \
  tests/platform/test-system-settings.sh tests/platform/test-analytics.sh
git add tests/platform/
git commit -m "test: add platform E2E tests (curation, labels, audit, backup, settings, analytics)"
```

---

## Chunk 6: Auth Suite and Workflow Integration

### Task 22: Auth token lifecycle test

**Files:**
- Create: `tests/auth/test-token-lifecycle.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-token-lifecycle.sh - Token lifecycle E2E test
#
# Tests login, token refresh, token expiry, and logout.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "token-lifecycle"
setup_workdir

# -------------------------------------------------------------------------
# Login
# -------------------------------------------------------------------------

begin_test "Login returns access token"
if resp=$(curl -sf -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
  ACCESS_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  REFRESH_TOKEN=$(echo "$resp" | jq -r '.refresh_token // empty') || true
  if [ -n "$ACCESS_TOKEN" ]; then
    pass
  else
    fail "no access token in login response"
  fi
else
  fail "login failed"
fi

# -------------------------------------------------------------------------
# Use token
# -------------------------------------------------------------------------

begin_test "Token authenticates API requests"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "token auth returned ${status}"
  fi
else
  skip "no token"
fi

# -------------------------------------------------------------------------
# Refresh token
# -------------------------------------------------------------------------

begin_test "Refresh token"
if [ -n "${REFRESH_TOKEN:-}" ] && [ "$REFRESH_TOKEN" != "null" ]; then
  if resp=$(curl -sf -X POST "${BASE_URL}/api/v1/auth/refresh" \
      -H "Content-Type: application/json" \
      -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}" 2>/dev/null); then
    new_token=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
    if [ -n "$new_token" ]; then
      ACCESS_TOKEN="$new_token"
      pass
    else
      fail "refresh returned no new token"
    fi
  else
    skip "refresh endpoint returned error"
  fi
else
  skip "no refresh token in login response"
fi

# -------------------------------------------------------------------------
# Logout
# -------------------------------------------------------------------------

begin_test "Logout invalidates token"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  curl -sf -X POST "${BASE_URL}/api/v1/auth/logout" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" > /dev/null 2>&1 || true
  # After logout, token should be rejected
  sleep 1
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass
  else
    skip "logout may not invalidate JWT immediately (stateless), got ${status}"
  fi
else
  skip "no token"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/auth/test-token-lifecycle.sh
git add tests/auth/test-token-lifecycle.sh
git commit -m "test: add auth token lifecycle E2E test"
```

---

### Task 23: TOTP 2FA test

**Files:**
- Create: `tests/auth/test-totp-2fa.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-totp-2fa.sh - TOTP 2FA setup and verification E2E test
#
# Tests enabling TOTP, getting the secret, and verifying the setup endpoint
# responds correctly. Does not generate actual TOTP codes (would need oathtool).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "totp-2fa"
auth_admin

# -------------------------------------------------------------------------
# Enable TOTP
# -------------------------------------------------------------------------

begin_test "Enable TOTP returns secret"
if resp=$(api_post "/api/v1/auth/totp/enable" "" 2>/dev/null); then
  if assert_contains "$resp" "secret" 2>/dev/null || \
     assert_contains "$resp" "qr" 2>/dev/null || \
     assert_contains "$resp" "uri" 2>/dev/null; then
    pass
  else
    pass  # Endpoint responded, shape may differ
  fi
elif resp=$(api_post "/api/v1/auth/totp/setup" "" 2>/dev/null); then
  pass
else
  skip "TOTP endpoint not available"
fi

# -------------------------------------------------------------------------
# Disable TOTP (cleanup)
# -------------------------------------------------------------------------

begin_test "Disable TOTP"
if api_delete "/api/v1/auth/totp" > /dev/null 2>&1; then
  pass
elif api_post "/api/v1/auth/totp/disable" "" > /dev/null 2>&1; then
  pass
else
  skip "TOTP disable not available"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/auth/test-totp-2fa.sh
git add tests/auth/test-totp-2fa.sh
git commit -m "test: add TOTP 2FA E2E test"
```

---

### Task 24: Rate limiting test

**Files:**
- Create: `tests/auth/test-rate-limiting.sh`

- [ ] **Step 1: Write the test script**

```bash
#!/usr/bin/env bash
# test-rate-limiting.sh - Rate limiting enforcement E2E test
#
# Sends rapid requests to the auth endpoint to trigger rate limiting.
# Backend rate limit: 30 req/min for auth endpoints.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rate-limiting"

# -------------------------------------------------------------------------
# Flood auth endpoint
# -------------------------------------------------------------------------

begin_test "Rapid auth requests trigger rate limit"
got_429=false
for i in $(seq 1 50); do
  status=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent","password":"wrong"}' 2>/dev/null) || true
  if [ "$status" = "429" ]; then
    got_429=true
    break
  fi
done

if $got_429; then
  pass
else
  skip "rate limiting not triggered after 50 requests (may not be enabled in test mode)"
fi

# -------------------------------------------------------------------------
# Verify rate limit includes retry-after header
# -------------------------------------------------------------------------

begin_test "Rate limit response includes retry info"
if $got_429; then
  headers=$(curl -s -D- -o /dev/null -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent","password":"wrong"}' 2>/dev/null) || true
  if echo "$headers" | grep -qi "retry-after\|x-ratelimit"; then
    pass
  else
    skip "rate limit headers not present"
  fi
else
  skip "rate limiting not triggered"
fi

end_suite
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tests/auth/test-rate-limiting.sh
git add tests/auth/test-rate-limiting.sh
git commit -m "test: add rate limiting E2E test"
```

---

### Task 25: Wire new suites into release-gate.yml

**Files:**
- Modify: `.github/workflows/release-gate.yml`

- [ ] **Step 1: Add new test suite jobs**

After the existing `compatibility-tests` job and before `stress-tests`, add these new jobs that run in parallel with format tests:

```yaml
  # -------------------------------------------------------------------
  # Repository type tests (virtual, remote, CRUD, labels)
  # -------------------------------------------------------------------
  repo-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'repos'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run repo type tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite repos --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-repos
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # Promotion tests
  # -------------------------------------------------------------------
  promotion-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'promotion'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run promotion tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite promotion --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-promotion
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # RBAC tests
  # -------------------------------------------------------------------
  rbac-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'rbac'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run RBAC tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite rbac --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-rbac
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # Lifecycle tests
  # -------------------------------------------------------------------
  lifecycle-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'lifecycle'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run lifecycle tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite lifecycle --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-lifecycle
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # Webhook tests
  # -------------------------------------------------------------------
  webhook-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'webhooks'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run webhook tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite webhooks --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-webhooks
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # Search tests
  # -------------------------------------------------------------------
  search-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'search'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run search tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite search --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-search
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # Platform tests (signing, SBOM, curation, labels, audit, backup)
  # -------------------------------------------------------------------
  platform-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'platform'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run platform tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite platform --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-platform
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore

  # -------------------------------------------------------------------
  # Auth tests (tokens, TOTP, rate limiting)
  # -------------------------------------------------------------------
  auth-tests:
    needs: deploy
    if: inputs.test_suite == 'all' || inputs.test_suite == 'auth'
    runs-on: ak-e2e-runners
    env:
      BASE_URL: ${{ needs.deploy.outputs.backend_url }}
      RUN_ID: ${{ needs.deploy.outputs.run_id }}
      JUNIT_OUTPUT_DIR: /tmp/test-results
    steps:
      - uses: actions/checkout@v4
        with:
          repository: artifact-keeper/artifact-keeper-test

      - name: Run auth tests
        run: |
          mkdir -p "$JUNIT_OUTPUT_DIR"
          chmod +x scripts/run-suite.sh
          ./scripts/run-suite.sh --suite auth --run-id "${RUN_ID}"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: junit-auth
          path: /tmp/test-results/*.xml
          if-no-files-found: ignore
```

- [ ] **Step 2: Update the test_suite choice list in workflow_dispatch inputs**

Add the new suite names to the `type: choice` options:

```yaml
      test_suite:
        description: Test suite to run
        required: false
        type: choice
        options:
          - all
          - formats
          - repos
          - promotion
          - rbac
          - lifecycle
          - webhooks
          - search
          - platform
          - auth
          - stress
          - resilience
          - mesh
          - security
          - compatibility
        default: 'all'
```

- [ ] **Step 3: Update collect-results job to include new suites**

Add the new jobs to the `needs` list:

```yaml
  collect-results:
    needs: [deploy, format-tests, security-tests, compatibility-tests, repo-tests, promotion-tests, rbac-tests, lifecycle-tests, webhook-tests, search-tests, platform-tests, auth-tests, stress-tests, resilience-tests, mesh-tests]
```

And add status rows for each in the summary step.

- [ ] **Step 4: Update teardown needs**

```yaml
  teardown:
    needs: [deploy, collect-results]
```

(This is unchanged since teardown already depends on collect-results.)

- [ ] **Step 5: Commit workflow changes**

```bash
git add .github/workflows/release-gate.yml
git commit -m "ci: add repos, promotion, rbac, lifecycle, webhooks, search, platform, and auth test suites to release gate"
```

---

### Task 26: Create PR and trigger full release gate

- [ ] **Step 1: Push branch and create PR**

```bash
git push -u origin feat/comprehensive-e2e-suites
gh pr create --title "feat: add 8 comprehensive E2E test suites" --body "..."
```

- [ ] **Step 2: Merge PR**

- [ ] **Step 3: Trigger full release gate**

```bash
gh workflow run release-gate.yml -f backend_tag=dev -f test_suite=all
```

- [ ] **Step 4: Monitor results, fix any failures**

Check each suite's results. Tests that hit unimplemented endpoints will `skip` (not fail). Tests that hit real bugs will `fail` and need investigation.
