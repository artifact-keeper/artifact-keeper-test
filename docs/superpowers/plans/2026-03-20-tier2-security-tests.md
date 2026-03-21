# Tier 2: Security Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure no exploitable vulnerability ships in 1.1.0 by migrating the red team suite and writing 22 new security/auth/RBAC tests.

**Architecture:** All tests written in `artifact-keeper-test/` following existing `common.sh` patterns. Red team scripts migrated from `artifact-keeper/scripts/redteam/` and adapted to use the common.sh framework. New security tests focus on access control, injection, supply chain, and authentication.

**Tech Stack:** Bash, curl, jq, common.sh test framework

**Spec:** `docs/superpowers/specs/2026-03-20-release-gate-organization-design.md` (Tier 2 section)

**Depends on:** Tier 1 must be complete (CI fixes ensure failures are not swallowed)

---

## File Structure

### New files
- `tests/security/redteam/lib.sh` - Migrated red team helpers (adapted for common.sh)
- `tests/security/redteam/test-01-recon.sh` through `test-15-metrics-auth.sh` - 15 migrated scripts
- `tests/security/redteam/payloads/` - Migrated payload files
- `tests/rbac/test-idor.sh` - T2-02: Cross-user resource access
- `tests/rbac/test-privilege-escalation.sh` - T2-03: Non-admin to admin
- `tests/rbac/test-admin-protection.sh` - T2-04: Admin endpoint systematic check
- `tests/rbac/test-scope-enforcement.sh` - T2-05: Token scope enforcement
- `tests/auth/test-jwt-manipulation.sh` - T2-06: JWT algorithm confusion
- `tests/security/test-dependency-confusion.sh` - T2-07: Virtual repo namespace shadowing
- `tests/security/test-artifact-integrity.sh` - T2-08: Checksum enforcement
- `tests/security/test-decompression-bomb.sh` - T2-09: Archive bomb protection
- `tests/security/test-wasm-sandbox.sh` - T2-10: WASM resource limits
- `tests/security/test-cache-poisoning.sh` - T2-11: Proxy checksum verification
- `tests/security/test-ssrf-prevention.sh` - T2-12: SSRF across all vectors
- `tests/security/test-default-credentials.sh` - T2-13: Default cred rejection
- `tests/security/test-path-traversal.sh` - T2-14: Path traversal payloads
- `tests/security/test-sql-injection.sh` - T2-15: SQL injection payloads
- `tests/security/test-grpc-security.sh` - T2-16: gRPC reflection + auth
- `tests/auth/test-token-expiry.sh` - T2-17: Expired token rejection
- `tests/auth/test-token-revocation.sh` - T2-18: Revoked token rejection
- `tests/security/test-mesh-peer-auth.sh` - T2-19: Rogue peer rejection
- `tests/security/test-stored-xss.sh` - T2-20: XSS in artifact metadata
- `tests/security/test-xxe-prevention.sh` - T2-21: XXE in Maven POM / NuGet nuspec
- `tests/security/test-upload-race.sh` - T2-22: TOCTOU concurrent upload
- `tests/auth/test-session-invalidation.sh` - T2-23: Session invalidation after password change

### Modified files
- `.github/workflows/release-gate.yml` - Add security/redteam job

---

## Tasks

### Task 1: T2-01 - Migrate red team suite (15 scripts)

**Files:**
- Create: `tests/security/redteam/` directory
- Copy from: `../artifact-keeper/scripts/redteam/`

- [ ] **Step 1: Create redteam directory structure**

```bash
mkdir -p tests/security/redteam/payloads
```

- [ ] **Step 2: Copy red team scripts and payloads**

```bash
cp ../artifact-keeper/scripts/redteam/tests/*.sh tests/security/redteam/
cp ../artifact-keeper/scripts/redteam/lib.sh tests/security/redteam/
cp -r ../artifact-keeper/scripts/redteam/payloads/* tests/security/redteam/payloads/
```

- [ ] **Step 3: Adapt lib.sh for common.sh compatibility**

The red team lib.sh uses its own `pass`/`fail`/`api_call` functions. Adapt to source common.sh as well, or keep the red team lib standalone but update env var defaults to match the test infrastructure:

```bash
# In tests/security/redteam/lib.sh, update defaults:
REGISTRY_URL="${BASE_URL:-http://localhost:8080}"  # Use BASE_URL from common.sh
```

- [ ] **Step 4: Update script source paths**

Each script sources `../../lib.sh`. Update to source from the new location:

```bash
# Change from:
source "$(dirname "$0")/../lib.sh"
# To:
source "$(dirname "$0")/lib.sh"
```

- [ ] **Step 5: Test one script locally**

Run: `BASE_URL=http://localhost:8080 bash tests/security/redteam/test-04-auth-bypass.sh`
Expected: Script runs and produces PASS/FAIL output

- [ ] **Step 6: Add redteam job to release-gate.yml**

Add a new job in the workflow:

```yaml
redteam-tests:
  name: Red Team Security Tests
  needs: [deploy]
  runs-on: [self-hosted, ak-e2e-runners]
  steps:
    - uses: actions/checkout@v4
    - name: Run red team tests
      env:
        BASE_URL: http://artifact-keeper-backend.${{ needs.deploy.outputs.namespace }}.svc.cluster.local:8080
        ADMIN_USER: admin
        ADMIN_PASS: ${{ secrets.TEST_ADMIN_PASS }}
      run: |
        FAILED=0
        for script in tests/security/redteam/test-*.sh; do
          [ -f "$script" ] || continue
          echo "=== Running ${script} ==="
          if ! bash "$script"; then
            FAILED=$((FAILED + 1))
          fi
        done
        if [ "$FAILED" -gt 0 ]; then
          echo "::error::${FAILED} red team test(s) failed"
          exit 1
        fi
```

- [ ] **Step 7: Commit**

```bash
git add tests/security/redteam/ .github/workflows/release-gate.yml
git commit -m "feat(security): migrate 15 red team scripts to release gate

Migrated from artifact-keeper/scripts/redteam/ and adapted for the
artifact-keeper-test framework. Covers: auth bypass, path traversal,
SQL injection, SSRF, CORS, default credentials, gRPC unauth,
information disclosure, metrics auth, OCI DoS, WASM plugin security,
and API key exposure."
```

---

### Task 2: T2-02 - IDOR cross-user resource access test

**Files:**
- Create: `tests/rbac/test-idor.sh`

- [ ] **Step 1: Write the test**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rbac-idor"
auth_admin
setup_workdir

USER_A="idor-user-a-${RUN_ID}"
USER_B="idor-user-b-${RUN_ID}"
PASSWORD="TestPass123!"

# Create two users
begin_test "Create User A"
resp=$(api_post "/api/v1/users" "{\"username\":\"${USER_A}\",\"password\":\"${PASSWORD}\",\"email\":\"a@test.com\"}")
USER_A_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$USER_A_ID" ]; then pass; else fail "could not create User A"; fi

begin_test "Create User B"
resp=$(api_post "/api/v1/users" "{\"username\":\"${USER_B}\",\"password\":\"${PASSWORD}\",\"email\":\"b@test.com\"}")
USER_B_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$USER_B_ID" ]; then pass; else fail "could not create User B"; fi

# Login as User A
begin_test "Login as User A"
login_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
  -d "{\"username\":\"${USER_A}\",\"password\":\"${PASSWORD}\"}" \
  "${BASE_URL}/api/v1/auth/login" 2>&1) || true
TOKEN_A=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
if [ -n "$TOKEN_A" ]; then pass; else fail "User A login failed"; fi

# User A tries to access User B's resources
begin_test "User A cannot access User B's tokens"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  "${BASE_URL}/api/v1/users/${USER_B_ID}/tokens" 2>&1) || true
if [ "$status" = "403" ]; then
  pass
else
  fail "expected 403, got ${status}"
fi

begin_test "User A cannot modify User B's profile"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PATCH -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com"}' \
  "${BASE_URL}/api/v1/users/${USER_B_ID}" 2>&1) || true
if [ "$status" = "403" ]; then
  pass
else
  fail "expected 403, got ${status}"
fi

begin_test "User A cannot delete User B"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "Authorization: Bearer ${TOKEN_A}" \
  "${BASE_URL}/api/v1/users/${USER_B_ID}" 2>&1) || true
if [ "$status" = "403" ]; then
  pass
else
  fail "expected 403, got ${status}"
fi

end_suite
```

- [ ] **Step 2: Commit**

```bash
git add tests/rbac/test-idor.sh
git commit -m "test(rbac): add IDOR test - User A cannot access User B's resources"
```

---

### Task 3: T2-03 - Privilege escalation test

**Files:**
- Create: `tests/rbac/test-privilege-escalation.sh`

- [ ] **Step 1: Write the test**

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rbac-privilege-escalation"
auth_admin
setup_workdir

USER="privesc-user-${RUN_ID}"
PASSWORD="TestPass123!"

begin_test "Create non-admin user"
resp=$(api_post "/api/v1/users" "{\"username\":\"${USER}\",\"password\":\"${PASSWORD}\",\"email\":\"privesc@test.com\"}")
USER_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$USER_ID" ]; then pass; else fail "could not create user"; fi

begin_test "Login as non-admin"
login_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
  -d "{\"username\":\"${USER}\",\"password\":\"${PASSWORD}\"}" \
  "${BASE_URL}/api/v1/auth/login" 2>&1) || true
USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
if [ -n "$USER_TOKEN" ]; then pass; else fail "login failed"; fi

begin_test "Non-admin cannot self-elevate via PATCH is_admin"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PATCH -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"is_admin":true}' \
  "${BASE_URL}/api/v1/users/${USER_ID}" 2>&1) || true
if [ "$status" = "403" ] || [ "$status" = "400" ]; then
  # Verify is_admin is still false
  check=$(curl -sf -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/users/${USER_ID}" 2>&1) || true
  is_admin=$(echo "$check" | jq -r '.is_admin // false')
  if [ "$is_admin" = "false" ]; then
    pass
  else
    fail "is_admin was set to true despite expected rejection"
  fi
else
  fail "expected 403 or 400, got ${status}"
fi

begin_test "Non-admin cannot create admin users"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"evil-admin-${RUN_ID}\",\"password\":\"${PASSWORD}\",\"is_admin\":true}" \
  "${BASE_URL}/api/v1/users" 2>&1) || true
if [ "$status" = "403" ]; then
  pass
else
  fail "expected 403, got ${status}"
fi

end_suite
```

- [ ] **Step 2: Commit**

```bash
git add tests/rbac/test-privilege-escalation.sh
git commit -m "test(rbac): add privilege escalation test - non-admin cannot self-elevate"
```

---

### Task 4: T2-04 through T2-05 - Admin protection and scope enforcement

**Files:**
- Create: `tests/rbac/test-admin-protection.sh`
- Create: `tests/rbac/test-scope-enforcement.sh`

- [ ] **Step 1: Write admin protection test**

Test that a non-admin user gets 403 on all /api/v1/admin/* endpoints: settings, backups, metrics, users (create), groups, plugins, monitoring.

- [ ] **Step 2: Write scope enforcement test**

Test that a read-only scoped API token cannot perform write operations. Test that a repo-scoped token cannot access other repos.

- [ ] **Step 3: Commit each**

---

### Task 5: T2-06 - JWT algorithm confusion test

**Files:**
- Create: `tests/auth/test-jwt-manipulation.sh`

- [ ] **Step 1: Write the test**

Craft a JWT with `alg: "none"` and valid claims using bash/python. Send it as a Bearer token. Assert 401.

```bash
#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-jwt-manipulation"
setup_workdir

begin_test "JWT with alg=none is rejected"
# Craft a JWT with alg=none: header.payload.
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"admin","user_id":"00000000-0000-0000-0000-000000000000","is_admin":true,"exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FAKE_JWT="${HEADER}.${PAYLOAD}."

status=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${FAKE_JWT}" \
  "${BASE_URL}/api/v1/repositories" 2>&1) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "JWT with alg=none accepted, got status ${status}"
fi

end_suite
```

- [ ] **Step 2: Commit**

```bash
git add tests/auth/test-jwt-manipulation.sh
git commit -m "test(auth): add JWT algorithm confusion test - alg=none must be rejected"
```

---

### Tasks 6-15: Remaining security tests (T2-07 through T2-23)

Each follows the same pattern: create a new test script in the appropriate suite directory, source common.sh, write the attack scenario, assert the expected rejection.

**Summary of remaining test scripts to create:**

| Task | File | Key assertion |
|------|------|--------------|
| T2-07 | `tests/security/test-dependency-confusion.sh` | Virtual repo serves local v1.0 over upstream v2.0 |
| T2-08 | `tests/security/test-artifact-integrity.sh` | Upload with wrong checksum returns 400 |
| T2-09 | `tests/security/test-decompression-bomb.sh` | Small archive expanding to 1GB+ is rejected |
| T2-10 | `tests/security/test-wasm-sandbox.sh` | Plugin exceeding memory/fuel limits terminated cleanly |
| T2-11 | `tests/security/test-cache-poisoning.sh` | Proxy verifies upstream checksums |
| T2-12 | `tests/security/test-ssrf-prevention.sh` | Webhook/proxy/plugin URLs reject private IPs |
| T2-13 | `tests/security/test-default-credentials.sh` | admin:admin, admin:password, root:root all rejected |
| T2-14 | `tests/security/test-path-traversal.sh` | ../../../etc/passwd variants return 400 |
| T2-15 | `tests/security/test-sql-injection.sh` | SQLi payloads in search/listing return normal results |
| T2-16 | `tests/security/test-grpc-security.sh` | gRPC reflection requires auth, unauth calls rejected |
| T2-17 | `tests/auth/test-token-expiry.sh` | Expired JWT returns 401 |
| T2-18 | `tests/auth/test-token-revocation.sh` | Revoked token returns 401 within cache window |
| T2-19 | `tests/security/test-mesh-peer-auth.sh` | Wrong peer API key returns 401 |
| T2-20 | `tests/security/test-stored-xss.sh` | Script tags in metadata are escaped/safe in API response |
| T2-21 | `tests/security/test-xxe-prevention.sh` | XXE payloads in POM/nuspec rejected |
| T2-22 | `tests/security/test-upload-race.sh` | Two concurrent same-version uploads: one wins, no corruption |
| T2-23 | `tests/auth/test-session-invalidation.sh` | Password change invalidates existing tokens |

Each script follows the exact same pattern shown in Tasks 2-5. For each:

- [ ] Write the test script with specific attack payloads
- [ ] Verify it runs locally (if backend available)
- [ ] Commit with descriptive message

---

### Task 16: Update release-gate.yml with all new security test jobs

**Files:**
- Modify: `.github/workflows/release-gate.yml`

- [ ] **Step 1: Add the new test scripts to the security-tests job**

Ensure the security-tests job in release-gate.yml runs all scripts in `tests/security/` including the new ones. If the job uses `run-suite.sh`, verify the suite discovers all test-*.sh files in subdirectories.

- [ ] **Step 2: Add new auth and rbac scripts to their respective jobs**

Verify the auth-tests and rbac-tests jobs will pick up the new test files.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release-gate.yml
git commit -m "ci(release-gate): add new security, auth, and rbac test scripts to workflow"
```
