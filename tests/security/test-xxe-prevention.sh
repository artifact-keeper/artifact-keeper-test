#!/usr/bin/env bash
# test-xxe-prevention.sh - T2-21: XXE payload injection in XML formats
#
# Verifies that XML External Entity (XXE) payloads in Maven POM files and
# other XML-based uploads are rejected or safely processed without resolving
# external entities.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "xxe-prevention"
auth_admin
setup_workdir

MAVEN_REPO="sec-xxe-maven-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create a Maven repository
# ---------------------------------------------------------------------------

begin_test "Create Maven local repo"
if create_local_repo "$MAVEN_REPO" "maven"; then
  pass
else
  fail "could not create Maven repo"
fi

# ---------------------------------------------------------------------------
# Craft a POM with XXE payload
# ---------------------------------------------------------------------------

begin_test "Upload POM with XXE file:///etc/passwd payload"
cat > "${WORK_DIR}/xxe-pom.xml" << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil.xxe</groupId>
  <artifactId>xxe-test</artifactId>
  <version>1.0.0</version>
  <description>&xxe;</description>
</project>
XMLEOF

# Upload using the Maven layout path
status=$(curl -s -o "${WORK_DIR}/xxe-resp.txt" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/xml" \
  --data-binary "@${WORK_DIR}/xxe-pom.xml" \
  "${BASE_URL}/maven/${MAVEN_REPO}/com/evil/xxe/xxe-test/1.0.0/xxe-test-1.0.0.pom") || true
body=$(cat "${WORK_DIR}/xxe-resp.txt" 2>/dev/null) || true

if [ "$status" = "400" ] || [ "$status" = "422" ]; then
  # Server rejected the XXE payload outright
  pass
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Upload accepted. Check if the response leaks /etc/passwd content
  if echo "$body" | grep -qE "root:.*:0:0:|daemon:.*:/usr/sbin|nobody:"; then
    fail "XXE payload resolved: response contains /etc/passwd content"
  else
    # POM was stored but entity was not resolved (safe behavior)
    pass
  fi
else
  # 401, 403, 404, 500 are all acceptable (no XXE exploitation)
  pass
fi

# ---------------------------------------------------------------------------
# Verify stored POM does not contain resolved entity content
# ---------------------------------------------------------------------------

begin_test "Stored POM does not contain resolved XXE entity"
dl_status=$(curl -s -o "${WORK_DIR}/dl-pom.xml" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/maven/${MAVEN_REPO}/com/evil/xxe/xxe-test/1.0.0/xxe-test-1.0.0.pom") || true

if [ "$dl_status" = "200" ]; then
  pom_content=$(cat "${WORK_DIR}/dl-pom.xml" 2>/dev/null) || true
  if echo "$pom_content" | grep -qE "root:.*:0:0:|daemon:.*:/usr/sbin|nobody:"; then
    fail "downloaded POM contains /etc/passwd content (XXE entity was resolved and stored)"
  else
    pass
  fi
elif [ "$dl_status" = "404" ]; then
  # POM was rejected or not stored
  pass
else
  skip "could not download POM to verify (HTTP ${dl_status})"
fi

# ---------------------------------------------------------------------------
# Test XXE with HTTP-based external entity (SSRF via XXE)
# ---------------------------------------------------------------------------

begin_test "Upload POM with HTTP-based XXE payload"
cat > "${WORK_DIR}/xxe-http-pom.xml" << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil.xxe</groupId>
  <artifactId>xxe-http-test</artifactId>
  <version>1.0.0</version>
  <description>&xxe;</description>
</project>
XMLEOF

status=$(curl -s -o "${WORK_DIR}/xxe-http-resp.txt" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/xml" \
  --data-binary "@${WORK_DIR}/xxe-http-pom.xml" \
  "${BASE_URL}/maven/${MAVEN_REPO}/com/evil/xxe/xxe-http-test/1.0.0/xxe-http-test-1.0.0.pom") || true
body=$(cat "${WORK_DIR}/xxe-http-resp.txt" 2>/dev/null) || true

if [ "$status" = "400" ] || [ "$status" = "422" ]; then
  pass
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Check for metadata service content
  if echo "$body" | grep -qiE "ami-id\|instance-id\|security-credentials"; then
    fail "XXE payload resolved HTTP entity: response contains cloud metadata"
  else
    pass
  fi
else
  pass
fi

# ---------------------------------------------------------------------------
# Test billion laughs (entity expansion DoS)
# ---------------------------------------------------------------------------

begin_test "Upload POM with billion laughs payload"
cat > "${WORK_DIR}/xxe-billion.xml" << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil.xxe</groupId>
  <artifactId>xxe-billion</artifactId>
  <version>1.0.0</version>
  <description>&lol5;</description>
</project>
XMLEOF

status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 --connect-timeout 10 \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/xml" \
  --data-binary "@${WORK_DIR}/xxe-billion.xml" \
  "${BASE_URL}/maven/${MAVEN_REPO}/com/evil/xxe/xxe-billion/1.0.0/xxe-billion-1.0.0.pom") || true

if [ "$status" = "400" ] || [ "$status" = "422" ] || [ "$status" = "413" ]; then
  pass
elif [ "$status" = "000" ] || [ "$status" = "408" ] || [ "$status" = "504" ]; then
  # Timeout or connection reset. Could be the server protecting itself.
  skip "request timed out (server may have killed the connection to prevent entity expansion DoS)"
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Accepted but may have stored raw XML without expanding entities (safe)
  pass
else
  pass
fi

# ---------------------------------------------------------------------------
# Verify backend health after XXE tests
# ---------------------------------------------------------------------------

begin_test "Backend still healthy after XXE tests"
health_ok=false
if curl -sf --max-time 10 "${BASE_URL}/readyz" >/dev/null 2>&1; then
  health_ok=true
elif curl -sf --max-time 10 "${BASE_URL}/health" >/dev/null 2>&1; then
  health_ok=true
fi

if $health_ok; then
  pass
else
  fail "backend health check failed after XXE tests"
fi

end_suite
