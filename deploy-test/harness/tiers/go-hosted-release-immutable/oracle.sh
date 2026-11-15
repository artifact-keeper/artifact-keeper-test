#!/usr/bin/env bash
# =============================================================================
# tiers/go-hosted-release-immutable/oracle.sh  (artifact-keeper#5885 / #5834)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR and COMMON_SH.
#
# A published hosted Go module version is a release: a non-admin repository
# owner cannot delete it, and once an admin has deleted it the version can come
# back with the same bytes only. See the manifest for the bugs.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SUF="${RUN_ID##*-}-$$"
REPO="go-immut-${DTF_SLOT:-x}-${SUF}"
OWNER="go-owner-${DTF_SLOT:-x}-${SUF}"
# Generated per run; nothing credential-shaped is committed.
OWNER_PASS="Dtf-$(openssl rand -hex 12)-Aa1"
MOD="example.com/dtf/immut${SUF//[^0-9]/}"
VER="v1.0.0"
ZIP_STORED="${MOD}/${VER}/${VER}.zip"
MOD_STORED="${MOD}/${VER}/go.mod"

# The original and the "other" bytes for each file. The handler does not open
# the zip, so random bytes stand in for a module zip.
openssl rand 512 > "${WORK}/zip.a"
openssl rand 512 > "${WORK}/zip.b"
printf 'module %s\n\ngo 1.21\n' "$MOD" > "${WORK}/mod.a"
printf 'module %s\n\ngo 1.21\n\n// changed\n' "$MOD" > "${WORK}/mod.b"

db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>&1; }

# put TOKEN LEAF FILE -> HTTP status of PUT /go/{repo}/{mod}/@v/{leaf}
put() {
  curl -s $CURL_TIMEOUT -o "${WORK}/putbody" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$3" "${BASE_URL}/go/${REPO}/${MOD}/@v/$2" 2>/dev/null || echo 000
}
# get LEAF OUTFILE -> HTTP status of the admin's GET /go/{repo}/{mod}/@v/{leaf}
get() {
  curl -s $CURL_TIMEOUT -o "$2" -w '%{http_code}' \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/go/${REPO}/${MOD}/@v/$1" 2>/dev/null || echo 000
}
# del TOKEN STORED_PATH -> HTTP status of the generic artifact delete
del() {
  curl -s $CURL_TIMEOUT -o "${WORK}/delbody" -w '%{http_code}' -X DELETE \
    -H "Authorization: Bearer $1" "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/$2" 2>/dev/null || echo 000
}
# same_as LEAF FILE -> 0 when the admin download is 200 and equals FILE
same_as() {
  local c
  c="$(get "$1" "${WORK}/got")"
  [ "$c" = "200" ] && cmp -s "${WORK}/got" "$2"
}
# describe LEAF -> "code=<c> bytes=<n> sha=<prefix>" for failure messages
describe() {
  local c
  c="$(get "$1" "${WORK}/got")"
  echo "code=${c} bytes=$(wc -c < "${WORK}/got" 2>/dev/null || echo 0) sha=$(sha256sum "${WORK}/got" 2>/dev/null | cut -c1-12)"
}

begin_suite "go-hosted-release-immutable"

auth_admin

if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"go\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1; then
  begin_test "setup: create hosted Go repository"
  fail "could not create repository ${REPO}"
  end_suite
fi

OWNER_ID="$(create_test_user_with_retry "$OWNER" "$OWNER_PASS" "${OWNER}@t.test")" || true
if [ -z "$OWNER_ID" ] || [ "$OWNER_ID" = "null" ]; then
  begin_test "setup: create non-admin user"
  fail "could not create user ${OWNER}"
  end_suite
fi
db "INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${OWNER}' AND r.name='repository-owner' AND repo.key='${REPO}'
  ON CONFLICT DO NOTHING" >/dev/null || true
GRANT="$(db "SELECT count(*) FROM role_assignments ra JOIN roles r ON r.id = ra.role_id
  JOIN repositories repo ON repo.id = ra.repository_id
  WHERE ra.user_id='${OWNER_ID}' AND r.name='repository-owner' AND repo.key='${REPO}'")"
OWNER_TOKEN="$(login_as "$OWNER" "$OWNER_PASS")" || true
if [ -z "$OWNER_TOKEN" ] || [ "$GRANT" != "1" ]; then
  begin_test "setup: grant repository-owner and log in"
  fail "grant='${GRANT}' token='${OWNER_TOKEN:0:8}'"
  end_suite
fi

# --- CONTROL: publish and read back ------------------------------------------
begin_test "CONTROL: admin publishes ${VER}.zip and ${VER}.mod (201)"
cz="$(put "$ADMIN_TOKEN" "${VER}.zip" "${WORK}/zip.a")"
cm="$(put "$ADMIN_TOKEN" "${VER}.mod" "${WORK}/mod.a")"
if [ "$cz" = "201" ] && [ "$cm" = "201" ]; then pass
else fail "publish zip=${cz} mod=${cm}, want 201/201" "$(head -c 300 "${WORK}/putbody")"; end_suite; fi

begin_test "CONTROL: both files download byte for byte"
if same_as "${VER}.zip" "${WORK}/zip.a" && same_as "${VER}.mod" "${WORK}/mod.a"; then pass
else fail "zip: $(describe "${VER}.zip"); mod: $(describe "${VER}.mod")"; fi

begin_test "CONTROL: the repository owner can publish v1.0.1 (the grant is live)"
c="$(put "$OWNER_TOKEN" "v1.0.1.zip" "${WORK}/zip.b")"
if [ "$c" = "201" ]; then pass; else fail "owner PUT v1.0.1.zip returned ${c}, want 201" "$(head -c 300 "${WORK}/putbody")"; fi

# --- FIX a: the owner cannot delete a published version ----------------------
for p in "$ZIP_STORED" "$MOD_STORED"; do
  begin_test "FIX a: repository owner (non-admin) DELETE ${p##*/} -> 409"
  c="$(del "$OWNER_TOKEN" "$p")"
  if [ "$c" = "409" ]; then pass
  else fail "owner DELETE ${p} returned ${c}, want 409 (a published Go version is a release)" "$(head -c 300 "${WORK}/delbody")"; fi
done

begin_test "FIX a: after the owner's attempts both files still download unchanged"
if same_as "${VER}.zip" "${WORK}/zip.a" && same_as "${VER}.mod" "${WORK}/mod.a"; then pass
else fail "zip: $(describe "${VER}.zip"); mod: $(describe "${VER}.mod")"; fi

# --- CONTROL: an admin can retract -------------------------------------------
begin_test "CONTROL: admin DELETE of both stored paths succeeds"
cz="$(del "$ADMIN_TOKEN" "$ZIP_STORED")"
zb="$(head -c 200 "${WORK}/delbody")"
cm="$(del "$ADMIN_TOKEN" "$MOD_STORED")"
case "$cz:$cm" in
  2??:2??) pass ;;
  *) fail "admin DELETE zip=${cz} mod=${cm}, want 2xx/2xx" "zip: ${zb} mod: $(head -c 200 "${WORK}/delbody")" ;;
esac

begin_test "CONTROL: after the admin delete both downloads are 404"
gz="$(get "${VER}.zip" "${WORK}/got")"; gm="$(get "${VER}.mod" "${WORK}/got")"
if [ "$gz" = "404" ] && [ "$gm" = "404" ]; then pass; else fail "zip=${gz} mod=${gm}, want 404/404"; fi

# --- FIX b: the version comes back with the same bytes only ------------------
begin_test "FIX b: republish ${VER}.zip with OTHER bytes -> 409"
c="$(put "$ADMIN_TOKEN" "${VER}.zip" "${WORK}/zip.b")"
if [ "$c" = "409" ]; then pass
else fail "PUT ${VER}.zip with other bytes returned ${c}, want 409" "$(head -c 300 "${WORK}/putbody")"; fi

begin_test "FIX b: republish ${VER}.mod with OTHER bytes -> 409"
c="$(put "$ADMIN_TOKEN" "${VER}.mod" "${WORK}/mod.b")"
if [ "$c" = "409" ]; then pass
else fail "PUT ${VER}.mod with other bytes returned ${c}, want 409" "$(head -c 300 "${WORK}/putbody")"; fi

begin_test "FIX b: republish both files with the ORIGINAL bytes succeeds"
cz="$(put "$ADMIN_TOKEN" "${VER}.zip" "${WORK}/zip.a")"; zb="$(head -c 200 "${WORK}/putbody")"
cm="$(put "$ADMIN_TOKEN" "${VER}.mod" "${WORK}/mod.a")"
case "$cz:$cm" in
  2??:2??) pass ;;
  *) fail "same-bytes PUT zip=${cz} mod=${cm}, want 2xx/2xx" "zip: ${zb} mod: $(head -c 200 "${WORK}/putbody")" ;;
esac

begin_test "FIX b: both files download as the ORIGINAL bytes"
if same_as "${VER}.zip" "${WORK}/zip.a" && same_as "${VER}.mod" "${WORK}/mod.a"; then pass
else fail "zip: $(describe "${VER}.zip"); mod: $(describe "${VER}.mod")"; fi

end_suite
