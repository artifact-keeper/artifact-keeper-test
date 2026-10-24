#!/usr/bin/env bash
# =============================================================================
# tiers/scan-gate-blocked-body-and-audit/oracle.sh - what the scan gates
# refuse is visible, attributed and answered consistently (1.12.0, G3)
# =============================================================================
#   #4777  PROXY_SCAN_BLOCKED audit row per refused proxied pull (principal,
#          IP, repository, path, digest), aggregated per minute; the
#          cross-repository proxy-blocked list; dashboard proxy_blocked.
#   #4510  the policy-blocks queue; a scan-policy hold answers 403 not 409.
#   #4363  a repository admin cannot weaken an instance-locked proxy policy.
#   #4288  .sha1/.md5 of a refused hosted Maven artifact is 404.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's control port), DB_CONTAINER, COMMON_SH. Grype (bundled, pre-seeded
# DB) grades; nothing leaves the host.
#
# Red: ak-backend:1.11.5. Green: main plus the G3 PRs.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

begin_suite "scan-gate-blocked-body-and-audit"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72/maven2"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

MVN="sgb-mvn-${SUF}"      # Remote, scan_on_proxy, fail_closed
LOCK="sgb-lock-${SUF}"    # Remote whose policy an instance admin locks
HPOL="sgb-hpol-${SUF}"    # hosted Maven with a severity scan policy
HADM="sgb-hadm-${SUF}"    # hosted Maven, admin quarantine, no policy
U_NAME="sgb-u-${SUF}"; U_PASS="SgbUser_${RUN_ID##*-}_Aa1!"

LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
PLAIN="com/example/sgb/plain/1.0/plain-1.0.jar"
POLICY_ID=""

cleanup() {
  local k
  [ -n "$POLICY_ID" ] && api_delete "/api/v1/security/policies/${POLICY_ID}" >/dev/null 2>&1 || true
  for k in "$MVN" "$LOCK" "$HPOL" "$HADM"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/maven2/$1" || true; }
BODY="${WORK_DIR}/body"
# req METHOD URL [TOKEN] [JSON] -> ST, body in $BODY
req() {
  local tok="${3:-$ADMIN_TOKEN}" data="${4:-}"
  if [ -n "$data" ]; then
    ST=$(curl -s -o "$BODY" -w '%{http_code}' --max-time 120 -X "$1" -H "Authorization: Bearer ${tok}" \
      -H 'Content-Type: application/json' -d "$data" "$2" 2>/dev/null) || ST="000"
  else
    ST=$(curl -s -o "$BODY" -w '%{http_code}' --max-time 120 -X "$1" -H "Authorization: Bearer ${tok}" "$2" 2>/dev/null) || ST="000"
  fi
}
anon() { ST=$(curl -s -o "$BODY" -w '%{http_code}' --max-time 60 "$1" 2>/dev/null) || ST="000"; }
jb() { jq -r "$@" "$BODY" 2>/dev/null || true; }
snippet() { head -c 240 "$BODY" | tr -c '[:print:]' '.'; }
repo_id() { psql_q "SELECT id FROM repositories WHERE key='$1'"; }
art_id() { psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.path='$2' AND NOT a.is_deleted"; }
login() {
  curl -s -X POST "$BASE_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.access_token // .token // empty' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream, a fail_closed Maven Remote, two hosted Maven repos, a repo-admin user on a second Remote"
ok=1; err=""
[ -n "$(golden_sha "$LOG4J")" ] || { ok=0; err="${err} mock"; }
for k in "$MVN" "$LOCK"; do create_repo "$k" maven remote "$UP" || { ok=0; err="${err} create:${k}"; }; done
for k in "$HPOL" "$HADM"; do create_repo "$k" maven local || { ok=0; err="${err} create:${k}"; }; done
req PUT "${BASE_URL}/api/v1/repositories/${MVN}/security" "" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed"}'
[ "$ST" = "200" ] || { ok=0; err="${err} scancfg:${ST}"; }
MVN_ID=$(repo_id "$MVN"); LOCK_ID=$(repo_id "$LOCK"); HPOL_ID=$(repo_id "$HPOL")
ADMIN_ID=$(psql_q "SELECT id FROM users WHERE username='${ADMIN_USER:-admin}'")
req POST "${BASE_URL}/api/v1/users" "" \
  "{\"username\":\"${U_NAME}\",\"password\":\"${U_PASS}\",\"email\":\"${U_NAME}@dtf.invalid\"}"
U_ID=$(psql_q "SELECT id FROM users WHERE username='${U_NAME}'")
req POST "${BASE_URL}/api/v1/permissions" "" \
  "{\"principal_type\":\"user\",\"principal_id\":\"${U_ID}\",\"target_type\":\"repository\",\"target_id\":\"${LOCK_ID}\",\"actions\":[\"read\",\"write\",\"admin\"]}"
case "$ST" in 200|201) ;; *) ok=0; err="${err} grant:${ST}:$(snippet)";; esac
UTOK=$(login "$U_NAME" "$U_PASS")
[ -n "$UTOK" ] || { ok=0; err="${err} user-login"; }
if [ "$ok" = 1 ] && [ -n "$MVN_ID" ] && [ -n "$ADMIN_ID" ]; then
  pass
else
  infra_fail "setup failed:${err}"
  end_suite
fi
D=$(golden_sha "$LOG4J")

# ---------------------------------------------------------------------------
# #4777: the refusal is audited, once per minute per principal and digest
# ---------------------------------------------------------------------------
begin_test "control: five authenticated pulls of log4j-core-2.14.1.jar through the fail_closed Remote are 403 scan_blocked"
codes=""
for _ in 1 2 3 4 5; do
  req GET "${BASE_URL}/maven/${MVN}/${LOG4J}"
  codes="${codes}${ST}:$(jb '.error')|"
done
if [ "$codes" = "403:scan_blocked|403:scan_blocked|403:scan_blocked|403:scan_blocked|403:scan_blocked|" ]; then
  pass
else
  fail "statuses ${codes} last body $(snippet)"
fi

audit_where="action='PROXY_SCAN_BLOCKED' AND resource_id='${MVN_ID}' AND details->>'checksum_sha256'='${D}'"
n=""
for _ in $(seq 1 20); do
  n=$(psql_q "SELECT count(*) FROM audit_log WHERE ${audit_where}")
  [ "${n:-0}" -ge 1 ] 2>/dev/null && break
  sleep 1
done
sleep 2
n=$(psql_q "SELECT count(*) FROM audit_log WHERE ${audit_where}")
begin_test "FIX #4777: the five refusals wrote exactly ONE PROXY_SCAN_BLOCKED row (aggregated; was none)"
if [ "$n" = "1" ]; then pass; else fail "PROXY_SCAN_BLOCKED rows for the digest: '${n}' (1.11.5 records no block at all)"; fi

begin_test "FIX #4777: the row names the principal, client IP, repository, path, digest and verdict"
row=$(psql_q "SELECT user_id::text||'|'||(ip_address IS NOT NULL)::text||'|'||(details->>'repository')||'|'||(details->>'path')||'|'||(details->>'verdict')||'|'||(details->>'principal')||'|'||(details->>'attempts') FROM audit_log WHERE ${audit_where} LIMIT 1")
want="${ADMIN_ID}|true|${MVN}|log4j-core-2.14.1.jar|vulnerable|${ADMIN_USER:-admin}|1"
if [ "$row" = "$want" ]; then pass; else fail "row '${row}', want '${want}'"; fi

begin_test "FIX #4777: GET /api/v1/security/proxy-blocked lists the jar with its CVE ids (was 404)"
req GET "${BASE_URL}/api/v1/security/proxy-blocked?repository=${MVN}"
got=$(jb --arg d "$D" '[.items[] | select(.checksum_sha256==$d)][0] | [.path, .max_severity, ((.cve_ids // []) | index("CVE-2021-44228") != null)] | join("|")')
if [ "$ST" = "200" ] && [ "$got" = "${LOG4J}|critical|true" ]; then
  pass
else
  fail "HTTP ${ST} item '${got}' body $(snippet)"
fi

begin_test "FIX #4777: the dashboard reports proxy_blocked >= 1 (field absent on 1.11.5)"
req GET "${BASE_URL}/api/v1/security/dashboard"
pb=$(jb '.proxy_blocked // "absent"')
if [ "$ST" = "200" ] && [ "$pb" != "absent" ] && [ "$pb" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "HTTP ${ST} proxy_blocked=${pb}"
fi

begin_test "FIX #4510: GET /api/v1/admin/holds/policy-blocks lists the refused proxied digest (was 404)"
req GET "${BASE_URL}/api/v1/admin/holds/policy-blocks?repository_key=${MVN}"
got=$(jb --arg d "$D" '[.items[] | select(.checksum_sha256==$d)][0] | [.source, .path] | join("|")')
if [ "$ST" = "200" ] && [ "$got" = "proxy-cache|${LOG4J}" ]; then pass; else fail "HTTP ${ST} item '${got}' body $(snippet)"; fi

# ---------------------------------------------------------------------------
# #4510: a scan-policy hold answers 403; an administrator hold stays 409.
# #4288: their checksums are 404.
# ---------------------------------------------------------------------------
begin_test "control: log4j-core uploads to a hosted repo with a severity policy, a Grype scan holds it ('quarantined')"
req POST "${BASE_URL}/api/v1/security/policies" "" "$(jq -n --arg r "$HPOL_ID" \
  '{name:"dtf-sgb-severity", repository_id:$r, max_severity:"high", block_unscanned:false, block_on_fail:false, require_signature:false}')"
POLICY_ID=$(jb '.id // empty')
JAR="${WORK_DIR}/log4j.jar"
curl -s --max-time 10 -o "$JAR" "${MOCK}/__golden/maven2/${LOG4J}" || true
up=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
  --data-binary "@${JAR}" "${BASE_URL}/maven/${HPOL}/${LOG4J}" 2>/dev/null) || up="000"
HPOL_ART=$(art_id "$HPOL" "$LOG4J")
[ -n "$HPOL_ART" ] && { trigger_and_wait_scan "$HPOL_ART" 240 grype >/dev/null 2>&1 || true; }
qs=""
for _ in $(seq 1 30); do
  qs=$(psql_q "SELECT quarantine_status FROM artifacts WHERE id='${HPOL_ART}'")
  [ "$qs" = "quarantined" ] && break
  sleep 2
done
if [ -n "$POLICY_ID" ] && [[ "$up" =~ ^20[01]$ ]] && [ "$qs" = "quarantined" ]; then
  pass
else
  fail "policy ${POLICY_ID:-none} upload ${up} artifact ${HPOL_ART:-none} quarantine_status '${qs}'"
fi

begin_test "FIX #4510: the scan-policy held jar answers 403 (was the quarantine 409)"
anon "${BASE_URL}/maven/${HPOL}/${LOG4J}"
if [ "$ST" = "403" ]; then pass; else fail "HTTP ${ST} $(snippet)"; fi

begin_test "FIX #4510: policy-blocks lists the hosted jar the policy refuses, with its violations"
req GET "${BASE_URL}/api/v1/admin/holds/policy-blocks?repository_key=${HPOL}"
got=$(jb --arg a "$HPOL_ART" '[.items[] | select(.artifact_id==$a)][0] | [.source, ((.violations // []) | length > 0)] | join("|")')
if [ "$ST" = "200" ] && [ "$got" = "hosted|true" ]; then pass; else fail "HTTP ${ST} item '${got}' body $(snippet)"; fi

begin_test "FIX #4288: the .sha1 and .md5 of the scan-policy held jar are 404 (were 200 with the digest)"
anon "${BASE_URL}/maven/${HPOL}/${LOG4J}.sha1"; s1="$ST"
anon "${BASE_URL}/maven/${HPOL}/${LOG4J}.md5"; s2="$ST"
if [ "$s1$s2" = "404404" ]; then pass; else fail ".sha1 ${s1} .md5 ${s2}"; fi

begin_test "control: a plain jar in a hosted repo without a policy serves, and its .sha1 is its SHA-1"
PJAR="${WORK_DIR}/plain.jar"
printf 'PK\003\004 dtf sgb plain jar %s' "$RUN_ID" > "$PJAR"
up=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
  --data-binary "@${PJAR}" "${BASE_URL}/maven/${HADM}/${PLAIN}" 2>/dev/null) || up="000"
want_sha1=$(sha1sum "$PJAR" | cut -d' ' -f1)
anon "${BASE_URL}/maven/${HADM}/${PLAIN}"; s0="$ST"
anon "${BASE_URL}/maven/${HADM}/${PLAIN}.sha1"
if [[ "$up" =~ ^20[01]$ ]] && [ "$s0" = "200" ] && [ "$ST" = "200" ] && [ "$(tr -d '[:space:]' < "$BODY")" = "$want_sha1" ]; then
  pass
else
  fail "upload ${up} jar ${s0} .sha1 ${ST} body $(snippet)"
fi

HADM_ART=$(art_id "$HADM" "$PLAIN")
req POST "${BASE_URL}/api/v1/quarantine/${HADM_ART}/quarantine" "" '{"reason":"dtf sgb admin hold"}'
QST="$ST"
begin_test "control: an administrator hold answers the quarantine 409"
anon "${BASE_URL}/maven/${HADM}/${PLAIN}"
if [ "$QST" = "200" ] && [ "$ST" = "409" ]; then pass; else fail "quarantine-now ${QST}, download ${ST} $(snippet)"; fi

begin_test "FIX #4288: the .sha1 of the administrator-held jar is 404 (was 200 with the digest)"
anon "${BASE_URL}/maven/${HADM}/${PLAIN}.sha1"
if [ "$ST" = "404" ]; then pass; else fail "HTTP ${ST} body $(snippet)"; fi

begin_test "control: once released, the jar and its .sha1 serve again"
req POST "${BASE_URL}/api/v1/quarantine/${HADM_ART}/release" "" '{}'
rs="$ST"
anon "${BASE_URL}/maven/${HADM}/${PLAIN}.sha1"
if [ "$rs" = "200" ] && [ "$ST" = "200" ] && [ "$(tr -d '[:space:]' < "$BODY")" = "$want_sha1" ]; then
  pass
else
  fail "release ${rs} .sha1 ${ST} $(snippet)"
fi

# ---------------------------------------------------------------------------
# #4363: instance lock on the proxy scan policy
# ---------------------------------------------------------------------------
begin_test "control: the instance admin sets ${LOCK}'s proxy scan policy (fail_open, scanning on)"
req PUT "${BASE_URL}/api/v1/repositories/${LOCK}/security" "" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_open"}'
if [ "$ST" = "200" ]; then pass; else fail "HTTP ${ST} $(snippet)"; fi

begin_test "FIX #4363: the repository admin cannot switch the locked policy to record_only (403, nothing written; was 200)"
req PUT "${BASE_URL}/api/v1/repositories/${LOCK}/security" "$UTOK" '{"proxy_scan_action":"record_only"}'
after=$(psql_q "SELECT proxy_scan_action FROM scan_configs WHERE repository_id='${LOCK_ID}'")
if [ "$ST" = "403" ] && [ "$after" = "fail_open" ]; then pass; else fail "HTTP ${ST}, stored action '${after}' $(snippet)"; fi

begin_test "control: the repository admin can still tighten it to fail_closed"
req PUT "${BASE_URL}/api/v1/repositories/${LOCK}/security" "$UTOK" '{"proxy_scan_action":"fail_closed"}'
if [ "$ST" = "200" ] && [ "$(jb '.proxy_scan_action')" = "fail_closed" ]; then pass; else fail "HTTP ${ST} $(snippet)"; fi

begin_test "control: the instance admin can switch it to record_only"
req PUT "${BASE_URL}/api/v1/repositories/${LOCK}/security" "" '{"proxy_scan_action":"record_only"}'
if [ "$ST" = "200" ] && [ "$(jb '.proxy_scan_action')" = "record_only" ]; then pass; else fail "HTTP ${ST} $(snippet)"; fi

end_suite
