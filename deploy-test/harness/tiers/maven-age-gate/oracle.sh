#!/usr/bin/env bash
# =============================================================================
# tiers/maven-age-gate/oracle.sh: the publish-age gate on Maven Remote and
# Virtual repositories (artifact-keeper#4702)
# =============================================================================
# run.sh has stood up `filesystem + upstreams.mock-maven-agegate`: the backend
# plus `mock-maven` (fixtures/mock_maven_agegate.py). run.sh exported BASE_URL,
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DB_CONTAINER, COMMON_SH.
# See the manifest for the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

begin_suite "maven-age-gate-4702"
auth_admin
setup_workdir

SUF="${DTF_SLOT}x${RUN_ID##*-}"
REPO="dtf-mvn-agegate-${SUF}"
VREPO="dtf-mvn-agegate-v-${SUF}"
MOCK="ak-dtf${DTF_SLOT}-mock-maven"
UPSTREAM="http://mock-maven/"
G="com/example/agegate/widget"
OLD="1.0.0"
YOUNG="2.0.0"
PKG="com.example.agegate:widget"

cleanup_repos() {
  api_delete "/api/v1/repositories/${VREPO}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${REPO}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

jqr() { jq -r "$1" 2>/dev/null || true; }
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

api_call() { # METHOD PATH [BODY] -> API_STATUS + API_BODY
  local method="$1" path="$2" body="${3:-}" tmp="${WORK_DIR}/api.$$"
  if [ -n "$body" ]; then
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' --max-time 30 -X "$method" \
      -H "$(auth_header)" -H 'Content-Type: application/json' -d "$body" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  else
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' --max-time 30 -X "$method" \
      -H "$(auth_header)" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  fi
  API_BODY="$(cat "$tmp" 2>/dev/null || true)"; rm -f "$tmp"
}

# fetch REPO PATH OUTFILE -> HTTP status
fetch() {
  curl -s -o "$3" -w '%{http_code}' --max-time 40 -H "$(auth_header)" \
    "${BASE_URL}/maven/$1/$2" 2>/dev/null || echo 000
}
mock_get() { # PATH -> body as the mock serves it
  docker exec "$MOCK" python3 -c \
    "import urllib.request,sys; sys.stdout.buffer.write(urllib.request.urlopen('http://127.0.0.1/$1').read())" 2>/dev/null || true
}
mock_log() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/__log').read().decode())" 2>/dev/null || true
}
sha1_of() { sha1sum "$1" 2>/dev/null | awk '{print $1}'; }
sha256_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
versions_in() { grep -oE '<version>[^<]+</version>' "$1" 2>/dev/null | sed -E 's#</?version>##g' | tr '\n' ' ' | sed 's/ $//'; }

# assert_refused WHAT STATUS FILE: 451 with the shared age_gate_blocked body
assert_refused() {
  local what="$1" st="$2" f="$3" err pkg ver
  err="$(jqr '.error' < "$f")"; pkg="$(jqr '.package' < "$f")"; ver="$(jqr '.version' < "$f")"
  if [ "$st" = "451" ] && [ "$err" = "age_gate_blocked" ] && [ "$pkg" = "$PKG" ] && [ "$ver" = "$YOUNG" ]; then
    pass
  else
    fail "#4702: young ${what} answered HTTP ${st} (expected 451 age_gate_blocked for ${PKG} ${YOUNG})" \
      "$(head -c 300 "$f" 2>/dev/null)"
  fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: create a REMOTE maven repo over the mock and a VIRTUAL over it"
if create_repo "$REPO" maven remote "$UPSTREAM" && create_repo "$VREPO" maven virtual; then
  rid="$(api_get "/api/v1/repositories/${REPO}" 2>/dev/null | jqr '.id // empty')"
  api_call POST "/api/v1/repositories/${VREPO}/members" "{\"member_key\":\"${REPO}\",\"priority\":1}"
  if [ "$API_STATUS" -ge 200 ] 2>/dev/null && [ "$API_STATUS" -lt 300 ] 2>/dev/null; then pass
  else fail "virtual member add HTTP ${API_STATUS}" "${API_BODY:0:300}"; end_suite; fi
else
  fail "repository create failed"; end_suite
fi

begin_test "Setup: enable the age gate on the Remote (min_age_days 7, upstream_publish_time)"
api_call PUT "/api/v1/repositories/${REPO}/age-gate" '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}'
put_status="$API_STATUS"; put_body="$API_BODY"
if [ "$put_status" = "200" ]; then
  GATE_VIA="api"
else
  # 1.11.5 refuses the config for Maven. Switch the gate on in the database
  # so the run shows what a gated Maven Remote served before #4702.
  echo "  age-gate PUT HTTP ${put_status} (${put_body:0:160}); enabling it in the database"
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -c \
    "UPDATE repositories SET age_gate_enabled = true, age_gate_min_age_days = 7, age_gate_mode = 'upstream_publish_time' WHERE key = '${REPO}'" >/dev/null 2>&1 || true
  GATE_VIA="db"
  # the repo cache holds the previous columns for up to 60 s
  sleep 61
fi
got="$(psql_q "SELECT age_gate_enabled::text||'|'||age_gate_min_age_days||'|'||age_gate_mode FROM repositories WHERE key='${REPO}'")"
if [ "$got" = "true|7|upstream_publish_time" ]; then pass
else fail "age gate not configured (via ${GATE_VIA}: ${got})" "${put_body:0:300}"; end_suite; fi

# ---------------------------------------------------------------------------
# Remote: metadata, then the young files, then the old one
# ---------------------------------------------------------------------------
META="${WORK_DIR}/meta.xml"
st=$(fetch "$REPO" "${G}/maven-metadata.xml" "$META")
vers="$(versions_in "$META")"
begin_test "FIX #4702: the Remote's maven-metadata.xml lists only ${OLD} (latest/release ${OLD})"
if [ "$st" = "200" ] && [ "$vers" = "$OLD" ] && grep -q "<latest>${OLD}</latest>" "$META" \
   && grep -q "<release>${OLD}</release>" "$META"; then pass
else fail "#4702: metadata HTTP ${st} lists [${vers}]; a resolver would pick the young ${YOUNG}" "$(head -c 600 "$META")"; fi

begin_test "CONTROL: the metadata .sha1 matches the served metadata body"
st=$(fetch "$REPO" "${G}/maven-metadata.xml.sha1" "${WORK_DIR}/meta.sha1")
want="$(sha1_of "$META")"; got="$(tr -d '[:space:]' < "${WORK_DIR}/meta.sha1" 2>/dev/null)"
if [ "$st" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass
else fail "metadata .sha1 HTTP ${st}: ${got:-none} vs body ${want:-none}"; fi

for what in jar pom jar.sha1; do
  begin_test "FIX #4702: the young ${YOUNG} ${what} is refused with 451 age_gate_blocked"
  f="${WORK_DIR}/young.${what}"
  st=$(fetch "$REPO" "${G}/${YOUNG}/widget-${YOUNG}.${what}" "$f")
  assert_refused "$what" "$st" "$f"
done

begin_test "FIX #4702: the refused young jar was never fetched from the upstream"
if mock_log | grep -qx "GET /${G}/${YOUNG}/widget-${YOUNG}.jar"; then
  fail "#4702: the backend fetched the young jar upstream" "$(mock_log | head -c 800)"
else pass; fi

begin_test "FIX #4702: the refusal recorded one pending review for ${PKG} ${YOUNG}"
reviews="$(psql_q "SELECT count(*) FROM age_gate_reviews r JOIN repositories x ON x.id = r.repository_id WHERE x.key='${REPO}' AND r.package_name='${PKG}' AND r.package_version='${YOUNG}' AND r.status='pending'")"
if [ "${reviews:-0}" = "1" ]; then pass
else fail "#4702: ${reviews:-0} pending reviews for ${YOUNG}"; fi

begin_test "CONTROL: the old ${OLD} jar downloads 200 with the upstream bytes"
st=$(fetch "$REPO" "${G}/${OLD}/widget-${OLD}.jar" "${WORK_DIR}/old.jar")
mock_get "${G}/${OLD}/widget-${OLD}.jar" > "${WORK_DIR}/old.mock"
if [ "$st" = "200" ] && [ -s "${WORK_DIR}/old.mock" ] && [ "$(sha256_of "${WORK_DIR}/old.jar")" = "$(sha256_of "${WORK_DIR}/old.mock")" ]; then pass
else fail "old jar HTTP ${st}, bytes $(sha256_of "${WORK_DIR}/old.jar") vs mock $(sha256_of "${WORK_DIR}/old.mock")"; fi

# ---------------------------------------------------------------------------
# Virtual over the gated Remote
# ---------------------------------------------------------------------------
begin_test "FIX #4702: through the Virtual the young jar is refused with 451"
f="${WORK_DIR}/v.young.jar"
st=$(fetch "$VREPO" "${G}/${YOUNG}/widget-${YOUNG}.jar" "$f")
assert_refused "jar (virtual)" "$st" "$f"

begin_test "FIX #4702: the Virtual's merged maven-metadata.xml lists only ${OLD}"
VMETA="${WORK_DIR}/vmeta.xml"
st=$(fetch "$VREPO" "${G}/maven-metadata.xml" "$VMETA")
vers="$(versions_in "$VMETA")"
if [ "$st" = "200" ] && [ "$vers" = "$OLD" ]; then pass
else fail "#4702: virtual metadata HTTP ${st} lists [${vers}]" "$(head -c 600 "$VMETA")"; fi

begin_test "CONTROL: the old ${OLD} jar downloads through the Virtual"
st=$(fetch "$VREPO" "${G}/${OLD}/widget-${OLD}.jar" "${WORK_DIR}/v.old.jar")
if [ "$st" = "200" ] && [ "$(sha256_of "${WORK_DIR}/v.old.jar")" = "$(sha256_of "${WORK_DIR}/old.mock")" ]; then pass
else fail "virtual old jar HTTP ${st}"; fi

# ---------------------------------------------------------------------------
# An approved review lets the young version through
# ---------------------------------------------------------------------------
begin_test "FIX #4702: once its review is approved the young jar downloads with the upstream bytes"
rv="$(psql_q "SELECT r.id FROM age_gate_reviews r JOIN repositories x ON x.id = r.repository_id WHERE x.key='${REPO}' AND r.package_version='${YOUNG}' LIMIT 1")"
if [ -z "$rv" ]; then
  fail "#4702: no review to approve for ${YOUNG}"
else
  api_call POST "/api/v1/admin/age-gate/reviews/${rv}/approve" '{"reason":"dtf maven-age-gate approve"}'
  ap="$API_STATUS"
  st=$(fetch "$REPO" "${G}/${YOUNG}/widget-${YOUNG}.jar" "${WORK_DIR}/young.ok.jar")
  mock_get "${G}/${YOUNG}/widget-${YOUNG}.jar" > "${WORK_DIR}/young.mock"
  if [ "$ap" = "200" ] && [ "$st" = "200" ] && [ "$(sha256_of "${WORK_DIR}/young.ok.jar")" = "$(sha256_of "${WORK_DIR}/young.mock")" ]; then pass
  else fail "approve HTTP ${ap}, young jar then HTTP ${st}" "$(head -c 300 "${WORK_DIR}/young.ok.jar" 2>/dev/null)"; fi
fi

end_suite
