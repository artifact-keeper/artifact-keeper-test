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
# #6284: a private gated Remote and a Virtual over it. A private member turns
# the Virtual's 60 s merge cache off (#3323), so each request runs the member's
# filter, as it does for any Virtual with a private member.
PREPO="dtf-mvn-agegate-p-${SUF}"
PVREPO="dtf-mvn-agegate-pv-${SUF}"
MOCK="ak-dtf${DTF_SLOT}-mock-maven"
UPSTREAM="http://mock-maven/"
G="com/example/agegate/widget"
GG="com/example/agegate"
OLD="1.0.0"
YOUNG="2.0.0"
PKG="com.example.agegate:widget"

cleanup_repos() {
  api_delete "/api/v1/repositories/${PVREPO}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${PREPO}" >/dev/null 2>&1 || true
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
# #6382: a gated GA-level document the gate cannot filter (no groupId /
# artifactId for the parser, or not UTF-8) answers the gate's retryable 503,
# with its .sha1, instead of the unfiltered upstream list. #6411: group-level
# plugin-prefix metadata has no version index, so it is still served.
# ---------------------------------------------------------------------------
# assert_unfilterable WHERE STATUS FILE GA: 503 age_gate_unavailable for GA
assert_unfilterable() {
  local where="$1" st="$2" f="$3" ga="$4" err pkg
  err="$(jqr '.error' < "$f")"; pkg="$(jqr '.package' < "$f")"
  if [ "$st" = "503" ] && [ "$err" = "age_gate_unavailable" ] && [ "$pkg" = "com.example.agegate:${ga}" ] \
     && ! grep -q "<version>${YOUNG}</version>" "$f"; then pass
  else fail "#6382: ${where} answered HTTP ${st} (error ${err:-none}); want 503 age_gate_unavailable, not the unfiltered list" \
    "$(head -c 400 "$f" 2>/dev/null)"; fi
}

for ga in broken latin; do
  what="unparseable"; [ "$ga" = "latin" ] && what="non-UTF-8"
  begin_test "FIX #6382: the gated Remote refuses the ${what} ${ga} maven-metadata.xml with 503"
  f="${WORK_DIR}/u6382.${ga}.xml"
  st=$(fetch "$REPO" "${GG}/${ga}/maven-metadata.xml" "$f")
  echo "  #6382 Remote ${ga}: HTTP ${st}, lists [$(versions_in "$f")]"
  assert_unfilterable "the Remote's ${what} ${ga} metadata" "$st" "$f" "$ga"

  begin_test "FIX #6382: the gated Remote refuses the ${ga} maven-metadata.xml.sha1 with 503"
  f="${WORK_DIR}/u6382.${ga}.sha1"
  st=$(fetch "$REPO" "${GG}/${ga}/maven-metadata.xml.sha1" "$f")
  assert_unfilterable "the Remote's ${ga} metadata .sha1" "$st" "$f" "$ga"
done

begin_test "FIX #6382: the gated Virtual refuses the unparseable broken maven-metadata.xml with 503"
f="${WORK_DIR}/u6382.v.broken.xml"
st=$(fetch "$VREPO" "${GG}/broken/maven-metadata.xml" "$f")
echo "  #6382 Virtual broken: HTTP ${st}, lists [$(versions_in "$f")]"
assert_unfilterable "the Virtual's broken metadata" "$st" "$f" broken

begin_test "FIX #6382: the gated Virtual refuses the broken maven-metadata.xml.sha1 with 503"
f="${WORK_DIR}/u6382.v.broken.sha1"
st=$(fetch "$VREPO" "${GG}/broken/maven-metadata.xml.sha1" "$f")
assert_unfilterable "the Virtual's broken metadata .sha1" "$st" "$f" broken

PP="org/apache/maven/plugins/maven-metadata.xml"
begin_test "GUARD #6411: the gated Remote serves group-level plugin-prefix metadata 200, byte for byte"
f="${WORK_DIR}/pp.remote.xml"
st=$(fetch "$REPO" "$PP" "$f")
mock_get "$PP" > "${WORK_DIR}/pp.mock"
if [ "$st" = "200" ] && [ -s "${WORK_DIR}/pp.mock" ] && cmp -s "$f" "${WORK_DIR}/pp.mock"; then pass
else fail "#6411: plugin-prefix metadata through the gated Remote HTTP ${st}; mvn prefix:goal cannot resolve" "$(head -c 400 "$f" 2>/dev/null)"; fi

begin_test "GUARD #6411: the gated Remote's plugin-prefix .sha1 matches the body"
st=$(fetch "$REPO" "${PP}.sha1" "${WORK_DIR}/pp.remote.sha1")
want="$(sha1_of "$f")"; got="$(tr -d '[:space:]' < "${WORK_DIR}/pp.remote.sha1" 2>/dev/null)"
if [ "$st" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass
else fail "#6411: plugin-prefix .sha1 HTTP ${st}: ${got:-none} vs body ${want:-none}"; fi

begin_test "GUARD #6411: the gated Virtual serves the plugin-prefix metadata 200 with both prefixes"
f="${WORK_DIR}/pp.virtual.xml"
st=$(fetch "$VREPO" "$PP" "$f")
if [ "$st" = "200" ] && grep -q '<prefix>compiler</prefix>' "$f" && grep -q '<prefix>surefire</prefix>' "$f" \
   && grep -q '<artifactId>maven-compiler-plugin</artifactId>' "$f"; then pass
else fail "#6411: plugin-prefix metadata through the gated Virtual HTTP ${st}" "$(head -c 400 "$f" 2>/dev/null)"; fi

begin_test "CONTROL #6382: the parseable widget metadata is still 200 through the Remote and the Virtual"
st1=$(fetch "$REPO" "${G}/maven-metadata.xml" "${WORK_DIR}/c6382.r.xml")
st2=$(fetch "$VREPO" "${G}/maven-metadata.xml" "${WORK_DIR}/c6382.v.xml")
if [ "$st1" = "200" ] && [ "$st2" = "200" ] && [ "$(versions_in "${WORK_DIR}/c6382.r.xml")" = "$OLD" ]; then pass
else fail "widget metadata Remote HTTP ${st1}, Virtual HTTP ${st2}"; fi

# ---------------------------------------------------------------------------
# #6284: while a GA is still being dated (more undated versions than one
# listing probes), the metadata body and its checksum sidecars must describe
# the same filtered document, and two downloads in a row must agree.
# ---------------------------------------------------------------------------
# metadata_round REPO GA TAG: body, .sha1, .md5, body again, back to back
metadata_round() {
  local repo="$1" ga="$2" tag="$3"
  R_ST1=$(fetch "$repo" "${GG}/${ga}/maven-metadata.xml" "${WORK_DIR}/${tag}.1.xml")
  R_STS=$(fetch "$repo" "${GG}/${ga}/maven-metadata.xml.sha1" "${WORK_DIR}/${tag}.sha1")
  R_STM=$(fetch "$repo" "${GG}/${ga}/maven-metadata.xml.md5" "${WORK_DIR}/${tag}.md5")
  R_ST2=$(fetch "$repo" "${GG}/${ga}/maven-metadata.xml" "${WORK_DIR}/${tag}.2.xml")
  R_N1=$(versions_in "${WORK_DIR}/${tag}.1.xml" | wc -w | tr -d ' ')
  R_N2=$(versions_in "${WORK_DIR}/${tag}.2.xml" | wc -w | tr -d ' ')
}
md5_of() { md5sum "$1" 2>/dev/null | awk '{print $1}'; }

# assert_round WHERE TAG: the checks on one metadata_round
assert_round() {
  local where="$1" tag="$2" body="${WORK_DIR}/${2}.1.xml" want got
  begin_test "FIX #6284: ${where}: maven-metadata.xml.sha1 matches the metadata body just served"
  want="$(sha1_of "$body")"; got="$(tr -d '[:space:]' < "${WORK_DIR}/${tag}.sha1" 2>/dev/null)"
  if [ "$R_ST1" = "200" ] && [ "$R_STS" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass
  else fail "#6284: ${where} body HTTP ${R_ST1} (${R_N1} versions), .sha1 HTTP ${R_STS}: ${got:-none} vs body ${want:-none}"; fi

  begin_test "FIX #6284: ${where}: maven-metadata.xml.md5 matches the metadata body just served"
  want="$(md5_of "$body")"; got="$(tr -d '[:space:]' < "${WORK_DIR}/${tag}.md5" 2>/dev/null)"
  if [ "$R_STM" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass
  else fail "#6284: ${where} .md5 HTTP ${R_STM}: ${got:-none} vs body ${want:-none}"; fi

  begin_test "FIX #6284: ${where}: two metadata downloads in a row list the same versions"
  if [ "$R_ST2" = "200" ] && [ "$R_N1" -gt 0 ] 2>/dev/null \
     && cmp -s "$body" "${WORK_DIR}/${tag}.2.xml"; then pass
  else fail "#6284: ${where} first download ${R_N1} versions, second ${R_N2} (HTTP ${R_ST2})"; fi

  begin_test "CONTROL: ${where}: the young ${YOUNG} is never listed while dating"
  if [ -s "$body" ] && ! grep -q "<version>${YOUNG}</version>" "$body" "${WORK_DIR}/${tag}.2.xml"; then pass
  else fail "${where}: the young ${YOUNG} is listed" "$(head -c 400 "$body")"; fi
}

metadata_round "$REPO" bulk r1
assert_round "Remote" r1

# The memo is short-lived (15 s): the next listing after it continues dating.
sleep 16
metadata_round "$REPO" bulk r2
N_FIRST="$(versions_in "${WORK_DIR}/r1.1.xml" | wc -w | tr -d ' ')"
begin_test "CONTROL: Remote: a listing after the memo window has dated more versions than the first"
if [ "$R_ST1" = "200" ] && [ "$R_N1" -gt "$N_FIRST" ] 2>/dev/null; then pass
else fail "a listing after the memo window lists ${R_N1} versions, the first ${N_FIRST}"; fi
assert_round "Remote, later pass" r2

begin_test "Setup #6284: a private gated Remote over the mock and a Virtual over it"
api_call POST "/api/v1/repositories" "{\"key\":\"${PREPO}\",\"name\":\"${PREPO}\",\"format\":\"maven\",\"repo_type\":\"remote\",\"upstream_url\":\"${UPSTREAM}\",\"is_public\":false}"
s1="$API_STATUS"
api_call POST "/api/v1/repositories" "{\"key\":\"${PVREPO}\",\"name\":\"${PVREPO}\",\"format\":\"maven\",\"repo_type\":\"virtual\",\"is_public\":false}"
s2="$API_STATUS"
api_call POST "/api/v1/repositories/${PVREPO}/members" "{\"member_key\":\"${PREPO}\",\"priority\":1}"
s3="$API_STATUS"
api_call PUT "/api/v1/repositories/${PREPO}/age-gate" '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}'
s4="$API_STATUS"
if [[ "$s1" == 20? && "$s2" == 20? && "$s3" == 20? && "$s4" == 200 ]]; then pass
else fail "create remote ${s1}, virtual ${s2}, member ${s3}, age-gate ${s4}" "${API_BODY:0:300}"; fi

metadata_round "$PVREPO" vbulk v1
assert_round "Virtual" v1

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

# ---------------------------------------------------------------------------
# #6345: a review decision reaches the Virtual's 60 s merge cache. The Virtual
# over the public gated Remote keeps its merged widget metadata (fully dated,
# so cacheable) for 60 s. Each check below reads the Virtual right after the
# decision, well inside that window.
# ---------------------------------------------------------------------------
# virtual_meta TAG -> V_ST, V_VERS, V_FILE: the Virtual's merged widget metadata
virtual_meta() {
  V_FILE="${WORK_DIR}/v6345.$1.xml"
  V_ST=$(fetch "$VREPO" "${G}/maven-metadata.xml" "$V_FILE")
  V_VERS="$(versions_in "$V_FILE")"
}
# assert_withheld WHAT: the Virtual's metadata lists only OLD, latest/release OLD
assert_withheld() {
  if [ "$V_ST" = "200" ] && [ "$V_VERS" = "$OLD" ] && grep -q "<latest>${OLD}</latest>" "$V_FILE" \
     && grep -q "<release>${OLD}</release>" "$V_FILE"; then pass
  else fail "#6345: $1: the Virtual's metadata HTTP ${V_ST} lists [${V_VERS}]; a resolver picks the ${YOUNG} the gate now refuses" \
    "$(head -c 500 "$V_FILE" 2>/dev/null)"; fi
}

begin_test "Setup #6345: the Virtual's merged metadata lists the approved ${YOUNG} (cache warm)"
# The approval above may still be hidden behind a merge cached before it (on
# an image without the fix, up to 60 s), so wait for the listing.
deadline=$((SECONDS + 75))
while :; do
  virtual_meta warm
  if [ "$V_ST" = "200" ] && [ "$V_VERS" = "${OLD} ${YOUNG}" ]; then break; fi
  [ "$SECONDS" -ge "$deadline" ] && break
  sleep 3
done
if [ "$V_ST" = "200" ] && [ "$V_VERS" = "${OLD} ${YOUNG}" ] && [ -n "$rv" ]; then pass
else fail "Virtual metadata HTTP ${V_ST} lists [${V_VERS}] after the approval (review ${rv:-none})"; end_suite; fi

begin_test "FIX #6345: right after the review is rejected, the Virtual's metadata withholds ${YOUNG}"
api_call POST "/api/v1/admin/age-gate/reviews/${rv}/reject" '{"reason":"dtf #6345 reject"}'
rj="$API_STATUS"
t_reject=$SECONDS
virtual_meta rejected
if [ "$rj" != "200" ]; then fail "reject HTTP ${rj}" "${API_BODY:0:300}"
else
  assert_withheld "after the rejection"
  # How long the Virtual keeps listing the rejected version (the number the
  # fix brings to 0; bounded by the 60 s merge cache).
  while [ "$V_VERS" != "$OLD" ] && [ $((SECONDS - t_reject)) -lt 75 ]; do
    sleep 1; virtual_meta converging
  done
  echo "  #6345 metric: the Virtual listed the rejected ${YOUNG} for $((SECONDS - t_reject)) s after the rejection"
fi

begin_test "CONTROL #6345: the Remote's own metadata withholds the rejected ${YOUNG}"
st=$(fetch "$REPO" "${G}/maven-metadata.xml" "${WORK_DIR}/r6345.rejected.xml")
vers="$(versions_in "${WORK_DIR}/r6345.rejected.xml")"
if [ "$st" = "200" ] && [ "$vers" = "$OLD" ]; then pass
else fail "Remote metadata HTTP ${st} lists [${vers}] after the rejection"; fi

begin_test "CONTROL #6345: the Virtual's metadata .sha1 matches the body served after the rejection"
st=$(fetch "$VREPO" "${G}/maven-metadata.xml.sha1" "${WORK_DIR}/v6345.sha1")
want="$(sha1_of "$V_FILE")"; got="$(tr -d '[:space:]' < "${WORK_DIR}/v6345.sha1" 2>/dev/null)"
if [ "$st" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass
else fail "Virtual .sha1 HTTP ${st}: ${got:-none} vs body ${want:-none}"; fi

begin_test "CONTROL #6345: the rejected ${YOUNG} jar answers 451 through the Virtual"
f="${WORK_DIR}/v6345.young.jar"
st=$(fetch "$VREPO" "${G}/${YOUNG}/widget-${YOUNG}.jar" "$f")
if [ "$st" = "451" ] && [ "$(jqr '.error' < "$f")" = "age_gate_blocked" ]; then pass
else fail "Virtual young jar HTTP ${st} after the rejection" "$(head -c 300 "$f" 2>/dev/null)"; fi

# Approve then reopen: the reopened (pending) version is withheld again at
# once. Without the fix the merge cached right after the approval keeps
# listing it.
begin_test "FIX #6345: approved, then reopened, the Virtual's metadata withholds ${YOUNG} at once"
api_call POST "/api/v1/admin/age-gate/reviews/${rv}/approve" '{"reason":"dtf #6345 approve"}'
ap="$API_STATUS"
virtual_meta reapproved
ap_vers="$V_VERS"
api_call POST "/api/v1/admin/age-gate/reviews/${rv}/reopen" '{"reason":"dtf #6345 reopen"}'
ro="$API_STATUS"
virtual_meta reopened
if [ "$ap" != "200" ] || [ "$ro" != "200" ]; then fail "approve HTTP ${ap}, reopen HTTP ${ro}" "${API_BODY:0:300}"
elif [ "$ap_vers" != "${OLD} ${YOUNG}" ]; then
  fail "#6345: right after the approval the Virtual lists [${ap_vers}], not ${OLD} ${YOUNG}"
else assert_withheld "after the reopen"; fi

end_suite
