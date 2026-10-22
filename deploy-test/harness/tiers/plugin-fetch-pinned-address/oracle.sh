#!/usr/bin/env bash
# =============================================================================
# tiers/plugin-fetch-pinned-address/oracle.sh: plugin git fetches connect only
# to addresses the SSRF policy admits (artifact-keeper#4827), and a redirect
# the policy refuses answers 400 on the plugin path and 503 on the proxy path
# (artifact-keeper#4869)
# =============================================================================
# run.sh has stood up storage.filesystem + upstreams.mock-git +
# upstreams.mock-git-rebind and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR. See the
# manifest for the bug and the shape of every case.
#
# Discriminating cases (RED on 1.11.3, GREEN on a build with the fix):
#   FIX-1 install from a name whose second lookup answers the internal host
#         -> 400 naming AK_SSRF_ALLOW_PRIVATE_CIDRS, internal mock never
#         contacted, no plugin row.
#   FIX-2 the same on reload of an installed plugin -> 400, version unchanged.
#   FIX-3 install whose reference advertisement redirects to the internal
#         host -> refused, internal mock never contacted, no plugin row.
#   FIX-4 install whose advertisement redirects to the backend's own
#         loopback port -> refused, the backend never serves that path.
#   FIX-5 reload whose advertisement redirects to the internal host ->
#         refused, internal mock never contacted, version unchanged.
# Discriminating cases for #4869 (RED on 1.11.4, which answers 500 for a
# redirect hop the policy refuses; GREEN on a build with #4872):
#   FIX-4 (above) additionally wants 400 with the plugin policy wording.
#   R-1   install whose advertisement redirects to the internal host's IP
#         literal (refused by the per-hop redirect policy, not the DNS guard)
#         -> 400 naming the redirect target and AK_SSRF_ALLOW_PRIVATE_CIDRS,
#         internal mock never contacted, no plugin row.
#   R-2   the same on reload -> 400, version unchanged, never contacted.
#   R-3   a generic Remote on the admitted host whose upstream answers a
#         download with a redirect to the internal IP literal -> 503 (the
#         policy-refusal status; the route sanitizes the body), internal mock
#         never contacted (1.11.4 answers 502 for it).
# Controls (GREEN on both): install and reload through the rebinding resolver
# in static mode, and an install redirected to another path on the admitted
# host.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SL="$DTF_SLOT"
SUF="${RUN_ID##*-}-$$"
TAG="${RUN_ID##*-}$$"
MOCK_OK="ak-dtf${SL}-mock-git"
MOCK_INT="ak-dtf${SL}-mock-git-internal"
MOCK_DNS="ak-dtf${SL}-mock-dns"
BACKEND_CTR="ak-dtf${SL}-backend"
OK_IP="172.16.${SL}.80"
INT_IP="172.16.${SL}.81"
REBIND_HOST="plugin-rebind.dtf.test"
# Each case has its own repository path (carrying the run id, so log greps
# never match an earlier run on a kept stack) and its own plugin name (so a
# baseline that installs from the internal host cannot collide later cases).
CTL_NAME="dtf-pin-ctl-${TAG}"

CODE=""; BODY=""
req() {
  local m="$1" p="$2" d="${3:-}" tmp
  tmp="$(mktemp)"
  if [ -n "$d" ]; then
    CODE="$(curl -s -o "$tmp" -w '%{http_code}' --max-time 40 -X "$m" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
      -d "$d" "${BASE_URL}${p}" 2>/dev/null)" || CODE="000"
  else
    CODE="$(curl -s -o "$tmp" -w '%{http_code}' --max-time 40 -X "$m" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}${p}" 2>/dev/null)" || CODE="000"
  fi
  BODY="$(cat "$tmp" 2>/dev/null || true)"
  rm -f "$tmp"
}
db1() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
# ctl CONTAINER PORT QUERY: steer a mock (git: version/sig/name/redirect; dns: mode/first).
ctl() {
  docker exec "$1" python3 -c \
    "import urllib.request,sys; print(urllib.request.urlopen('http://127.0.0.1:'+sys.argv[1]+'/__ctl?'+sys.argv[2],timeout=5).read().decode())" \
    "$2" "$3" 2>/dev/null
}
git_ctl() { ctl "$1" 80 "$2"; }
dns_ctl() { ctl "$MOCK_DNS" 8053 "$1"; }
# hits CONTAINER PATH: request lines a git mock served for one repository path.
hits() { docker logs "$1" 2>&1 | grep -c "MOCKGIT [a-z]* [A-Z]* /$2/" || true; }
# dns_answers IP: rebinding-resolver answers for REBIND_HOST that gave IP.
dns_answers() { docker logs "$MOCK_DNS" 2>&1 | grep -c "MOCKDNS A #[0-9]* ${REBIND_HOST} -> $1\$" || true; }
backend_served() { docker logs "$BACKEND_CTR" 2>&1 | grep -c "uri=/$1/info/refs" || true; }
plugin_rows() { db1 "SELECT count(*) FROM plugins WHERE name='$1'"; }
refused() { [ "$CODE" != "000" ] && [ "${CODE:0:1}" != "2" ]; }
# refused_400: the #4869 plugin-path answer for a redirect hop the policy
# refuses: 400 with the same policy wording as the connect-time refusal.
refused_400() {
  [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL" \
    && echo "$BODY" | grep -q "redirect target" \
    && echo "$BODY" | grep -q "SSRF policy" \
    && echo "$BODY" | grep -q "AK_SSRF_ALLOW_PRIVATE_CIDRS"
}

begin_suite "plugin-fetch-pinned-address-4827"
auth_admin

for m in "$MOCK_OK" "$MOCK_INT"; do git_ctl "$m" "version=1.0.0&sig=good&redirect=&name=" >/dev/null; done
dns_ctl "mode=static" >/dev/null

# ---------------------------------------------------------------------------
# CONTROLS
# ---------------------------------------------------------------------------
begin_test "CONTROL: install through the test resolver (static: ${REBIND_HOST} -> ${OK_IP}) clones from the admitted host"
git_ctl "$MOCK_OK" "name=${CTL_NAME}&version=1.0.0" >/dev/null
CTL_URL="http://${REBIND_HOST}/ctl-${SUF}.git"
req POST "/api/v1/plugins/install/git" "{\"url\":\"${CTL_URL}\"}"
PLUGIN_ID="$(echo "$BODY" | jq -r '.plugin_id // empty' 2>/dev/null)"
if [ "$CODE" = "200" ] && [ -n "$PLUGIN_ID" ] \
   && [ "$(echo "$BODY" | jq -r '.name' 2>/dev/null)" = "$CTL_NAME" ] \
   && [ "$(db1 "SELECT source_url FROM plugins WHERE id='${PLUGIN_ID}'")" = "$CTL_URL" ] \
   && [ "$(hits "$MOCK_OK" "ctl-${SUF}.git")" -ge 2 ] && [ "$(dns_answers "$OK_IP")" -ge 2 ]; then
  pass
else
  fail_fatal "install through the test resolver failed (HTTP ${CODE}); every reload case uses this plugin" \
    "body=${BODY:0:400} approved_hits=$(hits "$MOCK_OK" "ctl-${SUF}.git") dns_answers=$(dns_answers "$OK_IP")"
fi

begin_test "CONTROL: reload through the test resolver (static) replaces the plugin (1.0.0 -> 2.0.0)"
git_ctl "$MOCK_OK" "version=2.0.0" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if [ "$CODE" = "200" ] && [ "$(echo "$BODY" | jq -r '.version' 2>/dev/null)" = "2.0.0" ] && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "benign reload did not replace the plugin: HTTP ${CODE}, db version=${DB_VER}" "${BODY:0:400}"
fi

begin_test "CONTROL: an advertisement redirected to another path on the admitted host is followed and the plugin installs"
MOVED_NAME="dtf-pin-moved-${TAG}"
git_ctl "$MOCK_OK" "name=${MOVED_NAME}&version=1.0.0&redirect=http://plugin-src/moved-${SUF}.git" >/dev/null
req POST "/api/v1/plugins/install/git" "{\"url\":\"http://plugin-src/old-${SUF}.git\"}"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
if [ "$CODE" = "200" ] && [ "$(echo "$BODY" | jq -r '.name' 2>/dev/null)" = "$MOVED_NAME" ] \
   && [ "$(hits "$MOCK_OK" "moved-${SUF}.git")" -ge 2 ]; then
  pass
else
  fail "a same-host redirect was not followed: HTTP ${CODE}, moved-path hits=$(hits "$MOCK_OK" "moved-${SUF}.git")" "${BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# FIX-1/2: the host's address changes between the URL check and the fetch.
# The resolver answers the admitted host for the first lookup after a reset
# (the URL check) and the internal host after that.
# ---------------------------------------------------------------------------
begin_test "FIX #4827: install from a name that re-resolves to the internal host is refused 400; the internal host is never contacted"
RB_NAME="dtf-pin-rb-${TAG}"
git_ctl "$MOCK_INT" "name=${RB_NAME}&version=6.6.6" >/dev/null
INT_BEFORE="$(dns_answers "$INT_IP")"
dns_ctl "mode=rebind&first=1" >/dev/null
req POST "/api/v1/plugins/install/git" "{\"url\":\"http://${REBIND_HOST}/rb-${SUF}.git\"}"
dns_ctl "mode=static" >/dev/null
RB_HITS="$(hits "$MOCK_INT" "rb-${SUF}.git")"
RB_ROWS="$(plugin_rows "$RB_NAME")"
RB_SECOND="$(( $(dns_answers "$INT_IP") - INT_BEFORE ))"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL" \
   && echo "$BODY" | grep -q "AK_SSRF_ALLOW_PRIVATE_CIDRS" \
   && [ "$RB_HITS" = "0" ] && [ "$RB_ROWS" = "0" ] && [ "$RB_SECOND" -ge 1 ]; then
  pass
else
  fail "the fetch resolved the host again and connected where it pointed: HTTP ${CODE}, internal mock request lines=${RB_HITS}, plugin rows=${RB_ROWS}, internal answers served=${RB_SECOND}" \
    "${BODY:0:400}"
fi

begin_test "FIX #4827: reload of a plugin whose host re-resolves to the internal host is refused 400; version unchanged, internal host never contacted"
git_ctl "$MOCK_INT" "name=${CTL_NAME}&version=6.6.6" >/dev/null
HITS_BEFORE="$(hits "$MOCK_INT" "ctl-${SUF}.git")"
dns_ctl "mode=rebind&first=1" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
dns_ctl "mode=static" >/dev/null
HITS_AFTER="$(hits "$MOCK_INT" "ctl-${SUF}.git")"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "AK_SSRF_ALLOW_PRIVATE_CIDRS" \
   && [ "$HITS_AFTER" = "$HITS_BEFORE" ] && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "reload fetched from the re-resolved internal host: HTTP ${CODE}, internal request lines ${HITS_BEFORE}->${HITS_AFTER}, db version=${DB_VER} (6.6.6 = replaced from it)" \
    "${BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# FIX-3/4/5: the admitted host answers the reference advertisement with a
# redirect to an address the policy does not admit. The fetch must re-check
# the hop. FIX-3 and FIX-5 redirect to a NAME, which the connect-time DNS
# guard refuses; they assert the refusal, not its status class. FIX-4 and the
# #4869 cases below redirect to an IP literal, which the per-hop redirect
# policy refuses; before #4869 that refusal surfaced as a 500, so they want
# the 400.
# ---------------------------------------------------------------------------
begin_test "FIX #4827: install redirected to the internal host is refused; the internal host is never contacted and no plugin is stored"
RD_NAME="dtf-pin-rd-${TAG}"
git_ctl "$MOCK_INT" "name=${RD_NAME}&version=6.6.6" >/dev/null
git_ctl "$MOCK_OK" "redirect=http://plugin-src-internal/rdi-${SUF}.git" >/dev/null
req POST "/api/v1/plugins/install/git" "{\"url\":\"http://plugin-src/rd-${SUF}.git\"}"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
RD_HITS="$(hits "$MOCK_INT" "rdi-${SUF}.git")"
RD_ROWS="$(plugin_rows "$RD_NAME")"
if refused && [ "$RD_HITS" = "0" ] && [ "$RD_ROWS" = "0" ] \
   && [ "$(hits "$MOCK_OK" "rd-${SUF}.git")" -ge 1 ]; then
  pass
else
  fail "the redirect to the internal host was followed: HTTP ${CODE}, internal request lines=${RD_HITS}, plugin rows=${RD_ROWS}" "${BODY:0:400}"
fi

begin_test "FIX #4827/#4869: install redirected to the backend's own loopback port is refused 400 with the policy wording; the backend never serves that path"
git_ctl "$MOCK_OK" "redirect=http://127.0.0.1:8080/rdl-${SUF}.git" >/dev/null
req POST "/api/v1/plugins/install/git" "{\"url\":\"http://plugin-src/rl-${SUF}.git\"}"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
sleep 1
LOOP_SEEN="$(backend_served "rdl-${SUF}.git")"
if refused_400 && [ "$LOOP_SEEN" = "0" ] && [ "$(hits "$MOCK_OK" "rl-${SUF}.git")" -ge 1 ]; then
  pass
else
  fail "the redirect to loopback was not refused with the policy's 400: HTTP ${CODE} (500 = #4869), backend request-log lines for the redirected path=${LOOP_SEEN}" "${BODY:0:400}"
fi

begin_test "FIX #4827: reload redirected to the internal host is refused; version unchanged, internal host never contacted"
git_ctl "$MOCK_INT" "name=${CTL_NAME}&version=6.6.6" >/dev/null
git_ctl "$MOCK_OK" "redirect=http://plugin-src-internal/rdr-${SUF}.git" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
RR_HITS="$(hits "$MOCK_INT" "rdr-${SUF}.git")"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if refused && [ "$RR_HITS" = "0" ] && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "reload followed the redirect to the internal host: HTTP ${CODE}, internal request lines=${RR_HITS}, db version=${DB_VER}" "${BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# #4869: a redirect hop the per-hop policy refuses (an IP literal the policy
# does not admit) answers 400 on the plugin path and 503 on the proxy path.
# The redirect target is the internal mock's own address, so its request log
# proves the refusal happened before any connection.
# ---------------------------------------------------------------------------
begin_test "FIX #4869: install redirected to the internal host's IP literal is refused 400 naming the redirect target and AK_SSRF_ALLOW_PRIVATE_CIDRS; never contacted, nothing stored"
RX_NAME="dtf-pin-rx-${TAG}"
git_ctl "$MOCK_INT" "name=${RX_NAME}&version=6.6.6" >/dev/null
git_ctl "$MOCK_OK" "redirect=http://${INT_IP}/rxi-${SUF}.git" >/dev/null
req POST "/api/v1/plugins/install/git" "{\"url\":\"http://plugin-src/rx-${SUF}.git\"}"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
RX_HITS="$(hits "$MOCK_INT" "rxi-${SUF}.git")"
RX_ROWS="$(plugin_rows "$RX_NAME")"
if refused_400 && [ "$RX_HITS" = "0" ] && [ "$RX_ROWS" = "0" ] \
   && [ "$(hits "$MOCK_OK" "rx-${SUF}.git")" -ge 1 ]; then
  pass
else
  fail "a redirect hop the policy refuses did not answer the policy's 400: HTTP ${CODE} (500 = #4869), internal request lines=${RX_HITS}, plugin rows=${RX_ROWS}" "${BODY:0:400}"
fi

begin_test "FIX #4869: reload redirected to the internal host's IP literal is refused 400 with the policy wording; version unchanged, never contacted"
git_ctl "$MOCK_INT" "name=${CTL_NAME}&version=6.6.6" >/dev/null
git_ctl "$MOCK_OK" "redirect=http://${INT_IP}/rxr-${SUF}.git" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
RXR_HITS="$(hits "$MOCK_INT" "rxr-${SUF}.git")"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if refused_400 && [ "$RXR_HITS" = "0" ] && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "reload: a redirect hop the policy refuses did not answer the policy's 400: HTTP ${CODE} (500 = #4869), internal request lines=${RXR_HITS}, db version=${DB_VER}" "${BODY:0:400}"
fi

begin_test "FIX #4869: a Remote download whose upstream redirects to the internal host's IP literal answers 503 (an SSRF policy refusal, not an upstream failure); never contacted"
PX_REPO="dtf-pin-px-${TAG}"
req POST "/api/v1/repositories" \
  "{\"key\":\"${PX_REPO}\",\"name\":\"${PX_REPO}\",\"format\":\"generic\",\"repo_type\":\"remote\",\"upstream_url\":\"http://${OK_IP}\",\"is_public\":false}"
PX_CREATE="$CODE"
git_ctl "$MOCK_OK" "redirect=http://${INT_IP}/pxi-${SUF}" >/dev/null
req GET "/api/v1/repositories/${PX_REPO}/download/__redir/px-${SUF}.bin"
git_ctl "$MOCK_OK" "redirect=" >/dev/null
PX_HITS="$(docker logs "$MOCK_INT" 2>&1 | grep -c "MOCKGIT [a-z]* [A-Z]* /pxi-${SUF}/" || true)"
PX_ASKED="$(docker logs "$MOCK_OK" 2>&1 | grep -c "MOCKGIT [a-z]* GET /__redir/px-${SUF}.bin" || true)"
# The download route answers a 503 with a sanitized body ("Upstream
# temporarily unavailable"), so the status is the signal, not the wording.
if [[ "$PX_CREATE" == 20? ]] && [ "$CODE" = "503" ] \
   && [ "$PX_HITS" = "0" ] && [ "$PX_ASKED" -ge 1 ]; then
  pass
else
  fail "proxy path: create remote -> ${PX_CREATE}; download -> HTTP ${CODE} (want 503; 1.11.4 answers 502), upstream asked=${PX_ASKED}, internal request lines=${PX_HITS}" "${BODY:0:400}"
fi

end_suite
