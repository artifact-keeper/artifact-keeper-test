#!/usr/bin/env bash
# =============================================================================
# tiers/plugin-reload-ssrf/oracle.sh: plugin reload re-validates its git source
# (artifact-keeper#4757, GHSA-r8fc-5fvw-rvh4; fixed in 1.11.2 by #4761)
# =============================================================================
# run.sh has stood up storage.filesystem + upstreams.mock-git and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR. See the manifest for the bug and the
# shape of every case.
#
# Discriminating cases (RED on 1.11.1, GREEN on 1.11.2 and later):
#   FIX-1 DNS flip: the stored host now resolves to the internal mock ->
#         reload 400 naming AK_SSRF_ALLOW_PRIVATE_CIDRS, internal mock sees
#         no request, version unchanged.
#   FIX-2 stored loopback source (the backend's own port) -> 400, and the
#         backend's request log never shows the clone path.
#   FIX-3 stored cloud-metadata, blocked-service-name and file:// sources ->
#         400 from the outbound-URL guard.
# Controls (GREEN on both): signed install + benign reload to 2.0.0, install
# refuses the internal host, the signing gate refuses a bad and a missing
# detached signature on reload.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly, so a non-zero helper (grep with no match, jq on a
# non-JSON error body) must not end the suite before the assertion runs.
set +e

SL="$DTF_SLOT"
SUF="${RUN_ID##*-}-$$"
NET="ak-dtf${SL}-mockgit"
MOCK_OK="ak-dtf${SL}-mock-git"
MOCK_INT="ak-dtf${SL}-mock-git-internal"
BACKEND_CTR="ak-dtf${SL}-backend"
OK_IP="172.16.${SL}.80"
INT_IP="172.16.${SL}.81"
# The mock serves one repository whatever the path; the path carries the run
# id so log greps cannot match a previous run on a kept stack.
SRC_URL="http://plugin-src/dtf-plugin-${SUF}.git"
PLUGIN_NAME="dtf-reload-probe"

CODE=""; BODY=""
# req METHOD PATH [JSON] -> sets CODE and BODY. A curl transport failure
# (timeout, reset) leaves CODE=000 so a hung clone on the baseline is a FAIL,
# not an abort.
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
# mock_ctl CONTAINER QUERY: steer the next clone (version / signature mode).
mock_ctl() {
  docker exec "$1" python3 -c \
    "import urllib.request,sys; print(urllib.request.urlopen('http://127.0.0.1/__ctl?'+sys.argv[1],timeout=5).read().decode())" \
    "$2" 2>/dev/null
}
# mock_hits CONTAINER: request lines that mock has served for this run's path.
mock_hits() { docker logs "$1" 2>&1 | grep -c "MOCKGIT .* /dtf-plugin-${SUF}.git/" || true; }
# insert_git_plugin NAME SOURCE_URL -> echoes the new plugin id. Models a
# plugin whose stored source now names an internal target (the row an
# earlier, valid install left behind); the same shape the backend's own
# #4757 regression test inserts.
insert_git_plugin() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "INSERT INTO plugins (id, name, version, display_name, status, plugin_type, source_type, source_url)
     VALUES (gen_random_uuid(), '$1', '1.0.0', '$1', 'active', 'format_handler', 'wasm_git', '$2')
     RETURNING id;" 2>/dev/null | head -1 | tr -d '[:space:]'
}

begin_suite "plugin-reload-ssrf-4757"
auth_admin

# ---------------------------------------------------------------------------
# CONTROLS: the legitimate install and reload path
# ---------------------------------------------------------------------------
mock_ctl "$MOCK_OK" "version=1.0.0&sig=good" >/dev/null
mock_ctl "$MOCK_INT" "version=1.0.0&sig=good" >/dev/null

begin_test "CONTROL: install from the admitted host (signed plugin) succeeds and stores the source URL"
req POST "/api/v1/plugins/install/git" "{\"url\":\"${SRC_URL}\"}"
PLUGIN_ID="$(echo "$BODY" | jq -r '.plugin_id // empty' 2>/dev/null)"
if [ "$CODE" = "200" ] && [ -n "$PLUGIN_ID" ] \
   && [ "$(echo "$BODY" | jq -r '.version' 2>/dev/null)" = "1.0.0" ] \
   && [ "$(echo "$BODY" | jq -r '.name' 2>/dev/null)" = "$PLUGIN_NAME" ] \
   && [ "$(db1 "SELECT source_url FROM plugins WHERE id='${PLUGIN_ID}'")" = "$SRC_URL" ] \
   && [ "$(mock_hits "$MOCK_OK")" -ge 2 ]; then
  pass
else
  fail_fatal "install from ${SRC_URL} did not succeed (HTTP ${CODE}); every later case reloads this plugin" \
    "body=${BODY:0:400} approved_mock_hits=$(mock_hits "$MOCK_OK")"
fi

begin_test "CONTROL: benign reload from the admitted host replaces the plugin (1.0.0 -> 2.0.0, DB updated)"
mock_ctl "$MOCK_OK" "version=2.0.0&sig=good" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if [ "$CODE" = "200" ] && [ "$(echo "$BODY" | jq -r '.version' 2>/dev/null)" = "2.0.0" ] && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "benign reload did not replace the plugin: HTTP ${CODE}, db version=${DB_VER}" "${BODY:0:400}"
fi

begin_test "CONTROL (signing): reload whose clone carries a signature that does not verify is refused, version unchanged"
mock_ctl "$MOCK_OK" "version=3.0.0&sig=bad" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "signature verification failed" && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "bad-signature reload not refused by the signing gate: HTTP ${CODE}, db version=${DB_VER}" "${BODY:0:400}"
fi

begin_test "CONTROL (signing): reload whose clone has no plugin.wasm.sig is refused, version unchanged"
mock_ctl "$MOCK_OK" "version=3.0.0&sig=none" >/dev/null
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "missing a detached" && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "unsigned reload not refused by the signing gate: HTTP ${CODE}, db version=${DB_VER}" "${BODY:0:400}"
fi
mock_ctl "$MOCK_OK" "version=2.0.0&sig=good" >/dev/null

# The refusal wording gained the AK_SSRF_ALLOW_PRIVATE_CIDRS hint in 1.11.2
# (#4638), so this control asserts only the guard's stable prefix.
begin_test "CONTROL: install from the internal host is refused 400 by the outbound-URL guard before any clone"
INT_BEFORE="$(mock_hits "$MOCK_INT")"
req POST "/api/v1/plugins/install/git" "{\"url\":\"http://plugin-src-internal/dtf-plugin-${SUF}.git\"}"
INT_AFTER="$(mock_hits "$MOCK_INT")"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL IP '${INT_IP}' is not allowed" \
   && [ "$INT_AFTER" = "$INT_BEFORE" ]; then
  pass
else
  fail "install of the internal host was not refused up front: HTTP ${CODE}, internal hits ${INT_BEFORE}->${INT_AFTER}" "${BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# FIX-1: the advisory's DNS flip. Re-point `plugin-src` at the internal host;
# the stored source_url is untouched.
# ---------------------------------------------------------------------------
# Undo the flip on exit (--keep stacks and `down` then see the profile's
# topology again: plugin-src -> approved mock, internal mock on its own alias).
restore_flip() {
  docker network disconnect -f "$NET" "$MOCK_INT" >/dev/null 2>&1 || true
  docker network connect --ip "$INT_IP" --alias plugin-src-internal "$NET" "$MOCK_INT" >/dev/null 2>&1 || true
  docker network connect --ip "$OK_IP" --alias plugin-src "$NET" "$MOCK_OK" >/dev/null 2>&1 || true
}
add_exit_handler restore_flip
flip_ok=1
docker network disconnect -f "$NET" "$MOCK_OK" >/dev/null 2>&1 || flip_ok=0
docker network disconnect -f "$NET" "$MOCK_INT" >/dev/null 2>&1 || flip_ok=0
docker network connect --ip "$INT_IP" --alias plugin-src --alias plugin-src-internal "$NET" "$MOCK_INT" >/dev/null 2>&1 || flip_ok=0
RESOLVED=""
for _ in $(seq 1 20); do
  RESOLVED="$(docker exec "$MOCK_INT" python3 -c "import socket; print(socket.gethostbyname('plugin-src'))" 2>/dev/null || true)"
  [ "$RESOLVED" = "$INT_IP" ] && break
  sleep 1
done

begin_test "setup: plugin-src now resolves to the internal host ${INT_IP} (was ${OK_IP}); stored source_url unchanged"
if [ "$flip_ok" = "1" ] && [ "$RESOLVED" = "$INT_IP" ] \
   && [ "$(db1 "SELECT source_url FROM plugins WHERE id='${PLUGIN_ID}'")" = "$SRC_URL" ]; then
  pass
else
  fail_fatal "could not re-point plugin-src at the internal mock (flip_ok=${flip_ok}, resolves to '${RESOLVED}')"
fi

begin_test "FIX #4757: reload after the DNS flip is refused with install's 400 naming AK_SSRF_ALLOW_PRIVATE_CIDRS"
mock_ctl "$MOCK_INT" "version=6.6.6&sig=good" >/dev/null
INT_BEFORE="$(mock_hits "$MOCK_INT")"
req POST "/api/v1/plugins/${PLUGIN_ID}/reload"
FLIP_CODE="$CODE"; FLIP_BODY="$BODY"
INT_AFTER="$(mock_hits "$MOCK_INT")"
if [ "$FLIP_CODE" = "400" ] && echo "$FLIP_BODY" | grep -q "Plugin git URL" \
   && echo "$FLIP_BODY" | grep -q "$INT_IP" && echo "$FLIP_BODY" | grep -q "AK_SSRF_ALLOW_PRIVATE_CIDRS"; then
  pass
else
  fail "reload re-fetched a source that now resolves to ${INT_IP} without the outbound-URL check: HTTP ${FLIP_CODE}" "${FLIP_BODY:0:400}"
fi

begin_test "FIX #4757: no clone reached the internal host, and the plugin was not replaced from it"
DB_VER="$(db1 "SELECT version FROM plugins WHERE id='${PLUGIN_ID}'")"
if [ "$INT_AFTER" = "$INT_BEFORE" ] && [ "$DB_VER" = "2.0.0" ]; then
  pass
else
  fail "the backend connected to the internal host on reload: internal mock request lines ${INT_BEFORE}->${INT_AFTER}, db version=${DB_VER} (6.6.6 = replaced from the internal host)" \
    "$(docker logs "$MOCK_INT" 2>&1 | grep "MOCKGIT" | tail -4)"
fi

# ---------------------------------------------------------------------------
# FIX-2/3: stored sources naming loopback, metadata, a blocked service name
# and a non-http scheme. Each row is a plugin whose stored URL a reload must
# re-validate before cloning.
# ---------------------------------------------------------------------------
LOOP_PATH="dtf-loopback-${SUF}.git"
LOOP_ID="$(insert_git_plugin "dtf-loop-${SL}-${RUN_ID##*-}" "http://127.0.0.1:8080/${LOOP_PATH}")"
META_ID="$(insert_git_plugin "dtf-meta-${SL}-${RUN_ID##*-}" "http://169.254.169.254/latest/meta-data/dtf.git")"
SVC_ID="$(insert_git_plugin "dtf-svc-${SL}-${RUN_ID##*-}" "http://postgres:5432/dtf.git")"
FILE_ID="$(insert_git_plugin "dtf-file-${SL}-${RUN_ID##*-}" "file:///etc/passwd")"

begin_test "setup: four git plugin rows with internal stored sources inserted"
if [ -n "$LOOP_ID" ] && [ -n "$META_ID" ] && [ -n "$SVC_ID" ] && [ -n "$FILE_ID" ]; then
  pass
else
  fail_fatal "plugin row insert failed (loop=${LOOP_ID} meta=${META_ID} svc=${SVC_ID} file=${FILE_ID})"
fi

begin_test "FIX #4757: reload of a loopback source (the backend's own port) is refused 400 and never requested"
req POST "/api/v1/plugins/${LOOP_ID}/reload"
LOOP_SEEN="$(docker logs "$BACKEND_CTR" 2>&1 | grep -c "${LOOP_PATH}/info/refs" || true)"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL IP '127.0.0.1' is not allowed" && [ "$LOOP_SEEN" = "0" ]; then
  pass
else
  fail "loopback reload not refused up front: HTTP ${CODE}, backend log lines for the clone path=${LOOP_SEEN}" "${BODY:0:400}"
fi

begin_test "FIX #4757: reload of a cloud-metadata source (169.254.169.254) is refused 400 by the guard"
req POST "/api/v1/plugins/${META_ID}/reload"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL IP '169.254.169.254' is not allowed"; then
  pass
else
  fail "metadata reload not refused by the outbound-URL guard: HTTP ${CODE}" "${BODY:0:400}"
fi

begin_test "FIX #4757: reload of a blocked internal service name (postgres) is refused 400 by the guard"
req POST "/api/v1/plugins/${SVC_ID}/reload"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL host 'postgres' is not allowed"; then
  pass
else
  fail "service-name reload not refused by the outbound-URL guard: HTTP ${CODE}" "${BODY:0:400}"
fi

begin_test "FIX #4757: reload of a file:// source is refused 400 (http or https only)"
req POST "/api/v1/plugins/${FILE_ID}/reload"
if [ "$CODE" = "400" ] && echo "$BODY" | grep -q "Plugin git URL must use http or https"; then
  pass
else
  fail "file:// reload not refused by the outbound-URL guard: HTTP ${CODE}" "${BODY:0:400}"
fi

# Leave the rows for `down -v`; nothing else reads them.
end_suite
