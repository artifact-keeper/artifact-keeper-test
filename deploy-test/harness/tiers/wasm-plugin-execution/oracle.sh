#!/usr/bin/env bash
# =============================================================================
# tiers/wasm-plugin-execution/oracle.sh: a real format plugin runs in the
# sandbox (artifact-keeper#6276, the wasmtime 36 -> 48 upgrade)
# =============================================================================
# run.sh has stood up storage.filesystem + plugins.example-signed and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR. See the manifest for why and for every
# case. RED on wasmtime 36 (the plugin cannot instantiate: its WASI 0.2.12
# imports are not in the host), GREEN on 48.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on
# it explicitly.
set +e

ZIP="${HERE}/fixtures/unity-format-plugin.zip"
SPIN_ZIP="${HERE}/fixtures/spinner-plugin.zip"
SUF="${RUN_ID##*-}-$$"
REPO="wpe-${SUF}"
SPIN_REPO="wps-${SUF}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

CODE=""; BODY=""
# req METHOD PATH [JSON]: sets CODE and BODY.
req() {
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    CODE="$(curl -s -o "$W/body" -w '%{http_code}' --max-time 60 -X "$m" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
      -d "$d" "${BASE_URL}${p}" 2>/dev/null)" || CODE="000"
  else
    CODE="$(curl -s -o "$W/body" -w '%{http_code}' --max-time 60 -X "$m" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}${p}" 2>/dev/null)" || CODE="000"
  fi
  BODY="$(cat "$W/body" 2>/dev/null || true)"
}
# upload NAME FILE [REPO]: PUT through the repository upload route, the path
# that calls the plugin's validate and parse-metadata exports (call_async).
# Always declares application/octet-stream, so a stored application/gzip came
# from the guest.
upload() {
  CODE="$(curl -s -o "$W/body" -w '%{http_code}' --max-time 120 -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$2" "${BASE_URL}/api/v1/repositories/${3:-$REPO}/artifacts/$1" 2>/dev/null)" || CODE="000"
  BODY="$(cat "$W/body" 2>/dev/null || true)"
}
# install_zip FILE: POST the plugin ZIP; sets CODE, BODY.
install_zip() {
  CODE="$(curl -s -o "$W/body" -w '%{http_code}' --max-time 120 -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -F "file=@$1;type=application/zip" \
    "${BASE_URL}/api/v1/plugins/install/zip" 2>/dev/null)" || CODE="000"
  BODY="$(cat "$W/body" 2>/dev/null || true)"
}
# plugin_log NAME: the backend's plugin-error log lines for upload NAME (the
# first line of each; the wasm backtrace follows on lines of its own).
plugin_log() { docker logs "$BACKEND_CTR" 2>&1 | grep -F "$1" | grep -F "WASM plugin validate error"; }
db1() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
# stored NAME -> "<version>|<content_type>" of the live artifact row, or "".
stored() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT coalesce(a.version,'') || '|' || a.content_type FROM artifacts a
       JOIN repositories r ON r.id = a.repository_id
      WHERE r.key = '${REPO}' AND a.path = '$1' AND NOT a.is_deleted" 2>/dev/null | tr -d '[:space:]'
}
# gz_package FILE BYTES: a gzip (deflate) stream of BYTES of random data, the
# envelope a .unitypackage has. Incompressible, so the file is BYTES-sized.
gz_package() {
  head -c "$2" /dev/urandom | gzip -1 -c > "$1"
}

begin_suite "wasm-plugin-execution-6276"
auth_admin

# ---------------------------------------------------------------------------
# CONTROL: install, list, repository
# ---------------------------------------------------------------------------
begin_test "CONTROL: the signed Unity format plugin installs from its ZIP (format key unity)"
install_zip "$ZIP"
PLUGIN_ID="$(echo "$BODY" | jq -r '.plugin_id // empty' 2>/dev/null)"
if [ "$CODE" = "200" ] && [ -n "$PLUGIN_ID" ] \
   && [ "$(echo "$BODY" | jq -r '.format_key' 2>/dev/null)" = "unity" ]; then
  pass
else
  fail_fatal "plugin install from ${ZIP##*/} did not succeed (HTTP ${CODE}); every later case calls into it" \
    "body=${BODY:0:500}"
fi

begin_test "CONTROL: the plugin is listed and active"
req GET "/api/v1/plugins"
ST="$(echo "$BODY" | jq -r --arg id "$PLUGIN_ID" '(.items // .)[] | select(.id == $id) | .status' 2>/dev/null)"
if [ "$CODE" = "200" ] && [ "$ST" = "active" ]; then
  pass
else
  fail "plugin ${PLUGIN_ID} not listed as active: HTTP ${CODE}, status='${ST}'" "${BODY:0:400}"
fi

begin_test "CONTROL: the signed spinner plugin installs (format key spinner) and a spinner repository can be created"
install_zip "$SPIN_ZIP"
if [ "$CODE" = "200" ] && [ "$(echo "$BODY" | jq -r '.format_key' 2>/dev/null)" = "spinner" ] \
   && create_local_repo "$SPIN_REPO" "spinner"; then
  pass
else
  fail "spinner plugin install / repository: HTTP ${CODE}" "body=${BODY:0:400}"
fi

begin_test "CONTROL: a repository of the plugin's format (unity) can be created"
if create_local_repo "$REPO" "unity" \
   && [ "$(db1 "SELECT format_key FROM repositories WHERE key='${REPO}'")" = "unity" ]; then
  pass
else
  fail_fatal "could not create repository ${REPO} of format unity" ""
fi

# ---------------------------------------------------------------------------
# EXEC: the guest's validate and parse-metadata answers reach the stored row
# ---------------------------------------------------------------------------
begin_test "FIX #6276: (exec) a gzip .unitypackage is stored with the guest's metadata (version 4.5.6 from the filename, application/gzip)"
gz_package "$W/ok.unitypackage" 4096
upload "Demo-4.5.6.unitypackage" "$W/ok.unitypackage"
GOT="$(stored "Demo-4.5.6.unitypackage")"
if [ "${CODE:0:1}" = "2" ] && [ "$GOT" = "4.5.6|application/gzip" ]; then
  pass
else
  fail "upload HTTP ${CODE}; stored version|content_type='${GOT}', want '4.5.6|application/gzip' (the guest's parse-metadata answer)" "${BODY:0:400}"
fi

# refused CASE NAME FILE NEEDLE: a 400 whose body carries the guest's message,
# and no row stored.
refused() {
  upload "$2" "$3"
  local got; got="$(stored "$2")"
  if [ "$CODE" = "400" ] && echo "$BODY" | grep -qF "$4" && [ -z "$got" ]; then
    pass
  else
    fail "$1: HTTP ${CODE} (want 400 carrying \"$4\"), stored='${got}'" "${BODY:0:400}"
  fi
}

begin_test "FIX #6276: (exec) a non-gzip body is refused with the guest's validate message"
printf 'PK\003\004not-a-gzip-stream' > "$W/zip.unitypackage"
refused "non-gzip" "Bad-1.0.0.unitypackage" "$W/zip.unitypackage" "Invalid gzip header: expected [1f, 8b], got [50, 4b]"

begin_test "FIX #6276: (exec) a wrong extension is refused with the guest's validate message"
refused "wrong extension" "Demo-1.0.0.tar.gz" "$W/ok.unitypackage" "Expected .unitypackage extension, got: Demo-1.0.0.tar.gz"

begin_test "FIX #6276: (exec) a gzip stream that is not deflate is refused with the guest's validate message"
printf '\037\213\011\000\000\000\000\000' > "$W/m9.unitypackage"
refused "non-deflate" "Odd-1.0.0.unitypackage" "$W/m9.unitypackage" "Unsupported gzip compression method: 09 (expected 08/deflate)"

# ---------------------------------------------------------------------------
# SANDBOX: the memory cap, and the runtime survives a guest trap
# ---------------------------------------------------------------------------
begin_test "FIX #6276: (sandbox) an 8 MiB package fits the plugin's 32 MB memory cap and is stored"
gz_package "$W/8m.unitypackage" $((8 * 1024 * 1024))
upload "Big-8.0.0.unitypackage" "$W/8m.unitypackage"
GOT="$(stored "Big-8.0.0.unitypackage")"
if [ "${CODE:0:1}" = "2" ] && [ "$GOT" = "8.0.0|application/gzip" ]; then
  pass
else
  fail "8 MiB upload HTTP ${CODE}, stored='${GOT}'" "${BODY:0:400}"
fi

begin_test "FIX #6276: (sandbox) a 40 MiB package exceeds the 32 MB memory cap: the guest traps, the upload is refused, nothing is stored"
gz_package "$W/40m.unitypackage" $((40 * 1024 * 1024))
upload "Huge-9.0.0.unitypackage" "$W/40m.unitypackage"
GOT="$(stored "Huge-9.0.0.unitypackage")"
# The refusal must be the guest trapping inside the call, with the reason:
# its allocator (cabi_realloc) cannot grow memory past the cap and aborts,
# which is wasm `unreachable`. Not a plugin that never instantiated.
LOG="$(plugin_log "Huge-9.0.0.unitypackage")"
if [ "${CODE:0:1}" != "2" ] && [ "$CODE" != "000" ] && [ -z "$GOT" ] \
   && echo "$LOG" | grep -qF 'guest trapped (wasm trap: wasm `unreachable` instruction executed)' \
   && docker logs "$BACKEND_CTR" 2>&1 | grep -F -A8 "Huge-9.0.0.unitypackage" | grep -qF 'cabi_realloc'; then
  pass
else
  fail "40 MiB upload over a 32 MB plugin cap: HTTP ${CODE}, stored='${GOT}' (want a refusal, no row, and an unreachable trap from cabi_realloc in the log)" "log=${LOG:0:600}"
fi

begin_test "FIX #6276: (sandbox) a guest that never returns is stopped by fuel on the call path: refused within seconds, trap reason fuel, nothing stored"
gz_package "$W/spin.unitypackage" 1024
T0=$(date +%s)
upload "spin-forever-1.0.0.unitypackage" "$W/spin.unitypackage" "$SPIN_REPO"
DT=$(( $(date +%s) - T0 ))
GOT="$(REPO="$SPIN_REPO" stored "spin-forever-1.0.0.unitypackage")"
LOG="$(plugin_log "spin-forever-1.0.0.unitypackage")"
# The plugin's 2 s timeout gives it 200M fuel; the curl limit is 120 s.
if [ "${CODE:0:1}" != "2" ] && [ "$CODE" != "000" ] && [ -z "$GOT" ] && [ "$DT" -lt 30 ] \
   && echo "$LOG" | grep -qF 'WASM execution exceeded fuel limit'; then
  pass
else
  fail "spinning guest: HTTP ${CODE} after ${DT}s, stored='${GOT}' (want a refusal in under 30 s, no row, and 'WASM execution exceeded fuel limit' in the log)" "log=${LOG:0:600}"
fi

begin_test "FIX #6276: (sandbox) after the traps and the refusals the plugin still serves (another package is stored)"
gz_package "$W/after.unitypackage" 2048
upload "After-2.0.1.unitypackage" "$W/after.unitypackage"
GOT="$(stored "After-2.0.1.unitypackage")"
if [ "${CODE:0:1}" = "2" ] && [ "$GOT" = "2.0.1|application/gzip" ]; then
  pass
else
  fail "upload after the guest trap: HTTP ${CODE}, stored='${GOT}'" "${BODY:0:400}"
fi

end_suite
