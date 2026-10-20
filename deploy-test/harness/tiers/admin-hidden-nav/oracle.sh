#!/usr/bin/env bash
# =============================================================================
# tiers/admin-hidden-nav/oracle.sh
#   #4574 (fixed by #4575) an admin stores a list of web UI navigation entries
#         hidden for every user; GET /api/v1/system/config publishes it to
#         every caller, anonymous included, as ui.hidden_nav_items.
# See the manifest for THE FEATURE, the primitives and the gates. The server
# treats the identifiers as opaque and checks shape only (no allowed set, no
# un-hideable entry), so "invalid" here means a malformed identifier.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SETTING_KEY="ui.hidden_nav_items"
SETTINGS="/api/v1/admin/settings/system"
CONFIG="/api/v1/system/config"
USER_NAME="ahn-user-${DTF_SLOT}-${SUF}"
USER_PASS="Ahn_${SUF}_Aa1!"
# The four keys /system/config carried before #4575. ui is the only addition.
BASE_KEYS='["auth","demo_mode","guest_access_enabled","max_upload_size_bytes"]'

WORK="$(mktemp -d -t dtf-ahn-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code on stdout, body in $WORK/body.
# TOKEN may be empty (anonymous).
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 400; }
jb() { body | jq -c "$1" 2>/dev/null || true; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
stored() { db "SELECT value::text FROM system_settings WHERE key='${SETTING_KEY}'" | tr -d '[:space:]'; }
# nav_audits -> number of SETTING_CHANGED rows written for this setting.
nav_audits() {
  db "SELECT count(*) FROM audit_log WHERE action='SETTING_CHANGED' AND details->>'setting'='${SETTING_KEY}'" | tr -d '[:space:]'
}
# wait_audits N -> 0 once nav_audits reaches N (the write is fire-and-forget).
wait_audits() {
  local _i
  for _i in $(seq 1 20); do
    [ "$(nav_audits)" = "$1" ] && return 0
    sleep 0.5
  done
  return 1
}

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# =============================================================================
begin_suite "admin-hidden-nav"

begin_test "setup: admin login, a non-admin user, no stored ${SETTING_KEY} row"
auth_admin
ADMIN_ID="$(db "SELECT id FROM users WHERE username='${ADMIN_USER:-admin}'" | tr -d '[:space:]')"
UID_USER="$(create_test_user_with_retry "$USER_NAME" "$USER_PASS" "${USER_NAME}@dtf.test" 2>/dev/null || true)"
USER_TOKEN=""
[ -n "$UID_USER" ] && USER_TOKEN="$(login_as "$USER_NAME" "$USER_PASS" 2>/dev/null || true)"
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "?" ] || [ -z "$USER_TOKEN" ]; then
  infra_fail "setup failed: admin id='${ADMIN_ID}' user id='${UID_USER}' user token len=${#USER_TOKEN}"
  end_suite
fi
db "DELETE FROM system_settings WHERE key='${SETTING_KEY}'" >/dev/null
AUDITS0="$(nav_audits)"
code="$(req GET "$CONFIG" "")"
CONFIG0="$(jb 'del(.ui)')"
GUEST0="$(jb '.guest_access_enabled')"
if [ "$code" != "200" ] || [ -z "$CONFIG0" ] || [ "$CONFIG0" = "null" ]; then
  infra_fail "anonymous GET ${CONFIG} answered ${code}: $(snip)"; end_suite
fi
echo "-- admin=${ADMIN_ID} user=${USER_NAME} guest_access_enabled=${GUEST0} audits=${AUDITS0}"
pass

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: /system/config keeps its pre-#4575 keys; the admin settings read is admin-only"
reset_case
keys="$(printf '%s' "$CONFIG0" | jq -c 'keys' 2>/dev/null || true)"
[ "$keys" = "$BASE_KEYS" ] || gate "/system/config keys other than ui are ${keys}, expected ${BASE_KEYS}"
code="$(req GET "$SETTINGS" "$ADMIN_TOKEN")"
note "admin GET ${SETTINGS}: ${code} $(snip)"
[ "$code" = "200" ] || gate "admin GET ${SETTINGS} answered ${code}"
[ "$(jb '.guest_access_enabled')" = "$GUEST0" ] || gate "admin guest_access_enabled $(jb '.guest_access_enabled') != /system/config ${GUEST0}"
code="$(req GET "$SETTINGS" "$USER_TOKEN")"
case "$code" in 403|404) ;; *) gate "non-admin GET ${SETTINGS} answered ${code}, expected 403/404: $(snip)";; esac
code="$(req GET "$SETTINGS" "")"
case "$code" in 401|403|404) ;; *) gate "anonymous GET ${SETTINGS} answered ${code}: $(snip)";; esac
finish_case "the pre-existing settings and config surface changed"

begin_test "CONTROL: a non-admin PATCH is refused and stores nothing"
reset_case
code="$(req PATCH "$SETTINGS" "$USER_TOKEN" '{"hidden_nav_items":["/peers"]}')"
note "non-admin PATCH: ${code} $(snip)"
case "$code" in 403|404) ;; *) gate "non-admin PATCH answered ${code}, expected 403/404";; esac
[ -z "$(stored)" ] || gate "a ${SETTING_KEY} row exists after the refused PATCH: $(stored)"
code="$(req PATCH "$SETTINGS" "" '{"hidden_nav_items":["/peers"]}')"
case "$code" in 401|403|404) ;; *) gate "anonymous PATCH answered ${code}";; esac
[ -z "$(stored)" ] || gate "a ${SETTING_KEY} row exists after the anonymous PATCH: $(stored)"
finish_case "a non-admin could write the navigation setting"

begin_test "CONTROL: the guest-access PATCH (the field that predates #4575) still round-trips"
reset_case
code="$(req PATCH "$SETTINGS" "$ADMIN_TOKEN" "{\"guest_access_enabled\":${GUEST0}}")"
note "PATCH guest_access_enabled=${GUEST0}: ${code} $(snip)"
[ "$code" = "200" ] || gate "PATCH guest_access_enabled answered ${code}"
[ "$(jb '.guest_access_enabled')" = "$GUEST0" ] || gate "response guest_access_enabled $(jb '.guest_access_enabled') != ${GUEST0}"
finish_case "the guest-access setting no longer round-trips"

# =============================================================================
# FIX #4574 (RED on 1.11.3: the field is an unknown field, 422)
# =============================================================================
begin_test "FIX #4574: admin PATCH stores the list (trimmed, sorted, de-duplicated); admin GET and the DB echo it"
reset_case
WANT='["/peers","/plugins","/webhooks"]'
code="$(req PATCH "$SETTINGS" "$ADMIN_TOKEN" '{"hidden_nav_items":["/webhooks","/peers","/peers"," /plugins "]}')"
note "admin PATCH: ${code} $(snip)"
[ "$code" = "200" ] || gate "admin PATCH hidden_nav_items answered ${code}, expected 200"
[ "$(jb '.hidden_nav_items')" = "$WANT" ] || gate "PATCH response hidden_nav_items=$(jb '.hidden_nav_items'), expected ${WANT}"
[ "$(jb '.guest_access_enabled')" = "$GUEST0" ] || gate "guest_access_enabled moved to $(jb '.guest_access_enabled') on a navigation-only PATCH"
code="$(req GET "$SETTINGS" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(jb '.hidden_nav_items')" = "$WANT" ] \
  || gate "admin GET answered ${code} hidden_nav_items=$(jb '.hidden_nav_items'), expected ${WANT}"
[ "$(stored)" = "$WANT" ] || gate "system_settings ${SETTING_KEY}='$(stored)', expected ${WANT}"
finish_case "the admin could not store the hidden navigation entries"

begin_test "FIX #4574: anonymous and non-admin GET /system/config publish ui.hidden_nav_items"
reset_case
code="$(req GET "$CONFIG" "")"
note "anonymous /system/config: ${code} $(snip)"
[ "$code" = "200" ] || gate "anonymous GET ${CONFIG} answered ${code}"
[ "$(jb '.ui.hidden_nav_items')" = "$WANT" ] || gate "anonymous ui.hidden_nav_items=$(jb '.ui.hidden_nav_items'), expected ${WANT}"
code="$(req GET "$CONFIG" "$USER_TOKEN")"
[ "$code" = "200" ] && [ "$(jb '.ui.hidden_nav_items')" = "$WANT" ] \
  || gate "non-admin /system/config answered ${code} ui.hidden_nav_items=$(jb '.ui.hidden_nav_items')"
finish_case "/system/config does not publish the hidden navigation entries"

begin_test "FIX #4574: an invalid list is refused 400 naming hidden_nav_items and writes nothing"
reset_case
LONG="/$(printf 'a%.0s' $(seq 1 128))"
MANY="$(jq -cn '[range(0;201) | "/e\(.)"]')"
for bad in '["/peers","not allowed"]' '["/peers",""]' '["<script>"]' "[\"${LONG}\"]" "$MANY"; do
  code="$(req PATCH "$SETTINGS" "$ADMIN_TOKEN" "{\"hidden_nav_items\":${bad}}")"
  msg="$(body | jq -r '.message // .error // empty' 2>/dev/null | head -c 160 || true)"
  [ -n "$msg" ] || msg="$(body | head -c 160 || true)"
  note "PATCH $(printf '%s' "$bad" | head -c 40): ${code} ${msg}"
  [ "$code" = "400" ] || gate "invalid list $(printf '%s' "$bad" | head -c 40) answered ${code}, expected 400"
  printf '%s' "$msg" | grep -q 'hidden_nav_items' || gate "400 body does not name hidden_nav_items: ${msg}"
done
# Validated before anything is written: a valid guest flag beside an invalid
# list is refused whole.
code="$(req PATCH "$SETTINGS" "$ADMIN_TOKEN" "{\"guest_access_enabled\":${GUEST0},\"hidden_nav_items\":[\"bad entry\"]}")"
note "PATCH guest + invalid list: ${code} $(snip)"
[ "$code" = "400" ] || gate "guest flag + invalid list answered ${code}, expected 400"
[ "$(stored)" = "$WANT" ] || gate "stored list changed to '$(stored)' after refused PATCHes, expected ${WANT}"
finish_case "an invalid hidden_nav_items list was not refused cleanly"

begin_test "FIX #4574: each accepted navigation write is audited SETTING_CHANGED with from/to; refused ones are not"
reset_case
want_n=$(( AUDITS0 + 1 ))
wait_audits "$want_n" || gate "SETTING_CHANGED rows for ${SETTING_KEY}: $(nav_audits), expected ${want_n} (one accepted write so far)"
row="$(db "SELECT coalesce(user_id::text,'') || '|' || (details->'from')::text || '|' || (details->'to')::text FROM audit_log WHERE action='SETTING_CHANGED' AND details->>'setting'='${SETTING_KEY}' ORDER BY created_at DESC LIMIT 1" | tr -d '[:space:]')"
note "latest audit row: ${row}"
[ "$row" = "${ADMIN_ID}|[]|${WANT}" ] || gate "audit row '${row}', expected '${ADMIN_ID}|[]|${WANT}'"
code="$(req PATCH "$SETTINGS" "$ADMIN_TOKEN" '{"hidden_nav_items":[]}')"
[ "$code" = "200" ] && [ "$(jb '.hidden_nav_items')" = "[]" ] || gate "clearing PATCH answered ${code} $(snip)"
wait_audits $(( AUDITS0 + 2 )) || gate "the clearing write was not audited: $(nav_audits) rows, expected $(( AUDITS0 + 2 ))"
code="$(req GET "$CONFIG" "")"
[ "$(jb '.ui.hidden_nav_items')" = "[]" ] || gate "after clearing, /system/config ui.hidden_nav_items=$(jb '.ui.hidden_nav_items')"
finish_case "navigation writes are not audited"

begin_test "FIX #4574: a malformed stored value reads back as an empty list (admin GET and /system/config), never a 5xx"
reset_case
for bad in '{"not": "a list"}' '"/peers"' '[1, 2]' 'null'; do
  db "INSERT INTO system_settings (key, value) VALUES ('${SETTING_KEY}', '${bad}'::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value" >/dev/null
  code="$(req GET "$SETTINGS" "$ADMIN_TOKEN")"
  a="${code} $(jb '.hidden_nav_items')"
  code2="$(req GET "$CONFIG" "")"
  c="${code2} $(jb '.ui.hidden_nav_items')"
  note "stored ${bad}: admin GET ${a}; anonymous config ${c}"
  [ "$a" = "200 []" ] || gate "stored ${bad}: admin GET ${a}, expected 200 []"
  [ "$c" = "200 []" ] || gate "stored ${bad}: /system/config ${c}, expected 200 []"
done
code="$(req PATCH "$SETTINGS" "$ADMIN_TOKEN" '{"hidden_nav_items":["/peers"]}')"
[ "$code" = "200" ] && [ "$(stored)" = '["/peers"]' ] || gate "a PATCH over the malformed row answered ${code}, stored '$(stored)'"
finish_case "a malformed stored value broke the reads"

begin_test "CONTROL: the rest of /system/config is unchanged by the navigation writes"
reset_case
code="$(req GET "$CONFIG" "")"
after="$(jb 'del(.ui)')"
[ "$code" = "200" ] || gate "anonymous GET ${CONFIG} answered ${code}"
[ "$after" = "$CONFIG0" ] || gate "/system/config without ui changed: before ${CONFIG0} after ${after}"
finish_case "the navigation writes leaked into other config keys"

db "DELETE FROM system_settings WHERE key='${SETTING_KEY}'" >/dev/null
end_suite
