#!/usr/bin/env bash
# =============================================================================
# tiers/guest-access-runtime-visibility-banners/oracle.sh
#   Runtime guest access (artifact-keeper#867), repository visibility
#   `internal` (#3813 / #3812, #3855) and system banners (#2155). See the
#   manifest for the features, the two boots and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SLOT="$DTF_SLOT"
SUF="${RUN_ID##*-}-$$"
PUB="gav-pub-${SLOT}-${SUF}"        # public generic
PRIV="gav-priv-${SLOT}-${SUF}"      # private generic
INT="gav-int-${SLOT}-${SUF}"        # internal generic
PUB_OFF="gav-puboff-${SLOT}-${SUF}" # public, requested while guests are off
INT_OFF="gav-intoff-${SLOT}-${SUF}" # internal, requested while guests are off
CONTRA="gav-contra-${SLOT}-${SUF}"  # contradictory visibility / is_public
U_USER="gav-user-${SLOT}-${SUF}"    # authenticated, no grant anywhere
PW="Gav_${SUF}_Aa1!"
BYTES_PUB="gav-pub-bytes-${SUF}"
BYTES_INT="gav-int-bytes-${SUF}"
SETTING="security.guest_access_enabled"

WORK="$(mktemp -d -t dtf-gav-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code; body in $WORK/body.
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
upload() { # TOKEN REPO PATH BYTES -> HTTP code; body in $WORK/body
  printf '%s' "$4" > "$WORK/up"
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $1" --data-binary "@$WORK/up" \
    "${BASE_URL}/api/v1/repositories/$2/artifacts/$3" 2>/dev/null || echo 000
}
dl() { req GET "/api/v1/repositories/$2/download/obj.txt" "$1"; }   # TOKEN REPO
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 300 | tr '\n' ' ' || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }
anon_refused() { case "$1" in 401|403|404) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
mkrepo() { # TOKEN JSON_EXTRA KEY -> HTTP code
  req POST /api/v1/repositories "$1" "$(jq -nc --arg k "$3" --argjson x "$2" \
    '{key:$k,name:$k,format:"generic",repo_type:"local"} + $x')"
}
settings() { req GET /api/v1/admin/settings/system "$ADMIN_TOKEN"; }
set_guest() { req PATCH /api/v1/admin/settings/system "$ADMIN_TOKEN" "{\"guest_access_enabled\":$1}"; }
anon_pub_code() { dl "" "$PUB"; }
anon_pub_is() { [ "$(anon_pub_code)" = "$1" ]; }
setting_audits() { # -> count of SETTING_CHANGED rows for the guest setting
  db "SELECT count(*) FROM audit_log WHERE action = 'SETTING_CHANGED' AND details->>'setting' = '${SETTING}'"
}
audit_rows_reach() { [ "$(setting_audits)" -ge "$1" ] 2>/dev/null; }

# recreate_backend_pinned: phase 2. Same project and overlays as run.sh plus
# AK_GUEST_ACCESS_ENABLED=true; --wait health-gates it.
recreate_backend_pinned() {
  local override rc
  override="$(mktemp "${TMPDIR:-/tmp}/gav-pin-${SLOT}.XXXXXX.yml")"
  cat > "$override" <<'YML'
services:
  backend:
    environment:
      AK_GUEST_ACCESS_ENABLED: "true"
YML
  docker compose -p "ak-dtf${SLOT}" \
    -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "$override" \
    up -d --wait backend >/dev/null 2>&1
  rc=$?
  rm -f "$override"
  return "$rc"
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
begin_suite "guest-access-runtime-visibility-banners"

begin_test "setup: a grant-less user; public, private and internal repositories with one object each"
auth_admin
SETUP_ERR=""
create_test_user_with_retry "$U_USER" "$PW" "${U_USER}@t.test" >/dev/null || SETUP_ERR="${SETUP_ERR} user"
U_T="$(login_as "$U_USER" "$PW" || true)"; [ -n "$U_T" ] || SETUP_ERR="${SETUP_ERR} login"
is_2xx "$(mkrepo "$ADMIN_TOKEN" '{"is_public":true}' "$PUB")" || SETUP_ERR="${SETUP_ERR} pub($(snip))"
is_2xx "$(mkrepo "$ADMIN_TOKEN" '{"is_public":false}' "$PRIV")" || SETUP_ERR="${SETUP_ERR} priv($(snip))"
code="$(mkrepo "$ADMIN_TOKEN" '{"visibility":"internal"}' "$INT")"
INT_CREATE_BODY="$(body)"
is_2xx "$code" || SETUP_ERR="${SETUP_ERR} int(${code}:$(snip))"
is_2xx "$(upload "$ADMIN_TOKEN" "$PUB" obj.txt "$BYTES_PUB")" || SETUP_ERR="${SETUP_ERR} up-pub"
is_2xx "$(upload "$ADMIN_TOKEN" "$PRIV" obj.txt "priv-${SUF}")" || SETUP_ERR="${SETUP_ERR} up-priv"
is_2xx "$(upload "$ADMIN_TOKEN" "$INT" obj.txt "$BYTES_INT")" || SETUP_ERR="${SETUP_ERR} up-int"
INT_ART_ID="$(jr '.id // empty')"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- repos ${PUB} ${PRIV} ${INT}; user ${U_USER}; internal artifact ${INT_ART_ID}"
pass

# =============================================================================
# PHASE 1: AK_GUEST_ACCESS_ENABLED unset
# =============================================================================
begin_test "CONTROL: at boot guests are allowed: anonymous reads the public repository, /system/config says so"
reset_case
code="$(anon_pub_code)"; note "anonymous public download: ${code}"
[ "$code" = "200" ] && [ "$(body)" = "$BYTES_PUB" ] || gate "anonymous public download answered ${code}"
code="$(req GET /api/v1/system/config "")"; note "/system/config: ${code} guest_access_enabled=$(jr '.guest_access_enabled')"
[ "$code" = "200" ] && [ "$(jr '.guest_access_enabled')" = "true" ] || gate "/system/config does not report guests allowed"
finish_case "the default guest posture is broken"

begin_test "CONTROL: a private repository is refused to anonymous and to a grant-less user"
reset_case
c1="$(dl "" "$PRIV")"; c2="$(dl "$U_T" "$PRIV")"; note "private: anonymous ${c1}, grant-less ${c2}"
anon_refused "$c1" || gate "anonymous read a private repository (${c1})"
is_denied "$c2" || gate "a grant-less user read a private repository (${c2})"
finish_case "private repositories leak"

begin_test "FIX #867: GET /admin/settings/system reports the default posture; an unknown field is a 400"
reset_case
code="$(settings)"
note "settings: ${code} $(snip | head -c 200)"
[ "$code" = "200" ] || gate "GET settings answered ${code}"
[ "$(jr '.guest_access_enabled')|$(jr '.guest_access_source')|$(jr '.guest_access_editable')|$(jr '.guest_access_stored')" = "true|default|true|null" ] \
  || gate "settings are $(jr '[.guest_access_enabled,.guest_access_source,.guest_access_editable,.guest_access_stored]|tostring'), expected true/default/editable/stored null"
code="$(req PATCH /api/v1/admin/settings/system "$ADMIN_TOKEN" '{"guest_access":false}')"
note "PATCH with a misspelt field: ${code} (400 or 422: refused)"
case "$code" in 400|422) ;; *) gate "a misspelt field answered ${code} (a silent no-op)";; esac
anon_pub_is 200 || gate "the misspelt PATCH changed guest access"
finish_case "the runtime settings endpoint is missing or wrong"

begin_test "FIX #867: PATCH guest_access_enabled=false refuses anonymous within 5 s, /system/config follows, SETTING_CHANGED is audited"
reset_case
audits_before="$(setting_audits)"
code="$(set_guest false)"
note "PATCH false: ${code} enabled=$(jr '.guest_access_enabled') source=$(jr '.guest_access_source') stored=$(jr '.guest_access_stored')"
[ "$code" = "200" ] && [ "$(jr '.guest_access_enabled')" = "false" ] && [ "$(jr '.guest_access_source')" = "database" ] \
  || gate "PATCH false answered ${code}: $(snip)"
if wait_until "anonymous refused" 5 anon_pub_is 401; then note "anonymous public download now 401"
else gate "anonymous public download still answers $(anon_pub_code) 5 s after the PATCH"; fi
code="$(req GET /api/v1/system/config "")"; note "/system/config (anonymous, allowlisted): ${code} guest_access_enabled=$(jr '.guest_access_enabled')"
[ "$code" = "200" ] && [ "$(jr '.guest_access_enabled')" = "false" ] || gate "/system/config does not reflect the flip"
[ "$(db "SELECT value::text FROM system_settings WHERE key = '${SETTING}'")" = "false" ] || gate "system_settings row is not false"
if wait_until "SETTING_CHANGED row" 10 audit_rows_reach "$((audits_before + 1))"; then
  d="$(db "SELECT details->>'from' || '>' || (details->>'to') FROM audit_log WHERE action = 'SETTING_CHANGED' AND details->>'setting' = '${SETTING}' ORDER BY created_at DESC LIMIT 1")"
  note "latest SETTING_CHANGED from>to: ${d}"
  [ "$d" = "true>false" ] || gate "the audit row records ${d}, expected true>false"
else gate "no SETTING_CHANGED audit row for the flip"; fi
finish_case "guest access cannot be turned off at runtime"

begin_test "CONTROL: with guests off an authenticated user still reads the public repository"
reset_case
code="$(dl "$U_T" "$PUB")"; note "grant-less user, public repository: ${code}"
[ "$code" = "200" ] && [ "$(body)" = "$BYTES_PUB" ] || gate "an authenticated read of the public repository answered ${code}"
finish_case "authenticated reads broke"

begin_test "FIX #2155: with guests off, anonymous GET /api/v1/banners?target=ui lists the active banners, critical first"
reset_case
past2="$(date -u -d '-2 hours' +%Y-%m-%dT%H:%M:%SZ)"; past1="$(date -u -d '-1 hours' +%Y-%m-%dT%H:%M:%SZ)"
mkb() { req POST /api/v1/admin/banners "$ADMIN_TOKEN" "$1"; }
c1="$(mkb "$(jq -nc --arg t "gav-info-${SUF}" '{title:$t,message:"info all",severity:"info",target:"all"}')")"
c2="$(mkb "$(jq -nc --arg t "gav-crit-${SUF}" '{title:$t,message:"critical ui",severity:"critical",target:"ui",link_url:"https://status.example.com"}')")"
c3="$(mkb "$(jq -nc --arg t "gav-expired-${SUF}" --arg s "$past2" --arg e "$past1" '{title:$t,message:"expired",severity:"critical",target:"ui",starts_at:$s,ends_at:$e}')")"
c4="$(mkb "$(jq -nc --arg t "gav-api-${SUF}" '{title:$t,message:"api only",severity:"warning",target:"api"}')")"
c5="$(mkb "$(jq -nc --arg t "gav-off-${SUF}" '{title:$t,message:"disabled",severity:"critical",target:"all",enabled:false}')")"
note "admin creates: ${c1} ${c2} ${c3} ${c4} ${c5}"
for c in "$c1" "$c2" "$c3" "$c4" "$c5"; do is_2xx "$c" || gate "banner create answered ${c}"; done
c6="$(mkb '{"title":"x","message":"y","link_url":"javascript:alert(1)"}')"; note "javascript: link: ${c6}"
[ "$c6" = "400" ] || gate "a javascript: link answered ${c6}"
code="$(req GET "/api/v1/banners?target=ui" "")"
titles="$(jr "[.banners[].title | select(endswith(\"${SUF}\"))] | join(\",\")")"
note "anonymous ?target=ui: ${code} titles=${titles}"
[ "$code" = "200" ] || gate "anonymous banners answered ${code} with guests off"
[ "$titles" = "gav-crit-${SUF},gav-info-${SUF}" ] || gate "ui banners are '${titles}', expected critical then info, without the expired, api-only and disabled ones"
code="$(req GET "/api/v1/banners?target=api" "")"
titles="$(jr "[.banners[].title | select(endswith(\"${SUF}\"))] | join(\",\")")"
note "anonymous ?target=api: ${code} titles=${titles}"
[ "$titles" = "gav-api-${SUF},gav-info-${SUF}" ] || gate "api banners are '${titles}', expected warning(api) then info(all)"
finish_case "the banners API is missing or wrong"

begin_test "FIX #3855/#3813: with guests off, visibility public is refused 400 and internal is accepted"
reset_case
c1="$(mkrepo "$ADMIN_TOKEN" '{"visibility":"public"}' "$PUB_OFF")"; note "public: ${c1} $(jr '.message // empty' | head -c 160)"
c2="$(mkrepo "$ADMIN_TOKEN" '{"visibility":"internal"}' "$INT_OFF")"; note "internal: ${c2} visibility=$(jr '.visibility')"
[ "$c1" = "400" ] || gate "public with guests off answered ${c1}"
[ "$(db "SELECT count(*) FROM repositories WHERE key = '${PUB_OFF}'")" = "0" ] || gate "the public repository was created"
is_2xx "$c2" && [ "$(jr '.visibility')" = "internal" ] || gate "internal with guests off answered ${c2} visibility=$(jr '.visibility')"
finish_case "visibility is not reconciled with the guest-access switch"

begin_test "FIX #867: a system_settings row that is not a JSON boolean fails closed"
reset_case
set_guest true >/dev/null
wait_until "anonymous allowed again" 5 anon_pub_is 200 || gate "anonymous not allowed after PATCH true ($(anon_pub_code))"
db "UPDATE system_settings SET value = '\"yes\"'::jsonb WHERE key = '${SETTING}'" >/dev/null
if wait_until "invalid row refuses guests" 10 anon_pub_is 401; then note "anonymous refused after the row became \"yes\""
else gate "anonymous still answers $(anon_pub_code) 10 s after the row became a string"; fi
code="$(settings)"; note "settings: ${code} enabled=$(jr '.guest_access_enabled') source=$(jr '.guest_access_source')"
[ "$(jr '.guest_access_enabled')|$(jr '.guest_access_source')" = "false|invalid" ] || gate "settings report $(jr '.guest_access_enabled')/$(jr '.guest_access_source'), expected false/invalid"
code="$(set_guest true)"
wait_until "anonymous allowed again" 5 anon_pub_is 200 || gate "PATCH true did not restore anonymous ($(anon_pub_code))"
finish_case "an unreadable guest-access row opens anonymous access"

begin_test "FIX #3813: an internal repository: create response, anonymous refused, grant-less user reads but cannot write"
reset_case
note "create response visibility=$(printf '%s' "$INT_CREATE_BODY" | jq -r '.visibility' 2>/dev/null) is_public=$(printf '%s' "$INT_CREATE_BODY" | jq -r '.is_public' 2>/dev/null)"
[ "$(printf '%s' "$INT_CREATE_BODY" | jq -r '"\(.visibility)|\(.is_public)"' 2>/dev/null)" = "internal|false" ] || gate "the create response is not visibility internal / is_public false"
[ "$(db "SELECT visibility::text || '|' || is_public FROM repositories WHERE key = '${INT}'")" = "internal|false" ] || gate "DB row is $(db "SELECT visibility::text || '|' || is_public FROM repositories WHERE key = '${INT}'")"
c1="$(dl "" "$INT")"; note "anonymous download: ${c1}"
anon_refused "$c1" || gate "anonymous read an internal repository (${c1})"
c2="$(dl "$U_T" "$INT")"; note "grant-less user download: ${c2}"
[ "$c2" = "200" ] && [ "$(body)" = "$BYTES_INT" ] || gate "a grant-less authenticated user could not read the internal repository (${c2})"
c3="$(upload "$U_T" "$INT" "w-${SUF}.txt" x)"; note "grant-less user upload: ${c3}"
is_denied "$c3" || gate "a grant-less user wrote to an internal repository (${c3})"
[ "$(db "SELECT count(*) FROM artifacts WHERE path LIKE '%w-${SUF}%'")" = "0" ] || gate "the refused upload stored an artifact"
req GET "/api/v1/repositories?per_page=500" "" >/dev/null; anon_list="$(jr "[.items[]?.key] | index(\"${INT}\")")"
req GET "/api/v1/repositories?per_page=500" "$U_T" >/dev/null; user_list="$(jr "[.items[]?.key] | index(\"${INT}\")")"
note "listing position: anonymous=${anon_list} user=${user_list}"
[ "$anon_list" = "null" ] || gate "the anonymous repository listing shows the internal repository"
[ "$user_list" != "null" ] && [ -n "$user_list" ] || gate "the grant-less user's listing does not show the internal repository"
finish_case "internal visibility does not grant authenticated read or leaks to anonymous"

begin_test "FIX #3813: contradictory visibility and is_public is refused 400"
reset_case
code="$(mkrepo "$ADMIN_TOKEN" '{"visibility":"internal","is_public":true}' "$CONTRA")"; note "internal + is_public:true: ${code} $(jr '.message // empty' | head -c 160)"
[ "$code" = "400" ] || gate "contradictory booleans answered ${code}"
[ "$(db "SELECT count(*) FROM repositories WHERE key = '${CONTRA}'")" = "0" ] || gate "the repository was created"
finish_case "a contradictory request silently resolves to one side"

begin_test "FIX #3813: the artifact blast radius reports the internal repository's access_scope as internal"
reset_case
# The report lists repositories holding an artifact with a scan finding; no
# scanner runs in this profile, so one completed scan result with a single
# finding is seeded for the internal repository's artifact.
seeded="$(db "WITH sr AS (INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, findings_count, high_count)
  SELECT a.id, a.repository_id, 'dependency', 'completed', 1, 1 FROM artifacts a WHERE a.id = '${INT_ART_ID:-00000000-0000-0000-0000-000000000000}' RETURNING id, artifact_id)
  INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, cve_id)
  SELECT id, artifact_id, 'high', 'dtf seeded finding', 'CVE-2099-${SLOT}0001' FROM sr RETURNING 1")"
note "seeded finding rows: ${seeded}"
code="$(req GET "/api/v1/admin/security/artifact/${INT_ART_ID:-none}/blast-radius" "$ADMIN_TOKEN")"
scope="$(jr ".affected_repos[] | select(.repository_key == \"${INT}\") | .access_scope")"
note "blast radius: ${code} access_scope=${scope} is_public=$(jr ".affected_repos[] | select(.repository_key == \"${INT}\") | .is_public")"
[ "$code" = "200" ] && [ "$scope" = "internal" ] || gate "blast radius answered ${code} access_scope '${scope}'"
finish_case "the blast radius misreports internal exposure"

# =============================================================================
# PHASE 2: AK_GUEST_ACCESS_ENABLED=true pins the setting
# =============================================================================
begin_test "setup (phase 2): recreate ONLY the backend with AK_GUEST_ACCESS_ENABLED=true"
if recreate_backend_pinned && curl -sf --max-time 10 "${BASE_URL}/health" >/dev/null 2>&1; then
  ADMIN_TOKEN=""; auth_admin; pass
else
  infra_fail "could not recreate the backend with AK_GUEST_ACCESS_ENABLED=true"; end_suite
fi

begin_test "CONTROL: with the env pin true, anonymous reads the public repository"
reset_case
code="$(anon_pub_code)"; note "anonymous public download: ${code}"
[ "$code" = "200" ] || gate "anonymous public download answered ${code} under AK_GUEST_ACCESS_ENABLED=true"
finish_case "the env pin does not allow guests"

begin_test "FIX #867: the env pin is reported (source environment, not editable); a PATCH is stored but changes nothing"
reset_case
code="$(settings)"
note "settings: ${code} $(jr '[.guest_access_enabled,.guest_access_source,.guest_access_editable,.guest_access_stored]|tostring')"
[ "$code" = "200" ] && [ "$(jr '.guest_access_source')|$(jr '.guest_access_editable')|$(jr '.guest_access_enabled')" = "environment|false|true" ] \
  || gate "pinned settings answered ${code}: $(snip)"
audits_before="$(setting_audits)"
code="$(set_guest false)"
note "PATCH false under the pin: ${code} $(jr '[.guest_access_enabled,.guest_access_source,.guest_access_editable,.guest_access_stored]|tostring')"
[ "$code" = "200" ] && [ "$(jr '.guest_access_enabled')|$(jr '.guest_access_stored')|$(jr '.guest_access_editable')" = "true|false|false" ] \
  || gate "PATCH under the pin answered ${code}: $(snip)"
[ "$(db "SELECT value::text FROM system_settings WHERE key = '${SETTING}'")" = "false" ] || gate "the PATCH was not stored"
sleep 6
code="$(anon_pub_code)"; note "anonymous public download 6 s later: ${code}"
[ "$code" = "200" ] || gate "the stored false overrode the env pin (${code})"
if wait_until "SETTING_CHANGED row" 10 audit_rows_reach "$((audits_before + 1))"; then
  d="$(db "SELECT (details->>'effective_changed') || '|' || (details->>'source') FROM audit_log WHERE action = 'SETTING_CHANGED' AND details->>'setting' = '${SETTING}' ORDER BY created_at DESC LIMIT 1")"
  note "audit effective_changed|source: ${d}"
  [ "$d" = "false|environment" ] || gate "audit records ${d}, expected false|environment"
else gate "no SETTING_CHANGED row for the pinned write"; fi
finish_case "the env pin is not authoritative or not reported"

end_suite
