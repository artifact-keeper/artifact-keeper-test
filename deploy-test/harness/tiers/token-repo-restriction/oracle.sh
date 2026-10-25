#!/usr/bin/env bash
# =============================================================================
# tiers/token-repo-restriction/oracle.sh
#   #4219  a personal token's repo_selector is stored and enforced on read,
#          write and listing; a selector that does not restrict, or an unknown
#          field, is 400.
#   #4225  a repository-restricted credential mints only tokens that inherit
#          its restriction.
#   #4226  an unparseable stored selector grants nothing; every mint endpoint
#          refuses unknown fields and non-restricting selectors.
#   GHSA-2mfv-xg68-gq4p  a download ticket carries the minting credential's
#          repository restriction, and redeeming one works again.
#   GHSA-gvhj-8vg9-358g  PUT /repositories/{key}/security needs
#          write:repositories.
# See the manifest for THE BUGS, the fixture and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=../../lib/repo_delete.sh
source "${DTF_DIR:?}/harness/lib/repo_delete.sh"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
RA="trr-a-${SLOT}-${SUF}"      # private, inside TA's selector
RB="trr-b-${SLOT}-${SUF}"      # private, outside it
RC="trr-c-${SLOT}-${SUF}"      # private, deleted after a token is pinned to it
OBJ="dir/obj.txt"
BYTES_A="trr-bytes-A-${SUF}"
BYTES_B="trr-bytes-B-${SUF}"
USER_NAME="trr-user-${SLOT}-${SUF}"
USER_PASS="Trr_${SUF}_Aa1!"
SA_NAME="trr-sa-${SLOT}-${SUF}"

WORK="$(mktemp -d -t dtf-trr-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code on stdout, body in $WORK/body.
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 300 || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
# put_obj REPO PATH TOKEN BYTES -> HTTP code
put_obj() {
  printf '%s' "$4" > "$WORK/up"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $3" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$WORK/up" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null || echo 000
}
# dl REPO TOKEN -> HTTP code; body in $WORK/body
dl() { req GET "/api/v1/repositories/$1/download/${OBJ}" "$2"; }
# dl_ticket REPO TICKET -> HTTP code (no other credential)
dl_ticket() {
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' \
    "${BASE_URL}/api/v1/repositories/$1/download/${OBJ}?ticket=$2" 2>/dev/null || echo 000
}
# mint_ticket TOKEN JSON -> ticket on stdout (empty on failure); code in $WORK/tcode
mint_ticket() {
  req POST /api/v1/auth/ticket "$1" "$2" > "$WORK/tcode"
  jr '.ticket // empty'
}
# mint TOKEN PATH JSON -> sets MINT_CODE, MINT_TOKEN, MINT_ID
mint() {
  MINT_CODE="$(req POST "$2" "$1" "$3")"
  MINT_TOKEN="$(jr '.token // empty')"; MINT_ID="$(jr '.id // empty')"
}
selector_of() { db "SELECT COALESCE(repo_selector::text, 'NULL') FROM api_tokens WHERE id = '$1'"; }
tokens_named() { db "SELECT count(*) FROM api_tokens WHERE name = '$1'"; }

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
# expect_bytes CODE WANT WHAT: 200 and exactly WANT in the body
expect_bytes() {
  if [ "$1" != "200" ] || [ "$(body)" != "$2" ]; then
    gate "$3 answered $1 body='$(snip | head -c 120)', expected 200 '$2'"
  fi
}
# expect_denied CODE WHAT: 403/404 and none of the private bytes
expect_denied() {
  is_denied "$1" || gate "$2 answered $1, expected 403/404: $(snip | head -c 160)"
  body | grep -q -e "$BYTES_A" -e "$BYTES_B" && gate "$2 leaked repository bytes"
  return 0
}

# =============================================================================
begin_suite "token-repo-restriction"

begin_test "setup: private repos A, B, C with one object each, a user granted read/write/admin on all, its tokens, a service account"
auth_admin
SETUP_ERR=""
mk_repo() {
  req POST /api/v1/repositories "$ADMIN_TOKEN" \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null
  jr '.id // empty'
}
A_ID="$(mk_repo "$RA")"; B_ID="$(mk_repo "$RB")"; C_ID="$(mk_repo "$RC")"
[ -n "$A_ID" ] && [ -n "$B_ID" ] && [ -n "$C_ID" ] || SETUP_ERR="${SETUP_ERR} repos(a=${A_ID} b=${B_ID} c=${C_ID})"
is_2xx "$(put_obj "$RA" "$OBJ" "$ADMIN_TOKEN" "$BYTES_A")" || SETUP_ERR="${SETUP_ERR} upload-A"
is_2xx "$(put_obj "$RB" "$OBJ" "$ADMIN_TOKEN" "$BYTES_B")" || SETUP_ERR="${SETUP_ERR} upload-B"
U_ID="$(create_test_user_with_retry "$USER_NAME" "$USER_PASS" "${USER_NAME}@dtf.test" 2>/dev/null || true)"
[ -n "$U_ID" ] || SETUP_ERR="${SETUP_ERR} user"
grant() { # PRINCIPAL_TYPE PRINCIPAL_ID REPO_ID ACTIONS_JSON
  req POST /api/v1/permissions "$ADMIN_TOKEN" \
    "{\"principal_type\":\"$1\",\"principal_id\":\"$2\",\"target_type\":\"repository\",\"target_id\":\"$3\",\"actions\":$4}"
}
for r in "$A_ID" "$B_ID" "$C_ID"; do
  code="$(grant user "$U_ID" "$r" '["read","write","admin"]')"
  is_2xx "$code" || SETUP_ERR="${SETUP_ERR} grant-user(${r}:${code})"
done
UT="$(login_as "$USER_NAME" "$USER_PASS" 2>/dev/null || true)"
[ -n "$UT" ] || SETUP_ERR="${SETUP_ERR} login"
mint "$UT" /api/v1/auth/tokens "{\"name\":\"trr-ta-${SUF}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"],\"repo_selector\":{\"match_repos\":[\"${A_ID}\"]}}"
TA="$MINT_TOKEN"; TA_ID="$MINT_ID"
mint "$UT" /api/v1/auth/tokens "{\"name\":\"trr-tu-${SUF}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"]}"
TU="$MINT_TOKEN"
mint "$UT" /api/v1/auth/tokens "{\"name\":\"trr-tc-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_repos\":[\"${C_ID}\"]}}"
TC="$MINT_TOKEN"
mint "$UT" /api/v1/auth/tokens "{\"name\":\"trr-ro-${SUF}\",\"scopes\":[\"read:artifacts\"]}"
TRO="$MINT_TOKEN"
mint "$UT" /api/v1/auth/tokens "{\"name\":\"trr-wr-${SUF}\",\"scopes\":[\"read:artifacts\",\"write:repositories\"]}"
TWR="$MINT_TOKEN"
mint "$UT" /api/v1/auth/tokens "{\"name\":\"trr-rr-${SUF}\",\"scopes\":[\"read:repositories\"]}"
TRR="$MINT_TOKEN"
[ -n "$TA" ] && [ -n "$TU" ] && [ -n "$TC" ] && [ -n "$TRO" ] && [ -n "$TWR" ] && [ -n "$TRR" ] \
  || SETUP_ERR="${SETUP_ERR} personal-tokens($(snip | head -c 160))"
req POST /api/v1/service-accounts "$ADMIN_TOKEN" "{\"name\":\"${SA_NAME}\",\"description\":\"token-repo-restriction\",\"scopes\":[\"read:artifacts\"]}" >/dev/null
SA="$(jr '.id // empty')"
[ -n "$SA" ] || SETUP_ERR="${SETUP_ERR} service-account($(snip | head -c 160))"
for r in "$A_ID" "$B_ID"; do
  code="$(grant service_account "$SA" "$r" '["read"]')"
  is_2xx "$code" || SETUP_ERR="${SETUP_ERR} grant-sa(${r}:${code})"
done
mint "$ADMIN_TOKEN" "/api/v1/service-accounts/${SA}/tokens" "{\"name\":\"trr-sr-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repository_ids\":[\"${A_ID}\"]}"
SR="$MINT_TOKEN"
[ -n "$SR" ] || SETUP_ERR="${SETUP_ERR} sa-token($(snip | head -c 160))"
# Baseline scan configuration, written by the U session (a repository admin).
code="$(req PUT "/api/v1/repositories/${RA}/security" "$UT" \
  '{"scan_enabled":true,"scan_on_upload":true,"scan_on_proxy":false,"block_on_policy_violation":true,"severity_threshold":"high"}')"
is_2xx "$code" || SETUP_ERR="${SETUP_ERR} scan-config(${code}:$(snip | head -c 160))"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- A=${RA} (${A_ID}) B=${RB} (${B_ID}) C=${RC}; user=${USER_NAME}; TA=${TA_ID}; SA=${SA}"
pass

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: an unrestricted token and the session of the same user read, write and list both repositories"
reset_case
code="$(dl "$RA" "$TU")"; expect_bytes "$code" "$BYTES_A" "TU download A"
code="$(dl "$RB" "$TU")"; expect_bytes "$code" "$BYTES_B" "TU download B"
code="$(put_obj "$RB" "dir/tu.txt" "$TU" "tu-${SUF}")"; is_2xx "$code" || gate "TU upload to B answered ${code}"
for tok in TU UT; do
  code="$(req GET '/api/v1/repositories?per_page=200' "${!tok}")"
  keys="$(jr '[.items[]?.key] | join(" ")')"
  { [ "$code" = "200" ] && printf '%s' " $keys " | grep -q " $RA " && printf '%s' " $keys " | grep -q " $RB "; } \
    || gate "${tok} repository list answered ${code} without both A and B: ${keys}"
done
finish_case "the user's own reach changed; every denial below would be hollow"

begin_test "CONTROL: a service-account token pinned with repository_ids reads A and not B"
reset_case
code="$(dl "$RA" "$SR")"; expect_bytes "$code" "$BYTES_A" "SR download A"
code="$(dl "$RB" "$SR")"; expect_denied "$code" "SR download B"
finish_case "the pre-existing repository_ids restriction changed"

begin_test "CONTROL: no credential or a forged ticket reads none of the private bytes; an unauthenticated mint is 401"
reset_case
code="$(req POST /api/v1/auth/ticket "" '{"purpose":"download"}')"
[ "$code" = "401" ] || gate "unauthenticated POST /auth/ticket answered ${code}, expected 401"
code="$(dl "$RA" "")"
# No credential at all: 401 (today's main) or the 404 existence-hiding
# answer (1.10.0, 1.11.0) are both refusals; the bytes are what matters.
case "$code" in 401|403|404) ;; *) gate "anonymous download A answered ${code}, expected 401/403/404";; esac
body | grep -q "$BYTES_A" && gate "an anonymous request read A's bytes"
code="$(dl_ticket "$RA" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")"
is_2xx "$code" && gate "a forged ticket on A answered ${code}"
body | grep -q "$BYTES_A" && gate "a forged ticket read A's bytes"
finish_case "anonymous or forged access to a private repository"

begin_test "CONTROL: the repository admin's session and a write:repositories token may change the scan configuration"
reset_case
code="$(req PUT "/api/v1/repositories/${RA}/security" "$TWR" \
  '{"scan_enabled":true,"scan_on_upload":true,"scan_on_proxy":false,"block_on_policy_violation":true,"severity_threshold":"medium"}')"
[ "$code" = "200" ] && [ "$(jr '.severity_threshold')" = "medium" ] || gate "write:repositories token PUT /security answered ${code}: $(snip)"
code="$(req PUT "/api/v1/repositories/${RA}/security" "$UT" \
  '{"scan_enabled":true,"scan_on_upload":true,"scan_on_proxy":false,"block_on_policy_violation":true,"severity_threshold":"high"}')"
[ "$code" = "200" ] && [ "$(jr '.severity_threshold')" = "high" ] || gate "session PUT /security answered ${code}: $(snip)"
code="$(req GET "/api/v1/repositories/${RA}/security" "$TRO")"
[ "$code" = "200" ] && [ "$(jr '.config.scan_enabled')" = "true" ] || gate "read:artifacts token GET /security answered ${code}: $(snip)"
finish_case "legitimate scan-configuration writes are refused"

# =============================================================================
# FIX #4219: a personal token's repo_selector is stored and enforced
# =============================================================================
begin_test "FIX #4219: the personal token's repo_selector is stored as given"
reset_case
sel="$(selector_of "$TA_ID")"
note "api_tokens.repo_selector for TA: ${sel}"
[ "$(db "SELECT repo_selector->'match_repos'->>0 FROM api_tokens WHERE id = '${TA_ID}'")" = "$A_ID" ] \
  && [ "$(db "SELECT jsonb_array_length(repo_selector->'match_repos') FROM api_tokens WHERE id = '${TA_ID}'")" = "1" ] \
  || gate "TA's stored selector is ${sel}, expected {\"match_repos\":[\"${A_ID}\"]} (1.10.0 drops the field)"
finish_case "the selector was not stored"

begin_test "FIX #4219: the selector-restricted token reads A and is refused B on download, artifact listing and repository read"
reset_case
code="$(dl "$RA" "$TA")"; expect_bytes "$code" "$BYTES_A" "TA download A"
code="$(dl "$RB" "$TA")"; expect_denied "$code" "TA download B"
code="$(req GET "/api/v1/repositories/${RB}/artifacts" "$TA")"; expect_denied "$code" "TA list B's artifacts"
code="$(req GET "/api/v1/repositories/${RB}" "$TA")"; expect_denied "$code" "TA GET /repositories/B"
code="$(req GET "/api/v1/repositories/${RA}" "$TA")"
[ "$code" = "200" ] && [ "$(jr '.key')" = "$RA" ] || gate "TA GET /repositories/A answered ${code}"
finish_case "a selector-restricted personal token reads outside its selector"

begin_test "FIX #4219: the selector-restricted token's repository listing names A and not B"
reset_case
code="$(req GET '/api/v1/repositories?per_page=200' "$TA")"
keys="$(jr '[.items[]?.key] | join(" ")')"
note "TA repository list: ${code} ${keys}"
[ "$code" = "200" ] || gate "TA repository list answered ${code}"
printf '%s' " $keys " | grep -q " $RA " || gate "TA's listing does not name A"
printf '%s' " $keys " | grep -q " $RB " && gate "TA's listing names B"
finish_case "the listing is not confined to the selector"

begin_test "FIX #4219: the selector-restricted token writes into A and is refused B; nothing lands in B"
reset_case
code="$(put_obj "$RA" "dir/ta.txt" "$TA" "ta-${SUF}")"; is_2xx "$code" || gate "TA upload to A answered ${code}: $(snip)"
code="$(put_obj "$RB" "dir/ta.txt" "$TA" "ta-${SUF}")"
is_denied "$code" || gate "TA upload to B answered ${code}, expected 403/404"
n="$(db "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${RB}' AND a.path LIKE '%ta.txt'")"
[ "$n" = "0" ] || gate "B holds ${n} artifact row(s) written by TA"
finish_case "a selector-restricted personal token writes outside its selector"

begin_test "FIX #4219: a selector that would not restrict, or an unknown field, is 400 and mints nothing"
reset_case
for pair in "{}|empty" "{\"match_repoz\":[\"${A_ID}\"]}|misspelled criterion"; do
  sel="${pair%%|*}"; what="${pair##*|}"; nm="trr-bad-${what// /-}-${SUF}"
  code="$(req POST /api/v1/auth/tokens "$UT" "{\"name\":\"${nm}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":${sel}}")"
  note "/auth/tokens with ${what} selector: ${code} $(snip | head -c 140)"
  [ "$code" = "400" ] || gate "${what} selector answered ${code}, expected 400"
  [ "$(tokens_named "$nm")" = "0" ] || gate "${what} selector still stored a token"
done
nm="trr-unknown-${SUF}"
code="$(req POST /api/v1/auth/tokens "$UT" "{\"name\":\"${nm}\",\"scopes\":[\"read:artifacts\"],\"repo_selektor\":{\"match_repos\":[\"${A_ID}\"]}}")"
note "/auth/tokens with repo_selektor: ${code} $(snip | head -c 140)"
[ "$code" = "400" ] || gate "unknown field repo_selektor answered ${code}, expected 400 (1.10.0 mints an unrestricted token)"
body | grep -q 'repo_selektor' || gate "the 400 does not name the unknown field"
[ "$(tokens_named "$nm")" = "0" ] || gate "the misspelled request still stored a token"
finish_case "a mint request that does not restrict is accepted"

# =============================================================================
# FIX #4225: a restricted credential mints only restricted tokens
# =============================================================================
begin_test "FIX #4225: a token minted by the selector-restricted token inherits match_repos [A] (/auth/tokens and /profile/access-tokens)"
reset_case
for ep in /api/v1/auth/tokens /api/v1/profile/access-tokens; do
  mint "$TA" "$ep" "{\"name\":\"trr-child-${ep##*/}-${SUF}\",\"scopes\":[\"read:artifacts\"]}"
  note "TA mints via ${ep}: ${MINT_CODE}; stored selector $(selector_of "$MINT_ID")"
  if ! is_2xx "$MINT_CODE" || [ -z "$MINT_TOKEN" ]; then gate "TA mint via ${ep} answered ${MINT_CODE}: $(snip)"; continue; fi
  [ "$(db "SELECT repo_selector->'match_repos'->>0 FROM api_tokens WHERE id = '${MINT_ID}'")" = "$A_ID" ] \
    || gate "child via ${ep} stored selector $(selector_of "$MINT_ID"), expected match_repos [A]"
  code="$(dl "$RA" "$MINT_TOKEN")"; expect_bytes "$code" "$BYTES_A" "child via ${ep} download A"
  code="$(dl "$RB" "$MINT_TOKEN")"; expect_denied "$code" "child via ${ep} download B"
done
finish_case "a restricted token mints an unrestricted sibling"

begin_test "FIX #4225: a token minted by a repository_ids service-account token inherits its restriction"
reset_case
mint "$SR" /api/v1/auth/tokens "{\"name\":\"trr-sr-child-${SUF}\",\"scopes\":[\"read:artifacts\"]}"
note "SR mints: ${MINT_CODE}; stored selector $(selector_of "$MINT_ID")"
if is_2xx "$MINT_CODE" && [ -n "$MINT_TOKEN" ]; then
  code="$(dl "$RB" "$MINT_TOKEN")"; expect_denied "$code" "SR child download B"
  code="$(dl "$RA" "$MINT_TOKEN")"; expect_bytes "$code" "$BYTES_A" "SR child download A"
else
  gate "SR mint answered ${MINT_CODE}: $(snip)"
fi
finish_case "a repository_ids token mints an unrestricted sibling"

begin_test "FIX #4225: a restricted token may not name its own selector, and a restriction that matches nothing cannot mint"
reset_case
nm="trr-widen-${SUF}"
code="$(req POST /api/v1/auth/tokens "$TA" "{\"name\":\"${nm}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_repos\":[\"${B_ID}\"]}}")"
note "TA naming selector [B]: ${code} $(snip | head -c 140)"
[ "$code" = "403" ] || gate "TA naming a selector for B answered ${code}, expected 403"
[ "$(tokens_named "$nm")" = "0" ] || gate "the refused widening still stored a token"
code="$(req DELETE "/api/v1/repositories/${RC}" "$ADMIN_TOKEN")"
is_2xx "$code" || gate "deleting C answered ${code}"
# 1.12.0 answers 202 and removes C in a job (#4311); C's row (and so the
# selector's target) is gone only once the job completes. No-op on a 200.
if is_2xx "$code"; then
  repo_delete_wait "$BASE_URL" "$ADMIN_TOKEN" "$code" "$WORK/body" \
    || gate "deleting C did not finish: ${REPO_DELETE_ERROR}"
fi
for ep in /api/v1/auth/tokens /api/v1/profile/access-tokens; do
  nm="trr-orphan-${ep##*/}-${SUF}"
  code="$(req POST "$ep" "$TC" "{\"name\":\"${nm}\",\"scopes\":[\"read:artifacts\"]}")"
  note "TC (selector on deleted C) mints via ${ep}: ${code} $(snip | head -c 140)"
  [ "$code" = "403" ] || gate "a credential restricted to nothing minted via ${ep} (${code}), expected 403"
  [ "$(tokens_named "$nm")" = "0" ] || gate "the refused orphan mint via ${ep} still stored a token"
done
finish_case "a restricted credential widened or escaped its restriction"

# =============================================================================
# FIX #4226: stored selectors fail closed; mint endpoints refuse unknown fields
# =============================================================================
begin_test "FIX #4226: service-account token creation refuses a misspelled selector, an empty repository_ids and an unknown field"
reset_case
for pair in \
  "{\"name\":\"trr-sa-bad1-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_repoz\":[\"${A_ID}\"]}}|trr-sa-bad1-${SUF}|misspelled selector" \
  "{\"name\":\"trr-sa-bad2-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repository_ids\":[]}|trr-sa-bad2-${SUF}|empty repository_ids" \
  "{\"name\":\"trr-sa-bad3-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selektor\":{\"match_repos\":[\"${A_ID}\"]}}|trr-sa-bad3-${SUF}|unknown field"; do
  json="${pair%%|*}"; rest="${pair#*|}"; nm="${rest%%|*}"; what="${rest#*|}"
  code="$(req POST "/api/v1/service-accounts/${SA}/tokens" "$ADMIN_TOKEN" "$json")"
  note "SA token with ${what}: ${code} $(snip | head -c 140)"
  [ "$code" = "400" ] || gate "SA token with ${what} answered ${code}, expected 400"
  [ "$(tokens_named "$nm")" = "0" ] || gate "SA token with ${what} was stored"
done
finish_case "service-account token creation stores a selector that does not restrict"

begin_test "FIX #4226: /profile/access-tokens and /users/me/tokens refuse an unknown field"
reset_case
for ep in /api/v1/profile/access-tokens /api/v1/users/me/tokens; do
  nm="trr-unk-${ep//\//-}-${SUF}"
  code="$(req POST "$ep" "$UT" "{\"name\":\"${nm}\",\"scopes\":[\"read:artifacts\"],\"repo_selektor\":{\"match_repos\":[\"${A_ID}\"]}}")"
  note "${ep} with repo_selektor: ${code} $(snip | head -c 140)"
  [ "$code" = "400" ] || gate "${ep} with an unknown field answered ${code}, expected 400"
  [ "$(tokens_named "$nm")" = "0" ] || gate "${ep} stored a token for the misspelled request"
done
finish_case "a misspelled mint field is silently dropped"

begin_test "FIX #4226: a stored selector that does not parse grants no repository at all"
reset_case
mint "$ADMIN_TOKEN" "/api/v1/service-accounts/${SA}/tokens" "{\"name\":\"trr-sa-tamper-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_repos\":[\"${A_ID}\"]}}"
TT="$MINT_TOKEN"; TT_ID="$MINT_ID"
if [ -z "$TT" ]; then
  gate "could not mint the selector token to tamper (${MINT_CODE}): $(snip)"
else
  # Tamper BEFORE first use, so no validated-token cache entry exists yet.
  db "UPDATE api_tokens SET repo_selector = '{\"match_repoz\": [\"${A_ID}\"]}'::jsonb WHERE id = '${TT_ID}'" >/dev/null
  note "stored selector now $(selector_of "$TT_ID")"
  code="$(dl "$RA" "$TT")"; expect_denied "$code" "tampered-selector token download A"
  code="$(dl "$RB" "$TT")"; expect_denied "$code" "tampered-selector token download B"
fi
finish_case "an unparseable stored selector fails open"

# =============================================================================
# FIX GHSA-2mfv-xg68-gq4p: tickets carry the minter's restriction and redeem
# =============================================================================
begin_test "FIX GHSA-2mfv: a ticket minted by the restricted token records its restriction (download_tickets.allowed_repo_ids)"
reset_case
tk="$(mint_ticket "$TA" '{"purpose":"trr-record"}')"
note "mint: $(cat "$WORK/tcode") ticket=${tk:0:8}..."
[ -n "$tk" ] || gate "TA could not mint a ticket ($(cat "$WORK/tcode")): $(snip)"
row="$(db "SELECT scope_recorded::text || '|' || COALESCE(array_to_string(allowed_repo_ids, ','), 'NULL') FROM download_tickets WHERE purpose = 'trr-record'")"
note "download_tickets row: ${row}"
[ "$row" = "true|${A_ID}" ] || gate "the ticket row records '${row}', expected 'true|${A_ID}'"
finish_case "the ticket does not record the minting credential's restriction"

begin_test "FIX GHSA-2mfv: the restricted token's tickets redeem on A (bound and unbound), single use, and never read B"
reset_case
tk="$(mint_ticket "$TA" "{\"purpose\":\"download\",\"resource_path\":\"/api/v1/repositories/${RA}/download/${OBJ}\"}")"
code="$(dl_ticket "$RA" "$tk")"; note "TA path-bound ticket on A: ${code}"
expect_bytes "$code" "$BYTES_A" "TA path-bound ticket on A"
code="$(dl_ticket "$RA" "$tk")"; note "the same ticket again: ${code}"
body | grep -q "$BYTES_A" && gate "a redeemed ticket read A a second time"
tk="$(mint_ticket "$TA" '{"purpose":"download"}')"
code="$(dl_ticket "$RA" "$tk")"; note "TA unbound ticket on A: ${code}"
expect_bytes "$code" "$BYTES_A" "TA unbound ticket on A"
tk="$(mint_ticket "$TA" '{"purpose":"download"}')"
code="$(dl_ticket "$RB" "$tk")"; note "TA unbound ticket on B: ${code}"
expect_denied "$code" "TA unbound ticket on B"
tk="$(mint_ticket "$TA" "{\"purpose\":\"download\",\"resource_path\":\"/api/v1/repositories/${RB}/download/${OBJ}\"}")"
code="$(dl_ticket "$RB" "$tk")"; note "TA ticket bound to B's path: ${code}"
expect_denied "$code" "TA ticket bound to B's path"
finish_case "a restricted token's ticket does not redeem, or redeems outside the restriction"

begin_test "FIX GHSA-2mfv: an unrestricted credential's ticket reads B (redemption works; the B refusal above is the restriction)"
reset_case
for tok in UT TU; do
  tk="$(mint_ticket "${!tok}" "{\"purpose\":\"download\",\"resource_path\":\"/api/v1/repositories/${RB}/download/${OBJ}\"}")"
  code="$(dl_ticket "$RB" "$tk")"; note "${tok} ticket on B: ${code}"
  expect_bytes "$code" "$BYTES_B" "${tok} path-bound ticket on B"
done
finish_case "redeeming a valid ticket fails (every ticket is treated as anonymous)"

begin_test "FIX GHSA-2mfv: minting a ticket needs the read:artifacts scope"
reset_case
code="$(req POST /api/v1/auth/ticket "$TRR" '{"purpose":"trr-noscope"}')"
note "read:repositories-only token mints a ticket: ${code} $(snip | head -c 140)"
[ "$code" = "403" ] || gate "a token without read:artifacts minted a ticket (${code}), expected 403"
[ "$(db "SELECT count(*) FROM download_tickets WHERE purpose = 'trr-noscope'")" = "0" ] || gate "the refused mint stored a ticket"
finish_case "a token without read:artifacts mints a read ticket"

# =============================================================================
# FIX GHSA-gvhj-8vg9-358g: PUT /security needs write:repositories
# =============================================================================
begin_test "FIX GHSA-gvhj: a read:artifacts token held by a repository admin cannot change the scan configuration"
reset_case
before="$(db "SELECT scan_enabled::text || ',' || block_on_policy_violation::text || ',' || severity_threshold FROM scan_configs WHERE repository_id = '${A_ID}'")"
code="$(req PUT "/api/v1/repositories/${RA}/security" "$TRO" \
  '{"scan_enabled":false,"scan_on_upload":false,"scan_on_proxy":false,"block_on_policy_violation":false,"severity_threshold":"critical"}')"
after="$(db "SELECT scan_enabled::text || ',' || block_on_policy_violation::text || ',' || severity_threshold FROM scan_configs WHERE repository_id = '${A_ID}'")"
note "read:artifacts PUT /security: ${code} $(snip | head -c 140); scan_configs ${before} -> ${after}"
[ "$code" = "403" ] || gate "read:artifacts token PUT /security answered ${code}, expected 403"
[ "$before" = "true,true,high" ] && [ "$after" = "$before" ] || gate "scan configuration changed from '${before}' to '${after}'"
finish_case "a read-only token switched scanning off"

end_suite
