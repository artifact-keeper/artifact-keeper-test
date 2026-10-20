#!/usr/bin/env bash
# =============================================================================
# tiers/download-route-token-basic/oracle.sh - the generic download route
#   challenges and accepts an API token as the Basic password (#4654 / #4593),
#   and repository-scoped admin tokens are refused on the instance-wide admin
#   listings (#4550). Both fixed in 1.11.1; RED on 1.11.0.
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Fixture: private generic local Q (U holds `reader`), public generic local P,
# one artifact in each. U mints a read:artifacts API token TU. The admin mints
# an unrestricted token TA ("*") and a token TS ("*") with repo_selector
# {match_repos:[Q]}. N is a signed-in user with no grant.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
Q="drtb-priv-${SLOT}-${SUF}"
P="drtb-pub-${SLOT}-${SUF}"
MISSING="drtb-missing-${SLOT}-${SUF}"
ART="drtb/tool-1.0.bin"
Q_BYTES="drtb-private-payload-${SUF}"
P_BYTES="drtb-public-payload-${SUF}"
PW="Drtb_${SUF}_Aa1!"
U_USER="drtb-u-${SLOT}-${SUF}"
N_USER="drtb-n-${SLOT}-${SUF}"

WORK="$(mktemp -d -t dtf-drtb-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# hreq METHOD URL [curl args...] -> HTTP code; body $WORK/body, headers $WORK/hdr.
hreq() {
  local method="$1" url="$2"; shift 2
  : > "$WORK/body"; : > "$WORK/hdr"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -D "$WORK/hdr" -w '%{http_code}' \
    "$@" "${BASE_URL}${url}" 2>/dev/null || echo 000
}
body() { head -c 300 "$WORK/body" 2>/dev/null || true; }
raw() { cat "$WORK/body" 2>/dev/null || true; }
jb() { jq -r "$1" "$WORK/body" 2>/dev/null || true; }
# challenges -> the WWW-Authenticate values of the last response, sorted, one per line.
challenges() { grep -i '^www-authenticate:' "$WORK/hdr" 2>/dev/null | sed -e 's/^[^:]*:[[:space:]]*//' -e 's/\r$//' | sort || true; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null | tr -d '[:space:]' || echo "?"; }
setup_ok() {
  if [ "${2:0:1}" != "2" ]; then
    begin_test "setup: ${1}"; infra_fail "${1}: HTTP ${2}" "$(body)"; end_suite
  fi
}
bearer() { printf 'Authorization: Bearer %s' "$1"; }
DL() { printf '/api/v1/repositories/%s/download/%s' "$1" "$2"; }

begin_suite "download-route-token-basic"

# =============================================================================
# SETUP
# =============================================================================
auth_admin
AT="$ADMIN_TOKEN"
for u in "$U_USER" "$N_USER"; do
  if ! create_test_user_with_retry "$u" "$PW" "${u}@t.test" >/dev/null; then
    begin_test "setup: create user ${u}"; infra_fail "could not create user ${u}"; end_suite
  fi
done
UT="$(login_as "$U_USER" "$PW")" || true
NT="$(login_as "$N_USER" "$PW")" || true
if [ -z "$UT" ] || [ -z "$NT" ]; then
  begin_test "setup: log in the test users"; infra_fail "a login returned no token"; end_suite
fi
U_ID="$(db "SELECT id FROM users WHERE username='${U_USER}';")"

for spec in "$Q:false" "$P:true"; do
  k="${spec%%:*}"; pub="${spec##*:}"
  c="$(hreq POST /api/v1/repositories -H "$(bearer "$AT")" -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg k "$k" --argjson p "$pub" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:$p}')")"
  setup_ok "create repository ${k}" "$c"
done
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${U_USER}' AND r.name='reader' AND repo.key='${Q}'
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true
c="$(hreq PUT "/api/v1/repositories/${Q}/artifacts/${ART}" -H "$(bearer "$AT")" \
  -H 'Content-Type: application/octet-stream' --data-binary "$Q_BYTES")"; setup_ok "upload to ${Q}" "$c"
c="$(hreq PUT "/api/v1/repositories/${P}/artifacts/${ART}" -H "$(bearer "$AT")" \
  -H 'Content-Type: application/octet-stream' --data-binary "$P_BYTES")"; setup_ok "upload to ${P}" "$c"
Q_ID="$(db "SELECT id FROM repositories WHERE key='${Q}';")"
Q_ART_ID="$(db "SELECT a.id FROM artifacts a WHERE a.repository_id='${Q_ID}' AND a.path='${ART}';")"

mint() { # BEARER JSON -> token on stdout
  hreq POST /api/v1/auth/tokens -H "$(bearer "$1")" -H 'Content-Type: application/json' --data "$2" >/dev/null
  jb '.token // empty'
}
TU="$(mint "$UT" "$(jq -nc --arg n "drtb-u-${SUF}" '{name:$n,scopes:["read:artifacts"]}')")"
TA="$(mint "$AT" "$(jq -nc --arg n "drtb-admin-${SUF}" '{name:$n,scopes:["*"]}')")"
TS="$(mint "$AT" "$(jq -nc --arg n "drtb-scoped-${SUF}" --arg q "$Q_ID" '{name:$n,scopes:["*"],repo_selector:{match_repos:[$q]}}')")"
if [ -z "$TU" ] || [ -z "$TA" ] || [ -z "$TS" ]; then
  begin_test "setup: mint API tokens"; infra_fail "tokens TU='${TU:0:6}' TA='${TA:0:6}' TS='${TS:0:6}'" "$(body)"; end_suite
fi
SCOPED_ROWS="$(db "SELECT count(*) FROM api_tokens WHERE name='drtb-scoped-${SUF}' AND repo_selector IS NOT NULL;")"
if [ "$SCOPED_ROWS" != "1" ]; then
  begin_test "setup: scoped admin token carries its repo_selector"; infra_fail "api_tokens row with repo_selector: ${SCOPED_ROWS}"; end_suite
fi

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "control: anonymous download from the public repository -> 200 with its bytes"
c="$(hreq GET "$(DL "$P" "$ART")")"
if [ "$c" = "200" ] && [ "$(raw)" = "$P_BYTES" ]; then pass; else fail "public anonymous download: HTTP ${c}" "$(body)"; fi

begin_test "control: Bearer API token of a reader on the private download route -> 200 with its bytes"
c="$(hreq GET "$(DL "$Q" "$ART")" -H "$(bearer "$TU")")"
if [ "$c" = "200" ] && [ "$(raw)" = "$Q_BYTES" ]; then pass; else fail "bearer token download: HTTP ${c}" "$(body)"; fi

begin_test "control: valid credential without a grant on the private repository -> existence-hiding 404"
c="$(hreq GET "$(DL "$Q" "$ART")" -H "$(bearer "$NT")")"
if [ "$c" = "404" ] && ! grep -qF "$Q_BYTES" "$WORK/body"; then pass; else fail "non-entitled download: HTTP ${c}" "$(body)"; fi

begin_test "control: API token as the Basic password stays refused on /api/v1/auth/me and /api/v1/repositories"
c1="$(hreq GET /api/v1/auth/me -u "x:${TU}")"
c2="$(hreq GET /api/v1/repositories -u "x:${TU}")"
if [ "$c1" = "401" ] && [ "$c2" = "401" ]; then pass
else fail "management API accepted token-as-Basic: /auth/me ${c1}, /repositories ${c2}" "$(body)"; fi

begin_test "control: unrestricted admin API token reads /admin/stats and /admin/downloads -> 200"
c1="$(hreq GET /api/v1/admin/stats -H "$(bearer "$TA")")"
s1="$(jb 'keys | length')"
c2="$(hreq GET /api/v1/admin/downloads -H "$(bearer "$TA")")"
if [ "$c1" = "200" ] && [ "${s1:-0}" -gt 0 ] 2>/dev/null && [ "$c2" = "200" ]; then pass
else fail "unrestricted admin token: stats ${c1} (keys ${s1}), downloads ${c2}" "$(body)"; fi

# =============================================================================
# #4654 / #4593 - the download route
# =============================================================================
begin_test "#4654 fix: anonymous GET on a private repository -> 401 with Basic and Bearer challenges"
c="$(hreq GET "$(DL "$Q" "$ART")")"
PRIV_CH="$(challenges)"; PRIV_BODY="$(raw)"
if [ "$c" = "401" ] && grep -q '^Basic ' <<<"$PRIV_CH" && grep -q '^Bearer ' <<<"$PRIV_CH" \
   && ! grep -qF "$Q_BYTES" <<<"$PRIV_BODY"; then pass
else fail "anonymous private download: HTTP ${c}, challenges [$(tr '\n' '|' <<<"$PRIV_CH")]" "$(body)"; fi

begin_test "#4654 fix: anonymous GET on a nonexistent repository -> the same 401, challenges and body"
c="$(hreq GET "$(DL "$MISSING" "$ART")")"
if [ "$c" = "401" ] && [ "$(challenges)" = "$PRIV_CH" ] && [ "$(raw)" = "$PRIV_BODY" ]; then pass
else fail "existence oracle on the download route: HTTP ${c}, challenges [$(challenges | tr '\n' '|')] vs private [$(tr '\n' '|' <<<"$PRIV_CH")]" "$(body)"; fi

begin_test "#4654 fix: browser navigation (Accept: text/html) -> 401 with the Bearer challenge only"
c="$(hreq GET "$(DL "$Q" "$ART")" -H 'Accept: text/html,application/xhtml+xml')"
if [ "$c" = "401" ] && challenges | grep -q '^Bearer ' && ! challenges | grep -q '^Basic '; then pass
else fail "browser challenge: HTTP ${c}, challenges [$(challenges | tr '\n' '|')]" "$(body)"; fi

DL_BEFORE="$(db "SELECT count(*) FROM download_statistics WHERE artifact_id='${Q_ART_ID}' AND user_id='${U_ID}';")"

begin_test "#4654 fix: preemptive Basic x:<api_token> on the private download route -> 200 with its bytes"
c="$(hreq GET "$(DL "$Q" "$ART")" -u "x:${TU}")"
if [ "$c" = "200" ] && [ "$(raw)" = "$Q_BYTES" ]; then pass
else fail "token-as-Basic download: HTTP ${c}" "$(body)"; fi

begin_test "#4654 fix: reactive client (curl --anyauth, credentials only after a challenge) fetches the file"
c="$(hreq GET "$(DL "$Q" "$ART")" --anyauth -u "x:${TU}")"
if [ "$c" = "200" ] && [ "$(raw)" = "$Q_BYTES" ]; then pass
else fail "reactive-client download: HTTP ${c} (the client never got a challenge to answer)" "$(body)"; fi

begin_test "#4654 fix: the token-as-Basic download is attributed to the token owner in download_statistics"
want=$(( ${DL_BEFORE:-0} + 2 ))
got_rows() { db "SELECT count(*) FROM download_statistics WHERE artifact_id='${Q_ART_ID}' AND user_id='${U_ID}';"; }
attributed() { [ "$(got_rows)" -ge "$want" ] 2>/dev/null; }
if wait_until "download_statistics rows for ${U_USER}" 20 attributed; then pass
else fail "download_statistics rows for ${U_USER}: before ${DL_BEFORE}, now $(got_rows), want >= ${want}"; fi

# =============================================================================
# #4550 - repository-scoped admin token on the instance-wide admin listings
# =============================================================================
for route in stats downloads "downloads/by-user/{id}" "downloads/by-ip/127.0.0.1"; do
  begin_test "#4550 fix: repository-scoped admin token GET /api/v1/admin/${route} -> 403"
  c="$(hreq GET "/api/v1/admin/${route/\{id\}/${U_ID}}" -H "$(bearer "$TS")")"
  if [ "$c" = "403" ] && ! grep -qF "$U_USER" "$WORK/body"; then pass
  else fail "scoped admin token read an instance-wide listing: ${route} HTTP ${c}" "$(body)"; fi
done

begin_test "control: repository-scoped admin token is already refused on /admin/holds/summary (pre-existing #4273)"
c="$(hreq GET /api/v1/admin/holds/summary -H "$(bearer "$TS")")"
if [ "$c" = "403" ]; then pass; else fail "holds summary with scoped token: HTTP ${c}" "$(body)"; fi

begin_test "control: the unrestricted admin token sees the token owner's attributed download"
c="$(hreq GET "/api/v1/admin/downloads/by-user/${U_ID}" -H "$(bearer "$TA")")"
if [ "$c" = "200" ] && grep -qF "$Q_ART_ID" "$WORK/body"; then pass
else fail "by-user listing with unrestricted admin token: HTTP ${c}" "$(body)"; fi

end_suite
