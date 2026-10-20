#!/usr/bin/env bash
# =============================================================================
# tiers/npm-anon-audit/oracle.sh: anonymous `npm audit` on a PUBLIC npm
# repository (artifact-keeper#4317, fixed by #4785), filesystem + client.npm.
# =============================================================================
# Background (api/middleware/auth.rs::repo_visibility_middleware): the #508
# gate answers 401 to every anonymous write method, and POST counted as a write
# unless the path is on the is_anonymous_readable_format_post allowlist. The
# npm audit routes were not on it, so an anonymous `npm audit` against a public
# registry failed "Unable to authenticate". The permission arm used the sibling
# is_non_mutating_format_post list, so an authenticated non-admin without write
# got 403 as well. #4785 adds exactly
#     POST /npm/<repo>/-/npm/v1/security/advisories/bulk
#     POST /npm/<repo>/-/npm/v1/security/audits/quick
# to both lists. Visibility is unchanged: a private repo still refuses an
# anonymous caller with the 401 challenge (anonymous means unauthenticated, so
# 401 is the correct refusal here, not an authz denial).
#
# The handlers (api/handlers/npm.rs security_advisories_bulk /
# security_audits_quick) answer a hosted repo with the built-in empty report
# ({} for bulk; {actions,advisories,muted,metadata} for quick) and proxy a
# Remote upstream, falling back to the same empty report when the upstream is
# unreachable (the remote here points at an unresolvable `.invalid` host).
#
# Cases: see the manifest. run.sh exports BASE_URL, DB_CONTAINER,
# ADMIN_USER/ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
NPM_CTR="ak-dtf${SLOT}-client-npm"
AUTH="${ADMIN_USER}:${ADMIN_PASS}"

PUB="npmaudpub-${SLOT}-${SUF}"     # hosted npm, public
PRIV="npmaudpriv-${SLOT}-${SUF}"   # hosted npm, private
REM="npmaudrem-${SLOT}-${SUF}"     # remote npm, public, unresolvable upstream
PKG="dtfaudit"
UPSTREAM="http://npm-upstream-dtf-${SUF}.invalid/"
RO_USER="dtfaud${SLOT}${SUF//-/}"
RO_PASS="Dtf-Audit-${SUF}!x9"

# Realistic npm audit bodies (npm >= 7 bulk; npm 6 / yarn quick).
BULK_BODY="{\"${PKG}\":[\"1.0.0\"],\"left-pad\":[\"1.3.0\"]}"
QUICK_BODY="$(jq -nc --arg p "$PKG" '{name:"dtf-consumer",version:"1.0.0",
  requires:{($p):"^1.0.0","left-pad":"^1.3.0"},
  dependencies:{($p):{version:"1.0.0"},"left-pad":{version:"1.3.0"}}}')"

WORK="$(mktemp -d -t dtf-npmaudit-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# code [curl args...]: HTTP code; body in $WORK/last.
code() { curl -s --max-time 60 -o "$WORK/last" -w '%{http_code}' "$@" 2>/dev/null || echo 000; }
last() { head -c 300 "$WORK/last" 2>/dev/null; }

# audit_post KIND REPO [curl auth args...]: POST a realistic audit body; echo code.
audit_post() {
  local kind="$1" repo="$2"; shift 2
  local path body
  if [ "$kind" = "bulk" ]; then path="advisories/bulk"; body="$BULK_BODY"
  else path="audits/quick"; body="$QUICK_BODY"; fi
  code "$@" -X POST -H 'Content-Type: application/json' -d "$body" \
    "${BASE_URL}/npm/${repo}/-/npm/v1/security/${path}"
}

# The npm JSON shape the handler (and the npm client) expect for each kind.
shape_ok() {
  if [ "$1" = "bulk" ]; then jq -e 'type == "object"' "$WORK/last" >/dev/null 2>&1
  else jq -e 'type == "object" and has("advisories") and has("metadata")' "$WORK/last" >/dev/null 2>&1; fi
}

# expect_audit_ok LABEL REPO [curl auth args...]: both kinds 200 + JSON shape.
expect_audit_ok() {
  local label="$1" repo="$2"; shift 2
  local k c bad=""
  for k in bulk quick; do
    c="$(audit_post "$k" "$repo" "$@")"
    echo "-- ${label} POST ${k} /npm/${repo} -> ${c}: $(last)"
    if [ "$c" != "200" ]; then bad="${bad} ${k}=${c}"
    elif ! shape_ok "$k"; then bad="${bad} ${k}=200-but-not-npm-json"; fi
  done
  if [ -z "$bad" ]; then pass; else fail "${label} audit refused or malformed:${bad}"; fi
}

npm_sh() { docker exec -i "$NPM_CTR" bash -s 2>&1; }

repo_create() { # key type is_public [upstream]
  local body
  body="$(jq -nc --arg k "$1" --arg t "$2" --argjson p "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:"npm",repo_type:$t,is_public:$p} + (if $u == "" then {} else {upstream_url:$u} end)')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "${BASE_URL}/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}

begin_suite "npm-anon-audit"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: npm client, repositories, read-only user, published package"
SETUP_ERR=""
docker exec "$NPM_CTR" npm --version >/dev/null 2>&1 || SETUP_ERR="npm missing in ${NPM_CTR};"
PUB_ID="$(repo_create "$PUB" local true)";              [ -n "$PUB_ID" ]  || SETUP_ERR="${SETUP_ERR} create ${PUB};"
PRIV_ID="$(repo_create "$PRIV" local false)";           [ -n "$PRIV_ID" ] || SETUP_ERR="${SETUP_ERR} create ${PRIV};"
REM_ID="$(repo_create "$REM" remote true "$UPSTREAM")"; [ -n "$REM_ID" ]  || SETUP_ERR="${SETUP_ERR} create ${REM};"
RO_ID="$(create_test_user "$RO_USER" "$RO_PASS" "${RO_USER}@dtf.invalid" 2>/dev/null || true)"
if [ -z "$RO_ID" ]; then SETUP_ERR="${SETUP_ERR} create user;"
elif [ -n "$PRIV_ID" ]; then
  c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$RO_ID" --arg r "$PRIV_ID" '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read"]}')" \
    "${BASE_URL}/api/v1/permissions")"
  [ "${c:0:1}" = "2" ] || SETUP_ERR="${SETUP_ERR} read grant -> ${c} $(last);"
fi
# Publish ${PKG}@1.0.0 into the public repo with the real client (admin creds).
B64="$(printf '%s' "$AUTH" | base64 -w0)"
PUB_OUT="$(npm_sh <<SH
set -e
rm -rf /tmp/pub-${SUF} && mkdir -p /tmp/pub-${SUF} && cd /tmp/pub-${SUF}
printf '%s\n' 'registry=http://backend:8080/npm/${PUB}/' '//backend:8080/npm/${PUB}/:_auth=${B64}' > .npmrc
printf '{"name":"${PKG}","version":"1.0.0","license":"MIT","files":["index.js"]}' > package.json
echo 'module.exports = 1;' > index.js
npm publish --registry 'http://backend:8080/npm/${PUB}/' --no-audit --no-fund
SH
)"; PUB_RC=$?
echo "-- npm publish rc=${PUB_RC}: $(printf '%s' "$PUB_OUT" | tail -3 | tr '\n' ' ')"
[ "$PUB_RC" = "0" ] || SETUP_ERR="${SETUP_ERR} npm publish rc=${PUB_RC};"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# FIX #4317: anonymous audit on PUBLIC npm repositories
# =============================================================================
begin_test "FIX #4317: anonymous bulk + quick audit on the PUBLIC hosted repo -> 200 npm JSON"
expect_audit_ok "anon" "$PUB"

begin_test "FIX #4317: anonymous bulk + quick audit on the PUBLIC remote repo -> 200 npm JSON"
expect_audit_ok "anon" "$REM"

begin_test "FIX #4317: non-admin user without write, PUBLIC hosted repo -> 200 (was 403: audit classed as a write)"
expect_audit_ok "user(no-grants)" "$PUB" -u "${RO_USER}:${RO_PASS}"

begin_test "FIX #4317: non-admin user with a READ grant on the PRIVATE repo -> 200 (was 403)"
expect_audit_ok "user(read)" "$PRIV" -u "${RO_USER}:${RO_PASS}"

# =============================================================================
# CONTROLS: the fix did not open private repos or npm writes
# =============================================================================
begin_test "CONTROL: anonymous bulk + quick audit on the PRIVATE repo is refused (401 challenge)"
bad=""
for k in bulk quick; do
  c="$(audit_post "$k" "$PRIV")"
  echo "-- anon POST ${k} /npm/${PRIV} -> ${c}: $(last)"
  case "$c" in 401|403|404) ;; *) bad="${bad} ${k}=${c}" ;; esac
  grep -q '"advisories"\|"actions"' "$WORK/last" 2>/dev/null && bad="${bad} ${k}-served-a-report"
done
if [ -z "$bad" ]; then pass; else fail "private repo answered an anonymous audit:${bad}"; fi

begin_test "CONTROL: admin bulk + quick audit on the PUBLIC hosted repo -> 200"
expect_audit_ok "admin" "$PUB" -u "$AUTH"

begin_test "CONTROL: admin bulk + quick audit on the PRIVATE repo -> 200"
expect_audit_ok "admin" "$PRIV" -u "$AUTH"

begin_test "CONTROL: anonymous publish (PUT) and an anonymous POST past the audit route stay 401"
c1="$(code -X PUT -H 'Content-Type: application/json' -d '{"name":"dtfanon","versions":{}}' "${BASE_URL}/npm/${PUB}/dtfanon")"
echo "-- anon PUT /npm/${PUB}/dtfanon -> ${c1}: $(last)"
c2="$(code -X POST -H 'Content-Type: application/json' -d "$BULK_BODY" "${BASE_URL}/npm/${PUB}/-/npm/v1/security/advisories/bulk/extra")"
echo "-- anon POST .../advisories/bulk/extra -> ${c2}: $(last)"
if [ "$c1" = "401" ] && [ "$c2" = "401" ]; then pass; else
  fail "anonymous npm write shape not refused: PUT=${c1} POST(bulk/extra)=${c2} (want 401, 401)"
fi

# =============================================================================
# Real npm client, anonymous: install (control) then `npm audit` (fix)
# =============================================================================
CONS="/tmp/cons-${SUF}"
begin_test "CONTROL: real anonymous npm install of ${PKG} from the PUBLIC repo"
INST_OUT="$(npm_sh <<SH
rm -rf ${CONS} && mkdir -p ${CONS} && cd ${CONS}
printf 'registry=http://backend:8080/npm/${PUB}/\n' > .npmrc
printf '{"name":"dtf-consumer","version":"1.0.0","private":true}' > package.json
npm install '${PKG}@1.0.0' --cache ${CONS}/cache --no-audit --no-fund; echo "rc=\$?"
test -f node_modules/${PKG}/index.js && test -f package-lock.json && echo installed-ok
SH
)"
printf '%s\n' "$INST_OUT" | tail -6 | sed 's/^/   | /'
if printf '%s\n' "$INST_OUT" | grep -q '^rc=0' && printf '%s\n' "$INST_OUT" | grep -q installed-ok; then pass; else
  fail "anonymous npm install from public repo failed"
fi

begin_test "FIX #4317: real anonymous 'npm audit' against the PUBLIC repo exits 0"
AUD_OUT="$(npm_sh <<SH
cd ${CONS} && npm audit --cache ${CONS}/cache --loglevel http; echo "rc=\$?"
SH
)"
printf '%s\n' "$AUD_OUT" | tail -12 | sed 's/^/   | /'
if printf '%s\n' "$AUD_OUT" | grep -q '^rc=0' && printf '%s\n' "$AUD_OUT" | grep -q 'found 0 vulnerabilities'; then pass; else
  fail "anonymous npm audit failed: $(printf '%s\n' "$AUD_OUT" | grep -iE 'error|401|rc=' | head -4 | tr '\n' ' ')"
fi

end_suite
