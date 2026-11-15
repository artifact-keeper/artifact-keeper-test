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
# security_audits_quick) answer differently by backend version:
#   < 1.12.0  a hosted repo gets the built-in empty report ({} for bulk;
#             {actions,advisories,muted,metadata} for quick), and a Remote
#             proxies its upstream, falling back to the same empty report when
#             the upstream is unreachable. That empty report is a false
#             "0 vulnerabilities" (artifact-keeper#5631).
#   >= 1.12.0 (#5778, fixing #5631) a hosted repo answers
#             501 {"error":"npm audit is not available through repository ..."}
#             and a Remote whose upstream is unreachable answers
#             503 {"error":"npm audit could not be performed ..."}.
# The #4317 question is only whether the route REFUSES the caller, so on
# >= 1.12.0 the honest 501/503 is the pass and a 401/403 (or anything else) is
# the fail. The remote here points at an unresolvable `.invalid` host, so it is
# always the 503 arm in DTF.
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

# Backend version decides the expected audit answer (see the header).
AUDIT_HONEST_MIN="1.12.0"
BACKEND_VER="$(get_backend_version)"
audit_honest() { [ "$BACKEND_VER" != "unknown" ] && version_ge "$BACKEND_VER" "$AUDIT_HONEST_MIN"; }

# honest_ok KIND_OF_REPO CODE: the >= 1.12.0 answer for a route that was NOT
# refused. hosted -> 501 + JSON error "not available through repository";
# remote (unreachable upstream) -> 503 + JSON error "could not be performed".
honest_ok() {
  local rkind="$1" c="$2" want_code want_msg
  if [ "$rkind" = "remote" ]; then want_code=503; want_msg="could not be performed"
  else want_code=501; want_msg="not available through repository"; fi
  [ "$c" = "$want_code" ] || return 1
  jq -e --arg m "$want_msg" '(.error | type == "string") and (.error | contains($m))' "$WORK/last" >/dev/null 2>&1
}

# expect_audit_ok LABEL hosted|remote REPO [curl auth args...]: the route is
# not refused for this caller, for both kinds. Below 1.12.0 that is 200 + the
# npm JSON shape; from 1.12.0 it is the honest 501/503 JSON error.
expect_audit_ok() {
  local label="$1" rkind="$2" repo="$3"; shift 3
  local k c bad=""
  for k in bulk quick; do
    c="$(audit_post "$k" "$repo" "$@")"
    echo "-- ${label} POST ${k} /npm/${repo} -> ${c}: $(last)"
    if audit_honest; then
      honest_ok "$rkind" "$c" || bad="${bad} ${k}=${c}"
    elif [ "$c" != "200" ]; then bad="${bad} ${k}=${c}"
    elif ! shape_ok "$k"; then bad="${bad} ${k}=200-but-not-npm-json"; fi
  done
  if [ -z "$bad" ]; then pass
  elif audit_honest; then
    local want="501 'not available through repository'"
    [ "$rkind" = "remote" ] && want="503 'could not be performed'"
    fail "${label} audit refused or wrong answer:${bad} (backend ${BACKEND_VER} >= ${AUDIT_HONEST_MIN}: want ${want} JSON error, never 401/403)"
  else fail "${label} audit refused or malformed:${bad}"; fi
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
echo "-- backend version ${BACKEND_VER}: $(audit_honest && echo "honest audit contract (>= ${AUDIT_HONEST_MIN}, #5631)" || echo "empty-report audit contract (< ${AUDIT_HONEST_MIN})")"
[ "$BACKEND_VER" != "unknown" ] || SETUP_ERR="backend version unknown from ${BASE_URL}/health;"
docker exec "$NPM_CTR" npm --version >/dev/null 2>&1 || SETUP_ERR="${SETUP_ERR} npm missing in ${NPM_CTR};"
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
# Expected answer per backend: < 1.12.0 200 npm JSON; >= 1.12.0 501 (hosted)
# or 503 (remote, no egress) JSON error. Either way: never 401/403.
begin_test "FIX #4317: anonymous bulk + quick audit on the PUBLIC hosted repo is not refused (200 npm JSON; 501 honest error from 1.12.0)"
expect_audit_ok "anon" hosted "$PUB"

begin_test "FIX #4317: anonymous bulk + quick audit on the PUBLIC remote repo is not refused (200 npm JSON; 503 upstream-unavailable from 1.12.0)"
expect_audit_ok "anon" remote "$REM"

begin_test "FIX #4317: non-admin user without write, PUBLIC hosted repo is not refused (was 403: audit classed as a write)"
expect_audit_ok "user(no-grants)" hosted "$PUB" -u "${RO_USER}:${RO_PASS}"

begin_test "FIX #4317: non-admin user with a READ grant on the PRIVATE repo is not refused (was 403)"
expect_audit_ok "user(read)" hosted "$PRIV" -u "${RO_USER}:${RO_PASS}"

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

begin_test "CONTROL: admin bulk + quick audit on the PUBLIC hosted repo is not refused (200; 501 from 1.12.0)"
expect_audit_ok "admin" hosted "$PUB" -u "$AUTH"

begin_test "CONTROL: admin bulk + quick audit on the PRIVATE repo is not refused (200; 501 from 1.12.0)"
expect_audit_ok "admin" hosted "$PRIV" -u "$AUTH"

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

AUD_OUT="$(npm_sh <<SH
cd ${CONS} && npm audit --cache ${CONS}/cache --loglevel http; echo "rc=\$?"
SH
)"
aud_grep() { printf '%s\n' "$AUD_OUT" | grep -q "$@"; }
if audit_honest; then
  # #5631: a hosted repo holds no advisory data, so `npm audit` must fail and
  # say so; a clean "found 0 vulnerabilities" is the false-negative the fix
  # removed. #4317: the failure must not be an auth refusal.
  begin_test "FIX #5631: real anonymous 'npm audit' against the PUBLIC hosted repo exits non-zero with 'not available through repository', never 'found 0 vulnerabilities'"
  printf '%s\n' "$AUD_OUT" | tail -12 | sed 's/^/   | /'
  bad=""
  aud_grep '^rc=0$' && bad="${bad} exited 0;"
  aud_grep '^rc=' || bad="${bad} no exit code captured;"
  aud_grep 'found 0 vulnerabilities' && bad="${bad} printed 'found 0 vulnerabilities' (false clean report);"
  aud_grep 'not available through repository' || bad="${bad} no 'not available through repository' message;"
  aud_grep -iE 'Unable to authenticate|E401|E403| 401 | 403 ' && bad="${bad} auth refusal (#4317);"
  if [ -z "$bad" ]; then pass; else
    fail "npm audit on a hosted repo did not fail honestly:${bad} $(printf '%s\n' "$AUD_OUT" | grep -iE 'error|rc=' | head -4 | tr '\n' ' ')"
  fi
else
  begin_test "FIX #4317: real anonymous 'npm audit' against the PUBLIC repo exits 0"
  printf '%s\n' "$AUD_OUT" | tail -12 | sed 's/^/   | /'
  if aud_grep '^rc=0' && aud_grep 'found 0 vulnerabilities'; then pass; else
    fail "anonymous npm audit failed: $(printf '%s\n' "$AUD_OUT" | grep -iE 'error|401|rc=' | head -4 | tr '\n' ' ')"
  fi
fi

end_suite
