#!/usr/bin/env bash
# jq programs are single-quoted on purpose; their $vars are jq variables.
# shellcheck disable=SC2016
# =============================================================================
# tiers/index-metadata-cred-scoping/oracle.sh
#   A Remote's upstream credentials go only to its configured upstream's origin,
#   not to a host named by index metadata (GHSA-24rf-2gv2-j47c, fixed in
#   1.11.0 by artifact-keeper #4588)
# =============================================================================
# run.sh has stood up storage.filesystem + upstreams.mock-index-foreign with
# RATE_LIMIT_ENABLED=false and UPSTREAM_ALLOW_PRIVATE_IPS=true, and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# BACKEND_IMAGE, RELEASE_GATE=1, JUNIT_OUTPUT_DIR.
#
# mock-idx is the configured upstream of every Remote here. Its PyPI simple
# page and Helm index.yaml name files by ABSOLUTE URL, either on mock-idx
# itself or on mock-foreign (another host, same port: another origin). Both
# mocks record the Authorization header of every request they receive.
#
# FIX (red on ak-backend:1.10.0, green on 1.11.0 and later): a file named on
# mock-foreign is still fetched and served, but mock-foreign receives NO
# Authorization header, and the backend logs the sampled `security` WARN.
# CONTROL (green on both): files on mock-idx and the index documents keep the
# credentials; a cross-origin HTTP redirect was already stripped by the HTTP
# client (the advisory says so) and still is.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every check here records its own pass/fail and
# must not abort the run on a non-matching grep.
set +e

SUF="${RUN_ID##*-}$$"
IDX_CTR="ak-dtf${DTF_SLOT}-mock-idx"
FOREIGN_CTR="ak-dtf${DTF_SLOT}-mock-foreign"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"

UP_USER="idxuser${DTF_SLOT}"; UP_PASS="IdxPw${SUF}x"; UP_TOKEN="idxtoken${SUF}x"
R_PY="imcs-pypi-${DTF_SLOT}-${SUF}"      # PyPI, Basic credentials, private
R_HELM="imcs-helm-${DTF_SLOT}-${SUF}"    # Helm, Basic credentials, private
R_PUB="imcs-pub-${DTF_SLOT}-${SUF}"      # PyPI, Bearer token, PUBLIC (anonymous trigger)
R_GEN="imcs-gen-${DTF_SLOT}-${SUF}"      # generic, Basic credentials (redirect control)
OFF_PKG="offpkg${SUF}"; SAME_PKG="samepkg${SUF}"; OFF_PUB="offpub${SUF}"

# --- helpers (always return 0) ----------------------------------------------
jqr() { jq -r "$@" 2>/dev/null || true; }
basic() { printf 'Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
mock_auths() { # CTR PATH -> the Authorization values that host received for PATH, one per line
  docker exec "$1" python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1/__requests',timeout=5).read().decode())" 2>/dev/null \
    | jqr --arg p "$2" '.requests[] | select(.path == $p) | .auth'
}
get() { # PATH [token] -> "<code>|<body>"  (no token = anonymous)
  local b
  if [ -n "${2:-}" ]; then
    b="$(curl -s --max-time 30 -w '\n%{http_code}' -H "Authorization: Bearer $2" "${BASE_URL}$1" 2>/dev/null || printf '\n000')"
  else
    b="$(curl -s --max-time 30 -w '\n%{http_code}' "${BASE_URL}$1" 2>/dev/null || printf '\n000')"
  fi
  printf '%s|%s' "$(printf '%s\n' "$b" | tail -1)" "$(printf '%s\n' "$b" | sed '$d')"
}
mkremote() { # KEY FORMAT EXTRA-JSON -> http code
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST "${BASE_URL}/api/v1/repositories" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" --argjson x "$3" \
      '{key:$k,name:$k,format:$f,repo_type:"remote",is_public:false,upstream_url:"http://mock-idx/"} + $x')" 2>/dev/null || echo 000
}
# off_origin_case LABEL ROUTE FOREIGN-PATH EXPECT-BODY CRED [token]
# The file must be served from mock-foreign, and mock-foreign must not have
# received the credential CRED (nor any Authorization at all).
off_origin_case() {
  local r auths
  r="$(get "$2" "${6:-}")"
  auths="$(mock_auths "$FOREIGN_CTR" "$3")"
  echo "  GET $2 -> HTTP ${r%%|*} '${r#*|}'"
  echo "  mock-foreign ${3} Authorization: $(printf '%s' "$auths" | tr '\n' ' ')"
  if [ "${r%%|*}" != "200" ] || [ "${r#*|}" != "$4" ]; then
    fail "$1: expected 200 with mock-foreign's body '$4' (the off-origin file must still be fetched)"
  elif [ -z "$auths" ]; then
    fail "$1: mock-foreign recorded no request for $3"
  elif printf '%s\n' "$auths" | grep -qxF "$5"; then
    fail "$1: the Remote's upstream credential was sent to mock-foreign ($5)"
  elif printf '%s\n' "$auths" | grep -qvx 'NONE'; then
    fail "$1: mock-foreign received an Authorization header: $(printf '%s' "$auths" | tr '\n' ' ')"
  else
    pass
  fi
}
# same_origin_case LABEL ROUTE IDX-PATH EXPECT-BODY CRED [token]
same_origin_case() {
  local r auths
  r="$(get "$2" "${6:-}")"
  auths="$(mock_auths "$IDX_CTR" "$3")"
  echo "  GET $2 -> HTTP ${r%%|*} '${r#*|}'"
  echo "  mock-idx ${3} Authorization: $(printf '%s' "$auths" | tr '\n' ' ')"
  if [ "${r%%|*}" = "200" ] && [ "${r#*|}" = "$4" ] && printf '%s\n' "$auths" | grep -qxF "$5"; then
    pass
  else
    fail "$1: expected 200 with mock-idx's body and the credential '$5' at mock-idx"
  fi
}

begin_suite "index-metadata-cred-scoping"
auth_admin

BASIC_CRED="$(basic "$UP_USER" "$UP_PASS")"
BEARER_CRED="Bearer ${UP_TOKEN}"
BASIC_X="$(jq -nc --arg u "$UP_USER" --arg p "$UP_PASS" '{upstream_auth_type:"basic",upstream_username:$u,upstream_password:$p}')"
# The public Remote sends allow_public_with_upstream_credentials so it can be
# created on 1.11.1+ (#4662); older images ignore the unknown field.
BEARER_X="$(jq -nc --arg t "$UP_TOKEN" '{upstream_auth_type:"bearer",upstream_password:$t,is_public:true,allow_public_with_upstream_credentials:true}')"

begin_test "setup: credentialed Remotes on mock-idx (PyPI Basic, Helm Basic, public PyPI Bearer, generic Basic)"
C1="$(mkremote "$R_PY" pypi "$BASIC_X")"; C2="$(mkremote "$R_HELM" helm "$BASIC_X")"
C3="$(mkremote "$R_PUB" pypi "$BEARER_X")"; C4="$(mkremote "$R_GEN" generic "$BASIC_X")"
echo "  create: pypi=${C1} helm=${C2} public-pypi=${C3} generic=${C4}"
if [ "${C1:0:1}${C2:0:1}${C3:0:1}${C4:0:1}" = "2222" ]; then
  pass
else
  infra_fail "could not create the Remotes (pypi=${C1} helm=${C2} public-pypi=${C3} generic=${C4})"
  end_suite
fi

# =============================================================================
# PyPI simple-index href
# =============================================================================
begin_test "FIX GHSA-24rf: a PyPI file whose simple-index href names mock-foreign is fetched from there WITHOUT the Basic credentials"
off_origin_case "PyPI off-origin href" "/pypi/${R_PY}/simple/${OFF_PKG}/${OFF_PKG}-1.0.tar.gz" \
  "/files/${OFF_PKG}-1.0.tar.gz" "foreign served /files/${OFF_PKG}-1.0.tar.gz" "$BASIC_CRED" "$ADMIN_TOKEN"

begin_test "CONTROL: the PyPI simple page is fetched from mock-idx with the Basic credentials"
A="$(mock_auths "$IDX_CTR" "/simple/${OFF_PKG}/")"
echo "  mock-idx /simple/${OFF_PKG}/ Authorization: $(printf '%s' "$A" | tr '\n' ' ')"
if printf '%s\n' "$A" | grep -qxF "$BASIC_CRED"; then pass; else fail "the configured upstream did not receive the credentials for the index"; fi

begin_test "CONTROL: a PyPI file whose href names mock-idx itself (absolute URL, same origin) keeps the Basic credentials"
same_origin_case "PyPI same-origin href" "/pypi/${R_PY}/simple/${SAME_PKG}/${SAME_PKG}-1.0.tar.gz" \
  "/files/${SAME_PKG}-1.0.tar.gz" "index served /files/${SAME_PKG}-1.0.tar.gz" "$BASIC_CRED" "$ADMIN_TOKEN"

# =============================================================================
# Helm index.yaml urls
# =============================================================================
begin_test "FIX GHSA-24rf: a Helm chart whose index.yaml url names mock-foreign is fetched from there WITHOUT the Basic credentials"
off_origin_case "Helm off-origin url" "/helm/${R_HELM}/charts/offchart-1.0.0.tgz" \
  "/charts/offchart-1.0.0.tgz" "foreign served /charts/offchart-1.0.0.tgz" "$BASIC_CRED" "$ADMIN_TOKEN"

begin_test "CONTROL: a Helm chart whose index.yaml url names mock-idx keeps the Basic credentials"
same_origin_case "Helm same-origin url" "/helm/${R_HELM}/charts/samechart-1.0.0.tgz" \
  "/charts/samechart-1.0.0.tgz" "index served /charts/samechart-1.0.0.tgz" "$BASIC_CRED" "$ADMIN_TOKEN"

begin_test "CONTROL: the Helm index.yaml is fetched from mock-idx with the Basic credentials"
A="$(mock_auths "$IDX_CTR" "/index.yaml")"
echo "  mock-idx /index.yaml Authorization: $(printf '%s' "$A" | tr '\n' ' ')"
if printf '%s\n' "$A" | grep -qxF "$BASIC_CRED"; then pass; else fail "mock-idx did not receive the credentials for index.yaml"; fi

# =============================================================================
# Bearer token, public Remote, ANONYMOUS client (the advisory's exploit shape)
# =============================================================================
begin_test "FIX GHSA-24rf: an ANONYMOUS download through a public Bearer-token Remote does not hand the token to mock-foreign"
off_origin_case "public Bearer off-origin href" "/pypi/${R_PUB}/simple/${OFF_PUB}/${OFF_PUB}-1.0.tar.gz" \
  "/files/${OFF_PUB}-1.0.tar.gz" "foreign served /files/${OFF_PUB}-1.0.tar.gz" "$BEARER_CRED" ""

begin_test "CONTROL: that anonymous request still sent the Bearer token to mock-idx for the simple page"
A="$(mock_auths "$IDX_CTR" "/simple/${OFF_PUB}/")"
echo "  mock-idx /simple/${OFF_PUB}/ Authorization: $(printf '%s' "$A" | tr '\n' ' ')"
if printf '%s\n' "$A" | grep -qxF "$BEARER_CRED"; then pass; else fail "the configured upstream did not receive the Bearer token for the index"; fi

# =============================================================================
# Cross-origin redirect (already safe before the fix; must stay safe)
# =============================================================================
begin_test "CONTROL: a 302 from mock-idx to mock-foreign is followed, and the HTTP client strips Authorization on the cross-origin hop"
R="$(get "/api/v1/repositories/${R_GEN}/download/redir/rd${SUF}.bin" "$ADMIN_TOKEN")"
A_IDX="$(mock_auths "$IDX_CTR" "/redir/rd${SUF}.bin")"; A_FOR="$(mock_auths "$FOREIGN_CTR" "/files/rd${SUF}.bin")"
echo "  GET -> HTTP ${R%%|*} '${R#*|}'; mock-idx /redir: $(printf '%s' "$A_IDX" | tr '\n' ' '); mock-foreign /files: $(printf '%s' "$A_FOR" | tr '\n' ' ')"
if [ "${R%%|*}" = "200" ] && [ "${R#*|}" = "foreign served /files/rd${SUF}.bin" ] \
   && printf '%s\n' "$A_IDX" | grep -qxF "$BASIC_CRED" \
   && [ -n "$A_FOR" ] && ! printf '%s\n' "$A_FOR" | grep -qvx 'NONE'; then
  pass
else
  fail "expected the redirect followed to mock-foreign with no Authorization there, and the credentials on the first hop"
fi

# =============================================================================
# The sampled security WARN
# =============================================================================
begin_test "FIX GHSA-24rf: the backend logs the sampled 'security' WARN naming the off-origin URL"
WARN="$(docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep 'GHSA-24rf-2gv2-j47c' | grep -F "WITHOUT the remote's upstream credentials" | head -1)"
echo "  ${WARN:-<no WARN line>}" | cut -c1-400
if printf '%s' "$WARN" | grep -qF "url=http://mock-foreign/"; then
  pass
else
  fail "expected a security WARN 'fetching it WITHOUT the remote's upstream credentials (GHSA-24rf-2gv2-j47c) url=http://mock-foreign/...'"
fi

begin_test "CONTROL: no upstream secret appears in the backend log"
N="$(docker logs "$BACKEND_CTR" 2>&1 | grep -cE "${UP_PASS}|${UP_TOKEN}")"
if [ "$N" = "0" ]; then pass; else fail "${N} backend log line(s) carry the upstream password or token"; fi

end_suite
