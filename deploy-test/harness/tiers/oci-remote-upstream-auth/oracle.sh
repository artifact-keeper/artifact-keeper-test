#!/usr/bin/env bash
# =============================================================================
# tiers/oci-remote-upstream-auth/oracle.sh
#   an OCI Remote reports a refusal of its upstream credentials as 502 DENIED
#   (artifact-keeper#4453 token service, #4518 registry / Basic), keeps 404
#   MANIFEST_UNKNOWN when no credentials were sent (#4527), and forwards its
#   credentials to a cross-origin realm only when it is listed in
#   oci_trusted_bearer_realms, whose entries are validated (#3591).
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-registry` with
# UPSTREAM_ALLOW_PRIVATE_IPS=true and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. The mock registry is `mockreg` to the backend
# and http://127.0.0.1:${TRIVY_PORT} to this oracle (control endpoints only).
# See the manifest for the bugs and fixtures/mock_registry.py for the modes.
#
# Gates:
#   (CONTROL) a credentialed Remote pulls from the mock (same-origin token
#             service, and plain Basic); a Remote WITHOUT credentials answers
#             404 MANIFEST_UNKNOWN for every refusal mode with no security
#             warning; a credentialed Remote whose realm is cross-origin and
#             NOT trusted sends an anonymous token request (credentials
#             withheld, GHSA-78h6) and answers 404 MANIFEST_UNKNOWN; the
#             credentials never appear in the backend log.
#   (FIX)     502 DENIED for a credentialed refusal (token service, registry
#             after a token, Basic), on GET and HEAD, with ONE sampled
#             security warning across five pulls; oci_trusted_bearer_realms
#             is validated, echoed, and makes the cross-origin token request
#             carry the credentials so a private image pulls.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe below is judged explicitly by the
# assertion that reads it, so a failing probe must not end the oracle early.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
MOCK_CTL="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://mockreg:5000"
GOOD_USER="gooduser"; GOOD_PASS="goodpass"
BAD_PASS="wrong-${SUF}"
TRUSTED_REALM="https://mockreg:5443"

ACCEPT='application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
WORK="$(mktemp -d -t dtf-ociauth-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" --path-as-is "$@" "$url" 2>/dev/null || echo 000
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
jqr() { jq -r "$1" 2>/dev/null || true; }
oci_code() { jqr '.errors[0].code // empty' < "$1"; }
blog() { docker logs "$BACKEND_CTR" 2>&1 || true; }
count_log() { # FIXED-STRING... -> lines containing every string
  local out; out="$(blog)"
  local s
  for s in "$@"; do out="$(printf '%s\n' "$out" | grep -F -- "$s" || true)"; done
  printf '%s' "$out" | grep -c . || true
}
mock_log() { curl -s --max-time 10 "${MOCK_CTL}/__log" 2>/dev/null || echo '[]'; }

AUTHZ=()
pull() { # REMOTE IMAGE OUTFILE -> http code (GET manifest v1)
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/v1" "$3" "${AUTHZ[@]}" -H "Accept: ${ACCEPT}"
}
pull_head() { # REMOTE IMAGE -> http code (HEAD manifest v1)
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/v1" /dev/null -I "${AUTHZ[@]}" -H "Accept: ${ACCEPT}"
}
# mk_remote KEY USER PASS EXTRA_JSON -> http code (body in $WORK/mk-KEY.json).
# Empty USER = no credentials. Private, so a credentialed Remote needs no
# public-credentials opt-in.
mk_remote() {
  local creds=""
  [ -n "$2" ] && creds=",\"upstream_auth_type\":\"basic\",\"upstream_username\":\"${2}\",\"upstream_password\":\"${3}\""
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-${1}.json" -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"docker\",\"repo_type\":\"remote\",\"upstream_url\":\"${UPSTREAM}\",\"is_public\":false${creds}${4}}"
}

begin_suite "oci-remote-upstream-auth"

# ===========================================================================
# SETUP
# ===========================================================================
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
if [ "$(curl -s --max-time 5 "${MOCK_CTL}/__readyz" 2>/dev/null)" != "ok" ]; then
  begin_test "setup: reach the mock registry's control endpoint"
  infra_fail "mock registry not answering on ${MOCK_CTL}"
  end_suite
fi

# One Remote per scenario: the security warning is sampled per Remote, so a
# shared Remote would let one scenario's warning suppress another's.
R_GOOD="ra-good-${SLOT}-${SUF}"      # good creds, same-origin token service
R_BASIC_OK="ra-bok-${SLOT}-${SUF}"   # good creds, Basic registry
R_TOK="ra-tok-${SLOT}-${SUF}"        # creds, token service refuses (#4453)
R_MAN="ra-man-${SLOT}-${SUF}"        # good creds, registry refuses the token (#4518)
R_BASIC="ra-bas-${SLOT}-${SUF}"      # wrong creds, Basic registry (#4518)
R_ANON="ra-anon-${SLOT}-${SUF}"      # no creds at all (control)
R_XO="ra-xo-${SLOT}-${SUF}"          # good creds, untrusted cross-origin realm (#4527)
R_TRUST="ra-tr-${SLOT}-${SUF}"       # good creds, realm listed as trusted (#3591)
R_NOTRUST="ra-nt-${SLOT}-${SUF}"     # good creds, same TLS realm NOT listed (#3591 control)
# Image names carry the run suffix so log lines can be attributed to this run.
I_GOOD="good/app-${SUF}"; I_TOK="tokrefuse/app-${SUF}"; I_MAN="manrefuse/app-${SUF}"
I_BASIC="basic/app-${SUF}"; I_XO="xorigin/app-${SUF}"; I_TR="trusted/app-${SUF}"

SF=""
for spec in "$R_GOOD:$GOOD_USER:$GOOD_PASS" "$R_BASIC_OK:$GOOD_USER:$GOOD_PASS" "$R_TOK:$GOOD_USER:$BAD_PASS" \
            "$R_MAN:$GOOD_USER:$GOOD_PASS" "$R_BASIC:$GOOD_USER:$BAD_PASS" "$R_ANON::" \
            "$R_XO:$GOOD_USER:$GOOD_PASS" "$R_NOTRUST:$GOOD_USER:$GOOD_PASS"; do
  IFS=: read -r k u p <<<"$spec"
  c="$(mk_remote "$k" "$u" "$p" "")"; is_2xx "$c" || SF="${SF} ${k}=${c}:$(head -c 200 "${WORK}/mk-${k}.json")"
done
if [ -n "$SF" ]; then
  begin_test "setup: create the docker Remote repositories"
  infra_fail "Remote create failed:${SF}"
  end_suite
fi

# ===========================================================================
# CONTROLS
# ===========================================================================
begin_test "CONTROL: a Remote with good credentials pulls through the same-origin token service and through a Basic registry"
G="$(pull "$R_GOOD" "$I_GOOD" "${WORK}/g.json")"
GB="$(pull "$R_BASIC_OK" "$I_BASIC" "${WORK}/gb.json")"
GSCHEMA="$(jqr '.schemaVersion' < "${WORK}/g.json")"
if [ "$G" = "200" ] && [ "$GB" = "200" ] && [ "$GSCHEMA" = "2" ]; then pass; else
  fail "the mock registry path itself is broken: bearer pull=${G} basic pull=${GB} schemaVersion=${GSCHEMA} (want 200, 200, 2); every other gate depends on it" \
    "bearer body=$(head -c 200 "${WORK}/g.json") basic body=$(head -c 200 "${WORK}/gb.json")"
fi

begin_test "CONTROL: a Remote WITHOUT credentials answers 404 MANIFEST_UNKNOWN for every refusal mode, with no security warning"
F=""
for img in "$I_TOK" "$I_MAN" "$I_BASIC" "$I_XO"; do
  c="$(pull "$R_ANON" "$img" "${WORK}/an.json")"; oc="$(oci_code "${WORK}/an.json")"
  { [ "$c" = "404" ] && [ "$oc" = "MANIFEST_UNKNOWN" ]; } || F="${F} ${img%%/*}=${c}/${oc:-none}"
done
# Runs before any credentialed refusal, so ANY such warning so far is the
# anonymous Remote's.
ANON_WARN="$(count_log "rejected the proxy's authentication")"
if [ -z "$F" ] && [ "${ANON_WARN:-0}" = "0" ]; then pass; else
  fail "an anonymous refusal was not reported as a miss:${F:- (codes ok)}; 'rejected the proxy's authentication' warnings so far=${ANON_WARN} (want 0)"
fi

begin_test "CONTROL (#4527 / GHSA-78h6): a credentialed Remote with an UNTRUSTED cross-origin realm sends an anonymous token request and answers 404 MANIFEST_UNKNOWN"
X="$(pull "$R_XO" "$I_XO" "${WORK}/xo.json")"; XC="$(oci_code "${WORK}/xo.json")"
XH="$(pull_head "$R_XO" "$I_XO")"
XO_TOK="$(mock_log | jq -c --arg s "repository:${I_XO}:pull" '[.[] | select(.kind=="token" and .scope==$s)]' 2>/dev/null)"
XO_N="$(echo "$XO_TOK" | jq 'length' 2>/dev/null)"; XO_AUTH="$(echo "$XO_TOK" | jq '[.[] | select(.auth)] | length' 2>/dev/null)"
XO_PORT="$(echo "$XO_TOK" | jq -r '[.[].port] | unique | join(",")' 2>/dev/null)"
if [ "$X" = "404" ] && [ "$XC" = "MANIFEST_UNKNOWN" ] && [ "$XH" = "404" ] && [ "${XO_N:-0}" -ge 1 ] 2>/dev/null && \
   [ "$XO_AUTH" = "0" ] && [ "$XO_PORT" = "5001" ]; then pass; else
  fail "untrusted cross-origin realm: GET=${X}/${XC:-none} HEAD=${XH} (want 404 MANIFEST_UNKNOWN, 404); token requests at the cross-origin realm=${XO_N} on port(s) ${XO_PORT}, carrying credentials=${XO_AUTH} (want >=1 on 5001, 0 with credentials)" \
    "body=$(head -c 200 "${WORK}/xo.json")"
fi

# ===========================================================================
# #4453 / #4518: a credentialed refusal is 502 DENIED, sampled warning
# ===========================================================================
begin_test "#4453: the upstream TOKEN SERVICE refuses the Remote's credentials -> GET 502 DENIED (not 404 MANIFEST_UNKNOWN), with a security warning"
T="$(pull "$R_TOK" "$I_TOK" "${WORK}/t.json")"; TC="$(oci_code "${WORK}/t.json")"
TOK_AUTH="$(mock_log | jq --arg s "repository:${I_TOK}:pull" '[.[] | select(.kind=="token" and .scope==$s and .auth)] | length' 2>/dev/null)"
TW="$(count_log "upstream OCI token service rejected the proxy's authentication" "mockreg:5000")"
if [ "$T" = "502" ] && [ "$TC" = "DENIED" ] && [ "${TOK_AUTH:-0}" -ge 1 ] 2>/dev/null && [ "${TW:-0}" -ge 1 ] 2>/dev/null; then pass; else
  fail "token-service refusal of SENT credentials: GET=${T}/${TC:-none} (want 502 DENIED), credentialed token requests seen by the mock=${TOK_AUTH} (want >=1), security warnings=${TW} (want >=1). Pre-#4453 this was logged as a storage error and answered 404 MANIFEST_UNKNOWN" \
    "body=$(head -c 200 "${WORK}/t.json")"
fi

begin_test "#4518: the REGISTRY refuses the token minted for the Remote's credentials -> GET and HEAD 502 DENIED; five pulls log ONE sampled security warning"
M="$(pull "$R_MAN" "$I_MAN" "${WORK}/m.json")"; MC="$(oci_code "${WORK}/m.json")"
MH="$(pull_head "$R_MAN" "$I_MAN")"
for _ in 1 2 3; do pull "$R_MAN" "$I_MAN" /dev/null >/dev/null; done
MW="$(count_log "upstream OCI registry rejected the proxy's authentication on a manifest request" "$I_MAN")"
MAN_AUTH="$(mock_log | jq --arg s "repository:${I_MAN}:pull" '[.[] | select(.kind=="token" and .scope==$s and .auth)] | length' 2>/dev/null)"
if [ "$M" = "502" ] && [ "$MC" = "DENIED" ] && [ "$MH" = "502" ] && [ "$MW" = "1" ] && [ "${MAN_AUTH:-0}" -ge 1 ] 2>/dev/null; then pass; else
  fail "registry refusal after a credentialed token exchange: GET=${M}/${MC:-none} HEAD=${MH} (want 502 DENIED, 502); security warnings naming ${I_MAN} across 5 pulls=${MW} (want exactly 1: sampled once a minute per Remote); credentialed token requests=${MAN_AUTH}. Pre-#4518 this answered 404 MANIFEST_UNKNOWN" \
    "body=$(head -c 200 "${WORK}/m.json")"
fi

begin_test "#4518: a plain-Basic registry rejects the Remote's credentials -> GET 502 DENIED"
B="$(pull "$R_BASIC" "$I_BASIC" "${WORK}/b.json")"; BC="$(oci_code "${WORK}/b.json")"
BW="$(count_log "upstream OCI registry rejected the proxy's authentication on a manifest request" "$I_BASIC")"
if [ "$B" = "502" ] && [ "$BC" = "DENIED" ] && [ "${BW:-0}" -ge 1 ] 2>/dev/null; then pass; else
  fail "Basic refusal of sent credentials: GET=${B}/${BC:-none} (want 502 DENIED), security warnings naming ${I_BASIC}=${BW} (want >=1)" \
    "body=$(head -c 200 "${WORK}/b.json")"
fi

begin_test "CONTROL: no upstream credential (the good password or the wrong one) appears anywhere in the backend log"
LEAK="$(blog | grep -cF -e "$GOOD_PASS" -e "$BAD_PASS" || true)"
if [ "${LEAK:-0}" = "0" ]; then pass; else
  fail "${LEAK} backend log line(s) contain an upstream password"
fi

# ===========================================================================
# #3591: oci_trusted_bearer_realms
# ===========================================================================
begin_test "#3591: oci_trusted_bearer_realms rejects http://, a path, a wildcard and a non-Remote repository with 400"
F=""
for bad in "http://mockreg:5443" "${TRUSTED_REALM}/token" "https://*.mockreg"; do
  k="ra-bad-${SLOT}-$(echo "$bad" | md5sum | cut -c1-6)-${SUF}"
  c="$(mk_remote "$k" "$GOOD_USER" "$GOOD_PASS" ",\"oci_trusted_bearer_realms\":[\"${bad}\"]")"
  [ "$c" = "400" ] || F="${F} '${bad}'=${c}"
done
LK="ra-local-${SLOT}-${SUF}"
c="$(code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-local.json" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${LK}\",\"name\":\"${LK}\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":false,\"oci_trusted_bearer_realms\":[\"${TRUSTED_REALM}\"]}")"
[ "$c" = "400" ] || F="${F} local-repo=${c}"
if [ -z "$F" ]; then pass; else
  fail "invalid trusted realms were accepted:${F} (want 400 each)"
fi

begin_test "#3591: a Remote created with oci_trusted_bearer_realms echoes the canonical origin on GET /repositories/{key}"
c="$(mk_remote "$R_TRUST" "$GOOD_USER" "$GOOD_PASS" ",\"oci_trusted_bearer_realms\":[\"${TRUSTED_REALM}\"]")"
ECHO="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${AUTHZ[@]}" "${BASE_URL}/api/v1/repositories/${R_TRUST}" | jq -c '.oci_trusted_bearer_realms // null' 2>/dev/null)"
if is_2xx "$c" && [ "$ECHO" = "[\"${TRUSTED_REALM}\"]" ]; then pass; else
  fail "create=${c} echoed oci_trusted_bearer_realms=${ECHO:-<absent>} (want 2xx and [\"${TRUSTED_REALM}\"])" \
    "create body=$(head -c 200 "${WORK}/mk-${R_TRUST}.json")"
fi

begin_test "#3591: with the TLS cross-origin realm trusted, the token request carries the Remote's credentials and the private image pulls"
TR="$(pull "$R_TRUST" "$I_TR" "${WORK}/tr.json")"
TR_TOK="$(mock_log | jq -c --arg s "repository:${I_TR}:pull" '[.[] | select(.kind=="token" and .scope==$s and .port==5443)]' 2>/dev/null)"
TR_USER="$(echo "$TR_TOK" | jq -r '[.[] | select(.auth) | .user] | unique | join(",")' 2>/dev/null)"
TRW="$(count_log "listed in the repository's oci_trusted_bearer_realms")"
if [ "$TR" = "200" ] && [ "$(jqr '.schemaVersion' < "${WORK}/tr.json")" = "2" ] && [ "$TR_USER" = "$GOOD_USER" ] && [ "${TRW:-0}" -ge 1 ] 2>/dev/null; then pass; else
  fail "trusted realm: pull=${TR} (want 200), users presented at https realm=${TR_USER:-<none>} (want ${GOOD_USER}), INFO 'listed in oci_trusted_bearer_realms' lines=${TRW} (want >=1)" \
    "token requests=${TR_TOK} body=$(head -c 200 "${WORK}/tr.json")"
fi

begin_test "CONTROL (#3591 default): the same image through a credentialed Remote that does NOT list the TLS realm sends no credentials there and answers 404 MANIFEST_UNKNOWN"
cred5443() { mock_log | jq --arg s "repository:${I_TR}:pull" '[.[] | select(.kind=="token" and .scope==$s and .port==5443 and .auth)] | length' 2>/dev/null; }
C0="$(cred5443)"
NT="$(pull "$R_NOTRUST" "$I_TR" "${WORK}/nt.json")"; NTC="$(oci_code "${WORK}/nt.json")"
C1="$(cred5443)"
if [ "$NT" = "404" ] && [ "$NTC" = "MANIFEST_UNKNOWN" ] && [ -n "$C0" ] && [ "$C0" = "$C1" ]; then pass; else
  fail "unlisted TLS realm: pull=${NT}/${NTC:-none} (want 404 MANIFEST_UNKNOWN); credentialed token requests at :5443 before=${C0} after=${C1} (want unchanged: nothing is trusted by default)" \
    "body=$(head -c 200 "${WORK}/nt.json")"
fi

end_suite
