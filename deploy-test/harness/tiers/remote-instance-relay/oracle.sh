#!/usr/bin/env bash
# =============================================================================
# tiers/remote-instance-relay/oracle.sh
#   #4776 the remote-instance relay (/api/v1/instances/{id}/proxy/{*path})
#         forwards the query string and the caller's Content-Type, relays an
#         allow-list of response headers, and refuses a relay of a relay
#   #4795 the relay accepts PATCH, with the same path and owner guards
# See the manifest for THE BUG, THE PEER and the gates.
#
# run.sh exported BASE_URL (instance A), DB_CONTAINER (A's postgres),
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (instance B's published
# HTTP port, profiles/peer.second-instance.yml), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
: "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_DB="ak-dtf${SLOT}-peer-db"
B_CTR="ak-dtf${SLOT}-peer-backend"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"

# Three generic repos on B; the query filter must pick exactly one of them.
R1="rly-alpha-${SLOT}-${SUF}"
R2="rly-bravo-${SLOT}-${SUF}"
R3="rly-charlie-${SLOT}-${SUF}"
R_JSON="rly-json-${SLOT}-${SUF}"

W="$(mktemp -d -t dtf-relay-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# HTTP code of a request; body -> $W/last, response headers -> $W/hdr.
code() { curl -s --path-as-is -o "$W/last" -D "$W/hdr" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }
body() { cat "$W/last" 2>/dev/null; }
hdr() { grep -i "^$1:" "$W/hdr" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }

relay() { echo "${A}/api/v1/instances/${INST_ID:-none}/proxy/$1"; }

# Number of requests B's access log recorded whose URI starts with $1.
# (api::middleware::tracing logs `uri=<path?query>` for every request.)
b_seen() { docker logs "$B_CTR" 2>&1 | grep -c "uri=$1" || true; }

repo_keys() { jq -c '[.items[]?.key] | sort' 2>/dev/null || echo '?'; }

begin_suite "remote-instance-relay"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: instance B is up with three repos, B registered on A as a remote instance, B registered on itself"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
for k in "$R1" "$R2" "$R3"; do
  c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
    "${B}/api/v1/repositories")"
  [[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create ${k} on B -> ${c};"
done
B_KEY="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-relay-${SUF}\",\"scopes\":[\"*\"]}" "${B}/api/v1/auth/tokens" 2>/dev/null \
  | jq -r '.token // empty' 2>/dev/null || true)"
[ -n "$B_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint an API key on B;"
INST_ID="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-b-${SUF}\",\"url\":\"http://peer-backend:8080\",\"api_key\":\"${B_KEY}\"}" \
  "${A}/api/v1/instances" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
[ -n "$INST_ID" ] || SETUP_ERR="${SETUP_ERR} registering B on A (POST /api/v1/instances) failed;"
# B registered on B itself: the second hop of a relay-of-relay chain.
LOOP_ID="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-loop-${SUF}\",\"url\":\"http://peer-backend:8080\",\"api_key\":\"${B_KEY}\"}" \
  "${B}/api/v1/instances" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
[ -n "$LOOP_ID" ] || SETUP_ERR="${SETUP_ERR} registering B on B failed;"
[ "$(b_seen /health)" -ge 0 ] 2>/dev/null || SETUP_ERR="${SETUP_ERR} cannot read ${B_CTR} logs;"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: B's health, direct and relayed through A, report the same healthy instance"
c_d="$(code "${B}/health")"; v_d="$(body | jq -r '.status + "/" + .version' 2>/dev/null)"
c_r="$(code -u "$AUTH" "$(relay health)")"; v_r="$(body | jq -r '.status + "/" + .version' 2>/dev/null)"
if [ "$c_d" = "200" ] && [ "$c_r" = "200" ] && [[ "$v_d" == healthy/* ]] && [ "$v_r" = "$v_d" ]; then pass; else
  fail "direct ${c_d} ${v_d}; relayed ${c_r} ${v_r}"
fi

begin_test "CONTROL: a plain relayed GET (no query) returns what B returns directly"
c_d="$(code -u "$AUTH" "${B}/api/v1/repositories/${R2}")"; k_d="$(body | jq -r '.key // empty' 2>/dev/null)"
c_r="$(code -u "$AUTH" "$(relay "api/v1/repositories/${R2}")")"; k_r="$(body | jq -r '.key // empty' 2>/dev/null)"
if [ "$c_d" = "200" ] && [ "$c_r" = "200" ] && [ "$k_d" = "$R2" ] && [ "$k_r" = "$R2" ]; then pass; else
  fail "direct ${c_d} key=${k_d}; relayed ${c_r} key=${k_r} (want ${R2} both)"
fi

begin_test "CONTROL: a relayed JSON POST (Content-Type: application/json) creates a repository on B"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"key\":\"${R_JSON}\",\"name\":\"${R_JSON}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
  "$(relay api/v1/repositories)")"
on_b="$(psql_b "SELECT count(*) FROM repositories WHERE key = '${R_JSON}'")"
if [[ "$c" == 20? ]] && [ "$on_b" = "1" ]; then pass; else
  fail "relayed JSON POST -> ${c} $(body | head -c 200); rows on B for ${R_JSON}: ${on_b}"
fi

begin_test "CONTROL: B accepts a multipart upload sent to it directly"
printf 'direct multipart %s\n' "$SUF" > "$W/direct.txt"
c="$(code -u "$AUTH" -F "file=@${W}/direct.txt" -F "path=direct/${SUF}.txt" "${B}/api/v1/repositories/${R1}/artifacts")"
if [[ "$c" == 20? ]] && [ "$(body | jq -r '.checksum_sha256 // empty' 2>/dev/null)" = "$(sha256sum "$W/direct.txt" | cut -d' ' -f1)" ]; then pass; else
  fail "direct multipart -> ${c} $(body | head -c 200)"
fi

begin_test "CONTROL: a relay path outside api/ and health is refused with 400 (pre-existing path guard)"
c="$(code -u "$AUTH" "$(relay metrics)")"
if [ "$c" = "400" ] && body | grep -q 'must start with api/'; then pass; else
  fail "relayed GET metrics -> ${c} $(body | head -c 200) (want 400 'must start with api/ or health')"
fi

# =============================================================================
# FIX: query string forwarded
# =============================================================================
begin_test "FIX(#4776): a relayed GET with ?q=&per_page= returns B's filtered page, identical to the direct call"
QS="q=${R2}&per_page=1"
c_d="$(code -u "$AUTH" "${B}/api/v1/repositories?${QS}")"
d_keys="$(body | repo_keys)"; d_pg="$(body | jq -c '.pagination | {per_page,total}' 2>/dev/null)"
seen0="$(b_seen "/api/v1/repositories?${QS}")"
c_r="$(code -u "$AUTH" "$(relay "api/v1/repositories?${QS}")")"
r_keys="$(body | repo_keys)"; r_pg="$(body | jq -c '.pagination | {per_page,total}' 2>/dev/null)"
seen1="$(b_seen "/api/v1/repositories?${QS}")"
if [ "$c_d" = "200" ] && [ "$c_r" = "200" ] && [ "$d_keys" = "[\"${R2}\"]" ] && [ "$r_keys" = "$d_keys" ] \
   && [ "$r_pg" = "$d_pg" ] && [ "$seen1" -gt "$seen0" ]; then pass; else
  fail "direct ${c_d} keys=${d_keys} pagination=${d_pg}; relayed ${c_r} keys=${r_keys} pagination=${r_pg}; B log lines with the query: ${seen0} -> ${seen1}. The relay dropped the query string."
fi

# =============================================================================
# FIX: request Content-Type passed through
# =============================================================================
begin_test "FIX(#4776): a relayed multipart POST keeps its multipart/form-data Content-Type and B stores the file"
printf 'relayed multipart %s\n' "$SUF" > "$W/relay.txt"
want="$(sha256sum "$W/relay.txt" | cut -d' ' -f1)"
c="$(code -u "$AUTH" -F "file=@${W}/relay.txt" -F "path=relayed/${SUF}.txt" "$(relay "api/v1/repositories/${R1}/artifacts")")"
row="$(psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
               WHERE r.key = '${R1}' AND a.path = 'relayed/${SUF}.txt' AND a.is_deleted = false")"
if [[ "$c" == 20? ]] && [ "$row" = "$want" ]; then pass; else
  fail "relayed multipart -> ${c} $(body | head -c 200); B row sha=${row:-none} (want ${want}). The relay rewrote the Content-Type to application/json, so B could not parse the body."
fi

# =============================================================================
# FIX: response header allow-list
# =============================================================================
begin_test "FIX(#4776): a relayed download carries B's Content-Disposition and Accept-Ranges"
c_d="$(code -u "$AUTH" "${B}/api/v1/repositories/${R1}/download/direct/${SUF}.txt")"
cd_d="$(hdr content-disposition)"; ar_d="$(hdr accept-ranges)"
c_r="$(code -u "$AUTH" "$(relay "api/v1/repositories/${R1}/download/direct/${SUF}.txt")")"
cd_r="$(hdr content-disposition)"; ar_r="$(hdr accept-ranges)"; sha_r="$(sha256sum "$W/last" | cut -d' ' -f1)"
if [ "$c_d" = "200" ] && [ "$c_r" = "200" ] && [ -n "$cd_d" ] && [ "$cd_r" = "$cd_d" ] && [ "$ar_r" = "$ar_d" ] \
   && [ "$sha_r" = "$(sha256sum "$W/direct.txt" | cut -d' ' -f1)" ]; then pass; else
  fail "direct ${c_d} content-disposition='${cd_d}' accept-ranges='${ar_d}'; relayed ${c_r} content-disposition='${cd_r}' accept-ranges='${ar_r}'"
fi

# =============================================================================
# FIX: relay-of-relay refused before anything reaches B
# =============================================================================
refused() { # code: 400 VALIDATION_ERROR naming api/v1/instances
  [ "$1" = "400" ] && [ "$(body | jq -r '.code // empty' 2>/dev/null)" = "VALIDATION_ERROR" ] && body | grep -q 'api/v1/instances'
}

begin_test "FIX(#4776): relaying to B's instance registry (GET api/v1/instances) is refused 400 and never reaches B"
s0="$(b_seen /api/v1/instances)"
c="$(code -u "$AUTH" "$(relay api/v1/instances)")"
sleep 1; s1="$(b_seen /api/v1/instances)"
if refused "$c" && [ "$s1" = "$s0" ]; then pass; else
  fail "relayed GET api/v1/instances -> ${c} $(body | head -c 200); B's log requests to /api/v1/instances: ${s0} -> ${s1} (want 400 VALIDATION_ERROR and no new request on B)"
fi

begin_test "FIX(#4776): a chained relay (A -> B's relay -> B) is refused 400 and never reaches B"
s0="$(b_seen /api/v1/instances)"
c="$(code -u "$AUTH" "$(relay "api/v1/instances/${LOOP_ID}/proxy/api/v1/repositories/${R3}")")"
chained_key="$(body | jq -r '.key // empty' 2>/dev/null)"
sleep 1; s1="$(b_seen /api/v1/instances)"
if refused "$c" && [ "$s1" = "$s0" ]; then pass; else
  fail "relayed GET api/v1/instances/{B-self}/proxy/api/v1/repositories/${R3} -> ${c} key=${chained_key:-none}; B's log requests to /api/v1/instances: ${s0} -> ${s1}. The relay chained through B's own relay."
fi

begin_test "FIX(#4776): a relayed write to B's instance registry (POST api/v1/instances) is refused 400 and creates nothing on B"
n0="$(psql_b "SELECT count(*) FROM remote_instances")"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-chain-${SUF}\",\"url\":\"http://peer-backend:8080\",\"api_key\":\"x\"}" "$(relay api/v1/instances)")"
n1="$(psql_b "SELECT count(*) FROM remote_instances")"
if refused "$c" && [ "$n1" = "$n0" ]; then pass; else
  fail "relayed POST api/v1/instances -> ${c} $(body | head -c 200); remote_instances rows on B: ${n0} -> ${n1}"
fi

begin_test "FIX(#4776): the refusal also catches a doubled slash and mixed case (api//v1/Instances)"
c="$(code -u "$AUTH" "$(relay "api//v1/Instances/${LOOP_ID}/proxy/health")")"
if refused "$c"; then pass; else
  fail "relayed GET api//v1/Instances/{id}/proxy/health -> ${c} $(body | head -c 200) (want 400 VALIDATION_ERROR naming api/v1/instances)"
fi

# =============================================================================
# PATCH relay (#4795, fixed by #4876, 1.12.0)
# =============================================================================
# PATCH requests a non-admin second user on A makes; created here so the
# owner guard has someone who does not own INST_ID.
U2="rly-u2-${SLOT}-${SUF}"
U2_PASS="Dtf-$(openssl rand -hex 12 2>/dev/null || date +%s%N)-x"
U2_ID="$(create_test_user_with_retry "$U2" "$U2_PASS" "${U2}@t.test" 2>/dev/null)" || true
U2_TOKEN=""
[ -n "$U2_ID" ] && U2_TOKEN="$(login_as "$U2" "$U2_PASS" 2>/dev/null)" || true

# Number of lines in B's log that carry the marker $1 at all (any method).
b_marker() { docker logs "$B_CTR" 2>&1 | grep -c -- "$1" || true; }
# Number of PATCH lines in B's access log whose URI starts with $1.
b_patch_seen() { docker logs "$B_CTR" 2>&1 | grep 'PATCH' | grep -c "uri=$1" || true; }

begin_test "CONTROL: a second user cannot GET through the admin's instance (404, pre-existing owner guard)"
if [ -z "$U2_TOKEN" ]; then
  fail "could not create or log in the second user ${U2} (id=${U2_ID:-none})"
else
  c="$(code -H "Authorization: Bearer ${U2_TOKEN}" "$(relay "api/v1/repositories/${R3}")")"
  if [ "$c" = "404" ]; then pass; else
    fail "second user relayed GET through the admin's instance -> ${c} $(body | head -c 200) (want 404)"
  fi
fi

begin_test "FIX(#4795): a relayed PATCH reaches B, returns B's 200 and updated repository, and B stores the change"
DESC="patched through the relay ${SUF}"
p0="$(b_patch_seen "/api/v1/repositories/${R3}")"
c="$(code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' \
  -d "{\"description\":\"${DESC}\"}" "$(relay "api/v1/repositories/${R3}")")"
r_key="$(body | jq -r '.key // empty' 2>/dev/null)"; r_desc="$(body | jq -r '.description // empty' 2>/dev/null)"
on_b="$(psql_b "SELECT description FROM repositories WHERE key = '${R3}'")"
p1="$(b_patch_seen "/api/v1/repositories/${R3}")"
if [ "$c" = "200" ] && [ "$r_key" = "$R3" ] && [ "$r_desc" = "$DESC" ] && [ "$on_b" = "$DESC" ] && [ "$p1" -gt "$p0" ]; then pass; else
  fail "relayed PATCH api/v1/repositories/${R3} -> ${c} key=${r_key:-none} description='${r_desc}' $(body | head -c 160); B row description='${on_b}'; B PATCH log lines ${p0} -> ${p1} (want 200, the new description on B, one more PATCH on B)"
fi

begin_test "FIX(#4795): a relayed PATCH returns B's own error status and body (404 for a key B does not have)"
MISSING="rly-missing-${SLOT}-${SUF}"
c_d="$(code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' -d '{"description":"x"}' "${B}/api/v1/repositories/${MISSING}")"
b_d="$(body | jq -cS '{code,message}' 2>/dev/null)"
p0="$(b_patch_seen "/api/v1/repositories/${MISSING}")"
c_r="$(code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' -d '{"description":"x"}' "$(relay "api/v1/repositories/${MISSING}")")"
b_r="$(body | jq -cS '{code,message}' 2>/dev/null)"
p1="$(b_patch_seen "/api/v1/repositories/${MISSING}")"
if [ "$c_d" = "404" ] && [ "$c_r" = "404" ] && [ -n "$b_d" ] && [ "$b_r" = "$b_d" ] && [ "$p1" -gt "$p0" ]; then pass; else
  fail "direct PATCH on B -> ${c_d} ${b_d}; relayed -> ${c_r} ${b_r}; B PATCH log lines ${p0} -> ${p1} (want B's 404 body relayed verbatim and the request seen on B)"
fi

begin_test "FIX(#4795): a relayed PATCH to a path outside api/ is refused 400 by A and never reaches B"
MK="dtfpatchpath${SUF//-/}"
m0="$(b_marker "$MK")"
c="$(code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' -d '{"x":1}' "$(relay "admin/settings?probe=${MK}")")"
sleep 1; m1="$(b_marker "$MK")"
if [ "$c" = "400" ] && body | grep -q 'must start with api/' && [ "$m1" = "$m0" ]; then pass; else
  fail "relayed PATCH admin/settings -> ${c} $(body | head -c 200); B log lines with marker ${MK}: ${m0} -> ${m1} (want 400 'must start with api/ or health' and nothing on B)"
fi

begin_test "FIX(#4795): a relayed PATCH to B's instance registry is refused 400 and never reaches B"
MK="dtfpatchinst${SUF//-/}"
m0="$(b_marker "$MK")"
c="$(code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' -d '{"name":"x"}' "$(relay "api/v1/instances/${LOOP_ID}?probe=${MK}")")"
sleep 1; m1="$(b_marker "$MK")"
if refused "$c" && [ "$m1" = "$m0" ]; then pass; else
  fail "relayed PATCH api/v1/instances/{B-self} -> ${c} $(body | head -c 200); B log lines with marker ${MK}: ${m0} -> ${m1} (want 400 VALIDATION_ERROR naming api/v1/instances and nothing on B)"
fi

begin_test "FIX(#4795): a second user's PATCH through the admin's instance is 404 and never reaches B"
if [ -z "$U2_TOKEN" ]; then
  fail "no second-user token (see the owner CONTROL)"
else
  MK="dtfpatchowner${SUF//-/}"
  m0="$(b_marker "$MK")"
  before="$(psql_b "SELECT description FROM repositories WHERE key = '${R3}'")"
  c="$(code -H "Authorization: Bearer ${U2_TOKEN}" -X PATCH -H 'Content-Type: application/json' \
    -d '{"description":"not the owner"}' "$(relay "api/v1/repositories/${R3}?probe=${MK}")")"
  sleep 1; m1="$(b_marker "$MK")"
  after="$(psql_b "SELECT description FROM repositories WHERE key = '${R3}'")"
  if [ "$c" = "404" ] && [ "$m1" = "$m0" ] && [ "$after" = "$before" ]; then pass; else
    fail "second user relayed PATCH -> ${c} $(body | head -c 200); B log lines with marker ${MK}: ${m0} -> ${m1}; R3 description '${before}' -> '${after}' (want 404, nothing on B, no change)"
  fi
fi

end_suite
