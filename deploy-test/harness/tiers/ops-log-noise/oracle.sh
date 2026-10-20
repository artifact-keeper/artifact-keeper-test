#!/usr/bin/env bash
# =============================================================================
# tiers/ops-log-noise/oracle.sh - expected events are not logged as WARNs
#                                 (artifact-keeper#4552 / #4794,
#                                  #4526 / #4798)
# =============================================================================
# run.sh has stood up filesystem + upstreams.mock-ops + topology.two-replica
# and exported BASE_URL (replica A), TRIVY_PORT (the mock's control port),
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. Replica B shares A's network namespace and
# listens on 127.0.0.1:8081 inside it.
#
# Gates (see the manifest for the full prose):
#   (FIX #4552)  a replica waiting on the cross-replica proxy lock logs no
#                "slow statement ... pg_advisory_lock" WARN. RED on 1.11.2.
#   (FIX #4526)  401 / 403 refusals of an anonymous OCI Remote's manifest
#                requests log no "Proxy fetch failed" WARN. RED on 1.11.2.
#   (CONTROL)    the fill ran once and both replicas served the bytes; the
#                refused pulls reached the upstream and answered 404
#                MANIFEST_UNKNOWN; the INFO refusal line is logged; a 400
#                refusal still WARNs per pull; a working image proxies.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${TRIVY_PORT:?}"
: "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
CTR_A="${DB_CONTAINER%-db}-backend"
CTR_B="${DB_CONTAINER%-db}-backend-b"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${DTF_SLOT}.71"
MVN_REPO="opslog-mvn-${DTF_SLOT}-${SUF}"
OCI_REPO="opslog-oci-${DTF_SLOT}-${SUF}"
JAR="com/example/opslog/1.0/opslog-1.0-${SUF}.jar"
PULLS=3

WORK="$(mktemp -d -t dtf-opslog-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

BASIC="Authorization: Basic $(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64 | tr -d '\n')"

# backend_log CONTAINER SINCE -> the container's log since SINCE, ANSI stripped
# (images before the no-TTY fix colour their fields).
backend_log() { docker logs --since "$2" "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' || true; }
mock_count() { curl -s -m 5 "${MOCK}/__requests?path=$1" 2>/dev/null | jq -r '.count // empty' 2>/dev/null; }
count_lines() { grep -c "$@" || true; }

begin_suite "ops-log-noise"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: admin login, replica B healthy, Maven and OCI Remotes on the mock"
auth_admin
if [ "$(docker exec "$CTR_A" curl -s -m 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/health 2>/dev/null)" != "200" ]; then
  infra_fail "replica B (${CTR_B}) does not answer /health on 127.0.0.1:8081"; end_suite
fi
if ! create_remote_repo "$MVN_REPO" maven "${UPSTREAM}/slow" >/dev/null 2>&1; then
  infra_fail "could not create Maven Remote ${MVN_REPO} -> ${UPSTREAM}/slow"; end_suite
fi
if ! create_remote_repo "$OCI_REPO" docker "$UPSTREAM" >/dev/null 2>&1; then
  infra_fail "could not create OCI Remote ${OCI_REPO} -> ${UPSTREAM}"; end_suite
fi
SHA_UP="$(curl -s -m 30 "${MOCK}/__sha256/slow/${JAR}" 2>/dev/null)"
if [ "${#SHA_UP}" != "64" ]; then infra_fail "mock did not return the reference SHA-256" "$SHA_UP"; end_suite; fi
pass

# =============================================================================
# #4552: a replica waiting on the cross-replica advisory lock
# =============================================================================
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
# A: the cluster leader. Streams the 4 s upstream fill and holds the lock.
curl -s -m 60 -H "$BASIC" -o "${WORK}/a.jar" -w '%{http_code} %{time_total}' \
  "${BASE_URL}/maven/${MVN_REPO}/${JAR}" > "${WORK}/a.out" 2>/dev/null &
APID=$!
sleep 0.7
# B: another replica, same object, while A is still filling: it blocks on
# SELECT pg_advisory_lock until A publishes, then serves from the cache.
# The backend image has curl but no shell: the body comes back on stdout and
# the timing is taken here.
B_T0="$(date +%s.%N)"
B_RC=0
docker exec "$CTR_A" curl -sf -m 60 -H "$BASIC" "http://127.0.0.1:8081/maven/${MVN_REPO}/${JAR}" \
  > "${WORK}/b.jar" 2>/dev/null || B_RC=$?
B_T1="$(date +%s.%N)"
wait "$APID" 2>/dev/null || true
sleep 2
A_OUT="$(cat "${WORK}/a.out" 2>/dev/null)"
A_CODE="${A_OUT%% *}"; A_TIME="${A_OUT##* }"
A_SHA="$(sha256sum "${WORK}/a.jar" 2>/dev/null | awk '{print $1}')"
B_CODE="$([ "$B_RC" = "0" ] && echo 200 || echo "curl-rc-${B_RC}")"
B_TIME="$(awk -v a="$B_T0" -v b="$B_T1" 'BEGIN { printf "%.3f", b - a }')"
B_SHA="$(sha256sum "${WORK}/b.jar" 2>/dev/null | awk '{print $1}')"
FETCHES="$(mock_count "/slow/${JAR}")"
LOG_A="$(backend_log "$CTR_A" "$T0")"
LOG_B="$(backend_log "$CTR_B" "$T0")"
SLOW_A="$(printf '%s\n' "$LOG_A" | grep 'slow statement' | grep 'pg_advisory_lock' || true)"
SLOW_B="$(printf '%s\n' "$LOG_B" | grep 'slow statement' | grep 'pg_advisory_lock' || true)"
EV_FILL="A=${A_CODE} ${A_TIME}s sha=${A_SHA:0:12}; B=${B_CODE} ${B_TIME}s sha=${B_SHA:0:12}; upstream=${SHA_UP:0:12}; upstream fetches=${FETCHES}"

begin_test "CONTROL #4552: two replicas, one cold object: both serve the upstream bytes, the upstream is fetched ONCE, and replica B waited for the fill"
echo "  ${EV_FILL}" >&2
if [ "$A_CODE" = "200" ] && [ "$B_CODE" = "200" ] && [ "$A_SHA" = "$SHA_UP" ] && [ "$B_SHA" = "$SHA_UP" ] \
   && [ "$FETCHES" = "1" ] && awk -v t="$B_TIME" 'BEGIN { exit !(t + 0 >= 2.0) }'; then
  pass
else
  fail "the contended fill did not run once with B waiting on it" "$EV_FILL"
fi

begin_test "FIX #4552: the waiting replica logs no 'slow statement' WARN for SELECT pg_advisory_lock"
if [ -z "$SLOW_A$SLOW_B" ]; then
  pass
else
  fail "an expected advisory-lock wait was logged as a slow statement (1.11.2 behaviour)" \
    "$(printf 'A: %s\nB: %s' "${SLOW_A:0:400}" "${SLOW_B:0:400}")"
fi

# =============================================================================
# #4526: an anonymous OCI Remote whose upstream refuses
# =============================================================================
# pull NAME -> "CODE ERRCODE" for GET /v2/<remote>/<NAME>/manifests/v1
pull() {
  local code
  code="$(curl -s -m 30 -H "$BASIC" -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -o "${WORK}/m.body" -w '%{http_code}' "${BASE_URL}/v2/${OCI_REPO}/$1/manifests/v1" 2>/dev/null || echo 000)"
  printf '%s %s\n' "$code" "$(jq -r '.errors[0].code // "-"' "${WORK}/m.body" 2>/dev/null || echo -)"
}

T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
declare -A RESULTS=()
for name in deny401 deny403 bad400; do
  RESULTS[$name]=""
  for _ in $(seq 1 "$PULLS"); do
    RESULTS[$name]+="$(pull "$name" | tr ' ' '/') "
  done
done
OK_CODE="$(curl -s -m 30 -H "$BASIC" -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -o "${WORK}/ok.body" -w '%{http_code}' "${BASE_URL}/v2/${OCI_REPO}/okimg/manifests/v1" 2>/dev/null || echo 000)"
curl -s -m 10 -o "${WORK}/ok.golden" "${MOCK}/__manifest" 2>/dev/null || true
sleep 2
LOG_OCI="$(backend_log "$CTR_A" "$T1")"
warn_for() { printf '%s\n' "$LOG_OCI" | grep 'WARN' | grep 'Proxy fetch failed' | count_lines "$1"; }
W401="$(warn_for 'deny401')"; W403="$(warn_for 'deny403')"; W400="$(warn_for 'bad400')"
INFO_REFUSED="$(printf '%s\n' "$LOG_OCI" | grep 'INFO' | count_lines 'refused an anonymous manifest request')"
U401="$(mock_count "/v2/deny401/manifests/v1")"; U403="$(mock_count "/v2/deny403/manifests/v1")"
EV_OCI="deny401: ${RESULTS[deny401]}(upstream ${U401}, WARN ${W401}); deny403: ${RESULTS[deny403]}(upstream ${U403}, WARN ${W403}); bad400: ${RESULTS[bad400]}(WARN ${W400}); INFO refusals ${INFO_REFUSED}; okimg ${OK_CODE}"
echo "  ${EV_OCI}" >&2

begin_test "CONTROL #4526: each refused pull reaches the upstream and answers 404 MANIFEST_UNKNOWN; the INFO refusal line is logged"
WANT="$(for _ in $(seq 1 "$PULLS"); do printf '404/MANIFEST_UNKNOWN '; done)"
if [ "${RESULTS[deny401]}" = "$WANT" ] && [ "${RESULTS[deny403]}" = "$WANT" ] \
   && [ "$U401" = "$PULLS" ] && [ "$U403" = "$PULLS" ] && [ "$INFO_REFUSED" -ge 1 ]; then
  pass
else
  fail "refused anonymous pulls did not behave as expected" "$EV_OCI"
fi

begin_test "CONTROL #4526: a non-auth refusal (upstream 400) still logs one 'Proxy fetch failed' WARN per pull"
if [ "$W400" = "$PULLS" ]; then pass; else fail "expected ${PULLS} WARN lines for bad400, saw ${W400}" "$EV_OCI"; fi

begin_test "CONTROL #4526: a working image still proxies its manifest byte-identical"
if [ "$OK_CODE" = "200" ] && cmp -s "${WORK}/ok.body" "${WORK}/ok.golden"; then
  pass
else
  fail "okimg manifest: HTTP ${OK_CODE}, body $(head -c 200 "${WORK}/ok.body")"
fi

begin_test "FIX #4526: ${PULLS} pulls each of a 401 and a 403 manifest through the anonymous OCI Remote log no 'Proxy fetch failed' WARN"
if [ "$W401" = "0" ] && [ "$W403" = "0" ]; then
  pass
else
  fail "the anonymous refusal logged a WARN per pull (1.11.2 behaviour): 401 -> ${W401}, 403 -> ${W403}" \
    "$(printf '%s\n' "$LOG_OCI" | grep 'WARN' | grep 'Proxy fetch failed' | grep -E 'deny40[13]' | head -2 | cut -c1-400)"
fi

end_suite
