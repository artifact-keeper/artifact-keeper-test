#!/usr/bin/env bash
# selftest-dtf-client-fetch-infra.sh - pins how the DTF tells "the test client
# could not download its own tooling from the internet" (INFRA) from a product
# FAIL (deploy-test/harness/lib/internet_fetch.sh).
#
# The 1.12.1 candidate's dtf-advisory leg reported format-conformance as a
# product FAIL because mvn could not fetch maven-deploy-plugin from Maven
# Central (artifact-keeper run 44244223519). Pinned here, no docker, no
# network:
#   1. dtf_internet_fetch_failure on recorded client errors: public-host
#      download and DNS failures (mvn, pip, npm, apt, apk, curl to GitHub) are
#      INFRA; anything naming the candidate, and HTTP answers (404, checksum),
#      are not.
#      Judged per log: a log that names the candidate or a host beside it
#      (backend-b, peer-backend, *.dtf.local, 127.0.0.1 but not Docker's
#      127.0.0.11 resolver) next to an error, or a server error body quoting a
#      public host, is a FAIL even if another line is a Central timeout.
#   2. native_client.sh's _nc_step: a matching failed step is infra_fail, and
#      so are the steps it short-circuits.
#   3. format-conformance/oracle.sh's aggregate: 11 only when some plugin was
#      INFRA and none FAILed; one FAIL makes it 1.
#
# Usage: scripts/ci/selftest-dtf-client-fetch-infra.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

ok()  { echo "  PASS  $1"; }
bad() { echo "  FAIL  $1"; fails=$((fails + 1)); }

# shellcheck source=deploy-test/harness/lib/internet_fetch.sh
source "$ROOT/deploy-test/harness/lib/internet_fetch.sh"
export BASE_URL="http://127.0.0.1:8201"

# classify <want infra|fail> <label> <log text>
classify() {
  local want="$1" label="$2" got why
  printf '%s\n' "$3" > "$WORK/log"
  if why="$(dtf_internet_fetch_failure "$WORK/log")"; then got=infra; else got=fail; fi
  if [ "$got" = "$want" ]; then ok "$label"; else bad "$label: got $got (want $want) ${why:-}"; fi
}

echo "dtf_internet_fetch_failure: recorded client errors"
classify infra "mvn: deploy plugin not resolvable from Central (run 44244223519)" \
"Apache Maven 3.9.16 (2bdd9fddda4b155ebf8000e807eb73fd829a51d5)
[ERROR] No plugin found for prefix 'deploy' in the current project and in the plugin groups [org.apache.maven.plugins, org.codehaus.mojo] available from the repositories [local (/tmp/dtf-maven/.m2-deploy), central (https://repo.maven.apache.org/maven2)] -> [Help 1]
mvn deploy:deploy-file failed"
classify infra "mvn: transfer from central timed out" \
"[ERROR] Plugin org.apache.maven.plugins:maven-dependency-plugin:3.6.1 or one of its dependencies could not be resolved: Could not transfer artifact org.apache.maven.plugins:maven-dependency-plugin:pom:3.6.1 from/to central (https://repo.maven.apache.org/maven2): Connect timed out"
classify infra "pip: pypi.org unreachable" \
"WARNING: Retrying (Retry(total=0)) after connection broken by 'NewConnectionError(...: Failed to establish a new connection: [Errno -3] Temporary failure in name resolution')': /simple/twine/
ERROR: Could not install packages due to an OSError: HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded with url: /simple/twine/"
classify infra "npm: registry.npmjs.org ENOTFOUND" \
"npm error code ENOTFOUND
npm error network request to https://registry.npmjs.org/semver failed, reason: getaddrinfo ENOTFOUND registry.npmjs.org"
classify infra "apt: Debian mirror DNS" \
"W: Failed to fetch http://deb.debian.org/debian/dists/bookworm/InRelease  Temporary failure resolving 'deb.debian.org'"
classify infra "apk: Alpine CDN" \
"WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.20/main: temporary error (try again later)"
classify infra "curl: GitHub release download" \
"curl: (6) Could not resolve host: github.com"
classify infra "DNS failure for a host not on the list" \
"curl: (6) Could not resolve host: downloads.example.org"
classify fail "mvn: candidate refused the deploy" \
"[ERROR] Failed to deploy artifacts: Could not transfer artifact dtf:m:jar:1.0 from/to dtf (http://backend:8080/maven/dtf-maven-x): status code: 500, reason phrase: Internal Server Error (500)"
classify fail "npm: candidate reset the connection" \
"npm error network request to http://backend:8080/npm/dtf-npm-x/semver failed, reason: socket hang up ECONNRESET"
classify fail "curl to BASE_URL refused" \
"curl: (7) Failed to connect to 127.0.0.1 port 8201: Connection refused"
classify fail "DNS failure for a compose service name" \
"curl: (6) Could not resolve host: backend"
classify fail "an HTTP 404 from Central is an answer, not a network failure" \
"[ERROR] Failed to execute goal: Could not find artifact org.example:missing:jar:1.0 in central (https://repo.maven.apache.org/maven2)"
classify fail "sha mismatch" \
"nc_assert_sha_eq FAIL: resolved jar != deployed jar"
echo "dtf_internet_fetch_failure: judged per log, candidate hosts"
classify fail "candidate 404 plus a Central timeout in one log" \
"[ERROR] Failed to deploy artifacts: Could not transfer artifact dtf:m:pom:1.0 from/to dtf (http://backend:8080/maven/x): status code: 404
[ERROR] Plugin org.apache.maven.plugins:maven-deploy-plugin:3.1.1 could not be resolved: Could not transfer artifact from/to central (https://repo.maven.apache.org/maven2): Connect timed out"
classify fail "candidate error body quoting pypi.org (with the candidate URL)" \
"ERROR: HTTP error 502 while getting http://backend:8080/pypi/dtf-pypi-x/simple/requests/
{\"error\":\"upstream fetch failed: HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded\"}"
classify fail "candidate error body quoting pypi.org (body only)" \
"{\"error\":\"upstream fetch failed: HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded\"}"
classify fail "tf.dtf.local (the candidate's terraform alias) unresolvable" \
"Error: Failed to query available provider packages: could not connect to tf.dtf.local: dial tcp: lookup tf.dtf.local on 127.0.0.11:53: no such host"
classify fail "ldap.dtf.local refused" \
"ldap_sasl_bind(SIMPLE): Can't contact LDAP server: Connection refused (ldap.dtf.local:636)"
classify fail "backend-b reset the connection" \
"curl: (56) Recv failure: Connection reset by peer while fetching http://backend-b:8080/api/v1/x"
classify fail "peer-backend timed out" \
"npm error network request to http://peer-backend:8080/npm/x failed, reason: ETIMEDOUT"
classify infra "Go: public host unresolvable via Docker's 127.0.0.11 resolver" \
"go: github.com/x/y@v1.0.0: Get \"https://proxy.golang.org/github.com/x/y/@v/v1.0.0.mod\": dial tcp: lookup proxy.golang.org on 127.0.0.11:53: no such host"
classify infra "a benign candidate URL line (no error) does not block INFRA" \
"nc_post_file OK: POST http://127.0.0.1:8201/maven/dtf-x -> 201
curl: (6) Could not resolve host: github.com"
: > "$WORK/log"
if dtf_internet_fetch_failure "$WORK/log" >/dev/null; then bad "empty log is not INFRA"; else ok "empty log is not INFRA"; fi

# The real native_client.sh driver step: a failed hook whose log is a client
# download failure is recorded with infra_fail, anything else with fail.
# The stubs and WORK_DIR/FC_FORMAT are read by the sourced driver.
# shellcheck disable=SC2030,SC2031,SC2034,SC2329
step_expect() {
  local want="$1" label="$2" text="$3" got
  got="$(
    begin_test() { :; }; pass() { echo pass; }
    fail() { echo fail; }; infra_fail() { echo infra_fail; }
    export DTF_SLOT=1
    # shellcheck source=deploy-test/harness/lib/native_client.sh
    source "$ROOT/deploy-test/harness/lib/native_client.sh"
    WORK_DIR="$WORK" FC_FORMAT=t
    hook() { printf '%s\n' "$text"; return 1; }
    _nc_step "publish" hook
  )"
  if [ "$got" = "$want" ]; then ok "$label"; else bad "$label: recorded '$got' (want '$want')"; fi
}
echo "native_client.sh: a failed step"
step_expect infra_fail "client download failure -> infra_fail" "curl: (6) Could not resolve host: github.com"
step_expect fail       "anything else -> fail"                 "status code: 500 from http://backend:8080/x"

# After an INFRA step the short-circuited steps are INFRA too, so end_suite's
# "every failure was INFRA" rule still sees an all-INFRA suite; after a real
# FAIL they stay FAIL.
# shellcheck disable=SC2030,SC2031,SC2034,SC2329
chain_expect() {
  local want="$1" label="$2" text="$3" got
  got="$(
    begin_test() { :; }; pass() { echo pass; }
    fail() { echo fail; }; infra_fail() { echo infra_fail; }
    export DTF_SLOT=1
    # shellcheck source=deploy-test/harness/lib/native_client.sh
    source "$ROOT/deploy-test/harness/lib/native_client.sh"
    WORK_DIR="$WORK" FC_FORMAT=t FC_OK=1 FC_INFRA=0
    bad_hook() { printf '%s\n' "$text"; return 1; }
    good_hook() { return 0; }
    _nc_step "publish" bad_hook; _nc_step "consume" good_hook
  )"
  got="$(printf '%s' "$got" | paste -sd' ' -)"
  if [ "$got" = "$want" ]; then ok "$label"; else bad "$label: recorded '$got' (want '$want')"; fi
}
chain_expect "infra_fail infra_fail" "step after an INFRA step -> infra_fail" "curl: (6) Could not resolve host: github.com"
chain_expect "fail fail"             "step after a FAIL step -> fail"        "status code: 500 from http://backend:8080/x"

# --- 2. format-conformance oracle aggregate -----------------------------------
# The real oracle over stub plugins: a stub native_client.sh whose
# nc_run_plugin exits the number in the plugin's file name.
DT="$WORK/dt"
mkdir -p "$DT/harness/lib" "$DT/harness/tiers/format-conformance/plugins"
cp "$ROOT/deploy-test/harness/tiers/format-conformance/oracle.sh" "$DT/harness/tiers/format-conformance/"
cat > "$DT/harness/lib/native_client.sh" <<'EOF'
fc_enabled_and_selected() { return 0; }
nc_header() { basename "$1" .sh; }
nc_run_plugin() { local b; b="$(basename "$1" .sh)"; exit "${b#*-}"; }
EOF
printf 'DTF_EXIT_INFRA=11\n' > "$WORK/common.sh"

oracle_expect() {
  local want="$1" label="$2"; shift 2
  rm -f "$DT/harness/tiers/format-conformance/plugins/"*.sh
  local p; for p in "$@"; do : > "$DT/harness/tiers/format-conformance/plugins/${p}.sh"; done
  local rc
  BASE_URL=x DTF_SLOT=1 DTF_DIR="$DT" COMMON_SH="$WORK/common.sh" \
    bash "$DT/harness/tiers/format-conformance/oracle.sh" >/dev/null 2>&1; rc=$?
  if [ "$rc" = "$want" ]; then ok "$label"; else bad "$label: exit $rc (want $want)"; fi
}

echo "format-conformance oracle: aggregate exit code"
oracle_expect 0  "all plugins pass"                 a-0 b-0
oracle_expect 11 "one plugin INFRA, none FAIL -> 11" a-0 b-11
oracle_expect 1  "INFRA and FAIL -> 1 (FAIL wins)"  a-11 b-1
oracle_expect 1  "a plugin wiring error (2) is a FAIL" a-2 b-11

if [ "$fails" -ne 0 ]; then
  echo "dtf client-fetch INFRA selftest: $fails case(s) FAILED"
  exit 1
fi
echo "dtf client-fetch INFRA selftest: all cases passed"
