#!/usr/bin/env bash
# =============================================================================
# tiers/scan-grading-os-and-jar-trivy/oracle.sh
#   #6233 the Trivy filesystem scan does not grade the dependencies a JAR's
#         embedded build POM only declares (the Trivy half of #5262)
# The scan-grading-os-and-jar tier proves #5262 with the bundled Grype alone;
# this tier runs the same kind of fail_closed Maven Remote with the scanner
# adapter wired in, so every scan-on-proxy also runs the Trivy filesystem
# scan. See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), DB_CONTAINER, DTF_DIR, RELEASE_GATE=1,
# COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test
# that swallows its own failure.

begin_suite "scan-grading-os-and-jar-trivy"
auth_admin
setup_workdir
W="$WORK_DIR"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
PROJECT="ak-dtf${DTF_SLOT}"
ADAPTER="ak-dtf${DTF_SLOT}-trivy"
BACKEND="ak-dtf${DTF_SLOT}-backend"
FILES=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
       -f "${DTF_DIR}/profiles/upstreams.mock-files.yml" -f "${DTF_DIR}/profiles/scanners.trivy.yml"
       -f "${HERE}/fixtures/trivy-adapter.yml")

MVN="sgt-mvn-${SUF}"       # maven Remote, fail_closed

cleanup() {
  api_delete "/api/v1/repositories/${MVN}" >/dev/null 2>&1 || true
  # run.sh's `down -v` composes only the manifest's profiles, which do not
  # name the adapter, so it is removed here (with its DB volume) before the
  # network goes.
  docker rm -f "$ADAPTER" >/dev/null 2>&1 || true
  docker volume rm "ak-dtf${DTF_SLOT}_trivycache" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
uri() { jq -rn --arg v "$1" '$v|@uri'; }

BODY="${W}/body"
HDR="${W}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 300 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha_of "$BODY")
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { # a JSON body verbatim (truncated); package bytes as their size
  if [ "$(head -c 1 "$1" 2>/dev/null)" = "{" ]; then head -c 200 "$1" | tr -c '[:print:]' '.'; else echo "($(stat -c %s "$1" 2>/dev/null || echo 0) bytes)"; fi
}
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
findings_of() { psql_q "SELECT findings_count FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null || true
}
fx() { awk -F'\t' -v p="$1" '$1==p {print $2; exit}' "${W}/fx/files.tsv"; }
fx_sha() { sha_of "$(fx "$1")"; }
backend_env() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND" 2>/dev/null | grep "^$1=" | cut -d= -f2- || true; }
# up <service>: start one service with the overlay and wait for it to be
# healthy. Prints "up" or the failure.
up() {
  docker compose -p "$PROJECT" "${FILES[@]}" up -d --no-deps --force-recreate --wait "$1" \
    >"${W}/up-$1.log" 2>&1 && { echo up; return; }
  echo "failed: $(tail -3 "${W}/up-$1.log" | tr '\n' ' ' | head -c 300)"
}

M="${BASE_URL}/maven"
JAR_DECLARED="com/example/dtfgrade/dtf-declared-only/1.0.0/dtf-declared-only-1.0.0.jar"
JAR_LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
WAR_NESTED="com/example/dtfgrade/dtf-grade-webapp/1.0.0/dtf-grade-webapp-1.0.0.war"
JAR_NOPROPS="com/example/dtfgrade/dtf-no-props/1.0.0/dtf-no-props-1.0.0.jar"

# =============================================================================
# Setup
# =============================================================================
begin_test "Setup: scanner adapter up, backend recreated with TRIVY_ADAPTER_URL, Trivy DB warm"
err=""
r="$(up trivy)"; [ "$r" = up ] || err="${err} adapter: ${r};"
r="$(up backend)"; [ "$r" = up ] || err="${err} backend: ${r};"
[ "$(backend_env TRIVY_ADAPTER_URL)" = "http://trivy:8090" ] || err="${err} backend has no TRIVY_ADAPTER_URL;"
warmed=0
if [ -z "$err" ]; then
  for attempt in 1 2 3 4 5; do
    if docker exec "$ADAPTER" sh -c 'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' >/dev/null 2>&1; then
      warmed=1; break
    fi
    echo "   DB warm attempt ${attempt}/5 failed; retrying in 5s"; sleep 5
  done
  [ "$warmed" = 1 ] || err="${err} could not download the Trivy DB in ${ADAPTER};"
fi
# The backend logs which Trivy filesystem engine it registered at start.
docker logs "$BACKEND" 2>&1 | grep -q "Trivy filesystem scanner enabled (scanner-adapter" \
  || err="${err} the backend did not register the Trivy filesystem scanner on the adapter;"
if [ -z "$err" ]; then
  pass
else
  infra_fail "${err}"
  end_suite
fi
auth_admin

begin_test "Setup: fixtures built and stored in the mock upstream"
err=""
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"
  end_suite
fi
mkdir -p "${W}/fx"
n=$(python3 -I "${HERE}/fixtures/build_fixtures.py" "${W}/fx" 2>"${W}/fx.err") || n=""
if [ -z "$n" ]; then
  infra_fail "fixture build failed: $(head -c 300 "${W}/fx.err")"
  end_suite
fi
while IFS=$'\t' read -r p f ct; do
  b=$(curl -s --max-time 20 -X PUT --data-binary @"$f" "${MOCK}/__file?path=$(uri "$p")&ctype=$(uri "$ct")" \
        | jq -r '.bytes // empty' 2>/dev/null) || b=""
  [ "$b" = "$(stat -c %s "$f")" ] || err="${err} ${p}"
done < "${W}/fx/files.tsv"
if [ -z "$err" ]; then
  pass
else
  infra_fail "mock PUT failed for:${err}"
  end_suite
fi

begin_test "Setup: a fail_closed maven Remote on the mock"
ok=1
create_repo "$MVN" maven remote "${UP}/maven2" || ok=0
a="$(scan_cfg "$MVN" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed" ]; then
  pass
else
  infra_fail "repo setup failed (ok=${ok}) or action not persisted: '${a}'"
  end_suite
fi

# =============================================================================
# Controls (pass on every image)
# =============================================================================
begin_test "CONTROL: log4j-core 2.14.1 is graded on the component the JAR carries: 403 scan_blocked"
pull "${M}/${MVN}/${JAR_LOG4J}"
d=$(fx_sha "/maven2/${JAR_LOG4J}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")'"
fi

# Grype excludes embedded build POMs (#5340) and cannot identify a nested JAR
# with no pom.properties, manifest or version in its name, so only Trivy,
# reading the build POM, names log4j-core in the next two archives. They
# also prove the Trivy filesystem scan is in the loop.
begin_test "CONTROL: a WAR bundling an unidentifiable WEB-INF/lib JAR its build POM declares as log4j-core 2.14.1 is 403 scan_blocked (Trivy keeps a WAR's build POM)"
pull "${M}/${MVN}/${WAR_NESTED}"
d=$(fx_sha "/maven2/${WAR_NESTED}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")' findings='$(findings_of "$d")'"
fi

begin_test "CONTROL: a JAR whose build POM declares log4j-core 2.14.1 and that has no pom.properties is 403 scan_blocked (the POM is its only record)"
pull "${M}/${MVN}/${JAR_NOPROPS}"
d=$(fx_sha "/maven2/${JAR_NOPROPS}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")' findings='$(findings_of "$d")'"
fi

# =============================================================================
# #6233 build-POM declarations are not shipped dependencies, for Trivy too
# =============================================================================
begin_test "FIX #6233: a JAR whose build POM declares compile-scope log4j-core 2.14.1 and jackson-databind 2.9.8 without bundling them is 200 clean through Trivy (was 403)"
pull "${M}/${MVN}/${JAR_DECLARED}"
d=$(fx_sha "/maven2/${JAR_DECLARED}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet "$BODY") verdict='$(verdict_of "$d")' findings='$(findings_of "$d")'"
fi

end_suite
