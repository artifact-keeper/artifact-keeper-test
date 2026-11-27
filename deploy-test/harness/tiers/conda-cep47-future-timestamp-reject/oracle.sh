#!/usr/bin/env bash
# =============================================================================
# tiers/conda-cep47-future-timestamp-reject/oracle.sh
#   #6529 under CONDA_FUTURE_TIMESTAMP=reject a future builder timestamp is
#         refused at upload; a current one is not
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

SUF="${RUN_ID##*-}-$$"
R="ixr-${DTF_SLOT:-0}-${SUF}"
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
W="$(mktemp -d -t dtf-cep47r-XXXXXX)"
trap 'rm -rf "$W"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
conda_put() { # filename -> status; body in $W/last
  curl -s --max-time 60 -o "$W/last" -w '%{http_code}' -X PUT -H "$(auth_header)" \
    --data-binary "@$W/$1" "${BASE_URL}/conda/${R}/noarch/$1" 2>/dev/null || echo 000
}
rows_of() { psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                    WHERE r.key = '${R}' AND a.path = 'noarch/$1'"; }

begin_suite "conda-cep47-future-timestamp-reject (#6529)"
auth_admin

begin_test "SETUP: hosted channel and three packages (a day ahead, now, seconds in the past)"
setup_err=""
create_repo "$R" conda local || setup_err+="create repo; "
NOW_MS="$(date +%s%3N)"
CONDA_PKG_TIMESTAMP=$((NOW_MS + 86400000)) bash "$BUILD" "$W" dtfrj-future 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build future; "
CONDA_PKG_TIMESTAMP="$NOW_MS" bash "$BUILD" "$W" dtfrj-now 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build now; "
CONDA_PKG_TIMESTAMP=1600000000 bash "$BUILD" "$W" dtfrj-secs 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build secs; "
if [ -n "$setup_err" ]; then infra_fail "setup did not complete" "$setup_err"; end_suite; exit $?; fi
pass

FUT="dtfrj-future-1.0-0.tar.bz2"; NOW="dtfrj-now-1.0-0.tar.bz2"; SECS="dtfrj-secs-1.0-0.tar.bz2"

begin_test "FIX #6529: under CONDA_FUTURE_TIMESTAMP=reject a builder timestamp a day ahead is refused 400 naming the cause, and nothing is stored"
st="$(conda_put "$FUT")"
if [ "$st" = "400" ] && grep -q "in the future" "$W/last" && [ "$(rows_of "$FUT")" = "0" ]; then
  pass
else
  fail "a future-dated package was accepted" "HTTP ${st}: $(head -c 300 "$W/last"); rows $(rows_of "$FUT")"
fi

begin_test "CONTROL: a current timestamp and a past seconds-valued one still upload 201 and are listed"
s1="$(conda_put "$NOW")"; s2="$(conda_put "$SECS")"
curl -s --max-time 60 -o "$W/rd.json" -H "$(auth_header)" "${BASE_URL}/conda/${R}/noarch/repodata.json" 2>/dev/null
if [ "$s1" = "201" ] && [ "$s2" = "201" ] \
   && jq -e --arg a "$NOW" --arg b "$SECS" '.packages | has($a) and has($b)' "$W/rd.json" >/dev/null 2>&1; then
  pass
else
  fail "a normal upload was refused" "now HTTP ${s1}, seconds HTTP ${s2}: $(head -c 200 "$W/last")"
fi

end_suite
