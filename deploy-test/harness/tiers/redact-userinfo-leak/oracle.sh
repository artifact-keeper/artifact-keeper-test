#!/usr/bin/env bash
# =============================================================================
# tiers/redact-userinfo-leak/oracle.sh -- the #2926 ORACLE (userinfo redaction)
# =============================================================================
# run.sh has stood up backend+postgres+mock-redact on this slot and exported
# BASE_URL, DB_CONTAINER, BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR. mock-redact answers every fetch with a
# real HTTP 500 so AK's `validate_upstream_status` folds it into a diagnostic
# that echoes the upstream URL (a transport failure would short-circuit to 404
# and never render the URL; a real 5xx is what makes the leak observable).
#
# Flow:
#   1. admin login
#   2. create a maven REMOTE repo whose upstream_url carries `user:pass@`
#      userinfo pointing at mock-redact
#   3. drive a real proxy fetch (buffered metadata path + streaming jar path)
#      so AK logs "Fetching artifact from upstream: <url>" and the
#      "Upstream returned error status 500: <url>" 503 mapping
#   4. read the backend container log and assert:
#        R1  the configured username + password are NOT present anywhere
#        R2  the redacted host form `http://<host>/` IS present (redaction ran
#            and kept the host -- not over-redacted, diagnostic still useful)
#
# POSITIVE oracle (NON-ZERO-WHILE-BUG): exit = number of FAILED checks; a fully
# fixed image exits 0. Pre-#2926 the userinfo survives into the log so R1 fails
# and the oracle is discriminating.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

AK_ADMIN_USER="${ADMIN_USER:-admin}"
AK_ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"

# The credential material embedded in the remote repo's upstream_url. These
# exact strings are what must never survive into a diagnostic/log.
LEAK_USER="leakuser2926"
LEAK_PASS="leakpass2926SUPERSECRET"
UPSTREAM_HOST="mock-redact"
UPSTREAM_URL="http://${LEAK_USER}:${LEAK_PASS}@${UPSTREAM_HOST}/"
REPO_KEY="redact-mvn-${DTF_SLOT}"

log()  { printf '\033[36m[dtf-redact]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[dtf-redact]\033[0m %s\n' "$*" >&2; }

ak_login() {
  curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$AK_ADMIN_USER" --arg p "$AK_ADMIN_PASS" '{username:$u,password:$p}')" \
    | jq -r '.access_token // empty'
}

# ---- assert phase (returns failed-check count) ------------------------------
run_assert() {
  local TOK; TOK="$(ak_login)"
  [ -n "$TOK" ] || { err "admin login failed on ${BASE_URL}"; return 9; }

  # Create the creds-bearing maven remote repo. userinfo lives in upstream_url.
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/repositories" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$REPO_KEY" --arg u "$UPSTREAM_URL" \
          '{key:$k,name:$k,format:"maven",repo_type:"remote",upstream_url:$u}')")
  if [ "$code" != "200" ] && [ "$code" != "201" ]; then
    err "repo create returned HTTP ${code} (expected 200/201)"; return 9
  fi
  log "created remote repo ${REPO_KEY} -> ${UPSTREAM_HOST} (creds in upstream_url)"

  # Drive both proxy-fetch code paths so the diagnostic renders.
  #   streaming path : a .jar download
  #   buffered path  : maven-metadata.xml
  # mock-redact 500s both -> AK renders "Upstream returned error status 500: <url>".
  curl -s -o /dev/null -H "Authorization: Bearer $TOK" \
    "${BASE_URL}/maven/${REPO_KEY}/com/example/foo/1.0/foo-1.0.jar"
  curl -s -o /dev/null -H "Authorization: Bearer $TOK" \
    "${BASE_URL}/maven/${REPO_KEY}/com/example/foo/maven-metadata.xml"
  # small settle so the async log lines are flushed
  sleep 2

  # Strip ANSI, then inspect the backend log.
  local logs
  logs="$(docker logs "${BACKEND_CTR}" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"

  echo "================ #2926 POSITIVE ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE:-?}) ================" >&2
  local FAILS=0

  # ---- R1: username + password must NOT appear in the log --------------------
  local user_hits pass_hits
  user_hits=$(printf '%s\n' "$logs" | grep -cF "$LEAK_USER")
  pass_hits=$(printf '%s\n' "$logs" | grep -cF "$LEAK_PASS")
  echo "[R1] credential leak: username-hits=${user_hits} password-hits=${pass_hits} (want 0/0)" >&2
  if [ "$user_hits" -eq 0 ] && [ "$pass_hits" -eq 0 ]; then
    echo "     => R1 OK (no userinfo credentials in the diagnostic log)" >&2
  else
    FAILS=$((FAILS+1))
    echo "     => R1 FAIL (userinfo leaked into the diagnostic log -- pre-#2926 behaviour)" >&2
    printf '%s\n' "$logs" | grep -F "$LEAK_PASS" | head -2 | sed 's/^/    [leak] /' >&2
  fi

  # ---- R2: the redacted host form must be present (redaction ran, host kept) --
  # The diagnostic path executed AND redaction preserved the host (bare
  # `http://mock-redact/...`, no userinfo). Guards against over-redaction and
  # against a false pass where the fetch simply never happened.
  local host_hits
  host_hits=$(printf '%s\n' "$logs" | grep -cE "http://${UPSTREAM_HOST}/")
  echo "[R2] redacted-host diagnostic present: host-hits=${host_hits} (want >=1, form 'http://${UPSTREAM_HOST}/...')" >&2
  if [ "$host_hits" -ge 1 ]; then
    echo "     => R2 OK (redaction kept the useful host; diagnostic still renders)" >&2
  else
    FAILS=$((FAILS+1))
    echo "     => R2 FAIL (no redacted-host diagnostic -- fetch never ran or URL over-redacted)" >&2
  fi

  echo "===========================================================================================" >&2
  echo "POSITIVE_CHECKS_FAILED=${FAILS}" >&2
  return "$FAILS"
}

# ---- JUnit-wrapped suite ----------------------------------------------------
begin_suite "redact-userinfo-leak-2926"

begin_test "#2926 proxy-fetch diagnostic must not leak upstream_url userinfo (user:pass@) into the backend log"
rc=0; run_assert || rc=$?
if [ "$rc" -eq 0 ]; then
  pass
else
  fail "redact-userinfo-leak oracle reported ${rc} failed #2926 check(s) on ${BASE_URL}: the configured upstream credentials survived into the backend diagnostic log (pre-#2926 redact_url_for_diagnostics did not strip userinfo); see stdout above"
fi

end_suite
