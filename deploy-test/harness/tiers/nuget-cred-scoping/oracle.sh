#!/usr/bin/env bash
# =============================================================================
# tiers/nuget-cred-scoping/oracle.sh -- the #2925 ORACLE (upstream-cred scoping)
# =============================================================================
# run.sh has stood up backend+postgres+mock-nuget-index+mock-nuget-foreign on
# this slot and exported BASE_URL, DB_CONTAINER, BACKEND_IMAGE, DTF_SLOT,
# ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1 and JUNIT_OUTPUT_DIR.
#
# mock-nuget-index (the configured upstream) serves two service indexes:
#   /foreign/index.json  -> flat-container base on mock-nuget-foreign (exploit)
#   /samehost/index.json -> flat-container base on mock-nuget-index   (legit)
# Both mocks print `RECV <method> <path> AUTH=<value|NONE>` for every request,
# so the oracle reads the mock containers' logs to see exactly where the repo's
# configured Basic credentials were sent.
#
# Flow:
#   1. admin login
#   2. create two remote nuget repos (same Basic upstream creds), one per index
#   3. GET .../v3/flatcontainer/testpkg/index.json on each
#   4. assert:
#        N1  foreign host received NO credentialed request (no `AUTH=Basic`)
#        N2  AK refused the off-host resolution with 502 (not 200)
#        N3  regression: same-host resource still gets creds + AK 200
#
# POSITIVE oracle (NON-ZERO-WHILE-BUG): exit = number of FAILED checks; a fully
# fixed image exits 0. Pre-#2925 the foreign host gets `AUTH=Basic ...` and AK
# returns 200, so N1 + N2 fail and the oracle is discriminating.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

AK_ADMIN_USER="${ADMIN_USER:-admin}"
AK_ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

FOREIGN_CTR="ak-dtf${DTF_SLOT}-mock-nuget-foreign"
INDEX_CTR="ak-dtf${DTF_SLOT}-mock-nuget-index"

# The Basic upstream credentials pinned to the repo. base64("user:pass") is what
# a leaked `Authorization: Basic ...` header would carry to the foreign host.
UP_USER="nugetuser2925"
UP_PASS="nugetSECRETpw2925"
REPO_FOREIGN="nuget-foreign-${DTF_SLOT}"
REPO_SAMEHOST="nuget-samehost-${DTF_SLOT}"

log() { printf '\033[36m[dtf-nuget-cred]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[31m[dtf-nuget-cred]\033[0m %s\n' "$*" >&2; }

ak_login() {
  curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$AK_ADMIN_USER" --arg p "$AK_ADMIN_PASS" '{username:$u,password:$p}')" \
    | jq -r '.access_token // empty'
}

create_repo() { # $1=key $2=index-path  (uses $TOK)
  curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/repositories" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg url "http://mock-nuget-index/$2/index.json" \
          --arg u "$UP_USER" --arg p "$UP_PASS" \
          '{key:$k,name:$k,format:"nuget",repo_type:"remote",upstream_url:$url,
            upstream_auth_type:"basic",upstream_username:$u,upstream_password:$p}')"
}

run_assert() {
  TOK="$(ak_login)"
  [ -n "$TOK" ] || { err "admin login failed on ${BASE_URL}"; return 9; }

  local c1 c2
  c1=$(create_repo "$REPO_FOREIGN" foreign)
  c2=$(create_repo "$REPO_SAMEHOST" samehost)
  { [ "$c1" = 200 ] || [ "$c1" = 201 ]; } || { err "foreign repo create HTTP ${c1}"; return 9; }
  { [ "$c2" = 200 ] || [ "$c2" = 201 ]; } || { err "samehost repo create HTTP ${c2}"; return 9; }
  log "created ${REPO_FOREIGN} (foreign-pointing index) + ${REPO_SAMEHOST} (same-host index)"

  # Drive the flat-container resolution on each repo.
  local ak_foreign_status ak_samehost_status
  ak_foreign_status=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "${BASE_URL}/nuget/${REPO_FOREIGN}/v3/flatcontainer/testpkg/index.json")
  ak_samehost_status=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "${BASE_URL}/nuget/${REPO_SAMEHOST}/v3/flatcontainer/testpkg/index.json")
  sleep 2

  local foreign_log index_log
  foreign_log="$(docker logs "${FOREIGN_CTR}" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  index_log="$(docker logs "${INDEX_CTR}" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"

  echo "================ #2925 POSITIVE ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE:-?}) ================" >&2
  local FAILS=0

  # ---- N1: foreign host received NO credentialed request ---------------------
  local foreign_cred_hits
  foreign_cred_hits=$(printf '%s\n' "$foreign_log" | grep -c 'AUTH=Basic ')
  echo "[N1] foreign host credentialed requests: ${foreign_cred_hits} (want 0) on ${FOREIGN_CTR}" >&2
  if [ "$foreign_cred_hits" -eq 0 ]; then
    echo "     => N1 OK (configured credentials were never sent to the off-host resource)" >&2
  else
    FAILS=$((FAILS+1))
    echo "     => N1 FAIL (upstream credentials sent to the foreign host -- #2925 leak)" >&2
    printf '%s\n' "$foreign_log" | grep 'AUTH=Basic ' | head -2 | sed 's/^/    [leak] /' >&2
  fi

  # ---- N2: AK refused the off-host resolution with 502 -----------------------
  echo "[N2] AK response for the foreign-pointing repo: HTTP ${ak_foreign_status} (want 502)" >&2
  if [ "$ak_foreign_status" = "502" ]; then
    echo "     => N2 OK (off-host base refused before any credentialed fetch)" >&2
  else
    FAILS=$((FAILS+1))
    echo "     => N2 FAIL (AK did not refuse; pre-#2925 it fetches the foreign base and returns its content)" >&2
  fi

  # ---- N3: regression -- same-host resource still gets creds, AK 200 ----------
  local samehost_cred_hits
  samehost_cred_hits=$(printf '%s\n' "$index_log" | grep -E '/sh-flat/' | grep -c 'AUTH=Basic ')
  echo "[N3] same-host credentialed flat requests: ${samehost_cred_hits} (want >=1); AK status ${ak_samehost_status} (want 200)" >&2
  if [ "$samehost_cred_hits" -ge 1 ] && [ "$ak_samehost_status" = "200" ]; then
    echo "     => N3 OK (legitimate same-host proxying still credentialed and served)" >&2
  else
    FAILS=$((FAILS+1))
    echo "     => N3 FAIL (fix over-blocked the legitimate same-host resource)" >&2
  fi

  echo "===========================================================================================" >&2
  echo "POSITIVE_CHECKS_FAILED=${FAILS}" >&2
  return "$FAILS"
}

begin_suite "nuget-cred-scoping-2925"

begin_test "#2925 upstream credentials must stay pinned to the configured host (no off-host cred leak; same-host still works)"
rc=0; run_assert || rc=$?
if [ "$rc" -eq 0 ]; then
  pass
else
  fail "nuget-cred-scoping oracle reported ${rc} failed #2925 check(s) on ${BASE_URL}: the repo's configured upstream credentials were sent to a foreign host named by the service index and/or AK did not refuse the off-host base (pre-#2925 guard_upstream_base had no origin check); see stdout above"
fi

end_suite
