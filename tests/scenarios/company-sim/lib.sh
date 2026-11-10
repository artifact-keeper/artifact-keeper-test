#!/usr/bin/env bash
# shellcheck disable=SC2034  # CS_DIR, CS_BODY_FILE, CS_POM_STATUS are read by the scripts that source this
# lib.sh - helpers for the Halcyon Robotics company simulation.
#
# Source this from 00-found-company.sh, run-roles.sh, test-company-sim.sh and
# every roles/*.sh. It sources tests/lib/common.sh, so the Test Script
# Contract (begin_suite/begin_test/pass/fail/end_suite, JUnit XML in
# $JUNIT_OUTPUT_DIR, exit codes) applies unchanged.
#
# What it adds on top of common.sh:
#   - the company's naming scheme (every name carries RUN_ID, see HAL below);
#   - persona authentication (JWT, Basic, API token) without subshell loss;
#   - cs_http: one request with status, body and headers kept in globals;
#   - cs_expect / cs_record: run a check, print PASS/FAIL, write JUnit, and
#     emit a `CHECK|company-sim/<role>|<what>|<RESULT>|<note>` line;
#   - create-if-missing helpers the founder uses (users, groups, projects,
#     repositories, members, grants, service accounts, tokens);
#   - personas.env read/write;
#   - file barriers (cs_signal / cs_wait) so parallel roles can meet at the
#     few points the story needs an order (the offboarding of a departed
#     employee, for one).
#
# Requires: bash >= 4.3, curl, jq.

# shellcheck source=../../lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../lib/common.sh"

# common.sh turns on `set -euo pipefail`. A company-sim script is a list of
# independent checks that each record their own outcome, and cs_expect
# returns 1 on a FAIL so a role can gate follow-up checks with `if`. Under -e
# a bare failing check would end the role's day and hide every check after
# it, so errexit is off for every script that sources this file. -u and
# pipefail stay on.
set +e

CS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------
# HAL_RID is RUN_ID folded to the character set every AK name accepts
# (lowercase alphanumerics and '-'), capped at 24 characters so the longest
# repository key stays well under the 128-character limit. HAL is the company
# prefix: hal-<rid>. Every user, group, project, repository and service
# account the scenario creates starts with it.
_cs_fold_rid() {
  local r
  r=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed -e 's/--*/-/g' -e 's/^-//' -e 's/-$//')
  printf '%s' "${r:0:24}" | sed -e 's/-$//'
}
HAL_RID="${HAL_RID:-$(_cs_fold_rid "$RUN_ID")}"
HAL="hal-${HAL_RID}"
export HAL_RID HAL

# Where the founder writes personas.env and where roles leave CHECK lines,
# logs and barrier files. Override with COMPANY_SIM_STATE_DIR.
COMPANY_SIM_STATE_DIR="${COMPANY_SIM_STATE_DIR:-${JUNIT_OUTPUT_DIR}/company-sim-${HAL_RID}}"
PERSONAS_ENV="${PERSONAS_ENV:-${COMPANY_SIM_STATE_DIR}/personas.env}"
export COMPANY_SIM_STATE_DIR PERSONAS_ENV
mkdir -p "${COMPANY_SIM_STATE_DIR}/checks" "${COMPANY_SIM_STATE_DIR}/signals" "${COMPANY_SIM_STATE_DIR}/logs"

CS_ROLE="${CS_ROLE:-unknown}"

# ---------------------------------------------------------------------------
# Suite lifecycle
# ---------------------------------------------------------------------------

# cs_begin ROLE [--no-personas]
# Starts the JUnit suite "company-sim-<role>" and, unless told not to, loads
# personas.env (role scripts need it; the founder writes it).
cs_begin() {
  CS_ROLE="$1"
  begin_suite "company-sim-${CS_ROLE}"
  : > "${COMPANY_SIM_STATE_DIR}/checks/${CS_ROLE}.txt"
  if [ "${2:-}" != "--no-personas" ]; then
    cs_load_personas || {
      begin_test "load personas.env"
      infra_fail "personas.env not found at ${PERSONAS_ENV}; run 00-found-company.sh first"
      end_suite
    }
  fi
}

cs_load_personas() {
  [ -f "$PERSONAS_ENV" ] || return 1
  # shellcheck disable=SC1090
  source "$PERSONAS_ENV"
}

# ---------------------------------------------------------------------------
# Persona credentials
# ---------------------------------------------------------------------------
# A persona is the key used in personas.env: FW_DEV -> HAL_FW_DEV_USER,
# HAL_FW_DEV_PASS, HAL_FW_DEV_ID and, where minted, HAL_FW_DEV_TOKEN.

declare -gA CS_JWT=()

cs_user() { local v="HAL_${1}_USER"; printf '%s' "${!v:-}"; }
cs_pass() { local v="HAL_${1}_PASS"; printf '%s' "${!v:-}"; }
cs_uid()  { local v="HAL_${1}_ID";   printf '%s' "${!v:-}"; }

# cs_login PERSONA - log the persona in (once) and cache the JWT in CS_JWT.
# Returns 1 when the login fails; CS_STATUS/CS_BODY then hold the answer.
cs_login() {
  local p="$1"
  if [ -n "${CS_JWT[$p]:-}" ]; then return 0; fi
  local u pw
  u=$(cs_user "$p"); pw=$(cs_pass "$p")
  cs_http POST /api/v1/auth/login none \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$u" --arg p "$pw" '{username:$u,password:$p}')"
  if [ "$CS_STATUS" = "200" ]; then
    CS_JWT[$p]=$(printf '%s' "$CS_BODY" | jq -r '.access_token // .token // empty')
    [ -n "${CS_JWT[$p]}" ] && return 0
  fi
  return 1
}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
# cs_http METHOD PATH AUTH [curl args...]
#
# AUTH is one of:
#   admin            the bootstrap admin (common.sh auth_admin / ADMIN_TOKEN)
#   jwt:PERSONA      the persona's session JWT (logs in on first use)
#   basic:PERSONA    HTTP Basic with the persona's username and password
#   token:VAR        Bearer <value of $VAR>  (an API token from personas.env)
#   basictoken:PERSONA:VAR   HTTP Basic <persona username>:<value of $VAR>
#   none             no credentials
#
# PATH is either an absolute URL or a path appended to $BASE_URL.
# Sets CS_STATUS ("000" when no answer), CS_BODY and CS_HEADERS. Always
# returns 0, so callers branch on CS_STATUS and set -e never fires. Call it
# directly, never inside $(...), or the globals are lost.
CS_STATUS=""
CS_BODY=""
CS_HEADERS=""
CS_LAST_REQ=""
CS_BODY_FILE=""
cs_http() {
  local method="$1" path="$2" auth="$3"
  shift 3
  local url="$path"
  case "$path" in http://*|https://*) ;; *) url="${BASE_URL}${path}" ;; esac
  local -a hdr=()
  case "$auth" in
    admin)  hdr=(-H "Authorization: Bearer ${ADMIN_TOKEN}") ;;
    jwt:*)
      local p="${auth#jwt:}"
      if [ -z "${CS_JWT[$p]:-}" ]; then
        cs_login "$p" || true
      fi
      hdr=(-H "Authorization: Bearer ${CS_JWT[$p]:-invalid}") ;;
    basic:*)
      local p="${auth#basic:}"
      hdr=(-u "$(cs_user "$p"):$(cs_pass "$p")") ;;
    token:*)
      local v="${auth#token:}"
      hdr=(-H "Authorization: Bearer ${!v:-}") ;;
    basictoken:*)
      local rest="${auth#basictoken:}"
      local p="${rest%%:*}" v="${rest#*:}"
      hdr=(-u "$(cs_user "$p"):${!v:-}") ;;
    none) hdr=() ;;
    *) echo "cs_http: unknown auth spec '${auth}'" >&2; CS_STATUS="000"; CS_BODY=""; return 0 ;;
  esac
  local bf hf
  _cs_work
  bf="${CS_WORK}/last-body"; hf=$(mktemp)
  rm -f "$bf"
  CS_STATUS=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$bf" -D "$hf" -w '%{http_code}' \
    "${hdr[@]}" "$@" "$url" 2>/dev/null) || true
  [ -n "$CS_STATUS" ] || CS_STATUS="000"
  # CS_BODY is the text view (NUL bytes dropped); CS_BODY_FILE keeps the exact
  # bytes until the next cs_http, for checksum and Range comparisons.
  CS_BODY=$(tr -d '\000' < "$bf" 2>/dev/null || true)
  CS_BODY_FILE="$bf"
  CS_HEADERS=$(tr -d '\r' < "$hf" 2>/dev/null || true)
  rm -f "$hf"
  # auth names a persona or a variable, never a secret, so it is safe to log.
  CS_LAST_REQ="${method} ${path} as ${auth}"
  return 0
}

# cs_header NAME - value of a response header from the last cs_http (case-insensitive).
cs_header() {
  printf '%s\n' "$CS_HEADERS" | awk -v n="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" \
    'BEGIN{FS=": "} { k=tolower($1); if (k==n) { sub(/^[^:]*: /,""); v=$0 } } END{ if (v!="") print v }'
}

# cs_json FILTER - run jq FILTER over the last body ("" when it is not JSON).
cs_json() { printf '%s' "$CS_BODY" | jq -r "$1" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
# Every check prints PASS/FAIL (common.sh), lands in JUnit, and emits one
#   CHECK|company-sim/<role>|<what>|<PASS|FAIL|WARN|SKIP>|<note>
# line on stdout and in $COMPANY_SIM_STATE_DIR/checks/<role>.txt, in order.
#
# WARN is a JUnit pass with a CHECK WARN line: use it ONLY for a deviation
# already filed upstream (cite the issue in the note), never to soften an
# unexpected answer.

_cs_clean() { printf '%s' "$1" | tr '\n|' '  ' | cut -c1-300; }

_cs_emit() {
  local what="$1" res="$2" note="$3"
  local line
  line="CHECK|company-sim/${CS_ROLE}|$(_cs_clean "$what")|${res}|$(_cs_clean "$note")"
  echo "$line"
  echo "$line" >> "${COMPANY_SIM_STATE_DIR}/checks/${CS_ROLE}.txt"
}

# cs_record WHAT RESULT [NOTE] [BODY]
# Record an outcome you computed yourself. RESULT: PASS FAIL WARN SKIP.
# Always returns 0.
cs_record() {
  local what="$1" res="$2" note="${3:-}" body="${4:-}"
  begin_test "$what"
  case "$res" in
    PASS) pass ;;
    WARN) pass; echo "  WARN: ${note}" ;;
    SKIP) skip "${note:-skipped}" ;;
    *)    res=FAIL; fail "${note:-failed}" "$body" ;;
  esac
  _cs_emit "$what" "$res" "$note"
  return 0
}

# cs_expect WHAT EXPECTED [NOTE]
# Compare the last cs_http status with EXPECTED, a single code ("403") or a
# space-separated list ("200 201") ONLY where the product documents either
# answer for the same outcome. Pick exact codes (see the status-code guide in
# common.sh): "401 or 403" hides whether authn or authz is broken.
# Returns 0 on PASS and 1 on FAIL, so `if cs_expect ...; then <follow-up>`
# skips follow-ups that only make sense after a PASS. A bare call is safe:
# errexit is off (top of this file), so a FAIL never ends the role.
cs_expect() {
  local what="$1" expected="$2" note="${3:-}"
  local ok=false c
  for c in $expected; do
    [ "$CS_STATUS" = "$c" ] && ok=true
  done
  if $ok; then
    cs_record "$what" PASS "HTTP ${CS_STATUS}${note:+; ${note}}"
    return 0
  fi
  cs_record "$what" FAIL "expected HTTP ${expected}, got ${CS_STATUS} (${CS_LAST_REQ})${note:+; ${note}}" \
    "$(printf '%s' "$CS_BODY" | head -c 600)"
  return 1
}

# cs_expect_body WHAT NEEDLE - the last body contains NEEDLE.
cs_expect_body() {
  local what="$1" needle="$2"
  if printf '%s' "$CS_BODY" | grep -qF -- "$needle"; then
    cs_record "$what" PASS "HTTP ${CS_STATUS}; body has '${needle}'"
    return 0
  fi
  cs_record "$what" FAIL "body lacks '${needle}' (HTTP ${CS_STATUS}, ${CS_LAST_REQ})" \
    "$(printf '%s' "$CS_BODY" | head -c 600)"
  return 1
}

# cs_expect_no_body WHAT NEEDLE - the last body does NOT contain NEEDLE.
cs_expect_no_body() {
  local what="$1" needle="$2"
  if printf '%s' "$CS_BODY" | grep -qF -- "$needle"; then
    cs_record "$what" FAIL "body unexpectedly has '${needle}' (HTTP ${CS_STATUS}, ${CS_LAST_REQ})" \
      "$(printf '%s' "$CS_BODY" | head -c 600)"
    return 1
  fi
  cs_record "$what" PASS "HTTP ${CS_STATUS}; body has no '${needle}'"
  return 0
}

# cs_end - close the suite (writes JUnit, exits with the contract's code).
cs_end() { end_suite; }

# ---------------------------------------------------------------------------
# Barriers between parallel roles
# ---------------------------------------------------------------------------
# cs_signal NAME [OUTCOME] mark NAME as reached. The file holds
#                          "<epoch> <outcome>"; OUTCOME is one word the
#                          waiters act on (default "ok"), e.g. devops signals
#                          ops-image-pushed "none" when it pushed nothing.
# cs_signal_outcome NAME   the outcome word of this run's NAME ("" if none).
# cs_signalled NAME        true when NAME was signalled during this run.
# cs_wait NAME [SECONDS]   wait until NAME is signalled during this run
#                          (default CS_BARRIER_TIMEOUT, else 600 s). Returns 0
#                          when it arrived, 1 on timeout or when the
#                          signalling role exited without reaching it
#                          (outcome "failed"). CS_WAIT_WHY then says which, for
#                          the caller's FAIL ("waited for <barrier>: ...").
# cs_signals NAME...       declare the barriers this role signals. When the
#                          role exits (cs_end, an early cs_end after a failed
#                          sign-in, or a crash) every declared barrier it has
#                          not signalled this run is signalled "failed", so
#                          its waiters stop at once instead of timing out.
#
# "This run" starts at CS_RUN_START (epoch seconds). run-roles.sh sets it
# once, just before it launches the roles, and every role inherits it; a
# script started on its own gets the moment it sourced lib.sh. A signal file
# older than that is a leftover from an earlier run sharing the state dir
# (or from a concurrent `--only` run of another role) and does not count, so
# a barrier can never be satisfied by yesterday's signal.
CS_RUN_START="${CS_RUN_START:-$(date +%s)}"
export CS_RUN_START
cs_signal() {
  local out="${2:-ok}"
  printf '%s %s\n' "$(date +%s)" "$out" > "${COMPANY_SIM_STATE_DIR}/signals/$1"
  echo "  signal: $1 (${out})"
}
cs_signalled() {
  local ts f="${COMPANY_SIM_STATE_DIR}/signals/$1"
  [ -f "$f" ] || return 1
  read -r ts _ < "$f" || return 1
  case "$ts" in ''|*[!0-9]*) return 1 ;; esac
  [ "$ts" -ge "$CS_RUN_START" ]
}
cs_signal_outcome() {
  local ts out
  cs_signalled "$1" || return 0
  read -r ts out < "${COMPANY_SIM_STATE_DIR}/signals/$1" 2>/dev/null || true
  : "$ts"
  printf '%s' "${out:-ok}"
}
CS_WAIT_WHY=""
cs_wait() {
  local name="$1" limit="${2:-${CS_BARRIER_TIMEOUT:-600}}" waited=0
  CS_WAIT_WHY=""
  until cs_signalled "$name"; do
    if [ "$waited" -ge "$limit" ]; then
      CS_WAIT_WHY="barrier ${name} not signalled within ${limit}s"
      if [ -f "${COMPANY_SIM_STATE_DIR}/signals/${name}" ]; then
        CS_WAIT_WHY="${CS_WAIT_WHY} (only a stale signal from before ${CS_RUN_START})"
      fi
      echo "  wait: ${CS_WAIT_WHY}"
      return 1
    fi
    sleep 2; waited=$(( waited + 2 ))
  done
  if [ "$(cs_signal_outcome "$name")" = "failed" ]; then
    CS_WAIT_WHY="signaller exited before reaching ${name} (signal 'failed' after ${waited}s)"
    echo "  wait: ${CS_WAIT_WHY}"
    return 1
  fi
  echo "  wait: ${name} reached after ${waited}s ($(cs_signal_outcome "$name"))"
}
declare -ga CS_SIGNALS=()
cs_signals() {
  CS_SIGNALS+=("$@")
  if [ "${_CS_SIGNALS_TRAP:-0}" = 0 ]; then
    add_exit_handler _cs_release_signals
    _CS_SIGNALS_TRAP=1
  fi
}
_cs_release_signals() {
  local n
  for n in "${CS_SIGNALS[@]}"; do
    cs_signalled "$n" || cs_signal "$n" failed
  done
}
cs_reset_signals() { rm -f "${COMPANY_SIM_STATE_DIR}/signals/"* 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# personas.env
# ---------------------------------------------------------------------------
declare -gA CS_ENV=()
declare -ga CS_ENV_ORDER=()

# cs_env_set KEY VALUE - stage a personas.env entry (also exported now).
cs_env_set() {
  local k="$1" v="$2"
  [ -n "${CS_ENV[$k]+x}" ] || CS_ENV_ORDER+=("$k")
  CS_ENV[$k]="$v"
  printf -v "$k" '%s' "$v"
  export "${k?}"
}

# cs_env_write - write every staged entry to $PERSONAS_ENV (mode 600).
cs_env_write() {
  local tmp="${PERSONAS_ENV}.tmp" k
  {
    echo "# personas.env - written by 00-found-company.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# RUN_ID=${RUN_ID} BASE_URL=${BASE_URL}. Contains throwaway test credentials."
    for k in "${CS_ENV_ORDER[@]}"; do
      printf 'export %s=%q\n' "$k" "${CS_ENV[$k]}"
    done
  } > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$PERSONAS_ENV"
}

# ---------------------------------------------------------------------------
# Create-if-missing (admin). Each sets CS_ID and returns 0 on success, or
# returns 1 with CS_STATUS/CS_BODY describing the refusal. They converge an
# existing object to the founding state instead of failing on it, so the
# founder can be re-run against a namespace a previous run already used.
# ---------------------------------------------------------------------------
CS_ID=""

# cs_ensure_user USERNAME PASSWORD EMAIL DISPLAY_NAME IS_ADMIN(true|false)
cs_ensure_user() {
  local u="$1" pw="$2" email="$3" dn="$4" adm="$5"
  CS_ID=""
  cs_http GET "/api/v1/users?search=${u}&per_page=100" admin
  CS_ID=$(printf '%s' "$CS_BODY" | jq -r --arg u "$u" '.items[]? | select(.username==$u) | .id' 2>/dev/null | head -n1 || true)
  if [ -z "$CS_ID" ]; then
    cs_http POST /api/v1/users admin -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg u "$u" --arg p "$pw" --arg e "$email" --arg d "$dn" --argjson a "$adm" \
            '{username:$u,password:$p,email:$e,display_name:$d,is_admin:$a}')"
    CS_ID=$(cs_json '.user.id // .id // empty')
    [ -n "$CS_ID" ] || return 1
    return 0
  fi
  # Converge: active, admin flag, display name.
  cs_http PATCH "/api/v1/users/${CS_ID}" admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg d "$dn" --argjson a "$adm" '{display_name:$d,is_admin:$a,is_active:true}')"
  [ "${CS_STATUS:0:1}" = "2" ] || return 1
  # Converge the password when a previous run (or a role) changed it.
  local keep_id="$CS_ID"
  cs_http POST /api/v1/auth/login none -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$u" --arg p "$pw" '{username:$u,password:$p}')"
  if [ "$CS_STATUS" != "200" ]; then
    cs_http POST "/api/v1/users/${keep_id}/password" admin -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg p "$pw" '{new_password:$p}')"
    [ "${CS_STATUS:0:1}" = "2" ] || { CS_ID="$keep_id"; return 1; }
  fi
  CS_ID="$keep_id"
  return 0
}

# cs_ensure_group NAME DESCRIPTION
cs_ensure_group() {
  local n="$1" d="$2"
  cs_http GET "/api/v1/groups?search=${n}&per_page=100" admin
  CS_ID=$(printf '%s' "$CS_BODY" | jq -r --arg n "$n" '.items[]? | select(.name==$n) | .id' 2>/dev/null | head -n1 || true)
  [ -n "$CS_ID" ] && return 0
  cs_http POST /api/v1/groups admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg n "$n" --arg d "$d" '{name:$n,description:$d}')"
  CS_ID=$(cs_json '.id // empty')
  [ -n "$CS_ID" ]
}

# cs_set_group_members GROUP_ID USER_ID... - make the membership exactly this set.
cs_set_group_members() {
  local gid="$1"; shift
  local want_json have_json extra add
  want_json=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
  cs_http GET "/api/v1/groups/${gid}?member_limit=200" admin
  have_json=$(printf '%s' "$CS_BODY" | jq -c '[.members[]?.user_id]' 2>/dev/null || echo '[]')
  add=$(jq -nc --argjson w "$want_json" --argjson h "$have_json" '$w - $h')
  extra=$(jq -nc --argjson w "$want_json" --argjson h "$have_json" '$h - $w')
  if [ "$add" != "[]" ]; then
    cs_http POST "/api/v1/groups/${gid}/members" admin -H 'Content-Type: application/json' \
      -d "$(jq -nc --argjson ids "$add" '{user_ids:$ids}')"
    [ "${CS_STATUS:0:1}" = "2" ] || return 1
  fi
  if [ "$extra" != "[]" ]; then
    cs_http DELETE "/api/v1/groups/${gid}/members" admin -H 'Content-Type: application/json' \
      -d "$(jq -nc --argjson ids "$extra" '{user_ids:$ids}')"
    [ "${CS_STATUS:0:1}" = "2" ] || return 1
  fi
  CS_ID="$gid"
  return 0
}

# cs_ensure_project KEY NAME DESCRIPTION
cs_ensure_project() {
  local k="$1" n="$2" d="$3"
  cs_http GET "/api/v1/projects" admin
  CS_ID=$(printf '%s' "$CS_BODY" | jq -r --arg k "$k" '(if type=="array" then . else (.items // []) end)[]? | select(.key==$k) | .id' 2>/dev/null | head -n1 || true)
  [ -n "$CS_ID" ] && return 0
  cs_http POST /api/v1/projects admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$k" --arg n "$n" --arg d "$d" '{key:$k,name:$n,description:$d}')"
  CS_ID=$(cs_json '.id // empty')
  [ -n "$CS_ID" ]
}

# cs_ensure_project_member PROJECT_ID PRINCIPAL_TYPE PRINCIPAL_ID ACTIONS_JSON
# POST /projects/{id}/members is an upsert on (principal, project).
cs_ensure_project_member() {
  local pid="$1" pt="$2" prid="$3" acts="$4"
  cs_http POST "/api/v1/projects/${pid}/members" admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$pt" --arg i "$prid" --argjson a "$acts" '{principal_type:$t,principal_id:$i,actions:$a}')"
  [ "${CS_STATUS:0:1}" = "2" ]
}

# cs_ensure_repo KEY FORMAT TYPE VISIBILITY PROJECT_ID [UPSTREAM_URL]
# PROJECT_ID may be "" (unassigned).
cs_ensure_repo() {
  local k="$1" f="$2" t="$3" vis="$4" pid="$5" up="${6:-}"
  cs_http GET "/api/v1/repositories/${k}" admin
  if [ "$CS_STATUS" = "200" ]; then
    CS_ID=$(cs_json '.id // empty')
    local have_vis have_pid
    have_vis=$(cs_json '.visibility // empty')
    have_pid=$(cs_json '.project_id // empty')
    if [ "$have_vis" != "$vis" ] || [ "$have_pid" != "$pid" ]; then
      local body
      if [ -n "$pid" ]; then
        body=$(jq -nc --arg v "$vis" --arg p "$pid" '{visibility:$v,project_id:$p}')
      else
        body=$(jq -nc --arg v "$vis" '{visibility:$v}')
      fi
      cs_http PATCH "/api/v1/repositories/${k}" admin -H 'Content-Type: application/json' -d "$body"
      [ "${CS_STATUS:0:1}" = "2" ] || return 1
    fi
    return 0
  fi
  local body
  body=$(jq -nc --arg k "$k" --arg f "$f" --arg t "$t" --arg v "$vis" --arg p "$pid" --arg u "$up" \
    '{key:$k,name:$k,format:$f,repo_type:$t,visibility:$v}
     + (if $p != "" then {project_id:$p} else {} end)
     + (if $u != "" then {upstream_url:$u} else {} end)')
  cs_http POST /api/v1/repositories admin -H 'Content-Type: application/json' -d "$body"
  CS_ID=$(cs_json '.id // empty')
  [ -n "$CS_ID" ]
}

# cs_ensure_virtual_member VIRTUAL_KEY MEMBER_KEY PRIORITY
cs_ensure_virtual_member() {
  local v="$1" m="$2" prio="$3"
  cs_http GET "/api/v1/repositories/${v}/members" admin
  if printf '%s' "$CS_BODY" | jq -e --arg m "$m" \
      '(.members // .items // [])[]? | select(.member_repo_key==$m)' >/dev/null 2>&1; then
    return 0
  fi
  cs_http POST "/api/v1/repositories/${v}/members" admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg m "$m" --argjson p "$prio" '{member_key:$m,priority:$p}')"
  [ "${CS_STATUS:0:1}" = "2" ]
}

# cs_ensure_grant PRINCIPAL_TYPE PRINCIPAL_ID TARGET_TYPE TARGET_ID ACTIONS_JSON
# Fine-grained rule via /api/v1/permissions; converges the action list.
cs_ensure_grant() {
  local pt="$1" prid="$2" tt="$3" tid="$4" acts="$5"
  cs_http GET "/api/v1/permissions?principal_type=${pt}&principal_id=${prid}&target_type=${tt}&target_id=${tid}&per_page=100" admin
  local rid have
  rid=$(cs_json '.items[0].id // empty')
  have=$(cs_json '.items[0].actions // [] | sort | tostring')
  local want
  want=$(jq -nc --argjson a "$acts" '$a | sort | tostring')
  local body
  body=$(jq -nc --arg pt "$pt" --arg pi "$prid" --arg tt "$tt" --arg ti "$tid" --argjson a "$acts" \
    '{principal_type:$pt,principal_id:$pi,target_type:$tt,target_id:$ti,actions:$a}')
  if [ -z "$rid" ]; then
    cs_http POST /api/v1/permissions admin -H 'Content-Type: application/json' -d "$body"
    CS_ID=$(cs_json '.id // empty')
    [ -n "$CS_ID" ]
    return
  fi
  CS_ID="$rid"
  if [ "$have" != "$want" ]; then
    cs_http PUT "/api/v1/permissions/${rid}" admin -H 'Content-Type: application/json' -d "$body"
    [ "${CS_STATUS:0:1}" = "2" ] || return 1
  fi
  return 0
}

# cs_ensure_service_account NAME DESCRIPTION  (the account is "svc-NAME")
cs_ensure_service_account() {
  local n="$1" d="$2"
  cs_http GET /api/v1/service-accounts admin
  CS_ID=$(printf '%s' "$CS_BODY" | jq -r --arg u "svc-${n}" '(if type=="array" then . else (.items // []) end)[]? | select(.username==$u) | .id' 2>/dev/null | head -n1 || true)
  if [ -n "$CS_ID" ]; then
    local keep="$CS_ID"
    cs_http PATCH "/api/v1/service-accounts/${keep}" admin -H 'Content-Type: application/json' -d '{"is_active":true}'
    CS_ID="$keep"
    return 0
  fi
  cs_http POST /api/v1/service-accounts admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg n "$n" --arg d "$d" '{name:$n,description:$d}')"
  CS_ID=$(cs_json '.id // empty')
  [ -n "$CS_ID" ]
}

# cs_mint_sa_token SA_ID NAME SCOPES_JSON REPO_IDS_JSON
# Revokes any token of the same name first (a token is shown once, so a
# re-run cannot recover the old secret). Sets CS_TOKEN.
CS_TOKEN=""
cs_mint_sa_token() {
  local sa="$1" n="$2" scopes="$3" repos="$4" tid
  CS_TOKEN=""
  cs_http GET "/api/v1/service-accounts/${sa}/tokens" admin
  for tid in $(printf '%s' "$CS_BODY" | jq -r --arg n "$n" '(if type=="array" then . else (.items // []) end)[]? | select(.name==$n and (.is_revoked|not)) | .id' 2>/dev/null || true); do
    cs_http DELETE "/api/v1/service-accounts/${sa}/tokens/${tid}" admin
  done
  cs_http POST "/api/v1/service-accounts/${sa}/tokens" admin -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg n "$n" --argjson s "$scopes" --argjson r "$repos" \
          '{name:$n,scopes:$s,repository_ids:$r,expires_in_days:30}')"
  CS_TOKEN=$(cs_json '.token // empty')
  [ -n "$CS_TOKEN" ]
}

# cs_mint_user_token PERSONA NAME SCOPES_JSON
# The persona mints its own token through /api/v1/users/me/tokens (the
# self-service path a developer uses). Revokes same-named tokens first.
cs_mint_user_token() {
  local p="$1" n="$2" scopes="$3" tid
  CS_TOKEN=""
  cs_http GET /api/v1/users/me/tokens "jwt:${p}"
  for tid in $(printf '%s' "$CS_BODY" | jq -r --arg n "$n" '(if type=="array" then . else (.items // []) end)[]? | select(.name==$n) | .id' 2>/dev/null || true); do
    cs_http DELETE "/api/v1/users/me/tokens/${tid}" "jwt:${p}"
  done
  cs_http POST /api/v1/users/me/tokens "jwt:${p}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg n "$n" --argjson s "$scopes" '{name:$n,scopes:$s,expires_in_days:30}')"
  CS_TOKEN=$(cs_json '.token // empty')
  [ -n "$CS_TOKEN" ]
}

# ---------------------------------------------------------------------------
# Wire-protocol publish helpers
# ---------------------------------------------------------------------------
# Protocol-level publishes with curl, so a role does not need cargo, npm,
# twine or mvn installed. Each takes an AUTH spec (see cs_http) and leaves
# the answer in CS_STATUS/CS_BODY. Builders write into $CS_WORK (a per-run
# scratch dir removed on exit).

CS_WORK=""
_cs_work() {
  if [ -z "$CS_WORK" ]; then
    CS_WORK=$(mktemp -d)
    add_exit_handler "rm -rf \"$CS_WORK\""
  fi
}

# cs_publish_cargo REPO_KEY CRATE VERSION AUTH
# PUT /cargo/<key>/api/v1/crates/new with the cargo publish wire layout:
# u32le(json len) json u32le(crate len) .crate(tar.gz).
cs_publish_cargo() {
  local key="$1" name="$2" ver="$3" auth="$4"
  _cs_work
  local out="${CS_WORK}/${name}-${ver}.publish"
  python3 -I - "$name" "$ver" "$out" <<'PY'
import gzip, io, json, sys, tarfile
name, ver, out = sys.argv[1], sys.argv[2], sys.argv[3]
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
    for p, data in ((f"{name}-{ver}/Cargo.toml",
                     f'[package]\nname = "{name}"\nversion = "{ver}"\nedition = "2021"\nlicense = "MIT"\ndescription = "Halcyon Robotics"\n'.encode()),
                    (f"{name}-{ver}/src/lib.rs", b"pub fn halcyon() -> u32 { 42 }\n")):
        ti = tarfile.TarInfo(p); ti.size = len(data); ti.mtime = 1700000000
        t.addfile(ti, io.BytesIO(data))
crate = gzip.compress(buf.getvalue(), mtime=0)
meta = json.dumps({"name": name, "vers": ver, "deps": [], "features": {}, "authors": ["Halcyon Robotics"],
                   "description": "Halcyon Robotics", "license": "MIT", "keywords": [], "categories": [],
                   "links": None, "readme": None, "readme_file": None, "homepage": None,
                   "documentation": None, "repository": None, "badges": {}, "license_file": None}).encode()
open(out, "wb").write(len(meta).to_bytes(4, "little") + meta + len(crate).to_bytes(4, "little") + crate)
PY
  cs_http PUT "/cargo/${key}/api/v1/crates/new" "$auth" \
    -H 'Content-Type: application/octet-stream' --data-binary "@${out}"
}

# cs_publish_npm REPO_KEY PACKAGE VERSION AUTH
# PUT /npm/<key>/<package> with the npm publish document (tarball attached).
cs_publish_npm() {
  local key="$1" name="$2" ver="$3" auth="$4"
  _cs_work
  local out="${CS_WORK}/${name//\//_}-${ver}.json"
  python3 -I - "$name" "$ver" "$BASE_URL" "$key" "$out" <<'PY'
import base64, gzip, io, json, sys, tarfile
name, ver, base, key, out = sys.argv[1:6]
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
    for p, data in (("package/package.json", json.dumps({"name": name, "version": ver, "main": "index.js"}).encode()),
                    ("package/index.js", b"module.exports = 'halcyon';\n")):
        ti = tarfile.TarInfo(p); ti.size = len(data); ti.mtime = 1700000000
        t.addfile(ti, io.BytesIO(data))
tb = gzip.compress(buf.getvalue(), mtime=0)
short = name.split("/")[-1]
doc = {"_id": name, "name": name, "dist-tags": {"latest": ver},
       "versions": {ver: {"name": name, "version": ver, "main": "index.js", "license": "MIT",
                          "dist": {"tarball": f"{base}/npm/{key}/{name}/-/{short}-{ver}.tgz"}}},
       "_attachments": {f"{short}-{ver}.tgz": {"content_type": "application/octet-stream",
                        "data": base64.b64encode(tb).decode(), "length": len(tb)}}}
json.dump(doc, open(out, "w"))
PY
  cs_http PUT "/npm/${key}/${name}" "$auth" -H 'Content-Type: application/json' --data-binary "@${out}"
}

# cs_publish_pypi REPO_KEY PROJECT VERSION AUTH
# POST /pypi/<key>/ multipart, the way twine uploads an sdist.
cs_publish_pypi() {
  local key="$1" name="$2" ver="$3" auth="$4"
  _cs_work
  local norm="${name//-/_}"
  local dir="${CS_WORK}/${norm}-${ver}"
  mkdir -p "$dir"
  printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: Halcyon Robotics\n' "$name" "$ver" > "${dir}/PKG-INFO"
  printf 'from setuptools import setup\nsetup()\n' > "${dir}/setup.py"
  local sd="${CS_WORK}/${norm}-${ver}.tar.gz"
  tar -C "$CS_WORK" --sort=name --mtime=@1700000000 --owner=0 --group=0 --numeric-owner \
    --mode='u=rw,go=r,a+X' --format=ustar -cf - "${norm}-${ver}" | gzip -n > "$sd"
  local sha
  sha=$(sha256sum "$sd" | cut -d' ' -f1)
  cs_http POST "/pypi/${key}/" "$auth" \
    -F ":action=file_upload" -F "name=${name}" -F "version=${ver}" \
    -F "sha256_digest=${sha}" -F "filetype=sdist" -F "metadata_version=2.1" -F "protocol_version=1" \
    -F "content=@${sd};filename=$(basename "$sd")"
}

# cs_put_maven REPO_KEY GROUP_PATH ARTIFACT VERSION AUTH
# PUT the .pom and .jar of GROUP_PATH/ARTIFACT/VERSION (GROUP_PATH uses '/').
# CS_STATUS is the jar's answer; CS_POM_STATUS the pom's.
CS_POM_STATUS=""
cs_put_maven() {
  local key="$1" g="$2" a="$3" v="$4" auth="$5"
  _cs_work
  local base="/maven/${key}/${g}/${a}/${v}/${a}-${v}"
  local gid="${g//\//.}"
  printf '<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><packaging>jar</packaging></project>' \
    "$gid" "$a" "$v" > "${CS_WORK}/${a}-${v}.pom"
  printf 'PK-halcyon-%s-%s\n' "$a" "$v" > "${CS_WORK}/${a}-${v}.jar"
  cs_http PUT "${base}.pom" "$auth" -H 'Content-Type: application/octet-stream' --data-binary "@${CS_WORK}/${a}-${v}.pom"
  CS_POM_STATUS="$CS_STATUS"
  cs_http PUT "${base}.jar" "$auth" -H 'Content-Type: application/octet-stream' --data-binary "@${CS_WORK}/${a}-${v}.jar"
}

# cs_put_generic REPO_KEY PATH FILE AUTH
# PUT /api/v1/repositories/<key>/artifacts/<path> (the REST upload route).
cs_put_generic() {
  local key="$1" p="$2" f="$3" auth="$4"
  cs_http PUT "/api/v1/repositories/${key}/artifacts/${p}" "$auth" \
    -H 'Content-Type: application/octet-stream' --data-binary "@${f}"
}

# cs_fixture_bytes FILE SIZE SEED - deterministic pseudo-random file, so a
# Range check can compare exact bytes across runs.
cs_fixture_bytes() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import hashlib, sys
out, size, seed = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
b, i = bytearray(), 0
while len(b) < size:
    b += hashlib.sha256(seed + i.to_bytes(8, "little")).digest(); i += 1
open(out, "wb").write(bytes(b[:size]))
PY
}
