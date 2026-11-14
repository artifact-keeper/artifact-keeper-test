#!/usr/bin/env bash
# =============================================================================
# tiers/curation-popularity-download-checks/oracle.sh
#   artifact-keeper#5274 (PR #5275): opted-in `popularity` name checks on npm
#   Remote/Virtual downloads; rules without the opt-in change nothing.
# See the manifest for the topology and the cases.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
MOCK="http://172.16.${DTF_SLOT}.90"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-npm"
ON="dtf-popdl-on-${SUF}"
VON="dtf-popdl-von-${SUF}"
OFF="dtf-popdl-off-${SUF}"
NONE="dtf-popdl-none-${SUF}"
PKG="dtf-held"
# Cyrillic о (U+043E, UTF-8 D0 BE) for the `o` of the popular name dtf-hold.
HOMO_ENC="dtf-h%D0%BEld"

api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
# tarball <repo> <encoded name> -> HTTP code, body in $W/tgz.out
tarball() {
  curl -s -o "$W/tgz.out" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
    "${BASE_URL}/npm/$1/$2/-/$2-1.0.0.tgz" 2>/dev/null || echo 000
}
blocked() { # body of the last tarball() is the curation_blocked error
  [ "$(jq -r '.error // empty' "$W/tgz.out" 2>/dev/null || true)" = "curation_blocked" ]
}
backend_log() { docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$W/backend.log" || true; }
# flag_lines <repo key> -> number of flag lines for that repository and PKG
flag_lines() {
  grep 'curation flagged a proxy download' "$W/backend.log" | grep -F "$1" | grep -cF "$PKG" || true
}

begin_suite "curation-popularity-download-checks"

begin_test "setup: npm Remotes ON, OFF and NONE, Virtual VON over NONE, popularity rules"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at ${BASE_URL}"; end_suite; fi
RULES=()
cleanup() {
  local r
  for r in "${RULES[@]}"; do api DELETE "/api/v1/curation/rules/${r}" >/dev/null || true; done
  for r in "$VON" "$ON" "$OFF" "$NONE"; do api DELETE "/api/v1/repositories/${r}" >/dev/null || true; done
}
add_exit_handler "cleanup"
ERR=""
need2xx() { case "$1" in 2??) ;; *) ERR="${ERR} $2: HTTP $1 $(head -c 200 "$W/api.json");" ;; esac; }
mk() { # <key> <type> [upstream]
  need2xx "$(api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"npm",repo_type:$t,is_public:false} + (if $u != "" then {upstream_url:$u} else {} end)')")" "create $1"
}
curate() { # <key>
  need2xx "$(api PATCH "/api/v1/repositories/$1" '{"curation_enabled":true,"curation_default_action":"allow"}')" "curation on $1"
}
repo_id() { api GET "/api/v1/repositories/$1" >/dev/null; jq -r '.id // empty' "$W/api.json" 2>/dev/null || true; }
# rule <repo key> <opt-in true|false> -> saves the response as $W/rule-<key>.json
rule() {
  local id cfg
  id="$(repo_id "$1")"
  cfg='{"block_typosquat":true,"popular_packages":["dtf-hold"]}'
  [ "$2" = "true" ] && cfg='{"block_typosquat":true,"download_name_checks":true,"popular_packages":["dtf-hold"]}'
  need2xx "$(api POST /api/v1/curation/rules "$(jq -nc --arg r "$id" --argjson c "$cfg" \
    '{staging_repo_id:$r,rule_type:"popularity",action:"block",priority:10,reason:"dtf #5274 popularity",config:$c}')")" "rule on $1"
  cp "$W/api.json" "$W/rule-$1.json"
  local rid; rid="$(jq -r '.id // empty' "$W/api.json" 2>/dev/null || true)"
  [ -n "$rid" ] && RULES+=("$rid")
}
mk "$ON" remote "${MOCK}/on"
mk "$OFF" remote "${MOCK}/off"
mk "$NONE" remote "${MOCK}/none"
mk "$VON" virtual
need2xx "$(api POST "/api/v1/repositories/${VON}/members" "$(jq -nc --arg m "$NONE" '{member_key:$m}')")" "member of ${VON}"
curate "$ON"; curate "$OFF"; curate "$VON"
rule "$ON" true; rule "$VON" true; rule "$OFF" false
if [ -z "$ERR" ]; then pass; else infra_fail "$ERR"; end_suite; fi

# --- opted in ---------------------------------------------------------------------
st="$(tarball "$ON" "$HOMO_ENC")"
begin_test "FIX #5274: opted-in Remote refuses a homoglyph of a popular name (403 curation_blocked)"
if [ "$st" = "403" ] && blocked; then pass
else fail "HTTP ${st}, want 403 curation_blocked" "$(head -c 300 "$W/tgz.out" 2>/dev/null)"; fi

begin_test "FIX #5274: the refused homoglyph never reached the upstream"
seen="$(docker logs "$MOCK_CTR" 2>&1 | grep -c "^MOCKNPM GET /on/dtf-h" | tr -d ' ' || true)"
odd="$(docker logs "$MOCK_CTR" 2>&1 | grep "^MOCKNPM GET /on/" | grep -vc "/on/${PKG}" | tr -d ' ' || true)"
if [ "$st" = "403" ] && [ "${odd:-0}" = "0" ]; then pass
else fail "status ${st}; mock saw ${odd:-?} non-${PKG} request(s) under /on (all /on/dtf-h*: ${seen:-?})"; fi

st="$(tarball "$ON" "$PKG")"
backend_log
n="$(flag_lines "$ON")"
begin_test "FIX #5274: opted-in Remote serves an edit-distance match and logs the flag"
if [ "$st" = "200" ] && [ "${n:-0}" -ge 1 ]; then pass
else fail "HTTP ${st}, ${n:-0} flag line(s) for ${ON}/${PKG}; want 200 and at least one" \
  "$(grep 'curation' "$W/backend.log" | tail -5)"; fi

st="$(tarball "$VON" "$HOMO_ENC")"
begin_test "FIX #5274: opted-in Virtual refuses the homoglyph (403 curation_blocked)"
if [ "$st" = "403" ] && blocked; then pass
else fail "HTTP ${st}, want 403 curation_blocked" "$(head -c 300 "$W/tgz.out" 2>/dev/null)"; fi

begin_test "FIX #5274: a rule without download_name_checks on a Remote gets a create warning"
w_off="$(jq -r '(.warnings // []) | join(" | ")' "$W/rule-${OFF}.json" 2>/dev/null || true)"
w_on="$(jq -r '(.warnings // []) | length' "$W/rule-${ON}.json" 2>/dev/null || echo x)"
if printf '%s' "$w_off" | grep -q 'download_name_checks' && [ "$w_on" = "0" ]; then pass
else fail "OFF warnings='${w_off}', ON warning count=${w_on}; want a download_name_checks warning on OFF only"; fi

# --- not opted in / no curation: unchanged ----------------------------------------
st="$(tarball "$OFF" "$PKG")"
st_h="$(tarball "$OFF" "$HOMO_ENC")"; b_h=0; blocked && b_h=1
backend_log
n="$(flag_lines "$OFF")"
begin_test "CONTROL: a rule without download_name_checks changes no download (serves, no 403, no flag line)"
if [ "$st" = "200" ] && [ "$st_h" != "403" ] && [ "$b_h" = "0" ] && [ "${n:-0}" = "0" ]; then pass
else fail "${PKG}: HTTP ${st}; homoglyph: HTTP ${st_h} (blocked=${b_h}); flag lines for ${OFF}: ${n:-?}"; fi

st="$(tarball "$NONE" "$PKG")"
st_h="$(tarball "$NONE" "$HOMO_ENC")"
begin_test "CONTROL: a Remote with curation off serves the package and does not 403 the homoglyph"
if [ "$st" = "200" ] && [ "$st_h" != "403" ]; then pass
else fail "${PKG}: HTTP ${st}; homoglyph: HTTP ${st_h}"; fi

end_suite
