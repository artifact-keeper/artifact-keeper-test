#!/usr/bin/env bash
# =============================================================================
# tiers/curation-ascii-lookalikes-upgrade/oracle.sh
#   artifact-keeper#5840: an existing block_typosquat rule keeps refusing an
#   all-ASCII lookalike after the 1.13 upgrade; a new rule flags it.
# See the manifest for the phases and the cases.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# BACKEND_IMAGE, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"
: "${BACKEND_IMAGE:?candidate image (run.sh exports it from --backend-image)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=/dev/null
source "${HERE}/manifest"
export RATE_LIMIT_ENABLED

CAND_IMAGE="$BACKEND_IMAGE"
OLD_IMAGE="${UPGRADE_OLD_IMAGE:?manifest must set UPGRADE_OLD_IMAGE}"
PROJECT="ak-dtf${DTF_SLOT}"
COMPOSE=(-f "${DTF_DIR}/compose.base.yml")
for p in $PROFILES; do COMPOSE+=(-f "${DTF_DIR}/profiles/${p}.yml"); done
ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
MOCK="http://172.16.${DTF_SLOT}.90"
SUF="${RUN_ID##*-}-$$"
OLD_R="dtf-asclu-old-${SUF}"
NEW_R="dtf-asclu-new-${SUF}"
# Cyrillic а (U+0430, UTF-8 D0 B0) for the first `a` of paypal.
UNI_ENC="p%D0%B0ypal"

setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$1" 2>/dev/null || true; }
compose() { docker compose -p "$PROJECT" "${COMPOSE[@]}" "$@"; }
login() {
  curl -s --max-time 30 -X POST "$BASE_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMPASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty'
}
wait_health() { # <tries x 3 s>
  for _ in $(seq 1 "$1"); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/health" 2>/dev/null)" = "200" ] && return 0
    sleep 3
  done
  return 1
}
api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
tarball() { # <repo> <encoded name> -> HTTP code, body in $W/tgz.out
  curl -s -o "$W/tgz.out" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
    "${BASE_URL}/npm/$1/$2/-/$2-1.0.0.tgz" 2>/dev/null || echo 000
}
blocked() { [ "$(jqr '.error // empty' < "$W/tgz.out")" = "curation_blocked" ]; }
ERR=""
need2xx() { case "$1" in 2??) ;; *) ERR="${ERR} $2: HTTP $1 $(head -c 200 "$W/api.json");" ;; esac; }
remote_with_rule() { # <key> [extra config JSON] -> rule id in $W/rule-<key>.id
  local id cfg none='{}'
  local extra="${2:-$none}"
  need2xx "$(api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg u "${MOCK}/$1" \
    '{key:$k,name:$k,format:"npm",repo_type:"remote",is_public:false,upstream_url:$u}')")" "create $1"
  need2xx "$(api PATCH "/api/v1/repositories/$1" '{"curation_enabled":true,"curation_default_action":"allow"}')" "curation on $1"
  api GET "/api/v1/repositories/$1" >/dev/null; id="$(jqr '.id // empty' < "$W/api.json")"
  cfg="$(jq -nc --argjson x "$extra" '{download_name_checks:true,block_typosquat:true,popular_packages:["paypal"]} + $x')"
  need2xx "$(api POST /api/v1/curation/rules "$(jq -nc --arg r "$id" --argjson c "$cfg" \
    '{staging_repo_id:$r,rule_type:"popularity",action:"block",priority:10,reason:"dtf #5840",config:$c}')")" "rule on $1"
  jqr '.id // empty' < "$W/api.json" > "$W/rule-$1.id"
}

begin_suite "curation-ascii-lookalikes-upgrade"

# =============================================================================
# PHASE 1: the old release writes the rule.
# =============================================================================
echo "== PHASE 1: ${OLD_IMAGE} =="
compose down -v >/dev/null 2>&1
BACKEND_IMAGE="$OLD_IMAGE" compose up -d --wait >/dev/null 2>&1 || true
begin_test "setup (${OLD_IMAGE##*:}): npm Remote with a block_typosquat popularity rule that refuses paypa1"
if ! wait_health 80; then infra_fail "the old image did not become healthy"; end_suite; fi
TOK="$(login)"
[ -n "$TOK" ] || { infra_fail "admin login failed on the old image"; end_suite; }
remote_with_rule "$OLD_R"
st_old="$(tarball "$OLD_R" paypa1)"; b_old=0; blocked && b_old=1
if [ -n "$ERR" ]; then infra_fail "$ERR"; end_suite; fi
if [ "$st_old" = "403" ] && [ "$b_old" = "1" ]; then pass
else infra_fail "the old image did not refuse paypa1 (HTTP ${st_old}); wrong UPGRADE_OLD_IMAGE?"; end_suite; fi

# =============================================================================
# PHASE 2: the candidate on the same volume and database.
# =============================================================================
echo "== PHASE 2: ${CAND_IMAGE} =="
BACKEND_IMAGE="$CAND_IMAGE" compose up -d --no-deps --force-recreate --wait backend >/dev/null 2>&1 || true
begin_test "POST-UPGRADE: the candidate is healthy on the 1.12 database"
if wait_health 80 && TOK="$(login)" && [ -n "$TOK" ]; then pass
else fail "candidate not healthy or no admin login after the upgrade"; end_suite; fi

api GET "/api/v1/curation/rules/$(cat "$W/rule-${OLD_R}.id")" >/dev/null
stamp="$(jqr '.config.ascii_lookalikes // empty' < "$W/api.json")"
st="$(tarball "$OLD_R" paypa1)"; b=0; blocked && b=1
begin_test "FIX #5840: the rule written before the upgrade keeps ascii_lookalikes \"block\" and still refuses paypa1 (403)"
if [ "$st" = "403" ] && [ "$b" = "1" ] && [ "$stamp" = "block" ]; then pass
else fail "HTTP ${st} (blocked=${b}), config.ascii_lookalikes='${stamp}'; want 403 curation_blocked and \"block\""; fi

ERR=""
remote_with_rule "$NEW_R"
st="$(tarball "$NEW_R" paypa1)"; b=0; blocked && b=1
begin_test "FIX #5840: a rule written after the upgrade (no ascii_lookalikes) flags paypa1 instead of refusing it"
if [ -z "$ERR" ] && [ "$st" != "403" ] && [ "$b" = "0" ]; then pass
else fail "setup:${ERR:- ok}; HTTP ${st} (blocked=${b}); want anything but 403 curation_blocked"; fi

s1="$(tarball "$OLD_R" "$UNI_ENC")"; b1=0; blocked && b1=1
s2="$(tarball "$NEW_R" "$UNI_ENC")"; b2=0; blocked && b2=1
begin_test "CONTROL: on both Remotes the Cyrillic lookalike of paypal is refused (403 curation_blocked)"
if [ "$s1$b1$s2$b2" = "40314031" ]; then pass
else fail "old rule: HTTP ${s1} (blocked=${b1}); new rule: HTTP ${s2} (blocked=${b2})"; fi

api GET "/api/v1/repositories/${NEW_R}" >/dev/null; rid="$(jqr '.id // empty' < "$W/api.json")"
c="$(api POST /api/v1/curation/rules "$(jq -nc --arg r "$rid" \
  '{staging_repo_id:$r,rule_type:"popularity",action:"block",priority:20,reason:"dtf #5840 bad",config:{block_typosquat:true,ascii_lookalikes:"Block"}}')")"
begin_test "FIX #5840: ascii_lookalikes takes only \"block\" or \"flag\" (\"Block\" is a 400)"
if [ "$c" = "400" ]; then pass; else fail "HTTP ${c}: $(head -c 200 "$W/api.json")"; fi

end_suite
