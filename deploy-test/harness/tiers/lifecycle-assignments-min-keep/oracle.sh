#!/usr/bin/env bash
# =============================================================================
# tiers/lifecycle-assignments-min-keep/oracle.sh
#   1.11.0 lifecycle policy features and fixes: explicit repository
#   assignments (#3794), min_keep / match.path_prefix / match.version_pattern /
#   composite (#2024, #4456), "enabled": false honoured (#3869), a policy that
#   cannot reclaim anything in a non-OCI Remote is 422 (#3734), and the regex
#   validation family (#4461, #4502, #4504).
# See the manifest for the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# http <method> <path> <outfile> [curl args...] -> HTTP code (admin bearer)
http(){
  local m="$1" u="$2" o="$3"
  shift 3
  rm -f "$o"
  curl -s --max-time 60 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $TOK" "$@" "$BASE$u" || true
  [ -f "$o" ] || : > "$o"
}
body(){ head -c 400 "$1" 2>/dev/null | tr -d '\n' || true; }
post_json(){ http POST "$1" "$2" -H 'Content-Type: application/json' -d "$3"; }

# Every policy this oracle creates is deleted at the end of its case (and on
# exit), so execute-all in a later case only sees that case's policy. On
# 1.10.0 a policy without repository_id is GLOBAL and "enabled": false is
# ignored, so a leftover would delete in every later case.
POLICIES=()
policy_cleanup(){ local p; for p in "${POLICIES[@]:-}"; do [ -n "$p" ] && http DELETE "/api/v1/admin/lifecycle/$p" "$W/del" >/dev/null; done; POLICIES=(); }
trap policy_cleanup EXIT
mkpol(){ # <json body> -> sets PCODE, PID (empty on failure); response in $W/pol
  PCODE="$(post_json /api/v1/admin/lifecycle "$W/pol" "$1")"
  PID="$(jqr '.id // empty' < "$W/pol")"
  [ -n "$PID" ] && POLICIES+=("$PID")
  return 0
}

mkrepo(){ # <key> [format] [repo_type] [upstream] -> id
  local extra='{}'
  [ -n "${4:-}" ] && extra="$(jq -nc --arg u "$4" '{upstream_url:$u}')"
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "${2:-generic}" --arg t "${3:-local}" --argjson x "$extra" '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + $x')" \
    | jqr '.id // empty'
}
# put_ver <repo> <path> : upload a small unique generic file
put_ver(){
  printf '%s %s %s\n' "$1" "$2" "$RANDOM$RANDOM" > "$W/up.bin"
  curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$W/up.bin" "$BASE/api/v1/repositories/$1/artifacts/$2" || true
}
# age <repo> <path> <days> : backdate created_at (the max-age clock of a non-OCI artifact)
age(){ psql_x "UPDATE artifacts a SET created_at = NOW() - make_interval(days => $3) FROM repositories r WHERE r.id=a.repository_id AND r.key='$1' AND a.path='$2';"; }
live(){ # <repo> [path prefix] -> number of live artifacts
  psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.is_deleted=false AND a.path LIKE '${2:-}%';"
}
live_paths(){ # <repo> [prefix] -> sorted comma list of live paths
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT string_agg(a.path, ',' ORDER BY a.path) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.is_deleted=false AND a.path LIKE '${2:-}%';" 2>/dev/null | tr -d '[:space:]' || true
}
seed(){ # <repo> <name> <days-oldest> <ver>... : one artifact per version, oldest first, 1 day apart
  local repo="$1" name="$2" d="$3" v c
  shift 3
  for v in "$@"; do
    c="$(put_ver "$repo" "$name/$v/$name.bin")"
    [ "$c" = "201" ] || { infra_fail "seed upload $repo/$name/$v was HTTP $c"; end_suite; }
    age "$repo" "$name/$v/$name.bin" "$d"
    d=$((d-1))
  done
}

# =============================================================================
begin_suite "lifecycle-assignments-min-keep"

begin_test "setup: admin login and the generic repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
declare -A RID RK
SETUP_ERR=""
for k in leg dis dorm asg glA glB mk vp cmp rx; do
  key="lc-${k,,}-${DTF_SLOT}-${SUF}"
  id="$(mkrepo "$key")"
  [ -n "$id" ] || SETUP_ERR="${SETUP_ERR} ${key}"
  RID[$k]="$id"; RK[$k]="$key"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "could not create repositories:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
# CONTROL (both images): the legacy single-repository policy shape that every
# release accepts. max_versions keep=1 on one repository: preview counts what
# execute then removes, and only in that repository.
# =============================================================================
begin_test "CONTROL: legacy repository_id max_versions keep=1: preview == execute, newest version survives, other repositories untouched"
reset_case
seed "${RK[leg]}" app 10 v1 v2 v3
seed "${RK[dis]}" app 10 v1 v2 v3
mkpol "$(jq -nc --arg n "lc-leg-${SUF}" --arg r "${RID[leg]}" '{name:$n,repository_id:$r,policy_type:"max_versions",config:{keep:1}}')"
[ -n "$PID" ] || { infra_fail "legacy policy create was HTTP ${PCODE}: $(body "$W/pol")"; end_suite; }
c="$(http POST "/api/v1/admin/lifecycle/$PID/preview" "$W/pv")"
pm="$(jqr '.artifacts_matched' < "$W/pv")"
note "preview: HTTP ${c} matched=${pm}; live after preview $(live "${RK[leg]}")"
[ "$c" = "200" ] && [ "$pm" = "2" ] || fail_g "preview was HTTP ${c} matched=${pm}, expected 200 matched=2"
[ "$(live "${RK[leg]}")" = "3" ] || fail_g "the preview deleted something"
c="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"
er="$(jqr '.artifacts_removed' < "$W/ex")"
note "execute: HTTP ${c} removed=${er}; live $(live_paths "${RK[leg]}"); other repo live $(live "${RK[dis]}")"
[ "$c" = "200" ] && [ "$er" = "$pm" ] || fail_g "execute was HTTP ${c} removed=${er}, expected 200 removed=${pm} (== preview)"
[ "$(live_paths "${RK[leg]}")" = "app/v3/app.bin" ] || fail_g "survivors are $(live_paths "${RK[leg]}"), expected only app/v3/app.bin"
[ "$(live "${RK[dis]}")" = "3" ] || fail_g "the policy deleted in a repository it is not bound to"
policy_cleanup
finish_case "legacy single-repository lifecycle policy broken"

# =============================================================================
# FIX #3869: "enabled": false on create is honoured.
# =============================================================================
begin_test "FIX #3869: a policy created with \"enabled\": false is stored disabled and a live run of it is refused"
reset_case
mkpol "$(jq -nc --arg n "lc-dis-${SUF}" --arg r "${RID[dis]}" '{name:$n,repository_id:$r,policy_type:"max_versions",config:{keep:1},enabled:false}')"
[ -n "$PID" ] || { infra_fail "policy create was HTTP ${PCODE}: $(body "$W/pol")"; end_suite; }
e1="$(jqr '.enabled' < "$W/pol")"
http GET "/api/v1/admin/lifecycle/$PID" "$W/get" >/dev/null
e2="$(jqr '.enabled' < "$W/get")"
c="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"
note "create enabled=${e1}, GET enabled=${e2}; execute HTTP ${c} $(body "$W/ex"); live $(live "${RK[dis]}")"
[ "$e1" = "false" ] && [ "$e2" = "false" ] || fail_g "the policy is enabled=${e1}/${e2} (1.10.0 drops the field and creates it enabled)"
[ "$c" = "400" ] || fail_g "a live run of the disabled policy was HTTP ${c}, expected 400"
[ "$(live "${RK[dis]}")" = "3" ] || fail_g "the disabled policy deleted $((3 - $(live "${RK[dis]}"))) artifacts"
policy_cleanup
finish_case "#3869: enabled=false on create not honoured"

# =============================================================================
# FIX #3794: a policy with neither repository_id nor applies_to_all is
# DORMANT (was: global). execute-all leaves every repository alone.
# =============================================================================
begin_test "FIX #3794: a policy created without a scope is dormant (applies_to_all=false, repository_ids=[]) and execute-all deletes nothing with it"
reset_case
seed "${RK[dorm]}" old 40 v1 v2 v3
mkpol "$(jq -nc --arg n "lc-dorm-${SUF}" '{name:$n,policy_type:"max_age_days",config:{days:5}}')"
[ -n "$PID" ] || { infra_fail "policy create was HTTP ${PCODE}: $(body "$W/pol")"; end_suite; }
ata="$(jqr '.applies_to_all' < "$W/pol")"; rids="$(jqr '.repository_ids | length' < "$W/pol")"
note "create: applies_to_all=${ata} repository_ids=${rids}"
[ "$ata" = "false" ] && [ "$rids" = "0" ] || fail_g "create response applies_to_all=${ata} repository_ids=${rids}, expected false and [] (1.10.0 has neither field)"
c="$(http POST "/api/v1/admin/lifecycle/$PID/preview" "$W/pv")"
pm="$(jqr '.artifacts_matched' < "$W/pv")"
c2="$(http POST /api/v1/admin/lifecycle/execute-all "$W/ea")"
inres="$(jq -r --arg p "$PID" '[.[]? | select(.policy_id == $p)] | length' < "$W/ea" 2>/dev/null || true)"
note "preview HTTP ${c} matched=${pm}; execute-all HTTP ${c2}, entries for this policy ${inres}; live $(live "${RK[dorm]}")/3"
[ "$pm" = "0" ] || fail_g "the dormant policy previews ${pm} matches, expected 0"
[ "$c2" = "200" ] || fail_g "execute-all was HTTP ${c2}"
[ "$inres" = "0" ] || fail_g "execute-all ran the dormant policy"
[ "$(live "${RK[dorm]}")" = "3" ] || fail_g "execute-all deleted $((3 - $(live "${RK[dorm]}"))) 40-day-old artifacts through an unscoped policy (1.10.0 treats it as global)"
DORM_PID="$PID"
finish_case "#3794: an unscoped policy is not dormant"

# =============================================================================
# FIX #3794: attach / detach routes, ?repository_id= listing, /capabilities.
# =============================================================================
begin_test "FIX #3794: /capabilities advertises assignment; PUT/DELETE /lifecycle/{id}/repositories/{rid} are idempotent; ?repository_id= lists by assignment"
reset_case
c="$(http GET /api/v1/admin/lifecycle/capabilities "$W/cap")"
note "capabilities: HTTP ${c} $(body "$W/cap")"
[ "$c" = "200" ] && [ "$(jqr '.explicit_repository_assignment' < "$W/cap")" = "true" ] || fail_g "capabilities did not advertise explicit_repository_assignment=true"
A1="$(http PUT "/api/v1/admin/lifecycle/$DORM_PID/repositories/${RID[dorm]}" "$W/a1")"
A2="$(http PUT "/api/v1/admin/lifecycle/$DORM_PID/repositories/${RID[dorm]}" "$W/a2")"
r1="$(jqr '.repository_ids | join(",")' < "$W/a1")"; r2="$(jqr '.repository_ids | join(",")' < "$W/a2")"
note "attach twice: HTTP ${A1}/${A2}, repository_ids ${r1} / ${r2}"
[ "$A1" = "200" ] && [ "$A2" = "200" ] || fail_g "attach was HTTP ${A1}/${A2}, expected 200/200"
[ "$r1" = "${RID[dorm]}" ] && [ "$r2" = "${RID[dorm]}" ] || fail_g "attach did not leave exactly [${RID[dorm]}]"
http GET "/api/v1/admin/lifecycle?repository_id=${RID[dorm]}" "$W/l1" >/dev/null
http GET "/api/v1/admin/lifecycle?repository_id=${RID[asg]}" "$W/l2" >/dev/null
in1="$(jq -r --arg p "$DORM_PID" '[.[]? | select(.id == $p)] | length' < "$W/l1" 2>/dev/null || true)"
in2="$(jq -r --arg p "$DORM_PID" '[.[]? | select(.id == $p)] | length' < "$W/l2" 2>/dev/null || true)"
note "list ?repository_id=assigned contains it: ${in1}; ?repository_id=other contains it: ${in2}"
[ "$in1" = "1" ] && [ "$in2" = "0" ] || fail_g "?repository_id= filter wrong (assigned ${in1}, other ${in2}; expected 1 and 0)"
c="$(http POST "/api/v1/admin/lifecycle/$DORM_PID/preview" "$W/pv")"
pm="$(jqr '.artifacts_matched' < "$W/pv")"
note "preview once attached: HTTP ${c} matched=${pm}"
[ "$pm" = "3" ] || fail_g "the attached policy previews ${pm}, expected the 3 expired artifacts"
D1="$(http DELETE "/api/v1/admin/lifecycle/$DORM_PID/repositories/${RID[dorm]}" "$W/d1")"
D2="$(http DELETE "/api/v1/admin/lifecycle/$DORM_PID/repositories/${RID[dorm]}" "$W/d2")"
note "detach twice: HTTP ${D1}/${D2}, repository_ids $(jqr '.repository_ids | length' < "$W/d2")"
[ "$D1" = "200" ] && [ "$D2" = "200" ] && [ "$(jqr '.repository_ids | length' < "$W/d2")" = "0" ] || fail_g "detach was HTTP ${D1}/${D2} or left assignments"
c="$(http POST "/api/v1/admin/lifecycle/$DORM_PID/execute" "$W/ex")"
note "execute once detached: HTTP ${c} removed=$(jqr '.artifacts_removed' < "$W/ex"); live $(live "${RK[dorm]}")/3"
[ "$(live "${RK[dorm]}")" = "3" ] || fail_g "the detached policy deleted artifacts"
policy_cleanup
finish_case "#3794: assignment routes / listing / capabilities broken"

# =============================================================================
# FIX #3794 + #2024: applies_to_all runs independently in every repository;
# match.path_prefix confines it to the prefix.
# =============================================================================
begin_test "FIX #3794/#2024: applies_to_all max_versions keep=1 with match.path_prefix deletes per repository and only under the prefix"
reset_case
PFX="gp${SUF//-/}"
seed "${RK[glA]}" "$PFX" 10 v1 v2 v3
seed "${RK[glB]}" "$PFX" 10 v1 v2 v3
seed "${RK[glA]}" other 10 v1 v2 v3
mkpol "$(jq -nc --arg n "lc-glob-${SUF}" --arg p "$PFX/" '{name:$n,applies_to_all:true,policy_type:"max_versions",config:{keep:1,match:{path_prefix:$p}}}')"
note "create: HTTP ${PCODE} applies_to_all=$(jqr '.applies_to_all' < "$W/pol") $(body "$W/pol" | head -c 160)"
if [ -z "$PID" ]; then
  fail_g "an applies_to_all policy with match.path_prefix was refused (HTTP ${PCODE})"
else
  [ "$(jqr '.applies_to_all' < "$W/pol")" = "true" ] || fail_g "applies_to_all not echoed true"
  c="$(http POST "/api/v1/admin/lifecycle/$PID/preview" "$W/pv")"; pm="$(jqr '.artifacts_matched' < "$W/pv")"
  c2="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"; er="$(jqr '.artifacts_removed' < "$W/ex")"
  note "preview HTTP ${c} matched=${pm}; execute HTTP ${c2} removed=${er}"
  note "A under prefix: $(live_paths "${RK[glA]}" "$PFX/"); B under prefix: $(live_paths "${RK[glB]}" "$PFX/"); A other: $(live "${RK[glA]}" other/)"
  [ "$pm" = "4" ] && [ "$er" = "4" ] || fail_g "preview/execute ${pm}/${er}, expected 4/4 (two per repository)"
  [ "$(live_paths "${RK[glA]}" "$PFX/")" = "$PFX/v3/$PFX.bin" ] || fail_g "repository A kept $(live_paths "${RK[glA]}" "$PFX/")"
  [ "$(live_paths "${RK[glB]}" "$PFX/")" = "$PFX/v3/$PFX.bin" ] || fail_g "repository B kept $(live_paths "${RK[glB]}" "$PFX/")"
  [ "$(live "${RK[glA]}" other/)" = "3" ] || fail_g "the path_prefix scope did not protect other/ ($(live "${RK[glA]}" other/) of 3 live)"
fi
policy_cleanup
finish_case "#3794/#2024: applies_to_all or match.path_prefix broken"

# =============================================================================
# FIX #2024: max_age_days with min_keep keeps the newest N of each package.
# =============================================================================
begin_test "FIX #2024: max_age_days {days:5, min_keep:2} keeps the 2 newest of each package even when expired; preview == execute"
reset_case
seed "${RK[mk]}" alpha 40 v1 v2 v3 v4
seed "${RK[mk]}" beta 40 v1 v2 v3
seed "${RK[mk]}" young 2 v1 v2 v3
mkpol "$(jq -nc --arg n "lc-mk-${SUF}" --arg r "${RID[mk]}" '{name:$n,repository_ids:[$r],policy_type:"max_age_days",config:{days:5,min_keep:2}}')"
if [ -z "$PID" ]; then
  fail_g "a max_age_days policy with min_keep was refused (HTTP ${PCODE}: $(body "$W/pol"))"
else
  c="$(http POST "/api/v1/admin/lifecycle/$PID/preview" "$W/pv")"; pm="$(jqr '.artifacts_matched' < "$W/pv")"
  c2="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"; er="$(jqr '.artifacts_removed' < "$W/ex")"
  note "preview HTTP ${c} matched=${pm}; execute HTTP ${c2} removed=${er}; live $(live_paths "${RK[mk]}")"
  [ "$pm" = "3" ] && [ "$er" = "3" ] || fail_g "preview/execute ${pm}/${er}, expected 3/3 (alpha v1,v2 and beta v1)"
  [ "$(live_paths "${RK[mk]}")" = "alpha/v3/alpha.bin,alpha/v4/alpha.bin,beta/v2/beta.bin,beta/v3/beta.bin,young/v1/young.bin,young/v2/young.bin,young/v3/young.bin" ] \
    || fail_g "survivors are $(live_paths "${RK[mk]}")"
fi
policy_cleanup
finish_case "#2024: min_keep under max_age_days broken"

# =============================================================================
# FIX #4456: match.version_pattern scopes max_versions; out-of-scope versions
# neither count nor go.
# =============================================================================
begin_test "FIX #4456: max_versions keep=1 with match.version_pattern ^sha- prunes only sha- versions"
reset_case
seed "${RK[vp]}" img 20 sha-1 v1.0 sha-2 v2.0 sha-3
mkpol "$(jq -nc --arg n "lc-vp-${SUF}" --arg r "${RID[vp]}" '{name:$n,repository_ids:[$r],policy_type:"max_versions",config:{keep:1,match:{version_pattern:"^sha-"}}}')"
if [ -z "$PID" ]; then
  fail_g "a max_versions policy with match.version_pattern was refused (HTTP ${PCODE}: $(body "$W/pol"))"
else
  c="$(http POST "/api/v1/admin/lifecycle/$PID/preview" "$W/pv")"; pm="$(jqr '.artifacts_matched' < "$W/pv")"
  c2="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"; er="$(jqr '.artifacts_removed' < "$W/ex")"
  note "preview ${pm}, execute ${er}; live $(live_paths "${RK[vp]}")"
  [ "$pm" = "2" ] && [ "$er" = "2" ] || fail_g "preview/execute ${pm}/${er}, expected 2/2"
  [ "$(live_paths "${RK[vp]}")" = "img/sha-3/img.bin,img/v1.0/img.bin,img/v2.0/img.bin" ] || fail_g "survivors are $(live_paths "${RK[vp]}")"
fi
policy_cleanup
finish_case "#4456: match.version_pattern broken"

# =============================================================================
# FIX #4456: composite ANDs its conditions; the 36500-day cap.
# =============================================================================
begin_test "FIX #4456: composite [max_age_days 30, no_downloads_days 10] deletes only artifacts meeting both; days 36501 is refused"
reset_case
seed "${RK[cmp]}" oldidle 60 v1
seed "${RK[cmp]}" olduse 60 v1
seed "${RK[cmp]}" youngidle 20 v1
# A download inside the no-downloads window for olduse.
psql_x "INSERT INTO download_statistics (artifact_id, downloaded_at) SELECT a.id, NOW() - interval '1 day' FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${RK[cmp]}' AND a.path='olduse/v1/olduse.bin';" \
  || { infra_fail "could not seed a download_statistics row"; end_suite; }
mkpol "$(jq -nc --arg n "lc-cmp-${SUF}" --arg r "${RID[cmp]}" '{name:$n,repository_ids:[$r],policy_type:"composite",config:{conditions:[{type:"max_age_days",value:30},{type:"no_downloads_days",value:10}]}}')"
if [ -z "$PID" ]; then
  fail_g "a composite policy was refused (HTTP ${PCODE}: $(body "$W/pol"))"
else
  c="$(http POST "/api/v1/admin/lifecycle/$PID/preview" "$W/pv")"; pm="$(jqr '.artifacts_matched' < "$W/pv")"
  c2="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"; er="$(jqr '.artifacts_removed' < "$W/ex")"
  note "preview ${pm}, execute ${er}; live $(live_paths "${RK[cmp]}")"
  [ "$pm" = "1" ] && [ "$er" = "1" ] || fail_g "preview/execute ${pm}/${er}, expected 1/1"
  [ "$(live_paths "${RK[cmp]}")" = "olduse/v1/olduse.bin,youngidle/v1/youngidle.bin" ] || fail_g "survivors are $(live_paths "${RK[cmp]}")"
fi
mkpol "$(jq -nc --arg n "lc-cap-${SUF}" --arg r "${RID[cmp]}" '{name:$n,repository_ids:[$r],policy_type:"max_age_days",config:{days:36501},enabled:false}')"
note "days 36501: HTTP ${PCODE} $(body "$W/pol" | head -c 200)"
case "$PCODE" in 400|422) ;; *) fail_g "max_age_days days=36501 was HTTP ${PCODE}, expected 400";; esac
policy_cleanup
finish_case "#4456: composite / day cap broken"

# =============================================================================
# FIX #3734: a policy that cannot reclaim anything in a non-OCI Remote is 422.
# CONTROL: max_age_days on the same Remote is accepted.
# =============================================================================
begin_test "FIX #3734: max_versions bound to a maven Remote is 422; max_age_days bound to it and max_versions on a docker Remote are accepted"
reset_case
R_rm="lc-rmvn-${DTF_SLOT}-${SUF}"; R_rd="lc-rdkr-${DTF_SLOT}-${SUF}"
ID_rm="$(mkrepo "$R_rm" maven remote "https://repo.maven.apache.org/maven2")"
ID_rd="$(mkrepo "$R_rd" docker remote "https://registry-1.docker.io")"
[ -n "$ID_rm" ] && [ -n "$ID_rd" ] || { infra_fail "could not create the Remote repositories (${ID_rm}/${ID_rd})"; end_suite; }
mkpol "$(jq -nc --arg n "lc-rmv-${SUF}" --arg r "$ID_rm" '{name:$n,repository_id:$r,policy_type:"max_versions",config:{keep:1},enabled:false}')"
c1="$PCODE"; b1="$(body "$W/pol" | head -c 200)"
mkpol "$(jq -nc --arg n "lc-rma-${SUF}" --arg r "$ID_rm" '{name:$n,repository_id:$r,policy_type:"max_age_days",config:{days:30},enabled:false}')"
c2="$PCODE"
mkpol "$(jq -nc --arg n "lc-rdv-${SUF}" --arg r "$ID_rd" '{name:$n,repository_id:$r,policy_type:"max_versions",config:{keep:3},enabled:false}')"
c3="$PCODE"
note "maven Remote max_versions: HTTP ${c1} ${b1}; maven Remote max_age_days: HTTP ${c2}; docker Remote max_versions: HTTP ${c3}"
[ "$c1" = "422" ] || fail_g "max_versions on a maven Remote was HTTP ${c1}, expected 422"
case "$c2" in 200|201) ;; *) fail_g "max_age_days on a maven Remote was HTTP ${c2}, expected 200";; esac
case "$c3" in 200|201) ;; *) fail_g "max_versions on a docker Remote was HTTP ${c3}, expected 200";; esac
policy_cleanup
finish_case "#3734: inert Remote policy not refused"

# =============================================================================
# FIX #4461: lifecycle regexes are validated by PostgreSQL rules at create.
# =============================================================================
begin_test "FIX #4461: \\b in exclude.version_patterns is refused (400 VALIDATION_ERROR naming \\y); \\y is accepted"
reset_case
mkpol "$(jq -nc --arg n "lc-rxb-${SUF}" --arg r "${RID[rx]}" '{name:$n,repository_id:$r,policy_type:"max_age_days",config:{days:5,exclude:{version_patterns:["\\bstable\\b"]}},enabled:false}')"
cb="$PCODE"; bb="$(body "$W/pol")"
mkpol "$(jq -nc --arg n "lc-rxy-${SUF}" --arg r "${RID[rx]}" '{name:$n,repository_id:$r,policy_type:"max_age_days",config:{days:5,exclude:{version_patterns:["\\ystable\\y"]}},enabled:false}')"
cy="$PCODE"
note "\\b: HTTP ${cb} ${bb}; \\y: HTTP ${cy}"
[ "$cb" = "400" ] || fail_g "\\bstable\\b was HTTP ${cb}, expected 400"
[ "$(jqr '.code' <<<"$bb")" = "VALIDATION_ERROR" ] || fail_g "the refusal code is '$(jqr '.code' <<<"$bb")', expected VALIDATION_ERROR"
case "$(jqr '.message' <<<"$bb")" in *'\y'*) ;; *) fail_g "the refusal does not point at \\y";; esac
case "$cy" in 200|201) ;; *) fail_g "\\ystable\\y was HTTP ${cy}, expected 200";; esac
policy_cleanup
finish_case "#4461: \\b accepted in a lifecycle regex"

# Stored regexes the API no longer accepts: written with SQL onto a policy the
# API created in a shape every release accepts.
seed "${RK[rx]}" rel 20 v1 v2 v3
store_cfg(){ psql_x "UPDATE lifecycle_policies SET config = '$2'::jsonb WHERE id='$1';"; }

begin_test "FIX #4502: a stored \\b match.version_pattern / tag_pattern_delete pattern previews 200 with errors and 0 matches; execute is 400"
reset_case
mkpol "$(jq -nc --arg n "lc-rxm-${SUF}" --arg r "${RID[rx]}" '{name:$n,repository_id:$r,policy_type:"max_versions",config:{keep:1}}')"
P1="$PID"
mkpol "$(jq -nc --arg n "lc-rxt-${SUF}" --arg r "${RID[rx]}" '{name:$n,repository_id:$r,policy_type:"tag_pattern_delete",config:{pattern:"^v"}}')"
P2="$PID"
if [ -z "$P1" ] || [ -z "$P2" ]; then infra_fail "could not create the base policies"; end_suite; fi
store_cfg "$P1" '{"keep":1,"match":{"version_pattern":"\\bv"}}' || { infra_fail "could not store the \\b config"; end_suite; }
store_cfg "$P2" '{"pattern":"\\bv"}' || { infra_fail "could not store the \\b pattern"; end_suite; }
for P in "$P1" "$P2"; do
  c="$(http POST "/api/v1/admin/lifecycle/$P/preview" "$W/pv")"
  pm="$(jqr '.artifacts_matched' < "$W/pv")"; errs="$(jqr '.errors | join(" | ")' < "$W/pv")"
  c2="$(http POST "/api/v1/admin/lifecycle/$P/execute" "$W/ex")"
  note "policy ${P}: preview HTTP ${c} matched=${pm} errors=[${errs}]; execute HTTP ${c2} $(body "$W/ex" | head -c 200); live $(live "${RK[rx]}")/3"
  [ "$c" = "200" ] || fail_g "preview was HTTP ${c}, expected 200"
  [ "$pm" = "0" ] || fail_g "preview matched ${pm}, expected 0"
  case "$errs" in *'\b'*) ;; *) fail_g "preview errors do not name the \\b pattern: [${errs}]";; esac
  [ "$c2" = "400" ] && [ "$(jqr '.code' < "$W/ex")" = "VALIDATION_ERROR" ] || fail_g "execute was HTTP ${c2} code $(jqr '.code' < "$W/ex"), expected 400 VALIDATION_ERROR"
done
[ "$(live "${RK[rx]}")" = "3" ] || fail_g "a refused policy deleted artifacts"
policy_cleanup
finish_case "#4502: stored \\b selector patterns not reported / refused"

begin_test "FIX #4504: a stored pattern PostgreSQL cannot compile is a 400 naming the field on execute, not a 500"
reset_case
seed "${RK[rx]}" zz 20 v1 v2 v3
mkpol "$(jq -nc --arg n "lc-rxz-${SUF}" --arg r "${RID[rx]}" '{name:$n,repository_id:$r,policy_type:"max_versions",config:{keep:1}}')"
[ -n "$PID" ] || { infra_fail "could not create the base policy"; end_suite; }
store_cfg "$PID" '{"keep":1,"exclude":{"version_patterns":["foo\\z"]}}' || { infra_fail "could not store the foo\\z config"; end_suite; }
c="$(http POST "/api/v1/admin/lifecycle/$PID/execute" "$W/ex")"
msg="$(jqr '.message' < "$W/ex")"
note "execute: HTTP ${c} code $(jqr '.code' < "$W/ex") ${msg}; live $(live "${RK[rx]}" zz/)/3"
[ "$c" = "400" ] || fail_g "execute was HTTP ${c}, expected 400 (1.10.0: 500 DATABASE_ERROR)"
case "$msg" in *exclude.version_patterns*"not a valid PostgreSQL regular expression"*) ;; *) fail_g "the refusal does not name the field and the compile failure: ${msg}";; esac
[ "$(live "${RK[rx]}" zz/)" = "3" ] || fail_g "the refused policy deleted artifacts"
policy_cleanup
finish_case "#4504: uncompilable stored pattern is a 500"

end_suite
