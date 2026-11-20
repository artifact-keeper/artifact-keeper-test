#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2015,SC2001  # jq $variables; A && B || fail_g is intended
# =============================================================================
# tiers/npm-contract-1120/oracle.sh
#   npm native-protocol contracts fixed for 1.12.0: artifact-keeper#5345 (/-/
#   meta failure names its cause), #5870 (attestations 404 with no upstream), #5399 (concurrent same-version publishes),
#   #5403 (stale unpublish), #5676 (retention deletes retract dist-tags), #5724
#   (derived latest by SemVer precedence), #5725 (package-name rules). See the
#   manifest for each bug and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SUF="${DTF_SLOT}-${RUN_ID##*-}-$$"
setup_workdir
W="$WORK_DIR"
mkdir -p "$W/pub" "$W/race"
NPM_CTR="ak-dtf${DTF_SLOT}-client-npm"
MOCK="http://172.16.${DTF_SLOT}.91"
DEAD="http://npm-dead-${SUF}.invalid/"
jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# req <METHOD> <PATH> [JSON body] [content-type]: sets CODE and BODY (admin bearer).
req(){
  local m="$1" p="$2" d="${3:-}"
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$m" -H "Authorization: Bearer ${TOK}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}${p}" 2>/dev/null)"; [ -n "$CODE" ] || CODE=000
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
# npm URL form of a package name: @scope/name -> @scope%2fname
enc(){ printf '%s' "${1/\//%2f}"; }
safe(){ printf '%s' "$1" | tr '/@' '__'; }

# mkbody <name> <version> <out.json> [extra-content]: an `npm publish` body whose
# tarball (kept at <out.json>.tgz) carries package.json plus, if given, an extra
# file making the bytes unique.
mkbody(){
  local name="$1" ver="$2" out="$3" extra="${4:-}" src
  src="$(mktemp -d "$W/src.XXXXXX")"
  mkdir -p "$src/package"
  jq -nc --arg n "$name" --arg v "$ver" '{name:$n,version:$v}' > "$src/package/package.json"
  [ -n "$extra" ] && printf '%s\n' "$extra" > "$src/package/id.txt"
  tar czf "$out.tgz" -C "$src" package
  rm -rf "$src"
  local integ short="${name##*/}"
  integ="sha512-$(openssl dgst -sha512 -binary "$out.tgz" | base64 -w0)"
  base64 -w0 < "$out.tgz" > "$out.b64"
  jq -n --arg name "$name" --arg version "$ver" --arg integ "$integ" \
    --arg tarball "${BASE}/npm/x/${name}/-/${short}-${ver}.tgz" --rawfile data "$out.b64" \
    --argjson length "$(wc -c < "$out.tgz" | tr -d ' ')" --arg file "${short}-${ver}.tgz" \
    '{name:$name,"dist-tags":{latest:$version},
      versions:{($version):{name:$name,version:$version,dist:{tarball:$tarball,integrity:$integ}}},
      "_attachments":{($file):{content_type:"application/octet-stream",data:$data,length:$length}}}' > "$out"
  rm -f "$out.b64"
}
# publish <repo> <name> <version> [extra]: sets CODE/BODY.
publish(){
  local f; f="$W/pub/$(safe "$2")-$3-$RANDOM.json"
  mkbody "$2" "$3" "$f" "${4:-}"
  req PUT "/npm/$1/$(enc "$2")" "$(cat "$f")"
  PUB_TGZ="$f.tgz"
}
versions_of(){ # <repo> <name> -> sorted JSON array of packument versions ("404" if none)
  req GET "/npm/$1/$(enc "$2")"
  if [ "$CODE" = "200" ]; then jqr -c '.versions | keys | sort' <<<"$BODY"; else echo "$CODE"; fi
}
# integrity_ok <tgz file> <integrity string>: the bytes match the SRI string.
integrity_ok(){
  local algo="${2%%-*}" want="${2#*-}"
  case "$algo" in sha512|sha384|sha256|sha1) ;; *) return 1;; esac
  [ "$(openssl dgst "-${algo}" -binary "$1" | base64 -w0)" = "$want" ]
}
npm_sh(){ docker exec -i "$NPM_CTR" bash -s 2>&1; }
npmrc(){ # <repo> <dir>: shell text writing an .npmrc for <repo> into <dir>
  local b64; b64="$(printf 'admin:%s' "$ADMIN_PASS" | base64 -w0)"
  cat <<EOF
mkdir -p '$2' && cat > '$2/.npmrc' <<'RC'
registry=http://backend:8080/npm/$1/
//backend:8080/npm/$1/:_auth=${b64}
//backend:8080/npm/$1/:always-auth=true
RC
EOF
}

begin_suite "npm-contract-1120"

# =============================================================================
begin_test "setup: admin session, Local / Remote / Virtual npm repositories, the npm client"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; exit $?; }
mkrepo(){ # <key> <type> [upstream]: sets the repo id in RID
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"npm",repo_type:$t,is_public:true} + (if $u == "" then {} else {upstream_url:$u} end)')"
  RID="$(jqr '.id // empty' <<<"$BODY")"
  is_2xx "$CODE" && [ -n "$RID" ] || { infra_fail "creating $2 repo $1 answered ${CODE}: ${BODY:0:200}"; end_suite; exit 1; }
}
L="npmc-local-${SUF}";      mkrepo "$L" local
RACE="npmc-race-${SUF}";    mkrepo "$RACE" local
UNP="npmc-unpub-${SUF}";    mkrepo "$UNP" local
RET="npmc-ret-${SUF}";      mkrepo "$RET" local; RET_ID="$RID"
DEADR="npmc-dead-${SUF}";   mkrepo "$DEADR" remote "$DEAD"
FILT="npmc-filt-${SUF}";    mkrepo "$FILT" remote "$DEAD"
CO="npmc-co-${SUF}";        mkrepo "$CO" remote "$DEAD"
SCP="npmc-scope-${SUF}";    mkrepo "$SCP" remote "$DEAD"
SH_L="npmc-shl-${SUF}";     mkrepo "$SH_L" local
SH_R="npmc-shr-${SUF}";     mkrepo "$SH_R" remote "${MOCK}/ok/npm"
SH_V="npmc-shv-${SUF}"
req POST /api/v1/repositories "$(jq -nc --arg k "$SH_V" --arg l "$SH_L" --arg r "$SH_R" \
  '{key:$k,name:$k,format:"npm",repo_type:"virtual",is_public:true,member_repos:[{repo_key:$l,priority:1},{repo_key:$r,priority:2}]}')"
is_2xx "$CODE" || { infra_fail "creating virtual ${SH_V} answered ${CODE}: ${BODY:0:200}"; end_suite; exit 1; }
docker exec "$NPM_CTR" npm --version >/dev/null 2>&1 || { infra_fail "npm missing in ${NPM_CTR}"; end_suite; exit 1; }
echo "-- repos: ${L} ${RACE} ${UNP} ${RET} ${DEADR} ${FILT} ${CO} ${SCP} ${SH_V}=[${SH_L},${SH_R}]"
pass

# =============================================================================
# #5345: a Remote's /-/ meta failure names its cause
# =============================================================================
LOCAL_STUB="not implemented for local repositories"
begin_test "CONTROL: a Local repository's /-/v1/search is 501 naming local repositories; an unreachable Remote's /-/ping is 200"
reset_case
req GET "/npm/${L}/-/v1/search?text=x"
note "local search: ${CODE} ${BODY:0:160}"
[ "$CODE" = "501" ] && grep -q "$LOCAL_STUB" <<<"$BODY" || fail_g "Local /-/v1/search answered ${CODE}, not the 501 local stub"
req GET "/npm/${DEADR}/-/ping"
note "dead remote ping: ${CODE} ${BODY:0:120}"
[ "$CODE" = "200" ] || fail_g "/-/ping on the unreachable Remote answered ${CODE}, not 200"
finish_case "the Local /-/ stub or the Remote ping changed"

begin_test "FIX #5345: a Remote with an unreachable upstream answers /-/ search and attestations 503 'upstream unreachable', not the local stub"
reset_case
for ep in "v1/search?text=x" "npm/v1/attestations/lodash@4.17.21"; do
  req GET "/npm/${DEADR}/-/${ep}"
  note "${ep}: ${CODE} ${BODY:0:200}"
  [ "$CODE" = "503" ] || fail_g "${ep} answered ${CODE}, not 503"
  grep -q "upstream unreachable" <<<"$BODY" && grep -q "$DEADR" <<<"$BODY" || fail_g "${ep}: the message does not name the unreachable upstream of ${DEADR}"
  grep -q "$LOCAL_STUB" <<<"$BODY" && fail_g "${ep}: still the local-repository stub message"
done
finish_case "an unreachable Remote's /-/ failure does not name the cause"

begin_test "FIX #5345: a /-/ attestation path refused by the Remote's upstream filter is 404 naming that filter"
reset_case
req PUT "/api/v1/repositories/${FILT}/upstream-filter" '{"include_patterns":[],"exclude_patterns":["^-/npm/v1/attestations/"]}'
note "set filter: ${CODE} ${BODY:0:120}"
is_2xx "$CODE" || fail_g "setting the upstream filter answered ${CODE}"
req GET "/npm/${FILT}/-/npm/v1/attestations/lodash@4.17.21"
note "filtered attestations: ${CODE} ${BODY:0:200}"
[ "$CODE" = "404" ] || fail_g "the filtered attestation lookup answered ${CODE}, not 404"
grep -q "upstream filter of repository '${FILT}'" <<<"$BODY" || fail_g "the message does not name the upstream filter of ${FILT}"
finish_case "a filter-refused /-/ request does not name the filter"

begin_test "FIX #5345: a cache-only Remote answers an uncached /-/ search 404 naming cache-only mode"
reset_case
req PUT "/api/v1/repositories/${CO}/upstream-mode" '{"upstream_mode":"cache_only"}'
note "set cache_only: ${CODE} ${BODY:0:120}"
is_2xx "$CODE" || fail_g "setting cache_only answered ${CODE}"
req GET "/npm/${CO}/-/v1/search?text=x"
note "cache-only search: ${CODE} ${BODY:0:200}"
[ "$CODE" = "404" ] || fail_g "the cache-only search answered ${CODE}, not 404"
grep -q "is cache-only" <<<"$BODY" && grep -q "$CO" <<<"$BODY" || fail_g "the message does not name ${CO}'s cache-only mode"
finish_case "a cache-only Remote's /-/ refusal does not name the mode"

# =============================================================================
# #5870: attestation lookups on a repository with no upstream
# =============================================================================
# pnpm 11 (minimumReleaseAge) asks /-/npm/v1/attestations/<pkg>@<ver> for every
# resolved version. A Local, and a Virtual with no Remote member, answered 501,
# which pnpm retries as a server error. Hosted versions have no attestations:
# the answer is 404, as on registry.npmjs.org.
ATT_V="npmc-attv-${SUF}"
req POST /api/v1/repositories "$(jq -nc --arg k "$ATT_V" --arg l "$L" \
  '{key:$k,name:$k,format:"npm",repo_type:"virtual",is_public:true,member_repos:[{repo_key:$l,priority:1}]}')"
is_2xx "$CODE" || { infra_fail "creating virtual ${ATT_V} answered ${CODE}: ${BODY:0:200}"; end_suite; exit 1; }

begin_test "FIX #5870: /-/npm/v1/attestations on a Local and on a Virtual with no Remote member is 404, not 501"
reset_case
for r in "$L" "$ATT_V"; do
  for spec in "lodash@4.17.21" "@dtfatt/pkg@1.0.0"; do
    req GET "/npm/${r}/-/npm/v1/attestations/${spec}"
    note "${r} attestations ${spec}: ${CODE} ${BODY:0:200}"
    [ "$CODE" = "404" ] || fail_g "${r}: attestations for ${spec} answered ${CODE}, not 404"
    grep -q "$LOCAL_STUB" <<<"$BODY" && fail_g "${r}: attestations for ${spec} is still the local-repository stub"
  done
done
finish_case "an attestation lookup with no upstream to ask is not a 404"

# =============================================================================
# #5399: concurrent publishes of one version
# =============================================================================
begin_test "CONTROL: a sequential re-publish of an existing version is 409 and the first bytes stay served"
reset_case
publish "$RACE" dtfseq 1.0.0 "first-${SUF}"; c1="$CODE"; T1="$PUB_TGZ"
publish "$RACE" dtfseq 1.0.0 "second-${SUF}"; c2="$CODE"
note "publish #1 ${c1}, publish #2 ${c2} ${BODY:0:120}"
is_2xx "$c1" || fail_g "the first publish answered ${c1}"
[ "$c2" = "409" ] || fail_g "the duplicate publish answered ${c2}, not 409"
curl -s -o "$W/seq.tgz" --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/npm/${RACE}/dtfseq/-/dtfseq-1.0.0.tgz"
cmp -s "$W/seq.tgz" "$T1" || fail_g "the served tarball is not the first publish's bytes"
finish_case "sequential duplicate publish is not refused cleanly"

ROUNDS=8; RACERS=10
RACE_STATUS_ERR=""; RACE_BYTES_ERR=""; RACE_VERS=()
for r in $(seq 1 "$ROUNDS"); do
  ver="1.0.${r}"; pkg="dtfrace"
  for i in $(seq 1 "$RACERS"); do mkbody "$pkg" "$ver" "$W/race/r${r}-${i}.json" "racer-${r}-${i}-${SUF}-$RANDOM$RANDOM"; done
  for i in $(seq 1 "$RACERS"); do
    ( curl -s -o "$W/race/r${r}-${i}.out" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
        -H 'Content-Type: application/json' --data-binary "@$W/race/r${r}-${i}.json" \
        "${BASE}/npm/${RACE}/${pkg}" > "$W/race/r${r}-${i}.code" 2>/dev/null ) &
  done
  wait
  codes=""; winners=()
  for i in $(seq 1 "$RACERS"); do
    c="$(cat "$W/race/r${r}-${i}.code" 2>/dev/null)"; codes="${codes} ${c:-000}"
    is_2xx "$c" && winners+=("$i")
  done
  echo "   round ${r} (${pkg}@${ver}): statuses${codes}"
  others="$(tr ' ' '\n' <<<"$codes" | grep -v '^$' | grep -vc '^2..$\|^409$')"
  if [ "${#winners[@]}" -ne 1 ] || [ "$others" -ne 0 ]; then
    RACE_STATUS_ERR="${RACE_STATUS_ERR}round ${r}: ${#winners[@]} success(es), ${others} answer(s) neither 2xx nor 409:${codes}
"
    for i in $(seq 1 "$RACERS"); do
      c="$(cat "$W/race/r${r}-${i}.code")"; is_2xx "$c" || [ "$c" = "409" ] || { RACE_STATUS_ERR="${RACE_STATUS_ERR}  e.g. ${c}: $(head -c 160 "$W/race/r${r}-${i}.out")
"; break; }
    done
  fi
  req GET "/npm/${RACE}/${pkg}/${ver}"
  integ="$(jqr '.dist.integrity // empty' <<<"$BODY")"
  curl -s -o "$W/race/r${r}.served" --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/npm/${RACE}/${pkg}/-/${pkg}-${ver}.tgz"
  if [ "${#winners[@]}" -eq 1 ]; then
    cmp -s "$W/race/r${r}.served" "$W/race/r${r}-${winners[0]}.json.tgz" \
      || RACE_BYTES_ERR="${RACE_BYTES_ERR}round ${r}: the served tarball ($(wc -c < "$W/race/r${r}.served") bytes) is not the winning request's (#${winners[0]}) bytes
"
  fi
  integrity_ok "$W/race/r${r}.served" "$integ" \
    || RACE_BYTES_ERR="${RACE_BYTES_ERR}round ${r}: the served tarball does not match the advertised dist.integrity ${integ:0:30}...
"
  RACE_VERS+=("$ver")
done
# the real client: `npm pack` verifies the advertised integrity of every raced version
NPM_OUT="$( { npmrc "$RACE" "/tmp/race-${SUF}"
  echo "cd /tmp/race-${SUF} && for v in ${RACE_VERS[*]}; do npm pack dtfrace@\$v --dry-run=false --loglevel=error >/dev/null 2>err.txt; rc=\$?; echo \"pack \$v rc=\$rc \$(grep -m1 -o 'EINTEGRITY\|ECONNRESET\|code E[A-Z]*' err.txt)\"; done"; } | npm_sh)"
echo "$NPM_OUT" | sed 's/^/   /'
grep -q "rc=[1-9]" <<<"$NPM_OUT" && RACE_BYTES_ERR="${RACE_BYTES_ERR}npm pack failed: $(grep 'rc=[1-9]' <<<"$NPM_OUT" | tr '\n' ' ')
"
[ "$(grep -c 'rc=0' <<<"$NPM_OUT")" -eq "$ROUNDS" ] || [ -n "$RACE_BYTES_ERR" ] \
  || RACE_BYTES_ERR="npm pack did not run for every version: ${NPM_OUT:0:200}"

begin_test "FIX #5399: ${RACERS} concurrent publishes of one version (${ROUNDS} rounds): exactly one 2xx, every loser 409 (never 500)"
if [ -z "$RACE_STATUS_ERR" ]; then pass; else fail "a concurrent loser was not answered 409" "$RACE_STATUS_ERR"; fi
begin_test "FIX #5399: after each race the served tarball is the winner's bytes and matches dist.integrity; npm pack verifies"
if [ -z "$RACE_BYTES_ERR" ]; then pass; else fail "a loser's bytes replaced the winner's tarball" "$RACE_BYTES_ERR"; fi

# =============================================================================
# #5403: stale unpublish
# =============================================================================
begin_test "CONTROL: real 'npm unpublish pkg@1.0.0 --force' removes only that version"
reset_case
for v in 1.0.0 1.1.0 1.2.0; do publish "$UNP" dtfun-ctl "$v"; is_2xx "$CODE" || fail_g "publish dtfun-ctl@${v} answered ${CODE}"; done
out="$( { npmrc "$UNP" "/tmp/unp-${SUF}"; echo "cd /tmp/unp-${SUF} && npm unpublish dtfun-ctl@1.0.0 --force --registry http://backend:8080/npm/${UNP}/ 2>&1; echo rc=\$?"; } | npm_sh)"
note "npm unpublish: $(tail -2 <<<"$out" | tr '\n' ' ')"
got="$(versions_of "$UNP" dtfun-ctl)"
note "versions after: ${got}"
[ "$got" = '["1.1.0","1.2.0"]' ] || fail_g "versions after the unpublish are ${got}, want [1.1.0, 1.2.0]"
finish_case "a plain npm unpublish of one version is broken"

# read_doc <pkg>: the full packument as `npm unpublish` reads it; sets DOC and REV
read_doc(){
  req GET "/npm/${UNP}/$1?write=true"
  DOC="$BODY"; REV="$(jqr '._rev // empty' <<<"$DOC")"
}
begin_test "FIX #5403: the full packument carries a _rev, and a publish changes it"
reset_case
publish "$UNP" dtfun-rev 1.0.0
read_doc dtfun-rev; r1="$REV"
publish "$UNP" dtfun-rev 1.1.0
read_doc dtfun-rev; r2="$REV"
note "_rev after 1.0.0: '${r1}', after 1.1.0: '${r2}'"
[ -n "$r1" ] && [ -n "$r2" ] || fail_g "the ?write=true packument carries no _rev"
[ -n "$r1" ] && [ "$r1" = "$r2" ] && fail_g "the _rev did not change with a publish"
finish_case "the packument serves no usable _rev"

begin_test "FIX #5403: a packument rewrite from a read taken before a newer publish is 409 and removes nothing"
reset_case
publish "$UNP" dtfun-stale 1.0.0; publish "$UNP" dtfun-stale 1.0.1
read_doc dtfun-stale; A_DOC="$DOC"; A_REV="${REV:-undefined}"
publish "$UNP" dtfun-stale 2.0.0
note "read rev '${A_REV}', then published 2.0.0 (${CODE})"
req PUT "/npm/${UNP}/dtfun-stale/-rev/${A_REV}" "$(jq -c 'del(.versions["1.0.0"])' <<<"$A_DOC")"
note "rewrite without 1.0.0 at the old rev: ${CODE} ${BODY:0:160}"
[ "$CODE" = "409" ] || fail_g "the stale rewrite answered ${CODE}, not 409"
got="$(versions_of "$UNP" dtfun-stale)"
note "versions after: ${got}"
[ "$got" = '["1.0.0","1.0.1","2.0.0"]' ] || fail_g "versions after the stale rewrite are ${got}; the concurrently published 2.0.0 (or 1.0.0) is gone"
finish_case "a stale npm unpublish removes a version published after the read"

begin_test "FIX #5403: a revision-less rewrite (-rev/undefined) that would remove two versions is 409"
reset_case
for v in 1.0.0 1.1.0 1.2.0; do publish "$UNP" dtfun-norev "$v"; done
read_doc dtfun-norev
req PUT "/npm/${UNP}/dtfun-norev/-rev/undefined" "$(jq -c 'del(._rev) | del(.versions["1.0.0"]) | del(.versions["1.1.0"])' <<<"$DOC")"
note "rev-less rewrite dropping 1.0.0 and 1.1.0: ${CODE} ${BODY:0:160}"
[ "$CODE" = "409" ] || fail_g "the revision-less two-version rewrite answered ${CODE}, not 409"
got="$(versions_of "$UNP" dtfun-norev)"
note "versions after: ${got}"
[ "$got" = '["1.0.0","1.1.0","1.2.0"]' ] || fail_g "versions after are ${got}"
finish_case "a revision-less rewrite can remove several versions"

begin_test "FIX #5403: a whole-package unpublish from a read taken before a newer publish is 409 and removes nothing"
reset_case
publish "$UNP" dtfun-whole 1.0.0
read_doc dtfun-whole; W_REV="${REV:-undefined}"
publish "$UNP" dtfun-whole 1.1.0
req DELETE "/npm/${UNP}/dtfun-whole/-rev/${W_REV}"
note "DELETE /-rev/${W_REV}: ${CODE} ${BODY:0:160}"
[ "$CODE" = "409" ] || fail_g "the stale whole-package unpublish answered ${CODE}, not 409"
got="$(versions_of "$UNP" dtfun-whole)"
note "versions after: ${got}"
[ "$got" = '["1.0.0","1.1.0"]' ] || fail_g "versions after are ${got}; 1.1.0 was published after the read"
finish_case "a stale whole-package unpublish removes a newer version"

# =============================================================================
# #5676: a retention delete retracts dist-tags
# =============================================================================
PR_PKG="dtfret"
for v in 1.0.0 1.1.0 2.0.0; do publish "$RET" "$PR_PKG" "$v"; is_2xx "$CODE" || echo "   publish ${PR_PKG}@${v}: ${CODE}"; done
set_tag(){ req PUT "/npm/${RET}/-/package/${PR_PKG}/dist-tags/$1" "\"$2\""; echo "   tag $1 -> $2: ${CODE}"; }
set_tag latest 2.0.0; set_tag beta 2.0.0; set_tag stable 1.1.0
AGED="$(psql_q "UPDATE artifacts SET created_at = NOW() - INTERVAL '60 days' WHERE repository_id = '${RET_ID}' AND name = '${PR_PKG}' AND version = '2.0.0' RETURNING id" | grep -cE '^[0-9a-f-]{36}$')"
req POST /api/v1/admin/lifecycle "$(jq -nc --arg n "npmc-ret-${SUF}" --arg r "$RET_ID" \
  '{name:$n,policy_type:"max_age_days",config:{days:30},repository_ids:[$r],enabled:true}')"
LP_ID="$(jqr '.id // empty' <<<"$BODY")"; LP_CODE="$CODE"
req POST "/api/v1/admin/lifecycle/${LP_ID}/execute"
EX_CODE="$CODE"; REMOVED="$(jqr '.artifacts_removed // empty' <<<"$BODY")"
echo "   aged rows: ${AGED}; policy ${LP_ID:-none} (${LP_CODE}); execute ${EX_CODE} removed=${REMOVED} ${BODY:0:160}"

begin_test "CONTROL: a max_age_days policy removes the aged version only; latest falls back to 1.1.0"
reset_case
[ "$AGED" = "1" ] || fail_g "aging 2.0.0 touched ${AGED} rows"
is_2xx "$EX_CODE" && [ "$REMOVED" = "1" ] || fail_g "the policy run answered ${EX_CODE}, removed '${REMOVED}' (want 1)"
req GET "/npm/${RET}/${PR_PKG}"
got="$(jqr -c '.versions | keys | sort' <<<"$BODY")"
note "versions after: ${got}, latest $(jqr '."dist-tags".latest' <<<"$BODY")"
[ "$got" = '["1.0.0","1.1.0"]' ] || fail_g "versions after the sweep are ${got}"
[ "$(jqr '."dist-tags".latest' <<<"$BODY")" = "1.1.0" ] || fail_g "packument latest is not 1.1.0"
finish_case "the retention sweep did not remove exactly the aged version"

begin_test "FIX #5676: after the retention delete no dist-tag names the removed version ({latest:1.1.0, stable:1.1.0})"
reset_case
req GET "/npm/${RET}/-/package/${PR_PKG}/dist-tags"
note "dist-tags: ${CODE} ${BODY:0:200}"
[ "$(jqr -cS . <<<"$BODY")" = '{"latest":"1.1.0","stable":"1.1.0"}' ] || fail_g "dist-tags are $(jqr -cS . <<<"$BODY"), want {latest:1.1.0, stable:1.1.0}"
req GET "/npm/${RET}/${PR_PKG}"
note "packument dist-tags: $(jqr -cS '."dist-tags"' <<<"$BODY")"
[ "$(jqr '."dist-tags".beta // empty' <<<"$BODY")" = "" ] || fail_g "the packument still tags beta -> $(jqr '."dist-tags".beta' <<<"$BODY") (ETARGET for npm install ${PR_PKG}@beta)"
finish_case "a retention delete leaves dist-tags naming the removed version"

# =============================================================================
# #5724: derived latest by SemVer precedence
# =============================================================================
# latest_of <pkg>: "<full packument latest>|<abbreviated latest>"
latest_of(){
  local full abbr
  req GET "/npm/${L}/$1"; full="$(jqr '."dist-tags".latest // empty' <<<"$BODY")"
  abbr="$(curl -s --max-time 30 -H "Authorization: Bearer ${TOK}" -H 'Accept: application/vnd.npm.install-v1+json' \
    "${BASE}/npm/${L}/$1" | jqr '."dist-tags".latest // empty')"
  echo "${full}|${abbr}"
}
begin_test "CONTROL: with a stable version and a newer pre-release, the derived latest is the stable one"
reset_case
publish "$L" dtfsem-ctl 1.0.0; publish "$L" dtfsem-ctl 2.0.0-rc.1
got="$(latest_of dtfsem-ctl)"; note "latest full|abbreviated: ${got}"
[ "$got" = "1.0.0|1.0.0" ] || fail_g "latest is ${got}, want 1.0.0"
finish_case "the stable-first latest rule changed"

begin_test "FIX #5724: among pre-releases of one release the derived latest follows SemVer precedence, not publish order"
reset_case
publish "$L" dtfsem-a 1.0.0-rc.1; publish "$L" dtfsem-a 1.0.0-alpha
got="$(latest_of dtfsem-a)"; note "[1.0.0-rc.1, then 1.0.0-alpha] latest: ${got}"
[ "$got" = "1.0.0-rc.1|1.0.0-rc.1" ] || fail_g "latest is ${got}, want 1.0.0-rc.1"
publish "$L" dtfsem-b 2.0.0-beta.10; publish "$L" dtfsem-b 2.0.0-beta.2
got="$(latest_of dtfsem-b)"; note "[2.0.0-beta.10, then 2.0.0-beta.2] latest: ${got}"
[ "$got" = "2.0.0-beta.10|2.0.0-beta.10" ] || fail_g "latest is ${got}, want 2.0.0-beta.10"
out="$( { npmrc "$L" "/tmp/sem-${SUF}"; echo "cd /tmp/sem-${SUF} && npm install dtfsem-a --no-audit --no-fund --loglevel=error >/dev/null 2>&1; node -p \"require('./node_modules/dtfsem-a/package.json').version\" 2>&1"; } | npm_sh)"
note "npm install dtfsem-a installed: ${out}"
[ "$(tail -1 <<<"$out")" = "1.0.0-rc.1" ] || fail_g "the real npm client installed '$(tail -1 <<<"$out")', want 1.0.0-rc.1"
finish_case "the derived latest ignores SemVer precedence among pre-releases"

# =============================================================================
# #5725: package-name rules aligned with validate-npm-package-name
# =============================================================================
begin_test "FIX #5725: node_modules and favicon.ico are refused with 400 'not allowed' (publish, packument)"
reset_case
publish "$L" node_modules 1.0.0
note "publish node_modules: ${CODE} ${BODY:0:120}"
[ "$CODE" = "400" ] && grep -qi "not allowed" <<<"$BODY" || fail_g "publishing node_modules answered ${CODE}, not 400 'not allowed'"
publish "$L" favicon.ico 1.0.0
note "publish favicon.ico: ${CODE} ${BODY:0:120}"
[ "$CODE" = "400" ] || fail_g "publishing favicon.ico answered ${CODE}, not 400"
req GET "/npm/${L}/favicon.ico"
note "GET favicon.ico: ${CODE} ${BODY:0:120}"
[ "$CODE" = "400" ] || fail_g "the favicon.ico packument answered ${CODE}, not 400"
finish_case "npm's blocked names are accepted"

begin_test "FIX #5725: a scoped name with a '.' segment (@scope/%2e) is refused with 400 before any handler"
reset_case
req PUT "/npm/${L}/@dtfdot%2f%2e" "$(mkbody "@dtfdot/." 1.0.0 "$W/pub/dot.json"; cat "$W/pub/dot.json")"
note "publish @dtfdot/.: ${CODE} ${BODY:0:160}"
[ "$CODE" = "400" ] && grep -q "path segment" <<<"$BODY" || fail_g "publishing @dtfdot/. answered ${CODE}, not 400 naming the '.' path segment"
req GET "/npm/${L}/@dtfdot%2f%2e"
note "GET @dtfdot/.: ${CODE} ${BODY:0:120}"
[ "$CODE" = "400" ] || fail_g "the @dtfdot/. packument answered ${CODE}, not 400"
finish_case "a dot-segment scoped name reaches the handlers"

begin_test "CONTROL: the scope allow-list stores a plain scope and refuses '@..'"
reset_case
req PUT "/api/v1/repositories/${SCP}/npm-scope-policy" '{"allowed_scopes":["@dtfplain"],"allow_unscoped":true}'
note "@dtfplain: ${CODE} ${BODY:0:160}"
[ "$CODE" = "200" ] && [ "$(jqr -c .allowed_scopes <<<"$BODY")" = '["@dtfplain"]' ] || fail_g "a plain scope answered ${CODE}"
req PUT "/api/v1/repositories/${SCP}/npm-scope-policy" '{"allowed_scopes":["@.."],"allow_unscoped":true}'
note "@..: ${CODE} ${BODY:0:160}"
[ "$CODE" = "400" ] || fail_g "'@..' answered ${CODE}, not 400"
finish_case "scope allow-list validation broken"

begin_test "FIX #5725: the scope allow-list accepts the scopes npm allows: @_private, @.hidden, @~tilde"
reset_case
req PUT "/api/v1/repositories/${SCP}/npm-scope-policy" '{"allowed_scopes":["@_private","@.hidden","@~tilde"],"allow_unscoped":true}'
note "PUT: ${CODE} ${BODY:0:200}"
[ "$CODE" = "200" ] || fail_g "the allow-list answered ${CODE}, not 200"
[ "$(jqr -c '.allowed_scopes | sort' <<<"$BODY")" = '["@.hidden","@_private","@~tilde"]' ] || fail_g "stored scopes are $(jqr -c .allowed_scopes <<<"$BODY")"
finish_case "the scope allow-list refuses scopes npm allows"

# =============================================================================
# #5631: npm audit through a Virtual (or a hosted repo) is never a false all-clear
# =============================================================================
# AUD_V = [hosted SH_L, Remote SH_R over mock-multi]. mock-multi has no audit API
# (a POST answers 501), so no member can answer: the honest answer is 501, not
# `{}` ("found 0 vulnerabilities"). AUD_DV = [hosted L, Remote DEADR whose
# upstream is unreachable]: 503.
AUD_V="npmc-audv-${SUF}"; AUD_DV="npmc-auddv-${SUF}"
for spec in "${AUD_V}|${SH_L}|${SH_R}" "${AUD_DV}|${L}|${DEADR}"; do
  IFS='|' read -r k m1 m2 <<<"$spec"
  req POST /api/v1/repositories "$(jq -nc --arg k "$k" --arg l "$m1" --arg r "$m2" \
    '{key:$k,name:$k,format:"npm",repo_type:"virtual",is_public:true,member_repos:[{repo_key:$l,priority:1},{repo_key:$r,priority:2}]}')"
  echo "   virtual ${k} = [${m1}, ${m2}]: ${CODE}"
done
publish "$SH_L" dtfaud 1.0.0
echo "   publish dtfaud@1.0.0 to ${SH_L}: ${CODE}"
BULK='{"dtfaud":["1.0.0"]}'
QUICK='{"name":"dtf-audit-app","version":"1.0.0","requires":{"dtfaud":"^1.0.0"},"dependencies":{"dtfaud":{"version":"1.0.0"}}}'
# audit_probe <repo> <want status> <want message fragment>: both audit endpoints
audit_probe(){
  local ep body
  for ep in "advisories/bulk|$BULK" "audits/quick|$QUICK"; do
    body="${ep#*|}"; ep="${ep%%|*}"
    req POST "/npm/$1/-/npm/v1/security/${ep}" "$body"
    note "$1 ${ep}: ${CODE} ${BODY:0:200}"
    [ "$CODE" = "$2" ] || fail_g "$1 ${ep} answered ${CODE}, want $2"
    [ "$(jqr -c . <<<"$BODY")" = "{}" ] && fail_g "$1 ${ep} answered the empty advisory set {} (a false all-clear)"
    grep -q "$3" <<<"$BODY" || fail_g "$1 ${ep}: the answer does not say '$3'"
  done
}
NPM_AUD_DIR="/tmp/aud-${SUF}"
begin_test "CONTROL: the real npm client installs dtfaud through the Virtual ${AUD_V}"
reset_case
out="$( { npmrc "$AUD_V" "$NPM_AUD_DIR"; echo "cd '$NPM_AUD_DIR' && npm init -y >/dev/null 2>&1 && npm install dtfaud@1.0.0 --no-fund --loglevel=error 2>&1; echo rc=\$?; node -p \"require('./node_modules/dtfaud/package.json').version\" 2>&1"; } | npm_sh)"
note "npm install: $(tr '\n' ' ' <<<"$out" | head -c 300)"
grep -q '^rc=0$' <<<"$out" && [ "$(tail -1 <<<"$out")" = "1.0.0" ] || fail_g "npm install dtfaud through ${AUD_V} failed"
finish_case "npm install through the Virtual is broken"

begin_test "FIX #5631: a Virtual none of whose members can answer the audit API answers both audit endpoints 501, never {}"
reset_case
audit_probe "$AUD_V" 501 "npm audit is not available through repository '${AUD_V}'"
finish_case "npm audit through a Virtual is a false all-clear"

begin_test "FIX #5631: a Virtual whose Remote member's upstream is unreachable answers 503, never {}"
reset_case
audit_probe "$AUD_DV" 503 "npm audit could not be performed through repository '${AUD_DV}'"
finish_case "an unreachable audit upstream behind a Virtual reads as a clean audit"

begin_test "FIX #5631: a hosted (Local) repository answers both audit endpoints 501, never {}"
reset_case
audit_probe "$L" 501 "npm audit is not available through repository '${L}'"
finish_case "npm audit against a hosted repository is a false all-clear"

begin_test "FIX #5631: real 'npm audit' through the Virtual fails instead of reporting 'found 0 vulnerabilities'"
reset_case
out="$( { echo "cd '$NPM_AUD_DIR' && npm audit --registry http://backend:8080/npm/${AUD_V}/ 2>&1; echo rc=\$?"; } | npm_sh)"
note "npm audit: $(tr '\n' ' ' <<<"$out" | head -c 400)"
grep -qi "found 0 vulnerabilities" <<<"$out" && fail_g "npm audit printed 'found 0 vulnerabilities' for a tree nobody audited"
grep -q '^rc=0$' <<<"$out" && fail_g "npm audit exited 0"
grep -q '^rc=' <<<"$out" || fail_g "npm audit did not run"
finish_case "the real npm audit reports a clean tree through the Virtual"

# #3955 shadowing guard: the Virtual is [hosted SH_L (priority 1), Remote SH_R
# over mock-multi (priority 2)]; mock-multi offers every name at 1.0.1. A hosted
# member that owns name@1.0.1 must withhold the Remote for that tarball. While
# the hosted object is readable the hosted member answers first either way, so
# the guard is only observable once the hosted read misses: the oracle points the
# hosted row at a storage key that holds no object (a lost or unreadable object,
# a precondition no client can create) and fetches again. The Remote's bytes must never be served.
declare -A SH_TGZ
shadow_publish(){ # <pkg>: publish <pkg>@1.0.1 into SH_L and fetch it through the Virtual
  local pkg="$1" short="${1##*/}" st
  publish "$SH_L" "$pkg" 1.0.1 "hosted-${pkg}-${SUF}"; SH_TGZ[$pkg]="$PUB_TGZ"
  note "publish ${pkg}@1.0.1 to ${SH_L}: ${CODE}"
  is_2xx "$CODE" || fail_g "the hosted publish of ${pkg} answered ${CODE}"
  st="$(curl -s -o "$W/shadow.tgz" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
    "${BASE}/npm/${SH_V}/${pkg}/-/${short}-1.0.1.tgz")"
  note "virtual tarball ${pkg}: ${st}, $(wc -c < "$W/shadow.tgz") bytes"
  [ "$st" = "200" ] && cmp -s "$W/shadow.tgz" "${SH_TGZ[$pkg]}" || fail_g "the Virtual served ${st} and not the hosted member's bytes for ${pkg}@1.0.1"
}
shadow_drop(){ # <pkg>: point the hosted row of <pkg>@1.0.1 at a missing object; sets DROPPED
  DROPPED="$(psql_q "UPDATE artifacts a SET storage_key = a.storage_key || '.dtf-missing' FROM repositories r WHERE r.id = a.repository_id AND r.key = '${SH_L}' AND a.name = '$1' AND a.version = '1.0.1' AND a.is_deleted = false RETURNING a.storage_key" | grep -c 'dtf-missing$')"
  note "hosted row of $1@1.0.1 now names a missing object: ${DROPPED:-0} row(s)"
}
shadow_after_miss(){ # <pkg>: the Virtual must not serve the Remote's bytes
  local pkg="$1" short="${1##*/}" st
  st="$(curl -s -o "$W/shadow2.tgz" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
    "${BASE}/npm/${SH_V}/${pkg}/-/${short}-1.0.1.tgz")"
  note "virtual tarball ${pkg} after the hosted miss: ${st}, $(wc -c < "$W/shadow2.tgz") bytes, index.js='$(tar xzOf "$W/shadow2.tgz" package/index.js 2>/dev/null | head -c 60)'"
  [ "${DROPPED:-0}" -ge 1 ] 2>/dev/null || { fail_g "the hosted row of ${pkg} could not be staged (precondition)"; return; }
  [ "$st" = "200" ] && tar xzOf "$W/shadow2.tgz" package/index.js 2>/dev/null | grep -q "upstream" \
    && fail_g "the Virtual served the Remote member's bytes (${st}) for the hosted-owned ${pkg}@1.0.1"
  [ "$st" = "200" ] && ! cmp -s "$W/shadow2.tgz" "${SH_TGZ[$pkg]}" && fail_g "the Virtual answered 200 with bytes that are not the hosted member's"
}
begin_test "CONTROL: hosted @dtfsh/x@1.0.1 and @_dtfsh/x@1.0.1 are served from the hosted member through the Virtual"
reset_case
shadow_publish "@dtfsh/x"
shadow_publish "@_dtfsh/x"
finish_case "the Virtual does not serve the hosted member's bytes"

begin_test "CONTROL: after the hosted object of @dtfsh/x@1.0.1 goes missing, the Virtual still withholds the Remote's 1.0.1"
reset_case
shadow_drop "@dtfsh/x"; shadow_after_miss "@dtfsh/x"
finish_case "the npm virtual shadowing guard is broken for a plain scope"

begin_test "FIX #5725: for a hosted @_dtfsh/x@1.0.1 (scope starting with '_') the Virtual withholds the Remote's 1.0.1 too"
reset_case
shadow_drop "@_dtfsh/x"; shadow_after_miss "@_dtfsh/x"
finish_case "a Remote member shadows a hosted package whose scope starts with '_'"

end_suite
