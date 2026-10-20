#!/usr/bin/env bash
# =============================================================================
# tiers/image-build-spec-validation/oracle.sh
#   GHSA-59mx-6fq9-pp9p (1.11.0, artifact-keeper#4588) a pip requirement that
#   carries a line break (inside the extras bracket or around a comparator)
#   is refused 400 by POST /api/v1/repositories/{key}/image-builds/render and
#   by POST .../image-builds, through the legacy `pip` field and a `packages`
#   group, so it can no longer append its own `RUN` instruction to the
#   generated Containerfile while AK_IMAGE_BUILD_ALLOW_RUN is false
# See the manifest for the topology.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

post(){ # <path-suffix> <json> -> http code, body in $W/resp.json
  curl -s -o "$W/resp.json" -w '%{http_code}' --max-time 30 -X POST -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$2" "$BASE/api/v1/repositories/${R_IMG}/image-builds$1" || echo 000
}
build_count(){ curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/${R_IMG}/image-builds" | jqr '.items | length'; }
# Lines of the containerfile in $W/resp.json (render) that start a RUN instruction.
run_lines(){ jqr '.containerfile // empty' < "$W/resp.json" | grep -c '^RUN ' || true; }

# The hostile requirements from the advisory and the fix's unit test, as JSON
# string literals (the escapes are decoded by the server's JSON parser).
PAYLOADS=(
  '"foo[a\nRUN echo pwned]"'
  '"foo[a,\nRUN echo pwned]"'
  '"foo[a\r\nRUN echo pwned]"'
  '"foo[a\rRUN echo pwned]"'
  '"foo ==\n1.0"'
  '"foo==1.0 ,\n>=0.9"'
  '"foo[a\u000bRUN echo pwned]"'
  '"foo[a\u000cRUN echo pwned]"'
)

# =============================================================================
begin_suite "image-build-spec-validation"

begin_test "setup: admin login, local docker repository"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
R_IMG="ibs-${RUN_ID##*-}-$$"
k="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg k "$R_IMG" '{key:$k,name:$k,format:"docker",repo_type:"local",is_public:false}')" | jqr '.key // empty')"
if [ "$k" != "$R_IMG" ]; then infra_fail "could not create docker repository ${R_IMG}"; end_suite; fi
echo "-- repo: ${R_IMG}"
pass

begin_test "CONTROL: a benign spec renders: one RUN pip install line carrying each requirement, comparators and extras with spaces intact"
reset_case
code="$(post /render '{"spec":{"base_image":"python:3.12","pip":["requests==2.32.3","foo[a, b]","bar >= 1.0, < 2"]}}')"
note "render benign: HTTP ${code}, RUN lines $(run_lines)"
[ "$code" = "200" ] || fail_g "benign render answered ${code}: $(head -c 200 "$W/resp.json")"
cf="$(jqr '.containerfile // empty' < "$W/resp.json")"
for req in "'requests==2.32.3'" "'foo[a, b]'" "'bar >= 1.0, < 2'"; do
  case "$cf" in *"$req"*) ;; *) fail_g "rendered Containerfile lacks ${req}";; esac
done
[ "$(run_lines)" = "1" ] || fail_g "expected exactly one RUN line, got $(run_lines)"
finish_case "a well-formed spec must render"

begin_test "CONTROL: raw RUN lines are refused 400 while AK_IMAGE_BUILD_ALLOW_RUN is off, and an apt spec with a control character is refused 400"
reset_case
code="$(post /render '{"spec":{"base_image":"python:3.12","run":["echo pwned"]}}')"
note "render with run: HTTP ${code} $(jqr '.message // empty' < "$W/resp.json")"
[ "$code" = "400" ] || fail_g "a raw RUN line answered ${code}"
code="$(post /render '{"spec":{"base_image":"debian:12","apt":["curl\u000bRUN"]}}')"
note "render apt with VT: HTTP ${code} $(jqr '.message // empty' < "$W/resp.json")"
[ "$code" = "400" ] || fail_g "an apt spec with a control character answered ${code}"
finish_case "the setting the advisory bypasses must be in force"

begin_test "CONTROL: a benign build request is accepted and recorded (BuildKit is absent, so it fails to dispatch later)"
reset_case
before="$(build_count)"
code="$(post "" '{"image":"dtf/benign","tag":"v1","spec":{"base_image":"python:3.12","pip":["requests==2.32.3"]}}')"
after="$(build_count)"
note "create benign: HTTP ${code} status=$(jqr '.status // empty' < "$W/resp.json"); builds ${before} -> ${after}"
case "$code" in 2*) ;; *) fail_g "benign build answered ${code}: $(head -c 200 "$W/resp.json")";; esac
[ "${after:-0}" -gt "${before:-0}" ] 2>/dev/null || fail_g "no build was recorded"
finish_case "the create path must accept a well-formed spec"

begin_test "GHSA-59mx: render refuses each line-breaking pip requirement with 400 VALIDATION_ERROR, through the pip field and a packages group"
reset_case
for p in "${PAYLOADS[@]}"; do
  for shape in pip group; do
    if [ "$shape" = pip ]; then
      body="{\"spec\":{\"base_image\":\"python:3.12\",\"pip\":[${p}]}}"
    else
      body="{\"spec\":{\"base_image\":\"python:3.12\",\"packages\":[{\"manager\":\"pip\",\"packages\":[${p}]}]}}"
    fi
    code="$(post /render "$body")"
    if [ "$code" = "400" ] && [ "$(jqr '.code // empty' < "$W/resp.json")" = "VALIDATION_ERROR" ]; then
      note "${shape} ${p}: 400 $(jqr '.message // empty' < "$W/resp.json")"
    else
      note "${shape} ${p}: HTTP ${code}, RUN lines in the rendered Containerfile: $(run_lines)"
      fail_g "${shape} ${p} answered ${code}, expected 400 VALIDATION_ERROR"
    fi
  done
done
finish_case "a requirement must not be able to add a Containerfile instruction"

begin_test "GHSA-59mx: creating a build with a line-breaking pip requirement is refused 400 and records nothing"
reset_case
before="$(build_count)"
code="$(post "" '{"image":"dtf/hostile","tag":"v1","spec":{"base_image":"python:3.12","pip":["foo[a\nRUN echo pwned]"]}}')"
after="$(build_count)"
note "create hostile: HTTP ${code} $(head -c 160 "$W/resp.json"); builds ${before} -> ${after}"
[ "$code" = "400" ] || fail_g "hostile build answered ${code}, expected 400"
[ "$after" = "$before" ] || fail_g "a build was recorded for the hostile spec"
injected="$(curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/${R_IMG}/image-builds" \
  | jq -r '.items[].containerfile // empty' 2>/dev/null | grep -c '^RUN echo pwned' || true)"
note "recorded Containerfiles with an injected 'RUN echo pwned' line: ${injected}"
[ "$injected" = "0" ] || fail_g "a recorded Containerfile carries the injected RUN instruction"
finish_case "the build path must refuse the injection before recording a build"

end_suite
