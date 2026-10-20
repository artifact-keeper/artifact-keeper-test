#!/usr/bin/env bash
# =============================================================================
# tiers/openapi-curation-optional/oracle.sh: UpdateRepositoryRequest
# curation_default_action is optional in the served OpenAPI spec
# (artifact-keeper#4330, fixed by #4793), filesystem + api.swagger.
# =============================================================================
# Background (handlers/repositories.rs::UpdateRepositoryRequest): the field is
# `Option<String>` and update_repository only touches the stored value when it
# is present, but its utoipa override was `value_type = String`, so the served
# spec listed it under `required`. The fix makes the override
# `value_type = Option<String>`.
#
# Asserts against the RUNNING instance:
#   CONTROL  /api/v1/openapi.json is served and parses as JSON.
#   CONTROL  components.schemas.UpdateRepositoryRequest declares the
#            curation_default_action property (guards a vacuous pass).
#   FIX      curation_default_action is NOT in that schema's `required`.
#            RED on 1.11.2 (it is listed).
#   CONTROL  `required` minus curation_default_action equals the 1.11.2 list
#            (EXPECTED_OTHER_REQUIRED): the fix did not change the other fields.
#   CONTROL  PATCH with curation_default_action=review -> 200; API and DB say
#            review.
#   CONTROL  PATCH WITHOUT the field (description only) -> 200; description
#            changed, curation_default_action still review (API and DB).
#   CONTROL  PATCH with curation_default_action=allow -> 200, changes it back.
#   CONTROL  PATCH with curation_default_action=block -> 400, stored value kept.
#
# run.sh exports BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SCHEMA="UpdateRepositoryRequest"
FIELD="curation_default_action"
# `required` of UpdateRepositoryRequest on ak-backend:1.11.2, with FIELD
# removed (sorted, JSON). The fix must leave exactly this set.
EXPECTED_OTHER_REQUIRED='[]'

SUF="${RUN_ID##*-}-$$"
REPO="curopt-${DTF_SLOT}-${SUF}"
WORK="$(mktemp -d -t dtf-curopt-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

# req METHOD PATH [JSON]: sets CODE and BODY.
CODE=""; BODY=""
req() {
  local m="$1" p="$2" d="${3:-}"
  local args=(-s --max-time 60 -o "$WORK/body" -w '%{http_code}' -X "$m" -H "$(auth_header)")
  [ -n "$d" ] && args+=(-H 'Content-Type: application/json' -d "$d")
  CODE="$(curl "${args[@]}" "${BASE_URL}${p}" 2>/dev/null || echo 000)"
  BODY="$(cat "$WORK/body" 2>/dev/null || true)"
}

api_action() { req GET "/api/v1/repositories/${REPO}"; printf '%s' "$BODY" | jq -r ".${FIELD} // \"<absent>\"" 2>/dev/null; }
api_desc()   { req GET "/api/v1/repositories/${REPO}"; printf '%s' "$BODY" | jq -r '.description // ""' 2>/dev/null; }
db_action()  { psql_q "SELECT ${FIELD} FROM repositories WHERE key = '${REPO}'"; }

begin_suite "openapi-curation-optional"
auth_admin

# =============================================================================
# The served spec
# =============================================================================
begin_test "CONTROL: /api/v1/openapi.json is served and parses as JSON"
SPEC="$WORK/openapi.json"
HTTP="$(curl -s --max-time 60 -o "$SPEC" -w '%{http_code}' "${BASE_URL}/api/v1/openapi.json" 2>/dev/null || echo 000)"
echo "-- GET /api/v1/openapi.json -> HTTP ${HTTP} ($(wc -c <"$SPEC" 2>/dev/null || echo 0) bytes)"
SPEC_OK=0
if [ "$HTTP" != "200" ]; then
  fail "openapi.json not served (HTTP ${HTTP}); api.swagger must set ENABLE_SWAGGER=true"
elif ! jq -e '.openapi and .paths and .components.schemas' "$SPEC" >/dev/null 2>&1; then
  fail "openapi.json did not parse as an OpenAPI JSON document"
else
  SPEC_OK=1; pass
fi

REQUIRED='null'
begin_test "CONTROL: ${SCHEMA} declares the ${FIELD} property"
if [ "$SPEC_OK" != "1" ]; then
  fail "spec not retrievable"
else
  PROP="$(jq -c --arg s "$SCHEMA" --arg f "$FIELD" '.components.schemas[$s].properties[$f] // null' "$SPEC")"
  REQUIRED="$(jq -c --arg s "$SCHEMA" '(.components.schemas[$s].required // []) | sort' "$SPEC")"
  echo "-- ${SCHEMA}.properties.${FIELD} = ${PROP}"
  echo "-- ${SCHEMA}.required = ${REQUIRED}"
  if [ "$PROP" != "null" ]; then pass; else
    fail "${SCHEMA}.properties.${FIELD} missing from the served spec (cannot evaluate #4330)"
  fi
fi

begin_test "FIX #4330: ${FIELD} is not listed in ${SCHEMA}.required"
if [ "$REQUIRED" = "null" ]; then
  fail "schema not retrievable"
elif printf '%s' "$REQUIRED" | jq -e --arg f "$FIELD" 'index($f) == null' >/dev/null 2>&1; then
  pass
else
  fail "${SCHEMA}.required lists ${FIELD} (#4330): ${REQUIRED}; generated SDKs must then send it on every update"
fi

begin_test "CONTROL: ${SCHEMA}.required minus ${FIELD} equals the 1.11.2 list ${EXPECTED_OTHER_REQUIRED}"
if [ "$REQUIRED" = "null" ]; then
  fail "schema not retrievable"
else
  OTHER="$(printf '%s' "$REQUIRED" | jq -c --arg f "$FIELD" 'map(select(. != $f)) | sort')"
  echo "-- other required: ${OTHER}"
  if [ "$OTHER" = "$EXPECTED_OTHER_REQUIRED" ]; then pass; else
    fail "required set of the other fields changed: got ${OTHER}, want ${EXPECTED_OTHER_REQUIRED}"
  fi
fi

# =============================================================================
# The live update path
# =============================================================================
begin_test "SETUP: create generic repository ${REPO}"
req POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false,description:"before"}')"
if [ "${CODE:0:1}" = "2" ]; then
  echo "-- created; ${FIELD} api=$(api_action) db=$(db_action)"
  pass
else
  infra_fail "create repository ${REPO} -> HTTP ${CODE}: ${BODY:0:300}"; end_suite; exit $?
fi

begin_test "CONTROL: PATCH with ${FIELD}=review sets it (API and DB)"
req PATCH "/api/v1/repositories/${REPO}" '{"curation_default_action":"review"}'
C1="$CODE"; R1="$(printf '%s' "$BODY" | jq -r ".${FIELD} // empty" 2>/dev/null)"
A1="$(api_action)"; D1="$(db_action)"
echo "-- PATCH -> ${C1} (response ${FIELD}=${R1}); GET=${A1}; DB=${D1}"
if [ "$C1" = "200" ] && [ "$R1" = "review" ] && [ "$A1" = "review" ] && [ "$D1" = "review" ]; then pass; else
  fail "set to review: HTTP ${C1}, response=${R1}, GET=${A1}, DB=${D1}"
fi

begin_test "CONTROL: PATCH WITHOUT ${FIELD} succeeds and leaves the stored value untouched"
req PATCH "/api/v1/repositories/${REPO}" "{\"description\":\"after-${SUF}\"}"
C2="$CODE"; R2="$(printf '%s' "$BODY" | jq -r ".${FIELD} // empty" 2>/dev/null)"
A2="$(api_action)"; DESC="$(api_desc)"; D2="$(db_action)"
echo "-- PATCH {description} -> ${C2} (response ${FIELD}=${R2}); GET ${FIELD}=${A2} description=${DESC}; DB=${D2}"
if [ "$C2" = "200" ] && [ "$DESC" = "after-${SUF}" ] && [ "$A2" = "review" ] && [ "$D2" = "review" ]; then pass; else
  fail "omitting ${FIELD}: HTTP ${C2}, description=${DESC}, GET ${FIELD}=${A2}, DB=${D2} (want 200, after-${SUF}, review, review)"
fi

begin_test "CONTROL: PATCH with ${FIELD}=allow changes it back"
req PATCH "/api/v1/repositories/${REPO}" '{"curation_default_action":"allow"}'
C3="$CODE"; A3="$(api_action)"; D3="$(db_action)"
echo "-- PATCH -> ${C3}; GET=${A3}; DB=${D3}"
if [ "$C3" = "200" ] && [ "$A3" = "allow" ] && [ "$D3" = "allow" ]; then pass; else
  fail "set to allow: HTTP ${C3}, GET=${A3}, DB=${D3}"
fi

begin_test "CONTROL: PATCH with ${FIELD}=block is refused 400 and the stored value is kept"
req PATCH "/api/v1/repositories/${REPO}" '{"curation_default_action":"block"}'
C4="$CODE"; B4="$BODY"; A4="$(api_action)"; D4="$(db_action)"
echo "-- PATCH block -> ${C4}: ${B4:0:200}; GET=${A4}; DB=${D4}"
if [ "$C4" = "400" ] && [ "$A4" = "allow" ] && [ "$D4" = "allow" ]; then pass; else
  fail "block: HTTP ${C4} (want 400), GET=${A4}, DB=${D4} (want allow)"
fi

req DELETE "/api/v1/repositories/${REPO}"
end_suite
