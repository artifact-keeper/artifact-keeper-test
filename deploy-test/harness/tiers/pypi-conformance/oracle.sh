#!/usr/bin/env bash
# =============================================================================
# tiers/pypi-conformance/oracle.sh — corpus runner for conformance/corpus/pypi
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mockpypi-conf` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH, DTF_SLOT, DTF_DIR.
#
# For each corpus scenario (conformance/corpus/pypi/*.json) we:
#   1. create an AK remote pypi repo pointing at http://mock-pypi-conf/<variant>,
#   2. run each step (GET a rewritten path against AK),
#   3. assert expect.status / body_contains[] / body_not_contains[].
#
# The scenarios and the mock they drive are credited in conformance/CREDITS.md
# (mock pattern: astral-sh/uv pypi_proxy, Apache-2.0 OR MIT).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq

# Locate the corpus relative to this tier (DTF_DIR = harness/..).
CORPUS_DIR="${DTF_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}/conformance/corpus/pypi"
UPSTREAM_BASE="http://mock-pypi-conf"     # docker-internal host on the mock net
SUF="${RUN_ID##*-}-$$"

begin_suite "pypi-conformance"

if [ ! -d "$CORPUS_DIR" ]; then
  begin_test "preflight: pypi corpus present"; fail "no corpus dir at ${CORPUS_DIR}"; end_suite
fi

auth_admin
setup_workdir

# Resolve a scenario's fields, run it. Uses jq for the JSON walk.
SKIPPED_NONDTF=0
run_scenario() { # FILE
  local file="$1" id variant pkg nsteps repo runners
  id="$(jq -r '.id' "$file")"
  # The DTF runner only executes HTTP scenarios. Unit-level vectors (e.g. the
  # pypa/packaging version/tag corpus) carry runners:["unit"] and are consumed
  # by the (separate) unit runner — skip them here without noise.
  runners="$(jq -r '(.runners // ["dtf"]) | join(",")' "$file" 2>/dev/null)"
  case ",${runners}," in
    *",dtf,"*) : ;;
    *) SKIPPED_NONDTF=$((SKIPPED_NONDTF+1)); return 0 ;;
  esac
  variant="$(jq -r '.mock_variant // "clean"' "$file")"
  pkg="$(jq -r '.package // "dtfpkg"' "$file")"
  nsteps="$(jq -r '.steps | length' "$file")"
  repo="pyconf-$(printf '%s' "$id" | tr -c 'a-z0-9' '-' | tr -s '-')-${DTF_SLOT:-x}-${SUF}"
  repo="${repo:0:48}"

  # Point a remote repo at this scenario's variant route.
  if ! api_post "/api/v1/repositories" \
      "{\"key\":\"${repo}\",\"name\":\"${repo}\",\"format\":\"pypi\",\"repo_type\":\"remote\",\"upstream_url\":\"${UPSTREAM_BASE}/${variant}\",\"is_public\":true}" >/dev/null 2>&1; then
    begin_test "[${id}] setup: create remote repo -> ${variant}"
    fail "could not create remote pypi repo ${repo} (upstream ${UPSTREAM_BASE}/${variant})"
    return
  fi

  local i
  for (( i=0; i<nsteps; i++ )); do
    local desc method path exp_status body code ok reason
    desc="$(jq -r ".steps[$i].desc // \"step $i\"" "$file")"
    method="$(jq -r ".steps[$i].request.method // \"GET\"" "$file")"
    path="$(jq -r ".steps[$i].request.path" "$file")"
    exp_status="$(jq -r ".steps[$i].expect.status // empty" "$file")"
    # substitute {repo}/{pkg}
    path="${path//\{repo\}/$repo}"; path="${path//\{pkg\}/$pkg}"

    begin_test "[${id}] ${desc}"
    body="${WORK_DIR}/resp.$$.$i"
    code="$(curl -s -o "$body" -w '%{http_code}' $CURL_TIMEOUT -X "$method" \
            "${BASE_URL}${path}" -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000)"

    ok=1; reason=""
    if [ -n "$exp_status" ] && [ "$code" != "$exp_status" ]; then
      ok=0; reason="status=${code} want ${exp_status}"
    fi
    # body_contains[]
    while IFS= read -r needle; do
      [ -z "$needle" ] && continue
      if ! grep -qF -- "$needle" "$body" 2>/dev/null; then ok=0; reason="${reason}; missing '${needle}'"; fi
    done < <(jq -r ".steps[$i].expect.body_contains // [] | .[]" "$file")
    # body_not_contains[]
    while IFS= read -r needle; do
      [ -z "$needle" ] && continue
      if grep -qF -- "$needle" "$body" 2>/dev/null; then ok=0; reason="${reason}; leaked '${needle}'"; fi
    done < <(jq -r ".steps[$i].expect.body_not_contains // [] | .[]" "$file")

    if [ "$ok" = "1" ]; then
      pass
    else
      # Surface the response inline so a gate failure is triageable without a re-run.
      echo "  >> [${id}] AK ${method} ${path} -> ${code}; body: $(head -c 500 "$body" 2>/dev/null | tr '\n' ' ')" >&2
      fail "conformance step failed: ${reason}" "$(head -c 400 "$body" 2>/dev/null)"
    fi
    rm -f "$body"
  done

  api_delete "/api/v1/repositories/${repo}" >/dev/null 2>&1 || true
}

shopt -s nullglob
FILES=( "${CORPUS_DIR}"/*.json )
if [ "${#FILES[@]}" -eq 0 ]; then
  begin_test "preflight: at least one pypi scenario"; fail "no *.json in ${CORPUS_DIR}"; end_suite
fi
for f in "${FILES[@]}"; do
  run_scenario "$f"
done
if [ "$SKIPPED_NONDTF" -gt 0 ]; then
  echo "  >> pypi-conformance: skipped ${SKIPPED_NONDTF} unit-only scenario(s) (consumed by the unit runner, not the DTF runner)" >&2
fi

end_suite
