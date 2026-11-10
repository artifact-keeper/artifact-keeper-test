#!/usr/bin/env bash
# roles/contractor.sh - Nina Petrov, Petrov Embedded LLC, contractor at Halcyon Robotics.
#
# ROLES.md "## contractor". Nina's only grant is read on HAL_CONTRACTOR_REPO
# (${HAL}-fw-maven-local). The internal handbook is readable too, by design.
# Every other Halcyon repository must look exactly like a key that does not
# exist (#5458): same status, same body (with the key itself masked), on the
# native format routes, the REST routes, /general and OCI /v2, for reads and
# writes, with every credential form she holds. Writes to the one repository
# she can read answer 403. Mid-day the platform admin deletes her rule
# (barrier nina-offboarded); her SDK repository then joins the hidden set,
# while the internal handbook stays readable (observation, VIS).
#
# Credentials: CONTRACTOR (jwt:, basic:), plus a personal API token she mints
# for herself (${HAL}-contractor-laptop, read:artifacts + write:artifacts, no
# repository list) so the Basic user:token and Bearer token forms are covered.
# The token is revoked before cs_end. The role publishes nothing that succeeds,
# so it leaves no artifacts behind.
#
# Barriers: waits fw-sdk-1.1.0 (firmware), signals nina-done, waits
# nina-offboarded (platform-admin). Timeout: CS_BARRIER_TIMEOUT (default 600 s).

source "$(dirname "$0")/../lib.sh"

cs_begin contractor
# Barriers this role signals: released as "failed" if it exits early.
cs_signals nina-done

BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
SDK_G="${HAL_SEED_MAVEN_GROUP:-com/halcyon/fw}"
SDK_A="${HAL_SEED_MAVEN_ARTIFACT:-hal-sdk}"
SDK_V="${HAL_SEED_MAVEN_VERSION:-1.0.0}"
SDK_JAR="/maven/${HAL_CONTRACTOR_REPO}/${SDK_G}/${SDK_A}/${SDK_V}/${SDK_A}-${SDK_V}.jar"
SDK_POM="/maven/${HAL_CONTRACTOR_REPO}/${SDK_G}/${SDK_A}/${SDK_V}/${SDK_A}-${SDK_V}.pom"
SDK_JAR_PATH="${SDK_G}/${SDK_A}/${SDK_V}/${SDK_A}-${SDK_V}.jar"
BOGUS="${HAL}-contractor-nosuchrepo"
IMG="${HAL}-contractor-probe"
PROBE_PATH="${HAL}-contractor/probe.txt"

NATIVE_404="Repository not found"
NATIVE_403="You do not have permission to perform this action on this repository"

_cs_work
PROBE_FILE="${CS_WORK}/probe.txt"
printf 'Nina was here\n' > "$PROBE_FILE"
printf 'BZh9-not-really-a-conda-package\n' > "${CS_WORK}/probe-0.1-0.tar.bz2"
printf 'not-really-a-chart\n' > "${CS_WORK}/${HAL}-contractor-chart-0.1.0.tgz"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# like_unknown WHAT NEEDLE KEY CMD...
# Runs CMD once with @KEY@ replaced by a key that names no repository, then
# with @KEY@ replaced by KEY. PASS when the real key answers 404, the body has
# NEEDLE, and status and body (each with its own key masked) are identical to
# the unknown-key answer: the existence-hiding contract of #5458.
like_unknown() {
  local what="$1" needle="$2" key="$3"; shift 3
  local -a a=()
  local x us ub rb
  for x in "$@"; do a+=("${x//@KEY@/$BOGUS}"); done
  "${a[@]}"
  us="$CS_STATUS"; ub="${CS_BODY//$BOGUS/@KEY@}"
  local uct uwa
  uct=$(cs_header content-type); uwa=$(cs_header www-authenticate)
  a=()
  for x in "$@"; do a+=("${x//@KEY@/$key}"); done
  "${a[@]}"
  rb="${CS_BODY//$key/@KEY@}"
  if [ "$uct" != "$(cs_header content-type)" ] || [ "$uwa" != "$(cs_header www-authenticate)" ]; then
    cs_record "$what" FAIL "headers differ from the unknown-key answer: Content-Type '${uct}' vs '$(cs_header content-type)', WWW-Authenticate '${uwa}' vs '$(cs_header www-authenticate)' (${CS_LAST_REQ})"
    return 1
  fi
  if [ "$CS_STATUS" != "404" ]; then
    cs_record "$what" FAIL "expected 404 like unknown key, got ${CS_STATUS} (${CS_LAST_REQ}); unknown key gave ${us}" \
      "$(printf '%s' "$CS_BODY" | head -c 600)"
    return 1
  fi
  if ! printf '%s' "$CS_BODY" | grep -qF -- "$needle"; then
    cs_record "$what" FAIL "404 but body lacks '${needle}' (${CS_LAST_REQ})" "$(printf '%s' "$CS_BODY" | head -c 600)"
    return 1
  fi
  if [ "$us" != "$CS_STATUS" ] || [ "$ub" != "$rb" ]; then
    cs_record "$what" FAIL "404 differs from the unknown-key answer (unknown: ${us} '$(printf '%s' "$ub" | head -c 160)'; real: '$(printf '%s' "$rb" | head -c 160)') (${CS_LAST_REQ})" \
      "unknown=${ub:0:300} real=${rb:0:300}"
    return 1
  fi
  cs_record "$what" PASS "HTTP 404 '${needle}', identical to unknown key"
}

# expect_text WHAT STATUS NEEDLE - status and body needle in one check.
expect_text() {
  local what="$1" st="$2" needle="$3"
  if [ "$CS_STATUS" = "$st" ] && printf '%s' "$CS_BODY" | grep -qF -- "$needle"; then
    cs_record "$what" PASS "HTTP ${st} '${needle}'"
    return 0
  fi
  cs_record "$what" FAIL "expected HTTP ${st} with '${needle}', got ${CS_STATUS} (${CS_LAST_REQ})" \
    "$(printf '%s' "$CS_BODY" | head -c 600)"
  return 1
}

# listed_keys - the repository keys in the last listing that belong to this
# test: every key of this company (HAL_REPO_* in personas.env) and every
# private repository. Another company's internal or public repository on the
# same instance (a second RUN_ID) is readable by any login by design (VIS),
# so it is set aside and named in the note instead of failing the exact-set
# checks; a foreign PRIVATE repository in the list still fails them.
CS_COMPANY_KEYS=$(for v in $(compgen -v HAL_REPO_ | grep -v '_ID$'); do printf '%s\n' "${!v}"; done | jq -R . | jq -sc 'map(select(. != ""))')
listed_keys() {
  printf '%s' "$CS_BODY" | jq -c --argjson c "$CS_COMPANY_KEYS" \
    '[.items[]? | select((.key | IN($c[])) or (.visibility == "private")) | .key]' 2>/dev/null || echo '[]'
}
# foreign_open - the keys listed_keys set aside (comma-separated).
foreign_open() {
  printf '%s' "$CS_BODY" | jq -r --argjson c "$CS_COMPANY_KEYS" \
    '[.items[]? | select((.key | IN($c[])) | not) | select(.visibility != "private") | .key] | join(",")' 2>/dev/null || true
}

# expect_set WHAT EXPECTED_JSON_ARRAY ACTUAL_JSON_ARRAY - set equality.
expect_set() {
  local what="$1" want="$2" have="$3"
  if [ "$CS_STATUS" != "200" ]; then
    cs_record "$what" FAIL "HTTP ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:600}"
    return 1
  fi
  if jq -en --argjson w "$want" --argjson h "$have" '($w|unique) == ($h|unique)' >/dev/null 2>&1; then
    local fo
    fo=$(foreign_open)
    cs_record "$what" PASS "HTTP 200; exactly $(jq -nc --argjson h "$have" '$h|unique')${fo:+; also non-private repos of another company (VIS, by design): ${fo}}"
    return 0
  fi
  cs_record "$what" FAIL "expected exactly ${want}, got $(jq -nc --argjson h "$have" '$h|unique' 2>/dev/null) (${CS_LAST_REQ})" "${CS_BODY:0:600}"
  return 1
}

# expect_subset WHAT ALLOWED_JSON_ARRAY ACTUAL_JSON_ARRAY - every actual is allowed.
expect_subset() {
  local what="$1" allowed="$2" have="$3"
  if [ "$CS_STATUS" != "200" ]; then
    cs_record "$what" FAIL "HTTP ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:600}"
    return 1
  fi
  local extra
  extra=$(jq -nc --argjson a "$allowed" --argjson h "$have" '($h|unique) - $a' 2>/dev/null || echo '"unparsable"')
  if [ "$extra" = "[]" ]; then
    cs_record "$what" PASS "HTTP 200; repositories seen $(jq -nc --argjson h "$have" '$h|unique')"
    return 0
  fi
  cs_record "$what" FAIL "hits outside her repositories: ${extra} (${CS_LAST_REQ})" "${CS_BODY:0:600}"
  return 1
}

# Native read probe and native write for a repository, by format. @KEY@ is the
# repository key. Each prints nothing; they are CMD arrays for like_unknown.
declare -A FMT=(
  ["$HAL_REPO_FW_CARGO_LOCAL"]=cargo ["$HAL_REPO_FW_CARGO_REMOTE"]=cargo ["$HAL_REPO_FW_CARGO"]=cargo
  ["$HAL_REPO_FW_MAVEN_LOCAL"]=maven ["$HAL_REPO_FW_MAVEN_REMOTE"]=maven ["$HAL_REPO_FW_MAVEN"]=maven
  ["$HAL_REPO_WEB_NPM_LOCAL"]=npm ["$HAL_REPO_WEB_NPM_REMOTE"]=npm ["$HAL_REPO_WEB_NPM"]=npm
  ["$HAL_REPO_DATA_PYPI_LOCAL"]=pypi ["$HAL_REPO_DATA_PYPI_REMOTE"]=pypi ["$HAL_REPO_DATA_PYPI"]=pypi
  ["$HAL_REPO_DATA_CONDA_LOCAL"]=conda ["$HAL_REPO_DATA_CONDA_REMOTE"]=conda ["$HAL_REPO_DATA_CONDA"]=conda
  ["$HAL_REPO_OPS_DOCKER_LOCAL"]=docker ["$HAL_REPO_OPS_DOCKER_REMOTE"]=docker ["$HAL_REPO_OPS_DOCKER"]=docker
  ["$HAL_REPO_OPS_BUILDS"]=generic ["$HAL_REPO_OPS_HELM"]=helm
)
# An artifact path that exists (day-0) where there is one, for REST download/delete.
declare -A SEEDPATH=(
  ["$HAL_REPO_FW_MAVEN_LOCAL"]="$SDK_JAR_PATH"
  ["$HAL_REPO_OPS_BUILDS"]="${HAL_SEED_FW_BIN:-firmware/1.0.0/hal-fw-1.0.0.bin}"
)

native_read() {  # FORMAT AUTH -> sets CMD
  local f="$1" au="$2"
  case "$f" in
    cargo)   CMD=(cs_http GET "/cargo/@KEY@/index/${HAL_SEED_CRATE:0:2}/${HAL_SEED_CRATE:2:2}/${HAL_SEED_CRATE}" "$au") ;;
    maven)   CMD=(cs_http GET "/maven/@KEY@/${SDK_G}/${SDK_A}/${SDK_V}/${SDK_A}-${SDK_V}.jar" "$au") ;;
    npm)     CMD=(cs_http GET "/npm/@KEY@/${HAL_SEED_NPM:-halcyon-ui-kit}" "$au") ;;
    pypi)    CMD=(cs_http GET "/pypi/@KEY@/simple/${HAL_SEED_PYPI:-halcyon-telemetry}/" "$au") ;;
    conda)   CMD=(cs_http GET "/conda/@KEY@/noarch/repodata.json" "$au") ;;
    helm)    CMD=(cs_http GET "/helm/@KEY@/index.yaml" "$au") ;;
    generic) CMD=(cs_http GET "/general/@KEY@/${HAL_SEED_FW_BIN:-firmware/1.0.0/hal-fw-1.0.0.bin}" "$au") ;;
    docker)  CMD=(cs_http GET "/v2/@KEY@/${IMG}/manifests/1" "$au") ;;
  esac
}
native_read2() {  # a second read surface per format (metadata / config)
  local f="$1" au="$2"
  case "$f" in
    cargo)   CMD=(cs_http GET "/cargo/@KEY@/config.json" "$au") ;;
    maven)   CMD=(cs_http GET "/maven/@KEY@/${SDK_G}/${SDK_A}/maven-metadata.xml" "$au") ;;
    npm)     CMD=(cs_http GET "/npm/@KEY@/${HAL_SEED_NPM:-halcyon-ui-kit}/-/${HAL_SEED_NPM:-halcyon-ui-kit}-${HAL_SEED_NPM_VERSION:-1.0.0}.tgz" "$au") ;;
    pypi)    CMD=(cs_http GET "/pypi/@KEY@/simple/" "$au") ;;
    conda)   CMD=(cs_http GET "/conda/@KEY@/channeldata.json" "$au") ;;
    helm)    CMD=(cs_http GET "/helm/@KEY@/charts/${HAL}-contractor-chart-0.1.0.tgz" "$au") ;;
    generic) CMD=(cs_http GET "/general/@KEY@/${PROBE_PATH}" "$au") ;;
    docker)  CMD=(cs_http GET "/v2/@KEY@/${IMG}/tags/list" "$au") ;;
  esac
}
native_write() {  # FORMAT AUTH -> sets CMD
  local f="$1" au="$2"
  case "$f" in
    cargo)   CMD=(cs_publish_cargo @KEY@ "${HAL}-contractor-leak" 0.0.1 "$au") ;;
    maven)   CMD=(cs_put_maven @KEY@ "$SDK_G" "$SDK_A" 9.9.9 "$au") ;;
    npm)     CMD=(cs_publish_npm @KEY@ "${HAL}-contractor-leak" 0.0.1 "$au") ;;
    pypi)    CMD=(cs_publish_pypi @KEY@ "${HAL}-contractor-leak" 0.0.1 "$au") ;;
    conda)   CMD=(cs_http PUT "/conda/@KEY@/noarch/${HAL}-contractor-leak-0.1-0.tar.bz2" "$au"
                  -H 'Content-Type: application/octet-stream' --data-binary "@${CS_WORK}/probe-0.1-0.tar.bz2") ;;
    helm)    CMD=(cs_http POST "/helm/@KEY@/api/charts" "$au"
                  -F "chart=@${CS_WORK}/${HAL}-contractor-chart-0.1.0.tgz") ;;
    generic) CMD=(cs_http PUT "/general/@KEY@/${PROBE_PATH}" "$au"
                  -H 'Content-Type: application/octet-stream' --data-binary "@${PROBE_FILE}") ;;
    docker)  CMD=(cs_http POST "/v2/@KEY@/${IMG}/blobs/uploads/" "$au") ;;
  esac
}
needle_for() { case "$1" in docker) echo NAME_UNKNOWN ;; *) echo "$NATIVE_404" ;; esac; }

# hidden_matrix KEY TAG - the full "looks like an unknown key" matrix for one
# repository Nina cannot read. TAG goes into every check name.
hidden_matrix() {
  local key="$1" tag="$2" f="${FMT[$1]}" nd
  local dpath="${SEEDPATH[$1]:-$PROBE_PATH}"
  nd=$(needle_for "$f")
  # Native format route, every credential form she has.
  local au
  for au in basic:CONTRACTOR jwt:CONTRACTOR basictoken:CONTRACTOR:NINA_TOKEN; do
    [ "$au" = basictoken:CONTRACTOR:NINA_TOKEN ] && [ -z "${NINA_TOKEN:-}" ] && continue
    native_read "$f" "$au"
    like_unknown "${tag} ${key}: ${f} native read as ${au%%:*}" "$nd" "$key" "${CMD[@]}"
  done
  native_read2 "$f" basic:CONTRACTOR
  like_unknown "${tag} ${key}: ${f} native metadata read" "$nd" "$key" "${CMD[@]}"
  native_write "$f" basic:CONTRACTOR
  like_unknown "${tag} ${key}: ${f} native write (#5458)" "$nd" "$key" "${CMD[@]}"
  if [ -n "${NINA_TOKEN:-}" ]; then
    native_write "$f" basictoken:CONTRACTOR:NINA_TOKEN
    like_unknown "${tag} ${key}: ${f} native write with token (#5458)" "$nd" "$key" "${CMD[@]}"
  fi
  # /general (every format) and OCI /v2 against every repository, any format.
  if [ "$f" != generic ]; then
    like_unknown "${tag} ${key}: /general read" "$NATIVE_404" "$key" \
      cs_http GET "/general/@KEY@/${dpath}" basic:CONTRACTOR
  fi
  if [ "$f" != docker ]; then
    like_unknown "${tag} ${key}: OCI manifest read" NAME_UNKNOWN "$key" \
      cs_http GET "/v2/@KEY@/${IMG}/manifests/1" basic:CONTRACTOR
    like_unknown "${tag} ${key}: OCI blob upload (#5458, not 400 UNSUPPORTED)" NAME_UNKNOWN "$key" \
      cs_http POST "/v2/@KEY@/${IMG}/blobs/uploads/" basic:CONTRACTOR
  else
    like_unknown "${tag} ${key}: OCI manifest PUT (#5458)" NAME_UNKNOWN "$key" \
      cs_http PUT "/v2/@KEY@/${IMG}/manifests/1" basic:CONTRACTOR \
      -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
      --data-binary '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":2},"layers":[]}'
    # The docker-client path: a /v2/token pull token, then the manifest with it.
    cs_http GET "/v2/token?scope=repository:${key}/${IMG}:pull,push" basic:CONTRACTOR
    local tok
    tok=$(cs_json '.token // .access_token // empty')
    if [ "$CS_STATUS" = "200" ] && [ -n "$tok" ]; then
      # shellcheck disable=SC2034  # read by cs_http token:OCI_TOK
      OCI_TOK="$tok"
      like_unknown "${tag} ${key}: OCI manifest read with /v2/token bearer" NAME_UNKNOWN "$key" \
        cs_http GET "/v2/@KEY@/${IMG}/manifests/1" token:OCI_TOK
      like_unknown "${tag} ${key}: OCI blob upload with /v2/token bearer (#5458)" NAME_UNKNOWN "$key" \
        cs_http POST "/v2/@KEY@/${IMG}/blobs/uploads/" token:OCI_TOK
    else
      cs_record "${tag} ${key}: /v2/token for a hidden repository scope" FAIL \
        "expected 200 with a token (access is decided on the content route), got ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:400}"
    fi
  fi
  # REST surfaces, JWT and Bearer API token.
  for au in jwt:CONTRACTOR token:NINA_TOKEN; do
    [ "$au" = token:NINA_TOKEN ] && [ -z "${NINA_TOKEN:-}" ] && continue
    like_unknown "${tag} ${key}: REST GET repository as ${au%%:*}" NOT_FOUND "$key" \
      cs_http GET "/api/v1/repositories/@KEY@" "$au"
    like_unknown "${tag} ${key}: REST PUT artifact as ${au%%:*} (#5458)" NOT_FOUND "$key" \
      cs_http PUT "/api/v1/repositories/@KEY@/artifacts/${PROBE_PATH}" "$au" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${PROBE_FILE}"
  done
  like_unknown "${tag} ${key}: REST artifact list" NOT_FOUND "$key" \
    cs_http GET "/api/v1/repositories/@KEY@/artifacts" jwt:CONTRACTOR
  like_unknown "${tag} ${key}: REST download" "$NATIVE_404" "$key" \
    cs_http GET "/api/v1/repositories/@KEY@/download/${dpath}" basic:CONTRACTOR
  like_unknown "${tag} ${key}: REST DELETE artifact (#5458)" NOT_FOUND "$key" \
    cs_http DELETE "/api/v1/repositories/@KEY@/artifacts/${dpath}" jwt:CONTRACTOR
  like_unknown "${tag} ${key}: REST PATCH repository" NOT_FOUND "$key" \
    cs_http PATCH "/api/v1/repositories/@KEY@" jwt:CONTRACTOR \
    -H 'Content-Type: application/json' -d '{"description":"nina"}'
  case "$key" in
    *-remote)
      like_unknown "${tag} ${key}: REST age-gate read (#5458, RN:45)" NOT_FOUND "$key" \
        cs_http GET "/api/v1/repositories/@KEY@/age-gate" jwt:CONTRACTOR ;;
  esac
  case "$key" in
    "$HAL_REPO_FW_CARGO"|"$HAL_REPO_FW_MAVEN"|"$HAL_REPO_WEB_NPM"|"$HAL_REPO_DATA_PYPI"|"$HAL_REPO_DATA_CONDA"|"$HAL_REPO_OPS_DOCKER")
      like_unknown "${tag} ${key}: REST virtual members" NOT_FOUND "$key" \
        cs_http GET "/api/v1/repositories/@KEY@/members" jwt:CONTRACTOR ;;
  esac
}

# ---------------------------------------------------------------------------
# Morning: sign in, mint a laptop token
# ---------------------------------------------------------------------------
if cs_login CONTRACTOR; then
  cs_record "Nina signs in" PASS "JWT issued"
else
  cs_record "Nina signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  cs_end
fi

cs_http GET /api/v1/users/me jwt:CONTRACTOR
if [ "$CS_STATUS" = 200 ] && [ "$(cs_json '.is_admin')" = "false" ] && [ "$(cs_json '.username')" = "$HAL_CONTRACTOR_USER" ]; then
  cs_record "Nina is a plain user" PASS "username ${HAL_CONTRACTOR_USER}, is_admin false"
else
  cs_record "Nina is a plain user" FAIL "HTTP ${CS_STATUS}, is_admin=$(cs_json '.is_admin')" "${CS_BODY:0:300}"
fi

NINA_TOKEN=""; NINA_TOKEN_ID=""
if cs_mint_user_token CONTRACTOR "${HAL}-contractor-laptop" '["read:artifacts","write:artifacts"]'; then
  NINA_TOKEN="$CS_TOKEN"; NINA_TOKEN_ID=$(cs_json '.id // empty')
  cs_record "Nina mints a laptop token (read:artifacts, write:artifacts)" PASS "HTTP ${CS_STATUS}"
else
  cs_record "Nina mints a laptop token (read:artifacts, write:artifacts)" FAIL \
    "HTTP ${CS_STATUS} (${CS_LAST_REQ}); token forms are skipped below" "${CS_BODY:0:300}"
fi
export NINA_TOKEN

# ---------------------------------------------------------------------------
# Task 1: what she can see
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories?per_page=100" jwt:CONTRACTOR
expect_set "1 repository list is exactly the SDK repo and the handbook (RS:348-360)" \
  "$(jq -nc --arg a "$HAL_CONTRACTOR_REPO" --arg b "$HAL_REPO_HANDBOOK" '[$a,$b]')" \
  "$(listed_keys)"
if [ -n "$NINA_TOKEN" ]; then
  cs_http GET "/api/v1/repositories?per_page=100" token:NINA_TOKEN
  expect_set "1b repository list with her token (no repo list) is the same two" \
    "$(jq -nc --arg a "$HAL_CONTRACTOR_REPO" --arg b "$HAL_REPO_HANDBOOK" '[$a,$b]')" \
    "$(listed_keys)"
fi
cs_http GET "/api/v1/repositories?per_page=100&search=${HAL}" jwt:CONTRACTOR
expect_set "1c repository search for the company prefix is the same two" \
  "$(jq -nc --arg a "$HAL_CONTRACTOR_REPO" --arg b "$HAL_REPO_HANDBOOK" '[$a,$b]')" \
  "$(listed_keys)"

# ---------------------------------------------------------------------------
# Tasks 2-3: the SDK, every credential form
# ---------------------------------------------------------------------------
cs_http GET "$SDK_JAR" basic:CONTRACTOR
cs_expect "2 download day-0 SDK jar (basic)" 200
cs_http GET "$SDK_POM" basic:CONTRACTOR
cs_expect "2 download day-0 SDK pom (basic)" 200
cs_http GET "$SDK_JAR" jwt:CONTRACTOR
cs_expect "2 download day-0 SDK jar (Bearer JWT)" 200
if [ -n "$NINA_TOKEN" ]; then
  cs_http GET "$SDK_JAR" basictoken:CONTRACTOR:NINA_TOKEN
  cs_expect "2 download day-0 SDK jar (Basic user:token, native route)" 200
  cs_http GET "$SDK_JAR" token:NINA_TOKEN
  cs_expect "2 download day-0 SDK jar (Bearer API token)" 200
fi
cs_http GET "/api/v1/repositories/${HAL_CONTRACTOR_REPO}/download/${SDK_JAR_PATH}" jwt:CONTRACTOR
cs_expect "2 download day-0 SDK jar via REST download" 200
cs_http GET "/maven/${HAL_CONTRACTOR_REPO}/${SDK_G}/${SDK_A}/maven-metadata.xml" basic:CONTRACTOR
if cs_expect "3 maven-metadata.xml" 200; then
  cs_expect_body "3 maven-metadata.xml lists ${SDK_V}" "<version>${SDK_V}</version>"
fi
cs_http GET "/api/v1/repositories/${HAL_CONTRACTOR_REPO}" jwt:CONTRACTOR
cs_expect "REST repository detail of her repo" 200
cs_http GET "/api/v1/repositories/${HAL_CONTRACTOR_REPO}/artifacts" jwt:CONTRACTOR
cs_expect "REST artifact list of her repo" 200

# ---------------------------------------------------------------------------
# Task 5: the internal handbook
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}" jwt:CONTRACTOR
cs_expect "5 read onboarding handbook (internal = any principal, VIS)" 200
cs_http GET "/general/${HAL_REPO_HANDBOOK}/${HAL_SEED_HANDBOOK}" basic:CONTRACTOR
cs_expect "5 read onboarding handbook via /general (basic)" 200

# ---------------------------------------------------------------------------
# Tasks 6-7: search and packages show only her two repositories
# ---------------------------------------------------------------------------
ALLOWED=$(jq -nc --arg a "$HAL_CONTRACTOR_REPO" --arg b "$HAL_REPO_HANDBOOK" '[$a,$b]')
for q in hal halcyon "${HAL}" motor telemetry ui-kit firmware; do
  cs_http GET "/api/v1/search/quick?q=${q}" jwt:CONTRACTOR
  expect_subset "6 quick search q=${q} has no hit outside her repos (H/search.rs:540-557)" \
    "$ALLOWED" "$(cs_json '[.results[]?.repository_key // empty]')"
done
cs_http GET "/api/v1/search/quick?q=${SDK_A}" jwt:CONTRACTOR
cs_expect_body "6 quick search finds the SDK in her repo" "$HAL_CONTRACTOR_REPO"
cs_http GET "/api/v1/packages?per_page=100" jwt:CONTRACTOR
expect_subset "7 package listing only from her repos (H/packages.rs:36-50)" \
  "$ALLOWED" "$(cs_json '[.items[]?.repository_key // empty]')"
cs_expect_body "7 package listing includes the SDK" "${SDK_A}"

# ---------------------------------------------------------------------------
# No credential / bad credential: 401 everywhere, never a 404 (#1371)
# ---------------------------------------------------------------------------
cs_http GET "$SDK_JAR" none
if [ "$CS_STATUS" = 401 ] && [ -n "$(cs_header www-authenticate)" ]; then
  cs_record "anonymous read of her (private) SDK repo is 401 + challenge (A:2639-2659)" PASS "WWW-Authenticate: $(cs_header www-authenticate)"
else
  cs_record "anonymous read of her (private) SDK repo is 401 + challenge (A:2639-2659)" FAIL \
    "got ${CS_STATUS}, WWW-Authenticate='$(cs_header www-authenticate)' (${CS_LAST_REQ})" "${CS_BODY:0:300}"
fi
cs_http GET "/maven/${HAL_CONTRACTOR_REPO}/${SDK_JAR_PATH}" none -u "${HAL_CONTRACTOR_USER}:wrong-password"
cs_expect "wrong password on a native read is 401, not an anonymous downgrade (#1371)" 401
cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}" none
cs_expect "anonymous read of the internal handbook is 401 (VIS)" 401

# ---------------------------------------------------------------------------
# Should NOT work: writes to the repo she can read are 403
# ---------------------------------------------------------------------------
cs_put_maven "$HAL_CONTRACTOR_REPO" "$SDK_G" "$SDK_A" 9.9.9 basic:CONTRACTOR
expect_text "deploy hal-sdk 9.9.9 jar to her repo (reader, basic) (A:2710)" 403 "$NATIVE_403"
if [ "$CS_POM_STATUS" = 403 ]; then
  cs_record "deploy hal-sdk 9.9.9 pom to her repo (reader, basic)" PASS "HTTP 403"
else
  cs_record "deploy hal-sdk 9.9.9 pom to her repo (reader, basic)" FAIL "expected 403, got ${CS_POM_STATUS}"
fi
if [ -n "$NINA_TOKEN" ]; then
  cs_put_maven "$HAL_CONTRACTOR_REPO" "$SDK_G" "$SDK_A" 9.9.9 basictoken:CONTRACTOR:NINA_TOKEN
  expect_text "deploy hal-sdk 9.9.9 with her write:artifacts token (grant, not scope, refuses) (A:2710)" 403 "$NATIVE_403"
  cs_put_generic "$HAL_CONTRACTOR_REPO" "$PROBE_PATH" "$PROBE_FILE" token:NINA_TOKEN
  expect_text "REST PUT into her repo with token (reader) (RS:251-274)" 403 FORBIDDEN
fi
cs_put_generic "$HAL_CONTRACTOR_REPO" "$PROBE_PATH" "$PROBE_FILE" jwt:CONTRACTOR
expect_text "REST PUT into her repo with JWT (reader) (RS:251-274)" 403 FORBIDDEN
cs_http DELETE "/api/v1/repositories/${HAL_CONTRACTOR_REPO}/artifacts/${SDK_JAR_PATH}" jwt:CONTRACTOR
expect_text "REST DELETE the day-0 SDK jar (reader) (RS:13777-13800)" 403 FORBIDDEN
cs_http PUT "/general/${HAL_CONTRACTOR_REPO}/${PROBE_PATH}" basic:CONTRACTOR \
  -H 'Content-Type: application/octet-stream' --data-binary "@${PROBE_FILE}"
expect_text "PUT /general on her repo (reader: middleware 403 before the 405, H/general.rs)" 403 "$NATIVE_403"
cs_http DELETE "${SDK_JAR}" basic:CONTRACTOR
expect_text "native DELETE of the SDK jar (reader)" 403 "$NATIVE_403"
cs_http POST "/v2/${HAL_CONTRACTOR_REPO}/${IMG}/blobs/uploads/" basic:CONTRACTOR
expect_text "OCI blob upload into her (readable) repo keeps 403 DENIED (H/oci_v2.rs:834-907)" 403 DENIED
cs_http PATCH "/api/v1/repositories/${HAL_CONTRACTOR_REPO}" jwt:CONTRACTOR \
  -H 'Content-Type: application/json' -d '{"description":"nina"}'
expect_text "PATCH her repo (repo admin required, RS:6130-6186)" 403 FORBIDDEN
cs_http GET "/maven/${HAL_CONTRACTOR_REPO}/${SDK_G}/${SDK_A}/9.9.9/${SDK_A}-9.9.9.jar" basic:CONTRACTOR
cs_expect "nothing written: hal-sdk 9.9.9 is absent" 404
cs_http GET "/api/v1/repositories/${HAL_CONTRACTOR_REPO}/download/${PROBE_PATH}" jwt:CONTRACTOR
cs_expect "nothing written: REST probe is absent from her repo" 404
cs_http GET "$SDK_JAR" basic:CONTRACTOR
cs_expect "day-0 SDK jar still there after her refused DELETE" 200

# Handbook: she can read it, so a write is 403 (VIS "Write refusals").
cs_put_generic "$HAL_REPO_HANDBOOK" "${HAL}-contractor/notes.md" "$PROBE_FILE" jwt:CONTRACTOR
expect_text "write notes.md to the handbook (JWT) (VIS)" 403 FORBIDDEN
if [ -n "$NINA_TOKEN" ]; then
  cs_put_generic "$HAL_REPO_HANDBOOK" "${HAL}-contractor/notes.md" "$PROBE_FILE" token:NINA_TOKEN
  expect_text "write notes.md to the handbook (token) (VIS)" 403 FORBIDDEN
fi
cs_http PUT "/general/${HAL_REPO_HANDBOOK}/${HAL}-contractor/notes.md" basic:CONTRACTOR \
  -H 'Content-Type: application/octet-stream' --data-binary "@${PROBE_FILE}"
expect_text "PUT /general on the handbook (reader)" 403 "$NATIVE_403"
cs_http DELETE "/api/v1/repositories/${HAL_REPO_HANDBOOK}/artifacts/${HAL_SEED_HANDBOOK}" jwt:CONTRACTOR
expect_text "REST DELETE the onboarding handbook" 403 FORBIDDEN
cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL}-contractor/notes.md" jwt:CONTRACTOR
cs_expect "nothing written: notes.md absent from the handbook" 404

# ---------------------------------------------------------------------------
# Should NOT work: every other Halcyon repository is an unknown key (#5458)
# ---------------------------------------------------------------------------
HIDDEN=(
  "$HAL_REPO_FW_MAVEN" "$HAL_REPO_FW_MAVEN_REMOTE"
  "$HAL_REPO_FW_CARGO_LOCAL" "$HAL_REPO_FW_CARGO_REMOTE" "$HAL_REPO_FW_CARGO"
  "$HAL_REPO_WEB_NPM_LOCAL" "$HAL_REPO_WEB_NPM_REMOTE" "$HAL_REPO_WEB_NPM"
  "$HAL_REPO_DATA_PYPI_LOCAL" "$HAL_REPO_DATA_PYPI_REMOTE" "$HAL_REPO_DATA_PYPI"
  "$HAL_REPO_DATA_CONDA_LOCAL" "$HAL_REPO_DATA_CONDA_REMOTE" "$HAL_REPO_DATA_CONDA"
  "$HAL_REPO_OPS_DOCKER_LOCAL" "$HAL_REPO_OPS_DOCKER_REMOTE" "$HAL_REPO_OPS_DOCKER"
  "$HAL_REPO_OPS_BUILDS" "$HAL_REPO_OPS_HELM"
)
for k in "${HIDDEN[@]}"; do
  hidden_matrix "$k" "hidden"
done

# The ROLES.md named items, explicitly, with their exact requests.
cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${SDK_JAR_PATH}" basic:CONTRACTOR
expect_text "SDK through the firmware virtual is 404 (VIS 'Reading through a virtual')" 404 "$NATIVE_404"
cs_http GET "/npm/${HAL_REPO_WEB_NPM_LOCAL}/halcyon-ui-kit" basic:CONTRACTOR
expect_text "web npm local read is 404 Repository not found" 404 "$NATIVE_404"
cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" "${HAL}-contractor-leak" 0.0.1 basic:CONTRACTOR
expect_text "npm publish to web npm local is 404 (#5458)" 404 "$NATIVE_404"

# ---------------------------------------------------------------------------
# Task 4: the new SDK release
# ---------------------------------------------------------------------------
if cs_wait fw-sdk-1.1.0 "$BARRIER_TIMEOUT"; then
  cs_http GET "/maven/${HAL_CONTRACTOR_REPO}/${SDK_G}/${SDK_A}/1.1.0/${SDK_A}-1.1.0.jar" basic:CONTRACTOR
  cs_expect "4 download hal-sdk 1.1.0 jar" 200
  cs_http GET "/maven/${HAL_CONTRACTOR_REPO}/${SDK_G}/${SDK_A}/1.1.0/${SDK_A}-1.1.0.pom" basic:CONTRACTOR
  cs_expect "4 download hal-sdk 1.1.0 pom" 200
else
  cs_record "waited for fw-sdk-1.1.0 (firmware publishes hal-sdk 1.1.0)" FAIL "${CS_WAIT_WHY}"
fi

# ---------------------------------------------------------------------------
# Task 8-9: the engagement ends
# ---------------------------------------------------------------------------
cs_signal nina-done
if cs_wait nina-offboarded "$BARRIER_TIMEOUT"; then
  # One replica: next request. Allow the 30 s permission-cache TTL for N
  # replicas (S/permission_service.rs:293) with a deadline, never a bare sleep.
  deadline=$(( $(date +%s) + 35 ))
  start=$(date +%s)
  while :; do
    cs_http GET "$SDK_JAR" basic:CONTRACTOR
    [ "$CS_STATUS" = 404 ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 1
  done
  echo "  rule removal visible after $(( $(date +%s) - start ))s"
  expect_text "8 SDK jar after her rule is deleted is 404 (A:3406-3561)" 404 "$NATIVE_404"

  cs_http GET /api/v1/users/me jwt:CONTRACTOR
  cs_expect "8 her login still works (the rule was removed, not the user): /users/me" 200
  cs_http GET "/api/v1/repositories?per_page=100" jwt:CONTRACTOR
  expect_set "8 repository list is now only the handbook" \
    "$(jq -nc --arg b "$HAL_REPO_HANDBOOK" '[$b]')" "$(listed_keys)"
  cs_http GET "/api/v1/packages?per_page=100" jwt:CONTRACTOR
  expect_subset "8 package listing has nothing from the SDK repo" \
    "$(jq -nc --arg b "$HAL_REPO_HANDBOOK" '[$b]')" "$(cs_json '[.items[]?.repository_key // empty]')"
  cs_http GET "/api/v1/search/quick?q=${SDK_A}" jwt:CONTRACTOR
  expect_subset "8 search for the SDK finds nothing she lost" \
    "$(jq -nc --arg b "$HAL_REPO_HANDBOOK" '[$b]')" "$(cs_json '[.results[]?.repository_key // empty]')"

  # Her former repository now answers exactly like an unknown key, reads and
  # writes (a write by a non-reader is 404, #5458), every route.
  hidden_matrix "$HAL_CONTRACTOR_REPO" "revoked"

  # No credential is still the 401 challenge, not a 404.
  cs_http GET "$SDK_JAR" none
  cs_expect "8 anonymous read of the former SDK repo is 401 (A:2639-2659)" 401
  if [ -n "$NINA_TOKEN" ]; then
    cs_http GET /api/v1/users/me token:NINA_TOKEN
    cs_expect "8 her token is still a valid credential (rule removed, not the token)" 200
  fi

  # Task 9: internal is not a grant.
  cs_http GET "/api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}" jwt:CONTRACTOR
  cs_expect "9 handbook still readable after offboarding (observation: internal is not a grant, VIS)" 200
  cs_put_generic "$HAL_REPO_HANDBOOK" "${HAL}-contractor/notes.md" "$PROBE_FILE" jwt:CONTRACTOR
  expect_text "9 handbook write still 403 after offboarding (she can read it)" 403 FORBIDDEN
else
  cs_record "waited for nina-offboarded (platform-admin deletes her rule)" FAIL "${CS_WAIT_WHY}; post-offboarding checks skipped"
fi

# ---------------------------------------------------------------------------
# Cleanup: revoke the laptop token
# ---------------------------------------------------------------------------
if [ -n "$NINA_TOKEN_ID" ]; then
  cs_http DELETE "/api/v1/users/me/tokens/${NINA_TOKEN_ID}" jwt:CONTRACTOR
  cs_expect "cleanup: revoke her laptop token (DELETE /users/me/tokens/{id} answers 200)" 200
  cs_http GET "$SDK_JAR" basictoken:CONTRACTOR:NINA_TOKEN
  cs_expect "revoked token on a native read is 401, not a 404 (#1371, A:3203-3207)" 401
  cs_http GET /api/v1/users/me token:NINA_TOKEN
  cs_expect "revoked token on REST is 401" 401
fi

cs_end
