#!/usr/bin/env bash
# =============================================================================
# tiers/oci-push-scope/oracle.sh — OCI push with a least-privilege granular
#                                  token (artifact-keeper#3053)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real docker-push wire sequence
# against the candidate.
#
# The bug (#3053): the #2993/#2989 colon-form scope migration missed the 5 OCI
# write call sites in `oci_v2.rs`, which still require the BARE `write` action.
# The parent rule is broad-covers-specific ONLY, and #2996/#3001 made bare
# parents un-mintable, so the only write token a caller CAN mint
# (`write:artifacts`) is 403'd on every OCI blob/manifest write — directly, via
# the docker-login `/v2/token` exchange, and via the conan exchange. Only a
# wildcard `*`/`admin` token can still push.
#
# Discriminating gates:
#   (MAIN)       granular ["read:artifacts","write:artifacts"] token completes
#                a real push (upload init 202, monolithic POST?digest 201,
#                chunked PATCH 202, PUT?digest 201, manifest PUT 201, manifest
#                reads back 200) directly and via BOTH credential exchanges.
#                RED on rc.3 (403 "required scope: write"), GREEN on the fix.
#   (LEAST-PRIV) ["read:artifacts"]-only token, direct and exchanged, is 403'd
#                on blob upload and manifest PUT and leaves no tag. Must hold
#                on BOTH images — the fix must not widen the read ceiling.
#   (CONTROL)    a wildcard `*` token pushes on BOTH images (proves the push
#                path is functional, so a RED MAIN is the least-privilege
#                ceiling, not a broken registry); anonymous push -> 401.
#
# Setup failures use infra_fail(): a tier that could not be evaluated is RED
# but is NOT a statement about the candidate (harness/lib/exit_codes.sh).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
OCI_REPO="ops-oci-${DTF_SLOT:-x}-${SUF}"
CONAN_REPO="ops-cn-${DTF_SLOT:-x}-${SUF}"
IMG="app"
RW_TAG="rw-${SUF}"
WILD_TAG="wild-${SUF}"
RO_TAG="ro-${SUF}"

WORK="$(mktemp -d)"
# shellcheck disable=SC2016  # deferred on purpose: the handler is eval'd at exit
add_exit_handler 'rm -rf "$WORK"'

# --- low-level helpers ------------------------------------------------------

_last_body() { head -c 220 "${WORK}/body" 2>/dev/null | tr -d '\r' | tr '\n' ' '; }

# registry_call METHOD URL CONTENT_TYPE DATA_FILE [curl auth args...]
#   -> prints the http code; body lands in $WORK/body, headers in $WORK/hdr.
# CONTENT_TYPE and DATA_FILE may be empty; the auth args are appended verbatim
# so a caller can pass Basic (-u), a bearer header, or nothing (anonymous).
registry_call() {
  local method="$1" url="$2" ctype="$3" datafile="$4"
  shift 4
  local args=(-s -D "${WORK}/hdr" -o "${WORK}/body" -w '%{http_code}')
  # shellcheck disable=SC2206  # CURL_TIMEOUT is intentionally word-split
  args+=($CURL_TIMEOUT)
  args+=(-X "$method" "$@")
  [ -n "$ctype" ] && args+=(-H "Content-Type: ${ctype}")
  [ -n "$datafile" ] && args+=(--data-binary "@${datafile}")
  curl "${args[@]}" "$url" 2>/dev/null || echo 000
}

# location_header -> the Location value from the last response, absolutized.
location_header() {
  local loc
  loc="$(grep -i '^location:' "${WORK}/hdr" 2>/dev/null | tail -1 \
         | tr -d '\r' | sed 's/^[Ll]ocation:[[:space:]]*//')"
  [ -z "$loc" ] && return 1
  case "$loc" in http*) printf '%s' "$loc" ;; *) printf '%s%s' "$BASE_URL" "$loc" ;; esac
}

# with_digest URL DIGEST -> URL with a ?digest=/&digest= query appended.
with_digest() {
  case "$1" in *\?*) printf '%s&digest=%s' "$1" "$2" ;; *) printf '%s?digest=%s' "$1" "$2" ;; esac
}

is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac }

begin_suite "oci-push-scope-3053"

# ---------------------------------------------------------------------------
# SETUP — every failure here is INFRA: the harness could not evaluate the tier.
# ---------------------------------------------------------------------------
auth_admin   # sets ADMIN_TOKEN

create_private_repo() { # KEY FORMAT -> prints repo id
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/repositories" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"${2}\",\"repo_type\":\"local\",\"is_public\":false}" \
    2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}

OCI_ID="$(create_private_repo "$OCI_REPO" docker)"
CONAN_ID="$(create_private_repo "$CONAN_REPO" conan)"
if [ -z "$OCI_ID" ] || [ -z "$CONAN_ID" ]; then
  begin_test "setup: create the private docker + conan repositories"
  infra_fail "could not create the fixture repositories (docker id='${OCI_ID}' conan id='${CONAN_ID}')"
  end_suite
fi

create_sa() { # NAME SCOPES_JSON -> prints service-account id
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/service-accounts" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"${1}\",\"description\":\"oci-push-scope fixture\",\"scopes\":${2}}" \
    2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}

# Repository writes are DENY-BY-DEFAULT at the principal layer (#2603 G1), so
# without an explicit grant the repository-authorization layer would 403 every
# probe BEFORE the scope gate is consulted — and a broken scope gate could hide
# behind that denial. Grant each principal read+write on both fixture repos so
# the TOKEN SCOPE is the only layer left deciding. (The conan grant is what the
# credential-exchange endpoint checks before it will mint.)
grant_repo_rw() { # SA_ID REPO_ID -> http code
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    "${BASE_URL}/api/v1/permissions" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"principal_type\":\"service_account\",\"principal_id\":\"${1}\",\"target_type\":\"repository\",\"target_id\":\"${2}\",\"actions\":[\"read\",\"write\"]}" \
    2>/dev/null || echo 000
}

mint_sa_token() { # SA_ID SCOPES_JSON -> prints api token
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/service-accounts/${1}/tokens" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"ops-${SUF}-${RANDOM}\",\"scopes\":${2}}" \
    2>/dev/null | jq -r '.token // empty' 2>/dev/null || true
}

SA_RW="$(create_sa "ops-rw-${SUF}" '["read:artifacts","write:artifacts"]')"
SA_RO="$(create_sa "ops-ro-${SUF}" '["read:artifacts"]')"
SA_WILD="$(create_sa "ops-wild-${SUF}" '["*"]')"
if [ -z "$SA_RW" ] || [ -z "$SA_RO" ] || [ -z "$SA_WILD" ]; then
  begin_test "setup: create the RW / RO / wildcard service accounts"
  infra_fail "could not create service accounts (rw='${SA_RW}' ro='${SA_RO}' wild='${SA_WILD}')"
  end_suite
fi

GRANT_FAILS=""
for _sa in "$SA_RW" "$SA_RO" "$SA_WILD"; do
  for _repo in "$OCI_ID" "$CONAN_ID"; do
    _rc="$(grant_repo_rw "$_sa" "$_repo")"
    is_2xx "$_rc" || GRANT_FAILS="${GRANT_FAILS} sa=${_sa:0:8}/repo=${_repo:0:8}:${_rc}"
  done
done
if [ -n "$GRANT_FAILS" ]; then
  begin_test "setup: grant each principal repo read+write (#2603 deny-by-default fixture)"
  infra_fail "could not grant repository permissions:${GRANT_FAILS}"
  end_suite
fi

# The least-privilege pair. ["read:artifacts","write:artifacts"] is the ONLY
# shape of write token #2996/#3001 still permit at the mint choke-point.
RW_TOKEN="$(mint_sa_token "$SA_RW" '["read:artifacts","write:artifacts"]')"
RO_TOKEN="$(mint_sa_token "$SA_RO" '["read:artifacts"]')"
WILD_TOKEN="$(mint_sa_token "$SA_WILD" '["*"]')"
if [ -z "$RW_TOKEN" ] || [ -z "$RO_TOKEN" ] || [ -z "$WILD_TOKEN" ]; then
  begin_test "setup: mint the granular RW, RO and wildcard api-tokens"
  infra_fail "token mint returned empty (rw='${RW_TOKEN:0:8}' ro='${RO_TOKEN:0:8}' wild='${WILD_TOKEN:0:8}')" \
             "a 4xx/empty mint means the ceiling under test was never presented"
  end_suite
fi

# --- credential presentations ----------------------------------------------
# 1) direct: what `docker login -u <svc> -p <api-token>` sends on every request
RW_BASIC=(-u "token:${RW_TOKEN}")
RO_BASIC=(-u "token:${RO_TOKEN}")
WILD_BASIC=(-u "token:${WILD_TOKEN}")

# 2) the docker-login exchange: GET /v2/token with the api-token in Basic,
#    which is what a daemon does after the 401 challenge on /v2/.
oci_login_bearer() { # API_TOKEN -> prints the exchanged bearer
  curl -s $CURL_TIMEOUT -u "token:${1}" "${BASE_URL}/v2/token" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
RW_BEARER_TOK="$(oci_login_bearer "$RW_TOKEN")"
RO_BEARER_TOK="$(oci_login_bearer "$RO_TOKEN")"
if [ -z "$RW_BEARER_TOK" ] || [ -z "$RO_BEARER_TOK" ]; then
  begin_test "setup: docker-login exchange GET /v2/token mints a bearer"
  infra_fail "the /v2/token exchange returned no bearer (rw_len=${#RW_BEARER_TOK} ro_len=${#RO_BEARER_TOK})"
  end_suite
fi
RW_BEARER=(-H "Authorization: Bearer ${RW_BEARER_TOK}")
RO_BEARER=(-H "Authorization: Bearer ${RO_BEARER_TOK}")

# 3) the conan credential exchange, the other surface that mints an OCI-usable
#    credential from an api-token.
CONAN_JWT="$(curl -s $CURL_TIMEOUT -u "svc:${RW_TOKEN}" -X POST \
  "${BASE_URL}/conan/${CONAN_REPO}/v2/users/authenticate" 2>/dev/null || true)"
if [ -z "$CONAN_JWT" ] || ! printf '%s' "$CONAN_JWT" | grep -q '\.'; then
  begin_test "setup: conan credential exchange mints a JWT"
  infra_fail "conan exchange did not return a JWT: ${CONAN_JWT:0:120}"
  end_suite
fi
CONAN_BEARER=(-H "Authorization: Bearer ${CONAN_JWT}")

# --- fixture blobs ----------------------------------------------------------
CFG_FILE="${WORK}/config.json"
LAYER_FILE="${WORK}/layer.bin"
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' > "$CFG_FILE"
printf 'ops-push-scope-layer-%s' "$SUF" > "$LAYER_FILE"
CFG_DIGEST="sha256:$(sha256sum "$CFG_FILE" | cut -d' ' -f1)"
CFG_SIZE="$(wc -c < "$CFG_FILE" | tr -d '[:space:]')"
LAYER_DIGEST="sha256:$(sha256sum "$LAYER_FILE" | cut -d' ' -f1)"
LAYER_SIZE="$(wc -c < "$LAYER_FILE" | tr -d '[:space:]')"

write_manifest() { # OUT_FILE
  cat > "$1" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":${CFG_SIZE},"digest":"${CFG_DIGEST}"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":${LAYER_SIZE},"digest":"${LAYER_DIGEST}"}]}
EOF
}
MANIFEST_FILE="${WORK}/manifest.json"
MANIFEST_CT='application/vnd.docker.distribution.manifest.v2+json'
write_manifest "$MANIFEST_FILE"

BLOB_UPLOADS="${BASE_URL}/v2/${OCI_REPO}/${IMG}/blobs/uploads/"
MANIFEST_URL="${BASE_URL}/v2/${OCI_REPO}/${IMG}/manifests"

# ---------------------------------------------------------------------------
# (CONTROL) The registry ping a docker client makes before anything else.
# ---------------------------------------------------------------------------
begin_test "CONTROL: docker-login ping GET /v2/ with the granular api-token -> 200"
RC="$(registry_call GET "${BASE_URL}/v2/" '' '' "${RW_BASIC[@]}")"
if [ "$RC" = "200" ]; then
  pass
else
  fail "the api-token could not even complete the registry ping (HTTP ${RC}); authentication, not the scope ceiling, is broken here" \
       "code=${RC} body=$(_last_body)"
fi

# ---------------------------------------------------------------------------
# (CONTROL) A wildcard token pushes on BOTH images. This is the discriminator
# that makes a RED MAIN attributable: if this passes and MAIN fails, the OCI
# write path works and the ONLY thing being refused is least privilege.
# ---------------------------------------------------------------------------
begin_test "CONTROL: wildcard '*' api-token blob upload init -> 202 (push path functional on both images)"
RC="$(registry_call POST "$BLOB_UPLOADS" '' '' "${WILD_BASIC[@]}")"
if [ "$RC" = "202" ]; then
  pass
else
  # Deliberately fail(), not infra_fail(): "no token at all can push" is a
  # statement about the CANDIDATE, not about the harness. It also means the
  # MAIN block below is no longer attributable to the scope ceiling, which the
  # message says out loud so triage does not chase #3053.
  fail "a wildcard '*' token could not open a blob upload (HTTP ${RC}); the OCI push path is broken beyond the scope ceiling, so the MAIN results below are NOT attributable to #3053" \
       "code=${RC} body=$(_last_body)"
fi

# ---------------------------------------------------------------------------
# (CONTROL) Authentication still guards the write path.
# ---------------------------------------------------------------------------
begin_test "CONTROL: anonymous blob upload init -> 401"
RC="$(registry_call POST "$BLOB_UPLOADS" '' '')"
if [ "$RC" = "401" ]; then
  pass
else
  fail "anonymous blob upload returned ${RC} (expected 401); the OCI write path lost its authentication guard" \
       "code=${RC} body=$(_last_body)"
fi

# ---------------------------------------------------------------------------
# (MAIN) The direct presentation: `docker login -u <svc> -p <api-token>` puts
# the api-token in Basic on every subsequent request. RED on #3053.
# ---------------------------------------------------------------------------
begin_test "MAIN: granular write:artifacts api-token (docker-login Basic) blob upload init -> 202"
RC="$(registry_call POST "$BLOB_UPLOADS" '' '' "${RW_BASIC[@]}")"
if [ "$RC" = "202" ]; then
  pass
else
  fail "SCOPE-VOCABULARY MISMATCH (#3053): a least-privilege [read:artifacts,write:artifacts] token got ${RC} opening a blob upload; the OCI write sites still require the bare 'write' action, which is no longer mintable" \
       "code=${RC} body=$(_last_body)"
fi

# ---------------------------------------------------------------------------
# (MAIN) The exchanged-bearer presentation, driving the COMPLETE push: a
# monolithic config blob, a chunked layer blob, then the manifest.
# ---------------------------------------------------------------------------
begin_test "MAIN: exchanged bearer monolithic blob push (POST uploads/?digest) -> 201"
RC="$(registry_call POST "$(with_digest "$BLOB_UPLOADS" "$CFG_DIGEST")" 'application/octet-stream' "$CFG_FILE" "${RW_BEARER[@]}")"
if [ "$RC" = "201" ]; then
  pass
else
  fail "SCOPE-VOCABULARY MISMATCH (#3053): the docker-login-exchanged bearer got ${RC} on a monolithic blob push (expected 201)" \
       "code=${RC} body=$(_last_body)"
fi

begin_test "MAIN: exchanged bearer opens a chunked upload session (POST uploads/) -> 202 + Location"
UPLOAD_URL=""
RC="$(registry_call POST "$BLOB_UPLOADS" '' '' "${RW_BEARER[@]}")"
if [ "$RC" = "202" ]; then
  UPLOAD_URL="$(location_header || true)"
  if [ -n "$UPLOAD_URL" ]; then
    pass
  else
    fail "blob upload init returned 202 but no Location header; the client has no session URL to write the layer to" \
         "code=${RC} headers=$(head -c 220 "${WORK}/hdr" | tr -d '\r' | tr '\n' ' ')"
  fi
else
  fail "SCOPE-VOCABULARY MISMATCH (#3053): the docker-login-exchanged bearer got ${RC} opening a chunked upload session (expected 202)" \
       "code=${RC} body=$(_last_body)"
fi

begin_test "MAIN: exchanged bearer writes the layer chunk (PATCH) -> 202"
if [ -z "$UPLOAD_URL" ]; then
  fail "no upload session: the blob upload init above was refused, so the chunk-write site was never reached" \
       "this assertion is blocked by the upload-init denial, not independent of it"
else
  RC="$(registry_call PATCH "$UPLOAD_URL" 'application/octet-stream' "$LAYER_FILE" "${RW_BEARER[@]}")"
  if [ "$RC" = "202" ]; then
    NEXT_URL="$(location_header || true)"
    [ -n "$NEXT_URL" ] && UPLOAD_URL="$NEXT_URL"
    pass
  else
    fail "SCOPE-VOCABULARY MISMATCH (#3053): the exchanged bearer got ${RC} writing an upload chunk (expected 202)" \
         "code=${RC} body=$(_last_body)"
  fi
fi

begin_test "MAIN: exchanged bearer completes the layer upload (PUT ?digest) -> 201"
if [ -z "$UPLOAD_URL" ]; then
  fail "no upload session: the blob upload init above was refused, so the upload-complete site was never reached" \
       "this assertion is blocked by the upload-init denial, not independent of it"
else
  RC="$(registry_call PUT "$(with_digest "$UPLOAD_URL" "$LAYER_DIGEST")" 'application/octet-stream' '' "${RW_BEARER[@]}")"
  if [ "$RC" = "201" ]; then
    pass
  else
    fail "SCOPE-VOCABULARY MISMATCH (#3053): the exchanged bearer got ${RC} completing the layer upload (expected 201)" \
         "code=${RC} body=$(_last_body)"
  fi
fi

begin_test "MAIN: exchanged bearer PUT manifest -> 201 (the push completes)"
RC="$(registry_call PUT "${MANIFEST_URL}/${RW_TAG}" "$MANIFEST_CT" "$MANIFEST_FILE" "${RW_BEARER[@]}")"
if [ "$RC" = "201" ]; then
  pass
else
  fail "SCOPE-VOCABULARY MISMATCH (#3053): the exchanged bearer got ${RC} on the manifest PUT (expected 201); no image can be published with a least-privilege token" \
       "code=${RC} body=$(_last_body)"
fi

begin_test "MAIN(VERIFY): the pushed manifest reads back -> 200 and the tag is listed"
RC="$(registry_call GET "${MANIFEST_URL}/${RW_TAG}" '' '' "${RW_BEARER[@]}")"
if [ "$RC" != "200" ]; then
  fail "the manifest just pushed does not read back (HTTP ${RC}); the push did not actually persist" \
       "code=${RC} body=$(_last_body)"
else
  RC="$(registry_call GET "${BASE_URL}/v2/${OCI_REPO}/${IMG}/tags/list" '' '' "${RW_BEARER[@]}")"
  if [ "$RC" = "200" ] && grep -q "\"${RW_TAG}\"" "${WORK}/body" 2>/dev/null; then
    pass
  else
    fail "tag ${RW_TAG} is not in the tag list after a 201 manifest PUT (HTTP ${RC})" \
         "code=${RC} body=$(_last_body)"
  fi
fi

# ---------------------------------------------------------------------------
# (MAIN) The conan credential exchange — the other surface that mints an
# OCI-usable credential from an api-token. Migrated from the legacy
# security-tests #2430 positive control.
# ---------------------------------------------------------------------------
begin_test "MAIN: conan-exchanged RW JWT blob upload init -> 202 (#2430 positive control)"
RC="$(registry_call POST "$BLOB_UPLOADS" '' '' "${CONAN_BEARER[@]}")"
if [ "$RC" = "202" ]; then
  pass
else
  fail "SCOPE-VOCABULARY MISMATCH (#3053): the conan-exchanged JWT (scopes copied verbatim from the granular token) got ${RC} on a blob upload (expected 202)" \
       "code=${RC} body=$(_last_body)"
fi

# ---------------------------------------------------------------------------
# (LEAST-PRIVILEGE) A read-only token must NOT gain a write, on either image.
# The fix must buy the positive path without widening the read ceiling.
# ---------------------------------------------------------------------------
begin_test "LEAST-PRIVILEGE: read:artifacts-only api-token blob upload init -> 403"
RC="$(registry_call POST "$BLOB_UPLOADS" '' '' "${RO_BASIC[@]}")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "READ-TO-WRITE ESCALATION: a [read:artifacts]-only token got ${RC} opening a blob upload (expected 403)" \
       "code=${RC} body=$(_last_body)"
fi

begin_test "LEAST-PRIVILEGE: read:artifacts-only exchanged bearer blob upload init -> 403"
RC="$(registry_call POST "$BLOB_UPLOADS" '' '' "${RO_BEARER[@]}")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "READ-TO-WRITE ESCALATION (#2430 laundering): the docker-login exchange handed a read-only token a bearer that got ${RC} on a blob upload (expected 403)" \
       "code=${RC} body=$(_last_body)"
fi

begin_test "LEAST-PRIVILEGE: read:artifacts-only exchanged bearer PUT manifest -> 403"
RC="$(registry_call PUT "${MANIFEST_URL}/${RO_TAG}" "$MANIFEST_CT" "$MANIFEST_FILE" "${RO_BEARER[@]}")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "READ-TO-WRITE ESCALATION: a read-only exchanged bearer got ${RC} on the manifest PUT (expected 403)" \
       "code=${RC} body=$(_last_body)"
fi

begin_test "LEAST-PRIVILEGE(VERIFY): the denied read-only push left no tag behind -> 404"
RC="$(registry_call GET "${MANIFEST_URL}/${RO_TAG}" '' '' "${WILD_BASIC[@]}")"
if [ "$RC" = "404" ]; then
  pass
else
  fail "a scope-denied manifest PUT still published tag ${RO_TAG} (GET -> ${RC}); a refused write must persist nothing" \
       "code=${RC} body=$(_last_body)"
fi

# ---------------------------------------------------------------------------
# (CONTROL) The wildcard token completes the same manifest PUT the granular
# token is refused, on BOTH images. Together with the MAIN block this reads as
# the one-line finding: "only wildcard tokens can push".
# ---------------------------------------------------------------------------
begin_test "CONTROL: wildcard '*' api-token PUT manifest -> 201 (both images)"
RC="$(registry_call PUT "${MANIFEST_URL}/${WILD_TAG}" "$MANIFEST_CT" "$MANIFEST_FILE" "${WILD_BASIC[@]}")"
if [ "$RC" = "201" ]; then
  pass
else
  fail "a wildcard '*' token got ${RC} on the manifest PUT (expected 201); the OCI publish path is broken beyond the scope ceiling" \
       "code=${RC} body=$(_last_body)"
fi

end_suite
