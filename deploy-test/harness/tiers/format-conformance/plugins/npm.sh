# =============================================================================
# plugins/npm.sh — format-conformance plugin (npm)
# FC_FORMAT: npm
# FC_MOUNT: npm
# FC_REPO_FORMAT: npm
# FC_PROFILE: client.npm
# FC_SERVICE: client-npm
# FC_ENABLED: 1
# =============================================================================
# npm routes (backend handlers/npm.rs): nest /npm; publish scoped
# `PUT /:repo/@:scope/:package`; packument `GET /:repo/@:scope/:package`;
# scoped tarball `GET /:repo/@:scope/:package/-/:filename`. The packument's
# `versions[v].dist.tarball` is the advertised location a real client FOLLOWS.
#
# Consume via the advertised path: `npm install @dtf/marker` reads the packument,
# resolves `dist.tarball`, downloads + unpacks the tarball, and lands the marker
# file under node_modules. `@dtf:registry` pins the scope to AK ONLY so the
# install can succeed only via this registry (the discriminator).
#
# Edge cases (game-plan §4.18): scoped `@dtf/marker` + `_authToken` (Bearer) vs
# legacy `_auth` (Basic base64) header shapes; advertised `dist.integrity`
# (sha256-<b64>) must equal the served tarball bytes (npm verifies on install).
# =============================================================================
FC_CASES="auth_header_shapes integrity_sha"

NPM_SCOPE="@dtf"
NPM_NAME="@dtf/marker"
NPM_VER="1.0.0"
NPM_TARFILE="marker-${NPM_VER}.tgz"
NPM_MARKER_TOKEN="DTF-NPM-INSTALLED-${NPM_VER}"

# Basic base64 of admin creds — npm's legacy `_auth` line shape.
_npm_auth_b64() { printf '%s' "${ADMIN_USER}:${ADMIN_PASS}" | base64 -w0 2>/dev/null || printf '%s' "${ADMIN_USER}:${ADMIN_PASS}" | base64; }

# Write a channel-only .npmrc INSIDE the container at $1 (a dir). Points the
# default registry AND the @dtf scope ONLY at $FC_INT_URL — no npmjs.org.
_npm_write_rc() {
  local dir="$1"
  local host_noslash="${FC_INT_URL#http://}"   # backend:8080/npm/<repo>
  local b64; b64="$(_npm_auth_b64)"
  nc_exec "mkdir -p '${dir}' && cat > '${dir}/.npmrc' <<EOF
registry=${FC_INT_URL}/
${NPM_SCOPE}:registry=${FC_INT_URL}/
//${host_noslash}/:_authToken=${b64}
//${host_noslash}/:_auth=${b64}
//${host_noslash}/:always-auth=true
EOF
cat '${dir}/.npmrc'"
}

# ---------------------------------------------------------------------------
# fc_publish — build the scoped package in the container and `npm publish` it
# via the REAL client (the native upload path; the discriminating value is the
# client-side CONSUME below).
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v npm >/dev/null 2>&1 && npm --version' \
    || { echo "npm missing inside the provisioned npm client"; return 1; }
  nc_exec "rm -rf /tmp/pub && mkdir -p /tmp/pub && cd /tmp/pub
cat > package.json <<EOF
{
  \"name\": \"${NPM_NAME}\",
  \"version\": \"${NPM_VER}\",
  \"description\": \"DTF format-conformance marker package\",
  \"main\": \"index.js\",
  \"files\": [\"marker.txt\", \"index.js\"],
  \"license\": \"MIT\"
}
EOF
printf '%s\n' '${NPM_MARKER_TOKEN}' > marker.txt
printf 'module.exports = { marker: \"%s\" };\n' '${NPM_MARKER_TOKEN}' > index.js" || return 1
  _npm_write_rc /tmp/pub || return 1
  nc_exec "cd /tmp/pub && npm publish --registry '${FC_INT_URL}/' 2>&1" || return 1
  # Advertised packument must now list the version (host-side).
  nc_expect_code 200 "${FC_URL}/${NPM_NAME}" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — a fresh consumer dir whose .npmrc points ONLY at AK.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec "rm -rf /tmp/consume /tmp/npmcache && mkdir -p /tmp/consume
cat > /tmp/consume/package.json <<EOF
{ \"name\": \"dtf-consumer\", \"version\": \"0.0.0\", \"private\": true }
EOF" || return 1
  _npm_write_rc /tmp/consume || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `npm install @dtf/marker` reads the packument,
# resolves the advertised dist.tarball, downloads + verifies integrity, and
# unpacks it. Fresh cache + @dtf-scope pinned to AK => AK is the ONLY source.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "cd /tmp/consume && npm install '${NPM_NAME}@${NPM_VER}' \
    --registry '${FC_INT_URL}/' --cache /tmp/npmcache \
    --no-audit --no-fund --no-package-lock 2>&1" \
    || { echo "npm install failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker file was unpacked under
# node_modules AND npm records the package as installed.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "test -f /tmp/consume/node_modules/${NPM_NAME}/marker.txt && \
grep -q '${NPM_MARKER_TOKEN}' /tmp/consume/node_modules/${NPM_NAME}/marker.txt && \
cd /tmp/consume && npm ls '${NPM_NAME}' 2>/dev/null | grep -F '${NPM_NAME}@${NPM_VER}'" \
    || { echo "marker not unpacked / package not listed by npm"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. The packument advertises
# dist.tarball; that URL resolves (200) while the subdir-less bare-filename
# shape (a client following a truncated href would emit) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local tb path fname
  tb="$(nc_advertised "${FC_URL}/${NPM_NAME}" \
    "jq -r '.versions[\"${NPM_VER}\"].dist.tarball'")" || return 1
  echo "  advertised tarball=${tb}"
  path="$(printf '%s' "$tb" | sed -E 's#^https?://[^/]+##')"
  nc_expect_code 200 "${BASE_URL}${path}" || return 1
  fname="$(basename "$path")"
  # subdir-less shape must NOT resolve (no /:repo/:filename tarball route)
  nc_expect_code 404 "${FC_URL}/${fname}" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# auth_header_shapes — npm sends creds as `_authToken` (Bearer) on modern
# versions and `_auth` (Basic base64) on legacy ones; both must authenticate a
# read. And an UNAUTHENTICATED publish (PUT) must be rejected 401 — no
# anonymous-write fall-open. Bug class: auth-shape drift / anonymous write.
fc_case_auth_header_shapes() {
  # positive 1: Basic (the _auth shape) resolves the packument
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "${FC_URL}/${NPM_NAME}")"
  [ "$code" = "200" ] || { echo "  Basic _auth read -> ${code} (wanted 200)"; return 1; }
  echo "  Basic (_auth) read resolves the packument"
  # positive 2: Bearer (the _authToken shape) with a minted token resolves it
  local uid tok
  uid="$(resolve_user_id_by_username "${ADMIN_USER}")" \
    || { echo "could not resolve admin user id"; return 1; }
  tok="$(api_post "/api/v1/users/${uid}/tokens" \
    "{\"name\":\"dtf-npm-${RUN_ID}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"]}" \
    | jq -r '.token // empty')"
  [ -n "$tok" ] || { echo "token mint returned no token"; return 1; }
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -H "Authorization: Bearer ${tok}" "${FC_URL}/${NPM_NAME}")"
  [ "$code" = "200" ] || { echo "  Bearer _authToken read -> ${code} (wanted 200)"; return 1; }
  echo "  Bearer (_authToken) read resolves the packument"
  # negative: anonymous publish (PUT) must be rejected
  local bad
  bad="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -X PUT -H 'Content-Type: application/json' \
    --data '{"name":"@dtf/marker"}' "${FC_URL}/${NPM_NAME}")"
  case "$bad" in
    401|403) echo "  anonymous publish rejected (HTTP ${bad})" ;;
    *) echo "  anonymous publish -> HTTP ${bad} (expected 401/403; = anon-write fall-open)"; return 1 ;;
  esac
}

# integrity_sha — the packument advertises dist.integrity as `sha256-<base64>`.
# It MUST equal the sha256 of the bytes actually served at dist.tarball (npm
# verifies this on install; a mismatch fails the consume). Assert it explicitly
# host-side. Bug class: advertised-integrity vs served-bytes drift.
fc_case_integrity_sha() {
  local integrity tb path adv_b64 dl served_b64
  integrity="$(nc_advertised "${FC_URL}/${NPM_NAME}" \
    "jq -r '.versions[\"${NPM_VER}\"].dist.integrity'")" || return 1
  case "$integrity" in
    sha256-*) : ;;
    *) echo "  unexpected integrity shape: ${integrity}"; return 1 ;;
  esac
  adv_b64="${integrity#sha256-}"
  tb="$(nc_advertised "${FC_URL}/${NPM_NAME}" \
    "jq -r '.versions[\"${NPM_VER}\"].dist.tarball'")" || return 1
  path="$(printf '%s' "$tb" | sed -E 's#^https?://[^/]+##')"
  dl="${WORK_DIR}/served-${NPM_TARFILE}"
  nc_fetch "${BASE_URL}${path}" "$dl" || return 1
  served_b64="$(openssl dgst -sha256 -binary "$dl" 2>/dev/null | base64 -w0 2>/dev/null \
    || openssl dgst -sha256 -binary "$dl" | base64)"
  nc_assert_sha_eq "$adv_b64" "$served_b64" "dist.integrity != served-bytes sha256(b64)" || return 1
}
