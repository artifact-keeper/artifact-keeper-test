#!/usr/bin/env bash
# test-npm-github-packages-rewrite.sh - npm Remote over a GitHub-Packages-shaped
# upstream: tarball URLs are rewritten to the proxy and fetched with the
# repository's upstream credentials.
#
# Companion E2E for artifact-keeper#3785. GitHub Packages advertises tarballs
# as <host>/download/@scope/pkg/<version>/<hash>, which has no "/-/" segment.
# The unfixed backend only rewrote "/-/" tarball URLs, so the packument served
# by a Remote repo still pointed clients at the upstream host. Clients then
# bypassed the proxy and failed without GitHub credentials, and a direct GET of
# the canonical proxy path fetched {upstream}/@scope/pkg/-/pkg-<v>.tgz, which
# GitHub does not serve.
#
# Fixture:
#   GH mock   mock-bearer-upstream.py, answers 401 unless the request carries
#             "Authorization: Bearer <token>". Serves the scoped packument
#             /@acme%2Fwidget whose 1.2.3 tarball is
#             <mock>/download/@acme/widget/1.2.3/<sha256-hex>, plus that tarball.
#   NPM mock  the shared mock-upstream.py, npmjs-shaped: /@acme%2Fwidget with a
#             "/-/" tarball of DIFFERENT bytes (same filename widget-1.2.3.tgz).
#   R         Remote -> GH mock, bearer token configured.        (1)(2)(3)(6)
#   R2        Remote -> GH mock, bearer token configured.
#   L         empty Local npm repo.
#   V1        virtual: L priority 1, R2 priority 2.               (4)
#   P         Remote -> NPM mock (no auth).
#   R3        Remote -> GH mock, bearer token configured.
#   V2        virtual: P priority 1, R3 priority 2.               (5)
#
# Assertions:
#   (1) R's packument (full and abbreviated) advertises a dist.tarball under
#       /npm/R/, not the mock host.
#   (2) GET of that tarball returns the upstream bytes; dist.integrity verifies.
#   (3) The GH mock saw the bearer token on the tarball fetch, and never an
#       unauthenticated request; the client requests to the proxy carry no
#       Authorization header.
#   (4) Through V1 (package only in the priority-2 GH member) the merged
#       packument points at /npm/V1/ and the tarball is the upstream bytes.
#   (5) Priority guard: P (priority 1) has widget-1.2.3.tgz cached; with P's
#       packument then answering 503, V2 still serves P's bytes, never R3's.
#   (6) If npm is on PATH: `npm install @acme/widget --registry <R>` succeeds
#       with an empty userconfig (no GitHub credentials).
#
# Env: MOCK_UPSTREAM_HOSTNAME (name/IP the backend pod uses to reach this
# runner's mocks). Requires curl, jq, tar, openssl, python3.
source "$(dirname "$0")/../lib/common.sh"
begin_suite "npm-github-packages-rewrite"
if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; the backend must reach this runner's mock upstreams"
fi
auth_admin
setup_workdir

SUFFIX="${RUN_ID}"
R_KEY="npmgh-r-${SUFFIX}"
R2_KEY="npmgh-r2-${SUFFIX}"
R3_KEY="npmgh-r3-${SUFFIX}"
L_KEY="npmgh-l-${SUFFIX}"
P_KEY="npmgh-p-${SUFFIX}"
V1_KEY="npmgh-v1-${SUFFIX}"
V2_KEY="npmgh-v2-${SUFFIX}"
PKG="@acme/widget"
PKG_ENC="@acme%2Fwidget"
VER="1.2.3"
TGZ_NAME="widget-${VER}.tgz"
GH_TOKEN="ghp_mock_${RUN_ID//-/_}"
GH_MOCK_PID=""

cleanup_repos() {
  for key in "$V1_KEY" "$V2_KEY" "$R_KEY" "$R2_KEY" "$R3_KEY" "$L_KEY" "$P_KEY"; do
    api_delete "/api/v1/repositories/${key}" >/dev/null 2>&1 || true
  done
}
stop_gh_mock() {
  if [ -n "$GH_MOCK_PID" ] && kill -0 "$GH_MOCK_PID" 2>/dev/null; then
    kill "$GH_MOCK_PID" 2>/dev/null || true
  fi
}
add_exit_handler "cleanup_repos"
add_exit_handler "stop_gh_mock"

sri_of() {  # sri_of FILE -> sha512-<b64>
  echo "sha512-$(openssl dgst -sha512 -binary "$1" | base64 | tr -d '\n')"
}

# build_tgz MARKER OUT -- npm-layout tarball (package/package.json, index.js).
build_tgz() {
  local marker="$1" out="$2" src="${WORK_DIR}/src-$1"
  mkdir -p "${src}/package"
  printf '{"name":"%s","version":"%s","main":"index.js"}\n' "$PKG" "$VER" > "${src}/package/package.json"
  printf 'module.exports = "%s-%s";\n' "$marker" "$RUN_ID" > "${src}/package/index.js"
  tar czf "$out" -C "$src" package
}

# write_packument OUT TARBALL_URL TGZ
write_packument() {
  local out="$1" url="$2" tgz="$3"
  jq -n --arg name "$PKG" --arg v "$VER" --arg url "$url" \
    --arg integrity "$(sri_of "$tgz")" \
    --arg shasum "$(openssl dgst -sha1 "$tgz" | awk '{print $NF}')" \
    '{_id: $name, name: $name, "dist-tags": {latest: $v},
      versions: {($v): {name: $name, version: $v, main: "index.js",
        dist: {tarball: $url, integrity: $integrity, shasum: $shasum}}},
      time: {($v): "2026-01-01T00:00:00.000Z"}}' > "$out"
}

gh_auth_count() {  # gh_auth_count STATE PATH_PREFIX -> count of requests with that auth state
  grep -c " GET ${2} auth=${1}\$" "${GH_STATE}/request-log.txt" 2>/dev/null || true
}
gh_tarball_ok_hits() {
  grep -c " GET ${GH_TARBALL_PATH} auth=ok\$" "${GH_STATE}/request-log.txt" 2>/dev/null || true
}

# anon_get URL OUT -> HTTP status. No Authorization header, no netrc, so the
# client carries no credentials of any kind.
anon_get() {
  curl -s -o "$2" -w '%{http_code}' $CURL_TIMEOUT -H 'Authorization:' "$1" 2>/dev/null || echo "000"
}

# create_virtual_with_priorities KEY M1 P1 M2 P2
create_virtual_with_priorities() {
  local payload
  payload=$(jq -n --arg key "$1" --arg m1 "$2" --arg m2 "$4" \
    --argjson p1 "$3" --argjson p2 "$5" \
    '{key: $key, name: $key, format: "npm", repo_type: "virtual", is_public: true,
      member_repos: [{repo_key: $m1, priority: $p1}, {repo_key: $m2, priority: $p2}]}')
  api_post "/api/v1/repositories" "$payload" > /dev/null
}

set_bearer() {  # set_bearer KEY
  api_put "/api/v1/repositories/${1}/upstream-auth" \
    "$(jq -n --arg t "$GH_TOKEN" '{auth_type: "bearer", password: $t}')" > /dev/null
}

# ---------------------------------------------------------------------------
begin_test "Start GitHub-Packages-shaped bearer mock and npmjs-shaped mock"
GH_STATE="${WORK_DIR}/gh-mock"
mkdir -p "${GH_STATE}/files"
GH_PORT="$(_pick_mock_port)"
MOCK_STATE_DIR="$GH_STATE" MOCK_PORT="$GH_PORT" MOCK_BEARER_TOKEN="$GH_TOKEN" \
  python3 "$(dirname "$0")/../lib/mock-bearer-upstream.py" \
  > "${WORK_DIR}/gh-mock.out" 2> "${WORK_DIR}/gh-mock.err" &
GH_MOCK_PID=$!
disown "$GH_MOCK_PID" 2>/dev/null || true
GH_BASE="http://${MOCK_UPSTREAM_HOSTNAME}:${GH_PORT}"
gh_ready=""
for _ in $(seq 1 20); do
  if [ "$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${GH_PORT}/__readyz")" = "200" ]; then
    gh_ready=1; break
  fi
  sleep 0.5
done
if [ -n "$gh_ready" ] && start_mock_upstream "${WORK_DIR}/npm-mock"; then
  NPM_STATE="$MOCK_STATE_DIR"
  NPM_BASE="$MOCK_BASE_URL"
  pass
else
  fail "mocks did not boot (gh ready=${gh_ready:-no}; $(cat "${WORK_DIR}/gh-mock.err" 2>/dev/null | head -3))"
  end_suite
fi

begin_test "Seed fixtures: GitHub-layout packument + tarball, npmjs-layout packument + different tarball"
GH_TGZ="${WORK_DIR}/gh-${TGZ_NAME}"
NPM_TGZ="${WORK_DIR}/npm-${TGZ_NAME}"
build_tgz "github" "$GH_TGZ"
build_tgz "npmjs" "$NPM_TGZ"
GH_HASH=$(openssl dgst -sha256 "$GH_TGZ" | awk '{print $NF}')
GH_TARBALL_PATH="/download/${PKG}/${VER}/${GH_HASH}"
GH_TARBALL_URL="${GH_BASE}${GH_TARBALL_PATH}"
GH_INTEGRITY=$(sri_of "$GH_TGZ")
NPM_INTEGRITY=$(sri_of "$NPM_TGZ")
mkdir -p "${GH_STATE}/files/download/${PKG}/${VER}" "${NPM_STATE}/files/${PKG}/-"
cp "$GH_TGZ" "${GH_STATE}/files${GH_TARBALL_PATH}"
write_packument "${GH_STATE}/files/${PKG_ENC}" "$GH_TARBALL_URL" "$GH_TGZ"
cp "$NPM_TGZ" "${NPM_STATE}/files/${PKG}/-/${TGZ_NAME}"
write_packument "${NPM_STATE}/files/${PKG_ENC}" "${NPM_BASE}/${PKG}/-/${TGZ_NAME}" "$NPM_TGZ"
unauth=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${GH_PORT}${GH_TARBALL_PATH}")
authd=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer ${GH_TOKEN}" "http://127.0.0.1:${GH_PORT}${GH_TARBALL_PATH}")
: > "${GH_STATE}/request-log.txt"
if [ "$unauth" = "401" ] && [ "$authd" = "200" ] && ! cmp -s "$GH_TGZ" "$NPM_TGZ"; then
  pass
else
  fail "fixture self-check: tarball without token=${unauth} (want 401), with token=${authd} (want 200)"
  end_suite
fi

begin_test "Create repos: R/R2/R3 (Remote -> GH mock, bearer), L (Local), P (Remote -> npmjs mock), V1, V2"
if create_remote_repo "$R_KEY" npm "$GH_BASE" && set_bearer "$R_KEY" && \
   create_remote_repo "$R2_KEY" npm "$GH_BASE" && set_bearer "$R2_KEY" && \
   create_remote_repo "$R3_KEY" npm "$GH_BASE" && set_bearer "$R3_KEY" && \
   create_local_repo "$L_KEY" npm && \
   create_remote_repo "$P_KEY" npm "$NPM_BASE" && \
   create_virtual_with_priorities "$V1_KEY" "$L_KEY" 1 "$R2_KEY" 2 && \
   create_virtual_with_priorities "$V2_KEY" "$P_KEY" 1 "$R3_KEY" 2; then
  pass
else
  fail "could not create the repositories"
  end_suite
fi

# ---------------------------------------------------------------------------
# (1) packument rewrite
# ---------------------------------------------------------------------------
begin_test "(1) #3785: Remote packument dist.tarball points at this repository (full + abbreviated)"
st=$(anon_get "${BASE_URL}/npm/${R_KEY}/${PKG}" "${WORK_DIR}/r-full.json")
R_TARBALL=$(jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' "${WORK_DIR}/r-full.json" 2>/dev/null)
R_INTEGRITY=$(jq -r --arg v "$VER" '.versions[$v].dist.integrity // empty' "${WORK_DIR}/r-full.json" 2>/dev/null)
st_ab=$(curl -s -o "${WORK_DIR}/r-abbrev.json" -w '%{http_code}' $CURL_TIMEOUT -H 'Authorization:' \
  -H 'Accept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8' \
  "${BASE_URL}/npm/${R_KEY}/${PKG}" 2>/dev/null) || st_ab="000"
R_TARBALL_AB=$(jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' "${WORK_DIR}/r-abbrev.json" 2>/dev/null)
want_suffix="/npm/${R_KEY}/${PKG}/-/${TGZ_NAME}"
if [ "$st" != "200" ] || [ "$st_ab" != "200" ]; then
  fail "packument GET: full HTTP ${st}, abbreviated HTTP ${st_ab}"
elif [ "${R_TARBALL%"$want_suffix"}" = "$R_TARBALL" ] || [ "${R_TARBALL_AB%"$want_suffix"}" = "$R_TARBALL_AB" ]; then
  direct=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Authorization:' "$R_TARBALL" 2>/dev/null || echo 000)
  fail "dist.tarball not rewritten: full=${R_TARBALL} abbreviated=${R_TARBALL_AB} (want ...${want_suffix}); a credential-less client GET of it answers HTTP ${direct}"
elif [ "$R_INTEGRITY" != "$GH_INTEGRITY" ]; then
  fail "dist.integrity changed: ${R_INTEGRITY} (upstream ${GH_INTEGRITY})"
else
  pass
fi

# ---------------------------------------------------------------------------
# (2) download through the proxy
# ---------------------------------------------------------------------------
begin_test "(2) #3785: GET of the advertised tarball returns the upstream bytes; integrity verifies"
R_GET_URL="${BASE_URL}${want_suffix}"
case "$R_TARBALL" in *"$want_suffix") R_GET_URL="$R_TARBALL" ;; esac
st=$(anon_get "$R_GET_URL" "${WORK_DIR}/r-served.tgz")
if [ "$st" != "200" ]; then
  fail "GET ${R_GET_URL}: HTTP ${st} ($(head -c 200 "${WORK_DIR}/r-served.tgz" 2>/dev/null))"
elif ! cmp -s "${WORK_DIR}/r-served.tgz" "$GH_TGZ"; then
  fail "served bytes differ from the upstream tarball"
elif [ "$(sri_of "${WORK_DIR}/r-served.tgz")" != "$GH_INTEGRITY" ]; then
  fail "served bytes fail dist.integrity ${GH_INTEGRITY}"
else
  pass
fi

# ---------------------------------------------------------------------------
# (3) credentials
# ---------------------------------------------------------------------------
begin_test "(3) #3785: upstream saw the bearer token on the tarball fetch; no unauthenticated upstream request"
ok_hits=$(gh_tarball_ok_hits)
none_hits=$(grep -c ' auth=none$' "${GH_STATE}/request-log.txt" 2>/dev/null || true)
wrong_hits=$(grep -c ' auth=wrong$' "${GH_STATE}/request-log.txt" 2>/dev/null || true)
if [ "${ok_hits:-0}" -ge 1 ] && [ "${none_hits:-0}" = "0" ] && [ "${wrong_hits:-0}" = "0" ]; then
  pass
else
  fail "GH mock: tarball fetches with token=${ok_hits:-0} (want >=1), requests without auth=${none_hits:-0}, wrong auth=${wrong_hits:-0}; log: $(tail -5 "${GH_STATE}/request-log.txt" | tr '\n' ';')"
fi

# ---------------------------------------------------------------------------
# (4) virtual: package only in the priority-2 GH member
# ---------------------------------------------------------------------------
begin_test "(4) #3785: virtual (empty Local p1, GH Remote p2) advertises and serves the upstream tarball"
before_hits=$(gh_tarball_ok_hits)
st=$(anon_get "${BASE_URL}/npm/${V1_KEY}/${PKG}" "${WORK_DIR}/v1.json")
V1_TARBALL=$(jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' "${WORK_DIR}/v1.json" 2>/dev/null)
V1_INTEGRITY=$(jq -r --arg v "$VER" '.versions[$v].dist.integrity // empty' "${WORK_DIR}/v1.json" 2>/dev/null)
v1_suffix="/npm/${V1_KEY}/${PKG}/-/${TGZ_NAME}"
V1_GET_URL="${BASE_URL}${v1_suffix}"
case "$V1_TARBALL" in *"$v1_suffix") V1_GET_URL="$V1_TARBALL" ;; esac
st_t=$(anon_get "$V1_GET_URL" "${WORK_DIR}/v1-served.tgz")
after_hits=$(gh_tarball_ok_hits)
if [ "$st" != "200" ]; then
  fail "virtual packument GET: HTTP ${st}"
elif [ "${V1_TARBALL%"$v1_suffix"}" = "$V1_TARBALL" ]; then
  fail "virtual dist.tarball not rewritten: ${V1_TARBALL} (want ...${v1_suffix}); tarball GET HTTP ${st_t}"
elif [ "$st_t" != "200" ] || ! cmp -s "${WORK_DIR}/v1-served.tgz" "$GH_TGZ"; then
  fail "GET ${V1_GET_URL}: HTTP ${st_t}, bytes match upstream=$(cmp -s "${WORK_DIR}/v1-served.tgz" "$GH_TGZ" && echo yes || echo no)"
elif [ "$V1_INTEGRITY" != "$GH_INTEGRITY" ]; then
  fail "virtual dist.integrity ${V1_INTEGRITY} != upstream ${GH_INTEGRITY}"
elif [ "${after_hits:-0}" -le "${before_hits:-0}" ]; then
  fail "R2 never fetched the relocated tarball with the token (hits ${before_hits} -> ${after_hits})"
else
  pass
fi

# ---------------------------------------------------------------------------
# (5) priority guard
# ---------------------------------------------------------------------------
begin_test "(5) #3785: priority-1 npmjs member with the file cached wins even when its packument is 503"
st_pp=$(anon_get "${BASE_URL}/npm/${P_KEY}/${PKG}" "${WORK_DIR}/p.json")
st_pt=$(anon_get "${BASE_URL}/npm/${P_KEY}/${PKG}/-/${TGZ_NAME}" "${WORK_DIR}/p-served.tgz")
st_r3=$(anon_get "${BASE_URL}/npm/${R3_KEY}/${PKG}" "${WORK_DIR}/r3.json")
R3_TARBALL=$(jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' "${WORK_DIR}/r3.json" 2>/dev/null)
printf '%s 503\n%s 503\n' "/@acme%2F" "/@acme%2f" > "${NPM_STATE}/status-prefixes"
p_503=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${MOCK_PORT}/${PKG_ENC}")
st_v2=$(anon_get "${BASE_URL}/npm/${V2_KEY}/${PKG}/-/${TGZ_NAME}" "${WORK_DIR}/v2-served.tgz")
if [ "$st_pp" != "200" ] || [ "$st_pt" != "200" ] || ! cmp -s "${WORK_DIR}/p-served.tgz" "$NPM_TGZ"; then
  fail "priming P: packument HTTP ${st_pp}, tarball HTTP ${st_pt}"
elif [ "$st_r3" != "200" ] || [ "$p_503" != "503" ]; then
  fail "setup: R3 packument HTTP ${st_r3}, P packument now answers ${p_503} (want 503)"
elif [ "$st_v2" != "200" ]; then
  fail "GET via V2: HTTP ${st_v2}"
elif cmp -s "${WORK_DIR}/v2-served.tgz" "$GH_TGZ"; then
  fail "priority bypass: V2 served the priority-2 GitHub member's bytes although priority-1 ${P_KEY} has ${TGZ_NAME} cached"
elif ! cmp -s "${WORK_DIR}/v2-served.tgz" "$NPM_TGZ"; then
  fail "V2 served bytes matching neither member"
else
  pass
fi

begin_test "(5b) control: the priority-2 member R3 alone does serve the GitHub bytes for the same file"
st=$(anon_get "${BASE_URL}/npm/${R3_KEY}/${PKG}/-/${TGZ_NAME}" "${WORK_DIR}/r3-served.tgz")
if [ "$st" = "200" ] && cmp -s "${WORK_DIR}/r3-served.tgz" "$GH_TGZ"; then
  pass
else
  fail "GET via R3: HTTP ${st}, GitHub bytes=$(cmp -s "${WORK_DIR}/r3-served.tgz" "$GH_TGZ" && echo yes || echo no) (R3 packument tarball ${R3_TARBALL})"
fi

# ---------------------------------------------------------------------------
# (6) npm client
# ---------------------------------------------------------------------------
begin_test "(6) #3785: npm install ${PKG} --registry <Remote> succeeds without GitHub credentials"
if ! command -v npm >/dev/null 2>&1; then
  skip "npm CLI not on PATH"
else
  proj="${WORK_DIR}/npm-proj"
  mkdir -p "$proj"
  printf '{"name":"npmgh-client","version":"1.0.0","private":true}\n' > "${proj}/package.json"
  : > "${proj}/empty-npmrc"
  npm_out=$(cd "$proj" && env -u NPM_TOKEN -u NODE_AUTH_TOKEN -u GITHUB_TOKEN \
    npm install "${PKG}@${VER}" --registry "${BASE_URL}/npm/${R_KEY}/" \
      --userconfig "${proj}/empty-npmrc" --cache "${proj}/.npm-cache" \
      --no-audit --no-fund --prefer-online 2>&1) && npm_rc=0 || npm_rc=$?
  installed="${proj}/node_modules/${PKG}/index.js"
  if [ "$npm_rc" = "0" ] && grep -q "github-${RUN_ID}" "$installed" 2>/dev/null; then
    pass
  else
    fail "npm install exit ${npm_rc}: $(echo "$npm_out" | tail -5 | tr '\n' ' ')"
  fi
fi

end_suite
