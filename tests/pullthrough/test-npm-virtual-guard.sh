#!/usr/bin/env bash
# test-npm-virtual-guard.sh -- npm virtual repo: member-priority tarball guard
# and in-process negative caching of member 404s.
#
# Companion E2E for backend issues:
#   artifact-keeper#3955 -- the virtual tarball ownership guard ignored member
#     priority. With a Remote member at priority 1 and a hosted member at
#     priority 2 BOTH holding pkg@1.0.0 (different bytes -- a same-version
#     rebuild), the priority-aware packument merge (#2844) advertises the
#     REMOTE's dist.integrity while the priority-blind guard suppressed the
#     remote fetch and served the HOSTED bytes, so npm's SRI check fails with
#     EINTEGRITY. The guard must suppress a remote member only when an owning
#     non-remote member OUTRANKS it (the #2311 PyPI rule).
#   artifact-keeper#3951 -- a virtual with a private member bypasses the #2162
#     computed-packument cache by design (#3323), so every request re-walks
#     the members, and each re-walk re-fetched a member's definitive upstream
#     404 as soon as the proxy layer's 45 s disk negative entry expired. The
#     member walk now keeps a short-lived in-process negative cache per
#     (member, package) -- env NPM_VIRTUAL_NEGATIVE_CACHE_TTL_MS, default
#     5000 ms -- so a member that just 404'd is not re-asked within the TTL.
#
# Fixture shape (AK-to-AK upstreams, same rationale as
# test-npm-packument-swr.sh; the request-counting mock is reserved for the
# member that must 404):
#
#   U   local npm repo playing "upstream registry": GUARDPKG@1.0.0 (UPSTREAM
#       bytes) and NEGPKG@1.0.0 published here.
#   L   local npm member: GUARDPKG@1.0.0 published with LOCAL rebuild bytes.
#   M   remote npm member -> U's own AK URL (the backend dials itself).
#   B   remote npm member -> the request-counting mock, which serves NOTHING
#       (every GET 404s); B is PRIVATE.
#   V1  virtual: M priority 1, L priority 2  -> the remote entry must win.
#   V2  virtual: L priority 1, M priority 2  -> the local entry must win
#       (the dependency-confusion shadowing defence, unchanged).
#   V3  virtual: M priority 1, B priority 2  -> a private member forces the
#       per-request member walk; B's 404 must be absorbed in-process.
#
# Assertions:
#   #3955: V1's packument advertises U's integrity (via M) and a GET of the
#     advertised tarball through V1 returns the UPSTREAM bytes whose SRI
#     verifies. On the unfixed backend V1 serves the hosted rebuild and the
#     SRI fails -- the EINTEGRITY from the issue. V2 keeps serving the
#     hosted bytes when the hosted member outranks the remote.
#   #3951: two packument GETs through V3 hit B's mock only ONCE, with B's
#     disk negative-cache sidecar deleted between them so the second
#     request's absorption can come ONLY from the in-process entry. On the
#     unfixed backend the second GET re-fetches B (counter -> 2).
#
# Requires: curl, jq, tar, openssl, kubectl.
# Env:
#   MOCK_UPSTREAM_HOSTNAME -- name/IP the backend pod uses to reach this
#     runner's mock (same contract as test-cargo-virtual-members.sh).
#   NAMESPACE -- k8s namespace of the backend under test; the backend's own
#     service URL is derived from it for the AK-to-AK remote, and the #3951
#     leg execs into the backend pod to drop the disk negative sidecar.
source "$(dirname "$0")/../lib/common.sh"
begin_suite "npm-virtual-guard"
if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip_suite "MOCK_UPSTREAM_HOSTNAME unset; CI must set this to a name the backend can resolve to the test runner pod"
fi
if [ -z "${NAMESPACE:-}" ]; then
  skip_suite "NAMESPACE unset; the AK-to-AK remote and the #3951 sidecar exec both need the backend's namespace"
fi
require_cmd kubectl
auth_admin
setup_workdir

U_KEY="nvg-u-${RUN_ID}"
L_KEY="nvg-l-${RUN_ID}"
M_KEY="nvg-m-${RUN_ID}"
B_KEY="nvg-b-${RUN_ID}"
V1_KEY="nvg-v1-${RUN_ID}"
V2_KEY="nvg-v2-${RUN_ID}"
V3_KEY="nvg-v3-${RUN_ID}"
GUARDPKG="nvgguard${RUN_ID//-/}"
NEGPKG="nvgneg${RUN_ID//-/}"
VER="1.0.0"
GUARD_TGZ="${GUARDPKG}-${VER}.tgz"
# The backend dials itself through its own Service for the AK-to-AK remote
# member (BASE_URL is the runner-side port-forward and unreachable from pods).
SELF_URL="http://artifact-keeper-backend.${NAMESPACE}.svc.cluster.local:8080"

cleanup_repos() {
  for key in "$V1_KEY" "$V2_KEY" "$V3_KEY" "$L_KEY" "$M_KEY" "$B_KEY" "$U_KEY"; do
    api_delete "/api/v1/repositories/${key}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup_repos"

# sri_verify INTEGRITY FILE -- npm subresource-integrity check for the
# sha512/sha256/sha1 algorithms npm emits.
sri_verify() {
  local integrity="$1" file="$2"
  local algo="${integrity%%-*}" want="${integrity#*-}" got=""
  case "$algo" in
    sha512|sha256|sha1)
      got=$(openssl dgst "-${algo}" -binary "$file" | base64 | tr -d '\n')
      ;;
    *)
      return 1
      ;;
  esac
  [ -n "$want" ] && [ "$got" = "$want" ]
}

# create_virtual_with_priorities KEY M1 P1 M2 P2
# Creates a virtual npm repo whose two members carry EXPLICIT priorities
# (lower value = searched first); the create-time member_repos payload is
# the only API surface that pins priority atomically with creation.
create_virtual_with_priorities() {
  local key="$1" m1="$2" p1="$3" m2="$4" p2="$5"
  local payload
  payload=$(jq -n \
    --arg key "$key" --arg m1 "$m1" --arg m2 "$m2" \
    --argjson p1 "$p1" --argjson p2 "$p2" \
    '{key: $key, name: $key, format: "npm", repo_type: "virtual", is_public: true,
      member_repos: [{repo_key: $m1, priority: $p1}, {repo_key: $m2, priority: $p2}]}')
  api_post "/api/v1/repositories" "$payload" > /dev/null
}

# publish_npm REPO_KEY PACKAGE MARKER -- npm-native PUT with _attachments
# (same payload shape as test-npm-packument-swr.sh). Builds a real tar.gz
# whose index.js carries MARKER, publishes it, echoes the HTTP status, and
# leaves the tarball at ${WORK_DIR}/<marker>-<pkg>-<ver>.tgz for byte
# comparison later.
publish_npm() {
  local repo_key="$1" pkg="$2" marker="$3"
  local src="${WORK_DIR}/src-${marker}-${pkg}"
  mkdir -p "$src"
  printf '{"name":"%s","version":"%s"}\n' "$pkg" "$VER" > "${src}/package.json"
  printf 'module.exports = "%s-%s";\n' "$marker" "$RUN_ID" > "${src}/index.js"
  local tgz="${WORK_DIR}/${marker}-${pkg}-${VER}.tgz"
  tar czf "$tgz" -C "$src" .
  base64 < "$tgz" | tr -d '\n' > "${WORK_DIR}/b64-${marker}-${pkg}.txt"
  local size
  size=$(wc -c < "$tgz" | tr -d ' ')
  jq -n \
    --arg name "$pkg" --arg version "$VER" \
    --arg tarball "${BASE_URL}/npm/${repo_key}/${pkg}/-/${pkg}-${VER}.tgz" \
    --rawfile data "${WORK_DIR}/b64-${marker}-${pkg}.txt" \
    --argjson length "$size" \
    '{name: $name, versions: {($version): {name: $name, version: $version, dist: {tarball: $tarball}}},
      "_attachments": {("\($name)-\($version).tgz"): {content_type: "application/octet-stream", data: $data, length: $length}}}' \
    > "${WORK_DIR}/publish-${marker}-${pkg}.json"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/json" \
    --data-binary "@${WORK_DIR}/publish-${marker}-${pkg}.json" \
    "${BASE_URL}/npm/${repo_key}/${pkg}" 2>/dev/null) || status="000"
  echo "$status"
}

# ---------------------------------------------------------------------------
# Boot the 404 mock (member B's upstream: serves nothing, counts requests)
# ---------------------------------------------------------------------------
begin_test "404 mock upstream starts (member B upstream, request-counting)"
if start_mock_upstream "${WORK_DIR}/mock-404"; then
  B404_STATE_DIR="$MOCK_STATE_DIR"
  B404_BASE_URL="$MOCK_BASE_URL"
  pass
else
  fail "404 mock upstream did not boot"
  end_suite
fi

# ---------------------------------------------------------------------------
# Repositories: upstream U, members L/M/B, virtuals V1/V2/V3
# ---------------------------------------------------------------------------
begin_test "Create upstream U and member repos L (local), M (remote->U), B (PRIVATE remote->404 mock)"
b_payload=$(jq -n --arg key "$B_KEY" --arg url "$B404_BASE_URL" \
  '{key: $key, name: $key, format: "npm", repo_type: "remote",
    upstream_url: $url, is_public: false,
    description: "private 404 member for #3951"}')
if create_local_repo "$U_KEY" "npm" && \
   create_local_repo "$L_KEY" "npm" && \
   create_remote_repo "$M_KEY" "npm" "${SELF_URL}/npm/${U_KEY}" && \
   api_post "/api/v1/repositories" "$b_payload" > /dev/null; then
  pass
else
  fail "could not create repos U=${U_KEY} L=${L_KEY} M=${M_KEY} B=${B_KEY}"
  end_suite
fi


begin_test "Grant the admin user read on PRIVATE member B (else the #3323 walk filter hides it)"
admin_uid=$(resolve_user_id_by_username "$ADMIN_USER" 2>/dev/null || true)
b_repo_id=$(api_get "/api/v1/repositories/${B_KEY}" 2>/dev/null | jq -r '.id // empty')
if [ -n "$admin_uid" ] && [ -n "$b_repo_id" ] && \
   api_post "/api/v1/permissions" \
     "{\"principal_type\":\"user\",\"principal_id\":\"${admin_uid}\",\"target_type\":\"repository\",\"target_id\":\"${b_repo_id}\",\"actions\":[\"read\"]}" \
     > /dev/null 2>&1; then
  pass
else
  fail "could not grant ${ADMIN_USER} read on ${B_KEY} (uid=${admin_uid} repo_id=${b_repo_id})"
  end_suite
fi
begin_test "Create virtuals V1 (remote p1/local p2), V2 (local p1/remote p2), V3 (M p1/private-B p2)"
if create_virtual_with_priorities "$V1_KEY" "$M_KEY" 1 "$L_KEY" 2 && \
   create_virtual_with_priorities "$V2_KEY" "$L_KEY" 1 "$M_KEY" 2 && \
   create_virtual_with_priorities "$V3_KEY" "$M_KEY" 1 "$B_KEY" 2; then
  pass
else
  fail "could not create one of the virtual repos"
  end_suite
fi

# ---------------------------------------------------------------------------
# Seed packages: U holds the UPSTREAM GUARDPKG bytes + NEGPKG; L holds the
# same-version LOCAL rebuild of GUARDPKG (the #3955 trigger condition).
# ---------------------------------------------------------------------------
begin_test "Publish ${GUARDPKG}@${VER} (upstream bytes) and ${NEGPKG}@${VER} to U"
st1=$(publish_npm "$U_KEY" "$GUARDPKG" "upstream")
st2=$(publish_npm "$U_KEY" "$NEGPKG" "upstream")
if { [ "$st1" = "200" ] || [ "$st1" = "201" ]; } && \
   { [ "$st2" = "200" ] || [ "$st2" = "201" ]; }; then
  pass
else
  fail "publish to U failed: ${GUARDPKG}=${st1} ${NEGPKG}=${st2}"
  end_suite
fi
UP_TGZ="${WORK_DIR}/upstream-${GUARDPKG}-${VER}.tgz"

begin_test "Publish ${GUARDPKG}@${VER} to L (local rebuild, different bytes)"
st3=$(publish_npm "$L_KEY" "$GUARDPKG" "local")
if [ "$st3" = "200" ] || [ "$st3" = "201" ]; then
  pass
else
  fail "publish to L failed: HTTP ${st3}"
  end_suite
fi
LOCAL_TGZ="${WORK_DIR}/local-${GUARDPKG}-${VER}.tgz"

# U's own packument is the source of truth for the integrity the remote
# member M federates; the merged V1 packument must advertise this string.
begin_test "U's packument advertises an SRI integrity for ${GUARDPKG}@${VER}"
U_DOC=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
  "${BASE_URL}/npm/${U_KEY}/${GUARDPKG}" 2>/dev/null) || U_DOC=""
UP_INTEGRITY=$(echo "$U_DOC" | jq -r --arg v "$VER" '.versions[$v].dist.integrity // empty' 2>/dev/null)
if [ -n "$UP_INTEGRITY" ] && sri_verify "$UP_INTEGRITY" "$UP_TGZ"; then
  pass
else
  fail "U packument missing/invalid integrity for ${VER}: '${UP_INTEGRITY}'"
  end_suite
fi

# ---------------------------------------------------------------------------
# #3955, V1: the REMOTE member outranks the hosted owner. The merged
# packument must advertise the remote's integrity, and the advertised
# tarball must serve the remote's bytes. Pre-fix the guard suppressed the
# remote anyway and served the hosted rebuild -> EINTEGRITY.
# ---------------------------------------------------------------------------
begin_test "V1 (remote p1): merged packument advertises the remote member's integrity (#3955)"
V1_DOC=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
  "${BASE_URL}/npm/${V1_KEY}/${GUARDPKG}" 2>/dev/null) || V1_DOC=""
V1_ADVERTISED=$(echo "$V1_DOC" | jq -r --arg v "$VER" '.versions[$v].dist.integrity // empty' 2>/dev/null)
V1_TARBALL=$(echo "$V1_DOC" | jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' 2>/dev/null)
if [ -n "$V1_ADVERTISED" ] && [ "$V1_ADVERTISED" = "$UP_INTEGRITY" ] && \
   echo "$V1_TARBALL" | grep -q "/npm/${V1_KEY}/"; then
  pass
else
  fail "V1 packument must advertise the priority-1 remote's integrity ${UP_INTEGRITY} and a /npm/${V1_KEY}/ tarball; got integrity=${V1_ADVERTISED} tarball=${V1_TARBALL}"
fi

begin_test "V1 (remote p1): advertised tarball serves the remote bytes; SRI verifies -- no EINTEGRITY (#3955)"
if [ -z "$V1_TARBALL" ]; then
  fail "no tarball URL from the V1 packument (previous assertion)"
else
  v1_status=$(curl -s -o "${WORK_DIR}/v1-served.tgz" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" "$V1_TARBALL") || v1_status="000"
  if [ "$v1_status" != "200" ]; then
    fail "GET ${V1_TARBALL}: HTTP ${v1_status}"
  elif cmp -s "${WORK_DIR}/v1-served.tgz" "$LOCAL_TGZ"; then
    fail "EINTEGRITY class bug: V1 served the HOSTED rebuild's bytes although the packument advertises the priority-1 remote member's integrity"
  elif ! cmp -s "${WORK_DIR}/v1-served.tgz" "$UP_TGZ"; then
    fail "V1 served bytes match NEITHER the priority-1 remote member's tarball NOR the hosted rebuild"
  elif ! sri_verify "$V1_ADVERTISED" "${WORK_DIR}/v1-served.tgz"; then
    fail "served bytes fail the advertised SRI ${V1_ADVERTISED} (npm would abort with EINTEGRITY)"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# #3955, V2: the hosted owner OUTRANKS the remote. The dependency-confusion
# shadowing defence is unchanged: the virtual serves the hosted bytes.
# ---------------------------------------------------------------------------
begin_test "V2 (local p1): advertised tarball serves the hosted bytes; SRI verifies (#3955 shadowing defence)"
V2_DOC=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
  "${BASE_URL}/npm/${V2_KEY}/${GUARDPKG}" 2>/dev/null) || V2_DOC=""
V2_ADVERTISED=$(echo "$V2_DOC" | jq -r --arg v "$VER" '.versions[$v].dist.integrity // empty' 2>/dev/null)
V2_TARBALL=$(echo "$V2_DOC" | jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' 2>/dev/null)
if [ -z "$V2_TARBALL" ] || ! echo "$V2_TARBALL" | grep -q "/npm/${V2_KEY}/"; then
  fail "V2 packument missing a /npm/${V2_KEY}/ tarball for ${VER}: ${V2_DOC:0:200}"
else
  v2_status=$(curl -s -o "${WORK_DIR}/v2-served.tgz" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" "$V2_TARBALL") || v2_status="000"
  if [ "$v2_status" != "200" ]; then
    fail "GET ${V2_TARBALL}: HTTP ${v2_status}"
  elif ! cmp -s "${WORK_DIR}/v2-served.tgz" "$LOCAL_TGZ"; then
    fail "V2 must serve the OUTRANKING hosted member's bytes (shadowing defence), got different bytes"
  elif [ -n "$V2_ADVERTISED" ] && ! sri_verify "$V2_ADVERTISED" "${WORK_DIR}/v2-served.tgz"; then
    fail "V2 served bytes fail the advertised SRI ${V2_ADVERTISED}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# #3951, V3: private member B forces the per-request member walk. B's first
# 404 is written to the proxy layer's disk negative cache; deleting that
# sidecar between two GETs isolates the in-process negative cache, which
# must absorb the second walk's fetch of B.
# ---------------------------------------------------------------------------
begin_test "V3 first packument GET federates member M's version; private member B asked exactly once"
V3_DOC=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
  "${BASE_URL}/npm/${V3_KEY}/${NEGPKG}" 2>/dev/null) || V3_DOC=""
b_counter="${B404_STATE_DIR}/request-count.${NEGPKG}"
b_hits=$(cat "$b_counter" 2>/dev/null || echo 0)
if echo "$V3_DOC" | grep -q "\"${VER}\"" && [ "$b_hits" = "1" ]; then
  pass
else
  fail "first V3 GET: version ${VER} present=$(echo "$V3_DOC" | grep -c "\"${VER}\"" || true) B hits=${b_hits} (expected 1)"
fi

begin_test "Drop B's disk negative-cache sidecar in the backend pod (isolates the in-process entry)"
BACKEND_POD=$(kubectl get pods -n "$NAMESPACE" --no-headers \
  -o custom-columns=:metadata.name 2>/dev/null | grep 'backend' | head -1)
# Real deployments nest the cache under the named storage backend's UUID
# (the DB fixture's storage root maps to that backend dir directly).
STORE_UUID=$(kubectl exec -n "$NAMESPACE" "$BACKEND_POD" -- ls /data/storage/proxy-cache 2>/dev/null | head -1 || true)
SIDECAR="/data/storage/proxy-cache/${STORE_UUID}/${B_KEY}/${NEGPKG}/__cache_meta__.json"
# The sidecar is written by an async cache-commit task that outlives the
# client response; poll for it rather than assuming it landed with the 404.
sidecar_seen=""
for _ in $(seq 1 20); do
  if [ -n "$BACKEND_POD" ] && kubectl exec -n "$NAMESPACE" "$BACKEND_POD" -- ls "$SIDECAR" >/dev/null 2>&1; then
    sidecar_seen=1
    break
  fi
  sleep 1
done
if [ -z "$BACKEND_POD" ]; then
  fail "no backend pod found in namespace ${NAMESPACE}"
elif [ -z "$sidecar_seen" ]; then
  bcache_listing=$(kubectl exec -n "$NAMESPACE" "$BACKEND_POD" -- ls "/data/storage/proxy-cache/${B_KEY}" 2>&1 | head -5 || true)
  fail "disk negative sidecar never appeared in pod (${SIDECAR}) within 20s; B proxy-cache dir: ${bcache_listing}"
elif ! kubectl exec -n "$NAMESPACE" "$BACKEND_POD" -- rm -f "$SIDECAR" 2>/dev/null; then
  fail "could not delete ${SIDECAR} in pod ${BACKEND_POD}"
else
  pass
fi

begin_test "V3 second packument GET does NOT re-ask B (in-process negative cache) (#3951)"
V3_DOC2=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
  "${BASE_URL}/npm/${V3_KEY}/${NEGPKG}" 2>/dev/null) || V3_DOC2=""
b_hits2=$(cat "$b_counter" 2>/dev/null || echo 0)
if [ -z "$V3_DOC2" ]; then
  fail "second V3 GET returned no packument"
elif [ "$b_hits2" != "1" ]; then
  fail "member B re-fetched despite its definitive 404 moments ago: mock hits=${b_hits2} (expected 1); the member walk has no in-process negative cache"
else
  pass
fi

end_suite
