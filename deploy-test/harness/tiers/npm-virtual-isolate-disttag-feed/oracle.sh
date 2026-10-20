#!/usr/bin/env bash
# =============================================================================
# tiers/npm-virtual-isolate-disttag-feed/oracle.sh: npm virtual isolate mode,
#   writes routed to the caller's deployment target, the change-feed status
#   endpoint and the member-list-keyed packument cache
#   (artifact-keeper#3767, #968, #3069, #4240)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-multi` with a
# credential-bearing NPM_UPSTREAM_FEED_URL and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for what each case proves.
#
# Topology (keys suffixed per run; R's upstream offers every name at 1.0.1):
#   L  hosted, ISO 1.0.0 + CACHED 1.0.0     R  remote -> mock /ok/npm
#   P  hosted PRIVATE, CACHED 2.0.0
#   VD virtual {L, R} (default union)        VI virtual {L, R} + isolate
#   VP virtual {L, P, R} (has a private member; R's proxy TTL is 1 s)
#   W1, W2 hosted (W2 holds TAGGED 1.0.0); VW virtual {W1, W2};
#   user U may write VW and W2, not W1
#   VR virtual {R} (no hosted member)
#
# Every FIX case is RED on 1.10.0 and GREEN on 1.11.0+; every CONTROL holds on
# both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SUF="${RUN_ID##*-}$$"
SLOT="${DTF_SLOT}"
MOCK="http://172.16.${SLOT}.91"
MOCK_CTR="ak-dtf${SLOT}-mock-multi"

L="nvi-l-${SUF}";   P="nvi-p-${SUF}";   R="nvi-r-${SUF}"
VD="nvi-vd-${SUF}"; VI="nvi-vi-${SUF}"; VP="nvi-vp-${SUF}"
W1="nvi-w1-${SUF}"; W2="nvi-w2-${SUF}"; VW="nvi-vw-${SUF}"; VR="nvi-vr-${SUF}"
U="nviu${SUF}"; U_PASS="NviWriter_${SUF}_Aa1!"
ISO="dtfiso${SUF}"; UPONLY="dtfup${SUF}"; CACHED="dtfcache${SUF}"; PUB="dtfpub${SUF}"; TAGGED="dtftag${SUF}"

WORK="$(mktemp -d -t dtf-nvi-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
get() {  # get PATH OUT [curl args...] -> HTTP status
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
send() {  # send METHOD PATH JSON [token] -> HTTP status (body in $WORK/send.out)
  local tok="${4:-$ADMIN_TOKEN}"
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
is_denied() { [ "$1" = "403" ] || [ "$1" = "404" ]; }
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }
mock_hits() { docker logs "$MOCK_CTR" 2>&1 | grep -c "^MOCKMULTI GET /ok/npm/$1 " ; }
versions_of() { jq -r '.versions // {} | keys | sort | join(",")' "$1" 2>/dev/null; }
mkrepo() {
  local st; st="$(send POST /api/v1/repositories "$1")"
  ok2xx "$st" || err+="create $(echo "$1" | jq -r .key) -> ${st} $(head -c 160 "$WORK/send.out"); "
}
hosted() { mkrepo "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"npm\",\"repo_type\":\"local\",\"is_public\":$2}"; }
virtual() {  # virtual KEY MEMBER...
  local key="$1" members="" prio=1 m; shift
  for m in "$@"; do
    members+="${members:+,}{\"repo_key\":\"${m}\",\"priority\":${prio}}"; prio=$((prio + 1))
  done
  mkrepo "{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"npm\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[${members}]}"
}
# publish_doc NAME VERSION REPO OUT: an npm publish document for NAME@VERSION
publish_doc() {
  local name="$1" ver="$2" repo="$3" src="$WORK/src-$1-$2"
  mkdir -p "$src/package"
  printf '{"name":"%s","version":"%s"}\n' "$name" "$ver" > "$src/package/package.json"
  printf 'module.exports = "hosted %s %s";\n' "$name" "$ver" > "$src/package/index.js"
  tar czf "$src.tgz" -C "$src" package
  base64 < "$src.tgz" | tr -d '\n' > "$src.b64"
  jq -n --arg name "$name" --arg version "$ver" \
    --arg tarball "${BASE_URL}/npm/${repo}/${name}/-/${name}-${ver}.tgz" --rawfile data "$src.b64" \
    --argjson length "$(wc -c < "$src.tgz" | tr -d ' ')" \
    '{name: $name, "dist-tags": {latest: $version},
      versions: {($version): {name: $name, version: $version, dist: {tarball: $tarball}}},
      "_attachments": {("\($name)-\($version).tgz"): {content_type: "application/octet-stream", data: $data, length: $length}}}' \
    > "$4"
}
publish() {  # publish NAME VERSION REPO [token] -> HTTP status
  publish_doc "$1" "$2" "$3" "$WORK/pub-$1-$2.json"
  curl -s --max-time 60 -o "$WORK/pub.out" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${4:-$ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/pub-$1-$2.json" "${BASE_URL}/npm/$3/$1" 2>/dev/null || echo 000
}

begin_suite "npm-virtual-isolate-disttag-feed (#3767 #968 #3069 #4240)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: hosted, private and remote members, virtuals, a writer user"
auth_admin
err=""
hosted "$L" true; hosted "$P" false
mkrepo "{\"key\":\"${R}\",\"name\":\"${R}\",\"format\":\"npm\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"${MOCK}/ok/npm\"}"
virtual "$VD" "$L" "$R"; virtual "$VI" "$L" "$R"; virtual "$VP" "$L" "$P" "$R"
hosted "$W1" true; hosted "$W2" true; virtual "$VW" "$W1" "$W2"; virtual "$VR" "$R"
st="$(publish "$ISO" 1.0.0 "$L")";    ok2xx "$st" || err+="publish ${ISO} -> ${st} $(head -c 120 "$WORK/pub.out"); "
st="$(publish "$CACHED" 1.0.0 "$L")"; ok2xx "$st" || err+="publish ${CACHED}@L -> ${st}; "
st="$(publish "$CACHED" 2.0.0 "$P")"; ok2xx "$st" || err+="publish ${CACHED}@P -> ${st}; "
# Published straight into W2, so the dist-tag case does not depend on the
# publish-through-the-virtual case before it.
st="$(publish "$TAGGED" 1.0.0 "$W2")"; ok2xx "$st" || err+="publish ${TAGGED}@W2 -> ${st}; "
# R's own proxy cache expires after 1 s, so a recomputed virtual merge has to
# ask the upstream again: the mock's log then shows every recompute.
st="$(send PUT "/api/v1/repositories/${R}/cache-ttl" '{"cache_ttl_seconds":1}')"
ok2xx "$st" || err+="cache-ttl ${R} -> ${st} $(head -c 120 "$WORK/send.out"); "
U_ID="$(create_test_user_with_retry "$U" "$U_PASS" "${U}@t.test" 2>/dev/null || true)"
for target in "$VW" "$W2"; do
  tid="$(psql_q "SELECT id FROM repositories WHERE key='${target}'")"
  st="$(send POST /api/v1/permissions "{\"principal_type\":\"user\",\"principal_id\":\"${U_ID}\",\"target_type\":\"repository\",\"target_id\":\"${tid}\",\"actions\":[\"read\",\"write\"]}")"
  ok2xx "$st" || err+="grant write on ${target} -> ${st} $(head -c 120 "$WORK/send.out"); "
done
U_TOK=""
[ -n "$U_ID" ] && [ "$U_ID" != "null" ] && U_TOK="$(login_as "$U" "$U_PASS" 2>/dev/null || true)"
[ -n "$U_TOK" ] || err+="writer user/login; "
if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass

# =============================================================================
# A. #3767: isolate mode
# =============================================================================
begin_test "CONTROL: the default npm virtual merges the hosted 1.0.0 and the upstream 1.0.1 of a hosted name"
st="$(get "/npm/${VD}/${ISO}" "$WORK/vd.json")"
if [ "$st" = "200" ] && [ "$(versions_of "$WORK/vd.json")" = "1.0.0,1.0.1" ]; then
  pass
else
  fail "HTTP ${st}, versions '$(versions_of "$WORK/vd.json")', want 1.0.0,1.0.1" "$(head -c 300 "$WORK/vd.json")"
fi

begin_test "FIX #3767: npm_virtual_isolate_hosted_names is accepted on an npm virtual and echoed back"
st="$(send PATCH "/api/v1/repositories/${VI}" '{"npm_virtual_isolate_hosted_names":true}')"
cp "$WORK/send.out" "$WORK/vi-patch.json"
st2="$(get "/api/v1/repositories/${VI}" "$WORK/vi-get.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if ok2xx "$st" && jq -e '.npm_virtual_isolate_hosted_names == true' "$WORK/vi-patch.json" >/dev/null 2>&1 \
   && [ "$st2" = "200" ] && jq -e '.npm_virtual_isolate_hosted_names == true' "$WORK/vi-get.json" >/dev/null 2>&1; then
  pass
else
  fail "PATCH HTTP ${st}, GET HTTP ${st2}; want npm_virtual_isolate_hosted_names:true in both" \
    "$(head -c 200 "$WORK/vi-patch.json") | $(jq -c '{npm_virtual_isolate_hosted_names}' "$WORK/vi-get.json" 2>/dev/null)"
fi

begin_test "FIX #3767: the isolated virtual's packument for a hosted name drops the upstream 1.0.1"
st="$(get "/npm/${VI}/${ISO}" "$WORK/vi.json")"
if [ "$st" = "200" ] && [ "$(versions_of "$WORK/vi.json")" = "1.0.0" ] \
   && [ "$(jq -r '."dist-tags".latest' "$WORK/vi.json")" = "1.0.0" ]; then
  pass
else
  fail "HTTP ${st}, versions '$(versions_of "$WORK/vi.json")' latest '$(jq -r '."dist-tags".latest' "$WORK/vi.json" 2>/dev/null)', want 1.0.0 only" \
    "$(head -c 300 "$WORK/vi.json")"
fi

begin_test "FIX #3767: the isolated virtual refuses the upstream tarball of a hosted name, and never fetches it"
before="$(mock_hits "${ISO}/-/${ISO}-1.0.1.tgz")"
st="$(get "/npm/${VI}/${ISO}/-/${ISO}-1.0.1.tgz" "$WORK/vi.tgz")"
after="$(mock_hits "${ISO}/-/${ISO}-1.0.1.tgz")"
if [ "$st" = "404" ] && [ "$after" = "$before" ]; then
  pass
else
  fail "HTTP ${st}, upstream tarball fetches ${before} -> ${after}; want 404 and no fetch" "$(head -c 200 "$WORK/vi.tgz")"
fi

begin_test "CONTROL: the isolated virtual still federates a name no hosted member owns (packument + tarball)"
st="$(get "/npm/${VI}/${UPONLY}" "$WORK/viu.json")"
st2="$(get "/npm/${VI}/${UPONLY}/-/${UPONLY}-1.0.1.tgz" "$WORK/viu.tgz")"
if [ "$st" = "200" ] && [ "$(versions_of "$WORK/viu.json")" = "1.0.1" ] && [ "$st2" = "200" ] \
   && tar tzf "$WORK/viu.tgz" 2>/dev/null | grep -qx 'package/package.json'; then
  pass
else
  fail "packument HTTP ${st} versions '$(versions_of "$WORK/viu.json")', tarball HTTP ${st2}; want 200 1.0.1 + 200 tarball" \
    "$(head -c 200 "$WORK/viu.json")"
fi

# =============================================================================
# B. #968: writes through a virtual land in the caller's deployment target
# =============================================================================
begin_test "FIX #968: a publish through the virtual lands in the first hosted member the CALLER may write (W2, not W1)"
st="$(publish "$PUB" 1.0.0 "$VW" "$U_TOK")"
w1="$(get "/npm/${W1}/${PUB}" "$WORK/w1.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
w2="$(get "/npm/${W2}/${PUB}" "$WORK/w2.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if ok2xx "$st" && [ "$w2" = "200" ] && [ "$(versions_of "$WORK/w2.json")" = "1.0.0" ] && [ "$w1" = "404" ]; then
  pass
else
  fail "publish via ${VW} HTTP ${st} ($(head -c 160 "$WORK/pub.out")); W1 HTTP ${w1}, W2 HTTP ${w2} versions '$(versions_of "$WORK/w2.json")'; want 2xx, W2 has 1.0.0, W1 404"
fi

begin_test "FIX #968: a dist-tag write through the virtual lands in the same deployment target"
st="$(curl -s --max-time 60 -o "$WORK/dt.out" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${U_TOK}" -H 'Content-Type: application/json' -d '"1.0.0"' \
  "${BASE_URL}/npm/${VW}/-/package/${TAGGED}/dist-tags/beta" 2>/dev/null || echo 000)"
st2="$(get "/npm/${W2}/-/package/${TAGGED}/dist-tags" "$WORK/w2tags.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if ok2xx "$st" && [ "$st2" = "200" ] && [ "$(jq -r '.beta' "$WORK/w2tags.json" 2>/dev/null)" = "1.0.0" ]; then
  pass
else
  fail "dist-tag PUT via ${VW} HTTP ${st} ($(head -c 160 "$WORK/dt.out")); W2 dist-tags HTTP ${st2} $(head -c 120 "$WORK/w2tags.json"); want beta=1.0.0 in W2"
fi

begin_test "CONTROL: a virtual with no hosted member still refuses a publish with 400"
st="$(publish "$PUB" 2.0.0 "$VR")"
if [ "$st" = "400" ] && grep -qi 'virtual' "$WORK/pub.out"; then
  pass
else
  fail "HTTP ${st}, want 400 naming the virtual repository" "$(head -c 200 "$WORK/pub.out")"
fi

# =============================================================================
# C. #3069: npm upstream change-feed status
# =============================================================================
begin_test "FIX #3069: the admin feed status reports enabled=false, the feed URL without credentials, and the replica id"
st="$(get "/api/v1/admin/npm/upstream-feed/status" "$WORK/feed.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if [ "$st" = "200" ] \
   && jq -e '.enabled == false and .consumer_running == false and .is_leader == false
             and .feed_url == "https://feed.dtf.invalid/registry/_changes"
             and (.replica_id | test("^[^:]+:[0-9]+:[0-9a-f-]{36}$"))
             and (.leader_term_secs | type) == "number"' "$WORK/feed.json" >/dev/null 2>&1 \
   && ! grep -q 'dtffeedpw\|access_token\|feeduser' "$WORK/feed.json"; then
  pass
else
  fail "HTTP ${st}; want enabled=false, feed_url redacted, replica_id host:pid:uuid" "$(head -c 400 "$WORK/feed.json")"
fi

begin_test "CONTROL: the feed status is refused to a non-admin (403/404) and to an anonymous caller (401)"
st="$(get "/api/v1/admin/npm/upstream-feed/status" "$WORK/feed-u.json" -H "Authorization: Bearer ${U_TOK}")"
st2="$(get "/api/v1/admin/npm/upstream-feed/status" "$WORK/feed-a.json")"
if is_denied "$st" && [ "$st2" = "401" ] && ! grep -q 'replica_id' "$WORK/feed-u.json"; then
  pass
else
  fail "non-admin HTTP ${st}, anonymous HTTP ${st2}; want 403/404 and 401" "$(head -c 200 "$WORK/feed-u.json")"
fi

# =============================================================================
# D. #4240: a virtual with a private member is served from the packument cache
# =============================================================================
begin_test "CONTROL: the admin's merge through VP includes the private member's 2.0.0"
st="$(get "/npm/${VP}/${CACHED}" "$WORK/vp1.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if [ "$st" = "200" ] && [ "$(versions_of "$WORK/vp1.json")" = "1.0.0,1.0.1,2.0.0" ]; then
  pass
else
  fail "HTTP ${st}, versions '$(versions_of "$WORK/vp1.json")', want 1.0.0,1.0.1,2.0.0" "$(head -c 300 "$WORK/vp1.json")"
fi

begin_test "FIX #4240: a second packument request through VP is served from the cache, no member re-walk"
h1="$(mock_hits "${CACHED}")"
sleep 3   # past R's 1 s proxy TTL: a recompute must ask the upstream again
st="$(get "/npm/${VP}/${CACHED}" "$WORK/vp2.json" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
h2="$(mock_hits "${CACHED}")"
if [ "$st" = "200" ] && [ "$(versions_of "$WORK/vp2.json")" = "1.0.0,1.0.1,2.0.0" ] && [ "$h1" -ge 1 ] && [ "$h2" = "$h1" ]; then
  pass
else
  fail "HTTP ${st}, upstream packument fetches ${h1} -> ${h2}; want an unchanged count (cached merge)" \
    "$(versions_of "$WORK/vp2.json")"
fi

begin_test "CONTROL: an anonymous caller is never served the admin's cached merge (no private 2.0.0)"
st="$(get "/npm/${VP}/${CACHED}" "$WORK/vp3.json")"
if [ "$st" = "200" ] && [ "$(versions_of "$WORK/vp3.json")" = "1.0.0,1.0.1" ]; then
  pass
else
  fail "HTTP ${st}, versions '$(versions_of "$WORK/vp3.json")', want 1.0.0,1.0.1" "$(head -c 300 "$WORK/vp3.json")"
fi

end_suite
