#!/usr/bin/env bash
# =============================================================================
# tiers/conda-remote-shard-recovers/oracle.sh: a remote CEP-16 shard refused
#   for failing its address check recovers once the upstream does
#   (artifact-keeper#4829)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda-sharded` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH. The mock
# (conda-sharded-remote-virtual/fixtures/mock_conda_sharded.py) serves
# http://172.16.<slot>.71/main/, whose shard index lists dtfsh-tampered at
# address T while /main/noarch/shards/T.msgpack.zst serves different bytes;
# `GET /__heal` makes it serve the right bytes for T from then on (the
# upstream recovering). `/__requests` counts upstream hits per path.
#
# Topology (keys suffixed per run):
#   R  remote -> /main/
#   V  virtual [R]
#
# Gates (#4829; RED on 1.11.4, where the wrong bytes are committed to the
# proxy cache as immutable before the address check refuses them):
#   while the upstream is wrong: T through V and through R is 502 "does not
#     match its content address", and the proxy cache holds nothing for T
#     (no proxy_cache_artifacts row, no body on disk);
#   after /__heal: T through V is 200 with bytes hashing to T, the upstream is
#     asked again, and the proxy cache path holds exactly those bytes
#     (catalogue checksum T, body on disk hashing to T); T through R is then
#     200 from the cache without another upstream request.
# CONTROL (both images): a well-formed shard (dtfsh-alpha) is 200, hashes to
#   its address, and the second read is a cache hit (upstream asked once).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MOCK="ak-dtf${SLOT}-mock-conda-sharded"
BACKEND_CTR="ak-dtf${SLOT}-backend"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled for the db service
UP="http://172.16.${SLOT}.71"

R="csrr-remote-${SUF}"
V="csrr-virt-${SUF}"

WORK="$(mktemp -d -t dtf-csrr-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------

# fetch <tag> <path> -> HTTP status; body $WORK/<tag>.body (raw bytes)
fetch() {
  curl -s --max-time 60 -o "$WORK/$1.body" -w '%{http_code}' "${BASE_URL}$2" 2>/dev/null || echo 000
}
body_text() { head -c "${2:-200}" "$WORK/$1.body" 2>/dev/null | tr -dc '[:print:]' || true; }
sha_of() { { sha256sum "$WORK/$1.body" 2>/dev/null || echo none; } | cut -d' ' -f1; }
mock_get() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://127.0.0.1'+sys.argv[1]).read().decode())" \
    "$1" 2>/dev/null || true
}
mock_hits() { mock_get /__requests | jq -r --arg p "$1" '.[$p] // 0' 2>/dev/null || echo 0; }
addr() { jq -r --arg n "$1" '.main.shards[$n] // empty' "$WORK/manifest.json" 2>/dev/null || true; }
# The backend image has no shell: the cache volume is read through a
# throwaway container with --volumes-from the backend.
fsx() { docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }
# cached_row <address> -> checksum_sha256 of R's catalogue row for the shard ("" if none)
cached_row() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc \
    "SELECT coalesce(c.checksum_sha256, 'NULL') FROM proxy_cache_artifacts c
       JOIN repositories r ON r.id = c.repository_id
      WHERE r.key = '${R}' AND c.path = 'noarch/shards/$1.msgpack.zst'" 2>/dev/null || true
}
# cached_body_sha <address> -> sha256 of R's cached body on disk ("" if none)
cached_body_sha() {
  fsx "for f in /data/storage/proxy-cache/${R}/noarch/shards/$1.msgpack.zst/__content__ \
               /data/storage/proxy-cache/*/${R}/noarch/shards/$1.msgpack.zst/__content__; do \
         [ -f \"\$f\" ] && sha256sum \"\$f\" && break; done" | cut -d' ' -f1
}

begin_suite "conda-remote-shard-recovers (#4829)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, mock manifest, remote and virtual"
auth_admin
setup_err=""
mock_get /__manifest > "$WORK/manifest.json"
jq -e '.main.shards["dtfsh-tampered"]' "$WORK/manifest.json" >/dev/null 2>&1 \
  || setup_err+="mock manifest unreadable; "
create_repo "$R" conda remote "${UP}/main" || setup_err+="create remote; "
create_repo "$V" conda virtual || setup_err+="create virtual; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\"}" >/dev/null \
  || setup_err+="add R to V; "
docker image inspect "$FS_HELPER_IMAGE" >/dev/null 2>&1 \
  || docker pull -q "$FS_HELPER_IMAGE" >/dev/null 2>&1 || setup_err+="pull ${FS_HELPER_IMAGE}; "
# The virtual and the remote resolve the upstream shard index once, so a shard
# request below is about the shard alone.
st1="$(fetch r_idx "/conda/${R}/noarch/repodata_shards.msgpack.zst")"
st2="$(fetch v_idx "/conda/${V}/noarch/repodata_shards.msgpack.zst")"
[ "$st1" = "200" ] && [ "$st2" = "200" ] || setup_err+="shard index R HTTP ${st1}, V HTTP ${st2}; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

T="$(addr dtfsh-tampered)"
ALPHA="$(addr dtfsh-alpha)"
T_WRONG="$(jq -r '.main.tampered_served_sha256' "$WORK/manifest.json")"
P_T="/main/noarch/shards/${T}.msgpack.zst"

# =============================================================================
# CONTROL (both images)
# =============================================================================
begin_test "CONTROL: a well-formed remote shard is served, hashes to its address, and is a cache hit the second time"
p_alpha="/main/noarch/shards/${ALPHA}.msgpack.zst"
h0="$(mock_hits "$p_alpha")"
st1="$(fetch alpha1 "/conda/${R}/noarch/shards/${ALPHA}.msgpack.zst")"
st2="$(fetch alpha2 "/conda/${V}/noarch/shards/${ALPHA}.msgpack.zst")"
hits=$(( $(mock_hits "$p_alpha") - h0 ))
if [ "$st1" = "200" ] && [ "$st2" = "200" ] && [ "$(sha_of alpha1)" = "$ALPHA" ] \
   && [ "$(sha_of alpha2)" = "$ALPHA" ] && [ "$hits" = "1" ]; then
  pass
else
  fail "the control shard ${ALPHA:0:12} is not served from cache by address" \
    "R HTTP ${st1} sha $(sha_of alpha1 | head -c 12); V HTTP ${st2}; upstream hits ${hits}"
fi

# =============================================================================
# #4829: while the upstream is wrong, refused and not cached
# =============================================================================
begin_test "#4829: a shard whose upstream bytes do not hash to its address is 502 through the virtual and the remote"
h0="$(mock_hits "$P_T")"
st1="$(fetch v_bad "/conda/${V}/noarch/shards/${T}.msgpack.zst")"
st2="$(fetch r_bad "/conda/${R}/noarch/shards/${T}.msgpack.zst")"
HITS_BAD=$(( $(mock_hits "$P_T") - h0 ))
if [ "$st1" = "502" ] && [ "$st2" = "502" ] && grep -q "$R" "$WORK/v_bad.body" \
   && grep -q "does not match its content address" "$WORK/r_bad.body"; then
  pass
else
  fail "the tampered shard was not refused" "V HTTP ${st1} $(body_text v_bad); R HTTP ${st2} $(body_text r_bad)"
fi

begin_test "#4829: the refused bytes are not committed to the proxy cache (no catalogue row, no body)"
row="$(cached_row "$T")"; body_sha="$(cached_body_sha "$T")"
if [ -z "$row" ] && [ -z "$body_sha" ]; then
  pass
else
  fail "the proxy cache holds the refused shard under address ${T:0:12}" \
    "proxy_cache_artifacts checksum=${row:-<none>} body sha=${body_sha:-<none>} (the wrong bytes hash to ${T_WRONG:0:12}); upstream asked ${HITS_BAD}x for 2 requests"
fi

# =============================================================================
# #4829: once the upstream is right, served, verified and cached
# =============================================================================
begin_test "#4829: after the upstream recovers, the shard through the virtual is 200, verified, and the upstream is asked again"
mock_get /__heal >/dev/null
h0="$(mock_hits "$P_T")"
st="$(fetch v_good "/conda/${V}/noarch/shards/${T}.msgpack.zst")"
hits=$(( $(mock_hits "$P_T") - h0 ))
if [ "$st" = "200" ] && [ "$(sha_of v_good)" = "$T" ] && [ "$hits" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "the recovered shard is still refused" \
    "HTTP ${st}: $(body_text v_good) sha $(sha_of v_good | head -c 12); upstream asked again ${hits}x; proxy_cache_artifacts checksum=$(cached_row "$T")"
fi

begin_test "#4829: the proxy cache path now holds the right bytes (catalogue checksum and body both hash to the address)"
row="$(cached_row "$T")"; body_sha="$(cached_body_sha "$T")"
if [ "$row" = "$T" ] && [ "$body_sha" = "$T" ]; then
  pass
else
  fail "the cache entry for ${T:0:12} is not the verified shard" \
    "proxy_cache_artifacts checksum=${row:-<none>} body sha=${body_sha:-<none>} (wrong bytes hash to ${T_WRONG:0:12})"
fi

begin_test "#4829: the remote then serves the shard from the cache without asking the upstream"
h0="$(mock_hits "$P_T")"
st="$(fetch r_good "/conda/${R}/noarch/shards/${T}.msgpack.zst")"
hits=$(( $(mock_hits "$P_T") - h0 ))
if [ "$st" = "200" ] && [ "$(sha_of r_good)" = "$T" ] && [ "$hits" = "0" ]; then
  pass
else
  fail "the remote does not serve the cached verified shard" \
    "HTTP ${st}: $(body_text r_good) sha $(sha_of r_good | head -c 12); upstream asked ${hits}x"
fi

end_suite
