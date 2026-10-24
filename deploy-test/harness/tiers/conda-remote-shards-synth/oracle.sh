#!/usr/bin/env bash
# =============================================================================
# tiers/conda-remote-shards-synth/oracle.sh: a Remote conda repository whose
#   upstream publishes no CEP-16 shard index serves shards synthesised from
#   the cached upstream repodata, to a real rattler client (artifact-keeper#4178)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH.
#
# Topology (key suffixed per run):
#   R  public Remote conda repository on http://172.16.<slot>.70/synth/: the
#      mock publishes noarch/repodata.json.bz2 only (dtfsyn-alpha 1.0 and 2.0,
#      dtfsyn-beta 1.0) and no shard index; cache_ttl_secs = 2.
#   P  python:3.14-slim running fixtures/logproxy.py in the backend
#      container's network namespace (127.0.0.1:9123 -> backend:8080), which
#      logs every request.
#   C  ghcr.io/prefix-dev/pixi:0.81.0 in the same namespace, `pixi search`
#      against http://127.0.0.1:9123/conda/R with a fresh cache per run.
#
# Gates (1.12.0; RED on 1.11.5):
#   #4178 index   noarch/repodata_shards.msgpack.zst is 200 and lists
#                 dtfsyn-alpha and dtfsyn-beta, with binary shard addresses
#                 (1.11.5: 404).
#   #4178 client  pixi finds dtfsyn-alpha, and its noarch requests to R are
#                 the shard index and shards only: no repodata.json /
#                 .zst / .bz2 (1.11.5: the index 404s and rattler downloads
#                 repodata.json).
#   #4178 shards  every shard the index lists is 200 and hashes to its
#                 address (#4829).
#   #4178 refresh a package added upstream (dtfsyn-gamma) is in the index
#                 after the cache TTL, and pixi finds it from shards alone.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
R="synth-remote-${SUF}"
UPSTREAM="http://172.16.${DTF_SLOT}.70/synth/"
TIER_DIR="${DTF_DIR}/harness/tiers/conda-remote-shards-synth"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
PY_IMAGE="docker.io/library/python:3.14-slim"
PIXI_IMAGE="ghcr.io/prefix-dev/pixi:0.81.0"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-conda"
PROXY_CTR="ak-dtf${DTF_SLOT}-synth-proxy"
PIXI_CTR="ak-dtf${DTF_SLOT}-synth-pixi"
PROXY="http://127.0.0.1:9123"

WORK="$(mktemp -d -t dtf-synth-XXXXXX)"
cleanup() { docker rm -f "$PROXY_CTR" "$PIXI_CTR" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -Atc "$1" 2>&1 || true
}
fetch() {
  curl -s --max-time 180 -o "$WORK/$1.body" -w '%{http_code}' "${BASE_URL}$2" 2>/dev/null || echo 000
}
decode() {
  docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
    "$PY_IMAGE" python3 -I /app/cep16.py < "$WORK/$1.body" 2>/dev/null || echo '{"error":"decoder did not run"}'
}
index_names() {
  local st; st="$(fetch idx "/conda/${R}/noarch/repodata_shards.msgpack.zst")"
  decode idx > "$WORK/idx.json"
  echo "$st $(jq -c '.doc.shards | keys' "$WORK/idx.json" 2>/dev/null || echo null)"
}
# search <tag> <spec>: pixi search through the proxy with a fresh cache.
search() {
  docker exec "$PROXY_CTR" sh -c ': > /tmp/proxy.log' >/dev/null 2>&1
  docker exec -e PIXI_CACHE_DIR="/tmp/cache-$1" -e RATTLER_CACHE_DIR="/tmp/cache-$1" "$PIXI_CTR" \
    pixi search --channel "${PROXY}/conda/${R}" --platform linux-64 "$2" > "$WORK/$1.out" 2>&1
  printf '\nrc=%s\n' "$?" >> "$WORK/$1.out"
  docker exec "$PROXY_CTR" cat /tmp/proxy.log > "$WORK/$1.log" 2>/dev/null
}
noarch_requests() {
  jq -r 'select(.path | test("/noarch/")) | "\(.status) \(.path | split("/") | last)"' "$WORK/$1.log" 2>/dev/null || true
}
index_downloads() {
  noarch_requests "$1" | awk '$2 ~ /^repodata\.json(\.zst|\.bz2)?$/' | wc -l | tr -d ' '
}
shard_fetches() {
  noarch_requests "$1" | awk '$1 == 200 && $2 ~ /\.msgpack\.zst$/ && $2 != "repodata_shards.msgpack.zst"' | wc -l | tr -d ' '
}
index_fetches() {
  noarch_requests "$1" | awk '$1 == 200 && $2 == "repodata_shards.msgpack.zst"' | wc -l | tr -d ' '
}

begin_suite "conda-remote-shards-synth (#4178)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, remote on the shard-less mock channel, pixi behind a logging proxy"
auth_admin
setup_err=""
create_repo "$R" conda remote "$UPSTREAM" >/dev/null 2>&1 || setup_err+="create ${R}; "
rid="$(psql_q "SELECT id FROM repositories WHERE key = '${R}'" | tail -1)"
[ -n "$rid" ] || setup_err+="no repository id; "
psql_q "INSERT INTO repository_config (repository_id, key, value) VALUES ('${rid}', 'cache_ttl_secs', '2')" >/dev/null
for img in "$PY_IMAGE" "$PIXI_IMAGE"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null 2>&1 || setup_err+="pull ${img}; "
done
docker rm -f "$PROXY_CTR" "$PIXI_CTR" >/dev/null 2>&1 || true
docker run -d --name "$PROXY_CTR" --network "container:${BACKEND_CTR}" --security-opt label=disable \
  -v "${TIER_DIR}/fixtures:/fx:ro" -e PROXY_LOG=/tmp/proxy.log \
  "$PY_IMAGE" python3 -I /fx/logproxy.py >/dev/null 2>&1 || setup_err+="start proxy; "
docker run -d --name "$PIXI_CTR" --network "container:${BACKEND_CTR}" --entrypoint sleep \
  "$PIXI_IMAGE" infinity >/dev/null 2>&1 || setup_err+="start pixi; "
up=0
for _ in $(seq 1 30); do
  if docker exec "$PROXY_CTR" python3 -I -c "import urllib.request; urllib.request.urlopen('${PROXY}/health', timeout=5)" >/dev/null 2>&1; then
    up=1; break
  fi
  sleep 1
done
[ "$up" = 1 ] || setup_err+="proxy not reachable; "
echo "  client: $(docker exec "$PIXI_CTR" pixi --version 2>&1 | tail -1)"
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4178: the shard index exists
# =============================================================================
begin_test "#4178: the remote serves a shard index for an upstream that publishes none"
got="$(index_names)"
bin="$(jq -r '[.doc.shards[] | (type == "object" and .len == 32)] | all' "$WORK/idx.json" 2>/dev/null || echo false)"
echo "  index: ${got}; binary addresses: ${bin}"
if [ "$got" = '200 ["dtfsyn-alpha","dtfsyn-beta"]' ] && [ "$bin" = "true" ]; then
  pass
else
  fail "no synthesised shard index" "${got}; $(head -c 300 "$WORK/idx.body")"
fi

# =============================================================================
# #4178: every listed shard is served and hashes to its address
# =============================================================================
begin_test "#4178: every shard the index lists is served and hashes to its address"
bad=0; report=""
for name in dtfsyn-alpha dtfsyn-beta; do
  addr="$(jq -r --arg n "$name" '.doc.shards[$n].bin // empty' "$WORK/idx.json" 2>/dev/null)"
  st="$(fetch shard "/conda/${R}/noarch/shards/${addr:-0}.msgpack.zst")"
  decode shard > "$WORK/shard.json"
  sha="$(jq -r '.sha256 // empty' "$WORK/shard.json")"
  recs="$(jq -r '[(.doc.packages // {} | keys[]), (.doc["packages.conda"] // {} | keys[])] | length' "$WORK/shard.json" 2>/dev/null || echo 0)"
  report+="${name}: HTTP ${st} records ${recs}; "
  [ "$st" = "200" ] && [ -n "$addr" ] && [ "$sha" = "$addr" ] || bad=$((bad + 1))
  [ "$name" = "dtfsyn-alpha" ] && [ "$recs" != "2" ] && bad=$((bad + 1))
done
echo "  ${report}"
if [ "$bad" = "0" ]; then pass; else fail "a synthesised shard is missing or does not match its address" "$report"; fi

# =============================================================================
# #4178: a rattler client reads shards only
# =============================================================================
begin_test "#4178: pixi resolves dtfsyn-alpha from the remote's shards, never its repodata.json"
search s1 dtfsyn-alpha
reqs="$(noarch_requests s1 | tr '\n' ';')"
found="$(grep -c 'dtfsyn-alpha' "$WORK/s1.out" || true)"
detail="$(grep -a '^rc=' "$WORK/s1.out"); found ${found}; noarch requests: ${reqs}"
echo "  ${detail}"
if grep -q '^rc=0$' "$WORK/s1.out" && [ "$found" -ge 1 ] && [ "$(index_fetches s1)" -ge 1 ] \
   && [ "$(shard_fetches s1)" -ge 1 ] && [ "$(index_downloads s1)" = "0" ]; then
  pass
else
  fail "the client did not resolve from shards alone" "${detail}; $(tail -c 400 "$WORK/s1.out")"
fi

# =============================================================================
# #4178: a package added upstream appears after the refresh
# =============================================================================
begin_test "#4178: a package added upstream is in the shard index after the cache TTL, from shards"
add="$(docker exec "$MOCK_CTR" python3 -c \
  "import urllib.request; print(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1/__synth/add?name=dtfsyn-gamma&version=1.0', method='POST'), timeout=10).read().decode())" 2>&1 | tail -1)"
got=""
for _ in $(seq 1 20); do
  sleep 1
  got="$(index_names)"
  [ "$got" = '200 ["dtfsyn-alpha","dtfsyn-beta","dtfsyn-gamma"]' ] && break
done
search s2 dtfsyn-gamma
reqs="$(noarch_requests s2 | tr '\n' ';')"
found="$(grep -c 'dtfsyn-gamma' "$WORK/s2.out" || true)"
detail="mock add: ${add}; index: ${got}; $(grep -a '^rc=' "$WORK/s2.out"); found ${found}; noarch requests: ${reqs}"
echo "  ${detail}"
if [ "$got" = '200 ["dtfsyn-alpha","dtfsyn-beta","dtfsyn-gamma"]' ] && grep -q '^rc=0$' "$WORK/s2.out" \
   && [ "$found" -ge 1 ] && [ "$(index_downloads s2)" = "0" ]; then
  pass
else
  fail "the upstream addition did not reach the synthesised shards" "${detail}; $(tail -c 400 "$WORK/s2.out")"
fi

end_suite
