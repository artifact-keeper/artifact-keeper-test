#!/usr/bin/env bash
# =============================================================================
# tiers/conda-shard-native-search/oracle.sh: a real conda 26.7 client searches
#   a hosted and a virtual CEP-16 sharded channel (artifact-keeper#5432)
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH.
#
# Topology (keys suffixed per run):
#   H  public hosted conda channel: dtfsn-a 1.0 and dtfsn-b 1.0 (noarch)
#   V  public virtual conda channel whose only member is H
#   C  docker.io/condaforge/miniforge3:26.7.2-0 (conda 26.7.2, shards on by
#      default) running conda-jlap-incremental/fixtures/logproxy.py in the
#      backend container's network namespace (127.0.0.1:9123 ->
#      127.0.0.1:8080, one JSON line per request); its python 3.14 also runs
#      cep16.py to decode the shard documents.
#
# Gates (RED on ghcr.io/artifact-keeper/artifact-keeper-backend:main before
# the fix):
#   FIX #5432 wire     H's shard for dtfsn-a holds dtfsn-a-1.0-0.tar.bz2 with
#                      no `fn` key, and still carries name, version, depends,
#                      sha256 and md5 (main: `fn` present).
#   FIX #5432 hosted   `conda search` of H with shards finds dtfsn-a, exit 0,
#                      and read H's shard index and a shard (main: exit 1,
#                      "multiple values for keyword argument 'fn'").
#   FIX #5432 virtual  the same search of V (main: the same error).
# CONTROL (both images):
#   H's shard index decodes and lists dtfsn-a and dtfsn-b.
#   `conda search` of H with CONDA_REPODATA_USE_SHARDS=false finds dtfsn-a
#   from repodata.json, so the channel and package are sound and only the
#   shard path is under test.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
H="csns-host-${SUF}"
V="csns-virt-${SUF}"
PROXY_FX="${DTF_DIR}/harness/tiers/conda-jlap-incremental/fixtures"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
CLIENT_IMAGE="docker.io/condaforge/miniforge3:26.7.2-0"
CLIENT="ak-dtf${DTF_SLOT}-csns-client"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
PROXY="http://127.0.0.1:9123"
FN_A="dtfsn-a-1.0-0.tar.bz2"
FN_B="dtfsn-b-1.0-0.tar.bz2"
IDX="/noarch/repodata_shards.msgpack.zst"

WORK="$(mktemp -d -t dtf-csns-XXXXXX)"
cleanup() { docker rm -f "$CLIENT" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

cx() { docker exec "$CLIENT" bash -c "$1" 2>&1; }
fetch() {
  curl -s --max-time 60 -o "$WORK/$1.body" -w '%{http_code}' "${BASE_URL}$2" 2>/dev/null || echo 000
}
# decode <tag>: the CEP-16 document in $WORK/<tag>.body -> $WORK/<tag>.json.
decode() {
  docker exec -i "$CLIENT" python3 -I /app/cep16.py < "$WORK/$1.body" > "$WORK/$1.json" 2>/dev/null
  jq -e 'has("doc")' "$WORK/$1.json" >/dev/null 2>&1
}
# search <tag> <channel> [env...]: one `conda search` through the logging
# proxy with a fresh package cache; output in <tag>.out, request log in <tag>.log.
search() {
  local tag="$1" channel="$2"; shift 2
  cx ': > /tmp/proxy.log' >/dev/null
  local rc=0
  # common.sh runs under `set -e`: a failing search is a verdict, not an abort.
  cx "export CONDA_PKGS_DIRS=/tmp/pkgs-${tag} CONDA_LOCAL_REPODATA_TTL=0 $*; \
      conda search --override-channels -c ${PROXY}/conda/${channel} 'dtfsn-a'" > "$WORK/${tag}.out" || rc=$?
  printf '\nrc=%s\n' "$rc" >> "$WORK/${tag}.out"
  cx 'cat /tmp/proxy.log' > "$WORK/${tag}.log"
}
# requests <tag>: "<status> <file>" for every noarch request the client made.
requests() {
  jq -r 'select(.path | test("/noarch/")) | "\(.status) \(.path | split("/") | last)"' \
    "$WORK/$1.log" 2>/dev/null || true
}
shard_index_reads() {
  requests "$1" | awk '$1 == 200 && $2 == "repodata_shards.msgpack.zst"' | wc -l | tr -d ' '
}
shard_reads() {
  requests "$1" | awk '$1 == 200 && $2 ~ /\.msgpack\.zst$/ && $2 != "repodata_shards.msgpack.zst"' | wc -l | tr -d ' '
}
found() { grep -Ec '^dtfsn-a[[:space:]]+1\.0[[:space:]]' "$WORK/$1.out" || true; }
summary() {
  echo "$(grep -a '^rc=' "$WORK/$1.out"); found ${2:-$(found "$1")}; noarch requests: $(requests "$1" | tr '\n' ';')"
}
search_error() { { grep -aoE "[A-Za-z]*Error[^\"]{0,160}|multiple values for keyword argument '[a-z]+'" "$WORK/$1.out" || true; } | head -2 | tr '\n' ' '; }

begin_suite "conda-shard-native-search (#5432)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, hosted and virtual channels, two uploads, conda 26.7 client with a logging proxy"
auth_admin
setup_err=""
create_repo "$H" conda local >/dev/null 2>&1 || setup_err+="create ${H}; "
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
for n in dtfsn-a dtfsn-b; do
  bash "$BUILD" "$WORK" "$n" 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${n}; "
done
for fn in "$FN_A" "$FN_B"; do
  st="$(curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$WORK/${fn}" \
    "${BASE_URL}/conda/${H}/noarch/${fn}" 2>/dev/null || echo 000)"
  case "$st" in 200|201) ;; *) setup_err+="upload ${fn} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); " ;; esac
done
create_virtual_repo "$V" conda "$H" >/dev/null 2>&1 || setup_err+="create ${V}; "
docker image inspect "$CLIENT_IMAGE" >/dev/null 2>&1 || docker pull -q "$CLIENT_IMAGE" >/dev/null 2>&1 \
  || setup_err+="pull ${CLIENT_IMAGE}; "
docker rm -f "$CLIENT" >/dev/null 2>&1 || true
docker run -d --name "$CLIENT" --network "container:${BACKEND_CTR}" --security-opt label=disable \
  -v "${PROXY_FX}:/fx:ro" -v "${CEP16}:/app/cep16.py:ro" -e PROXY_LOG=/tmp/proxy.log \
  "$CLIENT_IMAGE" python3 -I /fx/logproxy.py >/dev/null 2>&1 || setup_err+="start client; "
up=0
for _ in $(seq 1 30); do
  if cx "python3 -I -c \"import urllib.request; urllib.request.urlopen('${PROXY}/health', timeout=5)\"" >/dev/null; then
    up=1; break
  fi
  sleep 1
done
[ "$up" = 1 ] || setup_err+="proxy not reachable; "
echo "  client: $(cx 'conda --version' | tail -1); repodata_use_shards: $(cx 'conda config --show repodata_use_shards' | tail -1)"
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROLS (true on both images)
# =============================================================================
begin_test "CONTROL: the hosted shard index decodes and lists both packages"
st="$(fetch idx "/conda/${H}${IDX}")"
if [ "$st" = "200" ] && decode idx \
   && [ "$(jq -c '.doc.shards | keys' "$WORK/idx.json")" = '["dtfsn-a","dtfsn-b"]' ]; then
  pass
else
  fail "hosted shard index unreadable" "HTTP ${st}: $(jq -c '.error // (.doc.shards|keys)' "$WORK/idx.json" 2>/dev/null)"
fi
ADDR_A="$(jq -r '.doc.shards["dtfsn-a"].bin // empty' "$WORK/idx.json" 2>/dev/null)"

begin_test "CONTROL: conda 26.7 with shards off finds dtfsn-a in the hosted channel's repodata.json"
search plain "$H" CONDA_REPODATA_USE_SHARDS=false
detail="$(summary plain)"
echo "  ${detail}"
if grep -q '^rc=0$' "$WORK/plain.out" && [ "$(found plain)" -ge 1 ] && [ "$(shard_index_reads plain)" = "0" ]; then
  pass
else
  fail "the channel does not serve dtfsn-a to a conda client reading repodata.json" "${detail}; $(tail -c 400 "$WORK/plain.out")"
fi

# =============================================================================
# FIX #5432: shard records carry no `fn`
# =============================================================================
begin_test "FIX #5432: the hosted shard record has no fn and keeps name, version, depends, sha256 and md5"
st="$(fetch shard "/conda/${H}/noarch/shards/${ADDR_A:-0}.msgpack.zst")"
keys="null"
if [ "$st" = "200" ] && decode shard; then
  keys="$(jq -c --arg f "$FN_A" '.doc.packages[$f] // {} | keys' "$WORK/shard.json")"
fi
echo "  shard HTTP ${st}; ${FN_A} keys: ${keys}"
if [ "$st" = "200" ] && jq -e 'index("fn") == null and (["name","version","depends","sha256","md5"] - . == [])' \
     <<<"$keys" >/dev/null 2>&1; then
  pass
else
  fail "the shard record repeats its filename as fn (or lost a field)" "HTTP ${st}; keys ${keys}"
fi

# =============================================================================
# FIX #5432: a real conda 26.7 client searches the sharded channels
# =============================================================================
begin_test "FIX #5432: conda 26.7 searching the hosted channel by shards finds dtfsn-a"
search hosted "$H"
detail="$(summary hosted)"
echo "  ${detail}"
if grep -q '^rc=0$' "$WORK/hosted.out" && [ "$(found hosted)" -ge 1 ] \
   && [ "$(shard_index_reads hosted)" -ge 1 ] && [ "$(shard_reads hosted)" -ge 1 ]; then
  pass
else
  fail "conda cannot search the hosted sharded channel" "${detail}; $(search_error hosted)"
fi

begin_test "FIX #5432: conda 26.7 searching the virtual channel by shards finds dtfsn-a"
search virtual "$V"
detail="$(summary virtual)"
echo "  ${detail}"
if grep -q '^rc=0$' "$WORK/virtual.out" && [ "$(found virtual)" -ge 1 ] \
   && [ "$(shard_index_reads virtual)" -ge 1 ] && [ "$(shard_reads virtual)" -ge 1 ]; then
  pass
else
  fail "conda cannot search the virtual sharded channel" "${detail}; $(search_error virtual)"
fi

end_suite
