#!/usr/bin/env bash
# =============================================================================
# tiers/conda-hosted-cep16-and-upload/oracle.sh: a hosted conda channel's
#   CEP-16 shard index and shards in the wire encoding rattler reads, and the
#   conda token-channel URLs kept out of the request log
#   (artifact-keeper#4555 / #4173, #4565)
# =============================================================================
# run.sh has stood up `storage.filesystem logging.json-file` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH. logging.json-file pins the
# backend's log driver so `docker logs` returns every request line.
#
# The `.msgpack.zst` documents are decoded by
# harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py in a throwaway
# python:3.14-slim container (stdlib `compression.zstd`), which reports every
# msgpack `bin` as {"bin": hex, "len": n} and every `str` as a JSON string, so
# a 32-byte binary digest is told apart from a 64-character hex string.
#
# Topology (key suffixed per run):
#   H  PRIVATE hosted conda channel: dtfhc-a 1.0 and 2.0, dtfhc-b 1.0 (noarch)
#   T  an API token with read:artifacts, carried in the URL by the conda
#      token-channel layouts /conda/t/<T>/<H>/... and /t/<T>/conda/<H>/...
#
# Gates (1.11.0; RED on 1.10.0):
#   #4555/#4173  H's shard index carries every shard address as a 32-byte
#                msgpack bin (1.10.0: a 64-char hex string) and is served with
#                no Content-Encoding (1.10.0: `zstd`, which invites a client to
#                strip the frame the CEP-16 reader expects); a shard is served
#                the same way, hashes to its address, and its records carry
#                sha256 (32 bytes) and md5 (16 bytes) as bin equal to the
#                uploaded files' digests.
#   #4565        after GETs through both token-channel layouts the backend log
#                never contains the token and records each path as
#                /conda/t/[REDACTED]/<H>/... and /t/[REDACTED]/conda/<H>/...
#                (1.10.0: the token in clear; the /t/ layout is new in 1.11.0)
# CONTROL (both images): H's index decodes and names both packages; the
#   /conda/t/<T>/ channel serves H's repodata.json and a bogus token is 401;
#   a plain request path appears in the log verbatim (the log is readable,
#   so "token absent" is not vacuous).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
BACKEND="ak-dtf${SLOT}-backend"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
DECODER_IMAGE="docker.io/library/python:3.14-slim"
H="chcu-host-${SUF}"
IDX="/noarch/repodata_shards.msgpack.zst"
FN_A1="dtfhc-a-1.0-0.tar.bz2"
FN_A2="dtfhc-a-2.0-0.tar.bz2"
FN_B1="dtfhc-b-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-chcu-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
fetch() {
  local tag="$1" path="$2"; shift 2
  curl -s --max-time 60 -D "$WORK/${tag}.hdr" -o "$WORK/${tag}.body" -w '%{http_code}' \
    "$@" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
header() {
  { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
body_text() { head -c "${2:-300}" "$WORK/$1.body" 2>/dev/null | tr -dc '[:print:]' || true; }
decode() {
  docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
    "$DECODER_IMAGE" python3 -I /app/cep16.py < "$WORK/$1.body" > "$WORK/$1.json" 2>/dev/null \
    && jq -e 'has("doc")' "$WORK/$1.json" >/dev/null 2>&1
}
jqd() { jq -r "$2" "$WORK/$1.json" 2>/dev/null || true; }
sha_of() { { sha256sum "$1" 2>/dev/null || echo none; } | cut -d' ' -f1; }
md5_of() { { md5sum "$1" 2>/dev/null || echo none; } | cut -d' ' -f1; }
backend_log() { docker logs "$BACKEND" > "$WORK/backend.log" 2>&1 || true; }
log_count() { grep -cF -- "$1" "$WORK/backend.log" 2>/dev/null || true; }

begin_suite "conda-hosted-cep16-and-upload (#4555 #4173 #4565)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, private hosted channel, three uploads, URL token, decoder image"
auth_admin
setup_err=""
st="$(curl -s --max-time 30 -o "$WORK/create.out" -w '%{http_code}' -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${H}\",\"name\":\"${H}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":false}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
case "$st" in 200|201) ;; *) setup_err+="create private hosted -> HTTP ${st}; " ;; esac
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
for spec in "dtfhc-a 1.0" "dtfhc-a 2.0" "dtfhc-b 1.0"; do
  # shellcheck disable=SC2086
  set -- $spec
  bash "$BUILD" "$WORK" "$1" "$2" 0 noarch >/dev/null 2>&1 || setup_err+="build $1-$2; "
done
for fn in "$FN_A1" "$FN_A2" "$FN_B1"; do
  st="$(curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$WORK/${fn}" \
    "${BASE_URL}/conda/${H}/noarch/${fn}" 2>/dev/null || echo 000)"
  case "$st" in 200|201) ;; *) setup_err+="upload ${fn} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); " ;; esac
done
URL_TOKEN="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"name\":\"chcu-${SUF}\",\"scopes\":[\"read:artifacts\"]}" \
  2>/dev/null | jq -r '.token // empty' 2>/dev/null || true)"
[ -n "$URL_TOKEN" ] || setup_err+="mint URL token; "
docker image inspect "$DECODER_IMAGE" >/dev/null 2>&1 || docker pull -q "$DECODER_IMAGE" >/dev/null 2>&1 \
  || setup_err+="pull ${DECODER_IMAGE}; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROLS (true on both images)
# =============================================================================
begin_test "CONTROL: the hosted shard index decodes and names both packages"
st="$(fetch idx "/conda/${H}${IDX}" -H "$(auth_header)")"
if [ "$st" = "200" ] && decode idx \
   && [ "$(jq -c '.doc.shards | keys' "$WORK/idx.json")" = '["dtfhc-a","dtfhc-b"]' ]; then
  pass
else
  fail "hosted shard index unreadable" "HTTP ${st}: $(jq -c '.error // (.doc.shards|keys)' "$WORK/idx.json" 2>/dev/null) $(body_text idx 120)"
fi
# The shard address as served: a bin (fixed) or a hex string (1.10.0).
ADDR_A="$(jqd idx '.doc.shards["dtfhc-a"] | if type == "object" then .bin else . end | values')"

begin_test "CONTROL: the /conda/t/<TOKEN>/ channel serves the private repodata.json; a bogus token is 401"
st1="$(fetch tok_rd "/conda/t/${URL_TOKEN}/${H}/noarch/repodata.json")"
st2="$(fetch bad_rd "/conda/t/not-a-token-${SUF}/${H}/noarch/repodata.json")"
if [ "$st1" = "200" ] && [ "$st2" = "401" ] \
   && jq -e --arg a "$FN_A1" --arg b "$FN_B1" '.packages | has($a) and has($b)' "$WORK/tok_rd.body" >/dev/null 2>&1; then
  pass
else
  fail "the conda token channel is not as before" "token HTTP ${st1} $(body_text tok_rd 160); bogus token HTTP ${st2}"
fi

# =============================================================================
# #4555 / #4173: CEP-16 wire encoding of the hosted index and shards
# =============================================================================
begin_test "#4173: the hosted shard index carries 32-byte bin addresses and no Content-Encoding"
ce="$(header idx Content-Encoding)"
bins="$(jqd idx '[.doc.shards[] | (type == "object" and .len == 32)] | all')"
if [ "$st" = "200" ] && [ -z "$ce" ] && [ "$bins" = "true" ] && [ "${#ADDR_A}" = "64" ] \
   && [ "$(jqd idx '.doc.info.shards_base_url')" = "./shards/" ]; then
  pass
else
  fail "hosted shard index is not in CEP-16 wire form" \
    "Content-Encoding=[${ce}] all addresses 32-byte bin=${bins}; shards=$(jq -c '.doc.shards' "$WORK/idx.json" 2>/dev/null | head -c 300)"
fi

begin_test "#4173: a hosted shard hashes to its address, has no Content-Encoding, and carries sha256/md5 as bin equal to the uploads"
st="$(fetch shard "/conda/${H}/noarch/shards/${ADDR_A:-0000000000000000000000000000000000000000000000000000000000000000}.msgpack.zst" -H "$(auth_header)")"
ce="$(header shard Content-Encoding)"
ok=1; detail=""
if [ "$st" != "200" ] || [ -n "$ce" ] || [ "$(sha_of "$WORK/shard.body")" != "$ADDR_A" ] || ! decode shard; then
  ok=0
fi
for fn in "$FN_A1" "$FN_A2"; do
  rec_sha="$(jqd shard ".doc.packages[\"${fn}\"].sha256 | if type == \"object\" then (.bin + \"/\" + (.len|tostring)) else (\"str:\" + tostring) end")"
  rec_md5="$(jqd shard ".doc.packages[\"${fn}\"].md5 | if type == \"object\" then (.bin + \"/\" + (.len|tostring)) else (\"str:\" + tostring) end")"
  [ "$rec_sha" = "$(sha_of "$WORK/${fn}")/32" ] || ok=0
  [ "$rec_md5" = "$(md5_of "$WORK/${fn}")/16" ] || ok=0
  detail+="${fn}: sha256=${rec_sha:0:24} md5=${rec_md5:0:24}; "
done
if [ "$ok" = "1" ] && [ "$(jq -c '.doc.packages | keys' "$WORK/shard.json")" = "[\"${FN_A1}\",\"${FN_A2}\"]" ]; then
  pass
else
  fail "hosted shard is not in CEP-16 wire form" \
    "HTTP ${st} Content-Encoding=[${ce}] body sha $(sha_of "$WORK/shard.body" | head -c 12) vs address ${ADDR_A:0:12}; ${detail}records=$(jq -c '.doc.packages // {} | keys' "$WORK/shard.json" 2>/dev/null)"
fi

# =============================================================================
# #4565: the token in a conda token-channel URL never reaches the log
# =============================================================================
st_plain="$(fetch plain_cd "/conda/${H}/channeldata.json" -H "$(auth_header)")"
st_ct="$(fetch ct_idx "/conda/t/${URL_TOKEN}/${H}${IDX}")"
st_tc="$(fetch tc_rd "/t/${URL_TOKEN}/conda/${H}/noarch/repodata.json")"
sleep 2
backend_log

begin_test "CONTROL: the backend log is readable: a plain request path is recorded verbatim"
n_plain="$(log_count "/conda/${H}/channeldata.json")"
if [ "$st_plain" = "200" ] && [ "${n_plain:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "cannot read request lines from the backend log" "channeldata HTTP ${st_plain}; lines naming /conda/${H}/channeldata.json: ${n_plain}; log lines: $(wc -l < "$WORK/backend.log")"
fi

begin_test "#4565: /conda/t/<TOKEN>/ requests are logged as /conda/t/[REDACTED]/<repo>/... and the token never appears"
n_tok="$(log_count "$URL_TOKEN")"
n_red="$(log_count "/conda/t/[REDACTED]/${H}/noarch/repodata.json")"
n_red_idx="$(log_count "/conda/t/[REDACTED]/${H}/noarch/repodata_shards.msgpack.zst")"
if [ "$st_ct" = "200" ] && [ "${n_tok:-1}" = "0" ] && [ "${n_red:-0}" -ge 1 ] 2>/dev/null && [ "${n_red_idx:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "the conda URL token reaches the request log" \
    "token-channel index HTTP ${st_ct}; lines containing the token: ${n_tok}; redacted repodata lines: ${n_red}; redacted index lines: ${n_red_idx}; e.g. $(grep -F -- "$URL_TOKEN" "$WORK/backend.log" 2>/dev/null | head -1 | sed "s/${URL_TOKEN}/<TOKEN>/g" | tr -dc '[:print:]' | head -c 300)"
fi

begin_test "#4565: rattler's /t/<TOKEN>/conda/ layout serves the channel and is logged as /t/[REDACTED]/conda/<repo>/..."
n_red_t="$(log_count "/t/[REDACTED]/conda/${H}/noarch/repodata.json")"
if [ "$st_tc" = "200" ] && jq -e --arg a "$FN_A2" '.packages | has($a)' "$WORK/tc_rd.body" >/dev/null 2>&1 \
   && [ "${n_tok:-1}" = "0" ] && [ "${n_red_t:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "the /t/<TOKEN>/conda/ layout is not served or not redacted" \
    "HTTP ${st_tc} $(body_text tc_rd 160); redacted lines: ${n_red_t}; lines containing the token: ${n_tok}"
fi

end_suite
