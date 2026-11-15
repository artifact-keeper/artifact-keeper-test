#!/usr/bin/env bash
# =============================================================================
# tiers/conda-remote-403-probe-fallback/oracle.sh - artifact-keeper#4929
# =============================================================================
# See manifest. Channels on the mock (paths are the Remote upstream bases):
#   /s3     plain repodata.json only; .zst, .bz2 and the CEP-16 index answer 403
#   /signed repodata.json (SIGNED), repodata.json.sig, and a .zst that decodes
#           to a DIFFERENT document
#   /evict  a .zst that is not a zstd frame on the first fetch, a valid one after
#   /zst    repodata.json.zst only (plain .json and .bz2 are 404)       #4180
#   /bz2    repodata.json.bz2 only (plain .json and .zst are 404)       #4180
#   /big    a ~2 MiB .zst whose plain document is larger than the 128 MiB
#           buffered-metadata ceiling (plain .json and .bz2 are 404)    #4180
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"
source "$COMMON_SH"

begin_suite "conda-remote-403-probe-fallback (#4929 #4180)"
auth_admin
setup_workdir
W="$WORK_DIR"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
R_S3="c403-s3-${SUF}"
R_SIG="c403-sig-${SUF}"
R_M="c403-m-${SUF}"
R_EV="c403-ev-${SUF}"
V="c403-v-${SUF}"
V_EV="c403-vev-${SUF}"
R_ZST="c403-zst-${SUF}"
R_BZ2="c403-bz2-${SUF}"
R_BIG="c403-big-${SUF}"

cleanup() {
  local k
  for k in "$V" "$V_EV" "$R_S3" "$R_SIG" "$R_M" "$R_EV" "$R_ZST" "$R_BZ2" "$R_BIG"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

mock_put() { curl -s --max-time 10 -X PUT --data-binary @"$2" "${MOCK}/__file?path=$1" | jq -r '.bytes // empty' 2>/dev/null || true; }
mock_status() { curl -s --max-time 10 -X POST "${MOCK}/__status?path=$1&code=$2" >/dev/null 2>&1 || true; }
mock_gets() { curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jq -r '.get // empty' 2>/dev/null || true; }
hget() { curl -s --max-time 60 -o "$2" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000; }
# hgeth <path> <out> [curl args...] -> HTTP status; headers in <out>.hdr
hgeth() {
  local p="$1" o="$2"; shift 2
  curl -s --max-time 60 -D "${o}.hdr" -o "$o" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
hdr() { { grep -i "^$2:" "$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
repodata() { # <file> <package-filename>
  printf '{"info":{"subdir":"noarch"},"packages":{"%s":{"name":"%s","version":"1.0","build":"0","build_number":0,"depends":[],"subdir":"noarch"}},"packages.conda":{},"repodata_version":1}' \
    "$2" "${2%%-1.0-0.tar.bz2}" > "$1"
}

begin_test "setup: mock channels, seven Remotes, two Virtuals"
err=""
repodata "$W/s3.json" "dtfs3-1.0-0.tar.bz2"
repodata "$W/signed.json" "dtfsigned-1.0-0.tar.bz2"
repodata "$W/other.json" "dtfother-1.0-0.tar.bz2"
repodata "$W/evict.json" "dtfevict-1.0-0.tar.bz2"
printf 'signature-over-the-plain-repodata.json-%s' "$SUF" > "$W/sig"
printf 'not a zstd frame' > "$W/garbage"
zstd -q -f "$W/other.json" -o "$W/other.json.zst"
zstd -q -f "$W/evict.json" -o "$W/evict.json.zst"
[ -n "$(mock_put /s3/noarch/repodata.json "$W/s3.json")" ] || err+="put s3; "
for p in /s3/noarch/repodata.json.zst /s3/noarch/repodata.json.bz2 /s3/noarch/repodata_shards.msgpack.zst; do
  mock_status "$p" 403
done
[ -n "$(mock_put /signed/noarch/repodata.json "$W/signed.json")" ] || err+="put signed; "
[ -n "$(mock_put /signed/noarch/repodata.json.sig "$W/sig")" ] || err+="put sig; "
[ -n "$(mock_put /signed/noarch/repodata.json.zst "$W/other.json.zst")" ] || err+="put signed zst; "
[ -n "$(mock_put /evict/noarch/repodata.json.zst "$W/garbage")" ] || err+="put evict garbage; "
create_repo "$R_S3" conda remote "${UP}/s3" || err+="create R_S3; "
create_repo "$R_M" conda remote "${UP}/s3" || err+="create R_M; "
create_repo "$R_SIG" conda remote "${UP}/signed" || err+="create R_SIG; "
create_repo "$R_EV" conda remote "${UP}/evict" || err+="create R_EV; "
# #4180: channels that publish only a compressed index. The /big document is
# ~140 MiB of plain JSON (past the 128 MiB LARGE_METADATA_MAX_BYTES ceiling)
# that zstd shrinks to a few MiB; it is generated, compressed and hashed as a
# stream, never written out plain.
repodata "$W/zst.json" "dtfzst-1.0-0.tar.bz2"
repodata "$W/bz2.json" "dtfbz2-1.0-0.tar.bz2"
zstd -q -f "$W/zst.json" -o "$W/zst.json.zst"
bzip2 -c "$W/bz2.json" > "$W/bz2.json.bz2"
python3 -I -c '
import sys
out = sys.stdout
out.write("{\"info\":{\"subdir\":\"noarch\"},\"packages\":{")
for i in range(560000):
    if i:
        out.write(",")
    out.write("\"dtfbig%07d-1.0-0.tar.bz2\":{\"name\":\"dtfbig%07d\",\"version\":\"1.0\",\"build\":\"0\",\"build_number\":0,\"depends\":[\"python >=3.8\",\"dtfbig-dep-%d\"],\"license\":\"MIT\",\"md5\":\"%032x\",\"sha256\":\"%064x\",\"size\":%d,\"subdir\":\"noarch\",\"timestamp\":1700000000000}" % (i, i, i % 97, i, i * 7919, 1000 + i))
out.write("},\"packages.conda\":{},\"repodata_version\":1}")
' | zstd -q -3 -c > "$W/big.json.zst" || err+="generate big.json.zst; "
BIG_PLAIN_BYTES="$(zstd -dcq "$W/big.json.zst" 2>/dev/null | wc -c)"
BIG_PLAIN_SHA="$(zstd -dcq "$W/big.json.zst" 2>/dev/null | sha256sum | cut -d' ' -f1)"
[ "${BIG_PLAIN_BYTES:-0}" -gt 134217728 ] || err+="big plain document only ${BIG_PLAIN_BYTES} bytes; "
[ -n "$(mock_put /zst/noarch/repodata.json.zst "$W/zst.json.zst")" ] || err+="put zst; "
[ -n "$(mock_put /bz2/noarch/repodata.json.bz2 "$W/bz2.json.bz2")" ] || err+="put bz2; "
[ -n "$(mock_put /big/noarch/repodata.json.zst "$W/big.json.zst")" ] || err+="put big zst; "
create_repo "$R_ZST" conda remote "${UP}/zst" || err+="create R_ZST; "
create_repo "$R_BZ2" conda remote "${UP}/bz2" || err+="create R_BZ2; "
create_repo "$R_BIG" conda remote "${UP}/big" || err+="create R_BIG; "
create_repo "$V" conda virtual || err+="create V; "
create_repo "$V_EV" conda virtual || err+="create V_EV; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R_M}\"}" >/dev/null 2>&1 || err+="member V; "
api_post "/api/v1/repositories/${V_EV}/members" "{\"member_key\":\"${R_EV}\"}" >/dev/null 2>&1 || err+="member V_EV; "
if [ -n "$err" ]; then infra_fail "setup did not complete" "$err"; # =============================================================================
# #4180: a Remote's plain repodata.json is built from the upstream compressed
# document. Before the fix (sha-b6265bf) the plain route asked upstream for
# its plain .json only, so a channel that publishes only .zst/.bz2 answered
# 404 for the document every classic conda client reads first.
# =============================================================================
begin_test "CONTROL: a Remote proxies upstream's repodata.json.zst byte for byte"
st=$(hget "${C}/${R_ZST}/noarch/repodata.json.zst" "$W/ctl_zst.zst")
if [ "$st" = "200" ] && [ "$(sha "$W/ctl_zst.zst")" = "$(sha "$W/zst.json.zst")" ]; then
  pass
else
  fail "HTTP ${st}" "upstream .zst GETs=$(mock_gets /zst/noarch/repodata.json.zst)"
fi

begin_test "FIX #4180: a Remote whose upstream has only repodata.json.zst serves plain repodata.json decoded from it"
st=$(hgeth "${C}/${R_ZST}/noarch/repodata.json" "$W/got_zst.json")
if [ "$st" = "200" ] && [ "$(sha "$W/got_zst.json")" = "$(sha "$W/zst.json")" ] \
   && [ -z "$(hdr "$W/got_zst.json" content-encoding)" ]; then
  pass
else
  fail "HTTP ${st}, body $(head -c 160 "$W/got_zst.json" | tr -c '[:print:]' '.')" \
       "upstream GETs: json=$(mock_gets /zst/noarch/repodata.json) zst=$(mock_gets /zst/noarch/repodata.json.zst)"
fi

begin_test "FIX #4180: a Remote whose upstream has only repodata.json.bz2 serves plain repodata.json decoded from it"
st=$(hget "${C}/${R_BZ2}/noarch/repodata.json" "$W/got_bz2.json")
if [ "$st" = "200" ] && [ "$(sha "$W/got_bz2.json")" = "$(sha "$W/bz2.json")" ]; then
  pass
else
  fail "HTTP ${st}, body $(head -c 160 "$W/got_bz2.json" | tr -c '[:print:]' '.')" \
       "upstream GETs: json=$(mock_gets /bz2/noarch/repodata.json) zst=$(mock_gets /bz2/noarch/repodata.json.zst) bz2=$(mock_gets /bz2/noarch/repodata.json.bz2)"
fi

begin_test "FIX #4180: the transcoded plain index carries its own ETag, revalidates with 304 and is served from the cached .zst"
z_before=$(mock_gets /zst/noarch/repodata.json.zst)
st1=$(hgeth "${C}/${R_ZST}/noarch/repodata.json" "$W/warm_zst.json")
etag_plain="$(hdr "$W/warm_zst.json" etag)"
st2=$(hgeth "${C}/${R_ZST}/noarch/repodata.json.zst" "$W/warm_zst.zst")
etag_zst="$(hdr "$W/warm_zst.zst" etag)"
st3="000"
[ -n "$etag_plain" ] && st3=$(hgeth "${C}/${R_ZST}/noarch/repodata.json" "$W/cond_zst.json" -H "If-None-Match: ${etag_plain}")
z_after=$(mock_gets /zst/noarch/repodata.json.zst)
if [ "$st1" = "200" ] && [ "$(sha "$W/warm_zst.json")" = "$(sha "$W/zst.json")" ] \
   && [ "$st2" = "200" ] && [ "$(sha "$W/warm_zst.zst")" = "$(sha "$W/zst.json.zst")" ] \
   && [ -n "$etag_plain" ] && [ "$etag_plain" != "$etag_zst" ] && [ "$st3" = "304" ] \
   && [ "${z_after:-x}" = "${z_before:-y}" ] && [ "$(mock_gets /zst/noarch/repodata.json)" = "0" ]; then
  pass
else
  fail "plain HTTP ${st1} etag=${etag_plain:-none}; .zst HTTP ${st2} etag=${etag_zst:-none}; conditional plain HTTP ${st3}" \
       "upstream .zst GETs ${z_before} -> ${z_after}; upstream plain GETs $(mock_gets /zst/noarch/repodata.json)"
fi

begin_test "FIX #4180: a plain index larger than the 128 MiB buffered ceiling is served whole from its small upstream .zst"
# The body is hashed as it arrives; curl writes the status and size to stderr.
curl -s --max-time 300 -o - -w '%{stderr}%{http_code} %{size_download}' \
  "${BASE_URL}${C}/${R_BIG}/noarch/repodata.json" 2>"$W/big.meta" | sha256sum | cut -d' ' -f1 > "$W/big.sha"
got="$(cat "$W/big.meta" 2>/dev/null)"; got="${got:-000 0}"
st="${got%% *}"; size="${got##* }"
if [ "$st" = "200" ] && [ "$size" = "$BIG_PLAIN_BYTES" ] && [ "$(cat "$W/big.sha" 2>/dev/null)" = "$BIG_PLAIN_SHA" ]; then
  pass
else
  fail "HTTP ${st}, ${size} bytes (want ${BIG_PLAIN_BYTES} bytes, the decoded $(wc -c < "$W/big.json.zst")-byte upstream .zst)" \
       "upstream GETs: json=$(mock_gets /big/noarch/repodata.json) zst=$(mock_gets /big/noarch/repodata.json.zst)"
fi

end_suite; fi
pass

C="/conda"

begin_test "control: the .sig of the signed Remote is proxied byte for byte"
st=$(hget "${C}/${R_SIG}/noarch/repodata.json.sig" "$W/got.sig")
if [ "$st" = "200" ] && [ "$(sha "$W/got.sig")" = "$(sha "$W/sig")" ]; then pass; else fail "HTTP ${st}"; fi

begin_test "FIX #4929: a Remote whose .zst/.bz2 answer 403 serves upstream's plain repodata.json"
st=$(hget "${C}/${R_S3}/noarch/repodata.json" "$W/got_s3.json")
if [ "$st" = "200" ] && [ "$(sha "$W/got_s3.json")" = "$(sha "$W/s3.json")" ]; then
  pass
else
  fail "HTTP ${st}, body $(head -c 160 "$W/got_s3.json" | tr -c '[:print:]' '.')" \
       "upstream GETs: zst=$(mock_gets /s3/noarch/repodata.json.zst) bz2=$(mock_gets /s3/noarch/repodata.json.bz2) json=$(mock_gets /s3/noarch/repodata.json)"
fi

begin_test "FIX #4929: a Virtual whose Remote member answers 403 for .zst/.bz2 merges the member's plain repodata.json"
st=$(hget "${C}/${V}/noarch/repodata.json" "$W/got_v.json")
if [ "$st" = "200" ] && jq -e '.packages | has("dtfs3-1.0-0.tar.bz2")' "$W/got_v.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}, body $(head -c 160 "$W/got_v.json" | tr -c '[:print:]' '.')"
fi

begin_test "FIX #4929: a signed Remote's plain repodata.json is upstream's signed .json, not its decoded .zst"
st=$(hget "${C}/${R_SIG}/noarch/repodata.json" "$W/got_sig.json")
if [ "$st" = "200" ] && [ "$(sha "$W/got_sig.json")" = "$(sha "$W/signed.json")" ]; then
  pass
else
  fail "HTTP ${st}, served $(jq -c '.packages | keys' "$W/got_sig.json" 2>/dev/null) (want dtfsigned, dtfother is the .zst)"
fi

begin_test "FIX #4929: a Virtual member that cached an undecodable .zst evicts it and refetches on the next request"
st1=$(hget "${C}/${V_EV}/noarch/repodata.json" "$W/got_ev1.json")
[ -n "$(mock_put /evict/noarch/repodata.json.zst "$W/evict.json.zst")" ] || true
st2=$(hget "${C}/${V_EV}/noarch/repodata.json" "$W/got_ev2.json")
n=$(mock_gets /evict/noarch/repodata.json.zst)
if [ "$st2" = "200" ] && jq -e '.packages | has("dtfevict-1.0-0.tar.bz2")' "$W/got_ev2.json" >/dev/null 2>&1; then
  pass
else
  fail "first HTTP ${st1}, second HTTP ${st2} (upstream .zst GETs=${n})" "$(head -c 200 "$W/got_ev2.json" | tr -c '[:print:]' '.')"
fi

# =============================================================================
# #4180: a Remote's plain repodata.json is built from the upstream compressed
# document. Before the fix (sha-b6265bf) the plain route asked upstream for
# its plain .json only, so a channel that publishes only .zst/.bz2 answered
# 404 for the document every classic conda client reads first.
# =============================================================================
begin_test "CONTROL: a Remote proxies upstream's repodata.json.zst byte for byte"
st=$(hget "${C}/${R_ZST}/noarch/repodata.json.zst" "$W/ctl_zst.zst")
if [ "$st" = "200" ] && [ "$(sha "$W/ctl_zst.zst")" = "$(sha "$W/zst.json.zst")" ]; then
  pass
else
  fail "HTTP ${st}" "upstream .zst GETs=$(mock_gets /zst/noarch/repodata.json.zst)"
fi

begin_test "FIX #4180: a Remote whose upstream has only repodata.json.zst serves plain repodata.json decoded from it"
st=$(hgeth "${C}/${R_ZST}/noarch/repodata.json" "$W/got_zst.json")
if [ "$st" = "200" ] && [ "$(sha "$W/got_zst.json")" = "$(sha "$W/zst.json")" ] \
   && [ -z "$(hdr "$W/got_zst.json" content-encoding)" ]; then
  pass
else
  fail "HTTP ${st}, body $(head -c 160 "$W/got_zst.json" | tr -c '[:print:]' '.')" \
       "upstream GETs: json=$(mock_gets /zst/noarch/repodata.json) zst=$(mock_gets /zst/noarch/repodata.json.zst)"
fi

begin_test "FIX #4180: a Remote whose upstream has only repodata.json.bz2 serves plain repodata.json decoded from it"
st=$(hget "${C}/${R_BZ2}/noarch/repodata.json" "$W/got_bz2.json")
if [ "$st" = "200" ] && [ "$(sha "$W/got_bz2.json")" = "$(sha "$W/bz2.json")" ]; then
  pass
else
  fail "HTTP ${st}, body $(head -c 160 "$W/got_bz2.json" | tr -c '[:print:]' '.')" \
       "upstream GETs: json=$(mock_gets /bz2/noarch/repodata.json) zst=$(mock_gets /bz2/noarch/repodata.json.zst) bz2=$(mock_gets /bz2/noarch/repodata.json.bz2)"
fi

begin_test "FIX #4180: the transcoded plain index carries its own ETag, revalidates with 304 and is served from the cached .zst"
z_before=$(mock_gets /zst/noarch/repodata.json.zst)
st1=$(hgeth "${C}/${R_ZST}/noarch/repodata.json" "$W/warm_zst.json")
etag_plain="$(hdr "$W/warm_zst.json" etag)"
st2=$(hgeth "${C}/${R_ZST}/noarch/repodata.json.zst" "$W/warm_zst.zst")
etag_zst="$(hdr "$W/warm_zst.zst" etag)"
st3="000"
[ -n "$etag_plain" ] && st3=$(hgeth "${C}/${R_ZST}/noarch/repodata.json" "$W/cond_zst.json" -H "If-None-Match: ${etag_plain}")
z_after=$(mock_gets /zst/noarch/repodata.json.zst)
if [ "$st1" = "200" ] && [ "$(sha "$W/warm_zst.json")" = "$(sha "$W/zst.json")" ] \
   && [ "$st2" = "200" ] && [ "$(sha "$W/warm_zst.zst")" = "$(sha "$W/zst.json.zst")" ] \
   && [ -n "$etag_plain" ] && [ "$etag_plain" != "$etag_zst" ] && [ "$st3" = "304" ] \
   && [ "${z_after:-x}" = "${z_before:-y}" ] && [ "$(mock_gets /zst/noarch/repodata.json)" = "0" ]; then
  pass
else
  fail "plain HTTP ${st1} etag=${etag_plain:-none}; .zst HTTP ${st2} etag=${etag_zst:-none}; conditional plain HTTP ${st3}" \
       "upstream .zst GETs ${z_before} -> ${z_after}; upstream plain GETs $(mock_gets /zst/noarch/repodata.json)"
fi

begin_test "FIX #4180: a plain index larger than the 128 MiB buffered ceiling is served whole from its small upstream .zst"
# The body is hashed as it arrives; curl writes the status and size to stderr.
curl -s --max-time 300 -o - -w '%{stderr}%{http_code} %{size_download}' \
  "${BASE_URL}${C}/${R_BIG}/noarch/repodata.json" 2>"$W/big.meta" | sha256sum | cut -d' ' -f1 > "$W/big.sha"
got="$(cat "$W/big.meta" 2>/dev/null)"; got="${got:-000 0}"
st="${got%% *}"; size="${got##* }"
if [ "$st" = "200" ] && [ "$size" = "$BIG_PLAIN_BYTES" ] && [ "$(cat "$W/big.sha" 2>/dev/null)" = "$BIG_PLAIN_SHA" ]; then
  pass
else
  fail "HTTP ${st}, ${size} bytes (want ${BIG_PLAIN_BYTES} bytes, the decoded $(wc -c < "$W/big.json.zst")-byte upstream .zst)" \
       "upstream GETs: json=$(mock_gets /big/noarch/repodata.json) zst=$(mock_gets /big/noarch/repodata.json.zst)"
fi

end_suite
