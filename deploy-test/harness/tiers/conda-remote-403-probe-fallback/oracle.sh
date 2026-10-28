#!/usr/bin/env bash
# =============================================================================
# tiers/conda-remote-403-probe-fallback/oracle.sh - artifact-keeper#4929
# =============================================================================
# See manifest. Channels on the mock (paths are the Remote upstream bases):
#   /s3     plain repodata.json only; .zst, .bz2 and the CEP-16 index answer 403
#   /signed repodata.json (SIGNED), repodata.json.sig, and a .zst that decodes
#           to a DIFFERENT document
#   /evict  a .zst that is not a zstd frame on the first fetch, a valid one after
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"
source "$COMMON_SH"

begin_suite "conda-remote-403-probe-fallback (#4929)"
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

cleanup() {
  local k
  for k in "$V" "$V_EV" "$R_S3" "$R_SIG" "$R_M" "$R_EV"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

mock_put() { curl -s --max-time 10 -X PUT --data-binary @"$2" "${MOCK}/__file?path=$1" | jq -r '.bytes // empty' 2>/dev/null || true; }
mock_status() { curl -s --max-time 10 -X POST "${MOCK}/__status?path=$1&code=$2" >/dev/null 2>&1 || true; }
mock_gets() { curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jq -r '.get // empty' 2>/dev/null || true; }
hget() { curl -s --max-time 60 -o "$2" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
repodata() { # <file> <package-filename>
  printf '{"info":{"subdir":"noarch"},"packages":{"%s":{"name":"%s","version":"1.0","build":"0","build_number":0,"depends":[],"subdir":"noarch"}},"packages.conda":{},"repodata_version":1}' \
    "$2" "${2%%-1.0-0.tar.bz2}" > "$1"
}

begin_test "setup: mock channels, three Remotes, two Virtuals"
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
create_repo "$V" conda virtual || err+="create V; "
create_repo "$V_EV" conda virtual || err+="create V_EV; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R_M}\"}" >/dev/null 2>&1 || err+="member V; "
api_post "/api/v1/repositories/${V_EV}/members" "{\"member_key\":\"${R_EV}\"}" >/dev/null 2>&1 || err+="member V_EV; "
if [ -n "$err" ]; then infra_fail "setup did not complete" "$err"; end_suite; fi
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

end_suite
