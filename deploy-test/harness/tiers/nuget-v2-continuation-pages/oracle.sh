#!/usr/bin/env bash
# =============================================================================
# tiers/nuget-v2-continuation-pages/oracle.sh: translated NuGet V2 feeds follow
#   the upstream's continuation pages (artifact-keeper#4856)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-multi` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug.
#
# Topology (keys suffixed per run; mock = http://172.16.<slot>.91):
#   NP   remote -> /nuget/v2paged/api/v2         page 1: 1.0.0, next (absolute)
#                                                page 2: 1.0.0 2.0.0 2.1.0, next (relative)
#                                                page 3: 3.0.0
#   NF   remote -> /nuget/v2pagedforeign/api/v2  page 1: 1.0.0, next on :8081
#   NV   virtual {NP}
#
# Every FIX case is RED on 1.11.0-1.11.3 (only page 1, i.e. 1.0.0) and GREEN on
# the fix; every CONTROL holds on both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SUF="${RUN_ID##*-}$$"
SLOT="${DTF_SLOT}"
MOCK="http://172.16.${SLOT}.91"
MOCK_CTR="ak-dtf${SLOT}-mock-multi"

NP="nvc-np-${SUF}"; NF="nvc-nf-${SUF}"; NV="nvc-nv-${SUF}"
ID="dtfpg-${SUF}"
ID_F="dtfpgf-${SUF}"
ALL='["1.0.0","2.0.0","2.1.0","3.0.0"]'

WORK="$(mktemp -d -t dtf-nvc-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
get() {  # get PATH OUT -> HTTP status
  curl -s --max-time 120 -o "$2" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000
}
send() {
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
mkrepo() {
  local st; st="$(send POST /api/v1/repositories "$1")"
  ok2xx "$st" || err+="create $(echo "$1" | jq -r .key) -> ${st} $(head -c 160 "$WORK/send.out"); "
}
remote() { mkrepo "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"nuget\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"$2\"}"; }
# feed_versions FILE -> the <d:Version> of every V2 <entry>, sorted, unique, as JSON
feed_versions() {
  python3 -I - "$1" <<'PY' 2>/dev/null
import json, sys, xml.etree.ElementTree as ET
ns = {"a": "http://www.w3.org/2005/Atom",
      "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",
      "d": "http://schemas.microsoft.com/ado/2007/08/dataservices"}
rows = [e.find("m:properties", ns).findtext("d:Version", "", ns)
        for e in ET.parse(sys.argv[1]).getroot().findall("a:entry", ns)]
print(json.dumps(sorted(rows), separators=(",", ":")))
PY
}
# feed_next FILE -> the feed-level <link rel="next"> href (entities decoded)
feed_next() {
  python3 -I - "$1" <<'PY' 2>/dev/null
import sys, xml.etree.ElementTree as ET
for l in ET.parse(sys.argv[1]).getroot().findall("{http://www.w3.org/2005/Atom}link"):
    if l.get("rel") == "next":
        print(l.get("href", ""))
PY
}
# reg_versions FILE -> every leaf version of a registration index, as listed
reg_versions() {
  jq -c '[.items[].items[].catalogEntry.version]' "$1" 2>/dev/null
}
# expect_all LABEL STATUS JSON-VERSIONS FILE
expect_all() {
  if [ "$2" = "200" ] && [ "$3" = "$ALL" ]; then
    pass
  else
    fail "$1: HTTP $2, versions ${3:-<none>}; want 200 with ${ALL} (pages 1-3, 1.0.0 once)" \
      "$(head -c 300 "$4")"
  fi
}

begin_suite "nuget-v2-continuation-pages (#4856)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: a remote over a paged V2 feed, one whose next link leaves the origin, a virtual over the first"
auth_admin
err=""
remote "$NP" "${MOCK}/nuget/v2paged/api/v2"
remote "$NF" "${MOCK}/nuget/v2pagedforeign/api/v2"
mkrepo "{\"key\":\"${NV}\",\"name\":\"${NV}\",\"format\":\"nuget\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[{\"repo_key\":\"${NP}\",\"priority\":1}]}"
if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass

# =============================================================================
# A. Remote over a paged V2 feed
# =============================================================================
begin_test "FIX #4856: the remote's V3 registration index lists the versions of every V2 page"
st="$(get "/nuget/${NP}/v3/registration/${ID}/index.json" "$WORK/np-reg.json")"
expect_all "remote registration" "$st" "$(reg_versions "$WORK/np-reg.json" | jq -c 'sort' 2>/dev/null)" "$WORK/np-reg.json"

begin_test "FIX #4856: the remote's V3 flat-container version list holds the versions of every V2 page"
st="$(get "/nuget/${NP}/v3/flatcontainer/${ID}/index.json" "$WORK/np-flat.json")"
expect_all "remote flat container" "$st" "$(jq -c '.versions' "$WORK/np-flat.json" 2>/dev/null)" "$WORK/np-flat.json"

# =============================================================================
# B. Virtual over the paged V2 member
# =============================================================================
begin_test "FIX #4856: the virtual's V3 registration index lists its V2 member's versions from every page"
st="$(get "/nuget/${NV}/v3/registration/${ID}/index.json" "$WORK/nv-reg.json")"
expect_all "virtual registration" "$st" "$(reg_versions "$WORK/nv-reg.json" | jq -c 'sort' 2>/dev/null)" "$WORK/nv-reg.json"

begin_test "FIX #4856: the virtual's V3 flat-container version list holds its V2 member's versions from every page"
st="$(get "/nuget/${NV}/v3/flatcontainer/${ID}/index.json" "$WORK/nv-flat.json")"
expect_all "virtual flat container" "$st" "$(jq -c '.versions' "$WORK/nv-flat.json" 2>/dev/null)" "$WORK/nv-flat.json"

begin_test "FIX #4856: the virtual's V2 FindPackagesById() lists its V2 member's versions from every page"
st="$(get "/nuget/${NV}/v2/FindPackagesById()?id='${ID}'" "$WORK/nv-v2.xml")"
expect_all "virtual V2 feed" "$st" "$(feed_versions "$WORK/nv-v2.xml")" "$WORK/nv-v2.xml"

# =============================================================================
# C. Controls
# =============================================================================
begin_test "CONTROL: the remote's raw V2 feed rewrites the next link onto AK, and following it serves page 2"
st="$(get "/nuget/${NP}/v2/FindPackagesById()?id='${ID}'" "$WORK/np-v2-p1.xml")"
p1="$(feed_versions "$WORK/np-v2-p1.xml")"
next="$(feed_next "$WORK/np-v2-p1.xml")"
st2="000"; p2=""
case "$next" in
  "${BASE_URL}/nuget/${NP}/v2/"*"\$skiptoken=page-2"*)
    st2="$(curl -s --max-time 60 -o "$WORK/np-v2-p2.xml" -w '%{http_code}' -g "$next" 2>/dev/null || echo 000)"
    p2="$(feed_versions "$WORK/np-v2-p2.xml")" ;;
esac
if [ "$st" = "200" ] && [ "$p1" = '["1.0.0"]' ] && [ "$st2" = "200" ] \
   && [ "$p2" = '["1.0.0","2.0.0","2.1.0"]' ]; then
  pass
else
  fail "page 1 HTTP ${st} ${p1:-<none>}, next '${next}', page 2 HTTP ${st2} ${p2:-<none>}; want page 1 [1.0.0] with next under ${BASE_URL}/nuget/${NP}/v2/ and page 2 [1.0.0,2.0.0,2.1.0]" \
    "$(head -c 300 "$WORK/np-v2-p1.xml")"
fi

begin_test "CONTROL: a next link to another origin is not requested, and the first page is still served"
st="$(get "/nuget/${NF}/v3/flatcontainer/${ID_F}/index.json" "$WORK/nf-flat.json")"
versions="$(jq -c '.versions' "$WORK/nf-flat.json" 2>/dev/null)"
st_reg="$(get "/nuget/${NF}/v3/registration/${ID_F}/index.json" "$WORK/nf-reg.json")"
reg="$(reg_versions "$WORK/nf-reg.json")"
foreign_hits="$(docker logs "$MOCK_CTR" 2>&1 | grep -c "^MOCKMULTI-FOREIGN .*${ID_F}")"
mock_hits="$(docker logs "$MOCK_CTR" 2>&1 | grep -c "^MOCKMULTI GET /nuget/v2pagedforeign/.*${ID_F}")"
if [ "$st" = "200" ] && [ "$versions" = '["1.0.0"]' ] && [ "$st_reg" = "200" ] \
   && [ "$reg" = '["1.0.0"]' ] && [ "$foreign_hits" = "0" ] && [ "$mock_hits" -ge 1 ]; then
  pass
else
  fail "flat container HTTP ${st} ${versions:-<none>}, registration HTTP ${st_reg} ${reg:-<none>}, other-origin requests ${foreign_hits}, configured-origin requests ${mock_hits}; want 200 [1.0.0] twice, 0 and >=1" \
    "$(head -c 200 "$WORK/nf-flat.json")"
fi

end_suite
