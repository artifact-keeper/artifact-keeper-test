#!/usr/bin/env bash
# =============================================================================
# tiers/nuget-protocol-translation/oracle.sh: NuGet V2 <-> V3 translation for
#   remote upstreams, a virtual's V2 feed from remote members, and proxied
#   registration pages (artifact-keeper#4122, #4021, #3870)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-multi` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bugs.
#
# Topology (keys suffixed per run; mock = http://172.16.<slot>.91; the mock
# answers every package id with versions 1.0.0 and 2.0.0):
#   N2   remote -> /nuget/v2/api/v2        (V2 OData upstream)
#   N3   remote -> /nuget/v3/index.json    (V3 upstream, paged registration)
#   N3D  remote -> /nuget/v3down/index.json (V3 upstream answering 503)
#   NH   hosted, SHARED 1.0.0 pushed       NVV virtual {NH (1), N2 (2)}
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

N2="npt-n2-${SUF}"; N3="npt-n3-${SUF}"; N3D="npt-n3d-${SUF}"
NH="npt-nh-${SUF}"; NVV="npt-nvv-${SUF}"
ID_V2="dtfnu-a${SUF}"       # resolved through the V2-upstream remote
ID_V3="dtfnu-b${SUF}"       # resolved through the V3-upstream remote
ID_REMOTE="dtfnu-r${SUF}"   # only the virtual's remote member has it
ID_SHARED="dtfnu-s${SUF}"   # hosted 1.0.0 AND remote 1.0.0/2.0.0

WORK="$(mktemp -d -t dtf-npt-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
get() {  # get PATH OUT -> HTTP status
  curl -s --max-time 60 -o "$2" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000
}
send() {
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
mock_bytes() {
  docker exec "$MOCK_CTR" python3 -c "import sys,urllib.request; sys.stdout.buffer.write(urllib.request.urlopen('http://127.0.0.1$1').read())" > "$2" 2>/dev/null
}
# feed_rows FILE -> "<version>|<description>" per V2 <entry>, sorted
feed_rows() {
  python3 -I - "$1" <<'PY' 2>/dev/null
import sys, xml.etree.ElementTree as ET
ns = {"a": "http://www.w3.org/2005/Atom",
      "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",
      "d": "http://schemas.microsoft.com/ado/2007/08/dataservices"}
rows = []
for e in ET.parse(sys.argv[1]).getroot().findall("a:entry", ns):
    p = e.find("m:properties", ns)
    rows.append("%s|%s" % (p.findtext("d:Version", "", ns), p.findtext("d:Description", "", ns)))
print("\n".join(sorted(rows)))
PY
}
mkrepo() {
  local st; st="$(send POST /api/v1/repositories "$1")"
  ok2xx "$st" || err+="create $(echo "$1" | jq -r .key) -> ${st} $(head -c 160 "$WORK/send.out"); "
}
remote() { mkrepo "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"nuget\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"$2\"}"; }

begin_suite "nuget-protocol-translation (#4122 #4021 #3870)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: V2, V3 and V3-down remotes, a hosted package, a virtual over hosted + V2"
auth_admin
err=""
remote "$N2" "${MOCK}/nuget/v2/api/v2"
remote "$N3" "${MOCK}/nuget/v3/index.json"
remote "$N3D" "${MOCK}/nuget/v3down/index.json"
mkrepo "{\"key\":\"${NH}\",\"name\":\"${NH}\",\"format\":\"nuget\",\"repo_type\":\"local\",\"is_public\":true}"
mkrepo "{\"key\":\"${NVV}\",\"name\":\"${NVV}\",\"format\":\"nuget\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[{\"repo_key\":\"${NH}\",\"priority\":1},{\"repo_key\":\"${N2}\",\"priority\":2}]}"
python3 -I - "$WORK/shared.nupkg" "$ID_SHARED" <<'PY'
import sys, zipfile
out, pid = sys.argv[1], sys.argv[2]
nuspec = ('<?xml version="1.0" encoding="utf-8"?>\n'
          '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>'
          f'<id>{pid}</id><version>1.0.0</version><authors>dtf</authors>'
          '<description>dtf-hosted</description></metadata></package>\n')
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr(f"{pid}.nuspec", nuspec)
    z.writestr("lib/net8.0/placeholder.txt", f"dtf-hosted {pid}\n")
PY
st="$(curl -s --max-time 60 -o "$WORK/push.out" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -F "package=@$WORK/shared.nupkg;type=application/octet-stream" \
  "${BASE_URL}/nuget/${NH}/api/v2/package" 2>/dev/null || echo 000)"
ok2xx "$st" || err+="push ${ID_SHARED} -> ${st} $(head -c 160 "$WORK/push.out"); "
if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass

# =============================================================================
# A. #4122: a V2 upstream answers the V3 surface
# =============================================================================
begin_test "FIX #4122: a remote over a V2 feed answers the V3 registration index from FindPackagesById(), URLs on AK"
st="$(get "/nuget/${N2}/v3/registration/${ID_V2}/index.json" "$WORK/n2reg.json")"
if [ "$st" = "200" ] \
   && jq -e --arg p "${BASE_URL}/nuget/${N2}/v3/flatcontainer/" \
        '[.items[].items[].catalogEntry.version] == ["1.0.0","2.0.0"]
         and all(.items[].items[]; .packageContent | startswith($p))' "$WORK/n2reg.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}; want 200 with leaves 1.0.0, 2.0.0 whose packageContent is under ${BASE_URL}/nuget/${N2}/v3/flatcontainer/" \
    "$(head -c 400 "$WORK/n2reg.json")"
fi

begin_test "FIX #4122: the V3 flat-container download through the V2-upstream remote serves the V2 package bytes"
st="$(get "/nuget/${N2}/v3/flatcontainer/${ID_V2}/1.0.0/${ID_V2}.1.0.0.nupkg" "$WORK/n2.nupkg")"
mock_bytes "/nuget/v2/api/v2/package/${ID_V2}/1.0.0" "$WORK/mock-v2.nupkg"
if [ "$st" = "200" ] && [ -s "$WORK/mock-v2.nupkg" ] && cmp -s "$WORK/n2.nupkg" "$WORK/mock-v2.nupkg"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/n2.nupkg") bytes; want the V2 feed's $(wc -c < "$WORK/mock-v2.nupkg") bytes" "$(head -c 200 "$WORK/n2.nupkg")"
fi

begin_test "CONTROL: a registration PAGE through a V2-upstream remote is 404 (a V2 feed links no pages), not 5xx"
st="$(get "/nuget/${N2}/v3/registration/${ID_V2}/page/1.0.0/2.0.0.json" "$WORK/n2page.json")"
if [ "$st" = "404" ]; then
  pass
else
  fail "HTTP ${st}, want 404" "$(head -c 200 "$WORK/n2page.json")"
fi

# =============================================================================
# B. #4122: a V3 upstream answers the V2 surface
# =============================================================================
begin_test "CONTROL: the V3-upstream remote serves the V3 flat-container version list"
st="$(get "/nuget/${N3}/v3/flatcontainer/${ID_V3}/index.json" "$WORK/n3flat.json")"
if [ "$st" = "200" ] && jq -e '.versions == ["1.0.0","2.0.0"]' "$WORK/n3flat.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}, want versions [1.0.0, 2.0.0]" "$(head -c 200 "$WORK/n3flat.json")"
fi

begin_test "FIX #4122: a remote over a V3 feed answers V2 FindPackagesById() with entries whose content src is on AK"
st="$(get "/nuget/${N3}/v2/FindPackagesById()?id='${ID_V3}'" "$WORK/n3v2.xml")"
rows="$(feed_rows "$WORK/n3v2.xml" | cut -d'|' -f1 | tr '\n' ' ')"
if [ "$st" = "200" ] && [ "$rows" = "1.0.0 2.0.0 " ] \
   && grep -q "src=\"${BASE_URL}/nuget/${N3}/v2/package/${ID_V3}/1.0.0\"" "$WORK/n3v2.xml"; then
  pass
else
  fail "HTTP ${st}, versions '${rows}'; want 1.0.0 2.0.0 with src on ${BASE_URL}/nuget/${N3}/v2/package/" "$(head -c 400 "$WORK/n3v2.xml")"
fi

begin_test "FIX #4122: the V2 package download through the V3-upstream remote serves the flat-container bytes"
st="$(get "/nuget/${N3}/v2/package/${ID_V3}/1.0.0" "$WORK/n3.nupkg")"
mock_bytes "/nuget/v3/flat/${ID_V3}/1.0.0/${ID_V3}.1.0.0.nupkg" "$WORK/mock-v3.nupkg"
if [ "$st" = "200" ] && [ -s "$WORK/mock-v3.nupkg" ] && cmp -s "$WORK/n3.nupkg" "$WORK/mock-v3.nupkg"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/n3.nupkg") bytes; want the V3 feed's $(wc -c < "$WORK/mock-v3.nupkg") bytes" "$(head -c 200 "$WORK/n3.nupkg")"
fi

begin_test "CONTROL: a V3 upstream in an outage answers the V3 registration with a 5xx, never a V2-fallback 404"
st="$(get "/nuget/${N3D}/v3/registration/${ID_V3}/index.json" "$WORK/n3d.json")"
if [ "$st" -ge 500 ] 2>/dev/null && [ "$st" -lt 600 ]; then
  pass
else
  fail "HTTP ${st}, want 5xx" "$(head -c 200 "$WORK/n3d.json")"
fi

# =============================================================================
# C. #3870: paged registrations, 3.6.0, autocomplete
# =============================================================================
begin_test "FIX #3870: the service index advertises RegistrationsBaseUrl/3.6.0 and a SearchAutocompleteService"
st="$(get "/nuget/${N3}/v3/index.json" "$WORK/n3idx.json")"
if [ "$st" = "200" ] && jq -e --arg b "${BASE_URL}/nuget/${N3}/v3/" \
     '[.resources[] | select(.["@type"] == "RegistrationsBaseUrl/3.6.0") | .["@id"] | startswith($b)] == [true]
      and any(.resources[]; .["@type"] == "SearchAutocompleteService" and (.["@id"] | startswith($b)))' \
     "$WORK/n3idx.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}; want RegistrationsBaseUrl/3.6.0 and SearchAutocompleteService under ${BASE_URL}/nuget/${N3}/v3/" \
    "$(jq -c '[.resources[]["@type"]]' "$WORK/n3idx.json" 2>/dev/null)"
fi

begin_test "CONTROL: the remote's paged registration index is served with its page link rewritten onto AK"
st="$(get "/nuget/${N3}/v3/registration/${ID_V3}/index.json" "$WORK/n3reg.json")"
PAGE="$(jq -r '.items[0]["@id"] // empty' "$WORK/n3reg.json" 2>/dev/null)"
want_page="${BASE_URL}/nuget/${N3}/v3/registration/${ID_V3}/page/1.0.0/2.0.0.json"
if [ "$st" = "200" ] && [ "$PAGE" = "$want_page" ]; then
  pass
else
  fail "HTTP ${st}, page @id '${PAGE}', want '${want_page}'" "$(head -c 300 "$WORK/n3reg.json")"
fi

begin_test "FIX #3870: the linked registration page is proxied (200) with its leaves rewritten onto AK"
st="$(get "/nuget/${N3}/v3/registration/${ID_V3}/page/1.0.0/2.0.0.json" "$WORK/n3page.json")"
if [ "$st" = "200" ] && jq -e --arg f "${BASE_URL}/nuget/${N3}/v3/flatcontainer/" \
     '[.items[].catalogEntry.version] == ["1.0.0","2.0.0"] and all(.items[]; .packageContent | startswith($f))' \
     "$WORK/n3page.json" >/dev/null 2>&1 && ! grep -q "172.16.${SLOT}.91" "$WORK/n3page.json"; then
  pass
else
  fail "HTTP ${st}; want 200 with leaves 1.0.0, 2.0.0 on ${BASE_URL}/nuget/${N3}/v3/flatcontainer/ and no upstream host" \
    "$(head -c 400 "$WORK/n3page.json")"
fi

begin_test "FIX #3870: autocomplete through the remote answers the upstream's ids"
st="$(get "/nuget/${N3}/v3/autocomplete?q=dtfac" "$WORK/n3ac.json")"
if [ "$st" = "200" ] && jq -e '.data | index("dtfnu-auto-dtfac") != null' "$WORK/n3ac.json" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${st}; want data to contain dtfnu-auto-dtfac" "$(head -c 300 "$WORK/n3ac.json")"
fi

# =============================================================================
# D. #4021: a virtual's V2 feed answers from its remote member too
# =============================================================================
begin_test "CONTROL: the hosted member's V2 feed lists its pushed package"
st="$(get "/nuget/${NH}/v2/FindPackagesById()?id='${ID_SHARED}'" "$WORK/nh.xml")"
rows="$(feed_rows "$WORK/nh.xml" | tr '\n' ' ')"
if [ "$st" = "200" ] && [ "$rows" = "1.0.0|dtf-hosted " ]; then
  pass
else
  fail "HTTP ${st}, rows '${rows}', want '1.0.0|dtf-hosted'" "$(head -c 300 "$WORK/nh.xml")"
fi

begin_test "FIX #4021: the virtual's V2 FindPackagesById() lists a package only its remote member has"
st="$(get "/nuget/${NVV}/v2/FindPackagesById()?id='${ID_REMOTE}'" "$WORK/nvvr.xml")"
rows="$(feed_rows "$WORK/nvvr.xml" | tr '\n' ' ')"
if [ "$st" = "200" ] && [ "$rows" = "1.0.0|dtf-upstream-v2 2.0.0|dtf-upstream-v2 " ] \
   && grep -q "src=\"${BASE_URL}/nuget/${NVV}/v2/package/${ID_REMOTE}/1.0.0\"" "$WORK/nvvr.xml"; then
  pass
else
  fail "HTTP ${st}, rows '${rows}'; want the remote's 1.0.0 and 2.0.0 with src on the virtual" "$(head -c 400 "$WORK/nvvr.xml")"
fi

begin_test "FIX #4021: on a shared coordinate the hosted copy wins, and the remote adds its other version"
st="$(get "/nuget/${NVV}/v2/FindPackagesById()?id='${ID_SHARED}'" "$WORK/nvvs.xml")"
rows="$(feed_rows "$WORK/nvvs.xml" | tr '\n' ' ')"
if [ "$st" = "200" ] && [ "$rows" = "1.0.0|dtf-hosted 2.0.0|dtf-upstream-v2 " ]; then
  pass
else
  fail "HTTP ${st}, rows '${rows}'; want '1.0.0|dtf-hosted 2.0.0|dtf-upstream-v2'" "$(head -c 400 "$WORK/nvvs.xml")"
fi

begin_test "FIX #4021: a V2 download through the virtual serves the remote member's package"
st="$(get "/nuget/${NVV}/v2/package/${ID_REMOTE}/1.0.0" "$WORK/nvvr.nupkg")"
mock_bytes "/nuget/v2/api/v2/package/${ID_REMOTE}/1.0.0" "$WORK/mock-r.nupkg"
if [ "$st" = "200" ] && [ -s "$WORK/mock-r.nupkg" ] && cmp -s "$WORK/nvvr.nupkg" "$WORK/mock-r.nupkg"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/nvvr.nupkg") bytes; want the remote's $(wc -c < "$WORK/mock-r.nupkg") bytes" "$(head -c 200 "$WORK/nvvr.nupkg")"
fi

begin_test "CONTROL: a V2 download of the shared coordinate through the virtual serves the hosted bytes"
st="$(get "/nuget/${NVV}/v2/package/${ID_SHARED}/1.0.0" "$WORK/nvvs.nupkg")"
if [ "$st" = "200" ] && cmp -s "$WORK/nvvs.nupkg" "$WORK/shared.nupkg"; then
  pass
else
  fail "HTTP ${st}, $(wc -c < "$WORK/nvvs.nupkg") bytes; want the pushed $(wc -c < "$WORK/shared.nupkg") bytes" "$(head -c 200 "$WORK/nvvs.nupkg")"
fi

end_suite
