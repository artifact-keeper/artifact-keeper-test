#!/usr/bin/env bash
# =============================================================================
# tiers/deps-1.12.0-controls/oracle.sh
#   Regression controls for the dependency bumps merged for 1.12.0:
#     #4375 quick-xml 0.41 -> 0.42 (seven XML readers adapted)
#     #4377 tower-http 0.6 -> 0.7.1 (CORS, trace, compression)
#     #4811 OpenTelemetry 0.33 / tracing-opentelemetry 0.34
#   Most cases must hold on the release before the bumps AND on main. Two
#   cases pin a deliberate upstream behaviour change and are RED on 1.11.3.
# See the manifest for the reach of each case and what is not covered.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the sink's published control port), DTF_DIR, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SINK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the sink at (profiles/telemetry.otlp-sink.yml).
SINK_IN="http://172.16.${DTF_SLOT}.71"
DTF_NET="ak-dtf${DTF_SLOT}-net"
MC_IMAGE="ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z"   # pulled by storage.s3
SAML_PROBE="${DTF_SAML_XSW_PROBE:-${DTF_DIR}/harness/tiers/sso/probe/target/release/dtf-saml-xsw-probe}"
CORS_ALLOWED="http://dtf-cors-allowed.example"                                 # profiles/http.cors-origins.yml

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# api <METHOD> <PATH> [JSON] -> sets API_CODE / API_BODY
api(){
  local method="$1" path="$2" body="${3:-}"
  rm -f "$W/api.out"
  if [ -n "$body" ]; then
    API_CODE="$(curl -s --max-time 60 -o "$W/api.out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$body" "${BASE}${path}")"
  else
    API_CODE="$(curl -s --max-time 60 -o "$W/api.out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $TOK" "${BASE}${path}")"
  fi
  API_BODY="$(cat "$W/api.out" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format> <type> [upstream] [public]
  local body
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" --arg p "${5:-false}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:($p=="true")} + (if $u == "" then {} else {upstream_url:$u} end)')"
  api POST /api/v1/repositories "$body"
  [ "$(printf '%s' "$API_BODY" | jqr '.key // empty')" = "$1" ]
}
# sink_fx <path> <file> <content-type>: the sink serves <file> at GET <path>.
sink_fx(){ curl -s --max-time 10 -X PUT -H "X-Fx-Content-Type: $3" --data-binary "@$2" "${SINK}/__fx$1" | jqr '.stored // empty'; }
sink_grep(){ curl -s --max-time 5 "${SINK}/__grep?needle=$1" | jqr '.hits // empty'; }
sink_mode(){ curl -s --max-time 5 -X POST "${SINK}/__mode?status=$1" | jqr '.mode // empty'; }
# wait_hits <needle> <min> <secs>: poll until the sink holds >= min bodies containing needle.
wait_hits(){
  local _i h=""
  for _i in $(seq 1 $(( $3 * 2 ))); do
    h="$(sink_grep "$1")"
    [ -n "$h" ] && [ "$h" -ge "$2" ] 2>/dev/null && break
    sleep 0.5
  done
  echo "${h:-0}"
}

# =============================================================================
begin_suite "deps-1.12.0-controls"

begin_test "setup: admin login, sink reachable, per-run names"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${SINK}/__readyz" || true)" != "ok" ]; then
  infra_fail "OTLP sink not reachable on ${SINK} (profiles/telemetry.otlp-sink.yml)"; end_suite
fi
sink_mode 200 >/dev/null
SUF="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd 'a-z0-9')"
echo "-- suffix ${SUF}, sink ${SINK} (backend side ${SINK_IN})"
pass

# =============================================================================
# quick-xml 0.42 (#4375). Every input carries entities, numeric references,
# non-ASCII text and, where the format allows it, a UTF-8 BOM and CDATA.
# =============================================================================

# --- NuGet: V2 OData upstream translated onto the V3 surface ----------------
begin_test "#4375 quick-xml / NuGet: a V2 upstream feed with entities, char refs and a BOM is projected onto V3 registration and search"
reset_case
NU_PATH="/nugetv2-${SUF}"
NU_ID="DtfXml.Pkg${SUF}"
NU_ID_LC="$(printf '%s' "$NU_ID" | tr '[:upper:]' '[:lower:]')"
python3 - "$NU_ID" > "$W/feed.xml" <<'PY'
import sys
pid = sys.argv[1]
def entry(ver):
    return (f"<entry><id>http://up/Packages(Id='{pid}',Version='{ver}')</id><title type=\"text\">{pid}</title>"
            f'<content type="application/zip" src="http://up/package/{pid}/{ver}"/><m:properties>'
            f'<d:Id>{pid}</d:Id><d:Version>{ver}</d:Version>'
            '<d:Authors>Renée &amp; J&#xF6;rg</d:Authors>'
            '<d:Description>Fish &amp; chips &lt;b&gt;caf&#233;&lt;/b&gt; über</d:Description>'
            '<d:PackageHash>AAAA</d:PackageHash><d:PackageSize>1234</d:PackageSize></m:properties></entry>')
doc = ('﻿<?xml version="1.0" encoding="utf-8"?><feed xml:base="http://up/" xmlns="http://www.w3.org/2005/Atom" '
       'xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" '
       'xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">'
       '<title type="text">Packages</title>' + entry("1.0.0") + entry("2.0.0-beta") + '</feed>')
sys.stdout.buffer.write(doc.encode("utf-8"))
PY
R_NU="dtfdeps-nuv2-${SUF}"
if [ "$(sink_fx "${NU_PATH}/FindPackagesById()" "$W/feed.xml" 'application/atom+xml;type=feed;charset=utf-8')" != "true" ] \
   || [ "$(sink_fx "${NU_PATH}/Search()" "$W/feed.xml" 'application/atom+xml;type=feed;charset=utf-8')" != "true" ] \
   || ! mk_repo "$R_NU" nuget remote "${SINK_IN}${NU_PATH}"; then
  infra_fail "could not stage the V2 feed or create the NuGet remote (HTTP ${API_CODE}: ${API_BODY:0:200})"; end_suite
fi
api GET "/nuget/${R_NU}/v3/registration/${NU_ID_LC}/index.json"
REG="$API_BODY"
reg_versions="$(printf '%s' "$REG" | jqr '[.items[].items[]?.catalogEntry.version] | sort | join(",")')"
reg_id="$(printf '%s' "$REG" | jqr '[.items[].items[]?.catalogEntry.id] | unique | join(",")')"
reg_desc="$(printf '%s' "$REG" | jqr '.items[0].items[0].catalogEntry.description // empty')"
reg_auth="$(printf '%s' "$REG" | jqr '.items[0].items[0].catalogEntry.authors // empty')"
note "registration: HTTP ${API_CODE}, id=${reg_id}, versions=${reg_versions}, description=\"${reg_desc}\", authors=\"${reg_auth}\""
[ "$API_CODE" = "200" ] || fail_g "registration over the V2 upstream was HTTP ${API_CODE}"
[ "$reg_id" = "$NU_ID" ] || fail_g "registration id is \"${reg_id}\", expected ${NU_ID} (read through the BOM-prefixed feed)"
[ "$reg_versions" = "1.0.0,2.0.0-beta" ] || fail_g "registration versions are \"${reg_versions}\", expected 1.0.0,2.0.0-beta"
case "$reg_desc" in *"über") ;; *) fail_g "description \"${reg_desc}\" does not keep the non-ASCII text after the last reference";; esac
# artifact-keeper#4816 (fixed on main adfa0206): entity references in V2 feed
# text survive whole, with the text around them.
[ "$reg_desc" = "Fish & chips <b>café</b> über" ] \
  || fail_g "#4816: V2 description is \"${reg_desc}\", expected \"Fish & chips <b>café</b> über\" (entity references lost)"
[ "$reg_auth" = "Renée & Jörg" ] \
  || fail_g "#4816: V2 authors is \"${reg_auth}\", expected \"Renée & Jörg\" (entity references lost)"
api GET "/nuget/${R_NU}/v3/search?q=dtfxml&prerelease=true"
s_hit="$(printf '%s' "$API_BODY" | jq -r --arg id "$NU_ID" '[.data[] | select(.id == $id) | .version] | join(",")' 2>/dev/null || true)"
note "search: HTTP ${API_CODE}, ${NU_ID} -> ${s_hit}"
[ "$API_CODE" = "200" ] && [ "$s_hit" = "2.0.0-beta" ] || fail_g "V3 search over the V2 Search() feed did not return ${NU_ID} 2.0.0-beta (HTTP ${API_CODE}, got \"${s_hit}\")"
finish_case "NuGet V2-upstream projection broken: the V2 feed reader no longer reads ids/versions through entities and a BOM"

# --- PyPI XML-RPC ------------------------------------------------------------
begin_test "#4375 quick-xml / PyPI XML-RPC: browse decodes entities, char refs, CDATA and a BOM; unknown entities fault"
reset_case
R_PY="dtfdeps-pypi-${SUF}"
PY_MOD="dtf_xml_${SUF}"; PY_NAME="${PY_MOD//_/-}"
CLASSIFIER="$(printf 'Topic :: DTF :: Caf\xc3\xa9 & <Cr\xc3\xa8me> "Br\xc3\xbbl\xc3\xa9e" %s' "$SUF")"
python3 - "$PY_MOD" "1.0.0" "$W/w.whl" "$CLASSIFIER" <<'PY'
import base64, hashlib, sys, zipfile
module, version, out, *classifiers = sys.argv[1:]
di = f"{module}-{version}.dist-info"
md = ["Metadata-Version: 2.1", f"Name: {module}", f"Version: {version}", "Summary: dtf"] + [f"Classifier: {c}" for c in classifiers] + ["", ""]
files = {f"{module}/__init__.py": "", f"{di}/METADATA": "\n".join(md),
         f"{di}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
rec = []
with zipfile.ZipFile(out, "w") as zf:
    for n, t in files.items():
        d = t.encode(); zf.writestr(n, d)
        rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}")
    rec.append(f"{di}/RECORD,,"); zf.writestr(f"{di}/RECORD", "\n".join(rec) + "\n")
PY
mk_repo "$R_PY" pypi local "" true || { infra_fail "could not create ${R_PY}"; end_suite; }
up="$(curl -s -o "$W/up.out" -w '%{http_code}' -X POST "$BASE/pypi/${R_PY}/" -H "Authorization: Bearer $TOK" \
  -F ":action=file_upload" -F "protocol_version=1" -F "metadata_version=2.1" -F "name=${PY_MOD}" -F "version=1.0.0" \
  -F "filetype=bdist_wheel" -F "pyversion=py3" -F "sha256_digest=$(sha256sum "$W/w.whl" | awk '{print $1}')" \
  -F "classifiers=${CLASSIFIER}" -F "content=@$W/w.whl;filename=${PY_MOD}-1.0.0-py3-none-any.whl")"
[ "$up" = "200" ] || [ "$up" = "201" ] || { infra_fail "wheel upload was HTTP ${up}: $(head -c 200 "$W/up.out")"; end_suite; }
# rpc <label> <body> -> stdout: "pairs:<name==ver,...>" or "fault:<code>:<string>" or "malformed:..."
rpc(){
  printf '%s' "$2" > "$W/rpc.xml"
  curl -s --max-time 20 -X POST -H 'Content-Type: text/xml' --data-binary "@$W/rpc.xml" "$BASE/pypi/${R_PY}/pypi" > "$W/rpc.out" 2>/dev/null || true
  python3 - "$W/rpc.out" <<'PY'
import sys, xmlrpc.client
raw = open(sys.argv[1], "rb").read()
try:
    (res,), _ = xmlrpc.client.loads(raw)
except xmlrpc.client.Fault as f:
    print(f"fault:{f.faultCode}:{f.faultString}"); sys.exit(0)
except Exception as e:
    print(f"malformed:{e}:{raw[:120]!r}"); sys.exit(0)
if not res or isinstance(res[0], (list, tuple)):
    print("pairs:" + ",".join(f"{a}=={b}" for a, b in res))
else:
    print("list:" + ",".join(map(str, res)))
PY
}
browse_body(){ printf '<?xml version="1.0"?><methodCall><methodName>browse</methodName><params><param><value><array><data><value><string>%s</string></value></data></array></value></param></params></methodCall>' "$1"; }
ENT="Topic :: DTF :: Caf&#233; &amp; &lt;Cr&#xE8;me&gt; &quot;Br&#251;l&#233;e&quot; ${SUF}"
CDATA="<![CDATA[${CLASSIFIER}]]>"
r1="$(rpc ent "$(browse_body "$ENT")")"
r2="$(rpc bom "$(printf '\xef\xbb\xbf')$(browse_body "$CDATA" | sed 's/<?xml version="1.0"?>/<?xml version="1.0" encoding="UTF-8"?>/')")"
r3="$(rpc near "$(browse_body "Topic :: DTF :: Cafe &amp; &lt;Creme&gt; ${SUF}")")"
r4="$(rpc meth '<?xml version="1.0"?><methodCall><methodName>list_p&#97;ckages</methodName></methodCall>')"
r5="$(rpc bad "$(browse_body 'a&dtfcustom;b')")"
note "entities+char refs: ${r1}"
note "BOM+CDATA raw UTF-8: ${r2}"
note "near miss:           ${r3}"
note "method via char ref: ${r4}"
note "custom entity:       ${r5}"
[ "$r1" = "pairs:${PY_NAME}==1.0.0" ] || fail_g "browse with the classifier spelled in entities and char refs returned \"${r1}\", expected ${PY_NAME}==1.0.0"
[ "$r2" = "pairs:${PY_NAME}==1.0.0" ] || fail_g "browse with a BOM and the classifier in CDATA returned \"${r2}\""
[ "$r3" = "pairs:" ] || fail_g "a near-miss classifier matched (\"${r3}\"): the decoded string is not exact"
case "$r4" in list:*"${PY_NAME}"*) ;; *) fail_g "methodName list_p&#97;ckages did not resolve to list_packages (\"${r4}\")";; esac
case "$r5" in "fault:-32700:"*) ;; *) fail_g "an undeclared entity was not refused as a -32700 parse fault (\"${r5}\")";; esac
finish_case "PyPI XML-RPC parser broken: entity/CDATA/BOM decoding changed"

# --- VSIX package manifest -----------------------------------------------------
begin_test "#4375 quick-xml / VSIX: TargetPlatform and the pre-release property are read through char refs and entities in a BOM-prefixed manifest"
reset_case
R_VS="dtfdeps-vsix-${SUF}"
VS_PUB="dtfp${SUF}"
mk_repo "$R_VS" vscode local "" true || { infra_fail "could not create ${R_VS}"; end_suite; }
python3 - "$VS_PUB" dtfxml 1.2.3 "$W/good.vsix" "$W/bad.vsix" <<'PY'
import sys, zipfile
pub, name, ver, good, bad = sys.argv[1:6]
manifest = ('﻿<?xml version="1.0" encoding="utf-8"?>\n'
 '<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">\n'
 '  <Metadata>\n'
 f'    <Identity Language="en-US" Id="{name}" Version="{ver}" Publisher="{pub}" TargetPlatform="linux&#45;&#x78;64" />\n'
 '    <DisplayName>Café &amp; Crème</DisplayName>\n'
 '    <Description xml:space="preserve"><![CDATA[a <b>CDATA</b> & description]]></Description>\n'
 '    <Properties>\n'
 '      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.80.0" />\n'
 '      <Property Id="Microsoft.VisualStudio.Code.Pre&#82;elease" Value="&#116;rue" />\n'
 '    </Properties>\n'
 '  </Metadata>\n'
 '  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>\n'
 '  <Dependencies/>\n'
 '</PackageManifest>\n')
pkg = ('{"name":"%s","displayName":"Café & Crème","version":"%s","publisher":"%s",'
       '"engines":{"vscode":"^1.80.0"},"description":"d"}' % (name, ver, pub))
with zipfile.ZipFile(good, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("extension.vsixmanifest", manifest.encode("utf-8"))
    z.writestr("extension/package.json", pkg.encode("utf-8"))
with zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("extension.vsixmanifest", '<?xml version="1.0"?><PackageManifest Version="2.0.0"><Metadata><DisplayName>x &amp; y</DisplayName></Metadata></PackageManifest>')
    z.writestr("extension/package.json", ('{"name":"bad","version":"1.0.0","publisher":"%s","engines":{"vscode":"^1.80.0"}}' % pub))
PY
vs_up(){ curl -s --max-time 30 -o "$W/vs.out" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$1" "$BASE/vscode/${R_VS}/api/extensions"; }
c_good="$(vs_up "$W/good.vsix")"; b_good="$(head -c 200 "$W/vs.out")"
c_bad="$(vs_up "$W/bad.vsix")"; b_bad="$(head -c 200 "$W/vs.out")"
note "publish (entity manifest): HTTP ${c_good} ${b_good}"
note "publish (no <Identity>):   HTTP ${c_bad} ${b_bad}"
[ "$c_good" = "201" ] || fail_g "publishing the BOM/entity manifest was HTTP ${c_good}"
if [ "$c_bad" != "400" ] || ! printf '%s' "$b_bad" | grep -q 'no <Identity> element'; then
  fail_g "a manifest with no <Identity> was not refused as 400 'no <Identity> element' (HTTP ${c_bad})"
fi
GQ="$(jq -nc --arg v "${VS_PUB}.dtfxml" '{filters:[{criteria:[{filterType:7,value:$v}],pageNumber:1,pageSize:10}],flags:19}')"
curl -s --max-time 20 -X POST -H 'Content-Type: application/json' -d "$GQ" "$BASE/vscode/${R_VS}/gallery/extensionquery" > "$W/gq.json" || true
g_tp="$(jqr '.results[0].extensions[0].versions[0].targetPlatform // empty' < "$W/gq.json")"
g_pre="$(jqr '[.results[0].extensions[0].versions[0].properties[]? | select(.key=="Microsoft.VisualStudio.Code.PreRelease") | .value] | join(",")' < "$W/gq.json")"
g_dn="$(jqr '.results[0].extensions[0].displayName // empty' < "$W/gq.json")"
note "gallery: targetPlatform=${g_tp:-absent} PreRelease=${g_pre:-absent} displayName=${g_dn:-absent}"
[ "$g_tp" = "linux-x64" ] || fail_g "targetPlatform is \"${g_tp}\", expected linux-x64 from TargetPlatform=\"linux&#45;&#x78;64\""
[ "$g_pre" = "true" ] || fail_g "pre-release property is \"${g_pre}\", expected true from Id=\"...Pre&#82;elease\" Value=\"&#116;rue\""
[ "$g_dn" = "Café & Crème" ] || fail_g "displayName is \"${g_dn}\""
finish_case "VSIX manifest reader broken: char refs / entities in attributes no longer decode"

# --- Curation: RPM repodata primary.xml ------------------------------------------
begin_test "#4375 quick-xml / curation RPM: a sync parses a BOM/entity/CDATA primary.xml, drops a custom-entity package and applies a block rule"
reset_case
RPM_PATH="/rpmup-${SUF}"
python3 - "$W" <<'PY'
import gzip, hashlib, sys
out = sys.argv[1]
def pkg(name, summary, desc):
    return (f'<package type="rpm"><name>{name}</name><arch>x86_64</arch><version epoch="0" ver="1.0" rel="1.el9"/>'
            f'<checksum type="sha256" pkgid="YES">{hashlib.sha256(name.encode()).hexdigest()}</checksum>'
            f'<summary>{summary}</summary><description>{desc}</description>'
            '<packager>Renée &lt;renee@example.test&gt;</packager><url>https://example.test/?a=1&amp;b=2</url>'
            '<time file="1700000000" build="1699999999"/><size package="1024" installed="4096" archive="4100"/>'
            f'<location href="Packages/{name}-1.0-1.el9.x86_64.rpm"/>'
            '<format><rpm:license>MIT &amp; BSD</rpm:license><rpm:vendor>V&#xE9;ndor</rpm:vendor>'
            '<rpm:group>Unspecified</rpm:group><rpm:buildhost>b</rpm:buildhost>'
            f'<rpm:sourcerpm>{name}-1.0-1.el9.src.rpm</rpm:sourcerpm><rpm:header-range start="4504" end="5000"/>'
            f'<rpm:provides><rpm:entry name="{name}" flags="EQ" epoch="0" ver="1.0" rel="1.el9"/></rpm:provides>'
            '<rpm:requires><rpm:entry name="lib&amp;c" flags="GE" ver="2.34"/></rpm:requires></format></package>')
pkgs = [pkg("dtf-ent", "Fish &amp; chips &lt;b&gt;caf&#233;&lt;/b&gt; &#x00FC;ber",
            "<![CDATA[raw <tag> & stuff]]> tail été"),
        pkg("dtf-plain", "Plain summary", "Plain description"),
        pkg("dtf-badent", "custom &dtfcustom; entity", "d")]
xml = ('﻿<?xml version="1.0" encoding="UTF-8"?>\n<metadata xmlns="http://linux.duke.edu/metadata/common" '
       'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="%d">' % len(pkgs) + "".join(pkgs) + '</metadata>')
raw = xml.encode("utf-8"); gz = gzip.compress(raw, mtime=0)
open(out + "/primary.xml.gz", "wb").write(gz)
open(out + "/repomd.xml", "w").write(
    '<?xml version="1.0" encoding="UTF-8"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>'
    f'<data type="primary"><checksum type="sha256">{hashlib.sha256(gz).hexdigest()}</checksum>'
    f'<open-checksum type="sha256">{hashlib.sha256(raw).hexdigest()}</open-checksum>'
    '<location href="repodata/primary.xml.gz"/></data></repomd>')
PY
R_RUP="dtfdeps-rpmup-${SUF}"; R_RST="dtfdeps-rpmst-${SUF}"
if [ "$(sink_fx "${RPM_PATH}/repodata/repomd.xml" "$W/repomd.xml" text/xml)" != "true" ] \
   || [ "$(sink_fx "${RPM_PATH}/repodata/primary.xml.gz" "$W/primary.xml.gz" application/gzip)" != "true" ] \
   || ! mk_repo "$R_RUP" rpm remote "${SINK_IN}${RPM_PATH}" || ! mk_repo "$R_RST" rpm staging; then
  infra_fail "could not stage repodata or create the RPM remote/staging repos (HTTP ${API_CODE}: ${API_BODY:0:200})"; end_suite
fi
# Curation wiring is DB-side (as tiers/rpm-p3-curation seeds it): the staging
# repo curates the remote, and opts into unverified ingest (no GPG key here).
psql_q "UPDATE repositories SET curation_enabled=true, curation_allow_unverified=true,
          curation_source_repo_id=(SELECT id FROM repositories WHERE key='${R_RUP}') WHERE key='${R_RST}'" >/dev/null
RST_ID="$(psql_q "SELECT id FROM repositories WHERE key='${R_RST}'" | tr -d '[:space:]')"
api POST /api/v1/curation/rules "$(jq -nc --arg s "$RST_ID" '{staging_repo_id:$s,package_pattern:"dtf-plain",version_constraint:"*",architecture:"*",action:"block",priority:10,reason:"dtf block rule",rule_type:"pattern",config:{}}')"
[ "$API_CODE" = "200" ] || [ "$API_CODE" = "201" ] || { infra_fail "could not create the block rule (HTTP ${API_CODE}: ${API_BODY:0:200})"; end_suite; }
api POST "/api/v1/curation/repos/${R_RST}/sync"
note "sync: HTTP ${API_CODE} ${API_BODY}"
[ "$(printf '%s' "$API_BODY" | jqr '.succeeded')" = "true" ] || fail_g "the curation sync did not succeed (HTTP ${API_CODE})"
row(){ psql_q "SELECT $2 FROM curation_packages WHERE staging_repo_id='${RST_ID}' AND package_name='$1'"; }
names="$(psql_q "SELECT string_agg(package_name, ',' ORDER BY package_name) FROM curation_packages WHERE staging_repo_id='${RST_ID}'" | tr -d '[:space:]')"
note "ingested: ${names}"
[ "$names" = "dtf-ent,dtf-plain" ] || fail_g "ingested packages are \"${names}\", expected dtf-ent,dtf-plain (dtf-badent carries a custom entity and must be dropped)"
chk(){ # <label> <sql expr> <expected>
  local got; got="$(row dtf-ent "$2")"
  [ "$got" = "$3" ] || fail_g "dtf-ent $1 is \"${got}\", expected \"$3\""
}
chk summary "primary_metadata->>'summary'" "Fish & chips <b>café</b> über"
chk description "primary_metadata->>'description'" "raw <tag> & stuff tail été"
chk packager "primary_metadata->>'packager'" "Renée <renee@example.test>"
chk url "primary_metadata->>'url'" "https://example.test/?a=1&b=2"
chk license "primary_metadata->'format'->>'license'" "MIT & BSD"
chk vendor "primary_metadata->'format'->>'vendor'" "Véndor"
chk requires "primary_metadata->'format'->'requires'->0->>'name'" "lib&c"
st_ent="$(row dtf-ent status | tr -d '[:space:]')"; st_plain="$(row dtf-plain status | tr -d '[:space:]')"
note "status: dtf-ent=${st_ent} dtf-plain=${st_plain}"
[ "$st_plain" = "blocked" ] || fail_g "the block rule did not block dtf-plain (status ${st_plain})"
[ "$st_ent" = "approved" ] || fail_g "dtf-ent is ${st_ent}, expected approved by the default allow"
finish_case "curation RPM primary.xml reader broken: entity/CDATA/BOM decoding or custom-entity fail-closed changed"

# --- SAML Response parser ----------------------------------------------------------
begin_test "#4375 quick-xml / SAML: the ACS parses a BOM-prefixed Response (status message echoed) and a signed assertion with a non-ASCII NameID"
reset_case
if [ ! -x "$SAML_PROBE" ]; then
  infra_fail "no SAML signer at ${SAML_PROBE} (the sso tier's dtf-saml-xsw-probe; the release gate's build-dtf-probes job provides it, or set DTF_SAML_XSW_PROBE)"
  end_suite
fi
"$SAML_PROBE" keygen "$W" >/dev/null 2>&1 || { infra_fail "probe keygen failed"; end_suite; }
SAML_ISS="https://idp.dtf-deps.test/${SUF}"
api POST /api/v1/admin/sso/saml "$(jq -nc --arg n "dtfdeps-saml-${SUF}" --arg e "$SAML_ISS" --arg c "$(cat "$W/idp_cert.pem")" \
  '{name:$n, entity_id:$e, sso_url:"https://idp.dtf-deps.test/sso", certificate:$c, sp_entity_id:"artifact-keeper",
    sign_requests:false, require_signed_assertions:true, admin_group:"dtf-never", is_enabled:true}')"
PID="$(printf '%s' "$API_BODY" | jqr '.id // empty')"
[ -n "$PID" ] || { infra_fail "could not create the SAML provider (HTTP ${API_CODE}: ${API_BODY:0:200})"; end_suite; }
# (a) Unsigned, non-Success: the parser runs before any signature check and
# the StatusMessage it read is the 401 message.
STATUS_MSG="$(printf 'IdP says: caf\xc3\xa9 \xc3\xbcber %s' "$SUF")"
printf '\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r%s" Version="2.0"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/><samlp:StatusMessage>%s</samlp:StatusMessage></samlp:Status></samlp:Response>' \
  "$SUF" "$SAML_ISS" "$STATUS_MSG" > "$W/status.xml"
code="$(curl -s -o "$W/acs1.out" -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "SAMLResponse=$(base64 -w0 < "$W/status.xml")" "$BASE/api/v1/auth/sso/saml/${PID}/acs")"
msg="$(jqr '.message // empty' < "$W/acs1.out")"
note "non-Success response: HTTP ${code}, message \"${msg}\""
[ "$code" = "401" ] && [ "$msg" = "$STATUS_MSG" ] || fail_g "the StatusMessage was not parsed back exactly (HTTP ${code}, \"${msg}\" != \"${STATUS_MSG}\")"
# (b) A signed positive assertion whose NameID is non-ASCII.
LOC="$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/api/v1/auth/sso/saml/${PID}/login")"
RID="$(python3 - "$LOC" <<'PY'
import sys, urllib.parse, base64, re, zlib
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
raw = base64.b64decode(q['SAMLRequest'][0])
if not raw.lstrip().startswith(b'<'):
    raw = zlib.decompress(raw, -15)
m = re.search(r'ID="([^"]+)"', raw.decode("utf-8", "replace"))
print(m.group(1) if m else "")
PY
)"
NAMEID="$(printf 'dtf-saml-%s-caf\xc3\xa9-\xc3\xbcber' "$SUF")"
B64="$("$SAML_PROBE" craft --key "$W/idp_key.pem" --case positive --issuer "$SAML_ISS" --audience artifact-keeper \
  --request-id "$RID" --name-id "$NAMEID" --groups "Caf$(printf '\xc3\xa9')-${SUF}" 2>/dev/null || true)"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "SAMLResponse=${B64}" "$BASE/api/v1/auth/sso/saml/${PID}/acs")"
urow="$(psql_q "SELECT username || '|' || email FROM users WHERE auth_provider='saml' AND external_id='${NAMEID}'")"
note "signed assertion: HTTP ${code}, user row \"${urow}\""
[ -n "$RID" ] && [ -n "$B64" ] || fail_g "could not obtain an AuthnRequest ID or craft the signed response"
[ "$code" = "302" ] || [ "$code" = "303" ] || [ "$code" = "307" ] || fail_g "the signed assertion was not accepted (HTTP ${code})"
[ "$urow" = "${NAMEID}|${NAMEID}@saml-e2e.test" ] || fail_g "no SAML user provisioned under the exact non-ASCII NameID (row \"${urow}\")"
finish_case "SAML Response parser broken: non-ASCII text or a BOM no longer parses"

# --- S3 ListObjectsV2 (REST fallback, S3_PROVIDER=oss) -------------------------------
begin_test "#4375 quick-xml / S3 listing: a storage reindex dry run lists keys with & and ' through the ListObjectsV2 XML parser"
reset_case
R_MV="dtfdeps-mvs3-${SUF}"; R_MVU="dtfdeps-mvs3u-${SUF}"
mk_repo "$R_MV" maven local || { infra_fail "could not create ${R_MV}"; end_suite; }
mk_repo "$R_MVU" maven local || { infra_fail "could not create ${R_MVU}"; end_suite; }
printf 'dtf deps jar %s\n' "$SUF" > "$W/a.jar"
mvput(){ curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/a.jar" "$BASE/maven/$1/$2"; }
c1="$(mvput "$R_MV" "com/dtf/plain/1.0/plain-1.0.jar")"
c2="$(mvput "$R_MV" "com/dtf/amp/1.0/amp-1.0-r%26d.jar")"
c3="$(mvput "$R_MVU" "com/dtf/uni/1.0/uni-1.0-caf%C3%A9.jar")"
[ "$c1$c2$c3" = "201201201" ] || { infra_fail "maven uploads were ${c1}/${c2}/${c3}"; end_suite; }
MV_ID="$(psql_q "SELECT id FROM repositories WHERE key='${R_MV}'" | tr -d '[:space:]')"
# A row-less object written straight to MinIO: a ghost whose key carries & and '.
GHOST_KEY="maven/${MV_ID}/com/dtf/ghost/1.0/ghost-1.0-o'r&d.jar"
# The MinIO root credentials are read from the minio container the storage.s3
# profile started, not repeated here.
MINIO_ENV="$(docker inspect "ak-dtf${DTF_SLOT}-minio" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || true)"
MINIO_USER="$(printf '%s\n' "$MINIO_ENV" | sed -n 's/^MINIO_ROOT_USER=//p')"
MINIO_PASS="$(printf '%s\n' "$MINIO_ENV" | sed -n 's/^MINIO_ROOT_PASSWORD=//p')"
docker run --rm -i --network "$DTF_NET" -e "MC_U=${MINIO_USER}" -e "MC_P=${MINIO_PASS}" -e "GHOST_KEY=${GHOST_KEY}" \
  --entrypoint sh "$MC_IMAGE" -c \
  'mc alias set l http://minio:9000 "$MC_U" "$MC_P" >/dev/null && mc pipe "l/ak-artifacts/${GHOST_KEY}" >/dev/null' < "$W/a.jar" \
  || { infra_fail "could not write the ghost object to MinIO"; end_suite; }
api POST "/api/v1/admin/repositories/${R_MV}/reindex-storage" '{"dry_run":true}'
RX="$API_BODY"
note "reindex ${R_MV}: HTTP ${API_CODE} ${RX}"
rx(){ printf '%s' "$RX" | jqr "$1"; }
[ "$API_CODE" = "200" ] || fail_g "reindex dry run was HTTP ${API_CODE}"
[ "$(rx .scanned)" = "3" ] || fail_g "scanned $(rx .scanned) objects, expected 3 (two rows plus the ghost)"
[ "$(rx .skipped)" = "2" ] || fail_g "skipped $(rx .skipped), expected 2: both rows' objects, including amp-1.0-r&d.jar, must match their rows"
[ "$(rx .missing_objects)" = "0" ] || fail_g "missing_objects $(rx .missing_objects) ($(rx '.missing_object_paths|join(",")')): a listed key did not decode back to its row path"
[ "$(rx .skipped_recent)" = "1" ] || fail_g "skipped_recent $(rx .skipped_recent), expected 1 (the ghost, written seconds ago)"
[ "$(rx .skipped_unknown_age)" = "0" ] || fail_g "skipped_unknown_age $(rx .skipped_unknown_age): <LastModified> did not parse"
api POST "/api/v1/admin/repositories/${R_MVU}/reindex-storage" '{"dry_run":true}'
umiss="$(printf '%s' "$API_BODY" | jqr '.missing_object_paths | join(",")')"
note "reindex ${R_MVU}: HTTP ${API_CODE} ${API_BODY}"
# artifact-keeper#4817 (fixed on main adfa0206): a non-ASCII path's
# percent-encoded object key decodes back to its row.
[ "$API_CODE" = "200" ] && [ "$(printf '%s' "$API_BODY" | jqr .missing_objects)" = "0" ] \
  || fail_g "#4817: reindex of ${R_MVU} reports a non-ASCII row missing on S3 (HTTP ${API_CODE}, missing=[${umiss}])"
finish_case "S3 ListObjectsV2 parser broken: keys with entities or <LastModified> no longer parse"

# =============================================================================
# tower-http 0.7.1 (#4377)
# =============================================================================
begin_test "#4377 tower-http / CORS: a preflight from the configured origin is allowed with the configured lists; another origin gets no allow-origin"
reset_case
pre(){ curl -s --max-time 10 -D - -o /dev/null -X OPTIONS -H "Origin: $1" -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: authorization,content-type' "$BASE/api/v1/repositories" | tr -d '\r'; }
H1="$(pre "$CORS_ALLOWED")"; H2="$(pre "http://dtf-cors-denied.example")"
hv(){ printf '%s\n' "$1" | grep -i "^$2:" | head -1 | cut -d: -f2- | sed 's/^ *//'; }
note "allowed: $(printf '%s' "$H1" | head -1); acao=$(hv "$H1" access-control-allow-origin); methods=$(hv "$H1" access-control-allow-methods); vary=$(hv "$H1" vary)"
note "denied:  $(printf '%s' "$H2" | head -1); acao=$(hv "$H2" access-control-allow-origin)"
[ "$(hv "$H1" access-control-allow-origin)" = "$CORS_ALLOWED" ] || fail_g "preflight from ${CORS_ALLOWED} did not echo it in Access-Control-Allow-Origin"
case ",$(hv "$H1" access-control-allow-methods)," in *,PUT,*) ;; *) fail_g "allow-methods lacks PUT";; esac
case ",$(hv "$H1" access-control-allow-headers | tr -d ' ')," in *,authorization,*) ;; *) fail_g "allow-headers lacks authorization";; esac
case "$(hv "$H1" vary | tr '[:upper:]' '[:lower:]')" in *origin*) ;; *) fail_g "preflight Vary lacks origin";; esac
[ -z "$(hv "$H2" access-control-allow-origin)" ] || fail_g "a preflight from an unlisted origin got Access-Control-Allow-Origin $(hv "$H2" access-control-allow-origin)"
HS="$(curl -s --max-time 10 -D - -o /dev/null -H "Origin: $CORS_ALLOWED" "$BASE/health" | tr -d '\r')"
[ "$(hv "$HS" access-control-allow-origin)" = "$CORS_ALLOWED" ] || fail_g "a simple GET from the allowed origin got no Access-Control-Allow-Origin"
finish_case "tower-http CorsLayer behaviour changed"

begin_test "#4377 tower-http / compression: npm metadata is gzip/br encoded on request and identity otherwise; tarballs are never recompressed"
reset_case
R_NPM="dtfdeps-npm-${SUF}"; NPM_PKG="dtf-gz-${SUF}"
mk_repo "$R_NPM" npm local || { infra_fail "could not create ${R_NPM}"; end_suite; }
mkdir -p "$W/npm/package"
printf '{"name":"%s","version":"1.0.0"}' "$NPM_PKG" > "$W/npm/package/package.json"
tar -C "$W/npm" -czf "$W/npm/t.tgz" package
DESC="$(head -c 3000 /dev/zero | tr '\0' 'x')"
jq -n --arg n "$NPM_PKG" --arg b "$(base64 -w0 < "$W/npm/t.tgz")" --arg s "$(sha1sum "$W/npm/t.tgz" | awk '{print $1}')" \
  --argjson l "$(wc -c < "$W/npm/t.tgz")" --arg d "$DESC" \
  '{_id:$n,name:$n,description:$d,"dist-tags":{latest:"1.0.0"},versions:{"1.0.0":{name:$n,version:"1.0.0",description:$d,dist:{shasum:$s,tarball:("http://x/"+$n+"/-/"+$n+"-1.0.0.tgz")}}},_attachments:{($n+"-1.0.0.tgz"):{content_type:"application/octet-stream",data:$b,length:$l}}}' > "$W/npm/pub.json"
pc="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' --data-binary "@$W/npm/pub.json" "$BASE/npm/${R_NPM}/${NPM_PKG}")"
[ "$pc" = "200" ] || [ "$pc" = "201" ] || { infra_fail "npm publish was HTTP ${pc}"; end_suite; }
npmget(){ # <accept-encoding> <url-suffix> -> "<code> <content-encoding>" ; body in $W/npm/o.bin
  local c ce
  c="$(curl -s --max-time 20 -o "$W/npm/o.bin" -D "$W/npm/h.txt" -w '%{http_code}' -H "Authorization: Bearer $TOK" -H "Accept-Encoding: $1" "$BASE/npm/${R_NPM}/$2")"
  ce="$(grep -i '^content-encoding:' "$W/npm/h.txt" | head -1 | cut -d: -f2 | tr -d ' \r')"
  echo "$c ${ce:-identity}"
}
read -r c ce <<<"$(npmget gzip "$NPM_PKG")"; gz_name="$(gzip -dc "$W/npm/o.bin" 2>/dev/null | jqr '.name // empty')"
note "gzip:     HTTP ${c}, ${ce}, decoded name ${gz_name:-?}"
[ "$c" = "200" ] && [ "$ce" = "gzip" ] && [ "$gz_name" = "$NPM_PKG" ] || fail_g "Accept-Encoding: gzip did not yield a gzip packument (HTTP ${c}, ${ce})"
read -r c ce <<<"$(npmget br "$NPM_PKG")"
note "br:       HTTP ${c}, ${ce}"
[ "$c" = "200" ] && [ "$ce" = "br" ] || fail_g "Accept-Encoding: br did not yield a br packument (HTTP ${c}, ${ce})"
read -r c ce <<<"$(npmget "" "$NPM_PKG")"; id_name="$(jqr '.name // empty' < "$W/npm/o.bin")"
note "identity: HTTP ${c}, ${ce}, name ${id_name:-?}"
[ "$c" = "200" ] && [ "$ce" = "identity" ] && [ "$id_name" = "$NPM_PKG" ] || fail_g "no Accept-Encoding did not yield an identity packument (HTTP ${c}, ${ce})"
read -r c ce <<<"$(npmget gzip "${NPM_PKG}/-/${NPM_PKG}-1.0.0.tgz")"
note "tarball:  HTTP ${c}, ${ce}"
if [ "$c" != "200" ] || [ "$ce" != "identity" ] || ! cmp -s "$W/npm/o.bin" "$W/npm/t.tgz"; then
  fail_g "the tarball was recompressed or altered (HTTP ${c}, ${ce})"
fi
finish_case "tower-http CompressionLayer behaviour changed on npm metadata"

begin_test "#4377 tower-http / compression BEHAVIOUR CHANGE (0.7): Accept-Encoding identity;q=0 with no alternative is 406 Not Acceptable"
reset_case
read -r c ce <<<"$(npmget "identity;q=0" "$NPM_PKG")"
note "identity;q=0: HTTP ${c}, ${ce}"
[ "$c" = "406" ] || fail_g "identity;q=0 answered HTTP ${c}; tower-http 0.7 answers 406 (RFC 9110 12.5.3), 0.6 fell back to identity 200"
read -r c ce <<<"$(npmget "gzip;q=0, identity" "$NPM_PKG")"
note "gzip;q=0, identity: HTTP ${c}, ${ce}"
[ "$c" = "200" ] && [ "$ce" = "identity" ] || fail_g "gzip;q=0, identity answered HTTP ${c} ${ce}, expected 200 identity"
finish_case "npm metadata does not carry tower-http 0.7's Accept-Encoding semantics"

begin_test "#4377 tower-http / trace + request id: X-Correlation-ID is echoed or generated; an oversized XML-RPC body is 413"
reset_case
CORR="dtfdeps-corr-${SUF}"
H="$(curl -s --max-time 10 -D - -o /dev/null -H "X-Correlation-ID: ${CORR}" "$BASE/health" | tr -d '\r')"
G="$(curl -s --max-time 10 -D - -o /dev/null "$BASE/health" | tr -d '\r')"
note "echoed: $(hv "$H" x-correlation-id); generated: $(hv "$G" x-correlation-id)"
[ "$(hv "$H" x-correlation-id)" = "$CORR" ] || fail_g "X-Correlation-ID was not echoed"
printf '%s' "$(hv "$G" x-correlation-id)" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || fail_g "no generated correlation id on a request without one"
python3 -c 'import sys; sys.stdout.write("<?xml version=\"1.0\"?><methodCall><methodName>list_packages</methodName><params><param><value><string>" + "a"*70000 + "</string></value></param></params></methodCall>")' > "$W/big.xml"
c="$(curl -s --max-time 20 -o "$W/big.out" -w '%{http_code}' -X POST -H 'Content-Type: text/xml' --data-binary "@$W/big.xml" "$BASE/pypi/${R_PY}/pypi")"
note "70 KB XML-RPC body: HTTP ${c} $(head -c 80 "$W/big.out")"
[ "$c" = "413" ] || fail_g "an XML-RPC body over the 64 KiB route limit answered HTTP ${c}, expected 413"
finish_case "request-id echo or body limit changed"

# =============================================================================
# OpenTelemetry 0.33 (#4811)
# =============================================================================
begin_test "#4811 otel: spans reach the OTLP/HTTP sink and carry the request's correlation id; /metrics still counts requests"
reset_case
MARK_OK="dtfdeps-otel-ok-${SUF}"
c="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -H "X-Correlation-ID: ${MARK_OK}" -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories")"
hits="$(wait_hits "$MARK_OK" 1 15)"
paths="$(curl -s --max-time 5 "${SINK}/__stats" | jqr '.paths | to_entries | map("\(.key)=\(.value)") | join(",")')"
note "request HTTP ${c}; sink bodies containing the marker: ${hits}; sink paths: ${paths}"
[ "${hits:-0}" -ge 1 ] 2>/dev/null || fail_g "no exported span carried correlation id ${MARK_OK} within 15 s"
api GET /api/v1/admin/metrics
mline="$(printf '%s\n' "$API_BODY" | grep -E '^ak_http_requests_total\{.*path="/api/v1/repositories"' | head -1)"
note "metrics: HTTP ${API_CODE}, ${mline:-no ak_http_requests_total line for /api/v1/repositories}"
[ "$API_CODE" = "200" ] && [ -n "$mline" ] || fail_g "Prometheus output lacks ak_http_requests_total for /api/v1/repositories"
finish_case "OTLP span export or the Prometheus request counter is broken"

begin_test "#4811 otel BEHAVIOUR CHANGE (0.33): a 503 from the collector is retried (4 attempts) without blocking requests"
reset_case
[ "$(sink_mode 503)" = "503" ] || { infra_fail "could not put the sink in 503 mode"; end_suite; }
MARK_R="dtfdeps-otel-retry-${SUF}"
t0="$(date +%s%N)"
c="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -H "X-Correlation-ID: ${MARK_R}" -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories")"
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
wait_hits "$MARK_R" 4 12 >/dev/null
sleep 3   # let any further attempt land, so an over-retry is seen too
r_hits="$(sink_grep "$MARK_R")"
hc="$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$BASE/health")"
sink_mode 200 >/dev/null
note "request during 503: HTTP ${c} in ${ms} ms; export attempts carrying the marker: ${r_hits}; /health ${hc}"
[ "$c" = "200" ] && [ "$ms" -lt 3000 ] || fail_g "a request while the collector answers 503 took ${ms} ms / HTTP ${c}: export must not block requests"
[ "$hc" = "200" ] || fail_g "/health was HTTP ${hc} while the collector answered 503"
[ "$r_hits" = "4" ] || fail_g "the batch carrying ${MARK_R} was sent ${r_hits} time(s); opentelemetry-otlp 0.33 retries a 503 up to 3 times (4 attempts), 0.32 sent it once"
MARK_B="dtfdeps-otel-back-${SUF}"
curl -s --max-time 10 -o /dev/null -H "X-Correlation-ID: ${MARK_B}" -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories" || true
b_hits="$(wait_hits "$MARK_B" 1 15)"
sleep 1; b_hits="$(sink_grep "$MARK_B")"
note "after the collector recovers: attempts carrying ${MARK_B}: ${b_hits}"
[ "$b_hits" = "1" ] || fail_g "after recovery the next batch was sent ${b_hits} time(s), expected exactly 1"
finish_case "OTLP exporter retry behaviour is not the 0.33 default"

end_suite
