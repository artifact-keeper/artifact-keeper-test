#!/usr/bin/env bash
# =============================================================================
# tiers/chunked-upload-format-finalize/oracle.sh
#   #1846 chunked uploads into Maven, npm, PyPI and RPM repositories are
#   indexed by the format as its own upload route indexes them.
# See the manifest for the gap and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh enables errexit; every probe below is judged by its assertion.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
MIB=1048576
W="$(mktemp -d -t dtf-cuff-XXXXXX)"
trap 'rm -rf "$W"' EXIT
RPM_FIXTURE="${DTF_DIR}/fixtures/rpm/akdep-lib-1.0-1.noarch.rpm"

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>/dev/null; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 120 "$@" 2>/dev/null || echo 000; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }

mk_repo() { # key format
  local body
  body="$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  code -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' -d "$body" "${BASE_URL}/api/v1/repositories"
}

# chunked <repo> <path> <file> [prefer] -> "<create>/<chunks>/<complete>"; the
# complete body lands in $W/complete, its headers in $W/complete.h.
chunked() {
  local repo="$1" path="$2" src="$3" prefer="${4:-}"
  local size csum body sess off end c chunks="" done_c
  local -a extra=()
  [ -n "$prefer" ] && extra=(-H "Prefer: ${prefer}")
  size="$(wc -c <"$src" | tr -d ' ')"; csum="$(sha "$src")"
  body="$(jq -nc --arg r "$repo" --arg p "$path" --arg c "$csum" --argjson s "$size" \
    '{repository_key:$r,artifact_path:$p,total_size:$s,checksum_sha256:$c,chunk_size:1048576}')"
  c="$(curl -s -o "$W/create" -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" -X POST \
    -H 'Content-Type: application/json' -d "$body" "${BASE_URL}/api/v1/uploads" 2>/dev/null || echo 000)"
  sess="$(jq -r '.session_id // empty' "$W/create" 2>/dev/null)"
  [ -n "$sess" ] || { echo "${c}/-/-"; return; }
  printf '%s' "$sess" > "$W/session"
  off=0
  while [ "$off" -lt "$size" ]; do
    end=$(( off + MIB - 1 )); [ "$end" -ge "$size" ] && end=$(( size - 1 ))
    tail -c "+$(( off + 1 ))" "$src" | head -c "$(( end - off + 1 ))" > "$W/chunk"
    chunks="${chunks:+${chunks}+}$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" -X PATCH \
      -H 'Content-Type: application/octet-stream' -H "Content-Range: bytes ${off}-${end}/${size}" \
      --data-binary @"$W/chunk" "${BASE_URL}/api/v1/uploads/${sess}" 2>/dev/null || echo 000)"
    off=$(( end + 1 ))
  done
  done_c="$(curl -s -D "$W/complete.h" -o "$W/complete" -w '%{http_code}' --max-time 120 "${AUTHZ[@]}" -X PUT \
    "${extra[@]}" "${BASE_URL}/api/v1/uploads/${sess}/complete" 2>/dev/null || echo 000)"
  echo "${c}/${chunks}/${done_c}"
}
completed_ok() { [[ "$1" =~ ^201/20[0-9](\+20[0-9])*/200$ ]]; }

begin_suite "chunked-upload-format-finalize"
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

# =============================================================================
# SETUP: fixtures (made now) and two repositories per format
# =============================================================================
begin_test "setup: Maven, npm, PyPI and RPM repositories (chunked and native) on S3, fixtures"
SF=""
for f in maven npm pypi rpm; do
  for side in ch nat; do
    eval "R_${f}_${side}=cuff-${f}-${side}-${SLOT}-${SUF}"
    k="R_${f}_${side}"
    c="$(mk_repo "${!k}" "$f")"; is_2xx "$c" || SF="${SF} create-${f}-${side}=${c}"
  done
done
[ -f "$RPM_FIXTURE" ] || SF="${SF} no-rpm-fixture"
G="com/acme/dtf${SLOT}"; A="demo"; V="1.2.3"
NPM_NAME="dtf-cuff-${SLOT}-${SUF}"; NPM_NAME="${NPM_NAME,,}"
PY_MOD="dtf_cuff_${SLOT}_${SUF//-/_}"; PY_PROJECT="${PY_MOD//_/-}"
python3 -I - "$W" "$G" "$A" "$V" "$NPM_NAME" "$PY_MOD" <<'PY' || SF="${SF} fixtures"
import base64, hashlib, io, json, os, sys, tarfile, zipfile
w, g, a, v, npm, py = sys.argv[1:]
# A jar of two chunks (random padding entry), and its POM.
with zipfile.ZipFile(f"{w}/demo.jar", "w", zipfile.ZIP_STORED) as z:
    z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    z.writestr("pad.bin", os.urandom(1536 * 1024))
gid = g.replace("/", ".")
open(f"{w}/demo.pom", "w").write(
    f'<?xml version="1.0"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">'
    f"<modelVersion>4.0.0</modelVersion><groupId>{gid}</groupId><artifactId>{a}</artifactId>"
    f"<version>{v}</version><description>chunked through the upload API</description></project>\n")
def tgz(path, name, version):
    pj = json.dumps({"name": name, "version": version, "description": "dtf chunked",
                     "dependencies": {"left-pad": "^1.3.0"}}).encode()
    with tarfile.open(path, "w:gz") as t:
        for n, d in (("package/package.json", pj), ("package/index.js", b"module.exports = 1;\n"),
                     ("package/pad.bin", os.urandom(1200 * 1024))):
            info = tarfile.TarInfo(n); info.size = len(d); t.addfile(info, io.BytesIO(d))
tgz(f"{w}/pkg.tgz", npm, "1.0.0")
tgz(f"{w}/pkg-native.tgz", npm, "1.0.0")
tgz(f"{w}/pkg-wrong.tgz", "someone-else", "1.0.0")
def wheel(path):
    di = f"{py}-0.4.0.dist-info"
    md = f"Metadata-Version: 2.1\nName: {py}\nVersion: 0.4.0\nSummary: dtf chunked\nRequires-Python: >=3.9\n\n"
    files = {f"{py}/__init__.py": "", f"{di}/METADATA": md,
             f"{di}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    rec = []
    with zipfile.ZipFile(path, "w") as z:
        for n, t in files.items():
            d = t.encode(); z.writestr(n, d)
            rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}")
        rec.append(f"{di}/RECORD,,"); z.writestr(f"{di}/RECORD", "\n".join(rec) + "\n")
wheel(f"{w}/{py}-0.4.0-py3-none-any.whl")
# The npm publish document for the native control.
data = open(f"{w}/pkg-native.tgz", "rb").read()
short = npm.split("/")[-1]
doc = {"_id": npm, "name": npm, "dist-tags": {"latest": "1.0.0"},
       "versions": {"1.0.0": {"name": npm, "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"},
                              "dist": {"tarball": f"http://x/{npm}/-/{short}-1.0.0.tgz",
                                       "shasum": hashlib.sha1(data).hexdigest()}}},
       "_attachments": {f"{short}-1.0.0.tgz": {"content_type": "application/octet-stream",
                                               "data": base64.b64encode(data).decode(), "length": len(data)}}}
json.dump(doc, open(f"{w}/npm-publish.json", "w"))
PY
WHEEL="${PY_MOD}-0.4.0-py3-none-any.whl"
if [ -n "$SF" ]; then infra_fail "setup failed:${SF}" "$(head -c 300 "$W/last" 2>/dev/null)"; end_suite; fi
pass

# =============================================================================
# CONTROL: the native routes index the same artifacts (both images)
# =============================================================================
begin_test "CONTROL: Maven PUT, npm publish, twine POST and RPM PUT appear in their format indexes"
CF=""
c="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/demo.jar" "${BASE_URL}/maven/${R_maven_nat}/${G}/${A}/${V}/${A}-${V}.jar")"; is_2xx "$c" || CF="${CF} maven-jar=${c}"
c="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/demo.pom" "${BASE_URL}/maven/${R_maven_nat}/${G}/${A}/${V}/${A}-${V}.pom")"; is_2xx "$c" || CF="${CF} maven-pom=${c}"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/maven/${R_maven_nat}/${G}/${A}/maven-metadata.xml")"
{ [ "$c" = 200 ] && grep -q "<version>${V}</version>" "$W/last"; } || CF="${CF} maven-metadata=${c}"
c="$(code "${AUTHZ[@]}" -X PUT -H 'Content-Type: application/json' --data-binary @"$W/npm-publish.json" "${BASE_URL}/npm/${R_npm_nat}/${NPM_NAME}")"; is_2xx "$c" || CF="${CF} npm-publish=${c}:$(head -c 120 "$W/last")"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/npm/${R_npm_nat}/${NPM_NAME}")"
{ [ "$c" = 200 ] && [ "$(jq -r '.versions["1.0.0"].dependencies["left-pad"] // empty' "$W/last")" = "^1.3.0" ]; } || CF="${CF} npm-packument=${c}"
c="$(code "${AUTHZ[@]}" -X POST "${BASE_URL}/pypi/${R_pypi_nat}/" -F ":action=file_upload" -F "protocol_version=1" \
  -F "metadata_version=2.1" -F "name=${PY_MOD}" -F "version=0.4.0" -F "filetype=bdist_wheel" -F "pyversion=py3" \
  -F "content=@$W/${WHEEL};filename=${WHEEL}")"; is_2xx "$c" || CF="${CF} pypi-upload=${c}"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/pypi/${R_pypi_nat}/simple/${PY_PROJECT}/")"
{ [ "$c" = 200 ] && grep -q "$WHEEL" "$W/last"; } || CF="${CF} pypi-simple=${c}"
c="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$RPM_FIXTURE" "${BASE_URL}/rpm/${R_rpm_nat}/packages/akdep-lib-1.0-1.noarch.rpm")"; is_2xx "$c" || CF="${CF} rpm-put=${c}"
NAT_RPM="$(psqlq "SELECT a.name || '|' || a.version FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${R_rpm_nat}' AND a.is_deleted = false")"
[ "$NAT_RPM" = "akdep-lib|1.0-1" ] || CF="${CF} rpm-native-row=${NAT_RPM}"
if [ -z "$CF" ]; then pass; else fail "a native upload did not index:${CF}"; fi

# =============================================================================
# FIX: Maven jar + POM through the chunked API
# =============================================================================
begin_test "#1846 chunked Maven jar and POM appear in the generated maven-metadata.xml"
r1="$(chunked "$R_maven_ch" "${G}/${A}/${V}/${A}-${V}.jar" "$W/demo.jar")"
r2="$(chunked "$R_maven_ch" "${G}/${A}/${V}/${A}-${V}.pom" "$W/demo.pom")"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/maven/${R_maven_ch}/${G}/${A}/maven-metadata.xml")"
MAVEN_DESC="$(psqlq "SELECT am.metadata->>'description' FROM artifacts a JOIN repositories r ON r.id = a.repository_id JOIN artifact_metadata am ON am.artifact_id = a.id WHERE r.key = '${R_maven_ch}' AND a.path LIKE '%.pom'")"
if completed_ok "$r1" && completed_ok "$r2" && [ "$c" = 200 ] && grep -q "<version>${V}</version>" "$W/last" \
   && [ "$MAVEN_DESC" = "chunked through the upload API" ]; then
  pass
else
  fail "jar ${r1}, pom ${r2}; maven-metadata.xml HTTP ${c} ($(head -c 160 "$W/last" | tr '\n' ' ')); POM description '${MAVEN_DESC}'"
fi

# =============================================================================
# FIX: npm tarball through the chunked API
# =============================================================================
begin_test "#1846 chunked npm tarball appears in the packument with its package.json"
r="$(chunked "$R_npm_ch" "${NPM_NAME}/1.0.0/${NPM_NAME}-1.0.0.tgz" "$W/pkg.tgz")"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/npm/${R_npm_ch}/${NPM_NAME}")"
DEP="$(jq -r '.versions["1.0.0"].dependencies["left-pad"] // empty' "$W/last" 2>/dev/null)"
TB="$(jq -r '.versions["1.0.0"].dist.tarball // empty' "$W/last" 2>/dev/null)"
if completed_ok "$r" && [ "$c" = 200 ] && [ "$DEP" = "^1.3.0" ] && [ -n "$TB" ]; then
  tc="$(curl -s -o "$W/tb" -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" "${BASE_URL}/npm/${R_npm_ch}/${NPM_NAME}/-/${NPM_NAME}-1.0.0.tgz" 2>/dev/null)"
  if [ "$tc" = 200 ] && [ "$(sha "$W/tb")" = "$(sha "$W/pkg.tgz")" ]; then pass; else fail "tarball download HTTP ${tc}"; fi
else
  fail "upload ${r}; packument HTTP ${c}, left-pad '${DEP}', tarball '${TB}' ($(head -c 160 "$W/last"))"
fi

begin_test "#1846 a chunked npm tarball whose package.json names another package is refused, nothing stored"
r="$(chunked "$R_npm_ch" "${NPM_NAME}/2.0.0/${NPM_NAME}-2.0.0.tgz" "$W/pkg-wrong.tgz")"
ROWS="$(psqlq "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${R_npm_ch}' AND a.path LIKE '%/2.0.0/%'")"
if [[ "$r" == */400 ]] && [ "$ROWS" = "0" ]; then pass; else fail "completion ${r}, rows at 2.0.0: ${ROWS}"; fi

# =============================================================================
# FIX: PyPI wheel through the chunked API
# =============================================================================
begin_test "#1846 chunked PyPI wheel appears in /simple/<project>/ with data-requires-python"
r="$(chunked "$R_pypi_ch" "${PY_PROJECT}/0.4.0/${WHEEL}" "$W/${WHEEL}")"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/pypi/${R_pypi_ch}/simple/${PY_PROJECT}/")"
if completed_ok "$r" && [ "$c" = 200 ] && grep -q "$WHEEL" "$W/last" && grep -q 'data-requires-python="&gt;=3.9"' "$W/last"; then
  pass
else
  fail "upload ${r}; simple index HTTP ${c} ($(head -c 200 "$W/last" | tr '\n' ' '))"
fi

# =============================================================================
# FIX: RPM through the chunked API
# =============================================================================
begin_test "#1846 chunked RPM is named and catalogued by its NEVRA and listed in primary.xml"
r="$(chunked "$R_rpm_ch" "packages/akdep-lib-1.0-1.noarch.rpm" "$RPM_FIXTURE")"
CH_RPM="$(psqlq "SELECT a.name || '|' || a.version FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${R_rpm_ch}' AND a.is_deleted = false")"
CAT="$(psqlq "SELECT p.name || '|' || pv.version FROM packages p JOIN package_versions pv ON pv.package_id = p.id JOIN repositories r ON r.id = p.repository_id WHERE r.key = '${R_rpm_ch}'")"
c="$(code "${AUTHZ[@]}" "${BASE_URL}/rpm/${R_rpm_ch}/repodata/primary.xml.gz")"
PRIMARY="$(gzip -dc "$W/last" 2>/dev/null)"
if completed_ok "$r" && [ "$CH_RPM" = "akdep-lib|1.0-1" ] && [ "$CAT" = "akdep-lib|1.0-1" ] \
   && [ "$c" = 200 ] && grep -q '<name>akdep-lib</name>' <<<"$PRIMARY"; then
  pass
else
  fail "upload ${r}; row '${CH_RPM}' (native: '${NAT_RPM}'), catalog '${CAT}', primary HTTP ${c}"
fi

# =============================================================================
# FIX: asynchronous completion
# =============================================================================
begin_test "#1846 Prefer: respond-async answers 202 with the session as Location and polls to completed"
r="$(chunked "$R_maven_ch" "${G}/${A}/1.2.4/${A}-1.2.4.jar" "$W/demo.jar" "respond-async")"
SESSION="$(cat "$W/session" 2>/dev/null)"
LOC="$(grep -i '^location:' "$W/complete.h" 2>/dev/null | tr -d '\r' | awk '{print $2}')"
ST=""; AID=""
for _ in $(seq 1 60); do
  curl -s -o "$W/poll" --max-time 20 "${AUTHZ[@]}" "${BASE_URL}${LOC:-/api/v1/uploads/${SESSION}}" 2>/dev/null
  ST="$(jq -r '.status // empty' "$W/poll" 2>/dev/null)"; AID="$(jq -r '.artifact_id // empty' "$W/poll" 2>/dev/null)"
  [ "$ST" = "committing" ] || break
  sleep 1
done
if [[ "$r" == */202 ]] && [ "$LOC" = "/api/v1/uploads/${SESSION}" ] && [ "$ST" = "completed" ] && [ -n "$AID" ]; then
  pass
else
  fail "completion ${r}, Location '${LOC}', polled status '${ST}', artifact_id '${AID}'"
fi

end_suite
