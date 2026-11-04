#!/usr/bin/env bash
# test-generic-upload-native-parity.sh - a package PUT through the generic
# artifact endpoint at its format's native layout path yields the same
# client-visible index as the format's native publish (artifact-keeper#5254).
#
# The generic endpoint
#   PUT /api/v1/repositories/{repo}/artifacts/{path}
# accepts a file into a repository of any format. When {path} is the format's
# native layout path, a client reading the format's index must see the same
# package it would see after a native publish of the same bytes. Per format,
# two repositories of that format are created; one gets the native publish,
# the other the generic PUT, and the client-visible index of each is compared:
#
#   Debian  native PUT /debian/{repo}/pool/main/<file>.deb
#           index  dists/stable/main/binary-amd64/Packages: the stanza keeps
#                  Depends (and every other field) from the control file
#   npm     native PUT /npm/{repo}/<name> (npm publish document)
#           generic at <name>/-/<name>-<ver>.tgz
#           index  GET /npm/{repo}/<name>: versions[<ver>] exists and keeps
#                  `dependencies` from the tarball's package.json
#   Maven   native PUT /maven/{repo}/<g>/<a>/<v>/<a>-<v>.{jar,pom}
#           index  <g>/<a>/maven-metadata.xml: 200 and lists <v>
#
# Field values that legitimately differ between two repositories (the repo key
# inside URLs, Maven <lastUpdated>) are normalised before comparing.
#
# On 1.11.11 the generic upload records no format metadata: the Debian stanza
# has no Depends/Maintainer and "Description: No description available", the
# packument lists version "-" with no dependencies, and maven-metadata.xml is
# 404. Alpine is covered by test-alpine-apkindex-parity.sh.
#
# No network: every package is built here.
#
# Requires: curl, jq, tar, gzip, python3
source "$(dirname "$0")/../lib/common.sh"

begin_suite "generic-upload-native-parity"
require_cmd python3
require_cmd jq
require_cmd tar
auth_admin
setup_workdir

SFX="${RUN_ID}"
DEB_N="test-gnp-deb-nat-${SFX}"; DEB_G="test-gnp-deb-gen-${SFX}"
NPM_N="test-gnp-npm-nat-${SFX}"; NPM_G="test-gnp-npm-gen-${SFX}"
MVN_N="test-gnp-mvn-nat-${SFX}"; MVN_G="test-gnp-mvn-gen-${SFX}"
ALL_REPOS=("$DEB_N" "$DEB_G" "$NPM_N" "$NPM_G" "$MVN_N" "$MVN_G")

if [ "${KEEP_REPOS:-0}" != "1" ]; then
  for r in "${ALL_REPOS[@]}"; do
    add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"\${BASE_URL}/api/v1/repositories/${r}\" || true"
  done
fi

# generic_put REPO PATH FILE -> HTTP status
generic_put() {
  curl -s -o "${WORK_DIR}/generic-put.json" -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
    --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" || echo 000
}

# native_put URL FILE [CONTENT_TYPE] -> HTTP status
native_put() {
  curl -s -o "${WORK_DIR}/native-put.json" -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: ${3:-application/octet-stream}" \
    --data-binary "@$2" "$1" || echo 000
}

# fetch URL OUT -> HTTP status
fetch() {
  curl -s -o "$2" -w '%{http_code}' $CURL_TIMEOUT -H "$(format_auth_header)" "$1" || echo 000
}

begin_test "Create a native-publish and a generic-upload repository per format"
ok=1
for pair in "$DEB_N debian" "$DEB_G debian" "$NPM_N npm" "$NPM_G npm" "$MVN_N maven" "$MVN_G maven"; do
  set -- $pair
  create_local_repo "$1" "$2" || ok=0
done
if [ "$ok" = 1 ]; then pass; else fail_fatal "could not create the repositories"; fi

# ===========================================================================
# Debian
# ===========================================================================

DEB_PKG="gnp-parity"
DEB_VER="1.2.3"
DEB_FILE="${DEB_PKG}_${DEB_VER}_amd64.deb"
DEB_DEPENDS="libc6 (>= 2.31), zlib1g"
DEB_PATH="pool/main/${DEB_FILE}"

# A .deb is an ar archive of debian-binary, control.tar.gz, data.tar.gz.
# Written with python3 so the suite does not need dpkg-deb or binutils.
mkdir -p "${WORK_DIR}/deb/control" "${WORK_DIR}/deb/data/usr/share/${DEB_PKG}"
cat > "${WORK_DIR}/deb/control/control" <<EOF
Package: ${DEB_PKG}
Version: ${DEB_VER}
Architecture: amd64
Maintainer: E2E Parity <e2e@example.com>
Depends: ${DEB_DEPENDS}
Section: misc
Priority: optional
Description: generic upload parity fixture
 Built by test-generic-upload-native-parity.sh.
EOF
echo "${RUN_ID}" > "${WORK_DIR}/deb/data/usr/share/${DEB_PKG}/marker"
(cd "${WORK_DIR}/deb/control" && tar czf ../control.tar.gz ./control)
(cd "${WORK_DIR}/deb/data" && tar czf ../data.tar.gz ./usr)
printf '2.0\n' > "${WORK_DIR}/deb/debian-binary"
python3 -I - "${WORK_DIR}/deb" "${WORK_DIR}/${DEB_FILE}" <<'PY'
import os, sys
src, out = sys.argv[1], sys.argv[2]
with open(out, "wb") as fh:
    fh.write(b"!<arch>\n")
    for name in ("debian-binary", "control.tar.gz", "data.tar.gz"):
        data = open(os.path.join(src, name), "rb").read()
        hdr = "%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name, 0, 0, 0, "100644", len(data))
        fh.write(hdr.encode())
        fh.write(data)
        if len(data) % 2:
            fh.write(b"\n")
PY

# deb_stanza PACKAGES_FILE -> JSON object of the stanza for DEB_PKG (or "null")
deb_stanza() {
  python3 -I - "$1" "$DEB_PKG" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for block in text.split("\n\n"):
    fields, key = {}, None
    for line in block.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line
        elif ":" in line:
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    if fields.get("Package") == sys.argv[2]:
        print(json.dumps(fields, sort_keys=True))
        break
else:
    print("null")
PY
}

begin_test "Debian: native and generic uploads of the same .deb are accepted"
s1=$(native_put "${BASE_URL}/debian/${DEB_N}/${DEB_PATH}" "${WORK_DIR}/${DEB_FILE}")
s2=$(generic_put "$DEB_G" "$DEB_PATH" "${WORK_DIR}/${DEB_FILE}")
if [[ "$s1" =~ ^2 ]] && [[ "$s2" =~ ^2 ]]; then pass; else fail "native=${s1} generic=${s2}"; fi

PKGS_PATH="dists/stable/main/binary-amd64/Packages"
fetch "${BASE_URL}/debian/${DEB_N}/${PKGS_PATH}" "${WORK_DIR}/deb-nat.Packages" >/dev/null
fetch "${BASE_URL}/debian/${DEB_G}/${PKGS_PATH}" "${WORK_DIR}/deb-gen.Packages" >/dev/null
DEB_NAT_JSON=$(deb_stanza "${WORK_DIR}/deb-nat.Packages")
DEB_GEN_JSON=$(deb_stanza "${WORK_DIR}/deb-gen.Packages")

begin_test "Debian: native upload's Packages stanza carries the control file's Depends (control)"
got=$(jq -r '.Depends // empty' <<<"$DEB_NAT_JSON")
if [ "$got" = "$DEB_DEPENDS" ]; then pass; else fail "Depends='${got}'" "$(cat "${WORK_DIR}/deb-nat.Packages")"; fi

begin_test "Debian: generic upload's Packages stanza carries the control file's Depends"
got=$(jq -r '.Depends // empty' <<<"$DEB_GEN_JSON")
if [ "$got" = "$DEB_DEPENDS" ]; then
  pass
else
  fail "Depends='${got}', expected '${DEB_DEPENDS}'" "$(cat "${WORK_DIR}/deb-gen.Packages")"
fi

begin_test "Debian: generic upload's Packages stanza equals the native upload's"
diff_out=$(jq -rn --argjson n "$DEB_NAT_JSON" --argjson g "$DEB_GEN_JSON" '
  if $g == null then "no stanza for the package"
  else [ ($n + $g) | keys[] as $k | select($n[$k] != $g[$k])
         | "\($k): native=[\($n[$k] // "<absent>")] generic=[\($g[$k] // "<absent>")]" ] | join("; ")
  end' 2>/dev/null || echo "could not compare")
if [ -z "$diff_out" ]; then pass; else fail "$diff_out"; fi

# ===========================================================================
# npm
# ===========================================================================

NPM_PKG="gnp-parity"
NPM_VER="1.2.3"
NPM_DEPS='{"left-pad":"^1.3.0","ms":"2.1.3"}'
NPM_TGZ="${NPM_PKG}-${NPM_VER}.tgz"

mkdir -p "${WORK_DIR}/npm/package"
jq -n --arg n "$NPM_PKG" --arg v "$NPM_VER" --argjson d "$NPM_DEPS" \
  '{name:$n, version:$v, description:"generic upload parity fixture", main:"index.js", license:"MIT", dependencies:$d}' \
  > "${WORK_DIR}/npm/package/package.json"
echo "module.exports = 1;" > "${WORK_DIR}/npm/package/index.js"
(cd "${WORK_DIR}/npm" && tar czf "${WORK_DIR}/${NPM_TGZ}" package)

NPM_SHASUM=$(sha1sum "${WORK_DIR}/${NPM_TGZ}" | cut -d' ' -f1)
NPM_INTEGRITY=$(python3 -I -c 'import base64,hashlib,sys; print("sha512-" + base64.b64encode(hashlib.sha512(open(sys.argv[1],"rb").read()).digest()).decode())' "${WORK_DIR}/${NPM_TGZ}")
jq -n --arg n "$NPM_PKG" --arg v "$NPM_VER" --argjson d "$NPM_DEPS" \
  --arg data "$(base64 -w0 "${WORK_DIR}/${NPM_TGZ}")" --arg f "$NPM_TGZ" \
  --arg tb "${BASE_URL}/npm/${NPM_N}/${NPM_PKG}/-/${NPM_TGZ}" \
  --arg shasum "$NPM_SHASUM" --arg integrity "$NPM_INTEGRITY" \
  --argjson len "$(wc -c < "${WORK_DIR}/${NPM_TGZ}" | tr -d ' ')" \
  '{_id:$n, name:$n, "dist-tags":{latest:$v},
    versions:{($v):{name:$n, version:$v, description:"generic upload parity fixture",
                    main:"index.js", license:"MIT", dependencies:$d,
                    dist:{tarball:$tb, shasum:$shasum, integrity:$integrity}}},
    _attachments:{($f):{content_type:"application/octet-stream", data:$data, length:$len}}}' \
  > "${WORK_DIR}/npm-publish.json"

begin_test "npm: native publish and generic upload of the same tarball are accepted"
s1=$(native_put "${BASE_URL}/npm/${NPM_N}/${NPM_PKG}" "${WORK_DIR}/npm-publish.json" application/json)
s2=$(generic_put "$NPM_G" "${NPM_PKG}/-/${NPM_TGZ}" "${WORK_DIR}/${NPM_TGZ}")
if [[ "$s1" =~ ^2 ]] && [[ "$s2" =~ ^2 ]]; then pass; else fail "native=${s1} generic=${s2}"; fi

n_st=$(fetch "${BASE_URL}/npm/${NPM_N}/${NPM_PKG}" "${WORK_DIR}/npm-nat.json")
g_st=$(fetch "${BASE_URL}/npm/${NPM_G}/${NPM_PKG}" "${WORK_DIR}/npm-gen.json")

# npm_version FILE REPO -> versions[NPM_VER] with the repo key normalised
npm_version() {
  sed "s#$2#<repo>#g" "$1" | jq -cS --arg v "$NPM_VER" '.versions[$v] // null' 2>/dev/null || echo null
}

begin_test "npm: native publish's packument lists ${NPM_VER} with its dependencies (control)"
got=$(jq -cS --arg v "$NPM_VER" '.versions[$v].dependencies // null' "${WORK_DIR}/npm-nat.json" 2>/dev/null || echo null)
if [ "$n_st" = 200 ] && [ "$got" = "$(jq -cS . <<<"$NPM_DEPS")" ]; then
  pass
else
  fail "HTTP ${n_st}, versions[${NPM_VER}].dependencies=${got}" "$(head -c 1500 "${WORK_DIR}/npm-nat.json")"
fi

begin_test "npm: generic upload's packument lists ${NPM_VER} with its dependencies"
got=$(jq -cS --arg v "$NPM_VER" '.versions[$v].dependencies // null' "${WORK_DIR}/npm-gen.json" 2>/dev/null || echo null)
vers=$(jq -c '.versions // {} | keys' "${WORK_DIR}/npm-gen.json" 2>/dev/null || echo "?")
if [ "$g_st" = 200 ] && [ "$got" = "$(jq -cS . <<<"$NPM_DEPS")" ]; then
  pass
else
  fail "HTTP ${g_st}, versions=${vers}, versions[${NPM_VER}].dependencies=${got}" "$(head -c 1500 "${WORK_DIR}/npm-gen.json")"
fi

begin_test "npm: generic upload's packument entry for ${NPM_VER} equals the native publish's"
nv=$(npm_version "${WORK_DIR}/npm-nat.json" "$NPM_N")
gv=$(npm_version "${WORK_DIR}/npm-gen.json" "$NPM_G")
nt=$(jq -cS '."dist-tags" // null' "${WORK_DIR}/npm-nat.json" 2>/dev/null || echo null)
gt=$(jq -cS '."dist-tags" // null' "${WORK_DIR}/npm-gen.json" 2>/dev/null || echo null)
if [ "$nv" != null ] && [ "$nv" = "$gv" ] && [ "$nt" = "$gt" ]; then
  pass
else
  fail "packument differs" "dist-tags native=${nt}
dist-tags generic=${gt}
versions[${NPM_VER}] native=${nv}
versions[${NPM_VER}] generic=${gv}"
fi

# ===========================================================================
# Maven
# ===========================================================================

MVN_G_ID="com.example.gnp"
MVN_A_ID="parity"
MVN_VER="1.2.3"
MVN_DIR="${MVN_G_ID//.//}/${MVN_A_ID}"
MVN_BASE="${MVN_DIR}/${MVN_VER}/${MVN_A_ID}-${MVN_VER}"

printf 'parity-jar-%s\n' "$RUN_ID" > "${WORK_DIR}/parity.jar"
cat > "${WORK_DIR}/parity.pom" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${MVN_G_ID}</groupId>
  <artifactId>${MVN_A_ID}</artifactId>
  <version>${MVN_VER}</version>
  <packaging>jar</packaging>
</project>
EOF

begin_test "Maven: native and generic uploads of the same jar and pom are accepted"
s=""
s="${s} $(native_put "${BASE_URL}/maven/${MVN_N}/${MVN_BASE}.pom" "${WORK_DIR}/parity.pom" application/xml)"
s="${s} $(native_put "${BASE_URL}/maven/${MVN_N}/${MVN_BASE}.jar" "${WORK_DIR}/parity.jar")"
s="${s} $(generic_put "$MVN_G" "${MVN_BASE}.pom" "${WORK_DIR}/parity.pom")"
s="${s} $(generic_put "$MVN_G" "${MVN_BASE}.jar" "${WORK_DIR}/parity.jar")"
bad=0
for st in $s; do [[ "$st" =~ ^2 ]] || bad=1; done
if [ "$bad" = 0 ]; then pass; else fail "native pom/jar, generic pom/jar =${s}"; fi

n_st=$(fetch "${BASE_URL}/maven/${MVN_N}/${MVN_DIR}/maven-metadata.xml" "${WORK_DIR}/mvn-nat.xml")
g_st=$(fetch "${BASE_URL}/maven/${MVN_G}/${MVN_DIR}/maven-metadata.xml" "${WORK_DIR}/mvn-gen.xml")

begin_test "Maven: native upload's maven-metadata.xml lists ${MVN_VER} (control)"
if [ "$n_st" = 200 ] && grep -q "<version>${MVN_VER}</version>" "${WORK_DIR}/mvn-nat.xml"; then
  pass
else
  fail "HTTP ${n_st}" "$(head -c 800 "${WORK_DIR}/mvn-nat.xml")"
fi

begin_test "Maven: generic upload's maven-metadata.xml is 200 and lists ${MVN_VER}"
if [ "$g_st" = 200 ] && grep -q "<version>${MVN_VER}</version>" "${WORK_DIR}/mvn-gen.xml"; then
  pass
else
  fail "HTTP ${g_st}" "$(head -c 800 "${WORK_DIR}/mvn-gen.xml")"
fi

begin_test "Maven: generic upload's maven-metadata.xml equals the native upload's"
strip_mvn() { sed -e 's#<lastUpdated>[0-9]*</lastUpdated>##' -e 's/[[:space:]]*$//' "$1" | grep -v '^$' || true; }
if [ "$g_st" = 200 ] && [ "$(strip_mvn "${WORK_DIR}/mvn-nat.xml")" = "$(strip_mvn "${WORK_DIR}/mvn-gen.xml")" ]; then
  pass
else
  fail "maven-metadata.xml differs (generic HTTP ${g_st})" "native:
$(strip_mvn "${WORK_DIR}/mvn-nat.xml")
generic:
$(head -c 800 "${WORK_DIR}/mvn-gen.xml")"
fi

end_suite
