#!/usr/bin/env bash
# =============================================================================
# tiers/conan-protocol-1-11/oracle.sh
#   #4329 a Conan revision is published by its manifest: an early manifest is
#         409 with nothing stored, files before the manifest are unlisted, a
#         body shorter than its Content-Length is 408 with nothing stored
#   #4333 `conan remove` works against a local repository (DELETE routes)
#   #4334 package search returns each binary's conaninfo.txt as {"content":..}
#         so `conan list -p "os=Linux"` filters
#   #4335 recipe and package /latest report the revision's stored time
# See the manifest for THE BUGS, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit. A client command that fails is an observation
# this oracle records and judges, never a reason to abort.
set +e

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
ADMIN="${ADMIN_USER:-admin}"
CC="ak-dtf${DTF_SLOT}-client-conan"
HOST_PORT="${BASE#http://}"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# cx <timeout> <script>: run a shell script in the conan client container.
cx(){
  docker exec "$CC" timeout "$1" bash -c "set -o pipefail; export HOME=/root CONAN_HOME=/root/.conan2 CONAN_NON_INTERACTIVE=1; $2" 2>&1
}
# api <outfile> <method> <path> [curl args...] -> http code
api(){
  local out="$1" m="$2" p="$3"; shift 3
  curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $TOK" "$@" "$BASE$p" || true
}

# =============================================================================
begin_suite "conan-protocol-1-11"

begin_test "setup: admin login, a local Conan repository, Conan 2 in the client container"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN}\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}"
REPO="conan-${SUF}"
body="$(jq -n --arg k "$REPO" '{key:$k,name:$k,format:"conan",repo_type:"local",is_public:false}')"
got="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty')"
[ "$got" = "$REPO" ] || { infra_fail "could not create conan repository ${REPO}"; end_suite; }
C="/conan/${REPO}/v2/conans"
out="$(cx 400 "pip install --quiet --disable-pip-version-check --no-input 'conan>=2,<3' 2>&1 | tail -2; conan --version")"
echo "$out" | grep -q 'Conan version 2' || { infra_fail "conan pip install failed in ${CC}" "$out"; end_suite; }
out="$(cx 60 "mkdir -p \$CONAN_HOME/profiles /work/rec && cat > \$CONAN_HOME/profiles/default <<'EOF'
[settings]
os=Linux
arch=x86_64
build_type=Release
compiler=gcc
compiler.version=12
compiler.cppstd=gnu17
compiler.libcxx=libstdc++11
EOF
cat > /work/rec/conanfile.py <<'EOF'
import os
from conan import ConanFile
from conan.tools.files import save

class DtfC11(ConanFile):
    name = 'dtf-c11'
    version = '1.0'
    settings = 'os', 'arch', 'compiler', 'build_type'

    def package(self):
        save(self, os.path.join(self.package_folder, 'share', 'marker.txt'), 'DTF-C11-${SUF}\n')

    def package_info(self):
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
EOF
cd /work/rec && conan create . 2>&1 | tail -3
conan remote remove conancenter >/dev/null 2>&1 || true
conan remote add ak 'http://backend:8080/conan/${REPO}' --force
conan remote login ak '${ADMIN}' -p '${ADMIN_PASS}' 2>&1 | tail -1")"; rc=$?
[ "$rc" -eq 0 ] || { infra_fail "conan create / remote login failed" "$out"; end_suite; }
echo "-- repo ${REPO}; client ${CC}"
pass

# =============================================================================
begin_test "CONTROL: a real 'conan upload' publishes recipe + binary; an empty-cache 'conan install --build=never' fetches it"
reset_case
out="$(cx 240 "conan upload 'dtf-c11/1.0' -r ak -c 2>&1 | tail -6")"; rc=$?
note "conan upload rc ${rc}"
[ "$rc" -eq 0 ] || { fail_g "conan upload failed"; note "$out"; }
RREV="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/latest" | jqr '.revision // empty')"
note "recipe revision ${RREV:-none}"
[ -n "$RREV" ] || fail_g "/latest names no recipe revision after the upload"
out="$(cx 240 "conan remove '*' -c >/dev/null 2>&1; conan install --requires=dtf-c11/1.0 -r ak --build=never 2>&1 | tail -4
f=\$(find \$CONAN_HOME -path '*share/marker.txt' | head -1); cat \"\$f\"")"; rc=$?
note "conan install rc ${rc}: $(echo "$out" | tail -1)"
echo "$out" | grep -q "DTF-C11-${SUF}" || fail_g "the installed binary does not carry the marker"
PKGID="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/revisions/${RREV}/search?list_only=True" | jqr 'keys[0] // empty')"
[ -n "$PKGID" ] || PKGID="$(cx 60 "conan list 'dtf-c11/1.0:*' -c --format=json 2>/dev/null" | jq -r '.. | objects | .packages? // empty | keys[0]' 2>/dev/null | head -1)"
PREV="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/revisions/${RREV}/packages/${PKGID}/latest" | jqr '.revision // empty')"
note "package id ${PKGID:-none}, package revision ${PREV:-none}"
[ -n "$PKGID" ] && [ -n "$PREV" ] || fail_g "could not resolve the uploaded package id / revision"
finish_case "conan upload/install control failed"

# =============================================================================
begin_test "FIX #4335: recipe and package /latest report the stored time, stable across reads and equal to /revisions"
reset_case
t1="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/latest" | jqr '.time // empty')"
sleep 2
t2="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/latest" | jqr '.time // empty')"
tr0="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/revisions" | jqr '.revisions[0].time // empty')"
note "recipe /latest.time read 1 '${t1}', read 2 '${t2}'; /revisions[0].time '${tr0}'"
[ -n "$t1" ] && [ "$t1" = "$t2" ] || fail_g "recipe /latest.time changed between two reads of the same revision"
[ -n "$t1" ] && [ "$t1" = "$tr0" ] || fail_g "recipe /latest.time does not equal /revisions[0].time"
P="$C/dtf-c11/1.0/_/_/revisions/${RREV}/packages/${PKGID}"
p1="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$P/latest" | jqr '.time // empty')"
sleep 2
p2="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$P/latest" | jqr '.time // empty')"
pr0="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$P/revisions" | jqr '.revisions[0].time // empty')"
note "package /latest.time read 1 '${p1}', read 2 '${p2}'; /revisions[0].time '${pr0}'"
[ -n "$p1" ] && [ "$p1" = "$p2" ] || fail_g "package /latest.time changed between two reads of the same revision"
[ -n "$p1" ] && [ "$p1" = "$pr0" ] || fail_g "package /latest.time does not equal /revisions[0].time"
finish_case "#4335 /latest time failed"

# =============================================================================
begin_test "FIX #4334: package search carries each binary's conaninfo.txt; 'conan list -p os=Linux' matches it"
reset_case
c="$(api "$W/search.json" GET "$C/dtf-c11/1.0/_/_/revisions/${RREV}/search")"
content="$(jq -r --arg p "$PKGID" '.[$p].content // empty' < "$W/search.json" 2>/dev/null)"
note "package search: ${c}; ${PKGID}.content: $(echo "$content" | tr '\n' ' ' | head -c 160)"
[ "$c" = "200" ] || fail_g "package search answered ${c}"
echo "$content" | grep -q '^os=Linux' || fail_g "package search gives ${PKGID} no conaninfo content with os=Linux"
lo="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/revisions/${RREV}/search?list_only=True" | jq -c --arg p "$PKGID" '.[$p]' 2>/dev/null)"
note "list_only=True entry: ${lo}"
out="$(cx 60 "conan list 'dtf-c11/1.0#${RREV}:*' -p 'os=Linux' -r ak --format=json 2>/dev/null")"
n_linux="$(echo "$out" | jq '[.. | objects | .packages? // empty | keys[]] | length' 2>/dev/null | tail -1)"
out="$(cx 60 "conan list 'dtf-c11/1.0#${RREV}:*' -p 'os=Windows' -r ak --format=json 2>/dev/null")"
n_win="$(echo "$out" | jq '[.. | objects | .packages? // empty | keys[]] | length' 2>/dev/null | tail -1)"
note "conan list -p os=Linux: ${n_linux:-?} package(s); -p os=Windows: ${n_win:-?} package(s)"
[ "${n_linux:-0}" = "1" ] || fail_g "conan list -p os=Linux matched ${n_linux:-0} binaries, expected 1"
[ "${n_win:-x}" = "0" ] || fail_g "conan list -p os=Windows matched ${n_win:-?} binaries, expected 0"
finish_case "#4334 package search content failed"

# =============================================================================
# Manifest-last publishing. Hand-driven revisions on a second recipe.
# =============================================================================
R2="$C/dtf-atomic/1.0/_/_"
printf 'from conan import ConanFile\nclass A(ConanFile):\n    name = "dtf-atomic"\n    version = "1.0"\n' > "$W/conanfile.py"
printf '1713000000\nconanfile.py: %s\n' "$(md5sum "$W/conanfile.py" | awk '{print $1}')" > "$W/conanmanifest.txt"
REV_A="aaaa${SUF}"; REV_B="bbbb${SUF}"

begin_test "FIX #4329: a manifest uploaded before its conanfile.py is refused 409 and nothing is stored"
reset_case
c="$(api "$W/m409" PUT "$R2/revisions/${REV_A}/files/conanmanifest.txt" --data-binary "@$W/conanmanifest.txt")"
note "early conanmanifest.txt PUT: ${c} $(head -c 200 "$W/m409")"
[ "$c" = "409" ] || fail_g "an early manifest answered ${c}, expected 409"
grep -q 'conanfile.py' "$W/m409" || fail_g "the 409 body does not name the missing conanfile.py"
rows="$(psql_q "SELECT count(*) FROM artifacts WHERE path LIKE '%${REV_A}%' AND is_deleted = false")"
note "artifact rows for revision ${REV_A}: ${rows}"
[ "$rows" = "0" ] || fail_g "the refused manifest left ${rows} artifact row(s)"
c="$(api "$W/fA" GET "$R2/revisions/${REV_A}/files")"
note "/revisions/${REV_A}/files: ${c} $(head -c 120 "$W/fA")"
[ "$c" = "404" ] || [ "$(jqr '.files | length' < "$W/fA")" = "0" ] || fail_g "the refused revision lists files"
finish_case "#4329 early manifest failed"

begin_test "FIX #4329: files uploaded before the manifest are unlisted until the manifest publishes the revision"
reset_case
c="$(api "$W/pB" PUT "$R2/revisions/${REV_B}/files/conanfile.py" --data-binary "@$W/conanfile.py")"
note "conanfile.py PUT: ${c}"
case "$c" in 2*) ;; *) fail_g "conanfile.py upload answered ${c}";; esac
c1="$(api "$W/lB" GET "$R2/latest")"
revs="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$R2/revisions" | jqr '[.revisions[]?.revision]|join(",")')"
c2="$(api "$W/fB" GET "$R2/revisions/${REV_B}/files")"
note "before manifest: /latest ${c1} $(head -c 100 "$W/lB"); /revisions [${revs}]; /files ${c2} $(head -c 100 "$W/fB")"
[ "$c1" = "404" ] || fail_g "/latest answered ${c1} for a revision with no manifest, expected 404"
case ",${revs}," in *",${REV_B},"*) fail_g "/revisions lists ${REV_B} before its manifest";; esac
{ [ "$c2" = "404" ] || [ "$(jqr '.files | length' < "$W/fB")" = "0" ]; } || fail_g "/files lists the pending revision's files"
c="$(api "$W/mB" PUT "$R2/revisions/${REV_B}/files/conanmanifest.txt" --data-binary "@$W/conanmanifest.txt")"
lrev="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$R2/latest" | jqr '.revision // empty')"
nfiles="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$R2/revisions/${REV_B}/files" | jqr '.files | keys | join(",")')"
note "manifest PUT: ${c}; then /latest.revision ${lrev:-none}; /files [${nfiles}]"
case "$c" in 2*) ;; *) fail_g "the manifest after conanfile.py answered ${c}";; esac
[ "$lrev" = "$REV_B" ] || fail_g "the manifest did not publish ${REV_B} (latest is '${lrev}')"
[ "$nfiles" = "conanfile.py,conanmanifest.txt" ] || fail_g "the published revision lists [${nfiles}]"
finish_case "#4329 manifest-last publication failed"

begin_test "FIX #4329: a package file shorter than its Content-Length is refused 408 and nothing is stored"
reset_case
PFX="/conan/${REPO}/v2/conans/dtf-atomic/1.0/_/_/revisions/${REV_B}/packages/pid${SUF}/revisions/prev${SUF}/files/conan_package.tgz"
resp="$(python3 -I - "$HOST_PORT" "$PFX" "$TOK" <<'PY'
import socket, sys
hp, path, tok = sys.argv[1], sys.argv[2], sys.argv[3]
host, port = hp.split(":")
s = socket.create_connection((host, int(port)), timeout=60)
req = ("PUT %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"
       "Content-Type: application/octet-stream\r\nContent-Length: 1048576\r\n\r\n" % (path, hp, tok))
s.sendall(req.encode() + b"\x1f\x8b\x08\x00")
s.shutdown(socket.SHUT_WR)
data = b""
try:
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
except Exception as e:  # a reset is an answer too
    data += ("<%s>" % type(e).__name__).encode()
print(data.decode("latin-1").split("\r\n")[0] or "<no response>")
body = data.decode("latin-1").split("\r\n\r\n", 1)
print(body[1][:200] if len(body) > 1 else "")
PY
)"
status="$(echo "$resp" | head -1)"
note "short body PUT: ${status} | $(echo "$resp" | sed -n 2p | head -c 160)"
echo "$status" | grep -q ' 408' || fail_g "a body shorter than its Content-Length answered '${status}', expected 408"
rows="$(psql_q "SELECT count(*) FROM artifacts WHERE path LIKE '%pid${SUF}%' AND is_deleted = false")"
note "artifact rows for the truncated package: ${rows}"
[ "$rows" = "0" ] || fail_g "the truncated upload left ${rows} artifact row(s)"
finish_case "#4329 short body failed"

# =============================================================================
begin_test "FIX #4333: a real 'conan remove' of the binaries, then of the recipe, against the local repository"
reset_case
out="$(cx 120 "conan remove 'dtf-c11/1.0:*' -r ak -c 2>&1 | tail -4")"; rc=$?
nb="$(curl -s -H "Authorization: Bearer $TOK" "$BASE$C/dtf-c11/1.0/_/_/revisions/${RREV}/search" | jq 'length' 2>/dev/null)"
cl="$(api "$W/rl1" GET "$C/dtf-c11/1.0/_/_/latest")"
note "conan remove ref:* rc ${rc}: $(echo "$out" | tail -1); package search now ${nb:-?} entr(y/ies); recipe /latest ${cl}"
[ "$rc" -eq 0 ] || fail_g "conan remove of the binaries failed"
[ "${nb:-x}" = "0" ] || fail_g "the binaries are still listed after conan remove (${nb})"
[ "$cl" = "200" ] || fail_g "removing the binaries also removed the recipe (/latest ${cl})"
out="$(cx 120 "conan remove 'dtf-c11/1.0' -r ak -c 2>&1 | tail -4")"; rc=$?
cl="$(api "$W/rl2" GET "$C/dtf-c11/1.0/_/_/latest")"
live="$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${REPO}' AND a.path LIKE '%dtf-c11%' AND a.is_deleted = false")"
note "conan remove ref rc ${rc}: $(echo "$out" | tail -1); recipe /latest ${cl}; live dtf-c11 rows ${live}"
[ "$rc" -eq 0 ] || fail_g "conan remove of the recipe failed"
[ "$cl" = "404" ] || fail_g "the recipe still resolves after conan remove (/latest ${cl})"
[ "$live" = "0" ] || fail_g "${live} live dtf-c11 artifact row(s) remain after conan remove"
out="$(cx 60 "conan list 'dtf-c11/1.0' -r ak --format=json 2>&1")"
echo "$out" | grep -q "$RREV" && fail_g "conan list -r ak still shows revision ${RREV}"
finish_case "#4333 conan remove failed"

end_suite
