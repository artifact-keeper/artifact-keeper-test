#!/usr/bin/env bash
# =============================================================================
# tiers/pacman-hosted/oracle.sh
#   #3343 hosted Arch Linux pacman repositories: upload, {repo}.db and
#         {repo}.files rendered on demand, .sig / %PGPSIG%, signed databases,
#         DELETE; driven by the real pacman in profiles/client.pacman.yml
#   #4424 {repo}.files reflects a publish and a delete on the next request
# See the manifest for the behaviour, the primitives and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
CLIENT="ak-dtf${DTF_SLOT}-client-pacman"
INT="http://backend:8080"     # the backend as the client container sees it

jqr(){ jq -r "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

auth(){ printf 'Authorization: Bearer %s' "$TOK"; }
# cx <bash script>: run in the pacman client container. Output on stdout;
# always returns 0 (common.sh runs under errexit and every assertion below
# reads the output, never the status).
cx(){ docker exec -i -e AKU=admin -e AKP="$ADMIN_PASS" "$CLIENT" bash -c "$1" 2>&1 || true; }
# put_pkg <repo> <file in /work/out> -> HTTP status of the upload from the client
put_pkg(){
  cx "curl -s -o /work/put.o -w '%{http_code}' -u \"\$AKU:\$AKP\" -T /work/out/$2 ${INT}/pacman/$1/$2" || true
}
# conf <section> <repo> <SigLevel>: a pacman.conf naming ONLY this AK repo.
conf(){
  cx "cat > /work/$1.conf <<'C'
[options]
Architecture = auto
SigLevel = $3
LocalFileSigLevel = Optional
DisableSandbox
CacheDir = /work/cache-$1/
[$1]
Server = ${INT}/pacman/$2/\$arch
C
mkdir -p /work/cache-$1 /work/db-$1" >/dev/null || true
}
pm(){ # <section> <pacman args...>
  local s="$1"; shift
  cx "pacman --config /work/${s}.conf --dbpath /work/db-${s} --noconfirm $*" || true
}

# =============================================================================
begin_suite "pacman-hosted"

begin_test "setup: admin login, packages built in the archlinux client, unsigned and gpg-signed pacman repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(docker inspect -f '{{.State.Running}}' "$CLIENT" 2>/dev/null || true)" != "true" ]; then
  infra_fail "pacman client container ${CLIENT} is not running (profiles/client.pacman.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
P="pac-${SUF}"     # unsigned hosted repo
PS="pacs-${SUF}"   # hosted repo with a gpg signing key attached
SETUP_ERR=""
# Packages are built the way makepkg lays them out (.MTREE, .PKGINFO, files),
# with bsdtar from the client image: no makepkg/fakeroot, nothing installed.
# shellcheck disable=SC2016  # the script runs in the client container
build_out="$(cx '
set -e
mkdir -p /work/out
mk(){ # name ver arch file
  d=$(mktemp -d); mkdir -p "$d/usr/share/$1"
  echo "$1 $2 dtf" > "$d/usr/share/$1/$4"
  cat > "$d/.PKGINFO" <<P
pkgname = $1
pkgbase = $1
pkgver = $2
pkgdesc = DTF fixture $1
url = https://example.invalid/$1
builddate = 1700000000
packager = DTF <dtf@example.invalid>
size = 64
arch = $3
license = MIT
P
  ( cd "$d" && bsdtar -czf .MTREE --format=mtree --options="!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link" .PKGINFO usr \
      && bsdtar --zstd -cf "/work/out/$1-$2-$3.pkg.tar.zst" .MTREE .PKGINFO usr )
}
mk dtf-hello 1.0-1 any hello.txt
mk dtf-extra 1.0-1 any extra.txt
mk dtf-tool 1.0-1 x86_64 tool.txt
cp /work/out/dtf-hello-1.0-1-any.pkg.tar.zst /work/out/dtf-misnamed-9.9-1-any.pkg.tar.zst
# A package-signing key of our own, for %PGPSIG% and SigLevel = Required.
export GNUPGHOME=/work/pkgkey; mkdir -p -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase "" --quick-gen-key "DTF packager <dtf@example.invalid>" ed25519 sign never
gpg --batch --quiet --detach-sign /work/out/dtf-hello-1.0-1-any.pkg.tar.zst
gpg --batch --quiet --detach-sign /work/out/dtf-tool-1.0-1-x86_64.pkg.tar.zst
gpg --batch --armor --export > /work/pkgkey.asc
gpg --batch --with-colons --list-keys | awk -F: "/^fpr/{print \$10; exit}" > /work/pkgkey.fpr
ls /work/out
')"
for f in dtf-hello-1.0-1-any.pkg.tar.zst dtf-extra-1.0-1-any.pkg.tar.zst dtf-tool-1.0-1-x86_64.pkg.tar.zst \
         dtf-hello-1.0-1-any.pkg.tar.zst.sig dtf-tool-1.0-1-x86_64.pkg.tar.zst.sig; do
  case "$build_out" in *"$f"*) ;; *) SETUP_ERR="${SETUP_ERR} build:${f}";; esac
done
mk(){ # <key> -> key
  curl -s -X POST "$BASE/api/v1/repositories" -H "$(auth)" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" '{key:$k,name:$k,format:"pacman",repo_type:"local",is_public:true}')" | jqr '.key // empty'
}
MK_P="$(mk "$P")"; MK_PS="$(mk "$PS")"
note "create ${P} -> '${MK_P}', ${PS} -> '${MK_PS}'"
# The signing key: POST /api/v1/signing/keys (key_type gpg) attached with
# POST /api/v1/signing/repositories/{uuid}/config (the signing tier's contract).
# Only meaningful when the pacman format exists; on 1.10.0 the FIX cases go red.
SIGN_OK=0
if [ "$MK_PS" = "$PS" ]; then
  kid="$(curl -s -X POST "$BASE/api/v1/signing/keys" -H "$(auth)" -H 'Content-Type: application/json' \
    -d "{\"name\":\"pacman-${SUF}\",\"key_type\":\"gpg\",\"algorithm\":\"rsa4096\"}" | jqr '.id // empty')"
  ruuid="$(curl -s -H "$(auth)" "$BASE/api/v1/repositories/${PS}" | jqr '.id // empty')"
  ac="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/signing/repositories/${ruuid}/config" -H "$(auth)" \
    -H 'Content-Type: application/json' -d "{\"signing_key_id\":\"${kid}\",\"sign_metadata\":true}" || true)"
  note "signing key ${kid:-?} attached to ${PS} (${ruuid:-?}) -> ${ac}"
  [ -n "$kid" ] && [ "$ac" = "200" ] && SIGN_OK=1
  [ "$SIGN_OK" = "1" ] || SETUP_ERR="${SETUP_ERR} signing-key"
fi
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}" "$DETAIL
${build_out}"; end_suite; fi
pass

# =============================================================================
# CONTROLS (both images): the client and the fixtures are sound, so a red
# below is the server's.
# =============================================================================
begin_test "CONTROL: the fixture package is a valid pacman package (pacman -Qip reads it; pacman -U installs it from the file)"
reset_case
# A copy without the adjacent .sig: pacman -U would otherwise insist on verifying it.
out="$(cx 'mkdir -p /work/plain /work/db-local; cp /work/out/dtf-hello-1.0-1-any.pkg.tar.zst /work/plain/; pacman -Qip /work/plain/dtf-hello-1.0-1-any.pkg.tar.zst 2>/dev/null | sed -n "1,3p"; pacman -U --noconfirm --dbpath /work/db-local /work/plain/dtf-hello-1.0-1-any.pkg.tar.zst >/dev/null 2>&1 && cat /usr/share/dtf-hello/hello.txt; pacman -R --noconfirm --dbpath /work/db-local dtf-hello >/dev/null 2>&1; test ! -e /usr/share/dtf-hello/hello.txt && echo removed')"
note "$(printf '%s' "$out" | tr '\n' '|')"
case "$out" in *"dtf-hello"*"1.0-1"*) ;; *) fail_g "pacman -Qip does not read the fixture";; esac
case "$out" in *"dtf-hello 1.0-1 dtf"*) ;; *) fail_g "pacman -U did not install the fixture's file";; esac
case "$out" in *removed*) ;; *) fail_g "pacman -R did not remove it again";; esac
finish_case "the pacman fixture or client is broken (tier would be hollow)"

begin_test "CONTROL: the client container reaches the backend"
reset_case
h="$(cx "curl -s -o /dev/null -w '%{http_code}' ${INT}/health" || true)"
note "GET ${INT}/health from ${CLIENT} -> ${h}"
[ "$h" = "200" ] || fail_g "the client cannot reach the backend (${h})"
finish_case "client network broken"

# =============================================================================
# FIX #3343
# =============================================================================
begin_test "FIX #3343: upload a package and its .sig; a misnamed package is 400 and a re-upload 409"
reset_case
c_pkg="$(put_pkg "$P" dtf-hello-1.0-1-any.pkg.tar.zst)"
c_sig="$(put_pkg "$P" dtf-hello-1.0-1-any.pkg.tar.zst.sig)"
c_tool="$(put_pkg "$P" dtf-tool-1.0-1-x86_64.pkg.tar.zst)"
c_bad="$(put_pkg "$P" dtf-misnamed-9.9-1-any.pkg.tar.zst)"; bad_body="$(cx 'head -c 200 /work/put.o')"
c_dup="$(put_pkg "$P" dtf-hello-1.0-1-any.pkg.tar.zst)"
note "package ${c_pkg}; sig ${c_sig}; tool ${c_tool}; misnamed ${c_bad} '${bad_body}'; duplicate ${c_dup}"
[ "$c_pkg" = "201" ] || fail_g "package upload answered ${c_pkg} (1.10.0 has no /pacman route)"
[ "$c_sig" = "201" ] || fail_g "signature upload answered ${c_sig}"
[ "$c_tool" = "201" ] || fail_g "x86_64 package upload answered ${c_tool}"
[ "$c_bad" = "400" ] || fail_g "a filename that disagrees with .PKGINFO answered ${c_bad}, expected 400"
[ "$c_dup" = "409" ] || fail_g "re-uploading the same package answered ${c_dup}, expected 409"
finish_case "pacman upload"

begin_test "FIX #3343: {repo}.db lists both packages with %FILENAME%, %SHA256SUM% and the uploaded signature as %PGPSIG%"
reset_case
out="$(cx "set -e; cd /work; curl -sf -o p.db ${INT}/pacman/${P}/x86_64/dtfp.db; bsdtar -tf p.db | sort | tr '\n' ' '; echo; bsdtar -xOf p.db 'dtf-hello-1.0-1/desc'; echo ===; base64 -w0 out/dtf-hello-1.0-1-any.pkg.tar.zst.sig; echo; sha256sum out/dtf-hello-1.0-1-any.pkg.tar.zst" || true)"
note "$(printf '%s' "$out" | head -n 1)"
desc="$(printf '%s\n' "$out" | sed -n '2,/^===$/p')"
sig_b64="$(printf '%s\n' "$out" | sed -n '/^===$/{n;p;}')"
pkg_sha="$(printf '%s\n' "$out" | tail -n 1 | awk '{print $1}')"
case "$out" in *"dtf-hello-1.0-1/desc"*"dtf-tool-1.0-1/desc"*) ;; *) fail_g "the database does not list dtf-hello and dtf-tool";; esac
printf '%s\n' "$desc" | grep -qx 'dtf-hello-1.0-1-any.pkg.tar.zst' || fail_g "%FILENAME% is not the uploaded file name"
printf '%s\n' "$desc" | grep -qx "${pkg_sha:-none}" || fail_g "%SHA256SUM% is not the package's sha256 (${pkg_sha:-?})"
if [ -n "$sig_b64" ] && printf '%s\n' "$desc" | grep -qxF "$sig_b64"; then :; else fail_g "%PGPSIG% does not carry the uploaded signature"; fi
note "desc: $(printf '%s' "$desc" | tr '\n' ' ' | head -c 400)"
finish_case "pacman .db rendering"

begin_test "FIX #3343: the real pacman -Sy / -S installs from the repository and pacman -F finds its file"
reset_case
# No signature policy here: the signed path is the last case, with its own keyring.
conf dtfp "$P" "Never"
out="$(pm dtfp -Syy; pm dtfp -S dtf-hello; cx 'cat /usr/share/dtf-hello/hello.txt'; pm dtfp -Fyy; pm dtfp -F usr/share/dtf-tool/tool.txt; pm dtfp -Fl dtf-hello)"
note "$(printf '%s' "$out" | tail -n 12 | tr '\n' '|')"
case "$out" in *"dtf-hello 1.0-1 dtf"*) ;; *) fail_g "pacman -S did not install dtf-hello from ${P}";; esac
case "$out" in *"dtfp/dtf-tool 1.0-1"*) ;; *) fail_g "pacman -F did not attribute usr/share/dtf-tool/tool.txt to dtfp/dtf-tool";; esac
case "$out" in *"dtf-hello usr/share/dtf-hello/hello.txt"*) ;; *) fail_g "pacman -Fl dtf-hello does not list its file";; esac
finish_case "pacman client against a hosted repository"

# =============================================================================
# FIX #4424: .files follows the package set.
# =============================================================================
begin_test "FIX #4424: a publish appears in {repo}.files on the next request, and a DELETE removes it from .db and .files"
reset_case
c_ex="$(put_pkg "$P" dtf-extra-1.0-1-any.pkg.tar.zst)"
after_pub="$(pm dtfp -Fyy; pm dtfp -Fl dtf-extra)"
d_code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$(auth)" "$BASE/pacman/${P}/x86_64/dtf-extra-1.0-1-any.pkg.tar.zst" || true)"
after_del="$(pm dtfp -Fyy; pm dtfp -Fl dtf-extra; cx "curl -sf ${INT}/pacman/${P}/x86_64/dtfp.db | bsdtar -tf - | sort | tr '\n' ' '")"
note "upload ${c_ex}; after publish: $(printf '%s' "$after_pub" | tail -n 2 | tr '\n' '|')"
note "DELETE ${d_code}; after delete: $(printf '%s' "$after_del" | tail -n 3 | tr '\n' '|')"
[ "$c_ex" = "201" ] || fail_g "dtf-extra upload answered ${c_ex}"
case "$after_pub" in *"dtf-extra usr/share/dtf-extra/extra.txt"*) ;; *) fail_g "the .files database did not pick up dtf-extra after it was published";; esac
[ "$d_code" = "204" ] || fail_g "DELETE /pacman/${P}/x86_64/dtf-extra-... answered ${d_code}, expected 204"
case "$after_del" in *"dtf-extra usr/share"*) fail_g "the .files database still lists dtf-extra after the DELETE";; esac
case "$after_del" in *"dtf-extra-1.0-1/"*) fail_g "the .db still lists dtf-extra after the DELETE";; esac
case "$after_del" in *"dtf-hello-1.0-1/"*) ;; *) fail_g "the .db lost dtf-hello (the delete removed the wrong package)";; esac
finish_case ".files does not follow the package set"

# =============================================================================
# FIX #3343: signed repositories.
# =============================================================================
begin_test "FIX #3343: a repository with a signing key serves a .db.sig that verifies against gpg-key.asc, and pacman runs with SigLevel = Required"
reset_case
c1="$(put_pkg "$PS" dtf-tool-1.0-1-x86_64.pkg.tar.zst)"
c2="$(put_pkg "$PS" dtf-tool-1.0-1-x86_64.pkg.tar.zst.sig)"
ver="$(cx "set -e; cd /work; curl -sf -o ps.db ${INT}/pacman/${PS}/x86_64/dtfs.db; curl -sf -o ps.db.sig ${INT}/pacman/${PS}/x86_64/dtfs.db.sig; curl -sf -o ak.asc ${INT}/pacman/${PS}/gpg-key.asc; mkdir -p -m 700 /work/verify; gpg --homedir /work/verify --batch --quiet --import ak.asc; gpg --homedir /work/verify --batch --status-fd 1 --verify ps.db.sig ps.db 2>/dev/null | grep -E 'GOODSIG|BADSIG|ERRSIG' || true" || true)"
unsigned_sig="$(cx "curl -s -o /dev/null -w '%{http_code}' ${INT}/pacman/${P}/x86_64/dtfp.db.sig" || true)"
note "uploads ${c1}/${c2}; gpg: ${ver:-<nothing>}; unsigned repo .db.sig -> ${unsigned_sig}"
case "$ver" in *GOODSIG*) ;; *) fail_g "dtfs.db.sig does not verify against the repository's gpg-key.asc";; esac
[ "$unsigned_sig" = "404" ] || fail_g "a repository without a signing key answered ${unsigned_sig} for .db.sig, expected 404"
# pacman's own keyring trusts exactly two keys: the repository's and our packager's.
# shellcheck disable=SC2016  # the script runs in the client container
kr="$(cx 'set -e; pacman-key --init >/dev/null 2>&1; for k in /work/ak.asc /work/pkgkey.asc; do pacman-key --add "$k" >/dev/null 2>&1; done
for f in $(gpg --with-colons --import-options show-only --import /work/ak.asc 2>/dev/null | awk -F: "/^fpr/{print \$10; exit}") $(cat /work/pkgkey.fpr); do pacman-key --lsign-key "$f" >/dev/null 2>&1 && echo "lsigned $f"; done' || true)"
note "$(printf '%s' "$kr" | tr '\n' ' ')"
conf dtfs "$PS" "Required"
out="$(pm dtfs -Syy; pm dtfs -S dtf-tool; cx 'cat /usr/share/dtf-tool/tool.txt')"
note "$(printf '%s' "$out" | tail -n 8 | tr '\n' '|')"
case "$out" in *"dtf-tool 1.0-1 dtf"*) ;; *) fail_g "pacman with SigLevel = Required did not install dtf-tool from ${PS}";; esac
# Not hollow: the same Required policy refuses the unsigned repository.
conf dtfu "$P" "Required"
neg="$(pm dtfu -Syy)"
note "SigLevel = Required against the unsigned ${P}: $(printf '%s' "$neg" | tail -n 2 | tr '\n' '|')"
case "$neg" in *"error"*) ;; *) fail_g "SigLevel = Required accepted the unsigned repository's database (the signed case would be hollow)";; esac
finish_case "signed pacman repository"

end_suite
