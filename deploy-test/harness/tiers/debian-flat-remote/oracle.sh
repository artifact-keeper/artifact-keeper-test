#!/usr/bin/env bash
# =============================================================================
# tiers/debian-flat-remote/oracle.sh
#   #4619 a Debian remote mirrors a FLAT APT repository (`deb <uri> /`):
#         InRelease/Release/Release.gpg byte-for-byte from the repository root,
#         indices checked against the signed Release, a real apt-get install
#         through the flat sources line; `debian.flat_repository = true`
#         answers dists/ with 404 and the sources line without contacting
#         upstream, and an unset remote over a flat upstream does the same
#   #4216 a hosted RPM repository with repodata_depth = 1 serves independent
#         YUM metadata per first-level directory; a real dnf install reads it
# See the manifest for THE BUGS, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, TRIVY_PORT (mock-files control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit. A client command that fails is an observation
# this oracle records and judges, never a reason to abort.
set +e

BASE="$BASE_URL"
ADMIN="${ADMIN_USER:-admin}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
MOCK_INT="http://172.16.${DTF_SLOT}.76"   # the address the BACKEND reaches mock-files at
CAPT="ak-dtf${DTF_SLOT}-client-apt"
CDNF="ak-dtf${DTF_SLOT}-client-dnf"
INT="http://backend:8080"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
size_of(){ wc -c < "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mk_repo(){ # <json body> -> key (empty on failure); body echoed to $W/mk.out
  curl -s --max-time 30 -o "$W/mk.out" -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$1" || true
  jqr '.key // empty' < "$W/mk.out"
}
mock_put(){ # <path> <file> -> http code
  curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X PUT --data-binary "@$2" "${MOCK}/__file?path=$1" || true
}
mock_gets(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get'; }
get(){ curl -s --max-time 60 -o "$2" -w '%{http_code}' -H "Authorization: Bearer $TOK" "$BASE$1" || true; }

# =============================================================================
begin_suite "debian-flat-remote"

begin_test "setup: admin login, a signed flat APT repository on the mock upstream, client containers"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN}\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock-files not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${RUN_ID##*-}"
DEB="dtf-flat_1.0-${SUF}_all.deb"
# 1. The .deb, built by the real dpkg-deb in the Debian client (umask: see
#    profiles/client.apt.yml).
out="$(docker exec "$CAPT" bash -c "set -e; umask 0022
rm -rf /tmp/pkg && mkdir -p /tmp/pkg/DEBIAN /tmp/pkg/usr/share/dtf-flat
echo 'DTF-FLAT-${SUF}' > /tmp/pkg/usr/share/dtf-flat/marker.txt
printf 'Package: dtf-flat\nVersion: 1.0-${SUF}\nArchitecture: all\nMaintainer: DTF <dtf@example.invalid>\nDescription: DTF flat repository marker\n' > /tmp/pkg/DEBIAN/control
dpkg-deb --root-owner-group --build /tmp/pkg /tmp/${DEB} >/dev/null" 2>&1)" \
  && docker cp "${CAPT}:/tmp/${DEB}" "$W/${DEB}" >/dev/null 2>&1
[ -s "$W/${DEB}" ] || { infra_fail "dpkg-deb build in ${CAPT} failed" "$out"; end_suite; }
# 2. Packages / Packages.gz / Release, signed with an ephemeral ed25519 key
#    into InRelease and Release.gpg (host gpg, throwaway GNUPGHOME).
python3 -I - "$W" "$DEB" "$SUF" <<'PY'
import gzip, hashlib, os, sys, time
w, deb, suf = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(os.path.join(w, deb), "rb").read()
pk = ("Package: dtf-flat\nVersion: 1.0-%s\nArchitecture: all\nMaintainer: DTF <dtf@example.invalid>\n"
      "Filename: ./%s\nSize: %d\nSHA256: %s\nDescription: DTF flat repository marker\n\n"
      % (suf, deb, len(data), hashlib.sha256(data).hexdigest())).encode()
open(os.path.join(w, "Packages"), "wb").write(pk)
gz = gzip.compress(pk, mtime=0)
open(os.path.join(w, "Packages.gz"), "wb").write(gz)
rel = "Origin: DTF\nLabel: DTF flat\nDate: %s\nSHA256:\n" % time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())
for name, body in (("Packages", pk), ("Packages.gz", gz)):
    rel += " %s %d %s\n" % (hashlib.sha256(body).hexdigest(), len(body), name)
open(os.path.join(w, "Release"), "w").write(rel)
PY
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
add_exit_handler "rm -rf \"$GNUPGHOME\""
gpg --batch --quiet --passphrase '' --quick-gen-key "DTF flat <dtf-flat@example.invalid>" ed25519 sign never >/dev/null 2>&1
gpg --batch --quiet --yes --clearsign -o "$W/InRelease" "$W/Release" 2>/dev/null
gpg --batch --quiet --yes -abs -o "$W/Release.gpg" "$W/Release" 2>/dev/null
gpg --batch --quiet --yes --export -o "$W/dtf-flat.gpg" 2>/dev/null
[ -s "$W/InRelease" ] && [ -s "$W/Release.gpg" ] && [ -s "$W/dtf-flat.gpg" ] \
  || { infra_fail "could not sign the flat repository with an ephemeral gpg key"; end_suite; }
SETUP_ERR=""
for f in InRelease Release Release.gpg Packages Packages.gz "$DEB"; do
  [ "$(mock_put "/flat/${f}" "$W/${f}")" = "200" ] || SETUP_ERR="${SETUP_ERR} mock:/flat/${f}"
done
# A conventional dists/ layout on another prefix, for the control.
printf 'Origin: DTF\nSuite: stable\nCodename: stable\nComponents: main\nArchitectures: amd64\n' > "$W/std-Release"
[ "$(mock_put "/std/dists/stable/Release" "$W/std-Release")" = "200" ] || SETUP_ERR="${SETUP_ERR} mock:/std"
R_FLAT="dflat-${SUF}"; R_CONF="dconf-${SUF}"; R_STD="dstd-${SUF}"
[ "$(mk_repo "$(jq -n --arg k "$R_FLAT" --arg u "${MOCK_INT}/flat/" '{key:$k,name:$k,format:"debian",repo_type:"remote",is_public:true,upstream_url:$u}')")" = "$R_FLAT" ] \
  || SETUP_ERR="${SETUP_ERR} ${R_FLAT}:$(head -c 160 "$W/mk.out")"
[ "$(mk_repo "$(jq -n --arg k "$R_STD" --arg u "${MOCK_INT}/std/" '{key:$k,name:$k,format:"debian",repo_type:"remote",is_public:true,upstream_url:$u}')")" = "$R_STD" ] \
  || SETUP_ERR="${SETUP_ERR} ${R_STD}:$(head -c 160 "$W/mk.out")"
for ctr in "$CAPT" "$CDNF"; do
  [ "$(docker inspect -f '{{.State.Running}}' "$ctr" 2>/dev/null)" = "true" ] || SETUP_ERR="${SETUP_ERR} container:${ctr}"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- flat upstream ${MOCK_INT}/flat/ (${DEB}); remotes ${R_FLAT}, ${R_STD}"
pass

# =============================================================================
begin_test "CONTROL: a Debian remote proxies a dists/<suite> Release from its upstream byte-for-byte"
reset_case
c="$(get "/debian/${R_STD}/dists/stable/Release" "$W/std.got")"
note "GET dists/stable/Release through ${R_STD}: ${c}"
[ "$c" = "200" ] || fail_g "dists/stable/Release answered ${c}"
[ "$(sha_of "$W/std.got")" = "$(sha_of "$W/std-Release")" ] || fail_g "the proxied Release differs from the upstream bytes"
finish_case "dists-layout remote control failed"

begin_test "FIX #4619: the flat layout is served from the repository root: release documents byte-for-byte, indices verified against Release"
reset_case
for f in InRelease Release Release.gpg Packages.gz; do
  c="$(get "/debian/${R_FLAT}/${f}" "$W/got.${f}")"
  same="no"; [ "$(sha_of "$W/got.${f}")" = "$(sha_of "$W/${f}")" ] && same="yes"
  note "GET /debian/${R_FLAT}/${f}: ${c}, identical to upstream: ${same}"
  [ "$c" = "200" ] || fail_g "${f} answered ${c}, expected 200"
  [ "$same" = "yes" ] || fail_g "${f} is not the upstream bytes"
done
# An index whose bytes do not match the signed Release is refused (Tier A).
# The tampered body replaces the upstream `Packages` that Release lists; the
# original is restored afterwards so apt sees an intact repository.
printf 'Package: tampered\n\n' > "$W/Packages.bad"
mock_put "/flat/Packages" "$W/Packages.bad" >/dev/null
c="$(get "/debian/${R_FLAT}/Packages" "$W/got.bad")"
note "GET Packages (upstream bytes tampered, signed Release lists the real hash): ${c}"
[ "$c" = "502" ] || fail_g "an index that does not match the signed Release answered ${c}, expected 502"
grep -q 'tampered' "$W/got.bad" && fail_g "the tampered index bytes were served"
mock_put "/flat/Packages" "$W/Packages" >/dev/null
# Only APT paths are proxied.
mock_put "/flat/robots.txt" "$W/Release" >/dev/null
c="$(get "/debian/${R_FLAT}/robots.txt" "$W/got.robots")"; n="$(mock_gets /flat/robots.txt)"
note "GET robots.txt (not an APT path): ${c}; upstream GETs ${n}"
[ "$c" = "404" ] || fail_g "a non-APT path answered ${c}, expected 404"
[ "${n:-0}" = "0" ] || fail_g "a non-APT path was fetched from the upstream (${n})"
finish_case "#4619 flat root documents failed"

begin_test "FIX #4619: a real 'apt-get install' through 'deb [signed-by=<key>] <base>/debian/<repo>/ /' verifies and installs"
reset_case
docker cp "$W/dtf-flat.gpg" "${CAPT}:/tmp/dtf-flat.gpg" >/dev/null 2>&1
out="$(docker exec "$CAPT" bash -c "set -e
install -d -m 0755 /etc/apt/keyrings && install -m 0644 /tmp/dtf-flat.gpg /etc/apt/keyrings/dtf-flat.gpg
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
echo 'deb [signed-by=/etc/apt/keyrings/dtf-flat.gpg] ${INT}/debian/${R_FLAT}/ /' > /etc/apt/sources.list.d/dtf-flat.list
timeout 120 apt-get update 2>&1 | tail -6
timeout 120 apt-get -y install dtf-flat 2>&1 | tail -3
cat /usr/share/dtf-flat/marker.txt" 2>&1)"; rc=$?
note "apt rc ${rc}:"; note "$(echo "$out" | tail -8)"
[ "$rc" -eq 0 ] || fail_g "apt-get update / install through the flat sources line failed"
echo "$out" | grep -q "DTF-FLAT-${SUF}" || fail_g "the installed package does not carry the marker"
echo "$out" | grep -qiE 'NO_PUBKEY|not signed|BADSIG' && fail_g "apt reported a signature problem"
# Tier B: the package matched the SHA-256 its cached Packages records, so it
# is cached; the next fetch does not reach the upstream.
before="$(mock_gets "/flat/${DEB}")"
hit=0
for _i in $(seq 1 20); do
  get "/debian/${R_FLAT}/${DEB}" "$W/deb.again" >/dev/null
  [ "$(mock_gets "/flat/${DEB}")" = "$before" ] && [ "$(sha_of "$W/deb.again")" = "$(sha_of "$W/${DEB}")" ] && { hit=1; break; }
  before="$(mock_gets "/flat/${DEB}")"; sleep 0.5
done
note "package re-fetch served from the cache: ${hit} (upstream GETs ${before})"
[ "$hit" = 1 ] || fail_g "the verified package was never served from the cache"
finish_case "#4619 real apt install failed"

begin_test "FIX #4619: dists/ on a flat upstream answers 404 naming the flat sources line (unset: detected; flat_repository=true: without contacting upstream)"
reset_case
c="$(get "/debian/${R_FLAT}/dists/stable/InRelease" "$W/auto.out")"
note "unset remote, GET dists/stable/InRelease: ${c} $(head -c 200 "$W/auto.out")"
[ "$c" = "404" ] || fail_g "dists/ on a flat upstream answered ${c}, expected 404"
grep -q "/debian/${R_FLAT}/ /" "$W/auto.out" || fail_g "the 404 does not give the flat sources line"
key="$(mk_repo "$(jq -n --arg k "$R_CONF" --arg u "${MOCK_INT}/flat/" '{key:$k,name:$k,format:"debian",repo_type:"remote",is_public:true,upstream_url:$u,debian:{flat_repository:true}}')")"
note "create ${R_CONF} with debian.flat_repository=true: ${key:-$(head -c 160 "$W/mk.out")}"
if [ "$key" != "$R_CONF" ]; then
  fail_g "a Debian remote with debian.flat_repository=true could not be created"
else
  fr="$(curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/${R_CONF}" | jqr '.debian.flat_repository')"
  note "GET repository: debian.flat_repository=${fr}"
  [ "$fr" = "true" ] || fail_g "the repository does not report debian.flat_repository=true (${fr})"
  n0="$(mock_gets /flat/dists/stable/Release)"
  c="$(get "/debian/${R_CONF}/dists/stable/Release" "$W/conf.out")"
  n1="$(mock_gets /flat/dists/stable/Release)"
  note "configured remote, GET dists/stable/Release: ${c} $(head -c 160 "$W/conf.out"); upstream GETs ${n0} -> ${n1}"
  [ "$c" = "404" ] || fail_g "dists/ on a configured-flat remote answered ${c}, expected 404"
  grep -q "/debian/${R_CONF}/ /" "$W/conf.out" || fail_g "the 404 does not give the flat sources line"
  [ "$n0" = "$n1" ] || fail_g "the configured-flat remote contacted the upstream for dists/ (${n0} -> ${n1})"
  c="$(get "/debian/${R_CONF}/InRelease" "$W/conf.ir")"
  note "configured remote, GET InRelease: ${c}"
  [ "$c" = "200" ] && [ "$(sha_of "$W/conf.ir")" = "$(sha_of "$W/InRelease")" ] || fail_g "the configured-flat remote does not serve InRelease"
fi
finish_case "#4619 dists/ refusal failed"

# =============================================================================
# RPM repodata_depth
# =============================================================================
begin_test "setup: build two noarch RPMs in the Fedora client"
RPMA="dtf-dep-a-1.0-1.noarch.rpm"; RPMB="dtf-dep-b-1.0-1.noarch.rpm"; RPMC="dtf-dep-c-1.0-1.noarch.rpm"
# shellcheck disable=SC2016 # $n and %{buildroot} expand inside the container
out="$(timeout 420 docker exec "$CDNF" bash -c '
set -e
command -v rpmbuild >/dev/null || dnf -y -q install rpm-build >/dev/null
mkdir -p /root/rpmbuild/{SPECS,BUILD,RPMS,SOURCES,SRPMS}
for n in a b c; do
cat > /root/rpmbuild/SPECS/dtf-dep-$n.spec <<SPEC
Name: dtf-dep-$n
Version: 1.0
Release: 1
Summary: DTF repodata depth marker $n
License: MIT
BuildArch: noarch
%description
DTF repodata depth marker $n.
%install
mkdir -p %{buildroot}/usr/share/dtf-dep
echo "DTF-DEP-$n" > %{buildroot}/usr/share/dtf-dep/$n.txt
%files
/usr/share/dtf-dep/$n.txt
SPEC
rpmbuild -bb --quiet /root/rpmbuild/SPECS/dtf-dep-$n.spec >/dev/null
done
ls /root/rpmbuild/RPMS/noarch/' 2>&1)"
for r in "$RPMA" "$RPMB" "$RPMC"; do docker cp "${CDNF}:/root/rpmbuild/RPMS/noarch/${r}" "$W/${r}" >/dev/null 2>&1; done
if [ ! -s "$W/$RPMA" ] || [ ! -s "$W/$RPMB" ] || [ ! -s "$W/$RPMC" ]; then
  infra_fail "rpmbuild in ${CDNF} failed (egress or tooling)" "$(echo "$out" | tail -20)"; end_suite
fi
R_D0="rpm0-${SUF}"; R_D1="rpm1-${SUF}"
[ "$(mk_repo "$(jq -n --arg k "$R_D0" '{key:$k,name:$k,format:"rpm",repo_type:"local",is_public:true}')")" = "$R_D0" ] \
  || { infra_fail "could not create ${R_D0}"; end_suite; }
[ "$(mk_repo "$(jq -n --arg k "$R_D1" '{key:$k,name:$k,format:"rpm",repo_type:"local",is_public:true}')")" = "$R_D1" ] \
  || { infra_fail "could not create ${R_D1}"; end_suite; }
pass

dnf_from(){ # <baseurl> <package> -> output; rc in $DNF_RC
  DNF_RC=0
  DNF_OUT="$(timeout 180 docker exec "$CDNF" bash -c "set -e
rpm -e $2 >/dev/null 2>&1 || true
cat > /etc/yum.repos.d/dtf-dep.repo <<REPO
[dtf-dep]
name=DTF depth
baseurl=$1
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
dnf -y -q --disablerepo='*' --enablerepo=dtf-dep --refresh install $2 2>&1 | tail -4
rpm -q $2" 2>&1)" || DNF_RC=$?
}
primary_names(){ # <repo> <dir-prefix> -> sorted package names in that primary.xml.gz
  curl -s --max-time 30 "$BASE/rpm/$1/${2}repodata/primary.xml.gz" | gzip -dc 2>/dev/null \
    | grep -o '<name>[^<]*</name>' | sed 's/<[^>]*>//g' | sort | tr '\n' ',' | sed 's/,$//'
}

begin_test "CONTROL: a depth-0 hosted RPM repository serves root repodata and a real dnf install"
reset_case
c="$(curl -s --max-time 60 -o "$W/u0" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
  --upload-file "$W/$RPMC" "$BASE/rpm/${R_D0}/packages/${RPMC}" || true)"
note "PUT packages/${RPMC}: ${c}"
case "$c" in 2*) ;; *) fail_g "depth-0 upload answered ${c}";; esac
names="$(primary_names "$R_D0" "")"
note "root primary.xml.gz names: [${names}]"
[ "$names" = "dtf-dep-c" ] || fail_g "root primary lists [${names}], expected [dtf-dep-c]"
dnf_from "${INT}/rpm/${R_D0}/" dtf-dep-c
note "dnf install dtf-dep-c rc ${DNF_RC}: $(echo "$DNF_OUT" | tail -1)"
[ "$DNF_RC" -eq 0 ] || fail_g "dnf install from the depth-0 repository failed"
finish_case "depth-0 RPM control failed"

begin_test "FIX #4216: repodata_depth=1 is accepted on an empty local RPM repository and refused once it has artifacts"
reset_case
c="$(curl -s --max-time 30 -o "$W/p1" -w '%{http_code}' -X PATCH "$BASE/api/v1/repositories/${R_D1}" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"repodata_depth":1}' || true)"
dep="$(jqr '.repodata_depth' < "$W/p1")"; ed="$(jqr '.repodata_depth_editable' < "$W/p1")"
note "PATCH repodata_depth=1: ${c}; response repodata_depth=${dep}, editable=${ed}"
[ "$c" = "200" ] && [ "$dep" = "1" ] || fail_g "repodata_depth=1 was not applied (HTTP ${c}, repodata_depth=${dep})"
c="$(curl -s --max-time 30 -o "$W/p0" -w '%{http_code}' -X PATCH "$BASE/api/v1/repositories/${R_D0}" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"repodata_depth":1}' || true)"
note "PATCH repodata_depth=1 on the non-empty ${R_D0}: ${c} $(head -c 160 "$W/p0")"
case "$c" in 4*) ;; *) fail_g "changing repodata_depth on a repository with artifacts answered ${c}, expected a 4xx refusal";; esac
grep -q 'repodata_depth' "$W/p0" || fail_g "the refusal does not name repodata_depth"
finish_case "#4216 repodata_depth setting failed"

begin_test "FIX #4216: each first-level directory serves its own repodata; a real dnf install reads one of them"
reset_case
for spec in "a:$RPMA" "b:$RPMB"; do
  d="${spec%%:*}"; f="${spec#*:}"
  c="$(curl -s --max-time 60 -o "$W/u.$d" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    --upload-file "$W/$f" "$BASE/rpm/${R_D1}/${d}/${f}" || true)"
  note "PUT ${d}/${f}: ${c} $(head -c 120 "$W/u.$d")"
  case "$c" in 2*) ;; *) fail_g "upload to ${d}/ answered ${c}";; esac
done
na="$(primary_names "$R_D1" "a/")"; nb="$(primary_names "$R_D1" "b/")"
croot="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' "$BASE/rpm/${R_D1}/repodata/repomd.xml" || true)"
note "a/ primary: [${na}]; b/ primary: [${nb}]; root repodata/repomd.xml: ${croot}"
[ "$na" = "dtf-dep-a" ] || fail_g "a/repodata lists [${na}], expected only [dtf-dep-a]"
[ "$nb" = "dtf-dep-b" ] || fail_g "b/repodata lists [${nb}], expected only [dtf-dep-b]"
[ "$croot" = "404" ] || fail_g "the root repodata of a depth-1 repository answered ${croot}, expected 404"
dnf_from "${INT}/rpm/${R_D1}/a/" dtf-dep-a
note "dnf install dtf-dep-a from a/ rc ${DNF_RC}: $(echo "$DNF_OUT" | tail -1)"
[ "$DNF_RC" -eq 0 ] || fail_g "dnf install from ${R_D1}/a/ failed"
dnf_from "${INT}/rpm/${R_D1}/a/" dtf-dep-b
note "dnf install dtf-dep-b from a/ rc ${DNF_RC}: $(echo "$DNF_OUT" | tail -1)"
[ "$DNF_RC" -ne 0 ] || fail_g "dnf installed dtf-dep-b from a/, whose repodata must not list it"
finish_case "#4216 per-directory repodata failed"

end_suite
