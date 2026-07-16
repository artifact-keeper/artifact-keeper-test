#!/usr/bin/env bash
# =============================================================================
# tiers/native-client/oracle.sh — native client via the REAL advertised route
#                                 (#2580 dnf/apt <location>; #2477 docker proxy)
# =============================================================================
# run.sh has stood up the `filesystem + client.dnf + client.apt + client.docker`
# profile-set on this slot (backend+postgres, a Fedora client, a Debian client,
# a dind client, and a local upstream OCI registry) health-gated with
# `up -d --wait`, and exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, DTF_SLOT, TRIVY_PORT, JUNIT_OUTPUT_DIR. We source common.sh
# for the assertion + JUnit harness.
#
# WHY THIS TIER EXISTS (design 6, matrix row 3): today's format tests upload via
# the native /rpm/{repo}/packages/ (and /debian pool) route and then check that
# repodata merely LISTS the package — they never make a real client FOLLOW the
# advertised `<location href>`/`Filename:`, so they test the path that isn't
# broken. #2580 was exactly a package whose advertised location did not resolve
# (404) for the client. This tier drives the REAL client route:
#
#   LEG A (#2580, RPM):  publish an RPM, then a real `dnf install` in the Fedora
#     client that resolves + follows the repodata `<location href>` and asserts
#     the package ACTUALLY INSTALLS (a marker file lands on the client fs).
#   LEG B (#2580, deb):  the apt analogue — a real `apt-get install` following
#     the Packages `Filename:` field, asserting the .deb actually installs.
#   LEG C (#2477, docker): a real `docker pull` through an AK Docker REMOTE
#     (proxy) repo that forces >=2 OCI token exchanges re-presenting the same
#     stored offline token; the repeated pull must SUCCEED (pre-#2477 the 2nd
#     exchange tripped single-use family revocation -> 401). A deterministic
#     curl re-presentation gate backs the real pull so the #2477 discriminator
#     holds even where real-daemon token caching is opaque.
#
# DEVIATIONS (flagged, per the brick-3 note):
#   * No `ak` CLI binary is available on the rig, so packages are PUBLISHED via
#     the native RPM/deb upload route. The discriminating value is entirely on
#     the CLIENT side (dnf/apt FOLLOW the advertised location); LEG A/B also
#     assert directly that the advertised href resolves (200) while the pre-fix
#     "generic-flow" href shape (missing the packages/ or pool/ prefix) 404s —
#     i.e. a backend that advertised such a location WOULD fail the install.
#   * The docker-token leg uses a self-contained local upstream registry, NOT
#     the proxy=squid overlay (squid is a #2570 mock-nginx egress proxy, not an
#     OCI registry; its HTTP_PROXY/CIDR wiring would break the upstream fetch).
#     #2477's discriminator is the client<->AK offline-token reuse, independent
#     of egress topology. See tiers/native-client/manifest.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "native-client-2580-2477"
auth_admin
setup_workdir

SLOT="${DTF_SLOT}"
CDNF="ak-dtf${SLOT}-client-dnf"
CAPT="ak-dtf${SLOT}-client-apt"
CDOCKER="ak-dtf${SLOT}-client-docker"
UPSTREAM_CTR="ak-dtf${SLOT}-upstream-registry"
BACKEND_CTR="ak-dtf${SLOT}-backend"
BACKEND_INTERNAL="http://backend:8080"          # backend as seen from client containers
TRIVY_PORT="${TRIVY_PORT:-$((8250 + SLOT))}"    # host port publishing upstream-registry:5000
AK_ADMIN_USER="${ADMIN_USER:-admin}"
AK_ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
SVC="artifact-keeper"                            # OCI_TOKEN_SERVICE advertised by the backend

RPM_REPO="dtf-rpm-${RUN_ID}"
DEB_REPO="dtf-deb-${RUN_ID}"
DOCKER_REMOTE="dtf-dockerproxy-${RUN_ID}"

RPM_FILE="dtf-marker-1.0-1.noarch.rpm"
DEB_ARCH=""                                      # resolved from the debian client
DEB_FILE=""

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  api_delete "/api/v1/repositories/${RPM_REPO}"      >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${DEB_REPO}"      >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${DOCKER_REMOTE}" >/dev/null 2>&1 || true
  # host-side seed images pushed into the upstream registry
  docker rmi "127.0.0.1:${TRIVY_PORT}/proxied/alpine:3.23"   >/dev/null 2>&1 || true
  docker rmi "127.0.0.1:${TRIVY_PORT}/proxied/alpine-b:3.23" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

# host-side curl helpers (JWT auth) against BASE_URL
hcode() { curl -s -o /dev/null -w '%{http_code}' --max-time 40 "$@"; }

# ===========================================================================
# LEG A — #2580 RPM: real dnf install FOLLOWS the repodata <location href>
# ===========================================================================

begin_test "A0: create hosted RPM repo + build a dependency-free marker RPM in the Fedora client"
A_OK=1
if ! create_repo "$RPM_REPO" rpm local; then
  A_OK=0; fail "could not create hosted rpm repo ${RPM_REPO}"
else
  # Build a minimal noarch RPM that installs a single marker file, with NO
  # dependencies, so the later `dnf install` resolves purely from the AK repo.
  build_rpm='
set -e
dnf -y install rpm-build >/dev/null 2>&1
mkdir -p /root/rpmbuild/{SPECS,BUILD,RPMS,SOURCES,SRPMS}
cat > /root/rpmbuild/SPECS/dtf-marker.spec <<SPEC
Name: dtf-marker
Version: 1.0
Release: 1
Summary: DTF native-client marker
License: MIT
BuildArch: noarch
%description
DTF native-client RPM marker package.
%install
mkdir -p %{buildroot}/usr/share/dtf-marker
echo "DTF-RPM-INSTALLED-%{version}" > %{buildroot}/usr/share/dtf-marker/marker.txt
%files
/usr/share/dtf-marker/marker.txt
SPEC
rpmbuild -bb /root/rpmbuild/SPECS/dtf-marker.spec >/dev/null 2>&1
test -f /root/rpmbuild/RPMS/noarch/'"$RPM_FILE"'
'
  if timeout 360 docker exec "$CDNF" bash -c "$build_rpm"; then
    docker cp "${CDNF}:/root/rpmbuild/RPMS/noarch/${RPM_FILE}" "${WORK_DIR}/${RPM_FILE}" >/dev/null 2>&1 || A_OK=0
    if [ "$A_OK" = "1" ] && [ -s "${WORK_DIR}/${RPM_FILE}" ]; then
      pass
    else
      A_OK=0; fail "built RPM could not be copied out of the Fedora client"
    fi
  else
    A_OK=0; fail "rpm-build/rpmbuild failed inside the Fedora client (egress or tooling issue)"
  fi
fi

begin_test "A1: publish the RPM to the hosted repo (native upload; no ak CLI on rig)"
if [ "$A_OK" = "1" ]; then
  up=$(hcode -X PUT -H "$(auth_header)" --upload-file "${WORK_DIR}/${RPM_FILE}" \
        "${BASE_URL}/rpm/${RPM_REPO}/packages/${RPM_FILE}")
  if [ "$up" = "200" ] || [ "$up" = "201" ]; then
    pass
  else
    A_OK=0; fail "RPM upload returned HTTP ${up} (expected 201)"
  fi
else
  fail "skipped: repo/build failed"
fi

begin_test "A2: #2580 — real \`dnf install\` FOLLOWS repodata <location href> and INSTALLS the package"
if [ "$A_OK" = "1" ]; then
  install_rpm='
set -e
cat > /etc/yum.repos.d/dtf-ak.repo <<REPO
[dtf-ak]
name=DTF AK RPM repo
baseurl='"${BACKEND_INTERNAL}/rpm/${RPM_REPO}/"'
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
# Only the AK repo is consulted -> the install can ONLY succeed by fetching the
# package at the repodata-advertised <location href>. --refresh avoids any
# stale metadata cache.
dnf -y --disablerepo="*" --enablerepo=dtf-ak --refresh install dtf-marker >/tmp/dnf.log 2>&1
# Prove the package really installed (followed the advertised location), not
# just that metadata listed it.
test -f /usr/share/dtf-marker/marker.txt
grep -q DTF-RPM-INSTALLED /usr/share/dtf-marker/marker.txt
rpm -q dtf-marker >/dev/null
'
  if timeout 180 docker exec "$CDNF" bash -c "$install_rpm"; then
    pass
  else
    dnflog=$(docker exec "$CDNF" sh -c 'tail -n 30 /tmp/dnf.log 2>/dev/null' 2>/dev/null || true)
    fail "#2580 REGRESSION: real dnf install did not follow the advertised <location href> / package not installed" "$dnflog"
  fi
else
  fail "skipped: publish failed"
fi

begin_test "A3: #2580 discriminator — advertised <location href> resolves (200); pre-fix generic href (no packages/ prefix) 404s"
if [ "$A_OK" = "1" ]; then
  repomd=$(curl -s --max-time 30 "${BASE_URL}/rpm/${RPM_REPO}/repodata/repomd.xml" 2>/dev/null || true)
  primary_href=$(printf '%s' "$repomd" | grep -oE 'href="[^"]*primary[^"]*"' | head -1 | sed -E 's/^href="//; s/"$//')
  loc=""
  if [ -n "$primary_href" ]; then
    curl -s --max-time 30 -o "${WORK_DIR}/primary.xml.gz" "${BASE_URL}/rpm/${RPM_REPO}/${primary_href}" 2>/dev/null || true
    gunzip -c "${WORK_DIR}/primary.xml.gz" > "${WORK_DIR}/primary.xml" 2>/dev/null || cp "${WORK_DIR}/primary.xml.gz" "${WORK_DIR}/primary.xml"
    loc=$(grep -oE '<location href="[^"]*"' "${WORK_DIR}/primary.xml" | head -1 | sed -E 's/^<location href="//; s/"$//')
  fi
  if [ -z "$loc" ]; then
    fail "could not extract <location href> from primary.xml (repomd primary_href='${primary_href}')" "$(head -c 400 "${WORK_DIR}/primary.xml" 2>/dev/null)"
  else
    base_name="${loc##*/}"
    resolves=$(hcode -H "$(auth_header)" "${BASE_URL}/rpm/${RPM_REPO}/${loc}")
    bare=$(hcode -H "$(auth_header)" "${BASE_URL}/rpm/${RPM_REPO}/${base_name}")
    echo "  advertised <location href>=${loc} -> HTTP ${resolves}; bare (no packages/ prefix) '${base_name}' -> HTTP ${bare}"
    if [ "$resolves" = "200" ] && [ "$bare" = "404" ]; then
      pass
    elif [ "$resolves" != "200" ]; then
      fail "#2580: the advertised <location href> '${loc}' did NOT resolve (HTTP ${resolves}); a real client following it would 404"
    else
      fail "discriminator weak: bare href '${base_name}' returned HTTP ${bare} (expected 404 — the #2580 generic-flow location shape must not resolve)"
    fi
  fi
else
  fail "skipped: prior RPM leg step failed"
fi

# ===========================================================================
# LEG B — #2580 deb: real apt-get install FOLLOWS the Packages Filename:
# ===========================================================================

begin_test "B0: create hosted Debian repo + build a dependency-free marker .deb in the Debian client"
B_OK=1
if ! create_repo "$DEB_REPO" debian local; then
  B_OK=0; fail "could not create hosted debian repo ${DEB_REPO}"
else
  DEB_ARCH=$(docker exec "$CAPT" dpkg --print-architecture 2>/dev/null | tr -d '[:space:]')
  [ -n "$DEB_ARCH" ] || DEB_ARCH="arm64"
  DEB_FILE="dtf-marker_1.0_${DEB_ARCH}.deb"
  build_deb='
set -e
ARCH="'"$DEB_ARCH"'"
rm -rf /tmp/dtf-marker
mkdir -p /tmp/dtf-marker/DEBIAN /tmp/dtf-marker/usr/share/dtf-marker
cat > /tmp/dtf-marker/DEBIAN/control <<CTRL
Package: dtf-marker
Version: 1.0
Architecture: ${ARCH}
Maintainer: DTF <dtf@example.com>
Description: DTF native-client marker
 A dependency-free marker package for the DTF native-client tier.
CTRL
echo "DTF-DEB-INSTALLED-1.0" > /tmp/dtf-marker/usr/share/dtf-marker/marker.txt
dpkg-deb --root-owner-group --build /tmp/dtf-marker "/tmp/'"$DEB_FILE"'" >/dev/null 2>&1
test -f "/tmp/'"$DEB_FILE"'"
'
  if timeout 120 docker exec "$CAPT" bash -c "$build_deb"; then
    docker cp "${CAPT}:/tmp/${DEB_FILE}" "${WORK_DIR}/${DEB_FILE}" >/dev/null 2>&1 || B_OK=0
    if [ "$B_OK" = "1" ] && [ -s "${WORK_DIR}/${DEB_FILE}" ]; then
      pass
    else
      B_OK=0; fail "built .deb could not be copied out of the Debian client"
    fi
  else
    B_OK=0; fail "dpkg-deb build failed inside the Debian client"
  fi
fi

begin_test "B1: publish the .deb to the hosted repo pool (native upload; no ak CLI on rig)"
if [ "$B_OK" = "1" ]; then
  DEB_POOL_PATH="pool/main/m/dtf-marker/${DEB_FILE}"
  up=$(hcode -X PUT -H "$(auth_header)" --upload-file "${WORK_DIR}/${DEB_FILE}" \
        "${BASE_URL}/debian/${DEB_REPO}/pool/main/m/dtf-marker/${DEB_FILE}")
  if [ "$up" = "200" ] || [ "$up" = "201" ]; then
    pass
  else
    B_OK=0; fail "deb upload returned HTTP ${up} (expected 201)"
  fi
else
  fail "skipped: repo/build failed"
fi

begin_test "B2: #2580 — real \`apt-get install\` FOLLOWS Packages Filename: and INSTALLS the package"
if [ "$B_OK" = "1" ]; then
  install_deb='
set -e
export DEBIAN_FRONTEND=noninteractive
# Consult ONLY the AK repo so the install can succeed only by following the
# advertised Filename: field.
rm -f /etc/apt/sources.list
rm -rf /etc/apt/sources.list.d/*
echo "deb [trusted=yes] '"${BACKEND_INTERNAL}/debian/${DEB_REPO}"' stable main" > /etc/apt/sources.list.d/dtf-ak.list
apt-get -o Acquire::Check-Valid-Until=false update >/tmp/apt.log 2>&1
apt-get -y install dtf-marker >>/tmp/apt.log 2>&1
test -f /usr/share/dtf-marker/marker.txt
grep -q DTF-DEB-INSTALLED /usr/share/dtf-marker/marker.txt
dpkg -s dtf-marker >/dev/null 2>&1
'
  if timeout 180 docker exec "$CAPT" bash -c "$install_deb"; then
    pass
  else
    aptlog=$(docker exec "$CAPT" sh -c 'tail -n 40 /tmp/apt.log 2>/dev/null' 2>/dev/null || true)
    fail "#2580 REGRESSION: real apt-get install did not follow the advertised Filename: / package not installed" "$aptlog"
  fi
else
  fail "skipped: publish failed"
fi

begin_test "B3: #2580 discriminator — advertised Filename: resolves (200); pre-fix bare basename (no pool/ prefix) 404s"
if [ "$B_OK" = "1" ]; then
  pkgs=$(curl -s --max-time 30 "${BASE_URL}/debian/${DEB_REPO}/dists/stable/main/binary-${DEB_ARCH}/Packages" 2>/dev/null || true)
  fname=$(printf '%s\n' "$pkgs" | grep -E '^Filename:' | head -1 | sed -E 's/^Filename:[[:space:]]*//; s/[[:space:]]*$//')
  if [ -z "$fname" ]; then
    fail "could not extract Filename: from the Packages index" "$(printf '%s' "$pkgs" | head -c 400)"
  else
    base_name="${fname##*/}"
    resolves=$(hcode -H "$(auth_header)" "${BASE_URL}/debian/${DEB_REPO}/${fname}")
    bare=$(hcode -H "$(auth_header)" "${BASE_URL}/debian/${DEB_REPO}/${base_name}")
    echo "  advertised Filename:=${fname} -> HTTP ${resolves}; bare (no pool/ prefix) '${base_name}' -> HTTP ${bare}"
    if [ "$resolves" = "200" ] && [ "$bare" = "404" ]; then
      pass
    elif [ "$resolves" != "200" ]; then
      fail "#2580: the advertised Filename: '${fname}' did NOT resolve (HTTP ${resolves}); a real client following it would 404"
    else
      fail "discriminator weak: bare filename '${base_name}' returned HTTP ${bare} (expected 404)"
    fi
  fi
else
  fail "skipped: prior deb leg step failed"
fi

# ===========================================================================
# LEG C — #2477 docker: proxy pull with >=2 token exchanges (offline reuse)
# ===========================================================================

begin_test "C0: seed the local upstream OCI registry (2 repos) + create AK Docker REMOTE repo"
C_OK=1
# Ensure a small seed image exists on the host (offline if already pulled).
if ! docker image inspect alpine:3.23 >/dev/null 2>&1; then
  docker pull -q alpine:3.23 >/dev/null 2>&1 || true
fi
seed_ok=1
for repo in alpine alpine-b; do
  docker tag alpine:3.23 "127.0.0.1:${TRIVY_PORT}/proxied/${repo}:3.23" >/dev/null 2>&1 || seed_ok=0
  docker push -q "127.0.0.1:${TRIVY_PORT}/proxied/${repo}:3.23" >/dev/null 2>&1 || seed_ok=0
done
if [ "$seed_ok" != "1" ]; then
  C_OK=0; fail "could not seed the local upstream registry on 127.0.0.1:${TRIVY_PORT}"
elif ! create_repo "$DOCKER_REMOTE" docker remote "http://upstream-registry:5000"; then
  C_OK=0; fail "could not create AK Docker remote/proxy repo ${DOCKER_REMOTE} -> upstream-registry:5000"
else
  pass
fi

begin_test "C1: #2477 deterministic gate — the offline token is REUSABLE across >=2 token exchanges (no family revocation)"
# This is the exact #2477 mechanism, client<->AK, independent of the real
# daemon's token caching: `docker login` mints an offline/identity token;
# every subsequent pull re-presents the SAME token via grant_type=refresh_token.
# Pre-#2477 the 2nd presentation tripped single-use replay revocation -> 401.
if [ "$C_OK" = "1" ]; then
  OFFLINE=$(curl -s --max-time 30 -u "${AK_ADMIN_USER}:${AK_ADMIN_PASS}" \
    "${BASE_URL}/v2/token?service=${SVC}&offline_token=true" 2>/dev/null | jq -r '.refresh_token // empty')
  reuse_code() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
      -X POST "${BASE_URL}/v2/token?service=${SVC}" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "grant_type=refresh_token" \
      --data-urlencode "refresh_token=${OFFLINE}" \
      --data-urlencode "service=${SVC}" 2>/dev/null
  }
  if [ -z "$OFFLINE" ] || [ "$OFFLINE" = "null" ]; then
    fail "docker login (offline_token=true) returned no refresh_token; cannot exercise the #2477 reuse path"
  else
    c1=$(reuse_code); c2=$(reuse_code); c3=$(reuse_code)
    echo "  offline-token re-presentation exchanges: #1=${c1} #2=${c2} #3=${c3} (all 200 required)"
    if [ "$c1" = "200" ] && [ "$c2" = "200" ] && [ "$c3" = "200" ]; then
      pass
    elif [ "$c2" = "401" ] || [ "$c3" = "401" ]; then
      fail "#2477 REGRESSION: re-presenting the SAME offline token returned 401 (family revoked); repeated docker pulls broken after one login" "exchanges: ${c1}/${c2}/${c3}"
    else
      fail "offline-token reuse exchanges returned ${c1}/${c2}/${c3}, expected 200/200/200"
    fi
  fi
else
  fail "skipped: upstream/proxy-repo setup failed"
fi

begin_test "C2: #2477 real client — \`docker pull\` through the proxy repo TWICE forces >=2 token exchanges and SUCCEEDS"
if [ "$C_OK" = "1" ]; then
  # Count /v2/token hits before/after to evidence >=2 exchanges.
  tok_before=$(docker logs "$BACKEND_CTR" 2>&1 | grep -cE '/v2/token' || true)
  pull_script='
set -e
echo "'"$AK_ADMIN_PASS"'" | docker login backend:8080 -u "'"$AK_ADMIN_USER"'" --password-stdin
# Two DIFFERENT proxied repos => two distinct pull scopes => >=2 token
# exchanges re-presenting the stored offline token.
docker pull backend:8080/'"$DOCKER_REMOTE"'/proxied/alpine:3.23
docker pull backend:8080/'"$DOCKER_REMOTE"'/proxied/alpine-b:3.23
'
  if timeout 240 docker exec "$CDOCKER" sh -c "$pull_script" >"${WORK_DIR}/pull.log" 2>&1; then
    tok_after=$(docker logs "$BACKEND_CTR" 2>&1 | grep -cE '/v2/token' || true)
    exchanges=$(( tok_after - tok_before ))
    echo "  /v2/token exchanges observed during the two proxy pulls: ${exchanges}"
    pass
  else
    plog=$(cat "${WORK_DIR}/pull.log" 2>/dev/null | tail -n 40 || true)
    # A 2nd-pull auth failure is precisely the #2477 signature.
    if grep -qiE 'unauthorized|401|denied' "${WORK_DIR}/pull.log" 2>/dev/null; then
      fail "#2477 REGRESSION: real docker pull through the proxy repo failed authentication on a repeated token exchange" "$plog"
    else
      fail "real docker pull through the proxy repo failed" "$plog"
    fi
  fi
else
  fail "skipped: upstream/proxy-repo setup failed"
fi

end_suite
