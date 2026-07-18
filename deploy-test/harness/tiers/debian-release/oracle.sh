#!/usr/bin/env bash
# =============================================================================
# tiers/debian-release/oracle.sh — hosted Debian `Release` metadata customization
#   PKT-B (epic #2458): #2489 (apt_origin/apt_label/apt_release_version/
#   apt_description rendered into the served dists/{dist}/Release)
# =============================================================================
# run.sh has stood up the `filesystem + client.apt` profile-set (backend +
# postgres + a real Debian APT client) health-gated with `up -d --wait`, and
# exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT,
# JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit harness.
#
# The whole point is a SERVED-BYTES assertion: we GET the rendered
# `dists/stable/Release` document and assert the exact custom field lines are
# IN THE BYTES the server returns, and — on a second repo with no overrides —
# that the same custom strings are ABSENT and the DEFAULT Origin/Label appear.
#
#   POSITIVE (custom repo):
#     PATCH apt_origin="DTF Corp" apt_label="DTF Internal"
#           apt_release_version="2026.7" apt_description="DTF custom release"
#     GET dists/stable/Release ->
#       Origin: DTF Corp        (custom, not the "artifact-keeper" default)
#       Label: DTF Internal     (custom)
#       Version: 2026.7         (line present only because the key is set)
#       Description: DTF custom release  (first deb822 line)
#     A real `apt-get update` + `apt-get install` in client.apt against the
#     customized repo still succeeds (customization did not break the index).
#
#   NEGATIVE / discrimination (default repo, NO apt_* keys):
#     GET dists/stable/Release ->
#       Origin: artifact-keeper (default) and Label: artifact-keeper (default)
#       and the document does NOT contain any of the custom strings, and
#       carries NO `Version:` / `Description:` line at all.
#     This is what proves the positive assertion is not vacuous: if the custom
#     values appeared here (hardcoded constant) OR were absent on the custom
#     repo (backend ignoring apt_* config) the tier goes RED.
#
# Backend surface CONFIRMED against ak-backend:candidate-a4d7f9d1 (deviations
# from the build plan are in MATRIX-ROW.md):
#   * apt_* are TOP-LEVEL create/update request fields (NOT nested under
#     `debian`); update verb is PATCH /api/v1/repositories/{key}.
#   * Defaults: DEFAULT_APT_ORIGIN = DEFAULT_APT_LABEL = "artifact-keeper".
#   * Version:/Description: lines are omitted entirely when the keys are unset.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "debian-release-2489"
auth_admin
setup_workdir

SLOT="${DTF_SLOT}"
CAPT="ak-dtf${SLOT}-client-apt"
BACKEND_INTERNAL="http://backend:8080"     # backend as seen from the apt client

CUSTOM_KEY="dtf-debrel-custom-${RUN_ID}"
DEFAULT_KEY="dtf-debrel-default-${RUN_ID}"
DIST="stable"

# The exact custom values whose rendered lines are the load-bearing assertion.
C_ORIGIN="DTF Corp"
C_LABEL="DTF Internal"
C_VERSION="2026.7"
C_DESC="DTF custom release"

# The backend defaults an unset repo must render (DEFAULT_APT_ORIGIN/LABEL).
DEF_ORIGIN="artifact-keeper"
DEF_LABEL="artifact-keeper"

DEB_ARCH=""
DEB_FILE=""

cleanup() {
  api_delete "/api/v1/repositories/${CUSTOM_KEY}"  >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${DEFAULT_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

# req METHOD PATH [DATA] -> sets REQ_STATUS + writes body to REQ_BODY_FILE.
REQ_STATUS=""; REQ_BODY_FILE="${WORK_DIR}/req-body"
req() {
  local method="$1" path="$2" data="${3:-}"
  local args=(-s -o "$REQ_BODY_FILE" -w '%{http_code}' --max-time 40 -X "$method" -H "$(auth_header)")
  [ -n "$data" ] && args+=(-H "Content-Type: application/json" -d "$data")
  REQ_STATUS=$(curl "${args[@]}" "$path" 2>/dev/null) || REQ_STATUS="000"
}
body() { cat "$REQ_BODY_FILE" 2>/dev/null || true; }
hcode() { curl -s -o /dev/null -w '%{http_code}' --max-time 40 "$@"; }

# has_line FILE "Origin: DTF Corp"  -> exact deb822 line match (whole-line, so
# "Origin: DTF Corp" does not spuriously match a longer "Origin: DTF Corp X").
has_line() { grep -qxF "$2" "$1"; }

# ---------------------------------------------------------------------------
# Build one dependency-free marker .deb inside the Debian client (native upload;
# no `ak` CLI on the rig). Reused as the published content for BOTH repos so the
# rendered Release has real component/arch layout to describe.
# ---------------------------------------------------------------------------
begin_test "S0: build a dependency-free marker .deb in the Debian client"
S0_OK=1
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
Description: DTF debian-release marker
 A dependency-free marker package for the DTF debian-release tier.
CTRL
echo "DTF-DEB-RELEASE-INSTALLED-1.0" > /tmp/dtf-marker/usr/share/dtf-marker/marker.txt
dpkg-deb --root-owner-group --build /tmp/dtf-marker "/tmp/'"$DEB_FILE"'" >/dev/null 2>&1
test -f "/tmp/'"$DEB_FILE"'"
'
if timeout 120 docker exec "$CAPT" bash -c "$build_deb"; then
  docker cp "${CAPT}:/tmp/${DEB_FILE}" "${WORK_DIR}/${DEB_FILE}" >/dev/null 2>&1 || S0_OK=0
  if [ "$S0_OK" = "1" ] && [ -s "${WORK_DIR}/${DEB_FILE}" ]; then
    pass
  else
    S0_OK=0; fail "built .deb could not be copied out of the Debian client"
  fi
else
  S0_OK=0; fail "dpkg-deb build failed inside the Debian client"
fi

# publish_deb REPO_KEY -> uploads the marker .deb into the repo pool. Echoes 0/1.
publish_deb() {
  local key="$1"
  local up
  up=$(hcode -X PUT -H "$(auth_header)" --upload-file "${WORK_DIR}/${DEB_FILE}" \
        "${BASE_URL}/debian/${key}/pool/main/m/dtf-marker/${DEB_FILE}")
  [ "$up" = "200" ] || [ "$up" = "201" ]
}

# ===========================================================================
# POSITIVE — custom repo carries the operator-set apt_* values in the served
# Release bytes.
# ===========================================================================

begin_test "P0: create hosted debian repo ${CUSTOM_KEY} + PATCH custom apt_origin/apt_label/apt_release_version/apt_description"
P_OK=1
if ! create_repo "$CUSTOM_KEY" debian local; then
  P_OK=0; fail "could not create hosted debian repo ${CUSTOM_KEY}"
else
  req PATCH "${BASE_URL}/api/v1/repositories/${CUSTOM_KEY}" \
    "{\"apt_origin\":\"${C_ORIGIN}\",\"apt_label\":\"${C_LABEL}\",\"apt_release_version\":\"${C_VERSION}\",\"apt_description\":\"${C_DESC}\"}"
  if [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; then
    pass
  else
    P_OK=0; fail "PATCH apt_* on hosted debian repo expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
  fi
fi

begin_test "P1: publish the marker .deb to ${CUSTOM_KEY} pool (native upload) so the Release has content"
if [ "$P_OK" = "1" ] && [ "$S0_OK" = "1" ]; then
  if publish_deb "$CUSTOM_KEY"; then pass; else P_OK=0; fail "marker .deb upload to ${CUSTOM_KEY} failed"; fi
else
  fail "skipped: repo create/PATCH or .deb build failed"
fi

CUSTOM_REL="${WORK_DIR}/custom-release"
begin_test "P2: #2489 SERVED-BYTES — custom dists/${DIST}/Release carries the EXACT custom Origin/Label/Version/Description"
if [ "$P_OK" = "1" ]; then
  code=$(curl -s -o "$CUSTOM_REL" -w '%{http_code}' --max-time 40 -H "$(auth_header)" \
          "${BASE_URL}/debian/${CUSTOM_KEY}/dists/${DIST}/Release")
  if [ "$code" != "200" ]; then
    fail "GET custom dists/${DIST}/Release expected 200, got ${code}" "$(head -c 400 "$CUSTOM_REL" 2>/dev/null)"
  else
    missing=""
    has_line "$CUSTOM_REL" "Origin: ${C_ORIGIN}"        || missing="${missing} [Origin: ${C_ORIGIN}]"
    has_line "$CUSTOM_REL" "Label: ${C_LABEL}"          || missing="${missing} [Label: ${C_LABEL}]"
    has_line "$CUSTOM_REL" "Version: ${C_VERSION}"      || missing="${missing} [Version: ${C_VERSION}]"
    has_line "$CUSTOM_REL" "Description: ${C_DESC}"     || missing="${missing} [Description: ${C_DESC}]"
    if [ -z "$missing" ]; then
      echo "  served custom Release header:"; sed -n '1,8p' "$CUSTOM_REL" | sed 's/^/    /'
      pass
    else
      fail "#2489: custom Release is MISSING these operator-set lines:${missing} (backend ignored apt_* config?)" "$(sed -n '1,10p' "$CUSTOM_REL")"
    fi
  fi
else
  fail "skipped: custom repo not published"
fi

begin_test "P3: consumer — real \`apt-get update\` + \`apt-get install\` against the customized repo still succeeds"
if [ "$P_OK" = "1" ]; then
  install_deb='
set -e
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list
rm -rf /etc/apt/sources.list.d/*
echo "deb [trusted=yes] '"${BACKEND_INTERNAL}/debian/${CUSTOM_KEY}"' '"${DIST}"' main" > /etc/apt/sources.list.d/dtf-ak.list
apt-get -o Acquire::Check-Valid-Until=false update >/tmp/apt.log 2>&1
apt-get -y install dtf-marker >>/tmp/apt.log 2>&1
test -f /usr/share/dtf-marker/marker.txt
grep -q DTF-DEB-RELEASE-INSTALLED /usr/share/dtf-marker/marker.txt
dpkg -s dtf-marker >/dev/null 2>&1
'
  if timeout 180 docker exec "$CAPT" bash -c "$install_deb"; then
    pass
  else
    aptlog=$(docker exec "$CAPT" sh -c 'tail -n 40 /tmp/apt.log 2>/dev/null' 2>/dev/null || true)
    fail "customized Release broke the index: real apt-get update/install failed" "$aptlog"
  fi
else
  fail "skipped: custom repo not published"
fi

# ===========================================================================
# NEGATIVE / DISCRIMINATION — a repo with NO apt_* keys renders defaults, and
# never the custom strings. Proves the positive assertion is not vacuous.
# ===========================================================================

begin_test "N0: create a SECOND hosted debian repo ${DEFAULT_KEY} with NO apt_* overrides + publish the same marker"
N_OK=1
if ! create_repo "$DEFAULT_KEY" debian local; then
  N_OK=0; fail "could not create default hosted debian repo ${DEFAULT_KEY}"
elif [ "$S0_OK" != "1" ]; then
  N_OK=0; fail "skipped: .deb build failed"
elif ! publish_deb "$DEFAULT_KEY"; then
  N_OK=0; fail "marker .deb upload to ${DEFAULT_KEY} failed"
else
  pass
fi

DEFAULT_REL="${WORK_DIR}/default-release"
begin_test "N1: #2489 DISCRIMINATOR — default repo Release shows DEFAULT Origin/Label and NONE of the custom strings"
if [ "$N_OK" = "1" ]; then
  code=$(curl -s -o "$DEFAULT_REL" -w '%{http_code}' --max-time 40 -H "$(auth_header)" \
          "${BASE_URL}/debian/${DEFAULT_KEY}/dists/${DIST}/Release")
  if [ "$code" != "200" ]; then
    fail "GET default dists/${DIST}/Release expected 200, got ${code}" "$(head -c 400 "$DEFAULT_REL" 2>/dev/null)"
  else
    leaked=""
    # A hardcoded-constant / cross-repo bleed would put the custom strings here.
    grep -qF "$C_ORIGIN"  "$DEFAULT_REL" && leaked="${leaked} [Origin=${C_ORIGIN}]"
    grep -qF "$C_LABEL"   "$DEFAULT_REL" && leaked="${leaked} [Label=${C_LABEL}]"
    grep -qF "$C_VERSION" "$DEFAULT_REL" && leaked="${leaked} [Version=${C_VERSION}]"
    grep -qF "$C_DESC"    "$DEFAULT_REL" && leaked="${leaked} [Description=${C_DESC}]"
    # Version:/Description: lines must be OMITTED entirely when unset.
    extra=""
    grep -qE '^Version:'     "$DEFAULT_REL" && extra="${extra} [stray Version:]"
    grep -qE '^Description:' "$DEFAULT_REL" && extra="${extra} [stray Description:]"
    # Defaults must be the ones the backend documents.
    def_ok=1
    has_line "$DEFAULT_REL" "Origin: ${DEF_ORIGIN}" || def_ok=0
    has_line "$DEFAULT_REL" "Label: ${DEF_LABEL}"   || def_ok=0

    if [ -n "$leaked" ]; then
      fail "#2489 RED: custom strings appeared on a repo that never set them:${leaked} (assertion is vacuous / values are not per-repo)" "$(sed -n '1,10p' "$DEFAULT_REL")"
    elif [ -n "$extra" ]; then
      fail "#2489 RED: default repo Release carries a line that should be omitted when unset:${extra}" "$(sed -n '1,10p' "$DEFAULT_REL")"
    elif [ "$def_ok" != "1" ]; then
      fail "default repo Release did not render the documented defaults (Origin/Label: ${DEF_ORIGIN})" "$(sed -n '1,10p' "$DEFAULT_REL")"
    else
      echo "  served default Release header:"; sed -n '1,8p' "$DEFAULT_REL" | sed 's/^/    /'
      pass
    fi
  fi
else
  fail "skipped: default repo not published"
fi

end_suite
