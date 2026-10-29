#!/usr/bin/env bash
# =============================================================================
# tiers/rpm-hosted-repodata-precomputed/oracle.sh: precomputed hosted RPM
# repodata (artifact-keeper#4544)
# =============================================================================
# run.sh has stood up `filesystem + client.dnf` on this slot and exported
# BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT,
# DB_CONTAINER, COMMON_SH.
#
#   P1  publish akdep-lib, build it (rebuild?wait=true), publish akdep-app
#       (Requires: akdep-libfoo), rebuild?wait=true again: 200, status built,
#       2 packages. 1.11.9 has no rebuild endpoint (404): RED.
#   P2  the served repomd.xml is the stored revision: byte-equal to
#       rpm_repodata_roots.built_repomd of the revision P1 returned, and the
#       documents exist under repodata/<repo id>/<rev>/ in storage.
#   P3  a real `dnf makecache` + `dnf install akdep-app` in the Fedora client
#       resolves akdep-lib from the stored primary.xml and installs both.
#   P4  repodata_mode: on_request renders the same repomd.xml, primary,
#       filelists and other bytes as the stored revision.
#   P5  repodata_mode round-trips on the repository API and back to
#       precomputed.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "rpm-hosted-repodata-precomputed-4544"
auth_admin
setup_workdir

SLOT="${DTF_SLOT}"
CDNF="ak-dtf${SLOT}-client-dnf"
BACKEND_CTR="ak-dtf${SLOT}-backend"
BACKEND_INTERNAL="http://backend:8080"
REPO="dtf-rpmpre-${RUN_ID}"
FIX="${DTF_DIR}/fixtures/rpm"
LIB="akdep-lib-1.0-1.noarch.rpm"
APP="akdep-app-2.0-1.noarch.rpm"
DOCS="repomd.xml primary.xml.gz filelists.xml.gz other.xml.gz"

cleanup() { api_delete "/api/v1/repositories/${REPO}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup"

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>/dev/null; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }
# post_rebuild QUERY OUTFILE -> http code
post_rebuild() {
  curl -s -o "$2" -w '%{http_code}' --max-time 330 -X POST -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO}/rpm/repodata/rebuild$1" 2>/dev/null || echo 000
}
publish() {
  code -X PUT -H "$(auth_header)" --upload-file "${FIX}/$1" "${BASE_URL}/rpm/${REPO}/packages/$1"
}
# save_docs DIR: the four generated documents, anonymous (repo is public)
save_docs() {
  mkdir -p "$1"
  for d in $DOCS; do
    curl -s -o "$1/$d" --max-time 60 "${BASE_URL}/rpm/${REPO}/repodata/$d" 2>/dev/null
  done
}
patch_mode() {
  curl -s -o "${WORK_DIR}/patch.json" -w '%{http_code}' --max-time 60 -X PATCH \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"repodata_mode\":\"$1\"}" "${BASE_URL}/api/v1/repositories/${REPO}" 2>/dev/null || echo 000
}

OK=1
begin_test "setup: hosted RPM repository and fixture RPMs"
if [ ! -s "${FIX}/${LIB}" ] || [ ! -s "${FIX}/${APP}" ]; then
  OK=0; infra_fail "fixture RPMs missing under ${FIX}"
elif ! create_repo "$REPO" rpm local; then
  OK=0; infra_fail "could not create hosted RPM repository ${REPO}"
else
  pass
fi
REPO_ID="$(psqlq "SELECT id FROM repositories WHERE key = '${REPO}'" || true)"

begin_test "FIX #4544 P1: rebuild?wait=true after each publish answers 200 built, ending with both packages"
REV=""
if [ "$OK" = "1" ]; then
  c1="$(publish "$LIB")"
  r1="$(post_rebuild '?wait=true' "${WORK_DIR}/r1.json")"
  c2="$(publish "$APP")"
  r2="$(post_rebuild '?wait=true' "${WORK_DIR}/r2.json")"
  REV="$(jq -r '.revision // empty' "${WORK_DIR}/r2.json" 2>/dev/null || true)"
  PK="$(jq -r '.packages // empty' "${WORK_DIR}/r2.json" 2>/dev/null || true)"
  ST="$(jq -r '.status // empty' "${WORK_DIR}/r2.json" 2>/dev/null || true)"
  R1REV="$(jq -r '.revision // empty' "${WORK_DIR}/r1.json" 2>/dev/null || true)"
  if [ "$c1" = "201" ] && [ "$c2" = "201" ] && [ "$r1" = "200" ] && [ "$r2" = "200" ] \
     && [ "$ST" = "built" ] && [ "$PK" = "2" ] && [ -n "$REV" ] && [ -n "$R1REV" ] \
     && [ "$REV" -gt "$R1REV" ]; then
    pass
  else
    OK=0
    fail "publish ${c1}/${c2}; rebuild ${r1}/${r2}; last response $(head -c 300 "${WORK_DIR}/r2.json" 2>/dev/null). \
Before #4544 there is no precomputed repodata and no rebuild endpoint (404)."
  fi
else
  fail "skipped: setup failed"
fi

begin_test "FIX #4544 P2: the served repomd.xml is the stored revision (database row and storage objects)"
if [ "$OK" = "1" ]; then
  save_docs "${WORK_DIR}/stored"
  ROW="$(psqlq "SELECT built_revision || '|' || encode(built_repomd, 'hex') FROM rpm_repodata_roots \
                WHERE repository_id = '${REPO_ID}' AND root = ''" || true)"
  ROW_REV="${ROW%%|*}"; ROW_HEX="${ROW#*|}"
  SERVED_HEX="$(od -An -v -tx1 "${WORK_DIR}/stored/repomd.xml" 2>/dev/null | tr -d ' \n' || true)"
  STORE="$(psqlq "SELECT storage_path FROM repositories WHERE id = '${REPO_ID}'" || true)"
  missing=""
  for d in $DOCS; do
    docker exec "$BACKEND_CTR" test -s "${STORE}/repodata/${REPO_ID}/${REV}/${d}" 2>/dev/null \
      || missing="${missing} ${d}"
  done
  if [ "$ROW_REV" = "$REV" ] && [ -n "$ROW_HEX" ] && [ "$ROW_HEX" = "$SERVED_HEX" ] && [ -z "$missing" ]; then
    pass
  else
    fail "row revision ${ROW_REV:-?} (rebuild said ${REV}); served repomd matches row: \
$([ "$ROW_HEX" = "$SERVED_HEX" ] && echo yes || echo no); missing in storage under ${STORE}/repodata/${REPO_ID}/${REV}/:${missing:- none}"
  fi
else
  fail "skipped: P1 failed"
fi

begin_test "FIX #4544 P3: real dnf makecache + dnf install akdep-app resolves akdep-lib from the stored primary.xml"
if [ "$OK" = "1" ]; then
  dnf_script='
set -e
cat > /etc/yum.repos.d/dtf-rpmpre.repo <<REPO
[dtf-rpmpre]
name=DTF precomputed repodata
baseurl='"${BACKEND_INTERNAL}/rpm/${REPO}/"'
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
dnf -y --disablerepo="*" --enablerepo=dtf-rpmpre makecache >/tmp/dnf-pre.log 2>&1
dnf -y --disablerepo="*" --enablerepo=dtf-rpmpre install akdep-app >>/tmp/dnf-pre.log 2>&1
rpm -q akdep-app akdep-lib >/dev/null
'
  if timeout 300 docker exec "$CDNF" bash -c "$dnf_script"; then
    pass
  else
    fail "dnf could not install akdep-app (and its dependency) from the stored repodata" \
      "$(docker exec "$CDNF" sh -c 'tail -n 30 /tmp/dnf-pre.log' 2>/dev/null || true)"
  fi
else
  fail "skipped: P1 failed"
fi

begin_test "FIX #4544 P4: repodata_mode on_request renders exactly the stored bytes"
if [ "$OK" = "1" ]; then
  pc="$(patch_mode on_request)"
  MODE="$(jq -r '.repodata_mode // empty' "${WORK_DIR}/patch.json" 2>/dev/null || true)"
  save_docs "${WORK_DIR}/rendered"
  diffs=""
  for d in $DOCS; do
    cmp -s "${WORK_DIR}/stored/$d" "${WORK_DIR}/rendered/$d" || diffs="${diffs} ${d}"
  done
  if [ "$pc" = "200" ] && [ "$MODE" = "on_request" ] && [ -z "$diffs" ]; then
    pass
  else
    fail "PATCH repodata_mode=on_request -> ${pc} (mode '${MODE}'); documents that differ:${diffs:- none}"
  fi
else
  fail "skipped: P1 failed"
fi

begin_test "FIX #4544 P5: repodata_mode reads back and switches back to precomputed"
if [ "$OK" = "1" ]; then
  gc="$(curl -s -o "${WORK_DIR}/get.json" -w '%{http_code}' --max-time 60 -H "$(auth_header)" \
        "${BASE_URL}/api/v1/repositories/${REPO}" 2>/dev/null || echo 000)"
  GOT="$(jq -r '.repodata_mode // empty' "${WORK_DIR}/get.json" 2>/dev/null || true)"
  pc="$(patch_mode precomputed)"
  BACK="$(jq -r '.repodata_mode // empty' "${WORK_DIR}/patch.json" 2>/dev/null || true)"
  if [ "$gc" = "200" ] && [ "$GOT" = "on_request" ] && [ "$pc" = "200" ] && [ "$BACK" = "precomputed" ]; then
    pass
  else
    fail "GET ${gc} mode '${GOT}' (want on_request); PATCH precomputed ${pc} mode '${BACK}'"
  fi
else
  fail "skipped: P1 failed"
fi

end_suite
