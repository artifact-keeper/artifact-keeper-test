#!/usr/bin/env bash
# =============================================================================
# tiers/debian-rpm-maintenance/oracle.sh: the Debian backfill dry run and the
# RPM repodata revision GC (artifact-keeper#5082, #5088, #5072)
# =============================================================================
# run.sh has stood up `filesystem` on this slot and exported BASE_URL,
# ADMIN_USER/ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT, DB_CONTAINER,
# COMMON_SH.
#
# Candidates for `POST /api/v1/admin/repositories/{key}/backfill-debian` are
# `.deb` rows with no Debian control document: what the migration importer
# left before #4657. The oracle makes them the way a user can: a generic
# `PUT /api/v1/repositories/{key}/artifacts/<path>` of a real `.deb`; then it
# deletes any `debian` artifact_metadata row of those uploads (psql), so the
# rows have exactly the pre-#4657 migrated shape. Destination rows that must
# NOT be candidates are native Debian uploads (`PUT /debian/{key}/pool/...`).
#
#   A  #5082  misfiled packages whose pool/main/ destination holds a different
#             package, a trashed row, or the move of another misfiled copy:
#             the dry run must report the refusals the real run reports.
#   B  #5088  misfiled packages that merge into a same-bytes destination row
#             which is itself a candidate, some on a later candidate page
#             (1000 filler candidates; pages are 500 rows by id): the package
#             counts once, and the dry run counts what the real run counts.
#   C  #5072  a hosted RPM repository's storage_path moves (copy + repoint,
#             psql: no API changes a repository's location); two more builds
#             must delete the revisions written to the previous location.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

TIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
begin_suite "debian-rpm-maintenance"
auth_admin
setup_workdir

SLOT="${DTF_SLOT}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
RID="$(printf '%s' "${RUN_ID}" | tr -cd 'a-z0-9' | tail -c 8)"
REPO_A="dtf-debbf-a-${RID}"
REPO_B="dtf-debbf-b-${RID}"
REPO_C="dtf-rpmloc-${RID}"
RPMFIX="${DTF_DIR}/fixtures/rpm"
DEBS="${WORK_DIR}/debs"
mkdir -p "$DEBS"
AH="$(auth_header)"
PAGE=500
FILLERS=1000

cleanup() {
  for r in "$REPO_A" "$REPO_B" "$REPO_C"; do
    api_delete "/api/v1/repositories/${r}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>/dev/null; }
repo_id() { psqlq "SELECT id FROM repositories WHERE key = '$1'"; }
mkdeb() { python3 -I "${TIER_DIR}/fixtures/build_deb.py" "${DEBS}/$1" "$2" 1.0 amd64 "$3"; }
# gput REPO PATH FILE -> http code (generic upload: no control document)
gput() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$AH" \
    -H 'Content-Type: application/vnd.debian.binary-package' --data-binary "@$3" \
    "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null || echo 000
}
# nput REPO POOLPATH FILE -> http code (native Debian upload, registered)
nput() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$AH" \
    --data-binary "@$3" "${BASE_URL}/debian/$1/$2" 2>/dev/null || echo 000
}
# backfill REPO DRY OUT -> http code
backfill() {
  curl -s -o "$3" -w '%{http_code}' --max-time 150 -X POST -H "$AH" \
    -H 'Content-Type: application/json' -d "{\"dry_run\": $2, \"limit\": 10000}" \
    "${BASE_URL}/api/v1/admin/repositories/$1/backfill-debian" 2>/dev/null || echo 000
}
j() { jq -r "$1 // empty" "$2" 2>/dev/null; }
counts() {
  jq -c '{artifacts_scanned, packages_registered, packages_relocated, artifacts_failed, truncated}' "$1" 2>/dev/null
}
# strip REPO_ID SQL_PATH_PREDICATE: drop the debian control documents of those rows
strip() {
  psqlq "DELETE FROM artifact_metadata WHERE format = 'debian' AND artifact_id IN \
         (SELECT id FROM artifacts WHERE repository_id = '$1' AND ($2))" >/dev/null
}
CAND_SQL="a.is_deleted = false AND a.path NOT LIKE 'dists/%' \
  AND lower(a.path) LIKE ANY (ARRAY['%.deb', '%.udeb', '%.ddeb']) \
  AND NOT EXISTS (SELECT 1 FROM artifact_metadata am WHERE am.artifact_id = a.id AND am.format = 'debian')"
candidates() { psqlq "SELECT count(*) FROM artifacts a WHERE a.repository_id = '$1' AND ${CAND_SQL}"; }
packages_index() {
  curl -s -o "$2" -w '%{http_code}' --max-time 60 \
    "${BASE_URL}/debian/$1/dists/stable/main/binary-amd64/Packages" 2>/dev/null || echo 000
}

# =============================================================================
# A. #5082: the dry run checks the move destination
# =============================================================================
OK_A=1
begin_test "setup A: hosted Debian repository with misfiled packages and taken destinations"
A_FAIL=""
if ! create_repo "$REPO_A" debian local; then
  OK_A=0; infra_fail "could not create hosted Debian repository ${REPO_A}"
else
  RA="$(repo_id "$REPO_A")"
  mkdeb free.deb akfree "free package" \
    && mkdeb clash1.deb akclash "misfiled copy" && mkdeb clash2.deb akclash "another package at the destination" \
    && mkdeb trash1.deb aktrash "misfiled copy" && mkdeb trash2.deb aktrash "trashed destination" \
    && mkdeb pair1.deb akpair "first misfiled copy" && mkdeb pair2.deb akpair "second misfiled copy" \
    || A_FAIL="fixture build failed"
  # Destinations that are not candidates: a native upload with different
  # bytes, and a native upload moved to the trash.
  c1="$(nput "$REPO_A" pool/main/a/akclash/akclash_1.0_amd64.deb "${DEBS}/clash2.deb")"
  c2="$(nput "$REPO_A" pool/main/a/aktrash/aktrash_1.0_amd64.deb "${DEBS}/trash2.deb")"
  c3="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X DELETE -H "$AH" \
        "${BASE_URL}/api/v1/repositories/${REPO_A}/artifacts/pool/main/a/aktrash/aktrash_1.0_amd64.deb" 2>/dev/null || echo 000)"
  # Misfiled candidates: Nexus pool/<letter>/<name>/ layout (and one with no
  # pool/ prefix) that the backfill files under pool/main/.
  g1="$(gput "$REPO_A" pool/a/akfree/akfree_1.0_amd64.deb "${DEBS}/free.deb")"
  g2="$(gput "$REPO_A" pool/a/akclash/akclash_1.0_amd64.deb "${DEBS}/clash1.deb")"
  g3="$(gput "$REPO_A" pool/a/aktrash/aktrash_1.0_amd64.deb "${DEBS}/trash1.deb")"
  g4="$(gput "$REPO_A" pool/a/akpair/akpair_1.0_amd64.deb "${DEBS}/pair1.deb")"
  g5="$(gput "$REPO_A" a/akpair/akpair_1.0_amd64.deb "${DEBS}/pair2.deb")"
  strip "$RA" "path NOT LIKE 'pool/main/%'"
  NA="$(candidates "$RA")"
  TRASHED="$(psqlq "SELECT is_deleted FROM artifacts WHERE repository_id = '${RA}' \
                    AND path = 'pool/main/a/aktrash/aktrash_1.0_amd64.deb'")"
  if [ -z "$A_FAIL" ] && [ "$c1" = 201 ] && [ "$c2" = 201 ] && [ "${c3:0:1}" = 2 ] \
     && [ "$TRASHED" = t ] && [ "${g1:0:1}${g2:0:1}${g3:0:1}${g4:0:1}${g5:0:1}" = 22222 ] \
     && [ "$NA" = 5 ]; then
    pass
  else
    OK_A=0
    infra_fail "${A_FAIL:-staging}: native ${c1}/${c2}, delete ${c3} (trashed=${TRASHED}), generic ${g1}/${g2}/${g3}/${g4}/${g5}; candidates ${NA} (want 5)"
  fi
fi

if [ "$OK_A" = 1 ]; then
  DA_CODE="$(backfill "$REPO_A" true "${WORK_DIR}/a-dry.json")"
  NA_AFTER_DRY="$(candidates "$RA")"
  FREE_PATH_AFTER_DRY="$(psqlq "SELECT count(*) FROM artifacts WHERE repository_id = '${RA}' \
      AND path = 'pool/a/akfree/akfree_1.0_amd64.deb' AND is_deleted = false")"
  RA_CODE="$(backfill "$REPO_A" false "${WORK_DIR}/a-real.json")"
  echo "  dry  ${DA_CODE} $(counts "${WORK_DIR}/a-dry.json")"
  echo "  real ${RA_CODE} $(counts "${WORK_DIR}/a-real.json")"
fi

begin_test "CONTROL: a dry run writes nothing (candidates and paths unchanged)"
if [ "$OK_A" = 1 ]; then
  if [ "$DA_CODE" = 200 ] && [ "$NA_AFTER_DRY" = 5 ] && [ "$FREE_PATH_AFTER_DRY" = 1 ]; then
    pass
  else
    fail "dry run -> ${DA_CODE}; candidates after it ${NA_AFTER_DRY} (want 5); misfiled akfree still at its path: ${FREE_PATH_AFTER_DRY} (want 1)" \
      "$(head -c 600 "${WORK_DIR}/a-dry.json" 2>/dev/null)"
  fi
else
  fail "skipped: setup A failed"
fi

begin_test "CONTROL: the real run moves the free package and refuses the three taken destinations"
if [ "$OK_A" = 1 ]; then
  R_REG="$(j .packages_registered "${WORK_DIR}/a-real.json")"
  R_REL="$(j .packages_relocated "${WORK_DIR}/a-real.json")"
  R_FAIL="$(j .artifacts_failed "${WORK_DIR}/a-real.json")"
  R_ERR="$(jq -r '.errors[]?' "${WORK_DIR}/a-real.json" 2>/dev/null)"
  pi="$(packages_index "$REPO_A" "${WORK_DIR}/a-packages")"
  if [ "$RA_CODE" = 200 ] && [ "$R_REG" = 2 ] && [ "$R_REL" = 2 ] && [ "$R_FAIL" = 3 ] \
     && grep -q 'akclash.*different package' <<<"$R_ERR" && grep -q 'aktrash.*deleted row' <<<"$R_ERR" \
     && grep -q 'akpair.*different package' <<<"$R_ERR" \
     && [ "$pi" = 200 ] && grep -q '^Filename: pool/main/a/akfree/akfree_1.0_amd64.deb$' "${WORK_DIR}/a-packages"; then
    pass
  else
    fail "real run -> ${RA_CODE} registered=${R_REG} relocated=${R_REL} failed=${R_FAIL} (want 2/2/3 with a different-package refusal for akclash and akpair and a deleted-row refusal for aktrash); Packages ${pi} lists pool/main/a/akfree: $(grep -c 'pool/main/a/akfree' "${WORK_DIR}/a-packages" 2>/dev/null)" \
      "$(head -c 1500 "${WORK_DIR}/a-real.json" 2>/dev/null)"
  fi
else
  fail "skipped: setup A failed"
fi

begin_test "FIX #5082: the dry run checks each move destination and reports the real run's refusals"
if [ "$OK_A" = 1 ]; then
  D_REG="$(j .packages_registered "${WORK_DIR}/a-dry.json")"
  D_REL="$(j .packages_relocated "${WORK_DIR}/a-dry.json")"
  D_FAIL="$(j .artifacts_failed "${WORK_DIR}/a-dry.json")"
  D_ERRS="$(jq -r '.errors[]?' "${WORK_DIR}/a-dry.json" 2>/dev/null | sort)"
  R_ERRS="$(jq -r '.errors[]?' "${WORK_DIR}/a-real.json" 2>/dev/null | sort)"
  if [ "$DA_CODE" = 200 ] && [ "$D_FAIL" = 3 ] && [ "$D_REG" = "$R_REG" ] && [ "$D_REL" = "$R_REL" ] \
     && [ "$D_FAIL" = "$R_FAIL" ] && [ "$D_ERRS" = "$R_ERRS" ]; then
    pass
  else
    fail "dry run registered=${D_REG} relocated=${D_REL} failed=${D_FAIL}; real run ${R_REG}/${R_REL}/${R_FAIL}. \
Before #5082 the dry run did not check the destination, so it counted the three refused moves as registrations." \
      "dry errors:
${D_ERRS:-<none>}
real errors:
${R_ERRS:-<none>}"
  fi
else
  fail "skipped: setup A failed"
fi

# =============================================================================
# B. #5088: a merged package counts once, in the dry run as in the real run
# =============================================================================
OK_B=1
begin_test "setup B: misfiled copies whose same-bytes destination is itself a candidate, across candidate pages"
B_DIAG=""
if ! create_repo "$REPO_B" debian local; then
  OK_B=0; infra_fail "could not create hosted Debian repository ${REPO_B}"
else
  RB="$(repo_id "$REPO_B")"
  # Filler candidates: .deb paths whose bytes are not a package, so each one
  # fails fast; they only push rows onto later candidate pages.
  printf 'not a debian package\n' > "${WORK_DIR}/filler.bin"
  seq 1 "$FILLERS" | xargs -P 8 -I{} curl -s -o /dev/null --max-time 60 -X PUT -H "$AH" \
    --data-binary "@${WORK_DIR}/filler.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_B}/artifacts/filler/akfill{}_1.0_amd64.deb"
  # Pairs: pool/a/akmrgN/... (misfiled) and pool/main/a/akmrgN/... (its
  # destination), same bytes, both candidates. Ids are random, so add pairs
  # until the walk order holds at least one pair with the misfiled row on an
  # earlier page than its destination ("cross") and one on the same page
  # ("same"). A pair whose destination comes first counts 2 on every image
  # (documented in #5212) and is only included in the expected total.
  NPAIRS=0; CROSS=0; SAME=0; REV=0; PUT_BAD=0
  while [ "$NPAIRS" -lt 40 ] && { [ "$CROSS" -lt 1 ] || [ "$SAME" -lt 1 ]; }; do
    for _ in 1 2 3 4 5 6 7 8; do
      NPAIRS=$((NPAIRS + 1)); n="akmrg${NPAIRS}"
      mkdeb "${n}.deb" "$n" "merged package ${NPAIRS}" || PUT_BAD=$((PUT_BAD + 1))
      cm="$(gput "$REPO_B" "pool/a/${n}/${n}_1.0_amd64.deb" "${DEBS}/${n}.deb")"
      cd_="$(gput "$REPO_B" "pool/main/a/${n}/${n}_1.0_amd64.deb" "${DEBS}/${n}.deb")"
      [ "${cm:0:1}${cd_:0:1}" = 22 ] || PUT_BAD=$((PUT_BAD + 1))
    done
    strip "$RB" "path LIKE '%akmrg%'"
    # rank of every candidate in the walk order; page = rank / 500
    psqlq "SELECT a.path, (row_number() OVER (ORDER BY a.id) - 1) / ${PAGE} \
           FROM artifacts a WHERE a.repository_id = '${RB}' AND ${CAND_SQL} ORDER BY a.id" \
      > "${WORK_DIR}/b-walk"
    CROSS=0; SAME=0; REV=0
    for i in $(seq 1 "$NPAIRS"); do
      n="akmrg${i}"
      lm="$(grep -n "^pool/a/${n}/${n}_1.0_amd64.deb|" "${WORK_DIR}/b-walk" | head -1)"
      ld="$(grep -n "^pool/main/a/${n}/${n}_1.0_amd64.deb|" "${WORK_DIR}/b-walk" | head -1)"
      [ -n "$lm" ] && [ -n "$ld" ] || continue
      if [ "${lm%%:*}" -gt "${ld%%:*}" ]; then REV=$((REV + 1))
      elif [ "${lm##*|}" != "${ld##*|}" ]; then CROSS=$((CROSS + 1))
      else SAME=$((SAME + 1)); fi
    done
  done
  NB="$(candidates "$RB")"
  EXP_REG=$((CROSS + SAME + 2 * REV))
  B_DIAG="pairs=${NPAIRS} cross-page=${CROSS} same-page=${SAME} destination-first=${REV}; candidates=${NB}; expected registered=${EXP_REG}"
  echo "  ${B_DIAG}"
  if [ "$PUT_BAD" = 0 ] && [ "$CROSS" -ge 1 ] && [ "$SAME" -ge 1 ] \
     && [ "$NB" = "$((FILLERS + 2 * NPAIRS))" ]; then
    pass
  else
    OK_B=0
    infra_fail "could not stage the walk order (${PUT_BAD} failed uploads): ${B_DIAG} (want candidates $((FILLERS + 2 * NPAIRS)))"
  fi
fi

if [ "$OK_B" = 1 ]; then
  DB_CODE="$(backfill "$REPO_B" true "${WORK_DIR}/b-dry.json")"
  RB_CODE="$(backfill "$REPO_B" false "${WORK_DIR}/b-real.json")"
  echo "  dry  ${DB_CODE} $(counts "${WORK_DIR}/b-dry.json")"
  echo "  real ${RB_CODE} $(counts "${WORK_DIR}/b-real.json")"
  BD_REG="$(j .packages_registered "${WORK_DIR}/b-dry.json")"
  BR_REG="$(j .packages_registered "${WORK_DIR}/b-real.json")"
  BR_FAIL="$(j .artifacts_failed "${WORK_DIR}/b-real.json")"
fi

begin_test "CONTROL: the real run merges every misfiled copy and Packages lists each package once"
if [ "$OK_B" = 1 ]; then
  pi="$(packages_index "$REPO_B" "${WORK_DIR}/b-packages")"
  LISTED="$(grep -c '^Package: akmrg' "${WORK_DIR}/b-packages" 2>/dev/null)"
  UNIQ="$(grep '^Package: akmrg' "${WORK_DIR}/b-packages" 2>/dev/null | sort -u | wc -l)"
  LIVE_MISFILED="$(psqlq "SELECT count(*) FROM artifacts WHERE repository_id = '${RB}' \
       AND path LIKE 'pool/a/akmrg%' AND is_deleted = false")"
  if [ "$RB_CODE" = 200 ] && [ "$BR_FAIL" = "$FILLERS" ] && [ "$pi" = 200 ] \
     && [ "$LISTED" = "$NPAIRS" ] && [ "$UNIQ" = "$NPAIRS" ] && [ "$LIVE_MISFILED" = 0 ]; then
    pass
  else
    fail "real run -> ${RB_CODE} failed=${BR_FAIL} (want the ${FILLERS} fillers); Packages ${pi} lists ${LISTED} akmrg entries (${UNIQ} distinct, want ${NPAIRS}); live misfiled rows left ${LIVE_MISFILED} (want 0)" \
      "$(counts "${WORK_DIR}/b-real.json")"
  fi
else
  fail "skipped: setup B failed"
fi

begin_test "FIX #5088: the dry run counts a merged package as the real run does (destination on a later page)"
if [ "$OK_B" = 1 ]; then
  if [ "$DB_CODE" = 200 ] && [ -n "$BD_REG" ] && [ "$BD_REG" = "$BR_REG" ]; then
    pass
  else
    fail "dry run packages_registered=${BD_REG}, real run ${BR_REG} (${B_DIAG}). Before #5088 the dry run counted a merged package again when its destination row came up as a candidate on a later page." \
      "dry: $(counts "${WORK_DIR}/b-dry.json")
real: $(counts "${WORK_DIR}/b-real.json")"
  fi
else
  fail "skipped: setup B failed"
fi

begin_test "FIX #5088: a misfiled copy merged into a candidate destination registers the package once"
if [ "$OK_B" = 1 ]; then
  if [ "$RB_CODE" = 200 ] && [ "$BR_REG" = "$EXP_REG" ]; then
    pass
  else
    fail "real run packages_registered=${BR_REG}, want ${EXP_REG} (${B_DIAG}: 1 per pair whose misfiled row comes first, 2 per destination-first pair). \
Before #5088 a destination later on the same page was registered a second time." \
      "$(counts "${WORK_DIR}/b-real.json")"
  fi
else
  fail "skipped: setup B failed"
fi

# =============================================================================
# C. #5072: revisions in a previous storage location are collected
# =============================================================================
DOCS="repomd.xml primary.xml.gz filelists.xml.gz other.xml.gz"
LIB="akdep-lib-1.0-1.noarch.rpm"
APP="akdep-app-2.0-1.noarch.rpm"
rpm_publish() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$AH" \
    --upload-file "${RPMFIX}/$1" "${BASE_URL}/rpm/${REPO_C}/packages/$1" 2>/dev/null || echo 000
}
# rebuild_wait OUT -> http code (POST without wait first: forces a new build)
rebuild_now() {
  curl -s -o /dev/null --max-time 60 -X POST -H "$AH" \
    "${BASE_URL}/api/v1/repositories/${REPO_C}/rpm/repodata/rebuild" 2>/dev/null
  curl -s -o "$1" -w '%{http_code}' --max-time 330 -X POST -H "$AH" \
    "${BASE_URL}/api/v1/repositories/${REPO_C}/rpm/repodata/rebuild?wait=true" 2>/dev/null || echo 000
}
# present DIR -> how many of the four documents exist under DIR in the backend
present() {
  local d n=0
  for d in $DOCS; do
    docker exec "$BACKEND_CTR" test -e "$1/$d" 2>/dev/null && n=$((n + 1))
  done
  echo "$n"
}

OK_C=1
begin_test "setup C: hosted RPM repository with two precomputed revisions in its first location"
if [ ! -s "${RPMFIX}/${LIB}" ] || [ ! -s "${RPMFIX}/${APP}" ]; then
  OK_C=0; infra_fail "fixture RPMs missing under ${RPMFIX}"
elif ! create_repo "$REPO_C" rpm local; then
  OK_C=0; infra_fail "could not create hosted RPM repository ${REPO_C}"
else
  RC="$(repo_id "$REPO_C")"
  p1="$(rpm_publish "$LIB")"
  b1="$(rebuild_now "${WORK_DIR}/c1.json")"
  p2="$(rpm_publish "$APP")"
  b2="$(rebuild_now "${WORK_DIR}/c2.json")"
  REV1="$(j .revision "${WORK_DIR}/c1.json")"; REV2="$(j .revision "${WORK_DIR}/c2.json")"
  OLD="$(psqlq "SELECT storage_path FROM repositories WHERE id = '${RC}'")"
  if [ "$p1" = 201 ] && [ "$p2" = 201 ] && [ "$b1" = 200 ] && [ "$b2" = 200 ] \
     && [ -n "$REV1" ] && [ -n "$REV2" ] && [ "$REV2" -gt "$REV1" ] && [ -n "$OLD" ]; then
    pass
  else
    OK_C=0
    infra_fail "publish ${p1}/${p2}; rebuild ${b1}/${b2} revisions '${REV1}'/'${REV2}'; storage_path '${OLD}'" \
      "$(head -c 400 "${WORK_DIR}/c2.json" 2>/dev/null)"
  fi
fi

begin_test "CONTROL: the current and previous revisions are stored in the first location"
if [ "$OK_C" = 1 ]; then
  O1="$(present "${OLD}/repodata/${RC}/${REV1}")"; O2="$(present "${OLD}/repodata/${RC}/${REV2}")"
  if [ "$O1" = 4 ] && [ "$O2" = 4 ]; then
    pass
  else
    fail "documents under ${OLD}/repodata/${RC}/: revision ${REV1}: ${O1}/4, revision ${REV2}: ${O2}/4" \
      "$(docker exec "$BACKEND_CTR" ls -R "${OLD}/repodata" 2>&1 | head -40)"
  fi
else
  fail "skipped: setup C failed"
fi

if [ "$OK_C" = 1 ]; then
  # The operator moves the repository: copy its package objects to a new
  # directory and point storage_path at it (no API changes a repository's
  # storage location). The previous location keeps its repodata revisions.
  NEW="${OLD%/}-relocated"
  # (the backend image has coreutils but no shell)
  MV_OUT="$(docker exec "$BACKEND_CTR" cp -a "${OLD%/}" "$NEW" 2>&1 \
            && docker exec "$BACKEND_CTR" rm -rf "${NEW}/repodata" 2>&1)"
  MV_RC=$?
  psqlq "UPDATE repositories SET storage_path = '${NEW}' WHERE id = '${RC}'" >/dev/null
  b3="$(rebuild_now "${WORK_DIR}/c3.json")"
  b4="$(rebuild_now "${WORK_DIR}/c4.json")"
  REV3="$(j .revision "${WORK_DIR}/c3.json")"; REV4="$(j .revision "${WORK_DIR}/c4.json")"
  echo "  revisions ${REV1} ${REV2} (old ${OLD}) -> ${REV3} ${REV4} (new ${NEW}); rebuild ${b3}/${b4}"
fi

begin_test "CONTROL: after the move, two builds serve the newest revision from the new location"
if [ "$OK_C" = 1 ]; then
  ROW="$(psqlq "SELECT built_revision || '|' || storage_path || '|' || encode(built_repomd, 'hex') \
                FROM rpm_repodata_roots WHERE repository_id = '${RC}' AND root = ''")"
  ROW_REV="${ROW%%|*}"; rest="${ROW#*|}"; ROW_PATH="${rest%%|*}"; ROW_HEX="${rest#*|}"
  curl -s -o "${WORK_DIR}/repomd.xml" --max-time 60 "${BASE_URL}/rpm/${REPO_C}/repodata/repomd.xml" 2>/dev/null
  curl -s -o "${WORK_DIR}/primary.xml.gz" --max-time 60 "${BASE_URL}/rpm/${REPO_C}/repodata/primary.xml.gz" 2>/dev/null
  SERVED_HEX="$(od -An -v -tx1 "${WORK_DIR}/repomd.xml" 2>/dev/null | tr -d ' \n')"
  PKGS="$(gzip -dc "${WORK_DIR}/primary.xml.gz" 2>/dev/null | grep -o '<name>akdep-[a-z]*</name>' | sort -u | wc -l)"
  N3="$(present "${NEW}/repodata/${RC}/${REV3}")"; N4="$(present "${NEW}/repodata/${RC}/${REV4}")"
  if [ "$MV_RC" = 0 ] && [ "$b3" = 200 ] && [ "$b4" = 200 ] && [ -n "$REV3" ] && [ -n "$REV4" ] \
     && [ "$REV3" -gt "$REV2" ] && [ "$REV4" -gt "$REV3" ] && [ "$ROW_REV" = "$REV4" ] \
     && [ "$ROW_PATH" = "$NEW" ] && [ -n "$ROW_HEX" ] && [ "$ROW_HEX" = "$SERVED_HEX" ] \
     && [ "$PKGS" = 2 ] && [ "$N3" = 4 ] && [ "$N4" = 4 ]; then
    pass
  else
    fail "move rc ${MV_RC} ${MV_OUT}; rebuild ${b3}/${b4} revisions '${REV3}'/'${REV4}' (after ${REV2}); row revision ${ROW_REV} location ${ROW_PATH} (want ${REV4} at ${NEW}); served repomd is the row's: $([ "$ROW_HEX" = "$SERVED_HEX" ] && echo yes || echo no); primary lists ${PKGS}/2 packages; new location documents ${N3}/4 and ${N4}/4"
  fi
else
  fail "skipped: setup C failed"
fi

begin_test "FIX #5072: superseded revisions in the previous storage location are deleted"
if [ "$OK_C" = 1 ]; then
  L1="$(present "${OLD}/repodata/${RC}/${REV1}")"; L2="$(present "${OLD}/repodata/${RC}/${REV2}")"
  if [ "$b4" = 200 ] && [ "$L1" = 0 ] && [ "$L2" = 0 ]; then
    pass
  else
    fail "after revisions ${REV3} and ${REV4} in ${NEW}, the previous location still holds revision ${REV1}: ${L1}/4 and revision ${REV2}: ${L2}/4 documents (want 0). \
Before #5072 the builder deleted superseded revisions only through the current location." \
      "$(docker exec "$BACKEND_CTR" ls -R "${OLD}/repodata" 2>&1 | head -40)"
  fi
else
  fail "skipped: setup C failed"
fi

end_suite
