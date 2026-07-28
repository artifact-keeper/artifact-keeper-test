#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade/origin_cases.sh — additional upgrade ORIGIN legs (issue #2688)
# =============================================================================
# Sourced by oracle.sh AFTER it has defined the shared per-slot machinery
# (compose / wait_health / get_code / get_body), sourced seed.sh (seed_login /
# seed_put / seed_get_code) and the manifest (CAND_IMAGE / ADMPASS /
# UPGRADE_ORIGIN_156 / UPGRADE_ORIGIN_158 / MIG_* ). It adds two more origin
# legs, each a distinct JUnit suite run in its OWN subshell by oracle.sh so a
# failure in one cannot poison the other. Each leg resets the SAME slot with
# `down -v`, stands PHASE 1 up on a PUBLISHED prior-release image, seeds, then
# swaps ONLY the backend to the candidate (PHASE 2) against the same
# postgres+minio volumes and lets the candidate's migrations run — exactly the
# two-phase pattern the legacy-rowless gate uses, differing only in the origin
# image and the post-upgrade assertions.
#
#   upgrade_case_v156_noop
#     Origin = UPGRADE_ORIGIN_156 (a release PRE-dating the Maven cloud
#     isolation migrations). No-divergence / no-op path: assert the candidate
#     boots on the 1.5.6 volume with NO failed/divergent migration row and the
#     ledger only grew forward (no history rewrite), and an artifact seeded on
#     1.5.6 is byte-intact after the upgrade (no data loss).
#
#   upgrade_case_v158_mig154_155
#     Origin = UPGRADE_ORIGIN_158 (the release that already ships BOTH Maven
#     cloud isolation migrations: MIG_MAVEN_GUARD = #2504/#2507 cross-tenant
#     read+write guard, MIG_MAVEN_ATTRIB = #2574/#2584 row-less attribution
#     table). Assert those two migrations apply idempotently across the upgrade
#     (present exactly once, success, installed_on UNCHANGED = not re-run, no
#     failed rows) and that cross-tenant isolation still holds after the upgrade.
#
# All version-specific inputs (origin images, migration version numbers, ledger
# table name) come from the manifest with env-overridable defaults, so a private
# registry mirror or a migration renumber never needs a code edit here.
# =============================================================================

# Defensive defaults (normally set by the manifest, sourced in oracle.sh).
: "${MIG_LEDGER_TABLE:=_sqlx_migrations}"
: "${MIG_MAVEN_GUARD:=154}"
: "${MIG_MAVEN_ATTRIB:=155}"
: "${UPGRADE_ORIGIN_156:=ghcr.io/artifact-keeper/artifact-keeper-backend:1.5.6}"
: "${UPGRADE_ORIGIN_158:=ghcr.io/artifact-keeper/artifact-keeper-backend:1.5.8}"

# _mig_q <sql> -> single scalar value (whitespace-stripped), never aborts.
# The sqlx migration ledger (_sqlx_migrations) columns used: version (bigint),
# success (bool), installed_on (timestamptz). All queries are `|| true`-guarded
# so a missing table on an unexpected candidate yields an EMPTY value that a
# load-bearing assertion turns into a loud FAIL (never a false pass, never an
# abort under common.sh `set -e`).
_mig_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" \
    2>/dev/null | tr -d '[:space:]' || true
}

# _mig_present -> 't' if the ledger table exists, else 'f'/empty.
_mig_present() {
  _mig_q "SELECT to_regclass('public.${MIG_LEDGER_TABLE}') IS NOT NULL;"
}

# -----------------------------------------------------------------------------
# Leg 1: v1.5.6-origin — no-divergence / no-op upgrade (no data loss)
# -----------------------------------------------------------------------------
upgrade_case_v156_noop() {
  local OLD156="${UPGRADE_ORIGIN_156}"
  begin_suite "upgrade-origin-v156-noop-s3"
  echo "== v1.5.6-origin: no-divergence / no-op upgrade (${OLD156} -> ${CAND_IMAGE}) =="

  # --- PHASE 1: clean slot, stand up the 1.5.6 origin, seed durable data -----
  compose down -v >/dev/null 2>&1 || true
  BACKEND_IMAGE="$OLD156" compose up -d --wait >/dev/null 2>&1 || true
  if ! wait_health 40; then
    begin_test "v156 PHASE1: origin ${OLD156} healthy on s3"
    fail "origin image ${OLD156} did not become healthy (image unpullable, or not a clean migration ancestor of the candidate)"
    BACKEND_IMAGE="$OLD156" compose logs backend --tail=40 2>&1 | tail -40 || true
    end_suite; return 1
  fi

  local suf="v156${RUN_ID:-r}$RANDOM"
  local repo="up156-$suf" gav="com/up156/$suf/1.0" jar="up156-$suf-1.0.jar"
  local secret="UP156-KEEP-$suf"
  local TOKO; TOKO="$(seed_login "$BASE_URL" admin "$ADMPASS")"
  if [ -z "$TOKO" ]; then
    begin_test "v156 PHASE1: admin login on origin ${OLD156}"
    fail "admin login failed on ${OLD156}"; end_suite; return 1
  fi
  curl -s -X POST "$BASE_URL/api/v1/repositories" -H "Authorization: Bearer $TOKO" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$repo\",\"name\":\"$repo\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null || true
  local p_put; p_put=$(seed_put "$BASE_URL" "/maven/$repo/$gav/$jar" "$TOKO" "PK\003\004$secret")
  local a_get; a_get=$(seed_get_code "$BASE_URL" "/maven/$repo/$gav/$jar" "$TOKO")
  begin_test "v156 PHASE1: seeded artifact stored + owner-readable on origin ${OLD156}"
  if [ "$a_get" = "200" ]; then
    pass
  else
    fail "seed artifact not readable on origin (PUT=$p_put GET=$a_get); fixture invalid"
    end_suite; return 1
  fi

  # Capture the origin migration ledger (baseline for the no-divergence check).
  local pre_present pre_count pre_max
  pre_present="$(_mig_present)"
  pre_count="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE};")"
  pre_max="$(_mig_q "SELECT COALESCE(max(version),0) FROM ${MIG_LEDGER_TABLE} WHERE success;")"
  echo "   origin ledger: table=${MIG_LEDGER_TABLE} present=${pre_present:-?} applied=${pre_count:-?} max_version=${pre_max:-?}"

  # --- PHASE 2: swap ONLY the backend to the candidate (same volumes) --------
  echo "== v156 PHASE2: swap backend -> candidate ${CAND_IMAGE} (same volume) =="
  BACKEND_IMAGE="$CAND_IMAGE" compose up -d backend >/dev/null 2>&1 || true
  if ! wait_health 60; then
    begin_test "v156 PHASE2: candidate boots on the 1.5.6-origin volume (no-divergence)"
    fail "candidate ${CAND_IMAGE} did not become healthy after upgrade from ${OLD156} (divergent migration history against the 1.5.6 volume?)"
    BACKEND_IMAGE="$CAND_IMAGE" compose logs backend --tail=60 2>&1 | tail -60 || true
    end_suite; return 1
  fi
  local migdone
  migdone=$(BACKEND_IMAGE="$CAND_IMAGE" compose logs backend 2>&1 | grep -c "Database migrations complete" || true)
  echo "   candidate healthy; 'migrations complete' log hits=${migdone}"

  # (a) NO-DIVERGENCE: booted healthy + ledger present + zero failed rows +
  #     ledger only grew forward (no shrink, max_version did not go backward).
  local post_present post_count post_max post_fail
  post_present="$(_mig_present)"
  post_count="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE};")"
  post_max="$(_mig_q "SELECT COALESCE(max(version),0) FROM ${MIG_LEDGER_TABLE} WHERE success;")"
  post_fail="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE} WHERE success = false;")"
  echo "   post-upgrade ledger: present=${post_present:-?} applied=${post_count:-?} max_version=${post_max:-?} failed_rows=${post_fail:-?}"
  begin_test "v156 (a): candidate applied the 1.5.6->candidate delta cleanly (no failed/divergent migration)"
  if [ "$post_present" = "t" ] && [ "${post_fail:-1}" = "0" ] \
     && [ "${post_count:-0}" -ge "${pre_count:-0}" ] 2>/dev/null \
     && [ "${post_max:-0}" -ge "${pre_max:-0}" ] 2>/dev/null; then
    pass
  else
    fail "migration ledger shows a failed/shrunken/divergent history after upgrade from ${OLD156}" \
      "table=${MIG_LEDGER_TABLE} present=${post_present:-<none>}; pre(count=${pre_count} max=${pre_max}) post(count=${post_count} max=${post_max} failed=${post_fail}). A clean forward upgrade only appends success=true rows and never rewrites/removes an applied migration."
  fi

  # (b) NO DATA LOSS: the artifact seeded on 1.5.6 is byte-intact post-upgrade.
  local TOKN; TOKN="$(seed_login "$BASE_URL" admin "$ADMPASS")"
  local pu_get pu_body has_secret=no
  pu_get=$(get_code "/maven/$repo/$gav/$jar" "$TOKN")
  pu_body=$(get_body "/maven/$repo/$gav/$jar" "$TOKN")
  echo "$pu_body" | grep -q "$secret" && has_secret=yes
  begin_test "v156 (b): artifact seeded on 1.5.6 is intact after upgrade (no data loss)"
  if [ "$pu_get" = "200" ] && [ "$has_secret" = "yes" ]; then
    pass
  else
    fail "artifact seeded on ${OLD156} not intact after upgrade (HTTP $pu_get, own bytes present=$has_secret)" \
      "owner GET /maven/${repo}/${gav}/${jar} => ${pu_get}; a clean upgrade must preserve pre-existing catalogued data."
  fi

  end_suite
}

# -----------------------------------------------------------------------------
# Leg 2: v1.5.8-origin — migrations 154+155 idempotent + isolation holds
# -----------------------------------------------------------------------------
upgrade_case_v158_mig154_155() {
  local OLD158="${UPGRADE_ORIGIN_158}"
  local MG="${MIG_MAVEN_GUARD}" MA="${MIG_MAVEN_ATTRIB}"
  begin_suite "upgrade-origin-v158-mig154-155-s3"
  echo "== v1.5.8-origin: migrations ${MG}+${MA} idempotent + isolation (${OLD158} -> ${CAND_IMAGE}) =="

  # --- PHASE 1: clean slot, stand up the 1.5.8 origin, seed isolation shape ---
  compose down -v >/dev/null 2>&1 || true
  BACKEND_IMAGE="$OLD158" compose up -d --wait >/dev/null 2>&1 || true
  if ! wait_health 40; then
    begin_test "v158 PHASE1: origin ${OLD158} healthy on s3"
    fail "origin image ${OLD158} did not become healthy (image unpullable, or not a clean migration ancestor of the candidate)"
    BACKEND_IMAGE="$OLD158" compose logs backend --tail=40 2>&1 | tail -40 || true
    end_suite; return 1
  fi

  # Fixture: alice = developer on MVA only; a secret artifact lives in MVB.
  local suf="v158${RUN_ID:-r}$RANDOM"
  local mva="up158a-$suf" mvb="up158b-$suf" alice="al158-$suf" apass="Al158Pass!2026x"
  local gav="com/up158/$suf/1.0" jar="up158-$suf-1.0.jar" secret="UP158-SECRET-$suf"
  local TOKO; TOKO="$(seed_login "$BASE_URL" admin "$ADMPASS")"
  if [ -z "$TOKO" ]; then
    begin_test "v158 PHASE1: admin login on origin ${OLD158}"
    fail "admin login failed on ${OLD158}"; end_suite; return 1
  fi
  curl -s -X POST "$BASE_URL/api/v1/users" -H "Authorization: Bearer $TOKO" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$alice\",\"email\":\"$alice@t.test\",\"password\":\"$apass\",\"is_admin\":false}" >/dev/null || true
  local k
  for k in "$mva" "$mvb"; do
    curl -s -X POST "$BASE_URL/api/v1/repositories" -H "Authorization: Bearer $TOKO" \
      -H 'Content-Type: application/json' \
      -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null || true
  done
  # Grant alice developer(write) on MVA only (none on MVB) — same technique as seed.sh.
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
    INSERT INTO role_assignments (user_id, role_id, repository_id)
    SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
    WHERE u.username='$alice' AND r.name='developer' AND repo.key='$mva'
    ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

  seed_put "$BASE_URL" "/maven/$mvb/$gav/$jar" "$TOKO" "PK\003\004$secret" >/dev/null
  local a_get; a_get=$(seed_get_code "$BASE_URL" "/maven/$mvb/$gav/$jar" "$TOKO")
  begin_test "v158 PHASE1: victim artifact stored + owner-readable on origin ${OLD158}"
  if [ "$a_get" = "200" ]; then
    pass
  else
    fail "victim artifact not readable on origin (GET=$a_get); fixture invalid"
    end_suite; return 1
  fi

  # Pre-upgrade isolation baseline: alice must NOT reach MVB via her own repo.
  local ATOKO; ATOKO="$(seed_login "$BASE_URL" "$alice" "$apass")"
  local pre_leak; pre_leak=$(get_code "/maven/$mva/$gav/$jar" "$ATOKO")
  echo "   origin isolation baseline: alice cross-tenant GET via ${mva} => ${pre_leak} (want 403/404 on 1.5.8)"

  # Capture 154/155 ledger state on the origin (v1.5.8 must ship both).
  local pre_c154 pre_c155 pre_ok154 pre_ok155 pre_ts154 pre_ts155
  pre_c154="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE} WHERE version=$MG;")"
  pre_c155="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE} WHERE version=$MA;")"
  pre_ok154="$(_mig_q "SELECT bool_and(success) FROM ${MIG_LEDGER_TABLE} WHERE version=$MG;")"
  pre_ok155="$(_mig_q "SELECT bool_and(success) FROM ${MIG_LEDGER_TABLE} WHERE version=$MA;")"
  pre_ts154="$(_mig_q "SELECT COALESCE(extract(epoch FROM max(installed_on))::bigint,0) FROM ${MIG_LEDGER_TABLE} WHERE version=$MG;")"
  pre_ts155="$(_mig_q "SELECT COALESCE(extract(epoch FROM max(installed_on))::bigint,0) FROM ${MIG_LEDGER_TABLE} WHERE version=$MA;")"
  echo "   origin ledger: v${MG}(count=${pre_c154:-?} ok=${pre_ok154:-?} ts=${pre_ts154:-?}) v${MA}(count=${pre_c155:-?} ok=${pre_ok155:-?} ts=${pre_ts155:-?})"

  begin_test "v158 PHASE1: origin ${OLD158} already ships migrations ${MG}+${MA}"
  if [ "${pre_c154:-0}" = "1" ] && [ "${pre_c155:-0}" = "1" ] \
     && [ "${pre_ok154}" = "t" ] && [ "${pre_ok155}" = "t" ]; then
    pass
  else
    fail "origin ${OLD158} does not have migrations ${MG}+${MA} applied as expected" \
      "v${MG} count=${pre_c154} ok=${pre_ok154}; v${MA} count=${pre_c155} ok=${pre_ok155}. v1.5.8 must ship both Maven cloud isolation migrations; check UPGRADE_ORIGIN_158 / MIG_MAVEN_GUARD / MIG_MAVEN_ATTRIB / MIG_LEDGER_TABLE."
    end_suite; return 1
  fi

  # --- PHASE 2: swap to the candidate; 154+155 already applied -> must no-op --
  echo "== v158 PHASE2: swap backend -> candidate ${CAND_IMAGE} (same volume) =="
  BACKEND_IMAGE="$CAND_IMAGE" compose up -d backend >/dev/null 2>&1 || true
  if ! wait_health 60; then
    begin_test "v158 PHASE2: candidate boots on the 1.5.8-origin volume"
    fail "candidate ${CAND_IMAGE} did not become healthy after upgrade from ${OLD158}"
    BACKEND_IMAGE="$CAND_IMAGE" compose logs backend --tail=60 2>&1 | tail -60 || true
    end_suite; return 1
  fi
  local migdone
  migdone=$(BACKEND_IMAGE="$CAND_IMAGE" compose logs backend 2>&1 | grep -c "Database migrations complete" || true)
  echo "   candidate healthy; 'migrations complete' log hits=${migdone}"

  # (a) 154+155 IDEMPOTENT: still exactly one success row each, installed_on
  #     UNCHANGED (proves not re-applied), and no failed rows anywhere.
  local post_c154 post_c155 post_ok154 post_ok155 post_ts154 post_ts155 post_fail
  post_c154="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE} WHERE version=$MG;")"
  post_c155="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE} WHERE version=$MA;")"
  post_ok154="$(_mig_q "SELECT bool_and(success) FROM ${MIG_LEDGER_TABLE} WHERE version=$MG;")"
  post_ok155="$(_mig_q "SELECT bool_and(success) FROM ${MIG_LEDGER_TABLE} WHERE version=$MA;")"
  post_ts154="$(_mig_q "SELECT COALESCE(extract(epoch FROM max(installed_on))::bigint,0) FROM ${MIG_LEDGER_TABLE} WHERE version=$MG;")"
  post_ts155="$(_mig_q "SELECT COALESCE(extract(epoch FROM max(installed_on))::bigint,0) FROM ${MIG_LEDGER_TABLE} WHERE version=$MA;")"
  post_fail="$(_mig_q "SELECT count(*) FROM ${MIG_LEDGER_TABLE} WHERE success = false;")"
  echo "   post-upgrade ledger: v${MG}(count=${post_c154:-?} ok=${post_ok154:-?} ts=${post_ts154:-?}) v${MA}(count=${post_c155:-?} ok=${post_ok155:-?} ts=${post_ts155:-?}) failed=${post_fail:-?}"
  begin_test "v158 (a): migrations ${MG}+${MA} apply idempotently across the upgrade (no re-run, no duplicate, no failure)"
  if [ "${post_c154:-0}" = "1" ] && [ "${post_c155:-0}" = "1" ] \
     && [ "${post_ok154}" = "t" ] && [ "${post_ok155}" = "t" ] \
     && [ "${post_ts154}" = "${pre_ts154}" ] && [ "${post_ts155}" = "${pre_ts155}" ] \
     && [ "${post_fail:-1}" = "0" ]; then
    pass
  else
    fail "migrations ${MG}/${MA} were re-applied, duplicated, or failed on upgrade from ${OLD158}" \
      "pre v${MG}(c=${pre_c154} ts=${pre_ts154}) v${MA}(c=${pre_c155} ts=${pre_ts155}); post v${MG}(c=${post_c154} ts=${post_ts154}) v${MA}(c=${post_c155} ts=${post_ts155}) failed=${post_fail}. An idempotent upgrade leaves each row present once, success=true, installed_on unchanged."
  fi

  # (b) ISOLATION HOLDS: owner reads MVB; alice cannot; no secret bytes leak.
  local TOKN ATOKN
  TOKN="$(seed_login "$BASE_URL" admin "$ADMPASS")"
  ATOKN="$(seed_login "$BASE_URL" "$alice" "$apass")"
  local own_get; own_get=$(get_code "/maven/$mvb/$gav/$jar" "$TOKN")
  begin_test "v158 (b1): owner can still read the victim artifact after upgrade"
  { [ "$own_get" = "200" ]; } && pass || fail "owner read of MVB artifact regressed after upgrade (HTTP $own_get)"

  local al_get al_body
  al_get=$(get_code "/maven/$mva/$gav/$jar" "$ATOKN")
  al_body=$(get_body "/maven/$mva/$gav/$jar" "$ATOKN")
  begin_test "v158 (b2): cross-tenant isolation holds after upgrade from ${OLD158} (no #2504/#2584 leak)"
  if echo "$al_body" | grep -q "$secret"; then
    fail "cross-tenant LEAK: alice read MVB's artifact bytes via ${mva} (HTTP $al_get) after upgrade from ${OLD158}"
  elif [ "$al_get" = "403" ] || [ "$al_get" = "404" ]; then
    pass
  else
    fail "unexpected cross-tenant response for alice after upgrade (HTTP $al_get)"
  fi

  end_suite
}
