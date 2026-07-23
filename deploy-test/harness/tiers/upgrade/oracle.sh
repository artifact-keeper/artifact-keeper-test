#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade/oracle.sh — upgrade-with-LEGACY-DATA gate (#2574/#2584 class)
# =============================================================================
# Matrix row 6. Proves that upgrading a cloud-storage deployment that already
# contains OLD-SHAPE (row-less Maven) data (a) does NOT leave legitimate owner
# access broken (#2574) AND (b) does NOT open a cross-tenant leak (#2504/#2584).
#
# MULTI-ORIGIN (#2688): the tier runs the SAME two-phase in-place image swap
# against EVERY supported upgrade origin so all origins are proven by a real
# container swap, not just unit tests. Each origin is an independent begin_suite:
#   * v1.5.6-origin  — max migration slot 153, NO divergence. The candidate's
#                      repair_release_1_5_x_divergence step no-ops and the
#                      migrator applies 154..HEAD fresh. "No-op / no-divergence"
#                      case: the clean-boot assertion IS the proof the repair
#                      correctly does nothing on a pre-divergence history.
#   * v1.5.7-origin  — slot 154, pre-attribution base (the historical default;
#                      ak-backend:nexus2457-v157base). The #2574/#2584 legacy
#                      class only manifests on a shared object store, so this
#                      row-less-Maven fixture is the load-bearing payload.
#   * v1.5.8-origin  — slots 154 AND 155 diverged (the maven_flat_object_owner
#                      attribution table shipped as 155 on the release/1.5.x
#                      line but was renumbered to 163 on the merge to main).
#                      The candidate must reconcile the divergence (155->163
#                      renumber + apply 168 fresh) and still boot: a clean boot
#                      + intact fixture assertions prove the renumber path.
#
# Two-phase, driven BY THIS ORACLE (the only tier that does so — see manifest):
#   PHASE 1  stand up on the OLD origin backend, seed the row-less legacy Maven
#            shape (tiers/upgrade/seed.sh, which reuses the isolation prove.sh
#            Scenario F plant+strip technique), and establish the fixture is real.
#   PHASE 2  swap ONLY the backend container to the candidate image
#            (--backend-image, exported by run.sh as BACKEND_IMAGE) against the
#            SAME postgres+minio volumes, let its migrations run, then re-run the
#            isolation assertions.
#
# Discriminating (RELEASE_GATE=1), per origin:
#   * FIXED candidate (attribution migration present): the row-less signature
#     sidecar is RESTORED to its owner (200) AND stays isolated from other
#     tenants (404) -> PASS.
#   * Over-restrictive #2504-only candidate (no attribution migration): the
#     owner read stays broken (404) -> the (a) assertion FAILS. This is the exact
#     #2574 regression this tier exists to catch.
#   * A candidate whose migrator cannot reconcile a diverged origin history
#     (e.g. the v1.5.8 155->163 renumber) fails to boot in PHASE 2 -> the
#     "candidate boots" assertion FAILS. That is the divergence-repair guard.
#
# run.sh has already stood the candidate up once on a fresh volume (health-gated)
# and exported BASE_URL / DB_CONTAINER / ADMIN_PASS / RELEASE_GATE / BACKEND_IMAGE
# / DTF_SLOT + the port block / DTF_DIR / COMMON_SH. We tear that down (down -v)
# and rebuild from each OLD image; run.sh's own dtf_down handles final teardown.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"
: "${BACKEND_IMAGE:?candidate image (run.sh exports it from --backend-image)}"
: "${DTF_SLOT:?}"; : "${S3_PORT:?}"; : "${S3_CONSOLE_PORT:?}"; : "${HTTP_PORT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=seed.sh
source "${HERE}/seed.sh"
# Pick up the origin list (single source of truth = the manifest).
# shellcheck source=/dev/null
source "${HERE}/manifest"

CAND_IMAGE="$BACKEND_IMAGE"
PROJECT="ak-dtf${DTF_SLOT}"
COMPOSE=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.s3.yml")
ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"

compose() { docker compose -p "$PROJECT" "${COMPOSE[@]}" "$@"; }
get_code() { curl -s -o /dev/null -w '%{http_code}' -X GET "$BASE_URL$1" -H "Authorization: Bearer $2"; }
get_body() { curl -s -X GET "$BASE_URL$1" -H "Authorization: Bearer $2"; }
wait_health() { # <max_tries>
  local n="$1" i h
  for i in $(seq 1 "$n"); do
    h=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/health" 2>/dev/null)
    [ "$h" = "200" ] && return 0
    sleep 3
  done
  return 1
}

# --- Resolve the origin list --------------------------------------------------
# UPGRADE_ORIGINS (manifest bash array) is authoritative: each entry is
# "image|label|note". Fall back to the legacy single UPGRADE_OLD_IMAGE so an
# override of just that var still works. UPGRADE_ONLY (space/comma list of
# labels) narrows the run for a quick local check without editing the manifest.
declare -a ORIGINS=()
if declare -p UPGRADE_ORIGINS >/dev/null 2>&1 && [ "${#UPGRADE_ORIGINS[@]}" -gt 0 ]; then
  ORIGINS=("${UPGRADE_ORIGINS[@]}")
else
  ORIGINS=("${UPGRADE_OLD_IMAGE:?manifest must set UPGRADE_ORIGINS or UPGRADE_OLD_IMAGE}|v1.5.x-origin|legacy single-origin")
fi

TIER_RC=0

# run_origin_upgrade <old_image> <label> <note>
# Full PHASE1+PHASE2 cycle for ONE origin. Records failures into TIER_RC and
# RETURNS (never exit) so a fault in one origin does not mask the others.
run_origin_upgrade() {
  local OLD_IMAGE="$1" LABEL="$2" NOTE="$3"

  echo
  echo "############ UPGRADE tier (slot ${DTF_SLOT}) — origin ${LABEL}"
  echo "   OLD image (legacy deployment) : ${OLD_IMAGE}"
  echo "   candidate image (upgrade to)  : ${CAND_IMAGE}"
  echo "   origin note                   : ${NOTE}"
  echo "   volumes: ak-dtf${DTF_SLOT}_data + minio (shared across the swap)"

  begin_suite "upgrade-legacy-rowless-s3-${LABEL}"

  # --- PHASE 1: OLD image + seed ------------------------------------------
  echo "== [${LABEL}] PHASE 1: stand up OLD image and seed row-less legacy data =="
  compose down -v >/dev/null 2>&1
  if ! BACKEND_IMAGE="$OLD_IMAGE" compose up -d --wait >/dev/null 2>&1; then
    # --wait can report unhealthy on a slow first migration; fall back to a poll.
    :
  fi
  if ! wait_health 30; then
    begin_test "[${LABEL}] PHASE1: OLD image ${OLD_IMAGE} healthy on s3"
    fail "OLD image did not become healthy; cannot seed legacy fixture"
    BACKEND_IMAGE="$OLD_IMAGE" compose logs backend --tail=40 2>&1 | tail -40 || true
    end_suite; TIER_RC=1; return 1
  fi

  if ! seed_rowless_legacy "$BASE_URL" "$DB_CONTAINER" "$ADMPASS"; then
    begin_test "[${LABEL}] PHASE1: seed row-less legacy Maven fixture"
    fail "could not plant the row-less legacy fixture (see seed output); origin skipped"
    end_suite; TIER_RC=1; return 1
  fi

  # Fixture-reality baseline + demonstrate the pre-fix #2574 symptom on the OLD image.
  local TOK_OLD OLD_ANCHOR OLD_JARASC
  TOK_OLD="$(seed_login "$BASE_URL" admin "$ADMPASS")"
  OLD_ANCHOR=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JAR" "$TOK_OLD")
  OLD_JARASC=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK_OLD")
  echo "   [${LABEL}] PHASE1 baseline: owner anchor jar => $OLD_ANCHOR (want 200) ; owner row-less .jar.asc => $OLD_JARASC (row-less on the OLD image)"

  begin_test "[${LABEL}] PHASE1: legacy fixture is real (anchor jar owner-readable on OLD ${OLD_IMAGE})"
  if [ "$OLD_ANCHOR" = "200" ]; then
    pass
  else
    fail "anchor jar not owner-readable on OLD image (HTTP $OLD_ANCHOR); fixture invalid"
    end_suite; TIER_RC=1; return 1
  fi

  # --- PHASE 2: swap backend to the candidate (same volumes), let migrations run --
  echo "== [${LABEL}] PHASE 2: swap backend -> candidate ${CAND_IMAGE} (same volumes) =="
  BACKEND_IMAGE="$CAND_IMAGE" compose up -d backend >/dev/null 2>&1
  begin_test "[${LABEL}] PHASE2: candidate ${CAND_IMAGE} boots on the upgraded ${LABEL} volume (clean migration reconcile)"
  if ! wait_health 60; then
    fail "candidate backend did not become healthy after in-place upgrade from ${LABEL} (migration incompatibility / unreconciled divergence with the origin volume?)" \
      "For ${LABEL} the candidate must apply/reconcile its migrations on top of the origin's applied set (${NOTE}). A boot failure here is the divergence-repair guard firing."
    BACKEND_IMAGE="$CAND_IMAGE" compose logs backend --tail=40 2>&1 | tail -40 || true
    end_suite; TIER_RC=1; return 1
  fi
  local MIGDONE
  MIGDONE=$(BACKEND_IMAGE="$CAND_IMAGE" compose logs backend 2>&1 | grep -c "Database migrations complete" || true)
  echo "   [${LABEL}] candidate healthy; 'migrations complete' log hits=${MIGDONE}"
  # Informational: applied-migration count on the upgraded volume (proves the
  # candidate's full set is present after reconciling the origin history).
  local APPLIED
  APPLIED=$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM _sqlx_migrations WHERE success;" 2>/dev/null | tr -d '[:space:]' || true)
  echo "   [${LABEL}] applied migrations on upgraded volume = ${APPLIED:-unknown}"
  # Healthy boot is the pass condition; the migration-complete log line is a
  # supporting signal (log-format drift must not fail an otherwise clean boot).
  pass
  if [ "${MIGDONE:-0}" -lt 1 ]; then
    echo "   [${LABEL}] note: candidate healthy but no 'migrations complete' log line matched (log format drift?)"
  fi

  # Fresh tokens against the upgraded backend.
  local TOK ATOK
  TOK="$(seed_login "$BASE_URL" admin "$ADMPASS")"
  ATOK="$(seed_login "$BASE_URL" "$SD_ALICE" "$SD_APASS")"

  # DB-layer supporting evidence (prove.sh-style): did the upgrade's backfill
  # attribute the row-less signature sidecar to its owning repo (MVB)? Non-fatal:
  # on an over-restrictive #2504-only candidate the maven_flat_object_owner table
  # does not exist, so the query errors; the load-bearing assertion is the HTTP
  # owner read below. Every psql here is `|| true`-guarded.
  local ATTR
  ATTR="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM maven_flat_object_owner o JOIN repositories r ON r.id=o.repository_id
     WHERE o.storage_key='maven/$SD_VP/$SD_JARASC' AND r.key='$SD_MVB';" 2>/dev/null | tr -d '[:space:]' || true)"
  echo "   [${LABEL}] DB: attribution rows for maven/$SD_VP/$SD_JARASC owned by $SD_MVB = ${ATTR:-0 (no attribution table / not attributed)}"

  # (a) NO #2574 REGRESSION: the owner can read the row-less legacy signature
  #     sidecar after the upgrade. FIXED restores it (200); an over-restrictive
  #     #2504-only candidate leaves it 404 -> this assertion FAILS (the gate).
  local OWN_JARASC OWN_BODY OWN_HAS_SECRET
  OWN_JARASC=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK")
  OWN_BODY=$(get_body "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK")
  OWN_HAS_SECRET=no; echo "$OWN_BODY" | grep -q "$SD_SECRET" && OWN_HAS_SECRET=yes
  begin_test "[${LABEL}] POST-UPGRADE (a): owner CAN read the legacy row-less signature sidecar (no #2574 404 regression)"
  if [ "$OWN_JARASC" = "200" ] && [ "$OWN_HAS_SECRET" = "yes" ]; then
    pass
  else
    fail "owner read of legacy row-less .jar.asc regressed after upgrade from ${LABEL} (HTTP ${OWN_JARASC}, own bytes present=${OWN_HAS_SECRET}); candidate ${CAND_IMAGE} broke legitimate access to old-shape data (#2574)" \
      "owner GET /maven/${SD_MVB}/${SD_VP}/${SD_JARASC} => HTTP ${OWN_JARASC}; DB attribution rows=${ATTR:-0}. A fixed candidate backfills attribution for the row-less sidecar (owner 200); this candidate left it unattributed (owner 404)."
    TIER_RC=1
  fi

  # (a2) the catalogued anchor is still owner-readable (upgrade broke nothing).
  local OWN_ANCHOR
  OWN_ANCHOR=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JAR" "$TOK")
  begin_test "[${LABEL}] POST-UPGRADE (a2): catalogued anchor jar still owner-readable"
  if [ "$OWN_ANCHOR" = "200" ]; then pass; else fail "anchor jar read regressed after upgrade from ${LABEL} (HTTP $OWN_ANCHOR)"; TIER_RC=1; fi

  # (b) NO #2504/#2584 LEAK: alice (grant on MVA only, none on MVB) must NOT reach
  #     MVB's legacy objects via her own repo, and no secret bytes may leak.
  local AL_JARASC AL_BODY
  AL_JARASC=$(get_code "/maven/$SD_MVA/$SD_VP/$SD_JARASC" "$ATOK")
  AL_BODY=$(get_body "/maven/$SD_MVA/$SD_VP/$SD_JARASC" "$ATOK")
  begin_test "[${LABEL}] POST-UPGRADE (b): legacy row-less sidecar stays isolated from other tenants (no #2504/#2584 leak)"
  if echo "$AL_BODY" | grep -q "$SD_SECRET"; then
    fail "cross-tenant LEAK: alice read MVB's legacy .jar.asc bytes via MVA (HTTP $AL_JARASC) after upgrade from ${LABEL} (#2504/#2584)"
    TIER_RC=1
  elif [ "$AL_JARASC" = "403" ] || [ "$AL_JARASC" = "404" ]; then
    pass
  else
    fail "unexpected cross-tenant response for alice on legacy .jar.asc (HTTP $AL_JARASC)"
    TIER_RC=1
  fi

  # (b2) the catalogued anchor is also isolated cross-tenant.
  local AL_ANCHOR AL_ANCHOR_BODY
  AL_ANCHOR=$(get_code "/maven/$SD_MVA/$SD_VP/$SD_JAR" "$ATOK")
  AL_ANCHOR_BODY=$(get_body "/maven/$SD_MVA/$SD_VP/$SD_JAR" "$ATOK")
  begin_test "[${LABEL}] POST-UPGRADE (b2): catalogued anchor jar stays isolated cross-tenant"
  if echo "$AL_ANCHOR_BODY" | grep -q "ANCHOR-"; then
    fail "cross-tenant LEAK: alice read MVB's anchor jar via MVA (HTTP $AL_ANCHOR) after upgrade from ${LABEL}"
    TIER_RC=1
  elif [ "$AL_ANCHOR" = "403" ] || [ "$AL_ANCHOR" = "404" ]; then
    pass
  else
    fail "unexpected cross-tenant response for alice on anchor jar (HTTP $AL_ANCHOR)"
    TIER_RC=1
  fi

  end_suite
  return 0
}

# --- Optional narrowing (local convenience) -----------------------------------
# UPGRADE_ONLY="v1.5.6-origin v1.5.8-origin" runs a subset by label.
ONLY="${UPGRADE_ONLY:-}"
want_origin() {
  [ -z "$ONLY" ] && return 0
  local l="$1" tok
  for tok in ${ONLY//,/ }; do [ "$tok" = "$l" ] && return 0; done
  return 1
}

echo "############ UPGRADE tier: ${#ORIGINS[@]} origin(s) -> candidate ${CAND_IMAGE}"
for entry in "${ORIGINS[@]}"; do
  IFS='|' read -r o_img o_label o_note <<< "$entry"
  o_label="${o_label:-$o_img}"; o_note="${o_note:-}"
  if ! want_origin "$o_label"; then
    echo ">> skipping origin ${o_label} (UPGRADE_ONLY=${ONLY})"
    continue
  fi
  run_origin_upgrade "$o_img" "$o_label" "$o_note"
done

# Teardown is left to run.sh (dtf_down / --keep). The last upgraded candidate
# stack stays up so --keep can inspect the post-upgrade state.
exit "$TIER_RC"
