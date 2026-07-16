#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade/oracle.sh — upgrade-with-LEGACY-DATA gate (#2574/#2584 class)
# =============================================================================
# Matrix row 6. Proves that upgrading a cloud-storage deployment that already
# contains OLD-SHAPE (row-less Maven) data (a) does NOT leave legitimate owner
# access broken (#2574) AND (b) does NOT open a cross-tenant leak (#2504/#2584).
#
# Two-phase, driven BY THIS ORACLE (the only tier that does so — see manifest):
#   PHASE 1  stand up on the OLD pre-attribution backend (UPGRADE_OLD_IMAGE),
#            seed the row-less legacy Maven shape (tiers/upgrade/seed.sh, which
#            reuses the isolation prove.sh Scenario F plant+strip technique),
#            and establish the fixture is real.
#   PHASE 2  swap ONLY the backend container to the candidate image
#            (--backend-image, exported by run.sh as BACKEND_IMAGE) against the
#            SAME postgres+minio volumes, let its migrations run, then re-run the
#            isolation assertions.
#
# Discriminating (RELEASE_GATE=1):
#   * FIXED candidate (attribution migration present): the row-less signature
#     sidecar is RESTORED to its owner (200) AND stays isolated from other
#     tenants (404) -> PASS (exit 0).
#   * Over-restrictive #2504-only candidate (no attribution migration): the
#     owner read stays broken (404) -> the (a) assertion FAILS -> exit non-zero.
#     This is the exact #2574 regression this tier exists to catch.
#
# run.sh has already stood the candidate up once on a fresh volume (health-gated)
# and exported BASE_URL / DB_CONTAINER / ADMIN_PASS / RELEASE_GATE / BACKEND_IMAGE
# / DTF_SLOT + the port block / DTF_DIR / COMMON_SH. We tear that down (down -v)
# and rebuild from the OLD image; run.sh's own dtf_down handles final teardown.
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
# Pick up UPGRADE_OLD_IMAGE (single source of truth = the manifest).
# shellcheck source=/dev/null
source "${HERE}/manifest"

CAND_IMAGE="$BACKEND_IMAGE"
OLD_IMAGE="${UPGRADE_OLD_IMAGE:?manifest must set UPGRADE_OLD_IMAGE}"
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

echo "############ UPGRADE tier (slot ${DTF_SLOT})"
echo "   OLD image (legacy deployment) : ${OLD_IMAGE}"
echo "   candidate image (upgrade to)  : ${CAND_IMAGE}"
echo "   volumes: ak-dtf${DTF_SLOT}_data + minio (shared across the swap)"

begin_suite "upgrade-legacy-rowless-s3"

# --- PHASE 1: OLD image + seed --------------------------------------------
echo "== PHASE 1: stand up OLD image and seed row-less legacy data =="
compose down -v >/dev/null 2>&1
if ! BACKEND_IMAGE="$OLD_IMAGE" compose up -d --wait >/dev/null 2>&1; then
  # --wait can report unhealthy on a slow first migration; fall back to a poll.
  :
fi
if ! wait_health 30; then
  begin_test "PHASE1: OLD image ${OLD_IMAGE} healthy on s3"
  fail "OLD image did not become healthy; cannot seed legacy fixture"
  BACKEND_IMAGE="$OLD_IMAGE" compose logs backend --tail=40 2>&1 | tail -40 || true
  end_suite; exit 1
fi

if ! seed_rowless_legacy "$BASE_URL" "$DB_CONTAINER" "$ADMPASS"; then
  begin_test "PHASE1: seed row-less legacy Maven fixture"
  fail "could not plant the row-less legacy fixture (see seed output); tier cannot run"
  end_suite; exit 1
fi

# Fixture-reality baseline + demonstrate the pre-fix #2574 symptom on the OLD image.
ATOK_OLD="$(seed_login "$BASE_URL" "$SD_ALICE" "$SD_APASS")"
TOK_OLD="$(seed_login "$BASE_URL" admin "$ADMPASS")"
OLD_ANCHOR=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JAR" "$TOK_OLD")
OLD_JARASC=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK_OLD")
echo "   PHASE1 baseline: owner anchor jar => $OLD_ANCHOR (want 200) ; owner row-less .jar.asc => $OLD_JARASC (#2574 symptom on the OLD image: 404 = access already broken pre-fix)"

begin_test "PHASE1: legacy fixture is real (anchor jar owner-readable on OLD ${OLD_IMAGE})"
if [ "$OLD_ANCHOR" = "200" ]; then
  pass
else
  fail "anchor jar not owner-readable on OLD image (HTTP $OLD_ANCHOR); fixture invalid"
  end_suite; exit 1
fi

# --- PHASE 2: swap backend to the candidate (same volumes), let migrations run --
echo "== PHASE 2: swap backend -> candidate ${CAND_IMAGE} (same volumes) =="
BACKEND_IMAGE="$CAND_IMAGE" compose up -d backend >/dev/null 2>&1
if ! wait_health 60; then
  begin_test "PHASE2: candidate ${CAND_IMAGE} boots on the upgraded volume"
  fail "candidate backend did not become healthy after in-place upgrade (migration incompatibility with the legacy volume?)"
  BACKEND_IMAGE="$CAND_IMAGE" compose logs backend --tail=40 2>&1 | tail -40 || true
  end_suite; exit 1
fi
MIGDONE=$(BACKEND_IMAGE="$CAND_IMAGE" compose logs backend 2>&1 | grep -c "Database migrations complete" || true)
echo "   candidate healthy; 'migrations complete' log hits=${MIGDONE}"

# Fresh tokens against the upgraded backend.
TOK="$(seed_login "$BASE_URL" admin "$ADMPASS")"
ATOK="$(seed_login "$BASE_URL" "$SD_ALICE" "$SD_APASS")"

# DB-layer supporting evidence (prove.sh-style): did the upgrade's backfill
# attribute the row-less signature sidecar to its owning repo (MVB)? This is
# non-fatal on purpose — on an over-restrictive #2504-only candidate the
# `maven_flat_object_owner` table does not even exist, so the query errors; we
# must not let that abort under common.sh's `set -e`, because the load-bearing
# assertion is the HTTP owner read below, not this probe. Every psql here is
# `|| true`-guarded.
ATTR="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM maven_flat_object_owner o JOIN repositories r ON r.id=o.repository_id
   WHERE o.storage_key='maven/$SD_VP/$SD_JARASC' AND r.key='$SD_MVB';" 2>/dev/null | tr -d '[:space:]' || true)"
echo "   DB: attribution rows for maven/$SD_VP/$SD_JARASC owned by $SD_MVB = ${ATTR:-0 (no attribution table / not attributed)}"

# (a) NO #2574 REGRESSION: the owner can read the row-less legacy signature
#     sidecar after the upgrade. FIXED restores it (200); an over-restrictive
#     #2504-only candidate leaves it 404 -> this assertion FAILS (the gate).
OWN_JARASC=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK")
OWN_BODY=$(get_body "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK")
OWN_HAS_SECRET=no; echo "$OWN_BODY" | grep -q "$SD_SECRET" && OWN_HAS_SECRET=yes
begin_test "POST-UPGRADE (a): owner CAN read the legacy row-less signature sidecar (no #2574 404 regression)"
if [ "$OWN_JARASC" = "200" ] && [ "$OWN_HAS_SECRET" = "yes" ]; then
  pass
else
  fail "owner read of legacy row-less .jar.asc regressed after upgrade (HTTP ${OWN_JARASC}, own bytes present=${OWN_HAS_SECRET}); candidate ${CAND_IMAGE} broke legitimate access to old-shape data (#2574)" \
    "owner GET /maven/${SD_MVB}/${SD_VP}/${SD_JARASC} => HTTP ${OWN_JARASC}; DB attribution rows=${ATTR:-0}. A fixed candidate backfills attribution for the row-less sidecar (owner 200); this candidate left it unattributed (owner 404)."
fi

# (a2) the catalogued anchor is still owner-readable (upgrade broke nothing).
OWN_ANCHOR=$(get_code "/maven/$SD_MVB/$SD_VP/$SD_JAR" "$TOK")
begin_test "POST-UPGRADE (a2): catalogued anchor jar still owner-readable"
{ [ "$OWN_ANCHOR" = "200" ]; } && pass || fail "anchor jar read regressed after upgrade (HTTP $OWN_ANCHOR)"

# (b) NO #2504/#2584 LEAK: alice (grant on MVA only, none on MVB) must NOT reach
#     MVB's legacy objects via her own repo, and no secret bytes may leak.
AL_JARASC=$(get_code "/maven/$SD_MVA/$SD_VP/$SD_JARASC" "$ATOK")
AL_BODY=$(get_body "/maven/$SD_MVA/$SD_VP/$SD_JARASC" "$ATOK")
begin_test "POST-UPGRADE (b): legacy row-less sidecar stays isolated from other tenants (no #2504/#2584 leak)"
if echo "$AL_BODY" | grep -q "$SD_SECRET"; then
  fail "cross-tenant LEAK: alice read MVB's legacy .jar.asc bytes via MVA (HTTP $AL_JARASC) after upgrade (#2504/#2584)"
elif [ "$AL_JARASC" = "403" ] || [ "$AL_JARASC" = "404" ]; then
  pass
else
  fail "unexpected cross-tenant response for alice on legacy .jar.asc (HTTP $AL_JARASC)"
fi

# (b2) the catalogued anchor is also isolated cross-tenant.
AL_ANCHOR=$(get_code "/maven/$SD_MVA/$SD_VP/$SD_JAR" "$ATOK")
AL_ANCHOR_BODY=$(get_body "/maven/$SD_MVA/$SD_VP/$SD_JAR" "$ATOK")
begin_test "POST-UPGRADE (b2): catalogued anchor jar stays isolated cross-tenant"
if echo "$AL_ANCHOR_BODY" | grep -q "ANCHOR-"; then
  fail "cross-tenant LEAK: alice read MVB's anchor jar via MVA (HTTP $AL_ANCHOR)"
elif [ "$AL_ANCHOR" = "403" ] || [ "$AL_ANCHOR" = "404" ]; then
  pass
else
  fail "unexpected cross-tenant response for alice on anchor jar (HTTP $AL_ANCHOR)"
fi

end_suite
# Teardown is left to run.sh (dtf_down / --keep). The upgraded candidate stack
# stays up so --keep can inspect the post-upgrade state.
