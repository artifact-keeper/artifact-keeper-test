#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade-v156-origin/oracle.sh — v1.5.6-origin upgrade (#2688, the
# no-divergence NO-OP case; control for the #2686 startup repair)
# =============================================================================
# A v1.5.6 database's applied ledger (max version 153) is an exact checksum
# prefix of main's migration chain — it predates the release/1.5.x renumbered
# slots (154/155). Booting a main-line candidate on that volume must:
#   * NOT fire repair_release_1_5_x_divergence (nothing to reconcile),
#   * NOT hit any VersionMismatch (the <=153 prefix must be byte-stable),
#   * apply main's 154+ chain fresh (webhook_deliveries_claim at 154,
#     storage_key_index at 157, maven_flat_object_attribution at 163, ...),
#   * leave the applied prefix untouched (installed_on preserved, no row lost),
#   * preserve all data seeded on the origin.
#
# Discriminating: this tier goes RED if (a) the repair ever spuriously fires
# on a clean ancestor ledger, or (b) anyone edits a shipped <=153 migration
# file on main — the origin checksums then mismatch, the migrator aborts with
# VersionMismatch(n), and the candidate never reaches healthy. Proven RED
# locally by corrupting the origin's stored checksum for slot 153 before the
# swap — see the tier notes in the batch MR.
#
# Two-phase, driven BY THIS ORACLE (same legitimate tier-specific pattern as
# tiers/upgrade): run.sh health-gates an initial candidate `up`; we tear that
# down (down -v) and rebuild from the origin image on a fresh volume, then swap
# only the backend to the candidate. run.sh's dtf_down handles final teardown.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"
: "${BACKEND_IMAGE:?candidate image (run.sh exports it from --backend-image)}"
: "${DTF_SLOT:?}"; : "${HTTP_PORT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# Pick up UPGRADE_OLD_IMAGE (single source of truth = the manifest).
# shellcheck source=/dev/null
source "${HERE}/manifest"

CAND_IMAGE="$BACKEND_IMAGE"
OLD_IMAGE="${UPGRADE_OLD_IMAGE:?manifest must set UPGRADE_OLD_IMAGE}"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
COMPOSE=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml")
ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"

compose() { docker compose -p "$PROJECT" "${COMPOSE[@]}" "$@"; }
psq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
# Backend tracing output wraps field values in ANSI color codes; strip them so
# literal greps match regardless of terminal styling.
blog() { docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
blog_count() { blog | grep -c "$1" || true; }
o_login() {
  curl -s -X POST "$BASE_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.access_token // empty' 2>/dev/null
}
o_code() { curl -s -o /dev/null -w '%{http_code}' -X GET "$BASE_URL$1" -H "Authorization: Bearer $2"; }
o_body() { curl -s -X GET "$BASE_URL$1" -H "Authorization: Bearer $2"; }
wait_health() { # <max_tries>
  local n="$1" i h
  for i in $(seq 1 "$n"); do
    h=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/health" 2>/dev/null)
    [ "$h" = "200" ] && return 0
    sleep 3
  done
  return 1
}

echo "############ UPGRADE-V156-ORIGIN tier (slot ${DTF_SLOT})"
echo "   origin image (v1.5.6 ledger)  : ${OLD_IMAGE}"
echo "   candidate image (upgrade to)  : ${CAND_IMAGE}"

begin_suite "upgrade-v156-origin-noop"

# --- PHASE 1: origin image on a fresh volume ---------------------------------
echo "== PHASE 1: stand up origin ${OLD_IMAGE} and capture the ancestor ledger =="
compose down -v >/dev/null 2>&1
BACKEND_IMAGE="$OLD_IMAGE" compose up -d --wait >/dev/null 2>&1 || true
begin_test "PHASE1: origin ${OLD_IMAGE} healthy"
if wait_health 40; then
  pass
else
  fail "origin image did not become healthy; cannot establish the v1.5.6 fixture"
  BACKEND_IMAGE="$OLD_IMAGE" compose logs backend --tail=40 2>&1 | tail -40 || true
  end_suite; exit 1
fi

# Origin-ledger signature (fail-closed: any other image/ledger aborts the tier).
G_MAX=$(psq "SELECT max(version) FROM _sqlx_migrations;" | tr -d '[:space:]')
G_154=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE version>=154;" | tr -d '[:space:]')
begin_test "PHASE1: ledger is the v1.5.6 signature (max=153, nothing at 154+)"
if [ "$G_MAX" = "153" ] && [ "$G_154" = "0" ]; then
  pass
else
  fail "origin ledger is not v1.5.6's (max=$G_MAX, rows at 154+=$G_154); wrong UPGRADE_OLD_IMAGE?"
  end_suite; exit 1
fi

# Anchors for the prefix-untouched proof.
TS153_ORIGIN=$(psq "SELECT installed_on FROM _sqlx_migrations WHERE version=153;")
ROWS_ORIGIN=$(psq "SELECT count(*) FROM _sqlx_migrations;" | tr -d '[:space:]')
echo "   origin: rows=$ROWS_ORIGIN ts(153)='$TS153_ORIGIN'"

# Seed data that must survive: non-admin user + maven repo + one artifact with
# a byte-detectable marker.
SUF="${RUN_ID:-r}$RANDOM"
SD_REPO="mvn-upg-$SUF"; SD_USER="carol-$SUF"; SD_UPASS="CarolPass!2026x"
SD_VP="com/upgrade/app$SUF/1.0"; SD_JAR="app$SUF-1.0.jar"
SD_MARK="UPG-V156-ORIGIN-MARKER-$SUF"
TOK="$(o_login admin "$ADMPASS")"
curl -s -X POST "$BASE_URL/api/v1/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$SD_USER\",\"email\":\"$SD_USER@t.test\",\"password\":\"$SD_UPASS\",\"is_admin\":false}" >/dev/null
curl -s -X POST "$BASE_URL/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$SD_REPO\",\"name\":\"$SD_REPO\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
P_JAR=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE_URL/maven/$SD_REPO/$SD_VP/$SD_JAR" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/octet-stream' \
  --data-binary "PK\003\004$SD_MARK")
G_JAR=$(o_code "/maven/$SD_REPO/$SD_VP/$SD_JAR" "$TOK")
CTOK="$(o_login "$SD_USER" "$SD_UPASS")"
begin_test "PHASE1: seed on origin (PUT jar=$P_JAR, GET jar=$G_JAR, non-admin login works)"
if [ "$G_JAR" = "200" ] && [ -n "$CTOK" ]; then
  pass
else
  fail "seed failed on the origin image (PUT=$P_JAR GET=$G_JAR user-token-empty=$([ -z "$CTOK" ] && echo yes || echo no))"
  end_suite; exit 1
fi

# --- PHASE 2: swap backend -> candidate (same volume), migrator applies 154+ --
echo "== PHASE 2: swap backend -> candidate ${CAND_IMAGE} (same volume) =="
BACKEND_IMAGE="$CAND_IMAGE" compose up -d backend >/dev/null 2>&1
begin_test "POST-UPGRADE: candidate healthy on the v1.5.6 volume (prefix accepted, no VersionMismatch)"
if wait_health 60; then
  pass
else
  fail "candidate did not become healthy on a clean v1.5.6 ancestor ledger — either a spurious repair or a shipped <=153 migration file changed on main (VersionMismatch)" \
    "docker logs tail: $(docker logs "$BACKEND_CTR" 2>&1 | tail -8)"
  end_suite; exit 1
fi

# The NO-OP core: the #2686 divergence repair must NOT fire, and no mismatch
# may appear anywhere in the candidate boot log.
REPAIRS=$(blog_count "migration_release_1_5_x_divergence_repair")
MISMATCH=$(blog_count "VersionMismatch")
begin_test "POST-UPGRADE: no divergence repair fired and no VersionMismatch logged (repair=$REPAIRS mismatch=$MISMATCH)"
{ [ "$REPAIRS" = "0" ] && [ "$MISMATCH" = "0" ]; } && pass \
  || fail "expected a pure no-op upgrade; repair hits=$REPAIRS (want 0), VersionMismatch hits=$MISMATCH (want 0)"

# Prefix untouched: the origin's applied rows are all still there, none
# re-applied (installed_on of the newest origin row preserved verbatim).
TS153=$(psq "SELECT installed_on FROM _sqlx_migrations WHERE version=153;")
ROWS_PREFIX=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE version<=153;" | tr -d '[:space:]')
begin_test "POST-UPGRADE: applied <=153 prefix untouched (rows $ROWS_ORIGIN preserved, ts(153) unchanged)"
{ [ "$ROWS_PREFIX" = "$ROWS_ORIGIN" ] && [ -n "$TS153" ] && [ "$TS153" = "$TS153_ORIGIN" ]; } && pass \
  || fail "origin prefix disturbed: rows<=153 $ROWS_ORIGIN -> $ROWS_PREFIX, ts(153) '$TS153_ORIGIN' -> '$TS153'"

# Fresh chain applied at main's own numbering, exactly once each, none failed.
D154=$(psq "SELECT description FROM _sqlx_migrations WHERE version=154;")
D157=$(psq "SELECT description FROM _sqlx_migrations WHERE version=157;")
D163=$(psq "SELECT description FROM _sqlx_migrations WHERE version=163;")
C_SKI=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE description='artifacts storage key index';" | tr -d '[:space:]')
C_MFA=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE description='maven flat object attribution';" | tr -d '[:space:]')
C_BAD=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE success=false;" | tr -d '[:space:]')
N_MAX=$(psq "SELECT max(version) FROM _sqlx_migrations;" | tr -d '[:space:]')
begin_test "POST-UPGRADE: main chain applied fresh at main numbering (154=webhook, 157=storage_key, 163=maven_flat, each once, max=$N_MAX)"
if [ "$D154" = "webhook deliveries claim" ] && [ "$D157" = "artifacts storage key index" ] \
   && [ "$D163" = "maven flat object attribution" ] && [ "$C_SKI" = "1" ] && [ "$C_MFA" = "1" ] \
   && [ "$C_BAD" = "0" ] && [ "${N_MAX:-0}" -ge 163 ]; then
  pass
else
  fail "chain not applied cleanly: 154='$D154' 157='$D157' 163='$D163' storage_key rows=$C_SKI maven_flat rows=$C_MFA failed=$C_BAD max=$N_MAX"
fi

# Schema end-state probes for the freshly-applied migrations.
OBJS=$(psq "SELECT (to_regclass('public.maven_flat_object_owner') IS NOT NULL)::int + (to_regclass('public.idx_artifacts_storage_key') IS NOT NULL)::int + (to_regclass('public.projects') IS NOT NULL)::int;" | tr -d '[:space:]')
begin_test "POST-UPGRADE: schema objects present (maven_flat_object_owner + idx_artifacts_storage_key + projects)"
[ "$OBJS" = "3" ] && pass || fail "expected all 3 objects present, got $OBJS/3"

# Data survival: origin-seeded artifact readable with its bytes; origin-created
# non-admin user can still log in.
TOK="$(o_login admin "$ADMPASS")"
S_JAR=$(o_code "/maven/$SD_REPO/$SD_VP/$SD_JAR" "$TOK")
S_BODY=$(o_body "/maven/$SD_REPO/$SD_VP/$SD_JAR" "$TOK")
S_MARK=no; echo "$S_BODY" | grep -q "$SD_MARK" && S_MARK=yes
CTOK2="$(o_login "$SD_USER" "$SD_UPASS")"
begin_test "POST-UPGRADE: origin data survived (jar=$S_JAR marker=$S_MARK, non-admin login ok)"
{ [ "$S_JAR" = "200" ] && [ "$S_MARK" = "yes" ] && [ -n "$CTOK2" ]; } && pass \
  || fail "data loss across upgrade: jar GET=$S_JAR marker-present=$S_MARK user-login-ok=$([ -n "$CTOK2" ] && echo yes || echo no)"

# Idempotency: a second candidate boot must apply nothing and fire no repair.
ROWS_BEFORE=$(psq "SELECT count(*) FROM _sqlx_migrations;" | tr -d '[:space:]')
docker restart "$BACKEND_CTR" >/dev/null 2>&1
begin_test "IDEMPOTENCY: second candidate boot is a no-op (repair still 0 hits, ledger unchanged)"
if ! wait_health 40; then
  fail "candidate unhealthy on second boot of the upgraded volume"
else
  REPAIRS2=$(blog_count "migration_release_1_5_x_divergence_repair")
  MIGDONE2=$(blog_count "Database migrations complete")
  ROWS_AFTER=$(psq "SELECT count(*) FROM _sqlx_migrations;" | tr -d '[:space:]')
  if [ "$REPAIRS2" = "0" ] && [ "$MIGDONE2" = "2" ] && [ "$ROWS_AFTER" = "$ROWS_BEFORE" ]; then
    pass
  else
    fail "second boot not a no-op: repair hits=$REPAIRS2 (want 0), 'migrations complete' hits=$MIGDONE2 (want 2), ledger rows $ROWS_BEFORE -> $ROWS_AFTER"
  fi
fi

end_suite
# Teardown is left to run.sh (dtf_down / --keep).
