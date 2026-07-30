#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade-v158-origin/oracle.sh — v1.5.8-origin upgrade (#2688, the
# "154+155" migration-ledger divergence case; startup repair from #2686)
# =============================================================================
# A v1.5.8 database carries release/1.5.x's diverged slots:
#   154 = artifacts_storage_key_index    (main's 157, byte-identical content)
#   155 = maven_flat_object_attribution  (main's 163, byte-identical content)
# Booting a main-line candidate on that volume must:
#   * RENUMBER the two applied rows (154->157, 155->163) instead of failing
#     with Migration(VersionMismatch(154)),
#   * apply main's own 154/155/156 (webhook_deliveries_claim / projects /
#     upstream_feed_state) and the rest of the chain FRESH,
#   * NOT double-apply the renumbered content (proven via installed_on
#     preservation + single-occurrence description counts), and
#   * preserve all data seeded on the origin.
#
# Discriminating: a candidate lacking (or regressing) the #2686 repair aborts
# startup at VersionMismatch(154) and never reaches healthy, so the PHASE-2
# health assertion fails. Proven RED locally by corrupting the origin 154
# checksum (the repair's detection key) before the swap — see the tier notes
# in the batch MR.
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
# literal greps like `renumber_155=true` match.
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

echo "############ UPGRADE-V158-ORIGIN tier (slot ${DTF_SLOT})"
echo "   origin image (v1.5.8 ledger)  : ${OLD_IMAGE}"
echo "   candidate image (upgrade to)  : ${CAND_IMAGE}"

begin_suite "upgrade-v158-origin-154-155"

# --- PHASE 1: origin image on a fresh volume ---------------------------------
echo "== PHASE 1: stand up origin ${OLD_IMAGE} and capture the diverged ledger =="
compose down -v >/dev/null 2>&1
BACKEND_IMAGE="$OLD_IMAGE" compose up -d --wait >/dev/null 2>&1 || true
begin_test "PHASE1: origin ${OLD_IMAGE} healthy"
if wait_health 40; then
  pass
else
  fail "origin image did not become healthy; cannot establish the v1.5.8 fixture"
  BACKEND_IMAGE="$OLD_IMAGE" compose logs backend --tail=40 2>&1 | tail -40 || true
  end_suite; exit 1
fi

# Origin-ledger signature (fail-closed: any other image/ledger aborts the tier
# rather than green-lighting a different upgrade path).
G_MAX=$(psq "SELECT max(version) FROM _sqlx_migrations;" | tr -d '[:space:]')
G_154=$(psq "SELECT description FROM _sqlx_migrations WHERE version=154;")
G_155=$(psq "SELECT description FROM _sqlx_migrations WHERE version=155;")
G_HI=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE version IN (156,157,163);" | tr -d '[:space:]')
begin_test "PHASE1: ledger is the v1.5.8 signature (154=storage_key_index, 155=maven_flat, max=155, no 156/157/163)"
if [ "$G_MAX" = "155" ] && [ "$G_154" = "artifacts storage key index" ] \
   && [ "$G_155" = "maven flat object attribution" ] && [ "$G_HI" = "0" ]; then
  pass
else
  fail "origin ledger is not v1.5.8's (max=$G_MAX, 154='$G_154', 155='$G_155', 156/157/163 rows=$G_HI); wrong UPGRADE_OLD_IMAGE?"
  end_suite; exit 1
fi

# Origin timestamps + row count: the renumber-not-reapply proof anchors.
TS154_ORIGIN=$(psq "SELECT installed_on FROM _sqlx_migrations WHERE version=154;")
TS155_ORIGIN=$(psq "SELECT installed_on FROM _sqlx_migrations WHERE version=155;")
ROWS_ORIGIN=$(psq "SELECT count(*) FROM _sqlx_migrations;" | tr -d '[:space:]')
echo "   origin: rows=$ROWS_ORIGIN ts(154)='$TS154_ORIGIN' ts(155)='$TS155_ORIGIN'"

# Seed data that must survive the upgrade: a non-admin user + a maven repo +
# one artifact with a byte-detectable marker.
SUF="${RUN_ID:-r}$RANDOM"
SD_REPO="mvn-upg-$SUF"; SD_USER="carol-$SUF"; SD_UPASS="CarolPass!2026x"
SD_VP="com/upgrade/app$SUF/1.0"; SD_JAR="app$SUF-1.0.jar"
SD_MARK="UPG-V158-ORIGIN-MARKER-$SUF"
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

# --- PHASE 2: swap backend -> candidate (same volume), let repair + migrator run
echo "== PHASE 2: swap backend -> candidate ${CAND_IMAGE} (same volume) =="
BACKEND_IMAGE="$CAND_IMAGE" compose up -d backend >/dev/null 2>&1
begin_test "POST-UPGRADE: candidate healthy on the v1.5.8 volume (no VersionMismatch(154) abort)"
if wait_health 60; then
  pass
else
  fail "candidate did not become healthy on a v1.5.8 ledger — the #2686 divergence repair regressed (expected renumber 154->157 / 155->163, likely Migration(VersionMismatch(154)))" \
    "docker logs tail: $(docker logs "$BACKEND_CTR" 2>&1 | tail -8)"
  end_suite; exit 1
fi

# The repair must have fired EXACTLY once, with the v1.5.8 branch (renumber_155).
REPAIRS=$(blog_count "migration_release_1_5_x_divergence_repair")
RENUM155=$(blog | grep "migration_release_1_5_x_divergence_repair" | grep -c "renumber_155=true" || true)
begin_test "POST-UPGRADE: #2686 repair fired exactly once with renumber_155=true (hits=$REPAIRS, renumber_155=$RENUM155)"
{ [ "$REPAIRS" = "1" ] && [ "$RENUM155" = "1" ]; } && pass \
  || fail "expected exactly one divergence-repair event with renumber_155=true; got hits=$REPAIRS renumber_155-hits=$RENUM155"

# Renumber-not-reapply: 157/163 must carry the ORIGIN 154/155 installed_on
# timestamps verbatim (the rows moved; nothing re-executed), while main's fresh
# 154/155 are new rows.
TS157=$(psq "SELECT installed_on FROM _sqlx_migrations WHERE version=157;")
TS163=$(psq "SELECT installed_on FROM _sqlx_migrations WHERE version=163;")
D157=$(psq "SELECT description FROM _sqlx_migrations WHERE version=157;")
D163=$(psq "SELECT description FROM _sqlx_migrations WHERE version=163;")
begin_test "POST-UPGRADE: 154->157 and 155->163 were RENUMBERED, not re-applied (installed_on preserved)"
if [ -n "$TS157" ] && [ "$TS157" = "$TS154_ORIGIN" ] && [ "$TS163" = "$TS155_ORIGIN" ] \
   && [ "$D157" = "artifacts storage key index" ] && [ "$D163" = "maven flat object attribution" ]; then
  pass
else
  fail "renumbered rows wrong: 157='$D157'@'$TS157' (want storage_key_index@'$TS154_ORIGIN'), 163='$D163'@'$TS163' (want maven_flat@'$TS155_ORIGIN')"
fi

# Single application: each diverged migration exists exactly once in the ledger
# (a double-apply would show the description at two versions), and nothing is
# recorded failed.
C_SKI=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE description='artifacts storage key index';" | tr -d '[:space:]')
C_MFA=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE description='maven flat object attribution';" | tr -d '[:space:]')
C_BAD=$(psq "SELECT count(*) FROM _sqlx_migrations WHERE success=false;" | tr -d '[:space:]')
begin_test "POST-UPGRADE: no migration double-applied or failed (storage_key_index x$C_SKI, maven_flat x$C_MFA, failed=$C_BAD)"
{ [ "$C_SKI" = "1" ] && [ "$C_MFA" = "1" ] && [ "$C_BAD" = "0" ]; } && pass \
  || fail "ledger inconsistent: storage_key_index rows=$C_SKI (want 1), maven_flat rows=$C_MFA (want 1), failed rows=$C_BAD (want 0)"

# Main's own 154/155/156 must be applied FRESH into the freed slots, and the
# chain must have continued past 163.
D154=$(psq "SELECT description FROM _sqlx_migrations WHERE version=154;")
D155=$(psq "SELECT description FROM _sqlx_migrations WHERE version=155;")
D156=$(psq "SELECT description FROM _sqlx_migrations WHERE version=156;")
N_MAX=$(psq "SELECT max(version) FROM _sqlx_migrations;" | tr -d '[:space:]')
begin_test "POST-UPGRADE: main's 154/155/156 applied fresh and chain continued (max=$N_MAX)"
if [ "$D154" = "webhook deliveries claim" ] && [ "$D155" = "projects" ] \
   && [ "$D156" = "upstream feed state" ] && [ "${N_MAX:-0}" -ge 163 ]; then
  pass
else
  fail "main slots not reconciled: 154='$D154' 155='$D155' 156='$D156' max=$N_MAX (want webhook/projects/upstream_feed and max>=163)"
fi

# Schema end-state: the objects behind both the renumbered and the fresh
# migrations actually exist.
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

# Idempotency: a second candidate boot must be a strict no-op (repair fires 0
# more times, ledger unchanged, migrator green again).
ROWS_BEFORE=$(psq "SELECT count(*) FROM _sqlx_migrations;" | tr -d '[:space:]')
docker restart "$BACKEND_CTR" >/dev/null 2>&1
begin_test "IDEMPOTENCY: second candidate boot is a no-op (repair still 1 hit, ledger unchanged)"
if ! wait_health 40; then
  fail "candidate unhealthy on second boot of the upgraded volume"
else
  REPAIRS2=$(blog_count "migration_release_1_5_x_divergence_repair")
  MIGDONE2=$(blog_count "Database migrations complete")
  ROWS_AFTER=$(psq "SELECT count(*) FROM _sqlx_migrations;" | tr -d '[:space:]')
  if [ "$REPAIRS2" = "1" ] && [ "$MIGDONE2" = "2" ] && [ "$ROWS_AFTER" = "$ROWS_BEFORE" ]; then
    pass
  else
    fail "second boot not a no-op: repair hits=$REPAIRS2 (want 1), 'migrations complete' hits=$MIGDONE2 (want 2), ledger rows $ROWS_BEFORE -> $ROWS_AFTER"
  fi
fi

end_suite
# Teardown is left to run.sh (dtf_down / --keep).
