#!/usr/bin/env bash
# =============================================================================
# perf/harness/lib/seed.sh — bulk dataset seeder for the PTF scale profiles
# =============================================================================
# The scale profiles (million-artifact-lite, metadata-scale, search-at-scale)
# need K existing artifacts across R repos BEFORE they measure. Uploading one at
# a time over HTTP is far too slow at K=50k (minutes-to-hours). This seeder takes
# the fastest bulk path: a single `INSERT ... SELECT generate_series(...)` per
# table executed straight against the slot's postgres container. 50k artifact
# rows land in seconds. The read surfaces the scale profiles hit — list, search,
# repo browse, GET /api/v1/admin/stats, analytics storage/breakdown — all read
# the `artifacts` (+ optional `artifact_metadata`) tables, so DB-direct rows are
# fully visible to them. (Download of a seeded row is NOT the target here: blobs
# are optional; see --blobs. Seeding is idempotent and RUN_ID/prefix-scoped.)
#
# Usage (standalone, against any running slot's DB container):
#   bash harness/lib/seed.sh --db-container ak-perf1-db --count 50000 --repos 5
#   [--format generic] [--size-bytes 4096] [--prefix perfseed] [--run-id ID]
#   [--metadata 0|1] [--blobs 0|1] [--volume ak-perf1_data] [--truncate] [--quiet]
#
# Or sourced:  source harness/lib/seed.sh ; perf_seed --db-container ... --count ...
#
# Schema anchored to target-backend/backend/migrations:
#   repositories(key,name,format(enum),repo_type(enum),storage_backend,
#                storage_path,is_public)                      003_repositories.sql
#   artifacts(repository_id,path,name,version,size_bytes,checksum_sha256,
#             content_type,storage_key,is_deleted)            004_artifacts.sql
#   artifact_metadata(artifact_id,format,metadata)            004_artifacts.sql
# =============================================================================
set -uo pipefail

# valid repository_format enum values (003_repositories.sql)
_PERF_SEED_FORMATS="maven gradle npm pypi nuget go rubygems docker helm rpm debian conan cargo generic"

perf_seed() {
  local DB="" VOL="" COUNT=1000 REPOS=1 FORMAT="generic" SIZE=4096
  local PREFIX="perfseed" RUN_ID_LOCAL="" META=1 BLOBS=0 TRUNCATE=0 QUIET=0
  local PGUSER="registry" PGDB="artifact_registry"

  while [ $# -gt 0 ]; do
    case "$1" in
      --db-container) DB="$2"; shift 2 ;;
      --volume)       VOL="$2"; shift 2 ;;
      --count)        COUNT="$2"; shift 2 ;;
      --repos)        REPOS="$2"; shift 2 ;;
      --format)       FORMAT="$2"; shift 2 ;;
      --size-bytes)   SIZE="$2"; shift 2 ;;
      --prefix)       PREFIX="$2"; shift 2 ;;
      --run-id)       RUN_ID_LOCAL="$2"; shift 2 ;;
      --metadata)     META="$2"; shift 2 ;;
      --blobs)        BLOBS="$2"; shift 2 ;;
      --pguser)       PGUSER="$2"; shift 2 ;;
      --pgdb)         PGDB="$2"; shift 2 ;;
      --truncate)     TRUNCATE=1; shift ;;
      --quiet)        QUIET=1; shift ;;
      *) echo "seed: unknown arg: $1" >&2; return 2 ;;
    esac
  done

  [ -n "$DB" ] || { echo "seed: --db-container required" >&2; return 2; }
  case "$COUNT" in ''|*[!0-9]*) echo "seed: --count must be an integer" >&2; return 2 ;; esac
  case "$REPOS" in ''|*[!0-9]*|0) echo "seed: --repos must be a positive integer" >&2; return 2 ;; esac
  case "$SIZE"  in ''|*[!0-9]*) echo "seed: --size-bytes must be an integer" >&2; return 2 ;; esac
  # validate format against the enum allowlist (also blocks SQL injection via it)
  printf '%s\n' $_PERF_SEED_FORMATS | grep -qx "$FORMAT" \
    || { echo "seed: --format '${FORMAT}' not a valid repository_format" >&2; return 2; }
  # sanitize prefix to a safe, interpolation-proof token
  case "$PREFIX" in *[!A-Za-z0-9-]*) echo "seed: --prefix must match [A-Za-z0-9-]" >&2; return 2 ;; esac
  # run-id scoping makes concurrent/idempotent seeds not collide
  [ -n "$RUN_ID_LOCAL" ] && PREFIX="${PREFIX}-${RUN_ID_LOCAL//[!A-Za-z0-9-]/}"

  local psql=(docker exec -i "$DB" psql -v ON_ERROR_STOP=1 -U "$PGUSER" -d "$PGDB" -qtA)

  [ "$QUIET" = 1 ] || echo ">> seed: DB=${DB} prefix=${PREFIX} repos=${REPOS} count=${COUNT} format=${FORMAT} size=${SIZE}B metadata=${META} blobs=${BLOBS}"

  local t0; t0="$(date +%s.%N)"

  # ---- optional truncate of THIS prefix's prior rows (idempotent reseed) ------
  if [ "$TRUNCATE" = 1 ]; then
    "${psql[@]}" <<SQL >/dev/null || { echo "seed: truncate failed" >&2; return 1; }
DELETE FROM repositories WHERE key LIKE '${PREFIX}-r%';
SQL
  fi

  # ---- repos: R rows ----------------------------------------------------------
  # ON CONFLICT keeps reseeds idempotent. storage_path is synthetic (read-surface
  # seeding does not touch the object store).
  "${psql[@]}" <<SQL >/dev/null || { echo "seed: repo insert failed" >&2; return 1; }
INSERT INTO repositories (key, name, format, repo_type, storage_backend, storage_path, is_public)
SELECT '${PREFIX}-r'||g, '${PREFIX}-r'||g,
       '${FORMAT}'::repository_format, 'local'::repository_type,
       'filesystem', '/data/storage/${PREFIX}-r'||g, true
FROM generate_series(1, ${REPOS}) g
ON CONFLICT (key) DO NOTHING;
SQL

  # ---- artifacts: K rows spread round-robin across the R repos -----------------
  # checksum_sha256 is CHAR(64): md5()||md5() == 64 hex chars. path is globally
  # unique (embeds g) so it never collides across repos.
  "${psql[@]}" <<SQL >/dev/null || { echo "seed: artifact insert failed" >&2; return 1; }
INSERT INTO artifacts
  (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
SELECT r.id,
       'seed/${PREFIX}/'||g||'.bin',
       '${PREFIX}-pkg-'||g,
       '1.0.'||(g % 1000),
       ${SIZE},
       md5(g::text || '${PREFIX}') || md5((g * 7 + 1)::text),
       'application/octet-stream',
       '${PREFIX}/'||((g % ${REPOS}) + 1)||'/'||g||'.bin',
       false
FROM generate_series(1, ${COUNT}) g
JOIN repositories r ON r.key = '${PREFIX}-r'||((g % ${REPOS}) + 1)
ON CONFLICT (repository_id, path) DO NOTHING;
SQL

  # ---- optional artifact_metadata (for the metadata / format read surfaces) ----
  if [ "$META" = 1 ]; then
    "${psql[@]}" <<SQL >/dev/null || { echo "seed: metadata insert failed" >&2; return 1; }
INSERT INTO artifact_metadata (artifact_id, format, metadata)
SELECT a.id, '${FORMAT}', '{}'::jsonb
FROM artifacts a
WHERE a.path LIKE 'seed/${PREFIX}/%'
ON CONFLICT (artifact_id) DO NOTHING;
SQL
  fi

  # ---- optional minimal blob write (ONE shared placeholder per repo) ----------
  # DB-direct rows have no backing object. If a profile needs downloads to not
  # 404, --blobs writes a single small placeholder into each repo's storage dir.
  # This is intentionally minimal (not per-artifact): the scale profiles measure
  # the metadata/read plane, not object transfer.
  if [ "$BLOBS" = 1 ]; then
    if [ -z "$VOL" ]; then
      echo "seed: --blobs requires --volume <docker volume>" >&2; return 2
    fi
    local mp; mp="$(docker volume inspect "$VOL" -f '{{.Mountpoint}}' 2>/dev/null)"
    if [ -n "$mp" ]; then
      local r
      for r in $(seq 1 "$REPOS"); do
        local d="${mp}/storage/${PREFIX}-r${r}"
        ( mkdir -p "$d" 2>/dev/null && head -c "$SIZE" /dev/zero > "${d}/.seed-placeholder.bin" 2>/dev/null ) \
          || ( sudo -n mkdir -p "$d" 2>/dev/null && sudo -n sh -c "head -c ${SIZE} /dev/zero > '${d}/.seed-placeholder.bin'" 2>/dev/null ) \
          || echo "seed: warn: could not write placeholder blob under ${d} (perms)" >&2
      done
    else
      echo "seed: warn: volume ${VOL} not found; skipping blobs" >&2
    fi
  fi

  local t1; t1="$(date +%s.%N)"

  # ---- validate + report ------------------------------------------------------
  local seeded rate secs
  seeded="$("${psql[@]}" -c "SELECT count(*) FROM artifacts WHERE path LIKE 'seed/${PREFIX}/%';" 2>/dev/null | tr -d '[:space:]')"
  seeded="${seeded:-0}"
  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
  rate="$(awk -v n="$seeded" -v s="$secs" 'BEGIN{printf "%.0f", (s>0)? n/s : 0}')"
  [ "$QUIET" = 1 ] || echo ">> seed: ${seeded} artifact rows across ${REPOS} repos in ${secs}s (${rate} rows/s)"

  # export for callers that want the numbers
  PERF_SEED_ROWS="$seeded"; PERF_SEED_SECS="$secs"; PERF_SEED_RATE="$rate"
  PERF_SEED_PREFIX="$PREFIX"
  export PERF_SEED_ROWS PERF_SEED_SECS PERF_SEED_RATE PERF_SEED_PREFIX
  return 0
}

# run standalone when executed directly (not sourced)
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  perf_seed "$@"
fi
