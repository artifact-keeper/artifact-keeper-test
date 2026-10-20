#!/usr/bin/env bash
# =============================================================================
# tiers/ingest-archive-entries-limit/oracle.sh: MAX_INGEST_ARCHIVE_ENTRIES is
# honoured by the upload metadata extractors (artifact-keeper#4093, fixed by
# #4802), filesystem + ingest.archive-entries.
# =============================================================================
# Background (util/bounded_archive.rs): read_metadata_from_zip refuses a zip
# whose central directory lists more entries than the cap with
#     AppError::Validation("ZIP archive contains too many entries (> N);
#                           refusing suspected decompression bomb")
# The Composer upload handler (api/handlers/composer.rs::upload) maps that to
#     400 "Failed to parse composer.json from archive: Validation error: ..."
# Before #4802 N was the const 10000; after, it is MAX_INGEST_ARCHIVE_ENTRIES
# (blank / zero / non-numeric fall back to 10000).
#
# The manifest sets the cap to 50 for the compose backend. The oracle builds
# Composer packages (composer.json + filler files) of CAP+31 and CAP-29
# entries and uploads them.
#
# Default leg: the cap is process-wide, so "unset means 10000" needs a backend
# without the variable. The oracle starts a second container from the same
# image on the same compose network, database and /data volume
# (--volumes-from), with the compose backend's env minus
# MAX_INGEST_ARCHIVE_ENTRIES, and uploads through it with `docker exec curl`
# (the image ships curl for its healthcheck; no host port is published). It is
# removed on exit.
#
# run.sh exports BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, RUN_ID,
# DTF_SLOT, BACKEND_IMAGE, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
: "${BACKEND_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
AUTH="${ADMIN_USER}:${ADMIN_PASS}"
CAP="${MAX_INGEST_ARCHIVE_ENTRIES:-50}"
OVER=$((CAP + 31))
UNDER=$((CAP - 29))
BACKEND_CTR="ak-dtf${SLOT}-backend"
DEFAULT_CTR="ak-dtf${SLOT}-backend-defaultcap"
REPO="cmpcap-${SLOT}-${SUF}"
VENDOR="dtfcap"

WORK="$(mktemp -d -t dtf-ingestcap-XXXXXX)"
cleanup() { docker rm -f "$DEFAULT_CTR" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
rows_for() { # package name -> live artifact rows in REPO
  psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE r.key = '${REPO}' AND a.name = '$1' AND a.is_deleted = false"
}

# mkpkg NAME VERSION ENTRIES OUT: a Composer zip with exactly ENTRIES entries
# (composer.json + ENTRIES-1 small vendored files).
mkpkg() {
  python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import json, sys, zipfile
name, version, entries, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("composer.json", json.dumps({"name": name, "version": version,
               "type": "library", "license": "MIT", "description": "dtf entry-cap probe"}))
    for i in range(entries - 1):
        z.writestr("vendor/dtf/filler/src/F%05d.php" % i, "<?php // %d\n" % i)
PY
}
zip_entries() { python3 -I -c 'import sys,zipfile; print(len(zipfile.ZipFile(sys.argv[1]).namelist()))' "$1" 2>/dev/null; }

# upload FILE: PUT to the compose backend; sets CODE and BODY.
CODE=""; BODY=""
upload() {
  CODE="$(curl -s --max-time 120 -o "$WORK/resp" -w '%{http_code}' -u "$AUTH" -X PUT \
    -H 'Content-Type: application/zip' --data-binary "@$1" \
    "${BASE_URL}/composer/${REPO}/api/packages" 2>/dev/null || echo 000)"
  BODY="$(head -c 400 "$WORK/resp" 2>/dev/null || true)"
}

begin_suite "ingest-archive-entries-limit"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: cap ${CAP} reaches the backend, composer repo, ${OVER}- and ${UNDER}-entry packages"
SETUP_ERR=""
ENV_CAP="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null \
  | sed -n 's/^MAX_INGEST_ARCHIVE_ENTRIES=//p')"
echo "-- ${BACKEND_CTR} env MAX_INGEST_ARCHIVE_ENTRIES=${ENV_CAP:-<unset>} (image ${BACKEND_IMAGE})"
[ "$ENV_CAP" = "$CAP" ] || SETUP_ERR="backend env MAX_INGEST_ARCHIVE_ENTRIES=${ENV_CAP:-<unset>}, want ${CAP};"
command -v python3 >/dev/null 2>&1 || SETUP_ERR="${SETUP_ERR} python3 missing;"
c="$(curl -s --max-time 60 -o "$WORK/resp" -w '%{http_code}' -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"composer",repo_type:"local",is_public:false}')" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
[ "${c:0:1}" = "2" ] || SETUP_ERR="${SETUP_ERR} create ${REPO} -> ${c};"
mkpkg "${VENDOR}/over" "1.0.0" "$OVER" "$WORK/over.zip"
mkpkg "${VENDOR}/under" "1.0.0" "$UNDER" "$WORK/under.zip"
mkpkg "${VENDOR}/overdefault" "1.0.0" "$OVER" "$WORK/overdefault.zip"
N_OVER="$(zip_entries "$WORK/over.zip")"; N_UNDER="$(zip_entries "$WORK/under.zip")"
echo "-- over.zip ${N_OVER} entries, under.zip ${N_UNDER} entries (cap ${CAP})"
[ "$N_OVER" = "$OVER" ] && [ "$N_UNDER" = "$UNDER" ] || SETUP_ERR="${SETUP_ERR} fixture entry counts ${N_OVER}/${N_UNDER};"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# FIX #4093: the configured cap refuses an archive over it
# =============================================================================
begin_test "FIX #4093: ${OVER}-entry Composer package over MAX_INGEST_ARCHIVE_ENTRIES=${CAP} is refused 400 naming the cap"
upload "$WORK/over.zip"
R="$(rows_for "${VENDOR}/over")"
echo "-- PUT over.zip -> ${CODE}: ${BODY}"
echo "-- artifacts rows for ${VENDOR}/over: ${R}"
if [ "$CODE" = "400" ] && printf '%s' "$BODY" | grep -q "too many entries (> ${CAP})" && [ "$R" = "0" ]; then pass; else
  fail "over-cap package not refused by the configured cap: HTTP ${CODE}, rows=${R} (want 400 'too many entries (> ${CAP})', 0 rows); pre-#4802 the env var is ignored and the 10000 const accepts it"
fi

# =============================================================================
# CONTROLS
# =============================================================================
begin_test "CONTROL: ${UNDER}-entry Composer package under the cap is accepted and stored"
upload "$WORK/under.zip"
R="$(rows_for "${VENDOR}/under")"
echo "-- PUT under.zip -> ${CODE}: ${BODY:0:200}"
echo "-- artifacts rows for ${VENDOR}/under: ${R}"
if [ "${CODE:0:1}" = "2" ] && [ "$R" = "1" ]; then pass; else
  fail "under-cap package not accepted: HTTP ${CODE}, rows=${R}"
fi

begin_test "CONTROL: a backend WITHOUT the variable (default 10000) accepts the ${OVER}-entry package"
NET="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$BACKEND_CTR" 2>/dev/null | head -1)"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null \
  | grep -E '^(DATABASE_URL|STORAGE_PATH|BACKUP_PATH|PLUGINS_DIR|JWT_SECRET|ADMIN_PASSWORD|RUST_LOG|HOST|PORT|STORAGE_BACKEND|RATE_LIMIT_ENABLED|UPSTREAM_ALLOW_PRIVATE_IPS)=' \
  > "$WORK/default.env"
docker rm -f "$DEFAULT_CTR" >/dev/null 2>&1 || true
RUN_ERR=""
if [ -z "$NET" ] || ! docker run -d --name "$DEFAULT_CTR" --network "$NET" --env-file "$WORK/default.env" \
     --volumes-from "$BACKEND_CTR" "$BACKEND_IMAGE" >/dev/null 2>"$WORK/run.err"; then
  RUN_ERR="docker run failed (net=${NET:-?}): $(head -c 300 "$WORK/run.err")"
fi
UP=0
if [ -z "$RUN_ERR" ]; then
  for _ in $(seq 1 60); do
    if docker exec "$DEFAULT_CTR" curl -sf --max-time 5 http://localhost:8080/health >/dev/null 2>&1; then UP=1; break; fi
    sleep 2
  done
fi
if [ -n "$RUN_ERR" ] || [ "$UP" != "1" ]; then
  docker logs --tail 40 "$DEFAULT_CTR" 2>&1 | sed 's/^/   | /'
  fail "second backend without MAX_INGEST_ARCHIVE_ENTRIES did not come up: ${RUN_ERR:-health never 200 in 120s}"
else
  DENV="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$DEFAULT_CTR" | grep -c '^MAX_INGEST_ARCHIVE_ENTRIES=' || true)"
  DCODE="$(docker exec -i "$DEFAULT_CTR" curl -s --max-time 120 -o /tmp/dtf-resp -w '%{http_code}' -u "$AUTH" -X PUT \
    -H 'Content-Type: application/zip' --data-binary @- \
    "http://localhost:8080/composer/${REPO}/api/packages" <"$WORK/overdefault.zip" 2>/dev/null || echo 000)"
  DBODY="$(docker exec "$DEFAULT_CTR" head -c 300 /tmp/dtf-resp 2>/dev/null || true)"
  R="$(rows_for "${VENDOR}/overdefault")"
  echo "-- ${DEFAULT_CTR}: MAX_INGEST_ARCHIVE_ENTRIES entries in env: ${DENV}"
  echo "-- PUT overdefault.zip (${OVER} entries) via default-cap backend -> ${DCODE}: ${DBODY:0:200}"
  echo "-- artifacts rows for ${VENDOR}/overdefault: ${R}"
  if [ "$DENV" = "0" ] && [ "${DCODE:0:1}" = "2" ] && [ "$R" = "1" ]; then pass; else
    fail "default-cap backend refused or did not store the ${OVER}-entry package: env-count=${DENV}, HTTP ${DCODE}, rows=${R}"
  fi
fi

end_suite
