#!/usr/bin/env bash
# =============================================================================
# tiers/conda-migration-indexed-timestamp/oracle.sh: a conda package migrated
# from Artifactory keeps the source's created time as its CEP 47
# indexed_timestamp (artifact-keeper#6528). See the manifest for the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${DTF_SLOT}x${RUN_ID##*-}"
MOCK="ak-dtf${DTF_SLOT}-mock-artifactory"
SRC_REPO="dtfcat-conda"
PKG="dtfmig-1.0-0.tar.bz2"
SOURCE_MS="1767225600000"   # 2026-01-01T00:00:00Z, what the mock reports
WORK="$(mktemp -d -t dtf-cmig-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
CURLF=(--max-time 60)

aj() { local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then curl -s "${CURLF[@]}" -X "$m" "${BASE_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' -d "$b" 2>/dev/null || true
  else curl -s "${CURLF[@]}" -X "$m" "${BASE_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true; fi; }
jqf() { echo "$1" | jq -r "$2" 2>/dev/null || echo "$3"; }
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

run_job() { # -> job id once terminal
  local body id
  body="$(jq -nc --arg cid "$CONN_ID" --arg repo "$SRC_REPO" '{
    source_connection_id: $cid, job_type: "full",
    config: { include_repos: [$repo], dry_run: false, conflict_resolution: "overwrite",
              verify_checksums: true, include_users: false, include_groups: false,
              include_permissions: false, concurrent_transfers: 1, throttle_delay_ms: 0 } }')"
  id="$(jqf "$(aj POST /api/v1/migrations "$body")" '.id // empty' '')"
  [ -n "$id" ] || return 0
  aj POST "/api/v1/migrations/${id}/start" >/dev/null
  for _ in $(seq 1 120); do
    case "$(jqf "$(aj GET "/api/v1/migrations/${id}")" '.status // ""' '')" in
      completed|completed_with_errors|failed|cancelled) break ;;
    esac
    sleep 1
  done
  echo "$id"
}
repodata_ts() { # -> indexed_timestamp of PKG in the destination's noarch repodata.json ("absent")
  curl -s "${CURLF[@]}" -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/conda/${DEST}/noarch/repodata.json" 2>/dev/null \
    | jq -r --arg f "$PKG" '(.packages // {})[$f].indexed_timestamp // "absent"' 2>/dev/null || echo absent
}
row_ms() { psql_q "SELECT (extract(epoch FROM a.created_at) * 1000)::bigint FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key='${DEST}' AND a.path LIKE '%${PKG}' AND a.is_deleted = false"; }

begin_suite "conda-migration-indexed-timestamp (#6528)"

begin_test "setup: a real conda package in the mock Artifactory, a connection, the first migration"
auth_admin
setup_err=""
mkdir -p "$WORK/src/${SRC_REPO}/noarch"
bash "${DTF_DIR}/fixtures/conda/build.sh" "$WORK/src/${SRC_REPO}/noarch" dtfmig 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build; "
docker cp "$WORK/src/." "${MOCK}:/srv/catalog/" >/dev/null 2>&1 || setup_err+="docker cp; "
CONN_ID="$(jqf "$(aj POST /api/v1/migrations/connections "$(jq -nc --arg n "dtf-cmig-${SUF}" '{
  name: $n, url: "http://mock-artifactory", auth_type: "basic_auth",
  source_type: "artifactory", credentials: {username: "dtf", password: "dtf"} }')")" '.id // empty' '')"
[ -n "$CONN_ID" ] || setup_err+="connection; "
if [ -n "$setup_err" ]; then infra_fail "setup did not complete" "$setup_err"; end_suite; fi
JOB1="$(run_job)"
ROW1="$(aj GET "/api/v1/migrations/${JOB1}")"
DEST="$(psql_q "SELECT r.key FROM repositories r JOIN artifacts a ON a.repository_id = r.id WHERE a.path LIKE '%${PKG}' LIMIT 1")"
DEST="${DEST:-$SRC_REPO}"
pass

begin_test "CONTROL: the migration completes with the one source file into a conda repository"
st="$(jqf "$ROW1" '.status // "?"' '?')"; done1="$(jqf "$ROW1" '.completed_items // 0' 0)"
fmt="$(psql_q "SELECT format::text FROM repositories WHERE key='${DEST}'")"
if [ "$st" = "completed" ] && [ "$done1" = "1" ] && { [ "$fmt" = "conda" ] || [ "$fmt" = "conda_native" ]; }; then pass
else fail "migration status=${st} completed=${done1} destination=${DEST} format=${fmt}" "$(echo "$ROW1" | head -c 400)"; fi

# A hosted conda row's created_at is what repodata serves as indexed_timestamp.
ms="$(row_ms)"
begin_test "FIX #6528: the migrated row's created_at (its indexed_timestamp) is the source's created time (${SOURCE_MS})"
if [ "$ms" = "$SOURCE_MS" ]; then pass
else fail "#6528: created_at ${ms:-none} ms (the import time) instead of the source's ${SOURCE_MS}"; fi
ts="$(repodata_ts)"
begin_test "FIX #6532: the destination's repodata.json lists the package with the source's created time as indexed_timestamp"
if [ "$ts" = "$SOURCE_MS" ]; then pass
else fail "#6528: repodata.json indexed_timestamp for ${PKG}: ${ts} (want ${SOURCE_MS})"; fi

# Revival: a soft-deleted row (with an older time) is brought back by a
# re-import. It became visible again now, so it counts from now.
psql_q "UPDATE artifacts a SET created_at = '2000-01-01T00:00:00Z', is_deleted = true FROM repositories r WHERE r.id = a.repository_id AND r.key = '${DEST}' AND a.path LIKE '%${PKG}'" >/dev/null
T_REVIVE="$(psql_q "SELECT (extract(epoch FROM NOW()) * 1000)::bigint")"
JOB2="$(run_job)"
ROW2="$(aj GET "/api/v1/migrations/${JOB2}")"
ms="$(row_ms)"
begin_test "FIX #6528: a re-import that revives a soft-deleted row counts it from the revival"
if [ -n "$ms" ] && [ "$ms" -ge "$T_REVIVE" ] 2>/dev/null; then pass
else fail "#6528: revived row created_at ${ms:-none} ms, revival at ${T_REVIVE} (status $(jqf "$ROW2" '.status // "?"' '?'), completed $(jqf "$ROW2" '.completed_items // 0' 0))"; fi

# ...unless this server's age-gate sighting ledger already holds the same
# bytes, which keep their first sighting.
PKG_SHA="$(sha256sum "$WORK/src/${SRC_REPO}/noarch/${PKG}" | awk '{print $1}')"
LEDGER_MS="1748736000000"   # 2025-06-01T00:00:00Z
DEST_ID="$(psql_q "SELECT id FROM repositories WHERE key='${DEST}'")"
psql_q "INSERT INTO conda_first_seen_channels (repository_id, subdir, upstream_fingerprint, baseline_at) VALUES ('${DEST_ID}', 'dtf-ledger', 'dtf', NOW())" >/dev/null
CH="$(psql_q "SELECT id FROM conda_first_seen_channels WHERE repository_id='${DEST_ID}' AND subdir='dtf-ledger'")"
psql_q "INSERT INTO conda_record_first_seen (channel_id, filename, sha256, first_seen_at) VALUES (${CH:-0}, '${PKG}', '${PKG_SHA}', '2025-06-01T00:00:00Z')" >/dev/null
psql_q "UPDATE artifacts a SET is_deleted = true FROM repositories r WHERE r.id = a.repository_id AND r.key = '${DEST}' AND a.path LIKE '%${PKG}'" >/dev/null
run_job >/dev/null
ms="$(row_ms)"
begin_test "FIX #6528: a revived row whose bytes the sighting ledger holds keeps that first sighting"
if [ "$ms" = "$LEDGER_MS" ]; then pass
else fail "#6528: revived row created_at ${ms:-none} ms (want the ledger's ${LEDGER_MS}; channel ${CH:-none})"; fi

end_suite
