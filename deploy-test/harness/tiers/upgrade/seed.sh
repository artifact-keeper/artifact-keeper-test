#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade/seed.sh — canned OLD-SHAPE (row-less Maven) legacy-data seeder
# =============================================================================
# Plants the exact #2574/#2584 legacy shape on an S3-backed stack: Maven
# companion objects that physically exist in the shared bucket with NO per-file
# `artifacts` row (and NO `maven_flat_object_owner` attribution row), the
# "pristine legacy" state a pre-attribution deployment left behind.
#
# This reuses the isolation tier prove.sh Scenario F technique verbatim — plant
# each companion through the REAL Maven write handler, POSITIVELY confirm it was
# stored, then DELETE its DB rows so the physical object survives row-less — with
# ONE deliberate addition required by the upgrade path: a live "anchor" main
# `.jar` row is KEPT. That anchor is what the candidate's backfill migration
# derives ownership from (per the #2574 fix: "derived checksum/signature sidecars
# inherit the base object's owner"), so it is exactly the shape whose owner read
# the fix must RESTORE. A genuinely orphan companion (no live sibling) is left
# unattributed on purpose and stays fail-closed 404 for every tenant — that is
# the documented correct behavior, not the regression this tier gates.
#
# Sourced by oracle.sh. Sets, on success, the following globals for the oracle:
#   SD_MVA SD_MVB          — alice-writable repo / victim repo keys (this run)
#   SD_ALICE SD_APASS      — alice username / password
#   SD_VP                  — the GAV version path prefix (maven/<VP>/...)
#   SD_JAR SD_JARASC       — anchor jar file name / stored row-less .jar.asc name
#   SD_POM SD_POMASC        — orphan row-less pom / pom.asc names
#   SD_SECRET              — secret bytes embedded in the sidecars (leak detector)
# =============================================================================

# seed_login <base> <user> <pass> -> prints access token
seed_login() {
  curl -s -X POST "$1/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$2\",\"password\":\"$3\"}" | jq -r '.access_token // empty' 2>/dev/null
}
# seed_put <base> <path> <token> <body> [content-type] -> prints http code
seed_put() {
  local ct="${5:-application/octet-stream}"
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$1$2" \
    -H "Authorization: Bearer $3" -H "Content-Type: $ct" --data-binary "$4"
}
# seed_get_code <base> <path> <token> -> prints http code
seed_get_code() {
  curl -s -o /dev/null -w '%{http_code}' -X GET "$1$2" -H "Authorization: Bearer $3"
}

# seed_rowless_legacy <base_url> <db_container> <admin_pass>
# Returns 0 and exports the SD_* globals on a valid fixture; non-zero if the
# fixture could not be planted (so a false "denied" pass is impossible).
seed_rowless_legacy() {
  local BASE="$1" DBC="$2" ADMPASS="$3"
  local SUF="${RUN_ID:-r}$RANDOM$RANDOM"
  SD_MVA="mvn-a-$SUF"; SD_MVB="mvn-b-$SUF"
  SD_ALICE="alice-$SUF"; SD_APASS="AlicePass!2026x"
  local AID="applegacy$SUF"
  SD_VP="com/legacy/$AID/1.0"
  SD_JAR="$AID-1.0.jar"; SD_JARASC="$AID-1.0.jar.asc"
  SD_POM="$AID-1.0.pom"; SD_POMASC="$AID-1.0.pom.asc"
  SD_SECRET="LEGACY-ROWLESS-SIG-$SUF"

  local TOK; TOK="$(seed_login "$BASE" admin "$ADMPASS")"
  [ -z "$TOK" ] && { echo "   seed: admin login FAILED" >&2; return 1; }

  # alice + repos (maven local). alice is developer(write) on MVA ONLY, no grant on MVB.
  curl -s -X POST "$BASE/api/v1/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SD_ALICE\",\"email\":\"$SD_ALICE@t.test\",\"password\":\"$SD_APASS\",\"is_admin\":false}" >/dev/null
  local k
  for k in "$SD_MVA" "$SD_MVB"; do
    curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
      -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
  done
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc "
    INSERT INTO role_assignments (user_id, role_id, repository_id)
    SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
    WHERE u.username='$SD_ALICE' AND r.name='developer' AND repo.key='$SD_MVA'
    ON CONFLICT DO NOTHING;" >/dev/null

  # Fail-closed precondition: this class cannot manifest on filesystem storage.
  local SB
  SB=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT DISTINCT storage_backend FROM repositories WHERE key IN ('$SD_MVA','$SD_MVB');" 2>/dev/null | tr -d '[:space:]')
  if [ "$SB" = "filesystem" ] || [ -z "$SB" ]; then
    echo "   seed: repos on storage_backend='$SB'; upgrade tier requires a shared object store (s3/gcs)" >&2
    return 2
  fi

  # Companion content: a GPG-signature sidecar carries no DB checksum column, so
  # it is a genuinely STORED object (unlike .sha1/.md5/.sha256, which the backend
  # recomputes from the anchor row). The secret is embedded so a cross-tenant
  # leak is byte-detectable.
  local pomdoc
  pomdoc=$(printf '<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>com.legacy</groupId><artifactId>%s</artifactId><version>1.0</version></project>' "${AID}")

  local p_jar p_jarasc p_pom p_pomasc
  p_jar=$(seed_put "$BASE" "/maven/$SD_MVB/$SD_VP/$SD_JAR" "$TOK" "PK\003\004ANCHOR-$SUF")
  p_pom=$(seed_put "$BASE" "/maven/$SD_MVB/$SD_VP/$SD_POM" "$TOK" "$pomdoc" text/xml)
  p_jarasc=$(seed_put "$BASE" "/maven/$SD_MVB/$SD_VP/$SD_JARASC" "$TOK" "-----BEGIN PGP SIGNATURE-----$SD_SECRET-----END-----" text/plain)
  p_pomasc=$(seed_put "$BASE" "/maven/$SD_MVB/$SD_VP/$SD_POMASC" "$TOK" "-----BEGIN PGP SIGNATURE-----POM$SD_SECRET-----END-----" text/plain)
  echo "   seed: PUT anchor jar=$p_jar pom=$p_pom jar.asc=$p_jarasc pom.asc=$p_pomasc (expect 201)"

  # Positively confirm the anchor is stored + owner-readable BEFORE stripping, so
  # a rejected PUT can't masquerade as a later "denied" pass.
  local a_jar; a_jar=$(seed_get_code "$BASE" "/maven/$SD_MVB/$SD_VP/$SD_JAR" "$TOK")
  if [ "$a_jar" != "200" ]; then
    echo "   seed: anchor jar not stored/readable (GET=$a_jar); fixture invalid" >&2
    return 3
  fi

  # Make every COMPANION row-less: delete the artifacts rows for the companions,
  # keeping ONLY the anchor jar row. The physical objects survive in the bucket
  # with no per-file catalog row — the #2574/#2584 pristine-legacy shape.
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "DELETE FROM artifacts WHERE storage_key LIKE 'maven/$SD_VP/%' AND storage_key <> 'maven/$SD_VP/$SD_JAR';" >/dev/null
  # Belt-and-suspenders: strip any attribution rows too (a pre-attribution OLD
  # image has none, but a re-run must not inherit stale ownership).
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "DELETE FROM maven_flat_object_owner WHERE storage_key LIKE 'maven/$SD_VP/%';" >/dev/null 2>&1 || true

  local left_comp left_anchor
  left_comp=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM artifacts WHERE storage_key LIKE 'maven/$SD_VP/%' AND storage_key <> 'maven/$SD_VP/$SD_JAR';" | tr -d '[:space:]')
  left_anchor=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM artifacts WHERE storage_key = 'maven/$SD_VP/$SD_JAR';" | tr -d '[:space:]')
  echo "   seed: after strip -> companion rows=$left_comp (want 0), anchor rows=$left_anchor (want 1)"
  if [ "${left_comp:-1}" != "0" ] || [ "${left_anchor:-0}" != "1" ]; then
    echo "   seed: row-less fixture not achieved (companions=$left_comp anchor=$left_anchor)" >&2
    return 4
  fi
  return 0
}
