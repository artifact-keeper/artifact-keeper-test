#!/usr/bin/env bash
# =============================================================================
# tiers/maven-files-casing/oracle.sh — Maven flat-key companion casing gate
# (#2706 / #2707), S3/MinIO storage.
# =============================================================================
# Discriminating oracle for the 1.6.0 Maven flat-key attribution casing bug.
#
# Background (maven_flat_attribution.rs::OWNER_BY_METADATA_FILES_SQL):
#   A row-less legacy GAV companion (.pom/.module/-sources.jar) — a physical
#   object in the shared bucket with NO artifacts row and NO attribution-table
#   row — is attributed to its owning repo ONLY by matching its storage key
#   against the parent artifact's metadata `files[]` array. The upload handler
#   writes those elements in camelCase (`storageKey`). The pre-#2706 resolver
#   compared snake_case (f->>'storage_key'), which never matched, so on a CLOUD
#   backend the OWNER's own GET of the companion 404'd. #2706 reads
#   COALESCE(f->>'storageKey', f->>'storage_key').
#
# Fixture (built to isolate exactly the files[] attribution layer):
#   * repo MVA (owner) + repo MVB (foreign), both maven/local on the s3 backend
#   * admin PUTs a GAV group into MVA: the parent .jar (keeps its row) plus the
#     .pom/.module/-sources.jar companions (planted + verified readable)
#   * the parent .jar's artifact_metadata.metadata.files[] is set to a camelCase
#     `storageKey` array naming the companions
#   * the companions' OWN artifacts rows AND maven_flat_object_owner rows are
#     deleted, so the physical objects survive row-less — resolvable ONLY via
#     the parent's files[] array (the #2706 code path).
#
# Asserts:
#   POSITIVE  — owner (via MVA) GET .module / -sources.jar -> 200 + owner bytes.
#               Pre-#2706: 404 (snake_case never matched). rc (fixed): 200.
#   ISOLATION — foreign (via MVB) GET the same shared flat keys -> 404, no bytes
#               (single-owner-per-backend preserved on the fixed image).
#
# run.sh has already stood up the s3 profile-set and exported BASE_URL,
# DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SUF="$RANDOM$RANDOM"
MVA="mfc-a-$SUF"      # owning repo
MVB="mfc-b-$SUF"      # foreign repo (same shared bucket)
AID="applib$SUF"      # unique artifactId so path version segments stay valid
GAV="com/legacy/$AID/1.0"
JARPATH="$GAV/$AID-1.0.jar"
POM="$GAV/$AID-1.0.pom"
MODULE="$GAV/$AID-1.0.module"
SOURCES="$GAV/$AID-1.0-sources.jar"
SECRET="MFC-COMPANION-SECRET-$SUF"

# --- self-contained HTTP + DB helpers (prove.sh style) ----------------------
jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
code(){ # METHOD PATH TOKEN [BODY] [CT]
  local m="$1" p="$2" t="$3" b="${4:-}" ct="${5:-application/octet-stream}"
  if [ -n "$b" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H "Content-Type: $ct" --data-binary "$b"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t"
  fi; }
body(){ curl -s -X "$1" "$BASE$2" -H "Authorization: Bearer $3"; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

# camelCase files[] content, one per companion. The secret is embedded so a
# cross-repo leak (or a correct owner read) is byte-detectable. Format-valid so
# the Maven write validators accept the PUT (a raw string 400s for .pom/.jar).
plant_content(){
  case "$1" in
    *.pom)     printf '<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>com.legacy</groupId><artifactId>%s</artifactId><version>1.0</version><!--%s--></project>' "$AID" "$SECRET" ;;
    *.module)  printf '{"formatVersion":"1.1","component":{"group":"com.legacy","module":"%s","version":"1.0"},"marker":"%s"}' "$AID" "$SECRET" ;;
    *.jar)     printf 'PK\003\004%s' "$SECRET" ;;
    *)         printf '%s' "$SECRET" ;;
  esac
}

begin_suite "maven-files-casing-s3"

begin_test "Maven row-less GAV companion attribution: owner reads .module/-sources.jar via parent camelCase files[] (#2706) while a foreign repo is denied (S3)"

FAILS=0
fail_leak(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); }

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then fail "admin login failed at $BASE"; end_suite; exit 1; fi

# repos (maven/local); storage_backend inherits the stack's STORAGE_BACKEND=s3
for k in "$MVA" "$MVB"; do
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
done

# Fail-closed precondition: this gate is meaningless on a filesystem backend
# (flat_key_readable short-circuits true; the casing bug cannot manifest).
SB=$(psql_q "SELECT DISTINCT storage_backend FROM repositories WHERE key IN ('$MVA','$MVB');" | tr -d '[:space:]')
echo "-- storage_backend of repos: '$SB'"
if [ "$SB" = "filesystem" ] || [ -z "$SB" ]; then
  fail "GATE-ABORT: repos are on storage_backend='$SB'; this tier must run on a shared object store (storage.s3)"
  end_suite; exit 1
fi

# --- Plant the GAV group into MVA through the normal handler -----------------
JC="$(plant_content "$JARPATH")"
echo "-- admin PUT parent $MVA/$JARPATH => $(code PUT "/maven/$MVA/$JARPATH" "$TOK" "$JC")"
for cp in "$POM" "$MODULE" "$SOURCES"; do
  C="$(plant_content "$cp")"
  pc=$(code PUT "/maven/$MVA/$cp" "$TOK" "$C")
  ab=$(body GET "/maven/$MVA/$cp" "$TOK")
  if echo "$ab" | grep -q "$SECRET"; then
    echo "   [setup] planted+verified $cp (PUT=$pc)"
  else
    fail_leak "setup: companion $cp not stored/readable pre-strip (PUT=$pc) — fixture invalid"
  fi
done

# Resolve the parent .jar artifact id.
JARID=$(psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$MVA' AND a.storage_key='maven/$JARPATH' AND a.is_deleted=false LIMIT 1;" | tr -d '[:space:]')
echo "-- parent .jar artifact id: '${JARID:-<none>}'"
if [ -z "$JARID" ]; then fail_leak "setup: could not resolve parent .jar artifact row"; fi

# Overwrite the parent's metadata files[] with a camelCase `storageKey` array
# naming the three companions (the #2706 shape). Merge (||) so any existing
# groupId/artifactId metadata is preserved.
if [ -n "$JARID" ]; then
  FILES_JSON=$(cat <<JSON
{"files":[
 {"path":"$POM","extension":"pom","storageKey":"maven/$POM","sizeBytes":200,"sha256":"pom-$SUF"},
 {"path":"$MODULE","extension":"module","storageKey":"maven/$MODULE","sizeBytes":180,"sha256":"mod-$SUF"},
 {"path":"$SOURCES","extension":"jar","classifier":"sources","storageKey":"maven/$SOURCES","sizeBytes":800,"sha256":"src-$SUF"}
]}
JSON
)
  docker exec -i "$DBC" psql -U registry -d artifact_registry -tA >/dev/null 2>&1 <<SQL
INSERT INTO artifact_metadata (artifact_id, format, metadata)
VALUES ('$JARID', 'maven', '$FILES_JSON'::jsonb)
ON CONFLICT (artifact_id) DO UPDATE SET metadata = artifact_metadata.metadata || EXCLUDED.metadata;
SQL
  FCNT=$(psql_q "SELECT jsonb_array_length(metadata->'files') FROM artifact_metadata WHERE artifact_id='$JARID';" | tr -d '[:space:]')
  echo "-- parent files[] length after set: '${FCNT:-0}'"
  [ "${FCNT:-0}" = "3" ] || fail_leak "setup: parent files[] not set to 3 companions (got '${FCNT:-0}')"
fi

# Strip the companions to genuinely row-less (no artifacts row, no attribution
# row) so the ONLY resolution path is the parent's files[] array.
for cp in "$POM" "$MODULE" "$SOURCES"; do
  psql_q "DELETE FROM artifacts WHERE storage_key='maven/$cp';" >/dev/null
  psql_q "DELETE FROM maven_flat_object_owner WHERE storage_key='maven/$cp';" >/dev/null 2>&1 || true
done
LEFT_ART=$(psql_q "SELECT count(*) FROM artifacts WHERE storage_key IN ('maven/$POM','maven/$MODULE','maven/$SOURCES');" | tr -d '[:space:]')
LEFT_OWN=$(psql_q "SELECT count(*) FROM maven_flat_object_owner WHERE storage_key IN ('maven/$POM','maven/$MODULE','maven/$SOURCES');" 2>/dev/null | tr -d '[:space:]')
echo "-- after strip: companion artifacts rows=$LEFT_ART attribution rows=${LEFT_OWN:-NA} (both must be 0)"
[ "${LEFT_ART:-1}" = "0" ] || fail_leak "setup: companions not row-less (artifacts rows remain=$LEFT_ART)"

# --- POSITIVE: owner (via MVA) must now read the row-less companions ---------
# .module and -sources.jar are plain byte companions (no dynamic maven-metadata
# generation), so a 200 here is a genuine served-object, not a synthesized body.
for cp in "$MODULE" "$SOURCES"; do
  rc=$(code GET "/maven/$MVA/$cp" "$TOK")
  b=$(body GET "/maven/$MVA/$cp" "$TOK")
  if [ "$rc" = "200" ] && echo "$b" | grep -q "$SECRET"; then
    echo "   POSITIVE OK: owner served $cp (HTTP 200, owner bytes) — files[] camelCase attribution resolved"
  else
    fail_leak "POSITIVE: owner GET $MVA/$cp expected 200+owner-bytes, got HTTP $rc (pre-#2706 snake_case miss => 404)"
  fi
done

# --- ISOLATION: a foreign repo on the same shared bucket must be denied ------
for cp in "$POM" "$MODULE" "$SOURCES"; do
  rc=$(code GET "/maven/$MVB/$cp" "$TOK")
  b=$(body GET "/maven/$MVB/$cp" "$TOK")
  if echo "$b" | grep -q "$SECRET"; then
    fail_leak "ISOLATION: foreign repo MVB leaked companion $cp bytes (cross-tenant read)"
  elif [ "$rc" = "404" ] || [ "$rc" = "403" ]; then
    echo "   ISOLATION OK: foreign MVB denied $cp (HTTP $rc)"
  else
    fail_leak "ISOLATION: foreign MVB GET $cp unexpected HTTP $rc (expected 404/403)"
  fi
done

if [ "$FAILS" -eq 0 ]; then
  pass
else
  fail "maven flat-key companion casing GATE failed: $FAILS assertion(s) — either the owner could not read a row-less companion via camelCase files[] (pre-#2706) or a foreign repo leaked it; see stdout above"
fi

end_suite
