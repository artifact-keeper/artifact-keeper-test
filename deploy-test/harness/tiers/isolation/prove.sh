#!/usr/bin/env bash
# Cross-tenant read/write GATE for #2504 (cloud-storage cross-tenant read+write)
# plus #2574/#2584 (Maven row-less flat-key read/write isolation, GHSA-g6ph).
#
# Usage: prove.sh <BASE_URL> <DB_CONTAINER> <LABEL>
#
# This is a GATE, not a demo: every scenario asserts the isolated outcome and
# any cross-tenant leak (or a broken same-tenant regression) accumulates into
# $FAILS. The script exits NON-ZERO if ANY leak/regression is observed, so it
# can be wired directly into a required CI job.
#   - Against a fixed image (isolation holds): exit 0.
#   - Against a pre-fix image (leaks): exit 1.
set -uo pipefail
BASE="$1"; DBC="$2"; LABEL="$3"
# Parametrized so the gate matches whatever ADMIN_PASSWORD the compose sets.
ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
APASS="AlicePass!2026x"
SUF="$RANDOM$RANDOM"
MVA="mvn-a-$SUF"; MVB="mvn-b-$SUF"
COORD="com/secret/app/1.0-$SUF/app-1.0-$SUF.jar"
SECRET="MVNB-SECRET-BYTES-$SUF"
EVIL="ALICE-EVIL-CLOBBER-$SUF"
OWN="ALICE-OWN-BYTES-$SUF"
OWNCOORD="com/alice/lib/2.0-$SUF/lib-2.0-$SUF.jar"

FAILS=0
fail_leak(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); }

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // empty'; }
code(){ # METHOD PATH TOKEN [BODY] [CT]
  local m="$1" p="$2" t="$3" b="${4:-}" ct="${5:-application/octet-stream}"
  if [ -n "$b" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H "Content-Type: $ct" --data-binary "$b"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t"
  fi; }
body(){ curl -s -X "$1" "$BASE$2" -H "Authorization: Bearer $3"; }

echo "############ GATE: $LABEL  ($BASE) ############"
TOK=$(login admin "$ADMPASS"); [ -z "$TOK" ] && { echo "admin login FAILED"; exit 1; }

# alice
curl -s -X POST "$BASE/api/v1/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice-$SUF\",\"email\":\"alice-$SUF@t.test\",\"password\":\"$APASS\",\"is_admin\":false}" >/dev/null
# repos (maven, local) — default storage_backend inherits the stack's STORAGE_BACKEND
for k in "$MVA" "$MVB"; do
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
done
# grant alice developer(write) on MVA only; NO grant on MVB
docker exec "$DBC" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='alice-$SUF' AND r.name='developer' AND repo.key='$MVA'
  ON CONFLICT DO NOTHING;" >/dev/null
ATOK=$(login "alice-$SUF" "$APASS"); [ -z "$ATOK" ] && { echo "alice login FAILED"; exit 1; }

# Fail-closed precondition: this gate is meaningless on a filesystem backend
# (each repo physically owns its key space, so the cross-tenant class cannot
# manifest). Assert both repos are on a shared object-store namespace.
SB=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT DISTINCT storage_backend FROM repositories WHERE key IN ('$MVA','$MVB');" 2>/dev/null | tr -d '[:space:]')
echo "-- backend storage_backend of repos: '$SB'"
if [ "$SB" = "filesystem" ] || [ -z "$SB" ]; then
  echo "   !!! GATE-ABORT: repos are on storage_backend='$SB'; this gate must run on a shared object store (s3/gcs/azure)."
  exit 2
fi

# admin uploads the private secret into MVB at COORD
UP_B=$(code PUT "/maven/$MVB/$COORD" "$TOK" "$SECRET")
echo "-- [setup] admin PUT secret into $MVB/$COORD => $UP_B (expect 201)"
DL_B=$(body GET "/maven/$MVB/$COORD" "$TOK")
echo "-- [setup] admin GET $MVB/$COORD => '$DL_B'"

echo
echo "== A. CROSS-REPO READ (alice reads MVA for a coord that exists only in MVB) =="
RC=$(code GET "/maven/$MVA/$COORD" "$ATOK")
RB=$(body GET "/maven/$MVA/$COORD" "$ATOK")
echo "   alice GET $MVA/$COORD => HTTP $RC ; body='$RB'"
if [ "$RC" = "200" ] && [ "$RB" = "$SECRET" ]; then
  fail_leak "A: alice read MVB's secret bytes via MVA (cross-tenant READ)"
elif [ "$RC" = "404" ] || [ "$RC" = "403" ]; then
  echo "   A OK: DENIED ($RC), no bytes leaked"
else
  fail_leak "A: unexpected RC=$RC body='$RB'"
fi
# control: alice has no grant on MVB, direct access must be denied too
CTL=$(code GET "/maven/$MVB/$COORD" "$ATOK")
echo "   (control) alice GET $MVB directly => $CTL (expect 403/404, no grant)"
{ [ "$CTL" = "403" ] || [ "$CTL" = "404" ]; } || fail_leak "A-control: alice reached MVB directly (RC=$CTL)"

echo
echo "== B. CROSS-REPO WRITE (alice PUTs colliding coord into her own MVA) =="
WC=$(code PUT "/maven/$MVA/$COORD" "$ATOK" "$EVIL")
echo "   alice PUT $MVA/$COORD (colliding key) => HTTP $WC"
AFTER=$(body GET "/maven/$MVB/$COORD" "$TOK")
echo "   admin GET $MVB/$COORD after alice's write => '$AFTER'"
if [ "$AFTER" != "$SECRET" ]; then
  fail_leak "B: MVB poisoned by cross-tenant WRITE (now '$AFTER')"
elif [ "$WC" = "200" ] || [ "$WC" = "201" ]; then
  # bytes survived, but the write should have been refused at the door; an
  # accepted colliding write into a foreign flat key is a latent poisoning bug.
  fail_leak "B: colliding cross-repo WRITE accepted (WC=$WC); MVB bytes intact this run but the guard did not refuse"
else
  echo "   B OK: REFUSED (WC=$WC); MVB bytes intact"
fi

echo
echo "== C. NO-REGRESSION (alice hosted upload+download to her OWN repo) =="
OC=$(code PUT "/maven/$MVA/$OWNCOORD" "$ATOK" "$OWN")
OB=$(body GET "/maven/$MVA/$OWNCOORD" "$ATOK")
echo "   alice PUT $MVA/$OWNCOORD => $OC ; GET => '$OB' (expect 201 + matching bytes)"
{ { [ "$OC" = "200" ] || [ "$OC" = "201" ]; } && [ "$OB" = "$OWN" ]; } \
  || fail_leak "C: legit same-repo upload/download regressed (OC=$OC OB='$OB')"
OC2=$(code PUT "/maven/$MVA/$OWNCOORD" "$ATOK" "${OWN}-v2")
echo "   alice same-repo overwrite PUT again => $OC2 (200/201 = mutable, 409 = release-immutability; both legit same-repo)"
# A same-repo re-PUT is legitimately either accepted (mutable policy) or refused
# 409 (release-immutability, cf. test-maven-s3.sh 'Reject release re-upload').
# What must NOT happen is a 403 (authz) or 5xx — that would be a same-repo
# regression from the cross-tenant guard over-reaching onto the owner.
{ [ "$OC2" = "200" ] || [ "$OC2" = "201" ] || [ "$OC2" = "409" ]; } \
  || fail_leak "C: legit same-repo overwrite regressed (OC2=$OC2; expected 200/201/409)"

echo
echo "== D. READ-LEG sidecars (checksum + metadata) cross-repo =="
# admin stores a checksum sidecar + a group-level metadata file into MVB (no rows)
CKSUM="B-CHECKSUM-$SUF"; META="B-PRIVATE-METADATA-$SUF"
METAPATH="com/secret/app/maven-metadata.xml"
echo "   [setup] admin PUT $MVB/$COORD.sha1 => $(code PUT "/maven/$MVB/$COORD.sha1" "$TOK" "$CKSUM" "text/plain")"
echo "   [setup] admin PUT $MVB/$METAPATH => $(code PUT "/maven/$MVB/$METAPATH" "$TOK" "$META" "text/xml")"
# D1 cross-repo checksum sidecar (maven.rs:918)
CKC=$(code GET "/maven/$MVA/$COORD.sha1" "$ATOK"); CKB=$(body GET "/maven/$MVA/$COORD.sha1" "$ATOK")
echo "   D1 alice GET $MVA/$COORD.sha1 => HTTP $CKC ; body='$CKB'"
if [ "$CKC" = "200" ] && [ "$CKB" = "$CKSUM" ]; then
  fail_leak "D1: alice read MVB's stored checksum sidecar via MVA"
else
  echo "      D1 OK: DENIED (CKC=$CKC)"
fi
# D2 cross-repo metadata (maven.rs:1368)
MTC=$(code GET "/maven/$MVA/$METAPATH" "$ATOK"); MTB=$(body GET "/maven/$MVA/$METAPATH" "$ATOK")
echo "   D2 alice GET $MVA/$METAPATH => HTTP $MTC ; body='$MTB'"
if echo "$MTB" | grep -q "$META"; then
  fail_leak "D2: alice read MVB's private metadata via MVA"
else
  echo "      D2 OK: DENIED (no B metadata leaked)"
fi
# D3 same-repo checksum still served (computed from alice's OWN row) — no regression
OWNCK=$(code GET "/maven/$MVA/$OWNCOORD.sha1" "$ATOK")
echo "   D3 alice GET own $MVA/$OWNCOORD.sha1 => HTTP $OWNCK (expect 200, computed from own row)"
[ "$OWNCK" = "200" ] || fail_leak "D3: alice's OWN checksum regressed (OWNCK=$OWNCK)"

echo
echo "== E. WRITE soft-delete carve-out =="
SDCOORD="com/victim/mod/3.0-$SUF/mod-3.0-$SUF.jar"; SDB="VICTIM-BYTES-$SUF"
echo "   [setup] admin PUT $MVB/$SDCOORD => $(code PUT "/maven/$MVB/$SDCOORD" "$TOK" "$SDB")"
# soft-delete B's row (physical object persists)
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "UPDATE artifacts SET is_deleted=true WHERE storage_key='maven/$SDCOORD';" >/dev/null
DELCNT=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM artifacts WHERE storage_key='maven/$SDCOORD' AND is_deleted=true;")
echo "   [setup] soft-deleted B rows at key: $DELCNT"
SDC=$(code PUT "/maven/$MVA/$SDCOORD" "$ATOK" "ALICE-POISON-$SUF")
echo "   E1 alice PUT colliding $MVA/$SDCOORD (B soft-deleted) => HTTP $SDC"
if [ "$SDC" = "201" ] || [ "$SDC" = "200" ]; then
  fail_leak "E: poison-on-resurrect allowed (alice PUT into soft-deleted foreign key accepted, SDC=$SDC)"
else
  echo "      E OK: REFUSED (poison-on-resurrect blocked, SDC=$SDC)"
fi

echo
echo "== F. LEGACY ROW-LESS objects (#2574/#2584 shape) =="
# The #2574/#2584 class: flat maven/{path} objects that physically exist in the
# shared bucket with NO per-file artifacts row and NO attribution row (pristine
# legacy state). We reproduce that shape deterministically: admin PUTs the
# companion files into MVB through the normal handler, then we delete BOTH the
# artifacts rows AND the maven_flat_object_owner attribution rows for those
# keys, so the physical objects survive completely row-less/unattributed.
# A correctly-fixed backend attributes such a key to NO repository and 404s it
# for every tenant; a pre-fix backend serves it to anyone.
# Unique per-run artifactId so the path version segment (1.0) matches the
# declared POM/module version — the Maven write validators 400 a path/version
# mismatch, which would silently drop these files from the fixture.
AID="applegacy$SUF"
LEG="com/legacy/$AID/1.0"
LSECRET="LEGACY-ROWLESS-SECRET-$SUF"
LEG_FILES="$AID-1.0.pom $AID-1.0.module $AID-1.0-sources.jar maven-metadata.xml $AID-1.0.jar.sha1 $AID-1.0.jar.md5"
# Companion files need format-valid content to be accepted by the write
# validators (a raw string 400s for .pom/.module/*.jar); the secret is embedded
# so a cross-repo leak is byte-detectable. Checksums/metadata accept the raw
# secret and store row-less.
plant_content(){
  case "$1" in
    *.pom)     printf '<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>com.legacy</groupId><artifactId>%s</artifactId><version>1.0</version><!--%s--></project>' "$AID" "$LSECRET" ;;
    *.module)  printf '{"formatVersion":"1.1","component":{"group":"com.legacy","module":"%s","version":"1.0"},"marker":"%s"}' "$AID" "$LSECRET" ;;
    *.jar)     printf 'PK\003\004%s' "$LSECRET" ;;
    *)         printf '%s' "$LSECRET" ;;
  esac
}
# Plant each file into MVB through the normal handler, then POSITIVELY confirm it
# is stored AND attributed-readable to its owner (admin/MVB) before we strip
# rows. This guards against a false pass where a rejected PUT leaves nothing to
# read (a 404 would then trivially look "denied").
PLANTED=0
for f in $LEG_FILES; do
  C="$(plant_content "$f")"
  pc=$(code PUT "/maven/$MVB/$LEG/$f" "$TOK" "$C")
  ab=$(body GET "/maven/$MVB/$LEG/$f" "$TOK")
  if echo "$ab" | grep -q "$LSECRET"; then
    PLANTED=$((PLANTED+1))
  else
    echo "   [warn] F: '$f' not stored/attributed-readable pre-strip (PUT=$pc) — excluded from fixture"
  fi
done
echo "   [setup] planted+verified $PLANTED/6 row-backed-or-attributed objects in MVB"
if [ "$PLANTED" -eq 0 ]; then
  fail_leak "F-setup: no legacy object could be planted+verified; fixture is not exercising the row-less class"
fi
# Strip every DB trace (artifact rows AND attribution owner rows) so the
# physical objects survive genuinely row-less/unattributed — the #2574/#2584
# pristine-legacy state.
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "DELETE FROM artifacts WHERE storage_key LIKE 'maven/$LEG/%';" >/dev/null
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "DELETE FROM maven_flat_object_owner WHERE storage_key LIKE 'maven/$LEG/%';" >/dev/null 2>&1 || true
LEFT_ART=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM artifacts WHERE storage_key LIKE 'maven/$LEG/%';" | tr -d '[:space:]')
LEFT_OWN=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM maven_flat_object_owner WHERE storage_key LIKE 'maven/$LEG/%';" 2>/dev/null | tr -d '[:space:]')
echo "   [setup] after strip: artifacts=$LEFT_ART owner_rows=${LEFT_OWN:-NA} (both must be 0 for a valid row-less fixture)"
if [ "${LEFT_ART:-1}" != "0" ]; then
  fail_leak "F-setup: could not make objects row-less (artifacts rows remain=$LEFT_ART); fixture invalid"
fi
# alice (grant on MVA only) tries to read each row-less object via MVA. On a
# fixed backend these are unattributed -> 404 for everyone. On a pre-fix backend
# the flat key leaks the owner's bytes to alice.
for f in $LEG_FILES; do
  FC=$(code GET "/maven/$MVA/$LEG/$f" "$ATOK")
  FB=$(body GET "/maven/$MVA/$LEG/$f" "$ATOK")
  if echo "$FB" | grep -q "$LSECRET"; then
    fail_leak "F: row-less legacy object '$f' leaked cross-repo (#2574/#2584 class); HTTP $FC"
  elif [ "$FC" = "403" ] || [ "$FC" = "404" ]; then
    echo "   F OK: $f DENIED (HTTP $FC)"
  elif [ "$FC" = "200" ]; then
    # 200 without the secret (e.g. dynamically-generated empty metadata from
    # alice's own rows) is acceptable — no foreign bytes served.
    echo "   F OK: $f 200 but no foreign secret (dynamic own-repo response)"
  else
    echo "   F ?: $f HTTP $FC body='$FB'"
  fi
done

echo
if [ "$FAILS" -ne 0 ]; then
  echo "############ $LABEL: $FAILS GATE FAILURE(S) — CROSS-TENANT LEAK/REGRESSION ############"
  exit 1
fi
echo "############ $LABEL: PASS (isolation holds) ############"
echo
