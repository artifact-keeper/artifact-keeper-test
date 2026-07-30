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
#   - Setup/fixture could not be established (wrong topology, login failed, a
#     precondition matched no rows): exit $EXIT_INFRA — the candidate is
#     UNJUDGED, and the tier reports INFRA/SETUP rather than a regression.
#
# STORAGE KEY SCHEME (#2624). The backend defaults to
# StorageKeyScheme::RepoScoped: a cloud-backed write lands on
# `maven/{repository_id}/{path}`, so the SAME Maven coordinate in two repos is
# two physically distinct objects and no tenant can name another's key. The
# legacy `Flat` scheme (STORAGE_KEY_SCHEME=flat|legacy) shares one
# `maven/{path}` namespace, where cross-tenant collision IS reachable and the
# ledger-first guard (`guard_flat_key_writable`) must refuse a foreign-owned
# key at the door.
#
# The invariant this gate asserts is the same under both: NO cross-tenant read,
# NO cross-tenant corruption. What differs is the mechanism, so the two
# scheme-specific WRITE checks (B, E) branch on $KEY_SCHEME. Asserting the flat
# door-refuse (403) under repo-scoped is not merely redundant, it is wrong: it
# demands a 403 on a tenant's write to her OWN repo just because another repo
# uses the same coordinate, which would be a namespace-squatting DoS and a
# cross-tenant existence oracle. Sections A/C/D/F are scheme-independent and
# run unchanged in both modes.
set -uo pipefail
BASE="$1"; DBC="$2"; LABEL="$3"

# Exit code for "the harness could not evaluate this gate" — must match
# DTF_EXIT_INFRA / harness/lib/exit_codes.sh, and is mapped straight through by
# tiers/isolation/oracle.sh (artifact-keeper-test#323).
EXIT_INFRA=11

# Which physical key layout the candidate is running. Mirrors
# backend/src/storage/keys.rs StorageKeyScheme::from_env: only "flat"/"legacy"
# select the shared namespace; anything else (including unset, the shipped
# default) is repo-scoped.
case "${STORAGE_KEY_SCHEME:-}" in
  flat|legacy) KEY_SCHEME="flat" ;;
  *)           KEY_SCHEME="repo-scoped" ;;
esac
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
# The gate could not be SET UP (fixture/topology/precondition). Not a verdict
# about the candidate — abort immediately with the INFRA code so the tier is
# reported as "harness could not evaluate", never as a regression (#323).
abort_infra(){
  echo "   !!! GATE-INFRA: $1"
  echo "   !!! (setup/fixture failure — the candidate is UNJUDGED on this gate)"
  exit "$EXIT_INFRA"
}

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
echo "-- storage key scheme: $KEY_SCHEME (STORAGE_KEY_SCHEME='${STORAGE_KEY_SCHEME:-<unset, backend default>}')"
TOK=$(login admin "$ADMPASS"); [ -z "$TOK" ] && abort_infra "admin login to $BASE failed (no access_token); the gate never ran"

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
ATOK=$(login "alice-$SUF" "$APASS"); [ -z "$ATOK" ] && abort_infra "alice-$SUF login failed (no access_token); the gate never ran"

# Fail-closed precondition: this gate is meaningless on a filesystem backend
# (each repo physically owns its key space, so the cross-tenant class cannot
# manifest). Assert both repos are on a shared object-store namespace.
SB=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT DISTINCT storage_backend FROM repositories WHERE key IN ('$MVA','$MVB');" 2>/dev/null | tr -d '[:space:]')
echo "-- backend storage_backend of repos: '$SB'"
if [ "$SB" = "filesystem" ] || [ -z "$SB" ]; then
  abort_infra "repos are on storage_backend='$SB'; this gate must run on a shared object store (s3/gcs/azure)"
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
# The invariant, in BOTH schemes: MVB's bytes must survive alice's colliding
# write. That is the corruption gate and it is unconditional.
if [ "$AFTER" != "$SECRET" ]; then
  fail_leak "B: MVB poisoned by cross-tenant WRITE (now '$AFTER')"
elif [ "$KEY_SCHEME" = "flat" ]; then
  # FLAT/LEGACY layout only: alice's write targets MVB's SHARED physical key,
  # so surviving bytes are not enough — the ledger-first guard
  # (guard_flat_key_writable) must refuse the foreign-owned key at the door, or
  # the next write wins the race and poisons MVB.
  if [ "$WC" = "200" ] || [ "$WC" = "201" ]; then
    fail_leak "B(flat): colliding cross-repo WRITE into a FOREIGN flat key accepted (WC=$WC); MVB bytes intact this run but the guard did not refuse"
  else
    echo "   B OK (flat): REFUSED at the door (WC=$WC); MVB bytes intact"
  fi
else
  # REPO-SCOPED (shipped default, #2624): alice's PUT is addressed
  # maven/{MVA_id}/$COORD and MVB's object is maven/{MVB_id}/$COORD, so a 201
  # is a correct write to her OWN repo and there is no foreign key to refuse.
  # Demanding a 403 here would forbid two tenants from ever sharing a Maven
  # coordinate (squatting DoS + existence oracle), so the door-refuse check is
  # deliberately NOT applied. Instead assert the property that actually makes
  # the collision harmless: the two writes resolved to DISTINCT physical keys.
  echo "   B OK (repo-scoped): MVB bytes intact after alice's own-repo write (WC=$WC)"
  KEY_A=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id
      WHERE r.key='$MVA' AND a.storage_key LIKE '%$COORD' LIMIT 1;" 2>/dev/null | tr -d '[:space:]')
  KEY_B=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id
      WHERE r.key='$MVB' AND a.storage_key LIKE '%$COORD' LIMIT 1;" 2>/dev/null | tr -d '[:space:]')
  echo "   B keys: MVA='$KEY_A'  MVB='$KEY_B'"
  if [ -z "$KEY_A" ] || [ -z "$KEY_B" ]; then
    abort_infra "B: could not read back both repos' storage_key rows for $COORD (MVA='$KEY_A' MVB='$KEY_B'); the key-separation assertion has no fixture"
  elif [ "$KEY_A" = "$KEY_B" ]; then
    fail_leak "B: the same coordinate resolved to the SAME physical key in two repos ('$KEY_A') under the repo-scoped scheme — #2624 key separation is broken"
  else
    echo "   B OK: colliding coordinate resolved to two DISTINCT physical keys (no shared object to poison)"
  fi
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
echo "== E. WRITE soft-delete carve-out (poison-on-resurrect) =="
# The class: B soft-deletes an artifact (row hidden, PHYSICAL object persists).
# If a foreign tenant can then write "into" that carved-out state, restoring
# B's row resurrects the ATTACKER's bytes under B's name.
SDCOORD="com/victim/mod/3.0-$SUF/mod-3.0-$SUF.jar"; SDB="VICTIM-BYTES-$SUF"
SDPOISON="ALICE-POISON-$SUF"
echo "   [setup] admin PUT $MVB/$SDCOORD => $(code PUT "/maven/$MVB/$SDCOORD" "$TOK" "$SDB")"
# Soft-delete B's row by its ACTUAL stored key. The old hard-coded flat literal
# ('maven/$SDCOORD') matches ZERO rows under the repo-scoped default, so the
# carve-out state never materialised and E asserted against a fixture that did
# not exist. Look the key up instead, and hard-require the UPDATE to bite.
SDKEY=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id
    WHERE r.key='$MVB' AND a.storage_key LIKE '%$SDCOORD' LIMIT 1;" 2>/dev/null | tr -d '[:space:]')
echo "   [setup] MVB's actual stored key for the victim coord: '$SDKEY'"
[ -z "$SDKEY" ] && abort_infra "E: MVB has no artifacts row for $SDCOORD; the soft-delete fixture cannot be built"
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "UPDATE artifacts SET is_deleted=true WHERE storage_key='$SDKEY';" >/dev/null
DELCNT=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM artifacts WHERE storage_key='$SDKEY' AND is_deleted=true;" 2>/dev/null | tr -d '[:space:]')
echo "   [setup] soft-deleted B rows at key: $DELCNT"
# PRECONDITION, not an assertion about the candidate: with 0 soft-deleted rows
# there is no carve-out to attack and everything below is vacuous.
[ "${DELCNT:-0}" -gt 0 ] || abort_infra "E: soft-delete matched 0 rows at '$SDKEY'; the carve-out state never existed, so E would assert nothing"

SDC=$(code PUT "/maven/$MVA/$SDCOORD" "$ATOK" "$SDPOISON")
echo "   E1 alice PUT colliding $MVA/$SDCOORD (B soft-deleted) => HTTP $SDC"
if [ "$KEY_SCHEME" = "flat" ]; then
  # FLAT: alice's write lands on B's own carved-out key — it must be refused.
  if [ "$SDC" = "201" ] || [ "$SDC" = "200" ]; then
    fail_leak "E(flat): poison-on-resurrect allowed (alice PUT into soft-deleted FOREIGN flat key accepted, SDC=$SDC)"
  else
    echo "      E OK (flat): REFUSED at the door (poison-on-resurrect blocked, SDC=$SDC)"
  fi
else
  echo "      E note (repo-scoped): alice's PUT addresses her own maven/{MVA_id}/... key, so 2xx is correct here"
fi
# E2 — the outcome that matters in BOTH schemes: restore B's row and confirm
# the resurrected artifact still serves B's ORIGINAL bytes, not alice's poison.
# This is the actual "poison-on-resurrect" property; it is asserted regardless
# of key scheme, so E stays load-bearing on the shipped default.
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "UPDATE artifacts SET is_deleted=false WHERE storage_key='$SDKEY';" >/dev/null
SDAFTER=$(body GET "/maven/$MVB/$SDCOORD" "$TOK")
echo "   E2 admin GET $MVB/$SDCOORD after restoring the row => '$SDAFTER'"
if [ "$SDAFTER" = "$SDPOISON" ]; then
  fail_leak "E: POISON-ON-RESURRECT — restoring B's soft-deleted row served alice's bytes ('$SDAFTER')"
elif [ "$SDAFTER" = "$SDB" ]; then
  echo "      E OK: resurrected artifact still serves B's ORIGINAL bytes (no poison)"
else
  fail_leak "E: resurrected artifact served neither B's original bytes nor a clean denial (got '$SDAFTER')"
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
