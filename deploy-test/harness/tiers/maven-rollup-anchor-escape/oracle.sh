#!/usr/bin/env bash
# =============================================================================
# tiers/maven-rollup-anchor-escape/oracle.sh — the Maven rollup anchor guard's
#                       missing LIKE ESCAPE (artifact-keeper#3492 / #3493)
# =============================================================================
# run.sh has stood up the `storage.s3 gc.maven-flat` profile-set with
# STORAGE_KEY_SCHEME=flat and RATE_LIMIT_ENABLED=false, and exported BASE_URL,
# DB_CONTAINER, DTF_SLOT, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR and COMMON_SH. We source common.sh for the assertion +
# JUnit harness and drive the real HTTP flow against the backend.
#
# THE BUG. The two guards that decide whether a `maven-metadata.xml` rollup is
# still anchored build a directory-prefix `LIKE` pattern out of a stored key
# and carried no `ESCAPE` clause. A literal backslash in the key is then read
# as Postgres's default LIKE escape character, the pattern stops describing
# the directory it came from, the `NOT EXISTS` guard reports "nothing anchors
# this", and a document that is still being served is deleted.
#
# WHY BYTES AND NOT STATUS CODES. The Maven read path synthesises a substitute
# `maven-metadata.xml` when the stored one is missing, so `GET` still answers
# 200 after the loss. Every boundary gate here compares the sha256 of what is
# served (and of what is physically in the object store) against the sha256 of
# the document the fixture published.
#
# TWO CALL SITES. Section A drives the opt-in GC sweep
# (`POST /api/v1/admin/storage-gc`); section B drives the UNGATED
# repository-delete purge, in its cross-repository shape. See the manifest.
#
# THE COLLAPSED-SIBLING TRAP (this tier was written green once, by accident).
# When the un-escaped pattern eats the backslash, `com/cr\oss/lib/` becomes the
# pattern `com/cross/lib/`. So a fixture is only a witness if NOTHING lives
# under its COLLAPSED spelling: if some other repository happens to hold an
# artifact at `com/cross/lib/1.0/...`, the broken guard finds that foreign
# artifact, believes the rollup is anchored, and spares it -- on the vulnerable
# image, for entirely the wrong reason. The first draft of this oracle named
# its plain-ASCII control `cross` next to a boundary fixture called `cr\oss`
# and the whole repository-delete section passed on the pre-fix parent.
# Every plain control here is therefore named so that it is NOT the collapsed
# form of any backslash fixture (`back`, `dead`, `cross`, `self`, `purge` are
# all deliberately empty), and `assert_collapsed_siblings_empty` re-checks that
# invariant at runtime rather than trusting the names to stay disjoint.
#
# --path-as-is on EVERY curl: `%5C` must reach the backend unmolested.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
NET="ak-dtf${SLOT}-net"
BUCKET="ak-artifacts"

# Repositories. Suffixed per slot+run so nothing in the slot can collide.
SWEEP_REPO="mesc-sweep-${SLOT}-${SUF}"     # section A: sweep fixtures
DOOMED_REPO="mesc-doomed-${SLOT}-${SUF}"   # section B: the repository deleted
KEEPER_REPO="mesc-keeper-${SLOT}-${SUF}"   # section B: owns the anchoring JARs

# Key roots. Under STORAGE_KEY_SCHEME=flat every Maven object lands at
# `maven/{request path}`, with no repository segment — which is exactly what
# lets DOOMED_REPO own a rollup whose subtree KEEPER_REPO populates.
ROOT_A="dtfesc/${SLOT}-${SUF}/sweep"
ROOT_B="dtfesc/${SLOT}-${SUF}/purge"

WORK="$(mktemp -d -t dtf-mesc-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CURL_RAW="--path-as-is"

code_put() { # LOCAL_FILE REPO REQUEST_PATH
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW \
    -X PUT "${BASE_URL}/maven/${2}/${3}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "@${1}" 2>/dev/null || echo 000
}
get_to_file() { # REPO REQUEST_PATH OUTFILE -> prints the http code
  curl -s -o "${3}" -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW \
    "${BASE_URL}/maven/${1}/${2}" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    2>/dev/null || echo 000
}
# NOTE on error handling: common.sh runs under `set -euo pipefail`, so every
# probe below must swallow its own failure explicitly. An unguarded pipeline
# whose first stage 404s would kill the oracle mid-suite and report as an
# exit-code failure with no JUnit case, instead of as the assertion it is.
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }

# --- fixture builder --------------------------------------------------------
# A rollup document with markers the synthesised substitute cannot reproduce:
# a fixed historical `lastUpdated`, a `<version>` the repository does not hold,
# and a plugin `<prefix>` block. If the stored document is deleted and the read
# path answers with its own reconstruction, none of these survive — which is
# why the gates compare bytes and not status codes.
make_rollup() { # GROUP_ID OUTFILE
  cat > "$2" <<EOT
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>${1}</groupId>
  <artifactId>lib</artifactId>
  <versioning>
    <latest>1.0</latest>
    <release>1.0</release>
    <versions>
      <version>1.0</version>
      <version>0.9-published-only-in-this-document</version>
    </versions>
    <lastUpdated>20200101000000</lastUpdated>
  </versioning>
  <plugins>
    <plugin>
      <name>dtf marker ${SUF}</name>
      <prefix>dtf</prefix>
      <artifactId>lib</artifactId>
    </plugin>
  </plugins>
</metadata>
EOT
}

# --- observers --------------------------------------------------------------
attr_rows() { # KEY_SQL_LITERAL -> number of maven_flat_object_owner rows
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM maven_flat_object_owner WHERE storage_key = '${1}';" \
    2>/dev/null | tr -d '[:space:]' || echo "?"
}
# The object store is the ground truth for "were the bytes destroyed". mc
# percent-decodes its path argument, so the SAME `%5C` spelling the request
# path uses addresses the object whose stored key holds a literal backslash.
mc_sh() { # SHELL_SNIPPET
  docker run --rm --network "$NET" --entrypoint sh minio/mc:latest -c \
    "mc alias set l http://minio:9000 minioadmin minioadmin >/dev/null 2>&1; ${1}" 2>/dev/null || true
}
mc_exists() { # ENCODED_KEY -> prints yes|no
  # The verdict travels on STDOUT, not on `mc_sh`'s exit status: `mc_sh`
  # swallows its own failure (see the note above) so a missing object would
  # otherwise read as "present" and every deletion gate would pass vacuously.
  local out
  out="$(mc_sh "if mc stat 'l/${BUCKET}/${1}' >/dev/null 2>&1; then echo yes; else echo no; fi")"
  case "$out" in *yes*) echo yes ;; *no*) echo no ;; *) echo "unknown(${out})" ;; esac
}
mc_sha() { # ENCODED_KEY -> sha256 of the stored object (of nothing, if absent)
  { mc_sh "mc cat 'l/${BUCKET}/${1}'" | sha256sum | cut -d' ' -f1; } || true
}

begin_suite "maven-rollup-anchor-escape"

# ===========================================================================
# SETUP
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

mk_repo() { # KEY
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW \
    -X POST "${BASE_URL}/api/v1/repositories" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}" \
    2>/dev/null || echo 000
}
REPO_FAILS=""
for r in "$SWEEP_REPO" "$DOOMED_REPO" "$KEEPER_REPO"; do
  c="$(mk_repo "$r")"
  case "$c" in 200|201) ;; *) REPO_FAILS="${REPO_FAILS} ${r}=${c}" ;; esac
done
if [ -n "$REPO_FAILS" ]; then
  begin_test "setup: create the three Maven repositories"
  infra_fail "repository create failed:${REPO_FAILS}"
  end_suite
fi

# The backend must actually be on a cloud backend with the flat key layout, or
# `maven_flat_object_owner` is empty and every gate below is vacuous. Assert
# the precondition instead of discovering it as a mystery pass.
printf 'DTF-JAR-%s\n' "$SUF" > "${WORK}/lib.jar"
printf 'dtf-sidecar-%s\n' "$SUF" > "${WORK}/side.sha1"

PUT_FAILS=""
put() { # LOCAL REPO PATH
  c="$(code_put "$1" "$2" "$3")"
  case "$c" in 200|201) ;; *) PUT_FAILS="${PUT_FAILS} ${2}:${3}=${c}" ;; esac
}

# --- section A fixtures: the GC sweep --------------------------------------
# A1 (BOUNDARY): live JAR + its rollup + the rollup's `.sha1`, under a
#     directory whose name contains a literal backslash.
make_rollup 'com.ba\ck' "${WORK}/a1.xml"
put "${WORK}/lib.jar" "$SWEEP_REPO" "${ROOT_A}/com/ba%5Cck/lib/1.0/lib-1.0.jar"
put "${WORK}/a1.xml"  "$SWEEP_REPO" "${ROOT_A}/com/ba%5Cck/lib/maven-metadata.xml"
put "${WORK}/side.sha1" "$SWEEP_REPO" "${ROOT_A}/com/ba%5Cck/lib/maven-metadata.xml.sha1"
# A2 (CONTROL): the identically shaped fixture with a plain ASCII directory.
#     Spared on both images — it is the "did we break the normal case" half.
make_rollup 'com.plain' "${WORK}/a2.xml"
put "${WORK}/lib.jar" "$SWEEP_REPO" "${ROOT_A}/com/plain/lib/1.0/lib-1.0.jar"
put "${WORK}/a2.xml"  "$SWEEP_REPO" "${ROOT_A}/com/plain/lib/maven-metadata.xml"
# A3 (CONTROL): a genuinely orphaned rollup whose directory ALSO contains a
#     backslash. Nothing anywhere sits under it, so it is garbage under either
#     escape mode and MUST still be reclaimed. This is the fixture that stops
#     "spare everything containing a backslash" from passing this tier.
make_rollup 'com.de\ad' "${WORK}/a3.xml"
put "${WORK}/a3.xml" "$SWEEP_REPO" "${ROOT_A}/com/de%5Cad/lib/maven-metadata.xml"
# A4 (CONTROL): the plain-ASCII orphan twin of A3. Named `gone` and not
#     `dead`, because `dead` is the string `de\ad` COLLAPSES TO when the
#     backslash is eaten as an escape — see the collapsed-sibling note above.
make_rollup 'com.gone' "${WORK}/a4.xml"
put "${WORK}/a4.xml" "$SWEEP_REPO" "${ROOT_A}/com/gone/lib/maven-metadata.xml"
# A5 (CONTROL): an orphan the OPERATOR wrote (#3431 source allowlist). Its
#     attribution row is re-labelled `operator_repair` below; such a row is not
#     a re-derivable cache, so no anchor argument makes it garbage and the
#     sweep must leave it alone even though it is unreferenced.
make_rollup 'com.re\pair' "${WORK}/a5.xml"
put "${WORK}/a5.xml" "$SWEEP_REPO" "${ROOT_A}/com/re%5Cpair/lib/maven-metadata.xml"

if [ -n "$PUT_FAILS" ]; then
  begin_test "setup: publish the GC-sweep fixtures"
  infra_fail "Maven upload failed:${PUT_FAILS}"
  end_suite
fi

# Literal (decoded) storage keys, as they are stored in the DB and in MinIO.
A1_MD="maven/${ROOT_A}/com/ba\\ck/lib/maven-metadata.xml"
A1_SHA1="${A1_MD}.sha1"
A1_JAR="maven/${ROOT_A}/com/ba\\ck/lib/1.0/lib-1.0.jar"
A2_MD="maven/${ROOT_A}/com/plain/lib/maven-metadata.xml"
A3_MD="maven/${ROOT_A}/com/de\\ad/lib/maven-metadata.xml"
A4_MD="maven/${ROOT_A}/com/gone/lib/maven-metadata.xml"
A5_MD="maven/${ROOT_A}/com/re\\pair/lib/maven-metadata.xml"
# The same keys in the `%5C` spelling both curl and mc accept.
A1_MD_ENC="maven/${ROOT_A}/com/ba%5Cck/lib/maven-metadata.xml"

# The attribution table is the whole subject of this tier. If it is empty the
# stack is not on a cloud backend and nothing below can discriminate.
OWNED="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM maven_flat_object_owner WHERE storage_key LIKE 'maven/${ROOT_A}/%';" \
  2>/dev/null | tr -d '[:space:]' || echo 0)"
if ! [[ "$OWNED" =~ ^[0-9]+$ ]] || [ "$OWNED" -lt 6 ]; then
  begin_test "setup: the row-less Maven objects were attributed (cloud backend + flat keys)"
  infra_fail "expected >=6 maven_flat_object_owner rows under 'maven/${ROOT_A}/', saw '${OWNED}'. \
On a filesystem backend this table is empty and this tier cannot discriminate — the profile-set must be storage.s3." \
    "$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -c \
       "SELECT storage_key, source FROM maven_flat_object_owner ORDER BY storage_key;" 2>&1 | head -30)"
  end_suite
fi

# Re-label A5's row as operator-written and age every row past the sweep's
# one-hour floor for in-flight publishes (the sweep would otherwise find no
# candidates at all and pass vacuously).
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "UPDATE maven_flat_object_owner SET source = 'operator_repair' WHERE storage_key = '${A5_MD}';" \
  >/dev/null 2>&1
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "UPDATE maven_flat_object_owner SET created_at = NOW() - INTERVAL '3 hours';" >/dev/null 2>&1
A5_SOURCE="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT source FROM maven_flat_object_owner WHERE storage_key = '${A5_MD}';" 2>/dev/null | tr -d '[:space:]' || echo '?')"
AGED="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM maven_flat_object_owner WHERE created_at < NOW() - INTERVAL '1 hour';" \
  2>/dev/null | tr -d '[:space:]' || echo 0)"
if [ "$A5_SOURCE" != "operator_repair" ] || [ "${AGED:-0}" -lt 6 ]; then
  begin_test "setup: label the operator-repair row and age the fixtures past the sweep's floor"
  infra_fail "A5 source='${A5_SOURCE}' (want operator_repair), aged rows=${AGED} (want >=6)"
  end_suite
fi

# The byte-identity gates are only meaningful if the read path serves the
# PUBLISHED document verbatim to begin with. Establish that before the sweep.
A1_WANT="$(sha_of "${WORK}/a1.xml")"
A2_WANT="$(sha_of "${WORK}/a2.xml")"
PRE="${WORK}/pre.xml"
PRE_CODE="$(get_to_file "$SWEEP_REPO" "${ROOT_A}/com/ba%5Cck/lib/maven-metadata.xml" "$PRE")"
PRE_SHA="$(sha_of "$PRE")"
if [ "$PRE_CODE" != "200" ] || [ "$PRE_SHA" != "$A1_WANT" ]; then
  begin_test "setup: the published rollup is served back verbatim before any GC"
  infra_fail "GET of the freshly published rollup returned ${PRE_CODE} with sha256 ${PRE_SHA}, expected 200 and ${A1_WANT}; \
without this the byte-identity gates below would prove nothing" "$(head -c 400 "$PRE" 2>/dev/null)"
  end_suite
fi

# Runtime re-check of the collapsed-sibling invariant (see the header). Each
# backslash fixture is a witness only while its collapsed spelling is empty;
# an object there would anchor the rollup even on the vulnerable image and the
# gate would pass for the wrong reason. Called once per section, after that
# section's fixtures are published and before its delete decision runs.
assert_collapsed_siblings_empty() { # SECTION_LABEL DIR...
  local label="$1"; shift
  local d n bad=""
  for d in "$@"; do
    n="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
          "SELECT count(*) FROM artifacts WHERE storage_key LIKE 'maven/${d}%' AND is_deleted = false;" \
          2>/dev/null | tr -d '[:space:]' || echo 0)"
    [ "${n:-0}" = "0" ] || bad="${bad} maven/${d}=${n}"
  done
  [ -z "$bad" ] && return 0
  begin_test "setup (${label}): the collapsed spelling of every backslash fixture is empty"
  infra_fail "a live artifact sits under the COLLAPSED form of a backslash fixture's directory:${bad}. \
The un-escaped pattern derived from 'com/ba\\ck/' is 'com/back/', so such an artifact anchors the rollup even on the \
vulnerable image and every boundary gate in this section would pass for the wrong reason."
  end_suite
}
assert_collapsed_siblings_empty "section A" \
  "${ROOT_A}/com/back/" "${ROOT_A}/com/dead/" "${ROOT_A}/com/repair/"

# ===========================================================================
# SECTION A — the storage-GC sweep (guard 3), MAVEN_FLAT_GC_ENABLED=true
# ===========================================================================
GC_OUT="${WORK}/gc.json"
GC_CODE="$(curl -s -o "$GC_OUT" -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW \
  -X POST "${BASE_URL}/api/v1/admin/storage-gc" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d '{"dry_run":false}' 2>/dev/null || echo 000)"
GC_DELETED="$(jq -r '.storage_keys_deleted // "?"' "$GC_OUT" 2>/dev/null || echo '?')"
GC_GATED="$(jq -r '.maven_flat_objects_gated // "?"' "$GC_OUT" 2>/dev/null || echo '?')"
if [ "$GC_CODE" != "200" ]; then
  begin_test "setup: run the storage GC sweep"
  infra_fail "POST /api/v1/admin/storage-gc returned ${GC_CODE}" "$(head -c 400 "$GC_OUT" 2>/dev/null)"
  end_suite
fi
if [ "$GC_GATED" != "0" ]; then
  begin_test "setup: the Maven flat-object sweep is opted in (MAVEN_FLAT_GC_ENABLED)"
  infra_fail "the sweep reported maven_flat_objects_gated=${GC_GATED}: it identified orphans but deleted nothing, \
so its delete decision was never exercised. The gc.maven-flat profile overlay must be in PROFILES." \
    "$(cat "$GC_OUT" 2>/dev/null)"
  end_suite
fi

begin_test "A/CONTROL: the two genuinely orphaned rollups were RECLAIMED in this pass, backslash directory and plain alike"
A3_ROWS="$(attr_rows "$A3_MD")"; A4_ROWS="$(attr_rows "$A4_MD")"
if [ "$A3_ROWS" = "0" ] && [ "$A4_ROWS" = "0" ]; then pass; else
  fail "the sweep left a genuinely unreferenced rollup behind: 'com/de\\ad/lib' rows=${A3_ROWS}, 'com/gone/lib' rows=${A4_ROWS} (both must be 0). \
This control is what stops a fix that simply spares every key containing a backslash from passing this tier." \
    "gc=$(cat "$GC_OUT" 2>/dev/null)"
fi

begin_test "A/BOUNDARY: the rollup of a LIVE subtree whose directory contains a backslash is SPARED (row + object + bytes)"
A1_ROWS="$(attr_rows "$A1_MD")"
A1_OBJ="$(mc_exists "$A1_MD_ENC")"
GOT="${WORK}/a1-after.xml"
A1_CODE="$(get_to_file "$SWEEP_REPO" "${ROOT_A}/com/ba%5Cck/lib/maven-metadata.xml" "$GOT")"
A1_GOT_SHA="$(sha_of "$GOT")"
if [ "$A1_ROWS" = "1" ] && [ "$A1_OBJ" = "yes" ] && [ "$A1_CODE" = "200" ] && [ "$A1_GOT_SHA" = "$A1_WANT" ]; then
  pass
else
  fail "MAVEN ROLLUP DATA LOSS (#3492): the storage GC deleted '${A1_MD}' while its JAR '${A1_JAR}' was still live. \
attribution rows=${A1_ROWS} (want 1), object in the store=${A1_OBJ} (want yes), GET=${A1_CODE}, served sha256=${A1_GOT_SHA} (want ${A1_WANT}). \
The guard derives its directory-prefix LIKE pattern from the stored key and, without ESCAPE '', reads the literal backslash as \
Postgres's escape character, so the pattern names 'com/back/lib/' and the live artifact under 'com/ba\\ck/lib/' no longer matches. \
Note the 200: the Maven read path SYNTHESISES a substitute document, so the loss is silent and the client's published \
lastUpdated / version list / plugin prefixes are permanently gone." \
    "gc=$(cat "$GC_OUT" 2>/dev/null)
served: $(head -c 500 "$GOT" 2>/dev/null)"
fi

begin_test "A/BOUNDARY: the spared rollup's .sha1 sidecar survived with it (a rollup and its sidecars stand or fall together)"
A1_SHA1_ROWS="$(attr_rows "$A1_SHA1")"
if [ "$A1_SHA1_ROWS" = "1" ]; then pass; else
  fail "the '.sha1' companion of a spared rollup was reclaimed (attribution rows=${A1_SHA1_ROWS}, want 1): the sweep resolves a \
sidecar's fate through the same rollup anchor as its base, so the under-matching prefix takes the sidecar with the document." \
    "key=${A1_SHA1}"
fi

begin_test "A/CONTROL: the same fixture with a plain-ASCII directory is spared and served byte-identical (the normal case did not regress)"
A2_ROWS="$(attr_rows "$A2_MD")"
GOT2="${WORK}/a2-after.xml"
A2_CODE="$(get_to_file "$SWEEP_REPO" "${ROOT_A}/com/plain/lib/maven-metadata.xml" "$GOT2")"
A2_GOT_SHA="$(sha_of "$GOT2")"
if [ "$A2_ROWS" = "1" ] && [ "$A2_CODE" = "200" ] && [ "$A2_GOT_SHA" = "$A2_WANT" ]; then pass; else
  fail "an anchored rollup under a plain directory was not served back intact: rows=${A2_ROWS} (want 1), GET=${A2_CODE}, \
sha256=${A2_GOT_SHA} (want ${A2_WANT}). This control must hold on BOTH images." "gc=$(cat "$GC_OUT" 2>/dev/null)"
fi

begin_test "A/CONTROL: an operator_repair attribution row is preserved even though nothing anchors it (#3431 source allowlist)"
A5_ROWS="$(attr_rows "$A5_MD")"
if [ "$A5_ROWS" = "1" ]; then pass; else
  fail "the sweep reclaimed an 'operator_repair' row (rows=${A5_ROWS}, want 1). Only rows the SYSTEM wrote are re-derivable \
caches the GC may reclaim; an operator-inserted row is the documented repair for keys the catalog-only backfill cannot see, \
and for such an object every anchor arm is true by construction and permanently." "key=${A5_MD}"
fi

begin_test "A/BOUNDARY: the pass reclaimed EXACTLY the two orphans and nothing else (storage_keys_deleted == 2)"
if [ "$GC_DELETED" = "2" ]; then pass; else
  fail "the sweep reported storage_keys_deleted=${GC_DELETED}, expected exactly 2 (the two unreferenced rollups). \
A higher count means it also reclaimed a document that is still anchored — on the pre-fix image the backslash rollup is \
counted here as a third." "gc=$(cat "$GC_OUT" 2>/dev/null)"
fi

# ===========================================================================
# SECTION B — the repository-delete purge collector. NOT gated by
# MAVEN_FLAT_GC_ENABLED: it runs on every repository delete on a cloud
# backend. Cross-repository shape: the DOOMED repository owns the attribution
# row, the KEEPER repository owns the artifact that anchors it.
# ===========================================================================
PUT_FAILS=""
# B1 (BOUNDARY): keeper's live JAR anchors doomed's rollup, backslash directory.
make_rollup 'com.cr\oss' "${WORK}/b1.xml"
put "${WORK}/lib.jar"   "$KEEPER_REPO" "${ROOT_B}/com/cr%5Coss/lib/1.0/lib-1.0.jar"
put "${WORK}/b1.xml"    "$DOOMED_REPO" "${ROOT_B}/com/cr%5Coss/lib/maven-metadata.xml"
put "${WORK}/side.sha1" "$DOOMED_REPO" "${ROOT_B}/com/cr%5Coss/lib/maven-metadata.xml.sha1"
# B2 (CONTROL): the same cross-repository shape with a plain directory.
#     Named `sibling` and NOT `cross`: `cross` is what `cr\oss` collapses to,
#     so a control there would silently anchor B1 on the vulnerable image and
#     turn this whole section green — see the collapsed-sibling note above.
make_rollup 'com.sibling' "${WORK}/b2.xml"
put "${WORK}/lib.jar" "$KEEPER_REPO" "${ROOT_B}/com/sibling/lib/1.0/lib-1.0.jar"
put "${WORK}/b2.xml"  "$DOOMED_REPO" "${ROOT_B}/com/sibling/lib/maven-metadata.xml"
# B3 (CONTROL): the doomed repository's OWN artifact under a backslash
#     directory must NOT anchor its own rollup (`mb.repository_id <> $1`), or
#     the object leaks forever after the repository is gone.
make_rollup 'com.sel\f' "${WORK}/b3.xml"
put "${WORK}/lib.jar" "$DOOMED_REPO" "${ROOT_B}/com/sel%5Cf/lib/1.0/lib-1.0.jar"
put "${WORK}/b3.xml"  "$DOOMED_REPO" "${ROOT_B}/com/sel%5Cf/lib/maven-metadata.xml"
# B4 (CONTROL): a plain unreferenced backslash rollup must still be purged.
make_rollup 'com.pu\rge' "${WORK}/b4.xml"
put "${WORK}/b4.xml" "$DOOMED_REPO" "${ROOT_B}/com/pu%5Crge/lib/maven-metadata.xml"

if [ -n "$PUT_FAILS" ]; then
  begin_test "setup: publish the repository-delete purge fixtures"
  infra_fail "Maven upload failed:${PUT_FAILS}"
  end_suite
fi

B1_MD_ENC="maven/${ROOT_B}/com/cr%5Coss/lib/maven-metadata.xml"
B1_SHA1_ENC="${B1_MD_ENC}.sha1"
B1_JAR_ENC="maven/${ROOT_B}/com/cr%5Coss/lib/1.0/lib-1.0.jar"
B2_MD_ENC="maven/${ROOT_B}/com/sibling/lib/maven-metadata.xml"
B3_MD_ENC="maven/${ROOT_B}/com/sel%5Cf/lib/maven-metadata.xml"
B4_MD_ENC="maven/${ROOT_B}/com/pu%5Crge/lib/maven-metadata.xml"
B1_WANT="$(sha_of "${WORK}/b1.xml")"
B2_WANT="$(sha_of "${WORK}/b2.xml")"

# Precondition: everything is on the store before the delete, or "gone after"
# proves nothing.
B_PRE_MISSING=""
for k in "$B1_MD_ENC" "$B1_SHA1_ENC" "$B1_JAR_ENC" "$B2_MD_ENC" "$B3_MD_ENC" "$B4_MD_ENC"; do
  [ "$(mc_exists "$k")" = "yes" ] || B_PRE_MISSING="${B_PRE_MISSING} ${k}"
done
if [ -n "$B_PRE_MISSING" ]; then
  begin_test "setup: the purge fixtures are on the object store before the repository delete"
  infra_fail "missing from ${BUCKET} before the delete:${B_PRE_MISSING}"
  end_suite
fi

assert_collapsed_siblings_empty "section B" \
  "${ROOT_B}/com/cross/" "${ROOT_B}/com/self/" "${ROOT_B}/com/purge/"

DEL_OUT="${WORK}/del.json"
DEL_CODE="$(curl -s -o "$DEL_OUT" -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW \
  -X DELETE "${BASE_URL}/api/v1/repositories/${DOOMED_REPO}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000)"
if [ "$DEL_CODE" != "200" ] && [ "$DEL_CODE" != "204" ]; then
  begin_test "setup: delete the doomed repository"
  infra_fail "DELETE /api/v1/repositories/${DOOMED_REPO} returned ${DEL_CODE}" "$(head -c 400 "$DEL_OUT" 2>/dev/null)"
  end_suite
fi

begin_test "B/CONTROL: the delete purged the doomed repository's own unanchored rollups (the <> \$1 scoping still holds)"
B3_OBJ="$(mc_exists "$B3_MD_ENC")"; B4_OBJ="$(mc_exists "$B4_MD_ENC")"
if [ "$B3_OBJ" = "no" ] && [ "$B4_OBJ" = "no" ]; then pass; else
  fail "deleting the repository left its own row-less Maven objects behind: 'com/sel\\f/lib/maven-metadata.xml' present=${B3_OBJ}, \
'com/pu\\rge/lib/maven-metadata.xml' present=${B4_OBJ} (both must be gone). The doomed repository's OWN artifact must not anchor \
its own rollup, or every such object leaks forever once the repository row is gone — and a fix that spares anything containing a \
backslash fails here." "repo=${DOOMED_REPO}"
fi

begin_test "B/BOUNDARY: deleting one repository did NOT purge the rollup another repository is still anchoring, backslash directory (bytes identical)"
B1_OBJ="$(mc_exists "$B1_MD_ENC")"
B1_SHA1_OBJ="$(mc_exists "$B1_SHA1_ENC")"
B1_GOT="$(mc_sha "$B1_MD_ENC")"
if [ "$B1_OBJ" = "yes" ] && [ "$B1_SHA1_OBJ" = "yes" ] && [ "$B1_GOT" = "$B1_WANT" ]; then pass; else
  fail "CROSS-REPOSITORY MAVEN ROLLUP DATA LOSS (#3492): deleting '${DOOMED_REPO}' destroyed the rollup at \
'${B1_MD_ENC}' (present=${B1_OBJ}, sidecar present=${B1_SHA1_OBJ}, sha256=${B1_GOT}, want ${B1_WANT}) while '${KEEPER_REPO}' \
still holds the live JAR at '${B1_JAR_ENC}' under that very directory. This collector runs on EVERY repository delete and \
carries no opt-in gate; the only difference from the surviving control below is the literal backslash in the directory name, \
which the un-escaped LIKE pattern consumes." \
    "delete response: $(head -c 300 "$DEL_OUT" 2>/dev/null)"
fi

begin_test "B/CONTROL: the same cross-repository shape with a plain directory survived the delete, byte-identical (both images)"
B2_OBJ="$(mc_exists "$B2_MD_ENC")"
B2_GOT="$(mc_sha "$B2_MD_ENC")"
if [ "$B2_OBJ" = "yes" ] && [ "$B2_GOT" = "$B2_WANT" ]; then pass; else
  fail "deleting '${DOOMED_REPO}' destroyed a rollup under a PLAIN directory that '${KEEPER_REPO}' still anchors \
(present=${B2_OBJ}, sha256=${B2_GOT}, want ${B2_WANT}). That is the base cross-repository guarantee and must hold on both images." \
    "key=${B2_MD_ENC}"
fi

begin_test "B/CONTROL: the surviving repository's own live artifact was untouched by the delete"
B1_JAR_OBJ="$(mc_exists "$B1_JAR_ENC")"
if [ "$B1_JAR_OBJ" = "yes" ]; then pass; else
  fail "deleting '${DOOMED_REPO}' removed '${KEEPER_REPO}'s live JAR at '${B1_JAR_ENC}'. The purge is scoped to the doomed \
repository's own attribution rows and must never reach another repository's artifacts." "repo=${KEEPER_REPO}"
fi

end_suite
