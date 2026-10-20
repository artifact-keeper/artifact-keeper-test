#!/usr/bin/env bash
# =============================================================================
# tiers/format-catalog-fixes/oracle.sh — conan repo-scoped cloud keys (#4694),
#   Maven version size = total of its files (#4633), RubyGems hyphen-digit
#   gem names in the specs index (#4645), npm repo-scoped cloud keys (#4293)
# =============================================================================
# run.sh has stood up the `storage.s3` profile-set (MinIO, bucket
# `ak-artifacts`) with RATE_LIMIT_ENABLED=false and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, COMMON_SH,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR. Everything is driven over the native
# format protocols with raw HTTP; MinIO is read and written through a transient
# `mc` container joined to the minio container's network namespace (the
# storage-integrity-s3 pattern); the catalog is read through the packages API
# and cross-checked in Postgres.
#
# Gates (see the manifest for the bug write-ups):
#   CONAN    CONTROL  one-repo recipe + package publish and download (both).
#            FIX      the SAME revision publishes into a second repo (2xx, not
#                     409); both repos serve it; MinIO holds it under two
#                     `conan/{repo_id}/...` keys and no flat `conan/{name}/...`.
#            LEGACY   a row whose storage_key is the legacy flat key still
#                     downloads (both); a re-upload moves it to the scoped key
#                     (fix only).
#   MAVEN    CONTROL  a single-file version's size is that file's size (both).
#            FIX      jar + pom + sources (+ a row-less .sha1 sidecar) -> the
#                     version size is jar + pom + sources, in the packages API
#                     and in package_versions; the admin catalog backfill
#                     re-derives the same total.
#   NPM      CONTROL  one-repo publish; packument + exact tarball (both).
#            FIX      the SAME name@version publishes into a second repo (2xx,
#                     not 409); both repos serve it; the two tarball rows carry
#                     distinct `npm/{repo_id}/...` keys, both in MinIO.
#   RUBYGEMS CONTROL  `demo` 1.0.0 and `dtf-s3` 1.2.3 index correctly (both).
#            FIX      `dtf-gem-2` 1.2.3 is advertised as [dtf-gem-2, 1.2.3,
#                     ruby] in specs.4.8.gz and latest_specs.4.8.gz.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="${HERE}/fixtures"

MINIO_CTR="ak-dtf${DTF_SLOT}-minio"
BUCKET="ak-artifacts"
MC_IMAGE="${FCF_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"

WORK="$(mktemp -d -t dtf-fcf-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>/dev/null; }
mcx() {
  docker run --rm -i --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}
repo_id() { psqlq "SELECT id FROM repositories WHERE key = '$1'"; }
is2xx() { [ "${1:-0}" -ge 200 ] 2>/dev/null && [ "${1:-0}" -lt 300 ] 2>/dev/null; }

# PUT FILE to URL with Basic auth; echoes the status (and the body to $WORK/last.body).
put_file() { # URL FILE
  curl -s -o "${WORK}/last.body" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/octet-stream" \
    --data-binary "@$2" "$1" 2>/dev/null || echo 000
}
get_file() { # URL OUT
  curl -s -o "$2" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -H "$(format_auth_header)" "$1" 2>/dev/null || echo 000
}
last_body() { head -c 300 "${WORK}/last.body" 2>/dev/null; }

begin_suite "format-catalog-fixes"
auth_admin

# =============================================================================
# CONAN (#4694)
# =============================================================================
CA="fcf-conan-a-${SUF}"
CB="fcf-conan-b-${SUF}"
CL="fcf-conan-legacy-${SUF}"
for r in "$CA" "$CB" "$CL"; do
  if ! create_repo "$r" conan; then
    begin_test "setup: create conan repository ${r}"
    infra_fail "could not create conan repo ${r}"
    end_suite
  fi
done
CA_ID="$(repo_id "$CA")"; CB_ID="$(repo_id "$CB")"; CL_ID="$(repo_id "$CL")"
if [ -z "$CA_ID" ] || [ -z "$CB_ID" ] || [ -z "$CL_ID" ]; then
  begin_test "setup: resolve conan repository ids"
  infra_fail "could not read repository ids from the DB (a='${CA_ID}' b='${CB_ID}' legacy='${CL_ID}')"
  end_suite
fi

CN="fcfsame"; CV="1.0"
RREV="4694aaaabbbbccccddddeeeeffff0000"
PID="9a4eb3c8701508aa9458b1a73d0633783ecc2270"
PREV="4694111122223333444455556666aaaa"

mkdir -p "${WORK}/conan"
cat > "${WORK}/conan/conanfile.py" <<'EOF'
from conan import ConanFile

class FcfSame(ConanFile):
    name = "fcfsame"
    version = "1.0"
EOF
printf '[settings]\n    os=Linux\n' > "${WORK}/conan/conaninfo.txt"
printf 'dtf-format-catalog-fixes conan package payload\n' > "${WORK}/conan/conan_package.tgz"

# conan_publish REPO NAME -> "recipe_conanfile recipe_manifest pkg_info pkg_tgz pkg_manifest"
conan_publish() {
  local repo="$1" name="$2"
  local base="${BASE_URL}/conan/${repo}/v2/conans/${name}/${CV}/_/_/revisions/${RREV}"
  local s1 s2 s3 s4 s5
  s1="$(put_file "${base}/files/conanfile.py" "${WORK}/conan/conanfile.py")"
  [ "$s1" = "409" ] && cp "${WORK}/last.body" "${WORK}/conan-409-${repo}.body"
  s2="$(conan_publish_revision "${base}/files")" || true
  local pbase="${base}/packages/${PID}/revisions/${PREV}/files"
  s3="$(put_file "${pbase}/conaninfo.txt" "${WORK}/conan/conaninfo.txt")"
  s4="$(put_file "${pbase}/conan_package.tgz" "${WORK}/conan/conan_package.tgz")"
  s5="$(conan_publish_revision "$pbase" conaninfo.txt conan_package.tgz)" || true
  echo "$s1 $s2 $s3 $s4 $s5"
}
all2xx() { local s; for s in "$@"; do is2xx "$s" || return 1; done; }

# conan_serves REPO NAME -> 0 when both recipe and package bytes come back intact
conan_serves() {
  local repo="$1" name="$2"
  local base="${BASE_URL}/conan/${repo}/v2/conans/${name}/${CV}/_/_/revisions/${RREV}"
  local c1 c2
  c1="$(get_file "${base}/files/conanfile.py" "${WORK}/dl-recipe")"
  c2="$(get_file "${base}/packages/${PID}/revisions/${PREV}/files/conan_package.tgz" "${WORK}/dl-pkg")"
  CONAN_DL="recipe=${c1} package=${c2}"
  [ "$c1" = "200" ] && [ "$c2" = "200" ] \
    && cmp -s "${WORK}/dl-recipe" "${WORK}/conan/conanfile.py" \
    && cmp -s "${WORK}/dl-pkg" "${WORK}/conan/conan_package.tgz"
}

begin_test "CONTROL conan: recipe + package revision publish into repo A -> all 2xx (both images)"
# shellcheck disable=SC2207
SA=($(conan_publish "$CA" "$CN"))
if all2xx "${SA[@]}"; then pass; else
  fail "publishing ${CN}/${CV}#${RREV} into ${CA} did not succeed: statuses ${SA[*]} (conanfile, recipe manifest, conaninfo, package tgz, package manifest)"
fi

begin_test "CONTROL conan: repo A serves the recipe and package bytes it was given (both images)"
if conan_serves "$CA" "$CN"; then pass; else
  fail "repo ${CA} did not serve its own revision back byte-for-byte (${CONAN_DL})"
fi

begin_test "FIX #4694: the SAME recipe/package revision publishes into repo B on shared S3 -> all 2xx (1.11.1: 409 cross-repository overwrite)"
# shellcheck disable=SC2207
SB=($(conan_publish "$CB" "$CN"))
if all2xx "${SB[@]}"; then pass; else
  fail "the second repository could not take a revision repo ${CA} already holds: statuses ${SB[*]} (conanfile, recipe manifest, conaninfo, package tgz, package manifest). On shared cloud storage every conan repo wrote the flat key conan/{name}/{version}/..., so guard_cross_repo_write refused it." \
    "first 409 body: $(head -c 300 "${WORK}/conan-409-${CB}.body" 2>/dev/null)"
fi

begin_test "FIX #4694: repo B serves the revision through its own repo key"
if conan_serves "$CB" "$CN"; then pass; else
  fail "repo ${CB} does not serve the revision it was given (${CONAN_DL})"
fi

begin_test "CONTROL conan: repo A still serves its bytes after repo B's publish (both images)"
if conan_serves "$CA" "$CN"; then pass; else
  fail "repo ${CA} lost its revision after a publish into ${CB} (${CONAN_DL})"
fi

CONAN_KEYS="$(mcx "mc find local/${BUCKET}/conan" 2>/dev/null | sed "s#^local/${BUCKET}/##")"
begin_test "FIX #4694: MinIO holds the conanfile under two distinct repo-scoped keys conan/{repo_id}/${CN}/... and no flat conan/${CN}/... key"
KA="conan/${CA_ID}/${CN}/${CV}/_/_/recipe/${RREV}/conanfile.py"
KB="conan/${CB_ID}/${CN}/${CV}/_/_/recipe/${RREV}/conanfile.py"
FLAT_COUNT="$(printf '%s\n' "$CONAN_KEYS" | grep -c "^conan/${CN}/" || true)"
if printf '%s\n' "$CONAN_KEYS" | grep -qxF "$KA" \
   && printf '%s\n' "$CONAN_KEYS" | grep -qxF "$KB" \
   && [ "$FLAT_COUNT" = "0" ]; then pass; else
  fail "expected ${KA} and ${KB} in the bucket and no flat conan/${CN}/ key (flat keys found: ${FLAT_COUNT})" \
    "$(printf '%s\n' "$CONAN_KEYS" | head -20)"
fi

begin_test "FIX #4694: the artifact rows of both repos record the repo-scoped keys"
ROWKEYS="$(psqlq "SELECT r.key || ' ' || a.storage_key FROM artifacts a JOIN repositories r ON r.id = a.repository_id
  WHERE r.id IN ('${CA_ID}','${CB_ID}') AND a.is_deleted = false ORDER BY 1")"
BAD_ROWS="$(printf '%s\n' "$ROWKEYS" | awk -v a="$CA" -v ai="$CA_ID" -v b="$CB" -v bi="$CB_ID" '
  NF==2 { want = ($1==a) ? "conan/" ai "/" : "conan/" bi "/"; if (index($2, want) != 1) n++ }
  END { print n+0 }')"
NROWS="$(printf '%s\n' "$ROWKEYS" | grep -c . || true)"
if [ "$BAD_ROWS" = "0" ] && [ "${NROWS:-0}" -ge 8 ]; then pass; else
  fail "${BAD_ROWS} of ${NROWS} live conan rows in ${CA}/${CB} do not carry conan/{their repo_id}/ (expected >= 8 rows, all scoped)" \
    "$(printf '%s\n' "$ROWKEYS" | head -12)"
fi

# --- legacy flat-key row (written as 1.11.1 wrote it) -------------------------
CNL="fcflegacy"
LEGACY_KEY="conan/${CNL}/${CV}/_/_/recipe/${RREV}/conanfile.py"
LBASE="${BASE_URL}/conan/${CL}/v2/conans/${CNL}/${CV}/_/_/revisions/${RREV}"
L1="$(put_file "${LBASE}/files/conanfile.py" "${WORK}/conan/conanfile.py")"
L2="$(conan_publish_revision "${LBASE}/files")" || true
L_ART="$(psqlq "SELECT a.id || ' ' || a.storage_key FROM artifacts a WHERE a.repository_id = '${CL_ID}'
  AND a.is_deleted = false AND a.path LIKE '%/conanfile.py'")"
L_ID="${L_ART%% *}"; L_KEY0="${L_ART#* }"
if ! is2xx "$L1" || ! is2xx "$L2" || [ -z "$L_ID" ]; then
  begin_test "setup: publish the legacy-leg recipe"
  infra_fail "could not publish ${CNL} into ${CL} (conanfile=${L1} manifest=${L2} row='${L_ART}')"
  end_suite
fi
# Move the object to the legacy flat key and point the row at it, exactly the
# state a 1.11.1 upload left behind. On 1.11.1 the row already has that key.
if [ "$L_KEY0" != "$LEGACY_KEY" ]; then
  if ! mcx "mc cp 'local/${BUCKET}/${L_KEY0}' 'local/${BUCKET}/${LEGACY_KEY}' >/dev/null && mc rm 'local/${BUCKET}/${L_KEY0}' >/dev/null" \
     || [ "$(psqlq "UPDATE artifacts SET storage_key = '${LEGACY_KEY}' WHERE id = '${L_ID}' RETURNING storage_key")" != "$LEGACY_KEY" ]; then
    begin_test "setup: rewrite the legacy-leg row to the flat key"
    infra_fail "could not move ${L_KEY0} to ${LEGACY_KEY} in MinIO / the artifacts row"
    end_suite
  fi
fi

begin_test "CONTROL conan legacy: a recipe row on the legacy flat key (no scoped object) still downloads (both images)"
LC="$(get_file "${LBASE}/files/conanfile.py" "${WORK}/dl-legacy")"
if [ "$LC" = "200" ] && cmp -s "${WORK}/dl-legacy" "${WORK}/conan/conanfile.py"; then pass; else
  fail "legacy-key recipe ${LEGACY_KEY} did not serve: HTTP ${LC}" "$(head -c 200 "${WORK}/dl-legacy" 2>/dev/null)"
fi

begin_test "FIX #4694: re-uploading the legacy-key recipe moves its row to conan/{repo_id}/... and it still downloads"
LR="$(put_file "${LBASE}/files/conanfile.py" "${WORK}/conan/conanfile.py")"
L_KEY1="$(psqlq "SELECT storage_key FROM artifacts WHERE repository_id = '${CL_ID}' AND is_deleted = false AND path LIKE '%/conanfile.py'")"
LC2="$(get_file "${LBASE}/files/conanfile.py" "${WORK}/dl-legacy2")"
if is2xx "$LR" && [ "$L_KEY1" = "conan/${CL_ID}/${CNL}/${CV}/_/_/recipe/${RREV}/conanfile.py" ] \
   && [ "$LC2" = "200" ] && cmp -s "${WORK}/dl-legacy2" "${WORK}/conan/conanfile.py"; then pass; else
  fail "re-upload=${LR}, row key after='${L_KEY1}' (want conan/${CL_ID}/...), download=${LC2}"
fi

# =============================================================================
# MAVEN (#4633)
# =============================================================================
MR="fcf-maven-${SUF}"
if ! create_repo "$MR" maven; then
  begin_test "setup: create maven repository"
  infra_fail "could not create maven repo ${MR}"
  end_suite
fi
G="com/example/fcf"; GID="com.example.fcf"
mkdir -p "${WORK}/mvn"
head -c 40000 /dev/zero | tr '\0' 'j' > "${WORK}/mvn/demo.jar"
head -c 7000 /dev/zero | tr '\0' 's' > "${WORK}/mvn/demo-sources.jar"
cat > "${WORK}/mvn/demo.pom" <<EOF
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GID}</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
</project>
EOF
sha1sum "${WORK}/mvn/demo.jar" | cut -d' ' -f1 | tr -d '\n' > "${WORK}/mvn/demo.jar.sha1"
head -c 12345 /dev/zero | tr '\0' 'o' > "${WORK}/mvn/solo.jar"
N1=$(stat -c %s "${WORK}/mvn/demo.jar"); N2=$(stat -c %s "${WORK}/mvn/demo.pom")
N3=$(stat -c %s "${WORK}/mvn/demo-sources.jar"); NS=$(stat -c %s "${WORK}/mvn/solo.jar")
SUM=$((N1 + N2 + N3))

MB="${BASE_URL}/maven/${MR}/${G}"
M1="$(put_file "${MB}/demo/1.0.0/demo-1.0.0.jar" "${WORK}/mvn/demo.jar")"
M1S="$(put_file "${MB}/demo/1.0.0/demo-1.0.0.jar.sha1" "${WORK}/mvn/demo.jar.sha1")"
M2="$(put_file "${MB}/demo/1.0.0/demo-1.0.0.pom" "${WORK}/mvn/demo.pom")"
M3="$(put_file "${MB}/demo/1.0.0/demo-1.0.0-sources.jar" "${WORK}/mvn/demo-sources.jar")"
M4="$(put_file "${MB}/solo/1.0.0/solo-1.0.0.jar" "${WORK}/mvn/solo.jar")"
if ! all2xx "$M1" "$M1S" "$M2" "$M3" "$M4"; then
  begin_test "setup: deploy the maven fixture files"
  infra_fail "maven PUTs: jar=${M1} jar.sha1=${M1S} pom=${M2} sources=${M3} solo=${M4}"
  end_suite
fi

# api_version_size NAME VERSION -> size_bytes of that version via the packages API
api_version_size() {
  local pid
  pid="$(api_get "/api/v1/packages?repository_key=${MR}&per_page=100" \
    | jq -r --arg n "$1" '.items[] | select(.name == $n) | .id' | head -1)"
  [ -n "$pid" ] || { echo "no-package"; return; }
  api_get "/api/v1/packages/${pid}/versions" \
    | jq -r --arg v "$2" '[.versions[] | select(.version == $v) | .size_bytes][0] // "no-version"'
}
db_version_size() { # NAME VERSION
  psqlq "SELECT pv.size_bytes FROM package_versions pv JOIN packages p ON p.id = pv.package_id
    JOIN repositories r ON r.id = p.repository_id
    WHERE r.key = '${MR}' AND p.name = '$1' AND pv.version = '$2'"
}

begin_test "CONTROL maven: a single-file version's size is that file's size, API and DB (both images)"
SA_API="$(api_version_size "${GID}:solo" 1.0.0)"; SA_DB="$(db_version_size "${GID}:solo" 1.0.0)"
if [ "$SA_API" = "$NS" ] && [ "$SA_DB" = "$NS" ]; then pass; else
  fail "solo 1.0.0: packages API size=${SA_API}, package_versions.size_bytes=${SA_DB}, expected ${NS}"
fi

begin_test "FIX #4633: packages API reports demo 1.0.0 as jar+pom+sources = ${SUM} bytes (the .sha1 sidecar is row-less and not counted)"
DA_API="$(api_version_size "${GID}:demo" 1.0.0)"
if [ "$DA_API" = "$SUM" ]; then pass; else
  fail "packages API size for ${GID}:demo 1.0.0 = ${DA_API}, expected ${SUM} (jar ${N1} + pom ${N2} + sources ${N3}); a single file's size here is the #4633 bug"
fi

begin_test "FIX #4633: package_versions.size_bytes for demo 1.0.0 agrees (${SUM})"
DA_DB="$(db_version_size "${GID}:demo" 1.0.0)"
if [ "$DA_DB" = "$SUM" ]; then pass; else
  fail "package_versions.size_bytes = ${DA_DB}, expected ${SUM} (jar ${N1} / pom ${N2} / sources ${N3})"
fi

begin_test "FIX #4633: the admin catalog backfill re-derives the total after the row is reset"
psqlq "UPDATE package_versions pv SET size_bytes = 1 FROM packages p, repositories r
  WHERE p.id = pv.package_id AND r.id = p.repository_id AND r.key = '${MR}'
  AND p.name = '${GID}:demo' AND pv.version = '1.0.0'" >/dev/null
BF="$(api_post "/api/v1/admin/packages/backfill?repository_key=${MR}" || echo FAILED)"
DA_BF="$(db_version_size "${GID}:demo" 1.0.0)"
if [ "$DA_BF" = "$SUM" ]; then pass; else
  fail "after POST /api/v1/admin/packages/backfill the version size is ${DA_BF}, expected ${SUM}" "backfill response: ${BF:0:300}"
fi

# =============================================================================
# NPM (#4293)
# =============================================================================
NA="fcf-npm-a-${SUF}"
NB="fcf-npm-b-${SUF}"
for r in "$NA" "$NB"; do
  if ! create_repo "$r" npm; then
    begin_test "setup: create npm repository ${r}"
    infra_fail "could not create npm repo ${r}"
    end_suite
  fi
done
NA_ID="$(repo_id "$NA")"; NB_ID="$(repo_id "$NB")"
NPKG="fcf-npm-same"; NVER="1.0.0"; NTGZ="${NPKG}-${NVER}.tgz"
mkdir -p "${WORK}/npm/package"
printf '{"name":"%s","version":"%s","main":"index.js","license":"MIT"}\n' "$NPKG" "$NVER" > "${WORK}/npm/package/package.json"
printf 'module.exports = "dtf %s";\n' "$SUF" > "${WORK}/npm/package/index.js"
tar -czf "${WORK}/npm/${NTGZ}" -C "${WORK}/npm" package
# npm_publish REPO -> status (body in $WORK/last.body); the same tarball every time
npm_publish() {
  local f="${WORK}/npm/${NTGZ}" payload="${WORK}/npm/publish-$1.json"
  jq -n --arg name "$NPKG" --arg ver "$NVER" --arg tgz "$NTGZ" \
    --arg url "${BASE_URL}/npm/$1/${NPKG}/-/${NTGZ}" \
    --arg shasum "$(sha1sum "$f" | cut -d' ' -f1)" \
    --arg integrity "sha512-$(openssl dgst -sha512 -binary "$f" | base64 | tr -d '\n')" \
    --arg data "$(base64 < "$f" | tr -d '\n')" --arg len "$(wc -c < "$f" | tr -d ' ')" \
    '{name:$name, "dist-tags":{latest:$ver},
      versions:{($ver):{name:$name, version:$ver, main:"index.js", license:"MIT",
                        dist:{tarball:$url, shasum:$shasum, integrity:$integrity}}},
      _attachments:{($tgz):{content_type:"application/octet-stream", data:$data, length:($len|tonumber)}}}' > "$payload"
  curl -s -o "${WORK}/last.body" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
    -H "$(format_auth_header)" -H "Content-Type: application/json" \
    --data-binary "@${payload}" "${BASE_URL}/npm/$1/${NPKG}" 2>/dev/null || echo 000
}
# npm_serves REPO -> 0 when the packument lists the version and its tarball downloads byte-exact
npm_serves() {
  local c1 c2 tb
  c1="$(get_file "${BASE_URL}/npm/$1/${NPKG}" "${WORK}/npm/packument-$1.json")"
  tb="$(jq -r --arg v "$NVER" '.versions[$v].dist.tarball // empty' "${WORK}/npm/packument-$1.json" 2>/dev/null)"
  c2="$(get_file "${BASE_URL}/npm/$1/${NPKG}/-/${NTGZ}" "${WORK}/npm/dl-$1.tgz")"
  [ "$c1" = "200" ] && [ -n "$tb" ] && [ "$c2" = "200" ] && cmp -s "${WORK}/npm/dl-$1.tgz" "${WORK}/npm/${NTGZ}"
}

begin_test "CONTROL npm: ${NPKG}@${NVER} publishes into repo A and A serves the packument and the exact tarball (both images)"
NSA="$(npm_publish "$NA")"
if is2xx "$NSA" && npm_serves "$NA"; then pass; else
  fail "publish into ${NA}: HTTP ${NSA}; packument/tarball served: $(npm_serves "$NA" && echo yes || echo no)" "$(last_body)"
fi

begin_test "FIX #4293: the SAME ${NPKG}@${NVER} publishes into a second npm repo on the shared bucket (2xx, not 409 cross-repository overwrite)"
NSB="$(npm_publish "$NB")"
if is2xx "$NSB"; then pass; else
  fail "publish into ${NB}: HTTP ${NSB}. On shared cloud storage every npm repository wrote the same tarball key, so guard_cross_repo_write refused the second repository" "$(last_body)"
fi

begin_test "FIX #4293: repo B serves the packument and the exact tarball, and repo A still does"
if npm_serves "$NB" && npm_serves "$NA"; then pass; else
  fail "served by ${NB}: $(npm_serves "$NB" && echo yes || echo no); by ${NA}: $(npm_serves "$NA" && echo yes || echo no)"
fi

begin_test "FIX #4293: the two tarball rows carry distinct repo-scoped keys npm/{repo_id}/... and both objects are in MinIO"
NROWS="$(psqlq "SELECT r.id || ' ' || a.storage_key FROM artifacts a JOIN repositories r ON r.id = a.repository_id
  WHERE r.key IN ('${NA}','${NB}') AND a.path LIKE '%${NTGZ}' AND NOT a.is_deleted ORDER BY r.key")"
NKA="$(printf '%s\n' "$NROWS" | awk -v id="$NA_ID" '$1 == id {print $2}')"
NKB="$(printf '%s\n' "$NROWS" | awk -v id="$NB_ID" '$1 == id {print $2}')"
NOBJ="$(mcx "mc find local/${BUCKET}/npm --name '${NTGZ}'" 2>/dev/null | sed "s#^local/${BUCKET}/##")"
if [[ "$NKA" == "npm/${NA_ID}/"* ]] && [[ "$NKB" == "npm/${NB_ID}/"* ]] && [ "$NKA" != "$NKB" ] \
   && printf '%s\n' "$NOBJ" | grep -qxF "$NKA" && printf '%s\n' "$NOBJ" | grep -qxF "$NKB"; then pass; else
  fail "tarball rows: A='${NKA}' B='${NKB}' (want npm/${NA_ID}/... and npm/${NB_ID}/...); MinIO objects named ${NTGZ}: $(printf '%s' "$NOBJ" | tr '\n' ' ')"
fi

# =============================================================================
# RUBYGEMS (#4645)
# =============================================================================
GR="fcf-gems-${SUF}"
if ! create_repo "$GR" rubygems; then
  begin_test "setup: create rubygems repository"
  infra_fail "could not create rubygems repo ${GR}"
  end_suite
fi
push_gem() { # NAME VERSION -> status
  local f="${WORK}/$1-$2.gem"
  python3 -I "${FIX}/build_gem.py" "$1" "$2" "$f" || { echo build-failed; return; }
  curl -s -o "${WORK}/last.body" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X POST \
    -H "$(format_auth_header)" -H "Content-Type: application/octet-stream" \
    --data-binary "@${f}" "${BASE_URL}/gems/${GR}/api/v1/gems" 2>/dev/null || echo 000
}
P1="$(push_gem demo 1.0.0)"; P2="$(push_gem dtf-s3 1.2.3)"; P3="$(push_gem dtf-gem-2 1.2.3)"
if ! all2xx "$P1" "$P2" "$P3"; then
  begin_test "setup: push the gem fixtures"
  infra_fail "gem push: demo=${P1} dtf-s3=${P2} dtf-gem-2=${P3}" "$(last_body)"
  end_suite
fi

decode_index() { # FILE_NAME -> writes $WORK/<name>.tsv, echoes HTTP status
  local c
  c="$(get_file "${BASE_URL}/gems/${GR}/$1" "${WORK}/$1")"
  python3 -I "${FIX}/marshal_specs.py" "${WORK}/$1" > "${WORK}/$1.tsv" 2>"${WORK}/$1.err" || c="${c}/undecodable"
  echo "$c"
}
SPECS_C="$(decode_index specs.4.8.gz)"
LATEST_C="$(decode_index latest_specs.4.8.gz)"
if [ "$SPECS_C" != "200" ] || [ "$LATEST_C" != "200" ]; then
  begin_test "setup: fetch and decode the specs indexes"
  infra_fail "specs.4.8.gz=${SPECS_C} latest_specs.4.8.gz=${LATEST_C}" \
    "$(cat "${WORK}/specs.4.8.gz.err" "${WORK}/latest_specs.4.8.gz.err" 2>/dev/null)"
  end_suite
fi
has_entry() { grep -qxF "$(printf '%s\t%s\truby' "$2" "$3")" "${WORK}/$1.tsv"; }

begin_test "CONTROL rubygems: demo 1.0.0 and dtf-s3 1.2.3 are advertised with their own coordinates in specs.4.8.gz (both images)"
if has_entry specs.4.8.gz demo 1.0.0 && has_entry specs.4.8.gz dtf-s3 1.2.3; then pass; else
  fail "specs.4.8.gz lacks [demo,1.0.0,ruby] or [dtf-s3,1.2.3,ruby]" "$(cat "${WORK}/specs.4.8.gz.tsv")"
fi

begin_test "FIX #4645: specs.4.8.gz advertises [dtf-gem-2, 1.2.3, ruby] (1.11.1: [dtf-gem, 2-1.2.3, ruby])"
if has_entry specs.4.8.gz dtf-gem-2 1.2.3; then pass; else
  fail "the full index does not carry the gemspec's coordinates for dtf-gem-2 1.2.3; gem install dtf-gem-2 cannot resolve it" \
    "$(cat "${WORK}/specs.4.8.gz.tsv")"
fi

begin_test "FIX #4645: latest_specs.4.8.gz advertises [dtf-gem-2, 1.2.3, ruby]"
if has_entry latest_specs.4.8.gz dtf-gem-2 1.2.3; then pass; else
  fail "the latest index does not carry [dtf-gem-2,1.2.3,ruby]" "$(cat "${WORK}/latest_specs.4.8.gz.tsv")"
fi

begin_test "CONTROL rubygems: the packages API lists dtf-gem-2 1.2.3 (push reads the gemspec; both images)"
GEM_PKGS="$(api_get "/api/v1/packages?repository_key=${GR}&per_page=100" | jq -r '.items[] | "\(.name) \(.version)"' | sort)"
if printf '%s\n' "$GEM_PKGS" | grep -qxF "dtf-gem-2 1.2.3"; then pass; else
  fail "packages API does not list name=dtf-gem-2 version=1.2.3" "$GEM_PKGS"
fi

begin_test "CONTROL rubygems: the gem downloads from /gems/{repo}/gems/dtf-gem-2-1.2.3.gem (both images)"
DLC="$(get_file "${BASE_URL}/gems/${GR}/gems/dtf-gem-2-1.2.3.gem" "${WORK}/dl.gem")"
if [ "$DLC" = "200" ] && cmp -s "${WORK}/dl.gem" "${WORK}/dtf-gem-2-1.2.3.gem"; then pass; else
  fail "download of dtf-gem-2-1.2.3.gem: HTTP ${DLC} (or bytes differ)"
fi

end_suite
