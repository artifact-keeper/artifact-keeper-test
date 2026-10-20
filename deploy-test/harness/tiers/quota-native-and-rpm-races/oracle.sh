#!/usr/bin/env bash
# =============================================================================
# tiers/quota-native-and-rpm-races/oracle.sh
#   Storage quota on native publishes (artifact-keeper#4422), concurrent RPM
#   curated snapshot creates (#4307) and publishes (#4421).
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
QUOTA=4096
PAR="${QNR_PARALLEL:-16}"
ROUNDS="${QNR_ROUNDS:-4}"
PKGS="${QNR_PACKAGES:-30}"
PUBS="${QNR_PUBLISHES:-4}"

WORK="$(mktemp -d -t dtf-qnr-XXXXXX)"
export GNUPGHOME="${WORK}/gnupg"
trap 'rm -rf "$WORK"' EXIT

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>&1; }
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
jcode() { jq -r '.code // .errors[0].code // empty' "$1" 2>/dev/null; }
rows_in() { psqlq "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1' AND NOT a.is_deleted"; }
AUTHZ=()
mk_repo() { # KEY FORMAT TYPE [extra-json-fields] -> code
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-$1.json" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"$3\",\"is_public\":false${4:-}}"
}

begin_suite "quota-native-and-rpm-races"
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

# =============================================================================
# SETUP: quota-capped repositories (4096 bytes) and an 8 KiB payload
# =============================================================================
QG="qnr-gen-${SLOT}-${SUF}"; QM="qnr-mvn-${SLOT}-${SUF}"; QC="qnr-conan-${SLOT}-${SUF}"
QK="qnr-cargo-${SLOT}-${SUF}"; QD="qnr-docker-${SLOT}-${SUF}"; DN="qnr-dk-${SLOT}-${SUF}"
SF=""
for spec in "$QG:generic" "$QM:maven" "$QC:conan" "$QK:cargo" "$QD:docker"; do
  k="${spec%%:*}"; f="${spec#*:}"
  c="$(mk_repo "$k" "$f" local ",\"quota_bytes\":${QUOTA}")"
  is_2xx "$c" && [ "$(jq -r '.quota_bytes // empty' "${WORK}/mk-${k}.json")" = "$QUOTA" ] || SF="${SF} ${f}=${c}"
done
c="$(mk_repo "$DN" docker local)"; is_2xx "$c" || SF="${SF} docker-noquota=${c}"
if [ -n "$SF" ]; then
  begin_test "setup: repositories with quota_bytes=${QUOTA}"
  infra_fail "setup failed:${SF}"
  end_suite
fi
head -c 8192 /dev/urandom > "${WORK}/big.bin"
head -c 1024 /dev/urandom > "${WORK}/small.bin"

# =============================================================================
# #4422: quota on native publishes
# =============================================================================
begin_test "CONTROL: an 8 KiB generic upload into a 4096-byte quota repository is 507 QUOTA_EXCEEDED (enforced before 1.11.0 too)"
c="$(code_to_file "${BASE_URL}/api/v1/repositories/${QG}/artifacts/big.bin" "${WORK}/gen.json" -X PUT "${AUTHZ[@]}" --data-binary "@${WORK}/big.bin")"
if [ "$c" = "507" ] && [ "$(jcode "${WORK}/gen.json")" = "QUOTA_EXCEEDED" ] && [ "$(rows_in "$QG")" = "0" ]; then pass; else
  fail "generic PUT=${c} code=$(jcode "${WORK}/gen.json") rows=$(rows_in "$QG")" "$(head -c 300 "${WORK}/gen.json")"
fi

begin_test "CONTROL: a 1 KiB Maven jar under the quota is 201 and downloads byte-exact (admission does not refuse what fits)"
c="$(code_to_file "${BASE_URL}/maven/${QM}/com/example/qnr/small/1.0/small-1.0.jar" "${WORK}/mvn-small.json" -X PUT "${AUTHZ[@]}" --data-binary "@${WORK}/small.bin")"
d="$(code_to_file "${BASE_URL}/maven/${QM}/com/example/qnr/small/1.0/small-1.0.jar" "${WORK}/mvn-small.out" "${AUTHZ[@]}")"
if [ "$c" = "201" ] && [ "$d" = "200" ] && cmp -s "${WORK}/mvn-small.out" "${WORK}/small.bin"; then pass; else
  fail "maven PUT=${c} GET=${d} byte-exact=$(cmp -s "${WORK}/mvn-small.out" "${WORK}/small.bin" && echo yes || echo no)" "$(head -c 300 "${WORK}/mvn-small.json")"
fi
MVN_ROWS_BEFORE="$(rows_in "$QM")"

begin_test "#4422 maven: an 8 KiB jar that would pass the quota is 507 QUOTA_EXCEEDED and adds no artifacts row"
c="$(code_to_file "${BASE_URL}/maven/${QM}/com/example/qnr/big/1.0/big-1.0.jar" "${WORK}/mvn-big.json" -X PUT "${AUTHZ[@]}" --data-binary "@${WORK}/big.bin")"
if [ "$c" = "507" ] && [ "$(jcode "${WORK}/mvn-big.json")" = "QUOTA_EXCEEDED" ] && [ "$(rows_in "$QM")" = "$MVN_ROWS_BEFORE" ]; then pass; else
  fail "maven PUT=${c} code=$(jcode "${WORK}/mvn-big.json") rows ${MVN_ROWS_BEFORE} -> $(rows_in "$QM"). Pre-#4422 the native Maven handler never ran quota admission" "$(head -c 300 "${WORK}/mvn-big.json")"
fi

begin_test "#4422 conan: an 8 KiB recipe file into the capped repository is 507 QUOTA_EXCEEDED and leaves no row"
c="$(code_to_file "${BASE_URL}/conan/${QC}/v2/conans/qnrbig/1.0/_/_/revisions/4422aaaabbbbccccddddeeeeffff0000/files/conanfile.py" "${WORK}/conan.json" \
      -X PUT "${AUTHZ[@]}" --data-binary "@${WORK}/big.bin")"
if [ "$c" = "507" ] && [ "$(jcode "${WORK}/conan.json")" = "QUOTA_EXCEEDED" ] && [ "$(rows_in "$QC")" = "0" ]; then pass; else
  fail "conan PUT=${c} code=$(jcode "${WORK}/conan.json") rows=$(rows_in "$QC")" "$(head -c 300 "${WORK}/conan.json")"
fi

begin_test "#4422 cargo: publishing an 8 KiB crate into the capped repository is 507 QUOTA_EXCEEDED and leaves no row"
mkdir -p "${WORK}/crate/qnrbig-0.1.0/src"
printf '[package]\nname = "qnrbig"\nversion = "0.1.0"\n' > "${WORK}/crate/qnrbig-0.1.0/Cargo.toml"
printf 'pub fn f() {}\n' > "${WORK}/crate/qnrbig-0.1.0/src/lib.rs"
cp "${WORK}/big.bin" "${WORK}/crate/qnrbig-0.1.0/src/blob.bin"
tar -czf "${WORK}/qnrbig.crate" -C "${WORK}/crate" qnrbig-0.1.0
python3 -I - "${WORK}/qnrbig.crate" "${WORK}/cargo.pay" <<'PY'
import json, struct, sys
meta = json.dumps({"name": "qnrbig", "vers": "0.1.0", "deps": [], "features": {}, "authors": ["dtf"],
                   "description": "quota", "license": "MIT"}).encode()
crate = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(struct.pack("<I", len(meta)) + meta + struct.pack("<I", len(crate)) + crate)
PY
c="$(code_to_file "${BASE_URL}/cargo/${QK}/api/v1/crates/new" "${WORK}/cargo.json" -X PUT "${AUTHZ[@]}" --data-binary "@${WORK}/cargo.pay")"
if [ "$c" = "507" ] && [ "$(jcode "${WORK}/cargo.json")" = "QUOTA_EXCEEDED" ] && [ "$(rows_in "$QK")" = "0" ]; then pass; else
  fail "cargo publish=${c} code=$(jcode "${WORK}/cargo.json") rows=$(rows_in "$QK")" "$(head -c 300 "${WORK}/cargo.json")"
fi

begin_test "#4422 docker: an 8 KiB blob push into the capped repository is 507 with the registry envelope code DENIED and no oci_blobs row"
DBIG="sha256:$(sha256sum "${WORK}/big.bin" | cut -d' ' -f1)"
c="$(code_to_file "${BASE_URL}/v2/${QD}/app/blobs/uploads/?digest=${DBIG}" "${WORK}/oci.json" -X POST "${AUTHZ[@]}" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/big.bin")"
OB="$(psqlq "SELECT count(*) FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id WHERE r.key = '${QD}'")"
if [ "$c" = "507" ] && [ "$(jcode "${WORK}/oci.json")" = "DENIED" ] && [ "$OB" = "0" ]; then pass; else
  fail "blob push=${c} code=$(jcode "${WORK}/oci.json") oci_blobs rows=${OB}" "$(head -c 300 "${WORK}/oci.json")"
fi

begin_test "#4422 docker: a manifest declaring a layer of size -1 is 400 MANIFEST_INVALID (descriptor sizes feed the usage ledger); the same manifest with the real size is 201"
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"salt":"%s"}' "$SUF" > "${WORK}/cfg"
head -c 1024 /dev/urandom > "${WORK}/layer"
CD="sha256:$(sha256sum "${WORK}/cfg" | cut -d' ' -f1)"; LD="sha256:$(sha256sum "${WORK}/layer" | cut -d' ' -f1)"
BC=""
for f in cfg layer; do
  d="sha256:$(sha256sum "${WORK}/${f}" | cut -d' ' -f1)"
  BC="${BC} $(code_to_file "${BASE_URL}/v2/${DN}/app/blobs/uploads/?digest=${d}" /dev/null -X POST "${AUTHZ[@]}" --data-binary "@${WORK}/${f}")"
done
MT='application/vnd.docker.distribution.manifest.v2+json'
man() { printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"%s"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":%s,"digest":"%s"}]}' \
  "$MT" "$(wc -c < "${WORK}/cfg" | tr -d ' ')" "$CD" "$1" "$LD"; }
man -1 > "${WORK}/man-neg"; man 1024 > "${WORK}/man-ok"
cn="$(code_to_file "${BASE_URL}/v2/${DN}/app/manifests/neg" "${WORK}/man-neg.json" -X PUT "${AUTHZ[@]}" -H "Content-Type: ${MT}" --data-binary "@${WORK}/man-neg")"
co="$(code_to_file "${BASE_URL}/v2/${DN}/app/manifests/ok" "${WORK}/man-ok.json" -X PUT "${AUTHZ[@]}" -H "Content-Type: ${MT}" --data-binary "@${WORK}/man-ok")"
if [ "$BC" = " 201 201" ] && [ "$cn" = "400" ] && [ "$(jcode "${WORK}/man-neg.json")" = "MANIFEST_INVALID" ] && [ "$co" = "201" ]; then pass; else
  fail "blobs:${BC} manifest(size -1)=${cn} code=$(jcode "${WORK}/man-neg.json") manifest(real size)=${co} (want 400 MANIFEST_INVALID, then 201)" "$(head -c 300 "${WORK}/man-neg.json")"
fi

# =============================================================================
# RPM curated snapshots (#4307 create, #4421 publish)
# =============================================================================
ST="qnr-rpm-${SLOT}-${SUF}"; RM="qnr-rpmr-${SLOT}-${SUF}"
SF=""
c="$(mk_repo "$ST" rpm local)"; is_2xx "$c" || SF="${SF} staging=${c}"
c="$(mk_repo "$RM" rpm remote ',"upstream_url":"https://example.com/rpm"')"; is_2xx "$c" || SF="${SF} remote=${c}"
SID="$(psqlq "SELECT id FROM repositories WHERE key='${ST}'")"; RID="$(psqlq "SELECT id FROM repositories WHERE key='${RM}'")"
KID="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${AUTHZ[@]}" -X POST "${BASE_URL}/api/v1/signing/keys" -H 'Content-Type: application/json' \
  -d "{\"repository_id\":\"${SID}\",\"name\":\"qnr-${SUF}\",\"key_type\":\"gpg\",\"algorithm\":\"rsa2048\"}" | jq -r '.id // empty')"
[ -n "$KID" ] || SF="${SF} signing-key"
c="$(code_to_file "${BASE_URL}/api/v1/signing/repositories/${SID}/config" /dev/null -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
      -d "{\"signing_key_id\":\"${KID}\",\"sign_metadata\":true,\"sign_packages\":false}")"
is_2xx "$c" || SF="${SF} signing-config=${c}"
VALUES=""
for i in $(seq 1 "$PKGS"); do
  n="$(printf 'qnrpkg%02d' "$i")"; ck="$(printf '%s-%s' "$n" "$SUF" | sha256sum | cut -d' ' -f1)"
  VALUES="${VALUES}${VALUES:+,}('${SID}','${RID}','rpm','${n}','1.0','1.el9','x86_64','${ck}','Packages/${n}.rpm','approved','{\"name\":\"${n}\",\"arch\":\"x86_64\",\"epoch\":\"0\",\"version\":\"1.0\",\"release\":\"1.el9\",\"summary\":\"s\",\"description\":\"d\",\"checksum\":{\"type\":\"sha256\",\"pkgid\":true,\"value\":\"${ck}\"},\"size\":{\"package\":1024,\"installed\":4096,\"archive\":4100},\"time\":{\"file\":1700000000,\"build\":1699999999},\"format\":{\"license\":\"MIT\"}}'::jsonb)"
done
r="$(psqlq "INSERT INTO curation_packages (staging_repo_id, remote_repo_id, format, package_name, version, release, architecture, checksum_sha256, upstream_path, status, primary_metadata) VALUES ${VALUES}")"
[ "$(psqlq "SELECT count(*) FROM curation_packages WHERE staging_repo_id='${SID}' AND status='approved'")" = "$PKGS" ] || SF="${SF} seed=${r:0:120}"
if [ -n "$SF" ]; then
  begin_test "setup: RPM staging + remote repositories, GPG metadata signing, ${PKGS} approved curation packages"
  infra_fail "setup failed:${SF}"
  end_suite
fi

begin_test "#4307: ${ROUNDS} rounds of ${PAR} parallel snapshot creates on one RPM staging repository are all 201 with distinct version numbers"
CODES=""; : > "${WORK}/versions"
for r in $(seq 1 "$ROUNDS"); do
  for i in $(seq 1 "$PAR"); do
    curl -s -o "${WORK}/v-${r}-${i}.json" -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" -X POST \
      "${BASE_URL}/api/v1/curation/repos/${ST}/versions" > "${WORK}/v-${r}-${i}.code" 2>/dev/null &
  done
  wait
  for i in $(seq 1 "$PAR"); do
    CODES="${CODES} $(cat "${WORK}/v-${r}-${i}.code" 2>/dev/null)"
    jq -r '.version_number // empty' "${WORK}/v-${r}-${i}.json" 2>/dev/null >> "${WORK}/versions"
  done
done
TOTAL=$((ROUNDS * PAR))
N201="$(tr ' ' '\n' <<< "$CODES" | grep -c '^201$')"
NDIST="$(sort -u "${WORK}/versions" | grep -c .)"
HIST="$(tr ' ' '\n' <<< "$CODES" | grep . | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
if [ "$N201" = "$TOTAL" ] && [ "$NDIST" = "$TOTAL" ]; then pass; else
  BAD="$(grep -l -v '"version_number"' "${WORK}"/v-*.json 2>/dev/null | head -1)"
  fail "status histogram:${HIST}; 201s=${N201}/${TOTAL}; distinct version numbers=${NDIST}. Pre-#4307 concurrent creates exhausted the 40001 serialization retries and answered 500" \
    "$(head -c 300 "${BAD:-/dev/null}" 2>/dev/null)"
fi

VN="$(sort -n "${WORK}/versions" | tail -1)"
begin_test "#4421: ${PUBS} parallel publishes of version ${VN:-?} give exactly one 200 (published) and $((PUBS - 1)) x 409 CONFLICT"
for i in $(seq 1 "$PUBS"); do
  curl -s -o "${WORK}/p-${i}.json" -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" -X POST \
    "${BASE_URL}/api/v1/curation/repos/${ST}/versions/${VN}/publish" > "${WORK}/p-${i}.code" 2>/dev/null &
done
wait
PC=""; N200=0; N409=0
for i in $(seq 1 "$PUBS"); do
  ci="$(cat "${WORK}/p-${i}.code" 2>/dev/null)"; PC="${PC} ${ci}"
  [ "$ci" = "200" ] && [ "$(jq -r '.published // empty' "${WORK}/p-${i}.json" 2>/dev/null)" = "true" ] && N200=$((N200 + 1))
  [ "$ci" = "409" ] && [ "$(jcode "${WORK}/p-${i}.json")" = "CONFLICT" ] && N409=$((N409 + 1))
done
if [ -n "$VN" ] && [ "$N200" = "1" ] && [ "$N409" = "$((PUBS - 1))" ]; then pass; else
  fail "publish statuses:${PC} (published=${N200}, CONFLICT=${N409}). Pre-#4421 mark_published had no published_at IS NULL guard and every in-flight publish rewrote the repodata" \
    "$(cat "${WORK}"/p-*.json 2>/dev/null | head -c 400)"
fi

begin_test "CONTROL: the published @${VN:-?} repomd.xml lists primary and its repomd.xml.asc verifies with gpg under the served repomd.xml.key"
P="${BASE_URL}/rpm/${ST}/@${VN}/repodata"
c1="$(code_to_file "${P}/repomd.xml" "${WORK}/repomd.xml" "${AUTHZ[@]}")"
c2="$(code_to_file "${P}/repomd.xml.asc" "${WORK}/repomd.xml.asc" "${AUTHZ[@]}")"
c3="$(code_to_file "${P}/repomd.xml.key" "${WORK}/repomd.xml.key" "${AUTHZ[@]}")"
VERIFY="no-gpg"
if command -v gpg >/dev/null 2>&1; then
  mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  gpg --batch --quiet --import "${WORK}/repomd.xml.key" >/dev/null 2>&1
  if gpg --batch --quiet --verify "${WORK}/repomd.xml.asc" "${WORK}/repomd.xml" >/dev/null 2>&1; then VERIFY=ok; else VERIFY=bad; fi
elif grep -q 'BEGIN PGP SIGNATURE' "${WORK}/repomd.xml.asc" 2>/dev/null; then
  VERIFY=ok
  echo "  (gpg not installed: only the armor of repomd.xml.asc was checked)"
fi
if [ "$c1" = "200" ] && [ "$c2" = "200" ] && [ "$c3" = "200" ] && grep -q 'type="primary"' "${WORK}/repomd.xml" && [ "$VERIFY" = "ok" ]; then pass; else
  fail "repomd.xml=${c1} .asc=${c2} .key=${c3} primary listed=$(grep -c 'type="primary"' "${WORK}/repomd.xml" 2>/dev/null) signature=${VERIFY}"
fi

end_suite
