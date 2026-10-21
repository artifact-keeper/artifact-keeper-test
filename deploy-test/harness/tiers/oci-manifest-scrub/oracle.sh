#!/usr/bin/env bash
# =============================================================================
# tiers/oci-manifest-scrub/oracle.sh
#   #4666 storage-scrub checks an OCI manifest against oci_manifests.size_bytes
#         (its body length), not artifacts.size_bytes (the image size), so an
#         intact image is not flagged and a damaged manifest still is
# See the manifest for the fix and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
# The backend image is distroless (no shell): touch its volume from a shell
# helper (the stack's own postgres image) that mounts the same volumes, as the
# storage-integrity tier does.
FS_HELPER_IMAGE="${FS_HELPER_IMAGE:-postgres:16-alpine}"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1"; }
sha_of(){ sha256sum "$1" | awk '{print $1}'; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 120 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }

# push_blob <file> -> HTTP code of the monolithic POST+PUT upload
push_blob(){
  local dg loc
  dg="sha256:$(sha_of "$1")"
  loc="$(curl -s -D - -o /dev/null -X POST -H "Authorization: Bearer $OCI_TOK" \
    "$BASE/v2/${REPO}/${IMG}/blobs/uploads/" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p' | head -1)"
  [ -n "$loc" ] || { echo 000; return; }
  case "$loc" in http*) ;; *) loc="$BASE$loc";; esac
  case "$loc" in *\?*) loc="${loc}&digest=${dg}";; *) loc="${loc}?digest=${dg}";; esac
  curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $OCI_TOK" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$1" "$loc" || echo 000
}
# scrub_repo -> HTTP code; summary in $W/api.body
scrub_repo(){ api POST /api/v1/admin/storage-scrub "{\"repair\":false,\"repository\":\"${REPO}\"}"; }
findings_for(){ # <artifact id> -> "status|expected_size|actual_size" lines
  psqlq "SELECT status||'|'||COALESCE(expected_size::text,'')||'|'||COALESCE(actual_size::text,'')
         FROM storage_scrub_findings WHERE object_id='$1'"
}

# =============================================================================
begin_suite "oci-manifest-scrub"

begin_test "setup: admin login, a docker repository, an image pushed (config, two layers, manifest)"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
REPO="ociscrub-${SFX}"; IMG="scrubbed"; TAG="1.0.0"
c1="$(api POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"docker",repo_type:"local",is_public:false}')")"
OCI_TOK="$(curl -s -u "admin:${ADMIN_PASS}" "$BASE/v2/token?service=artifact-keeper&scope=repository:${REPO}/${IMG}:push,pull" | jqr '.token // empty')"
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{"Labels":{"dtf":"%s"}}}' "$SFX" > "$W/config.json"
head -c 70000 /dev/urandom > "$W/layer1.bin"; head -c 30000 /dev/urandom > "$W/layer2.bin"
b1="$(push_blob "$W/config.json")"; b2="$(push_blob "$W/layer1.bin")"; b3="$(push_blob "$W/layer2.bin")"
jq -nc --arg c "sha256:$(sha_of "$W/config.json")" --argjson cs "$(wc -c < "$W/config.json")" \
  --arg l1 "sha256:$(sha_of "$W/layer1.bin")" --argjson s1 "$(wc -c < "$W/layer1.bin")" \
  --arg l2 "sha256:$(sha_of "$W/layer2.bin")" --argjson s2 "$(wc -c < "$W/layer2.bin")" \
  '{schemaVersion:2, mediaType:"application/vnd.oci.image.manifest.v1+json",
    config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$c,size:$cs},
    layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$l1,size:$s1},
            {mediaType:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$l2,size:$s2}]}' \
  | tr -d '\n' > "$W/manifest.json"
MAN_DIGEST="sha256:$(sha_of "$W/manifest.json")"; MAN_LEN="$(wc -c < "$W/manifest.json" | tr -d ' ')"
m="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $OCI_TOK" \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$W/manifest.json" \
  "$BASE/v2/${REPO}/${IMG}/manifests/${TAG}" || echo 000)"
RID="$(psqlq "SELECT id FROM repositories WHERE key='${REPO}'")"
MAN_ART="$(psqlq "SELECT id FROM artifacts WHERE repository_id='${RID}' AND storage_key='oci-manifests/${MAN_DIGEST}' AND is_deleted=false LIMIT 1")"
ART_SIZE="$(psqlq "SELECT size_bytes FROM artifacts WHERE id='${MAN_ART}'")"
OM_SIZE="$(psqlq "SELECT size_bytes FROM oci_manifests WHERE repository_id='${RID}' AND digest='${MAN_DIGEST}'")"
note "repo ${c1}; token ${OCI_TOK:+ok}; blobs ${b1}/${b2}/${b3}; manifest PUT ${m} (${MAN_LEN} bytes, ${MAN_DIGEST:0:19})"
note "manifest artifact ${MAN_ART}: artifacts.size_bytes=${ART_SIZE} oci_manifests.size_bytes=${OM_SIZE}"
if [[ "$c1" =~ ^20[01]$ ]] && [ -n "$OCI_TOK" ] && [ "$b1$b2$b3" = "201201201" ] && [ "$m" = "201" ] && [ -n "$MAN_ART" ]; then
  pass
else
  infra_fail "setup: $(printf '%s' "$DETAIL" | tr '\n' ' ')"; end_suite
fi

begin_test "CONTROL: the push recorded the manifest body length (oci_manifests) and the image size (artifacts) as different numbers"
reset_case
[ "$OM_SIZE" = "$MAN_LEN" ] || fail_g "oci_manifests.size_bytes=${OM_SIZE}, expected the body length ${MAN_LEN}"
[ -n "$ART_SIZE" ] && [ "$ART_SIZE" != "$MAN_LEN" ] || fail_g "artifacts.size_bytes=${ART_SIZE} equals the body length: the case would not exercise #4666"
finish_case "OCI push bookkeeping"

# -----------------------------------------------------------------------------
begin_test "FIX #4666: a report-only scrub of an intact image reports no corrupt object and records no finding"
reset_case
code="$(scrub_repo)"
note "scrub -> ${code}: $(abody | jq -c 'del(.findings)' 2>/dev/null || abody | head -c 300)"
if [ "$code" != "200" ]; then
  fail_g "POST /api/v1/admin/storage-scrub -> ${code}"
else
  [ "$(abody | jqr '.corrupt')" = "0" ] || fail_g "corrupt=$(abody | jqr '.corrupt') on an intact image"
  [ "$(abody | jqr '.missing')" = "0" ] || fail_g "missing=$(abody | jqr '.missing')"
  f="$(findings_for "$MAN_ART")"
  [ -z "$f" ] || fail_g "the intact manifest has a finding: ${f}"
  n="$(psqlq "SELECT count(*) FROM storage_scrub_findings WHERE repository_id='${RID}'")"
  [ "$n" = "0" ] || fail_g "${n} storage_scrub_findings row(s) for the intact image"
fi
finish_case "intact OCI manifest flagged as corrupt"

begin_test "CONTROL: the image's blobs and manifest are counted intact by the same scrub"
reset_case
intact="$(abody | jqr '.intact // 0')"
note "intact=${intact}"
[ "${intact:-0}" -ge 3 ] 2>/dev/null || fail_g "intact=${intact}, expected at least the three blobs"
finish_case "scrub did not walk the OCI repository"

# -----------------------------------------------------------------------------
begin_test "setup: truncate the stored manifest body by 20 bytes"
reset_case
ROOT="$(psqlq "SELECT storage_path FROM repositories WHERE id='${RID}'")"
# The filesystem layout shards keys; find the stored manifest by its name.
REF="$(fsx "find '${ROOT}' -type f -path '*oci-manifests*' -name '*${MAN_DIGEST#sha256:}*' 2>/dev/null | head -1" || true)"
if [ -z "$REF" ]; then
  REF="$(fsx "grep -rl -F '$(jq -r '.layers[0].digest' "$W/manifest.json")' '${ROOT}' 2>/dev/null | head -1" || true)"
fi
note "storage_path ${ROOT}; stored manifest: ${REF:-not found}"
if [ -n "$REF" ] && fsx "set -e; n=\$(wc -c < '$REF'); [ \"\$n\" = '${MAN_LEN}' ]; head -c $((MAN_LEN - 20)) '$REF' > /tmp/t; cat /tmp/t > '$REF'; wc -c < '$REF'" | grep -qx "$((MAN_LEN - 20))"; then
  pass
else
  infra_fail "could not locate or truncate the stored manifest body (${REF:-not found})"
fi

begin_test "CONTROL: a truncated manifest is still reported corrupt"
reset_case
code="$(scrub_repo)"
note "scrub -> ${code}: $(abody | jq -c 'del(.findings)' 2>/dev/null || abody | head -c 300)"
f="$(findings_for "$MAN_ART")"
note "manifest finding: ${f:-none}"
[ "$code" = "200" ] || fail_g "scrub -> ${code}"
[ "$(abody | jqr '.corrupt')" = "1" ] || fail_g "corrupt=$(abody | jqr '.corrupt'), expected exactly 1 (the manifest)"
case "$f" in corrupt\|*) ;; *) fail_g "no corrupt finding for the manifest artifact";; esac
finish_case "damaged manifest not reported"

begin_test "FIX #4666: the truncated manifest's finding expects the body length (oci_manifests.size_bytes), not the image size"
reset_case
IFS='|' read -r st exp act <<<"$(findings_for "$MAN_ART" | head -1)"
note "finding: status=${st} expected_size=${exp} actual_size=${act} (body ${MAN_LEN}, image ${ART_SIZE})"
[ "$exp" = "$OM_SIZE" ] || fail_g "expected_size=${exp}, expected oci_manifests.size_bytes=${OM_SIZE}"
[ "$act" = "$((MAN_LEN - 20))" ] || fail_g "actual_size=${act}, expected $((MAN_LEN - 20))"
finish_case "manifest finding measured against the image size"

end_suite
