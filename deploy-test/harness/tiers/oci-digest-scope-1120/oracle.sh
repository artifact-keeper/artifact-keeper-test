#!/usr/bin/env bash
# =============================================================================
# tiers/oci-digest-scope-1120/oracle.sh
#   a hosted OCI digest resolves only under the image that holds it
#   (artifact-keeper#5793), tags/list answers `name` with the full request name
#   (#5794), and a Remote repairs a corrupt stored blob from its upstream
#   (#5169).
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-oci-classify` with
# UPSTREAM_ALLOW_PRIVATE_IPS=true and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's control
# port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the
# bugs and the controls.
#
# Every probe is the OCI distribution wire protocol (curl of /v2 routes). psql
# reads the staged blob's storage key, and a throwaway container rewrites one
# byte of that object: both only stage the #5169 precondition.
# Setup failures use infra_fail(): the candidate is unjudged (exit 11).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${TRIVY_PORT:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe below is judged explicitly by the
# assertion that reads it, so a failing probe must not end the oracle early.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
MOCK_CTL="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${SLOT}.83/"
FS_HELPER_IMAGE="${ODS_FS_HELPER_IMAGE:-postgres:16-alpine}"

HOSTED="odsh-${SLOT}-${SUF}"     # local docker repo: the #5793 / #5794 fixture
VIRT="odsv-${SLOT}-${SUF}"       # Virtual over HOSTED
REMOTE="odsr-${SLOT}-${SUF}"     # Remote over the mock, scan-on-proxy fail_closed

IMG="aktest/tags"     # pushed
NEVER="nobody/ever"   # never pushed
OTHER="other/img"     # holds a different image

MT_OCI='application/vnd.oci.image.manifest.v1+json'
MT_INDEX='application/vnd.oci.image.index.v1+json'
MT_DOCKER='application/vnd.docker.distribution.manifest.v2+json'
ACCEPT_ALL="${MT_OCI}, ${MT_INDEX}, ${MT_DOCKER}"

WORK="$(mktemp -d -t dtf-ods-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ----------------------------------------------------------------
# --path-as-is on every /v2 probe: references carry `sha256:` colons.
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" --path-as-is "$@" "$url" 2>/dev/null || echo 000
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
size_of() { wc -c < "$1" 2>/dev/null | tr -d '[:space:]'; }
db() { { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; } | tr -d '[:space:]'; }
jqr() { jq -r "$1" 2>/dev/null || true; }
oci_code() { jqr '.errors[0].code // empty' < "$1"; }
snip() { head -c 200 "$1" 2>/dev/null | tr -d '\n'; }

AUTHZ=()   # set after auth_admin

push_blob() { # REPO IMAGE FILE -> http code (monolithic POST ?digest=)
  code_to_file "${BASE_URL}/v2/${1}/${2}/blobs/uploads/?digest=sha256:$(sha_of "$3")" /dev/null -X POST \
    "${AUTHZ[@]}" -H 'Content-Type: application/octet-stream' --data-binary "@${3}"
}
put_manifest() { # REPO IMAGE REF FILE MEDIATYPE -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/${3}" /dev/null -X PUT \
    "${AUTHZ[@]}" -H "Content-Type: ${5}" --data-binary "@${4}"
}
get_manifest() { # REPO IMAGE REF OUTFILE -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/${3}" "$4" "${AUTHZ[@]}" -H "Accept: ${ACCEPT_ALL}"
}
head_manifest() { # REPO IMAGE REF -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/${3}" /dev/null -I "${AUTHZ[@]}" -H "Accept: ${ACCEPT_ALL}"
}
get_blob() { # REPO IMAGE DIGEST OUTFILE -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/blobs/${3}" "$4" "${AUTHZ[@]}"
}
head_blob() { # REPO IMAGE DIGEST -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/blobs/${3}" /dev/null -I "${AUTHZ[@]}"
}
mount_blob() { # TARGET_REPO TARGET_IMAGE DIGEST FROM -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/blobs/uploads/?mount=${3}&from=${4}" /dev/null -X POST \
    "${AUTHZ[@]}" -H 'Content-Length: 0'
}
tags_list() { # REPO IMAGE QUERY OUTFILE -> http code (headers in OUTFILE.h)
  code_to_file "${BASE_URL}/v2/${1}/${2}/tags/list${3}" "$4" -D "${4}.h" "${AUTHZ[@]}"
}

# make_image SALT -> $WORK/<salt>.{cfg,l1,manifest} (OCI image, one layer)
make_image() {
  local s="$1" cfg="${WORK}/${1}.cfg" l="${WORK}/${1}.l1"
  printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"salt":"%s-%s"}' "$s" "$SUF" > "$cfg"
  printf 'dtf-ods-layer-%s-%s' "$s" "$SUF" > "$l"
  printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":%s,"digest":"sha256:%s"},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":%s,"digest":"sha256:%s"}]}' \
    "$MT_OCI" "$(size_of "$cfg")" "$(sha_of "$cfg")" "$(size_of "$l")" "$(sha_of "$l")" > "${WORK}/${s}.manifest"
}
push_image_blobs() { # REPO IMAGE SALT -> "" or diagnostics
  local f="" c
  c="$(push_blob "$1" "$2" "${WORK}/${3}.cfg")"; is_2xx "$c" || f="${f} ${3}.cfg=${c}"
  c="$(push_blob "$1" "$2" "${WORK}/${3}.l1")"; is_2xx "$c" || f="${f} ${3}.l1=${c}"
  echo "$f"
}
digest_of() { echo "sha256:$(sha_of "$1")"; }

# --- storage access (filesystem volume of the backend) ------------------------
fsx() { docker run --rm -i --name "ak-dtf${SLOT}-odsfsx-$$" --volumes-from "$BACKEND_CTR" \
  --entrypoint sh "$FS_HELPER_IMAGE" -c "$1"; }
repo_root() { db "SELECT storage_path FROM repositories WHERE key='$1';"; }
obj_put() { # REPO KEY INFILE: overwrite the stored object, keep ownership
  local root; root="$(repo_root "$1")"
  fsx "set -e; f='$root/$2'; o=\$(stat -c %u:%g \"\$f\"); cat > \"\$f\"; chown \"\$o\" \"\$f\"" < "$3"
}
obj_sha() { local f="${WORK}/objsha"; fsx "cat '$(repo_root "$1")/$2'" > "$f" 2>/dev/null; sha_of "$f"; }
# flip REPO KEY ORIGINAL: rewrite the object with one byte changed (same size)
# and confirm the store now holds different bytes.
flip() {
  local bad="${WORK}/bad.bin" off b; cp "$3" "$bad"
  off=$(( $(size_of "$bad") / 2 ))
  b="$(od -An -tu1 -j "$off" -N1 "$bad" | tr -d '[:space:]')"
  if [ "$b" = "0" ]; then printf '\001'; else printf '\000'; fi | dd of="$bad" bs=1 seek="$off" conv=notrunc 2>/dev/null
  obj_put "$1" "$2" "$bad" || return 1
  local now; now="$(obj_sha "$1" "$2")"
  [ -n "$now" ] && [ "$now" = "$(sha_of "$bad")" ] && [ "$now" != "$(sha_of "$3")" ]
}

begin_suite "oci-digest-scope-1120"

# ===========================================================================
# SETUP
# ===========================================================================
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

api() { # METHOD PATH [JSON] -> http code, body in $WORK/api.json
  local -a a=(-X "$1" "${AUTHZ[@]}")
  [ $# -ge 3 ] && a+=(-H 'Content-Type: application/json' -d "$3")
  code_to_file "${BASE_URL}$2" "${WORK}/api.json" "${a[@]}"
}
mk_repo() { # KEY TYPE [EXTRA_JSON]
  local c; c="$(api POST /api/v1/repositories \
    "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"docker\",\"repo_type\":\"${2}\",\"is_public\":false${3:-}}")"
  is_2xx "$c" || echo " create ${1}=${c} $(snip "${WORK}/api.json")"
}

begin_test "setup: hosted, Virtual and scan-on-proxy Remote docker repositories; fixture images over /v2"
ERR=""
ERR="${ERR}$(mk_repo "$HOSTED" local)$(mk_repo "$VIRT" virtual)"
ERR="${ERR}$(mk_repo "$REMOTE" remote ",\"upstream_url\":\"${UPSTREAM}\"")"
c="$(api POST "/api/v1/repositories/${VIRT}/members" "{\"member_key\":\"${HOSTED}\",\"priority\":1}")"
is_2xx "$c" || ERR="${ERR} virtual member=${c}"
c="$(api PUT "/api/v1/repositories/${REMOTE}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true}')"
[ "$c" = "200" ] || ERR="${ERR} remote security=${c} $(snip "${WORK}/api.json")"

# aktest/tags: platform image `plat` pushed by digest, an index over it as 1.0;
# `old` then `new` pushed as `moving` (the #1681 overwrite). other/img: `oth`.
make_image plat; make_image old; make_image new; make_image oth
PLAT_D="$(digest_of "${WORK}/plat.manifest")"
printf '{"schemaVersion":2,"mediaType":"%s","manifests":[{"mediaType":"%s","size":%s,"digest":"%s","platform":{"architecture":"amd64","os":"linux"}}]}' \
  "$MT_INDEX" "$MT_OCI" "$(size_of "${WORK}/plat.manifest")" "$PLAT_D" > "${WORK}/index.json"
IDX_D="$(digest_of "${WORK}/index.json")"
LAYER_D="$(digest_of "${WORK}/plat.l1")"
OLD_D="$(digest_of "${WORK}/old.manifest")"
NEW_D="$(digest_of "${WORK}/new.manifest")"
ERR="${ERR}$(push_image_blobs "$HOSTED" "$IMG" plat)$(push_image_blobs "$HOSTED" "$IMG" old)"
ERR="${ERR}$(push_image_blobs "$HOSTED" "$IMG" new)$(push_image_blobs "$HOSTED" "$OTHER" oth)"
c="$(put_manifest "$HOSTED" "$IMG" "$PLAT_D" "${WORK}/plat.manifest" "$MT_OCI")"; is_2xx "$c" || ERR="${ERR} plat@d=${c}"
c="$(put_manifest "$HOSTED" "$IMG" 1.0 "${WORK}/index.json" "$MT_INDEX")"; is_2xx "$c" || ERR="${ERR} index:1.0=${c}"
c="$(put_manifest "$HOSTED" "$IMG" moving "${WORK}/old.manifest" "$MT_OCI")"; is_2xx "$c" || ERR="${ERR} old:moving=${c}"
c="$(put_manifest "$HOSTED" "$IMG" moving "${WORK}/new.manifest" "$MT_OCI")"; is_2xx "$c" || ERR="${ERR} new:moving=${c}"
c="$(put_manifest "$HOSTED" "$OTHER" 1.0 "${WORK}/oth.manifest" "$MT_OCI")"; is_2xx "$c" || ERR="${ERR} other:1.0=${c}"
if [ -n "${ERR// /}" ]; then infra_fail "fixture setup failed:${ERR}"; end_suite; fi
pass

# ===========================================================================
# #5793: a hosted digest resolves only under the image that holds it
# ===========================================================================
begin_test "CONTROL: ${IMG} serves its index, platform manifest and layer by digest, byte-identical"
a="$(get_manifest "$HOSTED" "$IMG" "$IDX_D" "${WORK}/g-idx")"
b="$(get_manifest "$HOSTED" "$IMG" "$PLAT_D" "${WORK}/g-plat")"
l="$(get_blob "$HOSTED" "$IMG" "$LAYER_D" "${WORK}/g-layer")"
if [ "$a$b$l" = "200200200" ] && [ "$(digest_of "${WORK}/g-idx")" = "$IDX_D" ] && \
   [ "$(digest_of "${WORK}/g-plat")" = "$PLAT_D" ] && [ "$(digest_of "${WORK}/g-layer")" = "$LAYER_D" ]; then pass
else fail "index=${a} platform=${b} layer=${l}, want 200 and the pushed bytes for all three"; fi

begin_test "CONTROL: tags/list of the never-pushed ${NEVER} is 404 NAME_UNKNOWN"
c="$(tags_list "$HOSTED" "$NEVER" "" "${WORK}/tl-never")"
if [ "$c" = "404" ] && [ "$(oci_code "${WORK}/tl-never")" = "NAME_UNKNOWN" ]; then pass
else fail "HTTP ${c} code=$(oci_code "${WORK}/tl-never"), want 404 NAME_UNKNOWN" "$(snip "${WORK}/tl-never")"; fi

begin_test "CONTROL (#1681): the old digest of the overwritten tag moving stays pullable under ${IMG}, and moving names the new one"
a="$(get_manifest "$HOSTED" "$IMG" "$OLD_D" "${WORK}/g-old")"
b="$(get_manifest "$HOSTED" "$IMG" moving "${WORK}/g-moving")"
if [ "$a" = "200" ] && [ "$(digest_of "${WORK}/g-old")" = "$OLD_D" ] && \
   [ "$b" = "200" ] && [ "$(digest_of "${WORK}/g-moving")" = "$NEW_D" ]; then pass
else fail "old digest=${a} ($(digest_of "${WORK}/g-old")), moving=${b} ($(digest_of "${WORK}/g-moving")), want 200 ${OLD_D} and 200 ${NEW_D}"; fi

begin_test "CONTROL: a blob uploaded under a fresh name HEADs and GETs under it before any manifest names it"
printf 'dtf-ods-fresh-%s' "$SUF" > "${WORK}/fresh.bin"; FRESH_D="$(digest_of "${WORK}/fresh.bin")"
u="$(push_blob "$HOSTED" fresh/upload "${WORK}/fresh.bin")"
h="$(head_blob "$HOSTED" fresh/upload "$FRESH_D")"
g="$(get_blob "$HOSTED" fresh/upload "$FRESH_D" "${WORK}/g-fresh")"
if [ "$u" = "201" ] && [ "$h" = "200" ] && [ "$g" = "200" ]; then pass
else fail "upload=${u} HEAD=${h} GET=${g}, want 201 200 200"; fi

begin_test "CONTROL: a manifest PUT under a second name that only references existing blobs is accepted, and its layer pulls there"
p="$(put_manifest "$HOSTED" second/name v1 "${WORK}/plat.manifest" "$MT_OCI")"
g="$(get_blob "$HOSTED" second/name "$LAYER_D" "${WORK}/g-second")"
if [ "$p" = "201" ] && [ "$g" = "200" ] && [ "$(digest_of "${WORK}/g-second")" = "$LAYER_D" ]; then pass
else fail "manifest PUT=${p} layer GET=${g}, want 201 and 200"; fi

begin_test "CONTROL: a same-repository mount from the never-pushed ${NEVER} starts an upload (202)"
m="$(mount_blob "$HOSTED" same/target "$LAYER_D" "${HOSTED}/${NEVER}")"
if [ "$m" = "202" ]; then pass; else fail "mount=${m}, want 202"; fi

begin_test "FIX #5793: the index digest of ${IMG}:1.0 is 404 MANIFEST_UNKNOWN under the never-pushed ${NEVER} (GET and HEAD)"
g="$(get_manifest "$HOSTED" "$NEVER" "$IDX_D" "${WORK}/n-idx")"
h="$(head_manifest "$HOSTED" "$NEVER" "$IDX_D")"
if [ "$g" = "404" ] && [ "$(oci_code "${WORK}/n-idx")" = "MANIFEST_UNKNOWN" ] && [ "$h" = "404" ]; then pass
else fail "GET=${g} code=$(oci_code "${WORK}/n-idx") HEAD=${h}, want 404 MANIFEST_UNKNOWN; pre-#5793 the repository-wide row answered" "$(snip "${WORK}/n-idx")"; fi

begin_test "FIX #5793: the platform manifest digest is 404 MANIFEST_UNKNOWN under the never-pushed ${NEVER} (GET and HEAD)"
g="$(get_manifest "$HOSTED" "$NEVER" "$PLAT_D" "${WORK}/n-plat")"
h="$(head_manifest "$HOSTED" "$NEVER" "$PLAT_D")"
if [ "$g" = "404" ] && [ "$(oci_code "${WORK}/n-plat")" = "MANIFEST_UNKNOWN" ] && [ "$h" = "404" ]; then pass
else fail "GET=${g} code=$(oci_code "${WORK}/n-plat") HEAD=${h}, want 404 MANIFEST_UNKNOWN" "$(snip "${WORK}/n-plat")"; fi

begin_test "FIX #5793: the layer is 404 BLOB_UNKNOWN under the never-pushed ${NEVER} (GET and HEAD)"
g="$(get_blob "$HOSTED" "$NEVER" "$LAYER_D" "${WORK}/n-layer")"
h="$(head_blob "$HOSTED" "$NEVER" "$LAYER_D")"
if [ "$g" = "404" ] && [ "$(oci_code "${WORK}/n-layer")" = "BLOB_UNKNOWN" ] && [ "$h" = "404" ]; then pass
else fail "GET=${g} code=$(oci_code "${WORK}/n-layer") HEAD=${h}, want 404 BLOB_UNKNOWN" "$(snip "${WORK}/n-layer")"; fi

begin_test "FIX #5793: ${OTHER} (which holds a different image) answers 404 for ${IMG}'s index and layer"
g="$(get_manifest "$HOSTED" "$OTHER" "$IDX_D" "${WORK}/o-idx")"
l="$(get_blob "$HOSTED" "$OTHER" "$LAYER_D" "${WORK}/o-layer")"
if [ "$g" = "404" ] && [ "$(oci_code "${WORK}/o-idx")" = "MANIFEST_UNKNOWN" ] && \
   [ "$l" = "404" ] && [ "$(oci_code "${WORK}/o-layer")" = "BLOB_UNKNOWN" ]; then pass
else fail "index GET=${g} ($(oci_code "${WORK}/o-idx")) layer GET=${l} ($(oci_code "${WORK}/o-layer")), want 404 MANIFEST_UNKNOWN / BLOB_UNKNOWN"; fi

begin_test "FIX #5793: through the Virtual, ${NEVER} answers 404 for the index digest and the layer"
g="$(get_manifest "$VIRT" "$NEVER" "$IDX_D" "${WORK}/v-idx")"
l="$(get_blob "$VIRT" "$NEVER" "$LAYER_D" "${WORK}/v-layer")"
a="$(get_manifest "$VIRT" "$IMG" "$IDX_D" "${WORK}/v-idx-ok")"
if [ "$g" = "404" ] && [ "$l" = "404" ] && [ "$a" = "200" ]; then pass
else fail "virtual ${NEVER}@index=${g} ${NEVER} layer=${l} (holder ${IMG}@index=${a}), want 404 404 (and 200)" "$(snip "${WORK}/v-idx")"; fi

# ===========================================================================
# #5794: tags/list answers `name` with the full request name
# ===========================================================================
begin_test "CONTROL: tags/list of ${IMG} lists exactly 1.0 and moving"
c="$(tags_list "$HOSTED" "$IMG" "" "${WORK}/tl")"
t="$(jqr '[.tags[]] | sort | join(",")' < "${WORK}/tl")"
if [ "$c" = "200" ] && [ "$t" = "1.0,moving" ]; then pass
else fail "HTTP ${c} tags='${t}', want 200 1.0,moving" "$(snip "${WORK}/tl")"; fi

begin_test "FIX #5794: tags/list answers name ${HOSTED}/${IMG} (the request name), unpaginated and with ?n=1"
n0="$(jqr '.name' < "${WORK}/tl")"
c1="$(tags_list "$HOSTED" "$IMG" "?n=1" "${WORK}/tl1")"; n1="$(jqr '.name' < "${WORK}/tl1")"
lk="$(grep -i '^link:' "${WORK}/tl1.h" 2>/dev/null | tr -d '\r')"
if [ "$n0" = "${HOSTED}/${IMG}" ] && [ "$c1" = "200" ] && [ "$n1" = "${HOSTED}/${IMG}" ] && \
   printf '%s' "$lk" | grep -qF "/v2/${HOSTED}/${IMG}/tags/list"; then pass
else fail "name='${n0}', ?n=1 HTTP ${c1} name='${n1}' ${lk:-no Link}, want '${HOSTED}/${IMG}' and a Link naming it"; fi

begin_test "FIX #5794: tags/list through the Virtual answers name ${VIRT}/${IMG}"
c="$(tags_list "$VIRT" "$IMG" "" "${WORK}/tlv")"; n="$(jqr '.name' < "${WORK}/tlv")"
if [ "$c" = "200" ] && [ "$n" = "${VIRT}/${IMG}" ]; then pass
else fail "HTTP ${c} name='${n}', want 200 '${VIRT}/${IMG}'" "$(snip "${WORK}/tlv")"; fi

# ===========================================================================
# #5169: a Remote repairs a corrupt stored blob from its upstream
# ===========================================================================
begin_test "setup (#5169): the scan-on-proxy Remote pulls the runnable image, staging its layer in oci_blobs"
ERR=""
c="$(code_to_file "${BASE_URL}/v2/${REMOTE}/app/manifests/runnable" "${WORK}/r-man" --max-time 180 "${AUTHZ[@]}" -H "Accept: ${ACCEPT_ALL}")"
[ "$c" = "200" ] || ERR="${ERR} manifest pull=${c} $(snip "${WORK}/r-man")"
RL_D="$(jqr '.layers[0].digest // empty' < "${WORK}/r-man")"
[ -n "$RL_D" ] || ERR="${ERR} no layer digest in the manifest"
c="$(code_to_file "${MOCK_CTL}/v2/app/blobs/${RL_D}" "${WORK}/r-layer.orig")"
{ [ "$c" = "200" ] && [ "$(digest_of "${WORK}/r-layer.orig")" = "$RL_D" ]; } || ERR="${ERR} upstream layer read=${c}"
RL_KEY="$(db "SELECT ob.storage_key FROM oci_blobs ob JOIN repositories r ON r.id = ob.repository_id
  WHERE r.key = '${REMOTE}' AND ob.digest = '${RL_D}';")"
[ -n "$RL_KEY" ] || ERR="${ERR} no oci_blobs row for the staged layer"
if [ -n "${ERR// /}" ]; then infra_fail "Remote staging failed:${ERR}"; end_suite; fi
echo "   staged layer ${RL_D} ($(size_of "${WORK}/r-layer.orig") bytes) at ${RL_KEY}"
pass

begin_test "CONTROL: the Remote serves the intact staged layer byte-identical"
c="$(get_blob "$REMOTE" app "$RL_D" "${WORK}/r-ok")"
if [ "$c" = "200" ] && [ "$(digest_of "${WORK}/r-ok")" = "$RL_D" ]; then pass
else fail "HTTP ${c} sha=$(digest_of "${WORK}/r-ok"), want 200 ${RL_D}"; fi

begin_test "FIX #5169: a corrupt stored layer on the Remote is refetched from upstream: 200 with the digest's bytes, and the stored object is repaired"
if ! flip "$REMOTE" "$RL_KEY" "${WORK}/r-layer.orig"; then
  infra_fail "could not corrupt the stored object ${RL_KEY}"
else
  c="$(get_blob "$REMOTE" app "$RL_D" "${WORK}/r-bad")"
  got="$(digest_of "${WORK}/r-bad")"; now="sha256:$(obj_sha "$REMOTE" "$RL_KEY")"
  if [ "$c" = "200" ] && [ "$got" = "$RL_D" ] && [ "$now" = "$RL_D" ]; then pass
  else
    why="HTTP ${c} code=$(oci_code "${WORK}/r-bad") body sha=${got:7:16} stored sha=${now:7:16}, want 200 and ${RL_D:7:16} for both"
    [ "$c" = "502" ] && why="${why}; pre-#5169 a Remote answered 502 STORED_OBJECT_INTEGRITY on every pull"
    [ "$c" = "200" ] && [ "$got" != "$RL_D" ] && why="${why}; the corrupt stored bytes were served"
    fail "$why"
  fi
  begin_test "FIX #5169: the next pull of the repaired layer is 200 byte-identical"
  c="$(get_blob "$REMOTE" app "$RL_D" "${WORK}/r-again")"
  if [ "$c" = "200" ] && [ "$(digest_of "${WORK}/r-again")" = "$RL_D" ]; then pass
  else fail "HTTP ${c} code=$(oci_code "${WORK}/r-again") sha=$(digest_of "${WORK}/r-again"), want 200 ${RL_D}"; fi
fi

end_suite
