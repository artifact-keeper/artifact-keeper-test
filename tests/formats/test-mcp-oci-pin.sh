#!/usr/bin/env bash
# test-mcp-oci-pin.sh - OCI packages in an own-repos MCP registry are pinned
# to a manifest digest at publish (artifact-keeper#5253).
#
# An image is pushed to a docker Local with the OCI distribution API over
# curl (config blob + one layer + manifest, tag 1.0.0; no daemon needed), the
# docker Local is mapped as `oci` in mcp_package_repos, and server.json
# entries name it as <ak-host>/<repo>/<image>:<tag>. <ak-host> is host[:port]
# of the request's external base URL (AK_EXTERNAL_URL when set, else
# BASE_URL): services/mcp_packages.rs oci_backing_path strips
# "<ak-host>/<repo>/" to find the image path.
#
# Asserted:
#   - a tag publish serves <ak-host>/<repo>/<image>:1.0.0@sha256:<manifest
#     digest> and _meta["com.artifactkeeper/resolved"] on the package
#   - :latest and tagless identifiers are 422 mcp_oci_floating_tag
#   - version / registryBaseUrl / fileSha256 on an OCI entry are 422
#     mcp_oci_legacy_fields
#   - re-pushing the tag with different content does not move the served
#     digest of the published version
#   - a digest-only publish serves @sha256:<digest> alone
#   - a tag+digest that disagree pins the digest
#   - optional: podman or docker pulls the served dual-form reference from
#     the backend (plain http); per-test skip when neither can
#
# Requires: curl, jq, python3, sha256sum, tar, gzip

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-oci-pin"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd sha256sum
require_cmd tar
require_cmd gzip
mcp_require_registry

MCP_KEY="test-mcp-oci-${RUN_ID}"
NS="io.github.ak-e2e-${RUN_ID}"
IMAGE="echo-image"
OCI_HOST=$(printf '%s' "${AK_EXTERNAL_URL:-$BASE_URL}" | sed -E 's#^[A-Za-z]+://##; s#/.*$##')

# ---------------------------------------------------------------------------
# OCI push over curl
# ---------------------------------------------------------------------------

REG_TOKEN=""
oci_token() {
  REG_TOKEN=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null) || REG_TOKEN=""
  [ -n "$REG_TOKEN" ]
}

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# oci_push_blob FILE: monolithic upload (POST then PUT ?digest=). 0 on 201.
oci_push_blob() {
  local f="$1" digest loc sep st
  digest="sha256:$(sha_of "$f")"
  loc=$(curl -s -D - -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" -X POST -H "Authorization: Bearer ${REG_TOKEN}" \
    "${BASE_URL}/v2/${MCP_OCI_KEY}/${IMAGE}/blobs/uploads/" 2>/dev/null \
    | grep -i '^location:' | tail -1 | tr -d '\r' | sed -E 's/^[Ll]ocation: *//')
  [ -n "$loc" ] || return 1
  case "$loc" in http*) ;; *) loc="${BASE_URL}${loc}" ;; esac
  sep='?'
  [[ "$loc" == *\?* ]] && sep='&'
  st=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
    -H "Authorization: Bearer ${REG_TOKEN}" -H "Content-Type: application/octet-stream" \
    --data-binary "@${f}" "${loc}${sep}digest=${digest}" 2>/dev/null) || st="000"
  [ "$st" = "201" ]
}

# oci_push_image TAG CONTENT: push a one-layer image whose single file holds
# CONTENT, tagged TAG. Sets OCI_DIGEST (manifest digest) and OCI_ERROR.
oci_push_image() {
  local tag="$1" content="$2" dir layer config manifest diff st
  dir=$(mktemp -d "${WORK_DIR}/img-XXXXXX")
  mkdir -p "${dir}/root"
  printf '%s\n' "$content" > "${dir}/root/hello.txt"
  layer="${dir}/layer.tar.gz"
  tar -cf - -C "${dir}/root" hello.txt | gzip -n > "$layer"
  diff=$(gzip -dc "$layer" | sha256sum | cut -d' ' -f1)
  config="${dir}/config.json"
  jq -cnj --arg d "sha256:${diff}" '{architecture:"amd64",os:"linux",config:{Cmd:["/hello.txt"]},rootfs:{type:"layers",diff_ids:[$d]}}' > "$config"
  oci_push_blob "$config" || { OCI_ERROR="config blob upload failed"; return 1; }
  oci_push_blob "$layer" || { OCI_ERROR="layer blob upload failed"; return 1; }
  manifest="${dir}/manifest.json"
  jq -cnj --arg cd "sha256:$(sha_of "$config")" --argjson cs "$(stat -c%s "$config")" \
    --arg ld "sha256:$(sha_of "$layer")" --argjson ls "$(stat -c%s "$layer")" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$ld,size:$ls}]}' > "$manifest"
  st=$(curl -s -o "${dir}/manifest.out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
    -H "Authorization: Bearer ${REG_TOKEN}" -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    --data-binary "@${manifest}" "${BASE_URL}/v2/${MCP_OCI_KEY}/${IMAGE}/manifests/${tag}" 2>/dev/null) || st="000"
  if [ "$st" != "201" ]; then
    OCI_ERROR="manifest PUT HTTP ${st}: $(head -c 300 "${dir}/manifest.out")"
    return 1
  fi
  OCI_DIGEST="sha256:$(sha_of "$manifest")"
}

# publish_oci NAME IDENTIFIER: publish a one-package OCI server, version 1.0.0.
publish_oci() {
  local f
  f=$(mktemp "${WORK_DIR}/doc-XXXXXX.json")
  mcp_server_json "$1" "1.0.0" "$(mcp_oci_package_json "$2")" > "$f"
  mcp_publish "$MCP_KEY" "$f"
}

served_id() { mcp_json '.server.packages[0].identifier // empty'; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create docker backing repository and push ${IMAGE}:1.0.0 over curl"
# shellcheck disable=SC2034 # read by mcp_package_repos_json
MCP_NPM_KEY=""
MCP_OCI_KEY="test-mcp-oci-${RUN_ID}-oci"
if ! create_local_repo "$MCP_OCI_KEY" docker; then
  fail_fatal "could not create docker repository ${MCP_OCI_KEY}"
fi
mcp_delete_repo_on_exit "$MCP_OCI_KEY"
if ! oci_token; then
  fail_fatal "could not obtain a registry token from /v2/token"
fi
if oci_push_image "1.0.0" "mcp-oci-pin ${RUN_ID} v1"; then
  DIGEST1="$OCI_DIGEST"
  echo "  pushed ${MCP_OCI_KEY}/${IMAGE}:1.0.0 = ${DIGEST1}"
  pass
else
  fail_fatal "image push failed: ${OCI_ERROR}"
fi

begin_test "Create MCP repository (own-repos, oci mapped)"
if mcp_create_repo "$MCP_KEY" "$(jq -cn --argjson m "$(mcp_package_repos_json)" '{mcp_package_repos:$m}')"; then
  pass
else
  fail_fatal "could not create MCP repository: ${MCP_CREATE_ERROR}"
fi

REF="${OCI_HOST}/${MCP_OCI_KEY}/${IMAGE}"

# ---------------------------------------------------------------------------
# Pinning
# ---------------------------------------------------------------------------

begin_test "A tag publish serves <host>/<repo>/<image>:1.0.0@sha256:<manifest digest>"
publish_oci "${NS}/tagged" "${REF}:1.0.0"
want="${REF}:1.0.0@${DIGEST1}"
if [ "$MCP_STATUS" != "200" ]; then
  fail "publish ${REF}:1.0.0 answered HTTP ${MCP_STATUS}" "$(mcp_snip)"
elif [ "$(served_id)" != "$want" ]; then
  fail "served identifier '$(served_id)', expected '${want}'"
else
  mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/tagged" "1.0.0")" anon
  if [ "$(served_id)" = "$want" ]; then pass; else fail "read serves '$(served_id)', expected '${want}'"; fi
fi

begin_test "The package carries _meta[\"com.artifactkeeper/resolved\"]"
res='.server.packages[0]._meta["com.artifactkeeper/resolved"]'
why=""
[ "$(mcp_json "${res}.submittedIdentifier")" = "${REF}:1.0.0" ] || why="${why} submittedIdentifier='$(mcp_json "${res}.submittedIdentifier")';"
[ "$(mcp_json "${res}.digest")" = "$DIGEST1" ] || why="${why} digest='$(mcp_json "${res}.digest")';"
[ "$(mcp_json "${res}.mediaType")" = "application/vnd.oci.image.manifest.v1+json" ] || why="${why} mediaType='$(mcp_json "${res}.mediaType")';"
[ "$(mcp_json "${res}.backingRepository")" = "$MCP_OCI_KEY" ] || why="${why} backingRepository='$(mcp_json "${res}.backingRepository")';"
[ -n "$(mcp_json "${res}.resolvedAt // empty")" ] || why="${why} no resolvedAt;"
if [ -z "$why" ]; then pass; else fail "resolved meta:${why}" "$(mcp_snip)"; fi

for case_line in "oci-latest.json:mcp_oci_floating_tag" "oci-tagless.json:mcp_oci_floating_tag" \
                 "oci-legacy-version.json:mcp_oci_legacy_fields" "oci-legacy-registry-base.json:mcp_oci_legacy_fields" \
                 "oci-legacy-sha.json:mcp_oci_legacy_fields"; do
  f="${case_line%%:*}"
  code="${case_line#*:}"
  begin_test "${f} is 422 ${code}"
  out="${WORK_DIR}/case-${f}"
  mcp_render_fixture "${MCP_FIXTURES_DIR}/server-json/own-repos/${f}" "$out" \
    "SLUG=oci-${RUN_ID}-${f%.json}" "OCI_REF=${REF}" "AK_BASE=${BASE_URL}"
  mcp_publish "$MCP_KEY" "$out"
  if r=$(mcp_check_problem 422 "$code"); then pass; else fail "$r"; fi
done

begin_test "Re-pushing the tag with different content does not move the served digest"
if ! oci_push_image "1.0.0" "mcp-oci-pin ${RUN_ID} v2 moved"; then
  fail "re-push failed: ${OCI_ERROR}"
else
  DIGEST2="$OCI_DIGEST"
  mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/tagged" "1.0.0")" anon
  got=$(served_id)
  mcp_get "$MCP_KEY" "servers/$(mcp_encode_name "${NS}/tagged")/versions/latest" anon
  lat=$(served_id)
  if [ "$DIGEST2" = "$DIGEST1" ]; then
    fail "re-push produced the same digest; the fixture did not move the tag"
  elif [ "$MCP_STATUS" = "200" ] && [ "$got" = "${REF}:1.0.0@${DIGEST1}" ] && [ "$lat" = "$got" ]; then
    pass
  else
    fail "after the tag moved to ${DIGEST2}: exact='${got}' latest='${lat}' (HTTP ${MCP_STATUS}), expected the ${DIGEST1} pin"
  fi
fi

begin_test "A new version published by tag after the move pins the new digest"
publish_oci "${NS}/tagged-again" "${REF}:1.0.0"
if [ "$MCP_STATUS" = "200" ] && [ "$(served_id)" = "${REF}:1.0.0@${DIGEST2}" ]; then
  pass
else
  fail "HTTP ${MCP_STATUS} served '$(served_id)', expected '${REF}:1.0.0@${DIGEST2}'" "$(mcp_snip)"
fi

begin_test "A digest-only publish serves @sha256:<digest> alone"
publish_oci "${NS}/by-digest" "${REF}@${DIGEST2}"
if [ "$MCP_STATUS" = "200" ] && [ "$(served_id)" = "${REF}@${DIGEST2}" ] \
   && [ "$(mcp_json '.server.packages[0]._meta["com.artifactkeeper/resolved"].digest')" = "$DIGEST2" ]; then
  pass
else
  fail "HTTP ${MCP_STATUS} served '$(served_id)', expected '${REF}@${DIGEST2}'" "$(mcp_snip)"
fi

begin_test "A tag+digest that disagree pins the digest"
# The tag 1.0.0 now names DIGEST2; the identifier names DIGEST1, which the
# first pin kept a manifest record for.
publish_oci "${NS}/mismatch" "${REF}:1.0.0@${DIGEST1}"
if [ "$MCP_STATUS" = "200" ] && [ "$(served_id)" = "${REF}:1.0.0@${DIGEST1}" ] \
   && [ "$(mcp_json '.server.packages[0]._meta["com.artifactkeeper/resolved"].digest')" = "$DIGEST1" ]; then
  pass
else
  fail "HTTP ${MCP_STATUS} served '$(served_id)', expected '${REF}:1.0.0@${DIGEST1}'" "$(mcp_snip)"
fi

begin_test "An unknown digest is 422 mcp_package_not_found"
publish_oci "${NS}/unknown-digest" "${REF}@sha256:$(printf 'absent-%s' "$RUN_ID" | sha256sum | cut -d' ' -f1)"
if r=$(mcp_check_problem 422 mcp_package_not_found); then pass; else fail "$r"; fi

# ---------------------------------------------------------------------------
# Optional run leg
# ---------------------------------------------------------------------------

begin_test "A container client pulls the served dual-form reference"
mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/tagged" "1.0.0")" anon
PULL_REF=$(served_id)
pulled=""
pull_log="${WORK_DIR}/pull.log"
if command -v podman >/dev/null 2>&1 && timeout 120 podman pull --tls-verify=false "$PULL_REF" > "$pull_log" 2>&1; then
  pulled=podman
  got=$(podman image inspect --format '{{.Digest}}' "$PULL_REF" 2>/dev/null || true)
  podman rmi -f "$PULL_REF" >/dev/null 2>&1 || true
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && timeout 120 docker pull "$PULL_REF" > "$pull_log" 2>&1; then
  pulled=docker
  got="${PULL_REF##*@}"
  docker rmi -f "$PULL_REF" >/dev/null 2>&1 || true
fi
if [ -z "$pulled" ]; then
  skip "neither podman nor docker could pull ${PULL_REF} from the backend over plain http ($(tail -c 200 "$pull_log" 2>/dev/null | tr '\n' ' '))"
elif [ "$got" = "$DIGEST1" ]; then
  pass
else
  fail "${pulled} pulled ${PULL_REF} but the image digest is '${got}', expected ${DIGEST1}"
fi

end_suite
