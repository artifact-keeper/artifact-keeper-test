#!/usr/bin/env bash
# =============================================================================
# tiers/migration/nexus_seed.sh — enable Docker realm + seed the #2457 fixtures
# =============================================================================
# VENDORED + adapted from rig/harness/nexus_seed.sh (endpoints come from
# nexus_lib.sh per-slot; logic verbatim). All steps idempotent:
#   1. Enable the Docker Bearer Token realm (DockerToken).
#   2. Create a Docker HOSTED repo `docker-hosted` (HTTP connector, in-container
#      port 8082, published to host :${NEXUS_DOCKER_PORT}).
#   3. docker login the connector.
#   4. Seed three fixtures — one per #2457 defect class:
#        (a) single-arch  -> Finding 1 (config-blob 404 after migration)
#        (b) multi-arch   -> Finding 1 (child manifest) + Finding 2 (recursion)
#            *** the leg the pre-v1.5.8 fix missed — MUST be exercised ***
#        (c) large-multi  -> Finding 2 (manifest/size handling on a big index)
#   5. Record index/child/config digests to the fixtures state file so the
#      oracle can assert exact /v2 paths.
# skopeo runs containerized (host has none) with --network host so it reaches
# the connector at 127.0.0.1:${NEXUS_DOCKER_PORT}.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

# Source images (small, multi-arch public images). Pinned by tag for determinism.
SRC_SINGLE="${SRC_SINGLE:-docker.io/library/busybox:1.36}"
SRC_MULTI="${SRC_MULTI:-docker.io/library/busybox:1.36}"
SRC_LARGE="${SRC_LARGE:-docker.io/library/debian:bookworm-slim}"

DEST="${NEXUS_DOCKER}"           # 127.0.0.1:${NEXUS_DOCKER_PORT}
DCREDS="${NEXUS_ADMIN_USER}:$(nx_pass)"

nexus_is_up || die "Nexus is not running — run nexus_bootstrap.sh first."
[ -f "${NEXUS_PASS_FILE}" ] || die "No resolved admin password — run nexus_bootstrap.sh first."

# Materialise the (digest-pinned) skopeo image up front, with the pull output
# on the log, instead of letting the first silenced `skopeo` call pull it.
skopeo_ensure_image || die "skopeo image unavailable — cannot seed Nexus fixtures"

# --- 1. enable DockerToken realm ---------------------------------------------
log "Ensuring DockerToken realm is active ..."
active=$(nx_curl GET /service/rest/v1/security/realms/active)
if echo "$active" | grep -q 'DockerToken'; then
  log "DockerToken realm already active."
else
  newlist=$(echo "$active" | jq -c '. + ["DockerToken"] | unique')
  code=$(nx_curl PUT /service/rest/v1/security/realms/active \
      -H 'Content-Type: application/json' --data "$newlist" -o /dev/null -w '%{http_code}')
  log "realms/active PUT -> HTTP ${code} (list: ${newlist})"
fi

# --- 2. create docker-hosted repo with HTTP connector -------------------------
log "Ensuring docker-hosted repo '${NEXUS_DOCKER_REPO}' with HTTP :${NEXUS_DOCKER_HTTP_PORT} ..."
if nx_curl GET "/service/rest/v1/repositories" | jq -e --arg n "${NEXUS_DOCKER_REPO}" '.[]|select(.name==$n)' >/dev/null 2>&1; then
  log "Repo '${NEXUS_DOCKER_REPO}' already exists."
else
  body=$(jq -nc --arg name "${NEXUS_DOCKER_REPO}" --argjson port "${NEXUS_DOCKER_HTTP_PORT}" '{
    name:$name, online:true,
    storage:{blobStoreName:"default", strictContentTypeValidation:true, writePolicy:"ALLOW"},
    docker:{v1Enabled:false, forceBasicAuth:true, httpPort:$port, subdomain:null}
  }')
  code=$(nx_curl POST "/service/rest/v1/repositories/docker/hosted" \
      -H 'Content-Type: application/json' --data "$body" -o /dev/null -w '%{http_code}')
  log "create docker/hosted -> HTTP ${code}"
  [ "$code" = "201" ] || warn "unexpected create status ${code}"
  # Give Nexus a moment to bind the new connector port.
  for _ in $(seq 1 20); do
    curl -s -o /dev/null "http://${DEST}/v2/" && break || sleep 2
  done
fi

# --- 3. docker login the connector ---------------------------------------------
log "docker login ${DEST} ..."
echo "$(nx_pass)" | docker login "${DEST}" -u "${NEXUS_ADMIN_USER}" --password-stdin >&2 \
  || warn "docker login failed (skopeo copy uses --dest-creds directly, continuing)"

# --- 4/5. seed fixtures + record digests ----------------------------------------
# raw_digest <docker-ref>  -> prints sha256:<hex> of the exact manifest bytes
raw_digest() {
  local ref="$1"
  skopeo inspect --raw --tls-verify=false --creds "${DCREDS}" "docker://${ref}" 2>/dev/null \
    | sha256sum | awk '{print "sha256:"$1}'
}
raw_json() {
  local ref="$1"
  skopeo inspect --raw --tls-verify=false --creds "${DCREDS}" "docker://${ref}" 2>/dev/null
}
dest_exists() {
  skopeo inspect --raw --tls-verify=false --creds "${DCREDS}" "docker://${DEST}/$1" >/dev/null 2>&1
}

seed_one() {  # $1=name:tag  $2=src  $3=multiarch(all|system)
  local nametag="$1" src="$2" mode="$3"
  if dest_exists "$nametag"; then
    log "fixture ${nametag} already present (skip copy)."
  else
    log "copying ${src} -> ${DEST}/${nametag} (multi-arch=${mode}) ..."
    local marg=""; [ "$mode" = "all" ] && marg="--multi-arch all" || marg="--multi-arch system"
    # shellcheck disable=SC2086
    skopeo copy $marg --dest-tls-verify=false --dest-creds "${DCREDS}" \
      "docker://${src}" "docker://${DEST}/${nametag}" >&2 \
      || die "skopeo copy failed for ${nametag}"
  fi
}

seed_one "single-arch:latest" "${SRC_SINGLE}" system
seed_one "multi-arch:latest"  "${SRC_MULTI}"  all
seed_one "large-multi:latest" "${SRC_LARGE}"  all

log "Recording fixture digests ..."

# --- single-arch: top manifest is an image manifest; grab its config digest
sa_top=$(raw_digest "${DEST}/single-arch:latest")
sa_json=$(raw_json "${DEST}/single-arch:latest")
sa_config=$(echo "$sa_json" | jq -r '.config.digest // empty')
sa_mediatype=$(echo "$sa_json" | jq -r '.mediaType // "unknown"')

# --- multi-arch: top manifest is an index; grab child digests + first child's config
ma_index=$(raw_digest "${DEST}/multi-arch:latest")
ma_json=$(raw_json "${DEST}/multi-arch:latest")
ma_children=$(echo "$ma_json" | jq -c '[.manifests[].digest]')
ma_child0=$(echo "$ma_json" | jq -r '.manifests[0].digest')
ma_child0_json=$(raw_json "${DEST}/multi-arch@${ma_child0}")
ma_child0_config=$(echo "$ma_child0_json" | jq -r '.config.digest // empty')

# --- large-multi: index + children
lg_index=$(raw_digest "${DEST}/large-multi:latest")
lg_json=$(raw_json "${DEST}/large-multi:latest")
lg_children=$(echo "$lg_json" | jq -c '[.manifests[].digest]')
lg_child0=$(echo "$lg_json" | jq -r '.manifests[0].digest')
lg_size=$(echo "$lg_json" | wc -c)

# The `skopeo inspect` helpers above are `2>/dev/null`, so a broken inspect
# would otherwise be recorded as an empty/garbage digest and only surface much
# later as a confusing assert.sh failure. Refuse to write a hollow fixtures
# file: an unusable fixture is a SETUP failure and must say so here.
for _f in "sa_top:${sa_top}" "sa_config:${sa_config}" "ma_index:${ma_index}" \
          "ma_child0:${ma_child0}" "ma_child0_config:${ma_child0_config}" \
          "lg_index:${lg_index}" "lg_child0:${lg_child0}"; do
  _name="${_f%%:*}"; _val="${_f#*:}"
  case "$_val" in
    sha256:*) : ;;
    *) die "fixture digest '${_name}' is not a sha256 ref (got '${_val}') — skopeo inspect against ${DEST} did not return a usable manifest; the fixtures are unusable" ;;
  esac
done

jq -n \
  --arg repo "${NEXUS_DOCKER_REPO}" \
  --arg connector "${DEST}" \
  --arg sa_top "$sa_top" --arg sa_config "$sa_config" --arg sa_mt "$sa_mediatype" \
  --arg ma_index "$ma_index" --argjson ma_children "$ma_children" \
  --arg ma_child0 "$ma_child0" --arg ma_child0_config "$ma_child0_config" \
  --arg lg_index "$lg_index" --argjson lg_children "$lg_children" \
  --arg lg_child0 "$lg_child0" --argjson lg_index_bytes "${lg_size:-0}" \
  '{
    repo:$repo, connector:$connector,
    single_arch: { name:"single-arch", tag:"latest", top_digest:$sa_top,
                   media_type:$sa_mt, config_digest:$sa_config },
    multi_arch:  { name:"multi-arch", tag:"latest", index_digest:$ma_index,
                   children:$ma_children, child0:$ma_child0, child0_config:$ma_child0_config },
    large_multi: { name:"large-multi", tag:"latest", index_digest:$lg_index,
                   children:$lg_children, child0:$lg_child0, index_bytes:$lg_index_bytes }
  }' > "${NEXUS_FIXTURES_FILE}"

log "Fixtures recorded at ${NEXUS_FIXTURES_FILE}:"
cat "${NEXUS_FIXTURES_FILE}" >&2
echo "${NEXUS_FIXTURES_FILE}"
