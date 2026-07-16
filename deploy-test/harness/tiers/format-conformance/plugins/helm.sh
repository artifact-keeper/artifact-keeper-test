# =============================================================================
# plugins/helm.sh — format-conformance plugin (helm classic + OCI)
# FC_FORMAT: helm
# FC_MOUNT: helm
# FC_REPO_FORMAT: helm
# FC_PROFILE: client.helm
# FC_SERVICE: client-helm
# FC_ENABLED: 1
# =============================================================================
# Helm routes (backend handlers/helm.rs): nest /helm; index `GET
# /:repo/index.yaml`; download `GET /:repo/charts/:filename`; upload (ChartMuseum
# multipart, field "chart") `POST /:repo/api/charts`. index.yaml advertises each
# chart's location as a `urls[]` path `/helm/<repo>/charts/<file>.tgz`.
#
# The consume is a REAL `helm repo add/update` + `helm pull dtf/dtf-marker`,
# which reads index.yaml and FOLLOWS the advertised `urls[]` entry to download
# the chart. There is NO curl fallback in the consume path — a failing helm pull
# fails the test. That is deliberate: the corpus test-helm.sh:127-137 falls back
# to a direct curl download when `helm pull` fails, which structurally hides the
# #2580 bug class (advertised location != servable route). This tier bans it.
# =============================================================================
FC_CASES="version_update oci_push_pull index_immutable_digest"

HELM_CHART="dtf-marker"
HELM_VER="0.1.0"
HELM_VER2="0.1.1"
HELM_TGZ="${HELM_CHART}-${HELM_VER}.tgz"
HELM_TGZ2="${HELM_CHART}-${HELM_VER2}.tgz"

# Writable HELM_* dirs + repo creds for every helm invocation (the alpine/helm
# image is root; keep all state under /tmp so nothing depends on image WORKDIR).
_helm() {
  printf 'export HOME=/tmp HELM_CACHE_HOME=/tmp/.helm/cache HELM_CONFIG_HOME=/tmp/.helm/config HELM_DATA_HOME=/tmp/.helm/data; '
}

# Build a minimal chart (name=$1, version=$2) inside the container at /tmp/src/$1
# and `helm package` it to /tmp/out; echoes nothing, returns non-zero on failure.
_helm_build() {
  local name="$1" ver="$2"
  nc_exec "$(_helm) set -e
mkdir -p /tmp/src/${name}/templates /tmp/out
cat > /tmp/src/${name}/Chart.yaml <<EOF
apiVersion: v2
name: ${name}
description: DTF format-conformance marker chart
type: application
version: ${ver}
appVersion: \"1.0.0\"
EOF
cat > /tmp/src/${name}/values.yaml <<EOF
marker: DTF-HELM-INSTALLED-${ver}
EOF
cat > /tmp/src/${name}/templates/configmap.yaml <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Chart.Name }}-config
data:
  version: {{ .Chart.Version | quote }}
EOF
helm package /tmp/src/${name} -d /tmp/out >/dev/null
test -f /tmp/out/${name}-${ver}.tgz"
}

# ---------------------------------------------------------------------------
# fc_publish — build the v0.1.0 chart in-ctr, copy it out for the byte-identity
# proof, and upload via the ChartMuseum multipart route (host POST is the
# accepted brick-3 deviation; the discriminating value is the client CONSUME).
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec "$(_helm) command -v helm >/dev/null && helm version --short" \
    || { echo "helm missing inside the provisioned helm client"; return 1; }
  _helm_build "$HELM_CHART" "$HELM_VER" || { echo "helm package v${HELM_VER} failed"; return 1; }
  nc_copy_from_ctr "/tmp/out/${HELM_TGZ}" "${WORK_DIR}/${HELM_TGZ}" || return 1
  HELM_PUB_SHA="$(nc_sha256 "${WORK_DIR}/${HELM_TGZ}")"
  echo "  chart=${HELM_TGZ} sha256=${HELM_PUB_SHA}"
  nc_post_file "${WORK_DIR}/${HELM_TGZ}" "${FC_URL}/api/charts" chart || return 1
  # The generated index must now advertise the chart.
  local idx="${WORK_DIR}/index.yaml"
  nc_fetch "${FC_URL}/index.yaml" "$idx" || return 1
  grep -q "${HELM_CHART}" "$idx" || { echo "index.yaml does not list ${HELM_CHART}"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_client_setup — `helm repo add` pointing ONLY at $FC_INT_URL (no other
# source). Public repo, but pass creds too so the auth path is exercised.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec "$(_helm) helm repo add dtf '${FC_INT_URL}' --username '${ADMIN_USER}' --password '${ADMIN_PASS}' --force-update" \
    || { echo "helm repo add failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `helm repo update` fetches index.yaml; `helm
# pull` resolves the advertised urls[] entry and downloads the chart. NO curl
# fallback: if helm cannot follow the advertised location, this fails.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec "$(_helm) set -e
rm -rf /tmp/pull && mkdir -p /tmp/pull
helm repo update dtf
helm pull dtf/${HELM_CHART} --version ${HELM_VER} -d /tmp/pull
test -f /tmp/pull/${HELM_TGZ}" \
    || { echo "helm pull (following index.yaml urls[]) failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the pulled chart is byte-identical to what we
# published AND parses as a chart (helm show chart).
# ---------------------------------------------------------------------------
fc_assert() {
  nc_copy_from_ctr "/tmp/pull/${HELM_TGZ}" "${WORK_DIR}/pulled-${HELM_TGZ}" || return 1
  local pulled_sha
  pulled_sha="$(nc_sha256 "${WORK_DIR}/pulled-${HELM_TGZ}")"
  nc_assert_sha_eq "$HELM_PUB_SHA" "$pulled_sha" "pulled chart != published chart" || return 1
  nc_exec "$(_helm) helm show chart /tmp/pull/${HELM_TGZ} | grep -E '^name:\s*${HELM_CHART}$'" \
    || { echo "helm show chart did not parse name=${HELM_CHART}"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. index.yaml advertises the chart
# at a `urls[]` path under /charts/; that path 200s while a bare-basename URL at
# the repo root (the wrong shape a naive client might emit) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local adv
  adv="$(nc_advertised "${FC_URL}/index.yaml" \
    "grep -oE '/helm/[^[:space:]]+${HELM_CHART}-${HELM_VER}\\.tgz' | head -1")" || return 1
  echo "  advertised url=${adv}"
  nc_expect_code 200 "${BASE_URL}${adv}" || return 1
  # bare-basename at the repo root must NOT resolve (real path is /charts/<file>)
  nc_expect_code 404 "${FC_URL}/${HELM_TGZ}" || return 1
}

fc_cleanup() {
  [ -n "${HELM_OCI_REPO:-}" ] && api_delete "/api/v1/repositories/${HELM_OCI_REPO}" >/dev/null 2>&1
  return 0
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# version_update — publish 0.1.1; after `helm repo update`, an unversioned pull
# must fetch the NEWEST (0.1.1) while a pinned `--version 0.1.0` must still fetch
# the OLD bytes. Bug class: index/version resolution drift (a stale index or a
# pin that silently serves latest).
fc_case_version_update() {
  _helm_build "$HELM_CHART" "$HELM_VER2" || { echo "helm package v${HELM_VER2} failed"; return 1; }
  nc_copy_from_ctr "/tmp/out/${HELM_TGZ2}" "${WORK_DIR}/${HELM_TGZ2}" || return 1
  local sha2
  sha2="$(nc_sha256 "${WORK_DIR}/${HELM_TGZ2}")"
  nc_post_file "${WORK_DIR}/${HELM_TGZ2}" "${FC_URL}/api/charts" chart || return 1
  # positive: unversioned pull follows the index to the NEWEST version
  nc_exec "$(_helm) set -e
rm -rf /tmp/pu-latest && mkdir -p /tmp/pu-latest
helm repo update dtf
helm pull dtf/${HELM_CHART} -d /tmp/pu-latest
test -f /tmp/pu-latest/${HELM_TGZ2}" \
    || { echo "unversioned pull did not fetch newest ${HELM_VER2}"; return 1; }
  nc_copy_from_ctr "/tmp/pu-latest/${HELM_TGZ2}" "${WORK_DIR}/latest-${HELM_TGZ2}" || return 1
  nc_assert_sha_eq "$sha2" "$(nc_sha256 "${WORK_DIR}/latest-${HELM_TGZ2}")" \
    "unversioned pull bytes != published 0.1.1" || return 1
  echo "  unversioned pull -> ${HELM_VER2} (newest)"
  # negative: a pinned 0.1.0 pull must still return the ORIGINAL bytes
  nc_exec "$(_helm) set -e
rm -rf /tmp/pu-old && mkdir -p /tmp/pu-old
helm pull dtf/${HELM_CHART} --version ${HELM_VER} -d /tmp/pu-old
test -f /tmp/pu-old/${HELM_TGZ}" \
    || { echo "pinned 0.1.0 pull failed"; return 1; }
  nc_copy_from_ctr "/tmp/pu-old/${HELM_TGZ}" "${WORK_DIR}/pinned-${HELM_TGZ}" || return 1
  nc_assert_sha_eq "$HELM_PUB_SHA" "$(nc_sha256 "${WORK_DIR}/pinned-${HELM_TGZ}")" \
    "pinned 0.1.0 pull served wrong bytes" || return 1
  echo "  pinned 0.1.0 pull -> original bytes (no silent latest)"
}

# oci_push_pull — exercise the /v2 OCI route with a NON-docker (helm) client:
# `helm push chart oci://backend:8080/<docker-repo> --plain-http` then `helm
# pull oci://...`. Bug class: OCI artifact interop (a helm-typed OCI manifest
# rejected/misstored by the docker registry path).
fc_case_oci_push_pull() {
  HELM_OCI_REPO="dtf-helmoci-${RUN_ID}"
  create_repo "$HELM_OCI_REPO" docker local || { echo "could not create docker repo for OCI leg"; return 1; }
  # `helm registry login` has no --plain-http in 3.16, so write the registry
  # auth config directly (docker-config-json shape) and push over plain HTTP.
  nc_exec "$(_helm) set -e
mkdir -p /tmp/.helm/config/registry
AUTHB64=\$(printf '%s:%s' '${ADMIN_USER}' '${ADMIN_PASS}' | base64 | tr -d '\n')
cat > /tmp/.helm/config/registry/config.json <<EOF
{\"auths\":{\"backend:8080\":{\"auth\":\"\${AUTHB64}\"}}}
EOF
helm push /tmp/out/${HELM_TGZ} oci://backend:8080/${HELM_OCI_REPO} --plain-http" \
    || { echo "helm push oci:// failed"; return 1; }
  echo "  pushed oci://backend:8080/${HELM_OCI_REPO}/${HELM_CHART}:${HELM_VER}"
  nc_exec "$(_helm) set -e
rm -rf /tmp/oci && mkdir -p /tmp/oci
helm pull oci://backend:8080/${HELM_OCI_REPO}/${HELM_CHART} --version ${HELM_VER} --plain-http -d /tmp/oci
test -f /tmp/oci/${HELM_TGZ}" \
    || { echo "helm pull oci:// failed"; return 1; }
  nc_copy_from_ctr "/tmp/oci/${HELM_TGZ}" "${WORK_DIR}/oci-${HELM_TGZ}" || return 1
  nc_assert_sha_eq "$HELM_PUB_SHA" "$(nc_sha256 "${WORK_DIR}/oci-${HELM_TGZ}")" \
    "OCI-pulled chart != published chart" || return 1
  echo "  OCI round-trip byte-identical"
}

# index_immutable_digest — index.yaml carries a `digest` per chart that MUST
# equal the sha256 of the served .tgz (helm cross-checks on pull). Bug class:
# advertised-digest vs served-bytes drift.
fc_case_index_immutable_digest() {
  local served="${WORK_DIR}/served-${HELM_TGZ}"
  nc_fetch "${FC_URL}/charts/${HELM_TGZ}" "$served" || return 1
  [ -s "$served" ] || { echo "served chart empty"; return 1; }
  local served_sha
  served_sha="$(nc_sha256 "$served")"
  local idx="${WORK_DIR}/index-digest.yaml"
  nc_fetch "${FC_URL}/index.yaml" "$idx" || return 1
  # the served-bytes sha256 must appear as a digest in the index
  if grep -qE "digest:\s*(sha256:)?${served_sha}" "$idx"; then
    echo "  index digest matches served bytes (${served_sha})"
  else
    echo "  DRIFT: served sha ${served_sha} not advertised as a digest in index.yaml"
    grep -nE 'digest:' "$idx" | head; return 1
  fi
}
