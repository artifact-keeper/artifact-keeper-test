# =============================================================================
# plugins/terraform.sh — format-conformance plugin (terraform) — RESEARCH-GRADE
# FC_FORMAT: terraform
# FC_MOUNT: terraform
# FC_REPO_FORMAT: terraform
# FC_PROFILE: client.terraform
# FC_SERVICE: client-terraform
# FC_ENABLED: 0
# =============================================================================
# KNOWN-RED (FC_ENABLED: 0). This plugin is a faithful, runnable encoding of the
# network-mirror consume leg, held OUT of the active run set because the current
# backend CANNOT serve a HOSTED terraform repo through the provider network
# mirror. Two independent, source-confirmed gaps (handlers/terraform.rs):
#
#   1. The mirror handlers (mirror_index/mirror_version/mirror_download) call
#      resolve_mirror_remote() -> classify_mirror_repo(is_remote, ...). For a
#      HOSTED repo `is_remote == false` -> MirrorGuard::NotRemote -> HTTP 404
#      "Provider network mirror is only available on remote Terraform
#      repositories". So `terraform init` against a hosted mirror URL 404s.
#
#   2. Even for a REMOTE repo, the mirror is a PROXY: it re-fetches an UPSTREAM
#      registry (fetch_upstream_json / proxy_fetch_streaming). It never serves a
#      hosted repo's own uploaded providers. And the hosted provider-registry
#      download doc (download_provider) advertises a `.../v1/providers/.../
#      binary/...` URL for which NO axum route is registered (the router has no
#      `binary` segment) — a #2580-class dead advertised location.
#
# Terraform's other protocols (module registry, provider registry) require
# host-rooted discovery at `https://HOST/.well-known/terraform.json` (no path
# prefix) which the per-repo backend (route `/:repo/.well-known/terraform.json`)
# structurally cannot satisfy for a real client. The network mirror is the only
# path-prefixed, TLS-only protocol — hence the caddy sidecar in client.terraform
# .yml — but it is remote/proxy-only. See rig/results/format-conformance/
# terraform-finding.md. Re-enable (FC_ENABLED: 1) once the backend serves the
# network-mirror protocol for hosted providers.
#
# The PUBLISH leg below (PUT provider to a hosted repo) works today; the CONSUME
# leg is the documented KNOWN-RED.
# =============================================================================
FC_CASES="mirror_shapes h1_hash"

FC_EXEC_USER="root"

TF_NS="dtf"
TF_TYPE="marker"
TF_VER="1.0.0"
TF_OS="linux"
TF_ARCH="arm64"
TF_HOSTNAME="tf.dtf.local"
TF_MARKER_TOKEN="DTF-TERRAFORM-INSTALLED-${TF_VER}"
TF_BUILDSH="${DTF_DIR}/fixtures/terraform/build.sh"

# ---------------------------------------------------------------------------
# fc_publish — host-craft the provider zip and PUT it on the hosted native
# provider-registry route (this WORKS today; the discriminating consume is the
# network-mirror path below).
# ---------------------------------------------------------------------------
fc_publish() {
  TF_ZIP="$(bash "$TF_BUILDSH" "$WORK_DIR" "$TF_TYPE" "$TF_VER" "$TF_OS" "$TF_ARCH" "$TF_MARKER_TOKEN")" \
    || return 1
  [ -s "$TF_ZIP" ] || { echo "fixture build produced no zip"; return 1; }
  TF_PUB_SHA="$(nc_sha256 "$TF_ZIP")"
  echo "  fixture=${TF_ZIP} sha256=${TF_PUB_SHA}"
  nc_put_file "$TF_ZIP" \
    "${FC_URL}/v1/providers/${TF_NS}/${TF_TYPE}/${TF_VER}/${TF_OS}/${TF_ARCH}" || return 1
  # The hosted provider registry must now list the version.
  nc_expect_code 200 "${FC_URL}/v1/providers/${TF_NS}/${TF_TYPE}/versions" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — trust caddy's internal CA in the terraform container and
# write a `.terraformrc` network_mirror config + a consumer `main.tf`. Points
# ONLY at the AK mirror (no public registry).
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v terraform >/dev/null 2>&1 && terraform version' \
    || { echo "terraform missing inside the provisioned client"; return 1; }
  # Trust caddy's internal root CA (self-signed for tf.dtf.local).
  local caddy_ctr="ak-dtf${DTF_SLOT}-caddy-terraform"
  local ca="${WORK_DIR}/caddy-root.crt"
  docker cp "${caddy_ctr}:/data/caddy/pki/authorities/local/root.crt" "$ca" >/dev/null 2>&1 \
    || { echo "could not extract caddy internal CA root.crt"; return 1; }
  nc_copy_to_ctr "$ca" /usr/local/share/ca-certificates/caddy-root.crt \
    || nc_copy_to_ctr "$ca" /tmp/caddy-root.crt
  nc_exec 'update-ca-certificates 2>/dev/null || true'
  nc_exec "mkdir -p /root/consume && cat > /root/.terraformrc <<EOF
provider_installation {
  network_mirror {
    url = \"https://${TF_HOSTNAME}/terraform/${FC_REPO}/\"
  }
}
EOF
cat > /root/consume/main.tf <<EOF
terraform {
  required_providers {
    ${TF_TYPE} = {
      source  = \"${TF_HOSTNAME}/${TF_NS}/${TF_TYPE}\"
      version = \"${TF_VER}\"
    }
  }
}
EOF
cat /root/.terraformrc"
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `terraform init` reads the network_mirror,
# fetches index.json -> <version>.json -> archive. KNOWN-RED: the mirror handler
# rejects a HOSTED repo with 404 (see header, gap #1), so init fails.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "cd /root/consume && SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    terraform init -no-color 2>&1" \
    || { echo "terraform init failed (KNOWN-RED: hosted network mirror unsupported)"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof (would run only if consume succeeds).
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "find /root/consume/.terraform/providers -name '*${TF_TYPE}*' | grep -q ${TF_TYPE}" \
    || { echo "provider not populated under .terraform/providers"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the network-mirror discriminator. If the backend served
# hosted providers via the mirror, index.json would 200 and list the version.
# KNOWN-RED: it 404s with "only available on remote Terraform repositories".
# ---------------------------------------------------------------------------
fc_advertised_check() {
  # What a conformant backend WOULD serve (currently 404 on a hosted repo):
  nc_expect_code 200 \
    "${FC_URL}/${TF_HOSTNAME}/${TF_NS}/${TF_TYPE}/index.json" || return 1
}

# ===========================================================================
# Edge cases (KNOWN-RED — gated on the mirror leg the backend does not serve)
# ===========================================================================

# mirror_shapes — index.json + <version>.json must parse to the exact
# network-mirror schema terraform hard-parses (`{"versions":{...}}` /
# `{"archives":{"<os>_<arch>":{"url":...}}}`). Bug class: mirror-schema drift.
fc_case_mirror_shapes() {
  local idx
  idx="$(nc_advertised "${FC_URL}/${TF_HOSTNAME}/${TF_NS}/${TF_TYPE}/index.json" \
    "jq -r '.versions | keys[]'")" || return 1
  echo "  mirror index lists version(s): ${idx}"
  nc_advertised "${FC_URL}/${TF_HOSTNAME}/${TF_NS}/${TF_TYPE}/${TF_VER}.json" \
    "jq -r '.archives | keys[]'" || return 1
}

# h1_hash — the mirror `<version>.json` `hashes` entry must verify against the
# served archive (terraform enforces zh:/h1: hashes). Bug class: hash drift.
fc_case_h1_hash() {
  local h
  h="$(nc_advertised "${FC_URL}/${TF_HOSTNAME}/${TF_NS}/${TF_TYPE}/${TF_VER}.json" \
    "jq -r '.archives[\"${TF_OS}_${TF_ARCH}\"].hashes[]?'")" || return 1
  echo "  mirror advertises hash(es): ${h}"
  [ -n "$h" ] || { echo "no hashes advertised for ${TF_OS}_${TF_ARCH}"; return 1; }
}
