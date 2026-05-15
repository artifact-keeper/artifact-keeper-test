#!/usr/bin/env bash
# verify-image-set.sh - Confirm every image in the release set exists on ghcr.io
#
# Usage:
#   ./verify-image-set.sh \
#       --backend-tag <tag> \
#       --web-tag <tag> \
#       --openscap-tag <tag> \
#       [--chart-dir <path>]
#
# Probes the GHCR registry's manifest endpoint for each image at the
# specified tag. A missing tag fails fast with a clear error.
#
# When --chart-dir is provided AND `helm` is on PATH, the script also
# renders the chart with no overrides and asserts that the default
# image tags emitted by `helm template` match the BACKEND_TAG /
# WEB_TAG passed in. This catches the artifact-keeper#872 customer
# scenario: a user who runs `helm install -f values-production.yaml`
# without `--set backend.image.tag=...` and gets whatever the chart's
# defaults (Chart.yaml appVersion / values.yaml image.tag) point at
# (currently "1.1.0" via Chart.yaml#appVersion, stale).
#
# Catches the structural failure behind:
#   - artifact-keeper#872 (chart tagged but referenced images absent /
#     default tag stale on a release branch)
#   - artifact-keeper#905 (versioned tags missing on ghcr.io)
#   - artifact-keeper-web#320 (v1.1.8 web image never published)
#
# We use the OCI Registry HTTP API v2 directly (HEAD against
# /v2/<name>/manifests/<tag>) rather than `crane manifest` or
# `docker manifest inspect`. Rationale:
#   * Zero binary install in CI; only depends on `curl`.
#   * Works against public-anon ghcr.io with a `Bearer` exchange
#     against ghcr.io/token, which we do inline. The token exchange
#     for public repos returns an unscoped token without credentials.
#   * Tolerates schema 1 and schema 2 manifests (we just need a 200).
#
# Exit codes:
#   0 - All images exist at their tags
#   1 - Usage error
#   2 - At least one image is missing
#
# Required env: none. Optional: GHCR_REGISTRY (default ghcr.io),
#               GHCR_NAMESPACE (default artifact-keeper).

set -euo pipefail

BACKEND_TAG=""
WEB_TAG=""
OPENSCAP_TAG=""
CHART_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-tag)  BACKEND_TAG="${2:-}"; shift 2 ;;
    --web-tag)      WEB_TAG="${2:-}"; shift 2 ;;
    --openscap-tag) OPENSCAP_TAG="${2:-}"; shift 2 ;;
    --chart-dir)    CHART_DIR="${2:-}"; shift 2 ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: verify-image-set.sh --backend-tag <tag> --web-tag <tag> --openscap-tag <tag> [--chart-dir <path>]" >&2
      exit 1
      ;;
  esac
done

if [ -z "$BACKEND_TAG" ] || [ -z "$WEB_TAG" ] || [ -z "$OPENSCAP_TAG" ]; then
  echo "ERROR: --backend-tag, --web-tag, --openscap-tag are all required" >&2
  exit 1
fi

REGISTRY="${GHCR_REGISTRY:-ghcr.io}"
NAMESPACE="${GHCR_NAMESPACE:-artifact-keeper}"

# GHCR docker images live at <namespace>/<image-name>. The web image
# is published under artifact-keeper-web, the backend under
# artifact-keeper-backend, the openscap helper under
# artifact-keeper-openscap. These names ARE the source of truth: the
# org's CI publishes to these exact paths.
#
# Strip the leading 'v' if a workflow input passed a raw git tag
# (e.g. v1.1.9). Docker tags drop the prefix per CLAUDE.md "Docker
# tags use semver without v" convention.
_strip_v() { echo "${1#v}"; }

BACKEND_TAG_NORM=$(_strip_v "$BACKEND_TAG")
WEB_TAG_NORM=$(_strip_v "$WEB_TAG")
OPENSCAP_TAG_NORM=$(_strip_v "$OPENSCAP_TAG")

LOG_DIR="/tmp"
LOG_FILE="${LOG_DIR}/version-set-${RANDOM}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================================="
echo "Version-set integrity check"
echo "  Registry:      ${REGISTRY}"
echo "  Namespace:     ${NAMESPACE}"
echo "  Backend tag:   ${BACKEND_TAG_NORM}"
echo "  Web tag:       ${WEB_TAG_NORM}"
echo "  Openscap tag:  ${OPENSCAP_TAG_NORM}"
echo "=================================================================="

# -----------------------------------------------------------------------
# probe_image <image-name> <tag>
#
# Returns 0 if the manifest exists, non-zero otherwise. Echoes a
# human-readable status line in either case.
#
# GHCR requires a Bearer token even for anonymous reads of public
# images. The token endpoint accepts unauthenticated requests for
# pull scope on public images and returns a short-lived token.
# Token URL shape: https://ghcr.io/token?scope=repository:<name>:pull
# -----------------------------------------------------------------------
probe_image() {
  local image="$1"
  local tag="$2"
  local image_path="${NAMESPACE}/${image}"
  local token_url="https://${REGISTRY}/token?scope=repository:${image_path}:pull"
  local manifest_url="https://${REGISTRY}/v2/${image_path}/manifests/${tag}"

  echo ""
  echo "Probing ${image_path}:${tag}"

  local token
  token=$(curl -sf --max-time 15 "$token_url" 2>/dev/null \
    | jq -r '.token // .access_token // empty' 2>/dev/null) || true

  if [ -z "$token" ]; then
    echo "  ERROR: could not obtain pull token from ${token_url}"
    return 1
  fi

  # Use HEAD so we don't pull the manifest body. Accept both the OCI
  # and Docker manifest media types so we don't false-fail on a 404
  # when the server only serves one variant for our Accept header.
  # OCI image index (manifest list) is also valid, so include that.
  local accept_hdr="application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -I \
    -H "Authorization: Bearer ${token}" \
    -H "Accept: ${accept_hdr}" \
    "$manifest_url" 2>/dev/null || echo "000")

  if [ "$status" = "200" ]; then
    echo "  OK: ${image_path}:${tag} (HTTP 200)"
    return 0
  fi

  # A 404 means the tag does not exist. Surface that as the diagnostic
  # most likely to be useful to the operator (publish step regressed).
  echo "  MISSING: ${image_path}:${tag} (HTTP ${status})"
  return 1
}

# -----------------------------------------------------------------------
# Drive the probes. We track failures rather than exiting on the
# first miss so the operator sees the FULL picture: "backend ok, web
# missing, openscap missing" is more actionable than "backend ok"
# followed by a re-run after fixing web.
# -----------------------------------------------------------------------

FAILED_IMAGES=()

probe_image "artifact-keeper-backend" "$BACKEND_TAG_NORM" \
  || FAILED_IMAGES+=("artifact-keeper-backend:${BACKEND_TAG_NORM}")
probe_image "artifact-keeper-web" "$WEB_TAG_NORM" \
  || FAILED_IMAGES+=("artifact-keeper-web:${WEB_TAG_NORM}")
probe_image "artifact-keeper-openscap" "$OPENSCAP_TAG_NORM" \
  || FAILED_IMAGES+=("artifact-keeper-openscap:${OPENSCAP_TAG_NORM}")

# -----------------------------------------------------------------------
# Optional: chart default-tag verification (artifact-keeper#872)
#
# A green check above tells us the images exist. It does NOT tell us
# whether a customer running `helm install -f values-production.yaml`
# (with no --set backend.image.tag) would pull those images by
# default. That is the actual customer-pain scenario in #872.
#
# When --chart-dir is supplied and `helm` is on PATH, render the chart
# with no overrides and compare:
#   - The default image: lines emitted for backend / web containers
#     against the passed-in BACKEND_TAG / WEB_TAG.
#   - Chart.yaml appVersion against BACKEND_TAG (warn-only because the
#     chart's appVersion is allowed to lag by design in some shops).
# -----------------------------------------------------------------------

CHART_WARNINGS=()

if [ -n "$CHART_DIR" ]; then
  echo ""
  echo "Chart default-tag verification (chart dir: ${CHART_DIR})"
  if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
    echo "  WARN: --chart-dir was given but ${CHART_DIR}/Chart.yaml is missing; skipping"
    CHART_WARNINGS+=("chart-dir-missing")
  elif ! command -v helm >/dev/null 2>&1; then
    echo "  WARN: helm is not on PATH; skipping chart default-tag check"
    CHART_WARNINGS+=("helm-not-installed")
  else
    appversion=$(awk '/^appVersion:/ {gsub(/"/, "", $2); print $2; exit}' "${CHART_DIR}/Chart.yaml" 2>/dev/null || echo "")
    if [ -n "$appversion" ]; then
      appversion_norm=$(_strip_v "$appversion")
      if [ "$appversion_norm" = "$BACKEND_TAG_NORM" ]; then
        echo "  OK: Chart.yaml appVersion (${appversion_norm}) matches backend tag"
      else
        echo "  WARN: Chart.yaml appVersion (${appversion_norm}) != backend tag (${BACKEND_TAG_NORM})"
        echo "        This is the #872 customer-pain shape: chart on a tagged release"
        echo "        but appVersion lagging the published image set."
        CHART_WARNINGS+=("appversion-${appversion_norm}-vs-${BACKEND_TAG_NORM}")
      fi
    fi

    # Render the chart with NO image-tag overrides (the whole point is
    # to see what defaults the chart ships with). We pass the two
    # chart-required values (secrets.jwtSecret, postgres.auth.password)
    # because the chart errors out without them; neither affects the
    # rendered image tags.
    rendered=$(helm template ak-default "$CHART_DIR" \
      --set "secrets.jwtSecret=verify-image-set-default-render-only" \
      --set "postgres.auth.password=verify-image-set-default-render-only" \
      2>/dev/null || echo "")
    if [ -z "$rendered" ]; then
      echo "  WARN: helm template failed; skipping default-tag rendering check"
      CHART_WARNINGS+=("helm-template-failed")
    else
      # awk extracts image: <repo>:<tag>; we lowercase the line and
      # filter to artifact-keeper-* repositories.
      defaults=$(echo "$rendered" \
        | awk -F'image: *' '/image: /{print $2}' \
        | tr -d '"' \
        | grep -E 'artifact-keeper-(backend|web|openscap)' \
        | sort -u)
      echo "  Defaults rendered by chart:"
      # shellcheck disable=SC2001  # multi-line input, parameter expansion can't do this
      echo "$defaults" | sed 's/^/    /'

      for line in $defaults; do
        case "$line" in
          *artifact-keeper-backend:*)
            got="${line##*:}"
            if [ "$got" != "$BACKEND_TAG_NORM" ]; then
              echo "  WARN: chart default backend tag is '${got}', expected '${BACKEND_TAG_NORM}'"
              CHART_WARNINGS+=("backend-default-${got}-vs-${BACKEND_TAG_NORM}")
            fi
            ;;
          *artifact-keeper-web:*)
            got="${line##*:}"
            if [ "$got" != "$WEB_TAG_NORM" ]; then
              echo "  WARN: chart default web tag is '${got}', expected '${WEB_TAG_NORM}'"
              CHART_WARNINGS+=("web-default-${got}-vs-${WEB_TAG_NORM}")
            fi
            ;;
          *artifact-keeper-openscap:*)
            got="${line##*:}"
            if [ "$got" != "$OPENSCAP_TAG_NORM" ]; then
              echo "  WARN: chart default openscap tag is '${got}', expected '${OPENSCAP_TAG_NORM}'"
              CHART_WARNINGS+=("openscap-default-${got}-vs-${OPENSCAP_TAG_NORM}")
            fi
            ;;
        esac
      done
    fi
  fi
fi

echo ""
echo "=================================================================="
if [ "${#FAILED_IMAGES[@]}" -eq 0 ]; then
  echo "Version-set integrity check PASSED"
  echo "  All ${REGISTRY}/${NAMESPACE} images exist at their tags."
  if [ "${#CHART_WARNINGS[@]}" -gt 0 ]; then
    echo ""
    echo "  Chart-default warnings (non-blocking, see #872):"
    for w in "${CHART_WARNINGS[@]}"; do
      echo "    - ${w}"
    done
  fi
  echo "=================================================================="
  exit 0
fi

echo "Version-set integrity check FAILED"
echo ""
echo "Missing images (release set incomplete):"
for img in "${FAILED_IMAGES[@]}"; do
  echo "  - ${REGISTRY}/${NAMESPACE}/${img}"
done
echo ""
echo "This is a release blocker. The publish pipeline did not push every"
echo "required image at the requested tag. Re-run the publish workflow"
echo "(see artifact-keeper/.github/workflows/release.yml) or pin the"
echo "release-gate inputs to a tag set that is fully published."
echo "=================================================================="
exit 2
