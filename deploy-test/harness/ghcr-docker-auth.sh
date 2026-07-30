#!/usr/bin/env bash
# ghcr-docker-auth.sh - authenticate the local docker daemon to ghcr.io.
#
# The single auth path for the DTF release-gate jobs (dtf-gate and
# dtf-advisory in .github/workflows/release-gate.yml), shared by BOTH
# invocation modes of that workflow (artifact-keeper#2701):
#
#   workflow_call     (real release): GHCR_DOCKER_CONFIG arrives via
#                     `secrets: inherit` from the calling repo.
#   workflow_dispatch (rehearsal):    the same secret name resolves
#                     from the artifact-keeper-test repo/org secrets.
#
# This script cannot tell the two apart - by design. Whoever set the
# env gets identical behaviour.
#
# Env contract (all optional):
#   GHCR_DOCKER_CONFIG  base64-encoded ~/.docker/config.json holding a
#                       pull-scope-only ghcr.io credential. Same
#                       encoding convention as every other consumer in
#                       this repo (scripts/create-test-namespace.sh,
#                       scripts/clean-install-smoke.sh,
#                       tests/release-gate/chart-upgrade-smoke.sh).
#   GH_ACTOR, GH_TOKEN  fallback `docker login` with the workflow token
#                       (public images only).
#
# SECURITY: the secret value is never echoed or logged. It is decoded
# straight to ~/.docker/config.json with 0600 permissions, and the file
# is removed again if validation fails.

set -euo pipefail

DOCKER_CONFIG_FILE="${HOME}/.docker/config.json"

if [ -n "${GHCR_DOCKER_CONFIG:-}" ]; then
  mkdir -p "${HOME}/.docker"
  umask 077
  if ! printf '%s' "${GHCR_DOCKER_CONFIG}" | base64 -d \
      > "${DOCKER_CONFIG_FILE}" 2>/dev/null; then
    rm -f "${DOCKER_CONFIG_FILE}"
    echo "::error::GHCR_DOCKER_CONFIG is not valid base64. The secret" \
      "must be base64(~/.docker/config.json); see the invocation-paths" \
      "comment in .github/workflows/release-gate.yml." >&2
    exit 1
  fi
  # Tripwire for the wrong-payload class (e.g. a raw JSON or an
  # unrelated token stored in the secret): a docker config.json used as
  # a pull secret must carry an "auths" map. Do NOT print the file.
  if ! grep -q '"auths"' "${DOCKER_CONFIG_FILE}"; then
    rm -f "${DOCKER_CONFIG_FILE}"
    echo "::error::GHCR_DOCKER_CONFIG decoded to something that is not" \
      "a docker config.json (no \"auths\" key). Re-create the secret as" \
      "base64 of a ~/.docker/config.json with a pull-scope ghcr.io" \
      "credential." >&2
    exit 1
  fi
  echo "Installed GHCR_DOCKER_CONFIG as docker config"
elif [ -n "${GH_TOKEN:-}" ]; then
  echo "${GH_TOKEN}" | docker login ghcr.io \
    -u "${GH_ACTOR:-github-actions}" --password-stdin
  echo "Logged in to ghcr.io with the workflow token (public images only)"
else
  echo "WARN: neither GHCR_DOCKER_CONFIG nor GH_TOKEN is set;" \
    "private image pulls will fail." >&2
fi
