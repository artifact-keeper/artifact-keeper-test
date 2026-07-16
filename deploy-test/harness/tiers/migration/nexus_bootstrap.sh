#!/usr/bin/env bash
# =============================================================================
# tiers/migration/nexus_bootstrap.sh — automated first-run setup for the
# per-slot Nexus migration source
# =============================================================================
# VENDORED + adapted from rig/harness/nexus_bootstrap.sh. Deviation: step 1
# ("compose up") is dropped — harness/run.sh already brought the slot up with
# `up -d --wait`, so Nexus is health-gated (REST answering) before this runs.
# Everything else is verbatim:
#   1. Wait for the REST API (belt-and-braces; --wait already gated it).
#   2. Read the first-run bootstrap password from inside the container.
#   3. Change admin password to a known value (REST change-password).
#   4. Accept the mandatory EULA (Nexus CE >= 3.68 rejects all repo writes
#      until accepted -> docker push/skopeo copy 403 otherwise).
#   5. Disable anonymous access (clears the onboarding prompt).
#   6. Persist the resolved password to the per-run state dir.
# Hands-off + re-runnable.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

WAIT_SECS="${WAIT_SECS:-240}"

nexus_is_up || die "Nexus container ${NEXUS_CTR} is not running (run.sh should have started it — check the upstreams.nexus profile)"

# Accept the Nexus EULA (idempotent). Must run with a working admin password.
accept_eula() {
  local disc code
  disc=$(curl -s -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASS}" \
         "${NEXUS_API}/service/rest/v1/system/eula" | jq -r '.disclaimer // ""')
  [ -n "$disc" ] || { warn "EULA endpoint returned no disclaimer (older Nexus? skipping)"; return 0; }
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASS}" \
    -X POST "${NEXUS_API}/service/rest/v1/system/eula" \
    -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg d "$disc" '{disclaimer:$d, accepted:true}')")
  log "EULA accept -> HTTP ${code}"
}

# --- helper: does the TARGET password already work? -------------------------
target_pass_works() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASS}" \
    "${NEXUS_API}/service/rest/v1/status/writable")
  [ "$code" = "200" ]
}

# --- 1. wait for API (usually instant: run.sh health-gated the slot) ---------
log "Waiting up to ${WAIT_SECS}s for Nexus REST to answer on ${NEXUS_API} ..."
deadline=$(( $(date +%s) + WAIT_SECS ))
api_ready=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "${NEXUS_API}/service/rest/v1/status" || true)
  if [ "$code" = "200" ]; then api_ready=1; break; fi
  sleep 5
done
[ "$api_ready" = "1" ] || die "Nexus REST /status never returned 200 within ${WAIT_SECS}s (check: docker logs ${NEXUS_CTR})"
log "Nexus REST is up."

# Already bootstrapped to target password? (idempotent re-run)
if target_pass_works; then
  log "Target admin password already active — re-asserting EULA + anonymous."
  accept_eula
  curl -s -o /dev/null -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASS}" \
    -X PUT "${NEXUS_API}/service/rest/v1/security/anonymous" -H 'Content-Type: application/json' \
    --data '{"enabled":false,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' || true
  printf '%s' "${NEXUS_ADMIN_PASS}" > "${NEXUS_PASS_FILE}"
  log "Resolved password stored at ${NEXUS_PASS_FILE}"
  exit 0
fi

# --- 2. read the first-run bootstrap password from inside the container ------
boot_pass=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  if docker exec "${NEXUS_CTR}" test -f /nexus-data/admin.password 2>/dev/null; then
    boot_pass=$(docker exec "${NEXUS_CTR}" cat /nexus-data/admin.password 2>/dev/null | tr -d '\r\n')
    [ -n "$boot_pass" ] && break
  fi
  sleep 5
done
[ -n "$boot_pass" ] || die "admin.password never appeared (fresh volume expected — run.sh uses 'down -v' between runs)"
log "Bootstrap password obtained (len ${#boot_pass})."

# --- 3. change admin password to the known target ----------------------------
log "Rotating admin password to the harness target value ..."
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -u "${NEXUS_ADMIN_USER}:${boot_pass}" \
  -X PUT "${NEXUS_API}/service/rest/v1/security/users/admin/change-password" \
  -H 'Content-Type: text/plain' \
  --data "${NEXUS_ADMIN_PASS}")
[ "$code" = "204" ] || [ "$code" = "200" ] || warn "change-password returned HTTP ${code}; verifying ..."

# --- 4. accept EULA (blocks all repo writes until accepted) ------------------
accept_eula

# --- 5. disable anonymous access (clears onboarding prompt) ------------------
curl -s -o /dev/null -w 'anon-set HTTP %{http_code}\n' \
  -u "${NEXUS_ADMIN_USER}:${NEXUS_ADMIN_PASS}" \
  -X PUT "${NEXUS_API}/service/rest/v1/security/anonymous" \
  -H 'Content-Type: application/json' \
  --data '{"enabled":false,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' >&2 || true

# --- 6. verify + persist ------------------------------------------------------
if target_pass_works; then
  printf '%s' "${NEXUS_ADMIN_PASS}" > "${NEXUS_PASS_FILE}"
  log "SUCCESS: admin password rotated + EULA accepted + verified. Stored at ${NEXUS_PASS_FILE}"
  exit 0
else
  die "Password rotation did not verify (target password rejected on ${NEXUS_API})."
fi
