#!/usr/bin/env bash
# =============================================================================
# tiers/inline-scan-hosted-gate-2954/oracle.sh — hosted download policy gate
# =============================================================================
# #2954 Part 1: fold PolicyService::evaluate_artifact into the shared download
# choke point quarantine_service::check_artifact_download (new
# enforce_download_gate) so a repo-scoped scan policy blocks the raw download
# path for all ~30 formats — not just the promotion gate.
#
# run.sh has stood up `storage.filesystem` and exported BASE_URL, ADMIN_USER,
# ADMIN_PASS, RUN_ID, COMMON_SH, DTF_SLOT. No upstream / internet needed.
#
# Discriminator:
#   hosted-blocked  (block_unscanned policy, unscanned jar) GET -> 403 on fix,
#                   200 pre-#2954 (policy never consulted on download).
#   hosted-nopolicy (no policy)                             GET -> 200 on BOTH
#                   (regression guard: no-policy repos unaffected).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "inline-scan-hosted-gate-2954"
auth_admin
setup_workdir

BLOCKED_KEY="dtf-hosted-blocked-${RUN_ID}"
NOPOLICY_KEY="dtf-hosted-nopolicy-${RUN_ID}"
JAR_PATH="com/ex/app/1.0/app-1.0.jar"
POLICY_ID=""

cleanup() {
  [ -n "$POLICY_ID" ] && api_delete "/api/v1/security/policies/${POLICY_ID}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${BLOCKED_KEY}"  >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${NOPOLICY_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

# GET a download path anonymously; echo the HTTP status.
dl_status() { # <repo_key>
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    "${BASE_URL}/maven/$1/${JAR_PATH}" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# Setup: two local maven repos, each with an uploaded jar.
# ---------------------------------------------------------------------------
JAR="${WORK_DIR}/app-1.0.jar"
printf 'PK\003\004 dtf-2954 hosted-gate probe jar %s' "$RUN_ID" > "$JAR"

for KEY in "$BLOCKED_KEY" "$NOPOLICY_KEY"; do
  begin_test "Setup: create local maven repo ${KEY} + upload jar"
  if create_repo "$KEY" "maven" "local" \
     && api_upload "/maven/${KEY}/${JAR_PATH}" "$JAR" >/dev/null 2>&1; then
    pass
  else
    fail "could not create/upload to ${KEY}"
    end_suite
  fi
done

# Baseline: both downloadable before any policy (proves the jars serve at all).
begin_test "Baseline: both repos serve the jar (200) before any policy"
b1=$(dl_status "$BLOCKED_KEY"); b2=$(dl_status "$NOPOLICY_KEY")
if [ "$b1" = "200" ] && [ "$b2" = "200" ]; then
  pass
else
  fail "baseline download not 200 (blocked=${b1} nopolicy=${b2})"
fi

# ---------------------------------------------------------------------------
# Attach a block_unscanned policy scoped to hosted-blocked ONLY.
# ---------------------------------------------------------------------------
begin_test "Setup: create block_unscanned scan policy scoped to ${BLOCKED_KEY}"
RID=$(api_get "/api/v1/repositories" | jq -r --arg k "$BLOCKED_KEY" \
  '(.items // .)[] | select(.key==$k) | .id' 2>/dev/null | head -1)
if [ -z "$RID" ] || [ "$RID" = "null" ]; then
  fail "could not resolve repo id for ${BLOCKED_KEY}"; end_suite
fi
POL=$(api_post "/api/v1/security/policies" "$(jq -n --arg r "$RID" \
  '{name:"dtf-2954-block-unscanned", repository_id:$r, max_severity:"high",
    block_unscanned:true, block_on_fail:false, require_signature:false}')" 2>/dev/null)
POLICY_ID=$(printf '%s' "$POL" | jq -r '.id // empty' 2>/dev/null)
if [ -n "$POLICY_ID" ]; then pass; else fail "policy create failed: ${POL:0:200}"; fi

# ---------------------------------------------------------------------------
# The discriminating assertions.
# ---------------------------------------------------------------------------
begin_test "#2954: ${BLOCKED_KEY} download is BLOCKED by scan policy (403; was 200)"
s=$(dl_status "$BLOCKED_KEY")
if [ "$s" = "403" ]; then
  pass
else
  fail "expected 403 on policy-blocked download, got ${s} (pre-#2954 serves 200 because the download path never consulted evaluate_artifact)"
fi

begin_test "#2954 regression guard: ${NOPOLICY_KEY} (no policy) still serves 200"
s=$(dl_status "$NOPOLICY_KEY")
if [ "$s" = "200" ]; then
  pass
else
  fail "no-policy repo must be unaffected by the shared-choke-point fold, got ${s}"
fi

end_suite
