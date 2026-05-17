#!/usr/bin/env bash
# test-scheduled-scan.sh -- Scheduled scan (cron) E2E
#
# Covers Epic 2 sub-task 2.13 (artifact-keeper-test#67): the scheduled-scan
# policy machinery. Backend exposes a CRUD endpoint family for cron-driven
# scan policies; this test pins three contracts:
#
#   1. CRUD: a policy can be created with a cron expression and is visible
#      on the list endpoint.
#   2. Force-trigger: an admin endpoint synchronously fires the policy and
#      produces a scan row for the targeted repository. This is the
#      release-gate-safe assertion (no >60s wait).
#   3. Cron-driven trigger: if no force-trigger endpoint is mounted, the
#      cadence assertion is gated behind SCHEDULED_SCAN_WAIT_FOR_CRON=1
#      and skipped by default. We refuse to fake-pass by polling for a
#      single minute and calling it good; cron-cadence E2E is
#      manual-only / nightly-only.
#
# Skip semantics
# --------------
# - 404 on the policy CRUD endpoint -> SKIP_SUITE (feature not shipped)
# - 5xx on policy CRUD -> FAIL (broken subsystem)
# - 404 on force-trigger AND SCHEDULED_SCAN_WAIT_FOR_CRON unset -> SKIP
#   the cadence assertion with a precise reason. This is the documented
#   manual-only escape hatch and does NOT silently pass.
#
# Requires: curl, jq
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "scheduled-scan"
auth_admin
setup_workdir

REPO_KEY="sched-scan-${RUN_ID}"
POLICY_NAME="sched-${RUN_ID}"
POLICY_ID=""
SCHEDULED_SCAN_WAIT_FOR_CRON="${SCHEDULED_SCAN_WAIT_FOR_CRON:-0}"

cleanup() {
  if [ -n "$POLICY_ID" ]; then
    api_delete "/api/v1/security/scan-schedules/${POLICY_ID}" >/dev/null 2>&1 || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler 'cleanup'

begin_test "Create target repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo ${REPO_KEY}"
fi

begin_test "Create scheduled scan policy (cron every minute)"
# Cron "* * * * *" fires every minute; concrete enough that a manual run with
# SCHEDULED_SCAN_WAIT_FOR_CRON=1 can validate cadence inside ~120s.
payload=$(jq -n --arg name "$POLICY_NAME" --arg key "$REPO_KEY" \
  '{name:$name, repository_key:$key, cron:"* * * * *", enabled:true}')
crt_status=$(curl -s -o "${WORK_DIR}/policy.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$payload" \
  "${BASE_URL}/api/v1/security/scan-schedules") || crt_status="000"
case "$crt_status" in
  200|201)
    POLICY_ID=$(jq -r '.id // empty' < "${WORK_DIR}/policy.json" 2>/dev/null || echo "")
    if [ -n "$POLICY_ID" ]; then
      pass
    else
      fail "policy created but response missing id (body: $(head -c 200 "${WORK_DIR}/policy.json"))"
    fi
    ;;
  404)
    skip_suite "scan-schedules endpoint not mounted (HTTP 404); scheduled-scan feature not shipped on this backend"
    ;;
  *)
    fail "POST /security/scan-schedules returned HTTP ${crt_status} (body: $(head -c 200 "${WORK_DIR}/policy.json"))"
    ;;
esac

begin_test "Policy appears on list endpoint"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id from create step"
else
  list_resp=$(api_get "/api/v1/security/scan-schedules" 2>/dev/null || true)
  if [ -z "$list_resp" ]; then
    fail "list endpoint returned empty body"
  else
    found=$(echo "$list_resp" | jq -r --arg id "$POLICY_ID" '
      (.items // .) | (if type=="array" then . else [] end) | map(select(.id == $id)) | length')
    if [ "$found" = "1" ]; then
      pass
    else
      fail "policy ${POLICY_ID} not visible on list endpoint (found=${found})"
    fi
  fi
fi

# Force-trigger path: synchronous, release-gate-safe. If the backend mounts
# an admin/trigger endpoint we use it and assert the scan row appears within
# 30s. If not, the cadence-based assertion is gated behind an opt-in env.
begin_test "Force-trigger schedule produces a scan row"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id from create step"
else
  trigger_start=$(date -u +%s)
  sleep 2
  ft_status=$(curl -s -o "${WORK_DIR}/trigger.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/scan-schedules/${POLICY_ID}/trigger") || ft_status="000"
  case "$ft_status" in
    200|201|202)
      # Poll repo-scoped scan list for any row newer than trigger_start.
      observed=0
      elapsed=0
      while [ "$elapsed" -lt 30 ]; do
        resp=$(api_get "/api/v1/repositories/${REPO_KEY}/security/scans" 2>/dev/null || true)
        if [ -n "$resp" ]; then
          fresh=$(echo "$resp" | jq -r --argjson cutoff "$trigger_start" '
            (.items // []) | map(select(
              .created_at != null and
              (.created_at | sub("\\.[0-9]+Z?$"; "Z") | sub("\\+[0-9:]+$"; "Z")
                | fromdateiso8601? // 0) >= $cutoff
            )) | length' 2>/dev/null || echo "0")
          if [ "$fresh" != "0" ] && [ -n "$fresh" ]; then
            observed=1; break
          fi
        fi
        sleep 3
        elapsed=$(( elapsed + 3 ))
      done
      if [ "$observed" = "1" ]; then
        pass
      else
        fail "force-trigger returned ${ft_status} but no fresh scan row appeared within 30s"
      fi
      ;;
    404)
      if [ "$SCHEDULED_SCAN_WAIT_FOR_CRON" = "1" ]; then
        # Opt-in cadence assertion: wait up to TEST_TIMEOUT (default 120s)
        # for cron "* * * * *" to fire. Manual / nightly only.
        echo "  force-trigger not mounted; SCHEDULED_SCAN_WAIT_FOR_CRON=1 -> waiting for cron tick"
        elapsed=0
        wait_max="${TEST_TIMEOUT:-120}"
        observed=0
        while [ "$elapsed" -lt "$wait_max" ]; do
          resp=$(api_get "/api/v1/repositories/${REPO_KEY}/security/scans" 2>/dev/null || true)
          fresh=$(echo "$resp" | jq -r --argjson cutoff "$trigger_start" '
            (.items // []) | map(select(
              .created_at != null and
              (.created_at | sub("\\.[0-9]+Z?$"; "Z") | sub("\\+[0-9:]+$"; "Z")
                | fromdateiso8601? // 0) >= $cutoff
            )) | length' 2>/dev/null || echo "0")
          if [ "$fresh" != "0" ] && [ -n "$fresh" ]; then
            observed=1; break
          fi
          sleep 5
          elapsed=$(( elapsed + 5 ))
        done
        if [ "$observed" = "1" ]; then
          pass
        else
          fail "no scheduled scan fired within ${wait_max}s of cron '* * * * *' (force-trigger unavailable, cadence path failed)"
        fi
      else
        skip "force-trigger endpoint not mounted (HTTP 404) and SCHEDULED_SCAN_WAIT_FOR_CRON unset; cron-cadence is manual-only to keep gate runtime bounded"
      fi
      ;;
    *)
      fail "force-trigger returned HTTP ${ft_status} (body: $(head -c 200 "${WORK_DIR}/trigger.json"))"
      ;;
  esac
fi

begin_test "Delete policy"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/scan-schedules/${POLICY_ID}") || del_status="000"
  case "$del_status" in
    200|204) POLICY_ID=""; pass ;;
    *)       fail "DELETE policy returned HTTP ${del_status}" ;;
  esac
fi

end_suite
