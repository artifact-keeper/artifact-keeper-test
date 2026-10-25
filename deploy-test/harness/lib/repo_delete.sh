#!/usr/bin/env bash
# shellcheck disable=SC2034  # REPO_DELETE_* are read by the sourcing oracle
# =============================================================================
# harness/lib/repo_delete.sh: repository delete that works on 1.11 and 1.12
# =============================================================================
# `DELETE /api/v1/repositories/{key}` has two contracts:
#
#   * 1.11.x answers 200 (or 204). The rows are gone when it answers; the
#     storage purge runs in a background task right after.
#   * 1.12.0 (artifact-keeper#4311, #4996) answers 202 with a job:
#       {"id": "<uuid>", "status": "pending", "phase": "queued",
#        "status_url": "/api/v1/repository-deletions/<uuid>", ...}
#     and a `Location` header naming the same status URL. The repository is
#     renamed to `~deleting~<job id>` at once (its key stops resolving); its
#     rows and objects are removed by the job. The job is terminal at
#     `completed` or `failed`.
#
# An oracle that asserts anything about rows or objects after a repository
# delete must wait for the job on 1.12. These helpers leave the 1.11 path
# unchanged: a 200/204 returns at once, exactly as before.
#
# Usage (source after common.sh, with `set +e` in effect):
#
#   source "${DTF_DIR}/harness/lib/repo_delete.sh"
#
#   delete_repository_and_wait BASE_URL TOKEN KEY [TIMEOUT_S]
#       DELETE the repository, then wait for its job if the answer is 202.
#       Returns 0 when the delete was accepted (200/204) or its job reached
#       `completed`; non-zero otherwise. Sets:
#         REPO_DELETE_CODE    HTTP status of the DELETE
#         REPO_DELETE_BODY    file holding the DELETE response body
#         REPO_DELETE_JOB_ID  job id (202 only, else empty)
#         REPO_DELETE_JOB_STATUS  terminal job status, `timeout`, or empty
#         REPO_DELETE_ERROR   human-readable reason when it returns non-zero
#       Call it directly, not in `$(...)`, or the variables are lost.
#
#   repo_delete_wait BASE_URL TOKEN CODE BODY_FILE [TIMEOUT_S]
#       For an oracle that issued the DELETE itself (at a precise moment) and
#       waits later: given the DELETE's status and body file, wait for the job
#       on 202, return at once on 200/204. Same return value and variables
#       (REPO_DELETE_CODE is set to CODE).
#
# The timeout defaults to REPO_DELETE_TIMEOUT (120 s). Polling is once per
# second. A 202 without a job id, a failed job and a timeout all return
# non-zero with REPO_DELETE_ERROR saying which.
# =============================================================================

REPO_DELETE_TIMEOUT="${REPO_DELETE_TIMEOUT:-120}"
REPO_DELETE_CODE=""
REPO_DELETE_BODY=""
REPO_DELETE_JOB_ID=""
REPO_DELETE_JOB_STATUS=""
REPO_DELETE_ERROR=""

_repo_delete_tmp() {
  if [ -z "${_REPO_DELETE_DIR:-}" ] || [ ! -d "${_REPO_DELETE_DIR}" ]; then
    _REPO_DELETE_DIR="$(mktemp -d -t dtf-repo-delete-XXXXXX)"
  fi
  printf '%s' "${_REPO_DELETE_DIR}"
}

repo_delete_wait() {
  local base="$1" token="$2" code="$3" body="$4" timeout="${5:-$REPO_DELETE_TIMEOUT}"
  local url job status phase err deadline poll pcode
  REPO_DELETE_CODE="$code"
  REPO_DELETE_BODY="$body"
  REPO_DELETE_JOB_ID=""
  REPO_DELETE_JOB_STATUS=""
  REPO_DELETE_ERROR=""
  case "$code" in
    200|204) return 0 ;;
    202) ;;
    *)
      REPO_DELETE_ERROR="DELETE answered ${code}: $(head -c 300 "$body" 2>/dev/null)"
      return 1 ;;
  esac
  job="$(jq -r '.id // empty' "$body" 2>/dev/null)"
  url="$(jq -r '.status_url // empty' "$body" 2>/dev/null)"
  if [ -z "$job" ]; then
    REPO_DELETE_ERROR="DELETE answered 202 without a job id: $(head -c 300 "$body" 2>/dev/null)"
    return 1
  fi
  REPO_DELETE_JOB_ID="$job"
  [ -n "$url" ] || url="/api/v1/repository-deletions/${job}"
  case "$url" in http*) ;; *) url="${base}${url}" ;; esac
  poll="$(_repo_delete_tmp)/job-${job}.json"
  deadline=$(( $(date +%s) + timeout ))
  status=""; phase=""
  while :; do
    pcode="$(curl -s --max-time 30 -o "$poll" -w '%{http_code}' \
      -H "Authorization: Bearer ${token}" "$url" 2>/dev/null || echo 000)"
    if [ "$pcode" = "200" ]; then
      status="$(jq -r '.status // empty' "$poll" 2>/dev/null)"
      phase="$(jq -r '.phase // empty' "$poll" 2>/dev/null)"
      case "$status" in
        completed)
          REPO_DELETE_JOB_STATUS="completed"
          return 0 ;;
        failed)
          err="$(jq -r '.error_summary // empty' "$poll" 2>/dev/null)"
          REPO_DELETE_JOB_STATUS="failed"
          REPO_DELETE_ERROR="repository delete job ${job} failed in phase '${phase}': ${err:-no error_summary}"
          return 1 ;;
      esac
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      REPO_DELETE_JOB_STATUS="timeout"
      REPO_DELETE_ERROR="repository delete job ${job} not terminal after ${timeout}s (last poll HTTP ${pcode}, status '${status:-?}', phase '${phase:-?}'): $(head -c 300 "$poll" 2>/dev/null)"
      return 1
    fi
    sleep 1
  done
}

delete_repository_and_wait() {
  local base="$1" token="$2" key="$3" timeout="${4:-$REPO_DELETE_TIMEOUT}"
  local body code
  body="$(_repo_delete_tmp)/delete-${key}.json"
  code="$(curl -s --max-time 120 -o "$body" -w '%{http_code}' -X DELETE \
    -H "Authorization: Bearer ${token}" "${base}/api/v1/repositories/${key}" 2>/dev/null || echo 000)"
  repo_delete_wait "$base" "$token" "${code:-000}" "$body" "$timeout"
}
