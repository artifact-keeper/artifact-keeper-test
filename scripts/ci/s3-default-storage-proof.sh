#!/usr/bin/env bash
# s3-default-storage-proof.sh - prove that the nightly S3 format matrix's
# backend really stores on MinIO by default (artifact-keeper#6121).
#
# A format suite that passes on this namespace means something only if its
# bytes went to object storage. The backend falls back to the filesystem
# silently when STORAGE_BACKEND is unset or misspelled, so this checks the
# outcome, not the configuration:
#
#   pre   (before the format tiers): the admin storage-backends listing has
#         s3; a generic repository created WITHOUT a storage_backend reports
#         storage_backend "s3"; a unique blob uploaded to it round-trips and
#         its sha256 content key is an object in the MinIO bucket.
#   post  (after the format tiers): every repository still on the instance
#         reports storage_backend "s3" (most suites delete their repositories
#         when they finish, so this is the survivors, never a count), and NO
#         content-addressed file (a 64-hex sha256 name) exists under the
#         backend pod's STORAGE_PATH: artifact bytes a handler wrote to the
#         local disk instead of the bucket are a product bug on S3, and this
#         is the check that sees them. The bucket's object count is reported.
#
# Usage: s3-default-storage-proof.sh pre|post
# Env:   BASE_URL, ADMIN_PASS, RUN_ID, NAMESPACE (the test namespace),
#        JUNIT_OUTPUT_DIR. S3_BUCKET/MINIO_* default to helm/storage-emulators.yaml.
set -uo pipefail

PHASE="${1:?usage: s3-default-storage-proof.sh pre|post}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../tests/lib/common.sh
source "${SCRIPT_DIR}/../../tests/lib/common.sh"

: "${NAMESPACE:?NAMESPACE is required}"
S3_BUCKET="${S3_BUCKET:-ak-e2e}"
MINIO_USER="${MINIO_USER:-ak-test-access}"
MINIO_PASS="${MINIO_PASS:-ak-test-secret-2026}"
MC_IMAGE="${MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"

# bucket_listing OUT: `mc ls --recursive` of the bucket, run from a short-lived
# pod in the test namespace (MinIO is only reachable in-cluster under its
# Service name, and the runner has no S3 client). Requests are set because
# the namespace carries a ResourceQuota.
bucket_listing() {
  local out="$1" pod
  pod="s3-proof-${PHASE}-$(date +%s)"
  local overrides
  overrides=$(cat <<JSON
{"apiVersion":"v1","spec":{"restartPolicy":"Never","containers":[{"name":"mc","image":"${MC_IMAGE}",
 "command":["/bin/sh","-c","mc alias set l http://storage-minio:9000 ${MINIO_USER} ${MINIO_PASS} >/dev/null && mc ls --recursive l/${S3_BUCKET}"],
 "resources":{"requests":{"cpu":"10m","memory":"32Mi"},"limits":{"cpu":"200m","memory":"128Mi"}}}]}}
JSON
)
  kubectl -n "$NAMESPACE" run "$pod" --image="$MC_IMAGE" --restart=Never --overrides="$overrides" >/dev/null || return 1
  local phase=""
  for _ in $(seq 1 60); do
    phase=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [[ "$phase" == "Succeeded" || "$phase" == "Failed" ]] && break
    sleep 2
  done
  kubectl -n "$NAMESPACE" logs "$pod" > "$out" 2>&1 || true
  kubectl -n "$NAMESPACE" delete pod "$pod" --wait=false >/dev/null 2>&1 || true
  [[ "$phase" == "Succeeded" ]]
}

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

begin_suite "s3-default-storage-${PHASE}"
auth_admin
setup_workdir

case "$PHASE" in
  pre)
    begin_test "s3 is a registered storage backend"
    if api_get "/api/v1/admin/storage-backends" > "${WORK_DIR}/backends.json" 2>/dev/null \
       && jq -e '(if type=="array" then . elif (.backends|type)=="array" then .backends elif (.items|type)=="array" then .items else [] end)
                 | map(if type=="string" then . else (.name // .key // .backend_type // "") end) | index("s3") != null' \
            "${WORK_DIR}/backends.json" >/dev/null; then
      pass
    else
      fail "admin storage-backends does not list s3: $(head -c 300 "${WORK_DIR}/backends.json" 2>/dev/null)"
    fi

    repo="s3-proof-${RUN_ID}"
    begin_test "A repository created without storage_backend lands on s3"
    code=$(curl -s -o "${WORK_DIR}/create.json" -w '%{http_code}' $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "{\"key\":\"${repo}\",\"name\":\"${repo}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
      "${BASE_URL}/api/v1/repositories")
    backend=$(api_get "/api/v1/repositories/${repo}" 2>/dev/null | jq -r '.storage_backend // empty')
    if [[ "$code" =~ ^20[01]$ && "$backend" == "s3" ]]; then
      pass
    else
      fail "create answered ${code}; the repository reports storage_backend '${backend:-<none>}', want 's3' (STORAGE_BACKEND=s3 is not the default)" \
        "$(head -c 400 "${WORK_DIR}/create.json")"
    fi

    begin_test "An uploaded blob is an object in the MinIO bucket"
    printf 's3 default storage proof %s %s\n' "$RUN_ID" "$(date +%s%N)" > "${WORK_DIR}/proof.txt"
    want=$(sha256_of "${WORK_DIR}/proof.txt")
    if ! api_upload "/api/v1/repositories/${repo}/artifacts/proof/proof.txt" "${WORK_DIR}/proof.txt" text/plain >/dev/null; then
      fail "upload to ${repo} failed"
    elif ! api_get "/api/v1/repositories/${repo}/download/proof/proof.txt" -o "${WORK_DIR}/proof.down" \
         || [[ "$(sha256_of "${WORK_DIR}/proof.down")" != "$want" ]]; then
      fail "download from ${repo} did not round-trip"
    elif ! bucket_listing "${WORK_DIR}/bucket.txt"; then
      fail "could not list bucket ${S3_BUCKET}" "$(tail -n 20 "${WORK_DIR}/bucket.txt")"
    elif grep -q "${want}" "${WORK_DIR}/bucket.txt"; then
      echo "  object: $(grep "${want}" "${WORK_DIR}/bucket.txt" | head -n1)"
      pass
    else
      fail "no object keyed by sha256 ${want} in bucket ${S3_BUCKET} ($(wc -l < "${WORK_DIR}/bucket.txt") objects); the bytes went somewhere else" \
        "$(head -n 20 "${WORK_DIR}/bucket.txt")"
    fi
    ;;

  post)
    begin_test "Every repository on the instance is on s3"
    if fetch_all_pages "/api/v1/repositories" "${WORK_DIR}/repos.json" "$(auth_header)"; then
      total=$(jq '.items | length' "${WORK_DIR}/repos.json")
      echo "  by backend: $(jq -r '.items | group_by(.storage_backend) | map("\(.[0].storage_backend)=\(length)") | join(" ")' "${WORK_DIR}/repos.json")"
      others=$(jq -r '.items[] | select(.storage_backend != "s3") | "\(.key) (\(.format), \(.storage_backend))"' "${WORK_DIR}/repos.json")
      if [[ "$total" -lt 1 ]]; then
        fail "no repositories on the instance; even the pre-proof repository is gone"
      elif [[ -n "$others" ]]; then
        fail "$(wc -l <<<"$others") of ${total} repositories are not on s3" "$others"
      else
        pass
      fi
    else
      fail "could not list repositories (HTTP ${FETCH_ALL_STATUS:-?})"
    fi

    begin_test "No artifact bytes on the backend's local disk"
    pod=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/component=backend \
            --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    root=""
    [[ -n "$pod" ]] && root=$(kubectl -n "$NAMESPACE" exec "$pod" -- printenv STORAGE_PATH 2>/dev/null | tr -d '\r' || true)
    if [[ -z "$pod" || -z "$root" ]]; then
      fail "could not find the running backend pod or its STORAGE_PATH (pod '${pod}')"
    elif ! kubectl -n "$NAMESPACE" exec "$pod" -- ls -d "$root" > "${WORK_DIR}/fs.txt" 2>&1; then
      fail "could not read ${root} in ${pod}" "$(tail -n 20 "${WORK_DIR}/fs.txt")"
    else
      # ls -laR prints "<dir>:" headers, then entries; keep regular files whose
      # name is a sha256 and prefix them with their directory. Its exit code is
      # ignored (an unreadable lost+found makes it non-zero); the ls -d above
      # proved the root itself is readable.
      kubectl -n "$NAMESPACE" exec "$pod" -- ls -laR "$root" > "${WORK_DIR}/fs.txt" 2>/dev/null || true
      awk '/:$/ { dir=substr($0, 1, length($0)-1); next }
           /^-/ && $NF ~ /^[0-9a-f]{64}$/ { print dir "/" $NF " (" $5 " bytes)" }' "${WORK_DIR}/fs.txt" > "${WORK_DIR}/fs-cas.txt"
      echo "  ${root}: $(grep -c '^-' "${WORK_DIR}/fs.txt" || true) regular files, $(wc -l < "${WORK_DIR}/fs-cas.txt") content-addressed"
      if [[ -s "${WORK_DIR}/fs-cas.txt" ]]; then
        fail "$(wc -l < "${WORK_DIR}/fs-cas.txt") content-addressed files under ${root} on an S3-default backend" "$(head -n 30 "${WORK_DIR}/fs-cas.txt")"
      else
        pass
      fi
    fi

    begin_test "The MinIO bucket is listable"
    if bucket_listing "${WORK_DIR}/bucket.txt"; then
      echo "  bucket ${S3_BUCKET}: $(grep -c . "${WORK_DIR}/bucket.txt" || true) objects after the format tiers (suites delete what they create)"
      pass
    else
      fail "could not list bucket ${S3_BUCKET}" "$(tail -n 20 "${WORK_DIR}/bucket.txt")"
    fi
    ;;
  *)
    echo "usage: s3-default-storage-proof.sh pre|post" >&2
    exit 2
    ;;
esac

end_suite
