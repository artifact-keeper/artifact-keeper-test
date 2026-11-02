#!/usr/bin/env bash
# =============================================================================
# tiers/gcs-error-url-redaction/oracle.sh
#   artifact-keeper#5093 (PR #5094): GCS request URLs stay out of client-visible
#   error messages. See the manifest for the method and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
OCI="dtf-gcsredact-oci-${SUF}"
MVN="dtf-gcsredact-mvn-${SUF}"
EMU_CTR="ak-dtf${DTF_SLOT}-fake-gcs"
COORD="com/dtf/redact/1.0.0/redact-1.0.0.jar"
BUCKET="ak-artifacts"
HOST="fake-gcs"
# /health's cache TTL for the storage probe is seconds; poll past it.
HEALTH_WAIT_SECS=60

# What a client must never see: a URL, the endpoint host or port, the bucket.
leak_in() { grep -aoE "https?://[^\" ]*|${HOST}|:4443|${BUCKET}|storage/v1|upload/storage" "$1" 2>/dev/null | sort -u | tr '\n' ' ' || true; }
snip() { head -c 500 "$1" 2>/dev/null | tr -d '\n' || true; }
api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
push_blob() { # <file> <out> -> HTTP code
  curl -s -o "$2" -w '%{http_code}' --max-time 90 -u "admin:${ADMIN_PASS}" -X POST \
    -H 'Content-Type: application/octet-stream' --data-binary "@$1" \
    "${BASE_URL}/v2/${OCI}/app/blobs/uploads/?digest=sha256:$(sha256sum "$1" | awk '{print $1}')" 2>/dev/null || echo 000
}
storage_status() { jq -r '.checks.storage.status // empty' "$1" 2>/dev/null || true; }

begin_suite "gcs-error-url-redaction"

begin_test "setup: admin login, a docker and a maven repository on the GCS backend"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at ${BASE_URL}"; end_suite; fi
ERR=""
for spec in "$OCI docker" "$MVN maven"; do
  set -- $spec
  st="$(api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')")"
  case "$st" in 2??) ;; *) ERR="${ERR} create $1: HTTP ${st} $(head -c 200 "$W/api.json");" ;; esac
done
if [ -z "$ERR" ]; then pass; else infra_fail "$ERR"; end_suite; fi

begin_test "CONTROL: with the emulator up, /health reports storage healthy and a blob upload succeeds"
curl -s -o "$W/health0.json" --max-time 30 "${BASE_URL}/health" 2>/dev/null || true
printf 'blob-up-%s' "$SUF" > "$W/up.blob"
st="$(push_blob "$W/up.blob" "$W/up.out")"
h="$(storage_status "$W/health0.json")"
if [ "$h" = "healthy" ] && [ "$st" = "201" ]; then pass
else fail "storage '${h}', blob upload HTTP ${st}, want healthy and 201" "$(snip "$W/health0.json")"; fi

begin_test "CONTROL: the Maven artifact uploads with the emulator up"
st="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X PUT -H "Authorization: Bearer ${TOK}" \
  -H 'Content-Type: application/octet-stream' --data-binary "payload-${SUF}" "${BASE_URL}/maven/${MVN}/${COORD}" 2>/dev/null || echo 000)"
case "$st" in 2??) pass ;; *) fail "HTTP ${st}, want 2xx" ;; esac

# ---------------------------------------------------------------------------
# Every GCS request now fails in transport.
# ---------------------------------------------------------------------------
if ! docker stop -t 2 "$EMU_CTR" >/dev/null 2>&1; then
  begin_test "setup: stop the emulator"; infra_fail "could not stop ${EMU_CTR}"; end_suite
fi

begin_test "CONTROL: /health reports the storage failure once the emulator is down"
h=""
for _ in $(seq 1 "$HEALTH_WAIT_SECS"); do
  curl -s -o "$W/health.json" --max-time 30 "${BASE_URL}/health" 2>/dev/null || true
  h="$(storage_status "$W/health.json")"
  [ -n "$h" ] && [ "$h" != "healthy" ] && break
  sleep 1
done
msg="$(jq -r '.checks.storage.message // empty' "$W/health.json" 2>/dev/null || true)"
if [ -n "$h" ] && [ "$h" != "healthy" ] && [ -n "$msg" ]; then pass
else fail "storage '${h}' message '${msg}', want a non-healthy status with a message" "$(snip "$W/health.json")"; fi

begin_test "FIX #5093: the /health body names no URL, endpoint host or bucket"
leak="$(leak_in "$W/health.json")"
if [ -z "$leak" ]; then pass; else fail "/health leaks: ${leak}" "$(snip "$W/health.json")"; fi

begin_test "FIX #5093: the /healthz body names no URL, endpoint host or bucket"
curl -s -o "$W/healthz.json" --max-time 30 "${BASE_URL}/healthz" 2>/dev/null || true
leak="$(leak_in "$W/healthz.json")"
if [ -s "$W/healthz.json" ] && [ -z "$leak" ]; then pass; else fail "/healthz leaks: '${leak}'" "$(snip "$W/healthz.json")"; fi

begin_test "FIX #5093: a failing OCI blob upload body names no URL, host, bucket or object key"
printf 'blob-down-%s' "$SUF" > "$W/down.blob"
st="$(push_blob "$W/down.blob" "$W/down.out")"
leak="$(leak_in "$W/down.out")"
grep -aq "oci-blobs" "$W/down.out" 2>/dev/null && leak="${leak} oci-blobs-key"
case "$st" in 5??) failed=1 ;; *) failed=0 ;; esac
if [ "$failed" = "1" ] && [ -z "$leak" ]; then pass
else fail "HTTP ${st} (want 5xx), leaks: '${leak}'" "$(snip "$W/down.out")"; fi

begin_test "CONTROL: a failing Maven upload body names no URL, host, bucket or object key"
st="$(curl -s -o "$W/mvnup.out" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
  -H 'Content-Type: application/octet-stream' --data-binary "down-${SUF}" \
  "${BASE_URL}/maven/${MVN}/com/dtf/redact/2.0.0/redact-2.0.0.jar" 2>/dev/null || echo 000)"
leak="$(leak_in "$W/mvnup.out")"
grep -aq "redact-2.0.0" "$W/mvnup.out" 2>/dev/null && leak="${leak} object-key"
case "$st" in 5??) failed=1 ;; *) failed=0 ;; esac
if [ "$failed" = "1" ] && [ -z "$leak" ]; then pass
else fail "HTTP ${st} (want 5xx), leaks: '${leak}'" "$(snip "$W/mvnup.out")"; fi

begin_test "CONTROL: a failing Maven download body names no URL, host, bucket or object key"
st="$(curl -s -o "$W/mvndl.out" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
  "${BASE_URL}/maven/${MVN}/${COORD}" 2>/dev/null || echo 000)"
leak="$(leak_in "$W/mvndl.out")"
grep -aq "redact-1.0.0" "$W/mvndl.out" 2>/dev/null && leak="${leak} object-key"
case "$st" in 2??) failed=0 ;; *) failed=1 ;; esac
if [ "$failed" = "1" ] && [ -z "$leak" ]; then pass
else fail "HTTP ${st} (want a failure), leaks: '${leak}'" "$(snip "$W/mvndl.out")"; fi

end_suite
