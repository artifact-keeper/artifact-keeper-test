#!/usr/bin/env bash
# =============================================================================
# tiers/s3-copy-length-required/oracle.sh
#   Proxy-cache publishes succeed on an S3 endpoint that answers 411 to a
#   CopyObject without Content-Length (artifact-keeper#3737).
# =============================================================================
# run.sh has stood up `storage.s3 storage.s3-copy-411 upstreams.mock-static`
# with RATE_LIMIT_ENABLED=false and UPSTREAM_ALLOW_PRIVATE_IPS=true, and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock upstream's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. The shim's counters are read with docker exec.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
BACKEND_CTR="ak-dtf${SLOT}-backend"
SHIM_CTR="ak-dtf${SLOT}-s3-copy-411"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${SLOT}.70/"
GREPO="s3l-gen-${SLOT}-${SUF}"
RREPO="s3l-remote-${SLOT}-${SUF}"

WORK="$(mktemp -d -t dtf-s3l-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
shim() { # FIELD -> counter value
  docker exec "$SHIM_CTR" python3 -c \
    "import json,urllib.request;print(json.load(urllib.request.urlopen('http://127.0.0.1:9000/__shim/stats'))['$1'])" 2>/dev/null
}
mock_count() { curl -s --max-time 5 "${MOCK}/__requests?path=/f/$1" | jq -r '.count // empty' 2>/dev/null; }
failed_publishes() { docker logs "$BACKEND_CTR" 2>&1 | grep -c 'failed to publish staged proxy-cache object'; }
AUTHZ=()
mk_repo() { # KEY TYPE [extra] -> code
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-$1.json" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"$2\",\"is_public\":false${3:-}}"
}
remote_get() { # NAME TAG -> code (body in $WORK/TAG)
  code_to_file "${BASE_URL}/api/v1/repositories/${RREPO}/download/f/$1" "${WORK}/$2" "${AUTHZ[@]}"
}

begin_suite "s3-copy-length-required"
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
SF=""
c="$(mk_repo "$GREPO" local)"; is_2xx "$c" || SF="${SF} generic=${c}"
c="$(mk_repo "$RREPO" remote ",\"upstream_url\":\"${UPSTREAM}\"")"; is_2xx "$c" || SF="${SF} remote=${c}"
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || SF="${SF} mock-static"
[ -n "$(shim forwarded)" ] || SF="${SF} shim-stats"
if [ -n "$SF" ]; then
  begin_test "setup: generic local + remote repositories, mock upstream, 411 shim"
  infra_fail "setup failed:${SF}" "$(head -c 300 "${WORK}/mk-${RREPO}.json" 2>/dev/null)"
  end_suite
fi

# =============================================================================
# CONTROLS
# =============================================================================
begin_test "CONTROL: a 64 KiB generic upload through the 411 shim is 201 and downloads byte-exact; the shim forwards the backend's S3 traffic"
head -c 65536 /dev/urandom > "${WORK}/gen.bin"
F0="$(shim forwarded)"
c="$(code_to_file "${BASE_URL}/api/v1/repositories/${GREPO}/artifacts/gen/a-${SUF}.bin" "${WORK}/gen.put" -X PUT "${AUTHZ[@]}" --data-binary "@${WORK}/gen.bin")"
d="$(code_to_file "${BASE_URL}/api/v1/repositories/${GREPO}/download/gen/a-${SUF}.bin" "${WORK}/gen.out" "${AUTHZ[@]}" -L)"
F1="$(shim forwarded)"
if [ "$c" = "201" ] && [ "$d" = "200" ] && cmp -s "${WORK}/gen.out" "${WORK}/gen.bin" && [ "${F1:-0}" -gt "${F0:-0}" ]; then pass; else
  fail "PUT=${c} GET=${d} byte-exact=$(cmp -s "${WORK}/gen.out" "${WORK}/gen.bin" && echo yes || echo no) shim forwarded ${F0} -> ${F1}" "$(head -c 300 "${WORK}/gen.put")"
fi

NAME="s3l-${SUF}.bin"
curl -s --max-time 10 -o "${WORK}/golden" "${MOCK}/__golden/${NAME}"
FP0="$(failed_publishes)"
R411_0="$(shim refused_411)"; CWL_0="$(shim copies_with_length)"
CODES=""; EXACT=""
for i in 1 2 3; do
  CODES="${CODES} $(remote_get "$NAME" "r${i}")"
  if cmp -s "${WORK}/r${i}" "${WORK}/golden"; then EXACT="${EXACT} y"; else EXACT="${EXACT} n"; fi
  sleep 1
done
UP="$(mock_count "$NAME")"
FP1="$(failed_publishes)"
R411_1="$(shim refused_411)"; CWL_1="$(shim copies_with_length)"

begin_test "CONTROL: three GETs of one file through the remote repository all answer 200 with the exact upstream bytes"
if [ "$CODES" = " 200 200 200" ] && [ "$EXACT" = " y y y" ] && [ -s "${WORK}/golden" ]; then pass; else
  fail "GET codes:${CODES} byte-exact:${EXACT}"
fi

# =============================================================================
# #3737
# =============================================================================
begin_test "#3737: the proxy cache published the first fetch: the three GETs reached the upstream once and no failed publish was logged"
if [ "$UP" = "1" ] && [ "$((FP1 - FP0))" = "0" ]; then pass; else
  fail "upstream GETs=${UP} (want 1); 'failed to publish staged proxy-cache object' log lines added: $((FP1 - FP0)). Pre-#3737 every CopyObject publish was refused with 411, nothing was cached and every request refetched the upstream"
fi

begin_test "#3737: the 411-refused CopyObject was retried with Content-Length (the shim saw CopyObjects carrying it)"
if [ "$((CWL_1 - CWL_0))" -ge 1 ] && [ "${R411_1:-0}" -ge 1 ]; then pass; else
  fail "shim: 411 refusals ${R411_0} -> ${R411_1}, CopyObjects with Content-Length ${CWL_0} -> ${CWL_1} (want >=1 refusal overall and >=1 new copy carrying Content-Length)"
fi

begin_test "#3737: a later proxy-cache publish sends Content-Length up front (no new 411, one more copy with Content-Length)"
NAME2="s3l-${SUF}-2.bin"
c="$(remote_get "$NAME2" r4)"
R411_2="$(shim refused_411)"; CWL_2="$(shim copies_with_length)"
if [ "$c" = "200" ] && [ "$R411_2" = "$R411_1" ] && [ "$((CWL_2 - CWL_1))" -ge 1 ]; then pass; else
  fail "GET=${c}; 411 refusals ${R411_1} -> ${R411_2} (want unchanged); copies with Content-Length ${CWL_1} -> ${CWL_2} (want +1)"
fi

end_suite
