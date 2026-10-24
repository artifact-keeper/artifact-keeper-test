#!/usr/bin/env bash
# =============================================================================
# tiers/conda-jlap-incremental/oracle.sh: a real conda client with JLAP
#   enabled updates a hosted channel's cached index from repodata.json.jlap
#   alone, after an upload and after a withdrawal (artifact-keeper#4175)
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1,
# COMMON_SH.
#
# Topology (key suffixed per run):
#   H  public hosted conda channel; jl-a 1.0 uploaded, then jl-b 1.0, then
#      jl-b withdrawn.
#   C  condaforge/miniforge3:25.11.0-1 (conda 25.11, --experimental=jlap,
#      local_repodata_ttl=0) in the backend container's network namespace,
#      reaching the backend through fixtures/logproxy.py, which logs every
#      request (path, Range, status, bytes).
#
# Gates (1.12.0; RED on 1.11.5):
#   #4175 patch   after the second upload, the client's refresh requests
#                 noarch/repodata.jlap (the name conda requests) and
#                 downloads no noarch
#                 repodata.json / .zst / .bz2, and ends with a cached index
#                 equal to a full fetch that lists jl-b (1.11.5: the JLAP
#                 has no patch, conda falls back to the full .zst).
#   #4175 chain   the JLAP's BLAKE2b chain verifies, it carries at least one
#                 patch, and its footer names the hash of the repodata.json
#                 served now (1.11.5: no patch).
#   #4175 withdrawal  after jl-b is withdrawn the refresh is a range request
#                 answered 206, again no index download, and the cached index
#                 equals a full fetch and no longer lists jl-b (1.11.5: full
#                 .zst download).
# CONTROL (both images): the first refresh (no cache) downloads the full
#   index and caches a document equal to a full fetch.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
H="jlap-host-${SUF}"
TIER_DIR="${DTF_DIR}/harness/tiers/conda-jlap-incremental"
CLIENT_IMAGE="docker.io/condaforge/miniforge3:25.11.0-1"
CLIENT="ak-dtf${DTF_SLOT}-jlap-client"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
PROXY="http://127.0.0.1:9123"
DIRECT="http://127.0.0.1:8080"
FN_A="jl-a-1.0-0.tar.bz2"
FN_B="jl-b-1.0-0.tar.bz2"

WORK="$(mktemp -d -t dtf-jlap-XXXXXX)"
cleanup() { docker rm -f "$CLIENT" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

put_pkg() {
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$WORK/$1" \
    "${BASE_URL}/conda/${H}/noarch/$1" 2>/dev/null || echo 000
}
cx() { docker exec "$CLIENT" bash -c "$1" 2>&1; }
# refresh <tag>: one conda search against the channel through the proxy, with
# a fresh request log; the log lands in $WORK/<tag>.log, output in <tag>.out.
refresh() {
  cx ': > /tmp/proxy.log' >/dev/null
  cx "export CONDA_PKGS_DIRS=/tmp/pkgs CONDA_LOCAL_REPODATA_TTL=0 CONDA_EXPERIMENTAL=jlap; \
      conda search --override-channels -c ${PROXY}/conda/${H} --experimental=jlap --json 'jl-*'" \
    > "$WORK/$1.out"
  printf '\nrc=%s\n' "$?" >> "$WORK/$1.out"
  cx 'cat /tmp/proxy.log' > "$WORK/$1.log"
}
# noarch_requests <tag>: "<status> <range|-> <file>" per noarch request.
noarch_requests() {
  jq -r 'select(.path | test("/noarch/")) | "\(.status) \(.range // "-") \(.path | split("/") | last)"' \
    "$WORK/$1.log" 2>/dev/null || true
}
# index_downloads <tag>: noarch full-index documents answered with a body.
index_downloads() {
  noarch_requests "$1" | awk '$1 == 200 && $3 ~ /^repodata\.json(\.zst|\.bz2)?$/' | wc -l | tr -d ' '
}
cache_report() {
  cx "python3 -I /fx/jlap_check.py cache /tmp/pkgs/cache ${DIRECT}/conda/${H}/noarch/repodata.json $1" | tail -1
}

begin_suite "conda-jlap-incremental (#4175)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, hosted channel, packages, conda client with a logging proxy"
auth_admin
setup_err=""
st="$(curl -s --max-time 30 -o "$WORK/create.out" -w '%{http_code}' -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${H}\",\"name\":\"${H}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":true}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
case "$st" in 200|201) ;; *) setup_err+="create ${H} -> HTTP ${st}; " ;; esac
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
for n in jl-a jl-b; do
  bash "$BUILD" "$WORK" "$n" 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${n}; "
done
st="$(put_pkg "$FN_A")"
case "$st" in 200|201) ;; *) setup_err+="upload ${FN_A} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); " ;; esac
docker image inspect "$CLIENT_IMAGE" >/dev/null 2>&1 || docker pull -q "$CLIENT_IMAGE" >/dev/null 2>&1 \
  || setup_err+="pull ${CLIENT_IMAGE}; "
docker rm -f "$CLIENT" >/dev/null 2>&1 || true
docker run -d --name "$CLIENT" --network "container:${BACKEND_CTR}" --security-opt label=disable \
  -v "${TIER_DIR}/fixtures:/fx:ro" -e PROXY_LOG=/tmp/proxy.log \
  "$CLIENT_IMAGE" python3 -I /fx/logproxy.py >/dev/null 2>&1 || setup_err+="start client; "
up=0
for _ in $(seq 1 30); do
  if cx "python3 -I -c \"import urllib.request; urllib.request.urlopen('${PROXY}/health', timeout=5)\"" >/dev/null; then
    up=1; break
  fi
  sleep 1
done
[ "$up" = 1 ] || setup_err+="proxy not reachable; "
ver="$(cx 'conda --version' | tail -1)"
echo "  client: ${ver}"
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROL: the first refresh downloads the whole index
# =============================================================================
begin_test "CONTROL: a client with no cache downloads the full index and caches what the server serves"
refresh r1
reqs="$(noarch_requests r1 | tr '\n' ';')"
rep="$(cache_report "$FN_A")"
detail="$(tail -1 "$WORK/r1.out"); noarch requests: ${reqs}; cache: ${rep}"
echo "  ${detail}"
if grep -q '^rc=0$' "$WORK/r1.out" && [ "$(index_downloads r1)" -ge 1 ] \
   && [ "$(echo "$rep" | jq -r '.equal' 2>/dev/null)" = "true" ] \
   && [ "$(echo "$rep" | jq -r '.listed' 2>/dev/null)" = "true" ]; then
  pass
else
  fail "the first refresh did not cache the served index" "$detail"
fi

# =============================================================================
# #4175: after an upload the client updates from the JLAP alone
# =============================================================================
begin_test "#4175: after an upload, the refresh fetches only .jlap and ends equal to a full fetch"
st="$(put_pkg "$FN_B")"
refresh r2
reqs="$(noarch_requests r2 | tr '\n' ';')"
dl="$(index_downloads r2)"
jl="$(noarch_requests r2 | awk '$3 ~ /^repodata(\.json)?\.jlap$/ && ($1 == 200 || $1 == 206)' | wc -l | tr -d ' ')"
rep="$(cache_report "$FN_B")"
detail="upload HTTP ${st}; $(tail -1 "$WORK/r2.out"); noarch requests: ${reqs}; full-index downloads ${dl}; cache: ${rep}"
echo "  ${detail}"
if grep -q '^rc=0$' "$WORK/r2.out" && [ "$jl" -ge 1 ] && [ "$dl" = "0" ] \
   && [ "$(echo "$rep" | jq -r '.equal' 2>/dev/null)" = "true" ] \
   && [ "$(echo "$rep" | jq -r '.listed' 2>/dev/null)" = "true" ]; then
  pass
else
  fail "the client did not update its index from the JLAP" "$detail"
fi

begin_test "#4175: the JLAP chain verifies, carries a patch and names the served repodata.json"
ch="$(cx "python3 -I /fx/jlap_check.py chain ${DIRECT}/conda/${H}/noarch/repodata.jlap ${DIRECT}/conda/${H}/noarch/repodata.json" | tail -1)"
echo "  ${ch}"
if [ "$(echo "$ch" | jq -r '.ok' 2>/dev/null)" = "true" ] \
   && [ "$(echo "$ch" | jq -r '.patches' 2>/dev/null)" -ge 1 ] 2>/dev/null \
   && [ "$(echo "$ch" | jq -r '.latest_is_served' 2>/dev/null)" = "true" ]; then
  pass
else
  fail "the JLAP is not a patch chain ending at the served index" "$ch"
fi

# =============================================================================
# #4175: a withdrawal reaches the client through a range request
# =============================================================================
begin_test "#4175: after a withdrawal, a range request alone removes the package from the cached index"
wd="$(curl -s --max-time 60 -o "$WORK/wd.json" -w '%{http_code}' -X DELETE \
  -H "$(auth_header)" -H 'Content-Type: application/json' -d '{"reason":"dtf conda-jlap-incremental"}' \
  "${BASE_URL}/conda/${H}/noarch/${FN_B}" 2>/dev/null || echo 000)"
refresh r3
reqs="$(noarch_requests r3 | tr '\n' ';')"
dl="$(index_downloads r3)"
ranged="$(noarch_requests r3 | awk '$1 == 206 && $2 != "-" && $3 ~ /^repodata(\.json)?\.jlap$/' | wc -l | tr -d ' ')"
rep="$(cache_report "$FN_B")"
detail="withdraw HTTP ${wd}; $(tail -1 "$WORK/r3.out"); noarch requests: ${reqs}; full-index downloads ${dl}; cache: ${rep}"
echo "  ${detail}"
if [ "$wd" = "200" ] && grep -q '^rc=0$' "$WORK/r3.out" && [ "$ranged" -ge 1 ] && [ "$dl" = "0" ] \
   && [ "$(echo "$rep" | jq -r '.equal' 2>/dev/null)" = "true" ] \
   && [ "$(echo "$rep" | jq -r '.listed' 2>/dev/null)" = "false" ] \
   && [ "$(echo "$rep" | jq -r '.server_listed' 2>/dev/null)" = "false" ]; then
  pass
else
  fail "the withdrawal did not reach the client through the JLAP" "$detail"
fi

end_suite
