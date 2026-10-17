#!/usr/bin/env bash
# =============================================================================
# tiers/metrics-and-backlog/oracle.sh — artifact transfer metrics are recorded
#   (artifact-keeper#4642) and HTTP_LISTEN_BACKLOG reaches the kernel with a
#   startup diagnostic (artifact-keeper#4647)
# =============================================================================
# run.sh has stood up `storage.filesystem listener.backlog-explicit` with
# RATE_LIMIT_ENABLED=false and HTTP_LISTEN_BACKLOG exported by the manifest
# (777), and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Metrics are scraped from the admin-gated exporter on the API port,
# GET /api/v1/admin/metrics (routes.rs nests health::metrics under /admin).
# The separate unauthenticated METRICS_PORT listener renders the same handle,
# so it adds nothing here and is not enabled.
#
# Discriminating gates (see the manifest for the full story):
#   (CONTROL) both images: /health 200; the exporter answers with the
#             pre-existing ak_http_* series; a generic upload and two
#             downloads serve the uploaded bytes and write two
#             download_statistics rows; a Maven PUT/GET round-trips; the API
#             listener is LISTENing on :8080.
#   (FIX #4642) ak_artifact_uploads_total{repository,format} moves by exactly 1
#             per upload (generic API and the Maven native route),
#             ak_artifact_upload_size_bytes_sum{format} records the uploaded
#             size, ak_artifact_downloads_total moves by exactly 2 for two GETs
#             and agrees with the download_statistics rows, and a HEAD is not
#             counted. RED on 1.11.1: the series are absent.
#   (FIX #4647) the startup line "HTTP listener accept backlog" names
#             requested=Some(777) and effective=Some(min(777, somaxconn)), and
#             `ss -ltn` in the backend's network namespace shows Send-Q =
#             min(777, somaxconn) on :8080. RED on 1.11.1: no line, Send-Q 4096.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
# Same bounds as common.sh's CURL_TIMEOUT, as an array so it is never word-split.
CT=(--max-time 60 --connect-timeout 10)
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
BACKLOG="${HTTP_LISTEN_BACKLOG:-777}"
# iproute2's `ss` in a throwaway container that joins the backend's network
# namespace (the backend image has no shell). Pinned tag; override for a mirror.
NETSHOOT_IMAGE="${NETSHOOT_IMAGE:-docker.io/nicolaka/netshoot:v0.13}"

GEN_REPO="mb-gen-${SLOT}-${SUF}"
MVN_REPO="mb-mvn-${SLOT}-${SUF}"
GEN_PATH="dtf/metrics/payload.bin"
MVN_PATH="org/dtf/metered/1.0.0/metered-1.0.0.jar"

WORK="$(mktemp -d -t dtf-metrics-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }

# scrape OUTFILE -> HTTP status of GET /api/v1/admin/metrics
scrape() {
  curl -s "${CT[@]}" -o "$1" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}

# metric_value FILE NAME [label=value ...] -> the sample value of the series
# whose labels are EXACTLY the given set (order-insensitive), or "absent".
metric_value() {
  python3 - "$@" <<'PY'
import re, sys
path, name, want = sys.argv[1], sys.argv[2], dict(a.split("=", 1) for a in sys.argv[3:])
line_re = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)')
lab_re = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
for line in open(path, encoding="utf-8", errors="replace"):
    m = line_re.match(line)
    if not m or m.group(1) != name:
        continue
    if dict(lab_re.findall(m.group(2) or "")) == want:
        v = float(m.group(3))
        print(int(v) if v.is_integer() else v)
        sys.exit(0)
print("absent")
PY
}
# as_num VALUE -> 0 for "absent", else the value (the baseline of a fresh series)
as_num() { [ "$1" = "absent" ] && echo 0 || echo "$1"; }

downloads_reached() { # FILE REPO FORMAT WANT
  scrape "$1" >/dev/null
  [ "$(metric_value "$1" ak_artifact_downloads_total "repository=$2" "format=$3")" = "$4" ]
}
stats_rows() { psql_q "SELECT count(*) FROM download_statistics d JOIN artifacts a ON a.id = d.artifact_id JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1'"; }
stats_rows_reached() { [ "$(stats_rows "$1")" = "$2" ]; }

begin_suite "dtf-metrics-and-backlog"

# --- setup ------------------------------------------------------------------
begin_test "setup: admin login, generic + maven repositories, exporter reachable"
auth_admin
if ! create_repo "$GEN_REPO" generic local || ! create_repo "$MVN_REPO" maven local; then
  infra_fail "could not create the tier's repositories"
  end_suite
fi
head -c 4093 /dev/urandom > "${WORK}/payload.bin"
GEN_SIZE=$(wc -c < "${WORK}/payload.bin" | tr -d ' ')
printf 'PK\003\004 dtf metrics-and-backlog jar %s\n' "$SUF" > "${WORK}/metered.jar"
MVN_SIZE=$(wc -c < "${WORK}/metered.jar" | tr -d ' ')
code=$(scrape "${WORK}/m0.txt")
if [ "$code" != "200" ]; then
  infra_fail "GET /api/v1/admin/metrics returned HTTP ${code}" "$(head -c 300 "${WORK}/m0.txt" 2>/dev/null)"
  end_suite
fi
pass

# --- controls ---------------------------------------------------------------
begin_test "control: /health is 200 and the exporter serves the pre-existing ak_http_* series"
hcode=$(curl -s "${CT[@]}" -o "${WORK}/health.json" -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo 000)
if [ "$hcode" = "200" ] && grep -q '^# TYPE ak_http_requests_total counter' "${WORK}/m0.txt"; then
  pass
else
  fail "/health=${hcode}; ak_http_requests_total TYPE line present: $(grep -c '^# TYPE ak_http_requests_total' "${WORK}/m0.txt")"
fi

# Baselines. Repository keys are unique to this run, so a correct backend has
# no series for them yet; "absent" is the 0 baseline.
UP_GEN0=$(as_num "$(metric_value "${WORK}/m0.txt" ak_artifact_uploads_total "repository=${GEN_REPO}" format=generic)")
UP_MVN0=$(as_num "$(metric_value "${WORK}/m0.txt" ak_artifact_uploads_total "repository=${MVN_REPO}" format=maven)")
DL_GEN0=$(as_num "$(metric_value "${WORK}/m0.txt" ak_artifact_downloads_total "repository=${GEN_REPO}" format=generic)")
DL_MVN0=$(as_num "$(metric_value "${WORK}/m0.txt" ak_artifact_downloads_total "repository=${MVN_REPO}" format=maven)")
SZ_GEN0=$(as_num "$(metric_value "${WORK}/m0.txt" ak_artifact_upload_size_bytes_sum format=generic)")
SZ_MVN0=$(as_num "$(metric_value "${WORK}/m0.txt" ak_artifact_upload_size_bytes_sum format=maven)")

begin_test "control: generic upload, then two downloads serve the uploaded bytes"
ucode=$(curl -s "${CT[@]}" -o "${WORK}/up.json" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/payload.bin" \
  "${BASE_URL}/api/v1/repositories/${GEN_REPO}/artifacts/${GEN_PATH}" 2>/dev/null || echo 000)
up_size=$(jq -r '.size_bytes // empty' "${WORK}/up.json" 2>/dev/null)
d_ok=0
for i in 1 2; do
  dcode=$(curl -s "${CT[@]}" -o "${WORK}/dl${i}.bin" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${GEN_REPO}/download/${GEN_PATH}" 2>/dev/null || echo 000)
  [ "$dcode" = "200" ] && cmp -s "${WORK}/payload.bin" "${WORK}/dl${i}.bin" && d_ok=$((d_ok + 1))
done
if [ "$ucode" = "201" ] || [ "$ucode" = "200" ]; then :; else
  fail_fatal "generic upload returned HTTP ${ucode}" "$(head -c 300 "${WORK}/up.json")"
fi
if [ "$up_size" = "$GEN_SIZE" ] && [ "$d_ok" = "2" ]; then
  pass
else
  fail "upload size_bytes=${up_size:-<none>} (want ${GEN_SIZE}); byte-exact downloads ${d_ok}/2"
fi

begin_test "control: the two downloads are written to download_statistics"
if wait_until "2 download_statistics rows for ${GEN_REPO}" 20 stats_rows_reached "$GEN_REPO" 2; then
  pass
else
  fail "download_statistics rows for ${GEN_REPO}: $(stats_rows "$GEN_REPO") (want 2)"
fi

begin_test "control: Maven native PUT + GET round-trips (HEAD answers too)"
mput=$(curl -s "${CT[@]}" -o "${WORK}/mput.txt" -w '%{http_code}' -X PUT -H "$(format_auth_header)" \
  --data-binary "@${WORK}/metered.jar" "${BASE_URL}/maven/${MVN_REPO}/${MVN_PATH}" 2>/dev/null || echo 000)
mget=$(curl -s "${CT[@]}" -o "${WORK}/mget.jar" -w '%{http_code}' -H "$(format_auth_header)" \
  "${BASE_URL}/maven/${MVN_REPO}/${MVN_PATH}" 2>/dev/null || echo 000)
mhead=$(curl -s "${CT[@]}" -I -o "${WORK}/mhead.txt" -w '%{http_code}' -H "$(format_auth_header)" \
  "${BASE_URL}/maven/${MVN_REPO}/${MVN_PATH}" 2>/dev/null || echo 000)
if [ "$mput" = "201" ] && [ "$mget" = "200" ] && cmp -s "${WORK}/metered.jar" "${WORK}/mget.jar" && [ "$mhead" = "200" ]; then
  pass
else
  fail "maven PUT=${mput} GET=${mget} HEAD=${mhead}; GET body matches jar: $(cmp -s "${WORK}/metered.jar" "${WORK}/mget.jar" && echo yes || echo no)"
fi
wait_until "1 download_statistics row for ${MVN_REPO}" 20 stats_rows_reached "$MVN_REPO" 1 || true

# --- #4642 ------------------------------------------------------------------
begin_test "#4642: ak_artifact_downloads_total{generic} moves by exactly 2 for two GETs"
want_dl_gen=$((DL_GEN0 + 2))
wait_until "downloads counter for ${GEN_REPO} = ${want_dl_gen}" 20 \
  downloads_reached "${WORK}/m1.txt" "$GEN_REPO" generic "$want_dl_gen" || true
scrape "${WORK}/m1.txt" >/dev/null
dl_gen=$(metric_value "${WORK}/m1.txt" ak_artifact_downloads_total "repository=${GEN_REPO}" format=generic)
if [ "$dl_gen" = "$want_dl_gen" ]; then
  pass
else
  fail "ak_artifact_downloads_total{repository=\"${GEN_REPO}\",format=\"generic\"} = ${dl_gen} (baseline ${DL_GEN0}, want ${want_dl_gen})" \
    "$(grep -E '^ak_artifact_' "${WORK}/m1.txt" | head -20)"
fi

begin_test "#4642: the downloads counter equals the download_statistics rows"
rows=$(stats_rows "$GEN_REPO")
if [ "$dl_gen" != "absent" ] && [ "$((dl_gen - DL_GEN0))" = "$rows" ]; then
  pass
else
  fail "counter delta for ${GEN_REPO}: ${dl_gen} - ${DL_GEN0}; download_statistics rows: ${rows}"
fi

begin_test "#4642: ak_artifact_uploads_total{generic} moves by exactly 1 and the size is recorded"
up_gen=$(metric_value "${WORK}/m1.txt" ak_artifact_uploads_total "repository=${GEN_REPO}" format=generic)
sz_gen=$(metric_value "${WORK}/m1.txt" ak_artifact_upload_size_bytes_sum format=generic)
if [ "$up_gen" = "$((UP_GEN0 + 1))" ] && [ "$sz_gen" != "absent" ] && [ "$(( ${sz_gen%.*} - ${SZ_GEN0%.*} ))" = "$GEN_SIZE" ]; then
  pass
else
  fail "uploads_total{${GEN_REPO},generic}=${up_gen} (want $((UP_GEN0 + 1))); upload_size_bytes_sum{generic}=${sz_gen} (baseline ${SZ_GEN0}, want +${GEN_SIZE})"
fi

begin_test "#4642: a Maven native PUT counts one upload with format=maven and the jar size"
up_mvn=$(metric_value "${WORK}/m1.txt" ak_artifact_uploads_total "repository=${MVN_REPO}" format=maven)
sz_mvn=$(metric_value "${WORK}/m1.txt" ak_artifact_upload_size_bytes_sum format=maven)
if [ "$up_mvn" = "$((UP_MVN0 + 1))" ] && [ "$sz_mvn" != "absent" ] && [ "$(( ${sz_mvn%.*} - ${SZ_MVN0%.*} ))" = "$MVN_SIZE" ]; then
  pass
else
  fail "uploads_total{${MVN_REPO},maven}=${up_mvn} (want $((UP_MVN0 + 1))); upload_size_bytes_sum{maven}=${sz_mvn} (baseline ${SZ_MVN0}, want +${MVN_SIZE})"
fi

begin_test "#4642: a Maven GET counts one download and the HEAD is not counted"
dl_mvn=$(metric_value "${WORK}/m1.txt" ak_artifact_downloads_total "repository=${MVN_REPO}" format=maven)
if [ "$dl_mvn" = "$((DL_MVN0 + 1))" ]; then
  pass
else
  fail "ak_artifact_downloads_total{repository=\"${MVN_REPO}\",format=\"maven\"} = ${dl_mvn} (want $((DL_MVN0 + 1)): one GET, the HEAD must not count); download_statistics rows: $(stats_rows "$MVN_REPO")"
fi

begin_test "#4642: labels are repository + format only (no artifact path or name)"
if grep -E '^ak_artifact_(uploads|downloads)_total\{' "${WORK}/m1.txt" | grep -qE 'payload|metered|path=|name=|version='; then
  fail "an artifact series carries a per-artifact label" "$(grep -E '^ak_artifact_(uploads|downloads)_total' "${WORK}/m1.txt")"
elif grep -qE '^ak_artifact_(uploads|downloads)_total\{' "${WORK}/m1.txt"; then
  pass
else
  fail "no ak_artifact_uploads_total / ak_artifact_downloads_total series exported at all"
fi

# --- #4647 ------------------------------------------------------------------
SS_OUT=""
SOMAXCONN=""
begin_test "setup: read the backend's listen sockets from its network namespace"
if ! SS_OUT=$(docker run --rm --net "container:${BACKEND_CTR}" "$NETSHOOT_IMAGE" \
      sh -c 'cat /proc/sys/net/core/somaxconn; ss -Hltn' 2>"${WORK}/ss.err"); then
  infra_fail "could not run ss in ${BACKEND_CTR}'s netns with ${NETSHOOT_IMAGE}" "$(head -c 400 "${WORK}/ss.err")"
  end_suite
fi
SOMAXCONN=$(printf '%s\n' "$SS_OUT" | head -1)
if ! [[ "$SOMAXCONN" =~ ^[0-9]+$ ]]; then
  infra_fail "could not read net.core.somaxconn in the backend netns" "$SS_OUT"
  end_suite
fi
EFFECTIVE=$(( BACKLOG < SOMAXCONN ? BACKLOG : SOMAXCONN ))
echo "  HTTP_LISTEN_BACKLOG=${BACKLOG} somaxconn=${SOMAXCONN} -> expected effective ${EFFECTIVE}"
pass

# ss -Hltn columns: State Recv-Q Send-Q Local Peer. For a LISTEN socket Send-Q
# is sk_max_ack_backlog, i.e. the accept-queue length the kernel granted.
SENDQ_8080=$(printf '%s\n' "$SS_OUT" | awk '$1=="LISTEN" && $4 ~ /:8080$/ {print $3; exit}')

begin_test "control: the API listener is LISTENing on :8080"
if [ -n "$SENDQ_8080" ]; then pass; else fail "no LISTEN socket on :8080 in ${BACKEND_CTR}" "$SS_OUT"; fi

begin_test "#4647: the kernel accept backlog on :8080 is min(HTTP_LISTEN_BACKLOG, somaxconn) = ${EFFECTIVE}"
if [ "$SENDQ_8080" = "$EFFECTIVE" ]; then
  pass
else
  fail "ss Send-Q for :8080 = ${SENDQ_8080:-<none>}, want ${EFFECTIVE} (HTTP_LISTEN_BACKLOG=${BACKLOG}, somaxconn=${SOMAXCONN})" "$SS_OUT"
fi

begin_test "#4647: the startup log names the requested and effective backlog"
docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "${WORK}/backend.log"
diag=$(grep -m1 'HTTP listener accept backlog' "${WORK}/backend.log" || true)
if [ -z "$diag" ]; then
  fail "no 'HTTP listener accept backlog' line in docker logs ${BACKEND_CTR} ($(wc -l < "${WORK}/backend.log") lines read)"
elif printf '%s' "$diag" | grep -q "requested=Some(${BACKLOG})" \
  && printf '%s' "$diag" | grep -q "somaxconn=Some(${SOMAXCONN})" \
  && printf '%s' "$diag" | grep -q "effective=Some(${EFFECTIVE})"; then
  pass
else
  fail "diagnostic line does not name requested=${BACKLOG} somaxconn=${SOMAXCONN} effective=${EFFECTIVE}" "$diag"
fi

begin_test "control: /health and an authenticated API call still work after the scrape and ss"
hcode=$(curl -s "${CT[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo 000)
rkey=$(curl -s "${CT[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${GEN_REPO}" 2>/dev/null | jq -r '.key // empty')
if [ "$hcode" = "200" ] && [ "$rkey" = "$GEN_REPO" ]; then
  pass
else
  fail "/health=${hcode}; GET /api/v1/repositories/${GEN_REPO} -> key=${rkey:-<none>}"
fi

end_suite
