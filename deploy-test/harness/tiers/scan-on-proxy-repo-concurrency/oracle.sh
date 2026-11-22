#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-repo-concurrency/oracle.sh: one repository's proxy scans
#   use every scan slot, not only the first wave (artifact-keeper#5243)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-files` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# TRIVY_PORT, COMMON_SH and the slot's port block.
#
# The backend is recreated once with a grype stub (from the
# scan-queue-upload-image-rescan tier) that sleeps DELAY seconds before the
# real grype runs, so each scan holds its scan slot for a known time and the
# slots in use can be counted as stub processes in the backend container.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

begin_suite "scan-on-proxy-repo-concurrency"
auth_admin
setup_workdir
require_cmd python3

W="$WORK_DIR"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"
STUB_DIR="${DTF_DIR}/harness/tiers/scan-queue-upload-image-rescan/fixtures"
BUSYBOX_IMAGE="busybox:1.37.0-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478"
N=12          # concurrent first pulls
DELAY=6       # seconds the stub holds each scan before the real grype
SLOTS=4       # MAX_CONCURRENT_SCAN_EXTRACTIONS default
REPO="sopc-mvn-${SUF}"
GROUP="com/example/dtfconc${SUF//[^a-z0-9]/}"

cleanup() { api_delete "/api/v1/repositories/${REPO}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup"

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mock_put(){ # <path> <file> -> stored byte count
  curl -s --max-time 30 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=application/java-archive" | jq -r '.bytes // empty' 2>/dev/null
}
# stub_running -> stubbed grype scans sleeping in the backend right now
stub_running() {
  local out
  out="$(docker top "$BACKEND_CTR" -o pid,args 2>/dev/null)" || { echo -1; return; }
  printf '%s\n' "$out" | grep -c "busybox sleep ${DELAY}\$" || true
}
recreate_stubbed() {
  DTF_GRYPE_STUB_DELAY="$DELAY" DTF_SCANNER_PROCESS_TIMEOUT=600 \
  DTF_GRYPE_STUB_BUSYBOX="${W}/busybox" docker compose -p "$PROJECT" \
    -f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "${DTF_DIR}/profiles/upstreams.mock-files.yml" -f "${STUB_DIR}/grype-stub.yml" \
    up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1 \
    || { tail -20 "${W}/recreate.log"; return 1; }
  wait_until "backend health after recreate" 120 curl -sf --max-time 3 "${BASE_URL}/health" || return 1
  auth_admin >/dev/null 2>&1
}

# =============================================================================
begin_test "setup: grype stub (${DELAY}s per scan), ${N} clean jars on the mock, a fail_closed scan_on_proxy Maven Remote"
docker pull -q "$BUSYBOX_IMAGE" >"${W}/bb.log" 2>&1
bb_ctr="$(docker create "$BUSYBOX_IMAGE" 2>>"${W}/bb.log")"
[ -n "$bb_ctr" ] && docker cp "${bb_ctr}:/bin/busybox" "${W}/busybox" >>"${W}/bb.log" 2>&1
[ -n "$bb_ctr" ] && docker rm "$bb_ctr" >/dev/null 2>&1
chmod 755 "${W}/busybox" 2>/dev/null
SETUP_ERR=""
[ -x "${W}/busybox" ] || SETUP_ERR="${SETUP_ERR} busybox"
[ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" = "ok" ] || SETUP_ERR="${SETUP_ERR} mock"
# Jars whose pom.properties name the coordinate they are served under, so the
# pin matches and each grades clean (no advisory names these coordinates).
python3 -I - "$W/jars" "${GROUP//\//.}" "$N" <<'PY' 2>>"${W}/mk.err" || SETUP_ERR="${SETUP_ERR} jars"
import io, os, sys, zipfile
out, group, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.makedirs(out, exist_ok=True)
for i in range(n):
    art = f"lib{i}"
    props = f"groupId={group}\nartifactId={art}\nversion=1.0.0\n"
    pom = ('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
           f'<groupId>{group}</groupId><artifactId>{art}</artifactId><version>1.0.0</version></project>\n')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in ((f"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"),
                           (f"META-INF/maven/{group}/{art}/pom.properties", props),
                           (f"META-INF/maven/{group}/{art}/pom.xml", pom),
                           (f"dtf/{art}/Marker.txt", f"{art} {group}\n")):
            zi = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            z.writestr(zi, data)
    open(os.path.join(out, f"{art}-1.0.0.jar"), "wb").write(buf.getvalue())
PY
for i in $(seq 0 $((N - 1))); do
  [ -n "$(mock_put "/m2/${GROUP}/lib${i}/1.0.0/lib${i}-1.0.0.jar" "$W/jars/lib${i}-1.0.0.jar")" ] \
    || SETUP_ERR="${SETUP_ERR} mock:lib${i}"
done
recreate_stubbed || SETUP_ERR="${SETUP_ERR} recreate"
create_repo "$REPO" maven remote "${UP}/m2" || SETUP_ERR="${SETUP_ERR} repo"
act="$(api_put "/api/v1/repositories/${REPO}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed"}' 2>/dev/null \
  | jq -r '.proxy_scan_action // empty' 2>/dev/null)"
[ "$act" = "fail_closed" ] || SETUP_ERR="${SETUP_ERR} scan_cfg:${act:-none}"
if [ -z "$SETUP_ERR" ]; then pass
else infra_fail "setup failed:${SETUP_ERR} $(tail -3 "${W}/bb.log" "${W}/mk.err" 2>/dev/null | tr '\n' ' ')"; end_suite; fi

# =============================================================================
reset_case
begin_test "FIX #5243: ${N} concurrent first pulls through one scan_on_proxy Remote keep all ${SLOTS} scan slots busy after the first wave (was ${SLOTS} then 2 at a time)"
: >"${W}/samples"
(
  t0=$(date +%s%N)
  while [ ! -e "${W}/done" ]; do
    echo "$(( ($(date +%s%N) - t0) / 1000000 )) $(stub_running)" >>"${W}/samples"
    sleep 0.5
  done
) &
SAMPLER=$!
T0=$(date +%s%N)
pids=()
for i in $(seq 0 $((N - 1))); do
  ( p="${GROUP}/lib${i}/1.0.0/lib${i}-1.0.0.jar"
    st=$(curl -s -D "${W}/h${i}" -o "${W}/b${i}" -w '%{http_code}' --max-time 170 \
      "${BASE_URL}/maven/${REPO}/${p}" 2>/dev/null) || st=000
    sc=$(grep -i '^x-ak-scan:' "${W}/h${i}" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1)
    echo "${i} ${st} ${sc:-none} $(( ($(date +%s%N) - T0) / 1000000 ))" >"${W}/r${i}" ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
T_ALL=$(( ($(date +%s%N) - T0) / 1000000 ))
touch "${W}/done"; wait "$SAMPLER" 2>/dev/null
cat "${W}"/r* >"${W}/results" 2>/dev/null
ok=$(awk '$2 == 200 && $3 == "clean"' "${W}/results" | wc -l)
same=0
for i in $(seq 0 $((N - 1))); do
  cmp -s "${W}/b${i}" "$W/jars/lib${i}-1.0.0.jar" && same=$((same + 1))
done
# First wave: the first sample with SLOTS running. After it: the samples from
# the moment the count first fell below SLOTS (that wave finishing) onwards,
# until the last scan's stub was gone.
read -r peak1 peak2 mean2 n2 <<<"$(awk -v s="$SLOTS" '
  { c = $2 + 0; if (c > p1) p1 = c
    if (!after && seen && c < s) after = 1
    if (c >= s) seen = 1
    if (after) { n++; sum += c; if (c > p2) p2 = c; if (c > 0) last = n; sums[n] = sum } }
  END { m = (last > 0) ? sums[last] / last : 0; printf "%d %d %.2f %d\n", p1, p2, m, last }' "${W}/samples")"
note "pulls: ${ok}/${N} 200 clean, ${same}/${N} upstream bytes; results (i status scan ms): $(tr '\n' ';' <"${W}/results")"
note "samples (ms running): $(tr '\n' ';' <"${W}/samples" | head -c 900)"
note "MEASURE: ${N} concurrent first pulls (${DELAY}s stubbed scans, ${SLOTS} slots) took ${T_ALL} ms; scans running at once: first wave ${peak1}, after it peak ${peak2}, mean ${mean2} over ${n2} samples"
[ "$ok" = "$N" ] || fail_g "${ok}/${N} pulls answered 200 X-AK-Scan: clean"
[ "$same" = "$N" ] || fail_g "${same}/${N} pulls served the upstream bytes"
[ "${peak1:-0}" -ge "$SLOTS" ] 2>/dev/null || fail_g "the first wave ran ${peak1:-0} scans at once, not ${SLOTS}: the stub did not hold the slots as planned"
[ "${peak2:-0}" -ge "$SLOTS" ] 2>/dev/null || fail_g "after the first wave the repository never ran more than ${peak2:-0} scans at once, though ${SLOTS} slots were free"
finish_case "a lone repository's proxy scans did not use the free scan slots after the first wave"

end_suite
