#!/usr/bin/env bash
# =============================================================================
# tiers/transfer-quota-redirect-downloads/oracle.sh
#   #6035 every presigned redirect download adds the object size to the
#         TRANSFER_QUOTA_BYTES meter, as a streamed download adds its body
# See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, TRIVY_PORT
# (the mock's published control port), S3_PORT, DB_CONTAINER, RELEASE_GATE=1,
# COMMON_SH.
#
# Phases:
#   1  the profile set as deployed (redirects on)   FIX + CONTROL, redirected
#   2  backend recreated with fixtures/redirect-off  CONTROL, streamed
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on it.
set +e

begin_suite "transfer-quota-redirect-downloads"

# Version floor first, before any case can pass: on a backend below 1.12.1 the
# whole tier is NOT APPLICABLE (the 1.12.0 gate runs this main tree).
begin_test "version floor: redirect downloads are metered in backend >= 1.12.1"
if ! require_feature "transfer_quota_redirect_metering"; then end_suite; exit 0; fi
pass

auth_admin
setup_workdir
require_cmd python3

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$WORK_DIR"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
PROJECT="ak-dtf${DTF_SLOT}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"   # where the BACKEND reaches the mock
P="tq${SUF}"                        # mock path prefix, per run
SLACK=131072                        # bytes other responses may add to a window
IMG="img"
PROJ="dtfquota${SUF}"
WHEEL="${PROJ}-1.0.0-py3-none-any.whl"

GEN="tq-gen-${SUF}"; OCI="tq-oci-${SUF}"; VIRT="tq-virt-${SUF}"
REM="tq-rem-${SUF}"; PY="tq-py-${SUF}"
ALL_REPOS="$VIRT $GEN $OCI $REM $PY"
cleanup() {
  local k
  for k in $ALL_REPOS; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
}
add_exit_handler "cleanup"

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

uri() { jq -rn --arg v "$1" '$v|@uri'; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
size_of() { stat -c %s "$1" 2>/dev/null || echo 0; }
hdr() { grep -i "^$2:" "$1" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
mock_put() { # PATH FILE CTYPE -> stored bytes
  curl -s --max-time 20 -X PUT --data-binary @"$2" "${MOCK}/__file?path=$(uri "$1")&ctype=$(uri "$3")" \
    | jq -r '.bytes // empty' 2>/dev/null || true
}
# quota_get -> writes $W/quota.json; HTTP status
quota_get() {
  curl -s -o "${W}/quota.json" -w '%{http_code}' --max-time 15 -H "$(auth_header)" \
    "${BASE_URL}/api/v1/system/quota" 2>/dev/null || echo 000
}
used() { quota_get >/dev/null; jq -r '.transfer_quota.used_bytes // empty' "${W}/quota.json" 2>/dev/null; }

# fetch URL TAG [auth] -> sets ST, STORE (X-Artifact-Storage), DL (bytes received), BSHA
fetch() {
  local -a a=()
  [ "${3:-}" = "auth" ] && a=(-H "$(auth_header)")
  local out
  out=$(curl -s -D "${W}/$2.h" -o "${W}/$2.b" -w '%{http_code} %{size_download}' --max-time 120 \
        "${a[@]}" "$1" 2>/dev/null) || out="000 0"
  ST="${out%% *}"; DL="${out##* }"
  STORE="$(hdr "${W}/$2.h" x-artifact-storage)"
  BSHA="$(sha_of "${W}/$2.b")"
}
# metered URL TAG AUTH SIZE: one download between two meter readings. Sets
# DELTA (the growth of used_bytes; polled up to 25 s for the 10 s flush and
# the count to land) plus fetch's ST/STORE/DL/BSHA.
metered() {
  local before now t_end r i
  # A reading taken while a flush is in progress can miss the bytes it is
  # moving (pending already reset, the shared total not yet updated), which
  # would inflate DELTA. Keep the largest of three readings.
  before=""
  for i in 1 2 3; do
    r="$(used)"
    [ -n "$r" ] && { [ -z "$before" ] || [ "$r" -gt "$before" ]; } && before="$r"
    [ "$i" -lt 3 ] && sleep 0.5
  done
  fetch "$1" "$2" "$3"
  DELTA=""
  [ -n "$before" ] || return 0
  t_end=$(( $(date +%s) + 25 ))
  while :; do
    now="$(used)"
    [ -n "$now" ] && DELTA=$(( now - before ))
    [ -n "$DELTA" ] && [ "$DELTA" -ge "$4" ] && break
    [ "$(date +%s)" -ge "$t_end" ] && break
    sleep 1
  done
}
# The meter's view starts at the last flush after a restart: wait until two
# readings 11 s apart agree before measuring anything.
meter_settled() {
  local a b
  a="$(used)"; sleep 11; b="$(used)"
  [ -n "$a" ] && [ "$a" = "$b" ]
}
judge_count() { # SIZE LABEL
  if [ -z "$DELTA" ]; then fail_g "$2: transfer_quota.used_bytes could not be read"; return; fi
  [ "$DELTA" -ge "$1" ] || fail_g "$2: used_bytes grew by ${DELTA}, less than the object size $1 (the download was not counted)"
  [ "$DELTA" -le $(( $1 + SLACK )) ] || fail_g "$2: used_bytes grew by ${DELTA}, more than the object size $1 + ${SLACK} (counted twice?)"
}
judge_redirect() { # SIZE LABEL
  note "$2: HTTP ${ST} X-Artifact-Storage='${STORE}' body ${DL} B; used_bytes +${DELTA:-?} (object ${1} B)"
  case "$ST" in 302|307) ;; *) fail_g "$2: answered ${ST}, not a presigned redirect";; esac
  case "$STORE" in redirect-*) ;; *) fail_g "$2: X-Artifact-Storage '${STORE}' is not redirect-*";; esac
  [ "$DL" = "0" ] || fail_g "$2: the redirect carried a ${DL}-byte body"
  judge_count "$1" "$2"
}
judge_stream() { # SIZE SHA LABEL
  note "$3: HTTP ${ST} X-Artifact-Storage='${STORE}' body ${DL} B; used_bytes +${DELTA:-?} (object ${1} B)"
  [ "$ST" = "200" ] || fail_g "$3: answered ${ST}, expected a streamed 200"
  case "$STORE" in redirect-*) fail_g "$3: redirected with redirects off";; esac
  [ "$BSHA" = "$2" ] || fail_g "$3: the body is not the object (sha ${BSHA})"
  judge_count "$1" "$3"
}

U_GEN="${BASE_URL}/api/v1/repositories/${GEN}/download/dir/gen-${SUF}.bin"
U_OCI="${BASE_URL}/v2/${OCI}/${IMG}/blobs/sha256:"
U_VIRT="${BASE_URL}/v2/${VIRT}/${IMG}/blobs/sha256:"
U_REM="${BASE_URL}/v2/${REM}/${IMG}/blobs/sha256:"
U_PY="${BASE_URL}/pypi/${PY}/simple/${PROJ}/${WHEEL}"

# =============================================================================
begin_test "setup: objects, upstream files and repositories (generic, local/virtual/remote docker, PyPI remote)"
err=""
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
# Distinct sizes around 1 MiB: a missed count (0) and a double count (2x) are
# both far outside [size, size + SLACK].
head -c $(( 1048576 + 101 )) /dev/urandom > "${W}/gen.bin"
head -c $(( 1048576 + 211 )) /dev/urandom > "${W}/layer"
head -c $(( 1048576 + 307 )) /dev/urandom > "${W}/rblob"
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"salt":"%s"}' "$SUF" > "${W}/cfg"
python3 -I - "${W}/${WHEEL}" "$PROJ" <<'PY' 2>>"${W}/fx.err" || err="${err} wheel"
import os, sys, zipfile
path, proj = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
    z.writestr(f"{proj}/__init__.py", "")
    z.writestr(f"{proj}/payload.bin", os.urandom(1048576 + 409))
    z.writestr(f"{proj}-1.0.0.dist-info/METADATA",
               f"Metadata-Version: 2.1\nName: {proj}\nVersion: 1.0.0\n")
    z.writestr(f"{proj}-1.0.0.dist-info/WHEEL",
               "Wheel-Version: 1.0\nGenerator: dtf\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    z.writestr(f"{proj}-1.0.0.dist-info/RECORD", "")
PY
S_GEN=$(size_of "${W}/gen.bin"); S_LAYER=$(size_of "${W}/layer"); S_RBLOB=$(size_of "${W}/rblob"); S_WHEEL=$(size_of "${W}/${WHEEL}")
H_GEN=$(sha_of "${W}/gen.bin"); LD=$(sha_of "${W}/layer"); CD=$(sha_of "${W}/cfg"); RD=$(sha_of "${W}/rblob"); H_WHEEL=$(sha_of "${W}/${WHEEL}")

# Upstream: the remote blob under both image spellings, a /v2/ base, and a
# PEP 503 index whose link is absolute on the mock.
printf '{}' > "${W}/v2base"
[ -n "$(mock_put "/${P}/v2/" "${W}/v2base" application/json)" ] || err="${err} mock:v2"
for p in "/${P}/v2/${IMG}/blobs/sha256:${RD}" "/${P}/v2/library/${IMG}/blobs/sha256:${RD}"; do
  [ "$(mock_put "$p" "${W}/rblob" application/octet-stream)" = "$S_RBLOB" ] || err="${err} mock:${p}"
done
[ "$(mock_put "/${P}py/packages/${WHEEL}" "${W}/${WHEEL}" application/octet-stream)" = "$S_WHEEL" ] || err="${err} mock:wheel"
printf '<!DOCTYPE html><html><body><a href="%s/%spy/packages/%s#sha256=%s">%s</a></body></html>\n' \
  "$UP" "$P" "$WHEEL" "$H_WHEEL" "$WHEEL" > "${W}/index.html"
for p in "/${P}py/simple/${PROJ}/" "/${P}py/simple/${PROJ}"; do
  [ -n "$(mock_put "$p" "${W}/index.html" text/html)" ] || err="${err} mock:index"
done

create_repo "$GEN" generic local || err="${err} create:gen"
create_repo "$OCI" docker local || err="${err} create:oci"
create_repo "$VIRT" docker virtual || err="${err} create:virt"
create_repo "$REM" docker remote "${UP}/${P}/" || err="${err} create:rem"
create_repo "$PY" pypi remote "${UP}/${P}py" || err="${err} create:py"
c=$(curl -s -o "${W}/member.out" -w '%{http_code}' --max-time 30 -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' -d "{\"member_key\":\"${OCI}\"}" \
  "${BASE_URL}/api/v1/repositories/${VIRT}/members" 2>/dev/null || echo 000)
case "$c" in 2??) ;; *) err="${err} member:${c}";; esac
c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${W}/gen.bin" \
  "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/dir/gen-${SUF}.bin" 2>/dev/null || echo 000)
case "$c" in 2??) ;; *) err="${err} gen-upload:${c}";; esac
for f in cfg layer; do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X POST -H "$(auth_header)" \
    -H 'Content-Type: application/octet-stream' --data-binary "@${W}/${f}" \
    "${BASE_URL}/v2/${OCI}/${IMG}/blobs/uploads/?digest=sha256:$(sha_of "${W}/${f}")" 2>/dev/null || echo 000)
  case "$c" in 2??) ;; *) err="${err} blob-${f}:${c}";; esac
done
MT='application/vnd.docker.distribution.manifest.v2+json'
printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"sha256:%s"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":%s,"digest":"sha256:%s"}]}' \
  "$MT" "$(size_of "${W}/cfg")" "$CD" "$S_LAYER" "$LD" > "${W}/manifest"
c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" -H "Content-Type: ${MT}" \
  --data-binary "@${W}/manifest" "${BASE_URL}/v2/${OCI}/${IMG}/manifests/v1" 2>/dev/null || echo 000)
case "$c" in 2??) ;; *) err="${err} manifest:${c}";; esac
if [ -z "$err" ]; then pass; else infra_fail "setup:${err}"; end_suite; fi

begin_test "setup: first pulls through the remotes fill their proxy caches (streamed from the mock upstream)"
fetch "${U_REM}${RD}" rem-cold auth; rc="${ST}/${BSHA}"
fetch "$U_PY" py-cold; pc="${ST}/${BSHA}"
sleep 2
echo "   remote blob: ${rc%%/*}; pypi wheel: ${pc%%/*}"
if [ "$rc" = "200/${RD}" ] && [ "$pc" = "200/${H_WHEEL}" ]; then pass
else infra_fail "cold pulls: remote blob ${rc} (want 200/${RD}), pypi ${pc} (want 200/${H_WHEEL}); mock log: $(curl -s --max-time 5 "${MOCK}/__log" | tail -5 | tr '\n' ' ')"; end_suite; fi

begin_test "setup: the deployment meters downloads (TRANSFER_QUOTA_BYTES set; GET /api/v1/system/quota)"
qs=$(quota_get)
qe="$(jq -r '.transfer_quota.enabled // empty' "${W}/quota.json" 2>/dev/null)"
qb="$(jq -r '.transfer_quota.quota_bytes // empty' "${W}/quota.json" 2>/dev/null)"
echo "   HTTP ${qs} transfer_quota.enabled=${qe:-absent} quota_bytes=${qb:-absent}"
if [ "$qs" = "200" ] && [ "$qe" = "true" ] && [ -n "$qb" ]; then pass
else
  require_or_fail "no transfer quota on this deployment (set TRANSFER_QUOTA_BYTES; profiles/limits.transfer-quota.yml)" "$(head -c 300 "${W}/quota.json" 2>/dev/null)"
  end_suite
fi

begin_test "setup: presigned redirect downloads are on (the generic download answers a redirect)"
fetch "$U_GEN" gen-probe auth
echo "   HTTP ${ST} X-Artifact-Storage='${STORE}'"
REDIRECTS=0
case "$ST/$STORE" in 30[27]/redirect-*) REDIRECTS=1; pass ;;
  *) require_or_fail "downloads are not redirected on this deployment (needs S3 storage with PRESIGNED_DOWNLOADS_ENABLED=true and S3_REDIRECT_DOWNLOADS=true; profiles/storage.s3-presigned.yml)" "HTTP ${ST} X-Artifact-Storage='${STORE}'" ;;
esac

# =============================================================================
# Phase 1: redirects on
# =============================================================================
# remote_redirect URL TAG AUTH SIZE: a cached remote object redirects once its
# cache entry is complete; measure up to three tries, judging the first
# redirect (a try that still streams is counted in its own window).
remote_redirect() {
  local i
  for i in 1 2 3; do
    metered "$1" "$2-$i" "$3" "$4"
    case "$ST" in 302|307) return 0;; esac
    note "try ${i}: HTTP ${ST} (not yet redirected), used_bytes +${DELTA:-?}"
    sleep 3
  done
}

if [ "$REDIRECTS" = 1 ]; then
  wait_until "meter settled" 60 meter_settled

  reset_case
  begin_test "FIX #6035: a redirected repository download API GET adds the artifact size to the transfer meter"
  metered "$U_GEN" gen-r auth "$S_GEN"
  judge_redirect "$S_GEN" "GET /api/v1/repositories/<generic>/download"
  finish_case "the repository download API redirect was not metered"

  reset_case
  begin_test "CONTROL: a redirected OCI blob GET on the local repository adds the blob size (counted before #6035 too)"
  metered "${U_OCI}${LD}" oci-r auth "$S_LAYER"
  judge_redirect "$S_LAYER" "GET /v2/<local>/blobs"
  finish_case "the local OCI blob redirect was not metered"

  reset_case
  begin_test "FIX #6035: a redirected OCI blob GET through a virtual repository (local member) adds the blob size"
  metered "${U_VIRT}${LD}" virt-r auth "$S_LAYER"
  judge_redirect "$S_LAYER" "GET /v2/<virtual>/blobs"
  finish_case "the virtual repository's member blob redirect was not metered"

  reset_case
  begin_test "FIX #6035: a redirected OCI blob GET of a remote repository's cached blob adds the blob size"
  remote_redirect "${U_REM}${RD}" rem-r auth "$S_RBLOB"
  judge_redirect "$S_RBLOB" "GET /v2/<remote>/blobs (cached)"
  finish_case "the remote repository's cached blob redirect was not metered"

  reset_case
  begin_test "FIX #6035: a redirected PyPI remote file GET (proxy-cache hit) adds the file size"
  remote_redirect "$U_PY" py-r "" "$S_WHEEL"
  judge_redirect "$S_WHEEL" "GET /pypi/<remote>/simple/<project>/<wheel> (cached)"
  finish_case "the PyPI proxy-cache redirect was not metered"

  # Let this phase's counts reach the shared counter before the restart.
  sleep 12
fi

# =============================================================================
# Phase 2: redirects off, the same downloads stream
# =============================================================================
begin_test "setup: recreate the backend with PRESIGNED_DOWNLOADS_ENABLED=false (same MinIO store)"
ok=0
if [ -n "${DB_CONTAINER:-}" ]; then
  if DTF_SLOT="$DTF_SLOT" docker compose -p "$PROJECT" -f "${DTF_DIR}/compose.base.yml" \
       -f "${DTF_DIR}/profiles/storage.s3.yml" -f "${DTF_DIR}/profiles/storage.s3-presigned.yml" \
       -f "${DTF_DIR}/profiles/upstreams.mock-files.yml" -f "${DTF_DIR}/profiles/limits.transfer-quota.yml" \
       -f "${HERE}/fixtures/redirect-off.yml" \
       up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1 \
     && wait_until "backend health after recreate" 120 curl -sf --max-time 3 "${BASE_URL}/health"; then
    auth_admin >/dev/null 2>&1
    ok=1
  fi
fi
if [ "$ok" = 1 ]; then pass; else infra_fail "recreate failed: $(tail -5 "${W}/recreate.log" 2>/dev/null)"; end_suite; fi

wait_until "meter settled" 60 meter_settled

reset_case
begin_test "CONTROL: redirects off, the five downloads stream the exact bytes and each adds its object size"
for spec in "gen-s|${U_GEN}|auth|${S_GEN}|${H_GEN}|repository download API" \
            "oci-s|${U_OCI}${LD}|auth|${S_LAYER}|${LD}|/v2/<local>/blobs" \
            "virt-s|${U_VIRT}${LD}|auth|${S_LAYER}|${LD}|/v2/<virtual>/blobs" \
            "rem-s|${U_REM}${RD}|auth|${S_RBLOB}|${RD}|/v2/<remote>/blobs (cached)" \
            "py-s|${U_PY}||${S_WHEEL}|${H_WHEEL}|/pypi/<remote> wheel (cached)"; do
  IFS='|' read -r tag url au size sha label <<<"$spec"
  metered "$url" "$tag" "$au" "$size"
  judge_stream "$size" "$sha" "streamed ${label}"
done
finish_case "a streamed download was not metered by its size"

end_suite
