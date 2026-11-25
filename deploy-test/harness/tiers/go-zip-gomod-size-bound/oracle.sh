#!/usr/bin/env bash
# =============================================================================
# tiers/go-zip-gomod-size-bound/oracle.sh: a Go module zip's go.mod is read
# with a size bound (artifact-keeper#6405, fixed by #6493), filesystem.
# =============================================================================
# See the manifest. run.sh exports BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, COMMON_SH.
#
# Memory is read from the host: VmHWM (peak RSS) of the backend process in
# /proc/<pid>/status, where <pid> is the artifact-keeper process `docker top`
# reports for the backend container. A request that inflates a 256 MiB go.mod
# into a String raises it by at least that much; a bounded read does not.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${RUN_ID:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BACKEND_CTR="${DB_CONTAINER%-db}-backend"
SUF="${RUN_ID##*-}-$$"
REPO="gomodcap-${DTF_SLOT:-x}-${SUF}"
MOD="example.com/dtf/gomodcap${SUF//[^0-9]/}"
VER="v1.0.0"
BIG_MIB=256
RSS_SLACK_KB=$((64 * 1024))
TIME_CAP_S=10
WORK="$(mktemp -d -t dtf-gomodcap-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

FAILS=0; DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

backend_pid(){ docker top "$BACKEND_CTR" -eo pid,comm 2>/dev/null | awk '$2=="artifact-keeper"{print $1; exit}'; }
hwm_kb(){ awk '/^VmHWM:/{print $2}' "/proc/$(backend_pid)/status" 2>/dev/null; }
started_at(){ docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$BACKEND_CTR" 2>/dev/null; }
health(){ curl -s --max-time 10 -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo 000; }

# mkzip KIND OUT: a module zip for $MOD@$VER.
#   normal  : <mod>@<ver>/go.mod + a .go file
#   big     : <mod>@<ver>/go.mod of BIG_MIB MiB (module line + comment lines)
#   lying   : big, with the local and central headers claiming 1024 bytes
#   nested  : <mod>@<ver>/vendor/example.com/nested/go.mod listed first
mkzip(){
  python3 -I - "$1" "$2" "$MOD" "$VER" "$BIG_MIB" <<'PY'
import struct, sys, zipfile
kind, out, mod, ver, big_mib = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
pre = "%s@%s/" % (mod, ver)
head = ("module %s\n\ngo 1.21\n" % mod).encode()
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    if kind == "nested":
        z.writestr(pre + "vendor/example.com/nested/go.mod", "module example.com/nested\n\ngo 1.21\n")
    if kind in ("big", "lying"):
        line = b"// dtf go.mod padding line to inflate the entry past the cap\n"
        total = big_mib * 1024 * 1024
        with z.open(pre + "go.mod", "w") as f:
            f.write(head)
            n = len(head)
            chunk = line * 16384
            while n + len(chunk) <= total:
                f.write(chunk); n += len(chunk)
            while n + len(line) <= total:
                f.write(line); n += len(line)
    else:
        z.writestr(pre + "go.mod", head)
    z.writestr(pre + "dtf.go", "package dtf\n\nconst Marker = \"%s\"\n" % kind)
if kind == "lying":
    b = bytearray(open(out, "rb").read())
    target = (pre + "go.mod").encode()
    patched = 0
    i = b.find(b"PK\x03\x04")
    while i != -1:
        nlen = struct.unpack_from("<H", b, i + 26)[0]
        if bytes(b[i + 30:i + 30 + nlen]) == target:
            struct.pack_into("<I", b, i + 22, 1024); patched += 1
        i = b.find(b"PK\x03\x04", i + 4)
    i = b.find(b"PK\x01\x02")
    while i != -1:
        nlen = struct.unpack_from("<H", b, i + 28)[0]
        if bytes(b[i + 46:i + 46 + nlen]) == target:
            struct.pack_into("<I", b, i + 24, 1024); patched += 1
        i = b.find(b"PK\x01\x02", i + 4)
    if patched != 2:
        sys.exit("patched %d headers, want 2" % patched)
    open(out, "wb").write(bytes(b))
PY
}
# declared and real size of the go.mod entry, as python's zipfile reads them
entry_sizes(){
  python3 -I -c '
import sys, zipfile, zlib
z = zipfile.ZipFile(sys.argv[1]); i = z.getinfo(sys.argv[2])
f = open(sys.argv[1], "rb"); f.seek(i.header_offset + 26); import struct
n, e = struct.unpack("<HH", f.read(4)); f.seek(i.header_offset + 30 + n + e)
print(i.file_size, len(zlib.decompressobj(-15).decompress(f.read(i.compress_size))))
' "$1" "${MOD}@${VER}/go.mod" 2>/dev/null
}

# ftest ZIP -> sets FT_CODE FT_TIME FT_VALID FT_ERR FT_PERR FT_VER FT_DHWM
ftest(){
  local before after
  jq -n --arg p "${MOD}/@v/${VER}.zip" --rawfile c <(base64 -w0 "$1") \
    '{path:$p, content:$c, base64:true}' > "$WORK/req.json"
  before="$(hwm_kb)"
  read -r FT_CODE FT_TIME <<<"$(curl -s --max-time 120 -o "$WORK/ft.out" -w '%{http_code} %{time_total}' \
    -X POST -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/req.json" "${BASE_URL}/api/v1/formats/go/test" 2>/dev/null || echo '000 0')"
  after="$(hwm_kb)"
  FT_DHWM=$(( ${after:-0} - ${before:-0} ))
  FT_VALID="$(jq -r '.valid' "$WORK/ft.out" 2>/dev/null)"
  FT_ERR="$(jq -r '.validation_error // ""' "$WORK/ft.out" 2>/dev/null)"
  FT_PERR="$(jq -r '.parse_error // ""' "$WORK/ft.out" 2>/dev/null)"
  FT_VER="$(jq -r '.metadata.version // ""' "$WORK/ft.out" 2>/dev/null)"
  echo "-- POST /api/v1/formats/go/test $(basename "$1") ($(wc -c <"$1") B) -> ${FT_CODE} in ${FT_TIME}s, VmHWM +${FT_DHWM} kB: $(head -c 300 "$WORK/ft.out")"
}
# put ZIP -> HTTP status of the native PUT (as the admin), then GET compares
put_zip(){
  curl -s --max-time 120 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/zip' \
    --data-binary "@$1" "${BASE_URL}/go/${REPO}/${2}/@v/${VER}.zip" 2>/dev/null || echo 000
}
get_same(){ # MODULE ZIP -> 0 when GET returns the same bytes
  local c
  c="$(curl -s --max-time 60 -o "$WORK/got" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/go/${REPO}/${1}/@v/${VER}.zip" 2>/dev/null)"
  [ "$c" = 200 ] && cmp -s "$WORK/got" "$2"
}

begin_suite "go-zip-gomod-size-bound"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: Go repository, four module zips, the backend process's VmHWM is readable"
SETUP_ERR=""
command -v python3 >/dev/null 2>&1 || SETUP_ERR="python3 missing;"
[ -n "${ADMIN_TOKEN:-}" ] || SETUP_ERR="${SETUP_ERR} no admin token;"
api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"go\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1 \
  || SETUP_ERR="${SETUP_ERR} create ${REPO} failed;"
for k in normal big lying nested; do
  mkzip "$k" "$WORK/$k.zip" 2>"$WORK/mk.err" || SETUP_ERR="${SETUP_ERR} mkzip $k: $(head -c 200 "$WORK/mk.err");"
done
read -r BIG_DECL BIG_REAL <<<"$(entry_sizes "$WORK/big.zip")"
read -r LIE_DECL LIE_REAL <<<"$(entry_sizes "$WORK/lying.zip")"
echo "-- big.zip $(wc -c <"$WORK/big.zip") B: go.mod declared ${BIG_DECL:-?} real ${BIG_REAL:-?}"
echo "-- lying.zip $(wc -c <"$WORK/lying.zip") B: go.mod declared ${LIE_DECL:-?} real ${LIE_REAL:-?}"
[ "${BIG_REAL:-0}" -ge $((BIG_MIB * 1024 * 1024 - 128)) ] && [ "${BIG_DECL:-0}" = "${BIG_REAL:-x}" ] \
  || SETUP_ERR="${SETUP_ERR} big.zip go.mod sizes ${BIG_DECL:-?}/${BIG_REAL:-?};"
[ "${LIE_DECL:-0}" = 1024 ] && [ "${LIE_REAL:-0}" = "${BIG_REAL:-x}" ] \
  || SETUP_ERR="${SETUP_ERR} lying.zip go.mod sizes ${LIE_DECL:-?}/${LIE_REAL:-?};"
PID="$(backend_pid)"; H0="$(hwm_kb)"; S0="$(started_at)"
echo "-- backend ${BACKEND_CTR} pid ${PID:-?} VmHWM ${H0:-?} kB, started/restarts ${S0}"
[ -n "$H0" ] || SETUP_ERR="${SETUP_ERR} cannot read VmHWM of the backend process;"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# CONTROL: a normal module zip
# =============================================================================
begin_test "CONTROL: a normal module zip validates through the Go handler (valid, version ${VER})"
reset_case
ftest "$WORK/normal.zip"
[ "$FT_CODE" = 200 ] || fail_g "format test answered ${FT_CODE}"
[ "$FT_VALID" = true ] || fail_g "valid=${FT_VALID} err='${FT_ERR}${FT_PERR}', want a valid module zip"
[ "$FT_VER" = "$VER" ] || fail_g "metadata.version='${FT_VER}', want ${VER}"
finish_case "a normal module zip no longer validates"

begin_test "CONTROL: the native PUT of a normal module zip answers 201 and downloads byte for byte"
reset_case
c="$(put_zip "$WORK/normal.zip" "$MOD")"
note "PUT normal.zip -> ${c}: $(head -c 200 "$WORK/put.out")"
[ "$c" = 201 ] || fail_g "native PUT answered ${c}, want 201"
get_same "$MOD" "$WORK/normal.zip" || fail_g "GET did not return the uploaded bytes"
finish_case "a normal module no longer publishes"

# =============================================================================
# FIX #6405: an oversized go.mod entry is refused without inflating it
# =============================================================================
begin_test "FIX #6405: a module zip whose ${MOD##*/}@${VER}/go.mod inflates to ${BIG_MIB} MiB is refused naming the cap, within ${TIME_CAP_S} s, VmHWM +< 64 MiB"
reset_case
ftest "$WORK/big.zip"
[ "$FT_CODE" = 200 ] || fail_g "format test answered ${FT_CODE}"
[ "$FT_VALID" = false ] || fail_g "valid=${FT_VALID}: the ${BIG_MIB} MiB go.mod was read in full and accepted"
printf '%s' "$FT_ERR" | grep -q "maximum allowed size" || fail_g "validation_error '${FT_ERR}' does not name the size cap"
awk -v t="$FT_TIME" -v c="$TIME_CAP_S" 'BEGIN{exit !(t+0 < c+0)}' || fail_g "answered in ${FT_TIME}s, want < ${TIME_CAP_S}s"
[ "$FT_DHWM" -lt "$RSS_SLACK_KB" ] || fail_g "backend peak RSS grew by ${FT_DHWM} kB (>= ${RSS_SLACK_KB}): the entry was inflated"
[ "$(health)" = 200 ] || fail_g "/health is not 200 afterwards"
finish_case "an oversized go.mod is inflated without a bound"

# The zip crate itself stops an entry at its declared size ("File is larger
# than its declared uncompressed size"), on main as on the fix, so this case is
# a guard that the bound holds when the header lies, not a RED case.
begin_test "GUARD #6405: the same go.mod with headers claiming 1024 bytes is refused at the declared size, VmHWM +< 64 MiB"
reset_case
ftest "$WORK/lying.zip"
[ "$FT_CODE" = 200 ] || fail_g "format test answered ${FT_CODE}"
[ "$FT_VALID" = false ] || fail_g "valid=${FT_VALID}: the understated entry was read past its header and accepted"
printf '%s' "$FT_ERR" | grep -Eq "maximum allowed size|declared uncompressed size" \
  || fail_g "validation_error '${FT_ERR}' names neither the cap nor the declared size"
awk -v t="$FT_TIME" -v c="$TIME_CAP_S" 'BEGIN{exit !(t+0 < c+0)}' || fail_g "answered in ${FT_TIME}s, want < ${TIME_CAP_S}s"
[ "$FT_DHWM" -lt "$RSS_SLACK_KB" ] || fail_g "backend peak RSS grew by ${FT_DHWM} kB (>= ${RSS_SLACK_KB}): the entry was inflated"
[ "$(health)" = 200 ] || fail_g "/health is not 200 afterwards"
finish_case "an understated go.mod header bypasses the bound"

begin_test "FIX #6405: the module's own @${VER}/go.mod is read, not a nested vendor go.mod listed first"
reset_case
ftest "$WORK/nested.zip"
[ "$FT_CODE" = 200 ] || fail_g "format test answered ${FT_CODE}"
[ "$FT_VALID" = true ] || fail_g "valid=${FT_VALID} err='${FT_ERR}': the nested module's go.mod was read"
finish_case "the first */go.mod match wins over the module's own"

# =============================================================================
# CONTROL: the native upload path never reads go.mod
# =============================================================================
begin_test "CONTROL: the native PUT stores the ${BIG_MIB} MiB-go.mod zip as bytes (201, byte for byte) without inflating it"
reset_case
H1="$(hwm_kb)"
c="$(put_zip "$WORK/big.zip" "${MOD}/big")"
H2="$(hwm_kb)"
note "PUT big.zip -> ${c}: $(head -c 200 "$WORK/put.out"); VmHWM +$(( ${H2:-0} - ${H1:-0} )) kB"
[ "$c" = 201 ] || fail_g "native PUT answered ${c}, want 201"
get_same "${MOD}/big" "$WORK/big.zip" || fail_g "GET did not return the uploaded bytes"
[ $(( ${H2:-0} - ${H1:-0} )) -lt "$RSS_SLACK_KB" ] || fail_g "the native PUT grew peak RSS by $(( ${H2:-0} - ${H1:-0} )) kB"
finish_case "the native Go upload inflates the module zip"

begin_test "CONTROL: the backend stayed up: /health 200, same process, no restart"
reset_case
S1="$(started_at)"; P1="$(backend_pid)"
note "started/restarts before '${S0}' after '${S1}'; pid ${PID} -> ${P1:-?}; VmHWM ${H0} -> $(hwm_kb) kB"
[ "$(health)" = 200 ] || fail_g "/health is not 200"
[ "$S1" = "$S0" ] && [ "$P1" = "$PID" ] || fail_g "the backend restarted during the tier"
finish_case "the backend did not survive the oversized go.mod"

end_suite
