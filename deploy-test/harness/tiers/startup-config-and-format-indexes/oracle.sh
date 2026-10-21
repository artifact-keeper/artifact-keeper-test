#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/startup-config-and-format-indexes/oracle.sh
#   #4211  JWT_SECRET strength is an entropy estimate: a 64-char hex secret
#          that misses a digit starts; a repeated short unit is refused
#   #4427  RPM curation sync ingests zstd, xz and bzip2 primary.xml, and a
#          sync that ingests nothing (or cannot decode) reports failure
# See the manifest for the gates and which image each case goes red on.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (mock-recorder's control port), BACKEND_IMAGE, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"; : "${BACKEND_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
MOCK="http://127.0.0.1:${TRIVY_PORT}"     # mock-recorder control (host side)
MOCK_IN="http://172.16.${DTF_SLOT}.77"    # the same server, backend side

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }

req(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 90 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format> <type> [upstream]
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')"
  is_2xx "$CODE"
}
# stage <url path> <file> <content type>: serve a file from mock-recorder.
stage(){ curl -s --max-time 10 -X PUT --data-binary "@$2" "${MOCK}/__file?path=$1&ctype=$3" >/dev/null; }

# --- #4211 helpers -----------------------------------------------------------
# A throwaway container of the image under test, given only JWT_SECRET and an
# unreachable database: config validation runs before the database is
# dialled, so a refused secret exits with "JWT_SECRET is unsuitable" and an
# accepted one gets as far as the database pool.
secret_probe(){ # <label> <secret> -> sets VERDICT (refused|accepted|unknown) and LINE
  local name="ak-dtf${DTF_SLOT}-jwtprobe-$1-$$" out _i
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" -e JWT_SECRET="$2" \
    -e DATABASE_URL="postgresql://probe:probe@127.0.0.1:1/none" \
    -e STORAGE_PATH=/tmp/s -e BACKUP_PATH=/tmp/b -e PLUGINS_DIR=/tmp/p "$BACKEND_IMAGE" >/dev/null 2>&1
  VERDICT="unknown"; LINE=""
  # A refused secret exits within a second or two; an accepted one keeps
  # running while it waits on the unreachable database pool (main logs
  # nothing until that times out, 1.10.0 exits with PoolTimedOut).
  for _i in $(seq 1 24); do
    out="$(docker logs "$name" 2>&1)"
    if grep -q 'JWT_SECRET is unsuitable' <<<"$out"; then
      VERDICT="refused"; LINE="$(grep -o 'JWT_SECRET is unsuitable: [^.(]*' <<<"$out" | head -1)"; break
    fi
    if grep -qiE 'database pool|PoolTimedOut|connect attempt' <<<"$out"; then
      VERDICT="accepted"; LINE="$(grep -iE 'database pool|PoolTimedOut|connect attempt' <<<"$out" | head -1 | cut -c1-140)"; break
    fi
    sleep 0.5
  done
  if [ "$VERDICT" = "unknown" ] && [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = "true" ]; then
    VERDICT="accepted"; LINE="still running after 12 s, past config validation, waiting on the database"
  fi
  docker rm -f "$name" >/dev/null 2>&1
}

begin_suite "startup-config-and-format-indexes"

begin_test "setup: admin session, mock-recorder up"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || { infra_fail "mock-recorder not reachable on ${MOCK}"; end_suite; }
echo "-- image under test: ${BACKEND_IMAGE}"
pass

# =============================================================================
begin_test "CONTROL: a strong base64 JWT_SECRET starts; 40 characters drawn from five letters are refused"
reset_case
secret_probe strong "$(head -c 48 /dev/urandom | base64 | tr -d '\n=')"
note "openssl-style base64 secret: ${VERDICT} (${LINE})"
[ "$VERDICT" = "accepted" ] || fail_g "a strong base64 secret was ${VERDICT}"
FIVE="$(python3 -I -c 'import random; print("".join(random.choice("abcde") for _ in range(40)))')"
secret_probe five "$FIVE"
note "40 chars from {a..e}: ${VERDICT} (${LINE})"
[ "$VERDICT" = "refused" ] || fail_g "a five-letter secret was ${VERDICT}"
finish_case "JWT_SECRET validation broken"

begin_test "#4211: a random 64-character hex JWT_SECRET that misses one hex digit starts"
reset_case
HEX15="$(python3 -I -c 'import random; print("".join(random.choice("0123456789abcde") for _ in range(64)))')"
secret_probe hex15 "$HEX15"
note "64 hex chars without 'f' (${HEX15:0:8}...): ${VERDICT} (${LINE})"
[ "$VERDICT" = "accepted" ] || fail_g "a 256-bit hex secret missing one digit was ${VERDICT}"
finish_case "a hex JWT_SECRET is refused for missing one of the sixteen digits"

begin_test "#4211: a short unit repeated (0123456789abcdef x4) is refused although it has 16 distinct characters"
reset_case
secret_probe repeat "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
note "0123456789abcdef x4: ${VERDICT} (${LINE})"
[ "$VERDICT" = "refused" ] || fail_g "a repeated 16-character unit was ${VERDICT}"
finish_case "a repeated short JWT_SECRET unit is accepted"

# --- #4427 -------------------------------------------------------------------
# build_repodata <dir> <codec gz|zst|xz|bz2> <href ext> <npkgs> [mode]: writes
# repomd.xml and the primary (named primary.xml.<href ext>) into <dir>. mode
# "plain": the bytes are the uncompressed XML although the href says <ext>;
# mode "declared": the root declares packages="<npkgs>" but holds none.
build_repodata(){
  python3 -I - "$@" <<'PY'
import bz2, gzip, hashlib, lzma, subprocess, sys
out, codec, ext, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
mode = sys.argv[5] if len(sys.argv) > 5 else ""
def pkg(i):
    name = f"dtf-{codec}-{i}"
    return (f'<package type="rpm"><name>{name}</name><arch>x86_64</arch>'
            '<version epoch="0" ver="1.0" rel="1.el9"/>'
            f'<checksum type="sha256" pkgid="YES">{hashlib.sha256(name.encode()).hexdigest()}</checksum>'
            f'<summary>{name}</summary><description>d</description><packager>p</packager><url>u</url>'
            '<time file="1700000000" build="1699999999"/><size package="1024" installed="4096" archive="4100"/>'
            f'<location href="Packages/{name}-1.0-1.el9.x86_64.rpm"/>'
            '<format><rpm:license>MIT</rpm:license><rpm:vendor>v</rpm:vendor><rpm:group>g</rpm:group>'
            f'<rpm:buildhost>b</rpm:buildhost><rpm:sourcerpm>{name}-1.0-1.el9.src.rpm</rpm:sourcerpm>'
            '<rpm:header-range start="4504" end="5000"/></format></package>')
xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<metadata xmlns="http://linux.duke.edu/metadata/common" '
       f'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="{n}">'
       + ("" if mode == "declared" else "".join(pkg(i) for i in range(n))) + '</metadata>')
raw = xml.encode()
if mode == "plain":
    data = raw
elif codec == "gz":
    data = gzip.compress(raw, mtime=0)
elif codec == "xz":
    data = lzma.compress(raw)
elif codec == "bz2":
    data = bz2.compress(raw)
elif codec == "zst":
    data = subprocess.run(["zstd", "-q", "-c"], input=raw, capture_output=True, check=True).stdout
open(f"{out}/primary.xml.{ext}", "wb").write(data)
open(f"{out}/repomd.xml", "w").write(
    '<?xml version="1.0" encoding="UTF-8"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>'
    f'<data type="primary"><checksum type="sha256">{hashlib.sha256(data).hexdigest()}</checksum>'
    f'<open-checksum type="sha256">{hashlib.sha256(raw).hexdigest()}</open-checksum>'
    f'<location href="repodata/primary.xml.{ext}"/></data></repomd>')
PY
}
# curate <label> <codec> <ext> <npkgs> [mode]: stage the repodata, wire a remote
# + curated staging repo, trigger a sync. Sets SYNC_CODE, SYNC_OK, NPKG, NAMES.
curate(){
  local label="$1" codec="$2" ext="$3" n="$4" mode="${5:-}" d="${W}/rpm-$1" up="/rpm-${1}-${SFX}"
  local rup="sc-rup-${1}-${SFX}" rst="sc-rst-${1}-${SFX}" sid
  mkdir -p "$d"
  if ! build_repodata "$d" "$codec" "$ext" "$n" "$mode" 2>"${d}/err"; then
    infra_fail "could not build the ${label} repodata: $(head -c 200 "${d}/err")"; end_suite
  fi
  stage "${up}/repodata/repomd.xml" "${d}/repomd.xml" text/xml
  stage "${up}/repodata/primary.xml.${ext}" "${d}/primary.xml.${ext}" application/octet-stream
  if ! mk_repo "$rup" rpm remote "${MOCK_IN}${up}" || ! mk_repo "$rst" rpm staging; then
    infra_fail "could not create the ${label} RPM remote/staging repos (${CODE}: ${BODY:0:200})"; end_suite
  fi
  # Curation wiring is DB-side, as tiers/rpm-p3-curation and
  # deps-1.12.0-controls seed it: the staging repo curates the remote and
  # opts into unverified ingest (no GPG key here).
  psql_q "UPDATE repositories SET curation_enabled=true, curation_allow_unverified=true,
          curation_source_repo_id=(SELECT id FROM repositories WHERE key='${rup}') WHERE key='${rst}'" >/dev/null
  sid="$(psql_q "SELECT id FROM repositories WHERE key='${rst}'")"
  req POST "/api/v1/curation/repos/${rst}/sync"
  SYNC_CODE="$CODE"; SYNC_OK="$(jqr 'if type == "object" and has("succeeded") then (.succeeded | tostring) else empty end' <<<"$BODY")"
  NPKG="$(psql_q "SELECT count(*) FROM curation_packages WHERE staging_repo_id='${sid}'")"
  NAMES="$(psql_q "SELECT string_agg(package_name, ',' ORDER BY package_name) FROM curation_packages WHERE staging_repo_id='${sid}'")"
}

begin_test "CONTROL: a curation sync of a gzip primary.xml ingests its packages; a truly empty primary is a successful empty sync"
reset_case
curate gz gz gz 3
note "primary.xml.gz: sync ${SYNC_CODE} succeeded=${SYNC_OK:-absent}; curation_packages=${NPKG} (${NAMES})"
[ "$SYNC_CODE" = "200" ] || fail_g "the sync answered ${SYNC_CODE}"
[ "$NPKG" = "3" ] || fail_g "${NPKG} packages ingested from a gzip primary, expected 3"
curate empty gz gz 0
note "gzip primary with packages=\"0\" and no packages: sync ${SYNC_CODE} succeeded=${SYNC_OK:-absent}; curation_packages=${NPKG}"
[ "$SYNC_CODE" = "200" ] && [ "$SYNC_OK" = "true" ] || fail_g "a truly empty primary answered ${SYNC_CODE} succeeded=${SYNC_OK:-absent}"
finish_case "RPM curation sync of a gzip or empty primary broken"

for codec in zst xz bz2; do
  begin_test "#4427: a curation sync of a ${codec}-compressed primary.xml ingests its packages and reports success"
  reset_case
  curate "$codec" "$codec" "$codec" 3
  note "primary.xml.${codec}: sync ${SYNC_CODE} succeeded=${SYNC_OK:-absent}; curation_packages=${NPKG} (${NAMES})"
  [ "$SYNC_CODE" = "200" ] && [ "$SYNC_OK" = "true" ] || fail_g "the sync answered ${SYNC_CODE} succeeded=${SYNC_OK:-absent}"
  [ "$NPKG" = "3" ] || fail_g "${NPKG} packages ingested from a ${codec} primary, expected 3"
  finish_case "a ${codec} primary.xml is not ingested"
done

begin_test "#4427: uncompressed bytes behind a .zst href, and a primary that declares packages but holds none, report succeeded:false"
reset_case
curate plain zst zst 3 plain
note "plain XML served as primary.xml.zst: sync ${SYNC_CODE} succeeded=${SYNC_OK:-absent}; curation_packages=${NPKG}"
[ "$SYNC_OK" = "false" ] || fail_g "a compressed href whose bytes are not that codec reported succeeded=${SYNC_OK:-absent}"
curate declared gz gz 3 declared
note "primary declaring packages=\"3\" with none: sync ${SYNC_CODE} succeeded=${SYNC_OK:-absent}; curation_packages=${NPKG}"
[ "$SYNC_OK" = "false" ] || fail_g "a primary that declares packages but yields none reported succeeded=${SYNC_OK:-absent}"
[ "$NPKG" = "0" ] || fail_g "${NPKG} packages ingested from a primary that holds none"
finish_case "a sync that cannot decode its primary, or ingests nothing from a non-empty one, still reports success"

end_suite
