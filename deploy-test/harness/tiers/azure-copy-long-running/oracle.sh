#!/usr/bin/env bash
# =============================================================================
# tiers/azure-copy-long-running/oracle.sh -- #4858 discriminating oracle
# =============================================================================
# The fake Azure endpoint (profiles/storage.azure-stub.yml) answers a Put
# Blob From URL only after the delay set through PUT /__ctl/delay/<secs>,
# reached with `docker exec` into the stub container.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, COMMON_SH, RUN_ID.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
SLOTPFX="${DB_CONTAINER%-db}"
STUB="${SLOTPFX}-fake-azure"
BC="${SLOTPFX}-backend"
SFX="$(printf '%s' "${RUN_ID:-$$}" | tr -cd 'a-z0-9' | tail -c 8)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SLOW=45

jqr(){ jq -r "$1" 2>/dev/null; }
stub(){ docker exec "$STUB" python3 -c "import sys,urllib.request as u; r=u.Request('http://127.0.0.1:10000'+sys.argv[1], method=sys.argv[2], data=(b'' if sys.argv[2]=='PUT' else None)); print(u.urlopen(r, timeout=5).read().decode())" "$1" "$2"; }
set_delay(){ stub "/__ctl/delay/$1" PUT >/dev/null; }
copies(){ stub /__ctl/stats GET | jqr '.copies_done'; }
# Response bodies may quote a SAS URL; never print its signature.
redact(){ head -c 600 "$1" | sed -E 's/sig=[^&")[:space:]]*/sig=<redacted>/g'; }

begin_suite "azure-copy-long-running"

TOK=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u admin --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" \
  | jqr '.access_token // .token // empty')
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; exit 1; fi
AH="Authorization: Bearer $TOK"
BASIC="Authorization: Basic $(printf 'admin:%s' "$ADMIN_PASS" | base64 | tr -d '\n')"

OCI="acl-oci-$SFX"; GEN="acl-gen-$SFX"
mkrepo(){ curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories" -H "$AH" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local"}')"; }

# push_blob <file> <outfile-prefix>: POST session + monolithic PUT ?digest=.
# Prints "<http code> <seconds>"; the PUT response body lands in <prefix>.body.
push_blob(){
  local f="$1" out="$2" d loc sep t0 code
  d="sha256:$(sha256sum "$f" | cut -c1-64)"
  loc=$(curl -s -D- -o /dev/null -X POST -H "$BASIC" "$BASE/v2/$OCI/app/blobs/uploads/" \
        | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  [ -n "$loc" ] || { echo "000 0"; return; }
  case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
  case "$loc" in *\?*) sep='&' ;; *) sep='?' ;; esac
  t0=$(date +%s)
  code=$(curl -s -o "$out.body" -w '%{http_code}' --max-time 300 -X PUT -H "$BASIC" \
         -H 'Content-Type: application/octet-stream' --data-binary @"$f" "${loc}${sep}digest=${d}")
  echo "$code $(( $(date +%s) - t0 ))"
}
blob_sha(){ curl -s -H "$BASIC" "$BASE/v2/$OCI/app/blobs/$1" | sha256sum | cut -c1-64; }
gen_put(){
  local t0 code; t0=$(date +%s)
  code=$(curl -s -o "$WORK/$2.body" -w '%{http_code}' --max-time 300 -X PUT \
         "$BASE/api/v1/repositories/$GEN/artifacts/$2" -H "$AH" \
         -H 'Content-Type: application/octet-stream' --data-binary @"$1")
  echo "$code $(( $(date +%s) - t0 ))"
}
gen_get(){ curl -s -o "$2" -w '%{http_code}' "$BASE/api/v1/repositories/$GEN/download/$1" -H "$AH"; }

# ---------------------------------------------------------------------------
begin_test "Setup: Azure-backed docker and generic repositories on the fake endpoint"
c1=$(mkrepo "$OCI" docker); c2=$(mkrepo "$GEN" generic)
echo "-- create $OCI -> $c1, $GEN -> $c2; stub stats: $(stub /__ctl/stats GET)"
case "$c1$c2" in 200200|201201|200201|201200) pass ;; *) fail_fatal "repository create failed ($c1/$c2)"; exit 1 ;; esac

# ---------------------------------------------------------------------------
begin_test "CONTROL: with an instant server-side copy a 1 MiB OCI blob push is 201 and reads back"
set_delay 0
head -c 1048576 /dev/urandom > "$WORK/fast.bin"
before=$(copies)
read -r code secs < <(push_blob "$WORK/fast.bin" "$WORK/fast")
after=$(copies)
FS=$(sha256sum "$WORK/fast.bin" | cut -c1-64)
GOT=$(blob_sha "sha256:$FS")
echo "-- finalize -> $code in ${secs}s; stub copies $before -> $after; read-back sha256 match: $([ "$GOT" = "$FS" ] && echo yes || echo no)"
if [ "$code" = "201" ] && [ "$GOT" = "$FS" ] && [ "${after:-0}" -gt "${before:-0}" ]; then
  pass
else
  fail "fast OCI push failed" "code=$code body=$(redact "$WORK/fast.body")"
fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: with an instant server-side copy a staged generic upload is 201, byte-exact, and used the copy"
head -c 3145728 /dev/urandom > "$WORK/gfast.bin"
before=$(copies)
read -r code secs < <(gen_put "$WORK/gfast.bin" gfast.bin)
after=$(copies)
gcode=$(gen_get gfast.bin "$WORK/gfast.out")
echo "-- upload -> $code in ${secs}s; stub copies $before -> $after; download -> $gcode"
if { [ "$code" = "201" ] || [ "$code" = "200" ]; } && cmp -s "$WORK/gfast.out" "$WORK/gfast.bin" \
   && [ "${after:-0}" -gt "${before:-0}" ]; then
  pass
else
  fail "fast generic upload failed" "code=$code body=$(redact "$WORK/gfast.bin.body")"
fi

# ---------------------------------------------------------------------------
begin_test "FIX #4858: an OCI blob push whose server-side copy takes ${SLOW}s is 201, not aborted at 30s"
set_delay "$SLOW"
head -c 1048576 /dev/urandom > "$WORK/slow.bin"
read -r code secs < <(push_blob "$WORK/slow.bin" "$WORK/slow")
SS=$(sha256sum "$WORK/slow.bin" | cut -c1-64)
set_delay 0
GOT=$(blob_sha "sha256:$SS")
echo "-- finalize -> $code in ${secs}s; body: $(redact "$WORK/slow.body")"
echo "-- stub: $(stub /__ctl/stats GET)"
if [ "$code" = "201" ] && [ "$secs" -ge "$SLOW" ] && [ "$GOT" = "$SS" ]; then
  pass
else
  fail "OCI finalize did not wait for the ${SLOW}s Put Blob From URL (#4858)" \
       "code=$code after ${secs}s, read-back match=$([ "$GOT" = "$SS" ] && echo yes || echo no)"
fi

# ---------------------------------------------------------------------------
begin_test "FIX #4858: a staged generic upload whose server-side copy takes ${SLOW}s is 201 and byte-exact"
set_delay "$SLOW"
head -c 3145728 /dev/urandom > "$WORK/gslow.bin"
read -r code secs < <(gen_put "$WORK/gslow.bin" gslow.bin)
set_delay 0
gcode=$(gen_get gslow.bin "$WORK/gslow.out")
echo "-- upload -> $code in ${secs}s; download -> $gcode; body: $(redact "$WORK/gslow.bin.body")"
if { [ "$code" = "201" ] || [ "$code" = "200" ]; } && [ "$secs" -ge "$SLOW" ] \
   && cmp -s "$WORK/gslow.out" "$WORK/gslow.bin"; then
  pass
else
  fail "generic upload did not wait for the ${SLOW}s Put Blob From URL (#4858)" "code=$code after ${secs}s"
fi

echo "-- backend log lines naming Put Blob From URL:"
docker logs "$BC" 2>&1 | grep -i 'put blob from url' | tail -3 | cut -c1-300 \
  | sed -E 's/sig=[^&")[:space:]]*/sig=<redacted>/g'

end_suite
