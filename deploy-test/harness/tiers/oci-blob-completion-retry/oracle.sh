#!/usr/bin/env bash
# =============================================================================
# tiers/oci-blob-completion-retry/oracle.sh -- #4902 discriminating oracle
# =============================================================================
# The proxy (profiles/proxy.timeout-504.yml) listens on 127.0.0.1:${TRIVY_PORT}
# and is armed with PUT /__ctl/cut/<count>/<secs>. The backend is also reached
# directly at BASE_URL for the controls and the blob HEADs.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, COMMON_SH, RUN_ID,
# TRIVY_PORT.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
PROXY="http://127.0.0.1:${TRIVY_PORT}"
SFX="$(printf '%s' "${RUN_ID:-$$}" | tr -cd 'a-z0-9' | tail -c 8)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Large enough that the completion's server-side work (re-read, re-hash,
# promote) outlasts the proxy's cut by a wide margin.
BIG_MIB="${DTF_OCI_RETRY_BIG_MIB:-768}"
CUT_SECS="${DTF_OCI_RETRY_CUT_SECS:-0.3}"

jqr(){ jq -r "$1" 2>/dev/null; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }
ctl(){ curl -s -X "$1" "$PROXY/__ctl/$2"; }

begin_suite "oci-blob-completion-retry"

if ! curl -sf -o /dev/null "$PROXY/__ctl/readyz"; then
  infra_fail "timeout proxy not reachable at $PROXY"; end_suite; exit 1
fi
TOK=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u admin --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" \
  | jqr '.access_token // .token // empty')
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; exit 1; fi
AH="Authorization: Bearer $TOK"
BASIC="Authorization: Basic $(printf 'admin:%s' "$ADMIN_PASS" | base64 | tr -d '\n')"
REPO="ocr-$SFX"

# new_session <base>: POST an upload session; prints its Location (absolute).
new_session(){
  local loc
  loc=$(curl -s -D- -o /dev/null -X POST -H "$BASIC" "$1/v2/$REPO/app/blobs/uploads/" \
        | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  [ -n "$loc" ] || return 1
  case "$loc" in http*) loc="$1/${loc#http*://*/}" ;; *) loc="$1$loc" ;; esac
  echo "$loc"
}
session_id(){ local p="${1%%\?*}"; echo "${p##*/}"; }
# put_blob <location> <file> <digest> <out-prefix>: the containerd shape, one
# monolithic PUT ?digest= carrying the whole blob. Prints "<code> <secs>".
put_blob(){
  local loc="$1" f="$2" d="$3" out="$4" sep
  case "$loc" in *\?*) sep='&' ;; *) sep='?' ;; esac
  curl -s -o "$out.body" -D "$out.hdr" -w '%{http_code} %{time_total}' --max-time 600 -X PUT -H "$BASIC" \
       -H 'Content-Type: application/octet-stream' --data-binary @"$f" "${loc}${sep}digest=${d}"
  echo
}
digest_hdr(){ tr -d '\r' < "$1.hdr" 2>/dev/null | awk 'tolower($1)=="docker-content-digest:"{print $2}'; }
head_blob(){ curl -s -o /dev/null -w '%{http_code}' -I -H "$BASIC" "$BASE/v2/$REPO/app/blobs/$1"; }
row_of(){ psql_q "SELECT state || ' ' || to_char(updated_at, 'HH24:MI:SS.US') FROM oci_upload_sessions WHERE id = '$1'"; }

# ---------------------------------------------------------------------------
begin_test "Setup: docker repository and a ${BIG_MIB} MiB layer"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories" -H "$AH" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"docker",repo_type:"local"}')")
head -c $((BIG_MIB * 1048576)) /dev/urandom > "$WORK/big.bin"
BIGD="sha256:$(sha256sum "$WORK/big.bin" | cut -c1-64)"
echo "-- create $REPO -> $c; big layer $BIGD"
case "$c" in 200|201) pass ;; *) fail_fatal "repository create failed ($c)"; exit 1 ;; esac

# ---------------------------------------------------------------------------
begin_test "CONTROL: a monolithic blob push straight to the backend is 201 and HEAD is 200"
head -c 4194304 /dev/urandom > "$WORK/small.bin"
SD="sha256:$(sha256sum "$WORK/small.bin" | cut -c1-64)"
loc=$(new_session "$BASE")
read -r code secs < <(put_blob "$loc" "$WORK/small.bin" "$SD" "$WORK/small")
h=$(head_blob "$SD")
echo "-- PUT -> $code in ${secs}s; HEAD -> $h"
if [ "$code" = "201" ] && [ "$h" = "200" ]; then pass; else fail "direct push failed" "code=$code head=$h body=$(head -c 300 "$WORK/small.body")"; fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: the same push through the proxy, not armed, is 201"
head -c 4194304 /dev/urandom > "$WORK/small2.bin"
SD2="sha256:$(sha256sum "$WORK/small2.bin" | cut -c1-64)"
ctl PUT cut/0/0 >/dev/null
loc=$(new_session "$PROXY")
read -r code secs < <(put_blob "$loc" "$WORK/small2.bin" "$SD2" "$WORK/small2")
h=$(head_blob "$SD2")
echo "-- PUT via proxy -> $code in ${secs}s; HEAD -> $h; proxy: $(ctl GET stats)"
if [ "$code" = "201" ] && [ "$h" = "200" ]; then pass; else fail "push through the pass-through proxy failed" "code=$code head=$h"; fi

# ---------------------------------------------------------------------------
# cut_put <tag>: open a session through the proxy, arm one cut and send the big
# PUT. Sets LOC and SID; prints nothing. The caller checks CUT_CODE.
cut_put(){
  LOC=$(new_session "$PROXY"); SID=$(session_id "$LOC")
  ctl PUT "cut/1/$CUT_SECS" >/dev/null
  read -r CUT_CODE CUT_SECS_TAKEN < <(put_blob "$LOC" "$WORK/big.bin" "$BIGD" "$WORK/$1")
  CUT_ROW=$(row_of "$SID")
}

begin_test "CONTROL: a retry with a different digest while the cut completion is still running is 409"
cut_put cutA
OTHER="sha256:$(printf 'not the layer %s' "$SFX" | sha256sum | cut -c1-64)"
case "$LOC" in *\?*) sep='&' ;; *) sep='?' ;; esac
ocode=$(curl -s -o "$WORK/other.body" -w '%{http_code}' -X PUT -H "$BASIC" "${LOC}${sep}digest=${OTHER}")
echo "-- cut PUT -> $CUT_CODE after ${CUT_SECS_TAKEN}s (row then: $CUT_ROW); different-digest PUT -> $ocode $(head -c 200 "$WORK/other.body")"
if [ "$CUT_CODE" != "504" ]; then
  infra_fail "the proxy did not cut the completion (got $CUT_CODE); raise DTF_OCI_RETRY_BIG_MIB"
elif [ "$ocode" = "409" ]; then
  pass
else
  fail "a different-digest retry during a running completion must stay 409" "code=$ocode"
fi
# Let that completion settle before the next case.
for _ in $(seq 1 60); do [ -z "$(row_of "$SID" | grep committing)" ] && break; sleep 1; done

# ---------------------------------------------------------------------------
begin_test "FIX #4902: the identical PUT re-sent after the proxy's 504 is 201 (503 then 201 allowed), not 409"
# A fresh layer, so the blob cannot already exist from the case above.
head -c $((BIG_MIB * 1048576)) /dev/urandom > "$WORK/big.bin"
BIGD="sha256:$(sha256sum "$WORK/big.bin" | cut -c1-64)"
cut_put cutB
read -r r1 r1s < <(put_blob "$LOC" "$WORK/big.bin" "$BIGD" "$WORK/retry1")
r2="-"
if [ "$r1" = "503" ]; then
  sleep 2
  read -r r2 _ < <(put_blob "$LOC" "$WORK/big.bin" "$BIGD" "$WORK/retry2")
fi
echo "-- cut PUT -> $CUT_CODE after ${CUT_SECS_TAKEN}s (row then: $CUT_ROW)"
echo "-- retry -> $r1 in ${r1s}s $(head -c 200 "$WORK/retry1.body"); second retry -> $r2"
echo "-- proxy: $(ctl GET stats)"
if [ "$CUT_CODE" != "504" ]; then
  infra_fail "the proxy did not cut the completion (got $CUT_CODE); raise DTF_OCI_RETRY_BIG_MIB"
elif [ "$r1" = "201" ] || { [ "$r1" = "503" ] && [ "$r2" = "201" ]; }; then
  if [ "$r1" = "201" ]; then got=$(digest_hdr "$WORK/retry1"); else got=$(digest_hdr "$WORK/retry2"); fi
  if [ "$got" = "$BIGD" ]; then pass; else fail "retry 201 without the layer's Docker-Content-Digest" "got '$got'"; fi
else
  fail "the retried completion PUT was refused (#4902)" "retry=$r1 second=$r2 body=$(head -c 200 "$WORK/retry1.body")"
fi

# ---------------------------------------------------------------------------
begin_test "FIX #4902: the layer is published: blob HEAD is 200"
h=$(head_blob "$BIGD")
echo "-- HEAD $BIGD -> $h"
if [ "$h" = "200" ]; then pass; else fail "the cut layer never landed" "HEAD=$h"; fi

# ---------------------------------------------------------------------------
begin_test "FIX #4902: no session is left committing (the cut completion did not strand its lease)"
left=""
for _ in $(seq 1 10); do
  left=$(row_of "$SID")
  case "$left" in committing*) sleep 1 ;; *) break ;; esac
done
stuck=$(psql_q "SELECT count(*) FROM oci_upload_sessions s JOIN repositories r ON r.id = s.repository_id WHERE r.key = '$REPO' AND s.state = 'committing'")
echo "-- session $SID row after 10s: '${left:-<gone>}' (at the cut: '$CUT_ROW'); committing rows in $REPO: $stuck"
if [ "${stuck:-1}" = "0" ] && case "$left" in committing*) false ;; *) true ;; esac; then
  pass
else
  fail "a cancelled completion left its session committing" "row='$left' at-cut='$CUT_ROW' committing=$stuck"
fi

echo "-- proxy log:"
docker logs "${DB_CONTAINER%-db}-timeout-proxy" 2>&1 | grep -E 'cut|PUT' | tail -8 | cut -c1-200

end_suite
