#!/usr/bin/env bash
# shellcheck disable=SC2015  # A && B || fail_g is intended
# =============================================================================
# tiers/pypi-remote-index-path/oracle.sh
#   #5643 a proxy 502 names the upstream's status; PEP 691 negotiation reads
#         q-values and the `latest` alias
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"
SUF="$(printf '%s' "${DTF_SLOT}${RUN_ID##*-}$$" | tr -cd '0-9a-z')"
PROJ="dtfidx${SUF}"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# get <path> [accept]: sets CODE, CT (content type), UST (x-ak-upstream-status), BODY
get(){
  local -a ca=(-s -D "$W/hdr" -o "$W/body" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}")
  [ -n "${2:-}" ] && ca+=(-H "Accept: $2")
  : >"$W/hdr"; : >"$W/body"
  CODE="$(curl "${ca[@]}" "${BASE}$1" 2>/dev/null)"; [ -n "$CODE" ] || CODE=000
  CT="$(grep -i '^content-type:' "$W/hdr" | tail -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | cut -d';' -f1)"
  UST="$(grep -i '^x-ak-upstream-status:' "$W/hdr" | tail -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')"
  BODY="$(cat "$W/body" 2>/dev/null || true)"
}
mkrepo(){ # <key> <type> [upstream] [index path or "-"]: HTTP code on stdout
  curl -s -o "$W/mk.body" -w '%{http_code}' --max-time 30 -X POST "${BASE}/api/v1/repositories" \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" --arg ip "${4:--}" \
      '{key:$k,name:$k,format:"pypi",repo_type:$t,is_public:true}
       + (if $u == "" then {} else {upstream_url:$u} end)
       + (if $ip == "-" then {} else {pypi_upstream_index_path:$ip} end)')" 2>/dev/null || echo 000
}

begin_suite "pypi-remote-index-path"

# =============================================================================
begin_test "setup: admin session, a flat-layout index in the mock (its /simple/ path answers 403), two Remotes and a hosted repository with one wheel"
err=""
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; exit 1; }
[ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" = "ok" ] || err="${err} mock upstream not ready on ${MOCK};"
printf '<!DOCTYPE html>\n<html><body>\n<a href="%s/idx/files/%s-1.0-py3-none-any.whl#sha256=%s">%s-1.0-py3-none-any.whl</a>\n</body></html>\n' \
  "$UP" "$PROJ" "$(printf x | sha256sum | cut -d' ' -f1)" "$PROJ" > "$W/page.html"
c="$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary "@$W/page.html" "${MOCK}/__file?path=/idx/${PROJ}/&ctype=text/html" || true)"
is_ok(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
is_ok "$c" || err="${err} store flat page ${c};"
c="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${MOCK}/__status?path=/idx/simple/${PROJ}/&code=403" || true)"
is_ok "$c" || err="${err} force 403 ${c};"
R_DEF="pyidx-def-${SUF}"; R_FLAT="pyidx-flat-${SUF}"; R_H="pyidx-h-${SUF}"
c="$(mkrepo "$R_DEF" remote "${UP}/idx")"; is_ok "$c" || err="${err} remote ${R_DEF} ${c} $(head -c 150 "$W/mk.body");"
c="$(mkrepo "$R_FLAT" remote "${UP}/idx" "")"; is_ok "$c" || err="${err} remote ${R_FLAT} ${c} $(head -c 150 "$W/mk.body");"
c="$(mkrepo "$R_H" local)"; is_ok "$c" || err="${err} local ${R_H} ${c};"
python3 - "$W/w.whl" "$PROJ" <<'PY'
import base64, hashlib, sys, zipfile
out, name = sys.argv[1], sys.argv[2]
di = f"{name}-1.0.dist-info"
files = {f"{name}/__init__.py": "",
         f"{di}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
         f"{di}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
rec = []
with zipfile.ZipFile(out, "w") as zf:
    for n, t in files.items():
        d = t.encode(); zf.writestr(n, d)
        rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}")
    rec.append(f"{di}/RECORD,,"); zf.writestr(f"{di}/RECORD", "\n".join(rec) + "\n")
PY
c="$(curl -s -o "$W/up.out" -w '%{http_code}' --max-time 60 -X POST "${BASE}/pypi/${R_H}/" -H "Authorization: Bearer ${TOK}" \
  -F ":action=file_upload" -F "protocol_version=1" -F "metadata_version=2.1" -F "name=${PROJ}" -F "version=1.0" \
  -F "filetype=bdist_wheel" -F "pyversion=py3" -F "sha256_digest=$(sha256sum "$W/w.whl" | awk '{print $1}')" \
  -F "content=@$W/w.whl;filename=${PROJ}-1.0-py3-none-any.whl" 2>/dev/null || echo 000)"
is_ok "$c" || err="${err} wheel upload ${c} $(head -c 150 "$W/up.out");"
if [ -z "$err" ]; then pass; else infra_fail "${err}"; end_suite; exit 1; fi

# =============================================================================
# #5643 item 1: the upstream's status on the 502
# =============================================================================
begin_test "CONTROL: with pypi_upstream_index_path \"\" the Remote serves the flat index; with the default it answers 502 'Failed to fetch from upstream'"
reset_case
get "/pypi/${R_FLAT}/simple/${PROJ}/" "text/html"
note "flat Remote: ${CODE} ${CT} ($(printf '%s' "$BODY" | grep -c "${PROJ}-1.0-py3-none-any.whl") anchor line(s))"
[ "$CODE" = "200" ] && grep -q "${PROJ}-1.0-py3-none-any.whl" <<<"$BODY" || fail_g "the flat-layout Remote answered ${CODE}: ${BODY:0:160}"
get "/pypi/${R_DEF}/simple/${PROJ}/" "text/html"
note "default Remote: ${CODE} body '${BODY:0:80}'"
[ "$CODE" = "502" ] || fail_g "the default-index-path Remote answered ${CODE}, not 502"
[ "$BODY" = "Failed to fetch from upstream" ] || fail_g "the 502 body changed: '${BODY:0:120}'"
finish_case "flat index or default-path 502"

begin_test "FIX #5643: the 502 from a Remote whose upstream answers 403 carries X-AK-Upstream-Status: 403"
reset_case
get "/pypi/${R_DEF}/simple/${PROJ}/" "text/html"
note "default Remote: ${CODE}, X-AK-Upstream-Status '${UST}'"
[ "$UST" = "403" ] || fail_g "X-AK-Upstream-Status is '${UST}', expected 403"
get "/pypi/${R_DEF}/simple/${PROJ}/" "application/vnd.pypi.simple.v1+json"
note "default Remote (JSON): ${CODE}, X-AK-Upstream-Status '${UST}'"
[ "$CODE" = "502" ] && [ "$UST" = "403" ] || fail_g "the JSON request answered ${CODE} with X-AK-Upstream-Status '${UST}', expected 502 / 403"
finish_case "the 502 does not name the upstream status"

# =============================================================================
# #5643 item 2: PEP 691 negotiation
# =============================================================================
PIP_ACCEPT="application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01"
begin_test "CONTROL: pip/uv's Accept gets PEP 691 JSON; text/html and */* get HTML (project page and root index)"
reset_case
for p in "/pypi/${R_H}/simple/${PROJ}/" "/pypi/${R_H}/simple/"; do
  get "$p" "$PIP_ACCEPT"; note "${p} pip: ${CODE} ${CT}"
  [ "$CODE" = "200" ] && [ "$CT" = "application/vnd.pypi.simple.v1+json" ] || fail_g "${p} with pip's Accept: ${CODE} ${CT}"
  for a in "text/html" "*/*"; do
    get "$p" "$a"; note "${p} ${a}: ${CODE} ${CT}"
    [ "$CODE" = "200" ] && [ "$CT" = "text/html" ] || fail_g "${p} with Accept ${a}: ${CODE} ${CT}, expected text/html"
  done
done
finish_case "negotiation for common clients"

begin_test "FIX #5643: Accept latest+json gets JSON and v1+json;q=0.1, text/html gets HTML"
reset_case
for p in "/pypi/${R_H}/simple/${PROJ}/" "/pypi/${R_H}/simple/"; do
  get "$p" "application/vnd.pypi.simple.latest+json"; note "${p} latest+json: ${CODE} ${CT}"
  [ "$CODE" = "200" ] && [ "$CT" = "application/vnd.pypi.simple.v1+json" ] || fail_g "${p} with latest+json: ${CODE} ${CT}, expected application/vnd.pypi.simple.v1+json"
  get "$p" "application/vnd.pypi.simple.v1+json;q=0.1, text/html"; note "${p} json q=0.1, html: ${CODE} ${CT}"
  [ "$CODE" = "200" ] && [ "$CT" = "text/html" ] || fail_g "${p} preferring HTML: ${CODE} ${CT}, expected text/html"
done
finish_case "q-values or the latest alias ignored"

end_suite
