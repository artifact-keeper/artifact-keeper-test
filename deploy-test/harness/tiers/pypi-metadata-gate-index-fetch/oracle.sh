#!/usr/bin/env bash
# shellcheck disable=SC2015  # A && B || fail_g is intended
# =============================================================================
# tiers/pypi-metadata-gate-index-fetch/oracle.sh
#   #6439 PEP 658 metadata is refused when its distribution is refused or held
#   #5983 the client-facing index is fetched gzip-coded, and a cold sidecar is
#         resolved from the cached index
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), DB_CONTAINER, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
SUF="$(printf '%s' "${DTF_SLOT}${RUN_ID##*-}$$" | tr -cd '0-9a-z')"
P="pmg${SUF}"
JSON_CT="application/vnd.pypi.simple.v1+json"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
is_ok(){ case "$1" in 2??) return 0;; *) return 1;; esac; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# get <path> [accept] [out]: CODE, and the body in <out> (default $W/body)
get(){
  local out="${3:-$W/body}"
  local -a ca=(-s -o "$out" -w '%{http_code} %{time_total}' --max-time 60 -H "Authorization: Bearer ${TOK}")
  [ -n "${2:-}" ] && ca+=(-H "Accept: $2")
  CODE="$(curl "${ca[@]}" "${BASE}$1" 2>/dev/null)"; [ -n "$CODE" ] || CODE="000 0"
  TIME_MS="$(awk '{printf "%d", $2 * 1000}' <<<"$CODE")"; CODE="${CODE%% *}"
}
mkrepo(){ # <key> <type> [upstream]: HTTP code on stdout
  curl -s -o "$W/mk.body" -w '%{http_code}' --max-time 30 -X POST "${BASE}/api/v1/repositories" \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" \
      '{key:$k,name:$k,format:"pypi",repo_type:$t,is_public:true}
       + (if $u == "" then {} else {upstream_url:$u} end)')" 2>/dev/null || echo 000
}
member(){ # <virtual> <member>
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST "${BASE}/api/v1/repositories/$1/members" \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$2" '{member_key:$k,priority:1}')" 2>/dev/null || echo 000
}
mock_put(){ # <path> <file> [query]: HTTP code
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X PUT --data-binary "@$2" "${MOCK}/__file?path=$1${3:-}" || echo 000
}
mock_req(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1"; }
# wheel <out> <name> <version> <summary>: a real wheel whose METADATA carries <summary>
wheel(){
  python3 - "$@" <<'PY'
import base64, hashlib, sys, zipfile
out, name, version, summary = sys.argv[1:5]
di = f"{name}-{version}.dist-info"
files = {f"{name}/__init__.py": "",
         f"{di}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: {summary}\n",
         f"{di}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
rec = []
with zipfile.ZipFile(out, "w") as zf:
    for n, t in files.items():
        d = t.encode(); zf.writestr(n, d)
        rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}")
    rec.append(f"{di}/RECORD,,"); zf.writestr(f"{di}/RECORD", "\n".join(rec) + "\n")
PY
}
sha_of(){ sha256sum "$1" | awk '{print $1}'; }
# publish <project> <filler versions> <version...>: the project's wheels, their
# sidecars and its index (HTML, and PEP 691 JSON for a JSON Accept, both
# served gzip-coded to a gzip request) in the mock. The filler versions are
# index entries with no files behind them, to give the index a realistic size.
publish(){
  local proj="$1" filler="$2"; shift 2
  local v f err=""
  : > "$W/$proj.entries"
  for v in "$@"; do
    f="${proj}-${v}-py3-none-any.whl"
    wheel "$W/$f" "$proj" "$v" "dtf-6439-in-wheel"
    printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: dtf-upstream-sidecar-%s\n' "$proj" "$v" "$v" > "$W/$f.metadata"
    is_ok "$(mock_put "/${P}/files/$f" "$W/$f")" || err="${err} $f"
    is_ok "$(mock_put "/${P}/files/$f.metadata" "$W/$f.metadata")" || err="${err} $f.metadata"
    echo "$f $(sha_of "$W/$f")" >> "$W/$proj.entries"
  done
  python3 - "$W/$proj.entries" "$UP/${P}/files" "$proj" "$filler" "$W/$proj.html" "$W/$proj.json" <<'PY'
import json, sys
entries, base, proj, filler, html_out, json_out = sys.argv[1:7]
rows = [l.split() for l in open(entries) if l.strip()]
fill = [(f"{proj}-0.{i}-py3-none-any.whl", f"{i:064x}") for i in range(int(filler))]
files = fill + [(f, s) for f, s in rows]
with open(html_out, "w") as h:
    h.write("<!DOCTYPE html>\n<html><body>\n")
    for f, s in files:
        h.write(f'<a href="{base}/{f}#sha256={s}" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256={s}" data-core-metadata="sha256={s}">{f}</a><br/>\n')
    h.write("</body></html>\n")
with open(json_out, "w") as j:
    json.dump({"meta": {"api-version": "1.1"}, "name": proj, "versions": [],
               "files": [{"filename": f, "url": f"{base}/{f}", "hashes": {"sha256": s},
                          "requires-python": ">=3.8", "core-metadata": {"sha256": s},
                          "data-dist-info-metadata": {"sha256": s}, "yanked": False,
                          "size": 1000, "upload-time": "2025-01-01T00:00:00.000000Z"} for f, s in files]}, j)
PY
  is_ok "$(mock_put "/${P}/simple/${proj}/" "$W/$proj.html" "&ctype=text/html&gzip=1")" || err="${err} index"
  is_ok "$(mock_put "/${P}/simple/${proj}/" "$W/$proj.json" "&ctype=${JSON_CT//+/%2B}&gzip=1&when_accept=${JSON_CT//+/%2B}")" || err="${err} json"
  [ -z "$err" ] || SETUP_ERR="${SETUP_ERR} publish ${proj}:${err}"
}

begin_suite "pypi-metadata-gate-index-fetch"

# =============================================================================
begin_test "setup: admin session; a hosted repository with a wheel and a virtual over it; Remotes over the mock, one under a virtual that scans on proxy"
SETUP_ERR=""
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; exit 1; }
[ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" = "ok" ] || SETUP_ERR="${SETUP_ERR} mock not ready on ${MOCK};"
L="pmg-l-${SUF}"; VL="pmg-vl-${SUF}"; R="pmg-r-${SUF}"; VS="pmg-vs-${SUF}"; RP="pmg-rp-${SUF}"
for spec in "$L local" "$VL virtual" "$R remote ${UP}/${P}" "$VS virtual" "$RP remote ${UP}/${P}"; do
  # shellcheck disable=SC2086
  c="$(mkrepo $spec)"; is_ok "$c" || SETUP_ERR="${SETUP_ERR} repo ${spec%% *} ${c} $(head -c 120 "$W/mk.body");"
done
is_ok "$(member "$VL" "$L")" || SETUP_ERR="${SETUP_ERR} member ${VL};"
is_ok "$(member "$VS" "$R")" || SETUP_ERR="${SETUP_ERR} member ${VS};"
repo_id(){ psqlq "SELECT id FROM repositories WHERE key = '$1'"; }
L_ID="$(repo_id "$L")"; R_ID="$(repo_id "$R")"; VS_ID="$(repo_id "$VS")"
ADMIN_ID="$(psqlq "SELECT id FROM users WHERE username = 'admin'")"
[ -n "$L_ID" ] && [ -n "$R_ID" ] && [ -n "$VS_ID" ] && [ -n "$ADMIN_ID" ] || SETUP_ERR="${SETUP_ERR} ids;"
# The virtual scans on proxy (fail_closed); its member Remote does not (#3023).
[[ "$(psqlq "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, scan_on_proxy, block_on_policy_violation, severity_threshold, proxy_scan_action)
             VALUES ('${VS_ID}', true, false, true, false, 'high', 'fail_closed')
             ON CONFLICT (repository_id) DO UPDATE SET scan_enabled = true, scan_on_proxy = true, proxy_scan_action = 'fail_closed'
             RETURNING 'cfg-ok'")" = *cfg-ok* ]] || SETUP_ERR="${SETUP_ERR} scan config;"
# Hosted wheel.
HP="pmgh${SUF}"; HW="${HP}-1.0-py3-none-any.whl"
wheel "$W/$HW" "$HP" "1.0" "dtf-6439-hosted"
c="$(curl -s -o "$W/up.out" -w '%{http_code}' --max-time 60 -X POST "${BASE}/pypi/${L}/" -H "Authorization: Bearer ${TOK}" \
  -F ":action=file_upload" -F "protocol_version=1" -F "metadata_version=2.1" -F "name=${HP}" -F "version=1.0" \
  -F "filetype=bdist_wheel" -F "pyversion=py3" -F "sha256_digest=$(sha_of "$W/$HW")" \
  -F "content=@$W/$HW;filename=${HW}" 2>/dev/null || echo 000)"
is_ok "$c" || SETUP_ERR="${SETUP_ERR} upload ${c} $(head -c 120 "$W/up.out");"
# Upstream projects: V (member wheel with a row), N (member wheel, no row),
# J / H (index-fetch measurements, JSON and HTML clients), K (never indexed).
VP="pmgv${SUF}"; NP="pmgn${SUF}"; JP="pmgj${SUF}"; HTP="pmgt${SUF}"; KP="pmgk${SUF}"
publish "$VP" 0 1.0
publish "$NP" 0 1.0
publish "$JP" 3000 1.0 1.1 1.2 1.3
publish "$HTP" 3000 1.0 1.1 1.2 1.3
publish "$KP" 3000 1.0 1.1 1.2 1.3
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; exit 1; fi
pass

# =============================================================================
# #6439, hosted rows
# =============================================================================
HMETA="${HP}/${HW}.metadata"
both(){ # -> "direct-wheel direct-meta virtual-wheel virtual-meta"
  local a b c d
  get "/pypi/${L}/simple/${HP}/${HW}"; a="$CODE"
  get "/pypi/${L}/simple/${HMETA}" "" "$W/hmeta"; b="$CODE"
  get "/pypi/${VL}/simple/${HP}/${HW}"; c="$CODE"
  get "/pypi/${VL}/simple/${HMETA}" "" "$W/hvmeta"; d="$CODE"
  echo "$a $b $c $d"
}
set_q(){ psqlq "UPDATE artifacts SET quarantine_status = $1, quarantine_until = $2 WHERE repository_id = '${L_ID}' RETURNING 'q-ok'"; }

begin_test "CONTROL: an open hosted wheel and its PEP 658 metadata answer 200, directly and through a virtual"
reset_case
r="$(both)"; note "wheel / metadata, direct and virtual: ${r}"
[ "$r" = "200 200 200 200" ] || fail_g "answered ${r}"
grep -q 'dtf-6439-hosted' "$W/hmeta" || fail_g "the metadata is not the wheel's: $(head -c 120 "$W/hmeta")"
finish_case "the hosted wheel or its metadata is not served"

begin_test "FIX #6439: a quarantined hosted wheel's metadata answers 409 like the wheel, directly and through a virtual"
reset_case
[[ "$(set_q "'quarantined'" "now() + interval '1 hour'")" = *q-ok* ]] || fail_g "could not quarantine the row"
r="$(both)"; note "wheel / metadata, direct and virtual: ${r}"
read -r dw dm vw vm <<<"$r"
[ "$dw" = "409" ] && [ "$vw" = "409" ] || note "(premise) the wheel answered ${dw} / ${vw}, expected 409"
[ "$dm" = "409" ] || fail_g "direct metadata answered ${dm} while the wheel is held"
[ "$vm" = "409" ] || fail_g "virtual metadata answered ${vm} while the wheel is held"
! grep -q 'dtf-6439-hosted' "$W/hmeta" "$W/hvmeta" || fail_g "served the held wheel's METADATA"
finish_case "a held distribution's METADATA was served"

begin_test "FIX #6439: a rejected hosted wheel's metadata answers 403 like the wheel, directly and through a virtual"
reset_case
[[ "$(set_q "'rejected'" "NULL")" = *q-ok* ]] || fail_g "could not reject the row"
r="$(both)"; note "wheel / metadata, direct and virtual: ${r}"
read -r dw dm vw vm <<<"$r"
[ "$dw" = "403" ] && [ "$vw" = "403" ] || note "(premise) the wheel answered ${dw} / ${vw}, expected 403"
[ "$dm" = "403" ] || fail_g "direct metadata answered ${dm} while the wheel is rejected"
[ "$vm" = "403" ] || fail_g "virtual metadata answered ${vm} while the wheel is rejected"
set_q "NULL" "NULL" >/dev/null
finish_case "a rejected distribution's METADATA was served"

# =============================================================================
# #6439, a virtual that scans over a Remote that does not
# =============================================================================
VW="${VP}-1.0-py3-none-any.whl"; NW="${NP}-1.0-py3-none-any.whl"
begin_test "setup (#6439): the member Remote caches two wheels; both carry a stored vulnerable verdict; one is also recorded as a proxy-cache artifacts row"
SETUP_ERR=""
for pw in "${VP}/${VW}" "${NP}/${NW}"; do
  get "/pypi/${R}/simple/${pw}" "" "$W/cachefill"
  [ "$CODE" = "200" ] || SETUP_ERR="${SETUP_ERR} fill ${pw} ${CODE};"
done
for f in "$VW" "$NW"; do
  [[ "$(psqlq "INSERT INTO proxy_scan_results (checksum_sha256, scan_type, verdict, findings_count, critical_count, max_severity)
               VALUES ('$(sha_of "$W/$f")', 'grype', 'vulnerable', 1, 1, 'critical')
               ON CONFLICT (checksum_sha256, scan_type) DO UPDATE SET verdict = 'vulnerable', critical_count = 1, max_severity = 'critical'
               RETURNING 'v-ok'")" = *v-ok* ]] || SETUP_ERR="${SETUP_ERR} verdict ${f};"
done
# The cache entry's content key, from the backend's storage volume.
KEY="$(docker cp "${BACKEND_CTR}:/data/storage/proxy-cache" - 2>/dev/null | tar -t 2>/dev/null \
  | grep -F "/${R}/simple/${VP}/${VW}/__content__" | head -n1)"
[ -n "$KEY" ] || SETUP_ERR="${SETUP_ERR} no cache entry for ${VW};"
[[ "$(psqlq "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by)
             VALUES ('${R_ID}', 'simple/${VP}/${VW}', '${VP}', '1.0', $(stat -c %s "$W/$VW"), '$(sha_of "$W/$VW")',
                     'application/octet-stream', '${KEY}', '${ADMIN_ID}') RETURNING 'row-ok'")" = *row-ok* ]] \
  || SETUP_ERR="${SETUP_ERR} row;"
note "cache key ${KEY:-?}"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; else pass; fi

begin_test "CONTROL: the member Remote's own route, which does not scan, serves both wheels' metadata"
reset_case
for pw in "${VP}/${VW}" "${NP}/${NW}"; do
  get "/pypi/${R}/simple/${pw}.metadata" "" "$W/rmeta"
  note "${pw##*/}.metadata on the Remote: ${CODE}"
  [ "$CODE" = "200" ] || fail_g "${pw##*/}: the Remote answered ${CODE}"
done
finish_case "the Remote's own policy no longer decides its own route"

begin_test "FIX #6439: through the scanning virtual, the metadata of a member wheel with a blocking verdict answers 403, from a proxy-cache row or not"
reset_case
get "/pypi/${VS}/simple/${VP}/${VW}.metadata" "" "$W/vsmeta"; a="$CODE"
get "/pypi/${VS}/simple/${NP}/${NW}.metadata" "" "$W/vsnmeta"; b="$CODE"
note "with a row: ${a} $(head -c 90 "$W/vsmeta" | tr '\n' ' ')"
note "without a row: ${b} $(head -c 90 "$W/vsnmeta" | tr '\n' ' ')"
[ "$a" = "403" ] || fail_g "with a row: answered ${a}, expected the wheel's 403"
[ "$b" = "403" ] || fail_g "without a row: answered ${b}, expected the wheel's 403"
! grep -q 'dtf-6439-in-wheel' "$W/vsmeta" || fail_g "served the row's METADATA"
! grep -q 'dtf-upstream-sidecar' "$W/vsnmeta" || fail_g "served the upstream sidecar"
finish_case "the metadata of a wheel the virtual refuses was served"

begin_test "CONTROL: the scanning virtual refuses the member's wheel itself (403; 423 if it re-grades without a scanner)"
reset_case
for pw in "${VP}/${VW}" "${NP}/${NW}"; do
  get "/pypi/${VS}/simple/${pw}" "" "$W/vswheel"
  note "${pw##*/} through the virtual: ${CODE}"
  case "$CODE" in 403|423) ;; *) fail_g "${pw##*/}: the wheel answered ${CODE}" ;; esac
done
finish_case "the premise does not hold: the virtual serves the wheel"

# =============================================================================
# #5983
# =============================================================================
idx_gets(){ mock_req "/${P}/simple/$1/" | jqr '.get // 0'; }
idx_bytes(){ mock_req "/${P}/simple/$1/" | jqr '.bytes // 0'; }
idx_codings(){ mock_req "/${P}/simple/$1/" | jqr '.codings | join(",")'; }
# sidecars <project>: four concurrent cold `.whl.metadata` GETs; SC_CODES,
# SC_MS (the slowest one's time), SC_BAD (a body that is not the upstream
# sidecar's).
sidecars(){
  local proj="$1" v t pids=()
  for v in 1.0 1.1 1.2 1.3; do
    ( curl -s -o "$W/sc-$proj-$v" -w '%{http_code} %{time_total}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
        "${BASE}/pypi/${RP}/simple/${proj}/${proj}-${v}-py3-none-any.whl.metadata" > "$W/sc-$proj-$v.code" 2>/dev/null ) &
    pids+=("$!")
  done
  wait "${pids[@]}"
  SC_MS=0; SC_CODES=""; SC_BAD=""
  for v in 1.0 1.1 1.2 1.3; do
    read -r c t < "$W/sc-$proj-$v.code"
    t="$(awk '{printf "%d", $1 * 1000}' <<<"${t:-0}")"
    [ "$t" -gt "$SC_MS" ] && SC_MS="$t"
    SC_CODES="${SC_CODES}${c} "
    cmp -s "$W/sc-$proj-$v" "$W/${proj}-${v}-py3-none-any.whl.metadata" || SC_BAD="${SC_BAD} ${v}"
  done
  SC_CODES="${SC_CODES% }"
}
# The index read takes 400 ms on the mock, as a large index over a slow link does.
for proj in "$JP" "$HTP" "$KP"; do
  curl -s -o /dev/null --max-time 5 -X POST "${MOCK}/__delay?path=/${P}/simple/${proj}/&ms=400"
done

begin_test "CONTROL: four concurrent cold sidecars of a project whose index was never fetched share one upstream index read (#6047)"
reset_case
sidecars "$KP"
note "sidecars ${SC_CODES} in ${SC_MS} ms; upstream index reads $(idx_gets "$KP"), $(idx_bytes "$KP") bytes, Accept-Encoding [$(idx_codings "$KP")]"
[ "$SC_CODES" = "200 200 200 200" ] || fail_g "the sidecars answered ${SC_CODES}"
[ -z "$SC_BAD" ] || fail_g "sidecar bodies differ from the upstream's for${SC_BAD}"
[ "$(idx_gets "$KP")" = "1" ] || fail_g "$(idx_gets "$KP") upstream index reads, expected 1"
echo "MEASURE cold-no-index project=${KP} sidecar_ms=${SC_MS} index_reads=$(idx_gets "$KP") index_bytes=$(idx_bytes "$KP")"
finish_case "concurrent cold sidecars each read the index"

for client in json html; do
  if [ "$client" = json ]; then proj="$JP"; acc="$JSON_CT"; who="uv"; else proj="$HTP"; acc="text/html"; who="pip"; fi
  begin_test "FIX #5983: the client-facing index (${client}, as ${who} asks) is fetched gzip-coded, and four cold sidecars after it read no upstream index"
  reset_case
  get "/pypi/${RP}/simple/${proj}/" "$acc" "$W/idx-$proj"; idx_ms="$TIME_MS"
  b1="$(idx_bytes "$proj")"; c1="$(idx_codings "$proj")"
  note "index ${CODE} in ${idx_ms} ms, $(wc -c < "$W/idx-$proj") bytes to the client; upstream ${b1} bytes, Accept-Encoding [${c1}]"
  [ "$CODE" = "200" ] && grep -q "${proj}-1.3-py3-none-any.whl" "$W/idx-$proj" || fail_g "the index answered ${CODE}"
  case ",${c1}," in *gzip*) ;; *) fail_g "the index was asked as [${c1}], not gzip" ;; esac
  sidecars "$proj"
  n="$(idx_gets "$proj")"
  note "sidecars ${SC_CODES} in ${SC_MS} ms; upstream index reads in all ${n}, $(idx_bytes "$proj") bytes"
  echo "MEASURE client=${client} project=${proj} index_ms=${idx_ms} index_upstream_bytes_first=${b1} sidecar_ms=${SC_MS} index_reads=${n} index_bytes_total=$(idx_bytes "$proj") codings=${c1}"
  [ "$SC_CODES" = "200 200 200 200" ] || fail_g "the sidecars answered ${SC_CODES}"
  [ -z "$SC_BAD" ] || fail_g "sidecar bodies differ from the upstream's for${SC_BAD}"
  [ "$n" = "1" ] || fail_g "${n} upstream index reads, expected 1 (the sidecars re-read the index)"
  finish_case "the sidecars re-read the upstream index, or it was fetched uncompressed"
done

begin_test "CONTROL: a release published upstream after the index was cached resolves, with the new sidecar's bytes; earlier sidecars are unchanged"
reset_case
publish "$JP" 3000 1.0 1.1 1.2 1.3 2.0
# The resolver reuses one upstream index read for 30 s (#3356); past that, a
# release the upstream published must resolve on every image.
sleep 31
get "/pypi/${RP}/simple/${JP}/${JP}-2.0-py3-none-any.whl.metadata" "" "$W/new"
note "new release metadata: ${CODE} $(head -c 90 "$W/new" | tr '\n' ' ')"
[ "$CODE" = "200" ] && cmp -s "$W/new" "$W/${JP}-2.0-py3-none-any.whl.metadata" || fail_g "the new release's metadata answered ${CODE} with other bytes"
get "/pypi/${RP}/simple/${JP}/${JP}-1.0-py3-none-any.whl.metadata" "" "$W/old"
cmp -s "$W/old" "$W/${JP}-1.0-py3-none-any.whl.metadata" || fail_g "an earlier sidecar changed"
finish_case "a release published since the index was cached does not resolve"

end_suite
