#!/usr/bin/env bash
# =============================================================================
# tiers/ops-log-and-metrics-1112/oracle.sh - the 1.11.2 operator signals:
#   plain collected logs + JSON request fields (artifact-keeper#4674), the
#   detection metrics and OCI route templates (#4676), the refused-login and
#   external-findings audit rows and trusted X-Request-ID correlation (#4677),
#   plus two 1.11.0 metric facets (#4434 histogram, #3914 gallery gauge)
# =============================================================================
# run.sh has stood up `storage.filesystem logging.json-text-ansi` with
# RATE_LIMIT_ENABLED=true and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# See the manifest for which case goes red on which image.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every assertion below inspects its own status
# (grep -c of 0 matches, a curl that fails) and records it with fail().
set +e

SUF="${RUN_ID##*-}-$$"
CT=(--max-time 60 --connect-timeout 10)
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
TEXT_CTR="ak-dtf${SLOT}-backend-text"
ANSI_CTR="ak-dtf${SLOT}-backend-ansi"
GW_NET="ak-dtf${SLOT}-opsgw"
MOCK_IP="172.16.${SLOT}.71"
TRUSTED_PEER_IP="172.16.${SLOT}.70"   # inside RATE_LIMIT_TRUSTED_PROXY_CIDRS (.64/28)
UNTRUSTED_PEER_IP="172.16.${SLOT}.90" # outside it
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.11.1}"
ESC=$'\033'

GEN_REPO="olm-gen-${SLOT}-${SUF}"
VSC_REPO="olm-vsc-${SLOT}-${SUF}"
SSRF_REPO="olm-ssrf-${SLOT}-${SUF}"
OCI_NAME="olm-oci-${SLOT}-${SUF}"
RL_USER="olm-rl-${SLOT}-${SUF}"
RID_USER="olm-rid-${SLOT}-${SUF}"
NORID_USER="olm-norid-${SLOT}-${SUF}"
CID_USER="olm-cid-${SLOT}-${SUF}"
RID="gw-${SUF}-trusted"
NORID="gw-${SUF}-untrusted"
CID="cid-${SUF}-explicit"
APICID="cid-${SUF}-api"
ANONCID="cid-${SUF}-anon"
MAL_ID="MAL-2026-${SLOT}0${$}"

WORK="$(mktemp -d -t dtf-olm-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }

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
as_num() { [ "$1" = "absent" ] && echo 0 || echo "$1"; }

login_code() { # USER PASS -> HTTP status of POST /api/v1/auth/login from the host
  curl -s "${CT[@]}" -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg u "$1" --arg p "$2" '{username:$u, password:$p}')" 2>/dev/null || echo 000
}

# peer_login PEER_IP USER HEADER -> response headers of a failed login sent
# from a throwaway curl container pinned to PEER_IP on the opsgw network.
peer_login() {
  docker run --rm --network "$GW_NET" --ip "$1" "$CURL_IMAGE" \
    -s -D - -o /dev/null --max-time 30 -H "$3" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg u "$2" '{username:$u, password:"not-the-password"}')" \
    "http://backend:8080/api/v1/auth/login" 2>/dev/null | tr -d '\r'
}
echoed_cid() { awk -F': ' 'tolower($1)=="x-correlation-id"{print $2}' <<<"$1" | tail -1; }
audit_cid_for() { # USERNAME -> correlation_id of its newest LOGIN_FAILED row
  psql_q "SELECT correlation_id FROM audit_log WHERE action='LOGIN_FAILED' AND details->>'username'='$1' ORDER BY created_at DESC LIMIT 1"
}
audit_cid_present() { [ -n "$(audit_cid_for "$1")" ]; }

# json_completed CORRELATION_ID -> the backend's JSON "Request completed" line
# carrying that id (top-level or nested), compact, or nothing.
json_completed() {
  docker logs "$BACKEND_CTR" 2>/dev/null \
    | jq -Rc --arg c "$1" 'fromjson? | select(.fields.message == "Request completed")
        | select(.correlation_id == $c or .fields.correlation_id == $c)' 2>/dev/null | tail -1
}
json_completed_present() { [ -n "$(json_completed "$1")" ]; }

begin_suite "dtf-ops-log-and-metrics-1112"

# --- setup ------------------------------------------------------------------
begin_test "setup: admin login, generic repository, exporter reachable"
auth_admin
if ! create_repo "$GEN_REPO" generic local; then
  infra_fail "could not create the generic repository"
  end_suite
fi
code=$(scrape "${WORK}/m0.txt")
if [ "$code" != "200" ]; then
  infra_fail "GET /api/v1/admin/metrics returned HTTP ${code}" "$(head -c 300 "${WORK}/m0.txt" 2>/dev/null)"
  end_suite
fi
pass

begin_test "control: the exporter serves the pre-existing ak_http_requests_total series"
if grep -q '^# TYPE ak_http_requests_total counter' "${WORK}/m0.txt"; then
  pass
else
  fail "no ak_http_requests_total TYPE line in the scrape" "$(head -c 400 "${WORK}/m0.txt")"
fi

# --- #4434 (1.11.0): latency is a histogram ---------------------------------
begin_test "FIX #4434: ak_http_request_duration_seconds exports _bucket{le} series (0.005 .. +Inf), no quantile series"
b005=$(grep -c '^ak_http_request_duration_seconds_bucket{.*le="0.005"' "${WORK}/m0.txt")
b60=$(grep -c '^ak_http_request_duration_seconds_bucket{.*le="60"' "${WORK}/m0.txt")
binf=$(grep -c '^ak_http_request_duration_seconds_bucket{.*le="+Inf"' "${WORK}/m0.txt")
quant=$(grep -c '^ak_http_request_duration_seconds{.*quantile=' "${WORK}/m0.txt")
if [ "$b005" -ge 1 ] && [ "$b60" -ge 1 ] && [ "$binf" -ge 1 ] && [ "$quant" -eq 0 ]; then
  pass
else
  fail "bucket le=0.005:${b005} le=60:${b60} le=+Inf:${binf}; quantile lines:${quant}" \
    "$(grep '^ak_http_request_duration_seconds' "${WORK}/m0.txt" | head -5)"
fi

# --- #4676: connections gauge -----------------------------------------------
begin_test "FIX #4676: ak_http_connections_open is exported and counts the scraping connection (>= 1)"
conns=$(metric_value "${WORK}/m0.txt" ak_http_connections_open)
if [ "$conns" != "absent" ] && [ "${conns%.*}" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "ak_http_connections_open=${conns}"
fi

# --- rate-limited logins: #4676 metrics + #4677 audit row -------------------
scrape "${WORK}/m1.txt" >/dev/null
RL0=$(as_num "$(metric_value "${WORK}/m1.txt" ak_rate_limit_rejections_total limiter=login)")
UU0=$(as_num "$(metric_value "${WORK}/m1.txt" ak_auth_failures_total surface=api reason=unknown_user)")
BP0=$(as_num "$(metric_value "${WORK}/m1.txt" ak_auth_failures_total surface=api reason=bad_password)")

begin_test "control: 13 wrong logins for one username answer 401 x10 then 429 x3; a wrong admin password is 401"
codes=""
for _ in $(seq 1 13); do codes="${codes}$(login_code "$RL_USER" "wrong-${SUF}") "; done
codes="${codes% }"
bad_admin=$(login_code "${ADMIN_USER:-admin}" "definitely-not-${SUF}")
want="401 401 401 401 401 401 401 401 401 401 429 429 429"
if [ "$codes" = "$want" ] && [ "$bad_admin" = "401" ]; then
  pass
else
  fail "login codes: [${codes}] (want [${want}]); wrong admin password: ${bad_admin}"
fi

scrape "${WORK}/m2.txt" >/dev/null
RL1=$(as_num "$(metric_value "${WORK}/m2.txt" ak_rate_limit_rejections_total limiter=login)")
UU1=$(as_num "$(metric_value "${WORK}/m2.txt" ak_auth_failures_total surface=api reason=unknown_user)")
BP1=$(as_num "$(metric_value "${WORK}/m2.txt" ak_auth_failures_total surface=api reason=bad_password)")

begin_test "FIX #4676: ak_rate_limit_rejections_total{limiter=\"login\"} grows by exactly the 3 refusals"
if [ "$(metric_value "${WORK}/m2.txt" ak_rate_limit_rejections_total limiter=login)" != "absent" ] \
   && [ $(( RL1 - RL0 )) -eq 3 ]; then
  pass
else
  fail "limiter=login before=${RL0} after=${RL1} (series: $(metric_value "${WORK}/m2.txt" ak_rate_limit_rejections_total limiter=login))"
fi

begin_test "FIX #4676: ak_auth_failures_total{surface=\"api\"} counts 10 unknown_user and 1 bad_password, never a username label"
leak=$(grep '^ak_auth_failures_total' "${WORK}/m2.txt" | grep -c -e "$RL_USER" -e 'username=')
if [ "$(metric_value "${WORK}/m2.txt" ak_auth_failures_total surface=api reason=unknown_user)" != "absent" ] \
   && [ $(( UU1 - UU0 )) -eq 10 ] && [ $(( BP1 - BP0 )) -eq 1 ] && [ "$leak" -eq 0 ]; then
  pass
else
  fail "unknown_user delta=$(( UU1 - UU0 )) (want 10), bad_password delta=$(( BP1 - BP0 )) (want 1), label leaks=${leak}" \
    "$(grep '^ak_auth_failures_total' "${WORK}/m2.txt")"
fi

rl_rows() { psql_q "SELECT count(*) FROM audit_log WHERE action='LOGIN_RATE_LIMITED' AND details->>'username'='${RL_USER}'"; }
rl_rows_present() { [ "$(rl_rows)" -ge 1 ] 2>/dev/null; }
begin_test "FIX #4677: three 429 refusals write exactly ONE LOGIN_RATE_LIMITED audit row (username, path, no password)"
wait_until "LOGIN_RATE_LIMITED row" 15 rl_rows_present || true
sleep 2 # fire-and-forget audit writes: let any (wrong) second row land too
n=$(rl_rows)
det=$(psql_q "SELECT details::text FROM audit_log WHERE action='LOGIN_RATE_LIMITED' AND details->>'username'='${RL_USER}' LIMIT 1")
if [ "$n" = "1" ] && [ "$(jq -r '.path' <<<"$det" 2>/dev/null)" = "/api/v1/auth/login" ] \
   && [ "$(jq -r 'has("password")' <<<"$det" 2>/dev/null)" = "false" ] \
   && ! grep -q "wrong-${SUF}" <<<"$det"; then
  pass
else
  fail "LOGIN_RATE_LIMITED rows for ${RL_USER}: ${n} (want 1); details: ${det}"
fi

begin_test "control: the 10 rejected (non-429) attempts each wrote a LOGIN_FAILED audit row"
nf=$(psql_q "SELECT count(*) FROM audit_log WHERE action='LOGIN_FAILED' AND details->>'username'='${RL_USER}'")
if [ "$nf" = "10" ]; then pass; else fail "LOGIN_FAILED rows for ${RL_USER}: ${nf} (want 10)"; fi

# --- SSRF refusal: #4676 ----------------------------------------------------
begin_test "control: a Remote whose upstream is 10.10.10.10 is refused at create and not stored"
scode=$(curl -s "${CT[@]}" -o "${WORK}/ssrf.json" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' "${BASE_URL}/api/v1/repositories" \
  -d "$(jq -cn --arg k "$SSRF_REPO" '{key:$k,name:$k,format:"generic",repo_type:"remote",upstream_url:"http://10.10.10.10/"}')" \
  2>/dev/null || echo 000)
stored=$(psql_q "SELECT count(*) FROM repositories WHERE key='${SSRF_REPO}'")
if [ "$scode" = "400" ] && grep -q '10\.10\.10\.10' "${WORK}/ssrf.json" && [ "$stored" = "0" ]; then
  pass
else
  fail "create=${scode} stored=${stored}" "$(head -c 300 "${WORK}/ssrf.json")"
fi

begin_test "FIX #4676: the refusal is counted in ak_ssrf_blocks_total{surface=\"upstream\"} (exactly +1)"
scrape "${WORK}/m3.txt" >/dev/null
S0=$(as_num "$(metric_value "${WORK}/m2.txt" ak_ssrf_blocks_total surface=upstream)")
S1=$(metric_value "${WORK}/m3.txt" ak_ssrf_blocks_total surface=upstream)
if [ "$S1" != "absent" ] && [ $(( S1 - S0 )) -eq 1 ]; then
  pass
else
  fail "ak_ssrf_blocks_total{surface=upstream} before=${S0} after=${S1}"
fi

# --- OCI route template: #4676 ----------------------------------------------
OCI_T='/v2/{name}/manifests/{reference}'
begin_test "control: GET /v2/<unknown>/manifests/latest with Basic admin answers 404 NAME_UNKNOWN"
ocode=$(curl -s "${CT[@]}" -o "${WORK}/oci.json" -w '%{http_code}' -u "${ADMIN_USER:-admin}:${ADMIN_PASS}" \
  "${BASE_URL}/v2/${OCI_NAME}/manifests/latest" 2>/dev/null || echo 000)
if [ "$ocode" = "404" ] && [ "$(jq -r '.errors[0].code' "${WORK}/oci.json" 2>/dev/null)" = "NAME_UNKNOWN" ]; then
  pass
else
  fail "HTTP ${ocode}" "$(head -c 300 "${WORK}/oci.json")"
fi

begin_test "FIX #4676: the OCI request is labelled path=\"${OCI_T}\" (not \"unmatched\"); no label carries the image name"
scrape "${WORK}/m4.txt" >/dev/null
O0=$(as_num "$(metric_value "${WORK}/m3.txt" ak_http_requests_total method=GET "path=${OCI_T}")")
O1=$(metric_value "${WORK}/m4.txt" ak_http_requests_total method=GET "path=${OCI_T}")
leak=$(grep -c "$OCI_NAME" "${WORK}/m4.txt")
if [ "$O1" != "absent" ] && [ $(( O1 - O0 )) -ge 1 ] && [ "$leak" -eq 0 ]; then
  pass
else
  fail "requests_total{path=${OCI_T}} before=${O0} after=${O1}; series naming the image: ${leak}" \
    "$(grep '^ak_http_requests_total' "${WORK}/m4.txt" | grep -e v2 -e unmatched | head -5)"
fi

# --- VS Code gallery sub-budget gauge: #3914 (1.11.0) -----------------------
begin_test "control: a public vscode Remote serves a gallery query from the mock upstream"
create_repo "$VSC_REPO" vscode remote "http://${MOCK_IP}/vscode/gallery" || true
gcode=$(curl -s "${CT[@]}" -o "${WORK}/gal.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d '{"filters":[],"flags":0}' "${BASE_URL}/vscode/${VSC_REPO}/gallery/extensionquery" 2>/dev/null || echo 000)
mock_hits=$(docker exec "$BACKEND_CTR" curl -s --max-time 10 "http://${MOCK_IP}/__requests" 2>/dev/null \
  | jq '[.[] | select(.method=="POST" and (.path|endswith("/extensionquery")))] | length' 2>/dev/null)
if [ "$gcode" = "200" ] && [ "$(jq -r '.results|type' "${WORK}/gal.json" 2>/dev/null)" = "array" ] \
   && [ "${mock_hits:-0}" -ge 1 ]; then
  pass
else
  fail "gallery query HTTP ${gcode}; mock POSTs=${mock_hits}" "$(head -c 300 "${WORK}/gal.json")"
fi

begin_test "FIX #3914: ak_proxy_metadata_sub_budget_saturation_ratio{family=\"vscode_gallery\"} is exported and 0 when idle"
scrape "${WORK}/m5.txt" >/dev/null
gv=$(metric_value "${WORK}/m5.txt" ak_proxy_metadata_sub_budget_saturation_ratio family=vscode_gallery)
if [ "$gv" = "0" ]; then pass; else fail "gauge=${gv}"; fi

# --- external findings audit row: #4677 -------------------------------------
begin_test "control: POST /api/v1/security/findings/external ingests a MAL-* and a CVE finding (200)"
ART_ID=$(curl -s "${CT[@]}" -X PUT -H "$(auth_header)" -H 'Content-Type: application/octet-stream' \
  --data-binary "olm ${SUF}" "${BASE_URL}/api/v1/repositories/${GEN_REPO}/artifacts/olm/${SUF}.bin" 2>/dev/null \
  | jq -r '.id // empty' 2>/dev/null)
fcode=$(curl -s "${CT[@]}" -o "${WORK}/find.json" -w '%{http_code}' -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' "${BASE_URL}/api/v1/security/findings/external" \
  -d "$(jq -cn --arg a "$ART_ID" --arg m "$MAL_ID" '{artifact_id:$a, scanner:"dtf-olm-scanner",
        findings:[{severity:"critical", title:"malicious package", cve_id:$m},
                  {severity:"low", title:"old bug", cve_id:"CVE-2020-11111"}]}')" 2>/dev/null || echo 000)
if [ -n "$ART_ID" ] && [ "$fcode" = "200" ] && [ "$(jq -r '.findings_ingested' "${WORK}/find.json" 2>/dev/null)" = "2" ]; then
  pass
else
  fail "artifact=${ART_ID:-none} ingest HTTP ${fcode}" "$(head -c 300 "${WORK}/find.json")"
fi

efi_row() { psql_q "SELECT details::text FROM audit_log WHERE action='EXTERNAL_FINDINGS_INGESTED' AND resource_id::text='${ART_ID}' LIMIT 1"; }
efi_present() { [ -n "$(efi_row)" ]; }
begin_test "FIX #4677: the ingest wrote an EXTERNAL_FINDINGS_INGESTED audit row (scanner, class counts, MAL-* id)"
wait_until "EXTERNAL_FINDINGS_INGESTED row" 15 efi_present || true
row=$(efi_row)
if [ -n "$row" ] && [ "$(jq -r '.scanner' <<<"$row")" = "dtf-olm-scanner" ] \
   && [ "$(jq -c '.malicious_ids' <<<"$row")" = "[\"${MAL_ID}\"]" ] \
   && [ "$(jq -r '.class_counts.malicious' <<<"$row")" = "1" ] \
   && [ "$(jq -r '.findings_ingested' <<<"$row")" = "2" ]; then
  pass
else
  fail "row: ${row:-<none>}"
fi

# --- trusted gateway X-Request-ID: #4677 ------------------------------------
begin_test "FIX #4677: X-Request-ID from a trusted gateway (${TRUSTED_PEER_IP}) is the correlation id: echoed, on the audit row, in the JSON log"
hdrs=$(peer_login "$TRUSTED_PEER_IP" "$RID_USER" "X-Request-ID: ${RID}")
echoed=$(echoed_cid "$hdrs")
wait_until "LOGIN_FAILED row for ${RID_USER}" 15 audit_cid_present "$RID_USER" || true
acid=$(audit_cid_for "$RID_USER")
wait_until "JSON line for ${RID}" 10 json_completed_present "$RID" || true
jl=$(json_completed "$RID")
if [ "$echoed" = "$RID" ] && [ "$acid" = "$RID" ] && [ -n "$jl" ]; then
  pass
else
  fail "echoed=${echoed:-none} audit=${acid:-none} json line: ${jl:-none}" "$hdrs"
fi

begin_test "control: the same X-Request-ID from an untrusted peer (${UNTRUSTED_PEER_IP}) is ignored (new id, audit row does not carry it)"
hdrs=$(peer_login "$UNTRUSTED_PEER_IP" "$NORID_USER" "X-Request-ID: ${NORID}")
echoed=$(echoed_cid "$hdrs")
wait_until "LOGIN_FAILED row for ${NORID_USER}" 15 audit_cid_present "$NORID_USER" || true
acid=$(audit_cid_for "$NORID_USER")
if [ -n "$echoed" ] && [ "$echoed" != "$NORID" ] && [ -n "$acid" ] && [ "$acid" = "$echoed" ]; then
  pass
else
  fail "echoed=${echoed:-none} audit=${acid:-none}" "$hdrs"
fi

begin_test "control: an explicit X-Correlation-ID (untrusted peer) is echoed and stamped on the audit row"
hdrs=$(peer_login "$UNTRUSTED_PEER_IP" "$CID_USER" "X-Correlation-ID: ${CID}")
echoed=$(echoed_cid "$hdrs")
wait_until "LOGIN_FAILED row for ${CID_USER}" 15 audit_cid_present "$CID_USER" || true
acid=$(audit_cid_for "$CID_USER")
if [ "$echoed" = "$CID" ] && [ "$acid" = "$CID" ]; then pass; else fail "echoed=${echoed:-none} audit=${acid:-none}"; fi

# --- JSON request fields: #4674 ---------------------------------------------
curl -s "${CT[@]}" -o /dev/null -H "$(auth_header)" -H "X-Correlation-ID: ${APICID}" \
  "${BASE_URL}/api/v1/repositories/${GEN_REPO}" 2>/dev/null
curl -s "${CT[@]}" -o /dev/null -H "X-Correlation-ID: ${ANONCID}" \
  "${BASE_URL}/api/v1/repositories/${GEN_REPO}" 2>/dev/null
wait_until "JSON line for ${APICID}" 10 json_completed_present "$APICID" || true
wait_until "JSON line for ${ANONCID}" 10 json_completed_present "$ANONCID" || true
JL_API=$(json_completed "$APICID")
JL_ANON=$(json_completed "$ANONCID")

begin_test "control: LOG_FORMAT=json logs one Request completed object per request with fields.correlation_id"
if [ -n "$JL_API" ] && [ "$(jq -r '.fields.correlation_id' <<<"$JL_API")" = "$APICID" ] && [ -n "$JL_ANON" ]; then
  pass
else
  fail "authenticated line: ${JL_API:-none}; anonymous line: ${JL_ANON:-none}"
fi

begin_test "FIX #4674: the JSON line carries top-level method, uri, correlation_id, http.route, status (int), user, ip, latency_ms (int)"
chk=$(jq -r --arg c "$APICID" --arg u "${ADMIN_USER:-admin}" --arg uri "/api/v1/repositories/${GEN_REPO}" '
  [ (.method == "GET"), (.uri == $uri), (.correlation_id == $c),
    (.["http.route"] == "/api/v1/repositories/:key"), (.status == 200),
    (.user == $u), ((.ip // "") | length > 0), ((.latency_ms | type) == "number") ] | all' <<<"${JL_API:-null}" 2>/dev/null)
if [ "$chk" = "true" ]; then pass; else fail "line: ${JL_API:-none}"; fi

begin_test "FIX #4674: an anonymous request's JSON line has top-level status but no user"
chk=$(jq -r '[ (.status | type) == "number", (has("user") | not), (.fields | has("user") | not) ] | all' \
  <<<"${JL_ANON:-null}" 2>/dev/null)
if [ "$chk" = "true" ]; then pass; else fail "line: ${JL_ANON:-none}"; fi

# --- ANSI in collected logs: #4674 ------------------------------------------
# One non-probe request per sidecar so each logs a Request completed line.
docker exec "$BACKEND_CTR" curl -s --max-time 10 -o /dev/null "http://127.0.0.1:8081/api/v1/repositories/${GEN_REPO}" 2>/dev/null
docker exec "$BACKEND_CTR" curl -s --max-time 10 -o /dev/null "http://127.0.0.1:8082/api/v1/repositories/${GEN_REPO}" 2>/dev/null
text_completed() { docker logs "$TEXT_CTR" 2>&1 | grep 'Request completed' | grep -q "$GEN_REPO"; }
ansi_completed() { docker logs "$ANSI_CTR" 2>&1 | grep 'Request completed' | grep -q "$GEN_REPO"; }
wait_until "backend-text Request completed" 10 text_completed || true
wait_until "backend-ansi Request completed" 10 ansi_completed || true
docker logs "$TEXT_CTR" > "${WORK}/text.log" 2>&1
docker logs "$ANSI_CTR" > "${WORK}/ansi.log" 2>&1

begin_test "control: both text-format sidecars logged the request (Request completed naming the URI)"
tl=$(grep 'Request completed' "${WORK}/text.log" | grep -c "$GEN_REPO")
al=$(grep 'Request completed' "${WORK}/ansi.log" | grep -c "$GEN_REPO")
if [ "$tl" -ge 1 ] && [ "$al" -ge 1 ]; then pass; else fail "text lines=${tl} ansi lines=${al}"; fi

begin_test "control: LOG_ANSI=true still colours the text format (ESC[ present)"
an=$(grep -c "${ESC}\[" "${WORK}/ansi.log")
if [ "$an" -ge 1 ]; then pass; else fail "no ANSI escape in the LOG_ANSI=true log"; fi

begin_test "FIX #4674: default text format on a non-TTY stdout has no ANSI escape, so status=/uri= match as plain strings"
tn=$(grep -c "${ESC}\[" "${WORK}/text.log")
plain=$(grep 'Request completed' "${WORK}/text.log" | grep "$GEN_REPO" | grep -cE 'status=[0-9]{3}')
if [ "$tn" -eq 0 ] && [ "$plain" -ge 1 ]; then
  pass
else
  fail "lines with ESC[: ${tn}; plain status=NNN lines: ${plain}" \
    "$(grep 'Request completed' "${WORK}/text.log" | tail -1 | cat -v | head -c 400)"
fi

end_suite
