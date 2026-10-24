#!/usr/bin/env bash
# =============================================================================
# tiers/otlp-upstream-client-spans/oracle.sh
#   #3954  upstream CLIENT spans for test-upstream and the curation sync, with
#          integer http.response.status_code / server.port; DB_QUERY_SPANS=all
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, TRIVY_PORT (the mock's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DB_CONTAINER:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every step records its outcome through fail_g
# instead of aborting the suite.
set +e

BASE="$BASE_URL"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
SPANS_CTR="ak-dtf${DTF_SLOT}-otlp-spans"
MOCK="http://127.0.0.1:${TRIVY_PORT}"          # control side (host)
MOCK_IN="http://172.16.${DTF_SLOT}.77"          # backend side
MK="ucs${DTF_SLOT}${RUN_ID##*-}"

PROFILES=""
# shellcheck source=/dev/null
source "${HERE}/manifest"
COMPOSE_ARGS=(-p "$PROJECT" -f "${DTF_DIR}/compose.base.yml")
for p in $PROFILES; do COMPOSE_ARGS+=(-f "${DTF_DIR}/profiles/${p}.yml"); done
COMPOSE_ARGS+=(-f "${FX}/backend.tracing.yml")

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

backend_logs(){ docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
login(){
  TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
}
hex(){ head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# api <METHOD> <PATH> [JSON] -> API_CODE / API_BODY, with a fresh traceparent
# whose trace id is left in API_TID.
api(){
  local method="$1" path="$2" body="${3:-}"
  API_TID="$(hex 16)"
  local tp
  tp="00-${API_TID}-$(hex 8)-01"
  rm -f "$W/api.out"
  local args=(-s --max-time 90 -o "$W/api.out" -w '%{http_code}' -X "$method"
    -H "Authorization: Bearer $TOK" -H "traceparent: ${tp}")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  API_CODE="$(curl "${args[@]}" "${BASE}${path}")"
  API_BODY="$(cat "$W/api.out" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format> <type> [upstream]
  api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')"
  [ "$(jqr '.key // empty' <<<"$API_BODY")" = "$1" ]
}
# mock_file <path> <file> [ctype]: the mock answers GET/HEAD <path> with <file>.
mock_file(){
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X PUT --data-binary "@$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}"
}
# spans_in <tid>: every exported span of that trace (JSON lines).
spans_in(){
  docker exec "$SPANS_CTR" cat /tmp/otlp/spans.jsonl 2>/dev/null \
    | jq -c --arg t "$1" 'select(.trace_id == $t)' 2>/dev/null
}
# client_spans <tid> <method>: the trace's CLIENT spans named <method>.
client_spans(){ spans_in "$1" | jq -c --arg m "$2" 'select(.kind == 3 and .name == $m)' 2>/dev/null; }
# wait_trace <tid> <jq-filter> [secs]: until a span of the trace matches.
wait_trace(){
  local t="$1" f="$2" s="${3:-20}" _i
  for _i in $(seq 1 $((s * 2))); do
    [ -n "$(spans_in "$t" | jq -c "select(${f})" 2>/dev/null | head -1)" ] && return 0
    sleep 0.5
  done
  return 1
}
# show <span>: the facets the gates read, on one line.
show(){ jq -c '{name,kind,url:.attrs["url.full"],status:.attrs["http.response.status_code"],port:.attrs["server.port"],db:.attrs["db.system.name"]}' <<<"$1" 2>/dev/null; }
# int_attr <span> <key> <value>: 0 when the attribute is the JSON NUMBER <value>.
int_attr(){ [ "$(jq -r --arg k "$2" '.attrs[$k] | if type == "number" then tostring else "not-a-number:" + tostring end' <<<"$1" 2>/dev/null)" = "$3" ]; }

begin_suite "otlp-upstream-client-spans"

curl -s --max-time 5 "${MOCK}/__readyz" | grep -q ok || { infra_fail "the mock upstream is not reachable at ${MOCK}"; end_suite; exit $?; }
docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1
login
[ -n "$TOK" ] || { infra_fail "no admin session after recreating the backend: $(tail -3 "${W}/recreate.log")"; end_suite; exit $?; }

# --- fixtures on the mock ------------------------------------------------------
printf 'upstream:%s\n' "$MK" > "$W/blob"
printf 'dtf upstream root\n' > "$W/root"
python3 - "$W" "$MK" <<'PY'
import gzip, hashlib, sys
out, mk = sys.argv[1], sys.argv[2]
pkgs = "".join(
    f'<package type="rpm"><name>dtf-{n}-{mk}</name><arch>x86_64</arch>'
    f'<version epoch="0" ver="1.0" rel="1.el9"/>'
    f'<checksum type="sha256" pkgid="YES">{hashlib.sha256(n.encode()).hexdigest()}</checksum>'
    f'<location href="Packages/dtf-{n}-{mk}-1.0-1.el9.x86_64.rpm"/></package>'
    for n in ("alpha", "beta"))
xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<metadata xmlns="http://linux.duke.edu/metadata/common" '
       'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">' + pkgs + '</metadata>')
gz = gzip.compress(xml.encode(), mtime=0)
open(out + "/primary.xml.gz", "wb").write(gz)
open(out + "/repomd.xml", "w").write(
    '<?xml version="1.0" encoding="UTF-8"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>'
    f'<data type="primary"><checksum type="sha256">{hashlib.sha256(gz).hexdigest()}</checksum>'
    '<location href="repodata/u-primary.xml.gz"/></data></repomd>')
PY
c1="$(mock_file "/gen/" "$W/root" text/plain)"
c2="$(mock_file "/gen/a-${MK}.bin" "$W/blob")"
c3="$(mock_file "/rpm/repodata/repomd.xml" "$W/repomd.xml" text/xml)"
c4="$(mock_file "/rpm/repodata/u-primary.xml.gz" "$W/primary.xml.gz" application/gzip)"
[ "$c1$c2$c3$c4" = "200200200200" ] || { infra_fail "could not stage the mock files (${c1} ${c2} ${c3} ${c4})"; end_suite; exit $?; }

R_GEN="dtf-ucs-gen-${MK}"; R_RUP="dtf-ucs-rpmup-${MK}"; R_RST="dtf-ucs-rpmst-${MK}"
mk_repo "$R_GEN" generic remote "${MOCK_IN}/gen/" \
  && mk_repo "$R_RUP" rpm remote "${MOCK_IN}/rpm" \
  && mk_repo "$R_RST" rpm staging \
  || { infra_fail "could not create the repositories (HTTP ${API_CODE}: ${API_BODY:0:200})"; end_suite; exit $?; }
psql_q "UPDATE repositories SET curation_enabled=true, curation_allow_unverified=true,
          curation_source_repo_id=(SELECT id FROM repositories WHERE key='${R_RUP}') WHERE key='${R_RST}'" >/dev/null

# --- the traced requests -------------------------------------------------------
api GET "/api/v1/repositories/${R_GEN}/download/a-${MK}.bin"; GEN_CODE="$API_CODE"; GEN_BODY="$API_BODY"; GEN_TID="$API_TID"
api POST "/api/v1/repositories/${R_GEN}/test-upstream"; TU_CODE="$API_CODE"; TU_BODY="$API_BODY"; TU_TID="$API_TID"
api POST "/api/v1/curation/repos/${R_RST}/sync"; CS_CODE="$API_CODE"; CS_BODY="$API_BODY"; CS_TID="$API_TID"
api GET "/api/v1/repositories/${R_GEN}"; DB_CODE="$API_CODE"; DB_TID="$API_TID"
wait_trace "$DB_TID" '.name == "http_request"' 30

begin_test "CONTROL: spans arrive, and each traced request's http_request span joins its traceparent"
reset_case
nspans="$(docker exec "$SPANS_CTR" cat /tmp/otlp/spans.jsonl 2>/dev/null | wc -l | tr -d ' ')"
note "spans recorded: ${nspans}; download ${GEN_CODE}, test-upstream ${TU_CODE}, curation sync ${CS_CODE}, repo GET ${DB_CODE}"
[ "${nspans:-0}" -gt 0 ] || fail_g "the collector recorded no spans"
for t in "$GEN_TID" "$TU_TID" "$CS_TID" "$DB_TID"; do
  [ -n "$(spans_in "$t" | jq -c 'select(.name == "http_request" and .kind == 2)' | head -1)" ] \
    || fail_g "no SERVER http_request span in trace ${t}"
done
SL="$(backend_logs | grep -m1 'OpenTelemetry tracing enabled')"
note "startup: ${SL:0:300}"
[ -n "$SL" ] || fail_g "the 'OpenTelemetry tracing enabled' startup line is missing"
finish_case "OTLP span export or traceparent adoption is broken"

begin_test "FIX #3954: a proxied download exports a CLIENT span whose http.response.status_code and server.port are integers"
reset_case
note "download: HTTP ${GEN_CODE} body='${GEN_BODY%$'\n'}'"
[ "$GEN_CODE" = "200" ] && [ "${GEN_BODY%$'\n'}" = "upstream:${MK}" ] || fail_g "the generic remote download answered ${GEN_CODE} '${GEN_BODY:0:80}'"
wait_trace "$GEN_TID" '.kind == 3 and .name == "GET"' 20
S="$(client_spans "$GEN_TID" GET | jq -c --arg u "${MOCK_IN}/gen/a-${MK}.bin" 'select(.attrs["url.full"] == $u)' | head -1)"
note "CLIENT span: $(show "$S")"
if [ -z "$S" ]; then
  fail_g "no CLIENT GET span to ${MOCK_IN}/gen/a-${MK}.bin in the request's trace"
else
  int_attr "$S" http.response.status_code 200 || fail_g "http.response.status_code is $(jq -c '.attrs["http.response.status_code"]' <<<"$S"), expected the integer 200"
  int_attr "$S" server.port 80 || fail_g "server.port is $(jq -c '.attrs["server.port"]' <<<"$S"), expected the integer 80"
fi
finish_case "#3954: the upstream CLIENT span exports its integer attributes as strings"

begin_test "FIX #3954: POST test-upstream exports a CLIENT HEAD span to the remote's upstream with an integer status"
reset_case
note "test-upstream: HTTP ${TU_CODE} ${TU_BODY:0:200}"
[ "$TU_CODE" = "200" ] && [ "$(jqr '.upstream_status' <<<"$TU_BODY")" = "200" ] || fail_g "test-upstream answered ${TU_CODE}, expected 200 with upstream_status 200"
wait_trace "$TU_TID" '.kind == 3 and .name == "HEAD"' 15
S="$(client_spans "$TU_TID" HEAD | head -1)"
note "CLIENT span: $(show "$S")"
if [ -z "$S" ]; then
  fail_g "no CLIENT HEAD span in the test-upstream request's trace"
else
  [ "$(jqr '.attrs["url.full"]' <<<"$S")" = "${MOCK_IN}/gen/" ] || fail_g "url.full is '$(jqr '.attrs["url.full"]' <<<"$S")', expected ${MOCK_IN}/gen/"
  int_attr "$S" http.response.status_code 200 || fail_g "http.response.status_code is $(jq -c '.attrs["http.response.status_code"]' <<<"$S"), expected the integer 200"
fi
finish_case "#3954: the test-upstream probe bypasses the traced upstream send"

begin_test "FIX #3954: a curation sync cycle exports a CLIENT span per repodata fetch, each with an integer status"
reset_case
RST_ID="$(psql_q "SELECT id FROM repositories WHERE key='${R_RST}'" | tr -d '[:space:]')"
names="$(psql_q "SELECT string_agg(package_name, ',' ORDER BY package_name) FROM curation_packages WHERE staging_repo_id='${RST_ID}'" | tr -d '[:space:]')"
note "sync: HTTP ${CS_CODE} ${CS_BODY:0:200}; ingested: ${names}"
[ "$(jqr '.succeeded' <<<"$CS_BODY")" = "true" ] || fail_g "the curation sync did not succeed (HTTP ${CS_CODE})"
[ "$names" = "dtf-alpha-${MK},dtf-beta-${MK}" ] || fail_g "the sync ingested '${names}', expected both repodata packages"
wait_trace "$CS_TID" '.kind == 3 and .name == "GET"' 15
sleep 1
for f in repodata/repomd.xml repodata/u-primary.xml.gz; do
  S="$(client_spans "$CS_TID" GET | jq -c --arg u "${MOCK_IN}/rpm/${f}" 'select(.attrs["url.full"] == $u)' | head -1)"
  note "${f}: $(show "$S")"
  if [ -z "$S" ]; then
    fail_g "no CLIENT GET span for ${MOCK_IN}/rpm/${f} in the sync request's trace"
  else
    int_attr "$S" http.response.status_code 200 || fail_g "${f}: http.response.status_code is $(jq -c '.attrs["http.response.status_code"]' <<<"$S"), expected the integer 200"
  fi
done
finish_case "#3954: the curation sync's upstream fetches bypass the traced upstream send"

begin_test "FIX #3954: with DB_QUERY_SPANS=all and RUST_LOG=info a request exports database CLIENT spans, and stdout still logs no SQL"
reset_case
wait_trace "$DB_TID" '.kind == 3 and .attrs["db.system.name"] == "postgresql"' 10
nd="$(spans_in "$DB_TID" | jq -c 'select(.kind == 3 and .attrs["db.system.name"] == "postgresql")' | wc -l | tr -d ' ')"
note "repo GET: HTTP ${DB_CODE}; database spans in its trace: ${nd}; e.g. $(spans_in "$DB_TID" | jq -c 'select(.kind == 3 and .attrs["db.system.name"] == "postgresql") | .name' | head -3 | tr '\n' ' ')"
[ "${nd:-0}" -gt 0 ] || fail_g "no database CLIENT span in the request's trace"
LOGS="$(backend_logs)"
if grep -q 'db.statement' <<<"$LOGS"; then
  fail_g "stdout logs statement text although RUST_LOG=info: $(grep -m1 'db.statement' <<<"$LOGS" | cut -c1-200)"
fi
finish_case "#3954: database spans still need sqlx::query=debug (and with it every statement on stdout)"

end_suite
