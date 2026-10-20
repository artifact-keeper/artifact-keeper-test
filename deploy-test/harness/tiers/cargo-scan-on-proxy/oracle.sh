#!/usr/bin/env bash
# =============================================================================
# tiers/cargo-scan-on-proxy/oracle.sh - the scan-on-proxy gate on proxied
# Cargo .crate downloads, Remote and Virtual
# =============================================================================
# artifact-keeper 1.11.0 #4101 (issue #4097). Before it, the Cargo download
# handler streamed a Remote's crate straight through even with
# scan_on_proxy=true; 1.11.0 sends it through
# proxy_helpers::serve_scanned_proxy_file with the Cargo identity (the
# crate's own Cargo.toml must declare the requested name and version) and the
# sparse-index cksum check.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH. Verdicts come from the backend
# image's bundled Grype and its pre-seeded DB; nothing leaves the host.
#
# Fixtures (profiles/upstreams.mock-scan-formats.yml): regex 1.5.4
# (GHSA-m5pq-gvj9-9vr8, high), dtf-scanclean 1.0.0 (no advisory),
# dtf-scanliar 2.0.0 (Cargo.toml says 1.0.0), dtf-badsum 1.0.0 (index cksum
# names other bytes).
#
# Green: ak-backend:1.11.0 and newer. Red: ak-backend:1.10.0.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "cargo-scan-on-proxy"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72/cargo"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

CR="csp-fc-${SUF}"    # Remote, scan_on_proxy, fail_closed
CR_FO="csp-fo-${SUF}" # Remote, scan_on_proxy, fail_open
CR_OFF="csp-off-${SUF}" # Remote, no scanning (control)
CR_M="csp-m-${SUF}"   # Remote member of the virtual, fail_closed
CV="csp-v-${SUF}"     # Virtual over CR_M

REGEX="api/v1/crates/regex/1.5.4/download"
CLEAN="api/v1/crates/dtf-scanclean/1.0.0/download"
LIAR="api/v1/crates/dtf-scanliar/2.0.0/download"
BADSUM="api/v1/crates/dtf-badsum/1.0.0/download"

cleanup() {
  local k
  for k in "$CV" "$CR_M" "$CR" "$CR_FO" "$CR_OFF"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/cargo/$1" || true; }
hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$1" | jq -r '.count // empty' 2>/dev/null; }

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock Cargo registry reachable and fixtures present"
if [ -n "$(golden_sha "$REGEX")" ] && [ -n "$(golden_sha "$CLEAN")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer"
fi

begin_test "Setup: Cargo Remotes (fail_closed, fail_open, unscanned) and a Virtual over a fail_closed Remote"
ok=1
for k in "$CR" "$CR_FO" "$CR_OFF" "$CR_M"; do create_repo "$k" cargo remote "$UP" || ok=0; done
create_repo "$CV" cargo virtual || ok=0
api_post "/api/v1/repositories/${CV}/members" "{\"member_key\":\"${CR_M}\"}" >/dev/null 2>&1 || ok=0
a="$(scan_cfg "$CR" fail_closed) $(scan_cfg "$CR_FO" fail_open) $(scan_cfg "$CR_M" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_open fail_closed" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

C="${BASE_URL}/cargo"

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: a Remote WITHOUT scan_on_proxy streams regex 1.5.4 unchanged, no X-AK-Scan"
pull "${C}/${CR_OFF}/${REGEX}"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "$REGEX")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: the sparse index entry for regex is proxied with the crate's real cksum"
pull "${C}/${CR}/re/ge/regex"
ck=$(jq -r 'select(.vers=="1.5.4") | .cksum' "$BODY" 2>/dev/null || true)
if [ "$ST" = "200" ] && [ "$ck" = "$(golden_sha "$REGEX")" ]; then
  pass
else
  fail "status=${ST} cksum='${ck}' body=$(snippet)"
fi

begin_test "control: config.json of the scanning Remote points cargo's dl at this repository"
pull "${C}/${CR}/config.json"
dl=$(jq -r '.dl // empty' "$BODY" 2>/dev/null || true)
if [ "$ST" = "200" ] && [[ "$dl" == *"/cargo/${CR}/api/v1/crates"* ]]; then
  pass
else
  fail "status=${ST} dl='${dl}'"
fi

begin_test "control: GET /api/v1/formats lists the cargo handler"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field cargo format_key)" = "cargo" ]; then pass; else fail "formats: $(head -c 200 "$FMT")"; fi

# ---------------------------------------------------------------------------
# #4101
# ---------------------------------------------------------------------------
begin_test "FIX #4101: /api/v1/formats reports cargo scan_on_proxy=enforced"
if [ "$(fmt_field cargo scan_on_proxy)" = "enforced" ]; then
  pass
else
  fail "cargo scan_on_proxy='$(fmt_field cargo scan_on_proxy)' (pre-1.11.0: field absent)"
fi

begin_test "FIX #4101: fail_open first pull of regex 1.5.4 is served 200 X-AK-Scan: pending, Cache-Control no-store"
pull "${C}/${CR_FO}/${REGEX}"
cc=$(hdr cache-control)
if [ "$ST" = "200" ] && [ "$SCAN" = "pending" ] && [ "$cc" = "no-store" ] && [ "$BSHA" = "$(golden_sha "$REGEX")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' cache-control='${cc}' (pre-1.11.0: streamed, no X-AK-Scan)"
fi

begin_test "FIX #4101: the async scan records a 'vulnerable' verdict (max high) for the crate's digest"
d=$(golden_sha "$REGEX")
regex_vulnerable() { [ "$(verdict_of "$d")" = "vulnerable" ]; }
wait_until "vulnerable verdict for regex-1.5.4.crate" 60 regex_vulnerable || true
sev=$(psql_q "SELECT max_severity FROM proxy_scan_results WHERE checksum_sha256='${d}' ORDER BY scanned_at DESC LIMIT 1")
if [ "$(verdict_of "$d")" = "vulnerable" ] && [ "$sev" = "high" ]; then
  pass
else
  fail "digest ${d}: verdict='$(verdict_of "$d")' max_severity='${sev}'"
fi

begin_test "FIX #4101: the next fail_open pull of regex 1.5.4 is 403 scan_blocked"
pull "${C}/${CR_FO}/${REGEX}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(jq -r '.file' "$BODY" 2>/dev/null)" = "regex-1.5.4.crate" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4101: the fail_closed Remote refuses regex 1.5.4 with 403 scan_blocked"
pull "${C}/${CR}/${REGEX}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4101: fail_closed inline scan serves a crate no advisory names: 200, X-AK-Scan: clean, immutable"
pull "${C}/${CR}/${CLEAN}"
cc=$(hdr cache-control)
if [ "$ST" = "200" ] && [ "$SCAN" = "clean" ] && [[ "$cc" == *immutable* ]] && [ "$BSHA" = "$(golden_sha "$CLEAN")" ] \
   && [ "$(verdict_of "$(golden_sha "$CLEAN")")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' cache-control='${cc}' verdict='$(verdict_of "$(golden_sha "$CLEAN")")'"
fi

begin_test "FIX #4101: a crate whose Cargo.toml declares another version is withheld under fail_closed (423, no verdict row)"
pull "${C}/${CR}/${LIAR}"
d=$(golden_sha "$LIAR")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4101: a crate that disagrees with the sparse-index cksum is refused 502 and not cached"
pull "${C}/${CR}/${BADSUM}"
st1="$ST"; b1=$(snippet)
h1=$(hits "/cargo/${BADSUM}")
pull "${C}/${CR}/${BADSUM}"
h2=$(hits "/cargo/${BADSUM}")
if [ "$st1" = "502" ] && grep -q "cksum" <<<"$b1" && [ "$ST" = "502" ] && [ -n "$h1" ] && [ "${h2:-0}" -gt "${h1:-0}" ] 2>/dev/null; then
  pass
else
  fail "first=${st1} ${b1} second=${ST} upstream GETs ${h1:-?} -> ${h2:-?}"
fi

begin_test "FIX #4101: through a Virtual whose Remote member scans, regex 1.5.4 is 403 scan_blocked"
pull "${C}/${CV}/${REGEX}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4101: through the same Virtual the clean crate is 200 with X-AK-Scan: clean"
pull "${C}/${CV}/${CLEAN}"
if [ "$ST" = "200" ] && [ "$SCAN" = "clean" ] && [ "$BSHA" = "$(golden_sha "$CLEAN")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

end_suite
