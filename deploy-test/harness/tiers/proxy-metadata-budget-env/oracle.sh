#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-metadata-budget-env/oracle.sh - AK_PROXY_METADATA_BUDGET_BYTES
#   above 4 GiB is honoured, and the conda merge gate's default slot count
#   grows with it (artifact-keeper#4881)
# =============================================================================
# run.sh has stood up `storage.filesystem limits.proxy-metadata-budget` with
# AK_PROXY_METADATA_BUDGET_BYTES=34359738368 and exported BASE_URL, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# See the manifest for the bug and the red/green evidence.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every step below checks its own status.
set +e

SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
WANT_BUDGET="${AK_PROXY_METADATA_BUDGET_BYTES:-34359738368}"
OLD_MAX_MERGES=3

WORK="$(mktemp -d -t dtf-pmb-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

SFX="$(date +%s)$$"
H="dtf-pmb-hosted-${SFX}"
V="dtf-pmb-virtual-${SFX}"

# field NAME -> the value of NAME on the gate's init line (text or JSON log).
field() {
  python3 -I - "$WORK/gate.log" "$1" <<'PY'
import re, sys
path, name = sys.argv[1], sys.argv[2]
line = ""
for l in open(path, encoding="utf-8", errors="replace"):
    if "conda virtual merge gate configured" in l:
        line = l
m = re.search(r'\b' + re.escape(name) + r'"?\s*[=:]\s*"?(\d+)', line)
print(m.group(1) if m else "")
PY
}

begin_suite "dtf-proxy-metadata-budget-env"

begin_test "setup: admin login, a hosted conda channel and a virtual over it"
auth_admin
setup_err=""
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$V" conda virtual || setup_err+="create virtual; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${H}\"}" >/dev/null \
  || setup_err+="add member; "
if [ -n "$setup_err" ]; then
  infra_fail "$setup_err"
  end_suite
fi
pass

# The merge gate is built on the first virtual merge; this request runs one.
begin_test "control: the virtual's noarch/repodata.json answers 200 (runs a merge through the gate)"
code="$(curl -s --max-time 60 -o "$WORK/rd.json" -w '%{http_code}' \
  -H "$(auth_header)" "${BASE_URL}/conda/${V}/noarch/repodata.json" 2>/dev/null || echo 000)"
if [ "$code" = "200" ]; then
  pass
else
  infra_fail "GET /conda/${V}/noarch/repodata.json returned HTTP ${code}" "$(head -c 300 "$WORK/rd.json" 2>/dev/null)"
fi

# The line can trail the response by a moment; poll the log briefly.
for _ in $(seq 1 15); do
  docker logs "$BACKEND_CTR" > "$WORK/gate.log" 2>&1
  grep -q 'conda virtual merge gate configured' "$WORK/gate.log" && break
  sleep 1
done

begin_test "control: the backend logged 'conda virtual merge gate configured'"
if grep -q 'conda virtual merge gate configured' "$WORK/gate.log"; then
  pass
else
  infra_fail "no merge gate init line in the backend log" "$(tail -5 "$WORK/gate.log")"
fi

BUDGET="$(field budget_bytes)"
MAX_MERGES="$(field max_merges)"
echo "   gate init: budget_bytes=${BUDGET:-?} max_merges=${MAX_MERGES:-?} (configured ${WANT_BUDGET})"

begin_test "FIX #4881: budget_bytes is the configured ${WANT_BUDGET}, not clamped to 4294967295"
if [ "$BUDGET" = "$WANT_BUDGET" ]; then
  pass
else
  fail "budget_bytes=${BUDGET:-absent}, configured ${WANT_BUDGET}" \
    "$(grep 'conda virtual merge gate configured' "$WORK/gate.log" | tail -1)"
fi

begin_test "FIX #4881: the default max_merges grows past ${OLD_MAX_MERGES} with the 32 GiB budget"
if [ -n "$MAX_MERGES" ] && [ "$MAX_MERGES" -gt "$OLD_MAX_MERGES" ]; then
  pass
else
  fail "max_merges=${MAX_MERGES:-absent}, want > ${OLD_MAX_MERGES}" \
    "$(grep 'conda virtual merge gate configured' "$WORK/gate.log" | tail -1)"
fi

end_suite
