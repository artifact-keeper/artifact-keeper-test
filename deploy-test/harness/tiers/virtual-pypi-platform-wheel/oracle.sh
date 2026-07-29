#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-pypi-platform-wheel/oracle.sh — #2937 distribution-granular
# ownership union oracle (reported #2748; hardened for the #2967 red-team)
# =============================================================================
# run.sh has already stood up `filesystem + upstreams.mockpypi-platform`: the
# backend plus a canned upstream `mock-pypi` that advertises several wheels of
# the project `dtfwheel` (see fixtures/mock_pypi_platform.py). run.sh exported
# BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT,
# DB_CONTAINER, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# TOPOLOGY: a LOCAL pypi repo owning the linux 2.0 wheel + a REMOTE over the
# mock, aggregated by a VIRTUAL in which the LOCAL outranks the REMOTE
# (priority 1 vs 2). The local member OWNS `dtfwheel`, so the #1600
# dependency-confusion guard engages against the lower-priority remote.
#
# DISCRIMINATORS, all through the VIRTUAL:
#   Case A (#2937)      dtfwheel-2.0-cp39-cp39-win_amd64.whl (platform-distinct
#                       wheel of the OWNED 2.0): PRESENT in the index (AK path)
#                       + download 200. Pre-fix-1 (name-coarse) suppressed it.
#   Case B (#1600)      dtfwheel-1.9-...whl (remote-only version): ABSENT + 404
#                       on every build.
#   #2967 HIGH          the attacker single-quoted anchor advertises the
#                       remote-only 3.3 off-site while its TEXT is an admitted
#                       owned wheel. The rendered index must carry NO off-site
#                       href (no `http://`, no `mock-pypi`) and MUST NOT surface
#                       3.3; 3.3 must 404 through AK. Pre-fix-2 (text-based
#                       filter + double-quote-only rewriter) leaked the off-site
#                       3.3 URL into the index.
#   #2967 MEDIUM (a)    dtfwheel-2.0-py3-none-any.whl (universal wheel of the
#                       owned version): ABSENT + 404. Pre-fix-2 admitted it.
#   #2967 MEDIUM (b)    dtfwheel-2.0-cp39-cp39-MANYLINUX_2_17_x86_64.whl
#                       (case-variant of the LOCAL's own tag): ABSENT + 404.
#                       Pre-fix-2 admitted it (raw-string tag compare).
#   Base                the local owner's own linux 2.0 wheel: PRESENT + 200.
#
# EXPECTED: PASS on the #2937/#2967 fix image; FAIL on the pre-fix-2 build (the
# HIGH + both MEDIUM assertions flip) — proving the oracle discriminates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "virtual-pypi-platform-wheel-2937"
auth_admin
setup_workdir

PKG="dtfwheel"
LOCAL_KEY="dtf-pypi-local-${RUN_ID}"
REMOTE_KEY="dtf-pypi-remote-${RUN_ID}"
VIRTUAL_KEY="dtf-pypi-virtual-${RUN_ID}"
MOCK_UPSTREAM="http://mock-pypi/"

LINUX_WHEEL="${PKG}-2.0-cp39-cp39-manylinux_2_17_x86_64.whl"       # local owner (Case-A backdrop)
CASE_A_WHEEL="${PKG}-2.0-cp39-cp39-win_amd64.whl"                  # remote, owned ver -> UNION
CASE_B_WHEEL="${PKG}-1.9-cp39-cp39-win_amd64.whl"                  # remote-only version -> SUPPRESS
UNIVERSAL_WHEEL="${PKG}-2.0-py3-none-any.whl"                      # universal -> SUPPRESS (#2967)
CASEVAR_WHEEL="${PKG}-2.0-cp39-cp39-MANYLINUX_2_17_x86_64.whl"     # case-variant -> SUPPRESS (#2967)
# #2967 R3: attacker off-site anchors, each an unclosed/malformed shape pointing
# at a distinct remote-only version. All must be absent from the index + 404.
#   4.4 unclosed single-quote  5.5 unclosed uppercase  6.6 </a >  7.7 </ a>  8.8 unquoted
ATTACK_VERSIONS="4.4 5.5 6.6 7.7 8.8"
EVIL_HOST="evilhost"

# #2967 R4 (CRITICAL content-type bypass): a second project the mock serves as an
# HTML body MISLABELED `Content-Type: application/json`. The local owns 1.0 linux.
PKG_R4="dtfjson"
R4_LINUX_WHEEL="${PKG_R4}-1.0-cp39-cp39-manylinux_2_17_x86_64.whl"   # local owner (1.0 linux)
R4_CASE_A_WHEEL="${PKG_R4}-1.0-cp39-cp39-win_amd64.whl"             # remote win of owned 1.0 -> UNION
R4_CASE_B_WHEEL="${PKG_R4}-2.0-cp39-cp39-win_amd64.whl"             # remote-only 2.0 off-site -> SUPPRESS

cleanup_repos() {
  api_delete "/api/v1/repositories/${VIRTUAL_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${REMOTE_KEY}"  >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${LOCAL_KEY}"   >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

create_repo_raw() {
  local payload="$1" body_file status body
  body_file="${WORK_DIR}/create.$$"
  status=$(curl -s -o "$body_file" -w '%{http_code}' --max-time 30 \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$payload" "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"
  body=$(cat "$body_file" 2>/dev/null || echo ""); rm -f "$body_file"
  echo "${status}|${body}"
}

add_member() {
  local vkey="$1" mkey="$2" prio="$3" payload
  payload=$(jq -n --arg m "$mkey" --argjson p "$prio" '{member_key:$m, priority:$p}')
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$payload" "${BASE_URL}/api/v1/repositories/${vkey}/members" 2>/dev/null || echo "000"
}

get_index() {
  local key="$1" pkg="${2:-$PKG}" body_file status body
  body_file="${WORK_DIR}/idx.$$"
  status=$(curl -s -o "$body_file" -w '%{http_code}' --max-time 40 \
    -H "$(auth_header)" -H "Accept: text/html" \
    "${BASE_URL}/pypi/${key}/simple/${pkg}/" 2>/dev/null) || status="000"
  body=$(cat "$body_file" 2>/dev/null || echo ""); rm -f "$body_file"
  echo "${status}|${body}"
}

get_download() {
  local key="$1" fn="$2" pkg="${3:-$PKG}"
  curl -s -o /dev/null -w '%{http_code}' --max-time 40 \
    -H "$(auth_header)" \
    "${BASE_URL}/pypi/${key}/simple/${pkg}/${fn}" 2>/dev/null || echo "000"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: create LOCAL pypi repo (${LOCAL_KEY})"
payload=$(jq -n --arg k "$LOCAL_KEY" '{key:$k, name:$k, format:"pypi", repo_type:"local", is_public:true}')
resp=$(create_repo_raw "$payload"); status="${resp%%|*}"; body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then pass
else fail "local PyPI create REJECTED (HTTP ${status}). body=${body:0:200}"; end_suite; fi

begin_test "Setup: upload the local owner's linux wheel (${LINUX_WHEEL})"
WHEEL_FILE="${WORK_DIR}/${LINUX_WHEEL}"
printf 'LOCAL-LINUX-WHEEL::%s' "$LINUX_WHEEL" > "$WHEEL_FILE"
ustatus=$(curl -s -o /dev/null -w '%{http_code}' --max-time 40 \
  -X POST -H "$(auth_header)" \
  -F ':action=file_upload' -F 'name='"$PKG" -F 'version=2.0' \
  -F "content=@${WHEEL_FILE};filename=${LINUX_WHEEL}" \
  "${BASE_URL}/pypi/${LOCAL_KEY}/" 2>/dev/null) || ustatus="000"
if [ "$ustatus" -ge 200 ] 2>/dev/null && [ "$ustatus" -lt 300 ] 2>/dev/null; then pass
else fail "local wheel upload REJECTED (HTTP ${ustatus}); cannot run the tier"; end_suite; fi

begin_test "Setup: upload the local owner's ${PKG_R4} linux wheel (${R4_LINUX_WHEEL})"
R4_WHEEL_FILE="${WORK_DIR}/${R4_LINUX_WHEEL}"
printf 'LOCAL-LINUX-WHEEL::%s' "$R4_LINUX_WHEEL" > "$R4_WHEEL_FILE"
ustatus=$(curl -s -o /dev/null -w '%{http_code}' --max-time 40 \
  -X POST -H "$(auth_header)" \
  -F ':action=file_upload' -F 'name='"$PKG_R4" -F 'version=1.0' \
  -F "content=@${R4_WHEEL_FILE};filename=${R4_LINUX_WHEEL}" \
  "${BASE_URL}/pypi/${LOCAL_KEY}/" 2>/dev/null) || ustatus="000"
if [ "$ustatus" -ge 200 ] 2>/dev/null && [ "$ustatus" -lt 300 ] 2>/dev/null; then pass
else fail "R4 local wheel upload REJECTED (HTTP ${ustatus}); cannot run the R4 discriminator"; end_suite; fi

begin_test "Setup: create REMOTE pypi repo over mock (${MOCK_UPSTREAM})"
payload=$(jq -n --arg k "$REMOTE_KEY" --arg u "$MOCK_UPSTREAM" \
  '{key:$k, name:$k, format:"pypi", repo_type:"remote", upstream_url:$u, is_public:true}')
resp=$(create_repo_raw "$payload"); status="${resp%%|*}"; body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then pass
else fail "remote PyPI create REJECTED (HTTP ${status}). body=${body:0:200}"; end_suite; fi

begin_test "Setup: create VIRTUAL with local(priority 1) outranking remote(priority 2)"
payload=$(jq -n --arg k "$VIRTUAL_KEY" '{key:$k, name:$k, format:"pypi", repo_type:"virtual", is_public:true}')
resp=$(create_repo_raw "$payload"); status="${resp%%|*}"; body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  ml=$(add_member "$VIRTUAL_KEY" "$LOCAL_KEY" 1)
  mr=$(add_member "$VIRTUAL_KEY" "$REMOTE_KEY" 2)
  if [ "$ml" -ge 200 ] 2>/dev/null && [ "$ml" -lt 300 ] 2>/dev/null \
     && [ "$mr" -ge 200 ] 2>/dev/null && [ "$mr" -lt 300 ] 2>/dev/null; then pass
  else fail "could not add members (local HTTP ${ml}, remote HTTP ${mr})"; end_suite; fi
else fail "virtual PyPI create REJECTED (HTTP ${status}). body=${body:0:200}"; end_suite; fi

# ---------------------------------------------------------------------------
# Fetch the rendered virtual index ONCE and classify.
# ---------------------------------------------------------------------------
resp=$(get_index "$VIRTUAL_KEY"); idx_status="${resp%%|*}"; idx_body="${resp#*|}"
snippet="HTTP ${idx_status}
index[0:900]=${idx_body:0:900}"

begin_test "Virtual simple index is served (HTTP 200)"
if [ "$idx_status" = "200" ]; then pass; else fail "virtual index not 200 (got ${idx_status})" "$snippet"; fi

begin_test "Base: local owner's linux wheel present in the virtual index"
if printf '%s' "$idx_body" | grep -qF "$LINUX_WHEEL"; then pass
else fail "local linux wheel '${LINUX_WHEEL}' missing from the virtual index" "$snippet"; fi

begin_test "#2937 Case A: remote windows wheel of the owned 2.0 present in the index"
if printf '%s' "$idx_body" | grep -qF "$CASE_A_WHEEL"; then pass
else fail "#2937: Case-A wheel '${CASE_A_WHEEL}' suppressed from the index" "$snippet"; fi

begin_test "#2937 Case B: remote-only version 1.9 absent from the index"
if printf '%s' "$idx_body" | grep -qF "$CASE_B_WHEEL"; then
  fail "#1600 REGRESSION: remote-only wheel '${CASE_B_WHEEL}' leaked into the index" "$snippet"
else pass; fi

# --- #2967 HIGH (R3): no off-site href of ANY anchor shape in the rendered index
begin_test "#2967 HIGH: rendered index carries NO off-site href (no http://, no mock-pypi, no ${EVIL_HOST})"
if printf '%s' "$idx_body" | grep -qiE "https?://|mock-pypi|${EVIL_HOST}"; then
  fail "#2967 HIGH: rendered virtual index leaks an off-site href (unclosed/malformed anchor passed through)" "$snippet"
else pass; fi

for v in $ATTACK_VERSIONS; do
  begin_test "#2967 HIGH: attacker off-site remote-only ${v} absent from the rendered index"
  if printf '%s' "$idx_body" | grep -qF "${PKG}-${v}-"; then
    fail "#2967 HIGH: remote-only version '${PKG}-${v}' surfaced via an unclosed/malformed off-site anchor" "$snippet"
  else pass; fi
done

# --- #2967 MEDIUM: universal + case-variant suppressed in the index ----------
begin_test "#2967 MEDIUM(a): universal py3-none-any wheel of owned 2.0 absent from the index"
if printf '%s' "$idx_body" | grep -qF "$UNIVERSAL_WHEEL"; then
  fail "#2967: universal wheel '${UNIVERSAL_WHEEL}' admitted (not a platform build)" "$snippet"
else pass; fi

begin_test "#2967 MEDIUM(b): case-variant of the local's own tag absent from the index"
if printf '%s' "$idx_body" | grep -qF "$CASEVAR_WHEEL"; then
  fail "#2967: case-variant wheel '${CASEVAR_WHEEL}' admitted (same platform as local)" "$snippet"
else pass; fi

# ---------------------------------------------------------------------------
# Download symmetry: what the index lists downloads; what it hides 404s.
# ---------------------------------------------------------------------------
begin_test "Base: local owner's linux wheel downloads (200) through the virtual"
d=$(get_download "$VIRTUAL_KEY" "$LINUX_WHEEL")
if [ "$d" = "200" ]; then pass; else fail "local linux wheel download expected 200, got ${d}"; fi

begin_test "#2937 Case A: remote windows wheel of owned 2.0 downloads (200) through the virtual"
d=$(get_download "$VIRTUAL_KEY" "$CASE_A_WHEEL")
if [ "$d" = "200" ]; then pass
else fail "#2937: Case-A wheel '${CASE_A_WHEEL}' download expected 200, got ${d}"; fi

begin_test "#2937 Case B: remote-only 1.9 stays suppressed on download (404)"
d=$(get_download "$VIRTUAL_KEY" "$CASE_B_WHEEL")
if [ "$d" = "404" ]; then pass
else fail "#1600 REGRESSION: remote-only wheel '${CASE_B_WHEEL}' download expected 404, got ${d}"; fi

for v in $ATTACK_VERSIONS; do
  begin_test "#2967 HIGH: attacker off-site remote-only ${v} stays 404 through AK"
  d=$(get_download "$VIRTUAL_KEY" "${PKG}-${v}-cp39-cp39-win_amd64.whl")
  if [ "$d" = "404" ]; then pass
  else fail "#2967: remote-only '${PKG}-${v}' download expected 404, got ${d}"; fi
done

begin_test "#2967 MEDIUM(a): universal wheel suppressed on download (404)"
d=$(get_download "$VIRTUAL_KEY" "$UNIVERSAL_WHEEL")
if [ "$d" = "404" ]; then pass
else fail "#2967: universal wheel '${UNIVERSAL_WHEEL}' download expected 404, got ${d}"; fi

begin_test "#2967 MEDIUM(b): case-variant wheel suppressed on download (404)"
d=$(get_download "$VIRTUAL_KEY" "$CASEVAR_WHEEL")
if [ "$d" = "404" ]; then pass
else fail "#2967: case-variant wheel '${CASEVAR_WHEEL}' download expected 404, got ${d}"; fi

# ---------------------------------------------------------------------------
# #2967 R4 (CRITICAL): the content-type bypass. The mock serves the second
# project (${PKG_R4}) as an HTML body MISLABELED `Content-Type: application/json`.
# Pre-R4: the ownership filter trusted the header, echoed the HTML verbatim, then
# sniffed HTML and ran the in-place `rewrite_upstream_urls` (no ownership filter,
# `[^>]*?` stops at the `>` inside the `title` attr) -> a RAW off-site href leaks
# AND the remote-only Case-B 2.0 surfaces. R4 fix: sniff the BODY not the header,
# route HTML through the ownership rebuild -> only owned Case-A AK paths survive.
# ---------------------------------------------------------------------------
resp=$(get_index "$VIRTUAL_KEY" "$PKG_R4"); r4_status="${resp%%|*}"; r4_body="${resp#*|}"
r4_snippet="HTTP ${r4_status}
index[0:900]=${r4_body:0:900}"

begin_test "#2967 R4: mislabeled application/json index still served (HTTP 200)"
if [ "$r4_status" = "200" ]; then pass; else fail "R4 virtual index not 200 (got ${r4_status})" "$r4_snippet"; fi

begin_test "#2967 R4 CRITICAL: rendered index carries NO off-site href (no http://, no ${EVIL_HOST})"
if printf '%s' "$r4_body" | grep -qiE "https?://|${EVIL_HOST}"; then
  fail "#2967 R4: mislabeled-json HTML body leaked an off-site href through rewrite_upstream_urls" "$r4_snippet"
else pass; fi

begin_test "#2967 R4 CRITICAL: remote-only Case-B ${R4_CASE_B_WHEEL} (2.0) absent from the index"
if printf '%s' "$r4_body" | grep -qF "$R4_CASE_B_WHEEL"; then
  fail "#2967 R4: remote-only Case-B '${R4_CASE_B_WHEEL}' surfaced (index/download asymmetry)" "$r4_snippet"
else pass; fi

begin_test "#2967 R4: owned Case-A ${R4_CASE_A_WHEEL} present as an AK path"
if printf '%s' "$r4_body" | grep -qF "/pypi/${VIRTUAL_KEY}/simple/${PKG_R4}/${R4_CASE_A_WHEEL}"; then pass
else fail "#2967 R4: owned Case-A '${R4_CASE_A_WHEEL}' missing or not AK-pathed" "$r4_snippet"; fi

begin_test "#2967 R4 Base: local owner's ${PKG_R4} linux 1.0 wheel present in the index"
if printf '%s' "$r4_body" | grep -qF "$R4_LINUX_WHEEL"; then pass
else fail "#2967 R4: local linux wheel '${R4_LINUX_WHEEL}' missing from the index" "$r4_snippet"; fi

begin_test "#2967 R4: owned Case-A ${R4_CASE_A_WHEEL} downloads (200) through the virtual"
d=$(get_download "$VIRTUAL_KEY" "$R4_CASE_A_WHEEL" "$PKG_R4")
if [ "$d" = "200" ]; then pass
else fail "#2967 R4: Case-A wheel '${R4_CASE_A_WHEEL}' download expected 200, got ${d}"; fi

begin_test "#2967 R4: remote-only Case-B ${R4_CASE_B_WHEEL} stays 404 through AK"
d=$(get_download "$VIRTUAL_KEY" "$R4_CASE_B_WHEEL" "$PKG_R4")
if [ "$d" = "404" ]; then pass
else fail "#2967 R4: remote-only Case-B '${R4_CASE_B_WHEEL}' download expected 404, got ${d}"; fi

end_suite
