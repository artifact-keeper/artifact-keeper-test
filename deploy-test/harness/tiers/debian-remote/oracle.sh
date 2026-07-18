#!/usr/bin/env bash
# =============================================================================
# tiers/debian-remote/oracle.sh — Debian remote/proxy discriminating oracle
#   PKT-A (epic #2458): #2459 (proxy integrity) + #2460 (dist/comp/arch filter)
# =============================================================================
# run.sh has stood up the `filesystem + upstreams=debian` profile-set (a mock
# APT upstream `deb-upstream` on the slot's 172.16/12 net serving a baked,
# signed-shaped dists/ tree: a clean `bookworm` and a tampered `bookworm-evil`)
# and exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT
# and JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit harness.
#
# The gate has TWO halves; BOTH must hold or the tier fails.
#
# --- #2459 integrity (enforce_dists_integrity) -------------------------------
#   POS  GET dists/bookworm/main/binary-amd64/Packages          -> 200, body
#        bytes hash to the sha the signed bookworm/Release vouches for.
#   NEG  GET dists/bookworm-evil/main/binary-amd64/Packages      -> 502 (the
#        served Packages sha != the sha bookworm-evil/Release pins) with body
#        "integrity verification". A backend WITHOUT the guard serves the
#        tampered index 200 -> the red.
#   EVICT a second GET of the poisoned path is ALSO 502 and never serves the
#        tampered bytes (no poisoned-cache serve).
#
# --- #2460 filtering (debian_config allowlist -> 404) ------------------------
#   set debian_config = {distribution_paths:[bookworm],components:[main],
#                        architectures:[amd64]} via the repo-update `debian` field
#   POS  GET dists/bookworm/main/binary-amd64/Packages           -> 200 (allowed)
#   NEG  GET dists/bookworm/contrib/binary-amd64/Packages        -> 404 (comp)
#        GET dists/bookworm/main/binary-arm64/Packages           -> 404 (arch)
#   GUARD clear the filter (debian:null) and re-GET the two filtered paths: both
#        now 200 -> proves the 404s were filter-driven, not dead routes.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "debian-remote-2459-2460"
auth_admin
setup_workdir

KEY="dtf-debremote-${RUN_ID}"
# No trailing slash needed; the proxy join trims either way. deb-upstream sits
# on 172.31.<slot>.60 (inside AK_SSRF_ALLOW_PRIVATE_CIDRS=172.16/12).
UPSTREAM="http://deb-upstream"
DEB="${BASE_URL}/debian/${KEY}/dists"

cleanup_repo() { api_delete "/api/v1/repositories/${KEY}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup_repo"

# req METHOD PATH [DATA] -> sets REQ_STATUS + writes body to REQ_BODY_FILE.
REQ_STATUS=""; REQ_BODY_FILE="${WORK_DIR}/req-body"
req() {
  local method="$1" path="$2" data="${3:-}"
  local args=(-s -o "$REQ_BODY_FILE" -w '%{http_code}' --max-time 40 -X "$method" -H "$(auth_header)")
  [ -n "$data" ] && args+=(-H "Content-Type: application/json" -d "$data")
  REQ_STATUS=$(curl "${args[@]}" "$path" 2>/dev/null) || REQ_STATUS="000"
}
body() { cat "$REQ_BODY_FILE" 2>/dev/null || true; }
body_sha() { sha256sum "$REQ_BODY_FILE" 2>/dev/null | cut -d' ' -f1; }

# ---------------------------------------------------------------------------
# Setup: create the Debian REMOTE repo pointing at the mock upstream.
# ---------------------------------------------------------------------------
begin_test "Create Debian remote repo ${KEY} -> ${UPSTREAM} (allowlisted 172.16/12)"
if create_repo "$KEY" "debian" "remote" "$UPSTREAM"; then
  pass
else
  fail "could not create Debian remote repo (see create_repo stderr above); the whole tier is untestable without it"
  end_suite
fi

# ===========================================================================
# HALF A — #2459 proxy integrity (run BEFORE any filter is set, so both dists
# are reachable).
# ===========================================================================

begin_test "#2459 POS: clean bookworm/main/binary-amd64/Packages served 200 + hash matches signed Release"
req GET "${DEB}/bookworm/main/binary-amd64/Packages"
if [ "$REQ_STATUS" != "200" ]; then
  fail "clean Packages expected 200, got ${REQ_STATUS}" "$(body | head -c 300)"
elif ! body | grep -q 'DTF-PKG-MARKER=bookworm-main-amd64-CLEAN'; then
  fail "clean Packages 200 but body marker missing (not the upstream bytes?)" "$(body | head -c 300)"
else
  served_sha="$(body_sha)"
  # Pull the sha the signed Release vouches for this exact path.
  req GET "${DEB}/bookworm/Release"
  rel_sha="$(body | awk '$3=="main/binary-amd64/Packages"{print $1; exit}')"
  if [ -z "$rel_sha" ]; then
    fail "could not read bookworm/Release SHA256 entry for main/binary-amd64/Packages" "$(body | head -c 400)"
  elif [ "$served_sha" != "$rel_sha" ]; then
    fail "served Packages sha ${served_sha} != Release-pinned sha ${rel_sha} (clean tree inconsistent)"
  else
    pass
  fi
fi

begin_test "#2459 NEG: tampered bookworm-evil Packages must 502 (enforce_dists_integrity), not serve poisoned bytes"
req GET "${DEB}/bookworm-evil/main/binary-amd64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'TAMPERED-POISON'; then
  fail "#2459 RED: tampered index served 200 with poisoned body -> integrity NOT enforced" "$(body | head -c 300)"
elif [ "$REQ_STATUS" != "502" ]; then
  fail "tampered index expected 502, got ${REQ_STATUS}" "$(body | head -c 300)"
elif ! body | grep -qi 'integrity verification'; then
  fail "got 502 but body lacks the integrity-verification message (wrong 502 cause?)" "$(body | head -c 300)"
else
  pass
fi

begin_test "#2459 EVICT: repeat GET of the poisoned path is still 502 (no poisoned-cache serve)"
req GET "${DEB}/bookworm-evil/main/binary-amd64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'TAMPERED-POISON'; then
  fail "#2459 RED: second GET served the poisoned bytes 200 (cache not evicted)" "$(body | head -c 300)"
elif [ "$REQ_STATUS" != "502" ]; then
  fail "second GET of poisoned path expected 502, got ${REQ_STATUS}" "$(body | head -c 300)"
else
  pass
fi

# ===========================================================================
# HALF B — #2460 dist/component/arch filtering.
# ===========================================================================

begin_test "Set debian_config filter: distribution_paths=[bookworm] components=[main] architectures=[amd64]"
req PATCH "${BASE_URL}/api/v1/repositories/${KEY}" \
  '{"debian":{"distribution_paths":["bookworm"],"components":["main"],"architectures":["amd64"]}}'
if [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "setting debian filter via repo update expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
fi

begin_test "#2460 POS: included main/binary-amd64 served 200 under the filter"
req GET "${DEB}/bookworm/main/binary-amd64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'DTF-PKG-MARKER=bookworm-main-amd64-CLEAN'; then
  pass
else
  fail "included (allowed) path expected 200+marker, got ${REQ_STATUS}" "$(body | head -c 300)"
fi

begin_test "#2460 NEG: filtered-out component (contrib) must 404"
req GET "${DEB}/bookworm/contrib/binary-amd64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'DTF-PKG-MARKER'; then
  fail "#2460 RED: filtered-out component 'contrib' was served ${REQ_STATUS} (filter ignored)" "$(body | head -c 300)"
elif [ "$REQ_STATUS" != "404" ]; then
  fail "filtered-out component expected 404, got ${REQ_STATUS}" "$(body | head -c 300)"
else
  pass
fi

begin_test "#2460 NEG: filtered-out arch (arm64) must 404"
req GET "${DEB}/bookworm/main/binary-arm64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'DTF-PKG-MARKER'; then
  fail "#2460 RED: filtered-out arch 'arm64' was served ${REQ_STATUS} (filter ignored)" "$(body | head -c 300)"
elif [ "$REQ_STATUS" != "404" ]; then
  fail "filtered-out arch expected 404, got ${REQ_STATUS}" "$(body | head -c 300)"
else
  pass
fi

# Allow-all guard: clear the filter and confirm the just-404'd paths now 200.
# This proves the 404s were driven by the filter, not by dead routes (the
# inline analogue of the EXPECT_FAILURE self-test named in the P1 spec).
begin_test "Clear the filter (debian:null -> full passthrough)"
req PATCH "${BASE_URL}/api/v1/repositories/${KEY}" '{"debian":null}'
if [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "clearing debian filter expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
fi

begin_test "#2460 GUARD: contrib now 200 with the filter cleared (proves the 404 was filter-driven)"
req GET "${DEB}/bookworm/contrib/binary-amd64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'DTF-PKG-MARKER=bookworm-contrib-amd64-CLEAN'; then
  pass
else
  fail "with filter cleared, contrib expected 200+marker (else the earlier 404 was a dead route), got ${REQ_STATUS}" "$(body | head -c 300)"
fi

begin_test "#2460 GUARD: arm64 now 200 with the filter cleared (proves the 404 was filter-driven)"
req GET "${DEB}/bookworm/main/binary-arm64/Packages"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'DTF-PKG-MARKER=bookworm-main-arm64-CLEAN'; then
  pass
else
  fail "with filter cleared, arm64 expected 200+marker (else the earlier 404 was a dead route), got ${REQ_STATUS}" "$(body | head -c 300)"
fi

end_suite
