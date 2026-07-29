#!/usr/bin/env bash
# =============================================================================
# tiers/scan-verdict-dbversion/oracle.sh - stale CVE-DB verdict reuse (#2976)
# =============================================================================
# run.sh has stood up `storage.filesystem scanners.trivy` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, ADMIN_USER, ADMIN_PASS,
# RUN_ID, COMMON_SH, DTF_SLOT, DB_CONTAINER, RELEASE_GATE=1. Probe wheels
# resolve against pypi.org (NEEDS_INTERNET).
#
# The defect (#2976): the PyPI proxy serve path called `verdict_is_fresh` with
# `current_version=None`, so a cached `clean` verdict was reused on TTL alone -
# a CVE-DB bump that newly flags the bytes did NOT invalidate the verdict, and
# the proxy kept serving `200 X-AK-Scan: clean` for up to 30 days. The fix
# threads the LIVE CVE-engine version (the same `grype-X.Y.Z` provenance string
# stored on the verdict) into the freshness check: stored != live -> stale ->
# re-scan (fail-closed: 403 on vulnerable / 423 on inconclusive).
#
# Injected version delta: a true live CVE-DB bump is impractical here, so the
# tier seeds the STORED side with a sentinel (`grype-0.0.1-dtf`) that can never
# equal the live probe - semantically identical to the live version having
# advanced past the stored one (the invalidation is provenance-mismatch).
#
# Discriminating gates, ALL must hold (RELEASE_GATE=1):
#   (A) STALE-VERSION  known-CVE wheel (Jinja2-2.10) seeded `clean` at the
#       sentinel version -> GET is 403 (re-scanned against the live engine,
#       which flags it), and the DB row is upserted to `vulnerable` at the
#       LIVE version. Baseline: 200 X-AK-Scan: clean from the stale row (RED).
#   (B) SAME-VERSION   known-CVE wheel (PyYAML-5.3.1) seeded `clean` AT the
#       live version -> GET is 200 X-AK-Scan: clean and the row is untouched
#       (matching provenance is honoured: no needless re-scan; #2976 is a
#       targeted invalidation, not a cache-off hammer). Passes on BOTH images.
#   (C) PROBE-UNKNOWN  with grype stubbed and the backend restarted (so the
#       version probe returns None and the 1h in-process version cache is
#       dropped), a cached `clean` digest must NOT be served under fail_closed:
#       423/403, never 200 X-AK-Scan: clean. A FRESH digest 423s in the same
#       state, proving the node is fail-closed while it serves the cached one.
#       Guards the fail-open hole in the first cut of the fix: `verdict_is_fresh`
#       treats an unknown version as "not provably stale", and that fast path
#       runs BEFORE the inline scan, so an unprovable clean verdict bypassed the
#       entire gate during exactly the engine-upgrade window this issue is about.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scan-verdict-dbversion"
auth_admin
setup_workdir

REPO_KEY="dtf-scanver-${RUN_ID}"
UPSTREAM="https://pypi.org"
STALE_SENTINEL="grype-0.0.1-dtf"

# (A) the stale-clean discriminator wheel: Grype flags CVE-2019-10906 et al.
CVE_WHEEL="Jinja2-2.10-py2.py3-none-any.whl"
CVE_PROJECT="jinja2"
# (B) the same-version control wheel: also CVE-bearing (GHSA-8q59-q68h-6hv4),
# so a 200 here proves the cache was HONOURED (a re-scan would have 403'd).
CTRL_WHEEL="PyYAML-5.3.1-cp38-cp38-win_amd64.whl"
CTRL_PROJECT="pyyaml"

# (C) the probe-unknown control wheel: never seeded, so its pull is a FRESH
# digest that proves the node is provably fail-closed at that moment.
FRESH_WHEEL="six-1.16.0-py2.py3-none-any.whl"
FRESH_PROJECT="six"

BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
DIGEST_CVE=""
DIGEST_CTRL=""
GRYPE_BAK=""

cleanup() {
  # Put grype back if leg (C) left the stub in place.
  [ -n "$GRYPE_BAK" ] && [ -f "$GRYPE_BAK" ] && \
    docker cp "$GRYPE_BAK" "${BACKEND_CONTAINER}:/usr/local/bin/grype" >/dev/null 2>&1 || true
  for d in "$DIGEST_CVE" "$DIGEST_CTRL"; do
    [ -n "$d" ] && docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
      "DELETE FROM proxy_scan_results WHERE checksum_sha256='${d}';" >/dev/null 2>&1 || true
  done
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

# GET a proxy file; echo "<status>|<x-ak-scan header>".
pull() { # <project> <wheel>
  local hdr="${WORK_DIR}/h.$$" st scan
  st=$(curl -s -D "$hdr" -o /dev/null -w '%{http_code}' --max-time 90 \
    "${BASE_URL}/pypi/${REPO_KEY}/simple/$1/$2" 2>/dev/null) || st="000"
  scan=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1)
  rm -f "$hdr"; echo "${st}|${scan}"
}

# The wheel's sha256 straight from the PEP 503 index href fragment
# (#sha256=<hex>): the SAME immutable bytes the proxy will fetch and digest.
# The filename's dots are regex-escaped: an unescaped `5.3.1` also matches
# `5.3b1`, silently resolving a SIBLING wheel's digest (found the hard way).
digest_from_index() { # <project> <wheel>
  local esc
  esc="$(printf '%s' "$2" | sed 's/[.[\*^$]/\\&/g')"
  curl -sL --max-time 60 "${UPSTREAM}/simple/$1/" 2>/dev/null \
    | grep -o "href=\"[^\"]*/${esc}#sha256=[0-9a-f]\{64\}" \
    | grep -o '[0-9a-f]\{64\}$' | head -1
}

# "verdict|scanner_version" for a digest's grype row ("" when absent).
row_state() { # <digest>
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT verdict || '|' || COALESCE(scanner_version,'<null>')
       FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype';" \
    2>/dev/null | tr -d '[:space:]'
}

# Render the bundled Grype engine non-functional (non-ELF file => both the
# `--version` probe AND the leaf scan fail to spawn), then RESTART the backend.
# The restart is load-bearing: `Scanner::version()` is VersionCache-backed with
# a 1h hit TTL, so an in-process cached Some() from the earlier legs would mask
# the probe failure. A restart drops that cache, which is exactly the real
# scenario (pod restarts onto a node where the engine is missing/upgrading).
break_grype_and_restart() {
  GRYPE_BAK="${WORK_DIR}/grype.orig"
  docker cp "${BACKEND_CONTAINER}:/usr/local/bin/grype" "$GRYPE_BAK" >/dev/null 2>&1 || return 1
  printf 'not-a-real-grype-binary\n' > "${WORK_DIR}/grype_stub"
  docker cp "${WORK_DIR}/grype_stub" "${BACKEND_CONTAINER}:/usr/local/bin/grype" >/dev/null 2>&1 || return 1
  docker restart "$BACKEND_CONTAINER" >/dev/null 2>&1 || return 1
  local i
  for i in $(seq 1 60); do
    curl -sf --max-time 5 "${BASE_URL}/health" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

# Seed / overwrite a clean verdict for a digest at a given scanner_version.
seed_clean_row() { # <digest> <scanner_version>
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "INSERT INTO proxy_scan_results (checksum_sha256, scan_type, verdict, scanner_version)
       VALUES ('$1','grype','clean','$2')
     ON CONFLICT (checksum_sha256, scan_type) DO UPDATE
       SET verdict='clean', findings_count=0, critical_count=0, high_count=0,
           medium_count=0, low_count=0, max_severity=NULL,
           scanner_version='$2', scanned_at=now();" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Setup: remote PyPI repo over pypi.org, fail-closed scan-on-proxy, live
# Grype version probe, wheel digests.
# ---------------------------------------------------------------------------
begin_test "Setup: create remote PyPI repo over ${UPSTREAM}"
if create_repo "$REPO_KEY" "pypi" "remote" "$UPSTREAM"; then pass; else fail "create remote pypi repo failed"; end_suite; fi

begin_test "Setup: enable scan + scan_on_proxy + fail_closed"
resp=$(api_put "/api/v1/repositories/${REPO_KEY}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true}' 2>/dev/null)
if [ "$(printf '%s' "$resp" | jq -r '.proxy_scan_action' 2>/dev/null)" = "fail_closed" ]; then
  pass
else
  fail "security config did not persist fail_closed: ${resp:0:200}"
fi

begin_test "Setup: probe the LIVE bundled Grype version (the 'current' side of verdict_is_fresh)"
RAW_VER="$(docker exec "$BACKEND_CONTAINER" /usr/local/bin/grype --version 2>/dev/null | head -1 | tr -d '\r')"
TOK1="$(printf '%s' "$RAW_VER" | awk '{print $1}')"
case "$TOK1" in
  grype|Grype|Version:) LIVE_NUM="$(printf '%s' "$RAW_VER" | awk '{print $2}')" ;;
  *)                    LIVE_NUM="$TOK1" ;;
esac
LIVE_VER="grype-${LIVE_NUM}"
if [ -n "$LIVE_NUM" ] && [ "$LIVE_VER" != "$STALE_SENTINEL" ]; then
  pass
else
  fail "could not probe the live grype version in ${BACKEND_CONTAINER} (raw='${RAW_VER}')"
  end_suite
fi

begin_test "Setup: resolve wheel digests from the ${UPSTREAM} index (#sha256 fragments)"
DIGEST_CVE="$(digest_from_index "$CVE_PROJECT" "$CVE_WHEEL")"
DIGEST_CTRL="$(digest_from_index "$CTRL_PROJECT" "$CTRL_WHEEL")"
if [ -n "$DIGEST_CVE" ] && [ -n "$DIGEST_CTRL" ] && [ "$DIGEST_CVE" != "$DIGEST_CTRL" ]; then
  pass
else
  fail "could not resolve wheel digests (cve='${DIGEST_CVE}' ctrl='${DIGEST_CTRL}')"
  end_suite
fi

# ---------------------------------------------------------------------------
# (A) STALE-VERSION - the load-bearing #2976 gate. A `clean` verdict recorded
#     by an older scanner/CVE-DB (sentinel provenance) must NOT be served once
#     the live engine differs: the pull re-scans and blocks the CVE wheel.
# ---------------------------------------------------------------------------
begin_test "Seed: poisoned stale-clean verdict for ${CVE_WHEEL} at ${STALE_SENTINEL}"
if seed_clean_row "$DIGEST_CVE" "$STALE_SENTINEL" && [ "$(row_state "$DIGEST_CVE")" = "clean|${STALE_SENTINEL}" ]; then
  pass
else
  fail "could not seed the stale-clean row (state='$(row_state "$DIGEST_CVE")')"
  end_suite
fi

begin_test "#2976 STALE-VERSION: pull of ${CVE_WHEEL} re-scans and BLOCKS (403; was 200 stale-clean)"
r=$(pull "$CVE_PROJECT" "$CVE_WHEEL"); st="${r%%|*}"; scan="${r#*|}"
if [ "$st" = "403" ]; then
  pass
else
  fail "STALE-CLEAN SERVED: clean verdict at ${STALE_SENTINEL} (live=${LIVE_VER}) was reused -> status=${st} X-AK-Scan='${scan}', expected 403. current_version is not being threaded into verdict_is_fresh (#2976)." \
       "status=${st} scan='${scan}' stored=${STALE_SENTINEL} live=${LIVE_VER}"
fi

begin_test "#2976 STALE-VERSION(DB): digest row upserted to 'vulnerable' at the LIVE version"
STATE="$(row_state "$DIGEST_CVE")"
if [ "$STATE" = "vulnerable|${LIVE_VER}" ]; then
  pass
else
  fail "expected the re-scan to record vulnerable|${LIVE_VER}, got '${STATE}' (a stale row left as clean|${STALE_SENTINEL} means NO re-scan happened)" \
       "row='${STATE}' expected='vulnerable|${LIVE_VER}'"
fi

# ---------------------------------------------------------------------------
# (B) SAME-VERSION control - matching provenance must keep using the cache.
#     The control wheel is ALSO CVE-bearing, so a 200 proves no re-scan ran.
# ---------------------------------------------------------------------------
begin_test "Seed: clean verdict for ${CTRL_WHEEL} AT the live version ${LIVE_VER}"
if seed_clean_row "$DIGEST_CTRL" "$LIVE_VER" && [ "$(row_state "$DIGEST_CTRL")" = "clean|${LIVE_VER}" ]; then
  pass
else
  fail "could not seed the same-version clean row (state='$(row_state "$DIGEST_CTRL")')"
  end_suite
fi

begin_test "#2976 SAME-VERSION: pull of ${CTRL_WHEEL} serves 200 X-AK-Scan: clean from cache (no needless re-scan)"
r=$(pull "$CTRL_PROJECT" "$CTRL_WHEEL"); st="${r%%|*}"; scan="${r#*|}"
if [ "$st" = "200" ] && [ "$scan" = "clean" ]; then
  pass
else
  fail "matching-provenance clean verdict must serve from cache, got status=${st} X-AK-Scan='${scan}' (a 403 means the fix re-scans even when versions match: cache-off hammer, perf regression)" \
       "status=${st} scan='${scan}' stored=live=${LIVE_VER}"
fi

begin_test "#2976 SAME-VERSION(DB): digest row untouched (still clean at ${LIVE_VER})"
STATE="$(row_state "$DIGEST_CTRL")"
if [ "$STATE" = "clean|${LIVE_VER}" ]; then
  pass
else
  fail "same-version cached row must not be rewritten, got '${STATE}'" \
       "row='${STATE}' expected='clean|${LIVE_VER}'"
fi

# ---------------------------------------------------------------------------
# (C) PROBE-UNKNOWN - the fail-open hole in the first cut of the #2976 fix.
#
# Threading the live version in is not enough on its own: `verdict_is_fresh`
# treats an UNKNOWN version (either side) as "not provably stale" and returns
# fresh. That fast path runs BEFORE the inline scan, so on a fail_closed repo a
# cached `clean` verdict short-circuited the entire gate whenever the version
# probe failed - engine mid-upgrade (a >=60s cache-miss window, i.e. exactly
# during the CVE-DB advance this issue is about), engine absent (permanent), or
# the probe past its 5s timeout under load.
#
# Reproduced by rendering grype non-functional and restarting the backend (the
# restart drops the 1h in-process version cache). The node is then provably
# fail-closed: a FRESH digest 423s. It must not serve a cached-clean digest.
#   Fixed:   423 (verdict not reusable -> re-scan -> inconclusive -> locked).
#   Pre-fix: 200 X-AK-Scan: clean, vulnerable bytes served (RED).
# ---------------------------------------------------------------------------
begin_test "Seed: re-seed ${CVE_WHEEL} as clean at ${STALE_SENTINEL} for the probe-unknown leg"
if seed_clean_row "$DIGEST_CVE" "$STALE_SENTINEL" && [ "$(row_state "$DIGEST_CVE")" = "clean|${STALE_SENTINEL}" ]; then
  pass
else
  fail "could not re-seed the clean row (state='$(row_state "$DIGEST_CVE")')"
  end_suite
fi

begin_test "Setup: render the Grype engine non-functional and restart the backend (probe -> None)"
if break_grype_and_restart; then pass; else fail "could not stub grype / backend did not come back healthy"; end_suite; fi

begin_test "#2976 PROBE-UNKNOWN(control): a FRESH digest (${FRESH_WHEEL}) is 423 - the node IS fail-closed"
r=$(pull "$FRESH_PROJECT" "$FRESH_WHEEL"); st="${r%%|*}"
if [ "$st" = "423" ]; then
  pass
else
  fail "with no working CVE engine a fresh fail-closed pull must be 423, got ${st}; the probe-unknown discriminator below is only meaningful against a fail-closed node" \
       "status=${st} wheel=${FRESH_WHEEL}"
fi

begin_test "#2976 PROBE-UNKNOWN: cached clean + unknown live version must NOT be served under fail_closed"
r=$(pull "$CVE_PROJECT" "$CVE_WHEEL"); st="${r%%|*}"; scan="${r#*|}"
if [ "$st" = "423" ] || [ "$st" = "403" ]; then
  pass
else
  fail "STALE-CLEAN SERVED ON UNKNOWN PROBE: with the CVE engine down (version probe -> None) a cached clean verdict short-circuited the fail-closed gate -> status=${st} X-AK-Scan='${scan}', expected 423 (re-scan inconclusive) or 403. The same node 423s a FRESH digest, so this serves vulnerable bytes that nothing on the node can vouch for." \
       "status=${st} scan='${scan}' stored=clean|${STALE_SENTINEL} live=<probe failed>"
fi

begin_test "#2976 PROBE-UNKNOWN(DB): no 'clean' verdict was (re)recorded from the inconclusive re-scan"
STATE="$(row_state "$DIGEST_CVE")"
if [ "$STATE" = "clean|${STALE_SENTINEL}" ]; then
  pass
else
  fail "an inconclusive re-scan must not persist a verdict; row is now '${STATE}'" \
       "row='${STATE}' expected='clean|${STALE_SENTINEL}' (untouched)"
fi

end_suite
