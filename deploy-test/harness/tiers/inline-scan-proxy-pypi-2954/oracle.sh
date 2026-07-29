#!/usr/bin/env bash
# =============================================================================
# tiers/inline-scan-proxy-pypi-2954/oracle.sh — PyPI proxy scan-and-block
# =============================================================================
# #2954 Part 2: run the leaf Grype scanner over the buffered upstream bytes on a
# PyPI proxy cache-miss (ScannerService::scan_content, synthetic Artifact, no DB
# row), persist a digest-keyed verdict (proxy_scan_results, migration 181), and
# block a vulnerable wheel fail-closed BEFORE the first byte is served.
#
# run.sh has stood up `storage.filesystem scanners.trivy` and exported BASE_URL,
# ADMIN_USER, ADMIN_PASS, RUN_ID, COMMON_SH, DTF_SLOT, DB_CONTAINER. The probe
# wheels are pulled from pypi.org (NEEDS_INTERNET).
#
# Discriminator (fail-closed):
#   Jinja2-2.10 (CVE wheel) GET -> 403 + `vulnerable` verdict row + repeat GET
#     still 403 from the verdict cache with NO second scan. Pre-#2954: 200.
#   six-1.16.0 (clean wheel) GET -> 200 X-AK-Scan: clean on both images.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "inline-scan-proxy-pypi-2954"
auth_admin
setup_workdir

REPO_KEY="dtf-pypi-scan-${RUN_ID}"
UPSTREAM="https://pypi.org"
CVE_WHEEL="Jinja2-2.10-py2.py3-none-any.whl"
CVE_PROJECT="jinja2"
CLEAN_WHEEL="six-1.16.0-py2.py3-none-any.whl"
CLEAN_PROJECT="six"

# Backend container name derives from the DB container the harness exports.
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
GRYPE_BAK=""

cleanup() {
  # Always put grype back if a discriminator test left the stub in place.
  [ -n "$GRYPE_BAK" ] && [ -f "$GRYPE_BAK" ] && \
    docker cp "$GRYPE_BAK" "${BACKEND_CONTAINER}:/usr/local/bin/grype" >/dev/null 2>&1 || true
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

# Count proxy_scan_results rows with a given verdict in the backend DB.
verdict_count() { # <verdict>
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -t -A \
    -c "SELECT count(*) FROM proxy_scan_results WHERE verdict='$1';" 2>/dev/null | tr -d '[:space:]'
}

# Render the bundled Grype CVE engine non-functional by swapping its binary for
# a real exit-1 ELF -- reproducing the documented stale-DB "exits 1 with no
# stderr" time-bomb (Dockerfile.backend). Falls back to a non-ELF garbage file
# (a spawn failure) when no C compiler is available; both make Grype's leaf scan
# return Err, which is the exact condition under test. The runtime image is
# distroless (no shell), so we mutate it with `docker cp`, not `exec sh`.
break_grype() {
  GRYPE_BAK="${WORK_DIR}/grype.orig"
  docker cp "${BACKEND_CONTAINER}:/usr/local/bin/grype" "$GRYPE_BAK" >/dev/null 2>&1 || return 1
  local stub="${WORK_DIR}/grype_stub"
  if printf 'int main(void){return 1;}\n' | cc -static -O2 -x c -o "$stub" - >/dev/null 2>&1 \
     || printf 'int main(void){return 1;}\n' | cc -O2 -x c -o "$stub" - >/dev/null 2>&1; then
    : # real exit-1 binary (matches the "runs, exits 1, no stderr" time-bomb)
  else
    printf 'not-a-real-grype-binary\n' > "$stub" # non-ELF -> spawn failure -> Err
  fi
  docker cp "$stub" "${BACKEND_CONTAINER}:/usr/local/bin/grype" >/dev/null 2>&1
}
restore_grype() {
  [ -n "$GRYPE_BAK" ] && [ -f "$GRYPE_BAK" ] && \
    docker cp "$GRYPE_BAK" "${BACKEND_CONTAINER}:/usr/local/bin/grype" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Setup: a remote PyPI repo over pypi.org, fail-closed scan-on-proxy.
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

# ---------------------------------------------------------------------------
# Discriminating assertions.
# ---------------------------------------------------------------------------
begin_test "#2954: fail-closed pull of CVE wheel ${CVE_WHEEL} is BLOCKED (403; was 200)"
r=$(pull "$CVE_PROJECT" "$CVE_WHEEL"); st="${r%%|*}"
if [ "$st" = "403" ]; then
  pass
else
  fail "expected 403 on CVE-wheel proxy pull, got ${st} (pre-#2954 streams the unscanned wheel: 200)"
fi

begin_test "#2954: a 'vulnerable' proxy_scan_results verdict row was persisted"
if [ "$(verdict_count vulnerable)" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "no vulnerable verdict row in proxy_scan_results after the CVE pull"
fi

begin_test "#2954: REPEAT pull is still 403 from the verdict cache (no upstream re-fetch)"
r=$(pull "$CVE_PROJECT" "$CVE_WHEEL"); st="${r%%|*}"
if [ "$st" = "403" ]; then
  pass
else
  fail "repeat pull of a known-vulnerable digest must stay 403, got ${st}"
fi

begin_test "#2954: clean wheel ${CLEAN_WHEEL} serves 200 with X-AK-Scan: clean"
r=$(pull "$CLEAN_PROJECT" "$CLEAN_WHEEL"); st="${r%%|*}"; scan="${r#*|}"
if [ "$st" = "200" ] && [ "$scan" = "clean" ]; then
  pass
else
  fail "clean wheel must serve 200 + X-AK-Scan: clean, got status=${st} scan='${scan}'"
fi

# ---------------------------------------------------------------------------
# CVE-ENGINE-ERROR discriminator (Finding 1 of the ship-blocker).
#
# The fail-closed hole: when the CVE engine (Grype) hard-errors / times out, the
# always-on DependencyScanner still returns Ok(empty) on a binary wheel, so the
# pre-fix `scan_content` aggregated to `clean` and served the UNSCANNED wheel
# 200. Render Grype non-functional and pull a FRESH CVE wheel (one not pulled
# above, so it has no cached verdict) under the fail-closed repo:
#   Fixed:     scan_content -> inconclusive -> 423, and NO `clean` verdict row
#              is persisted for the digest; restoring Grype + re-pull re-scans
#              and BLOCKS (403).
#   Pre-#2954: served 200 (unscanned) AND persisted a poisoned `clean` row, so
#              even after Grype is restored the cached-clean fast path stays 200.
#
# PyYAML-5.3.1 (GHSA-8q59-q68h-6hv4, Critical) is a binary wheel (a zip; non
# UTF-8, so DependencyScanner returns Ok(empty) -- the masking condition) that
# Grype flags in dir-mode from its `.dist-info/METADATA`.
# ---------------------------------------------------------------------------
ERR_WHEEL="PyYAML-5.3.1-cp38-cp38-win_amd64.whl"
ERR_PROJECT="pyyaml"

begin_test "#2954 setup: render the Grype CVE engine non-functional"
if break_grype; then pass; else fail "could not stub grype in ${BACKEND_CONTAINER}"; fi

CLEAN_BEFORE=$(verdict_count clean); [ -n "$CLEAN_BEFORE" ] || CLEAN_BEFORE=0

begin_test "#2954 DISCRIMINATOR: fail-closed pull with Grype ERRORING is 423, not 200-clean"
r=$(pull "$ERR_PROJECT" "$ERR_WHEEL"); st="${r%%|*}"
if [ "$st" = "423" ]; then
  pass
else
  fail "expected 423 when the CVE engine errors under fail-closed, got ${st} \
(pre-#2954 serves the unscanned wheel 200-clean because DependencyScanner masks the Grype error)"
fi

begin_test "#2954: NO 'clean' verdict was persisted from the Grype-errored scan (no cache poisoning)"
CLEAN_AFTER=$(verdict_count clean); [ -n "$CLEAN_AFTER" ] || CLEAN_AFTER=0
if [ "$CLEAN_AFTER" -le "$CLEAN_BEFORE" ] 2>/dev/null; then
  pass
else
  fail "a clean proxy_scan_results row was persisted from a Grype-errored scan (poisoned cache): before=${CLEAN_BEFORE} after=${CLEAN_AFTER}"
fi

begin_test "#2954 restore: Grype functional again"
if restore_grype; then pass; else fail "could not restore grype"; fi

begin_test "#2954: after restoring Grype, re-pull RE-SCANS and BLOCKS (403; pre-fix stays 200 from the poisoned clean row)"
r=$(pull "$ERR_PROJECT" "$ERR_WHEEL"); st="${r%%|*}"
if [ "$st" = "403" ]; then
  pass
else
  fail "expected 403 after restoring Grype (fresh scan flags the CVE wheel; a pre-fix poisoned clean row would keep it 200), got ${st}"
fi

end_suite
