#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-downloadcount/oracle.sh — proxy first-serve download-count oracle
#   PKT-F (P6): #2537 (proxy-cache first-serve download count)
# =============================================================================
# run.sh has stood up the `filesystem + upstreams=raworigin` profile-set (a tiny
# mock nginx origin `raw-origin` on the slot's 172.16/12 net returning a marker
# body for ANY path) and exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, DTF_SLOT, DB_CONTAINER, JUNIT_OUTPUT_DIR. We source common.sh
# for the assertion + JUnit harness.
#
# FEATURE (#2537): the FIRST cold proxy serve of a freshly-cached object must be
# counted. Pre-fix, the authoritative `proxy_cache_artifacts` catalog row was
# written only by the streaming tee AFTER the client drained the body, so the
# serve recorder found no catalog row and the first serve recorded +0 (each
# object undercounted by 1). The fix (`proxy_catalog::record_proxy_download`)
# ensures the catalog row for `(repo, path)` in the SAME statement as the stats
# insert, so the first serve writes exactly one `proxy_download_statistics` row.
#
# OBSERVABILITY (OQ#4, verified against candidate-a4d7f9d1): the proxy first-
# serve count has NO HTTP surface. admin/downloads, analytics/downloads/trend,
# and artifacts/{id}/stats all read the SEPARATE `download_statistics` table,
# which the remote pull-through serve path does not write. The only reader of
# `proxy_download_statistics` — `proxy_catalog::download_count_by_repo` — is not
# wired to any route. So this oracle asserts the count at the DB surface (the
# established DTF `docker exec $DB_CONTAINER psql` idiom), running exactly the
# `download_count_by_repo` query. This is a real deployment assertion: a real
# cold proxy serve through the real backend + the DB row it (should) write.
#
# DISCRIMINATING GATE:
#   POS  baseline (fresh repo) proxy count == 0.
#   POS  one cold GET /rpm/<key>/packages/<obj> -> 200 + origin marker body.
#   #2537 the proxy download count is EXACTLY 1 after that one serve (RED: 0 on a
#        pre-#2537 backend — the first serve undercounted). The assertion is ==1,
#        not >=1 (the audit's exact note: undercounted by exactly 1).
#   MONO a second GET -> count == 2 (counting continues; no double/under count).
#   HEAD a HEAD of the object does NOT increment (is_head short-circuit).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-downloadcount-2537"
auth_admin
setup_workdir

# Format = rpm (a REMOTE repo whose download path records proxy serves). NOTE:
# the generic `/general/` path (repositories::download_artifact) streams the
# proxy body but never calls record_proxy_download, so proxy downloads through
# GENERIC remotes are not counted — see MATRIX-ROW.md. The recording formats are
# rpm/pypi/cran/rubygems/hex/ansible/puppet/huggingface (via
# try_remote_or_virtual_download / direct); rpm is the simplest to drive against
# a raw origin (GET /rpm/<key>/packages/<path> -> upstream packages/<path>).
KEY="dtf-dlcount-${RUN_ID}"
UPSTREAM="http://raw-origin"
# A fresh object path so the serve is genuinely the first. (The stack is torn
# down `-v` each run, so the cache is empty regardless, but keep it RUN_ID-scoped.)
OBJ="firstserve-${RUN_ID}.rpm"
GEN="${BASE_URL}/rpm/${KEY}/packages"

cleanup_repo() { api_delete "/api/v1/repositories/${KEY}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup_repo"

# psql helper (DB-surface read; same idiom as storage-accounting/sso/upgrade).
psql_ak() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}

# The exact `proxy_catalog::download_count_by_repo` query, scoped to this repo.
proxy_count() {
  psql_ak "SELECT COUNT(*) FROM proxy_download_statistics pds \
           JOIN proxy_cache_artifacts pca ON pca.id = pds.proxy_cache_id \
           JOIN repositories r ON r.id = pca.repository_id \
           WHERE r.key = '${KEY}'"
}

# Poll the count until it reaches the expected value (tolerate tiny commit lag),
# then echo the final observed value. Bounded ~15s.
count_settles_to() {
  local want="$1" tries=15 got=""
  while [ "$tries" -gt 0 ]; do
    got="$(proxy_count)"
    [ "$got" = "$want" ] && { echo "$got"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  echo "$got"
  return 1
}

# req METHOD PATH -> sets REQ_STATUS + writes body to REQ_BODY_FILE.
# HEAD uses curl --head so curl does not block waiting for a body that a HEAD
# response never sends (a bare `-X HEAD` hangs until --max-time).
REQ_STATUS=""; REQ_BODY_FILE="${WORK_DIR}/req-body"
req() {
  local method="$1" url="$2"
  if [ "$method" = "HEAD" ]; then
    REQ_STATUS=$(curl -s -o "$REQ_BODY_FILE" -w '%{http_code}' --max-time 40 \
      --head -H "$(auth_header)" "$url" 2>/dev/null) || REQ_STATUS="000"
  else
    REQ_STATUS=$(curl -s -o "$REQ_BODY_FILE" -w '%{http_code}' --max-time 40 \
      -X "$method" -H "$(auth_header)" "$url" 2>/dev/null) || REQ_STATUS="000"
  fi
}
body() { cat "$REQ_BODY_FILE" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Setup: create the rpm REMOTE (pull-through) repo against the mock origin.
# ---------------------------------------------------------------------------
begin_test "Create rpm remote repo ${KEY} -> ${UPSTREAM} (allowlisted 172.16/12)"
if create_repo "$KEY" "rpm" "remote" "$UPSTREAM"; then
  pass
else
  fail "could not create rpm remote repo (see create_repo stderr); the whole tier is untestable without it"
  end_suite
fi

begin_test "Baseline: a fresh remote repo has ZERO proxy download rows"
base="$(proxy_count)"
if [ "$base" = "0" ]; then
  pass
else
  fail "expected baseline proxy_download_statistics count 0 for a fresh repo, got '${base}' (DB reachable? query wrong?)"
fi

# ---------------------------------------------------------------------------
# The load-bearing discriminator: ONE cold GET, then count MUST be exactly 1.
# ---------------------------------------------------------------------------
begin_test "One cold proxy GET /rpm/${KEY}/packages/${OBJ} -> 200 + origin marker body"
req GET "${GEN}/${OBJ}"
if [ "$REQ_STATUS" = "200" ] && body | grep -q 'DTF-PROXY-DLCOUNT-OK'; then
  pass
else
  fail "cold proxy GET expected 200 + origin marker, got ${REQ_STATUS}" "$(body | head -c 300)"
fi

begin_test "#2537: FIRST cold serve is counted -> proxy download count == 1 (RED: 0)"
c1="$(count_settles_to 1)"
if [ "$c1" = "1" ]; then
  pass
elif [ "$c1" = "0" ]; then
  fail "#2537 RED: first cold serve recorded 0 rows in proxy_download_statistics (first-serve undercounted by 1 — the catalog row was not ensured before the tee committed)"
else
  fail "expected proxy download count == 1 after one cold serve, got '${c1}'"
fi

begin_test "MONO: a second GET -> proxy download count == 2 (counting continues, no double/under count)"
req GET "${GEN}/${OBJ}"
if [ "$REQ_STATUS" != "200" ]; then
  fail "second proxy GET expected 200, got ${REQ_STATUS}" "$(body | head -c 200)"
else
  c2="$(count_settles_to 2)"
  if [ "$c2" = "2" ]; then
    pass
  else
    fail "expected proxy download count == 2 after a second serve, got '${c2}' (first-serve/repeat counting inconsistent)"
  fi
fi

begin_test "HEAD guard: a HEAD of the object does NOT increment the count (is_head short-circuit)"
req HEAD "${GEN}/${OBJ}"
# HEAD may 200 or 405 depending on route wiring; what matters is that it records
# no serve. Give any async write a moment to (not) land, then assert unchanged.
sleep 3
ch="$(proxy_count)"
if [ "$ch" = "2" ]; then
  pass
else
  fail "HEAD must not increment the proxy download count (is_head guard); count moved from 2 to '${ch}'"
fi

end_suite
