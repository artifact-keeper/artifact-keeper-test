#!/usr/bin/env bash
# =============================================================================
# tiers/ingest-tenant-fairness/oracle.sh -- #2598 per-tenant fairness oracle
# =============================================================================
# run.sh has stood up filesystem/single and exported BASE_URL, ADMIN_USER,
# ADMIN_PASS, RUN_ID, COMMON_SH, JUNIT_OUTPUT_DIR, DTF_SLOT, RELEASE_GATE=1, and
# (via the manifest) MAX_CONCURRENT_INGEST_EXTRACTIONS=2 /
# MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT=1.
#
# THREAT (#2598, follow-up to #2561): the shared ingestion decode seam
# (backend/src/util/bounded_archive.rs::acquire_ingest_extraction) caps the
# NUMBER of concurrent archive decodes with a single process-wide semaphore.
# That is fair in aggregate but not per tenant -- one repository firing a burst
# of concurrent uploads can hold every global permit and 503 a different
# repository's upload. The fix adds a per-tenant (repository) sub-limit on top
# of the global ceiling at the same seam, so a noisy tenant can never take the
# whole budget.
#
# With global=2 / per-tenant=1 the fixed image lets one repository hold at most
# ONE global permit, so the second permit is always available to a neighbour
# (deterministic GREEN). A pre-#2598 image lets the noisy repository hold BOTH
# permits, starving the neighbour with a 503 (RED). See the manifest for the
# determinism caveat.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-${DTF_SLOT:-x}-$$"
REPO_A="fair-a-${SUF}"   # the noisy tenant
REPO_B="fair-b-${SUF}"   # the neighbour that must not be starved

# Tunables (defaults chosen for a strong signal without excess load).
FILLER_MIB="${FAIR_FILLER_MIB:-100}"   # under the 128 MiB decode budget
A_WORKERS="${FAIR_A_WORKERS:-8}"       # sustained concurrent uploaders on A
B_PROBES="${FAIR_B_PROBES:-8}"         # neighbour probes during saturation

WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK" 2>/dev/null || true
  [ -n "${FLAG:-}" ] && rm -f "$FLAG" 2>/dev/null
  # Never let the trap's last command status leak into the script exit code
  # (end_suite already encodes pass/fail via its own exit).
  return 0
}
trap cleanup EXIT

# Build a helm chart tgz whose entries are walked in a fixed order: an optional
# large-but-under-budget filler FIRST (so the decode inflates it -- holding the
# permit -- before it reaches Chart.yaml), then a valid Chart.yaml.
#   build_chart <out.tgz> <name> <version> <filler_mib>
build_chart() {
  local out="$1" name="$2" version="$3" filler_mib="${4:-0}"
  local d="${WORK}/${name}-${version}"
  rm -rf "$d"; mkdir -p "$d"
  cat > "$d/Chart.yaml" <<EOF
apiVersion: v2
name: ${name}
version: ${version}
description: #2598 fairness fixture
EOF
  if [ "$filler_mib" -gt 0 ]; then
    head -c "$((filler_mib * 1024 * 1024))" /dev/zero > "$d/filler.bin"
    # filler BEFORE Chart.yaml in the archive stream.
    tar -C "$WORK" -czf "$out" "${name}-${version}/filler.bin" "${name}-${version}/Chart.yaml"
  else
    tar -C "$WORK" -czf "$out" "${name}-${version}/Chart.yaml"
  fi
}

# POST a chart to a helm repo; echo the HTTP status.
helm_push() { # <repo_key> <tgz>
  curl -s -o /dev/null -w '%{http_code}' --max-time 40 \
    -X POST "${BASE_URL}/helm/$1/api/charts" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -F "chart=@$2" 2>/dev/null || echo "000"
}

begin_suite "ingest-tenant-fairness-2598"

# --- setup -------------------------------------------------------------------
auth_admin
begin_test "setup: create two hosted helm repositories (distinct tenants)"
if ! create_repo "$REPO_A" helm local; then
  fail "could not create repo A (${REPO_A})"; end_suite
fi
if ! create_repo "$REPO_B" helm local; then
  fail "could not create repo B (${REPO_B})"; end_suite
fi
pass "repos A=${REPO_A} and B=${REPO_B} created"

# --- control: legit uploads to each tenant succeed ---------------------------
build_chart "${WORK}/a-normal.tgz" "chart-a" "0.0.1" 0
build_chart "${WORK}/b-normal.tgz" "chart-b" "0.0.1" 0

begin_test "control: a normal chart upload to tenant A succeeds"
code_a="$(helm_push "$REPO_A" "${WORK}/a-normal.tgz")"
if [ "$code_a" -ge 200 ] 2>/dev/null && [ "$code_a" -lt 300 ] 2>/dev/null; then
  pass "tenant A normal upload -> ${code_a}"
else
  fail "tenant A normal upload expected 2xx, got ${code_a}"
fi

begin_test "control: a normal chart upload to tenant B succeeds"
code_b="$(helm_push "$REPO_B" "${WORK}/b-normal.tgz")"
if [ "$code_b" -ge 200 ] 2>/dev/null && [ "$code_b" -lt 300 ] 2>/dev/null; then
  pass "tenant B normal upload -> ${code_b}"
else
  fail "tenant B normal upload expected 2xx, got ${code_b}"
fi

# --- fairness: A saturated must not starve B ---------------------------------
# Build the slow-to-decode chart for A's saturating burst.
build_chart "${WORK}/a-slow.tgz" "chart-a-slow" "9.9.9" "$FILLER_MIB"

# Sustained concurrent burst against tenant A: a pool of workers each keep
# POSTing the slow chart (each request holds a decode permit while the filler
# inflates) until the flag file is removed. Reusing one chart is fine -- the
# decode (permit acquire) runs before helm's duplicate/conflict check, so the
# permit is held on every request regardless of the eventual status.
FLAG="$(mktemp)"
a_worker() { while [ -f "$FLAG" ]; do helm_push "$REPO_A" "${WORK}/a-slow.tgz" >/dev/null; done; }
for _ in $(seq 1 "$A_WORKERS"); do a_worker & done
# Let the burst ramp up and fill the global budget.
sleep 3

begin_test "fairness: tenant B is not starved while tenant A saturates the decode budget"
b_starved=0
b_served=0
last_codes=""
for i in $(seq 1 "$B_PROBES"); do
  # Unique version per probe so each is a real 201 on success (not a 409).
  build_chart "${WORK}/b-probe-${i}.tgz" "chart-b" "1.0.${i}" 0
  cb="$(helm_push "$REPO_B" "${WORK}/b-probe-${i}.tgz")"
  last_codes="${last_codes} ${cb}"
  if [ "$cb" = "503" ]; then
    b_starved=$((b_starved + 1))
  elif [ "$cb" -ge 200 ] 2>/dev/null && [ "$cb" -lt 300 ] 2>/dev/null; then
    b_served=$((b_served + 1))
  fi
  sleep 1
done

# Stop the burst and reap the workers.
rm -f "$FLAG"; FLAG=""
wait 2>/dev/null

if [ "$b_starved" -eq 0 ] && [ "$b_served" -gt 0 ]; then
  pass "tenant B served ${b_served}/${B_PROBES} probes with 0 x 503 under A saturation (codes:${last_codes})"
else
  fail "tenant B was starved by tenant A: ${b_starved} x 503 across ${B_PROBES} probes (codes:${last_codes})" \
    "A pre-#2598 image has no per-tenant sub-limit, so a burst on repo A holds every global decode permit and sheds repo B with a 503. Codes seen for B:${last_codes}"
fi

end_suite
