#!/usr/bin/env bash
# =============================================================================
# tiers/storage-accounting/oracle.sh — deduplicated storage accounting (#2056)
# =============================================================================
# Discriminating e2e for GET /api/v1/repositories/{key}/storage. The feature
# reports the DEDUP-AWARE physical footprint: a single physical object backing a
# digest referenced by two repositories is counted ONCE in the instance total
# and surfaces as shared_bytes > 0 on each repo — NOT as a naive sum of every
# repo's uploads.
#
# THE LOAD-BEARING DISCRIMINATOR (dedup-aware vs naive double-count):
#   Push the SAME OCI layer blob X (size Sx) to two repos A and B on a shared
#   object store, and a DISTINCT blob Y (size Sy) to a third repo C.
#     * dedup-aware (candidate / #2056):
#         shared_bytes(A) == Sx,  shared_bytes(B) == Sx,  shared_bytes(C) == 0
#         instance_unique_bytes == Sx + Sy      (X counted once)
#     * naive double-count (pre-#2056):
#         shared_bytes == 0 everywhere
#         instance_unique_bytes == 2*Sx + Sy    (X counted twice)
#   Because naive_sum == physical(A)+physical(B)+physical(C) == 2*Sx + Sy, the
#   oracle asserts  instance_unique_bytes == naive_sum - Sx  (i.e. exactly one
#   copy of the shared blob was saved). A naive backend fails this by Sx.
#
# Why OCI (not Maven): identical Maven coordinates across repos share a flat key
# but the #2584 write guard REFUSES the cross-repo overwrite on cloud, so a
# shared Maven dedup key cannot be created. OCI blobs are digest-addressed and
# stored per (repository_id, digest) in oci_blobs; the same layer pushed to two
# repos yields two rows sharing the digest — exactly the cross-repo dedup the
# feature must account for. (migration 162 adds idx_oci_blobs_digest for this.)
#
# Why S3 (not filesystem): on filesystem the backend forces DedupScope::PerRepo
# so shared_bytes == 0 by construction and cross-repo dedup cannot manifest. The
# manifest therefore pins storage.s3. The SAME oracle branches on the reported
# dedup_scope, so an integrator can add a filesystem CONTRACT leg by dropping a
# sibling manifest with PROFILES="storage.filesystem" (see MATRIX-ROW.md).
#
# RED-DEMO MODE (executable proof the assertion discriminates, no pre-fix image
# needed): run with NAIVE_ORACLE=1 to assert the PRE-#2056 naive expectations
# (instance_unique == naive_sum, shared_bytes == 0). Against the fixed candidate
# that FAILS (non-zero) — proving the numbers actually gate the feature.
#
# run.sh has already: stood up storage.s3, exported BASE_URL, DB_CONTAINER,
# ADMIN_PASS, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, DTF_SLOT + the slot port block,
# BACKEND_IMAGE, DTF_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"
: "${DTF_SLOT:?}"; : "${ADMIN_PASS:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

NAIVE="${NAIVE_ORACLE:-0}"          # 1 = assert pre-#2056 naive expectations (red demo)
DESIRED_CRON="${STORAGE_STATS_SCHEDULE:-*/10 * * * * *}"
SUF="${RUN_ID##*-}-$RANDOM"
RA="oci-dedup-a-$SUF"               # holds shared blob X
RB="oci-dedup-b-$SUF"               # holds shared blob X (same digest)
RC="oci-dedup-c-$SUF"               # holds unique blob Y (negative guard)
SX=262144                           # 256 KiB shared layer
SY=131072                           # 128 KiB unique layer
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# 0. Ensure a FAST stats cron is live on the backend.
#
# compose.base.yml does not reference STORAGE_STATS_SCHEDULE and run.sh only
# passes RATE_LIMIT_ENABLED through, so a stock `run.sh storage-accounting`
# brings the backend up on the 4-hourly default. To stay standalone-testable
# (per PKT-D: "prefer a compose override in scope you own"), the oracle detects
# whether the fast cron is already on the container and, if not, recreates ONLY
# the backend with an in-scope override that adds it. If an integrator later
# wires STORAGE_STATS_SCHEDULE through run.sh+compose, this becomes a no-op.
# ---------------------------------------------------------------------------
ensure_fast_stats_cron() {
  local bc="ak-dtf${DTF_SLOT}-backend"
  local cur
  cur="$(docker inspect "$bc" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
          | sed -n 's/^STORAGE_STATS_SCHEDULE=//p' | head -n1)"
  if [ -n "$cur" ]; then
    echo ">> backend already has STORAGE_STATS_SCHEDULE='$cur' (integrator-wired); no recreate"
    return 0
  fi
  echo ">> injecting STORAGE_STATS_SCHEDULE='$DESIRED_CRON' via in-scope compose override + backend recreate"
  local ov="${WORK}/compose.stats-override.yml"
  cat > "$ov" <<YAML
services:
  backend:
    environment:
      STORAGE_STATS_SCHEDULE: "${DESIRED_CRON}"
YAML
  # Recreate ONLY the backend (--no-deps) with base + storage.s3 + override.
  # All interpolation vars (DTF_SLOT, *_PORT, BACKEND_IMAGE, STORAGE_BACKEND,
  # RATE_LIMIT_ENABLED) are already exported by run.sh.
  if docker compose -p "ak-dtf${DTF_SLOT}" \
       -f "${DTF_DIR}/compose.base.yml" \
       -f "${DTF_DIR}/profiles/storage.s3.yml" \
       -f "$ov" \
       up -d --no-deps --force-recreate --wait backend; then
    echo ">> backend recreated with fast stats cron"
  else
    echo "!! backend recreate failed; continuing (stats may never materialize)" >&2
  fi
}

# ---------------------------------------------------------------------------
# OCI helpers (monolithic blob push via curl + Basic auth; no docker daemon).
# A committed blob PUT inserts an oci_blobs row (pending_delete NULL); the stats
# union counts oci_blobs directly, so a blob-only push is sufficient and keeps
# exactly one dedup row per repo (clean, exact numbers).
# ---------------------------------------------------------------------------
oci_push_blob() {   # <repo> <file> <digest>  -> echoes final HTTP status
  local repo="$1" file="$2" dg="$3" loc url sep
  loc="$(curl -s -u "admin:${ADMIN_PASS}" -o /dev/null -D - -X POST \
           "${BASE_URL}/v2/${repo}/blobs/uploads/" 2>/dev/null \
         | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | head -n1)"
  [ -z "$loc" ] && { echo "000"; return 1; }
  case "$loc" in
    http*) url="$loc" ;;
    /*)    url="${BASE_URL}${loc}" ;;
    *)     url="${BASE_URL}/${loc}" ;;
  esac
  sep='?'; [[ "$url" == *\?* ]] && sep='&'
  curl -s -u "admin:${ADMIN_PASS}" -o /dev/null -w '%{http_code}' -X PUT \
    "${url}${sep}digest=${dg}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${file}"
}

digest_of() { echo "sha256:$(sha256sum "$1" | awk '{print $1}')"; }

# Admin GET .../{key}/storage -> raw JSON.
storage_json() {  # <repo>
  curl -s -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/$1/storage"
}
jnum() { jq -r "$1 // \"null\"" 2>/dev/null; }   # numeric/string field or "null"

# ===========================================================================
ensure_fast_stats_cron
begin_suite "storage-accounting-dedup-s3"

auth_admin   # sets ADMIN_TOKEN (admin sees the instance-scope dedup figures)

# --- 1. Create three docker (OCI) repos on the shared object store -----------
begin_test "setup: create three OCI repos on shared S3 storage"
setup_ok=1
for k in "$RA" "$RB" "$RC"; do
  create_repo "$k" docker local || setup_ok=0
done
if [ "$setup_ok" = "1" ]; then pass; else
  fail "repo creation failed (see stderr)"; end_suite
fi

# --- 2. Push shared blob X to A and B, unique blob Y to C --------------------
begin_test "setup: push shared OCI layer X to A+B, unique layer Y to C"
head -c "$SX" /dev/urandom > "${WORK}/blobX"
head -c "$SY" /dev/urandom > "${WORK}/blobY"
DGX="$(digest_of "${WORK}/blobX")"
DGY="$(digest_of "${WORK}/blobY")"
sA="$(oci_push_blob "$RA" "${WORK}/blobX" "$DGX")"
sB="$(oci_push_blob "$RB" "${WORK}/blobX" "$DGX")"
sC="$(oci_push_blob "$RC" "${WORK}/blobY" "$DGY")"
echo "   pushX->A=$sA  pushX->B=$sB  pushY->C=$sC  (expect 201)  DGX=$DGX"
if [ "$sA" = "201" ] && [ "$sB" = "201" ] && [ "$sC" = "201" ]; then
  pass
else
  # DB context to triage a push failure.
  dbg="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT r.key, count(b.*) FROM repositories r LEFT JOIN oci_blobs b ON b.repository_id=r.id WHERE r.key LIKE 'oci-dedup-%-$SUF' GROUP BY r.key;" 2>&1)"
  fail "OCI blob push did not return 201 (A=$sA B=$sB C=$sC)" "$dbg"
  end_suite
fi

# Sanity: confirm the shared digest lives in exactly two repos at the DB layer
# (this is what makes it 'shared' under instance scope).
begin_test "sanity: shared digest present in exactly 2 repos (oci_blobs)"
rcnt="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT count(DISTINCT repository_id) FROM oci_blobs WHERE digest='$DGX';" 2>/dev/null | tr -d '[:space:]')"
echo "   distinct repos referencing DGX = '$rcnt' (expect 2)"
assert_eq "$rcnt" "2" "shared digest DGX should be referenced by exactly 2 repos, got '$rcnt'" && pass

# --- 3. Wait for the materialized stats cache to refresh --------------------
# The stats refresher sleeps ~150-180s at startup before its first pass, then
# runs on the fast cron. Poll computed_at on repo A until it is non-null and the
# blob is reflected. Budget generously (up to ~5 min).
begin_test "materialization: repository_storage_stats refreshes within budget"
deadline=$(( $(date +%s) + 300 ))
computed=""; ja=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  ja="$(storage_json "$RA")"
  computed="$(echo "$ja" | jnum '.computed_at')"
  bc="$(echo "$ja" | jnum '.blob_count')"
  if [ "$computed" != "null" ] && [ -n "$computed" ] && [ "$bc" = "1" ]; then
    break
  fi
  sleep 5
done
if [ "$computed" != "null" ] && [ -n "$computed" ]; then
  echo "   computed_at=$computed  (repo A stats materialized)"
  pass
else
  fail "repository_storage_stats never materialized within 300s (computed_at still null)" "last A response: $ja"
  end_suite
fi

# --- 4. Read the materialized figures for A, B, C ---------------------------
JA="$(storage_json "$RA")"; JB="$(storage_json "$RB")"; JC="$(storage_json "$RC")"
scope="$(echo "$JA" | jnum '.dedup_scope')"
logA="$(echo "$JA" | jnum '.logical_bytes')"
physA="$(echo "$JA" | jnum '.physical_bytes')"
uniqA="$(echo "$JA" | jnum '.unique_bytes')"
shA="$(echo "$JA" | jnum '.shared_bytes')"
bcA="$(echo "$JA" | jnum '.blob_count')"
physB="$(echo "$JB" | jnum '.physical_bytes')"
shB="$(echo "$JB" | jnum '.shared_bytes')"
physC="$(echo "$JC" | jnum '.physical_bytes')"
uniqC="$(echo "$JC" | jnum '.unique_bytes')"
shC="$(echo "$JC" | jnum '.shared_bytes')"
iu="$(echo "$JA" | jnum '.instance_unique_bytes')"
echo "   A: dedup_scope=$scope logical=$logA physical=$physA unique=$uniqA shared=$shA blob_count=$bcA"
echo "   B: physical=$physB shared=$shB"
echo "   C: physical=$physC unique=$uniqC shared=$shC"
echo "   instance_unique_bytes=$iu   (Sx=$SX Sy=$SY)"

# naive_sum = the pre-#2056 double-counted footprint = sum of per-repo physical.
naive_sum=$(( physA + physB + physC ))
echo "   naive_sum (physA+physB+physC) = $naive_sum ; dedup savings expected = Sx = $SX"

# --- 5. Backend-semantics guard ---------------------------------------------
begin_test "dedup_scope is instance (shared object store)"
assert_eq "$scope" "instance" "expected dedup_scope=instance on S3, got '$scope'" && pass

begin_test "admin sees the cross-tenant-derivable dedup figures on instance scope"
if [ "$physA" != "null" ] && [ "$shA" != "null" ] && [ "$iu" != "null" ]; then
  pass
else
  fail "admin should see physical/shared/instance_unique on instance scope" "$JA"
fi

# --- 6. Per-repo footprint sanity -------------------------------------------
begin_test "repo A footprint reflects the single pushed layer"
{ assert_eq "$bcA" "1" "blob_count(A) expected 1, got $bcA" \
  && assert_eq "$logA" "$SX" "logical(A) expected $SX, got $logA" \
  && assert_eq "$physA" "$SX" "physical(A) expected $SX, got $physA"; } && pass

# ===========================================================================
# 7. THE DISCRIMINATOR — dedup-aware vs naive double-count.
# ===========================================================================
if [ "$NAIVE" = "1" ]; then
  echo "### NAIVE_ORACLE=1: asserting PRE-#2056 naive expectations (must FAIL on the fixed candidate) ###"
  begin_test "[naive-demo] shared_bytes(A) == 0 (pre-#2056: no cross-repo sharing)"
  assert_eq "$shA" "0" "naive expectation: shared_bytes(A)==0 (candidate reports $shA)" && pass
  begin_test "[naive-demo] instance_unique_bytes == naive_sum (double-counts X)"
  assert_eq "$iu" "$naive_sum" "naive expectation: instance_unique==$naive_sum (candidate reports $iu)" && pass
else
  begin_test "DISCRIMINATOR: shared_bytes(A) == Sx (the shared layer is detected as shared)"
  assert_eq "$shA" "$SX" "dedup-aware: shared_bytes(A) must equal Sx=$SX, got $shA (0 = naive/pre-#2056)" && pass

  begin_test "DISCRIMINATOR: shared_bytes(B) == Sx (same shared layer, other repo)"
  assert_eq "$shB" "$SX" "dedup-aware: shared_bytes(B) must equal Sx=$SX, got $shB" && pass

  begin_test "DISCRIMINATOR: instance_unique_bytes counts the shared layer ONCE"
  # dedup-aware: instance_unique == Sx + Sy == naive_sum - Sx (one copy saved).
  exp_iu=$(( SX + SY ))
  { assert_eq "$iu" "$exp_iu" "dedup-aware: instance_unique must be Sx+Sy=$exp_iu, got $iu" \
    && assert_eq "$iu" "$(( naive_sum - SX ))" "instance_unique must equal naive_sum-Sx=$(( naive_sum - SX )) (proves exactly one shared copy saved), got $iu"; } && pass

  begin_test "DISCRIMINATOR: dedup savings present (instance_unique STRICTLY < naive_sum)"
  if [ "$iu" -lt "$naive_sum" ] 2>/dev/null; then
    pass
  else
    fail "no dedup savings: instance_unique=$iu is not < naive_sum=$naive_sum (naive double-count)"
  fi

  begin_test "NEGATIVE GUARD: repo C (unique blob) shows shared_bytes == 0"
  # Rules out a 'shared_bytes always > 0' false-positive.
  { assert_eq "$shC" "0" "unique-blob repo C must have shared_bytes==0, got $shC" \
    && assert_eq "$uniqC" "$SY" "repo C unique_bytes expected Sy=$SY, got $uniqC" \
    && assert_eq "$physC" "$SY" "repo C physical expected Sy=$SY, got $physC"; } && pass
fi

end_suite
