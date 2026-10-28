#!/usr/bin/env bash
# =============================================================================
# harness/run.sh — THE Deployment Test Framework entrypoint (local + CI identical)
# =============================================================================
# Usage:
#   run.sh <tier|all>  [--backend-image IMG] [--keep] [--slot N]
#   run.sh up          [--storage X] [--sso Y] ... [--backend-image IMG] [--slot N]
#   run.sh down        [--slot N]
#   run.sh ports       [--slot N]
#
# A <tier> resolves to a profile-set + an oracle from harness/tiers/<tier>/manifest.
# The raw `up`/`down` verbs take explicit --<dimension> <value> flags (the §2.3
# form) so you can stand up an arbitrary topology by hand.
#
# Contract (per design §3.2), for a tier:
#   1. resolve tier -> profile-set (+ oracle) from the manifest
#   2. claim a free slot, compute its non-colliding port block (lib/ports.sh)
#   3. export the required compose vars + `up -d --wait` (health-gated)
#   4. export BASE_URL / RELEASE_GATE=1 / ADMIN_PASS / DB_CONTAINER / BACKEND_IMAGE
#   5. run the tier's oracle; collect JUnit into results/<tier>/
#   6. tear down (down -v) unless --keep
#   7. return non-zero if the oracle (any suite) failed, distinguishing an
#      oracle-asserted regression (exit 1) from an INFRA/SETUP failure the
#      harness could not evaluate around (DTF_EXIT_INFRA — see
#      harness/lib/exit_codes.sh); both are RED, only one is a product verdict
#   On a release/X.Y.x suite (deploy-test/.tests-ref, written by
#   scripts/switch-tests-ref.sh) a tier with no manifest is NOT ON THIS LINE:
#   a ::warning, a JUnit <skipped/>, exit 12 (DTF_EXIT_NOT_ON_LINE), which
#   run-tiers.sh does not count as RED. Without the marker it stays exit 4.
#
# Consolidated scope (bricks 0/1/2/3/4/5/6/7): the `smoke` (filesystem),
# `isolation` (s3), `migration` (nexus), `proxy-egress` (squid), `sso`
# (saml/keycloak), `native-client` (dnf/apt/docker), `upgrade` (two-phase image
# swap), `supply-chain` (trivy scanner efficacy), and `dos` (rate-limit /
# worker-starvation) tiers exist. Row 8 (WASM plugin signing) remains a GAP.
# `format-conformance` (filesystem, ONE shared AK + per-format client plugins)
# adds real publish->consume conformance per registry format (conda is the
# reference; more formats are drop-in plugins, no shared-file edits).
# `signing` (filesystem + apt/dnf/apk/helm clients) asks the question every other
# client leg disables: does the client actually VERIFY the advertised signature
# chain? (#72; no [trusted=yes] / --allow-untrusted / gpgcheck=0 anywhere.)
# `maven-rollup-anchor-escape` (s3 + the Maven flat-object GC opt-in) and
# `migration-progress-monotonic` (filesystem + a scripted Artifactory-shaped
# source) are the 1.8.2 data-integrity pair: both assert that a delete/write
# path does not destroy a record it cannot re-derive.
# =============================================================================
set -uo pipefail

DTF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/ports.sh
source "${DTF_DIR}/harness/lib/ports.sh"
# shellcheck source=lib/exit_codes.sh
source "${DTF_DIR}/harness/lib/exit_codes.sh"

# --- Locate the artifact-keeper-test corpus (common.sh / run-suite.sh) --------
# In the productized home (artifact-keeper-test/deploy-test) the corpus is the
# parent dir. On the redteam rig the runnable copy lives outside the corpus, so
# fall back to the known rig checkout. Override with AK_TEST_ROOT.
resolve_test_root() {
  if [ -n "${AK_TEST_ROOT:-}" ] && [ -f "${AK_TEST_ROOT}/tests/lib/common.sh" ]; then
    echo "$AK_TEST_ROOT"; return 0
  fi
  if [ -f "${DTF_DIR}/../tests/lib/common.sh" ]; then
    (cd "${DTF_DIR}/.." && pwd); return 0
  fi
  if [ -f "/home/khan/artifact-keeper-redteam/test/tests/lib/common.sh" ]; then
    echo "/home/khan/artifact-keeper-redteam/test"; return 0
  fi
  echo ""; return 1
}

# --- Argument parsing ---------------------------------------------------------
CMD="${1:-}"; shift || true
BACKEND_IMAGE_ARG=""
KEEP=0
SLOT_ARG=""
declare -A DIM=()   # dimension -> value (for raw up/down)

while [ $# -gt 0 ]; do
  case "$1" in
    --backend-image) BACKEND_IMAGE_ARG="$2"; shift 2 ;;
    --keep)          KEEP=1; shift ;;
    --slot)          SLOT_ARG="$2"; shift 2 ;;
    --storage)       DIM[storage]="$2"; shift 2 ;;
    --proxy)         DIM[proxy]="$2"; shift 2 ;;
    --upstreams)     DIM[upstreams]="$2"; shift 2 ;;
    --sso)           DIM[sso]="$2"; shift 2 ;;
    --topology)      DIM[topology]="$2"; shift 2 ;;
    --scanners)      DIM[scanners]="$2"; shift 2 ;;
    --client)        DIM[client]="$2"; shift 2 ;;
    *) echo "!! unknown argument: $1" >&2; exit 2 ;;
  esac
done

# --- Overlay-list builders ----------------------------------------------------
# Turn a space-separated list of overlay basenames into `-f` args, validating
# each file exists (a missing overlay for a later brick is a clear error, not a
# silent no-op).
profiles_to_files() {
  local p file
  COMPOSE_FILES=(-f "${DTF_DIR}/compose.base.yml")
  for p in "$@"; do
    file="${DTF_DIR}/profiles/${p}.yml"
    if [ ! -f "$file" ]; then
      echo "!! overlay not found: profiles/${p}.yml (a later-brick profile?)" >&2
      exit 3
    fi
    COMPOSE_FILES+=(-f "$file")
  done
}

# Build a profile-basename list from the raw --<dimension> flags.
dims_to_profiles() {
  local out=() dim val
  for dim in storage proxy upstreams sso topology scanners client; do
    val="${DIM[$dim]:-}"
    [ -z "$val" ] && continue
    [ "$val" = "none" ] && continue
    # storage=filesystem is a real (default) overlay; single topology has none.
    [ "$dim" = "topology" ] && [ "$val" = "single" ] && continue
    out+=("${dim}.${val}")
  done
  # default storage if the caller gave none
  local has_storage=0 x
  for x in "${out[@]:-}"; do [[ "$x" == storage.* ]] && has_storage=1; done
  [ "$has_storage" = "0" ] && out=("storage.filesystem" "${out[@]:-}")
  echo "${out[@]}"
}

# --- Bring a slot up on a profile-set ----------------------------------------
# Args: $1 = space-separated profile basenames. Uses globals SLOT/PROJECT + the
# exported port block. Honors env overrides already exported by the caller
# (e.g. RATE_LIMIT_ENABLED from a tier manifest).
dtf_up() {
  local profiles_str="$1"
  # shellcheck disable=SC2206
  local profiles=($profiles_str)
  profiles_to_files "${profiles[@]}"

  : "${BACKEND_IMAGE:?BACKEND_IMAGE not set (pass --backend-image)}"
  export BACKEND_IMAGE

  echo ">> DTF slot ${DTF_SLOT}: ${profiles[*]}"
  echo ">>   image=${BACKEND_IMAGE}"
  echo ">>   HTTP=:${HTTP_PORT}  PG=:${PG_PORT}  gRPC=:${GRPC_PORT}  S3=:${S3_PORT}"
  echo ">>   RATE_LIMIT_ENABLED=${RATE_LIMIT_ENABLED:-true (base default)}"
  docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" up -d --wait
}

dtf_down() {
  local profiles_str="$1"
  # shellcheck disable=SC2206
  local profiles=($profiles_str)
  profiles_to_files "${profiles[@]}"
  # BACKEND_IMAGE must interpolate even on down.
  export BACKEND_IMAGE="${BACKEND_IMAGE:-placeholder}"
  docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" down -v
  echo ">> DTF slot ${DTF_SLOT} down (volumes removed)"
}

# --- NOT ON THIS LINE ----------------------------------------------------------
# Args: tier, release line. Emits the GitHub annotation and a one-case JUnit
# file with <skipped/> into results/<tier>/, so the skip shows up in the gate's
# junit-dtf-<group> artifact next to the tiers that did run.
not_on_line() {
  local tier="$1" line="$2" results="${DTF_DIR}/results/${1}"
  local msg="${tier} has no manifest on ${line}; the matrix names it for main"
  echo "::warning title=Tier not on this line::${msg}"
  echo "=== TIER ${tier}: NOT ON THIS LINE (${line} has no harness/tiers/${tier}/manifest) ==="
  rm -rf "$results"; mkdir -p "$results"
  cat > "${results}/not-on-line.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="dtf-${tier}" tests="1" failures="0" skipped="1" time="0">
  <testcase name="${tier}" classname="dtf-${tier}" time="0">
    <skipped message="NOT ON THIS LINE: ${msg}" type="not-on-line"/>
  </testcase>
</testsuite>
EOF
}

# --- Tier runner --------------------------------------------------------------
run_tier() {
  local tier="$1"
  local manifest="${DTF_DIR}/harness/tiers/${tier}/manifest"
  if [ ! -f "$manifest" ]; then
    # On a release/X.Y.x suite (deploy-test/.tests-ref) a tier main's gate
    # matrix names may simply not exist: it covers a feature the line never
    # received. Record it as NOT ON THIS LINE, loudly, instead of failing the
    # group; see DTF_EXIT_NOT_ON_LINE in lib/exit_codes.sh. On main a missing
    # manifest stays a wiring bug (exit 4).
    local line
    line="$(dtf_tests_ref "$DTF_DIR")"
    if [ -n "$line" ] && [[ "$tier" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
      not_on_line "$tier" "$line"
      exit "$DTF_EXIT_NOT_ON_LINE"
    fi
    echo "!! no manifest for tier '${tier}' (${manifest})" >&2
    exit 4
  fi

  # Manifest is a sourced KV file: PROFILES, ORACLE, and optional env overrides
  # (e.g. RATE_LIMIT_ENABLED) which we export into the compose environment.
  PROFILES=""; ORACLE=""
  # shellcheck disable=SC1090
  source "$manifest"
  [ -n "${RATE_LIMIT_ENABLED:-}" ] && export RATE_LIMIT_ENABLED
  [ -n "${UPSTREAM_ALLOW_PRIVATE_IPS:-}" ] && export UPSTREAM_ALLOW_PRIVATE_IPS
  # Storage key layout (#2624): a tier that wants the legacy flat namespace
  # sets STORAGE_KEY_SCHEME=flat in its manifest; the oracle sees the same
  # value it configured the backend with.
  [ -n "${STORAGE_KEY_SCHEME:-}" ] && export STORAGE_KEY_SCHEME
  if [ -z "$PROFILES" ] || [ -z "$ORACLE" ]; then
    echo "!! manifest for '${tier}' must set PROFILES and ORACLE" >&2
    exit 4
  fi

  # Resolve corpus + backend image.
  AK_TEST_ROOT="$(resolve_test_root)"
  if [ -z "$AK_TEST_ROOT" ]; then
    echo "!! cannot locate artifact-keeper-test corpus (set AK_TEST_ROOT)" >&2
    exit 5
  fi
  export AK_TEST_ROOT
  export COMMON_SH="${AK_TEST_ROOT}/tests/lib/common.sh"
  export RUN_SUITE="${AK_TEST_ROOT}/scripts/run-suite.sh"
  BACKEND_IMAGE="${BACKEND_IMAGE_ARG:-${BACKEND_IMAGE:-}}"
  export BACKEND_IMAGE

  # Claim a slot + compute its port block.
  local slot
  if [ -n "$SLOT_ARG" ]; then slot="$SLOT_ARG"; else slot="$(dtf_claim_slot)" || exit 6; fi
  dtf_slot_env "$slot"
  PROJECT="ak-dtf${DTF_SLOT}"

  # Results dir + strict-gate runner contract vars.
  local results="${DTF_DIR}/results/${tier}"
  rm -rf "$results"; mkdir -p "$results"
  export JUNIT_OUTPUT_DIR="$results"
  export RESULTS_DIR="$results"
  export RELEASE_GATE=1
  export BASE_URL="http://127.0.0.1:${HTTP_PORT}"
  export DB_CONTAINER="ak-dtf${DTF_SLOT}-db"
  export ADMIN_USER="admin"
  export ADMIN_PASS="${ADMIN_PASSWORD:-TestRunner!2026secure}"
  export RUN_ID="dtf-${tier}-${DTF_SLOT}-$(date +%s)"
  export DTF_DIR

  local rc=0
  echo "=== DTF tier: ${tier}  (slot ${DTF_SLOT}) ==="
  if ! dtf_up "$PROFILES"; then
    echo "!! stack failed to come up healthy for tier '${tier}'" >&2
    docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" logs backend --tail=120 || true
    [ "$KEEP" = "1" ] || dtf_down "$PROFILES"
    exit 7
  fi

  echo "=== running oracle: tiers/${tier}/${ORACLE} ==="
  echo "===   BASE_URL=${BASE_URL}  DB_CONTAINER=${DB_CONTAINER}  RELEASE_GATE=1 ==="
  bash "${DTF_DIR}/harness/tiers/${tier}/${ORACLE}"; rc=$?

  if [ "$KEEP" = "1" ]; then
    echo ">> --keep: leaving slot ${DTF_SLOT} up (${BASE_URL})"
  else
    dtf_down "$PROFILES"
  fi

  if [ "$rc" -eq 0 ]; then
    echo "=== TIER ${tier}: PASS (exit 0) ==="
  elif [ "$rc" -eq "$DTF_EXIT_INFRA" ]; then
    # #323: the oracle could not evaluate the tier (probe build failed, token
    # mint empty/4xx, fixture precondition unmet, backend unreachable). This is
    # still RED — a required tier that cannot run cannot certify — but it is
    # NOT a statement about the candidate, so it must never read as one.
    echo "=== TIER ${tier}: INFRA/SETUP FAILURE (oracle exit ${rc}) ==="
    echo "===   the harness could not evaluate this tier — NOT a product verdict ==="
    echo "===   fix the harness/environment and re-run; the candidate is unjudged ==="
  else
    echo "=== TIER ${tier}: FAIL (oracle exit ${rc}) ==="
  fi
  return "$rc"
}

# --- Dispatch -----------------------------------------------------------------
case "$CMD" in
  "" | -h | --help)
    sed -n '2,42p' "${BASH_SOURCE[0]}"; exit 0 ;;

  up)
    profiles_str="$(dims_to_profiles)"
    slot="${SLOT_ARG:-$(dtf_claim_slot)}" || exit 6
    dtf_slot_env "$slot"; PROJECT="ak-dtf${DTF_SLOT}"
    BACKEND_IMAGE="${BACKEND_IMAGE_ARG:-${BACKEND_IMAGE:-}}"; export BACKEND_IMAGE
    dtf_up "$profiles_str"
    echo ">> up on slot ${DTF_SLOT}: http://127.0.0.1:${HTTP_PORT}  (profiles: ${profiles_str})"
    ;;

  down)
    if [ -z "$SLOT_ARG" ]; then echo "!! down needs --slot N" >&2; exit 2; fi
    dtf_slot_env "$SLOT_ARG"; PROJECT="ak-dtf${DTF_SLOT}"
    profiles_str="$(dims_to_profiles)"
    dtf_down "$profiles_str"
    ;;

  ports)
    dtf_ports "${SLOT_ARG:-1}" ;;

  all)
    # Consolidated tier set (bricks 0/1/2/3/4/5/6/7). Run SEQUENTIALLY — heavy
    # legs (migration = Nexus JVM, upgrade = two-phase image swap) never share a
    # slot with another tier. Each tier claims its own slot, health-gates up, and
    # `down -v` cleans before the next.
    # NOTE: `all` drives every tier with a SINGLE --backend-image; the tiers'
    # documented fixed images differ (some pin v158-4fix, some fix-2574), so for
    # the full-fidelity coexistence proof run the differing tiers individually.
    # Per-tier image support for `all` is a follow-up.
    overall=0
    # Base tiers, then the 1.6.1 feature/fix coverage tiers (ci-token-basic
    # #2786, virtual-usage #2785, maven-files-casing #2706/#2707, backup-reclaim
    # #2787, nexus-go-apt #2784, nexus-group-virtual #2783, pypi-contenttype
    # #2801, ldaps #2782), then the 1.7.0 backfill batch-1 tiers
    # (openapi-signing-tags #2721, maven-grouped-name #2723,
    # debian-encoded-separator #2562, cran-rubygems-download-url #2754,
    # backup-custom-name #2790).
    # Then the 1.11.2 fix-coverage tiers (artifact-keeper-test#452-#461), each
    # green on main 6a4e29f1 and red on the 1.11.1 release image: permissions
    # (#4026/#4639/#4690), metrics + listen backlog (#4642/#4647), format
    # catalog (#4694/#4633/#4645), npm unpublish + push sync (#4025/#4643/
    # #4658), conda channel types (#4708/#4709/#4711), migration catalog
    # (#4691/#4657), OIDC exchange + login (#4699/#4143/#4648/#4638), proxy
    # cache (#4630/#4646), auth under a DB outage (#4750), audit coverage
    # (#4710/#4718). audit-event-coverage is last: its retention leg waits for
    # the scheduler's first pass (~4.5 min).
    # Then the 1.11.4 companion tiers (artifact-keeper-test#574-#584), each
    # red on 1.11.3 and green on main with the fix: plugin fetch through the
    # SSRF-guarded client (#4827), logout ending the session (#4831), the
    # env-seeded LDAP provider lifecycle (#4857), repository delete and GC
    # reclaiming filesystem copies (#4833), concurrent generic PUTs (#4832),
    # NuGet V2 continuation pages (#4856), and the slow Azure server-side
    # copy (#4858, plus SAS-free error bodies; ~2 min).
    # Then the 1.11.5 companion tiers (artifact-keeper-test#597-#605), each
    # red on 1.11.4 and green on main with the fix: push replication without
    # echo and with late sidecars (#4792) and from upload sessions (#4791),
    # failed startup DB connects on /metrics (#4828), a refused remote conda
    # shard that recovers (#4829), the 32 GiB metadata budget (#4881), conda
    # virtual stale serve (#4879) and CRAN remote PACKAGES (#4877); then
    # repository delete purging older revisions of a versioned repository
    # (#4865). maven-upload-tx-and-quality-s3 (gates #4837 since #606) is not
    # in this line's list; the release gate runs it from main's
    # storage-1.11.0 group against this branch's tier.
    # 1.11.6: the PyPI upstream_publish_time age gate resolving a PEP
    # 440-equal filename version to its release publish time (#4907).
    # 1.11.7: protobuf label moves, late NuGet metadata and protobuf commits
    # reaching a push peer (#4889, #4921) and a blob completion PUT re-sent
    # after a proxy 504 (#4902). maven-upload-tx-and-quality-s3 also gates
    # #4892 since #617, still from main's storage-1.11.0 group.
    for t in smoke isolation migration proxy-egress sso native-client upgrade supply-chain dos format-conformance \
             ci-token-basic virtual-usage maven-files-casing backup-reclaim nexus-go-apt nexus-group-virtual pypi-contenttype ldaps \
             vvc3-scoped-admin qcmj-webhook-authz f7qf-peer-authz 5f2q-upload-scope qxxr-refresh-race \
             virtual-no-transfer proxy-upstream-url oidc-group-sync \
             openapi-signing-tags maven-grouped-name debian-encoded-separator cran-rubygems-download-url backup-custom-name \
             oidc-env-config gcs-custom-endpoint signing \
             oci-push-scope api-alias-repo-key oci-rest-delete-digest-authority empty-repo-key-no-body-read \
             maven-rollup-anchor-escape migration-progress-monotonic \
             repo-project-permissions metrics-and-backlog format-catalog-fixes npm-unpublish-and-push-sync \
             conda-channel-types migration-package-catalog oidc-exchange-and-login proxy-cache-empty-object \
             auth-db-outage audit-event-coverage \
             plugin-fetch-pinned-address auth-logout-revokes-session ldap-env-bootstrap-lifecycle \
             repo-delete-reclaims-storage generic-concurrent-put-contract nuget-v2-continuation-pages \
             azure-copy-long-running \
             push-sync-echo-and-sidecars push-sync-chunked-upload metrics-startup-db-retry \
             conda-remote-shard-recovers proxy-metadata-budget-env conda-virtual-stale-serve \
             cran-remote-packages-index repo-delete-purges-revisions \
             pypi-age-gate-pep440-lookup \
             replication-labels-and-late-metadata oci-blob-completion-retry \
             chunked-upload-admission proxy-rescan-verdict \
             conda-allowlist-hosted-members; do
      run_tier "$t" || overall=1
    done
    exit "$overall" ;;

  *)
    run_tier "$CMD"; exit $? ;;
esac
