#!/usr/bin/env bash
# =============================================================================
# harness/run.sh — THE Deployment Test Framework entrypoint (local + CI identical)
# =============================================================================
# Usage:
#   run.sh <tier|all>  [--backend-image IMG] [--keep] [--slot N]
#   run.sh up          [--storage X] [--sso Y] ... [--backend-image IMG] [--slot N]
#   run.sh down        [--slot N]   (tears down every profile's services)
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

# DTF_SLOT_PIN=N stands in for --slot N when the flag is absent. run-tiers.sh
# passes the environment through, so several tier groups can run side by side
# on one host each on its own slot (CI runs one group per runner and needs it
# not); without it every tier claims the lowest free slot.
[ -z "$SLOT_ARG" ] && SLOT_ARG="${DTF_SLOT_PIN:-}"

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

# Tear a slot down without knowing which profiles brought it up. `down` after a
# `--keep` run used to compose only the default storage overlay, so services
# from any other profile (peer.second-instance, topology.two-replica, the
# upstreams.mock-* sidecars, telemetry.otlp-sink, scanners.mock-hang, sso.*,
# auth.device, storage.s3-*, ...) were left running and the slot stayed
# occupied. This composes EVERY overlay in profiles/ so compose knows each
# service (and orders backend-b, which shares backend's netns, before backend),
# removes orphans (tier-local fixture overrides under the same project), then
# sweeps anything still carrying the slot's name prefix or project label
# (containers an oracle started with `docker run`, their networks/volumes).
dtf_down_all() {
  local f c
  COMPOSE_FILES=(-f "${DTF_DIR}/compose.base.yml")
  for f in "${DTF_DIR}"/profiles/*.yml; do COMPOSE_FILES+=(-f "$f"); done
  # Interpolation placeholders: down never starts anything, but every
  # `${VAR:?}` in the merged overlays must still resolve.
  export BACKEND_IMAGE="${BACKEND_IMAGE:-placeholder}"
  export DTF_WEBHOOK_SECRET_KEY="${DTF_WEBHOOK_SECRET_KEY:-placeholder}"
  export DTF_DIR
  docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" down -v --remove-orphans || true
  # Sweep: containers that share another container's netns go first.
  local ctrs=() dependents=() others=()
  mapfile -t ctrs < <( { docker ps -a --format '{{.Names}}' | grep "^${PROJECT}-";
                         docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Names}}'; } 2>/dev/null | sort -u)
  for c in "${ctrs[@]}"; do
    [ -z "$c" ] && continue
    case "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$c" 2>/dev/null)" in
      container:*) dependents+=("$c") ;;
      *) others+=("$c") ;;
    esac
  done
  [ ${#dependents[@]} -gt 0 ] && docker rm -f -v "${dependents[@]}" >/dev/null 2>&1
  [ ${#others[@]} -gt 0 ] && docker rm -f -v "${others[@]}" >/dev/null 2>&1
  local nets vols
  nets="$( { docker network ls --format '{{.Name}}' | grep "^${PROJECT}[-_]";
             docker network ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}'; } 2>/dev/null | sort -u)"
  # shellcheck disable=SC2086
  [ -n "$nets" ] && docker network rm $nets >/dev/null 2>&1
  vols="$( { docker volume ls --format '{{.Name}}' | grep "^${PROJECT}[-_]";
             docker volume ls --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Name}}'; } 2>/dev/null | sort -u)"
  # shellcheck disable=SC2086
  [ -n "$vols" ] && docker volume rm -f $vols >/dev/null 2>&1
  if docker ps -a --format '{{.Names}}' | grep -q "^${PROJECT}-"; then
    echo "!! slot ${DTF_SLOT}: containers remain after down:" >&2
    docker ps -a --format '{{.Names}}' | grep "^${PROJECT}-" >&2
    return 1
  fi
  echo ">> DTF slot ${DTF_SLOT} down (every profile, orphans and slot-prefixed leftovers removed)"
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
    # Any --<dimension> flags are accepted for compatibility but no longer
    # needed: down composes every overlay in profiles/ (see dtf_down_all).
    dtf_down_all
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
    # Then the 1.11.3 fix-coverage tiers (artifact-keeper-test#464-#473, #477),
    # green on 1.11.3 and main 2f08663f, red on 1.11.2: OpenAPI curation field
    # (#4793), migration items filters + Debian component (#4787/#4797), npm
    # anonymous audit (#4785), ingest archive entry cap (#4802), terraform
    # origin registry (#4357), readyz under a hung dependency (#4796), push
    # sync for native formats (#4779), remote-instance relay (#4789), proxy log
    # noise on two replicas (#4794/#4798). readyz-hung-dependency is slowest.
    # Then the 1.12.0 fix-coverage tiers (#470-#479, #490, #491, #499-#502),
    # green on main 2f08663f, red on 1.11.3: token virtual catalog (#4213/
    # #4217), hidden admin nav (#4575), trash purge (#4701), S3 max parts
    # (#4806), signing trust attestations (#4274), repo-admin age gate (#4239;
    # needs registry.npmjs.org), 1.12.0 dependency controls (#4816/#4817
    # KNOWN-RED pins), conda virtual shadowing (#4555/#4506), *_FILE secrets
    # (#4775; #4819 KNOWN-RED pin), device authorization grant (#3549), OIDC
    # group pre-provisioning (#4296), protobuf BSR proxy (#4276), proxy
    # stale-if-error (#4697/#4783). proxy-stale-if-error is slowest.
    # Then the 1.11.x security tiers (#480-#489, #492-#498), each green on the
    # fixed 1.11.x release and on main 2f08663f, red on the release before it:
    # token scoping and CI identity, REST mutation authz and existence hiding,
    # request-plane limits, upstream credential hygiene, plugin SSRF, virtual
    # member gates. upload-slot-exhaustion is slowest.
    # Then the older tiers the 1.11.x coverage audit relies on (storage
    # integrity, scan-on-proxy, authz regressions); storage-integrity-s3 is
    # last of all, its fresh-ghost leg waits out the 5-minute guard.
    # Then the P2-P9 coverage tiers (artifact-keeper-test#504-#570), one
    # block per audit wave, each green on the first release carrying its fix
    # (1.11.0 for most, 1.11.1/1.11.2 where noted in matrix.md) and on main
    # 2f08663f, red on the release before it. Slow tiers close each block.
    #   P2 1.11.0 features: access (k8s SA tokens, project admins and quota,
    #      guest access/visibility/banners) and policy (lifecycle assignments
    #      and min_keep, Ed25519 signing rotation, trash/blob GC/Remote cache;
    #      the GC leg waits ~2.5 min for the scheduler).
    #   P3 ops: log/metrics fields, DB keepalives and startup retry, bind IPs
    #      and OTel, upload receive errors and SMTP diagnostics, presigned
    #      redirects/readyz/SMTP TLS.
    #   P4 proxy, virtual and OCI: download ledger, cache TTL/refill, virtual
    #      member failure/timeout, npm isolate, NuGet translation, OCI digest
    #      scope/promotion, upstream auth, presigned blobs, usage counting.
    #   P5 conda: 1.11.0 channel surface, merge policy, CEP-16 shards hosted/
    #      remote/virtual, attestation trust, proxy scan grading and gates;
    #      conda-environments-reverse-index waits three scheduler ticks
    #      (~4 min).
    #   P6 scanning and promotion: scan-on-proxy for Maven/NuGet/Cargo,
    #      record_only and provenance, scan-on-upload completeness, OSV
    #      findings, ingest, SBOM licenses, OCI scrub, severity counts,
    #      promotion gate results and validation.
    #   P7 formats and clients: GitHub release mirror, VS Code gallery,
    #      pacman, bazel, Maven upload tx on S3; debian-flat-remote,
    #      conan-protocol-1-11 and native-client-modules-and-lfs install
    #      packages from the public internet (gate: dtf-advisory).
    #   P8 migration/upgrade/storage: 1.10.0 -> candidate upgrade, replicated
    #      chunked uploads, S3 staging, Azure default backend, per-repo OCI
    #      blob journal, native quota and RPM races, S3 411 CopyObject.
    #   P9 long tail: 1.11.0 API contracts, artifact.uploaded webhooks,
    #      catalog backfill, startup config, private-IP toggles, stock Caddy
    #      routes; trivy-server-mode needs the Trivy DB (gate: dtf-advisory).
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
    # (#4865). maven-upload-tx-and-quality-s3 above gates #4837 since #606.
    # 1.11.6: the PyPI upstream_publish_time age gate resolving a PEP
    # 440-equal filename version to its release publish time (#4907).
    # 1.11.7: protobuf label moves, late NuGet metadata and protobuf commits
    # reaching a push peer (#4889, #4921), and a 504-cut OCI blob completion
    # that succeeds when re-sent (#4902); maven-upload-tx-and-quality-s3 above gates #4892 since
    # #617. 1.11.8: chunked uploads apply the quota and the upload quarantine
    # hold like the native routes (#5003 on the line, #4992 on main).
    # 1.12.0 features (red on every 1.11.x image): the paged group members
    # list (#4027) and OTLP log and metric export (#4337);
    # remote-instance-relay above gates the relayed PATCH (#4795) since #623.
    # More 1.12.0 features: scan-on-proxy for Go, RubyGems, Composer, Pub,
    # Conan, CocoaPods and Swift (#4103-#4110), the admin downloads
    # downloader filter and lifecycle match.format (#4839, #2024), 304 on
    # conditional conda package downloads (#4579), logout ending the access
    # token (#4883), the per-Remote cache cap, digest-keyed pull history,
    # statistics retention and Maven X-Checksum-SHA1 (#4660, #4542, #4541,
    # #4573) and the proxy cache on Azure Blob storage (#4320). Batch 3:
    # scan-on-proxy coordinate pins for Go, Composer and Conan (#4952),
    # Debian, RPM and Alpine (#4111-#4113), the scan gate's refused-content
    # audit, listing and 403 (#4777, #4510, #4363, #4288), bounded storage GC
    # deletes (#2524), the oci_manifests reconcile (#4955), corrupted objects
    # failing closed on format and virtual routes (#4323), conditional
    # generic PUTs (#4186, split out of generic-concurrent-put-contract),
    # CEP-16 shards stored at write time (#4173), conda repodata revisions
    # (#4174, #4176, #4882) and CLIENT spans for upstream senders (#3954).
    # Batch 4: the Maven publish-age gate (#4702), chunked uploads indexed
    # by Maven, npm, PyPI and RPM (#1846), Maven single PUTs staged on object storage (#4990),
    # repository delete as a background job (#4311), conda JLAP patches
    # (#4175), synthesised shards for conda remotes (#4178) and OCI reads by
    # digest keyed on oci_manifests (#1683). Then repository grade status
    # and coverage in place of the F floor (#4336). Batch 5: ISO live media
    # inventoried through their squashfs rootfs (#1966), conda plain
    # repodata fallback on 401/403 probes (#4929), Composer Virtuals over
    # Packagist-style Remote members (#4951) and, for 1.11.8, a proxy
    # rescan that cannot grade a package keeping the stored verdict
    # (GHSA-9vgh-8jfp-78ff, #5030 on main, #5031 on the line).
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
             openapi-curation-optional migration-items-filters npm-anon-audit ingest-archive-entries-limit \
             terraform-origin-registry remote-instance-relay ops-log-noise push-sync-native-formats readyz-hung-dependency \
             token-virtual-catalog admin-hidden-nav signing-trust-attestations trash-purge s3-max-parts \
             age-gate-repo-admin conda-virtual-shadow-and-cache oidc-group-preprovision device-auth-flow \
             deps-1.12.0-controls secrets-file-env protobuf-bsr-proxy proxy-stale-if-error \
             image-build-spec-validation repo-read-hiding restricted-token-refresh download-route-token-basic \
             rest-mutation-authz-1-11 token-repo-restriction generic-route-scan-gate index-metadata-cred-scoping \
             upstream-url-userinfo-redaction virtual-member-gates plugin-reload-ssrf http-edge-limits \
             admin-setup-gate plugins-disabled xff-authz-trust ci-oidc-exchange upload-slot-exhaustion \
             repo-mutation-authz migration-authz token-colon-scope ledger-triggers-authoritative quota-admission-o1 \
             redact-userinfo-leak nuget-cred-scoping rpm-p3-curation inline-scan-hosted-gate-2954 \
             inline-scan-fail-open-2954 inline-scan-proxy-pypi-2954 scan-verdict-dbversion \
             storage-integrity storage-integrity-s3 \
             k8s-sa-pull-token project-admin-and-project-quota guest-access-runtime-visibility-banners \
             lifecycle-assignments-min-keep signing-ed25519-rotation-overlap-legacy trash-blob-gc-remote-cache \
             db-keepalive-startup-retry ops-log-and-metrics-1112 bind-ip-and-otel upload-receive-and-ops-errors \
             ops-endpoints-1110 \
             oci-usage-counts-layers-once oci-manifest-scrub oci-presigned-redirect oci-remote-upstream-auth \
             virtual-member-failure-policy nuget-protocol-translation npm-virtual-isolate-disttag-feed \
             proxy-cache-ttl-and-refill proxy-download-ledger virtual-member-metadata-timeout \
             oci-digest-scope-and-promotion \
             conda-virtual-merge-policy conda-channel-1110-surface conda-attestation-trust conda-sharded-remote-virtual \
             conda-proxy-scan-grading scan-on-proxy-conda-and-content conda-hosted-cep16-and-upload conda-virtual-shards \
             conda-environments-reverse-index \
             promotion-and-curation-validation promotion-gate-results-and-origin \
             severity-counts-agree cargo-scan-on-proxy osv-positional-findings sbom-license-expression \
             proxy-scan-record-only-provenance scan-on-proxy-maven-nuget scan-ingest-and-workspace \
             scan-on-upload-native-and-completeness \
             bazel-bzlmod-registry maven-upload-tx-and-quality-s3 github-release-mirror vscode-gallery-protocol \
             pacman-hosted debian-flat-remote conan-protocol-1-11 native-client-modules-and-lfs \
             quota-native-and-rpm-races s3-copy-length-required azure-default-backend oci-blob-journal-per-repo \
             replicated-and-chunked-uploads upgrade-v270-origin upload-staging-object-store \
             lifecycle-signing-webhook-config api-contracts-1110 catalog-backfill-liveness \
             webhook-artifact-uploaded-formats stock-compose-caddy startup-config-and-format-indexes \
             trivy-server-mode \
             plugin-fetch-pinned-address auth-logout-revokes-session ldap-env-bootstrap-lifecycle \
             repo-delete-reclaims-storage generic-concurrent-put-contract nuget-v2-continuation-pages \
             azure-copy-long-running \
             push-sync-echo-and-sidecars push-sync-chunked-upload metrics-startup-db-retry \
             conda-remote-shard-recovers proxy-metadata-budget-env conda-virtual-stale-serve \
             cran-remote-packages-index repo-delete-purges-revisions \
             pypi-age-gate-pep440-lookup \
             replication-labels-and-late-metadata group-members-list otlp-logs-metrics \
             oci-blob-completion-retry \
             scan-on-proxy-go-rubygems-composer scan-on-proxy-pub-conan scan-on-proxy-cocoapods-swift \
             api-contracts-1120 conda-package-304 auth-logout-revokes-access-token \
             proxy-cache-cap-and-history azure-proxy-cache \
             scan-on-proxy-coordinate-pins scan-on-proxy-debian-rpm scan-on-proxy-alpine \
             scan-gate-blocked-body-and-audit \
             storage-gc-bounded-deletes oci-manifests-reconcile storage-integrity-serve-routes \
             generic-conditional-put \
             conda-shard-o1 conda-repodata-revision otlp-upstream-client-spans \
             maven-age-gate \
             chunked-upload-format-finalize upload-staging-object-store-single-put \
             repo-delete-reclaims-storage-job \
             conda-jlap-incremental conda-remote-shards-synth \
             oci-last-tag-delete-by-digest oci-manifests-reconcile-populated \
             chunked-upload-admission \
             scan-grade-status-coverage \
             scan-iso-rootfs-inventory conda-remote-403-probe-fallback \
             composer-virtual-packagist-member \
             proxy-rescan-verdict \
             conda-allowlist-hosted-members; do
      run_tier "$t" || overall=1
    done
    exit "$overall" ;;

  *)
    run_tier "$CMD"; exit $? ;;
esac
