#!/usr/bin/env bash
# =============================================================================
# tiers/isolation-formats/oracle.sh — per-format cross-tenant isolation gate (S3)
# =============================================================================
# run.sh has stood up ONE shared S3 (MinIO) stack (backend+postgres+minio) plus
# the client overlay for every enabled/selected plugin that declares one (the
# manifest computes the profile-set), health-gated with `up -d --wait`, and
# exported BASE_URL / DB_CONTAINER / ADMIN_USER / ADMIN_PASS / RUN_ID /
# RELEASE_GATE=1 / DTF_SLOT / JUNIT_OUTPUT_DIR.
#
# We source the corpus common.sh (assertion + JUnit harness) and then the shared
# isolation driver lib/sec_isolation.sh (the generalized prove.sh A-F gate). Each
# plugin under plugins/ is run in its OWN subshell, SEQUENTIALLY, one
# begin_suite "isol-<fmt>" per plugin, so the fixed sec_* hook names never
# collide across plugins, a crashing plugin cannot poison the loop, and per-
# format red/green is a distinct JUnit suite in results/isolation-formats/.
#
# The oracle exit code is the gate signal (run.sh contract step 7), aggregated
# across plugins. Sequential (not parallel): rocky is CPU-load-sensitive and the
# shared S3 stack stays deterministic. Same shape as format-conformance/oracle.sh.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=/dev/null
source "${DTF_DIR}/harness/lib/sec_isolation.sh"

PLUGIN_DIR="${DTF_DIR}/harness/tiers/isolation-formats/plugins"

overall=0
ran=0
for p in "${PLUGIN_DIR}"/*.sh; do
  [ -e "$p" ] || continue
  if ! sec_enabled_and_selected "$p"; then
    fmt="$(sec_header "$p" SEC_FORMAT)"
    echo ">> isol: skipping ${fmt:-$(basename "$p")} (disabled or not selected by SEC_ONLY='${SEC_ONLY:-}')"
    continue
  fi
  ran=$((ran + 1))
  ( sec_run_plugin "$p" )        # subshell isolation
  rc=$?
  [ "$rc" -eq 0 ] || overall=1
  echo ">> isol: $(sec_header "$p" SEC_FORMAT) suite exit=${rc}"
done

if [ "$ran" -eq 0 ]; then
  echo "!! isolation-formats: no plugins ran (SEC_ONLY='${SEC_ONLY:-}' matched nothing)" >&2
  # A security tier that ran nothing is a silent pass — fail loudly under the
  # release gate (same spirit as format-conformance/oracle.sh).
  [ "${RELEASE_GATE:-0}" = "1" ] && exit 1
fi

exit "$overall"
