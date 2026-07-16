#!/usr/bin/env bash
# =============================================================================
# tiers/format-conformance/oracle.sh — publish->consume conformance per format
# =============================================================================
# run.sh has stood up ONE shared filesystem stack (backend+postgres) plus the
# client overlay for every enabled/selected plugin (manifest computes the
# profile-set), health-gated with `up -d --wait`, and exported BASE_URL /
# ADMIN_USER / ADMIN_PASS / RUN_ID / RELEASE_GATE=1 / DTF_SLOT / JUNIT_OUTPUT_DIR.
#
# We source the corpus common.sh (assertion + JUnit harness) and then the
# shared driver lib/native_client.sh. Each plugin under plugins/ is run in its
# OWN subshell, SEQUENTIALLY, one begin_suite "fc-<fmt>" per plugin, so:
#   * fixed hook names (fc_publish, ...) never collide across plugins,
#   * a crashing plugin cannot poison the loop,
#   * per-format red/green is a distinct JUnit suite in results/format-conformance/.
#
# The oracle exit code is the gate signal (run.sh contract step 7), aggregated
# across plugins — NOT JUnit parsing. Sequential (not parallel): rocky is
# CPU-load-sensitive and the shared AK stays deterministic; FC_PARALLEL is an
# explicit non-goal for v1.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=/dev/null
source "${DTF_DIR}/harness/lib/native_client.sh"

PLUGIN_DIR="${DTF_DIR}/harness/tiers/format-conformance/plugins"

overall=0
ran=0
for p in "${PLUGIN_DIR}"/*.sh; do
  [ -e "$p" ] || continue
  if ! fc_enabled_and_selected "$p"; then
    fmt="$(nc_header "$p" FC_FORMAT)"
    echo ">> fc: skipping ${fmt:-$(basename "$p")} (disabled or not selected by FC_ONLY='${FC_ONLY:-}')"
    continue
  fi
  ran=$((ran + 1))
  ( nc_run_plugin "$p" )        # subshell isolation
  rc=$?
  [ "$rc" -eq 0 ] || overall=1
  echo ">> fc: $(nc_header "$p" FC_FORMAT) suite exit=${rc}"
done

if [ "$ran" -eq 0 ]; then
  echo "!! format-conformance: no plugins ran (FC_ONLY='${FC_ONLY:-}' matched nothing)" >&2
  # A conformance tier that ran nothing is a silent pass — fail loudly under
  # the release gate (same spirit as require_cmd/skip_suite).
  [ "${RELEASE_GATE:-0}" = "1" ] && exit 1
fi

exit "$overall"
