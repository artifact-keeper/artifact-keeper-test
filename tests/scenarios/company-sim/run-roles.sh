#!/usr/bin/env bash
# run-roles.sh - run every roles/*.sh in parallel against one founded instance.
#
# Usage:
#   bash tests/scenarios/company-sim/run-roles.sh [--only role1,role2] [--timeout SECONDS]
#
# Preconditions: 00-found-company.sh ran with the same RUN_ID and
# COMPANY_SIM_STATE_DIR, so personas.env exists.
#
# Each role runs as its own process with its own JUnit suite
# (company-sim-<role>.xml in $JUNIT_OUTPUT_DIR), log
# ($COMPANY_SIM_STATE_DIR/logs/<role>.log) and CHECK file
# ($COMPANY_SIM_STATE_DIR/checks/<role>.txt). Roles meet only through
# cs_signal/cs_wait barrier files. CS_RUN_START is set once here, before the
# launch: a barrier counts only when it was signalled after it (lib.sh), so
# leftovers from an earlier run never satisfy a wait. A full run also clears
# the signals directory; an `--only` run leaves it alone, so two `--only`
# runs sharing a state dir do not wipe each other's barriers.
#
# Env:
#   CS_BARRIER_TIMEOUT        seconds a role waits per barrier (default 600)
#   COMPANY_SIM_ROLE_TIMEOUT  seconds before a role is killed (default
#                             2 x CS_BARRIER_TIMEOUT + CS_SCAN_TIMEOUT + 300;
#                             CS_SCAN_TIMEOUT defaults to 300)
#   CS_TOOL_PATH              extra PATH entries (colon-separated) for the
#                             real clients: cargo, mvn, uv, ... (prepended)
#   CS_NODE_DIR               a Node install; web adds <dir>/bin to PATH
#   HAL_CONDA_CLIENT_IMAGE    local image with pixi (data #9e)
#   RUSTUP_HOME, CARGO_HOME   passed through untouched for cargo
# The roles inherit the environment; the client preflight below prints what
# they will find, so a SKIP for a missing client is visible up front.
#
# Output: the merged CHECK lines (role by role, each in the order it ran) in
# $COMPANY_SIM_STATE_DIR/CHECKS.txt and on stdout, then a per-role summary.
# Exit: 0 when every role exited 0; 1 when any role failed; 11 (INFRA) when
# personas.env is missing.

source "$(dirname "$0")/lib.sh"

ONLY=""
CS_BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
export CS_BARRIER_TIMEOUT
ROLE_TIMEOUT="${COMPANY_SIM_ROLE_TIMEOUT:-$(( 2 * CS_BARRIER_TIMEOUT + ${CS_SCAN_TIMEOUT:-300} + 300 ))}"
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --timeout) ROLE_TIMEOUT="$2"; shift 2 ;;
    *) echo "run-roles.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

if [ ! -f "$PERSONAS_ENV" ]; then
  echo "run-roles.sh: ${PERSONAS_ENV} missing; run 00-found-company.sh first" >&2
  exit "${DTF_EXIT_INFRA:-11}"
fi

mapfile -t ROLES < <(find "${CS_DIR}/roles" -maxdepth 1 -name '*.sh' ! -name '_*' -type f | sort)
if [ -n "$ONLY" ]; then
  keep=()
  for r in "${ROLES[@]}"; do
    n=$(basename "$r" .sh)
    case ",${ONLY}," in *",${n},"*) keep+=("$r") ;; esac
  done
  ROLES=("${keep[@]}")
fi
if [ ${#ROLES[@]} -eq 0 ]; then
  echo "run-roles.sh: no role scripts in ${CS_DIR}/roles (only _template.sh?)" >&2
  exit 1
fi

if [ -n "${CS_TOOL_PATH:-}" ]; then
  PATH="${CS_TOOL_PATH}:${PATH}"
  export PATH
fi

# A full run owns the signals directory; an --only run must not clear the
# barriers of a concurrent run. Freshness (CS_RUN_START) covers both.
[ -z "$ONLY" ] && cs_reset_signals
CS_RUN_START=$(date +%s)
export CS_RUN_START

_cs_client() {
  local n="$1" bin="${2:-$1}" p
  p=$(PATH="${CS_NODE_DIR:+${CS_NODE_DIR}/bin:}${PATH}" command -v "$bin" 2>/dev/null || true)
  if [ -n "$p" ]; then printf '%s=yes ' "$n"; else printf '%s=no ' "$n"; fi
}
echo "========================================"
echo "  Halcyon Robotics: ${#ROLES[@]} roles in parallel"
echo "  Run ID: ${RUN_ID}  Company: ${HAL}"
echo "  State:  ${COMPANY_SIM_STATE_DIR}"
echo "  Barrier timeout ${CS_BARRIER_TIMEOUT}s, role timeout ${ROLE_TIMEOUT}s, run start ${CS_RUN_START}"
_cs_docker() { if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then printf 'docker=yes '; else printf 'docker=no '; fi; }
echo "  Clients: $(_cs_docker)$(_cs_client npm)$(_cs_client cargo)$(_cs_client mvn)$(_cs_client uv)pixi-image=${HAL_CONDA_CLIENT_IMAGE:-unset}"
echo "========================================"

declare -A PIDS=()
for r in "${ROLES[@]}"; do
  n=$(basename "$r" .sh)
  : > "${COMPANY_SIM_STATE_DIR}/checks/${n}.txt"
  timeout "$ROLE_TIMEOUT" bash "$r" > "${COMPANY_SIM_STATE_DIR}/logs/${n}.log" 2>&1 &
  PIDS[$n]=$!
  echo "  started ${n} (pid ${PIDS[$n]})"
done

declare -A RC=()
for n in "${!PIDS[@]}"; do
  if wait "${PIDS[$n]}"; then RC[$n]=0; else RC[$n]=$?; fi
done

MERGED="${COMPANY_SIM_STATE_DIR}/CHECKS.txt"
: > "$MERGED"
failed=0
echo ""
for r in "${ROLES[@]}"; do
  n=$(basename "$r" .sh)
  cat "${COMPANY_SIM_STATE_DIR}/checks/${n}.txt" >> "$MERGED"
done
cat "$MERGED"
echo ""
echo "========================================"
printf '  %-18s %5s %5s %5s %5s  %s\n' role PASS FAIL WARN SKIP exit
for r in "${ROLES[@]}"; do
  n=$(basename "$r" .sh)
  f="${COMPANY_SIM_STATE_DIR}/checks/${n}.txt"
  c() { grep -c "|$1|" "$f" 2>/dev/null || true; }
  rc="${RC[$n]}"
  note=""
  [ "$rc" = "124" ] && note=" (timed out after ${ROLE_TIMEOUT}s)"
  printf '  %-18s %5s %5s %5s %5s  %s%s\n' "$n" "$(c PASS)" "$(c FAIL)" "$(c WARN)" "$(c SKIP)" "$rc" "$note"
  [ "$rc" = "0" ] || failed=$(( failed + 1 ))
done
echo "  merged CHECK lines: ${MERGED}"
echo "  logs: ${COMPANY_SIM_STATE_DIR}/logs/"
echo "========================================"

[ "$failed" -eq 0 ]
