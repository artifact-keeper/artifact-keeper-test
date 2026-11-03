#!/usr/bin/env bash
# test-cli-smoke.sh - The released `ak` CLI against the candidate backend.
#
# The CLI's own E2E tests pin a backend release, so a candidate can break `ak`
# with nothing noticing until users upgrade. This installs `ak` the documented
# way and runs the everyday flow: doctor, repo create/list/show, artifact push
# and pull with a byte comparison, repo delete.
#
# Non-blocking in release-gate.yml for now: see the comment on the cli-smoke job.
#
# Required env:
#   BASE_URL   - Backend service URL
#   ADMIN_PASS - Bootstrap admin password
#   RUN_ID     - Unique run identifier
# Optional env:
#   CLI_TAG    - CLI release to test, such as v1.11.0 (default: the latest)
#   AK_BIN     - Use this binary and skip the install (for running this locally)

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "cli-smoke"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq

REPO_KEY="cli-smoke-${RUN_ID}"
OUT="${WORK_DIR}/out.txt"

# Keep ak away from anything else on the runner.
export HOME="${WORK_DIR}/home"
export AK_CONFIG_DIR="${HOME}/ak"
export XDG_CONFIG_HOME="${HOME}/.config"
export AK_CREDENTIAL_STORE=file
export AK_NO_INPUT=true
export NO_COLOR=1
mkdir -p "$AK_CONFIG_DIR"

# The backend is plain HTTP inside the cluster.
export AK_ALLOW_INSECURE_HTTP=1
export AK_TOKEN="$ADMIN_TOKEN"

begin_test "Install ak"
if [ -n "${AK_BIN:-}" ]; then
  AK="$AK_BIN"
else
  AK="${WORK_DIR}/bin/ak"
  version_args=()
  if [ -n "${CLI_TAG:-}" ]; then version_args=(--version "$CLI_TAG"); fi
  # shellcheck disable=SC2312
  curl -fsSL --retry 3 https://raw.githubusercontent.com/artifact-keeper/artifact-keeper-cli/main/install.sh \
    | sh -s -- --install-dir "${WORK_DIR}/bin" "${version_args[@]}" > "$OUT" 2>&1 \
    || fail_fatal "install.sh failed: $(tail -5 "$OUT")"
fi
if "$AK" --version > "$OUT" 2>&1; then
  echo "  $(cat "$OUT")"
  pass
else
  fail_fatal "ak --version failed: $(cat "$OUT")"
fi

# run <description> <ak args...>: pass on exit 0, and leave the output in $OUT.
run() {
  local description="$1"
  shift
  begin_test "$description"
  if "$AK" "$@" > "$OUT" 2>&1; then
    pass
  else
    fail "ak $* exited $?: $(tail -20 "$OUT")"
  fi
}

run "ak instance add" instance add gate "$BASE_URL"

run "ak doctor" doctor
begin_test "ak doctor supports this server"
if grep -q "is unsupported by ak" "$OUT"; then
  fail "$(grep "is unsupported by ak" "$OUT")"
else
  pass
fi

run "ak repo create" repo create "$REPO_KEY" --pkg-format generic

run "ak repo list" repo list --format json
begin_test "ak repo list shows the repository"
if grep -q "\"${REPO_KEY}\"" "$OUT"; then pass; else fail "$REPO_KEY not in: $(head -c 300 "$OUT")"; fi

run "ak repo show" repo show "$REPO_KEY" --format json
begin_test "ak repo show names the repository"
if grep -q "\"${REPO_KEY}\"" "$OUT"; then pass; else fail "$REPO_KEY not in: $(head -c 300 "$OUT")"; fi

head -c 4096 /dev/urandom > "${WORK_DIR}/payload.bin"
run "ak artifact push" artifact push "$REPO_KEY" "${WORK_DIR}/payload.bin" --path smoke/payload.bin
run "ak artifact pull" artifact pull "$REPO_KEY" smoke/payload.bin -o "${WORK_DIR}/pulled.bin"
begin_test "Pulled bytes match pushed bytes"
if cmp -s "${WORK_DIR}/payload.bin" "${WORK_DIR}/pulled.bin"; then pass; else fail "pulled file differs"; fi

# A 1.12 backend answers 202 and deletes in the background. ak before 1.11 fails on that.
run "ak repo delete" repo delete "$REPO_KEY" --yes

end_suite
