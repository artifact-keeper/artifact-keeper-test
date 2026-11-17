#!/usr/bin/env bash
# validate-gate-inputs.sh - refuse a release-gate run whose inputs are not
# plain names or digests.
#
# The gate's inputs are free text on both paths (workflow_dispatch and
# workflow_call). They reach `helm --set backend.image.tag=...`,
# `git clone --branch ...`, image references and API URLs. Helm --set splits
# on commas and treats `=` and `[` specially, and git reads a leading `-` as an
# option, so a value outside these shapes changes what those commands do rather
# than failing them. This runs before anything consumes a value, in
# version-set-integrity (which every cluster job depends on) and in the jobs
# that read an input without depending on it succeeding: build-dtf-probes,
# and teardown, which runs under `always()`.
#
# Inputs (environment; empty means "not supplied" where the input is optional):
#   BACKEND_TAG     required name
#   WEB_TAG         name
#   IAC_REF         name
#   CLI_TAG         name, or empty for the latest release
#   TEST_SUITE      name
#   BACKEND_DIGEST  sha256:<64 hex>, or empty for tag-only
#   SCANNER_ADAPTER_TAG  an image tag (no '/'), or empty for backend_tag
#   SCANNER_ADAPTER_DIGEST  sha256:<64 hex>, or empty for tag-only; needs
#                   SCANNER_ADAPTER_TAG (a digest pins a tag, it names no
#                   adapter on its own) (artifact-keeper-test#380)
#   GATE_ONLY_JOBS  the only_jobs input: empty for the full gate, else gate job
#                   ids and dtf-gate/<group> tokens separated by single spaces
#                   (artifact-keeper-test#830). Whether each token names a real
#                   job is scripts/gate-selection.sh's question; this checks
#                   only the shape, because the value reaches `if:` expressions
#                   and a log line.
#   GATE_TESTS_SHA  the tests_sha input: empty, or a full 40-hex commit
#
# The two GATE_* values come from the workflow-level env, so every job that
# runs this validator checks them without its step having to pass them.
#
# Exits 1 naming every value that is refused. Values are never echoed back.
set -uo pipefail

NAME_RE='^[A-Za-z0-9._/-]{1,128}$'
DIGEST_RE='^sha256:[0-9a-f]{64}$'
# An image tag, as the scanner-adapter tag is used: ghcr.io/...:<tag>.
TAG_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
SHA_RE='^[0-9a-f]{40}$'
# One token: a job id, or dtf-gate/<group>. Lower case only: the selection is
# matched with contains(), which ignores case, so upper case would be a second
# spelling of the same job.
TOKEN_RE='[a-z0-9][a-z0-9-]{0,63}(/[a-z0-9][a-z0-9.-]{0,63})?'
ONLY_RE="^${TOKEN_RE}( ${TOKEN_RE})*\$"
bad=0

check() { # check <input name> <value> <regex> <allow empty: 0|1>
  local name="$1" value="$2" re="$3" empty_ok="$4"
  if [[ -z "$value" && "$empty_ok" == 1 ]]; then return 0; fi
  # A leading '-' would be read as an option by git and helm.
  if [[ "$value" =~ $re && "$value" != -* ]]; then return 0; fi
  if [[ "$re" == "$NAME_RE" || "$re" == "$TAG_RE" || "$re" == "$ONLY_RE" ]]; then
    echo "::error title=Invalid release-gate input::${name} must match ${re} and must not start with '-'." >&2
  else
    echo "::error title=Invalid release-gate input::${name} must match ${re}." >&2
  fi
  bad=1
}

check backend_tag    "${BACKEND_TAG-}"    "$NAME_RE"   0
check web_tag        "${WEB_TAG-}"        "$NAME_RE"   1
check iac_ref        "${IAC_REF-}"        "$NAME_RE"   1
check cli_tag        "${CLI_TAG-}"        "$NAME_RE"   1
check test_suite     "${TEST_SUITE-}"     "$NAME_RE"   1
check backend_digest "${BACKEND_DIGEST-}" "$DIGEST_RE" 1
check scanner_adapter_tag "${SCANNER_ADAPTER_TAG-}" "$TAG_RE" 1
check scanner_adapter_digest "${SCANNER_ADAPTER_DIGEST-}" "$DIGEST_RE" 1
if [[ -n "${SCANNER_ADAPTER_DIGEST-}" && -z "${SCANNER_ADAPTER_TAG-}" ]]; then
  echo "::error title=Invalid release-gate input::scanner_adapter_digest needs scanner_adapter_tag: the digest pins the adapter the tag names." >&2
  bad=1
fi
check tests_sha      "${GATE_TESTS_SHA-}" "$SHA_RE"    1
check only_jobs      "${GATE_ONLY_JOBS-}" "$ONLY_RE"   1
only_jobs="${GATE_ONLY_JOBS-}"
if [[ ${#only_jobs} -gt 4096 ]]; then
  echo "::error title=Invalid release-gate input::only_jobs is longer than 4096 characters." >&2
  bad=1
fi

if [[ "$bad" -ne 0 ]]; then
  exit 1
fi
echo "release-gate inputs: all names and digests are well-formed"
