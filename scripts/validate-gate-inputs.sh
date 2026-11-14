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
# and mesh-tests and teardown, which run under `always()`.
#
# Inputs (environment; empty means "not supplied" where the input is optional):
#   BACKEND_TAG     required name
#   WEB_TAG         name
#   IAC_REF         name
#   CLI_TAG         name, or empty for the latest release
#   TEST_SUITE      name
#   BACKEND_DIGEST  sha256:<64 hex>, or empty for tag-only
#
# Exits 1 naming every value that is refused. Values are never echoed back.
set -uo pipefail

NAME_RE='^[A-Za-z0-9._/-]{1,128}$'
DIGEST_RE='^sha256:[0-9a-f]{64}$'
bad=0

check() { # check <input name> <value> <regex> <allow empty: 0|1>
  local name="$1" value="$2" re="$3" empty_ok="$4"
  if [[ -z "$value" && "$empty_ok" == 1 ]]; then return 0; fi
  # A leading '-' would be read as an option by git and helm.
  if [[ "$value" =~ $re && "$value" != -* ]]; then return 0; fi
  if [[ "$re" == "$NAME_RE" ]]; then
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

if [[ "$bad" -ne 0 ]]; then
  exit 1
fi
echo "release-gate inputs: all names and digests are well-formed"
