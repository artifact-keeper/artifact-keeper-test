#!/usr/bin/env bash
# selftest-validate-gate-inputs.sh - pins what scripts/validate-gate-inputs.sh
# accepts and refuses.
#
# The validator is the only thing between the release gate's free-text inputs
# and `helm --set` / `git clone --branch`. It fails safe in one direction only:
# loosen a pattern and nothing turns red. This runs it against the values the
# callers really pass (all must be accepted) and against the shapes it exists
# to refuse (all must exit 1). No network, no cluster; well under a second.
#
# Usage: scripts/selftest-validate-gate-inputs.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V="$ROOT/scripts/validate-gate-inputs.sh"
fails=0
DIGEST="sha256:$(printf '0123456789abcdef%.0s' 1 2 3 4)"

# expect <want rc> <label> [VAR=value ...] -- runs the validator in a clean env.
expect() {
  local want="$1" label="$2"; shift 2
  local out rc
  out="$(env -i PATH="$PATH" "$@" bash "$V" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ]; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label: exit $rc, want $want"
    printf '%s\n' "$out" | sed 's/^/        /'
    fails=$((fails + 1))
  fi
}

echo "validate-gate-inputs.sh: values the callers pass are accepted"
expect 0 "release.yml: a stable version and its digest" BACKEND_TAG=1.12.0 BACKEND_DIGEST="$DIGEST" WEB_TAG=latest TEST_SUITE=all
expect 0 "a maintenance version"                       BACKEND_TAG=1.11.13
expect 0 "release-candidate.yml: sha-<short>, iac main" BACKEND_TAG=sha-a94c2fd BACKEND_DIGEST="$DIGEST" IAC_REF=main WEB_TAG=latest TEST_SUITE=all
expect 0 "web docker-publish.yml: compatibility suite"  BACKEND_TAG=latest WEB_TAG=1.11.2 TEST_SUITE=compatibility
expect 0 "mesh-e2e style dev tag"                       BACKEND_TAG=dev
expect 0 "a CLI release tag"                            BACKEND_TAG=1.12.0 CLI_TAG=v1.11.0
expect 0 "a release-line iac ref"                       BACKEND_TAG=1.12.0 IAC_REF=release/1.12.x
expect 0 "another release-line iac ref"                 BACKEND_TAG=sha-abc1234 IAC_REF=release/1.11.x TEST_SUITE=dtf
expect 0 "a prerelease tag"                             BACKEND_TAG=v1.12.0-rc.1
expect 0 "optional inputs empty"                        BACKEND_TAG=1.12.0 WEB_TAG= IAC_REF= CLI_TAG= TEST_SUITE= BACKEND_DIGEST=
expect 0 "a 128-character name"                         BACKEND_TAG="$(printf 'a%.0s' $(seq 128))"

echo "validate-gate-inputs.sh: everything else is refused"
expect 1 "backend_tag missing"
expect 1 "backend_tag empty"                            BACKEND_TAG=
expect 1 "a comma (helm --set list)"                    BACKEND_TAG='1.12.0,backend.x=y'
expect 1 "an = sign"                                    BACKEND_TAG='a=b'
expect 1 "a space"                                      BACKEND_TAG=1.12.0 WEB_TAG='a b'
expect 1 "a leading -- (git option)"                    BACKEND_TAG=1.12.0 IAC_REF='--upload-pack=x'
expect 1 "a leading -"                                  BACKEND_TAG=1.12.0 IAC_REF='-x'
# shellcheck disable=SC2016 # the literal text is the point
expect 1 "command substitution"                         BACKEND_TAG=1.12.0 CLI_TAG='$(id)'
expect 1 "129 characters"                               BACKEND_TAG="$(printf 'a%.0s' $(seq 129))"
expect 1 "an embedded newline"                          BACKEND_TAG=$'1.12.0\nx'
expect 1 "a bad test_suite"                             BACKEND_TAG=1.12.0 TEST_SUITE='all;x'
expect 1 "digest: upper-case hex"                       BACKEND_TAG=1.12.0 BACKEND_DIGEST="sha256:$(printf 'A%.0s' $(seq 64))"
expect 1 "digest: too short"                            BACKEND_TAG=1.12.0 BACKEND_DIGEST=sha256:abc
expect 1 "digest: 65 hex digits"                        BACKEND_TAG=1.12.0 BACKEND_DIGEST="${DIGEST}0"
expect 1 "digest: wrong algorithm"                      BACKEND_TAG=1.12.0 BACKEND_DIGEST="sha512:${DIGEST#sha256:}"

if [ "$fails" -ne 0 ]; then
  echo "validate-gate-inputs.sh: $fails case(s) FAILED"
  exit 1
fi
echo "validate-gate-inputs.sh: all cases passed"
