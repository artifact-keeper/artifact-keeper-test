#!/usr/bin/env bash
# switch-tests-ref.sh - run the gate's suite from the tests ref that matches
# the candidate's release line.
#
# release-candidate.yml calls release-gate.yml@main, and every job in it checks
# this repository out at main. That is right for a candidate cut from the
# backend's main and wrong for a maintenance release: main's suite keeps
# gaining companion tests for features a release/X.Y.x line never receives,
# and the v1.10.2 candidate (artifact-keeper#4350) failed ten suites on tests
# for 1.11 features (anonymous principals, login-IP audit rows, quarantine
# release windows, storage-integrity tiers).
#
# This step runs right after the checkout in every job. It reads the
# candidate's version from Cargo.toml at the sha the backend tag names, and if
# this repository has a release/X.Y.x branch for that line, moves the working
# tree to it. No such branch -- the normal case for a main candidate -- leaves
# the checkout on main. Only the working tree moves; the workflow already
# running is main's copy, which is what the certification record names.
#
# Inputs (environment):
#   BACKEND_TAG   sha-<short>  (what release-candidate.yml passes), or X.Y.Z
#   BACKEND_REPO  owner/name of the backend (default artifact-keeper/artifact-keeper)
#   GH_TOKEN      optional; raises the API rate limit for the one Cargo.toml read
set -euo pipefail

BACKEND_TAG="${BACKEND_TAG:?BACKEND_TAG is required}"
BACKEND_REPO="${BACKEND_REPO:-artifact-keeper/artifact-keeper}"
API="https://api.github.com/repos/${BACKEND_REPO}/contents/Cargo.toml"

note() { echo "switch-tests-ref: $*"; }

version=""
case "$BACKEND_TAG" in
  sha-*)
    sha="${BACKEND_TAG#sha-}"
    auth=()
    if [[ -n "${GH_TOKEN:-}" ]]; then auth=(-H "Authorization: Bearer ${GH_TOKEN}"); fi
    if toml=$(curl -fsSL --retry 3 "${auth[@]}" -H 'Accept: application/vnd.github.raw' "${API}?ref=${sha}"); then
      version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' <<<"$toml" | head -1)
      [[ -n "$version" ]] || note "Cargo.toml at ${sha} has no workspace version line; staying on main"
    else
      note "could not read Cargo.toml at ${sha} from ${BACKEND_REPO}; staying on main"
    fi
    ;;
  v[0-9]*|[0-9]*)
    version="${BACKEND_TAG#v}"
    ;;
  *)
    note "backend tag '${BACKEND_TAG}' names no version; staying on main"
    ;;
esac
[[ -n "$version" ]] || exit 0

if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+ ]]; then
  note "version '${version}' is not X.Y.Z; staying on main"
  exit 0
fi
branch="release/${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.x"

if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
  git fetch --quiet --depth 1 origin "$branch"
  git checkout --quiet --detach FETCH_HEAD
  short=$(git rev-parse --short HEAD)
  note "candidate is ${version}: running the suite from ${branch} @ ${short}"
  echo "::notice title=Tests ref::candidate ${version} is gated by ${branch} @ ${short}, not main"
else
  note "candidate is ${version}: this repository has no ${branch}; running the suite from main"
fi
