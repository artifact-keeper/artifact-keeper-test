#!/usr/bin/env bash
# =============================================================================
# fixtures/cocoapods/build.sh — host-craft a minimal CocoaPods pod archive.
# =============================================================================
# The backend's push endpoint (POST /cocoapods/<repo>/pods) scans the uploaded
# tar.gz for any `*.podspec.json` and stores it. A real pod archive also carries
# the pod sources; for the conformance probe we ship the podspec plus a grep-able
# marker file. name+version are the only required podspec fields.
#
# args:   <workdir> <name> <version> <marker_token>
# stdout: absolute path to the produced .tar.gz (the only thing on stdout)
# =============================================================================
set -euo pipefail
work="$1"; name="$2"; ver="$3"; token="$4"

stage="${work}/pod-${name}-${ver}"
rm -rf "$stage"; mkdir -p "$stage"

cat > "${stage}/${name}.podspec.json" <<EOF
{
  "name": "${name}",
  "version": "${ver}",
  "summary": "DTF format-conformance marker pod",
  "homepage": "https://dtf.local/${name}",
  "license": { "type": "MIT" },
  "authors": { "dtf": "dtf@dtf.local" },
  "source": { "http": "http://backend:8080/cocoapods/PLACEHOLDER/pods/${name}-${ver}.tar.gz" },
  "platforms": { "ios": "12.0" }
}
EOF
printf '%s\n' "$token" > "${stage}/marker.txt"

tgz="${work}/${name}-${ver}.tar.gz"
rm -f "$tgz"
tar czf "$tgz" -C "$stage" .

echo "$tgz"
