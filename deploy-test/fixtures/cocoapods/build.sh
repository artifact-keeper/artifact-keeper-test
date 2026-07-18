#!/usr/bin/env bash
# =============================================================================
# fixtures/cocoapods/build.sh — host-craft a minimal CocoaPods pod archive.
# =============================================================================
# The backend's push endpoint (POST /cocoapods/<repo>/pods) scans the uploaded
# tar.gz for any `*.podspec.json` and stores it. The archive here is a real
# (if tiny) pod: a header carrying the marker token, plus a podspec that
# declares it via `source_files`.
#
# Two details matter for a real `pod install` to work end to end:
#   * `source.http` must point at the URL that actually serves the archive, i.e.
#     the AK pods/ route the caller passes in. The client resolves the podspec
#     from the CDN tree but downloads the pod itself from `source`.
#   * the podspec must reference the marker file (`source_files`). CocoaPods
#     runs a cleaner over the downloaded pod and deletes anything no podspec
#     attribute refers to, so an unreferenced marker never reaches Pods/.
#
# args:   <workdir> <name> <version> <marker_token> <source_url>
# stdout: absolute path to the produced .tar.gz (the only thing on stdout)
# =============================================================================
set -euo pipefail
work="$1"; name="$2"; ver="$3"; token="$4"; source_url="$5"

stage="${work}/pod-${name}-${ver}"
rm -rf "$stage"; mkdir -p "$stage"

cat > "${stage}/${name}.h" <<EOF
// ${token}
#import <Foundation/Foundation.h>
@interface ${name} : NSObject
@end
EOF

cat > "${stage}/${name}.podspec.json" <<EOF
{
  "name": "${name}",
  "version": "${ver}",
  "summary": "DTF format-conformance marker pod",
  "homepage": "https://dtf.local/${name}",
  "license": { "type": "MIT" },
  "authors": { "dtf": "dtf@dtf.local" },
  "source": { "http": "${source_url}" },
  "platforms": { "ios": "12.0" },
  "source_files": "*.h"
}
EOF

tgz="${work}/${name}-${ver}.tar.gz"
rm -f "$tgz"
tar czf "$tgz" -C "$stage" .

echo "$tgz"
