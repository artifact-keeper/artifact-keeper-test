#!/usr/bin/env bash
# Rebuild the committed akdep-*.noarch.rpm fixtures (artifact-keeper#3801).
# Built in rockylinux:9 so the payload is readable by the EL9 dnf client the
# test uses. Usage: deploy-test/fixtures/rpm/build.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
docker run --rm -v "${here}:/fx:z" rockylinux:9 bash -ec "
  dnf -y -q install rpm-build >/dev/null
  for s in akdep-lib akdep-app; do
    rpmbuild --define \"_topdir /tmp/rb\" --define \"_buildhost akt-fixture\" \
      --define \"source_date_epoch_from_changelog 0\" -bb /fx/\${s}.spec >/dev/null 2>&1
  done
  cp /tmp/rb/RPMS/noarch/akdep-*.rpm /fx/
  chown $(id -u):$(id -g) /fx/akdep-*.rpm
"
ls -l "${here}"/*.rpm
