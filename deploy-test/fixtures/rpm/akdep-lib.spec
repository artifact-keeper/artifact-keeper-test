# artifact-keeper#3801 fixture: a library package that Provides a virtual
# capability. akdep-app Requires that capability, so a client can only install
# akdep-app if the served primary.xml carries <rpm:provides>/<rpm:requires>.
Name:      akdep-lib
Version:   1.0
Release:   1
Summary:   artifact-keeper E2E dependency fixture (provider)
License:   MIT
BuildArch: noarch
Provides:  akdep-libfoo = 1.0

%description
Provides the akdep-libfoo capability for the artifact-keeper RPM dependency
metadata test (artifact-keeper#3801).

%install
mkdir -p %{buildroot}/usr/share/akdep-lib
echo "akdep-libfoo 1.0" > %{buildroot}/usr/share/akdep-lib/VERSION

%files
/usr/share/akdep-lib/VERSION
