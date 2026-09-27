# artifact-keeper#3801 fixture: an application package that Requires the
# akdep-libfoo capability provided only by akdep-lib.
Name:      akdep-app
Version:   2.0
Release:   1
Summary:   artifact-keeper E2E dependency fixture (consumer)
License:   MIT
BuildArch: noarch
Requires:  akdep-libfoo >= 1.0

%description
Requires the akdep-libfoo capability for the artifact-keeper RPM dependency
metadata test (artifact-keeper#3801).

%install
mkdir -p %{buildroot}/usr/share/akdep-app
echo "akdep-app 2.0" > %{buildroot}/usr/share/akdep-app/VERSION

%files
/usr/share/akdep-app/VERSION
