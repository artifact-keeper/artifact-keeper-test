# =============================================================================
# fixtures/conan/conanfile.py — minimal Conan 2 recipe for the marker package
# =============================================================================
# A dependency-free "binary" package whose payload is a single grep-able marker
# file. There is NO build step (the marker is written in package()), but the
# recipe DOES declare os/arch/build_type/compiler settings so `package_id` is
# settings-dependent. That is what makes the `--build=never` consume a real
# test: the pre-built binary for the create-time profile must be uploaded to
# and fetched from AK, and the `package_id_binary` edge case (install under a
# DIFFERENT profile with `--build=never`) must FAIL missing-binary rather than
# silently matching a wildcard.
#
# The marker is copied to share/dtf-marker/marker.txt inside the package folder
# so the plugin's fc_assert can prove the REAL client actually downloaded and
# unpacked the binary from AK (not merely that /latest listed a revision).
# =============================================================================
import os

from conan import ConanFile
from conan.tools.files import save


class DtfMarkerConan(ConanFile):
    name = "dtf-marker"
    version = "1.0"
    settings = "os", "arch", "compiler", "build_type"
    # A marker string the plugin greps for after `conan install` unpacks the
    # binary package fetched from AK. Bump in lockstep with the plugin token.
    MARKER = "DTF-CONAN-INSTALLED-1.0"

    def build(self):
        # No compilation: the package is a single data file.
        pass

    def package(self):
        save(
            self,
            os.path.join(self.package_folder, "share", "dtf-marker", "marker.txt"),
            self.MARKER + "\n",
        )

    def package_info(self):
        # Header/data-only: nothing to link.
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
