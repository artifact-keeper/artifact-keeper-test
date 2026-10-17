#!/usr/bin/env python3
"""Build a minimal, valid .gem: a tar of metadata.gz (YAML gemspec) and
data.tar.gz (one lib file). No ruby needed on the runner.

Usage: build_gem.py NAME VERSION OUT_PATH
"""
import gzip
import io
import sys
import tarfile
import time


def tar_member(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def main():
    name, version, out = sys.argv[1], sys.argv[2], sys.argv[3]
    lib = "lib/%s.rb" % name.replace("-", "_")
    gemspec = f"""--- !ruby/object:Gem::Specification
name: {name}
version: !ruby/object:Gem::Version
  version: '{version}'
platform: ruby
authors:
- DTF
bindir: bin
cert_chain: []
date: '2026-01-01'
dependencies: []
description: DTF format-catalog-fixes fixture
email: dtf@example.com
executables: []
extensions: []
extra_rdoc_files: []
files:
- {lib}
homepage: https://example.com
licenses:
- MIT
metadata: {{}}
rdoc_options: []
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubygems_version: 3.5.0
specification_version: 4
summary: DTF fixture gem {name} {version}
test_files: []
""".encode()

    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as data_tar:
        tar_member(data_tar, lib, f"module DtfFixture; VERSION = '{version}'; end\n".encode())

    with tarfile.open(out, mode="w") as gem:
        tar_member(gem, "metadata.gz", gzip.compress(gemspec))
        tar_member(gem, "data.tar.gz", data_buf.getvalue())


if __name__ == "__main__":
    main()
