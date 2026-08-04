# Conformance Corpus — Attribution & License Ledger

The conformance corpus learns from open-source clients, registries, and specs.
We take attribution seriously: every source we learn from is credited here and
in the file that uses it, and we respect each project's license.

## What "learn from" means, and our license discipline

We distinguish three kinds of reuse, because they carry different obligations:

1. **Pattern / approach** (an idea, a test design). Ideas are not copyrightable,
   but we credit them anyway as a matter of good practice. Example: the
   variant-route mock-server design in `mock_pypi_conf.py`, modeled on uv's
   `pypi_proxy.rs`. No code copied.
2. **Behavior / assertion** (what a client checks a registry does). Facts about
   a protocol are not copyrightable; we re-derive the check and cite the source
   in the scenario's `source` field.
3. **Vendored material** (actual fixture bytes or code copied in). This is the
   only kind with hard license obligations. We only vendor from permissive
   licenses (MIT / Apache-2.0 / BSD), and when we do we copy the upstream
   LICENSE alongside the material and note it here. We do **not** copy code or
   fixtures from copyleft (GPL/LGPL) projects — for those we re-derive behavior
   only (kind 2).

Every scenario JSON carries a `source:` field naming the origin and its
license. Every fixture/mock file carries an ATTRIBUTION header.

## Sources in this slice (pypi + oci)

| Source | Project | License | How we use it | Kind |
|---|---|---|---|---|
| `crates/uv-test/src/pypi_proxy.rs` | astral-sh/uv | Apache-2.0 OR MIT | mock variant-route pattern; several pypi scenarios (relative URL, advertised-404, upload-time) | 1, 2 |
| Simple Repository API | PyPA / PEPs 503, 691, 592, 658, 714, 700, 740, 792 | PEPs (public spec) | the pypi completeness checklist | spec |
| pip test suite | pypa/pip | MIT | scenario ideas (yanked, metadata) | 2 |
| distribution-spec `conformance/` | opencontainers/distribution-spec | Apache-2.0 | adopted and run unmodified (`oci-conformance` tier) | run-as-is |
| OCI image-spec | opencontainers/image-spec | Apache-2.0 | manifest/index shapes | spec |

## Planned sources (roadmap formats — recorded now so credit is not forgotten)

| Source | Project | License | Intended use | Kind |
|---|---|---|---|---|
| npm CLI test suite | npm/cli | Artistic-2.0 | npm scenario ideas | 2 |
| pacote | npm/pacote | ISC | packument/tarball/integrity behaviors | 2 |
| nub | nubjs/nub | MIT | npm client vectors; may vendor fixtures | 1, 2, (3) |
| verdaccio | verdaccio/verdaccio | MIT | npm registry conformance behaviors; may vendor fixtures | 2, (3) |
| conda test data | conda/conda, conda-forge | BSD-3-Clause | conda channel/repodata scenarios; may vendor | 2, (3) |
| cargo testsuite | rust-lang/cargo | Apache-2.0 OR MIT | cargo registry-protocol scenarios | 2 |
| createrepo_c / dnf | rpm-software-management | GPL-2.0+ | rpm repodata **behaviors only** (no vendoring) | 2 |
| apt test/integration | Debian apt | GPL-2.0+ | deb repo **behaviors only** (no vendoring) | 2 |

Note the deliberate asymmetry: MIT/Apache/BSD sources (uv, nub, verdaccio,
cargo, conda) may contribute vendored fixtures with their LICENSE preserved;
GPL sources (dnf, apt, createrepo_c) contribute re-derived behaviors only.

## Adding a source

When you harvest from a new project: add a row here, put its license in the
row, add an ATTRIBUTION header to any file that embodies it, and set the
`source:` field on every scenario derived from it. If you vendor bytes, also
copy the upstream LICENSE into the fixture directory.
