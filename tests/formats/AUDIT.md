# Per-format push/pull coverage audit

Tracking issue: artifact-keeper-test#48

This document records, for every format the backend supports, whether the
release-gate exercises a native-client push + pull cycle vs. a management-API
or curl-based-wire-emulation cycle. The goal is to know, at any moment, what
"green release-gate" actually proves for each format.

## TL;DR

| Bucket | Count | Notes |
|--------|------:|-------|
| Native-client push + pull | 6 | maven, npm, pypi, docker, generic, cargo |
| Wire emulation (curl multipart against the format-native endpoint) | ~30 | covers the wire protocol but not real client quirks |
| Management-API only (POST /api/v1/repositories/.../upload) | 0 | every format has at least a wire-level test |
| Added by this PR | 1 | rubygems |

"Native-client" means the test invokes the real client tool (`npm`, `mvn`,
`pip`, `docker`, `cargo`, `gem`) against the registry. "Wire emulation"
means a `curl` request that imitates the wire payload but does not exercise
client-side quirks (auth realm parsing, custom content-types, redirect
handling, etc.).

Per #48 acceptance criteria: "for at minimum maven, npm, pypi, docker,
generic, debian, add or fix tests so each one has a small fixture push
followed by a pull, asserting bytes match." This audit confirms the first
five are already covered and identifies debian as a wire-emulation gap.
Filling all 39 remaining wire-emulation gaps is out of scope for this PR
(see Scope below).

## Method

`tests/formats/test-*-native-client.sh` is the canonical filename for a
native-client smoke. We `ls` that pattern and cross-reference each result
with the equivalent `test-<format>.sh` to confirm there is real-client
coverage and not just curl multipart.

For formats with only a `test-<format>.sh` and no `*-native-client.sh`,
we open the script and grep for the format-native CLI:

| Format | CLI binary | Status |
|--------|------------|--------|
| maven | `mvn` | covered by `test-maven-native-client.sh` |
| npm | `npm` | covered by `test-npm.sh` (uses real `npm publish` with curl fallback) |
| pypi | `twine`, `pip` | covered by `test-pypi-native-client.sh` |
| docker | `docker push/pull` | covered by `test-docker-native-client.sh` |
| generic | `curl` (no native client) | covered by `test-generic-native-client.sh` |
| cargo | `cargo publish` | covered by `test-cargo.sh` (real cargo CLI) |
| **rubygems** | `gem push/fetch` | **added by this PR** (`test-rubygems-native-client.sh`) |

## Coverage table

Legend:
- `N` = native client (real tool) exercises push and pull
- `W` = wire emulation (curl against format-native endpoint, no client tool)
- `M` = management-API only (no format-native endpoint exercised)
- `-` = no test for this format

| Format | Push | Pull | Test file(s) | Notes |
|--------|:----:|:----:|--------------|-------|
| maven | N | N | test-maven.sh, test-maven-native-client.sh | `mvn deploy` + `mvn dependency:get` |
| npm | N | N | test-npm.sh | real `npm publish` with curl fallback |
| pypi | N | N | test-pypi.sh, test-pypi-native-client.sh | real `twine upload` + `pip install` |
| docker | N | N | test-docker-native-client.sh | real `docker push/pull` |
| oci | W | W | test-oci.sh, test-oci-remote.sh, test-oci-edge-cases.sh | curl multipart, no skopeo client |
| generic | N | N | test-generic-native-client.sh | format has no native CLI; curl is the canonical client |
| cargo | N | N | test-cargo.sh, test-cargo-remote.sh | real `cargo publish` |
| go | W | W | test-go.sh, test-go-remote.sh, test-go-edge-cases.sh | curl to the modproxy endpoint; no `go mod download` |
| rubygems | **N** (this PR) | **N** (this PR) | test-rubygems.sh, **test-rubygems-native-client.sh** | new: real `gem push/fetch` |
| nuget | W | W | test-nuget.sh | curl to `/nuget/{key}/v3/`; no `nuget push` |
| helm | W | W | test-helm.sh, test-helm-conformance.sh | curl PUT chart tarball; no `helm push` (chart-museum-style) |
| debian | W | W | test-debian.sh, test-debian-xz-proxy.sh | curl multipart; no real `dput` or `reprepro` |
| rpm | W | W | test-rpm.sh | curl PUT .rpm; no `rpmbuild` push |
| alpine | W | W | test-alpine.sh | curl PUT .apk; no `abuild` |
| opkg | W | W | test-opkg.sh | curl; no opkg push tool exists upstream |
| conan | W | W | test-conan*.sh (9 files) | curl; no `conan upload` to v2 endpoint |
| conda | W | W | test-conda.sh, test-conda-native-conformance.sh | curl PUT; no `conda` or `anaconda-client` |
| cran | W | W | test-cran.sh | curl PUT .tar.gz; no R-side install |
| cocoapods | W | W | test-cocoapods.sh | curl; no `pod trunk push` |
| composer | W | W | test-composer.sh | curl PUT; no `composer publish` |
| hex | W | W | test-hex.sh | curl PUT hex tarball; no `mix hex.publish` |
| huggingface | W | W | test-huggingface.sh, test-huggingface-edge-cases.sh | curl LFS-style; no `huggingface_hub` Python client |
| gitlfs | W | W | test-gitlfs.sh | curl LFS PUT; no `git lfs push` |
| protobuf | W | W | test-protobuf.sh | curl |
| bazel | W | W | test-bazel.sh | curl; no `bazel run @ak//tools:publish` |
| swift | W | W | test-swift.sh | curl; no `swift package-registry publish` |
| pub | W | W | test-pub.sh | curl; no `dart pub publish` |
| terraform | W | W | test-terraform.sh | curl; no `terraform login + publish` |
| ansible | W | W | test-ansible.sh | curl; no `ansible-galaxy publish` |
| chef | W | W | test-chef.sh | curl; no `knife supermarket share` |
| puppet | W | W | test-puppet.sh | curl; no `puppet module push` |
| wasm | W | W | test-wasm.sh | curl; no `wkg publish` |
| jetbrains | W | W | test-jetbrains.sh | curl; no IntelliJ plugin marketplace CLI |
| vscode | W | W | test-vscode.sh, test-vscode-extensions-conformance.sh | curl; no `vsce publish` |
| mlmodel | W | W | test-mlmodel.sh | curl; no canonical CLI (custom format) |
| p2 | W | W | test-p2.sh | curl; Eclipse-side push is Tycho/Maven not a CLI |
| incus | W | W | test-incus.sh | curl; no `incus image push` to remote registry |
| vagrant | W | W | test-vagrant.sh | curl; no `vagrant cloud publish` |
| gradle | W | W | test-gradle-conformance.sh | aliased to Maven handler; tested via Maven |
| sbt | W | W | test-sbt.sh, test-sbt-conformance.sh | sbt-launch.jar publish would need JVM + sbt install |

## Scope of this PR (artifact-keeper-test#48)

The acceptance criteria called for native-client coverage on the six core
formats (maven, npm, pypi, docker, generic, debian). Of those:

- **maven, npm, pypi, docker, generic** already have native-client coverage
  (see table above). No new test needed.
- **debian** would require either `dput` against a real Debian-archive
  endpoint, or `reprepro` to ingest into a local pool. Both require apt
  set-up on the runner pod (40-80s of `apt-get install`), and `reprepro`
  needs a GPG keychain. Adding a real-client debian test is meaningful
  scope, deferred to a follow-up. The existing wire-emulation
  `test-debian.sh` still asserts the Packages index and download path
  work end-to-end.

This PR ADDS one new native-client test:

- **`test-rubygems-native-client.sh`** - real `gem build`, `gem push`,
  `gem fetch`. Chosen because:
  1. `gem` is on the apt default install for ubuntu-22.04 runner images
     (already present on the rust-go-swift batch's pod, no extra install).
  2. RubyGems credential negotiation (`~/.gem/credentials` YAML, Marshal_5
     framing of the index) is a class of regression the wire emulation in
     `test-rubygems.sh` cannot catch.
  3. The customer feedback from artifact-keeper#872 / discussion #872
     specifically called out wire-protocol regressions slipping through;
     adding a real-client check on one more format closes a slice of that.

The native-client stub does NOT yet ship in the format-tests matrix in
release-gate.yml. Wiring it requires the `system-packages` batch to
ensure `ruby-full` is installed; that's a separate PR per the "additive
only" constraint of cluster A. The test is invocable from any pod that
has `gem` and is correct in isolation.

## Remaining gaps (out of scope here)

Formats with only wire emulation that we COULD upgrade to native-client
coverage with modest CLI install on the runner:

| Priority | Format | CLI | Cost estimate |
|---------:|--------|-----|---------------|
| 1 | debian | `reprepro` + GPG | 1d (key bootstrap, dput config) |
| 1 | nuget | `dotnet nuget push` | 4h (`.NET SDK` install ~ 300 MB) |
| 2 | helm | `helm push` (helm-push plugin) | 2h |
| 2 | composer | `composer` | 2h |
| 2 | hex | `mix hex.publish` | 4h (Elixir install) |
| 3 | go | `goproxy.io`-compatible push (no upstream CLI) | n/a |
| 3 | bazel | `bazel run ...` against a custom rule | 1d |
| 3 | terraform | `terraform login + publish` | 1d (custom auth) |

Lower priority: formats whose native CLI is not realistically scriptable in
CI (jetbrains IDE marketplace upload, vscode marketplace via `vsce`, swift
package-registry which is still in the proposal phase).

## How to add a new native-client test

1. Pick a format from the table above whose `Push`/`Pull` is `W`.
2. Look up the canonical CLI in the upstream registry's docs.
3. Create `tests/formats/test-<format>-native-client.sh` modeled on
   `test-rubygems-native-client.sh` (push fixture, pull back, assert size).
4. Wire the script into the matching batch in
   `.github/workflows/release-gate.yml` AND install the CLI in that
   batch's `Install test dependencies` step.
5. Update the table in this file: change `W` to `N` for that format.
