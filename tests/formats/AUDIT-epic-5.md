# Epic 5 Format/Test Mismatch Audit

Tracking issue: artifact-keeper-test#71

This document grounds the gap-analysis claims about handler/test mismatches by
inspecting the `release/1.1.x` backend at `/tmp/ak-1.1.x-analysis` and the
`main` branch of this test repo. It is descriptive, not prescriptive.

## TL;DR

The original gap analysis conflated two distinct artifacts in the backend:

1. The `FormatHandler` trait in `backend/src/formats/*.rs` (parse_metadata,
   validate, generate_index). Every format in the matrix has one of these,
   including mlmodel, opkg, p2, vagrant, and jetbrains.
2. HTTP handler/router modules in `backend/src/api/handlers/*.rs`. Only
   formats with a native wire protocol have these. mlmodel, opkg, p2 and
   vagrant do not have a dedicated HTTP handler module; jetbrains does.

So none of these handlers are missing in the trait sense, and only one
(`/jetbrains`) is wired as a native-protocol HTTP route. The rest are reachable
either via the WASM proxy at `/ext/{format_key}/{repo_key}/...` (when a WASM
plugin is loaded), or via the generic artifact API at
`/api/v1/repositories/{key}/artifacts/{path}`. The conformance tests already
take the second path; the basic tests take the first and skip cleanly when no
plugin is loaded.

Gradle is fully aliased onto the Maven handler at the repo-resolution layer.
There is no separate `/gradle/...` route; Gradle repos are addressed via
`/maven/{gradle-repo-key}/...`. There is no Gradle-specific E2E test in the
repo today.

## CI status

A separate gap surfaced while writing this audit: the 40 `*-conformance.sh`
scripts in `tests/formats/` are not invoked by any GitHub Actions workflow.
Before this PR, neither `.github/workflows/format-tests.yml` nor
`.github/workflows/release-gate.yml` referenced any of them. They run only
when invoked locally.

This PR wires `test-gradle-conformance.sh` into the `jvm` batch in both
workflows (added by the DevOps agent in parallel to this audit). That covers
the gradle-specific gap called out below.

The remaining 39 conformance scripts are still orphaned from CI. They are
not exercised by PR checks or by the release gate. That is a separate gap,
tracked as a follow-up issue (see Remediation options below). It is out of
scope for this PR.

## Method

### Backend evidence (`/tmp/ak-1.1.x-analysis/backend`)

- `src/formats/` directory listing shows individual files for every format in
  the matrix:
  - `jetbrains_plugins.rs`
  - `mlmodel.rs`
  - `opkg.rs`
  - `p2.rs`
  - `vagrant.rs`
  Each implements `FormatHandler` (parse_path/parse_metadata, validate,
  generate_index). These are domain logic, not HTTP routes.
- `src/formats/mod.rs` registers all of these in both `get_core_handler`
  (string keyed) and `get_handler_for_format` (enum keyed). All five are
  reachable from the format registry.
- `src/api/handlers/mod.rs` declares HTTP handler modules. Of the formats in
  scope, only `jetbrains` is declared. There is no `mlmodel`, `opkg`, `p2`,
  `vagrant`, or `gradle` HTTP handler module.
- `src/api/routes.rs` mounts the format-routing tree. Only `/jetbrains` is
  mounted from this group. Native-protocol routes for mlmodel, opkg, p2,
  vagrant, gradle are not mounted because the modules do not exist.
- `src/api/handlers/wasm_proxy.rs` mounts `/ext` and dispatches
  `/ext/:format_key/:repo_key/*path` to whichever WASM plugin is loaded for
  that format key. This is the only path through which mlmodel, opkg, p2,
  vagrant can serve native protocols.
- `src/api/handlers/maven.rs` line 47:
  `proxy_helpers::resolve_repo_by_key(db, repo_key, &["maven", "gradle"], "a Maven")`.
  Repos created with `format=gradle` are resolvable through `/maven/{key}/...`.
- `src/formats/mod.rs::get_handler_for_format` line 197:
  `RepositoryFormat::Maven | RepositoryFormat::Gradle => MavenHandler::new()`.
  Confirms the alias at the trait layer too.
- The generic artifact API is mounted at `/api/v1/repositories/:key/artifacts`
  and `/api/v1/repositories/:key/download/*path` (see
  `src/api/handlers/repositories.rs` lines 117 to 130). Any repo regardless of
  format can store and serve files through this API.

### Test repo evidence (`tests/formats/`)

- `test-jetbrains.sh` and `test-jetbrains-conformance.sh` hit
  `${BASE_URL}/jetbrains/${REPO_KEY}/...`.
- `test-mlmodel.sh` hits `${BASE_URL}/ext/mlmodel/${REPO_KEY}/...` and skips
  if it gets a 404 on the probe. `test-mlmodel-conformance.sh` uses
  `/api/v1/repositories/{key}/artifacts/{path}` instead.
- `test-opkg.sh` hits `${BASE_URL}/ext/opkg/${REPO_KEY}/...` for upload and
  `${BASE_URL}/ext/opkg/${REPO_KEY}/Packages` for the index, with a similar
  WASM-availability probe and skip. `test-opkg-conformance.sh` notes
  explicitly `OPKG does not have a dedicated native handler with custom
  routes` and uses the generic API.
- `test-p2.sh` and `test-vagrant.sh` follow the same pattern as opkg and
  mlmodel (probe `/ext/{format}/{repo}/`, skip on 404, otherwise upload).
  Conformance versions use the generic API and explicitly note the lack of a
  native handler.
- No `test-gradle*.sh` files exist.

## Per-format verdict

| Format | Trait handler? | API handler module? | Route mounted? | Native test file? | Test endpoint matches? | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| jetbrains_plugins | yes (`formats/jetbrains_plugins.rs`) | yes (`api/handlers/jetbrains.rs`) | yes (`/jetbrains` in `routes.rs`) | yes (`test-jetbrains.sh`, `test-jetbrains-conformance.sh`) | yes, both target `/jetbrains/{repo_key}/...` | works |
| mlmodel | yes (`formats/mlmodel.rs`) | no | no native route; reachable via `/ext/mlmodel/...` only when WASM plugin loaded | yes (`test-mlmodel.sh`, `test-mlmodel-conformance.sh`) | basic test targets `/ext/mlmodel/...` and skips on 404; conformance test targets generic `/api/v1/repositories/{key}/artifacts/{path}` | basic test conditionally works (depends on WASM plugin); conformance works against generic API. Not an orphan; not full-coverage either. |
| opkg | yes (`formats/opkg.rs`) | no | no native route; `/ext/opkg/...` only when WASM plugin loaded | yes (`test-opkg.sh`, `test-opkg-conformance.sh`) | basic test targets `/ext/opkg/...` and skips on 404; conformance targets generic API | same as mlmodel: conditional native, generic-API conformance is exercised |
| p2 | yes (`formats/p2.rs`) | no | no native route; `/ext/p2/...` only when WASM plugin loaded | yes (`test-p2.sh`, `test-p2-conformance.sh`) | basic test targets `/ext/p2/...` and skips on 404; conformance targets generic API | same pattern: conditional native, generic-API conformance is exercised |
| vagrant | yes (`formats/vagrant.rs`) | no | no native route; `/ext/vagrant/...` only when WASM plugin loaded | yes (`test-vagrant.sh`, `test-vagrant-conformance.sh`) | basic test targets `/ext/vagrant/...` and skips on 404; conformance targets generic API | same pattern: conditional native, generic-API conformance is exercised |
| gradle | aliased onto Maven trait handler (`formats/maven.rs` via `mod.rs`) | aliased onto `api/handlers/maven.rs` (accepts `gradle` as a repo format at the resolver) | yes, addressable through `/maven/{repo_key}/...` for repos with `format=gradle` | partial: `test-gradle-conformance.sh` added in this PR, curl-based only | partial: targets `/maven/{repo_key}/...` against a `format=gradle` repo via curl + Basic auth. Does not invoke the `gradle` CLI, so it cannot catch failures that only manifest with Gradle's real HTTP client (User-Agent gating, `.module` discovery semantics, variant selection). | partial coverage: alias resolution path is exercised; native-client behaviour is not. A native-client follow-up test is recommended (parallel to `test-maven-native-client.sh`). |

Legend for the Verdict column:

- **works**: handler exists, is routed, and tests target the matching endpoint.
- **conditional native**: native protocol is only available when a WASM
  plugin for that format is loaded. The test probes for it and skips
  cleanly. Not strictly an orphan, but the native protocol is uncovered when
  no plugin is loaded.
- **generic-API conformance is exercised**: the conformance test exists and
  uses `/api/v1/repositories/{key}/artifacts/{path}`, which works for any
  format.
- **test-but-no-coverage**: the format works in the backend but no test
  exercises it from this repo.
- **partial coverage**: a wire-protocol test exists but does not exercise
  the format's native client (e.g. curl in place of the real CLI). The
  alias or routing path is covered; client-specific behaviour is not.

## Specific claim-by-claim grading

| Claim from gap analysis | Reality |
| --- | --- |
| `jetbrains_plugins`: tests reference a handler that may not be wired into the format registry | False. The handler is in the registry (`get_core_handler` returns `JetbrainsHandler` for `"jetbrains"`) and the API module is mounted at `/jetbrains`. Tests pass. |
| `mlmodel`: handler unclear, tests exist | The trait handler exists. There is no API handler module. Tests target the WASM proxy and skip cleanly when no plugin is loaded. The conformance test uses the generic API. |
| `opkg`: no handler file, tests exist | Misleading. There is a trait handler at `src/formats/opkg.rs`. There is no API handler module, which is what the analysis probably meant. Same dual-test pattern as mlmodel. |
| `p2`: no handler file, tests exist | Same as opkg. Trait handler at `src/formats/p2.rs`; no API handler module. |
| `vagrant`: no handler file, tests exist | Same as opkg. Trait handler at `src/formats/vagrant.rs`; no API handler module. |
| `gradle`: zero E2E coverage despite Maven aliasing | Confirmed. The alias is real (resolver and trait both accept gradle). No test exercised a gradle-tagged repository before this PR. A starter `test-gradle-conformance.sh` is provided in this branch and wired into the `jvm` batch in `.github/workflows/format-tests.yml` and `.github/workflows/release-gate.yml`. The script is curl-based; a native-client test is still missing (see Remediation). |

## Remediation options (for triage, not done in this PR)

- For mlmodel/opkg/p2/vagrant: decide whether the project intends to ship
  native protocols. If yes, add API handler modules and routes and convert
  the basic tests from `/ext/...` (WASM proxy) to the native path. If no,
  retire the basic tests and keep the conformance tests (which already use
  the generic API and are not WASM-dependent).
- For jetbrains: working as intended; no action.
- For gradle: keep the new `test-gradle-conformance.sh` (added in this
  branch) so the alias is exercised. The script is curl-based and does not
  cover Gradle's real HTTP client. A native-client test (parallel to
  `test-maven-native-client.sh`, shelling out to the `gradle` CLI) is
  recommended as a follow-up. If a future change adds a `/gradle` router,
  expand the test to hit it directly.
- For the orphaned `*-conformance.sh` scripts: wire the remaining 39 into
  `.github/workflows/format-tests.yml` so they run on PRs and on the
  release gate.

### Follow-up issues

Filed in beads on 2026-04-27:

- `ak-un1n` (P3, task): Wire `*-conformance.sh` suite into
  `format-tests.yml` workflow matrix. Inventories the orphaned scripts and
  adds them to the matrix so regressions are caught automatically.
- `ak-2ze2` (P3, task): Add native gradle CLI conformance test (parallel
  to `test-maven-native-client.sh`). Shells out to a real `gradle` CLI to
  cover User-Agent gating, `.module` resolution priority over `.pom`, and
  variant selection.
- `ak-u3x1` (P3, task): Add gradle remote-repo conformance test. Parallel
  to `test-maven-remote.sh`. Verifies a `format=gradle` remote repo can
  proxy and resolve `.module` files (Gradle Module Metadata, JSON) from
  upstream, including the `.module`-404 / `.pom`-200 fallback.
- `ak-q8xh` (P3, task): Triage native HTTP handler modules vs WASM-only
  for mlmodel, opkg, p2, vagrant. Decide whether to add `api/handlers/<format>.rs`
  modules or retire the basic tests in favour of generic-API conformance.

## Files referenced

- `/tmp/ak-1.1.x-analysis/backend/src/formats/mod.rs` (lines 1 to 306)
- `/tmp/ak-1.1.x-analysis/backend/src/formats/jetbrains_plugins.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/formats/mlmodel.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/formats/opkg.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/formats/p2.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/formats/vagrant.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/api/routes.rs` (lines 44 to 80)
- `/tmp/ak-1.1.x-analysis/backend/src/api/handlers/mod.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/api/handlers/maven.rs` (line 47)
- `/tmp/ak-1.1.x-analysis/backend/src/api/handlers/jetbrains.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/api/handlers/wasm_proxy.rs`
- `/tmp/ak-1.1.x-analysis/backend/src/api/handlers/repositories.rs` (lines 117 to 135)
- `tests/formats/test-jetbrains.sh`, `test-jetbrains-conformance.sh`
- `tests/formats/test-mlmodel.sh`, `test-mlmodel-conformance.sh`
- `tests/formats/test-opkg.sh`, `test-opkg-conformance.sh`
- `tests/formats/test-p2.sh`, `test-p2-conformance.sh`
- `tests/formats/test-vagrant.sh`, `test-vagrant-conformance.sh`
