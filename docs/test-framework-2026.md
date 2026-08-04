# Artifact Keeper — Conformance Test Framework (2026)

Status: draft for team review
Owner: (release-gate / QA)
Scope: how we prove Artifact Keeper correctly implements each package-format
protocol, by harvesting the edge-case knowledge already encoded in mature
open-source clients and specs, and driving it into BOTH our unit tests and our
deployment tests (DTF).

---

## 1. Problem

We ship 38+ format handlers. Correctness bugs cluster on the *protocol edges*:
advertised-but-unserveable metadata (#3077), lying upstream `Content-Type`
(#2801), manifest-list child resolution and per-member scan gating (#3025),
grouped-listing pagination (#2722), version parsing from GAV paths (#3093), and
so on. Each was found and fixed one at a time. We want these to become a
*standing gate* rather than a stream of one-off fixes.

The knowledge of "what a registry must survive" already exists — it is encoded
in the test suites of mature clients (uv, cargo, pip, the npm CLI, nub) and in
the format specs themselves. We should harvest that knowledge once and reuse it
everywhere.

## 2. Thesis: harvest once, feed two layers

The valuable asset in those repos is not their test *code* (client-side, and
mostly under our reuse constraints only as ideas). It is the **corpus of
adversarial inputs and expected behaviors**. We capture that as a single,
versioned **Conformance Corpus**, and run it through two runners.

```
  Specs (authoritative)            OSS client/registry test suites (vectors)
  PEP 503/691/658/714/592/700      uv, cargo, nub, pip, npm CLI, pacote,
  OCI distribution-spec            verdaccio, OCI-conformance, createrepo_c,
  (npm: de-facto, see §9)          apt test/integration, packse
        │                                        │
        └───────────────┬────────────────────────┘
                        ▼   harvest (fixtures, mock servers, scenario lists, assertions)
            ┌───────────────────────────────┐
            │      CONFORMANCE CORPUS         │  scenario = { format, id, input, expected }
            │   versioned, format-keyed       │  e.g. pypi/metadata-advertised-404
            └───────────────┬────────────────┘
                  ┌─────────┴──────────┐
                  ▼                    ▼
            UNIT runner            DTF runner
            in-crate Rust,         real backend + mock upstream
            trait-mocked seams     + real client (uv / docker / npm)
            ms, every commit       minutes, release gate
```

The corpus is the spine. Harvesting funds both layers at once — no duplication.

## 3. Are we "off base"? No — but pair specs with client tests

Client suites are client-side. That is exactly why they are useful: they show
what a *client* demands of a registry, which is the mirror of what our registry
must serve. But client tests alone are not a checklist — they cover what that
client happens to exercise. So:

- **Spec = the checklist** of features we must implement (PEPs; OCI
  distribution-spec). This is the completeness axis.
- **Client tests = the vectors** that exercise those features under real and
  hostile conditions, including things specs under-specify (relative URLs,
  redirect chains, mislabeled content types). This is the robustness axis.

We build the corpus from **both**: walk the spec to enumerate required
behaviors, then attach the concrete adversarial inputs harvested from client
suites to each one.

## 4. Source-of-truth matrix (per format)

| Format | Authoritative spec | Client/registry suites to harvest | Mock server we can model on | Point-at-server suite | Priority |
|---|---|---|---|---|---|
| **PyPI** | PEP 503, 691, 592, 658, 714, 700, 427/440/425, 592, 740, 792 | uv (`uv-test/pypi_proxy.rs`), pip `tests/`, packse | uv `pypi_proxy` (wiremock); ours: `mock_pypi.py` | none | **1 (deep)** |
| **OCI/Docker** | OCI distribution-spec, image-spec | distribution-spec `conformance/`, `registry:2` | `registry:2` as origin | **YES — OCI conformance** | **1 (deep)** |
| **npm** | none formal — CouchDB registry API + npm CLI behavior (see §9) | npm CLI, `pacote`, `nub`, verdaccio | verdaccio; ours: new `mock_npm` | none | **2 (large)** |
| Debian/apt | Debian repo format + policy | apt `test/integration`, `debootstrap` | local repo builder | none | 3 |
| RPM/dnf | repodata (createrepo) | `createrepo_c`, `dnf` tests | local repo builder | none | 3 |
| cargo | cargo registry protocol | cargo `testsuite`, crates.io | test registry | none | 3 |
| maven/go/… | ecosystem conventions | real client E2E | — | none | 3 |

License discipline: MIT/Apache repos (uv, cargo, nub, packse, verdaccio,
distribution-spec) — we may vendor *fixtures/test data* with attribution.
GPL/copyleft (apt, dnf, createrepo_c) — re-derive *behaviors* only (facts are
not copyrightable); do not copy their code.

## 5. The Conformance Corpus

A versioned, format-keyed set of scenario files. One schema, format-agnostic:

```jsonc
// corpus/pypi/metadata-advertised-404.json
{
  "id": "pypi/metadata-advertised-404",
  "format": "pypi",
  "spec_refs": ["PEP 658", "PEP 714"],
  "source": "uv uv-test/pypi_proxy.rs (MIT); AK #3077",
  "given": {
    "upstream": {
      "simple/dtfpkg/": { "advertises": "data-core-metadata", "metadata_status": 404 },
      "files/dtfpkg-1.0-py3-none-any.whl": 200
    }
  },
  "when":  { "client": "GET /pypi/<repo>/simple/dtfpkg/ then the wheel" },
  "expect": { "wheel_served": 200, "not": "hard-500-because-metadata-missing" },
  "runners": ["unit", "dtf"]
}
```

- `given` describes upstream/registry state a mock must reproduce.
- `expect` is the assertion, phrased as observable behavior (HTTP code, DB row,
  bytes), not internal calls.
- `runners` says which layers consume it (some are DTF-only, e.g. real-client
  install; some are unit-friendly, e.g. metadata parsing).

The 9 fable idea-catalogs already written (`tiers/_fanout-ideas/*.md`) are the
first seed batch — each MAIN/CONTROL/BOUNDARY case maps to one scenario.

## 6. Two runners

### 6.1 Unit runner (in-crate Rust, backend)
Feeds `given` through **trait seams** so no network is involved, asserts
`expect` on the handler's output/decision. Fast, every commit.

Trait seams to add / confirm (the unit-side investment):
- Upstream HTTP client — already shaped by `services/http_client.rs`; make every
  proxy handler take it as a trait object so a scenario can inject a canned
  response (advertised-404, lying content-type, oversized body #3098).
- Storage backend — inject presence/absence and byte counts.
- Scanner verdict source — inject clean/vulnerable/inconclusive (scan-and-block).
- **Clock** — a `Clock` trait so age-gate (#3075) can test "package too young"
  deterministically instead of relying on wall-clock.
- OIDC/SSO HTTP — inject oversized/malformed IdP responses (#3098).

### 6.2 DTF runner (deployment)
Stands up the real backend + a **mock upstream** serving `given` + drives a
**real client** (uv/docker/npm) or a raw HTTP call, asserts `expect` on the
wire and in the DB. Slow, release gate. This is the existing
`format-conformance` / `native-client` harness; scenarios become new tiers or
plugin cases.

Mock upstreams model on uv's `pypi_proxy`: one small stdlib server per format
with variant routes keyed by URL prefix (the pattern `mock_pypi.py` already
uses), so one container serves the whole corpus for that format.

## 7. Harvest pipeline (repeatable, not one-off)

1. Target repos (§4). 2. Search patterns: `MockServer`, `wiremock`, `mockito`,
`mod tests`, plus protocol terms (`packument`, `dist-info-metadata`,
`repodata`, `manifests`), and their `tests/fixtures/` trees. 3. Extract four
things: fixture corpora, mock-server designs, scenario lists, assertion
catalogs — never the test code itself. 4. Normalize each into a corpus
scenario. 5. License gate before anything lands.

## 8. Deep-dive: PyPI (priority 1)

Walk the PEPs to build the completeness checklist, attach vectors from uv/pip.

Checklist (each becomes ≥1 scenario):
- **PEP 503** HTML Simple index: normalized names, trailing slash, link set.
- **PEP 691** JSON Simple (`application/vnd.pypi.simple.v1+json`): content
  negotiation, `meta.api-version`, `files[]`.
- **PEP 592** yanked: `yanked` bool/reason surfaced; installer avoids unless
  pinned.
- **PEP 658 + PEP 714** metadata: emit BOTH `data-dist-info-metadata` (legacy)
  and `data-core-metadata` (current); the advertised-but-404 fallback (#3077);
  hash on the metadata attr.
- **PEP 700** JSON extras: `versions`, `file.size`, `upload-time`.
- **PEP 427/440/425** wheel filename parse, version ordering, platform-tag
  selection (manylinux, macos, abi3) — the "right wheel for the platform" case.
- **PEP 740** index attestations (newer): advertise/serve if present.
- **PEP 792** project status markers (uv proxy has `/status/` routes).
- Non-PEP real-world vectors from `pypi_proxy`: relative file URLs, 302 redirect
  to files host, Basic-auth realms, mislabeled `Content-Type` (#2801),
  compressed upstream with preserved `Content-Length` (#2915).

Client leg: real `uv` and `pip install` against an AK proxy repo fronting our
`mock_pypi`. Unit leg: metadata/index parsing + fallback decision behind the
HTTP trait.

## 9. Deep-dive: OCI (priority 1)

OCI is the one ecosystem with a purpose-built **point-at-any-server** suite:
`opencontainers/distribution-spec/conformance`. Configure via `OCI_ROOT_URL`,
`OCI_NAMESPACE`, `OCI_USERNAME/PASSWORD`, and the workflow toggles
(`OCI_TEST_PULL/PUSH/CONTENT_DISCOVERY/CONTENT_MANAGEMENT`); it emits JUnit.

Plan: adopt it directly as a DTF tier (`tiers/oci-conformance/`) pointed at AK
`/v2/` on `--network host`, JUnit ingested into `collect-results`. Enable
pull + push + content-discovery first (AK should pass); gate
content-management (delete) behind a flag — it will surface the known
blob-delete gap (`DELETE /v2/<name>/blobs/<digest>` currently 405s; see the
#3054 analysis), which is exactly the kind of conformance gap this tier should
make visible. Layer AK-specific scenarios on top: manifest-list child scan
gating (#3025), offline-token reuse (#2477).

## 10. Deep-dive: npm (priority 2, largest)

No formal spec — this is the key difference. The "spec" is:
- the registry API surface: packument `GET /{pkg}` (full and abbreviated via
  `Accept: application/vnd.npm.install-v1+json`), version doc, tarball
  `/{pkg}/-/{pkg}-{ver}.tgz`, scoped `@scope%2fname`, dist-tags
  (`/-/package/{pkg}/dist-tags` GET/PUT/DELETE), publish `PUT /{pkg}` with
  base64 `_attachments`, search `/-/v1/search`, `/-/whoami`, deprecate,
  audit `/-/npm/v1/security/*`;
- integrity: `dist.integrity` (SHA-512 SRI) AND legacy `dist.shasum` (SHA-1);
- behavior encoded in npm CLI, `pacote`, `nub`, and verdaccio's tests.

Because there is no PEP to check against, npm's checklist must be *derived* from
those client suites + verdaccio — which is why it is the biggest harvest job and
the strong second priority. Concretely: read `nub` and `pacote`'s test dirs for
what they assert about packuments, dist-tags, scoped packages, and integrity;
model a `mock_npm` on the same variant-route pattern; drive real `npm install`
and `nub install` against an AK npm proxy.

## 11. Sequencing

- **M1 (reference vertical slice):** corpus schema + runner glue, proven on
  **pypi + oci** end-to-end (~15 scenarios each, both runners). Deliver the OCI
  conformance tier here.
- **M2:** npm — `mock_npm`, harvest from nub/pacote/verdaccio, real `npm`/`nub`
  legs, ~20 scenarios.
- **M3:** templatize to deb/rpm/cargo via the existing `format-conformance`
  plugin drop-in; harvest fixtures (GPL repos → behaviors only).
- **M4:** wire the corpus's unit-runner into backend CI; wire the DTF tiers into
  the release gate.

## 12. What AK already has (this is enrichment)

- `format-conformance` tier — plugin-per-format real-client harness (19 formats):
  the DTF runner already exists.
- `native-client` tier — real `dnf`/`apt`/`docker` legs.
- `mock_pypi.py`, `mock_oidc.py`, `net.private-upstream` profile — the
  mock-upstream skeleton (uv-`pypi_proxy` pattern, lighter).
- `services/http_client.rs` bounded reader — an existing trait-shaped seam.
- 9 fable idea-catalogs (`tiers/_fanout-ideas/`) — first corpus seed.

## 13. Attribution & licensing (non-negotiable)

We build on other people's work; we credit it. The rules live in
`conformance/CREDITS.md` and are enforced structurally:

- Every scenario JSON has a required `source:` field naming the upstream
  project and its license.
- Every mock/fixture file carries an ATTRIBUTION header (see
  `mock_pypi_conf.py`, crediting uv's `pypi_proxy`, Apache-2.0 OR MIT).
- Three kinds of reuse, three obligations: **pattern** (credit as courtesy),
  **behavior** (re-derive + cite — facts are not copyrightable), **vendored
  bytes** (only from MIT/Apache/BSD; copy the upstream LICENSE alongside).
- Deliberate asymmetry: permissive sources (uv, nub, verdaccio, cargo, conda)
  may contribute vendored fixtures; copyleft sources (dnf, apt, createrepo_c)
  contribute re-derived behaviors only, never copied code.

## 14. Roadmap — every format, same shape

The vertical slice (pypi + oci) is the reference implementation. Each later
format repeats the identical shape — corpus dir + mock (or adopted suite) +
one runner tier + CREDITS rows — so the marginal cost drops per format.

| Format | Milestone | Spec / source of truth | Harvest sources (license) | Vendor fixtures? | Point-at-server suite |
|---|---|---|---|---|---|
| **pypi** | M1 (this PR) | PEPs 503/691/592/658/714/700/740/792 | astral-sh/uv `pypi_proxy` (Apache/MIT), pypa/pip (MIT) | uv: yes | no — our mock |
| **oci** | M1 (this PR) | OCI distribution-spec / image-spec | opencontainers conformance (Apache-2.0) | run-as-is | **yes (adopted)** |
| **npm / node** | M2 | none formal — CouchDB registry API + npm CLI | npm/cli (Artistic-2.0), pacote (ISC), nubjs/nub (MIT), verdaccio (MIT) | nub/verdaccio: yes | no — our mock |
| **conda** | M3 | conda channel + repodata.json | conda/conda (BSD-3), conda-forge | yes | no — our mock |
| **deb** | M3 | Debian repo format + policy | apt test/integration (GPL) | **no** (behaviors only) | no — our mock |
| **rpm** | M3 | repodata (createrepo) | createrepo_c / dnf (GPL) | **no** (behaviors only) | no — our mock |
| **cargo** | M4 | cargo registry protocol | rust-lang/cargo (Apache/MIT), crates.io | yes | no — test registry |
| maven / go / helm / nuget | M4 | ecosystem conventions | real-client E2E via format-conformance plugins | n/a | no |

Per-format checklist (Definition of Done for adding a format):
1. Walk the spec → enumerate required behaviors (the completeness axis).
2. Read the client suites → attach concrete vectors (the robustness axis),
   record each in CREDITS.md with its license.
3. Build the mock variant routes (or adopt the point-at-server suite).
4. Drop the corpus scenarios (each with `source:`).
5. Add the `<fmt>-conformance` runner tier.
6. Later: wire the same corpus into the unit runner.

Cross-cutting after M2: stand up the **unit runner** so the corpus drives both
layers (the second half of the thesis), starting with pypi + npm.

## 15. Open questions

- Corpus format: JSON (shown) vs a Rust-native scenario enum the unit runner
  imports directly and the DTF runner reads as JSON. Leaning JSON + a codegen
  step so both runners share one source.
- How much of pip/uv's actual fixture *bytes* we vendor vs regenerate.
- Whether the OCI content-management gap is fixed before we make that workflow
  gating.
