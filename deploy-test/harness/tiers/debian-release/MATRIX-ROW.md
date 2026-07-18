# MATRIX-ROW — debian-release (PKT-B, epic #2458 / feature #2489)

Integrator: merge the row below into `matrix.md` (new row after the debian-remote
rows #13/#14). Keep the must-have framing consistent.

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 15 | **Hosted Debian `Release` metadata customization** (apt_origin/apt_label/apt_release_version/apt_description rendered into the served `dists/{dist}/Release`) — #2489 (epic #2458) | client=**apt** (+ filesystem/single) | create a hosted debian repo, `PATCH` custom `apt_origin="DTF Corp"` / `apt_label="DTF Internal"` / `apt_release_version="2026.7"` / `apt_description="DTF custom release"`, publish a real .deb, then GET the served `dists/stable/Release` and assert the bytes carry the EXACT custom `Origin:`/`Label:`/`Version:`/`Description:` lines; a real `apt-get update`+`install` against the customized repo still succeeds. DISCRIMINATOR: a SECOND repo with NO overrides renders the DEFAULT `Origin/Label: artifact-keeper` and OMITS `Version:`/`Description:` entirely, and carries NONE of the custom strings | **debian-release** | **COVERED** — self-discriminating via the custom-vs-default two-repo contrast (no pre-fix image needed): a backend that ignored `apt_*` config renders defaults on the custom repo -> P2 fails -> tier red; a hardcoded constant / cross-repo bleed would surface the custom strings on the default repo -> N1 fails -> tier red |

## Run evidence (candidate `ak-backend:candidate-a4d7f9d1`, foreground)

`./harness/run.sh debian-release --backend-image ak-backend:candidate-a4d7f9d1`
-> **7 passed, 0 failed** (exit 0). The two served `Release` documents:

CUSTOM repo (`dtf-debrel-custom-*`) served `dists/stable/Release`:
```
Origin: DTF Corp
Label: DTF Internal
Suite: stable
Codename: stable
Version: 2026.7
Description: DTF custom release
Date: Sat, 18 Jul 2026 18:08:39 UTC
Architectures: arm64
```
DEFAULT repo (`dtf-debrel-default-*`, no apt_* keys) served `dists/stable/Release`:
```
Origin: artifact-keeper
Label: artifact-keeper
Suite: stable
Codename: stable
Date: Sat, 18 Jul 2026 18:08:39 UTC
Architectures: arm64
Components: main
```
The default document has NO `Version:`/`Description:` lines and none of the custom
strings — the contrast is the discrimination proof.

## Shared-file needs (integrator single-pass)

- **`run.sh` `all` list:** ADD `debian-release`. It runs green on the single
  candidate image (`ak-backend:candidate-a4d7f9d1`), so it can join the one-image
  `all` run. NOTE: the peer 1.6.0 tiers `debian-remote` / `audit-export` /
  `storage-accounting` are already in the `all` list; `debian-release` is NOT yet
  present — add it (suggested: right after `debian-remote`).
- **`ports.sh`:** NO new published port. `client-apt` reaches the backend
  container-to-container (`http://backend:8080`) on the slot's `dtf` net; nothing
  is host-published.
- **`run.sh` manifest-env passthrough:** NONE new. The only manifest override is
  `RATE_LIMIT_ENABLED`, which `run.sh` already special-cases and exports.
- **New owned files (this packet only):**
  `harness/tiers/debian-release/{manifest,oracle.sh,MATRIX-ROW.md}`.
  No new profile/fixture — reuses `storage.filesystem` + `client.apt` as-is.

## EXPECT_FAILURE self-test

The oracle is EXPECT_FAILURE-aware via `end_suite` (no extra code). The
custom-vs-default two-repo contrast already proves discrimination inline (the two
served documents genuinely differ, captured above). To belt-and-suspenders the
fail path against a real pre-fix build (e.g. a `1.6.0`-minus-#2489 image that
ignores `apt_*`), run `EXPECT_FAILURE=1 ./harness/run.sh debian-release
--backend-image <pre-fix>` and confirm the tier exits 0 (i.e. it correctly caught
the custom-values-rendered-as-defaults red). No pre-fix image is required for the
primary gate.

## Backend-surface deviations from the build plan (verified against candidate-a4d7f9d1)

- **The apt_* config is set via TOP-LEVEL request fields, NOT nested under the
  `debian` field.** The debian-remote coder correctly found that the #2460 proxy
  FILTER lives under the request field `debian`; #2489's customization keys are
  DIFFERENT and separate: `apt_origin` / `apt_label` / `apt_release_version` /
  `apt_description` are top-level fields on both the create and update request
  bodies (`repositories.rs` `CreateRepository` ~575-588 / `UpdateRepository`
  ~688-701). They persist to `repository_config` rows of the same key names.
- **Update verb is `PATCH /api/v1/repositories/{key}`** (router `.patch(update_repository)`),
  same verb the debian-remote coder confirmed (NOT PUT). Sending an empty string
  for a field DELETES that config key (resets to default).
- **These fields are only accepted for HOSTED (local) APT repos** — the handler
  400s them on a non-debian repo.
- **Defaults are the constant `"artifact-keeper"`** for both Origin and Label
  (`DEFAULT_APT_ORIGIN` / `DEFAULT_APT_LABEL`, debian.rs:708-709). The build plan
  (§2 P2) did not name the default; it is `artifact-keeper`, and the oracle
  asserts exactly that on the default repo.
- **`Version:` and `Description:` lines are OMITTED entirely when their keys are
  unset** (they are `Option`s in `render_release_document`, debian.rs:1002-1009),
  not rendered empty. The oracle asserts their ABSENCE on the default repo.
- **`Description:` is deb822-folded** (`format_deb822_description`); for a
  single-line value it renders `Description: DTF custom release` verbatim, so the
  oracle matches that exact first line (per the plan's brittleness note).
- Everything else matches the plan: `GET /debian/{key}/dists/{dist}/Release`
  path, `render_release_document` -> `fetch_apt_release_metadata` sourcing.
