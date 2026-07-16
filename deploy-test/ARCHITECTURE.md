# Deployment Test Framework (DTF) — Architecture & Boundaries

This document explains **what DTF is, where it lives, and — most importantly — the
lines between it and the other places tests live in Artifact Keeper.** Read this
before adding a tier or wiring the CI gate.

---

## 1. What DTF is (and what it is not)

DTF is the **coverage half** of the release-assurance program. It answers *"does the
product behave correctly across every deployment topology we actually ship?"* — via a
composable docker-compose harness plus discriminating oracles that **fail on the bug**.

It exists because forensics on the last 8 real escaped defects showed **6 of them (both
CRITICALs) would pass a perfect release-*identity* gate** — the old gate deploys a
filesystem / single-node / no-proxy / no-migration / no-native-client / no-IdP stack
that *structurally cannot exhibit* those bugs. DTF is the environment that can.

DTF is **not**:
- the release *identity* gate (build-once / promote-by-digest / tag immutability) — that
  is the separate **Workstream A**; DTF meets it only at one env var, `BACKEND_IMAGE`.
- a replacement for backend unit tests (those stay in `artifact-keeper/backend`).
- the Helm/k8s packaging gate (that stays; see §6).

---

## 2. Where everything lives — the two worlds

There are two worlds, and most of the confusion is the boundary between them.

### World 1 — the local rig (never ships, never pushed)
`artifact-keeper-redteam/` on the build host. A private forge where things are built and
proven, and **where this framework currently lives, unpushed, behind the release freeze.**

```
artifact-keeper-redteam/
  rig/                 blue-fix worker pool (pool.sh, compose.worker.yml),
                       Nexus harness (compose.nexus.yml), results/patches/
  target-backend/      a CHECKOUT of artifact-keeper (proof/ S3 oracle born here)
  test/                a CHECKOUT of artifact-keeper-test (the corpus, AK_TEST_ROOT)
  dtf-repo/            a CHECKOUT of artifact-keeper-test on branch
                       feat/deployment-test-framework  <-- AUTHORITATIVE DTF tree
  deploy-test/         a plain-dir runnable MIRROR of dtf-repo/deploy-test/
```

### World 2 — the product repos (on GitHub, what ships)
```
github.com/artifact-keeper/
  artifact-keeper           backend (Rust)
    backend/{src,tests}       UNIT + integration tests (cargo nextest)
  artifact-keeper-test      the e2e / release-gate repo
    tests/**                  the E2E CORPUS: bash test-*.sh + tests/lib/common.sh
    .github/workflows/
      release-gate.yml        the k8s ARC gate that runs the corpus (on the CI host)
    deploy-test/              <-- DTF's HOME (this directory), sibling of tests/ + the gate
  artifact-keeper-web / -iac / -api / -cli
```

### The lines
- **Three kinds of tests, three places:** backend unit/integration → `artifact-keeper`;
  the e2e corpus → `artifact-keeper-test/tests/`; **DTF → `artifact-keeper-test/deploy-test/`
  (same repo as the corpus, a sibling dir).**
- **Rig (R&D) vs `deploy-test/` (productized):** oracles are *invented* in the rig
  (`proof/prove.sh`, the Nexus harness) and then **vendored/adapted into
  `harness/tiers/`** so DTF is self-contained and shippable — it does not depend on the rig
  at runtime.
- **DTF reuses the corpus, it does not replace it:** DTF's assertion library IS the corpus
  `tests/lib/common.sh` (strict `RELEASE_GATE=1` mode); the `smoke` tier wraps
  `tests/release-gate/test-real-flow-smoke.sh`. DTF adds the *topologies* (`profiles/`) and
  the *discriminating oracles* (`harness/tiers/`) the corpus never had.
- **DTF vs the k8s gate:** both in `artifact-keeper-test`, different jobs — see §6.

---

## 3. How it works — the contract

One entrypoint, identical locally and (eventually) in CI:

```
harness/run.sh <tier|all>  [--backend-image IMG] [--keep] [--slot N]
harness/run.sh up          [--storage X --sso Y ...] [--backend-image IMG]   # raw topology
harness/run.sh down        [--slot N]
```

For a `<tier>` it: resolves the tier → a **profile-set + oracle** (from
`harness/tiers/<tier>/manifest`), claims a free slot with a non-colliding port block
(`lib/ports.sh`, ports `8200+N`), health-gated `docker compose up -d --wait`, exports
`BASE_URL` / `RELEASE_GATE=1` / `ADMIN_PASS` / `DB_CONTAINER` / `BACKEND_IMAGE`, runs the
oracle, collects JUnit into `results/<tier>/`, tears down `down -v` (unless `--keep`), and
**returns the oracle's exit code** (the gate signal — not JUnit parsing).

### Composable profiles (the topology dimensions)
A deployment shape = one choice per dimension, layered as additive `-f` overlays:

| Dimension | Values | Overlay |
|---|---|---|
| storage | filesystem \| s3 \| (gcs) | `profiles/storage.*.yml` |
| proxy | none \| squid | `profiles/proxy.squid.yml` |
| upstreams | none \| nexus | `profiles/upstreams.nexus.yml` |
| sso | none \| saml (Keycloak) | `profiles/sso.saml.yml` |
| scanners | none \| trivy | `profiles/scanners.trivy.yml` |
| client | none \| dnf \| apt \| docker | `profiles/client.*.yml` |

`compose.base.yml` is the **only** file declaring `backend` + `postgres`, opinion-free,
with `RATE_LIMIT_ENABLED` **defaulting ON** (the old gate disabled it — that is why the
rate-limit DoS classes were untested). Overlays ADD services and/or PATCH
`backend.environment`.

---

## 4. The tiers (coverage) — see `matrix.md` for the full table

| Tier | Profile-set | Escaped class it catches | Discriminating red |
|---|---|---|---|
| `smoke` | filesystem | real push→pull→scan baseline | — (wiring) |
| `isolation` | s3 | cross-tenant r/w incl. row-less Maven — #2504/#2574/#2584 | 11 leaks on `base-2504` |
| `migration` | nexus | hollow migration single+multi-arch — #2457 | oci_blobs=0 on pre-#2457 |
| `native-client` | dnf/apt/docker(+proxy) | real client route — #2580/#2477 | 404 / token-reuse on pre-fix |
| `proxy-egress` | squid | SSRF vs egress proxy — #2570 | 502 on pre-#2570 |
| `sso` | saml (Keycloak) | SAML XSW admin escalation — #2449 | escalates on pre-#2449 |
| `upgrade` | s3 (two-phase swap) | legacy row-less across upgrade — #2574/#2584 | owner-read 404 on over-restrictive |
| `supply-chain` | trivy | scanner false-clean per-scanner floor — #2088 | false-clean fails |
| `dos` | filesystem, RATE_LIMIT=true | rate-limit + worker-starvation | no-429 when disabled |

**Coverage:** every must-have escaped-defect class + both previously-disabled controls
(scanner, rate-limit). The one **GAP** is row 8 (WASM/cosign plugin signing) — no signing
fixture yet.

---

## 5. Adding a tier (the brick pattern)

1. Add any new topology as `profiles/<dimension>.<value>.yml` (additive; ADD services /
   PATCH `backend.environment`; compute host ports from `${DTF_SLOT}` — do not hardcode).
2. Add `harness/tiers/<name>/manifest` (`PROFILES="..."`, tier env like `RATE_LIMIT_ENABLED`)
   and `oracle.sh` (source `tests/lib/common.sh`; use `begin_suite`/`pass`/`fail`/`end_suite`).
3. **The oracle must be DISCRIMINATING** — it must *fail on the bug*, both a positive
   (good case works) AND a negative (bad case refused) assertion. Check the response BODY
   and/or the DB layer, never `curl -o /dev/null`. Prove it goes red on a pre-fix image, not
   just green on a fixed one.
4. **Never** silently `skip` a capability the profile provisions (`require_cmd`/`skip_suite`
   hard-fail under `RELEASE_GATE=1` — that is by design).
5. Add a row to `matrix.md`.

> **Concurrency note:** when several tiers are built in parallel, keep each to its own new
> files and reconcile `matrix.md` / `run.sh` in a single pass — parallel edits to those
> shared files collide.

---

## 6. End-state: DTF vs the k8s release-gate

Both live in `artifact-keeper-test`; they do **disjoint** jobs:
- **k8s gate (`release-gate.yml`, ARC pods):** keeps only the Helm chart-install /
  clean-install / upgrade-smoke / packaging checks — the *cluster deploy path* DTF
  deliberately does not test.
- **DTF (`deploy-test/`, docker-compose):** owns all *behavioral* coverage across
  topologies. The behavioral suites currently in the k8s gate migrate here over time.
- **Release identity (Workstream A):** separate; meets DTF only at `BACKEND_IMAGE` — DTF
  asserts *behavior*, identity asserts *sameness* (bytes-tested == bytes-shipped).

---

## 7. Verification status (be honest about "verified")

**Verified — locally, on the rig (arm64):** all 9 tiers ran green sequentially on their
fixed images, each proven discriminating (red on a pre-fix image), clean per-slot teardown,
`:8080` untouched. Every tier was independently audited for the unfailable-test antipattern
(one hole found in `require_cmd` and fixed).

**NOT yet verified (the honest gaps):**
- **Nothing has run on `ak-docker-runners` / x86_64.** All local proof is on **arm64**; the
  backend images used (`fix-2574`, `v158-4fix`, …) are locally-built arm64 artifacts. A CI
  gate needs **x86_64 backend images** and a re-run of the tiers on x86.
- **`run.sh all` uses one `--backend-image`** but the tiers need different fixed images, so
  full-fidelity proof was per-tier, not a single `all` run. Per-tier-image support for `all`
  is a follow-up.
- **Discrimination is proven once (manual image swap), not continuously.** No standing
  tripwire re-proves the fail-path after a refactor — see the `EXPECT_FAILURE` follow-up.
- **Row 8 (WASM signing)** has no tier.
- **Nothing is pushed / no real CI run has validated any of this** — this branch and all
  patches are local, behind the release freeze.

---

## 8. Where the work restarts

**Freeze-safe (local, can do now):**
- `EXPECT_FAILURE` per-oracle self-tests — make each tier's discrimination a standing,
  checkable guarantee against a pinned known-bad image (audit recommendation).
- Row 8 — a WASM/cosign plugin-signing profile + tier.
- `run.sh all` per-tier `--backend-image` support.

**Online (needs the freeze lifted / owner go):**
- Push `feat/deployment-test-framework` → PR into `artifact-keeper-test` → merge (lands this
  `deploy-test/` in the repo).
- **Brick 8** — `deploy-test.yml` gate on `ak-docker-runners`; requires x86_64 backend
  images and validating the tiers under real ARC load.
- The **Workstream A** enforcement work (rollup exact-success, delete the half-open gate,
  gate `docker-publish.yml` on tests, quarantine the always-red suites) — still spec-only.
- Admin items: tag-immutability ruleset, branch protection on the three refs.
