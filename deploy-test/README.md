# deploy-test — Deployment Test Framework (DTF)

Coverage half of the release-assurance program (design:
`rig/results/deployment-test-framework-design.md`). One opinion-free
`compose.base.yml` (backend + postgres) plus additive overlay files under
`profiles/`, driven by a single `harness/run.sh <tier>` wrapper that reuses the
blue-fix pool's slot/port discipline and the existing `tests/lib/common.sh` /
`scripts/run-suite.sh` assertion harness in strict `RELEASE_GATE=1` mode.

## Status: built — 9 tiers green locally

> **See [`ARCHITECTURE.md`](ARCHITECTURE.md)** for the full layout, the lines between DTF /
> the corpus / the k8s gate / the rig, how to add a tier, and the honest verification status.

All nine tiers exist and ran green sequentially (each discriminating — passes on the fixed
image, fails on a pre-fix one): `smoke` `isolation` `migration` `native-client`
`proxy-egress` `sso` `upgrade` `supply-chain` `dos`. Coverage: every must-have escaped-defect
class + both previously-disabled controls; the one GAP is row 8 (WASM/cosign signing). See
`matrix.md`.

**Verified locally (arm64) only** — nothing has run on `ak-docker-runners` / x86_64 yet, and
the CI-gate workflow (brick 8) is deferred as online work. Details in `ARCHITECTURE.md` §7–8.

## Run

```bash
# smoke: any recent backend image
harness/run.sh smoke     --backend-image ak-backend:fix-2574

# isolation: needs an image with migration 163 (maven_flat_object_owner table)
harness/run.sh isolation --backend-image ak-backend:fix-2574     # -> exit 0 (isolation holds)
harness/run.sh isolation --backend-image artifact-keeper-backend:base-2504  # -> exit 1 (11 leaks)

harness/run.sh all       --backend-image ak-backend:fix-2574     # both tiers
harness/run.sh up   --storage s3 --backend-image <img> --keep    # raw topology, leave it up
harness/run.sh down --slot 1                                     # tear a slot down
```

Flags: `--backend-image IMG` (required), `--keep` (don't tear down),
`--slot N` (pin a slot instead of auto-claim).

Each tier claims a free slot `N` (project `ak-dtf<N>`) with a non-colliding port
block (HTTP 8200+N, gRPC 9200+N, PG 30700+N, S3 9300+N). It never touches the
red-team target on :8080 or the blue-fix pool on 8100+. JUnit lands in
`results/<tier>/`.

## Corpus resolution

`run.sh` finds `tests/lib/common.sh` at `../` (the productized
`artifact-keeper-test/deploy-test` layout) or, when this tree is copied onto the
redteam rig, falls back to `/home/khan/artifact-keeper-redteam/test`. Override
with `AK_TEST_ROOT`.

## Tier outcomes: regression vs INFRA/SETUP

A blocking gate is only useful if its RED means what it says. `harness/lib/exit_codes.sh`
is the single source of truth for what a tier's exit code means; the two that
matter when reading a red gate are:

| Exit | Summary label | Meaning |
|------|---------------|---------|
| `1`  | `FAIL (tier: oracle asserted a regression)` | The oracle ran and an assertion **about the candidate** fired. This is a product verdict. |
| `11` | `INFRA (INFRA/SETUP: harness could not evaluate the tier)` | The oracle started but could not evaluate anything — probe binary missing, token mint returned empty/4xx, a fixture precondition was not met, backend unreachable. The candidate is **unjudged**. |

Both are RED (a required tier that cannot run cannot certify — fail-closed), but
only exit 1 is ever described as a regression. When you write an oracle, use
`fail` for assertions about the candidate and `infra_fail` for "I could not set
this up"; `end_suite` picks the exit code. Same rule inside a standalone gate
script (e.g. `tiers/isolation/prove.sh`): exit `11` from setup, and the tier's
oracle maps it through.

## Probes are provisioned, not built at gate time

Required tiers depend only on the candidate image plus local containers — **no
external network calls**. A tier that needs a compiled helper (today: the `sso`
tier's SAML XSW payload generator, `tiers/sso/probe`) does NOT build it: the
`build-dtf-probes` job in `.github/workflows/release-gate.yml` builds it on a
network-capable runner as a static musl binary and hands it to the tier job as
an artifact, staged at `tiers/sso/probe/target/release/dtf-saml-xsw-probe`. The
oracle's `build_probe` no-ops when that binary exists, and under `RELEASE_GATE=1`
it refuses to fall back to `cargo build` at all, so the invariant is enforced
rather than merely documented. Locally, point `DTF_SAML_XSW_PROBE` at a binary
you already have, or just let it build (outside the gate, with a toolchain
present).

## Caveats (from the S3 work; see `matrix.md` + design)

- The isolation oracle DB-probes (`docker exec <db> psql`) because the repo API
  does not expose `storage_backend`.
- The `isolation` tier needs a backend image that includes **migration 163**
  (`maven_flat_object_owner`); `artifact-keeper-backend:fix-2504` (an early
  #2504-only image) is NOT a valid "fixed" reference for scenario F.
