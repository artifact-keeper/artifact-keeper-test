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

## Caveats (from the S3 work; see `matrix.md` + design)

- The isolation oracle DB-probes (`docker exec <db> psql`) because the repo API
  does not expose `storage_backend`.
- The `isolation` tier needs a backend image that includes **migration 163**
  (`maven_flat_object_owner`); `artifact-keeper-backend:fix-2504` (an early
  #2504-only image) is NOT a valid "fixed" reference for scenario F.
