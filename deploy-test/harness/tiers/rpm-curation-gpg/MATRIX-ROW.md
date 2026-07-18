# MATRIX-ROW — rpm-curation-gpg (PKT-E, P5, epic #2568)

Integrator: merge the row below into `matrix.md` (new row after the debian-remote /
audit-export / storage-accounting rows). Keep the must-have framing consistent.

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 17 | **RPM curation trusted GPG key, fail-closed** — #2568 (epic, `verify_detached` over `repomd.xml`/`repomd.xml.asc`) | upstreams=**rpm-gpg** + **client.dnf** (+ filesystem/single) | mock RPM upstream serves a GPG-signed `/signed` tree (`repomd.xml` + `.asc` by key A + `primary.xml.gz` whose sha == the repomd `<checksum>`) and an `/unsigned` tree with NO `.asc`. Curation staging repos are wired (repo_type=staging + curation_enabled + curation_source_repo_id via psql — the backend has no API for these; its own unit test sets them the same way) and synced via the manual synchronous trigger `POST /api/v1/curation/repos/{key}/sync`. Counts from `curation_packages`: **correct key -> >0**, no-key -> >0 (documented UNVERIFIED ingest, CONTROL), **wrong key -> 0** (the #2568 discriminator), **correct key + missing `.asc` -> 0** (fail-closed). Client leg: `dnf` `repo_gpgcheck=1 skip_if_unavailable=0` makecache succeeds with key A, **fails with the wrong key** (undoes the native-client `gpgcheck=0` bypass). | **rpm-curation-gpg** | **COVERED** — self-discriminating: a backend that trusted a wrong-key/absent-`.asc` upstream ingests >0 -> tier red; the POSITIVE + no-key CONTROL prove the pipeline ingests, so the 0s are attributable to signature verification, not a dead sync |

## Shared-file needs (integrator single-pass)

- **`run.sh` `all` list:** add `rpm-curation-gpg`. It runs green on the single
  candidate image (`ak-backend:candidate-a4d7f9d1`), so it can join the one-image
  `all` run alongside smoke/isolation/debian-remote/etc.
- **`ports.sh`:** NO new published port. `rpm-upstream` is reached
  container-to-container on the slot's private `rpmupstream` net
  (172.31.<slot>.0/24); the `dnf` client leg runs via `docker exec` (no host port).
- **`run.sh` manifest-env passthrough:** NONE new. The only manifest override is
  `RATE_LIMIT_ENABLED`, which `run.sh` already special-cases and exports. The SSRF
  allowlist envs live inside `profiles/upstreams.rpm-gpg.yml`, not the manifest.
- **Fixture pre-bake (one-time, host-side):** run `bash fixtures/rpm-gpg/build.sh`
  ONCE before the tier — it needs `gpg` (not present in `nginx:alpine`, and no
  offline `apk add` on the rig), so the tree is baked on the host and served
  read-only. Re-running regenerates keys + tree together (consistent asc/pubkey).
  Commit `fixtures/rpm-gpg/{build.sh, keys/, tree/}`.
- **PROFILES ORDER (already in the manifest):** `storage.filesystem client.dnf
  upstreams.rpm-gpg` — `upstreams.rpm-gpg` MUST come last so its `client-dnf`
  `networks:` mapping wins the merge over `client.dnf.yml`'s list form (gives
  `client-dnf` both the `dtf` and `rpmupstream` nets).
- **New owned files (this packet only):** `harness/tiers/rpm-curation-gpg/{manifest,oracle.sh,MATRIX-ROW.md}`, `profiles/upstreams.rpm-gpg.yml`, `fixtures/rpm-gpg/build.sh` (+ baked `fixtures/rpm-gpg/{keys,tree}`).

## OPEN QUESTION #2 (sync trigger) — RESOLVED

A manual, **synchronous** admin trigger exists and is what the oracle uses:
`POST /api/v1/curation/repos/{staging_key}/sync` (`handlers::curation::trigger_sync`,
#2357 WI-5) calls `scheduler_service::run_curation_sync_cycle(db, Some(repo.id))`
**inline** and returns after the pass finishes (`{triggered, succeeded}`). No
scheduler-cron sleep-and-hope, no fast-interval knob needed. Confirmed in
`backend/src/services/scheduler_service.rs` (the `only_repo` path is documented
as "the code path the manual `POST /curation/repos/{key}/sync` trigger uses").

## GPG fixture approach (which crate / flavor)

- Backend verifier: `signing_service::verify_detached` uses the **`pgp` crate
  (rPGP) 0.14.2**: `SignedPublicKey::from_string` + `StandaloneSignature::from_string`
  + `signature.verify(&key, data)`. The create-time `trusted_gpg_key` validator
  loads the key with the same `pgp::SignedPublicKey::from_string` (ASCII-armored
  PUBLIC key only; a private-key block or bad armor is rejected 400).
- Fixture flavor (mirrors the backend's own signer `sign_openpgp_detached_blocking`:
  `SignatureType::Binary` + **RSA** + **SHA256**): `fixtures/rpm-gpg/build.sh`
  generates two **RSA-3072** keypairs with host `gpg` (GnuPG 2.4), exports the
  ASCII-armored PUBLIC keys, and signs `repomd.xml` with `gpg --digest-algo SHA256
  --detach-sign --armor`. **Verified** these artifacts against the exact `pgp 0.14.2`
  crate before shipping: correct key -> VERIFY OK, wrong key -> VERIFY FAIL
  ("No matching issuer"). The primary checksum chain (`primary_gz_pinned_by_repomd`)
  is honored by computing the repomd `<checksum>`/`<open-checksum>` from the real
  `primary.xml.gz`/`primary.xml` bytes at bake time.

## EXPECT_FAILURE self-test

The oracle is EXPECT_FAILURE-aware via `end_suite` (no extra code). Discrimination
is proven inline: the POSITIVE (correct key -> >0) and the no-key CONTROL (-> >0)
establish the sync pipeline ingests, so the WRONG-key and missing-`.asc` **0s**
are attributable to signature verification, not a dead route. To belt-and-suspenders
against a hypothetical non-fail-closed build, `EXPECT_FAILURE=1
./harness/run.sh rpm-curation-gpg --backend-image <buggy>` should exit 0 (i.e. it
correctly caught the wrong-key-ingests-`>0` red). No pre-fix image is required for
the primary gate.

## Backend-surface notes (verified against candidate-a4d7f9d1)

- **No API to enable curation.** `curation_enabled` / `curation_source_repo_id` /
  `curation_default_action` / `repo_type='staging'` have no create/update request
  field; the oracle sets them via `psql` on the DB container, exactly as the
  backend's own `test_trigger_sync_authz_and_audit_db` unit test does.
- **`trusted_gpg_key` is a REMOTE-repo field**, set through the validated create
  path (`CreateRepositoryRequest.trusted_gpg_key`); the response echoes only
  `has_trusted_gpg_key: true`, never the key. The curation sync reads it off the
  remote joined via `curation_source_repo_id`.
- **Ingest surfaces as `curation_packages` rows** (via `CurationService::upsert_package`
  during the sync); the oracle counts them per `staging_repo_id`. The sync does NOT
  fetch the pool `.rpm` (so no `rpmbuild` is needed — the fixture pool object is a
  placeholder at the advertised `<location href>`).
- **Trigger authz:** `POST .../sync` requires admin (or an API token with the
  `trigger:sync` scope) + tenant-ownership; the oracle authenticates as admin.
