# DTF Coverage Matrix — the north star

Rows = escaped-defect classes + capability areas (design §4). Columns = the
profile-set that reproduces the class, the discriminating oracle, and the
current status. A release is coverage-clear only when every **must-have** row is
`COVERED`.

Legend: **COVERED** = a DTF tier stands up the profile AND a discriminating
oracle gates it (green here / red on the bug). **EXISTS** = a real asset exists
but is not yet wired as a DTF tier. **GAP** = no discriminating test yet.

Must-have rows for the un-freeze coverage floor: **1, 2, 3, 4, 5, 6** (escaped
defect classes) + **7, 9** (the two controls we currently disable/omit).

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 1 | **Cloud cross-tenant read+write** (incl. row-less Maven) — #2504/#2574/#2584 | storage=**s3** | `prove.sh` A–F (cross-repo read, write-poison, checksum/metadata sidecar, soft-delete carve-out, row-less #2574/#2584) + DB assert | **isolation** | **COVERED** (brick 1) — green on fix-2574, 11 gate-fails on base-2504 |
| 2 | **Migration source→native pull, single+multi-arch** — #2457 | upstreams=**nexus** (+ filesystem/single) | vendored `nexus_migrate_assert` → `tiers/migration/assert.sh` (config-blob 404, child-manifest 404, `oci_blobs==0`, **per-image** `docker pull` single AND multi-arch) | **migration** | **COVERED** (brick 2) — green (exit 0) on v1.5.8 (`ak-backend:v158-4fix`), red (5 findings, exit 1) on pre-fix `nexus2457-v157base` |
| 3 | **Native client via advertised route** — #2477/#2580 | client=**dnf/apt/docker** (+proxy) | `ak` push → `dnf/apt install` follows repodata `<location>`; `docker pull` proxy repo ≥2 token exchanges | **native-client** | **COVERED** (brick 3) — green (exit 0) on `ak-backend:v158-4fix`; DISCRIMINATING: LEG A/B follow the advertised location and reject the non-prefixed href a #2580 regression emits; LEG C's 2nd/3rd offline-token re-presentation is the exact call that 401'd pre-#2477 (v1.5.5) |
| 4 | **Egress proxy / SSRF hostname→private IP** — #2570 | proxy=**squid** | backend behind squid; legit egress-through-proxy works (not 502) AND SSRF upstream (IP-literal + hostname→private IP) still refused | **proxy-egress** | **COVERED** (brick 4) — green on fix-2574, legit half 502s on pre-#2570 (pr2578); SSRF half holds on both |
| 5 | **SAML XSW / SSO** — #2449 (CRITICAL) | sso=**saml (keycloak)** | XSW-wrapped assertion admin-escalation MUST fail; claim extraction scoped to signed subtree | **sso** | **COVERED** (brick 5) — green on fix-2574 (12/12), DISCRIMINATING: pre-#2449 fix-2329 reproduces XSW admin escalation (307 + attacker is_admin=t) and the tier exits non-zero |
| 6 | **Upgrade with legacy data** — #2574/#2584 class | upgrade (seed old rows → swap image) | seed row-less Maven object, upgrade candidate, re-run isolation → still isolated | **upgrade** | **COVERED** (brick 6) — green (exit 0) on `ak-backend:v158-4fix` upgraded in-place from OLD `ak-backend:nexus2457-v157base` on the same pg+minio volumes; post-upgrade the legacy row-less sidecar is owner-readable (200, no #2574 404 regression) AND cross-tenant isolated (404, no #2504/#2584 leak) + DB attribution assert |
| 7 | **Scanner efficacy (pinned-CVE)** — #2088 | scanners=**trivy** | pinned-CVE image → scan reports the known CVE; false-clean fails | **supply-chain** | **COVERED** (brick 7) — green (exit 0) on `ak-backend:v158-4fix` (digest-pinned alpine:3.4, scan_type=image `completed`, 12 findings ≥ 10 floor, trivy-0.71.2); DISCRIMINATING: a false-clean scanner (`completed`/0) reproduces the #2088 signature and the tier exits non-zero |
| 8 | **WASM plugin signing / cosign** | scanners=trivy + plugin overlay | signed plugin loads; tampered/unsigned rejected | supply-chain | **GAP** — brick 7 did NOT close it; the `filesystem+trivy` profile provisions no plugin-signing keypair or plugin-load fixture, so a real "tampered/unsigned plugin rejected" oracle is not stand-up-able without net-new fixtures (faking it would violate the no-unfailable-test rule). Deferred to a dedicated plugin-signing overlay (future brick) |
| 9 | **Rate-limit / worker-starvation DoS** | dos, **RATE_LIMIT_ENABLED=true** | login-limiter holds; TOTP/bcrypt does not bypass the auth semaphore | **dos** | **COVERED** (brick 7) — green (exit 0) on `ak-backend:v158-4fix`: limiter 10x401 then 20x429 (first 429 at attempt #11), `/health` 12/12 ok (slowest 4ms) under a capped 20-way bcrypt burst, 0 faults; DISCRIMINATING: with `RATE_LIMIT_ENABLED=false` the same 30 failed logins return 30x401 / ZERO 429 and the tier exits non-zero (today's-gate blind spot) |
| 10 | **40+ format handlers conformance** (real publish->consume via the advertised location — #2580 class) | filesystem/single, ONE shared AK + per-format client overlays | shared driver `harness/lib/native_client.sh` + per-format `plugins/<fmt>.sh`: a REAL native client publishes then CONSUMES by following the registry's own advertised metadata/location, asserting a client-side marker/sha (not just that metadata lists the artifact) | **format-conformance** | **COVERED** (bricks B0-B6, reconciled) — full-tier run (NO FC_ONLY, ONE shared filesystem AK on slot 1, `ak-backend:v158-4fix`) green: **all 14 ENABLED plugins exit 0** (conda, cargo, go, helm, nuget, composer, maven, conan, pub, cran, gitlfs, swift, npm, pypi — 127 real publish->consume cases, 0 failures), **5 DISABLED skipped** (apk, rubygems, hex, terraform, cocoapods = `FC_ENABLED:0`, each a filed KNOWN-RED backend-gap finding, NOT softened). Each format runs a REAL native client that consumes by following the registry's own advertised metadata/location and asserts a client-side marker/sha (#2580 class); DISCRIMINATING (goes red on a bad channel / corrupted advertised URL / dead route). The 5 red-with-findings + 2 observations (pypi auth-on-public-read, nuget X-NuGet-ApiKey 401) are consolidated in `results/format-conformance/FINDINGS-SUMMARY.md` for post-freeze backend triage. Plugins are drop-in (`plugins/<fmt>.sh` + `profiles/client.<fmt>.yml` + `fixtures/<fmt>/`, no shared-file edits; collision contract held) |
| 10s | **Real push→pull→scan smoke** | **filesystem**/single/none | `test-real-flow-smoke.sh` (npm publish → pack pull-back → scan → numeric findings_count) | **smoke** | **COVERED** (brick 0) — green, 8/8 |
| 11 | **Path-traversal (discriminating)** | any | body-assert traversal (not `/dev/null`) | (cross-tier rule) | Partly landed; enforce everywhere |
| 12 | **RBAC / quotas / retention / promotion / webhooks / search / mesh** | as-today (mesh→topology=mesh) | existing suites | (existing tiers) | EXISTS; keep |

## Consolidated status (this checkpoint)

- **COVERED now (all 8 must-have rows + smoke):** row 1 (isolation / S3, brick 1),
  row 2 (migration / Nexus, brick 2), row 3 (native-client / dnf+apt+docker, brick 3),
  row 4 (proxy-egress / #2570, brick 4), row 5 (sso / SAML XSW, brick 5),
  row 6 (upgrade / legacy-data #2574/#2584, brick 6), row 7 (supply-chain /
  scanner-efficacy #2088, brick 7), row 9 (dos / rate-limit + worker-starvation,
  brick 7), and row 10s (smoke / filesystem, brick 0). All run under the single
  `harness/run.sh <tier>` contract, health-gated, per-slot isolated, JUnit into
  `results/<tier>/`, real pass/fail exit codes, never touching :8080.
- **Still GAP:** row 8 WASM plugin signing / cosign only — brick 7's
  `filesystem+trivy` profile provisions no plugin-signing keypair or plugin-load
  fixture, so a real discriminating oracle is not stand-up-able without net-new
  fixtures; deferred to a dedicated plugin-signing overlay (future brick).
  The CI gate workflow (brick 8) is deferred as online work.
- **Profiles present:** `storage.filesystem`, `storage.s3`, `upstreams.nexus`,
  `proxy.squid`, `sso.saml`, `client.dnf/apt/docker`, `scanners.trivy`. Every
  other overlay in design §2.1 is a later brick.

## Brick-2 status (migration / Nexus — #2457)

- **Profile:** `profiles/upstreams.nexus.yml` stands up a pinned `sonatype/nexus3`
  as a real migration source; the tier bootstraps (EULA + admin), seeds single-
  AND multi-arch Docker fixtures, migrates into the candidate backend, then runs
  `tiers/migration/assert.sh` (vendored `nexus_migrate_assert`).
- **Discriminating both ways:** green (exit 0) on the #2457-fixed image
  (`ak-backend:v158-4fix`); red (5 findings, exit 1) on the pre-fix
  `nexus2457-v157base` — config-blob 404, child-manifest 404, `oci_blobs==0`,
  and the multi-arch leg (the leg the v1.5.5 single-arch-only fix missed).

## Brick-4 status (proxy-egress / #2570)

- **Profile:** `profiles/proxy.squid.yml` puts the backend behind a squid egress
  proxy (`HTTP(S)_PROXY` → squid). `tiers/proxy-egress` proves the legit
  egress-through-proxy path AND that SSRF upstreams (IP-literal + hostname
  resolving to a private IP) are still refused.
- **Discriminating both ways:** green on `ak-backend:fix-2574` (legit half works,
  SSRF half refused, 5/5); RED on pre-#2570 `ak-backend:pr2578` — the legit half
  returns the exact `502 BAD_GATEWAY "Failed to reach upstream"` (the SSRF DNS
  guard blocking the configured proxy's own private IP) while the SSRF half stays
  green, proving the oracle discriminates and the proxy exemption did not open a
  hole.

## Brick-5 status (sso / SAML XSW — #2449 CRITICAL)

- **Profile:** `profiles/sso.saml.yml` adds Keycloak 24.0 as a real SAML IdP with
  a canned realm-import (`fixtures/keycloak-realm.json`: SAML client
  `artifact-keeper` + a test user), health-gated on the realm SAML descriptor,
  published on the slot's spare `${TRIVY_PORT}`.
- **Oracle:** `tiers/sso/oracle.sh` drives the real per-provider ACS flow. A
  standalone Rust payload generator (`tiers/sso/probe/`, crates.io-only deps, NOT
  the backend crate) mints an ephemeral IdP keypair, registers it via
  `/api/v1/admin/sso/saml`, signs base assertions with **bergshamra** (the crate
  the backend verifies with), then crafts every XSW variant.
- **Discriminating both ways (asserts identity/role via DB, not just HTTP code):**
  green on `ak-backend:fix-2574` (12/12); RED on pre-#2449 `ak-backend:fix-2329` —
  XSW 1 reproduces the CRITICAL escalation (307 + attacker `is_admin=t`) and the
  tier exits non-zero. Supersedes `tests/security/test-saml-signature.sh` (which
  404s against the current per-provider ACS routes).
