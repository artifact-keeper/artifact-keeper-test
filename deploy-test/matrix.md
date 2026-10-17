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
| 8s | **Format signing & verification — real clients with verification ON** (#72) | filesystem + client=**apt/dnf/apk/helm** | `tiers/signing/oracle.sh`: per format, a REAL client verifies AK's advertised signature chain. **apt** imports `dists/<suite>/gpg-key.asc` and installs with `signed-by=` and NO `[trusted=yes]`; **dnf** with `repo_gpgcheck=1` + the advertised `gpgkey=`; **apk** `apk add` with NO `--allow-untrusted`; **helm** `pull --verify` against the `.prov`. Every leg carries a discrimination control (unsigned/tampered/untrusted-key/verification-off) | **signing** | **COVERED — standing GREEN regression gate** for the merged backend signing fixes: **rpm** #2645 (real OpenPGP repodata: importable key, gpg-verifiable `.asc`, real `dnf` `repo_gpgcheck=1` installs) + #2679 (`key_type=rsa` on a Debian/RPM repo → 400 at config time), **apk** #2634 (native `C:` Q1 form) + #2677 (fail-closed index signing), **helm** #2640/#2680 (`.prov` stored + served, real `helm pull --verify` succeeds). Negatives hold: unsigned deb repo REFUSED (`E: ... is not signed`), tampered Release/repomd = `BAD signature`, key-removed apk index = `UNTRUSTED signature`. **ONE KNOWN-RED pin remains (C4):** the end-to-end `apk add` verify — the served `.SIGN.RSA` is RSA-SHA256 over the uncompressed index text in a single gzip stream, where apk's contract is SHA1 over the compressed data segment in a two-stream archive, so real apk says `BAD signature`; still open on current main, pinned (fix arrives → pin fails → de-pin). (History: this row shipped as 1-green + 3 KNOWN-RED pins; the fixes merged and 7 of 8 pins were removed.) This tier is the answer to the `[trusted=yes]` / `--allow-untrusted` blind spot in rows 3 and 10 |
| 10s | **Real push→pull→scan smoke** | **filesystem**/single/none | `test-real-flow-smoke.sh` (npm publish → pack pull-back → scan → numeric findings_count) | **smoke** | **COVERED** (brick 0) — green, 8/8 |
| 11 | **Path-traversal (discriminating)** | any | body-assert traversal (not `/dev/null`) | (cross-tier rule) | Partly landed; enforce everywhere |
| 12 | **RBAC / quotas / retention / promotion / webhooks / search / mesh** | as-today (mesh→topology=mesh) | existing suites | (existing tiers) | EXISTS; keep |
| 13 | **Repository/project assignment, permission target names, virtual-only grants** — #4026/#4639/#4690 | filesystem | PATCH `project_id: null` clears the assignment (response + DB) and non-admin gets 403; `GET /api/v1/permissions` resolves `target_name` for group/project/artifact targets and `null` once the group is deleted; a user granted only the virtual gets the `X-AK-Virtual-Members-Notice` header and still 404 on the member | **repo-project-permissions** | **COVERED** (#452) — green on main 6a4e29f1 (18/18), red on 1.11.1 (8 fix cases fail, 10 controls hold) |
| 14 | **Artifact transfer metrics and HTTP listen backlog** — #4642/#4647 | filesystem + `listener.backlog-explicit` | `/api/v1/admin/metrics` moves `ak_artifact_uploads_total` / `ak_artifact_downloads_total` by exactly the requests made (generic and maven); `HTTP_LISTEN_BACKLOG=777` shows as Send-Q 777 on :8080 (`ss` in the backend's netns) and in the startup diagnostic line | **metrics-and-backlog** | **COVERED** (#453) — green (16/16), red on 1.11.1 (8 fail: series absent, backlog 4096 and no diagnostic) |
| 15 | **Format catalog fixes: conan repo-scoped cloud keys, maven version size, rubygems hyphen-digit names** — #4694/#4633/#4645 | storage=**s3** | same conan revision publishes into two repos and both serve it; MinIO + DB hold `conan/{repo_id}/…` keys and a legacy flat-key row still downloads; maven version `size_bytes` = jar+pom+sources, sidecar excluded, backfill agrees; `specs.4.8.gz` decodes to `[dtf-gem-2, 1.2.3]` | **format-catalog-fixes** | **COVERED** (#454) — green (18/18), red on 1.11.1 (10 fail: 409 on the second repo, size 154, `[dtf-gem, 2-1.2.3]`) |
| 16 | **npm unpublish and push-peer sync fan-out** — #4025/#4643/#4658 | filesystem + client=**npm** | real `npm unpublish` (version and whole package, scoped and unscoped) removes what the server serves, the row and writes the delete audit row; raw `-rev` routes answer as #4727 says; `npm publish`, Go `.mod`/`.zip` uploads queue one pending push task each (peer registered at an unresolvable host, held in backoff); a re-upload resets the completed task to pending | **npm-unpublish-and-push-sync** | **COVERED** (#458) — green (34/34), red on 1.11.1 (23 fail; unscoped unpublish exits 0 and leaves the package installable) |
| 17 | **Conda channel documents by repository type, conda audit rows, conda security metrics** — #4708/#4709/#4711 | filesystem + `upstreams.mock-conda` | Remote serves the upstream's `current_repodata.json`, `run_exports.json`, `patch_instructions.json`, `repodata.json.sig`; Virtual builds `current_repodata` from the newest versions and its `.sig` verifies; one audit row each for upload, withdraw, attestation reject, environment register/delete; `ak_conda_allowlist_dropped_total`, `ak_conda_install_script_findings_total`, `ak_conda_attestation_total` exported | **conda-channel-types** | **COVERED** (#460) — green (21/21), red on 1.11.1 (15 fail: empty hosted shape, 0 audit rows, no series) |
| 18 | **Migrated Maven and Debian packages reach the catalog** — #4691/#4657 | filesystem + `upstreams.mock-artifactory-catalog` | a migration from an Artifactory-shaped source with real jar/pom/`.deb` files registers `com.dtf:demo 1.0.0` and `dtfpkg 1.0`/`dtfflat 2.0` in the packages API and `package_versions`; the Debian `Packages` index carries the control-file Description/path/SHA256 and the flat-pool `.deb` is filed under `pool/main/`; recovery via the documented tools (maven backfill; debian re-run); `reindex-storage` registers nothing (control) | **migration-package-catalog** | **COVERED** (#455) — green (13/13), red on 1.11.1 (7 fail: artifacts stored, catalog empty) |
| 19 | **OIDC token exchange, forwarded redirect_uri, login expiry, SSRF refusal hint** — #4699/#4143/#4648/#4638 | filesystem + `sso.oidc-entra-shape` (mock IdP that returns an id_token only when the token request carries `openid`) | the recorded `/token` request carries the configured scopes and login completes; an IdP that never returns an id_token gets `502 OIDC_NO_ID_TOKEN`; forwarded headers honoured only from the trusted peer (in-network curl containers on fixed IPs); SSO exchange reports `expires_in` = configured TTL; LDAP/remote/webhook refusals of `10.10.10.10` name `AK_SSRF_ALLOW_PRIVATE_CIDRS`, metadata refusal names nothing | **oidc-exchange-and-login** | **COVERED** (#457) — green (17/17), red on 1.11.1 (11 fail: no `scope`, 500 INTERNAL_ERROR, spoofed https believed, field absent, settings unnamed) |
| 20 | **Poisoned proxy-cache entry heals; short OCI part is a storage failure** — #4630/#4646 | filesystem + `upstreams.mock-static` | an entry rewritten to empty `__content__` + intact sidecar + MD5-of-empty `storage_etag` is re-fetched once (full bytes, sha matches) and the entry rewritten; a stored OCI upload part truncated by 4 KiB fails commit with `BLOB_UPLOAD_UNKNOWN` naming the part and publishes no blob; a no-body/half-body upstream is never cached and recovers (control) | **proxy-cache-empty-object** | **COVERED** (#459) — green (8/8), red on 1.11.1 (2 fail: bodyless 200 with Content-Length 262144; `DIGEST_INVALID`). Remaining halves filed: artifact-keeper#4758 (no-ETag filesystem heal), #4759 (short upstream body drops the client connection) |
| 21 | **A DB outage during a credential check answers 503, not 401** — #4750 | filesystem (stops its own slot's postgres for ~45 s) | Bearer JWT, Basic (password / JWT / wrong password) on a private maven route, `/v2/` Bearer and Basic, `/v2/token` Basic all answer `503` + `Retry-After: 1` (OCI `UNAVAILABLE`) while the DB is down; `/readyz` reports the DB unhealthy; after restart the pool reconnects and the pre-outage JWT and API token still work | **auth-db-outage** | **COVERED** (#456) — green (24/24), red on 1.11.1 (7 fail: 401 without Retry-After). Finding filed: artifact-keeper#4756 (login itself still answers 500 DATABASE_ERROR) |
| 22 | **Privileged admin actions write audit rows; scheduled audit retention** — #4710/#4718 | filesystem + `secrets.webhook-key` | 23 actions (permission rules, webhooks incl. rotate-secret, OIDC provider, signing keys, quarantine release/reject, promotion, approvals, sync policies) each write exactly one `audit_log` row with action/resource/actor/client IP/details, none carrying secret material; with retention saved as 1 day the scheduler's first pass (~4.5 min after start) deletes rows backdated 2/30/100 days and keeps the 23-hour-old and fresh ones | **audit-event-coverage** | **COVERED** (#461) — green (35/35), red on 1.11.1 (27 fail: 2xx but 0 rows; settings report 90; no scheduled pass). Finding filed: artifact-keeper#4762 (REPOSITORY_CREATED/USER_CREATED rows carry no client IP) |

## Consolidated status (this checkpoint)

- **COVERED now (all 8 must-have rows + smoke):** row 1 (isolation / S3, brick 1),
  row 2 (migration / Nexus, brick 2), row 3 (native-client / dnf+apt+docker, brick 3),
  row 4 (proxy-egress / #2570, brick 4), row 5 (sso / SAML XSW, brick 5),
  row 6 (upgrade / legacy-data #2574/#2584, brick 6), row 7 (supply-chain /
  scanner-efficacy #2088, brick 7), row 9 (dos / rate-limit + worker-starvation,
  brick 7), and row 10s (smoke / filesystem, brick 0). All run under the single
  `harness/run.sh <tier>` contract, health-gated, per-slot isolated, JUnit into
  `results/<tier>/`, real pass/fail exit codes, never touching :8080.
- **NEW — row 8s (signing, #72):** the four corpus signing scripts had **0 hits in
  `release-gate.yml`** (they ran nowhere), and every real-client leg we owned ran with
  verification DISABLED (`[trusted=yes]`, `--allow-untrusted`, `gpgcheck=0`). The
  `signing` tier turns verification ON for apt/dnf/apk/helm. When first written it
  surfaced three real defects (rpm signature-theater, apk `C:` encoding, helm `.prov`
  discarded) that were pinned KNOWN-RED; the backend fixes (#2645/#2679, #2634/#2677,
  #2640/#2680) merged, 7 of 8 pins were removed, and the tier now stands as their
  permanent regression gate. One pin remains: the apk end-to-end verify (C4) — the
  `.SIGN.RSA` digest/framing is still not apk-verifiable on current main. Row 8s does
  NOT close row 8 (WASM/cosign plugin signing) — that remains a separate GAP.
- **Still GAP:** row 8 WASM plugin signing / cosign only — brick 7's
  `filesystem+trivy` profile provisions no plugin-signing keypair or plugin-load
  fixture, so a real discriminating oracle is not stand-up-able without net-new
  fixtures; deferred to a dedicated plugin-signing overlay (future brick).
  The CI gate workflow (brick 8) is deferred as online work.
- **Profiles present:** `storage.filesystem`, `storage.s3`, `upstreams.nexus`,
  `proxy.squid`, `sso.saml`, `client.dnf/apt/docker`, `scanners.trivy`. Every
  other overlay in design §2.1 is a later brick.

## 1.11.2 fix-coverage status (rows 13–22, artifact-keeper-test#452–#461)

- **Ten tiers, one per fix group of the artifact-keeper 1.11.2 milestone**, each
  proven both ways on this host: GREEN on the `:main` digest built from
  `6a4e29f1` (every 1.11.2 fix merged) and RED with exit 1 on the released
  `ghcr.io/artifact-keeper/artifact-keeper-backend:1.11.1` image, with every
  control case holding on both. The released image is the standing pre-fix
  baseline for discrimination; no locally built image is needed.
- **New profiles:** `listener.backlog-explicit`, `upstreams.mock-conda`,
  `upstreams.mock-artifactory-catalog`, `sso.oidc-entra-shape`,
  `upstreams.mock-static`, `secrets.webhook-key`. Mock fixtures are copied into
  each tier's `fixtures/` rather than shared, per the collision contract.
- **Four backend findings came out of writing them**, all filed on 1.11.2:
  artifact-keeper#4756 (login answers 500 during a DB outage), #4758 (the
  proxy-cache heal needs a pinned ETag, which filesystem storage never writes),
  #4759 (a short upstream body drops the client connection), #4762 (two audit
  writers record no client IP).
- **Host notes that are not product findings:** under rootless podman the
  journald log driver drops startup lines (`docker logs` returns one line), so
  tiers that read the backend log pin `logging: driver: json-file` in their
  profile; SELinux-enforcing hosts need `security_opt: [label=disable]` on
  containers that bind-mount a fixture script (the older mock profiles do not
  set it and will fail to start there).
- **Gate wiring:** the release gate's `dtf-gate` matrix carries them in three
  groups (`fixes-1.11.2-api`, `fixes-1.11.2-formats`, `fixes-1.11.2-ops`);
  `run.sh all` lists them after the existing tiers, `audit-event-coverage` last.

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
