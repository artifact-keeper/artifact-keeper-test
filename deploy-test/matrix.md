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
| 3 | **Native client via advertised route** — #2477/#2580 | client=**dnf/apt/docker** (+proxy) | `ak` push → `dnf/apt install` follows repodata `<location>`; `docker pull` proxy repo ≥2 token exchanges | native-client | GAP — **brick 3** |
| 4 | **Egress proxy / SSRF hostname→private IP** — #2570 | proxy=**squid** | backend behind squid; legit egress-through-proxy works (not 502) AND SSRF upstream (IP-literal + hostname→private IP) still refused | **proxy-egress** | **COVERED** (brick 4) — green on fix-2574, legit half 502s on pre-#2570 (pr2578); SSRF half holds on both |
| 5 | **SAML XSW / SSO** — #2449 (CRITICAL) | sso=**saml (keycloak)** | XSW-wrapped assertion admin-escalation MUST fail; claim extraction scoped to signed subtree | **sso** | **COVERED** (brick 5) — green on fix-2574 (12/12), DISCRIMINATING: pre-#2449 fix-2329 reproduces XSW admin escalation (307 + attacker is_admin=t) and the tier exits non-zero |
| 6 | **Upgrade with legacy data** — #2574/#2584 class | upgrade (seed old rows → swap image) | seed row-less Maven object, upgrade candidate, re-run isolation → still isolated | upgrade | GAP — **brick 6** (reuses row 1 oracle) |
| 7 | **Scanner efficacy (pinned-CVE)** — #2088 | scanners=**trivy** | pinned-CVE image → scan reports the known CVE; false-clean fails | supply-chain | EXISTS (k8s gate + pool trivy sidecar); MIGRATE — **brick 7** |
| 8 | **WASM plugin signing / cosign** | scanners=trivy + plugin overlay | signed plugin loads; tampered/unsigned rejected | supply-chain | Partial (exempted in gate) → GAP — **brick 7** |
| 9 | **Rate-limit / worker-starvation DoS** | dos, **RATE_LIMIT_ENABLED=true** | login-limiter holds; TOTP/bcrypt does not bypass the auth semaphore | dos | GAP (today's overlay disables the control; **DTF base now defaults it ON**) — **brick 7** |
| 10 | **40+ format handlers conformance** | filesystem/single | `tests/formats` (118), `tests/pullthrough` (11) | format-conformance | EXISTS; keep |
| 10s | **Real push→pull→scan smoke** | **filesystem**/single/none | `test-real-flow-smoke.sh` (npm publish → pack pull-back → scan → numeric findings_count) | **smoke** | **COVERED** (brick 0) — green, 8/8 |
| 11 | **Path-traversal (discriminating)** | any | body-assert traversal (not `/dev/null`) | (cross-tier rule) | Partly landed; enforce everywhere |
| 12 | **RBAC / quotas / retention / promotion / webhooks / search / mesh** | as-today (mesh→topology=mesh) | existing suites | (existing tiers) | EXISTS; keep |

## Consolidated status (this checkpoint)

- **COVERED now (5 of the must-have rows):** row 1 (isolation / S3, brick 1),
  row 2 (migration / Nexus, brick 2), row 4 (proxy-egress / #2570, brick 4),
  row 5 (sso / SAML XSW, brick 5), and row 10s (smoke / filesystem, brick 0).
  All run under the single `harness/run.sh <tier>` contract, health-gated,
  per-slot isolated, JUnit into `results/<tier>/`, real pass/fail exit codes,
  never touching :8080.
- **Still GAP (owning brick):** row 3 native-client (brick 3), row 6 upgrade
  (brick 6 — reuses the row-1 oracle), row 7 scanner-efficacy + row 8 WASM/cosign
  + row 9 rate-limit/DoS (brick 7), and the CI gate workflow (brick 8).
- **Profiles present:** `storage.filesystem`, `storage.s3`, `upstreams.nexus`,
  `proxy.squid`, `sso.saml`. Every other overlay in design §2.1 is a later brick.

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
