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
| 20 | **Poisoned proxy-cache entry heals; short OCI part is a storage failure; short upstream body is a 502** — #4630/#4646/#4758/#4759 | filesystem + `upstreams.mock-static` | an entry rewritten to empty `__content__` + intact sidecar is re-fetched once (full bytes, sha matches, upstream count +1) and rewritten, both with the MD5-of-empty `storage_etag` pinned (#4630) and with none pinned, the filesystem default (#4758); a stored OCI upload part truncated by 4 KiB fails commit with `BLOB_UPLOAD_UNKNOWN` naming the part and publishes no blob; an upstream that promises N bytes and sends none answers `502 UPSTREAM_SHORT_BODY` naming the repository and N/0, one that stops at half closes short and logs a warn with `expected_bytes`/`received_bytes` (#4759); neither is ever cached and both recover (control) | **proxy-cache-empty-object** | **COVERED** (#459, tightened in this PR) — green on main `087d395f` (11/11), red on main `6a4e29f1` (8 pass / 3 fail: #4758 bodyless 200, #4759 no 502, no warn) and on 1.11.1 (6 pass / 5 fail) |
| 21 | **A DB outage answers a retryable 503, not 401 or 500** — #4750/#4756/#4765 | filesystem (stops its own slot's postgres for ~60 s) | Bearer JWT, Basic (password / JWT / wrong password) on a private maven route, `/v2/` Bearer and Basic, `/v2/token` Basic all answer `503` + `Retry-After: 1` (OCI `UNAVAILABLE`) while the DB is down; login (correct and wrong password) and a Bearer API token on `/api/v1/auth/me` answer `503 DATABASE_UNAVAILABLE` + `Retry-After: 1` (#4756); a Git LFS batch answers 503 + `Retry-After: 1` in the LFS `{message, request_id}` envelope and an npm metadata GET answers `503 DATABASE_UNAVAILABLE` (#4765); `/readyz` reports the DB unhealthy; after restart the pool reconnects and the pre-outage JWT and API token still work | **auth-db-outage** | **COVERED** (#456, tightened in this PR) — green on main `087d395f` (32/32), red on main `6a4e29f1` (27 pass / 5 fail: 500 DATABASE_ERROR) and on 1.11.1 (20 pass / 12 fail: 401 / 500) |
| 22 | **Privileged admin actions write audit rows; scheduled audit retention** — #4710/#4718/#4762 | filesystem + `secrets.webhook-key` | 23 actions (permission rules, webhooks incl. rotate-secret, OIDC provider, signing keys, quarantine release/reject, promotion, approvals, sync policies) each write exactly one `audit_log` row with action/resource/actor/client IP/details, none carrying secret material; the REPOSITORY_CREATED/USER_CREATED rows record the client IP (#4762); with retention saved as 1 day the scheduler's first pass (~4.5 min after start) deletes rows backdated 2/30/100 days and keeps the 23-hour-old and fresh ones | **audit-event-coverage** | **COVERED** (#461, tightened in this PR) — REPOSITORY_CREATED/USER_CREATED rows now must carry the TCP peer IP (#4762). Green on main `087d395f` (37/37), red on main `6a4e29f1` (35 pass / 2 fail: ip_address NULL) and on 1.11.1 (8 pass / 29 fail: 2xx but 0 rows; settings report 90; no scheduled pass; no IP) |
| 145 | **Plugin install and reload fetch git sources through the SSRF-guarded client** - #4827 (fixed by #4841, backported to 1.11.4) | filesystem + `upstreams.mock-git` + `upstreams.mock-git-rebind` (a local DNS server whose answer changes between lookups) | an address that changes after the URL check is refused with 400 naming `AK_SSRF_ALLOW_PRIVATE_CIDRS` on install and reload, the internal host sees no request and nothing is stored; redirects off the admitted host (internal host, the backend's loopback) are refused; a same-host redirect and the static resolver still install and reload | **plugin-fetch-pinned-address** | **COVERED** (#574, `security-1.11.x-boundary`): green on main `adfa0206` (8/8, exit 0), red on 1.11.3 (3 pass / 5 fail: every FIX case, controls green). Extended by #604 for #4869 (fixed by #4872): a redirect hop the per-hop SSRF policy refuses (the backend's loopback, an internal IP literal) answers 400 with the plugin policy wording on install and reload and 503 on a Remote's download, never contacting the target: green on main `81f0b1c9` (11/11), red on 1.11.4 (7 pass / 4 fail: 500 on the plugin path, 502 on the proxy path). Gate-group proof on main `a5e0aeb3`: 11/11 |
| 146 | **Logout without the refresh token ends the session** - #4831 (fixed by #4862) | filesystem | a bearer logout with an empty body and a cookie-jar logout both make the session's refresh token 401 and revoke every `refresh_token_jti` row of its family; refresh-token-in-body and refresh-cookie logouts, rotated-token replay and per-session scoping hold on every image | **auth-logout-revokes-session** | **COVERED** (#575, `fixes-1.11.4`): green on `fix-auth` (main `adfa0206` + #4862 + #4863; 6/6, exit 0), red on 1.11.3 (4 pass / 2 fail: shapes A and D refresh 200, rows unrevoked) |
| 147 | **Removing LDAP_* disables the env-seeded LDAP provider** - #4857 (fixed by #4863) | filesystem + tier-local backend overrides with and without `LDAP_*` | a boot without `LDAP_*` keeps the row but disables it, local login comes back and the log names the provider; an admin re-enable takes ownership and survives the next boot; an admin-created provider is untouched | **ldap-env-bootstrap-lifecycle** | **COVERED** (#576, `fixes-1.11.4`): green on `fix-auth` (5/5, exit 0), red on 1.11.3 (3 pass / 2 fail: still enabled and listed, ownership record kept) |
| 148 | **Repository delete and storage GC reclaim filesystem copies of shared content** - #4833 (fixed by #4864) | filesystem | deleting repo A leaves nothing under A's tree even when repo B holds the same content key, and a GC pass finds nothing left; a trashed copy in C is reclaimed while D holds the key; B and D still serve byte-exact | **repo-delete-reclaims-storage** | **COVERED** (#577, `fixes-1.11.4`): green on `fix-storage` (main + #4864 + #4859; 7/7, exit 0), red on 1.11.3 (4 pass / 3 fail: A's shared file leaked, kept by GC, C's trashed copy kept) |
| 149 | **A slow Azure server-side copy completes; its error carries no SAS** - #4858 (fixed by #4859), #4866 | `storage.azure-stub` (a local fake Azure Blob endpoint that holds each Put Blob From URL for a set delay or drops it) | a 45 s copy under an OCI blob finalize and a staged generic upload both end 201 and read back byte-exact; a dropped copy fails naming Put Blob From URL with no `sig=`/`sp=` in the body or the backend log; 0 s copies pass on every image | **azure-copy-long-running** | **COVERED** (#578, extended by #579, `fixes-1.11.4`): green on `fix-azure-sas` (main with #4859 and #4866; 6/6, exit 0, ~2 min), red on 1.11.3 (3 pass / 3 fail: both copies 500 after ~30 s, the error body and log quote the signed URL). `fix-storage` (#4859 only) passes the two #4858 cases (5/5 before #579) |
| 150 | **Translated NuGet V2 feeds list versions from every upstream page** - #4856 (fixed by #4855) | filesystem + `upstreams.mock-multi` (three-page V2 feed, and one whose next link leaves the origin) | Remote V3 registration and flat container, and a virtual's registration, flat container and V2 `FindPackagesById()` list all four versions across three pages; a cross-origin continuation is not requested and page 1 is served | **nuget-v2-continuation-pages** | **COVERED** (#582, `fixes-1.11.4`): green on `fix-formats` (main + #4855 + #4867 + #4868; 8/8, exit 0), red on 1.11.3 (3 pass / 5 fail: every FIX case lists only `1.0.0`) |
| 151 | **Concurrent PUTs to one generic path have one winner** - #4832 (fixed by #4868) | filesystem | 16 concurrent distinct PUTs to one free path give one 201 and fifteen 409 `CONFLICT`, and the stored bytes and the single live row are the winner's; sequential re-PUT is 409, distinct paths all 201, a versioning repository appends revisions | **generic-concurrent-put-contract** | **COVERED** (#584, `fixes-1.11.4`): green on `fix-formats` (5/5, exit 0), red on 1.11.3 (4 pass / 1 fail: 16 x 201, the stored bytes are not the reported winner's) |
| 152 | **Push replication is not echoed back and a late pacman `.sig` reaches the peer** - #4792 (fixed by #4887) | filesystem + `peer.second-instance` + `client.pacman` (builds the `.nupkg`, the pacman package and its detached signature at run time) | a NuGet push and a nested RPM PUT arriving at B as peer writes (`X-Artifact-Keeper-Replication: true`) queue no push row back to A and never reach A; a `.sig` attached on A after its package was delivered is served by B byte-equal within 60 s; NuGet, nested RPM and pacman uploads on A each reach B once | **push-sync-echo-and-sidecars** | **COVERED** (#597, `fixes-1.11.5-sync`): green on `fix-4792-replication-gaps` (10/10), red on 1.11.4 (6 pass / 4 fail: both echoes queued and delivered back to A, the `.sig` 404 on B). Gate-group proof on main `a5e0aeb3`: 10/10 |
| 153 | **An artifact stored through an upload session is pushed to its peers** - #4791 (fixed by #4875) | filesystem + `peer.second-instance` | a three-chunk and a one-chunk `/api/v1/uploads` session on A each queue one push row for B, B holds the same sha256 and serves it within 90 s; a replicated session on B queues nothing back to A (guard); a REST PUT reaches B on every image (control) | **push-sync-chunked-upload** | **COVERED** (#605, `fixes-1.11.5-sync`): green on main `81f0b1c9` (7/7), red on 1.11.4 (5 pass / 2 fail: no push row after complete, B 404). Gate-group proof on main `a5e0aeb3`: 7/7 |
| 154 | **Failed startup database connects are exported on `/metrics`** - #4828 (fixed by #4888) | filesystem + `metrics.port` (`METRICS_PORT=9091`, json-file logs) | with the slot's Postgres paused across the boot, `ak_db_pool_connection_failures_total{stage="startup"}` is at least 1 once the backend is up, matching the logged failed attempts | **metrics-startup-db-retry** | **COVERED** (#601, `fixes-1.11.5-sync`): green on `fix-4828-startup-pool-metric` (5/5), red on 1.11.4 (4 pass / 1 fail: series absent after 3 logged failures). Gate-group proof on main `a5e0aeb3`: 5/5. Row 88's #4828 pin is now an assertion |
| 155 | **A remote CEP-16 shard refused for its content address is not cached and recovers** - #4829 (fixed by #4886) | filesystem + `upstreams.mock-conda-sharded` | while the upstream serves wrong bytes the shard is 502 through R and V and nothing is cached; after `/__heal` V serves the right bytes, the upstream is asked again, the cache holds the right checksum and R then serves it from cache | **conda-remote-shard-recovers** | **COVERED** (#598, `fixes-1.11.5-proxy`): green on `fix-4829-shard-cache-poison` (7/7), red on 1.11.4 (3 pass / 4 fail: wrong bytes cached, still 502 after heal). Gate-group proof on main `a5e0aeb3`: 7/7. Row 107's #4829 pin is now an assertion |
| 156 | **`AK_PROXY_METADATA_BUDGET_BYTES` above 4 GiB is honoured** - #4881 (fixed by #4885) | filesystem + `limits.proxy-metadata-budget` | with a 32 GiB budget the conda virtual merge gate logs `budget_bytes=34359738368` and its default `max_merges` grows past 3 | **proxy-metadata-budget-env** | **COVERED** (#599, `fixes-1.11.5-proxy`): green on `fix-4881-budget-clamp` (5/5), red on 1.11.4 (3 pass / 2 fail: clamped to 4294967295, `max_merges=3`). Gate-group proof on main `a5e0aeb3`: 5/5 |
| 157 | **A conda virtual merges each subdir once and serves the kept merge while it rebuilds** - #4879 (fixed by #4890) | filesystem + `upstreams.mock-conda-stale` (a remote whose next repodata generation answers late) | `repodata.json`, `.json.zst` and `.json.bz2` cost one merge miss; past the member TTL the virtual answers within 3 s with the previous generation, `Warning: 110` and the `via="stale"` hit counter (2 of 3 cycles), and serves the new generation within 40 s | **conda-virtual-stale-serve** | **COVERED** (#600, `fixes-1.11.5-proxy`): green on `fix-4879-conda-stale-serve` (7/7), red on 1.11.4 (4 pass / 3 fail: 3 misses, 0/3 stale serves, ~8 s first GET). Gate-group proof on main `a5e0aeb3`: 7/7 |
| 158 | **A CRAN remote serves its upstream `PACKAGES` so R installs through it** - #4877 (fixed by #4880) | filesystem + `upstreams.mock-multi` (`/ok/cranrich`, gzip-only `/ok/crangz`) + `client.cran` | the remote's `PACKAGES` and `PACKAGES.gz` list exactly the upstream's records byte-equal (continuation lines and MD5sum intact), a gzip-only upstream still yields an index, `install.packages("dtfcrana")` resolves and installs the dependency graph through the remote | **cran-remote-packages-index** | **COVERED** (#603, `fixes-1.11.5-proxy`): green on main `81f0b1c9` (8/8), red on 1.11.4 (2 pass / 6 fail: empty `PACKAGES`, R finds no package). Gate-group proof on main `a5e0aeb3`: 8/8 |
| 159 | **Deleting a versioned repository purges its older revisions** - #4865 (fixed by #4873) | filesystem (stored objects read off the backend's `/data` volume through a throwaway `postgres:16-alpine` with `--volumes-from`) | a versioning-enabled generic repository A with two revisions of each of two paths, and B pointed at A's root holding one shared revision; after `DELETE` of A the older revision's object is gone within 30 s and the spared shared revision key is in `oci_gc_candidates` with `source_repository_id` = A; HEAD objects are purged, `artifact_versions` cascade, B still downloads the shared object (controls) | **repo-delete-purges-revisions** | **COVERED** (#602, `fixes-1.11.5-storage`): green on `pr-4873` (6/6), red on 1.11.4 (4 pass / 2 fail: older revision object still on the volume, no GC candidate row). Gate-group proof on main `e211aa3f`: 6/6 |
| 160 | **The PyPI age gate resolves a PEP 440-equal filename version to its release publish time** - #4907 (fixed by #4908, backported to 1.11.x by #4912) | filesystem + `upstreams.mockpypi-agegate` (`172.28.<slot>.50`, a Warehouse JSON and PEP 691 simple index mock for `cuda-toolkit`) | with `upstream_publish_time` and `min_age_days=7` on a PyPI remote, `13.0.3.0` (filename spelling of the 2026-04-14 release `13.0.3`) is listed in the HTML and JSON simple index and downloads 200 with the mock's sha256; controls: `13.4.2` is served, `13.5.0` (one day old) and `13.0.3.1` (no equal release) are absent and 451, and the backend fetched `/pypi/cuda-toolkit/json` | **pypi-age-gate-pep440-lookup** | **COVERED** (#612, `fixes-1.11.6-pypi`): FIX gate, green on main `48b0424c` (`fix-4907`, 17/17) and on the 1.11.x line after #4912; red on 1.11.5 (14 pass / 3 fail: `13.0.3.0` missing from both indexes, download 451) |

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

## 1.11.4 fix-coverage status (rows 145-151, artifact-keeper-test#574-#584)

- **Seven tiers and one extension** cover the 1.11.4 backports: rows 145-151
  plus the #4851 case in row 47 (`upstream-url-userinfo-redaction`). Each
  was proven in its own PR: red on 1.11.3 on exactly its FIX cases with every
  control holding, green on a main build carrying the fix (`main-adfa0206`
  for #4827, `fix-auth`, `fix-storage`, `fix-azure-sas` and `fix-formats` for
  the others). All of those fixes are merged on backend main.
- **Gate wiring:** `plugin-fetch-pinned-address` joins
  `security-1.11.x-boundary` next to `plugin-reload-ssrf`; the other six form
  the new required group `fixes-1.11.4` (about 5 min, the Azure copy tier is
  ~2 min of it). Like the other fix groups these are red on every image older
  than the fix on main, so a 1.11.4 candidate runs them from
  `release/1.11.x`, which carries the same tiers.
- **New profiles:** `upstreams.mock-git-rebind` (a stdlib-python DNS server
  at `172.16.<slot>.82`, used as the backend's resolver) and
  `storage.azure-stub` (an in-memory fake Azure Blob endpoint; Azurite copies
  instantly and refuses Put Blob From URL on a SAS destination, so it cannot
  reproduce #4858). `upstreams.mock-multi` gained the paged V2 feeds and a
  second listener on port 8081; `mock_git.py` gained `name=` and `redirect=`.
- **Finding, since fixed:** on the 1.11.4 build a refused plugin-fetch
  redirect answers 500 instead of 400 (`clone_repository` mapped only
  "blocked by SSRF policy"); the target is never contacted. Filed as
  artifact-keeper#4869, fixed by #4872 and asserted since #604 (row 145).
- **On this line:** `matrix.md` carries rows 1-22 and 145-151; rows 23-144
  and row 47 (`upstream-url-userinfo-redaction`, whose #4851 case and
  `/readyz` wait came with #583) are in main's `matrix.md`, which is also
  where the gate matrix is read from. The tiers of rows 47 and 145-151 are
  all on this line.
- **#581** derives the `sso.ldap-env-bootstrap` bind password at run time in
  `ldaps`, so the profile no longer carries a literal. This line has had the
  same change since #580.

## 1.11.5 fix-coverage status (rows 152-159, artifact-keeper-test#597-#606)

- **Seven tiers and one extension** cover the 1.11.5 fixes: rows 152-158
  plus the #4869 cases in row 145 (`plugin-fetch-pinned-address`, #604).
  Each was proven in its own PR: red on 1.11.4 on exactly its FIX cases with
  every control holding, green on a build carrying the fix. All eight
  backend fixes are merged on main at `a5e0aeb3`
  (`ghcr.io/artifact-keeper/artifact-keeper-backend:sha-a5e0aeb`).
- **Gate wiring:** two new required groups. `fixes-1.11.5-sync` runs the two
  `peer.second-instance` push-sync tiers and the paused-Postgres
  `/metrics` tier (about 3 min locally); `fixes-1.11.5-proxy` runs the conda
  shard, metadata budget, conda stale-serve and CRAN tiers, each on its own
  mock (about 2.5 min locally with `rocker/r-ver:4.4` already pulled; a
  fresh runner pulls it first). Both are red on every image older than the
  fixes on main, so a 1.11.5 candidate runs them from `release/1.11.x`,
  which carries the same tiers (picked from #597-#605 by the line's 1.11.5
  batch).
- **KNOWN-RED pins flipped:** #4829 in `conda-sharded-remote-virtual` and
  #4828 in `db-keepalive-startup-retry` are assertions now; each is green on
  main `a5e0aeb3` and red on 1.11.4 on that case only. Both tiers are on
  this line; their rows (107 and 88) are in main's `matrix.md`.
- **Batch 2 (#602, #606, backend #4873 and #4874, on the 1.11.x line since
  backport batch 2, artifact-keeper#4894):** `repo-delete-purges-revisions`
  (row 159, #4865) runs as the required group `fixes-1.11.5-storage`. #606
  turned the #4837 pin in `maven-upload-tx-and-quality-s3` into a gate and
  added a control that a failed first publish overlapping a successful one
  of the same coordinate keeps the winner's bytes. That tier's row (124) is
  in main's `matrix.md`; the gate runs it in main's `storage-1.11.0` group,
  which is therefore red on 1.11.4. No KNOWN-RED pin from the 1.11.x wave
  is left open.
- **New profiles:** `upstreams.mock-conda-stale` (`172.16.<slot>.72`, a
  conda remote whose next repodata generation answers late),
  `limits.proxy-metadata-budget` and `metrics.port`.
  `limits.conda-merge-gate` passes `CONDA_VIRTUAL_MERGE_MAX_STALE_SECS`.
  `mock_multi.py` gained two CRAN upstreams (`/ok/cranrich`, `/ok/crangz`)
  and `mock_git.py` a `/__redir/` redirect; every tier on those mocks
  (`proxy-virtual-1.11.0`, `nuget-v2-continuation-pages`,
  `plugin-reload-ssrf`) is green on main `a5e0aeb3`.
- **On this line:** rows 152-159 and the row 145 update are added here; the
  gate reads its matrix (including `fixes-1.11.5-sync`,
  `fixes-1.11.5-proxy` and `fixes-1.11.5-storage`) from main's
  `release-gate.yml` and runs these tiers from this branch.

## 1.11.6 fix-coverage status (row 160, artifact-keeper-test#612)

- **`pypi-age-gate-pep440-lookup`** (row 160) covers #4907: the PyPI
  `upstream_publish_time` age gate looked a filename version up verbatim, so
  `13.0.3.0` found no publish time under the Warehouse release key `13.0.3`
  and was withheld. It is a FIX gate: red on 1.11.5 on exactly the three FIX
  cases with every control holding, green on main `48b0424c` (#4908) and on
  `release/1.11.x` after the backport #4912.
- **Gate wiring:** the new required group `fixes-1.11.6-pypi` (under a
  minute locally). `upstreams.mockpypi-agegate` is a new profile on the
  shared `172.28.<slot>.0/24` mockpypi subnet; each gate group claims its own
  slot and runs its tiers one after another, so it never overlaps
  `pypi-contenttype` or `virtual-pypi-platform-wheel` on one subnet.
  A 1.11.x candidate older than 1.11.6 is red on this group.
- **On this line:** row 160 is added here; the gate reads its matrix
  (including `fixes-1.11.6-pypi`) from main's `release-gate.yml` and runs
  the tier from this branch.

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
