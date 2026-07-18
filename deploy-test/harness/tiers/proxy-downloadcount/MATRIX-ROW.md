# MATRIX-ROW — proxy-downloadcount (PKT-F, P6, issue #2537)

Integrator: merge the row below into `matrix.md` (new row after the current last
row). One tier, `proxy-downloadcount`.

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 17 | **Proxy-cache first-serve download count** — #2537 | upstreams=**raworigin** (+ filesystem/single) | generic REMOTE repo -> tiny nginx origin; ONE cold `GET /general/<key>/<obj>` (200 + marker). Assert the proxy download count (`proxy_download_statistics` JOIN `proxy_cache_artifacts`, the `download_count_by_repo` query) is **exactly 1** after the first serve (RED: 0 — first serve undercounted). MONO: 2nd GET -> 2. HEAD guard: no increment | **proxy-downloadcount** | **COVERED** — self-discriminating on the count value (==1, not >=1); a pre-#2537 backend records 0 for the first cold serve -> tier red. Asserted at the **DB surface** (see observability note) |

## Shared-file needs (integrator single-pass)

- **`run.sh` `all` list:** add `proxy-downloadcount`. Runs green on the single
  candidate image (`ak-backend:candidate-a4d7f9d1`), so it joins the one-image
  `all` run.
- **`ports.sh`:** NO new published port. `raw-origin` is reached
  container-to-container on the slot's private `raworigin` net
  (172.30.<slot>.0/24); nothing is host-published.
- **`run.sh` manifest-env passthrough:** NONE new. Only `RATE_LIMIT_ENABLED`,
  already special-cased by `run.sh`.
- **New owned files (this packet only):**
  `harness/tiers/proxy-downloadcount/{manifest,oracle.sh,MATRIX-ROW.md}`,
  `profiles/upstreams.raworigin.yml`.

## OQ#4 RESOLVED — and a filed product-gap finding

The build plan (OQ#4) asked which of `GET /api/v1/admin/downloads` vs
`GET /api/v1/admin/analytics/downloads/trend` reflects the proxy first-serve
count. **Verified answer against `candidate-a4d7f9d1`: NEITHER — no HTTP endpoint
surfaces the proxy first-serve count at all.**

- `record_proxy_download` (proxy_helpers) -> `proxy_catalog::record_proxy_download`
  writes to the sibling table **`proxy_download_statistics`**, keyed via the
  `proxy_cache_artifacts` catalog row. This is the table the #2537 fix ensures a
  row in on the first cold serve.
- `admin/downloads` (`query_downloads`), `analytics/downloads/trend`
  (`analytics_service::get_download_trends`), AND `artifacts/{id}/stats` /
  `artifacts/{id}` all read the **separate** `download_statistics` table
  (hosted-artifact attribution, `record_download`). The remote pull-through serve
  path (`try_remote_or_virtual_download` Remote arm) calls **only**
  `record_proxy_download`, never `record_download`, and a proxy-cached object has
  **no `artifacts` row** (#1280) — so none of those endpoints ever reflect a
  proxy serve.
- The **only** reader of `proxy_download_statistics` is
  `proxy_catalog::download_count_by_repo`, and it is **not wired to any route**
  in the candidate (grep: zero HTTP callers). Its own doc says it "backs
  analytics that UNION ALL the hosted count with the proxy sibling" — that union
  is **not yet wired** into `get_download_trends` (which reads only
  `download_statistics`).

**Consequence:** the #2537 first-serve count is deployment-observable ONLY at the
DB surface, so this oracle asserts it via `docker exec $DB_CONTAINER psql` (the
established DTF DB-surface idiom used by storage-accounting / sso / upgrade /
migration). This is still a genuine deployment-level, discriminating test: a real
cold proxy serve through the real backend, then the exact `download_count_by_repo`
query against the row it should write.

**Filed finding for the product team (not a DTF gap):** `proxy_download_statistics`
has no HTTP surface — `download_count_by_repo` is dead code until wired into an
analytics union or an admin endpoint. Until then the proxy first-serve counting
that #2537 fixes is invisible to any API consumer. Recommend wiring
`download_count_by_repo` into `analytics/downloads/trend` (the UNION the code
comments already anticipate) or exposing a per-repo proxy-download count; once
that lands, this oracle can add an HTTP assertion alongside the DB one.

## EXPECT_FAILURE self-test

EXPECT_FAILURE-aware via `end_suite` (no extra code). The `==1` (not `>=1`)
assertion is the discriminator; to belt-and-suspenders against a real pre-#2537
build, run `EXPECT_FAILURE=1 ./harness/run.sh proxy-downloadcount
--backend-image <pre-#2537>` and confirm the tier exits 0 (it correctly caught
the first-serve-recorded-0 red). No pre-fix image is required for the primary gate.
