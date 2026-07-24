# PTF result — #2871 GIN-indexed search_vector (perf epic #2516)

**Profile:** `search-at-scale` · **Fix:** backend PR #2887 (migration `176_artifacts_search_vector.sql`) · **Baseline:** `1.6.2-rc` · **Date:** 2026-07-23

## TL;DR
Full-text artifact search at 500k artifacts went from a **~2.8 s p95 / ~4.2 s tail** to **sub-1-second across the board**, with the latency curve flattened across scales. This is the first PTF-driven performance fix — the profile found the hotspot, the fix landed, and the profile proved the win.

## The hotspot (baseline `1.6.2-rc`)
`SearchService::search` (`/search/quick`, `/search/advanced`) filtered on an **inline functional predicate**:

```sql
to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version,'')) @@ to_tsquery('english', $1)
```

Nothing on `artifacts` matched that expression, so the planner ran a **Parallel Seq Scan recomputing `to_tsvector(...)` per live row — twice** (the pagination `COUNT(*)` re-ran the same predicate). EXPLAIN at ~517k rows showed Postgres pegged at **11–17 cores**.

| scale | FTS p95 (before) |
|---|---|
| 10k | 272 ms |
| 100k | 1.09 s |
| 500k | 3.63 s (single-thread ~4.7 s; tail p99 ≈ 11.8 s under concurrency) |

## The fix (migration 176)
- Nullable `search_vector tsvector` column — catalog-only `ADD COLUMN`, **no table rewrite** (deliberately not `GENERATED ... STORED`, which would take `ACCESS EXCLUSIVE` at 500k–1M rows).
- `BEFORE INSERT OR UPDATE OF name, path, version` trigger maintaining it from the identical expression.
- In-migration backfill of existing rows.
- **Partial GIN index** `idx_artifacts_search_vector_gin ... WHERE is_deleted = false` (mirrors migration 173, matches every caller's filter).
- 2-line query swap inline → `a.search_vector` via one shared `SEARCH_VECTOR_MATCH` constant, so item query and COUNT can't diverge.

## Measured delta (`search-at-scale`, @500k, fix vs `1.6.2-rc`)

| metric @500k | before | after | change |
|---|---|---|---|
| app p95 | 2831 ms | **790 ms** | 3.6× |
| app p99 | 3772 ms | 911 ms | 4.1× |
| tail p99 (under concurrency) | 4220 ms | 980 ms | 4.3× |
| p99/p50 (latency cliff) | 4.44× | **1.53×** | cliff flattened |

- Curve now **flat** across 10k / 100k / 500k.
- DB EXPLAIN @500k: selective term **0.089 ms** (Bitmap Index Scan); broad-prefix 250k-match COUNT **75 ms**.
- **Parity:** 0 drift across 12 query shapes (results, ordering, exact counts, prefix, metachar-safety, fresh-upload searchability).
- Residual ~790 ms app p95 = broad-term stress mix sorting/serializing large match sets (`COUNT` + `ORDER BY`), **not** tsvector recompute (eliminated). Old bottleneck = PG query CPU, not pool/backend.

## Status / provenance
- Backend fix: PR **#2887** (`Closes #2871`), milestone 1.7.0 — locally validated, held under release freeze until 1.7.0 opens.
- Shareable report artifact (private): https://claude.ai/code/artifact/77997524-2c27-4af7-8928-9e1a987c11ea
- **TODO (CI-enforceable):** capture a committed post-fix baseline JSON (`--baseline`) from a real 500k harness run so the delta gate protects against regressions; only the pre-fix `1.6.2-rc` baseline is committed today.
