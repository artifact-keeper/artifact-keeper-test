# MATRIX-ROW — audit-export (PKT-C, feature #2413)

Integrator: merge the row below into `matrix.md` (new row, feature-coverage
block), and see the shared-file note at the bottom (the ONE optional `run.sh`
touch — not required for the tier to run).

## Row for matrix.md

| # | Class / capability | Profile-set | Discriminating oracle | DTF tier | Status |
|---|---|---|---|---|---|
| 13 | **Structured audit-log export, versioned SIEM schema** — #2413 | filesystem + **client.jsonschema** (python `jsonschema` sidecar), backend `AUDIT_STREAM=stdout` | `oracle.sh`: drive 5 audited actions (LOGIN, REPOSITORY_CREATED, API_TOKEN_CREATED, LOGIN_FAILED, REPOSITORY_DELETED) → capture backend stdout NDJSON → STRICTLY validate every `category:"audit"` line against the **vendored published** `audit-event.v1.schema.json` (draft 2020-12) → assert ≥1 line per action class → assert an exported `event_id` JOINS to `GET /api/v1/admin/audit` row → standing tripwire: strict validator must REJECT a `schema_version`-stripped line | **audit-export** | **COVERED** (PKT-C) — green (exit 0, 14/14) on `ak-backend:candidate-a4d7f9d1` with `AUDIT_STREAM=stdout`; DISCRIMINATING: `AUDIT_STREAM=off ./harness/run.sh audit-export ...` → 0 audit lines emitted, 8/14 fail (schema-validate + 5 class-present + join + tripwire), tier exits non-zero. A pre-#2413 backend (emits nothing) reds the same way. |

## Surface verified against the running candidate

- The plan's knob is **exactly right**: opt-in `AUDIT_STREAM=stdout` (also
  `on`/`true`/`1`; default `off`) makes the backend emit one NDJSON line per
  audited action to **stdout / `docker logs`** — NOT an HTTP endpoint. Verified
  live: with `AUDIT_STREAM=stdout` the candidate emitted all 5 driven events as
  NDJSON; with `AUDIT_STREAM=off` it emitted zero `category:"audit"` lines.
- Every emitted line is a valid instance of the **published contract**
  `backend/schemas/audit-event.v1.schema.json` (vendored here byte-for-byte,
  sha256 `dfe60086…f3249a`). `event_id` equals the `audit_log` row id — the
  join to `GET /api/v1/admin/audit items[].id` succeeded.
- serde serializes `schema_version` first, so audit lines are anchored with
  `grep -E '^\{"schema_version":[0-9]'` — this never matches a `RUST_LOG`
  diagnostic line, so the capture is clean without a dedicated stream splitter.

## Files owned by this packet (isolated; no shared-file edits)

- `harness/tiers/audit-export/manifest`
- `harness/tiers/audit-export/oracle.sh`
- `harness/tiers/audit-export/audit-event.v1.schema.json` (vendored published schema)
- `harness/tiers/audit-export/MATRIX-ROW.md` (this file)
- `profiles/client.jsonschema.yml` (python + `jsonschema` validator sidecar; also
  sets the backend `AUDIT_STREAM` env — see note)

## Shared-file note for the integrator (OFF-LIMITS files)

- **`run.sh` env passthrough is NOT required for this tier.** Per the off-limits
  rule, the `AUDIT_STREAM=stdout` opt-in is set via a **compose override in this
  packet's own profile** (`profiles/client.jsonschema.yml`:
  `AUDIT_STREAM: ${AUDIT_STREAM:-stdout}`), so the oracle is testable standalone
  with no `run.sh` edit. Compose reads the `${AUDIT_STREAM}` interpolation from
  the invoking shell, which is how the RED path
  (`AUDIT_STREAM=off ./harness/run.sh audit-export ...`) flips it without
  touching any shared file.
- **OPTIONAL** (only if you'd rather the manifest own the knob, matching the
  `dos` tier's `RATE_LIMIT_ENABLED` pattern): add `AUDIT_STREAM` to `run.sh`'s
  manifest-env export line (currently `run.sh:159` special-cases only
  `RATE_LIMIT_ENABLED`) and set `AUDIT_STREAM="stdout"` in this manifest. Not
  needed — the profile default already covers it, and leaving it in the profile
  keeps PKT-C self-contained.
- **`matrix.md`**: merge the row above (numbered here as 13; renumber to fit the
  final ordering alongside PKT-A/B/D/E/F rows).
- **`run.sh` `all` list**: this tier runs green on the single
  `candidate-a4d7f9d1` image, so it can join the `all` sequence after the
  existing tiers (no per-tier fixed-image caveat).
- **`ports.sh`**: no new published port needed — the validator sidecar is driven
  purely via `docker exec`/`docker cp` and has no host port.

## Reproduce

```bash
# GREEN (positive): 14/14 pass, exit 0
./harness/run.sh audit-export --backend-image ak-backend:candidate-a4d7f9d1

# RED (discrimination): audit stream off -> 8/14 fail, exit 1
AUDIT_STREAM=off ./harness/run.sh audit-export --backend-image ak-backend:candidate-a4d7f9d1
```
