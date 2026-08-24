# tests/security/redteam: what happened to the 15 scripts

`tests/security/redteam/` held 15 `test-*.sh` scripts and a private
`lib.sh`. They were migrated into this repo on 2026-03-20 (PR #4, from
`artifact-keeper/scripts/redteam/`) with the stated intent of adapting them to
`tests/lib/common.sh`. That adaptation never happened, and nothing noticed for
five months, because the outcome of not doing it was invisible: every one of
the 15 reported PASS on every release.

## Why they could not fail

`scripts/run-suite.sh` discovers with `find "$SUITE_DIR" -name 'test-*.sh'`,
which is recursive, so `--suite security` picked all 15 up. It judges a script
purely on its exit status.

`tests/security/redteam/lib.sh` defined:

```sh
fail() { _FAIL_COUNT=$((_FAIL_COUNT + 1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
```

`_FAIL_COUNT` was never converted to an exit code, `grep -rn "exit 1"` across
the directory returned nothing, and all 15 scripts ended in a literal
`exit 0`. They also emitted no JUnit XML, so the `junit-security` artifact
silently omitted them and no dashboard showed the gap.

`security-tests` is on the `collect-results` blocking predicate (#2700), so the
hard security gate's apparent coverage was inflated by 15 of 73 scripts that
were structurally incapable of failing.

They violated all three of the load-bearing clauses of this repo's own written
Test Script Contract (`CLAUDE.md`): source `tests/lib/common.sh`, produce JUnit
XML, exit non-zero on any failure.

## Triage

Each script was run against a live 1.8.1 backend before deciding.

### Ported to `tests/security/` on `common.sh` (7)

| was | is now | why it survives |
|---|---|---|
| `test-02-security-headers.sh` | `test-http-security-headers.sh` | Only place in the repo asserting X-Frame-Options / X-Content-Type-Options / CSP / HSTS. All four are emitted today. |
| `test-03-cors.sh` | `test-cors-policy.sh` | Only place in the repo asserting anything about CORS. |
| `test-04-auth-bypass.sh` | `test-unauthenticated-write-surface.sh` | Anonymous writes to the management API and to the pypi/npm/generic upload routes; anonymous read projection carries no upstream credentials. |
| `test-08-path-traversal.sh` | `test-path-traversal-encodings.sh` | Carries the CONTENT oracle and the double-encoded / overlong-UTF-8 / fullwidth-solidus matrix that the status-code sibling does not exercise. |
| `test-11-wasm-plugin.sh` | `test-wasm-plugin-install-url.sh` | Git-install URL scheme validation (`file://`, `gopher://`, `dict://`, `ftp://`) and plugin-endpoint authentication. `test-wasm-sandbox.sh` validates plugin BYTES only. |
| `test-14-api-key-exposure.sh` | `test-secret-field-exposure.sh` | Peer `api_key` and user `password_hash` / `totp_secret` must not cross the API boundary. Asserted nowhere else. |
| `test-15-metrics-auth.sh` | `test-metrics-auth.sh` | `/metrics` must not be anonymously readable. `tests/platform/test-metrics-unmatched-cardinality.sh` names this file as the owner of that invariant. |

Four of the seven were hollow as well as unfailable, and were fixed rather
than transcribed:

- `test-04` probed hardcoded repository keys (`test-pypi`, `test-npm`,
  `test-generic`) that this repo never creates. Every probe 404'd, and 404 was
  on the accept list, so "PyPI upload requires authentication" passed on a
  backend with no PyPI route at all. It now creates its own public
  repositories and asserts the exact code (401).
- `test-04`'s credential-leak check ran against whatever repositories existed;
  on an empty instance the `jq` filter matched nothing. It now registers a
  remote repository with a known upstream username/password first.
- `test-08` had the same hardcoded-key problem, so its content oracle never
  read a live response.
- `test-14`'s peer check ran against a bootstrap peer that carries no
  `api_key`, so it passed without a secret ever being stored. It now registers
  its own peer with a known key.

### Removed: superseded by a working sibling (6)

| removed | superseded by |
|---|---|
| `test-05-default-credentials.sh` | `tests/security/test-default-credentials.sh` (has a positive control). Its four extra credential pairs were ported over. Its Meilisearch and PostgreSQL probes dialled docker-compose service names that do not resolve in the gate namespace and had been permanently inert; its `change-me-in-production` peer key is the wrong-key case already covered by `tests/security/test-mesh-peer-auth.sh`. |
| `test-06-grpc-unauth.sh` | `tests/security/test-grpc-security.sh`, which resolves descriptors from the vendored `tests/proto/sbom.proto` instead of relying on reflection. See the false-red note below. |
| `test-09-sql-injection.sh` | `tests/security/test-sql-injection.sh` and `test-sql-injection-like-wildcards-helm.sh`. Its `sqlmap` branch was dead: sqlmap is installed on no runner. Its own opening lines were `fail "Payload file not found"` followed by `exit 0`. |
| `test-12-information-disclosure.sh` | `tests/security/test-config-debug-redaction.sh`. Both of its hard `fail` calls are covered there (stack traces in error responses), or unreachable (sensitive labels in `/metrics`, which `test-metrics-auth.sh` requires to be non-200 anyway). Everything else it did was a `warn`. |
| `test-13-ssrf-prevention.sh` | `tests/security/test-ssrf-prevention.sh`, which covers the webhook path AND remote-repo upstream URLs. Its four unique vectors (GCP/Azure metadata hostnames, in-cluster `postgres`/`redis` service names) were ported over. |
| `test-99-rate-limit.sh` | `tests/auth/test-zz-rate-limiting.sh`, which declares-then-verifies in both directions (#343). The gate chart sets `RATE_LIMIT_ENABLED: "false"`, so converting this script as written would have produced a guaranteed false red in a blocking job. |

`test-06` deserves a specific note. Run against a healthy 1.8.1 backend with
`grpcurl` installed it produced FIVE failures, all false:

```
[FAIL] gRPC server reflection is enabled - 1 application service(s) enumerable without auth
[INFO]   Failed to list services: server does not support the reflection API
[FAIL] Full gRPC schema exposed: 0 RPCs, 0 message types
[FAIL] ListSbomsForArtifact callable without authentication
[FAIL] GetSbom callable without authentication
[FAIL] UpdateCveStatus callable without authentication
```

Its reflection guard greps for `"Server does not support the reflection API"`
case-sensitively; grpcurl prints a lowercase `server`. The guard misses, the
error line itself is counted as a discovered service, and every subsequent
method probe fails to resolve a descriptor and falls through to
`fail "... callable without authentication"`. Making this script fail-capable
would have reported five CRITICAL findings on a correctly-configured backend.

### Removed: the assertion does not describe a real invariant (2)

**`test-01-recon.sh`** — deleted rather than fixed. `nmap` is installed on no
gate runner, so `NMAP_OUTPUT` was the shell's "command not found" text, which
matched neither guard; `OPEN_PORTS` came back empty and the script exited 0
having scanned nothing. Installing nmap would not rescue it. `BASE_URL` in the
gate is `http://artifact-keeper-backend.test-<run>.svc.cluster.local:8080`, a
ClusterIP Service, which by construction routes only the ports its spec
declares — so "no unexpected ports are open" is a property of the Helm chart
in `artifact-keeper-iac`, not of the release candidate, and it is vacuously
true. Its `EXPECTED_PORTS="8080 9090"` is hardcoded, so adding a metrics port
to the chart would red the gate for a non-security reason. The ports the
candidate actually serves are covered positively: 8080 by every HTTP suite,
9090 by `tests/security/test-grpc-security.sh`.

**`test-07-oci-dos.sh`** — the assertion is inverted. It failed when a 10 MB
OCI blob `PATCH` returned 202 ("accepted without size restriction"), but
accepting large layers is required registry behaviour. `MAX_UPLOAD_SIZE`
defaults to 10 GiB, `tests/platform/test-upload-limit.sh` verifies the
configurable limit, and `tests/platform/test-streaming-large-artifact.sh`
explicitly fails ON a 413. Made fail-capable as written, this script would
hard-red the gate on correct behaviour.

It had also never reached that assertion. Its repository-creation payload
(`{"name": ..., "repo_type": "oci"}`) omits the required `key` field and
passes a format where a repo type belongs, so it 400s; and its upload path
`/v2/{repo}/blobs/uploads/` is one segment short of the real
`/v2/{repo}/{image}/blobs/uploads/`. Both were confirmed live: the session
start returns 404 and the script exits 0 at its "OCI upload not available"
branch.

## The findings sink

`lib.sh` wrote every finding to `${RESULTS_DIR:-/results}/redteam-report.json`.
`/results` exists on no gate runner and `RESULTS_DIR` is set nowhere in this
repo or in `release-gate.yml`, so `init_report`'s `mkdir -p` failed and every
`add_finding` was discarded. The sink is gone: the ported scripts pass their
diagnostic body to `common.sh`'s `fail`, which renders it as a CDATA section
inside the JUnit `<failure>` element that `junit-security` already uploads.

## Preventing a recurrence

`tests/lib/selftest-release-gate-contract.sh` grew a case that asserts every
`test-*.sh` under `tests/` sources `tests/lib/common.sh`. It runs in the
`harness-contract-self-test` workflow, whose path filter was widened from the
three lib files to `tests/**` so adding a script anywhere re-runs it. A future
script that brings its own framework now fails that check instead of quietly
reporting PASS forever.

Tracked in artifact-keeper-test#388. The NUL-byte finding surfaced while
calibrating the traversal matrix is artifact-keeper#3545.
