# Halcyon Robotics: a company simulation

Halcyon Robotics builds warehouse robots. Its four engineering departments
keep their packages in one Artifact Keeper instance, run by a two-person
platform and security function. Today Priya, the platform admin, sets the
instance up from scratch. Then a normal working day runs, with every team
working at the same time. During the day a web engineer leaves the company
and his access is revoked. An outside auditor and a contractor also do their
narrow jobs.

The suite tests the access model the way a customer uses it. Each persona
does its own work with its own credentials. Each check records what the
persona tried, what Artifact Keeper answered, and the code or release note
that says what the answer should be.

- `00-found-company.sh`: Priya's script. It creates everything below and
  writes `personas.env`.
- `roles/*.sh`: one script per role. They run in parallel through
  `run-roles.sh`. `ROLES.md` specifies each one.
- `test-company-sim.sh`: the `run-suite.sh` entry point. It runs both steps.

## What Artifact Keeper offers, and how the company is built from it

Artifact Keeper has no "team" or "organisation" object. Its authorization
primitives are:

| Primitive | API | Used here for |
| --- | --- | --- |
| Instance admin flag (`users.is_admin`) | `POST/PATCH /api/v1/users` | platform admin, security lead |
| Groups | `/api/v1/groups`, `/api/v1/groups/{id}/members` | one group per team |
| Projects (a set of repositories; grants on a project are inherited by its repositories) | `/api/v1/projects`, `/api/v1/projects/{id}/members` | one project per department |
| Fine-grained rules: principal (`user`, `group`, `service_account`, `anonymous`) x target (`repository`, `project`) x actions (`read`, `write`, `delete`, `admin`) | `/api/v1/permissions` (project members are the same rows) | all access below |
| Repository visibility `public` / `internal` / `private` | `visibility` on the repository | private team repos, one internal handbook |
| Repository-owner role (`role_assignments`), auto-granted to a repository's creator | implicit | not used by the founder: the bootstrap admin creates every repository |
| Service accounts and tokens with scopes and a repository list | `/api/v1/service-accounts/{id}/tokens` | CI |
| Personal API tokens (self-service) | `/api/v1/users/me/tokens` | engineers' laptops |

Two things are not part of the model, and the scenario does not use them:

- `POST /api/v1/users/{id}/roles` is deprecated (#3522). It writes
  `user_roles`, which no authorization gate reads
  (`backend/src/api/handlers/users.rs`, doc comment on `assign_role`). The
  built-in roles `admin`, `developer`, `reader` and `user` are metadata only.
- There is no instance-wide "read everything" grant for a non-admin. A rule
  needs a repository or project target, so "view-only everywhere" for the
  auditor is a read grant on each department project. A repository outside
  every project (the handbook) is reached through its visibility instead.

Where the story asks for more than the product has, the scenario
approximates and records the gap rather than hiding it:

| Story asks for | What the scenario does | Gap a role checks |
| --- | --- | --- |
| Teams | a group per team plus a project per department, with the team's grants on the project | none, this is the intended model (#2472) |
| Auditor: view-only everywhere | read on each project via `HAL-auditors` | no non-admin can read the audit log (`/api/v1/admin/audit` is admin-only), so the auditor gets `403` |
| Security team | lead is an instance admin, analyst has read | acknowledging findings, policies and scans are instance-admin only, so the analyst cannot do them. The reverse is wider than the story wants: scan configs and scan policies (`GET /api/v1/security/configs`, `/policies`) are readable by any login, not only the security team (`backend/src/api/handlers/security.rs` 1407-1422, 2371-2380, 2435); security #12 records it |
| CI with a token scoped to its repos | service account with grants plus a token with `repository_ids` | the token is a ceiling, not a grant; Basic `user:token` is refused on REST |
| Contractor on one repo | one user rule | the `internal` handbook is still readable, by design, and stays readable after her grant is removed: `internal` is visibility, not a grant, so ending an engagement does not take it away. Anything a company would not show a contractor or an auditor does not belong in an `internal` repository |
| Offboarding | deactivate, remove from group, revoke tokens | none expected: every credential must answer `401` |

The access decision for a non-admin on a repository is
`PermissionService::check_repository_action`
(`backend/src/services/permission_service.rs`):

1. a `role_assignments` row carrying `admin` (repository-owner) always wins;
2. otherwise, if any rule names the principal (directly or through a group)
   on the repository or its project, the union of those rules' actions
   decides (`admin` implies every action);
3. otherwise the principal's role assignments decide.

Visibility only decides **reads** before any grant is consulted
(`docs/repository-visibility.md`). A refused write answers like an unknown
key (`404`) to a caller who cannot read the repository. A caller who can
read the repository gets `403` (#5458).

## Naming

Every object starts with `HAL = hal-<rid>`. `<rid>` is `RUN_ID` lowercased
and folded to `[a-z0-9-]`, at most 24 characters (`lib.sh`, `_cs_fold_rid`).
With `RUN_ID=company`, HAL is `hal-company`. A longer `RUN_ID` is cut at
24 characters, so two run ids that share their first 24 characters name the
same company: keep the distinguishing part early (CI's run ids do). Repository keys start with
their project key and a dash. Artifact Keeper enforces that such a key belongs
to that project (`check_repo_key_project_prefix`,
`backend/src/api/handlers/projects.rs`).

## Org chart and Artifact Keeper objects

| Persona key | User | Person | Job | Instance admin | Groups |
| --- | --- | --- | --- | --- | --- |
| `PADMIN` | `HAL-priya` | Priya Raman | Platform admin (IT) | yes | |
| `FW_LEAD` | `HAL-mara` | Mara Okafor | Firmware lead | | `HAL-firmware` |
| `FW_DEV` | `HAL-tomas` | Tomas Berg | Firmware engineer | | `HAL-firmware` |
| `WEB_LEAD` | `HAL-jun` | Jun Park | Web lead | | `HAL-web` |
| `WEB_DEV` | `HAL-leo` | Leo Varga | Web engineer, leaves today | | `HAL-web` |
| `DATA_LEAD` | `HAL-sofia` | Sofia Mendes | Data lead | | `HAL-data` |
| `DATA_DEV` | `HAL-arjun` | Arjun Das | Data engineer | | `HAL-data` |
| `OPS_LEAD` | `HAL-kai` | Kai Nakamura | DevOps lead | | `HAL-devops` |
| `SEC_LEAD` | `HAL-rhea` | Rhea Collins | Security lead | yes (see below) | `HAL-security` |
| `SEC_ANALYST` | `HAL-omar` | Omar Haddad | Security analyst | | `HAL-security` |
| `CONTRACTOR` | `HAL-nina` | Nina Petrov | Contractor, Petrov Embedded LLC | | none |
| `AUDITOR` | `HAL-ellen` | Ellen Shaw | External auditor | | `HAL-auditors` |
| CI | `svc-HAL-ci` | | Service account | | |

Passwords are deterministic per run: `Halcyon-<First>-<rid[0:8]>-2026!`.
Read them from `personas.env`, not from this table.

The security lead is an instance admin because scan policies, the
instance-wide age-gate queue, download holds and the security dashboards are
instance-admin routes (`admin_middleware` / `require_admin`; see ROLES.md
for each route). The security analyst is not an admin. He reviews findings
through his group's read grant, and ROLES.md lists what he cannot do.

### Departments (projects) and their repositories

| Project | Repository key | Format | Type | Visibility | Members (virtual) |
| --- | --- | --- | --- | --- | --- |
| `HAL-fw` | `HAL-fw-cargo-local` | cargo | local | private | |
| | `HAL-fw-cargo-remote` | cargo | remote `https://crates.io` | private | |
| | `HAL-fw-cargo` | cargo | virtual | private | local@1, remote@2 |
| | `HAL-fw-maven-local` | maven | local | private | |
| | `HAL-fw-maven-remote` | maven | remote `https://repo1.maven.org/maven2` | private | |
| | `HAL-fw-maven` | maven | virtual | private | local@1, remote@2 |
| `HAL-web` | `HAL-web-npm-local` | npm | local | private | |
| | `HAL-web-npm-remote` | npm | remote `https://registry.npmjs.org` | private | |
| | `HAL-web-npm` | npm | virtual | private | local@1, remote@2 |
| `HAL-data` | `HAL-data-pypi-local` | pypi | local | private | |
| | `HAL-data-pypi-remote` | pypi | remote `https://pypi.org` | private | |
| | `HAL-data-pypi` | pypi | virtual | private | local@1, remote@2 |
| | `HAL-data-conda-local` | conda | local | private | |
| | `HAL-data-conda-remote` | conda | remote `https://conda.anaconda.org/conda-forge` | private | |
| | `HAL-data-conda` | conda | virtual | private | local@1, remote@2 |
| `HAL-ops` | `HAL-ops-docker-local` | docker | local | private | |
| | `HAL-ops-docker-remote` | docker | remote `https://registry-1.docker.io` | private | |
| | `HAL-ops-docker` | docker | virtual | private | local@1, remote@2 |
| | `HAL-ops-builds` | generic | local | private | |
| | `HAL-ops-helm` | helm | local | private | |
| none | `HAL-handbook` | generic | local | **internal** | |

21 repositories. Set `HAL_UPSTREAM_{CRATES,MAVEN,NPM,PYPI,CONDA,DOCKER}` to
point the Remotes at mirrors when the runner has no internet.

### Grants

Project grants (rows with `target_type = project`, written through
`POST /api/v1/projects/{id}/members`):

| Principal | `HAL-fw` | `HAL-web` | `HAL-data` | `HAL-ops` |
| --- | --- | --- | --- | --- |
| group `HAL-firmware` | read, write | | | |
| user `HAL-mara` (FW lead) | read, write, delete, admin | | | |
| group `HAL-web` | | read, write | | |
| user `HAL-jun` (web lead) | | read, write, delete, admin | | |
| group `HAL-data` | | | read, write | |
| user `HAL-sofia` (data lead) | | | read, write, delete, admin | |
| group `HAL-devops` | read | read | read | read, write, delete |
| user `HAL-kai` (ops lead) | | | | read, write, delete, admin |
| group `HAL-security` | read | read | read | read |
| group `HAL-auditors` | read | read | read | read |
| service account `svc-HAL-ci` | read | read | read | read |

Repository grants (exceptions, `POST /api/v1/permissions`):

| Principal | Repository | Actions | Why |
| --- | --- | --- | --- |
| user `HAL-nina` (contractor) | `HAL-fw-maven-local` | read | builds against the firmware SDK jars, nothing else |
| service account `svc-HAL-ci` | `HAL-fw-cargo-local`, `HAL-fw-maven-local`, `HAL-web-npm-local`, `HAL-data-pypi-local`, `HAL-ops-docker-local`, `HAL-ops-builds`, `HAL-ops-helm` | read, write | publishes on merge |

The internal handbook needs no grant. Every authenticated principal reads
it, including the contractor. That is the documented meaning of `internal`
(`docs/repository-visibility.md`, "Any resolved principal is wider than every
employee with a login"). The scenario checks it on purpose.

### Tokens

| `personas.env` variable | Owner | Scopes | Repository list |
| --- | --- | --- | --- |
| `HAL_CI_TOKEN` | `svc-HAL-ci` | `read:artifacts`, `write:artifacts` | the 7 CI publish repos above, plus the virtuals `HAL-fw-cargo`, `HAL-fw-maven`, `HAL-web-npm`, `HAL-data-pypi`, `HAL-ops-docker` |
| `HAL_DEPLOY_TOKEN` | `svc-HAL-ci` | `read:artifacts` | `HAL-ops-docker`, `HAL-ops-docker-local`, `HAL-ops-helm` |
| `HAL_FW_DEV_TOKEN`, `HAL_WEB_DEV_TOKEN`, `HAL_DATA_DEV_TOKEN`, `HAL_OPS_LEAD_TOKEN` | the persona | `read:artifacts`, `write:artifacts` | none (the persona's own grants apply) |

`HAL-data-conda-local` is deliberately missing from the CI token's list.
Tokens expire after 30 days.

### Security policy at founding

`found-policies.sh` (sourced by the founder) sets these, all as the bootstrap admin:

| Policy | Where | Setting | Who may change it |
| --- | --- | --- | --- |
| Age gate (`PUT /api/v1/repositories/{key}/age-gate`) | `HAL-web-npm-remote`, `HAL-data-pypi-remote` | 7 days, `upstream_publish_time`, `instance_locked: false` | the department lead (repository admin through the project grant, #4238) |
| Age gate | `HAL-fw-maven-remote` | 7 days, `upstream_publish_time`, `instance_locked: true` | instance admins; the firmware lead may only tighten it or reject reviews |
| Scan on upload (`PUT .../security`) | `HAL-ops-docker-local` | `scan_enabled`, `scan_on_upload`, `block_on_policy_violation`, threshold `critical` (an admin write sets `instance_locked: true`) | instance admins |
| Scan policy `HAL-block-critical-images` (`POST /api/v1/security/policies`) | `HAL-ops-docker-local` | `max_severity: critical`, `block_on_fail: true`, `block_unscanned: false` | instance admins (`require_admin`) |
| Upload-period quarantine (`PATCH /api/v1/repositories/{key}`) | `HAL-ops-helm` | `quarantine_enabled`, 60 minutes: a new chart answers `409` until an admin releases it | instance admins |

### Day 0 content

The founder publishes one artifact into each hosted repository as the
bootstrap admin, so every role starts from the same catalogue:

| Repository | Artifact | `personas.env` |
| --- | --- | --- |
| `HAL-fw-maven-local` | `com.halcyon.fw:hal-sdk:1.0.0` (pom + jar) | `HAL_SEED_MAVEN_*` |
| `HAL-fw-cargo-local` | crate `HAL-motor` 0.1.0 (named per company: on S3 storage a cargo coordinate can live in only one repository of the instance) | `HAL_SEED_CRATE*` |
| `HAL-web-npm-local` | `halcyon-ui-kit@1.0.0` | `HAL_SEED_NPM*` |
| `HAL-data-pypi-local` | `halcyon-telemetry` 1.0.0 (sdist) | `HAL_SEED_PYPI*` |
| `HAL-ops-builds` | `firmware/1.0.0/hal-fw-1.0.0.bin`, 256 KiB of deterministic bytes | `HAL_SEED_FW_BIN*` (sha256 included) |
| `HAL-handbook` | `handbook/onboarding.md` | `HAL_SEED_HANDBOOK` |

Conda, docker and helm content is published by the roles themselves. A real
client is needed for those formats, or a builder this directory does not have yet.

## personas.env

`00-found-company.sh` writes `$COMPANY_SIM_STATE_DIR/personas.env` (mode
600). The default location is `$JUNIT_OUTPUT_DIR/company-sim-<rid>/`. Every
role sources it through `cs_begin`. The keys are:

- `HAL`, `HAL_RID`, `HAL_RUN_ID`, `HAL_BASE_URL`;
- per persona: `HAL_<KEY>_USER`, `_PASS`, `_ID`, `_NAME`, and `_TOKEN` where
  the table above says so;
- `HAL_GROUP_<TEAM>` and `HAL_GROUP_<TEAM>_ID` (FIRMWARE, WEB, DATA, DEVOPS,
  SECURITY, AUDITORS);
- `HAL_PROJECT_<FW|WEB|DATA|OPS>` and `_ID`;
- `HAL_REPO_<NAME>` and `_ID`, where NAME is the key suffix upper-cased with
  `_`, e.g. `HAL_REPO_FW_CARGO_LOCAL`, `HAL_REPO_OPS_BUILDS`,
  `HAL_REPO_HANDBOOK`;
- `HAL_CI_SA_ID`, `HAL_CI_SA_USER`, `HAL_CI_TOKEN`, `HAL_CI_TOKEN_REPOS`,
  `HAL_DEPLOY_TOKEN`, `HAL_CONTRACTOR_REPO`;
- `HAL_SEED_*` (the day 0 content).

The file holds throwaway test credentials. It is never committed. Keep it
out of anything you share: the JUnit results are the `*.xml` files only.

## How the day runs

```
00-found-company.sh          (sequential, bootstrap admin)
        |
        v
run-roles.sh  -- starts every roles/*.sh at once --------------------------
   platform-admin   firmware   web   data   devops   security   contractor
   auditor   ci   departed-employee
        |   roles meet only at named barriers (cs_signal / cs_wait):
        |   e.g. departed-employee signals "leo-worked", platform-admin
        |   offboards him and signals "leo-offboarded", departed-employee
        |   then proves every credential he held is dead.
        v
merged CHECK lines ($COMPANY_SIM_STATE_DIR/CHECKS.txt) + one JUnit file per role
```

Rules that keep parallel roles independent:

- **Shared objects are read-only for roles.** Do not change the users, groups,
  projects, repositories, grants, tokens or day 0 artifacts in the tables
  above, except where ROLES.md assigns the change to one role (offboarding
  belongs to `platform-admin`, policy changes to `security`). A role that
  needs its own object creates one named `${HAL}-<role>-...` and removes it
  before it ends.
- **Barriers, not sleeps.** A role that depends on another role's action
  waits on the barrier ROLES.md names, with a timeout, and records a FAIL if
  the barrier never arrives.
- **Grant changes take effect at once.** Every write to the permissions table
  calls `invalidate_cache()` on the serving replica. The permission cache has
  a 30 s TTL (`permission_service.rs`). With more than one backend replica,
  allow for that window, or check on a fresh request after it.

## Running it

This is a **manual suite**: run it by hand against a deployed instance. It
is registered with `run-suite.sh` as `scenarios-company-sim`, but it is not
part of the release gate and no workflow runs it. A full run (founder plus
every role, in parallel) takes about 5 minutes on one backend replica.

The whole suite, the way to run it (founds the company, then runs every
role; JUnit in `$JUNIT_OUTPUT_DIR`, merged CHECK lines in
`$COMPANY_SIM_STATE_DIR/CHECKS.txt`):

```bash
export BASE_URL=http://127.0.0.1:30010 ADMIN_USER=admin ADMIN_PASS='TestRunner!2026secure'
export JUNIT_OUTPUT_DIR=$PWD/junit COMPANY_SIM_STATE_DIR=$PWD/state
export CS_BARRIER_TIMEOUT=600                 # per barrier (default; 300 minimum)
./scripts/run-suite.sh --suite scenarios-company-sim --run-id company
```

The real package clients below are optional (their checks SKIP without
them); without docker, devops copies its images over the OCI API with curl,
so the scan and scan-policy checks still run. The steps one at a time:

```bash
export BASE_URL=http://127.0.0.1:30010 ADMIN_USER=admin ADMIN_PASS='TestRunner!2026secure'
export RUN_ID=company JUNIT_OUTPUT_DIR=$PWD/junit COMPANY_SIM_STATE_DIR=$PWD/state

export CS_BARRIER_TIMEOUT=600                 # per barrier (default; 300 minimum)
# Optional real clients (see "Requires" below):
export CS_NODE_DIR=/opt/node-22                # web: npm/node in <dir>/bin
export CS_TOOL_PATH="$HOME/.cargo/bin:/opt/maven/bin:$HOME/.local/bin"   # cargo, mvn, uv
export HAL_CONDA_CLIENT_IMAGE=localhost/pixi-client:0.81.0   # data #9e

bash tests/scenarios/company-sim/00-found-company.sh      # found (re-runnable)
bash tests/scenarios/company-sim/run-roles.sh             # every role, in parallel
bash tests/scenarios/company-sim/run-roles.sh --only security,auditor

./scripts/run-suite.sh --suite scenarios-company-sim --run-id company   # both
```

Re-run the founder before replaying the roles (ROLES.md, "Replay notes"):
the day offboards Leo and the contractor, and only the founder brings them
back. A role run on its own (`--only`) waits on barriers that its partner
roles signal: run the partners with it (`--only firmware,contractor`), or
expect `waited for <barrier>` FAILs. A barrier counts only when it was
signalled during the current run, so an earlier run's signals never stand
in for a partner that did not run. A role that exits before it reaches a
barrier it owns (a failed sign-in, say) releases it as `failed`, so its
partners record `waited for <barrier>: signaller exited` at once instead
of waiting out the timeout.

Keep `CS_BARRIER_TIMEOUT` at 300 s or more: security waits for the devops
image and then for its upload scan to settle before it signals
`ops-image-reviewed`, and devops, ci and the auditor wait on that.

A full run (founder plus every role) takes about 5 minutes on one backend
replica with every client present, most of it the upload scan. A role
is killed after `COMPANY_SIM_ROLE_TIMEOUT` seconds (default
2 x `CS_BARRIER_TIMEOUT` + `CS_SCAN_TIMEOUT` + 300, 1800 with the defaults).

The founder converges. Re-running it against the same `RUN_ID` restores the
founding state: it re-activates the departed employee, puts him back in his
group, resets changed passwords, re-applies grants and re-mints tokens. You
can replay the day without tearing the namespace down. Use a new `RUN_ID` to
get a second, independent company on the same instance.

Requires `bash` 4.3 or later, `curl`, `jq`, `python3`, GNU `tar`, `gzip` and
`sha256sum`. Real package clients are optional; each check that needs one
SKIPs when it is missing, and `run-roles.sh` prints which it found:

| Client | Used by | How the role finds it |
| --- | --- | --- |
| `docker` (daemon running) | devops, ci | `PATH` |
| Node 22 (`node`, `npm`) | web | `CS_NODE_DIR/bin`, else `PATH` |
| `cargo` | firmware | `PATH` / `CS_TOOL_PATH` (`RUSTUP_HOME`, `CARGO_HOME` pass through) |
| `mvn` (Maven 3) | firmware | `PATH` / `CS_TOOL_PATH` |
| `uv` | data | `PATH` / `CS_TOOL_PATH`, else `~/.local/bin/uv` |
| a local image with `pixi`, run by `podman` or `docker` | data #9e | `HAL_CONDA_CLIENT_IMAGE` |
| `psql` + `AK_PG_URL` | founder (developer role id only, read-only) | `PATH`; or set `HAL_DEVELOPER_ROLE_ID` |

## Files

| File | What |
| --- | --- |
| `README.md` | this file |
| `ROLES.md` | the brief for each role script |
| `lib.sh` | helpers on top of `tests/lib/common.sh` |
| `00-found-company.sh` | founder |
| `found-policies.sh` | founder: security policy section |
| `run-roles.sh` | parallel role runner and CHECK merger |
| `roles/_template.sh` | skeleton for a role script |
| `roles/<role>.sh` | one per role |
| `test-company-sim.sh` | `run-suite.sh` entry point |
