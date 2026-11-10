# Halcyon Robotics: role briefs

One section per `roles/<role>.sh`. Each script implements one section:
it starts from `roles/_template.sh`, then does the workday in order and the
"should NOT work" list. Every item is one `cs_expect`/`cs_record` check, or a
small group of them. Read README.md first for the company, the names and
`personas.env`.

Citations use the 1.12.0 tree (`artifact-keeper` at 4e2c6d4e):
`A` = `backend/src/api/middleware/auth.rs`, `RS` = `backend/src/api/handlers/repositories.rs`,
`H/x` = `backend/src/api/handlers/x.rs`, `S/x` = `backend/src/services/x.rs`,
`RN` = `.github/release-notes/1.12.0.md`, `VIS` = `docs/repository-visibility.md`,
`HOLDS` = `docs/security/download-holds.md`. Re-read a cited line before you
pin a status on it. Where this brief says VERIFY, the code reading was an
inference: assert what the code says, and if the product disagrees, record
FAIL with the request, the answer and the cite.

## Rules for every role

### Status codes

These come from the code. The table is for a **private** repository, which
every team repository is.

| Situation | Native format route (`/cargo`, `/maven`, `/npm`, `/pypi`, `/conda`, `/helm`) | REST `/api/v1/repositories/{key}/...` | OCI `/v2` |
| --- | --- | --- | --- |
| Read, caller has no read | `404` text `Repository not found` (A:2724) | `404` `{"code":"NOT_FOUND","message":"Repository not found"}` (RS:573-648) | `404 NAME_UNKNOWN` |
| Write, caller cannot read (#5458) | `404` `Repository not found` (A:2766-2804) | `404` NOT_FOUND (RS:126-226) | `404 NAME_UNKNOWN` (H/oci_v2.rs:834-907) |
| Write, caller can read but not write | `403` text `You do not have permission to perform this action on this repository` (A:2710) | `403` FORBIDDEN (RS:251-274) | `403 DENIED` |
| Write with a token whose repo list excludes the repo | `404` (A:3324-3335) | `404` (RS:99-107, 149-178) | `404 NAME_UNKNOWN` |
| Write with a token that has the grant but only `read:artifacts` | `403` `Token does not have required scope: write:artifacts` (A:425-441) | `403` FORBIDDEN, same message | `403 DENIED` |
| No credential on a private repo | `401` + `WWW-Authenticate` (A:2639-2659) | `401` | `401` |
| Presented credential is invalid, revoked or for a deactivated user | `401`, never an anonymous downgrade (#1371, A:3203-3207) | `401` (A:1807-1817) | `401` |
| Instance-admin route, non-admin caller | | `403` text `Admin access required` (`admin_middleware`, A:2027-2050) or JSON FORBIDDEN (`require_admin`, A:304-310) | |

On the `internal` handbook, any authenticated principal reads. A write by a
non-writer is `403`, because the caller can read (VIS, "Write refusals").
Anonymous callers get `401`.

### Credential forms

These trip people up (A:925-1022, 1487-1508):

- Bearer JWT, and Bearer or `X-API-Key` with an API token, work everywhere.
- **Basic `user:<api_token>` is `401` on `/api/v1` REST routes**, including
  `PUT /api/v1/repositories/{key}/artifacts/{path}` (#2806). It works on
  native format routes, on `GET /api/v1/repositories/{key}/download/{path}`
  and on `/v2/token`. Use `token:VAR` for REST and `basictoken:P:VAR` for
  native routes.
- Basic `user:password` (`basic:P`) works on REST and native routes.
- Native routes never check `read:artifacts`. Writes need `write:artifacts`
  in the handler. OCI `/v2` checks both exactly: a token with only
  `write:artifacts` cannot pull (H/oci_v2.rs:399-401, 638-660).
- An instance admin's API token is not admin unless it carries `admin` or
  `*` (A:298-301).

### Known and already filed

Record these as WARN citing the issue, not as FAIL:

- #5594: a generic `/download` of a docker manifest answers `502`.
- #5574: on a virtual **artifact** walk, a hosted member whose storage read
  fails reads as a miss (`404`).
- #5536 and #5593 (MCP only; not exercised here).
- #5603: `admin_middleware` records `PERMISSION_DENIED` audit rows with the
  nest-stripped path (`/audit`, not `/api/v1/admin/audit`). auditor checks it.
- #5604: a REST `DELETE` of an npm version leaves its `npm_dist_tags` row, so
  a deleted `latest` pin comes back when the version is republished. web
  avoids it with a whole-package npm unpublish at the end of its day. Without
  an npm client it falls back to REST deletes after tagging 1.0.0
  `rest-cleanup`; the next day's web #4 ("after 1.1.0 latest is 1.1.0") is a
  WARN citing #5604 when, and only when, `latest` is the stale `1.0.0` and
  the resurrected `rest-cleanup` tag proves the leftover rows.
- #5606: `docker push` cannot replace a tag the scan policy holds: docker's
  pre-push `HEAD`/`GET /v2/<name>/manifests/<tag>` gets the pull gate's `403`,
  so the `PUT` is never sent (pre-existing, 1.11.12 too). devops #3e checks it.
- `/health` on `dev` images reports `1.11.3`.

### Hygiene

- Act only as your persona(s). Use `admin` (the bootstrap admin) only to
  read back state for a verification the brief names.
- Create your own objects as `${HAL}-<role>-...` or as package names
  carrying your role. Never re-publish a day-0 artifact. Never change shared
  grants, users, tokens or repo settings unless your section owns the
  change. Delete what you created before `cs_end`, as long as your persona
  may delete it. Otherwise list it in the script's header comment.
- Released artifacts are immutable for non-admins: a released Maven, cargo,
  npm, PyPI or conda coordinate cannot be overwritten (`409`), and a deleted
  one can be republished only with the same bytes
  (`backend/src/api/handlers/mod.rs` `cleanup_soft_deleted_artifact_checked`).
  Non-admins cannot delete PyPI or conda files at all. So a role that
  publishes every run puts a run stamp in the version (data uses
  `0.1.<epoch>`), and the `lib.sh` publish helpers build byte-identical
  archives for the same name and version, so a delete-then-republish of the
  same coordinate (web #12 deletes Leo's widget, departed-employee #3
  publishes it again next run) is accepted.
- Barriers are listed per role. `cs_wait NAME` waits `CS_BARRIER_TIMEOUT`
  seconds (default 600, minimum 300). Record a FAIL named
  `waited for <barrier>` with `$CS_WAIT_WHY` when it returns 1, and skip
  only the checks that depended on it. A barrier counts only when it was
  signalled during this run (after `CS_RUN_START`, which `run-roles.sh` sets
  before it launches the roles), so a leftover signal file never satisfies a
  wait. Use `cs_signalled NAME` for a non-blocking test.
- A signal carries one outcome word (`cs_signal NAME OUTCOME`, read with
  `cs_signal_outcome NAME`). Waiters act on it, never on another role's
  CHECK text: `ops-image-pushed` is `pushed` or `none` (devops pushed no
  image: security, ci and the auditor SKIP their image checks);
  `ops-image-reviewed` is `blocked` (criticals left open, a pull answers
  `403`), `cleared` (every finding acknowledged, `200`) or `none`.
- Declare the barriers a role signals with `cs_signals NAME...` right after
  `cs_begin`. If the role exits before signalling one (a failed sign-in ends
  it early), lib.sh signals it `failed` on exit and `cs_wait` returns 1 at
  once with `CS_WAIT_WHY` "signaller exited", so no partner waits out the
  timeout.
- With one backend replica, grant and deactivation changes are visible on the
  next request. With N replicas, allow 5 s for deactivation
  (S/auth_service.rs:599) and up to 30 s for permission caches
  (S/permission_service.rs:293). Use `cs_wait`-style polling with a deadline,
  never a bare sleep.

### Barrier map

| Barrier | Signalled by | Awaited by |
| --- | --- | --- |
| `leo-worked` | departed-employee (after #4) | platform-admin (before #5) |
| `leo-offboarded` | platform-admin (#7) | departed-employee (before #6), web (before #10) |
| `leo-verified` | departed-employee (after its admin read-back) | web (before #11) |
| `fw-sdk-1.1.0` | firmware (#3) | contractor (#4), ci (#7), auditor |
| `fw-age-gate-relax-refused` | firmware (after #11) | security (before #10) |
| `nina-done` | contractor (#8) | platform-admin (before #10) |
| `nina-offboarded` | platform-admin (#10) | contractor (#8) |
| `ops-image-pushed` | devops (#3) | security (#3), ci (#10), auditor (#7, optional) |
| `ops-image-reviewed` | security (#8) | devops (#5), ci (#10), auditor (#7, optional) |
| `ops-chart-published` | devops (after #13: #11 and #13 need the chart still held) | security (#9) |
| `ops-chart-released` | security (#9) | devops (#12), ci (#9) |
| `web-age-gate-review` | web (#8) | security (#11, optional: a timeout is a SKIP) |

An optional barrier's timeout is a SKIP of the checks that need it, not a
FAIL. Every other barrier's timeout is a FAIL.

A role must not wait on a barrier that a role it waits for is itself waiting
on. The map above has no cycles. Keep it that way when you add one.

---

## platform-admin (Priya Raman, instance admin)

Credentials: `HAL_PADMIN_USER` / `HAL_PADMIN_PASS` (`jwt:PADMIN`, `basic:PADMIN`).

Priya runs the instance. She handles two lifecycle events today: offboarding
Leo, and ending the contractor's engagement. She also proves that her own
admin power has the limits the code gives it.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Sign in, confirm admin | `GET /api/v1/users/me` | `200`, `is_admin: true` | H/users.rs `get_current_user_record` |
| 2 | Review the org: list Halcyon users | `GET /api/v1/users?search=${HAL}&per_page=100` | `200`, exactly the 12 founded users + the SA (`is_service_account`) | H/users.rs:255-263 |
| 3 | Review group membership | `GET /api/v1/groups/${HAL_GROUP_WEB_ID}` | `200`, members are jun and leo | H/groups.rs (group detail lists members, #4027) |
| 4 | Read the permission table for the web project | `GET /api/v1/permissions?target_type=project&target_id=${HAL_PROJECT_WEB_ID}` | `200`, rows for group web (read, write) and jun (read, write, delete, admin) | H/permissions.rs:255-330 |
| 5 | Wait for `leo-worked`, then **offboard Leo**: (a) `PATCH /api/v1/users/${HAL_WEB_DEV_ID}` `{"is_active":false}`; (b) `DELETE /api/v1/groups/${HAL_GROUP_WEB_ID}/members` `{"user_ids":[leo]}`; (c) list and revoke his tokens `GET/DELETE /api/v1/users/${id}/tokens[/{tid}]` | | each `200` | H/users.rs:539-574 (deactivation revokes refresh families and flushes caches) |
| 6 | Confirm Leo is gone | `GET /api/v1/users/${id}` | `is_active: false`; group detail no longer lists him | |
| 7 | Signal `leo-offboarded` | | | |
| 8 | Audit trail of the offboarding | `GET /api/v1/admin/audit?resource_id=${HAL_WEB_DEV_ID}&per_page=50` | `200`, contains the user-updated event for Leo with Priya as actor (match the action name the API returns, e.g. `USER_UPDATED`) | H/admin.rs:64, 145-165 |
| 9 | Mint a short-lived admin-scoped token for a script | `POST /api/v1/users/me/tokens` `{"name":"${HAL}-padmin-script","scopes":["admin"],"expires_in_days":1}`, then `GET /api/v1/admin/audit` with it | `200` mint, `200` audit read, then revoke it | S/token_service.rs:160-170 (admin may mint admin-only scopes); A:298-301 |
| 10 | Wait for `nina-done`, then end the contract: find Nina's rule (`GET /api/v1/permissions?principal_id=${HAL_CONTRACTOR_ID}`) and `DELETE /api/v1/permissions/{id}` | | `200`; signal `nina-offboarded` | H/permissions.rs:767-791 (invalidates cache) |
| 11 | Create a short-lived repo for an incident, in a project, then delete it | `POST /api/v1/repositories` `{key:"${HAL}-ops-incident-<n>", format:"generic", repo_type:"local", visibility:"private", project_id:${HAL_PROJECT_OPS_ID}}`; `DELETE /api/v1/repositories/{key}` | `200` create; delete `202` with a job, key stops resolving (`GET` → `404`) | RN:"DELETE ... answers 202 with a job" (#4311) |
| 12 | Project key prefix is enforced: create `${HAL}-fw-sneaky` assigned to the **web** project | `POST /api/v1/repositories` | `400`, message names project `${HAL}-fw` (an admin sees the names) | H/projects.rs:249-295 |

Should NOT work:

- Priya assigns herself the deprecated `developer` role and expects repo access. `POST /api/v1/users/{id}/roles` answers `200` with `Deprecation` and `Link: </api/v1/permissions>; rel="successor-version"` headers. Record both headers. It grants nothing. Check the deprecation headers and stop there: she is an admin, so access cannot show it. Use a throwaway non-admin `${HAL}-padmin-probe` user, give it the role, then `GET` a private repo: `404`. Delete the user afterwards. (H/users.rs `assign_role` doc, #3522.)
- Approving her own approval request answers `403`, separation of duties (H/approval.rs:846-850). Only if the script sets up a request. Optional.
- Deleting herself: `DELETE /api/v1/users/${HAL_PADMIN_ID}` answers `400` `Cannot delete yourself` (H/users.rs:729-731).

---

## firmware (Mara Okafor, lead; Tomas Berg, engineer)

Credentials: `FW_LEAD`, `FW_DEV` (personal token `HAL_FW_DEV_TOKEN`).

Tomas ships a new SDK and a crate. Mara administers the department and
operates its (instance-locked) Maven age gate.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Tomas resolves the day-0 SDK through the virtual | `GET /maven/${HAL_REPO_FW_MAVEN}/com/halcyon/fw/hal-sdk/1.0.0/hal-sdk-1.0.0.jar` (`basic:FW_DEV`) | `200` | VIS "Reading through a virtual" (group read on all three via the project) |
| 2 | Tomas pulls an upstream jar through the virtual (old, so not age-gated) | `.../junit/junit/4.13.2/junit-4.13.2.pom` via `${HAL_REPO_FW_MAVEN}` | `200`; SKIP if no internet | |
| 3 | Tomas publishes `hal-sdk` 1.1.0 | `cs_put_maven "$HAL_REPO_FW_MAVEN_LOCAL" com/halcyon/fw hal-sdk 1.1.0 basictoken:FW_DEV:HAL_FW_DEV_TOKEN` | pom and jar `201`; signal `fw-sdk-1.1.0` | H/maven.rs:231, 4606 |
| 4 | Re-deploying a released version | same PUT of `hal-sdk-1.1.0.jar` again | the answer the Maven handler gives for a release overwrite (VERIFY in H/maven.rs: `409`/`400`; pin what the code says) | |
| 5 | Tomas publishes crate `${HAL}-fw-motor-ctl` 0.1.0 with his token as Bearer (cargo sends `Authorization: <token>`) | `cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" ... token:HAL_FW_DEV_TOKEN` | `200` with a `warnings` object | H/cargo.rs:1254, 1865-1878 |
| 6 | The crate is in the sparse index through the virtual | `GET /cargo/${HAL_REPO_FW_CARGO}/index/<pp>/<pp>/<name>` | `200`, has `"vers":"0.1.0"` | cargo index layout (see tests/formats/test-cargo.sh) |
| 7 | Tomas downloads it through the virtual | `GET /cargo/${HAL_REPO_FW_CARGO}/api/v1/crates/<name>/0.1.0/download` | `200` | |
| 8 | Publishing the same crate version again | repeat 5 | `409` or the cargo-protocol error the handler returns (VERIFY H/cargo.rs; pin it) | |
| 9 | Mara reads the locked Maven age gate | `GET /api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate` (`jwt:FW_LEAD`) | `200`, `instance_locked: true`, `min_age_days: 7` | H/age_gate.rs:47-52, 257-265 (repo admin via project admin grant) |
| 10 | Mara tightens it to 14 days | `PUT .../age-gate` `{"enabled":true,"min_age_days":14,"mode":"upstream_publish_time"}` (no `instance_locked` field) | `200` (tightening a locked policy is allowed) | H/age_gate.rs:142-148, 709-714 |
| 11 | Mara restores 7 days | `PUT ... min_age_days:7` | `403` (relaxing a locked policy is refused). Then restoring needs the security lead: signal `fw-age-gate-relax-refused` (whatever #11 answered) and leave a note in the CHECK. Security restores it, see security #10 | same |
| 12 | Mara lists her department's repos | `GET /api/v1/repositories?per_page=100` (`jwt:FW_LEAD`) | `200`, includes all 6 `${HAL}-fw-*` and the handbook, nothing from web/data/ops | RS:348-360, S/repository_service.rs:800-837 |
| 13 | Mara deletes Tomas's crate version | `DELETE /api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts/<path>` (`jwt:FW_LEAD`) | `200` (JWT sessions carry every scope, the project grant has delete) | RS:13777-13800 |
| 14 | Mara creates a department repo herself (project admin) | `POST /api/v1/repositories` `{key:"${HAL}-fw-scratch", format:"generic", repo_type:"local", visibility:"private", project_id:${HAL_PROJECT_FW_ID}}` | `200`; then `DELETE` it, `202` | RS:4634-4655 (project admin may create inside the project); RN #4311 |

Should NOT work:

- Tomas deletes with his personal token: `DELETE /api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts/<path>` with `token:HAL_FW_DEV_TOKEN` answers `403` `Token does not have required scope: delete:artifacts`. He could not mint `delete:artifacts` either: `POST /users/me/tokens` with `["delete:artifacts"]` answers `403` (S/token_service.rs:160-170).
- Tomas publishes to the web registry: `cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" ${HAL}-fw-leak 0.0.1 basic:FW_DEV` answers `404 Repository not found` (#5458).
- Mara creates a repo in the web project (`project_id` = web) answers `403` `Insufficient permissions to create repositories` (RS:4648-4655).
- Tomas (no admin grant) reads the age gate config: `GET .../age-gate` answers `403` (he can read the repository, so `403`, not `404`; H/age_gate.rs:257-265).

---

## web (Jun Park, lead)

Credentials: `WEB_LEAD`. Leo's own day is `departed-employee`.

Jun runs the npm side and its age gate, which is unlocked. He also checks
that Leo's departure took effect for his team.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Install the day-0 UI kit through the virtual | `GET /npm/${HAL_REPO_WEB_NPM}/halcyon-ui-kit` (`basic:WEB_LEAD`), then the tarball URL from `versions["1.0.0"].dist.tarball` | `200`, `200` | |
| 2 | Publish `${HAL}-web-forms` 1.0.0 to the local | `cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" ...` | `200`/`201` (pin what H/npm.rs returns) | H/npm.rs:6118-6178 |
| 3 | Its packument through the virtual lists 1.0.0 | `GET /npm/${HAL_REPO_WEB_NPM}/${HAL}-web-forms` | `200`, `dist-tags.latest == 1.0.0` | |
| 4 | Publish 1.1.0, then move `latest` back to 1.0.0 with a dist-tag | `PUT /npm/{local}/-/package/<name>/dist-tags/latest` body `"1.0.0"` | `200`; packument `latest == 1.0.0` | H/npm.rs dist-tag routes |
| 5 | Pull an old upstream package through the virtual | `GET /npm/${HAL_REPO_WEB_NPM}/left-pad/-/left-pad-1.3.0.tgz` | `200`; SKIP without internet | |
| 6 | Read the age gate (unlocked) | `GET /api/v1/repositories/${HAL_REPO_WEB_NPM_REMOTE}/age-gate` | `200`, `enabled: true`, `min_age_days: 7`, `instance_locked: false` | H/age_gate.rs:47-52 |
| 7 | Trigger the gate: pick an upstream package whose newest version is under 7 days old. Read `https://registry.npmjs.org/<pkg>` `time` directly, e.g. `@types/node` or `typescript` nightly. Then `GET` that version's tarball through `${HAL_REPO_WEB_NPM_REMOTE}` | | `451`, JSON `{"error":"age_gate_blocked","review_id":...}`, `Cache-Control: no-store`; or, if the remote has a last-known-good, the packument quietly serves the older version (record which happened) | H/proxy_helpers.rs:9496-9541, 9971-10036 |
| 8 | Signal `web-age-gate-review` (security may look). List the repo's review queue | `GET /api/v1/repositories/${HAL_REPO_WEB_NPM_REMOTE}/age-gate/reviews` | `200`, contains `review_id` from 7 | H/age_gate.rs:64-72 (#4238) |
| 9 | Approve it as repo admin | `POST .../age-gate/reviews/{id}/approve` `{"reason":"needed for release"}` | `200`; re-fetch the tarball: `200` | #4238 |
| 10 | Wait `leo-offboarded`; confirm the web group is now only Jun | `GET /api/v1/groups/${HAL_GROUP_WEB_ID}` (`jwt:WEB_LEAD`) | `200`, members == [jun] (a member may read its group; `200` checked live on `dev`) | H/groups.rs:39-70 |
| 11 | Wait `leo-verified` (departed-employee has read back Leo's package as admin). Leo's packages stay: the package Leo published in departed-employee #3 is still served | `GET /npm/${HAL_REPO_WEB_NPM}/${HAL}-web-leo-widget` | `200` (deactivation removes access, not content) | |
| 12 | Jun cleans up Leo's package | `DELETE` the tarball via REST (`jwt:WEB_LEAD`) or npm unpublish | `200` | RS:13777-13800 |

Should NOT work:

- Jun changes the age gate on the **firmware** remote: `PUT /api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate` answers `404` (he cannot read it; #5458 covers `.../age-gate`, RN:45).
- Jun reads the instance-wide review queue: `GET /api/v1/admin/age-gate/reviews` answers `403` `Admin access required` (H/age_gate.rs:38-45, R:1428).
- Jun sends `instance_locked: true` on his own gate: `403`, a repo admin may not set the lock (H/age_gate.rs:142-148).

---

## data (Sofia Mendes, lead; Arjun Das, engineer)

Credentials: `DATA_LEAD`, `DATA_DEV` (personal token `HAL_DATA_DEV_TOKEN`).

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Arjun installs day-0 `halcyon-telemetry` through the virtual | `GET /pypi/${HAL_REPO_DATA_PYPI}/simple/halcyon-telemetry/` then the sdist href | `200`, `200`, sha256 matches the href fragment | |
| 2 | Arjun uploads `${HAL}-data-etl` 0.1.0 (twine-style) with his token | `cs_publish_pypi "$HAL_REPO_DATA_PYPI_LOCAL" ... basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN` | `200` | H/pypi.rs:61, 6334-6461 |
| 3 | Same file again | repeat 2 | `400`/`409` per H/pypi.rs (VERIFY; PyPI semantics are "file already exists") | |
| 4 | Simple index through the virtual lists both packages | `GET /pypi/${HAL_REPO_DATA_PYPI}/simple/` | `200`, contains both normalised names | |
| 5 | Pull an old upstream package through the virtual | `GET /pypi/${HAL_REPO_DATA_PYPI}/simple/six/` | `200`; SKIP without internet | |
| 6 | Age gate on the PyPI remote (unlocked) | `GET /api/v1/repositories/${HAL_REPO_DATA_PYPI_REMOTE}/age-gate` (`jwt:DATA_LEAD`) | `200`, `instance_locked: false` | |
| 7 | Sofia switches it to `first_seen` mode, then back | `PUT .../age-gate` `{"enabled":true,"min_age_days":7,"mode":"first_seen"}` then `upstream_publish_time` | `200`, `200` | H/age_gate.rs:134-149 |
| 8 | Conda: Arjun uploads a minimal package to the conda local | build a `.tar.bz2` with `info/index.json` (see `tests/formats/test-conda.sh` for a builder) and `PUT /conda/${HAL_REPO_DATA_CONDA_LOCAL}/noarch/<file>` | `200`/`201` (pin) | H/conda.rs:670, 7563-7760 |
| 9 | `repodata.json` through the conda virtual lists it | `GET /conda/${HAL_REPO_DATA_CONDA}/noarch/repodata.json` | `200`, contains the filename | (#4173) |
| 10 | An age gate on conda cannot be enabled | `PUT /api/v1/repositories/${HAL_REPO_DATA_CONDA_REMOTE}/age-gate` `{"enabled":true,...}` | `400` (format not enforceable; message is stale and omits maven/mcp, note it) | H/age_gate.rs:690-701, backend/src/formats/mod.rs:503-617 |
| 11 | Sofia removes Arjun's sdist | REST `DELETE` (`jwt:DATA_LEAD`) | `409` "Cannot delete an immutable/released artifact": a released PyPI file is immutable for a non-instance-admin, project admin included. The sdist stays (hygiene note above) | RS:13745 `delete_blocked_by_immutability`; S/cache_classifier.rs `classify_pypi` |

Should NOT work:

- The CI token cannot publish to the conda local, which is outside its repository list. That belongs to the `ci` role. Data instead checks that Arjun's personal token cannot read firmware: `GET /cargo/${HAL_REPO_FW_CARGO_LOCAL}/config.json` with `basictoken:DATA_DEV:HAL_DATA_DEV_TOKEN` answers `404`.
- Arjun deletes the day-0 package with his token: `403` `Token does not have required scope: delete:artifacts`.
- Arjun (not project admin) changes the age gate: `PUT .../age-gate` answers `403`.

---

## devops (Kai Nakamura, lead)

Credentials: `OPS_LEAD`, personal token `HAL_OPS_LEAD_TOKEN`. Uses `docker`
with a private `DOCKER_CONFIG` under `$CS_WORK` when it is there. Without
it the docker-client items SKIP, and #3 copies both images over the OCI API
with curl instead, so the scan and scan-policy work (security, ci, auditor)
still runs.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | `docker login $REGISTRY -u ${HAL_OPS_LEAD_USER}` with his token as the password | | success (`/v2/token` accepts Basic user:api_token, tried first) | H/oci_v2.rs:5785-5790 |
| 2 | Pull an upstream image through the docker virtual | `docker pull $REG/${HAL_REPO_OPS_DOCKER}/library/busybox:1.36` | success; SKIP without internet | |
| 3 | Push an old, vulnerable image to the local (e.g. retag `alpine:3.12`) as `${HAL_REPO_OPS_DOCKER_LOCAL}/${HAL}-ops-base:1` | `docker push`; without docker, copy it from the upstream registry over the OCI API with curl (manifest PUT `201`) | success; signal `ops-image-pushed` `pushed`, or `none` when no image was pushed (SKIP without internet) | scan_on_upload is on for this repo (found-policies.sh) |
| 4 | Pull it back through the virtual | `docker pull $REG/${HAL_REPO_OPS_DOCKER}/${HAL}-ops-base:1` | success before the scan finishes, **or** refused once the policy blocks it. Wait for `ops-image-reviewed` and then pin the outcome | #4510: a scan-policy hold answers `403` |
| 5 | After `ops-image-reviewed`: pull the vulnerable image | `GET /v2/${HAL_REPO_OPS_DOCKER_LOCAL}/${HAL}-ops-base/manifests/1` (Bearer from `/v2/token`) | `403` with the scan-policy message, unless security acknowledged every finding (then `200`); assert the `ops-image-reviewed` outcome (`blocked` → `403`, `cleared` → `200`) | HOLDS:11-19, 142-146; RN:48 |
| 6 | Upload a build artifact to the generic repo with his token (Bearer) | `cs_put_generic "$HAL_REPO_OPS_BUILDS" ${HAL}-ops/app-1.0.0.tar.gz <file> token:HAL_OPS_LEAD_TOKEN` | `201` | RS:11117-11141 |
| 7 | Same upload with Basic `user:token` | `basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN` | `401` (Basic api-token refused on REST, #2806) | A:1012-1021 |
| 8 | Range on the day-0 firmware image | `GET /api/v1/repositories/${HAL_REPO_OPS_BUILDS}/download/${HAL_SEED_FW_BIN}` with `Range: bytes=0-1023`, `bytes=-16`, `bytes=262144-` | `206` with `Content-Range: bytes 0-1023/262144` and the first 1024 bytes of the deterministic fixture; `206` last 16 bytes; `416` with `Content-Range: bytes */262144` | RS:12659-12720, 12880-12950; RN:47 (#5502) |
| 9 | Range through `/general/` | `GET /general/${HAL_REPO_OPS_BUILDS}/${HAL_SEED_FW_BIN}` with `Range: bytes=100-199` | `206` | same helper |
| 10 | Package a helm chart and push it to the quarantined chart repo | `POST /helm/${HAL_REPO_OPS_HELM}/api/charts` multipart `chart=@${HAL}-ops-app-0.1.0.tgz` | `201`; signal `ops-chart-published` after #11 and #13 | H/helm.rs:50-73, 965 |
| 11 | Pull the chart immediately | `GET /helm/${HAL_REPO_OPS_HELM}/charts/<file>` | `409` `Artifact is quarantined and pending security review` | HOLDS; S/quarantine_service.rs:270-280 |
| 12 | After `ops-chart-released` | same GET | `200` | |
| 13 | Upload-period quarantine has no non-admin release | `POST /api/v1/quarantine/{artifact_id}/release` (`jwt:OPS_LEAD`) | `403` (repo admin too) | H/quarantine.rs:315 |
| 14 | Delete his build artifact | REST `DELETE` (`jwt:OPS_LEAD`) | `200` | |

Should NOT work:

- Kai pushes to the firmware cargo registry: `cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" ... basic:OPS_LEAD` answers `403`. Devops has **read** on the firmware project, so he can read the repo, which makes this `403`, not `404` (A:2766-2804).
- Kai triggers a scan: `POST /api/v1/security/scan` answers `403` `Admin access required` (H/security.rs:1455-1463).
- `PUT /general/${HAL_REPO_OPS_BUILDS}/x` (`basic:OPS_LEAD`, a writer) answers `405` with `Allow: GET, HEAD`. A non-writer (contractor) gets `404` there (H/general.rs:22-40).

---

## security (Rhea Collins, instance admin; Omar Haddad, analyst)

Credentials: `SEC_LEAD` (admin), `SEC_ANALYST`.

Rhea owns policy. Omar reviews findings with read only. Most security
operations are instance-admin only (matrix section 1). Only
`PUT /repositories/{key}/security` and the repo age gate accept a
repository admin.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Rhea opens the dashboard | `GET /api/v1/security/dashboard` | `200` | H/security.rs:1138 |
| 2 | Rhea reads the founded policy | `GET /api/v1/security/policies/${HAL_SCAN_POLICY_ID}` | `200`, `max_severity: critical`, repo = ops-docker-local | H/security.rs:983-997 |
| 3 | Wait `ops-image-pushed`; find the artifact and wait for the upload scan (or trigger it: `POST /api/v1/security/scan {"artifact_id":...}`) | `GET /api/v1/security/scans?artifact_id=...` until no scan is pending | completed scans with findings (alpine 3.12 has criticals) | H/security.rs:1455-1611 |
| 4 | Omar reads the findings | `GET /api/v1/security/scans/{id}/findings` (`jwt:SEC_ANALYST`) | `200` (read via the security group's project grant) | H/security.rs:1679-1713 |
| 5 | Omar tries to acknowledge one | `POST /api/v1/security/findings/{fid}/acknowledge` `{"reason":"false positive"}` | `403` | H/security.rs:2236 |
| 6 | Rhea acknowledges one (with `repository_id`) | same as Rhea | `200`; `409` if sent without `repository_id` and the scan has copies elsewhere | HOLDS:137; #5153 |
| 7 | Policy-blocks queue | `GET /api/v1/admin/holds/policy-blocks` | `200`, lists the blocked image | H/download_holds.rs:89-90 (#4510) |
| 8 | Signal `ops-image-reviewed` with outcome `blocked` (criticals left open, the block stays: the recommendation), `cleared` (every finding acknowledged) or `none` (no image reviewed). devops #5 and ci #10 pin their code on it | | | |
| 9 | Wait `ops-chart-published`; list the quarantine queue and release the chart | `GET /api/v1/admin/holds/quarantine`, `POST /api/v1/quarantine/{artifact_id}/release` | `200`, `200`; signal `ops-chart-released` | H/quarantine.rs:315 |
| 10 | Restore the firmware Maven gate that firmware #10 tightened: wait for `fw-age-gate-relax-refused`, then `PUT .../age-gate` 7 days `instance_locked:true`, so the gate ends the day as founded | `PUT /api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate` | `200` | H/age_gate.rs:709-714 |
| 11 | Instance-wide age-gate queue (sees web's review) | `GET /api/v1/admin/age-gate/reviews` | `200` | H/age_gate.rs:38-45 |
| 12 | Omar, who has read everywhere, lists scan configs. This read has no gate beyond authentication | `GET /api/v1/security/configs` (`jwt:SEC_ANALYST`) | `200`, every repo's config. Record it as an observation: any authenticated user can read it | H/security.rs:1407-1422 |
| 13 | Rhea creates a second policy for the conda local, then deletes it | `POST/DELETE /api/v1/security/policies` (`${HAL}-sec-tmp`) | `200`, `200` | H/security.rs:2400, 2510 |

Should NOT work:

- Omar creates a policy: `POST /api/v1/security/policies` answers `403` (H/security.rs:2400).
- Omar changes repository scan settings: `PUT /api/v1/repositories/${HAL_REPO_OPS_DOCKER_LOCAL}/security` answers `403` `Repository admin permission is required for this operation`. He can read the repo, so not `404` (H/security.rs:2596-2607).
- Omar reads the audit log: `GET /api/v1/admin/audit` answers `403` `Admin access required`.

---

## contractor (Nina Petrov, Petrov Embedded LLC)

Credentials: `CONTRACTOR`. Her only grant is read on `HAL_CONTRACTOR_REPO`
(= `${HAL}-fw-maven-local`). The internal handbook is readable too, by design.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Sign in, list what she can see | `GET /api/v1/repositories?per_page=100` | `200`, exactly `${HAL}-fw-maven-local` and `${HAL}-handbook` | RS:348-360 |
| 2 | Download the day-0 SDK jar and pom | `GET /maven/${HAL_CONTRACTOR_REPO}/com/halcyon/fw/hal-sdk/1.0.0/hal-sdk-1.0.0.jar` (`basic:CONTRACTOR`) | `200` | |
| 3 | Maven metadata | `GET /maven/${HAL_CONTRACTOR_REPO}/com/halcyon/fw/hal-sdk/maven-metadata.xml` | `200` | |
| 4 | Wait `fw-sdk-1.1.0`; download 1.1.0 | | `200` | |
| 5 | Read the onboarding handbook | `GET /api/v1/repositories/${HAL_REPO_HANDBOOK}/download/${HAL_SEED_HANDBOOK}` | `200` (internal = any principal, VIS) | |
| 6 | Search finds only what she can read | `GET /api/v1/search/quick?q=hal` | `200`, no hit outside her two repos | H/search.rs:540-557 |
| 7 | Package listing | `GET /api/v1/packages?per_page=100` | `200`, only packages from her repos | H/packages.rs:36-50 |
| 8 | Signal `nina-done`; wait `nina-offboarded`; read the jar again | | `404` (no rule left, private) | A:3406-3561 |
| 9 | After offboarding the handbook is still readable | | `200`. Internal is not a grant, so ending the engagement does not remove it. Record this as an observation for the README, not a failure | VIS |

Should NOT work:

- Deploying to the SDK repo: `cs_put_maven "$HAL_CONTRACTOR_REPO" com/halcyon/fw hal-sdk 9.9.9 basic:CONTRACTOR` answers `403` `You do not have permission...` (reader without write).
- Resolving through the firmware virtual: `GET /maven/${HAL_REPO_FW_MAVEN}/com/halcyon/fw/hal-sdk/1.0.0/hal-sdk-1.0.0.jar` answers `404`. She has no read on the virtual (VIS "Reading through a virtual").
- Any other team repo, e.g. `GET /npm/${HAL_REPO_WEB_NPM_LOCAL}/halcyon-ui-kit`, answers `404 Repository not found`. A write there (`cs_publish_npm ... basic:CONTRACTOR`) also answers `404` (#5458).
- Writing to the handbook: `cs_put_generic "$HAL_REPO_HANDBOOK" notes.md <f> jwt:CONTRACTOR` answers `403`, because she can read it (VIS).

---

## auditor (Ellen Shaw, external auditor)

Credentials: `AUDITOR`. Read on every department project, through group
`${HAL}-auditors`. Nothing else.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Inventory: list repositories | `GET /api/v1/repositories?per_page=100` | `200`, all 21 Halcyon repos | |
| 2 | Per-repo artifact listing for each hosted repo | `GET /api/v1/repositories/{key}/artifacts` | `200` each | |
| 3 | Virtual member listing | `GET /api/v1/repositories/${HAL_REPO_WEB_NPM}/members` | `200`, both members, no `X-AK-Virtual-Members-Notice` header (she can read both) | VIS (#4690) |
| 4 | Download one artifact per format through the virtuals (maven, cargo, npm, pypi) | | `200` each | |
| 5 | Read the generic firmware image and verify its sha256 against `HAL_SEED_FW_BIN_SHA256` | | match | |
| 6 | Read repository security config of ops-docker-local | `GET /api/v1/repositories/${HAL_REPO_OPS_DOCKER_LOCAL}/security` | `200` | H/security.rs:2540-2548 |
| 7 | Read scan results of the devops image (after `ops-image-pushed` if it exists; else SKIP) | `GET /api/v1/security/scans?repository_id=...` | `200` | H/security.rs:1593-1611 |
| 8 | Promotion history read | `GET /api/v1/promotion/repositories/${HAL_REPO_FW_MAVEN_LOCAL}/promotion-history` | `200` (visibility-gated) | H/promotion.rs:2191 |
| 9 | Storage tree | `GET /api/v1/tree?repository_key=${HAL_REPO_OPS_BUILDS}` (check the query name in H/tree.rs) | `200` | H/tree.rs:55-80 |
| 10 | Webhook list | `GET /api/v1/webhooks` | `200`, filtered to webhooks on repos she can read (none exist: empty) | H/webhooks.rs:521, 534 |

Should NOT work (each answers `403` with **nothing written**; re-read state as `admin` to prove it):

- `GET /api/v1/admin/audit` answers `403` `Admin access required`. There is no auditor role (H/admin.rs:64, 238-240). This is the headline gap the README records.
- Publishing anywhere she can read: `cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" ${HAL}-audit-x 0.0.1 basic:AUDITOR` answers `403`. Deleting the day-0 crate via REST (`jwt:AUDITOR`) answers `403`.
- Reading the permission table: `GET /api/v1/permissions` answers `403` (H/permissions.rs:268-269).
- Her denied admin reads are themselves audited: as `admin`, `GET /api/v1/admin/audit?user_id=<ellen>&action=PERMISSION_DENIED` lists one row per denied admin route, and each row's `details.path` should be the full request path. It records the nest-stripped path today: WARN citing #5603.
- Changing a repository: `PATCH /api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}` `{"description":"x"}` answers `403` (repo admin required, RS:6130-6186).

---

## ci (service account `svc-${HAL}-ci`)

Credentials: `HAL_CI_TOKEN` (`read:artifacts` and `write:artifacts`, on the
repositories in `HAL_CI_TOKEN_REPOS`) and `HAL_DEPLOY_TOKEN`
(`read:artifacts` on ops-docker, ops-docker-local and ops-helm). The service
account has grants: read on all four projects, write on the CI publish repos.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Token identity | `GET /api/v1/users/me` (`token:HAL_CI_TOKEN`) | `200`, `username == svc-${HAL}-ci`, `is_service_account: true` | |
| 2 | Publish a crate (merge build) | `cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" ${HAL}-ci-build ... token:HAL_CI_TOKEN` | `200` | |
| 3 | Publish npm, pypi and maven builds the same way (Basic `svc-...:token` on native routes) | | npm `200`, pypi `200`, maven pom and jar `201` | A:1487-1508 |
| 4 | Upload a build artifact via REST with Bearer | `cs_put_generic "$HAL_REPO_OPS_BUILDS" ${HAL}-ci/build-<n>.bin <f> token:HAL_CI_TOKEN` | `201` | |
| 5 | The same with `X-API-Key: $HAL_CI_TOKEN` | | `201` | A:948, 600-607 |
| 6 | Resolve dependencies through the virtuals it is scoped to (fw-maven, web-npm, data-pypi) | | `200` | VIS "Tokens scoped to a virtual" |
| 7 | Wait `fw-sdk-1.1.0`; resolve `hal-sdk` 1.1.0 through `${HAL_REPO_FW_MAVEN}` | | `200` | |
| 8 | Push an image with the CI token (docker login `svc-...` + token), if `docker` is present | | success | H/oci_v2.rs:638-660 |
| 9 | Wait `ops-chart-released`; the deploy token pulls the chart | `GET /helm/${HAL_REPO_OPS_HELM}/index.yaml` and the chart file (`basictoken` with `HAL_CI_SA_USER`) | `200` | |
| 10 | Wait `ops-image-pushed` (devops deletes and re-pushes the image every run) and `ops-image-reviewed`; the deploy token reads the image manifest through the docker virtual | `/v2/token` (with the `service` from the `/v2/` challenge) then `GET /v2/${HAL_REPO_OPS_DOCKER}/.../manifests/...` | `200`, or the scan-policy `403` for the vulnerable image (assert per security's note) | |
| 11 | Repository listing with the CI token is exactly its scoped set | `GET /api/v1/repositories?per_page=100` | `200`, the 12 repos of `HAL_CI_TOKEN_REPOS` and nothing else (the handbook drops out too) | RS:351-356 |
| 12 | Clean up its own artifacts. It can't: the token has no `delete:artifacts`. Record `403`, then have the admin delete them | REST `DELETE` with `token:HAL_CI_TOKEN` | `403` `Token does not have required scope: delete:artifacts` | |

Should NOT work:

- Publishing to `${HAL_REPO_DATA_CONDA_LOCAL}`, which is outside the token's list: REST `PUT` with `token:HAL_CI_TOKEN` answers `404` `{"code":"NOT_FOUND"...}`. Checked live on `dev`.
- Basic `svc-...:<token>` on REST `PUT .../artifacts/...` answers `401` (#2806).
- The deploy token writes to ops-helm: `403` `Token does not have required scope: write:artifacts`. It writes to ops-builds, outside its list: also `403` with the scope message, because the scope check runs before the repository list on REST (checked live on `dev`). Pin it, and note it.
- The CI token reads a firmware member directly, outside the virtual it is scoped to: `GET /cargo/${HAL_REPO_FW_CARGO_REMOTE}/config.json` answers `404`. Members are readable only through the scoped virtual (VIS).
- The CI token creates a group: `POST /api/v1/groups` answers `403` (bare `write` scope required; H/groups.rs:369).

---

## departed-employee (Leo Varga, web engineer)

Credentials: `WEB_DEV`, personal token `HAL_WEB_DEV_TOKEN`.

Leo works his last morning. Then the platform admin offboards him, and every
credential he held must stop working.

| # | Task | Request | Expected | Backed by |
| --- | --- | --- | --- | --- |
| 1 | Sign in; keep the JWT | `cs_login WEB_DEV` | `200` | |
| 2 | Also get a refresh token | the `refresh_token` from the login body | present | |
| 3 | Publish `${HAL}-web-leo-widget` 1.0.0 with his personal token | `cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" ... basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN` | `200` | H/npm.rs publish |
| 4 | Read it through the virtual with the JWT | | `200` | |
| 5 | Signal `leo-worked`; wait `leo-offboarded` | | | |
| 6 | Old JWT on REST | `GET /api/v1/users/me` (`jwt:WEB_DEV`, cached) | `401` | S/auth_service.rs:990-1015 |
| 7 | Old JWT on a native read | `GET /npm/${HAL_REPO_WEB_NPM}/${HAL}-web-leo-widget` | `401`, not an anonymous `404` (#1371) | A:3203-3207 |
| 8 | Personal token, Bearer, REST | `GET /api/v1/repositories/${HAL_REPO_WEB_NPM_LOCAL}` (`token:HAL_WEB_DEV_TOKEN`) | `401` | S/auth_service.rs:1039 |
| 9 | Personal token as npm Basic | publish 1.0.1 with `basictoken:WEB_DEV:HAL_WEB_DEV_TOKEN` | `401` | |
| 10 | Password login | `POST /api/v1/auth/login` | `401` `{"code":"AUTH_ERROR","message":"Invalid username or password"}`. It is the same body as a wrong password: check it against a deliberately wrong password for a live persona | S/auth_service.rs:1396, 1683, 1759 |
| 11 | Refresh token | `POST /api/v1/auth/refresh` with the token from 2 | `401` | H/users.rs:564-574 (families revoked) |
| 12 | Docker login with the token | `/v2/token` Basic `leo:token` | `401 UNAUTHORIZED` | H/oci_v2.rs:5603-5628 |
| 13 | A ticket minted before leaving (`POST /api/v1/auth/ticket` or the download-ticket route, before 5) used after | | `401` (VERIFY the ticket route and its deactivation check in A:1582-1584) | |

Should NOT work: everything after step 5, above. Also verify, as `admin`,
that nothing Leo did after step 5 was written. His 1.0.1 must be absent.

---

## Replay notes

- The founder re-activates Leo, restores the web group, restores Nina's
  grant, re-mints all tokens, and puts the age gates back. A replay after a
  full day therefore starts from the same state.
- **Re-run the founder before every replay of the roles.** platform-admin's
  offboarding is one-way within a day: Leo stays deactivated with his tokens
  revoked and Nina's grant stays deleted. Only `00-found-company.sh`
  re-activates Leo, resets his password, puts him back in the web group,
  restores Nina's grant and re-mints every token (including the ones
  departed-employee and contractor depend on). A roles-only replay without
  the founder fails departed-employee from its first sign-in and contractor
  from its first read. `test-company-sim.sh` (and so `run-suite.sh`) always
  runs the founder first.
- Things the founder does not undo: artifacts the roles published and did
  not delete, age-gate review decisions, finding acknowledgements, and audit
  rows. Roles must tolerate a previous run's leftovers: use version numbers
  that carry a run counter, or check-then-publish. firmware's `hal-sdk` 1.1.0
  is check-then-publish (released Maven is immutable), so on a replay its
  publish check SKIPs.
