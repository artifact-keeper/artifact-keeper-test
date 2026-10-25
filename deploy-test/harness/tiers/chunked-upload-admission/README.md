# chunked-upload-admission

Profile: `storage.filesystem`. Backend change: artifact-keeper/artifact-keeper#5003
on `release/1.11.x` (first line release 1.11.8) and #4992 on main.

The chunked upload-session API (`POST /api/v1/uploads`, `PATCH`, `PUT .../complete`)
admits writes the same way the native single-request routes do:

- Chunked uploads apply the repository quota unless the session is a trusted
  replication session (an administrator or a service account). The
  `x-artifact-keeper-replication` header on its own does not exempt a session.
- Chunked uploads honour the repository's upload quarantine hold. An artifact
  completed through the session API is `quarantined` and its download answers
  409 until the hold lapses, as a native upload into the same repository is.

| Gate | Kind | Expectation |
|---|---|---|
| CONTROL quota | control | non-admin chunked upload within the quota completes 200 and downloads byte-identical |
| FIX quota | fix | non-admin writer with the replication header, over the quota: 413 at session create (or 507 at completion) |
| FIX quota residue | fix | no artifact row, no stored object with the refused bytes, download 404 |
| CONTROL trusted | control | the same over-quota replication request from an administrator is admitted |
| FIX quarantine | fix | chunked upload into a quarantine-enabled repository: listing and DB `quarantined`, download 409 |
| CONTROL native hold | control | native `PUT` into the same repository is held the same way |

The FIX gates are red on backend 1.11.7 and earlier; the CONTROL gates are green
on every image.

Run: `harness/run.sh chunked-upload-admission --backend-image <image> --slot <N>`.
The object sweep reads the backend's `/data` volume through a throwaway
`postgres:16-alpine` container (`--volumes-from`), since the backend image has
no shell. The writer's password is generated per run.
