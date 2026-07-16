# =============================================================================
# plugins/gitlfs.sh — format-conformance plugin (Git LFS)
# FC_FORMAT: gitlfs
# FC_MOUNT: lfs                # routes.rs nest prefix is /lfs (NOT /gitlfs)
# FC_REPO_FORMAT: gitlfs
# FC_PROFILE: client.gitlfs
# FC_SERVICE: client-gitlfs
# FC_ENABLED: 1
# =============================================================================
# Git LFS routes (backend handlers/gitlfs.rs): nest /lfs; batch
# `POST /:repo/objects/batch`; object `GET|PUT /:repo/objects/:oid`; verify
# `POST /:repo/verify`; locks `POST|GET /:repo/locks`, verify + unlock. 2 GB body
# limit. Objects are content-addressed by their 64-hex sha256 OID.
#
# Flow (real client): a local `file://` bare repo carries the GIT bytes (commits
# + LFS pointer files); the LFS OBJECT bytes go to AK. The work repo's
# `.lfsconfig` sets `[lfs] url = $FC_INT_URL`, so `git push` drives the Batch API
# upload to AK. A fresh clone of the bare repo has EMPTY lfs cache; `git lfs
# pull` MUST fetch the object from AK via batch->download href (the #2580 path).
#
# Publish here IS the real git-lfs push (the client uploading), which is a
# stronger-than-brick-3 publish. The discriminating CONSUME is the fresh-clone
# `git lfs pull` from an empty cache.
# =============================================================================
# KNOWN-RED: locks_api is implemented (fc_case_locks_api below) but held OUT of
# the active run set — the Git LFS file-locking API is structurally broken in the
# backend. create_lock() inserts into artifact_metadata with
# `artifact_id = repo.id` (a REPOSITORY id used as a grouping key), but
# artifact_metadata.artifact_id is `UUID UNIQUE NOT NULL REFERENCES artifacts(id)`
# (migrations/004_artifacts.sql:27). A repository id is never a valid artifacts.id,
# so every POST /lfs/:repo/locks 500s on
# artifact_metadata_artifact_id_fkey; the UNIQUE column would additionally cap it
# at one lock per repo. list/verify/delete-lock read the same non-existent rows.
# See rig/results/format-conformance/gitlfs-finding.md. Re-add `locks_api` to
# FC_CASES once the backend gives locks their own storage (or a nullable/valid
# artifact_id); the hook is a positive+negative discriminator ready to go.
FC_CASES="multi_object_batch auth_batch verify_endpoint"

FC_EXEC_USER="root"

LFS_BARE="/srv/dtf-bare"
LFS_WORK="/srv/dtf-work"
LFS_WORK2="/srv/dtf-consume"
LFS_TRACK="assets/model.bin"

# _lfs_batch <download|upload> <auth:yes|no> <json-objects-array> <out-file>
# POSTs an LFS Batch API request from the HOST and echoes the HTTP status code.
_lfs_batch() {
  local op="$1" auth="$2" objs="$3" out="$4"
  local body="{\"operation\":\"${op}\",\"transfers\":[\"basic\"],\"objects\":${objs}}"
  local hargs=(-H "Content-Type: application/vnd.git-lfs+json"
               -H "Accept: application/vnd.git-lfs+json")
  [ "$auth" = "yes" ] && hargs+=(-H "$(format_auth_header)")
  curl -s -o "$out" -w '%{http_code}' --max-time 60 -X POST \
    "${hargs[@]}" --data-binary "$body" "${FC_URL}/objects/batch" 2>/dev/null
}

# ---------------------------------------------------------------------------
# fc_publish — install git/git-lfs, build a file:// bare + work repo, commit a
# 1 MiB random LFS blob, and `git push` (the pre-push hook drives the LFS batch
# upload to AK). Records the object OID (== sha256) and size for later hooks.
# ---------------------------------------------------------------------------
fc_publish() {
  # The client image installs bash/git/git-lfs at startup (see client.gitlfs.yml);
  # `up --wait` can report the container ready before that apk run finishes, so
  # wait for git-lfs to appear (no racing apk — a second apk would deadlock on the
  # apk db lock) rather than re-installing here.
  nc_exec -t 120 'for i in $(seq 1 30); do command -v git-lfs >/dev/null 2>&1 && break; sleep 2; done
command -v git >/dev/null 2>&1 && command -v git-lfs >/dev/null 2>&1 && git lfs version' \
    || { echo "git/git-lfs not present in the client after startup install"; return 1; }
  # Git identity + a credential-store entry so the LFS batch UPLOAD authenticates
  # to AK (basic auth; no anonymous write). Only the AK host is configured.
  nc_exec "git config --global user.email dtf@example.invalid
git config --global user.name 'DTF Rig'
git config --global credential.helper store
printf 'http://%s:%s@backend:8080\n' '${ADMIN_USER}' '${ADMIN_PASS}' > /root/.git-credentials
git lfs install --skip-repo" || return 1

  # Build the bare repo (git bytes only) + a working repo whose .lfsconfig points
  # the LFS transport at AK, then commit a random blob tracked by LFS.
  nc_exec -t 180 "set -e
rm -rf '${LFS_BARE}' '${LFS_WORK}' '${LFS_WORK2}'
git init --bare -b main '${LFS_BARE}' >/dev/null
git init -b main '${LFS_WORK}' >/dev/null
cd '${LFS_WORK}'
git lfs install --local >/dev/null
printf '[lfs]\n\turl = ${FC_INT_URL}\n' > .lfsconfig
mkdir -p assets
git lfs track '*.bin' >/dev/null
head -c 1048576 /dev/urandom > '${LFS_TRACK}'
git add .gitattributes .lfsconfig '${LFS_TRACK}'
git commit -m 'add lfs blob' >/dev/null
git remote add origin 'file://${LFS_BARE}'
git push -u origin main 2>&1" || { echo "git push (LFS upload) failed"; return 1; }

  # Capture the OID (sha256) + size the pointer references.
  LFS_OID="$(nc_exec "cd '${LFS_WORK}' && git lfs pointer --file '${LFS_TRACK}' 2>/dev/null | sed -n 's#^oid sha256:##p'" | tr -d '[:space:]')"
  LFS_SIZE="$(nc_exec "cd '${LFS_WORK}' && stat -c %s '${LFS_TRACK}'" | tr -d '[:space:]')"
  echo "  LFS object oid=${LFS_OID} size=${LFS_SIZE}"
  [ -n "$LFS_OID" ] && [ ${#LFS_OID} -eq 64 ] || { echo "could not resolve LFS oid"; return 1; }
  # The object must now be servable directly from AK (content-addressed route).
  nc_expect_code 200 "${FC_URL}/objects/${LFS_OID}" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real client is present (no silent skip). The
# consumer clone reuses the committed .lfsconfig, so no extra config is needed;
# the AK LFS url travels inside the repo.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v git >/dev/null 2>&1 && command -v git-lfs >/dev/null 2>&1 && git lfs version' \
    || { echo "git/git-lfs missing inside the provisioned client"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. Fresh-clone the bare repo (git bytes only, no
# LFS objects) with smudge SKIPPED, wipe the lfs cache to guarantee it is EMPTY,
# then `git lfs pull` — which reads .lfsconfig, hits the AK batch endpoint,
# follows the advertised download href, and fetches the object bytes from AK.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 180 "set -e
rm -rf '${LFS_WORK2}'
GIT_LFS_SKIP_SMUDGE=1 git clone 'file://${LFS_BARE}' '${LFS_WORK2}' 2>&1
cd '${LFS_WORK2}'
rm -rf .git/lfs   # guarantee an EMPTY lfs cache before the pull
git lfs pull 2>&1" || { echo "git lfs pull from AK failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the pulled blob's sha256 equals the OID (which
# IS its content sha256 == the published bytes), and git-lfs reports it resolved.
# ---------------------------------------------------------------------------
fc_assert() {
  local got
  got="$(nc_sha256_in_ctr "${LFS_WORK2}/${LFS_TRACK}")"
  nc_assert_sha_eq "$LFS_OID" "$got" "pulled blob sha256 != published OID" || return 1
  # `git lfs ls-files` marks a fully-resolved object with '*' (not '-').
  nc_exec "cd '${LFS_WORK2}' && git lfs ls-files" | grep -q '\*' \
    || { echo "git lfs ls-files does not show a resolved object"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. The batch response advertises a
# download href that 200s with the EXACT bytes; a bogus (valid-format) oid must
# return a PER-OBJECT error (code 404), NOT a 500 and NOT a fall-open action.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local out="${WORK_DIR}/lfs-batch-dl.json"
  local code
  code="$(_lfs_batch download yes "[{\"oid\":\"${LFS_OID}\",\"size\":${LFS_SIZE}}]" "$out")"
  [ "$code" = "200" ] || { echo "batch download -> HTTP ${code} (wanted 200)"; cat "$out"; return 1; }
  local href
  href="$(jq -r '.objects[0].actions.download.href // empty' "$out")"
  [ -n "$href" ] || { echo "batch response advertised no download href"; cat "$out"; return 1; }
  echo "  advertised download href=${href}"
  # The advertised href must resolve with the exact published bytes.
  local dl="${WORK_DIR}/lfs-served.bin"
  nc_fetch "$href" "$dl" || return 1
  nc_assert_sha_eq "$LFS_OID" "$(nc_sha256 "$dl")" "served bytes sha256 != OID" || return 1
  # Negative: a bogus but valid-format oid returns a per-object error, HTTP 200.
  local bogus="00000000000000000000000000000000000000000000000000000000deadbeef"
  local bout="${WORK_DIR}/lfs-batch-bogus.json"
  code="$(_lfs_batch download yes "[{\"oid\":\"${bogus}\",\"size\":123}]" "$bout")"
  [ "$code" = "200" ] || { echo "bogus-oid batch -> HTTP ${code} (expected 200 w/ per-object error, not 500)"; cat "$bout"; return 1; }
  local ecode has_action
  ecode="$(jq -r '.objects[0].error.code // empty' "$bout")"
  has_action="$(jq -r '.objects[0].actions.download.href // empty' "$bout")"
  [ -z "$has_action" ] || { echo "bogus oid fell open with a download action"; cat "$bout"; return 1; }
  [ "$ecode" = "404" ] || { echo "bogus oid error.code=${ecode} (expected 404)"; cat "$bout"; return 1; }
  echo "  bogus oid -> per-object error code 404 (no fall-open)"
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# multi_object_batch — three distinct objects negotiated in ONE batch request
# must each come back with a working download action. Bug class: batch that only
# handles the first object / drops or 500s on multi-object payloads.
fc_case_multi_object_batch() {
  local objs="[" first=1 i oid size
  for i in 1 2 3; do
    local blob="${WORK_DIR}/lfs-multi-${i}.bin"
    head -c $((4096 * i)) /dev/urandom > "$blob"
    oid="$(nc_sha256 "$blob")"
    size="$(wc -c < "$blob" | tr -d ' ')"
    # Publish each object by its content-addressed OID (authenticated PUT).
    nc_put_file "$blob" "${FC_URL}/objects/${oid}" 200 || return 1
    [ $first -eq 1 ] && first=0 || objs+=","
    objs+="{\"oid\":\"${oid}\",\"size\":${size}}"
    eval "MOB_OID_${i}='${oid}'"
  done
  objs+="]"
  local out="${WORK_DIR}/lfs-multi-batch.json"
  local code
  code="$(_lfs_batch download yes "$objs" "$out")"
  [ "$code" = "200" ] || { echo "multi-object batch -> HTTP ${code}"; cat "$out"; return 1; }
  local n
  n="$(jq -r '[.objects[] | select(.actions.download.href != null)] | length' "$out")"
  echo "  ${n}/3 objects returned a download action"
  [ "$n" = "3" ] || { echo "expected 3 resolvable objects, got ${n}"; cat "$out"; return 1; }
  # Each advertised href must actually resolve.
  local h
  for h in $(jq -r '.objects[].actions.download.href' "$out"); do
    nc_expect_code 200 "$h" || return 1
  done
}

# auth_batch — an UPLOAD batch requires basic auth; there must be no anonymous
# write fall-open. Bug class: anonymous LFS upload negotiation.
fc_case_auth_batch() {
  local blob="${WORK_DIR}/lfs-auth.bin"
  head -c 2048 /dev/urandom > "$blob"
  local oid size
  oid="$(nc_sha256 "$blob")"; size="$(wc -c < "$blob" | tr -d ' ')"
  # Negative: upload batch WITHOUT credentials must be rejected (401).
  local out="${WORK_DIR}/lfs-auth-anon.json"
  local code
  code="$(_lfs_batch upload no "[{\"oid\":\"${oid}\",\"size\":${size}}]" "$out")"
  [ "$code" = "401" ] || { echo "anonymous upload batch -> HTTP ${code} (expected 401; fall-open otherwise)"; cat "$out"; return 1; }
  echo "  anonymous upload batch rejected (401)"
  # Positive: WITH credentials the upload batch negotiates (200 + upload action).
  out="${WORK_DIR}/lfs-auth-ok.json"
  code="$(_lfs_batch upload yes "[{\"oid\":\"${oid}\",\"size\":${size}}]" "$out")"
  [ "$code" = "200" ] || { echo "authenticated upload batch -> HTTP ${code} (expected 200)"; cat "$out"; return 1; }
  jq -e '.objects[0].actions.upload.href' "$out" >/dev/null \
    || { echo "authenticated upload batch advertised no upload action"; cat "$out"; return 1; }
  echo "  authenticated upload batch negotiates an upload action"
}

# locks_api — the LFS file-locking API round-trips: create a lock, list it back,
# then unlock it. Locks endpoints require auth (no anonymous enumeration).
# Bug class: locks that vanish / cannot be released / leak without auth.
# KNOWN-RED (not in FC_CASES): POST /locks 500s because create_lock stores locks
# with artifact_id = repo.id, violating the artifact_metadata -> artifacts FK.
# Kept implemented so re-enabling is a one-line FC_CASES edit once the backend is
# fixed. See rig/results/format-conformance/gitlfs-finding.md.
fc_case_locks_api() {
  local lockpath="assets/model.bin"
  # Create (POST /locks) -> 201 with a lock id.
  local cout="${WORK_DIR}/lfs-lock-create.json"
  local code
  code="$(curl -s -o "$cout" -w '%{http_code}' --max-time 60 -X POST \
    -H "Content-Type: application/vnd.git-lfs+json" -H "$(format_auth_header)" \
    --data-binary "{\"path\":\"${lockpath}\"}" "${FC_URL}/locks" 2>/dev/null)"
  [ "$code" = "201" ] || { echo "create lock -> HTTP ${code} (wanted 201)"; cat "$cout"; return 1; }
  local lock_id
  lock_id="$(jq -r '.lock.id // empty' "$cout")"
  [ -n "$lock_id" ] || { echo "create lock returned no id"; cat "$cout"; return 1; }
  echo "  created lock id=${lock_id} path=${lockpath}"
  # Negative: listing locks WITHOUT auth must be rejected (no anonymous enum).
  local anoncode
  anoncode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 "${FC_URL}/locks" 2>/dev/null)"
  [ "$anoncode" = "401" ] || { echo "anonymous GET /locks -> HTTP ${anoncode} (expected 401)"; return 1; }
  # Positive: authenticated list shows our lock.
  local lout="${WORK_DIR}/lfs-lock-list.json"
  code="$(curl -s -o "$lout" -w '%{http_code}' --max-time 60 -H "$(format_auth_header)" "${FC_URL}/locks" 2>/dev/null)"
  [ "$code" = "200" ] || { echo "list locks -> HTTP ${code}"; cat "$lout"; return 1; }
  jq -e --arg p "$lockpath" '.locks[] | select(.path == $p)' "$lout" >/dev/null \
    || { echo "created lock not present in listing"; cat "$lout"; return 1; }
  # Unlock (POST /locks/:id/unlock) -> 200; then it must be gone.
  local uout="${WORK_DIR}/lfs-unlock.json"
  code="$(curl -s -o "$uout" -w '%{http_code}' --max-time 60 -X POST \
    -H "Content-Type: application/vnd.git-lfs+json" -H "$(format_auth_header)" \
    --data-binary '{}' "${FC_URL}/locks/${lock_id}/unlock" 2>/dev/null)"
  [ "$code" = "200" ] || { echo "unlock -> HTTP ${code} (wanted 200)"; cat "$uout"; return 1; }
  code="$(curl -s -o "$lout" -w '%{http_code}' --max-time 60 -H "$(format_auth_header)" "${FC_URL}/locks" 2>/dev/null)"
  jq -e --arg p "$lockpath" '.locks[] | select(.path == $p)' "$lout" >/dev/null \
    && { echo "lock still present after unlock"; cat "$lout"; return 1; }
  echo "  lock created, listed, and released cleanly"
}

# verify_endpoint — the post-upload verify action (git-lfs calls it when the
# batch upload response advertises it): a correct oid+size verifies (200); a size
# mismatch is rejected (422); an unknown oid is not found (404).
# Bug class: verify that rubber-stamps (would let a truncated upload look intact).
fc_case_verify_endpoint() {
  local vout="${WORK_DIR}/lfs-verify.json"
  local code
  # Positive: exact oid+size verifies.
  code="$(curl -s -o "$vout" -w '%{http_code}' --max-time 60 -X POST \
    -H "Content-Type: application/vnd.git-lfs+json" -H "$(format_auth_header)" \
    --data-binary "{\"oid\":\"${LFS_OID}\",\"size\":${LFS_SIZE}}" "${FC_URL}/verify" 2>/dev/null)"
  [ "$code" = "200" ] || { echo "verify exact -> HTTP ${code} (wanted 200)"; cat "$vout"; return 1; }
  echo "  verify exact oid+size -> 200"
  # Negative: a wrong size must be rejected (422), not rubber-stamped.
  code="$(curl -s -o "$vout" -w '%{http_code}' --max-time 60 -X POST \
    -H "Content-Type: application/vnd.git-lfs+json" -H "$(format_auth_header)" \
    --data-binary "{\"oid\":\"${LFS_OID}\",\"size\":$((LFS_SIZE + 1))}" "${FC_URL}/verify" 2>/dev/null)"
  [ "$code" = "422" ] || { echo "verify wrong-size -> HTTP ${code} (expected 422)"; cat "$vout"; return 1; }
  echo "  verify wrong size -> 422 (not rubber-stamped)"
  # Negative: an unknown (valid-format) oid is not found (404).
  local unknown="1111111111111111111111111111111111111111111111111111111111111111"
  code="$(curl -s -o "$vout" -w '%{http_code}' --max-time 60 -X POST \
    -H "Content-Type: application/vnd.git-lfs+json" -H "$(format_auth_header)" \
    --data-binary "{\"oid\":\"${unknown}\",\"size\":1}" "${FC_URL}/verify" 2>/dev/null)"
  [ "$code" = "404" ] || { echo "verify unknown-oid -> HTTP ${code} (expected 404)"; cat "$vout"; return 1; }
  echo "  verify unknown oid -> 404"
}
