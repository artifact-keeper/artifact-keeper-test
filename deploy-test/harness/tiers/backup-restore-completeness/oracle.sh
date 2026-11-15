#!/usr/bin/env bash
# =============================================================================
# tiers/backup-restore-completeness/oracle.sh: a full backup brings back a
#   deleted Docker repository's image, groups, webhooks, settings and scan
#   data, says what it excludes, and a restore that cannot bring bytes back
#   says so (artifact-keeper#5654)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH, DTF_DIR.
#
# Back up, delete and restore on the same server (see the manifest). The
# archive's manifest.json is read from the backend's storage volume with
# `docker cp` (the runtime image has no shell).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

DTF_DIR="${DTF_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
# shellcheck source=/dev/null
source "${DTF_DIR}/harness/lib/repo_delete.sh"

SLOT="${DTF_SLOT:-x}"
SUF="${RUN_ID##*-}$$"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"

DOCKER="brc-oci-${SLOT}-${SUF}"
GEN="brc-gen-${SUF}"
IMG="app"
TAG="v1"
USR="brc-user-${SUF}"
USR_PASS="Brc_${SUF}_Aa1!"
GROUP="brc-group-${SUF}"
HOOK="brc-hook-${SUF}"
POLICY="brc-policy-${SUF}"
SETTING="brc_setting_${SUF}"
N_GEN=5

WORK="$(mktemp -d -t dtf-brc-XXXXXX)"
_REPO_DELETE_DIR="${WORK}/repo-delete"; mkdir -p "$_REPO_DELETE_DIR"
trap 'rm -rf "$WORK"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }
AUTH() { printf 'Authorization: Bearer %s' "$ADMIN_TOKEN"; }

# req LABEL METHOD URL [CURL ARGS...] -> prints the status; body in $WORK/LABEL.body
req() {
  local l="$1" m="$2" url="$3"; shift 3
  curl -s --max-time 120 -X "$m" -o "${WORK}/${l}.body" -w '%{http_code}' "$@" "$url" 2>/dev/null || echo 000
}
jbody() { jq -c "${2:-.}" "${WORK}/$1.body" 2>/dev/null | head -c 600; }
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
digest_of() { echo "sha256:$(sha_of "$1")"; }

begin_suite "backup-restore-completeness"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: a Docker image, 5 generic artifacts, a group with a member, a webhook, a setting, a scan config and a scan policy"
auth_admin
if [ -z "${ADMIN_TOKEN:-}" ]; then infra_fail "admin login failed"; end_suite; fi
for spec in "$DOCKER:docker" "$GEN:generic"; do
  c="$(req mk POST "${BASE_URL}/api/v1/repositories" -H "$(AUTH)" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${spec%%:*}\",\"name\":\"${spec%%:*}\",\"format\":\"${spec##*:}\",\"repo_type\":\"local\",\"is_public\":false}")"
  case "$c" in 200|201) ;; *) infra_fail "create ${spec##*:} repo ${spec%%:*}: HTTP ${c}" "$(jbody mk)"; end_suite ;; esac
done
DOCKER_ID="$(psql_q "SELECT id FROM repositories WHERE key='${DOCKER}'")"

# The image: a config blob, a layer blob and an OCI manifest tagged v1.
printf '{"architecture":"amd64","os":"linux","dtf":"%s"}' "$SUF" > "${WORK}/config.json"
head -c 8192 /dev/urandom > "${WORK}/layer.bin"
for f in config.json layer.bin; do
  c="$(req blob POST "${BASE_URL}/v2/${DOCKER}/${IMG}/blobs/uploads/?digest=$(digest_of "${WORK}/$f")" \
    -H "$(AUTH)" -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/$f")"
  [ "$c" = "201" ] || { infra_fail "blob push of $f: HTTP ${c}" "$(jbody blob)"; end_suite; }
done
jq -nc --arg cd "$(digest_of "${WORK}/config.json")" --argjson cs "$(stat -c %s "${WORK}/config.json")" \
  --arg ld "$(digest_of "${WORK}/layer.bin")" --argjson ls "$(stat -c %s "${WORK}/layer.bin")" \
  '{schemaVersion:2, mediaType:"application/vnd.oci.image.manifest.v1+json",
    config:{mediaType:"application/vnd.oci.image.config.v1+json", digest:$cd, size:$cs},
    layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar+gzip", digest:$ld, size:$ls}]}' \
  | tr -d '\n' > "${WORK}/manifest.json"
MDIGEST="$(digest_of "${WORK}/manifest.json")"
c="$(req man PUT "${BASE_URL}/v2/${DOCKER}/${IMG}/manifests/${TAG}" -H "$(AUTH)" \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@${WORK}/manifest.json")"
[ "$c" = "201" ] || { infra_fail "manifest push: HTTP ${c}" "$(jbody man)"; end_suite; }

# Generic artifacts for the round-trip control.
for i in $(seq 1 "$N_GEN"); do
  head -c 8192 /dev/urandom > "${WORK}/gen-$i.bin"
  c="$(req gput PUT "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/brc/gen-$i.bin" -H "$(AUTH)" --data-binary "@${WORK}/gen-$i.bin")"
  case "$c" in 200|201) ;; *) infra_fail "generic upload $i: HTTP ${c}" "$(jbody gput)"; end_suite ;; esac
done

# A group with a member.
USER_ID="$(create_test_user_with_retry "$USR" "$USR_PASS" "${USR}@dtf.invalid")" || USER_ID=""
[ -n "$USER_ID" ] || { infra_fail "could not create user ${USR}"; end_suite; }
c="$(req grp POST "${BASE_URL}/api/v1/groups" -H "$(AUTH)" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$GROUP" '{name:$n, description:"dtf backup-restore-completeness"}')")"
GROUP_ID="$(jq -r '.id // empty' "${WORK}/grp.body" 2>/dev/null)"
[ -n "$GROUP_ID" ] || { infra_fail "create group: HTTP ${c}" "$(jbody grp)"; end_suite; }
add_group_members "$GROUP_ID" "$USR" >/dev/null 2>&1 || { infra_fail "add ${USR} to ${GROUP}"; end_suite; }

# A global webhook.
c="$(req hook POST "${BASE_URL}/api/v1/webhooks" -H "$(AUTH)" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$HOOK" '{name:$n, url:"https://example.com/hook", events:["artifact_uploaded"]}')")"
HOOK_ID="$(jq -r '.id // empty' "${WORK}/hook.body" 2>/dev/null)"
[ -n "$HOOK_ID" ] || { infra_fail "create webhook: HTTP ${c}" "$(jbody hook)"; end_suite; }

# A system_settings row (there is no API that removes a key, so the delete
# below goes through the database too, as in the backend's own test).
psql_q "INSERT INTO system_settings (key, value) VALUES ('${SETTING}', '\"kept-${SUF}\"'::jsonb)" >/dev/null
[ "$(psql_q "SELECT value #>> '{}' FROM system_settings WHERE key='${SETTING}'")" = "kept-${SUF}" ] \
  || { infra_fail "could not insert the system_settings row"; end_suite; }

# A scan config on the Docker repository, and a global scan policy.
c="$(req scfg PUT "${BASE_URL}/api/v1/repositories/${DOCKER}/security" -H "$(AUTH)" -H 'Content-Type: application/json' \
  -d '{"scan_enabled":true,"scan_on_upload":false,"scan_on_proxy":false}')"
case "$c" in 200|201) ;; *) infra_fail "set the Docker repository's scan config: HTTP ${c}" "$(jbody scfg)"; end_suite ;; esac
c="$(req pol POST "${BASE_URL}/api/v1/security/policies" -H "$(AUTH)" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$POLICY" '{name:$n, max_severity:"critical", block_unscanned:false, block_on_fail:false}')")"
POLICY_ID="$(jq -r '.id // empty' "${WORK}/pol.body" 2>/dev/null)"
[ -n "$POLICY_ID" ] || { infra_fail "create scan policy: HTTP ${c}" "$(jbody pol)"; end_suite; }
pass

# --- probes used before and after -------------------------------------------
# pull_ok: the manifest by tag and by digest, and both blobs by digest, answer
# 200 with the pushed bytes. Prints what differs.
pull_ok() {
  local out="" c p want
  for spec in "manifests/${TAG}:manifest.json" "manifests/${MDIGEST}:manifest.json" \
              "blobs/$(digest_of "${WORK}/config.json"):config.json" "blobs/$(digest_of "${WORK}/layer.bin"):layer.bin"; do
    p="${spec%:*}"; want="${spec##*:}"
    c="$(req pull GET "${BASE_URL}/v2/${DOCKER}/${IMG}/${p}" -H "$(AUTH)" \
      -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json')"
    if [ "$c" != "200" ] || ! cmp -s "${WORK}/pull.body" "${WORK}/${want}"; then
      out="${out}GET /v2/${DOCKER}/${IMG}/${p}: HTTP ${c} $(head -c 160 "${WORK}/pull.body" | tr -d '\0')"$'\n'
    fi
  done
  printf '%s' "$out"
}
# gen_ok: every generic artifact downloads with its SHA-256.
gen_ok() {
  local out="" i c
  for i in $(seq 1 "$N_GEN"); do
    c="$(req gget GET "${BASE_URL}/api/v1/repositories/${GEN}/download/brc/gen-$i.bin" -H "$(AUTH)")"
    if [ "$c" != "200" ] || [ "$(sha_of "${WORK}/gget.body")" != "$(sha_of "${WORK}/gen-$i.bin")" ]; then
      out="${out}gen-$i.bin: HTTP ${c}, sha256 $(sha_of "${WORK}/gget.body" | cut -c1-16)…"$'\n'
    fi
  done
  printf '%s' "$out"
}

begin_test "CONTROL before: the image pulls (manifest by tag and digest, both blobs) and the generic artifacts download"
OUT="$(pull_ok)$(gen_ok)"
if [ -z "$OUT" ]; then pass; else fail "pull/download before the backup failed" "$OUT"; fi

# =============================================================================
# BACKUPS
# =============================================================================
# backup TYPE [EXTRA JSON] -> echoes the backup id once it completed
run_backup() {
  local body bid c extra="${2:-}"
  [ -n "$extra" ] || extra='{}'
  body="$(jq -nc --arg t "$1" --argjson x "$extra" '{type:$t} + $x')"
  c="$(req bk POST "${BASE_URL}/api/v1/admin/backups" -H "$(AUTH)" -H 'Content-Type: application/json' -d "$body")"
  bid="$(jq -r '.id // empty' "${WORK}/bk.body" 2>/dev/null)"
  [ -n "$bid" ] || { echo "create ${1} backup: HTTP ${c} $(jbody bk)" >&2; return 1; }
  c="$(req bkx POST "${BASE_URL}/api/v1/admin/backups/${bid}/execute" -H "$(AUTH)" -H 'Content-Type: application/json')"
  if [ "$(psql_q "SELECT status FROM backups WHERE id='${bid}'")" != "completed" ]; then
    echo "execute ${1} backup ${bid}: HTTP ${c} $(jbody bkx)" >&2; return 1
  fi
  echo "$bid"
}

begin_test "CONTROL: a full backup and a metadata backup of the Docker repository complete"
FULL_ID="$(run_backup full 2>"${WORK}/bkerr")"
META_ID="$(run_backup metadata "{\"repository_ids\":[\"${DOCKER_ID}\"]}" 2>>"${WORK}/bkerr")"
if [ -n "$FULL_ID" ] && [ -n "$META_ID" ]; then
  pass
else
  fail_fatal "a backup did not complete" "$(cat "${WORK}/bkerr")"
fi

begin_test "FIX #5654: the full backup's manifest.json archives the image, group, webhook, settings and scan tables, names the Docker repository and reports what it excludes"
SP="$(psql_q "SELECT storage_path FROM backups WHERE id='${FULL_ID}'" | tr -d '[:space:]')"
docker cp "${BACKEND_CTR}:/data/storage/${SP}" "${WORK}/full.tar.gz" >/dev/null 2>&1
if ! tar -xzOf "${WORK}/full.tar.gz" manifest.json > "${WORK}/bk-manifest.json" 2>/dev/null; then
  tar -tzf "${WORK}/full.tar.gz" 2>/dev/null | grep -m1 'manifest.json$' > "${WORK}/mpath"
  tar -xzOf "${WORK}/full.tar.gz" "$(cat "${WORK}/mpath")" > "${WORK}/bk-manifest.json" 2>/dev/null
fi
if ! jq -e . "${WORK}/bk-manifest.json" >/dev/null 2>&1; then
  fail "could not read manifest.json from the archive at /data/storage/${SP}" "$(tar -tzf "${WORK}/full.tar.gz" 2>&1 | head -5)"
else
  MISSING="$(jq -r --arg r "$DOCKER" '
    [ (["oci_blobs","oci_manifests","oci_tags","groups","user_group_members","webhooks",
        "system_settings","scan_configs","scan_policies"]
        - (.database_tables // []) | map("table " + .))[],
      (if ((.contents.oci_repositories // []) | index($r)) == null then "contents.oci_repositories without " + $r else empty end),
      (if ((.contents.excluded // []) | map(.category) | index("webhook_deliveries")) == null then "contents.excluded without webhook_deliveries" else empty end),
      (if ((.contents.excluded_tables // []) | length) == 0 then "no contents.excluded_tables" else empty end)
    ] | join("; ")' "${WORK}/bk-manifest.json")"
  echo "  contents: $(jq -c '{oci_repositories: .contents.oci_repositories, excluded: [.contents.excluded[]?.category], excluded_tables: (.contents.excluded_tables | length?)}' "${WORK}/bk-manifest.json" 2>/dev/null)"
  if [ -z "$MISSING" ]; then
    pass
  else
    fail "the backup manifest is missing: ${MISSING}" "database_tables: $(jq -c '.database_tables' "${WORK}/bk-manifest.json" | head -c 400)"
  fi
fi

# =============================================================================
# DELETE
# =============================================================================
begin_test "CONTROL: delete the two repositories, the group, the webhook, the scan policy and the setting; the image 404s"
ERR=""
for k in "$DOCKER" "$GEN"; do
  delete_repository_and_wait "$BASE_URL" "$ADMIN_TOKEN" "$k" 180 || ERR="${ERR}delete ${k}: ${REPO_DELETE_ERROR}"$'\n'
done
for spec in "groups/${GROUP_ID}" "webhooks/${HOOK_ID}" "security/policies/${POLICY_ID}"; do
  c="$(req del DELETE "${BASE_URL}/api/v1/${spec}" -H "$(AUTH)")"
  case "$c" in 200|202|204) ;; *) ERR="${ERR}DELETE /api/v1/${spec}: HTTP ${c} $(jbody del)"$'\n' ;; esac
done
psql_q "DELETE FROM system_settings WHERE key='${SETTING}'" >/dev/null
C="$(req pull GET "${BASE_URL}/v2/${DOCKER}/${IMG}/manifests/${TAG}" -H "$(AUTH)")"
[ "$C" = "404" ] || ERR="${ERR}manifest GET after the delete: HTTP ${C}"$'\n'
LEFT="$(psql_q "SELECT (SELECT count(*) FROM groups WHERE id='${GROUP_ID}') + (SELECT count(*) FROM webhooks WHERE id='${HOOK_ID}')
  + (SELECT count(*) FROM scan_policies WHERE id='${POLICY_ID}') + (SELECT count(*) FROM system_settings WHERE key='${SETTING}')")"
[ "$LEFT" = "0" ] || ERR="${ERR}${LEFT} of the group/webhook/policy/setting rows survived the delete"$'\n'
if [ -z "$ERR" ]; then pass; else fail_fatal "the delete step did not take" "$ERR"; fi

# =============================================================================
# RESTORE THE FULL BACKUP
# =============================================================================
begin_test "CONTROL: the full restore answers 200"
RC="$(req rst POST "${BASE_URL}/api/v1/admin/backups/${FULL_ID}/restore" -H "$(AUTH)" -H 'Content-Type: application/json' \
  -d '{"restore_database":true,"restore_artifacts":true}')"
echo "  restore: HTTP ${RC} $(jbody rst '{status, errors, excluded, artifacts_restored, integrity_anchor}')"
cp "${WORK}/rst.body" "${WORK}/restore-full.json"
if [ "$RC" = "200" ]; then pass; else fail_fatal "restore answered ${RC}" "$(jbody rst)"; fi

begin_test "CONTROL: the 5 generic artifacts round-trip with matching SHA-256 checksums"
OUT="$(gen_ok)"
if [ -z "$OUT" ]; then pass; else fail "a generic artifact did not come back intact" "$OUT"; fi

begin_test "FIX #5654: the restored Docker image pulls again (manifest by tag and by digest, config and layer blobs, exact bytes)"
OUT="$(pull_ok)"
if [ -z "$OUT" ]; then pass; else fail "the restored image does not pull (pre-fix: the backup carried no image rows or blob bytes)" "$OUT"; fi

begin_test "FIX #5654: the group with its member, the webhook and the setting are restored"
OUT=""
c="$(req g GET "${BASE_URL}/api/v1/groups/${GROUP_ID}" -H "$(AUTH)")"
[ "$c" = "200" ] && [ "$(jq -r '.name // empty' "${WORK}/g.body")" = "$GROUP" ] || OUT="${OUT}GET group: HTTP ${c} $(jbody g)"$'\n'
[ "$(psql_q "SELECT count(*) FROM user_group_members WHERE group_id='${GROUP_ID}' AND user_id='${USER_ID}'")" = "1" ] \
  || OUT="${OUT}${USR} is not a member of the restored group"$'\n'
c="$(req w GET "${BASE_URL}/api/v1/webhooks/${HOOK_ID}" -H "$(AUTH)")"
[ "$c" = "200" ] && [ "$(jq -r '.name // empty' "${WORK}/w.body")" = "$HOOK" ] || OUT="${OUT}GET webhook: HTTP ${c} $(jbody w)"$'\n'
V="$(psql_q "SELECT value #>> '{}' FROM system_settings WHERE key='${SETTING}'")"
[ "$V" = "kept-${SUF}" ] || OUT="${OUT}system_settings ${SETTING} = '${V}' (want kept-${SUF})"$'\n'
if [ -z "$OUT" ]; then pass; else fail "groups, webhooks or settings did not come back" "$OUT"; fi

begin_test "FIX #5654: the Docker repository's scan config and the scan policy are restored"
OUT=""
c="$(req s GET "${BASE_URL}/api/v1/repositories/${DOCKER}/security" -H "$(AUTH)")"
[ "$(psql_q "SELECT count(*) FROM scan_configs WHERE repository_id='${DOCKER_ID}' AND scan_enabled")" = "1" ] \
  || OUT="${OUT}no scan_enabled scan_configs row for ${DOCKER} (GET .../security: HTTP ${c} $(jbody s))"$'\n'
c="$(req p GET "${BASE_URL}/api/v1/security/policies/${POLICY_ID}" -H "$(AUTH)")"
[ "$c" = "200" ] && [ "$(jq -r '.name // empty' "${WORK}/p.body")" = "$POLICY" ] || OUT="${OUT}GET scan policy: HTTP ${c} $(jbody p)"$'\n'
if [ -z "$OUT" ]; then pass; else fail "scan data did not come back" "$OUT"; fi

begin_test "FIX #5654: the full restore reports status completed, errors [] and the excluded categories"
if jq -e '.status == "completed" and (.errors | length) == 0 and ((.excluded // []) | length) > 0' "${WORK}/restore-full.json" >/dev/null 2>&1; then
  pass
else
  fail "the restore report is not {status: completed, errors: [], excluded: [...]}" "$(jq -c '{status, errors, excluded}' "${WORK}/restore-full.json" | head -c 400)"
fi

# =============================================================================
# HONESTY: a restore that cannot bring the bytes back says so
# =============================================================================
# A metadata backup carries the rows and no bytes. Since #5799 the restore
# lists `artifact_bytes` under `excluded` (a full archive whose rows reference
# bytes it lacks would answer `status: partial` with an error naming them);
# pre-fix the report was {errors: []} with nothing excluded, as if complete.
begin_test "FIX #5654: restoring a metadata backup (rows, no bytes) of the deleted Docker repository reports artifact_bytes as excluded, not a complete restore"
if ! delete_repository_and_wait "$BASE_URL" "$ADMIN_TOKEN" "$DOCKER" 180; then
  fail "could not delete ${DOCKER} again: ${REPO_DELETE_ERROR}"
else
  RC="$(req rstm POST "${BASE_URL}/api/v1/admin/backups/${META_ID}/restore" -H "$(AUTH)" -H 'Content-Type: application/json' \
    -d '{"restore_database":true,"restore_artifacts":true}')"
  echo "  restore: HTTP ${RC} $(jbody rstm '{status, errors, excluded}')"
  if [ "$RC" = "200" ] \
     && jq -e '(.status == "completed" or .status == "partial") and ((.excluded // []) | index("artifact_bytes")) != null' "${WORK}/rstm.body" >/dev/null 2>&1; then
    pass
  else
    fail "a restore that brings back no bytes answered HTTP ${RC} without a status and without artifact_bytes under excluded" "$(jbody rstm '{status, errors, excluded}')"
  fi
fi

end_suite
