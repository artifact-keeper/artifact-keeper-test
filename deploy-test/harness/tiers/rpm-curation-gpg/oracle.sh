#!/usr/bin/env bash
# =============================================================================
# tiers/rpm-curation-gpg/oracle.sh — RPM curation trusted-GPG fail-closed oracle
#   PKT-E (P5, epic #2568): verify_detached(trusted_key, repomd, repomd.xml.asc)
# =============================================================================
# run.sh has stood up `filesystem + client.dnf + upstreams=rpm-gpg`: a mock RPM
# upstream `rpm-upstream` on the slot's 172.16/12 net serving a GPG-signed
# repodata/ tree (fixtures/rpm-gpg/build.sh) at /signed (repomd.xml + .asc +
# primary.xml.gz) and /unsigned (same, NO .asc), plus a Fedora `client-dnf`
# reachable to the upstream. run.sh exported BASE_URL, DB_CONTAINER, COMMON_SH,
# ADMIN_USER/ADMIN_PASS, RUN_ID, DTF_DIR, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR.
#
# THE FEATURE (#2568). A curation staging repo synced by the scheduler runs
# `signing_service::verify_detached` over the upstream's repomd.xml and is
# FAIL-CLOSED: correct trusted key -> packages ingested; wrong/absent key or a
# missing repomd.xml.asc -> `continue` (0 packages). A signature over repomd
# alone is not enough — repomd's <checksum> must then pin primary.xml.gz
# (primary_gz_pinned_by_repomd); the fixture builds that checksum from the real
# primary bytes so the correct-key positive genuinely ingests.
#
# TRIGGER (OPEN QUESTION #2, RESOLVED). The sync is driven by the manual,
# SYNCHRONOUS admin endpoint POST /api/v1/curation/repos/{staging_key}/sync
# (#2357 WI-5), which calls run_curation_sync_cycle(only_repo=Some(id)) inline
# and returns after the pass completes — no scheduler-cron sleep-and-hope.
# There is NO API to wire curation_enabled / curation_source_repo_id (the backend
# has none — its OWN unit test sets them via SQL), so the oracle sets those two
# columns + repo_type='staging' via psql, exactly like the backend test does,
# then drives the real GPG-verify code path through the real HTTP trigger.
#
# DISCRIMINATION (all counted from curation_packages, the DB effect of ingest):
#   POS  correct key + signed tree    -> count > 0
#   CTRL no key       + signed tree   -> count > 0 (documented UNVERIFIED ingest; proves the pipeline works without a key,
#                                                    so the wrong-key 0 is attributable to VERIFY, not a dead pipeline)
#   NEG  wrong key    + signed tree   -> count == 0  <- THE #2568 discriminator (verify_detached fails -> continue)
#   NEG  correct key  + unsigned tree -> count == 0  (repomd.xml.asc 404 -> fail-closed)
#   CLIENT dnf repo_gpgcheck=1        -> makecache OK w/ correct key, FAILS w/ wrong key (undoes the native-client gpgcheck=0 bypass)
# A backend that trusted the wrong-key upstream ingests > 0 on the NEG wrong-key
# leg -> tier RED. That is the exact bug the dnf `gpgcheck=0` leg silently walks past.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

KEYS_DIR="${DTF_DIR}/fixtures/rpm-gpg/keys"
CLIENT_DNF="ak-dtf${DTF_SLOT}-client-dnf"
UP_SIGNED="http://rpm-upstream/signed"
UP_UNSIGNED="http://rpm-upstream/unsigned"

# --- helpers ----------------------------------------------------------------
# db_scalar SQL -> trimmed single-value result via psql in the DB container.
db_scalar() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}

REQ_STATUS=""; REQ_BODY_FILE=""
# req METHOD PATH [JSON] -> sets REQ_STATUS, writes body to REQ_BODY_FILE.
req() {
  local method="$1" path="$2" data="${3:-}"
  local args=(-s -o "$REQ_BODY_FILE" -w '%{http_code}' --max-time 90 -X "$method" -H "$(auth_header)")
  [ -n "$data" ] && args+=(-H "Content-Type: application/json" -d "$data")
  REQ_STATUS=$(curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null) || REQ_STATUS="000"
}
body() { cat "$REQ_BODY_FILE" 2>/dev/null || true; }

# create_remote KEY UPSTREAM [PUBKEY_FILE]  -> POST /repositories (rpm remote).
# When PUBKEY_FILE is given, trusted_gpg_key is set through the VALIDATED create
# path (must be accepted -> has_trusted_gpg_key=true). Sets REQ_STATUS/body.
create_remote() {
  local key="$1" upstream="$2" keyfile="${3:-}" payload
  if [ -n "$keyfile" ]; then
    payload=$(jq -n --arg k "$key" --arg u "$upstream" --arg g "$(cat "$keyfile")" \
      '{key:$k,name:$k,format:"rpm",repo_type:"remote",upstream_url:$u,trusted_gpg_key:$g,is_public:true}')
  else
    payload=$(jq -n --arg k "$key" --arg u "$upstream" \
      '{key:$k,name:$k,format:"rpm",repo_type:"remote",upstream_url:$u,is_public:true}')
  fi
  req POST "/api/v1/repositories" "$payload"
}

# wire_staging STAGING_KEY REMOTE_KEY -> create a hosted rpm repo via API, then
# turn it into a curation staging repo bound to REMOTE (repo_type + curation_*),
# exactly as the backend's own curation unit test does (no API for these cols).
# Prints the staging repo UUID.
wire_staging() {
  local skey="$1" rkey="$2"
  local payload
  payload=$(jq -n --arg k "$skey" '{key:$k,name:$k,format:"rpm",repo_type:"local",is_public:true}')
  req POST "/api/v1/repositories" "$payload"
  local sid rid
  sid="$(db_scalar "SELECT id FROM repositories WHERE key='${skey}'")"
  rid="$(db_scalar "SELECT id FROM repositories WHERE key='${rkey}'")"
  [ -n "$sid" ] && [ -n "$rid" ] || { echo "wire_staging: missing ids (sid='$sid' rid='$rid')" >&2; return 1; }
  db_scalar "UPDATE repositories SET repo_type='staging', curation_enabled=true, curation_default_action='allow', curation_source_repo_id='${rid}' WHERE id='${sid}'" >/dev/null
  echo "$sid"
}

# trigger_sync STAGING_KEY -> POST the manual synchronous sync; sets REQ_STATUS/body.
trigger_sync() { req POST "/api/v1/curation/repos/$1/sync"; }

# ingested_count STAGING_ID -> number of curation_packages rows for the staging repo.
ingested_count() { db_scalar "SELECT count(*) FROM curation_packages WHERE staging_repo_id='$1'"; }

# =============================================================================
begin_suite "rpm-curation-gpg-2568"
auth_admin
setup_workdir
REQ_BODY_FILE="${WORK_DIR}/req-body"

# Preflight: the baked fixture keys must exist (build.sh run before the tier).
if [ ! -s "${KEYS_DIR}/correct.pub.asc" ] || [ ! -s "${KEYS_DIR}/wrong.pub.asc" ]; then
  begin_test "fixture keys present (fixtures/rpm-gpg/build.sh baked)"
  fail "missing ${KEYS_DIR}/{correct,wrong}.pub.asc — run 'bash fixtures/rpm-gpg/build.sh' before this tier"
  end_suite
fi

RID="${RUN_ID}"
R_POS="dtf-rpmgpg-remote-pos-${RID}";   S_POS="dtf-rpmgpg-stg-pos-${RID}"
R_NOK="dtf-rpmgpg-remote-nokey-${RID}"; S_NOK="dtf-rpmgpg-stg-nokey-${RID}"
R_WRG="dtf-rpmgpg-remote-wrong-${RID}"; S_WRG="dtf-rpmgpg-stg-wrong-${RID}"
R_NOASC="dtf-rpmgpg-remote-noasc-${RID}"; S_NOASC="dtf-rpmgpg-stg-noasc-${RID}"

cleanup() {
  for k in "$S_POS" "$R_POS" "$S_NOK" "$R_NOK" "$S_WRG" "$R_WRG" "$S_NOASC" "$R_NOASC"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

# ---------------------------------------------------------------------------
# 0. Upstream sanity — the mock upstream really serves the signed tree + .asc,
#    and the unsigned tree really has NO .asc (so the negatives are real).
# ---------------------------------------------------------------------------
begin_test "Upstream serves signed repomd + repomd.xml.asc; unsigned tree has NO .asc"
ASC_SIGNED="$(docker exec "$CLIENT_DNF" sh -c "curl -s -o /dev/null -w '%{http_code}' ${UP_SIGNED}/repodata/repomd.xml.asc" 2>/dev/null)"
ASC_UNSIGNED="$(docker exec "$CLIENT_DNF" sh -c "curl -s -o /dev/null -w '%{http_code}' ${UP_UNSIGNED}/repodata/repomd.xml.asc" 2>/dev/null)"
if [ "$ASC_SIGNED" = "200" ] && [ "$ASC_UNSIGNED" = "404" ]; then
  pass
else
  fail "expected signed .asc=200 unsigned .asc=404 (got signed=${ASC_SIGNED} unsigned=${ASC_UNSIGNED})" \
       "the upstream fixture is not laid out as expected; the fail-closed negatives would be meaningless"
fi

# ---------------------------------------------------------------------------
# 1. POSITIVE — correct trusted key + signed tree -> packages ingested.
# ---------------------------------------------------------------------------
begin_test "Create rpm remote with the CORRECT trusted_gpg_key (validated create path accepts it)"
create_remote "$R_POS" "$UP_SIGNED" "${KEYS_DIR}/correct.pub.asc"
if [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; then
  if body | jq -e '.has_trusted_gpg_key == true' >/dev/null 2>&1; then
    pass
  else
    fail "remote created but has_trusted_gpg_key != true (key not stored?)" "$(body | head -c 400)"
  fi
else
  fail "creating rpm remote with trusted_gpg_key expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
  end_suite
fi

begin_test "POSITIVE: correct key + signed repomd.xml.asc -> sync ingests packages (count > 0)"
SID_POS="$(wire_staging "$S_POS" "$R_POS")" || { fail "could not wire staging repo $S_POS"; end_suite; }
trigger_sync "$S_POS"
TRG_OK=0; [ "$REQ_STATUS" = "200" ] && body | jq -e '.triggered == true' >/dev/null 2>&1 && TRG_OK=1
CNT_POS="$(ingested_count "$SID_POS")"
if [ "$TRG_OK" != "1" ]; then
  fail "manual sync trigger did not return 200/triggered=true (status=${REQ_STATUS})" "$(body | head -c 400)"
elif [ "${CNT_POS:-0}" -gt 0 ] 2>/dev/null; then
  pass
else
  fail "correct-key sync ingested ${CNT_POS:-0} packages, expected > 0" \
       "verify_detached should have accepted the correct key and the primary checksum chain should pin primary.xml.gz; if this is 0 the positive pipeline is broken (fixture or GPG-flavor mismatch)"
fi

# ---------------------------------------------------------------------------
# 2. CONTROL — no trusted key + signed tree -> UNVERIFIED ingest (documented).
#    Proves the pipeline ingests even without a key, so the wrong-key/no-asc 0s
#    below are attributable to VERIFICATION, not a dead sync path.
# ---------------------------------------------------------------------------
begin_test "CONTROL: NO trusted key + signed tree -> UNVERIFIED ingest proceeds (count > 0), NOT a security pass"
create_remote "$R_NOK" "$UP_SIGNED"
if ! { [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; }; then
  fail "creating keyless rpm remote expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
else
  SID_NOK="$(wire_staging "$S_NOK" "$R_NOK")" || SID_NOK=""
  trigger_sync "$S_NOK"
  CNT_NOK="$(ingested_count "${SID_NOK:-none}")"
  if [ -n "$SID_NOK" ] && [ "${CNT_NOK:-0}" -gt 0 ] 2>/dev/null; then
    pass
  else
    fail "keyless (unverified) sync ingested ${CNT_NOK:-0}, expected > 0 (the no-key path is documented to ingest UNVERIFIED)" \
         "if this is 0 the pipeline itself is broken and the fail-closed negatives below would pass vacuously"
  fi
fi

# ---------------------------------------------------------------------------
# 3. NEGATIVE (the #2568 discriminator) — WRONG key + signed tree -> 0 packages.
# ---------------------------------------------------------------------------
begin_test "NEGATIVE (#2568): WRONG trusted key vs signed repomd -> verify_detached fails -> 0 packages ingested"
create_remote "$R_WRG" "$UP_SIGNED" "${KEYS_DIR}/wrong.pub.asc"
if ! { [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; }; then
  fail "creating wrong-key rpm remote expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
else
  SID_WRG="$(wire_staging "$S_WRG" "$R_WRG")" || SID_WRG=""
  trigger_sync "$S_WRG"
  CNT_WRG="$(ingested_count "${SID_WRG:-none}")"
  if [ -n "$SID_WRG" ] && [ "${CNT_WRG:-x}" = "0" ]; then
    pass
  else
    fail "#2568 RED: wrong-key sync ingested ${CNT_WRG} packages, expected 0 (fail-closed)" \
         "verify_detached MUST reject a repomd signed by a different key; a non-zero count means the wrong-key upstream was trusted — the exact bug the dnf gpgcheck=0 leg bypasses"
  fi
fi

# ---------------------------------------------------------------------------
# 4. NEGATIVE — correct key but upstream repomd.xml.asc missing -> 0 packages.
# ---------------------------------------------------------------------------
begin_test "NEGATIVE: correct key but repomd.xml.asc 404 (unsigned tree) -> fail-closed -> 0 packages ingested"
create_remote "$R_NOASC" "$UP_UNSIGNED" "${KEYS_DIR}/correct.pub.asc"
if ! { [ "$REQ_STATUS" -ge 200 ] 2>/dev/null && [ "$REQ_STATUS" -lt 300 ] 2>/dev/null; }; then
  fail "creating correct-key/unsigned-upstream rpm remote expected 2xx, got ${REQ_STATUS}" "$(body | head -c 400)"
else
  SID_NOASC="$(wire_staging "$S_NOASC" "$R_NOASC")" || SID_NOASC=""
  trigger_sync "$S_NOASC"
  CNT_NOASC="$(ingested_count "${SID_NOASC:-none}")"
  if [ -n "$SID_NOASC" ] && [ "${CNT_NOASC:-x}" = "0" ]; then
    pass
  else
    fail "RED: correct-key + missing .asc ingested ${CNT_NOASC} packages, expected 0 (fail-closed)" \
         "with a trusted key set and repomd.xml.asc unavailable the sync must refuse the unverified upstream"
  fi
fi

# ---------------------------------------------------------------------------
# 5. CLIENT fail-closed (the audit's ask) — dnf repo_gpgcheck=1 must ENFORCE
#    the signature: makecache succeeds with the correct key, FAILS with the
#    wrong key. This undoes the native-client `gpgcheck=0` bypass.
# ---------------------------------------------------------------------------
# Each attempt runs in a FULLY ISOLATED dnf state (own reposdir/persistdir/
# cachedir + a unique repoid) so a key imported by an earlier leg cannot linger
# in the repo keyring and vouch for a later leg. `skip_if_unavailable=0` makes a
# failed repo FATAL (otherwise `dnf makecache` ignores a bad repo and still
# exits 0, so rc would not discriminate); `-y` auto-confirms the key import.
# Prints the dnf exit code (0 = metadata verified + cached, non-0 = verify failed).
dnf_makecache_with_key() { # dnf_makecache_with_key <tag> <local_pubkey_file> -> prints rc
  local tag="$1" keyfile="$2"
  docker exec -i "$CLIENT_DNF" sh -c "cat > /tmp/DTF-KEY-${tag}" < "$keyfile"
  docker exec "$CLIENT_DNF" sh -c '
    tag='"$tag"'; up='"$UP_SIGNED"'
    T=/tmp/dnf-leg-$tag; rm -rf "$T"; mkdir -p "$T/repos" "$T/persist" "$T/cache"
    cat > "$T/repos/dtf.repo" <<EOF
[dtf-$tag]
name=dtf-$tag
baseurl=$up
enabled=1
gpgcheck=0
repo_gpgcheck=1
skip_if_unavailable=0
gpgkey=file:///tmp/DTF-KEY-$tag
EOF
    dnf -y -q --setopt=reposdir="$T/repos" --setopt=persistdir="$T/persist" \
        --setopt=cachedir="$T/cache" --disablerepo="*" --enablerepo="dtf-$tag" \
        makecache --refresh >"/tmp/dnf-$tag.out" 2>&1
  ' && echo 0 || echo 1
}

begin_test "CLIENT: dnf repo_gpgcheck=1 makecache SUCCEEDS with the correct gpgkey"
RC_OK="$(dnf_makecache_with_key ok "${KEYS_DIR}/correct.pub.asc")"
if [ "$RC_OK" = "0" ]; then
  pass
else
  fail "dnf makecache with the correct key failed (rc=${RC_OK})" \
       "$(docker exec "$CLIENT_DNF" sh -c 'tail -c 800 /tmp/dnf-ok.out' 2>/dev/null)"
fi

begin_test "CLIENT: dnf repo_gpgcheck=1 makecache FAILS with the WRONG gpgkey (fail-closed, undoes gpgcheck=0)"
RC_WRONG="$(dnf_makecache_with_key wrong "${KEYS_DIR}/wrong.pub.asc")"
if [ "$RC_WRONG" != "0" ]; then
  pass
else
  fail "RED: dnf makecache SUCCEEDED with the WRONG key — repo_gpgcheck did not enforce the signature" \
       "$(docker exec "$CLIENT_DNF" sh -c 'tail -c 800 /tmp/dnf-wrong.out' 2>/dev/null)"
fi

# ---- discrimination summary (printed, not a gate) --------------------------
echo ""
echo "=== DISCRIMINATION SUMMARY (why this tier catches #2568) ==="
echo "  One signed upstream tree, one live backend, curation_packages ingest count:"
echo "    correct key + signed tree  -> ${CNT_POS:-?} ingested  (POSITIVE)"
echo "    NO key      + signed tree  -> ${CNT_NOK:-?} ingested  (CONTROL: unverified ingest works)"
echo "    WRONG key   + signed tree  -> ${CNT_WRG:-?} ingested  (must be 0 — the #2568 discriminator)"
echo "    correct key + no .asc      -> ${CNT_NOASC:-?} ingested  (must be 0 — fail-closed)"
echo "  A backend that trusted the wrong-key upstream would ingest > 0 on the"
echo "  wrong-key leg; verify_detached fail-closed keeps it at 0."

end_suite
