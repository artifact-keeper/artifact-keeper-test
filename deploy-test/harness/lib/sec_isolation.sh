#!/usr/bin/env bash
# =============================================================================
# harness/lib/sec_isolation.sh — the SHARED cross-tenant isolation oracle driver
# =============================================================================
# The sec_* sibling of native_client.sh's fc_* contract. Sourced by
# tiers/isolation-formats/oracle.sh *after* the corpus tests/lib/common.sh. It
# owns the COMMON cross-tenant A/B/C/F scaffolding, GENERALIZED from the
# Maven-hardcoded tiers/isolation/prove.sh; a per-format plugin owns ONLY the
# format-specific verbs (the collision coordinate + the object bytes; the
# publish/read default to a plain authenticated curl PUT/GET).
#
# WHY THIS EXISTS (game-plan §2a): the #2504/#2574/#2584 cross-tenant read+write
# fix is Maven-ONLY (the read attribution guard lives only in maven.rs /
# maven_proxy.rs). Every other flat-key format (npm/cargo/go/... — storage key
# is a bare coordinate with NO repo_id) is structurally exposed to the SAME
# class and was never per-format verified. This driver runs the exact A-F
# cross-tenant gate prove.sh runs, but parameterized on the format, so adding a
# format is a ~6-line plugin, not a new framework.
#
# THE SEC CONTRACT (what a plugin is — see plugins/maven.sh for the reference):
#   A plugin is ONE file `tiers/isolation-formats/plugins/<fmt>.sh` with:
#     * grep-parsed header comments (discovery needs zero shared-file edits):
#         # SEC_FORMAT:  <name>        display / JUnit suite name
#         # SEC_MOUNT:   <prefix>      routes.rs nest prefix (maven, npm, cargo,
#         #                            go, ...; NOT always the format name)
#         # SEC_REPO_FORMAT: <fmt>     value passed to create_repo (default SEC_FORMAT)
#         # SEC_PROFILE: client.<fmt>  client overlay basename ("" = pure-curl plant)
#         # SEC_SERVICE: client-<fmt>  compose service ("" = none)
#         # SEC_ENABLED: 1             0 = registered but not run
#         # SEC_FLATKEY: 1             1 = storage key is repo-LESS/flat (predicted
#         #                            RED; the row-less F leg APPLIES); 0 = key is
#         #                            repo-scoped (predicted GREEN; F is N/A)
#     * the hooks the driver calls (only the first two are mandatory):
#         sec_coord           echo the REPO-RELATIVE advertised path of the object.
#                             Reads $SEC_TAG so the driver can request DISTINCT
#                             coords per scenario (A/B share one, C+F get their own).
#         sec_secret_bytes    echo the object body, embedding $SEC_MARK verbatim so
#                             a cross-tenant leak is byte-detectable by grep. Emit a
#                             format-VALID object (a jar needs the PK\x03\x04 magic,
#                             a tarball needs gzip magic, ...) so the native write
#                             validator STORES it rather than 400-ing.
#         sec_plant           (OPTIONAL) override the default authenticated PUT for
#                             formats that must publish through a native client.
#                             DEFAULT = curl PUT sec_secret_bytes to
#                             /<mount>/<repo>/<coord>. Signature: <repo> <user> <pass>;
#                             echo the HTTP code, return 0 iff 2xx.
#         sec_read_body       (OPTIONAL) echo the body served for sec_coord under a
#                             repo. DEFAULT = curl GET. Signature: <repo> <user> <pass>.
#         sec_read_code       (OPTIONAL) echo the HTTP status for that GET. DEFAULT curl.
#         sec_owner_strip     (OPTIONAL) delete the format's per-key ATTRIBUTION rows
#                             for the row-less F fixture (Maven strips
#                             maven_flat_object_owner). DEFAULT = no-op (the driver
#                             already strips the `artifacts` rows generically).
#
# Hooks RETURN 0/non-zero and echo diagnostics; they do NOT call pass/fail
# (the driver wraps each scenario in begin_test/pass/fail). Each plugin is
# SOURCED IN A SUBSHELL by the oracle so the fixed hook names never collide and
# a crashing plugin cannot poison the loop — identical discipline to
# native_client.sh's nc_run_plugin.
#
# Everything else — auth, begin_test/pass/fail, JUnit, RELEASE_GATE=1 strictness
# — is inherited from the corpus common.sh.
# =============================================================================

: "${BASE_URL:?sec_isolation.sh: BASE_URL not set}"
: "${DTF_SLOT:?sec_isolation.sh: DTF_SLOT not set}"
: "${DB_CONTAINER:?sec_isolation.sh: DB_CONTAINER not set}"

# ---------------------------------------------------------------------------
# Header parsing + selection (SEC_ONLY narrows the loop, like FC_ONLY)
# ---------------------------------------------------------------------------

# sec_header <plugin-file> <KEY> -> echoes the value of `# KEY: value`
sec_header() {
  grep -m1 "^# ${2}:" "$1" 2>/dev/null | awk '{print $3}'
}

# sec_enabled_and_selected <plugin-file>
#   returns 0 if the plugin is SEC_ENABLED and (when SEC_ONLY is set) selected.
sec_enabled_and_selected() {
  local plugin="$1" en fmt
  en="$(sec_header "$plugin" SEC_ENABLED)"; en="${en:-1}"
  [ "$en" = "1" ] || return 1
  fmt="$(sec_header "$plugin" SEC_FORMAT)"
  if [ -n "${SEC_ONLY:-}" ]; then
    case " ${SEC_ONLY//,/ } " in
      *" ${fmt} "*) : ;;
      *) return 1 ;;
    esac
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Shared HTTP + DB helpers. All format-native auth is Basic (the format-native
# routes authenticate Basic; a public repo also lets Basic through). The
# per-principal user:pass is threaded explicitly so the attacker (alice) is a
# REAL distinct principal, not admin.
# ---------------------------------------------------------------------------

_sec_b64auth() { printf 'Authorization: Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }

# _sec_put <user> <pass> <url> <datafile>  -> echoes http_code, returns 0 iff 2xx
_sec_put() {
  local u="$1" p="$2" url="$3" f="$4" code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 \
    -X PUT -H "$(_sec_b64auth "$u" "$p")" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "@${f}" "$url" 2>/dev/null)"
  echo "$code"
  [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 300 ] 2>/dev/null
}

# _sec_body <user> <pass> <url>  -> echoes the response body
_sec_body() {
  curl -s --max-time 120 -H "$(_sec_b64auth "$1" "$2")" "$3" 2>/dev/null
}

# _sec_code <user> <pass> <url>  -> echoes the HTTP status
_sec_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 120 \
    -H "$(_sec_b64auth "$1" "$2")" "$3" 2>/dev/null
}

# _sec_psql <sql>  -> tuple-only psql on the tier DB container (prove.sh style)
_sec_psql() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null
}

# _sec_repo_uuid <key>  -> echoes the repositories.id for a repo key
_sec_repo_uuid() { _sec_psql "SELECT id FROM repositories WHERE key='$1';" | tr -d '[:space:]'; }

# _sec_create_private_repo <key> <format> -> creates a PRIVATE local repo.
#   The corpus create_repo hardcodes is_public:true, which would make the victim
#   repo world-readable and defeat the cross-tenant authz control. This mirrors
#   prove.sh's direct POST (is_public:false) so a no-grant principal is genuinely
#   denied. Retries the transient class (401/429/503/000), like create_repo.
_sec_create_private_repo() {
  local key="$1" fmt="$2"
  local payload="{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"${fmt}\",\"repo_type\":\"local\",\"is_public\":false}"
  local _attempt _status="000" _bf _body
  _bf="$(mktemp)"
  for _attempt in 1 2 3 4; do
    _status="$(curl -s -o "$_bf" -w '%{http_code}' --max-time 30 -X POST \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$payload" "${BASE_URL}/api/v1/repositories" 2>/dev/null)" || _status="000"
    if [ "$_status" -ge 200 ] 2>/dev/null && [ "$_status" -lt 300 ] 2>/dev/null; then rm -f "$_bf"; return 0; fi
    case "$_status" in 401|429|503|000) sleep 2 ;; *) break ;; esac
  done
  _body="$(head -c 300 "$_bf" 2>/dev/null || true)"; rm -f "$_bf"
  echo "  _sec_create_private_repo ${key} (${fmt}) failed: HTTP ${_status} ${_body}" >&2
  return 1
}

# _sec_grant_developer <username> <repo_key>  -> developer(write) grant on ONE repo
_sec_grant_developer() {
  _sec_psql "
    INSERT INTO role_assignments (user_id, role_id, repository_id)
    SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
    WHERE u.username='$1' AND r.name='developer' AND repo.key='$2'
    ON CONFLICT DO NOTHING;" >/dev/null
}

# ---------------------------------------------------------------------------
# DEFAULT format verbs (plugins override only when a native client is required)
# ---------------------------------------------------------------------------

# sec_plant <repo_key> <user> <pass>  -> echoes http_code, returns 0 iff 2xx
# Emits sec_secret_bytes (for the current $SEC_TAG/$SEC_MARK) to sec_coord.
_sec_default_plant() {
  local repo="$1" u="$2" p="$3" coord f
  coord="$(sec_coord)"
  f="${WORK_DIR}/sec-plant.${SEC_FORMAT}.$$"
  sec_secret_bytes > "$f"
  _sec_put "$u" "$p" "${BASE_URL}/${SEC_MOUNT}/${repo}/${coord}" "$f"
}

_sec_default_read_body() { _sec_body "$2" "$3" "${BASE_URL}/${SEC_MOUNT}/${1}/$(sec_coord)"; }
_sec_default_read_code() { _sec_code "$2" "$3" "${BASE_URL}/${SEC_MOUNT}/${1}/$(sec_coord)"; }
_sec_default_owner_strip() { :; }   # only flat-key formats with an attribution table override

# ---------------------------------------------------------------------------
# The white-box structural-exposure classifier (game-plan §0). Reads the actual
# storage_key the backend derived for the victim's object and decides whether
# the key embeds the repo id/key (isolated by construction) or is a bare
# coordinate (structurally exposed — the cross-tenant class is reachable).
# Prints its verdict; the caller records it in the finding. Returns 0 always
# (classification never fails), but sets SEC_WB_EXPOSED=1|0.
# ---------------------------------------------------------------------------
sec_whitebox_probe() {
  local repo_key="$1" repo_uuid="$2"
  local keys
  keys="$(_sec_psql "SELECT storage_key FROM artifacts WHERE repository_id='${repo_uuid}';")"
  echo "  white-box: storage_key(s) for repo ${repo_key} (${repo_uuid}):"
  echo "$keys" | sed 's/^/      /'
  # exposed IFF NO stored key embeds the repo id OR the repo key.
  if [ -z "$keys" ]; then
    echo "  white-box: no artifacts rows for ${repo_key} (cannot classify from rows)"
    SEC_WB_EXPOSED="unknown"
    return 0
  fi
  if echo "$keys" | grep -qF "$repo_uuid" || echo "$keys" | grep -qF "$repo_key"; then
    echo "  white-box: key EMBEDS the repo id/key -> STRUCTURALLY ISOLATED (repo-scoped)"
    SEC_WB_EXPOSED=0
  else
    echo "  white-box: key is a BARE coordinate (no repo id/key) -> STRUCTURALLY EXPOSED (flat)"
    SEC_WB_EXPOSED=1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# The driver: run one format's isolation suite. MUST be invoked in a subshell
# by the oracle so hook names + per-format state are isolated per plugin.
# ---------------------------------------------------------------------------
sec_run_plugin() {
  local plugin="$1"

  # The corpus common.sh runs `set -euo pipefail`. This driver DELIBERATELY
  # probes for denials (a 403/404 write-refusal is the GREEN outcome), so a
  # non-2xx return must NOT abort — every outcome is handled explicitly below
  # and the verdict is end_suite's fail-count, not errexit. Keep -u/pipefail
  # (real bugs still surface); drop -e for this security oracle.
  set +e

  # 1. parse the header
  SEC_FORMAT="$(sec_header "$plugin" SEC_FORMAT)"
  SEC_MOUNT="$(sec_header "$plugin" SEC_MOUNT)"
  SEC_REPO_FORMAT="$(sec_header "$plugin" SEC_REPO_FORMAT)"
  SEC_PROFILE="$(sec_header "$plugin" SEC_PROFILE)"
  SEC_SERVICE="$(sec_header "$plugin" SEC_SERVICE)"
  SEC_FLATKEY="$(sec_header "$plugin" SEC_FLATKEY)"; SEC_FLATKEY="${SEC_FLATKEY:-1}"
  : "${SEC_REPO_FORMAT:=$SEC_FORMAT}"
  if [ -z "$SEC_FORMAT" ] || [ -z "$SEC_MOUNT" ]; then
    echo "!! plugin ${plugin} missing SEC_FORMAT/SEC_MOUNT header" >&2
    return 2
  fi

  # 2. one JUnit suite per format
  begin_suite "isol-${SEC_FORMAT}"

  # 3. admin auth (create_repo uses Bearer) + a per-plugin workdir
  auth_admin
  setup_workdir

  # 4. per-format identifiers. VREPO = victim (holds the planted secret, owned
  #    by admin); AREPO = attacker (alice's repo, alice has a developer grant
  #    ONLY here, NO grant on VREPO); FREPO = a clean victim repo for the F
  #    row-less leg. This is prove.sh's MVB/MVA split, format-parameterized.
  # NOTE: VREPO/AREPO/FREPO are plain (non-local) so the EXIT-trap teardown sees
  # them (same discipline as native_client.sh's FC_REPO). The subshell isolates
  # them per plugin, so there is no cross-format leakage.
  local suf; suf="${RANDOM}${RANDOM}"
  SEC_SUF="$suf"
  VREPO="dtf-isol-${SEC_FORMAT}-v-${suf}"
  AREPO="dtf-isol-${SEC_FORMAT}-a-${suf}"
  FREPO="dtf-isol-${SEC_FORMAT}-f-${suf}"
  local ALICE="alice-isol-${SEC_FORMAT}-${suf}"
  local APASS="AliceIsol!2026-${suf}"

  # 5. hook defaults (overridable by the plugin), then load the plugin's verbs.
  sec_plant()      { _sec_default_plant "$@"; }
  sec_read_body()  { _sec_default_read_body "$@"; }
  sec_read_code()  { _sec_default_read_code "$@"; }
  sec_owner_strip(){ _sec_default_owner_strip "$@"; }
  # shellcheck disable=SC1090
  source "$plugin"

  add_exit_handler "sec_isol_teardown"
  sec_isol_teardown() {
    api_delete "/api/v1/repositories/${VREPO}" >/dev/null 2>&1 || true
    api_delete "/api/v1/repositories/${AREPO}" >/dev/null 2>&1 || true
    api_delete "/api/v1/repositories/${FREPO}" >/dev/null 2>&1 || true
  }

  echo ">> isol-${SEC_FORMAT}: victim=${VREPO} attacker=${AREPO} mount=/${SEC_MOUNT} flatkey=${SEC_FLATKEY}"

  # ==== setup: repos + attacker principal + fail-closed s3 precondition ====
  begin_test "setup: victim/attacker ${SEC_REPO_FORMAT} repos + alice principal + shared-store precondition"
  local setup_ok=1
  # PRIVATE repos: a public victim would let any principal read it, masking the
  # cross-tenant authz control. prove.sh creates private repos; so do we.
  _sec_create_private_repo "$VREPO" "$SEC_REPO_FORMAT" || { setup_ok=0; echo "victim repo create failed"; }
  _sec_create_private_repo "$AREPO" "$SEC_REPO_FORMAT" || { setup_ok=0; echo "attacker repo create failed"; }
  _sec_create_private_repo "$FREPO" "$SEC_REPO_FORMAT" || { setup_ok=0; echo "F-victim repo create failed"; }
  # alice: a real distinct principal, developer(write) on AREPO ONLY.
  create_test_user_with_retry "$ALICE" "$APASS" "${ALICE}@dtf.test" >/dev/null || { setup_ok=0; echo "alice create failed"; }
  _sec_grant_developer "$ALICE" "$AREPO"
  local ATOK; ATOK="$(login_as "$ALICE" "$APASS")"
  [ -n "$ATOK" ] || { setup_ok=0; echo "alice login failed"; }
  # Fail-closed: this gate is meaningless on a filesystem backend (each repo
  # physically owns its key space). Assert a shared object store (prove.sh:60).
  local SB; SB="$(_sec_psql "SELECT DISTINCT storage_backend FROM repositories WHERE key IN ('$VREPO','$AREPO');" | tr -d '[:space:]')"
  echo "  storage_backend of repos: '${SB}'"
  if [ "$SB" = "filesystem" ] || [ -z "$SB" ]; then
    setup_ok=0
    echo "GATE-ABORT: repos on storage_backend='${SB}'; the cross-tenant class needs a shared object store (s3/gcs/azure)"
  fi
  if [ "$setup_ok" = "1" ]; then pass; else fail "isolation setup failed" "victim=${VREPO} attacker=${AREPO} storage_backend=${SB}"; end_suite; fi

  # ==== white-box probe: structural exposure classifier ====
  begin_test "white-box: storage_key attribution probe (structural exposed-vs-isolated + SEC_FLATKEY sanity)"
  SEC_TAG="wb"; SEC_MARK="DTF-ISOL-WB-${suf}"
  local wb_plant_code; wb_plant_code="$(sec_plant "$VREPO" "$ADMIN_USER" "$ADMIN_PASS")"
  echo "  admin plant (probe) into ${VREPO}/$(sec_coord) => HTTP ${wb_plant_code}"
  local vuuid; vuuid="$(_sec_repo_uuid "$VREPO")"
  SEC_WB_EXPOSED="unknown"
  sec_whitebox_probe "$VREPO" "$vuuid"
  # sanity: the plugin's SEC_FLATKEY declaration must agree with the probe.
  # A disagreement means the plugin mis-declared or the backend key shape
  # changed — either way an operator must look, so fail it.
  if [ "$SEC_WB_EXPOSED" = "unknown" ]; then
    fail "white-box probe could not classify (no storage_key row for ${VREPO}); plant HTTP ${wb_plant_code}" \
      "The plant must succeed for the black-box legs to be meaningful; a 400/401 here means sec_secret_bytes is not a valid ${SEC_FORMAT} object."
  elif { [ "$SEC_WB_EXPOSED" = "1" ] && [ "$SEC_FLATKEY" = "1" ]; } || \
       { [ "$SEC_WB_EXPOSED" = "0" ] && [ "$SEC_FLATKEY" = "0" ]; }; then
    pass
  else
    fail "white-box classification disagrees with SEC_FLATKEY=${SEC_FLATKEY} (probe exposed=${SEC_WB_EXPOSED})" \
      "The plugin declared SEC_FLATKEY=${SEC_FLATKEY} but the derived storage_key says exposed=${SEC_WB_EXPOSED}. Re-check the storage-key derivation in the handler."
  fi

  # ==== A. CROSS-REPO READ (the #2504 read leak) ====
  # admin plants a secret into VREPO at coord(ab); alice (grant on AREPO only)
  # requests the SAME coord under AREPO. On a flat-key backend both map to the
  # identical shared-cloud key; a correct backend attributes it to VREPO and
  # denies alice. alice must NOT receive the secret bytes.
  begin_test "A: cross-repo READ denied (alice cannot read victim's secret via her own repo)"
  SEC_TAG="ab"; SEC_MARK="DTF-ISOL-SECRET-${suf}"
  local a_plant; a_plant="$(sec_plant "$VREPO" "$ADMIN_USER" "$ADMIN_PASS")"
  echo "  [setup] admin plant secret into ${VREPO}/$(sec_coord) => HTTP ${a_plant}"
  if ! { [ "$a_plant" -ge 200 ] 2>/dev/null && [ "$a_plant" -lt 300 ] 2>/dev/null; }; then
    fail "A-setup: victim plant did not store (HTTP ${a_plant}); cannot test the read leak" \
      "sec_secret_bytes must be a valid ${SEC_FORMAT} object the native write validator accepts."
  else
    local a_code a_body
    a_code="$(sec_read_code "$AREPO" "$ALICE" "$APASS")"
    a_body="$(sec_read_body "$AREPO" "$ALICE" "$APASS")"
    echo "  alice GET ${AREPO}/$(sec_coord) => HTTP ${a_code}"
    if echo "$a_body" | grep -qF "$SEC_MARK"; then
      fail "A: CROSS-TENANT READ LEAK — alice read the victim's secret via her own repo (#2504 class)" \
        "attacker=${AREPO} victim=${VREPO} coord=$(sec_coord) HTTP=${a_code} leaked-marker=${SEC_MARK}
storage-key exposed=${SEC_WB_EXPOSED}. This is a new instance of the cloud row-less cross-tenant read class on ${SEC_FORMAT}."
    elif [ "$a_code" = "403" ] || [ "$a_code" = "404" ]; then
      # control: alice has no grant on VREPO, direct access must also be denied.
      local ctl; ctl="$(sec_read_code "$VREPO" "$ALICE" "$APASS")"
      echo "  (control) alice GET ${VREPO}/$(sec_coord) directly => HTTP ${ctl} (expect 403/404, no grant)"
      if [ "$ctl" = "403" ] || [ "$ctl" = "404" ]; then
        pass
      else
        fail "A-control: alice reached the victim repo directly (HTTP ${ctl})" "alice has no grant on ${VREPO}"
      fi
    else
      fail "A: unexpected read outcome HTTP ${a_code} (no secret, but not a clean 403/404)" "body head: $(echo "$a_body" | head -c 200)"
    fi
  fi

  # ==== B. CROSS-REPO WRITE (write-poison / guard_cross_repo_write) ====
  # alice PUTs colliding-coord bytes into HER OWN repo AREPO. On a flat-key
  # backend this targets the victim's shared key. The victim's bytes must
  # survive: either the guard REFUSES the colliding write, or (defense in
  # depth) it is accepted but scoped so the victim read is unchanged. A poisoned
  # victim read is the fail.
  begin_test "B: cross-repo WRITE cannot poison the victim (guard_cross_repo_write)"
  SEC_TAG="ab"; SEC_MARK="DTF-ISOL-EVIL-${suf}"
  local b_wcode; b_wcode="$(sec_plant "$AREPO" "$ALICE" "$APASS")"
  echo "  alice PUT colliding ${AREPO}/$(sec_coord) => HTTP ${b_wcode}"
  SEC_MARK="DTF-ISOL-SECRET-${suf}"   # what the victim read MUST still contain
  local b_after; b_after="$(sec_read_body "$VREPO" "$ADMIN_USER" "$ADMIN_PASS")"
  if ! echo "$b_after" | grep -qF "$SEC_MARK"; then
    fail "B: victim POISONED by cross-tenant write (victim read no longer has the original secret)" \
      "attacker=${AREPO} victim=${VREPO} coord=$(sec_coord) write-HTTP=${b_wcode}"
  elif [ "$b_wcode" = "200" ] || [ "$b_wcode" = "201" ]; then
    fail "B: colliding cross-repo WRITE ACCEPTED (HTTP ${b_wcode}) — victim bytes intact this run but the guard did not refuse at the door (latent poisoning)" \
      "guard_cross_repo_write should refuse a colliding write into a foreign flat key."
  else
    echo "  B OK: colliding write REFUSED (HTTP ${b_wcode}); victim bytes intact"
    pass
  fi

  # ==== C. NO-REGRESSION (legit same-repo publish+read) ====
  begin_test "C: no-regression — alice's own publish+read on her own repo still works"
  SEC_TAG="c"; SEC_MARK="DTF-ISOL-OWN-${suf}"
  local c_wcode; c_wcode="$(sec_plant "$AREPO" "$ALICE" "$APASS")"
  local c_body; c_body="$(sec_read_body "$AREPO" "$ALICE" "$APASS")"
  echo "  alice PUT ${AREPO}/$(sec_coord) => HTTP ${c_wcode}; read back for marker ${SEC_MARK}"
  if { [ "$c_wcode" = "200" ] || [ "$c_wcode" = "201" ]; } && echo "$c_body" | grep -qF "$SEC_MARK"; then
    pass
  else
    fail "C: legit same-repo publish/read REGRESSED (write HTTP ${c_wcode}, marker present=$(echo "$c_body" | grep -qF "$SEC_MARK" && echo yes || echo no))" \
      "The cross-tenant guard must not over-reach onto a repo's own owner."
  fi

  # ==== F. ROW-LESS legacy objects (#2574/#2584 shape) — flat-key formats only ====
  # The #2574 class: a physical object in the shared bucket with NO artifacts
  # row and NO attribution row (pristine legacy state). We reproduce it: admin
  # plants into FREPO, confirms the owner can read it, then strips BOTH the
  # artifacts rows (generic) AND the format's attribution rows (sec_owner_strip).
  # A fixed backend attributes such a key to NO repo and 404s it for everyone;
  # a pre-fix backend serves it to any tenant.
  if [ "$SEC_FLATKEY" = "1" ]; then
    begin_test "F: row-less legacy object is not served cross-repo (#2574/#2584 class)"
    SEC_TAG="f"; SEC_MARK="DTF-ISOL-ROWLESS-${suf}"
    local f_plant; f_plant="$(sec_plant "$FREPO" "$ADMIN_USER" "$ADMIN_PASS")"
    local f_owner_body; f_owner_body="$(sec_read_body "$FREPO" "$ADMIN_USER" "$ADMIN_PASS")"
    echo "  [setup] admin plant row-less fixture ${FREPO}/$(sec_coord) => HTTP ${f_plant}"
    if ! echo "$f_owner_body" | grep -qF "$SEC_MARK"; then
      fail "F-setup: fixture not stored/attributed-readable pre-strip (HTTP ${f_plant}); the row-less class is not exercised" \
        "A 404 here would make the post-strip read a trivial false-pass."
    else
      local fuuid; fuuid="$(_sec_repo_uuid "$FREPO")"
      _sec_psql "DELETE FROM artifacts WHERE repository_id='${fuuid}';" >/dev/null
      sec_owner_strip "$FREPO" "$(sec_coord)"   # format attribution rows (Maven: maven_flat_object_owner)
      local left; left="$(_sec_psql "SELECT count(*) FROM artifacts WHERE repository_id='${fuuid}';" | tr -d '[:space:]')"
      echo "  [setup] after strip: artifacts rows for ${FREPO}=${left} (must be 0 for a valid row-less fixture)"
      if [ "${left:-1}" != "0" ]; then
        fail "F-setup: could not make the object row-less (artifacts rows remain=${left})" "fixture invalid"
      else
        local f_code f_body
        f_code="$(sec_read_code "$AREPO" "$ALICE" "$APASS")"
        f_body="$(sec_read_body "$AREPO" "$ALICE" "$APASS")"
        echo "  alice GET row-less ${AREPO}/$(sec_coord) => HTTP ${f_code}"
        if echo "$f_body" | grep -qF "$SEC_MARK"; then
          fail "F: row-less legacy object LEAKED cross-repo (#2574/#2584 class); HTTP ${f_code}" \
            "attacker=${AREPO} coord=$(sec_coord) leaked-marker=${SEC_MARK}"
        elif [ "$f_code" = "403" ] || [ "$f_code" = "404" ]; then
          echo "  F OK: row-less object DENIED (HTTP ${f_code})"
          pass
        else
          # 200 without the secret (e.g. a dynamically generated empty index) is
          # acceptable — no foreign bytes served.
          echo "  F OK: HTTP ${f_code} but no foreign secret in the body"
          pass
        fi
      fi
    fi
  else
    begin_test "F: row-less leg N/A (SEC_FLATKEY=0, repo-scoped key — isolated by construction)"
    skip "repo-scoped storage key: the row-less flat-key class cannot manifest"
  fi

  # verdict: end_suite exits 1 iff any test failed (the per-format gate signal).
  end_suite
}
