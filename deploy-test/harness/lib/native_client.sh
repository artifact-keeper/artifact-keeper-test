#!/usr/bin/env bash
# =============================================================================
# harness/lib/native_client.sh — the SHARED format-conformance driver
# =============================================================================
# One bash library, sourced by tiers/format-conformance/oracle.sh *after*
# the corpus tests/lib/common.sh. It owns the COMMON publish->consume lifecycle
# for every registry format; a per-format plugin owns only the format-specific
# verbs (the "unique" column).
#
# WHY THIS EXISTS (game-plan §1): today's format tests upload via the native
# route and then check that metadata merely LISTS the artifact — they never
# make a REAL client FOLLOW the advertised location (repodata.json -> fname,
# config.json -> dl template, index.yaml -> chart url, ...). That is the #2580
# bug class (advertised location != servable route) upload-only curl tests
# structurally cannot catch. This driver runs the real client and asserts on a
# client-side artifact (installed marker / fetched-bytes sha).
#
# THE CONTRACT (what a plugin is — see the conda reference for the template):
#   A plugin is ONE file `tiers/format-conformance/plugins/<fmt>.sh` with:
#     * grep-parsed header comments (so discovery needs zero shared-file edits):
#         # FC_FORMAT: <name>        display / JUnit suite name
#         # FC_MOUNT:  <prefix>      routes.rs nest prefix (NOT always the format
#         #                          name: rubygems->gems, gitlfs->lfs, sbt->ivy)
#         # FC_REPO_FORMAT: <fmt>    value passed to create_repo (defaults FC_FORMAT)
#         # FC_PROFILE: client.<fmt> profiles/client.<fmt>.yml basename ("" = none)
#         # FC_SERVICE: client-<fmt> compose service (ctr = ak-dtf${DTF_SLOT}-$svc)
#         # FC_ENABLED: 1            0 = registered but not run (research-grade)
#     * FC_CASES="case_a case_b ..."   the per-format edge-case registry
#     * the hooks the driver calls, in order:
#         fc_publish          get the fixture into $FC_REPO (host curl PUT OK)
#         fc_client_setup     write client config INSIDE the ctr, pointing ONLY
#                             at $FC_INT_URL (no fallback source!)
#         fc_consume          run the REAL client; non-zero = fail
#         fc_assert           marker-file / sha-equality proof, client-side
#         fc_advertised_check extract the advertised location from metadata and
#                             assert it 200s AND the pre-fix/wrong shape 404s
#         fc_cleanup          optional (extra repos, caches); defaults to no-op
#         fc_case_<name>      one function per FC_CASES entry
#
# Hooks RETURN 0/non-zero and echo diagnostics; they do NOT call pass/fail
# themselves (the driver wraps each in begin_test/pass/fail and captures the
# hook's stdout+stderr into a per-step log). Compose the shared nc_* helpers
# below with `|| return 1` so the first failed assertion fails the hook.
#
# Each plugin is SOURCED IN A SUBSHELL by the oracle (`( nc_run_plugin ... )`)
# so the fixed hook names never collide across plugins and a crashing plugin
# cannot poison the loop. A non-zero hook -> fail with the captured log; the
# remaining core hooks are short-circuited to `fail "skipped: prior step
# failed"` (the A0->A1->A2 chaining proven in tiers/native-client/oracle.sh).
#
# Everything else — auth, begin_test/pass/fail, JUnit, RELEASE_GATE=1 strictness
# — is inherited from the corpus common.sh. DTF's rule: the corpus IS the
# assertion library; DTF adds the topology + the discrimination.
# =============================================================================

# The driver assumes the caller already sourced common.sh (begin_suite, pass,
# fail, auth_admin, create_repo, api_delete, setup_workdir, add_exit_handler,
# format_auth_header, ...) and that run.sh exported BASE_URL / DTF_SLOT /
# RUN_ID / ADMIN_USER / ADMIN_PASS / JUNIT_OUTPUT_DIR / RELEASE_GATE.
: "${BASE_URL:?native_client.sh: BASE_URL not set}"
: "${DTF_SLOT:?native_client.sh: DTF_SLOT not set}"

# ---------------------------------------------------------------------------
# Header parsing + selection
# ---------------------------------------------------------------------------

# nc_header <plugin-file> <KEY> -> echoes the value of `# KEY: value`
nc_header() {
  grep -m1 "^# ${2}:" "$1" 2>/dev/null | awk '{print $3}'
}

# fc_enabled_and_selected <plugin-file>
#   returns 0 if the plugin is FC_ENABLED and (when FC_ONLY is set) selected.
fc_enabled_and_selected() {
  local plugin="$1"
  local en fmt
  en="$(nc_header "$plugin" FC_ENABLED)"; en="${en:-1}"
  [ "$en" = "1" ] || return 1
  fmt="$(nc_header "$plugin" FC_FORMAT)"
  if [ -n "${FC_ONLY:-}" ]; then
    case " ${FC_ONLY//,/ } " in
      *" ${fmt} "*) : ;;
      *) return 1 ;;
    esac
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Shared helpers (the "common" column). All auth defaults to Basic
# (format_auth_header): the format-native routes authenticate Basic, and a
# public repo lets anonymous reads through, so Basic-admin is a safe superset.
# ---------------------------------------------------------------------------

# nc_exec [-t SECS] '<script>'
#   `timeout docker exec $FC_CLIENT_CTR bash -c` with output tee'd to a per-
#   format exec log AND returned to the caller (so the driver captures it).
#   Honors FC_EXEC_USER (e.g. a plugin sets FC_EXEC_USER=root for a non-root
#   client image). Returns the container command's exit code.
nc_exec() {
  local secs=120
  if [ "${1:-}" = "-t" ]; then secs="$2"; shift 2; fi
  local script="$1"
  local uargs=()
  [ -n "${FC_EXEC_USER:-}" ] && uargs=(-u "$FC_EXEC_USER")
  timeout "$secs" docker exec "${uargs[@]}" "$FC_CLIENT_CTR" bash -c "$script" 2>&1 \
    | tee -a "${WORK_DIR}/${FC_FORMAT}-exec.log"
  return "${PIPESTATUS[0]}"
}

# nc_put_file <local> <url> [codes]   authenticated PUT upload (default 200/201)
nc_put_file() {
  local file="$1" url="$2" codes="${3:-200 201}"
  local code c
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 \
    -X PUT -H "$(format_auth_header)" --data-binary "@${file}" "$url" 2>/dev/null)"
  for c in $codes; do
    [ "$code" = "$c" ] && { echo "  nc_put_file OK: PUT ${url} -> ${code}"; return 0; }
  done
  echo "  nc_put_file FAIL: PUT ${url} -> ${code} (wanted: ${codes})" >&2
  return 1
}

# nc_post_file <local> <url> [form-field] [codes]   multipart POST upload
nc_post_file() {
  local file="$1" url="$2" field="${3:-file}" codes="${4:-200 201}"
  local code c
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 \
    -X POST -H "$(format_auth_header)" -F "${field}=@${file}" "$url" 2>/dev/null)"
  for c in $codes; do
    [ "$code" = "$c" ] && { echo "  nc_post_file OK: POST ${url} -> ${code}"; return 0; }
  done
  echo "  nc_post_file FAIL: POST ${url} -> ${code} (wanted: ${codes})" >&2
  return 1
}

# nc_expect_code <code> <url> [extra curl args]   status assertion (discriminator)
nc_expect_code() {
  local want="$1" url="$2"; shift 2
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -H "$(format_auth_header)" "$@" "$url" 2>/dev/null)"
  if [ "$code" = "$want" ]; then
    echo "  nc_expect_code OK: ${url} -> ${code}"
    return 0
  fi
  echo "  nc_expect_code MISMATCH: ${url} -> ${code} (wanted ${want})" >&2
  return 1
}

# nc_fetch <url> <out>   authenticated GET to a file
nc_fetch() {
  curl -s --max-time 180 -H "$(format_auth_header)" -o "$2" "$1" 2>/dev/null
}

# nc_sha256 <file>  /  nc_sha256_in_ctr <container-path>
nc_sha256() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
nc_sha256_in_ctr() {
  local uargs=()
  [ -n "${FC_EXEC_USER:-}" ] && uargs=(-u "$FC_EXEC_USER")
  docker exec "${uargs[@]}" "$FC_CLIENT_CTR" sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# nc_assert_sha_eq <a> <b> [msg]   byte-identity proof (published == consumed)
nc_assert_sha_eq() {
  local a="$1" b="$2" msg="${3:-sha256 mismatch}"
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    echo "  nc_assert_sha_eq OK: ${a}"
    return 0
  fi
  echo "  ${msg}: '${a}' != '${b}'" >&2
  return 1
}

# nc_advertised <metadata-url> <extract-cmd>
#   fetch the metadata doc, run <extract-cmd> (reads the doc on stdin), echo the
#   advertised path. Empty extraction => non-zero (a metadata endpoint that does
#   not advertise a resolvable location is itself the bug).
nc_advertised() {
  local url="$1" extract="$2"
  local tmp="${WORK_DIR}/adv.${FC_FORMAT}.$$"
  if ! curl -s --max-time 60 -H "$(format_auth_header)" -o "$tmp" "$url" 2>/dev/null; then
    echo "  nc_advertised: metadata fetch failed: ${url}" >&2
    return 1
  fi
  local out
  out="$(eval "$extract" < "$tmp")"
  if [ -z "$out" ]; then
    echo "  nc_advertised: extractor produced nothing from ${url}" >&2
    echo "    (extract: ${extract}; head: $(head -c 200 "$tmp" 2>/dev/null))" >&2
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
  echo "$out"
}

# nc_copy_to_ctr <local> <ctr-path>  /  nc_copy_from_ctr <ctr-path> <local>
nc_copy_to_ctr()   { docker cp "$1" "${FC_CLIENT_CTR}:$2"      >/dev/null 2>&1; }
nc_copy_from_ctr() { docker cp "${FC_CLIENT_CTR}:$1" "$2"      >/dev/null 2>&1; }

# nc_repo_delete   idempotent teardown of the per-format repo (exit-handler safe)
nc_repo_delete() {
  [ -n "${FC_REPO:-}" ] || return 0
  api_delete "/api/v1/repositories/${FC_REPO}" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# The driver
# ---------------------------------------------------------------------------

# Internal: run one core hook with begin_test + short-circuit chaining.
# Uses/updates the FC_OK flag so a failed step skips the rest of the core flow.
_nc_step() {
  local label="$1" hook="$2"
  begin_test "$label"
  if [ "${FC_OK:-1}" != "1" ]; then
    fail "skipped: prior step failed"
    return 0
  fi
  local log="${WORK_DIR}/${FC_FORMAT}-${hook}.log"
  if "$hook" >"$log" 2>&1; then
    sed -n '1,8p' "$log" 2>/dev/null | sed 's/^/    /'
    pass
  else
    FC_OK=0
    fail "${hook} failed" "$(tail -n 40 "$log" 2>/dev/null)"
  fi
}

# nc_run_plugin <plugin-file>
#   The COMMON lifecycle for one format. MUST be invoked inside a subshell by
#   the oracle so hook names + the FC_OK flag are isolated per plugin.
nc_run_plugin() {
  local plugin="$1"

  # 1. parse the header
  FC_FORMAT="$(nc_header "$plugin" FC_FORMAT)"
  FC_MOUNT="$(nc_header "$plugin" FC_MOUNT)"
  FC_REPO_FORMAT="$(nc_header "$plugin" FC_REPO_FORMAT)"
  FC_PROFILE="$(nc_header "$plugin" FC_PROFILE)"
  FC_SERVICE="$(nc_header "$plugin" FC_SERVICE)"
  : "${FC_REPO_FORMAT:=$FC_FORMAT}"
  if [ -z "$FC_FORMAT" ] || [ -z "$FC_MOUNT" ]; then
    echo "!! plugin ${plugin} missing FC_FORMAT/FC_MOUNT header" >&2
    return 2
  fi

  # 2. one JUnit suite per format
  begin_suite "fc-${FC_FORMAT}"

  # 3. admin auth (create_repo uses Bearer) + a per-plugin workdir
  auth_admin
  setup_workdir

  # 4. compute the per-format env the hooks see
  FC_REPO="dtf-${FC_FORMAT}-${RUN_ID}"
  FC_URL="${BASE_URL}/${FC_MOUNT}/${FC_REPO}"                 # host-side (oracle)
  FC_INT_URL="http://backend:8080/${FC_MOUNT}/${FC_REPO}"    # client-container-side
  FC_CLIENT_CTR="ak-dtf${DTF_SLOT}-${FC_SERVICE}"
  FC_CASES=""
  FC_OK=1
  fc_cleanup() { :; }   # optional hook default

  # 5. load the plugin's verbs (into THIS subshell)
  # shellcheck disable=SC1090
  source "$plugin"

  # 6. teardown the repo on subshell exit (end_suite exits -> handler fires)
  add_exit_handler "nc_repo_delete"

  echo ">> fc-${FC_FORMAT}: repo=${FC_REPO} mount=/${FC_MOUNT} client=${FC_CLIENT_CTR}"
  echo ">>   FC_URL=${FC_URL}"
  echo ">>   FC_INT_URL=${FC_INT_URL}"

  # 7. the COMMON sequence, with A0->A1 short-circuit chaining
  begin_test "repo: create hosted ${FC_REPO_FORMAT} repo ${FC_REPO}"
  if create_repo "$FC_REPO" "$FC_REPO_FORMAT" local; then
    pass
  else
    FC_OK=0
    fail "could not create hosted ${FC_REPO_FORMAT} repo ${FC_REPO}"
  fi

  _nc_step "publish: fixture -> ${FC_REPO} (native route)"        fc_publish
  _nc_step "clientcfg: point the client ONLY at ${FC_INT_URL}"    fc_client_setup
  _nc_step "consume: the REAL client follows the advertised path" fc_consume
  _nc_step "assert: client-side marker / sha proof"               fc_assert
  _nc_step "advertised: #2580 discriminator (200 real / 404 wrong shape)" fc_advertised_check

  # 8. per-format edge cases (gated on the core flow succeeding; each is its own
  #    positive+negative discriminator tied to a bug class)
  local c
  for c in ${FC_CASES:-}; do
    begin_test "edge:${c}"
    if [ "$FC_OK" != "1" ]; then
      fail "skipped: prior core step failed"
      continue
    fi
    if ! type "fc_case_${c}" >/dev/null 2>&1; then
      fail "edge case '${c}' listed in FC_CASES but fc_case_${c} is not defined"
      continue
    fi
    local elog="${WORK_DIR}/${FC_FORMAT}-case-${c}.log"
    if "fc_case_${c}" >"$elog" 2>&1; then
      sed -n '1,8p' "$elog" 2>/dev/null | sed 's/^/    /'
      pass
    else
      # An edge failure does NOT poison later independent cases (they each
      # re-check their own preconditions), but IS a suite failure.
      fail "edge case '${c}' failed" "$(tail -n 40 "$elog" 2>/dev/null)"
    fi
  done

  # 9. optional plugin cleanup, then the suite verdict (exit propagates to the
  #    oracle's subshell $?). end_suite exits 1 iff any test failed.
  fc_cleanup >/dev/null 2>&1 || true
  end_suite
}
