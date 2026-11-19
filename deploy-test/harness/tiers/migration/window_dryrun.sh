#!/usr/bin/env bash
# =============================================================================
# tiers/migration/window_dryrun.sh: Nexus date window and dry-run accounting
#          (artifact-keeper#6195, #6196)
# =============================================================================
# Sourced by oracle.sh after the #2457 leg, with common.sh already loaded and
# the slot's Nexus bootstrapped. Defines run_window_dryrun_cases, which adds
# its own JUnit cases to the open suite.
#
# THE BUGS
#   #6195 NexusClient::list_artifacts_with_date_filter dropped date_from and
#         date_to and listed the whole repository, while the worker logged that
#         the job was filtered to the window.
#   #6196 the worker's dry-run branch ran before the duplicate check, so a dry
#         run with conflict_resolution=skip reported artifacts the destination
#         already holds as completed (and their bytes as transferred).
#
# FIXTURE (no back-dating): a raw hosted repository on the slot's Nexus gets
# batch A (3 files), then, a couple of seconds later, batch B (2 files). The
# window bound T is the newest batch-A `lastModified` as Nexus itself reports
# it, so the two clocks never have to agree; the fixture checks that every
# batch-B asset is strictly newer than T before anything is asserted.
#
# CASES
#   (CONTROL)   the job with date_from=T ends completed with 0 failed.
#   (FIX #6195) that job migrates both batch-B files and no batch-A file
#               (red on main: all five).
#   (CONTROL)   an unwindowed re-run (skip) completes and the destination then
#               holds all five files (passes on both images).
#   (FIX #6196) a dry run (skip) over the same repository reports 0 completed,
#               5 skipped and 0 bytes transferred (red on main: 5 completed,
#               0 skipped).
#   (CONTROL)   the dry run writes no artifact.
# =============================================================================

WD_REPO="dtf-raw-window"
WD_A_FILES=(batch-a/a1.bin batch-a/a2.bin batch-a/a3.bin)
WD_B_FILES=(batch-b/b1.bin batch-b/b2.bin)
WD_TOTAL=$(( ${#WD_A_FILES[@]} + ${#WD_B_FILES[@]} ))

# --- Nexus side ----------------------------------------------------------------
wd_nx_create_repo() {
  local body code
  if nx_curl GET "/service/rest/v1/repositories" 2>/dev/null \
       | jq -e --arg n "$WD_REPO" '.[] | select(.name == $n)' >/dev/null 2>&1; then
    return 0
  fi
  body="$(jq -nc --arg n "$WD_REPO" '{
    name: $n, online: true,
    storage: { blobStoreName: "default", strictContentTypeValidation: false, writePolicy: "ALLOW" }
  }')"
  code="$(nx_curl POST "/service/rest/v1/repositories/raw/hosted" \
            -H 'Content-Type: application/json' --data "$body" -o /dev/null -w '%{http_code}')"
  [ "$code" = "201" ]
}

wd_nx_put() { # PATH -> 0 on 201
  local p="$1" f code
  f="$(mktemp)"
  printf 'dtf #6195/#6196 fixture %s %s\n' "$p" "$(date +%s%N)" > "$f"
  code="$(curl -sS -o /dev/null -w '%{http_code}' -u "${NEXUS_ADMIN_USER}:$(nx_pass)" \
            --upload-file "$f" "${NEXUS_API}/repository/${WD_REPO}/${p}" 2>/dev/null || echo 000)"
  rm -f "$f"
  [ "$code" = "201" ]
}

# Every `lastModified` Nexus reports for the paths under PREFIX, one per line.
wd_nx_last_modified() { # PREFIX
  nx_curl GET "/service/rest/v1/assets?repository=${WD_REPO}" 2>/dev/null \
    | jq -r --arg pre "$1" '.items[]
        | select((.path | ltrimstr("/")) | startswith($pre))
        | .lastModified // empty' 2>/dev/null
}

# --- Artifact Keeper side ------------------------------------------------------
wd_aj() { # METHOD PATH [BODY]
  local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then
    curl -s --max-time 60 -X "$m" "${BASE_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H 'Content-Type: application/json' -d "$b" 2>/dev/null || true
  else
    curl -s --max-time 60 -X "$m" "${BASE_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      2>/dev/null || true
  fi
}

wd_psql() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null \
    | tr -d '[:space:]'
}

wd_dest_count() { # LIKE-PATTERN -> live artifacts in the destination matching it
  wd_psql "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
           WHERE r.key = '${WD_REPO}' AND NOT a.is_deleted AND a.path LIKE '$1';"
}

# wd_run_job CONFIG_EXTRA_JSON -> prints the final job row (JSON); empty on error
wd_run_job() {
  local extra="$1" body id st i
  body="$(jq -nc --arg cid "$WD_CONN_ID" --arg repo "$WD_REPO" --argjson extra "$extra" '{
    source_connection_id: $cid, job_type: "full",
    config: ({ include_repos: [$repo], conflict_resolution: "skip", verify_checksums: true,
               include_users: false, include_groups: false, include_permissions: false }
             + $extra)
  }')"
  id="$(wd_aj POST /api/v1/migrations "$body" | jq -r '.id // empty' 2>/dev/null)"
  [ -n "$id" ] || return 1
  wd_aj POST "/api/v1/migrations/${id}/start" >/dev/null
  for ((i = 0; i < 180; i++)); do
    st="$(wd_aj GET "/api/v1/migrations/${id}" | jq -r '.status // empty' 2>/dev/null)"
    case "$st" in completed|completed_with_errors|failed|cancelled) break ;; esac
    sleep 1
  done
  wd_aj GET "/api/v1/migrations/${id}"
}

wd_counters() { # JOB_ROW -> compact counters for messages
  echo "$1" | jq -c '{status, total_items, completed_items, failed_items, skipped_items, transferred_bytes}' \
    2>/dev/null || echo "$1" | head -c 300
}

run_window_dryrun_cases() {
  local f t_bound b_lm row_w row_f row_d a_ct b_ct n_before n_after

  begin_test "setup: seed a raw Nexus repository in two batches for the #6195/#6196 cases"
  if ! wd_nx_create_repo; then
    infra_fail "could not create raw hosted repository ${WD_REPO} on the slot's Nexus"
    return 0
  fi
  for f in "${WD_A_FILES[@]}"; do
    wd_nx_put "$f" || { infra_fail "upload of ${f} to Nexus did not return 201"; return 0; }
  done
  t_bound="$(wd_nx_last_modified "batch-a/" | sort | tail -n 1)"
  sleep 3
  for f in "${WD_B_FILES[@]}"; do
    wd_nx_put "$f" || { infra_fail "upload of ${f} to Nexus did not return 201"; return 0; }
  done
  b_lm="$(wd_nx_last_modified "batch-b/" | sort | head -n 1)"
  if [ -z "$t_bound" ] || [ -z "$b_lm" ] || [[ ! "$b_lm" > "$t_bound" ]]; then
    infra_fail "Nexus did not report usable lastModified values (newest batch A '${t_bound}', oldest batch B '${b_lm}')" \
      "$(nx_curl GET "/service/rest/v1/assets?repository=${WD_REPO}" 2>/dev/null | head -c 800)"
    return 0
  fi
  echo "[6195] window bound T=${t_bound} (newest batch A); oldest batch B=${b_lm}" >&2

  auth_admin
  WD_CONN_ID="$(wd_aj POST /api/v1/migrations/connections "$(jq -nc \
      --arg url "$NEXUS_API_INTERNAL" --arg u "$NEXUS_ADMIN_USER" --arg p "$(nx_pass)" \
      --arg n "dtf-migration-window-${DTF_SLOT}-$$" '{
    name: $n, url: $url, auth_type: "basic_auth", source_type: "nexus",
    credentials: { username: $u, password: $p }
  }')" | jq -r '.id // empty' 2>/dev/null)"
  if [ -z "$WD_CONN_ID" ]; then
    infra_fail "POST /api/v1/migrations/connections returned no id for the Nexus source"
    return 0
  fi
  pass

  # --- #6195: date_from = T -------------------------------------------------
  row_w="$(wd_run_job "$(jq -nc --arg t "$t_bound" '{date_from: $t}')")"
  begin_test "CONTROL: the Nexus migration with date_from set ends completed with 0 failed"
  if [ "$(echo "$row_w" | jq -r '.status // empty' 2>/dev/null)" = "completed" ] \
     && [ "$(echo "$row_w" | jq -r '.failed_items // -1' 2>/dev/null)" = "0" ]; then
    pass
  else
    fail "windowed job did not complete cleanly: $(wd_counters "$row_w")"
  fi

  a_ct="$(wd_dest_count '%batch-a/%')"; b_ct="$(wd_dest_count '%batch-b/%')"
  begin_test "FIX #6195: a Nexus migration with date_from migrates only the batch modified after it"
  if [ "$a_ct" = "0" ] && [ "$b_ct" = "${#WD_B_FILES[@]}" ]; then
    pass
  else
    fail "with date_from=${t_bound} the destination holds ${a_ct:-?} batch-A file(s) (want 0) and ${b_ct:-?} batch-B file(s) (want ${#WD_B_FILES[@]}); job $(wd_counters "$row_w")"
  fi

  # --- unwindowed re-run, then the dry run -----------------------------------
  row_f="$(wd_run_job '{}')"
  a_ct="$(wd_dest_count '%batch-a/%')"; b_ct="$(wd_dest_count '%batch-b/%')"
  begin_test "CONTROL: an unwindowed re-run completes and the destination holds every file"
  if [ "$(echo "$row_f" | jq -r '.status // empty' 2>/dev/null)" = "completed" ] \
     && [ "$a_ct" = "${#WD_A_FILES[@]}" ] && [ "$b_ct" = "${#WD_B_FILES[@]}" ]; then
    pass
  else
    fail "re-run: $(wd_counters "$row_f"); destination batch A=${a_ct:-?} batch B=${b_ct:-?}"
  fi

  n_before="$(wd_dest_count '%')"
  row_d="$(wd_run_job '{"dry_run": true}')"
  n_after="$(wd_dest_count '%')"
  begin_test "FIX #6196: a dry run with conflict_resolution=skip reports artifacts already migrated as skipped, not completed"
  if [ "$(echo "$row_d" | jq -r '.status // empty' 2>/dev/null)" = "completed" ] \
     && [ "$(echo "$row_d" | jq -r '.completed_items // -1' 2>/dev/null)" = "0" ] \
     && [ "$(echo "$row_d" | jq -r '.skipped_items // -1' 2>/dev/null)" = "$WD_TOTAL" ] \
     && [ "$(echo "$row_d" | jq -r '.transferred_bytes // -1' 2>/dev/null)" = "0" ]; then
    pass
  else
    fail "dry run over ${WD_TOTAL} already-migrated files: $(wd_counters "$row_d") (want completed 0, skipped ${WD_TOTAL}, transferred_bytes 0)"
  fi

  begin_test "CONTROL: the dry run writes no artifact"
  if [ -n "$n_before" ] && [ "$n_before" = "$n_after" ]; then
    pass
  else
    fail "destination artifact count went from ${n_before:-?} to ${n_after:-?} during the dry run"
  fi
}
