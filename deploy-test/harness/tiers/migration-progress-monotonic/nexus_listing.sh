#!/usr/bin/env bash
# =============================================================================
# tiers/migration-progress-monotonic/nexus_listing.sh: bounded Nexus listing
#          (artifact-keeper#6360, #6260)
# =============================================================================
# Sourced by oracle.sh with common.sh loaded, ADMIN_TOKEN set and the helpers
# aj / jqf / psql_ak / job_row / job_field / wait_status defined. Defines
# run_nexus_listing_cases, which adds its own JUnit cases to the open suite.
#
# The source is fixtures/mock_nexus.py (profiles/upstreams.mock-nexus.yml).
# It counts every listing request per endpoint and repository; those counts
# are what the FIX gates read, because neither fix changes what a migration
# moves, only how much upstream work it takes and when it stops.
#
# THE ISSUES
#   #6360 NexusClient walked /service/rest/v1/assets for every repository,
#         after its components, although only raw and maven2 repositories can
#         hold assets the walk keeps. For npm, docker, pypi and the rest it
#         paged through every asset again and kept none.
#   #6260 Nexus has no server-side date filter, so one filtered listing call
#         fetched upstream pages until it had a full page inside the window or
#         the repository ended. The worker checks for pause and cancel between
#         listing calls' artifacts, so a cancel during a narrow window over a
#         large repository waited for the whole walk.
#
# CASES
#   (FIX #6360)  a dry run of the npm repository lists its 25 components and
#                makes no /assets request (main: 3, the whole asset listing).
#   (CONTROL)    a migration of the raw repository still walks /assets and
#                migrates its 5 component files and 2 loose files (both images).
#   (CONTROL)    a dry run of the Maven repository lists its 6 component files
#                and the one file without a component, not maven-metadata.xml
#                (both images).
#   (FIX #6260)  a job windowed to 2025+ over nx-wide (400 out-of-window pages
#                ahead of one in-window component) is cancelled once its walk is
#                under way; after the cancel the source sees at most one page
#                budget (50) more listing requests, plus slack (main: the rest
#                of the 401 component pages and then the 401 asset pages).
#   (CONTROL)    the same window over nx-wide-ok (120 empty pages, more than two
#                budgets) completes and finds the one in-window component
#                (both images).
# =============================================================================

NXL_CONTAINER="ak-dtf${DTF_SLOT}-mock-nexus"
NXL_NPM_COMPONENTS=25
NXL_RAW_FILES=7
NXL_MAVEN_ITEMS=7
# One listing call fetches at most 50 upstream pages on the fix. The slack
# covers the page in flight when the cancel lands and the worker's own
# status read; main walks hundreds more.
NXL_AFTER_CANCEL_MAX=60
NXL_WINDOW_FROM="2025-01-01T00:00:00Z"

nxl_stat() { # KEY -> request count (0 when the mock has not seen it)
  docker exec "$NXL_CONTAINER" python3 -c "
import json, sys, urllib.request
print(json.load(urllib.request.urlopen('http://127.0.0.1/__stats', timeout=5)).get(sys.argv[1], 0))
" "$1" 2>/dev/null || echo "?"
}

nxl_listing_total() { # REPO -> components + assets requests
  local c a
  c="$(nxl_stat "components:$1")"; a="$(nxl_stat "assets:$1")"
  case "$c$a" in *'?'*) echo "?"; return ;; esac
  echo $(( c + a ))
}

# nxl_job REPO DRY_RUN DATE_FROM_OR_EMPTY -> job id
nxl_job() {
  local body
  body="$(jq -nc --arg cid "$NXL_CONN_ID" --arg repo "$1" --argjson dry "$2" --arg from "$3" '{
    source_connection_id: $cid, job_type: (if $from == "" then "full" else "incremental" end),
    config: ({ include_repos: [$repo], dry_run: $dry,
              conflict_resolution: "skip", verify_checksums: true,
              include_users: false, include_groups: false, include_permissions: false,
              concurrent_transfers: 1, throttle_delay_ms: 0 }
             + (if $from == "" then {} else { date_from: $from } end))
  }')"
  jqf "$(aj POST /api/v1/migrations "$body")" '.id // empty' ""
}

nxl_start() { # JOB -> 0 when started
  [ -n "$1" ] && [ "$(ac POST "/api/v1/migrations/${1}/start")" = "200" ]
}

run_nexus_listing_cases() {
  # --- setup: a Nexus connection onto the mock -------------------------------
  local conn
  conn="$(aj POST /api/v1/migrations/connections "$(jq -nc --arg n "dtf-nxlist-${SUF}" '{
    name: $n, url: "http://mock-nexus", auth_type: "basic_auth",
    source_type: "nexus", credentials: {username: "dtf", password: "dtf"}
  }')")"
  NXL_CONN_ID="$(jqf "$conn" '.id // empty' '')"
  if [ -z "$NXL_CONN_ID" ] || [ "$(nxl_stat 'components:nx-npm')" = "?" ]; then
    begin_test "setup: a Nexus connection onto the scripted Nexus source"
    infra_fail "no connection id, or the mock-nexus container's stats are unreadable \
(the upstreams.mock-nexus overlay must be in the tier's PROFILES)" "$(echo "$conn" | head -c 400)"
    return 0
  fi

  # --- FIX #6360: an npm repository makes no asset walk ----------------------
  local job st="" row total assets
  job="$(nxl_job nx-npm true "")"
  nxl_start "$job" && st="$(wait_status "$job" 120 completed completed_with_errors failed cancelled)"
  row="$(job_row "$job")"
  total="$(jqf "$row" '.total_items // 0' 0)"
  assets="$(nxl_stat 'assets:nx-npm')"
  echo "  measured: nx-npm listing requests components=$(nxl_stat 'components:nx-npm') assets=${assets}"
  begin_test "FIX #6360: migrating a Nexus npm repository does not walk its /assets listing"
  if [ "${st:-}" != "completed" ] || [ "$total" != "$NXL_NPM_COMPONENTS" ]; then
    infra_fail "the npm dry run did not complete with ${NXL_NPM_COMPONENTS} items (status=${st:-none} \
total_items=${total}); the asset-walk count is meaningless without it" \
      "$(echo "$row" | jq -c '{status,total_items,completed_items,failed_items,error_message}' 2>/dev/null)"
  elif [ "$assets" = "0" ]; then
    pass
  else
    fail "WASTED ASSET WALK (#6360): the migration listed the npm repository's ${NXL_NPM_COMPONENTS} components \
and then made ${assets} /service/rest/v1/assets requests, paging through every asset again although no npm asset \
can be listed by that walk. Only raw and maven2 repositories hold component-less content."
  fi

  # --- CONTROL: a raw repository still walks /assets --------------------------
  job="$(nxl_job nx-raw false "")"; st=""
  nxl_start "$job" && st="$(wait_status "$job" 120 completed completed_with_errors failed cancelled)"
  row="$(job_row "$job")"
  local done_items raw_assets
  done_items="$(jqf "$row" '.completed_items // 0' 0)"
  raw_assets="$(nxl_stat 'assets:nx-raw')"
  begin_test "CONTROL: a Nexus raw repository still migrates the files no component owns"
  if [ "${st:-}" = "completed" ] && [ "$done_items" = "$NXL_RAW_FILES" ] && [ "${raw_assets:-0}" != "0" ] \
     && [ "$raw_assets" != "?" ]; then
    pass
  else
    fail "the raw repository's migration ended status=${st:-none} with ${done_items}/${NXL_RAW_FILES} items and \
${raw_assets} /assets requests; its 2 component-less files are only reachable through the asset walk" \
      "$(echo "$row" | jq -c '{status,total_items,completed_items,failed_items,error_message}' 2>/dev/null)"
  fi

  # --- CONTROL: a Maven repository's file without a component is listed --------
  job="$(nxl_job nx-maven true "")"; st=""
  nxl_start "$job" && st="$(wait_status "$job" 120 completed completed_with_errors failed cancelled)"
  row="$(job_row "$job")"
  total="$(jqf "$row" '.total_items // 0' 0)"
  begin_test "CONTROL: a Nexus Maven repository lists its file without a component, and not its metadata"
  if [ "${st:-}" = "completed" ] && [ "$total" = "$NXL_MAVEN_ITEMS" ] \
     && [ "$(nxl_stat 'assets:nx-maven')" != "0" ]; then
    pass
  else
    fail "the nx-maven dry run ended status=${st:-none} with total_items=${total} and \
$(nxl_stat 'assets:nx-maven') /assets requests; want completed with ${NXL_MAVEN_ITEMS} (6 component files plus \
docs/install.txt; maven-metadata.xml is regenerated, not listed)" \
      "$(echo "$row" | jq -c '{status,total_items,completed_items,failed_items,error_message}' 2>/dev/null)"
  fi

  # --- FIX #6260: a cancel lands within one page budget -----------------------
  local before at_cancel after prev i trace=""
  job="$(nxl_job nx-wide true "$NXL_WINDOW_FROM")"
  before="$(nxl_listing_total nx-wide)"
  if ! nxl_start "$job"; then
    begin_test "FIX #6260: cancelling a windowed Nexus migration stops its listing within one page budget"
    infra_fail "could not create or start the nx-wide job" "$(job_row "$job" | head -c 400)"
  else
    # Wait until the walk is under way: a handful of empty pages listed.
    for ((i = 0; i < 60; i++)); do
      at_cancel="$(nxl_listing_total nx-wide)"
      [ "$at_cancel" != "?" ] && [ $(( at_cancel - before )) -ge 10 ] && break
      sleep 1
    done
    ac POST "/api/v1/migrations/${job}/cancel" >/dev/null
    at_cancel="$(nxl_listing_total nx-wide)"
    # Let the walk run out: stop once the count holds still for 9 s, or after
    # 180 s (main's walk of ~800 pages takes about 100 s at 120 ms a page).
    prev=-1
    for ((i = 0; i < 60; i++)); do
      sleep 3
      after="$(nxl_listing_total nx-wide)"
      trace="${trace} t+$(( (i + 1) * 3 ))s=${after}"
      if [ "$after" = "$prev" ] && [ "$i" -ge 2 ]; then
        local again; sleep 6; again="$(nxl_listing_total nx-wide)"
        [ "$again" = "$after" ] && break
        after="$again"
      fi
      prev="$after"
    done
    st="$(job_field "$job" status)"
    echo "  measured: nx-wide listing requests before_cancel=$(( at_cancel - before )) after_cancel=$(( after - at_cancel ))"
    begin_test "FIX #6260: cancelling a windowed Nexus migration stops its listing within one page budget"
    if [ "$at_cancel" = "?" ] || [ "$after" = "?" ] || [ $(( at_cancel - before )) -lt 10 ]; then
      infra_fail "the nx-wide walk never got under way (listing requests before=${before} at_cancel=${at_cancel})" \
        "$(job_row "$job" | head -c 400)"
    elif [ $(( after - at_cancel )) -le "$NXL_AFTER_CANCEL_MAX" ] && [ "$st" = "cancelled" ]; then
      pass
    else
      fail "UNBOUNDED LISTING CALL (#6260): the job was cancelled after $(( at_cancel - before )) listing requests, \
and the source then served $(( after - at_cancel )) more (limit ${NXL_AFTER_CANCEL_MAX}); job status ${st}. With a \
date_from of ${NXL_WINDOW_FROM} every page but the last is empty, and one listing call kept fetching pages until \
it had a full page or the repository ended, so the worker's cancel check never ran." "samples:${trace}"
    fi
  fi

  # --- CONTROL: empty budgeted pages do not end the walk -----------------------
  job="$(nxl_job nx-wide-ok true "$NXL_WINDOW_FROM")"; st=""
  nxl_start "$job" && st="$(wait_status "$job" 180 completed completed_with_errors failed cancelled)"
  row="$(job_row "$job")"
  total="$(jqf "$row" '.total_items // 0' 0)"
  begin_test "CONTROL: a windowed Nexus migration past 120 empty pages still finds the one in-window component"
  if [ "${st:-}" = "completed" ] && [ "$total" = "1" ]; then
    pass
  else
    fail "the nx-wide-ok dry run ended status=${st:-none} with total_items=${total}, want completed with 1: \
a page the listing returned short because of its fetch budget was read as the end of the repository" \
      "$(echo "$row" | jq -c '{status,total_items,completed_items,failed_items,error_message}' 2>/dev/null)"
  fi
}
