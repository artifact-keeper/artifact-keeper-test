#!/usr/bin/env bash
# =============================================================================
# tiers/migration/source_timestamps.sh: opt-in import of Nexus dates
#          (artifact-keeper#6519)
# =============================================================================
# Sourced by oracle.sh after the #6195/#6196 cases, with common.sh loaded, the
# slot's Nexus bootstrapped and WD_CONN_ID / wd_* from window_dryrun.sh set.
# Defines run_source_timestamp_cases, which adds its own JUnit cases.
#
# THE FEATURE
#   A migration with import_source_timestamps=true keeps the source's creation
#   date as the artifact's created_at and records the source lastDownloaded as
#   one marker row in download_statistics. Off by default: without it every
#   migrated artifact is stamped with the import time.
#
# FIXTURE: two raw hosted repositories on the slot's Nexus, each holding two
# files. One file in the "on" repository is downloaded once from Nexus so it
# has a lastDownloaded. The oracle then waits a few seconds so the import time
# and the Nexus blobCreated cannot coincide. Both containers share the host
# clock, so the dates compare directly.
#
# CASES
#   (FIX)   with the flag, each migrated artifact's created_at is the Nexus
#           blobCreated (red on main: the import time).
#   (FIX)   the downloaded file has exactly one marker row at its Nexus
#           lastDownloaded (red on main: none).
#   (GUARD) the file nobody downloaded has no marker row.
#   (GUARD) without the flag, migrated artifacts carry the import time.
# =============================================================================

ST_ON_REPO="dtf-raw-dates-on"
ST_OFF_REPO="dtf-raw-dates-off"
ST_FILES=(dates/one.bin dates/two.bin)
ST_MARKER_AGENT="artifact-keeper-migration/nexus (lastDownloaded)"

st_nx_seed() { # REPO
  local repo="$1" f code tmp body
  body="$(jq -nc --arg n "$repo" '{
    name: $n, online: true,
    storage: { blobStoreName: "default", strictContentTypeValidation: false, writePolicy: "ALLOW" }
  }')"
  nx_curl POST "/service/rest/v1/repositories/raw/hosted" \
    -H 'Content-Type: application/json' --data "$body" -o /dev/null 2>/dev/null || true
  for f in "${ST_FILES[@]}"; do
    tmp="$(mktemp)"
    printf 'dtf #6519 fixture %s %s %s\n' "$repo" "$f" "$(date +%s%N)" > "$tmp"
    code="$(curl -sS -o /dev/null -w '%{http_code}' -u "${NEXUS_ADMIN_USER}:$(nx_pass)" \
              --upload-file "$tmp" "${NEXUS_API}/repository/${repo}/${f}" 2>/dev/null || echo 000)"
    rm -f "$tmp"
    [ "$code" = "201" ] || return 1
  done
}

st_nx_field() { # REPO PATH FIELD -> the asset's FIELD as Nexus reports it
  nx_curl GET "/service/rest/v1/assets?repository=$1" 2>/dev/null \
    | jq -r --arg p "$2" --arg f "$3" '.items[]
        | select((.path | ltrimstr("/")) == $p) | .[$f] // empty' 2>/dev/null
}

st_created_off_by() { # REPO PATH ISO -> whole seconds between created_at and ISO
  wd_psql "SELECT round(abs(extract(epoch FROM a.created_at - '$3'::timestamptz))) \
           FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
           WHERE r.key = '$1' AND a.path LIKE '%$2' AND NOT a.is_deleted;"
}

st_markers() { # REPO PATH [ISO] -> "count|seconds between the newest marker and ISO"
  local at="${3:-}"
  wd_psql "SELECT count(*) || '|' || coalesce(round(abs(extract(epoch FROM \
             max(d.downloaded_at) - nullif('${at}', '')::timestamptz)))::text, '') \
           FROM download_statistics d JOIN artifacts a ON a.id = d.artifact_id \
           JOIN repositories r ON r.id = a.repository_id \
           WHERE r.key = '$1' AND a.path LIKE '%$2' AND d.user_agent = '${ST_MARKER_AGENT}';"
}

run_source_timestamp_cases() {
  local f created downloaded off row_on row_off markers job_start ok=1 msg=""

  begin_test "setup: seed two raw Nexus repositories for the #6519 cases"
  if ! st_nx_seed "$ST_ON_REPO" || ! st_nx_seed "$ST_OFF_REPO"; then
    infra_fail "could not seed ${ST_ON_REPO}/${ST_OFF_REPO} on the slot's Nexus"
    return 0
  fi
  curl -sS -o /dev/null -u "${NEXUS_ADMIN_USER}:$(nx_pass)" \
    "${NEXUS_API}/repository/${ST_ON_REPO}/${ST_FILES[0]}" 2>/dev/null
  downloaded="$(st_nx_field "$ST_ON_REPO" "${ST_FILES[0]}" lastDownloaded)"
  if [ -z "$downloaded" ] || [ -z "$(st_nx_field "$ST_ON_REPO" "${ST_FILES[1]}" blobCreated)" ]; then
    infra_fail "Nexus reported no lastDownloaded/blobCreated for the #6519 fixture" \
      "$(nx_curl GET "/service/rest/v1/assets?repository=${ST_ON_REPO}" 2>/dev/null | head -c 800)"
    return 0
  fi
  pass
  sleep 5

  row_on="$(WD_REPO="$ST_ON_REPO" wd_run_job '{"import_source_timestamps": true}')"
  row_off="$(WD_REPO="$ST_OFF_REPO" wd_run_job '{}')"

  begin_test "FIX #6519: with import_source_timestamps each migrated artifact keeps its Nexus blobCreated"
  for f in "${ST_FILES[@]}"; do
    created="$(st_nx_field "$ST_ON_REPO" "$f" blobCreated)"
    off="$(st_created_off_by "$ST_ON_REPO" "$f" "$created")"
    if [ -z "$off" ] || [ "$off" -gt 1 ]; then
      ok=0; msg="${msg} ${f}: created_at is ${off:-?}s from blobCreated ${created};"
    fi
  done
  if [ "$ok" = "1" ]; then pass; else fail "${msg} job $(wd_counters "$row_on")"; fi

  markers="$(st_markers "$ST_ON_REPO" "${ST_FILES[0]}" "$downloaded")"
  begin_test "FIX #6519: the file downloaded on Nexus has one marker row at its lastDownloaded"
  if [ "${markers%%|*}" = "1" ] && [ -n "${markers#*|}" ] && [ "${markers#*|}" -le 1 ]; then
    pass
  else
    fail "marker rows for ${ST_FILES[0]}: count|seconds off = '${markers}' (want 1 within 1s of ${downloaded})"
  fi

  begin_test "GUARD #6519: a file nobody downloaded on Nexus gets no marker row"
  markers="$(st_markers "$ST_ON_REPO" "${ST_FILES[1]}")"
  if [ "${markers%%|*}" = "0" ]; then pass; else fail "marker rows for ${ST_FILES[1]}: '${markers}' (want 0)"; fi

  begin_test "GUARD #6519: without the flag migrated artifacts carry the import time"
  job_start="$(echo "$row_off" | jq -r '.started_at // .created_at // empty' 2>/dev/null)"
  ok=1; msg=""
  for f in "${ST_FILES[@]}"; do
    if [ "$(wd_psql "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
              WHERE r.key = '${ST_OFF_REPO}' AND a.path LIKE '%${f}' \
              AND a.created_at >= '${job_start}'::timestamptz - interval '1 second';")" != "1" ]; then
      ok=0; msg="${msg} ${f};"
    fi
  done
  if [ -n "$job_start" ] && [ "$ok" = "1" ]; then
    pass
  else
    fail "created_at before the job start ${job_start:-?} for:${msg} job $(wd_counters "$row_off")"
  fi
}
