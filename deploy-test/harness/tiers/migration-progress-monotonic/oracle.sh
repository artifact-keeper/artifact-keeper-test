#!/usr/bin/env bash
# =============================================================================
# tiers/migration-progress-monotonic/oracle.sh — a partial migration run must
#          not overwrite the job row's record (artifact-keeper#3510 / #3511)
# =============================================================================
# run.sh has stood up the `filesystem upstreams.mock-artifactory` profile-set
# with RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, DTF_SLOT,
# ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# THE BUG. `flush_job_counters` ran the status-guarded `update_job_totals` and
# then the UNGUARDED `update_job_progress`, an absolute `SET` keyed only on the
# job id. `process_job`'s counters restart at zero every run while the row's do
# not, so the flush on the interruption exit published a per-run numerator over
# a cumulative one: a job paused, resumed and paused again before the resumed
# run had re-listed anything had `completed_items` and `transferred_bytes` reset
# to zero while the transfers were still in `migration_items` and still in the
# destination. `generate_report` reads that row, so the report then counted the
# artifacts and claimed nothing had moved.
#
# HOW THIS ORACLE MAKES THE MOMENT DETERMINISTIC. Two mechanisms, both
# documented at their use site:
#   * the mock source delays its artifact listing for the interrupt job, so the
#     second pause lands inside a nine-second window rather than racing the
#     worker's between-artifacts check;
#   * the cancel-race gate does not race at all. It takes a `FOR UPDATE` lock on
#     the job row and lets Postgres's lock queue order start -> cancel -> the
#     worker's claim exactly.
#
# --path-as-is on every curl, per the harness convention.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh runs under `set -euo pipefail`, so every probe below swallows its
# own failure explicitly: an unguarded pipeline that 404s would kill the oracle
# mid-suite and report as an exit code with no JUnit case.

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT}"
CURL_RAW="--path-as-is"

# Source-side repository keys. They are fixed because the mock's catalogue is
# fixed (see profiles/upstreams.mock-artifactory.yml); each DTF slot owns its
# own mock container and its own Postgres, so they cannot collide across slots.
SRC_INT="dtfmig-int"      # 24 files, SLOW to list -- the interrupt/monotonicity job
SRC_DRYA="dtfmig-drya"    # 6 files, slow  -- dry run, first repository
SRC_DRYB="dtfmig-dryb"    # 6 files, slow  -- dry run, second repository
SRC_FULL="dtfmig-full"    # 6 files, fast  -- the uninterrupted control
SRC_RACE="dtfmig-race"    # 2 files, fast  -- the cancel-race gate
FULL_FILES=6
FULL_BYTES=3072           # 6 x MOCK_FILE_BYTES(512)
DRY_FILES=12              # drya + dryb

# The mock's listing delay for the slow repositories, in seconds. The oracle
# waits longer than this whenever it needs the delayed page to land.
LIST_DELAY_S=9

WORK="$(mktemp -d -t dtf-migmono-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- REST helpers ------------------------------------------------------------
aj() { # METHOD PATH [BODY] -> response body (never fails the shell)
  local m="$1" p="$2" b="${3:-}"
  if [ -n "$b" ]; then
    curl -s $CURL_TIMEOUT $CURL_RAW -X "$m" "${BASE_URL}${p}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
      -d "$b" 2>/dev/null || true
  else
    curl -s $CURL_TIMEOUT $CURL_RAW -X "$m" "${BASE_URL}${p}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true
  fi
}
ac() { # METHOD PATH -> http code only
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW -X "$1" \
    "${BASE_URL}${2}" -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo 000
}
jqf() { # JSON FILTER DEFAULT
  echo "$1" | jq -r "$2" 2>/dev/null || echo "$3"
}
psql_ak() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" \
    2>/dev/null | tr -d '[:space:]' || echo "?"
}

job_row() { aj GET "/api/v1/migrations/${1}"; }
job_field() { # JOB_ID FIELD
  jqf "$(job_row "$1")" ".${2} // empty" ""
}

# make_job SRC_REPO[,SRC_REPO...] DRY_RUN THROTTLE_MS -> prints the job id
make_job() {
  local repos_json throttle="$3"
  repos_json="$(printf '%s' "$1" | jq -Rc 'split(",")')"
  local body
  body="$(jq -nc --arg cid "$CONN_ID" --argjson repos "$repos_json" \
      --argjson dry "$2" --argjson th "$throttle" '{
    source_connection_id: $cid, job_type: "full",
    config: { include_repos: $repos, dry_run: $dry,
              conflict_resolution: "overwrite", verify_checksums: true,
              include_users: false, include_groups: false, include_permissions: false,
              concurrent_transfers: 1, throttle_delay_ms: $th }
  }')"
  jqf "$(aj POST /api/v1/migrations "$body")" '.id // empty' ""
}

wait_status() { # JOB_ID DEADLINE_SECONDS STATUS... -> prints the status reached
  local id="$1" budget="$2"; shift 2
  local want=" $* " st i
  for ((i = 0; i < budget; i++)); do
    st="$(job_field "$id" status)"
    case "$want" in *" ${st} "*) echo "$st"; return 0 ;; esac
    sleep 1
  done
  echo "${st:-unknown}"
  return 1
}

begin_suite "migration-progress-monotonic"

# ===========================================================================
# SETUP — a source connection onto the scripted mock
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

CONN="$(aj POST /api/v1/migrations/connections "$(jq -nc --arg n "dtf-migmono-${SUF}" '{
  name: $n, url: "http://mock-artifactory", auth_type: "basic_auth",
  source_type: "artifactory", credentials: {username: "dtf", password: "dtf"}
}')")"
CONN_ID="$(jqf "$CONN" '.id // empty' '')"
if [ -z "$CONN_ID" ]; then
  begin_test "setup: create the migration source connection"
  # The two usual causes are both configuration, not the candidate: the SSRF
  # check rejecting a private address, or the plain-HTTP client refusing to be
  # built. Both are set by the upstreams.mock-artifactory overlay.
  infra_fail "POST /api/v1/migrations/connections returned no id; the mock source is at a private address on \
http:// and needs AK_SSRF_ALLOW_PRIVATE_CIDRS + ALLOW_HTTP_INTEGRATIONS from the upstreams.mock-artifactory overlay" \
    "$(echo "$CONN" | head -c 500)"
  end_suite
fi

CONN_TEST="$(aj POST "/api/v1/migrations/connections/${CONN_ID}/test")"
if [ "$(jqf "$CONN_TEST" '.success // false' 'false')" != "true" ]; then
  begin_test "setup: the backend can reach the scripted migration source"
  infra_fail "connection test did not succeed" "$(echo "$CONN_TEST" | head -c 500)"
  end_suite
fi

SRC_LIST="$(aj GET "/api/v1/migrations/connections/${CONN_ID}/repositories")"
MISSING=""
for r in "$SRC_INT" "$SRC_DRYA" "$SRC_DRYB" "$SRC_FULL" "$SRC_RACE"; do
  echo "$SRC_LIST" | jq -e --arg k "$r" '[.items[]?.key] | index($k)' >/dev/null 2>&1 \
    || MISSING="${MISSING} ${r}"
done
if [ -n "$MISSING" ]; then
  begin_test "setup: the mock source advertises the fixture repositories"
  infra_fail "the source is missing fixture repositories:${MISSING} (MOCK_REPOS in the overlay must match this oracle)" \
    "$(echo "$SRC_LIST" | head -c 500)"
  end_suite
fi

# ===========================================================================
# GATE 1 (BOUNDARY) — pause, resume, pause again mid-listing
# ===========================================================================
JOB_INT="$(make_job "$SRC_INT" false 400)"
if [ -z "$JOB_INT" ]; then
  begin_test "setup: create the interrupt/monotonicity job"
  infra_fail "migration job create returned no id"
  end_suite
fi
if [ "$(ac POST "/api/v1/migrations/${JOB_INT}/start")" != "200" ]; then
  begin_test "setup: start the interrupt/monotonicity job"
  infra_fail "POST /start did not return 200" "$(job_row "$JOB_INT")"
  end_suite
fi

# Let the first run actually move some bytes: the whole point is that the row
# carries a real record before the second pass overwrites it.
FIRST_DONE=0
for ((i = 0; i < 90; i++)); do
  FIRST_DONE="$(job_field "$JOB_INT" completed_items)"; FIRST_DONE="${FIRST_DONE:-0}"
  [ "$FIRST_DONE" -ge 4 ] && break
  sleep 1
done
if [ "${FIRST_DONE:-0}" -lt 4 ]; then
  begin_test "setup: the first migration pass transferred some artifacts"
  infra_fail "after 90s the job had completed_items=${FIRST_DONE}, expected >=4 before pausing" \
    "$(job_row "$JOB_INT")
worker log: $(docker logs "ak-dtf${SLOT}-backend" 2>&1 | grep -i migrat | tail -20)"
  end_suite
fi

PAUSE1="$(ac POST "/api/v1/migrations/${JOB_INT}/pause")"
ST="$(wait_status "$JOB_INT" 30 paused)"
# Let the interrupted run's own flush land before reading the baseline.
sleep 5
ROW1="$(job_row "$JOB_INT")"
C1="$(jqf "$ROW1" '.completed_items // 0' 0)"
B1="$(jqf "$ROW1" '.transferred_bytes // 0' 0)"
T1="$(jqf "$ROW1" '.total_items // 0' 0)"
if [ "$PAUSE1" != "200" ] || [ "$ST" != "paused" ] || [ "${C1:-0}" -lt 1 ] || [ "${B1:-0}" -lt 1 ]; then
  begin_test "setup: the first pause left a real record on the job row"
  infra_fail "pause=${PAUSE1} status=${ST} completed_items=${C1} transferred_bytes=${B1}; \
the monotonicity gate needs a non-zero record to protect" "$ROW1"
  end_suite
fi

# The row now says: C1 items, B1 bytes, out of T1. Resume, then pause again
# while the resumed run is still waiting for its first page of the source --
# it has re-accounted for NOTHING at that point, so its per-run counters are
# all zero. On the fixed image that write is rejected; on the vulnerable one it
# is applied absolutely and the record above is erased.
RESUME="$(ac POST "/api/v1/migrations/${JOB_INT}/resume")"
sleep 2
PAUSE2="$(ac POST "/api/v1/migrations/${JOB_INT}/pause")"
if [ "$RESUME" != "200" ] || [ "$PAUSE2" != "200" ]; then
  begin_test "setup: resume then re-pause the job while it is still listing"
  infra_fail "resume=${RESUME} pause=${PAUSE2} (both must be 200)" "$(job_row "$JOB_INT")"
  end_suite
fi

# Sample the row across the WHOLE window in which the delayed page can land and
# the interruption flush can fire -- a single reading taken too early would
# miss the overwrite entirely (measured: it lands ~9s after the pause).
MIN_C="$C1"; MIN_B="$B1"; TRACE=""
for ((i = 0; i < LIST_DELAY_S + 16; i++)); do
  R="$(job_row "$JOB_INT")"
  c="$(jqf "$R" '.completed_items // 0' 0)"; b="$(jqf "$R" '.transferred_bytes // 0' 0)"
  s="$(jqf "$R" '.status // "?"' '?')"; t="$(jqf "$R" '.total_items // 0' 0)"
  TRACE="${TRACE}
  t+${i}s status=${s} total_items=${t} completed_items=${c} transferred_bytes=${b}"
  [ "${c:-0}" -lt "${MIN_C:-0}" ] && MIN_C="$c"
  [ "${b:-0}" -lt "${MIN_B:-0}" ] && MIN_B="$b"
  sleep 1
done
ROW2="$(job_row "$JOB_INT")"
ITEMS_DONE="$(psql_ak "SELECT count(*) FROM migration_items WHERE job_id='${JOB_INT}' AND status='completed';")"
ITEM_BYTES="$(psql_ak "SELECT coalesce(sum(size_bytes),0) FROM migration_items WHERE job_id='${JOB_INT}' AND status='completed';")"

begin_test "BOUNDARY: a resumed-then-re-paused run must not publish its per-run counters over the job row's record"
if [ "${MIN_C:-0}" -ge "${C1:-0}" ] && [ "${MIN_B:-0}" -ge "${B1:-0}" ]; then
  pass
else
  fail "MIGRATION PROGRESS CLOBBERED (#3510): the run that was interrupted before it had re-accounted for a single \
item published its own zeroed counters absolutely over the row. completed_items fell ${C1} -> ${MIN_C} and \
transferred_bytes fell ${B1} -> ${MIN_B}, while ${ITEMS_DONE} migration_items rows totalling ${ITEM_BYTES} bytes still \
record the transfers and the destination still holds them. total_items held at ${T1} because THAT write carries the \
paused/cancelled guard and the numerator's did not -- so the row reads '0 of ${T1}, 0%', which is exactly the symptom \
#3445 set out to remove." \
    "row after the second pause: $(echo "$ROW2" | jq -c '{status,total_items,completed_items,failed_items,skipped_items,total_bytes,transferred_bytes}' 2>/dev/null)
samples:${TRACE}"
fi

# ===========================================================================
# GATE 2 (BOUNDARY) — the report the operator is handed must be self-consistent
# ===========================================================================
CANCEL_INT="$(ac POST "/api/v1/migrations/${JOB_INT}/cancel")"
sleep 3
REPORT="$(aj GET "/api/v1/migrations/${JOB_INT}/report")"
R_MIGRATED="$(jqf "$REPORT" '.summary.artifacts.migrated // 0' 0)"
R_BYTES="$(jqf "$REPORT" '.summary.total_bytes_transferred // 0' 0)"

begin_test "BOUNDARY: the migration report cannot count migrated artifacts and simultaneously claim zero bytes moved"
if [ "$CANCEL_INT" != "200" ] || [ -z "$R_MIGRATED" ]; then
  infra_fail "could not materialise the report (cancel=${CANCEL_INT})" "$(echo "$REPORT" | head -c 400)"
elif [ "${R_MIGRATED:-0}" -gt 0 ] && [ "${R_BYTES:-0}" -ge "${B1:-0}" ] && [ "${R_BYTES:-0}" -gt 0 ]; then
  pass
else
  fail "the migration report is internally inconsistent (#3510): it reports ${R_MIGRATED} artifacts migrated but \
total_bytes_transferred=${R_BYTES} (must be >0 and at least the ${B1} bytes the row already carried). \
generate_report reads total_bytes_transferred straight off the job row, so the clobbered numerator becomes the \
operator's permanent record of the migration. NOTE: this gate asserts CONSISTENCY only, never an exact total -- \
under-reporting after a resume is the separate open issue #3512 and must not fail here." \
    "report: $(echo "$REPORT" | jq -c '.summary' 2>/dev/null || echo "$REPORT" | head -c 400)
migration_items completed=${ITEMS_DONE} bytes=${ITEM_BYTES}"
fi

# ===========================================================================
# GATE 3 (BOUNDARY) — a cancel that lands before the worker claims the job
#
# NOT a race. Measured on the vulnerable parent, the window between
# `start_migration`'s `UPDATE ... status='running'` and the worker's own flip
# is under 3ms, and a cancel fired at every offset from 0 to 40ms landed either
# side of it -- 0 hits in 22 attempts. So the oracle holds a `SELECT ... FOR
# UPDATE` lock on the job row and issues start and cancel against it in that
# order: both block on the lock, Postgres's queue releases them FIFO, and the
# worker's own status write -- issued later, from the task `start_migration`
# spawned -- necessarily lands third. The interleaving the operator hits by
# accident is thus produced exactly, every round, on both images.
# ===========================================================================
RACE_ROUNDS=4
RACE_BAD=""; RACE_EVIDENCE=""; RACE_VALID=0
for ((n = 1; n <= RACE_ROUNDS; n++)); do
  JOB_RACE="$(make_job "$SRC_RACE" false 0)"
  [ -n "$JOB_RACE" ] || continue
  # Hold the row for 5s. Start and cancel queue behind it, in that order.
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry \
    -c "BEGIN; SELECT id FROM migration_jobs WHERE id='${JOB_RACE}' FOR UPDATE; SELECT pg_sleep(5); COMMIT;" \
    >/dev/null 2>&1 &
  LOCK_PID=$!
  sleep 1
  ( ac POST "/api/v1/migrations/${JOB_RACE}/start"  > "${WORK}/start.${n}" ) &
  sleep 1
  ( ac POST "/api/v1/migrations/${JOB_RACE}/cancel" > "${WORK}/cancel.${n}" ) &
  wait "$LOCK_PID" 2>/dev/null || true
  wait
  SC="$(cat "${WORK}/start.${n}" 2>/dev/null || echo '?')"
  CC="$(cat "${WORK}/cancel.${n}" 2>/dev/null || echo '?')"
  FIN="$(wait_status "$JOB_RACE" 40 completed completed_with_errors failed cancelled)"
  DONE="$(job_field "$JOB_RACE" completed_items)"
  RACE_EVIDENCE="${RACE_EVIDENCE}
  round ${n}: start=${SC} cancel=${CC} final_status=${FIN} completed_items=${DONE:-0}"
  # A round only judges the candidate when the operator's two calls both
  # succeeded; anything else is an environment hiccup, counted but not blamed.
  if [ "$SC" = "200" ] && [ "$CC" = "200" ]; then
    RACE_VALID=$((RACE_VALID + 1))
    case "$FIN" in
      cancelled) [ "${DONE:-0}" -eq 0 ] || RACE_BAD="${RACE_BAD} round${n}:transferred=${DONE}" ;;
      *)         RACE_BAD="${RACE_BAD} round${n}:${FIN}" ;;
    esac
  fi
done

begin_test "BOUNDARY: a cancel that lands before the worker claims the job leaves it cancelled, and migrates nothing (${RACE_ROUNDS} rounds)"
if [ "$RACE_VALID" -lt "$RACE_ROUNDS" ]; then
  infra_fail "only ${RACE_VALID} of ${RACE_ROUNDS} rounds produced a usable start+cancel pair; the gate could not be evaluated" \
    "$RACE_EVIDENCE"
elif [ -z "$RACE_BAD" ]; then
  pass
else
  fail "CANCELLED MIGRATION RAN ANYWAY (#3510):${RACE_BAD}. The worker opened with an UNGUARDED \
update_job_status(Running), which undid the operator's cancel; finalize_job_status then had a 'running' row in front \
of its 'NOT IN (paused, cancelled)' guard and stamped the job 'completed' -- after transferring every artifact of a \
migration the operator had stopped. The claim must carry the same guard as the finalize." \
    "$RACE_EVIDENCE"
fi

# ===========================================================================
# GATE 4 — a RUNNING dry run reports a real numerator.
#
# Labelled (FIX) and not (CONTROL): #3511's second correction delivered this,
# so it is RED on the pre-fix parent as well -- but for the OPPOSITE reason to
# the boundary gates above. There the fix stops a write; here it adds one. Its
# companion assertion, that the dry run still ends at exactly 100%, IS a
# control and holds on both images.
# ===========================================================================
JOB_DRY="$(make_job "${SRC_DRYA},${SRC_DRYB}" true 0)"
DRY_START="$(ac POST "/api/v1/migrations/${JOB_DRY}/start")"
DRY_SAMPLES=0; DRY_WITH_NUM=0; DRY_TRACE=""
for ((i = 0; i < 60; i++)); do
  R="$(job_row "$JOB_DRY")"
  s="$(jqf "$R" '.status // "?"' '?')"; t="$(jqf "$R" '.total_items // 0' 0)"
  c="$(jqf "$R" '.completed_items // 0' 0)"
  # Only samples where the run has ALREADY published a denominator can judge
  # the numerator: before the first page lands there is nothing to report yet.
  if [ "$s" = "running" ] && [ "${t:-0}" -gt 0 ]; then
    DRY_SAMPLES=$((DRY_SAMPLES + 1))
    [ "${c:-0}" -gt 0 ] && DRY_WITH_NUM=$((DRY_WITH_NUM + 1))
    DRY_TRACE="${DRY_TRACE}
  t+${i}s ${c}/${t}"
  fi
  case "$s" in completed|completed_with_errors|failed|cancelled) break ;; esac
  sleep 1
done
DRY_ROW="$(job_row "$JOB_DRY")"

begin_test "FIX: a RUNNING dry run reports a real numerator, not a denominator on its own"
if [ "$DRY_START" != "200" ] || [ "$DRY_SAMPLES" -lt 3 ]; then
  infra_fail "start=${DRY_START}; only ${DRY_SAMPLES} samples caught the job running with a published denominator, \
so the gate could not be evaluated (the mock's listing delay is what creates that window)" \
    "$(echo "$DRY_ROW" | jq -c '{status,total_items,completed_items}' 2>/dev/null)${DRY_TRACE}"
elif [ "$DRY_WITH_NUM" -gt 0 ]; then
  pass
else
  fail "a running dry run reported 0/N at 0% for its whole life (${DRY_SAMPLES} samples, none with a numerator) and \
then jumped straight to N/N. A dry run 'continue's before the per-artifact progress write, so nothing published its \
numerator until the run was over -- the counters have to be published at the end of every page too." \
    "final: $(echo "$DRY_ROW" | jq -c '{status,total_items,completed_items}' 2>/dev/null)
running samples:${DRY_TRACE}"
fi

begin_test "CONTROL: the dry run finished at exactly 100% over every discovered artifact"
D_ST="$(jqf "$DRY_ROW" '.status // "?"' '?')"
D_T="$(jqf "$DRY_ROW" '.total_items // 0' 0)"; D_C="$(jqf "$DRY_ROW" '.completed_items // 0' 0)"
if [ "$D_ST" = "completed" ] && [ "${D_T:-0}" -eq "$DRY_FILES" ] && [ "${D_C:-0}" -eq "$DRY_FILES" ]; then
  pass
else
  fail "the dry run ended status=${D_ST} at ${D_C}/${D_T}, expected completed at ${DRY_FILES}/${DRY_FILES}" \
    "$(echo "$DRY_ROW" | jq -c '.' 2>/dev/null | head -c 400)"
fi

# ===========================================================================
# GATE 5 (CONTROL) — an ordinary, uninterrupted migration (both images)
# ===========================================================================
JOB_FULL="$(make_job "$SRC_FULL" false 0)"
FULL_START="$(ac POST "/api/v1/migrations/${JOB_FULL}/start")"
FULL_ST="$(wait_status "$JOB_FULL" 90 completed completed_with_errors failed cancelled)"
FULL_ROW="$(job_row "$JOB_FULL")"
F_T="$(jqf "$FULL_ROW" '.total_items // 0' 0)"
F_C="$(jqf "$FULL_ROW" '.completed_items // 0' 0)"
F_F="$(jqf "$FULL_ROW" '.failed_items // 0' 0)"
F_B="$(jqf "$FULL_ROW" '.transferred_bytes // 0' 0)"
F_LIVE="$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
  WHERE r.key = '${SRC_FULL}' AND a.is_deleted = false;")"

begin_test "CONTROL: an uninterrupted migration reaches exactly 100% with every artifact present in the destination"
if [ "$FULL_START" = "200" ] && [ "$FULL_ST" = "completed" ] \
   && [ "${F_T:-0}" -eq "$FULL_FILES" ] && [ "${F_C:-0}" -eq "$FULL_FILES" ] \
   && [ "${F_F:-0}" -eq 0 ] && [ "${F_B:-0}" -eq "$FULL_BYTES" ] && [ "${F_LIVE:-0}" -eq "$FULL_FILES" ]; then
  pass
else
  fail "the ordinary migration did not land exactly: start=${FULL_START} status=${FULL_ST} \
${F_C}/${F_T} items (want ${FULL_FILES}/${FULL_FILES}), failed=${F_F} (want 0), transferred_bytes=${F_B} \
(want ${FULL_BYTES}), live artifacts in the destination repository '${SRC_FULL}'=${F_LIVE} (want ${FULL_FILES}). \
The monotonic rule must never stop a run that enumerated the whole source from publishing its final figures -- \
that end-of-run write is what corrects an assessment's estimate (#3378)." \
    "$(echo "$FULL_ROW" | jq -c '.' 2>/dev/null | head -c 500)"
fi

begin_test "CONTROL: that migration's report agrees with its counters"
FULL_REPORT="$(aj GET "/api/v1/migrations/${JOB_FULL}/report")"
FR_M="$(jqf "$FULL_REPORT" '.summary.artifacts.migrated // -1' -1)"
FR_B="$(jqf "$FULL_REPORT" '.summary.total_bytes_transferred // -1' -1)"
if [ "${FR_M:-0}" -eq "$FULL_FILES" ] && [ "${FR_B:-0}" -eq "$FULL_BYTES" ]; then
  pass
else
  fail "the report for an uninterrupted migration disagrees with the job row: migrated=${FR_M} (want ${FULL_FILES}), \
total_bytes_transferred=${FR_B} (want ${FULL_BYTES})" \
    "$(echo "$FULL_REPORT" | jq -c '.summary' 2>/dev/null || echo "$FULL_REPORT" | head -c 400)"
fi

end_suite
