#!/usr/bin/env bash
# =============================================================================
# tiers/download-async-events/oracle.sh -- #2522 async download-events oracle
# =============================================================================
# run.sh has stood up filesystem/single and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1, COMMON_SH, JUNIT_OUTPUT_DIR, DTF_SLOT.
#
# THREAT/REGRESSION (#2522): the download epilogue used to await a
# `download_statistics` INSERT and an audit INSERT on the catalog pool before
# returning the byte stream. The fix spawns both writes off the hot path
# (`record_download` + `audit_fire_and_forget`). This oracle drives the real
# hosted-download path (maven GET) and asserts the OBSERVABLE CONTRACT: every
# GET serves the exact bytes AND the stats row eventually lands (polled, because
# the write is now asynchronous), while a HEAD records nothing.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-${DTF_SLOT:-x}-$$"
REPO="dl2522-${SUF}"
COORD="com/example/lib/1.0/lib-1.0-${SUF}.jar"
CONTENT="async-download-events-2522-${SUF}"
DL_COUNT=3
RED_SIM="${DTF_RED_SIM:-0}"   # 1 => drive GETs as HEAD (no stat row) to force RED

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# GET (or HEAD when RED_SIM) the artifact; echo "<http_code> <body>".
# NOTE: a HEAD MUST use curl -I, never -X HEAD: the server sets Content-Length
# but sends no body, so -X HEAD makes curl block waiting for bytes that never
# arrive. --max-time also caps any stall so a hang surfaces as a fast failure.
fetch_artifact() {
  local tmp code
  tmp="$(mktemp)"
  if [ "$RED_SIM" = "1" ]; then
    code="$(curl -s -I -o "$tmp" -w '%{http_code}' --max-time 15 \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}/maven/${REPO}/${COORD}" 2>/dev/null || echo 000)"
  else
    code="$(curl -s -o "$tmp" -w '%{http_code}' --max-time 15 \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}/maven/${REPO}/${COORD}" 2>/dev/null || echo 000)"
  fi
  printf '%s %s' "$code" "$(cat "$tmp")"
  rm -f "$tmp"
}

# Repo-scoped download_statistics row count (DB ground truth).
dl_rows() {
  psql_q "SELECT COUNT(*) FROM download_statistics ds
          JOIN artifacts a ON a.id = ds.artifact_id
          WHERE a.repository_id = (SELECT id FROM repositories WHERE key='${REPO}');"
}

# Poll dl_rows until it reaches $1 or a bounded budget (~12s) is exhausted;
# echoes the last observed value. This is the async-timing caveat in action.
poll_dl_rows() {
  local want="$1" last="-1" i
  for i in $(seq 1 60); do
    last="$(dl_rows)"
    [[ "$last" =~ ^[0-9]+$ ]] && [ "$last" -ge "$want" ] && { echo "$last"; return 0; }
    sleep 0.2
  done
  echo "$last"
}

begin_suite "download-async-events-2522"

# --- setup: repo + one hosted artifact ---------------------------------------
auth_admin

begin_test "setup: create a local maven repo and upload one hosted artifact"
setup_ok=1
api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}" \
  >/dev/null 2>&1 || setup_ok=0
up_code="$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" --data-binary "$CONTENT" \
  "${BASE_URL}/maven/${REPO}/${COORD}" 2>/dev/null || echo 000)"
art_id="$(psql_q "SELECT id FROM artifacts
          WHERE repository_id=(SELECT id FROM repositories WHERE key='${REPO}') AND is_deleted=false LIMIT 1;")"
if [ "$setup_ok" = "1" ] && [ "$up_code" = "201" ] && [ -n "$art_id" ]; then
  pass "repo created, artifact uploaded (HTTP ${up_code}, id=${art_id})"
else
  fail "setup failed (repo_ok=${setup_ok} upload=${up_code} art_id='${art_id}')"
  end_suite
fi

# baseline: no downloads recorded yet
begin_test "baseline: zero download_statistics rows before any GET"
base="$(dl_rows)"
assert_eq "$base" "0" "baseline download_statistics count is '${base}' (want 0)" \
  && pass "no rows before first download"

# --- part 1: every GET serves the exact bytes (byte-plane still works) --------
begin_test "each of ${DL_COUNT} downloads returns 200 with the exact uploaded bytes"
serve_ok=1
for _ in $(seq 1 "$DL_COUNT"); do
  out="$(fetch_artifact)"; code="${out%% *}"; body="${out#* }"
  if [ "$RED_SIM" = "1" ]; then
    # HEAD: headers-only 200, no body -- byte assertion is skipped by design.
    [ "$code" = "200" ] || serve_ok=0
  else
    { [ "$code" = "200" ] && [ "$body" = "$CONTENT" ]; } || serve_ok=0
  fi
done
if [ "$serve_ok" = "1" ]; then
  pass "byte stream returned intact on every request (red_sim=${RED_SIM})"
else
  fail "a download did not return the expected bytes (last code=${code})"
fi

# --- part 2: the stats rows EVENTUALLY land (async write, polled) ------------
# This is the discriminating assertion: on the fixed image the spawned INSERTs
# land shortly after the responses; a regression that drops them keeps the
# count below ${DL_COUNT} until the poll times out (RED). DTF_RED_SIM=1 drives
# HEAD probes (no row) to exercise exactly that RED path locally.
begin_test "download_statistics count eventually reaches ${DL_COUNT} (async write off the hot path)"
final="$(poll_dl_rows "$DL_COUNT")"
if [ "$final" = "$DL_COUNT" ]; then
  pass "spawned download_statistics writes all landed (count=${final})"
else
  fail "count reached '${final}' after the retry budget (want ${DL_COUNT}); the async write was dropped or never landed"
fi

# --- part 3: a HEAD serves no body and records NO extra row ------------------
begin_test "a HEAD probe records zero additional download_statistics rows"
before_head="$(dl_rows)"
# curl -I (proper HEAD) + --max-time: -X HEAD would hang on the bodyless response.
curl -s -I -o /dev/null --max-time 15 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/maven/${REPO}/${COORD}" >/dev/null 2>&1
sleep 1  # give any (erroneous) spawned write a chance to land before asserting
after_head="$(dl_rows)"
assert_eq "$after_head" "$before_head" \
  "count changed from '${before_head}' to '${after_head}' across a HEAD (want unchanged)" \
  && pass "HEAD served no body and wrote no stat row"

end_suite
