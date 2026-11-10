#!/usr/bin/env bash
# =============================================================================
# tiers/qcmj-webhook-authz/oracle.sh — webhook management BOLA + secret leak (GHSA-qcmj)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_DIR,
# DTF_SLOT, HTTP_PORT/GRPC_PORT/PG_PORT/S3_PORT..., BACKEND_IMAGE, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit harness.
#
# The defect (GHSA-qcmj):
#   * Management verbs (delete/enable/disable/test/rotate-secret/redeliver) used a
#     soft gate `is_admin OR creator OR repo-accessible`. Since create is
#     admin-only, the live exploit is a repo-accessible NON-admin mutating (or
#     destroying) a webhook they neither own nor admin — a cross-actor BOLA over
#     an egress + signing integration.
#   * rotate-secret leaked the raw signing `secret` in its response body.
#   The fix requires admin for management verbs (-> 403) and drops the raw secret
#   from the rotate response (id / secret_digest / expiry only). 1.12.0 (#5235)
#   returns the new secret once to that admin again, because a receiver cannot
#   verify after the overlap without it; the admin gate is what keeps it safe.
#
# Discriminating gates, ALL must hold (RELEASE_GATE=1):
#   (A) BOUNDARY  repo-accessible non-admin + seeded non-admin creator: disable /
#                 rotate / delete -> 403, DB unchanged. Baseline: 2xx + mutated.
#   (B) CONTROL   admin disable + rotate on a dedicated webhook -> 2xx.
#   (C) ONCE-ONLY  admin rotate 200 returns the new `secret` exactly once with
#                 Cache-Control: no-store (artifact-keeper#5235, 1.12.0); GET,
#                 LIST (which must return the webhook, and carry no raw
#                 whsec_ value at all), a repeat 409, a refused non-admin
#                 rotate, the backend log and audit_log never carry it. (1.6.1-1.11.x dropped the field instead;
#                 release/1.11.x keeps that assertion.)
#
# Signing (rotate-secret) needs AK_WEBHOOK_SECRET_KEY, which the shared compose
# base does not set. inject_webhook_key() recreates ONLY the backend service on
# the same compose project with the key added, via a tier-local override file.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_DIR:?}"; : "${DTF_SLOT:?}"; : "${HTTP_PORT:?}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
NA_USER="qcmj-na-${DTF_SLOT}-${SUF}"
NA_PASS="QcmjNa_${SUF}_Aa1!"
REPO="qcmj-repo-${DTF_SLOT}-${SUF}"

# ---------------------------------------------------------------------------
# inject_webhook_key — recreate ONLY the backend service with a real
# AK_WEBHOOK_SECRET_KEY so rotate-secret is exercisable. Uses a tier-local
# compose override (no shared-file edit) applied to the SAME compose project the
# harness owns, so the labels stay intact and the harness `down -v` reclaims it.
# Echoes 0 on a healthy recreate, non-zero otherwise.
# ---------------------------------------------------------------------------
inject_webhook_key() {
  local key override project
  key="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
  override="$(mktemp "${TMPDIR:-/tmp}/qcmj-wh-key-${DTF_SLOT}.XXXXXX.yml")"
  project="ak-dtf${DTF_SLOT}"
  cat > "$override" <<EOF
services:
  backend:
    environment:
      AK_WEBHOOK_SECRET_KEY: "${key}"
EOF
  # BACKEND_IMAGE + the port block are already exported by run.sh/ports.sh; the
  # base+filesystem overlays plus our override reproduce the running topology and
  # add just the signing key. --wait health-gates the recreated backend.
  BACKEND_IMAGE="${BACKEND_IMAGE:-}" \
  docker compose -p "$project" \
    -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "$override" \
    up -d --wait backend >/dev/null 2>&1
  local rc=$?
  rm -f "$override"
  return "$rc"
}

# --- curl / db helpers (always return 0; echo the numeric status/body) ------
req_code() { # METHOD URL BEARER
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$1" \
    -H "Authorization: Bearer ${3}" "$2" 2>/dev/null || echo 000
}
admin_json() { # METHOD PATH [JSON]  -> raw response body (admin bearer)
  local m="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -s $CURL_TIMEOUT -X "$m" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H 'Content-Type: application/json' -d "$body" "${BASE_URL}${path}" 2>/dev/null || true
  else
    curl -s $CURL_TIMEOUT -X "$m" -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}${path}" 2>/dev/null || true
  fi
}
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || echo "?"; }

# is_denied: a proper webhook-authz denial. The fix returns 403 (Forbidden) for
# a repo-accessible / non-admin-creator principal; 404 (existence-hiding) is the
# other acceptable authz-deny shape. 401 is deliberately NOT accepted — it means
# the credential itself was rejected (a broken token), not an authorization
# decision, and must not be mistaken for the gate holding. Anything 2xx is the
# vuln (the mutation was accepted) = RED.
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }

begin_suite "qcmj-webhook-authz"

# --- inject the signing key so rotate-secret is exercisable ------------------
begin_test "setup: inject AK_WEBHOOK_SECRET_KEY + health-gate the backend (enables webhook signing/rotation)"
if inject_webhook_key && curl -sf --max-time 10 "${BASE_URL}/health" >/dev/null 2>&1; then
  pass
else
  fail "could not recreate the backend with AK_WEBHOOK_SECRET_KEY; rotate-secret cannot be exercised"
  end_suite
fi

# --- setup: admin session, a repo-accessible non-admin, seeded webhooks ------
auth_admin   # sets ADMIN_TOKEN

NA_ID="$(create_test_user_with_retry "$NA_USER" "$NA_PASS" "${NA_USER}@t.test")" || true
NA_TOKEN=""
[ -n "$NA_ID" ] && [ "$NA_ID" != "null" ] && NA_TOKEN="$(login_as "$NA_USER" "$NA_PASS")" || true
if [ -z "$NA_TOKEN" ] || [ -z "$NA_ID" ] || [ "$NA_ID" = "null" ]; then
  begin_test "setup: create + login the non-admin principal"
  fail "could not provision non-admin ${NA_USER}"
  end_suite
fi

# A private repo the non-admin is granted a role on (=> repo-accessible).
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1; then
  begin_test "setup: create private repo for the webhook"
  fail "could not create repo ${REPO}"
  end_suite
fi
db "INSERT INTO role_assignments (user_id, role_id, repository_id)
    SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
    WHERE u.username='${NA_USER}' AND r.name='developer' AND repo.key='${REPO}'
    ON CONFLICT DO NOTHING;" >/dev/null
REPO_ID="$(db "SELECT id FROM repositories WHERE key='${REPO}' LIMIT 1;")"

# Admin creates the repo-scoped webhook the non-admin will try to hijack.
mk_repo_webhook() { # NAME -> echoes webhook id
  admin_json POST "/api/v1/webhooks" \
    "{\"name\":\"${1}\",\"url\":\"https://example.com/hook\",\"events\":[\"artifact_uploaded\"],\"repository_id\":\"${REPO_ID}\",\"secret\":\"whsec_seed_${SUF}\"}" \
    | jq -r '.id // empty' 2>/dev/null || true
}
WH_DISABLE="$(mk_repo_webhook "qcmj-hook-disable-${SUF}")"
WH_ROTATE="$(mk_repo_webhook  "qcmj-hook-rotate-${SUF}")"
WH_DELETE="$(mk_repo_webhook  "qcmj-hook-delete-${SUF}")"
if [ -z "$WH_DISABLE" ] || [ -z "$WH_ROTATE" ] || [ -z "$WH_DELETE" ]; then
  begin_test "setup: admin creates the repo-scoped webhooks"
  fail "could not create seed webhooks (disable='${WH_DISABLE}' rotate='${WH_ROTATE}' delete='${WH_DELETE}')"
  end_suite
fi

# A GLOBAL webhook whose created_by is the NON-admin (the legacy/seeded
# non-admin-creator soft-gate hole; create is admin-only so it must be seeded).
db "INSERT INTO webhooks (name, url, events, created_by)
    VALUES ('qcmj-hook-creator-${SUF}','https://example.com/hook',ARRAY['artifact.created'],'${NA_ID}');" >/dev/null
WH_CREATOR="$(db "SELECT id FROM webhooks WHERE name='qcmj-hook-creator-${SUF}' AND created_by='${NA_ID}' LIMIT 1;")"

# ---------------------------------------------------------------------------
# (A) BOUNDARY — the load-bearing gates. A repo-accessible non-admin (and a
#     non-admin creator) must NOT manage a webhook. Each verb is proven with a
#     DB no-mutation assertion so a "wrong status but real mutation" cannot slip.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: repo-accessible non-admin -> POST /webhooks/:id/disable -> denied (GHSA-qcmj BOLA)"
RC="$(req_code POST "${BASE_URL}/api/v1/webhooks/${WH_DISABLE}/disable" "$NA_TOKEN")"
ENABLED="$(db "SELECT is_enabled FROM webhooks WHERE id='${WH_DISABLE}';")"
if is_denied "$RC" && [ "$ENABLED" = "t" ]; then
  pass
else
  fail "WEBHOOK BOLA: repo-accessible non-admin disabled a webhook they neither own nor admin -> ${RC} (is_enabled now '${ENABLED}'); expected denial (403) + still-enabled. GHSA-qcmj soft gate." \
       "status=${RC} is_enabled=${ENABLED} principal=repo-accessible-nonadmin verb=disable"
fi

begin_test "BOUNDARY: repo-accessible non-admin -> POST /webhooks/:id/rotate-secret -> denied (GHSA-qcmj BOLA)"
DIGEST_BEFORE="$(db "SELECT secret_digest FROM webhooks WHERE id='${WH_ROTATE}';")"
RC="$(req_code POST "${BASE_URL}/api/v1/webhooks/${WH_ROTATE}/rotate-secret" "$NA_TOKEN")"
DIGEST_AFTER="$(db "SELECT secret_digest FROM webhooks WHERE id='${WH_ROTATE}';")"
if is_denied "$RC" && [ "$DIGEST_BEFORE" = "$DIGEST_AFTER" ]; then
  pass
else
  fail "WEBHOOK BOLA: repo-accessible non-admin rotated another actor's signing secret -> ${RC} (digest '${DIGEST_BEFORE}' -> '${DIGEST_AFTER}'); expected denial (403) + unchanged digest." \
       "status=${RC} digest_before=${DIGEST_BEFORE} digest_after=${DIGEST_AFTER} verb=rotate-secret"
fi

begin_test "BOUNDARY: non-admin CREATOR -> POST /webhooks/:id/disable -> denied (GHSA-qcmj soft gate)"
RC="$(req_code POST "${BASE_URL}/api/v1/webhooks/${WH_CREATOR}/disable" "$NA_TOKEN")"
CENABLED="$(db "SELECT is_enabled FROM webhooks WHERE id='${WH_CREATOR}';")"
if is_denied "$RC" && [ "$CENABLED" = "t" ]; then
  pass
else
  fail "non-admin CREATOR managed a webhook -> ${RC} (is_enabled now '${CENABLED}'); the fix requires admin, expected 403 + still-enabled (GHSA-qcmj)" \
       "status=${RC} is_enabled=${CENABLED} principal=nonadmin-creator verb=disable"
fi

begin_test "BOUNDARY: repo-accessible non-admin -> DELETE /webhooks/:id -> denied, webhook survives (GHSA-qcmj BOLA)"
RC="$(req_code DELETE "${BASE_URL}/api/v1/webhooks/${WH_DELETE}" "$NA_TOKEN")"
STILL="$(db "SELECT count(*) FROM webhooks WHERE id='${WH_DELETE}';")"
if is_denied "$RC" && [ "$STILL" = "1" ]; then
  pass
else
  fail "WEBHOOK BOLA: repo-accessible non-admin DELETED a webhook they neither own nor admin -> ${RC} (rows remaining '${STILL}'); expected denial (403) + row intact. GHSA-qcmj soft gate." \
       "status=${RC} rows_remaining=${STILL} principal=repo-accessible-nonadmin verb=delete"
fi

# ---------------------------------------------------------------------------
# (B/C) CONTROL + NON-DISCLOSURE — an admin CAN manage (proves not always-403),
#     and the rotate-secret 200 body must NOT carry the raw secret.
# ---------------------------------------------------------------------------
WH_ADMIN="$(mk_repo_webhook "qcmj-hook-admin-${SUF}")"
begin_test "CONTROL: admin -> POST /webhooks/:id/disable -> 2xx (management still works)"
RC="$(req_code POST "${BASE_URL}/api/v1/webhooks/${WH_ADMIN}/disable" "$ADMIN_TOKEN")"
if [ "$RC" = "200" ] || [ "$RC" = "204" ]; then
  pass
else
  fail "admin was refused on disable -> ${RC}, expected 2xx (the tier must not be a hollow always-deny)" \
       "status=${RC} principal=admin verb=disable webhook=${WH_ADMIN}"
fi

begin_test "ONCE-ONLY: admin rotate-secret returns 200 with the new secret exactly once (no-store), and no read, repeat or denied call returns it (#5235, GHSA-qcmj)"
# 1.12.0 contract (artifact-keeper#5235): the rotate 200 body carries the new
# raw `secret` once, with Cache-Control: no-store, the same contract create
# has. GHSA-qcmj's threat was a NON-admin obtaining a key; (A) above holds that
# gate. What must stay true: GET / LIST expose only `secret_digest`, a repeat
# rotation inside the overlap window answers 409 without the secret, a refused
# non-admin rotate carries no secret, and the backend log never prints it.
ROT_HDRS="$(mktemp "${TMPDIR:-/tmp}/qcmj-rot-hdr-${DTF_SLOT}.XXXXXX")"
ROT_BODY="$(curl -s $CURL_TIMEOUT -D "$ROT_HDRS" -X POST -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/webhooks/${WH_ADMIN}/rotate-secret" 2>/dev/null || true)"
ROT_ID="$(echo "$ROT_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
ROT_DIGEST="$(echo "$ROT_BODY" | jq -r '.secret_digest // empty' 2>/dev/null || true)"
ROT_SECRET="$(echo "$ROT_BODY" | jq -r 'if (.secret|type)=="string" then .secret else empty end' 2>/dev/null || true)"
NO_STORE="$(tr -d '\r' <"$ROT_HDRS" | grep -i '^cache-control:' | grep -ci 'no-store' || true)"
rm -f "$ROT_HDRS"
ONCE_ERR=""
[ -n "$ROT_ID" ] && [ -n "$ROT_DIGEST" ] || ONCE_ERR="${ONCE_ERR} rotate body lacks id/secret_digest;"
if [ "${#ROT_SECRET}" -lt 16 ]; then
  ONCE_ERR="${ONCE_ERR} rotate body carries no usable new secret (#5235 returns it once);"
else
  [ "${NO_STORE:-0}" -ge 1 ] || ONCE_ERR="${ONCE_ERR} rotate 200 lacks Cache-Control: no-store;"
  case "$ROT_DIGEST" in *"$ROT_SECRET"*) ONCE_ERR="${ONCE_ERR} secret_digest contains the raw secret;" ;; esac
  GET_BODY="$(admin_json GET "/api/v1/webhooks/${WH_ADMIN}")"
  LIST_BODY="$(admin_json GET "/api/v1/webhooks")"
  # Non-vacuous: GET must be THIS webhook and LIST must contain it, so an empty
  # or error body cannot pass the no-secret checks below.
  [ "$(echo "$GET_BODY" | jq -r '.id // empty' 2>/dev/null || true)" = "$WH_ADMIN" ] || \
    ONCE_ERR="${ONCE_ERR} GET /webhooks/:id did not return webhook ${WH_ADMIN};"
  echo "$LIST_BODY" | jq -e --arg id "$WH_ADMIN" \
    '[(.items? // .data? // .webhooks? // (if type=="array" then . else [] end))[]?.id] | index($id) != null' \
    >/dev/null 2>&1 || ONCE_ERR="${ONCE_ERR} GET /webhooks (list) does not list webhook ${WH_ADMIN};"
  # Any raw secret, new OR previous: the digest form is `whsec_...XXXX`, so a
  # `whsec_` followed by 16+ token characters is a raw value.
  RAW_RE='whsec_[A-Za-z0-9_-]{16,}'
  case "$GET_BODY" in *"$ROT_SECRET"*) ONCE_ERR="${ONCE_ERR} GET /webhooks/:id returns the new raw secret;" ;; esac
  case "$LIST_BODY" in *"$ROT_SECRET"*) ONCE_ERR="${ONCE_ERR} GET /webhooks (list) returns the new raw secret;" ;; esac
  grep -qE "$RAW_RE" <<<"$GET_BODY" && ONCE_ERR="${ONCE_ERR} GET /webhooks/:id returns a raw whsec_ secret;"
  grep -qE "$RAW_RE" <<<"$LIST_BODY" && ONCE_ERR="${ONCE_ERR} GET /webhooks (list) returns a raw whsec_ secret;"
  REP_CODE="$(curl -s -o "${TMPDIR:-/tmp}/qcmj-rep-${DTF_SLOT}-$$" -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/api/v1/webhooks/${WH_ADMIN}/rotate-secret" 2>/dev/null || echo 000)"
  REP_BODY="$(cat "${TMPDIR:-/tmp}/qcmj-rep-${DTF_SLOT}-$$" 2>/dev/null || true)"; rm -f "${TMPDIR:-/tmp}/qcmj-rep-${DTF_SLOT}-$$"
  [ "$REP_CODE" = "409" ] || ONCE_ERR="${ONCE_ERR} repeat rotate inside the window answered ${REP_CODE}, expected 409;"
  case "$REP_BODY" in *whsec_*|*"$ROT_SECRET"*) ONCE_ERR="${ONCE_ERR} repeat rotate body carries a secret;" ;; esac
  NA_BODY="$(curl -s $CURL_TIMEOUT -X POST -H "Authorization: Bearer ${NA_TOKEN}" \
    "${BASE_URL}/api/v1/webhooks/${WH_ADMIN}/rotate-secret" 2>/dev/null || true)"
  case "$NA_BODY" in *whsec_*|*"$ROT_SECRET"*) ONCE_ERR="${ONCE_ERR} a refused non-admin rotate body carries a secret;" ;; esac
  # Capture first, then search: piping `docker logs` into `grep -q` under
  # pipefail lets a MATCH kill docker logs with SIGPIPE (rc 141), which the `if`
  # would read as "no leak". An empty capture is unevaluable, not clean.
  # A failed `docker logs` (container renamed / gone) prints the daemon's error,
  # which is non-empty and secret-free: treat it as unevaluable, never as clean.
  LOG_OK=1
  BACKEND_LOG="$(docker logs "ak-dtf${DTF_SLOT}-backend" 2>&1)" || {
    LOG_OK=0; ONCE_ERR="${ONCE_ERR} docker logs failed, log leak check unevaluable;"; }
  if [ "$LOG_OK" = "0" ]; then
    :
  elif [ -z "$BACKEND_LOG" ]; then
    ONCE_ERR="${ONCE_ERR} could not read the backend log (empty capture), so the log leak check is unevaluable;"
  elif grep -qF -- "$ROT_SECRET" <<<"$BACKEND_LOG"; then
    ONCE_ERR="${ONCE_ERR} the backend log prints the rotated secret;"
  fi
  # The rotation's audit row records THAT it rotated (#4710), never the value.
  AUDIT_HITS="$(db "SELECT count(*) FROM audit_log WHERE strpos(COALESCE(details::text,''), '${ROT_SECRET}') > 0;")"
  case "$AUDIT_HITS" in
    0) ;;
    ''|*[!0-9]*) ONCE_ERR="${ONCE_ERR} audit_log leak check could not be evaluated (rows=${AUDIT_HITS:-?});" ;;
    *) ONCE_ERR="${ONCE_ERR} audit_log carries the rotated secret (rows=${AUDIT_HITS});" ;;
  esac
fi
if [ -z "$ONCE_ERR" ]; then
  pass
else
  # Never echo the secret itself into the JUnit body.
  fail "rotate-secret once-only contract broken:${ONCE_ERR}" \
       "id='${ROT_ID}' digest='${ROT_DIGEST}' secret_len=${#ROT_SECRET} no_store=${NO_STORE:-0} repeat=${REP_CODE:-n/a}"
fi

end_suite
