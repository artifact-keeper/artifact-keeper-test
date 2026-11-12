#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/webhook-delivery-fairness/oracle.sh
#   Webhook delivery is fair per endpoint (#5661): a backlog for receivers that
#   never answer no longer starves a live receiver. The legacy
#   X-Webhook-Signature signs the body alone (#5234). See the manifest.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${RUN_ID##*-}$$"
SFX="${SFX: -8}"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

SINK_CTR="ak-dtf${DTF_SLOT}-hook-sink"
SINK_IP="172.16.${DTF_SLOT}.79"
# Timing (#5661). The retry worker ticks every 30 s and the pre-fix sender
# waits 30 s per delivery, one at a time. DEAD_HOOKS x DEAD_UPLOADS rows to
# the black hole are queued first, so a pre-fix live delivery waits at least
# 4 x 5 x 30 s = 600 s. The fixed worker sends up to 8 endpoints in parallel
# and defers a failed endpoint's other rows, so the live delivery lands on the
# next pass, well inside LIVE_BOUND. The oracle waits LIVE_WAIT before
# deciding.
DEAD_HOOKS=4
DEAD_UPLOADS=5
LIVE_BOUND=120
LIVE_WAIT=150

# api <METHOD> <PATH> [JSON]: admin bearer call, sets CODE and BODY.
api(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2" 2>/dev/null)"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
sink_log(){
  docker exec "$SINK_CTR" python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/__log', timeout=5).read().decode())" 2>/dev/null || echo '[]'
}
# sink_count <port> <path-prefix>
sink_count(){ sink_log | jq --argjson p "$1" --arg s "$2" '[.[] | select(.port == $p and (.path | startswith($s)))] | length' 2>/dev/null || echo 0; }
upload(){ # <repo> <name>: PUT a small generic artifact, echoes the status
  printf 'webhook-delivery-fairness %s %s\n' "$SFX" "$2" > "${W}/a.bin"
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/octet-stream' --data-binary "@${W}/a.bin" \
    "${BASE}/api/v1/repositories/$1/artifacts/dl/$2" 2>/dev/null
}
mk_hook(){ # <name> <url> <repo-id> [secret]: echoes the webhook id
  local body
  body="$(jq -nc --arg n "$1" --arg u "$2" --arg r "$3" --arg s "${4:-}" \
    '{name:$n,url:$u,events:["artifact_uploaded"],repository_id:$r,enabled:true} + (if $s == "" then {} else {secret:$s} end)')"
  api POST /api/v1/webhooks "$body"
  is_2xx "$CODE" && jqr '.id // empty' <<<"$BODY"
}
# wait_live <path> <count> <seconds>: poll until <count> POSTs reached <path>;
# sets WAITED to the elapsed seconds (or the limit).
wait_live(){
  local start now
  start="$(date +%s)"
  while :; do
    now="$(date +%s)"; WAITED=$((now - start))
    [ "$(sink_count 80 "$1")" -ge "$2" ] 2>/dev/null && return 0
    [ "$WAITED" -ge "$3" ] && return 1
    sleep 2
  done
}

begin_suite "webhook-delivery-fairness"

# =============================================================================
begin_test "setup: admin session, a live and a dead-receiver generic repository, the sink answers"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "${ADMIN_USER:-admin}" --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(sink_log | jqr 'type')" = "array" ] || { infra_fail "the hook sink does not answer"; end_suite; }
R_LIVE="wdf-live-${SFX}"; R_DEAD="wdf-dead-${SFX}"
for k in "$R_LIVE" "$R_DEAD"; do
  api POST /api/v1/repositories "$(jq -nc --arg k "$k" '{key:$k,name:$k,format:"generic",repo_type:"local"}')"
  is_2xx "$CODE" || { infra_fail "creating ${k} answered ${CODE}: ${BODY:0:200}"; end_suite; }
done
api GET "/api/v1/repositories/${R_LIVE}"; LIVE_ID="$(jqr '.id // empty' <<<"$BODY")"
api GET "/api/v1/repositories/${R_DEAD}"; DEAD_ID="$(jqr '.id // empty' <<<"$BODY")"
[ -n "$LIVE_ID" ] && [ -n "$DEAD_ID" ] || { infra_fail "no repository ids"; end_suite; }
SECRET="whs-$(openssl rand -hex 16)"
LIVE_PATH="/hook/live-${SFX}"
HOOK_LIVE="$(mk_hook "wdf-live-${SFX}" "http://${SINK_IP}${LIVE_PATH}" "$LIVE_ID" "$SECRET")"
[ -n "$HOOK_LIVE" ] || { infra_fail "creating the live webhook answered ${CODE}: ${BODY:0:200}"; end_suite; }
pass

# =============================================================================
begin_test "CONTROL: with no backlog, an upload's delivery reaches the live receiver and its v1 signature verifies"
reset_case
c="$(upload "$R_LIVE" "first.bin")"
note "upload to ${R_LIVE}: ${c}"
is_2xx "$c" || fail_g "the upload answered ${c}"
if wait_live "$LIVE_PATH" 1 90; then
  note "first live delivery after ${WAITED}s"
else
  fail_g "no delivery reached the live receiver within 90 s (no backlog)"
fi
sink_log | jq -c --arg s "$LIVE_PATH" '[.[] | select(.port == 80 and .path == $s)][0] // empty' > "${W}/first.json"
SIGS="$(python3 - "${W}/first.json" "$SECRET" <<'PY'
import base64, hashlib, hmac, json, sys
try:
    e = json.load(open(sys.argv[1]))
except Exception:
    print("none none none none"); sys.exit(0)
key = sys.argv[2].encode(); body = base64.b64decode(e["body_b64"]); h = e["headers"]
ak = h.get("x-artifactkeeper-signature", "")
parts = dict(p.split("=", 1) for p in ak.split(",") if "=" in p)
t = parts.get("t", "")
v1 = [p.split("=", 1)[1] for p in ak.split(",") if p.startswith("v1=")]
want_v1 = hmac.new(key, t.encode() + b"." + body, hashlib.sha256).hexdigest()
body_only = "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
timestamped = "sha256=" + want_v1
legacy = h.get("x-webhook-signature", "")
print("v1ok" if want_v1 in v1 else "v1bad",
      "legacy_body" if legacy == body_only else ("legacy_timestamped" if legacy == timestamped else "legacy_other"),
      "t=" + (t or "none"), "legacy=" + (legacy[:20] or "none"))
PY
)"
note "signatures: ${SIGS}"
case "$SIGS" in v1ok*) ;; *) fail_g "the X-ArtifactKeeper-Signature v1 token does not verify over \"<t>.<body>\" (${SIGS})";; esac
finish_case "webhook delivery or its v1 signature is broken"

# =============================================================================
begin_test "FIX #5234: the legacy X-Webhook-Signature is sha256=HMAC(secret, body), not the timestamped value"
reset_case
note "signatures: ${SIGS}"
case "$SIGS" in
  *legacy_body*) ;;
  *legacy_timestamped*) fail_g "X-Webhook-Signature equals HMAC(secret, \"<t>.<body>\") (the v1 value); a receiver reading only this header cannot verify it";;
  *) fail_g "X-Webhook-Signature matches neither form (${SIGS})";;
esac
finish_case "the legacy webhook signature signs the timestamped value"

# =============================================================================
begin_test "FIX #5661: a backlog for receivers that never answer does not starve a live receiver"
reset_case
for i in $(seq 1 "$DEAD_HOOKS"); do
  id="$(mk_hook "wdf-dead${i}-${SFX}" "http://${SINK_IP}:81/hook/dead${i}-${SFX}" "$DEAD_ID")"
  [ -n "$id" ] || fail_g "creating dead webhook ${i} answered ${CODE}: ${BODY:0:160}"
done
for i in $(seq 1 "$DEAD_UPLOADS"); do
  c="$(upload "$R_DEAD" "dead-${i}.bin")"
  is_2xx "$c" || fail_g "upload ${i} to ${R_DEAD} answered ${c}"
done
# The worker must be busy on the backlog before the live event is raised.
start="$(date +%s)"; hang=0
while [ $(( $(date +%s) - start )) -lt 75 ]; do
  hang="$(sink_count 81 /hook/dead)"
  [ "$hang" -ge 1 ] 2>/dev/null && break
  sleep 2
done
note "$((DEAD_HOOKS * DEAD_UPLOADS)) deliveries queued for ${DEAD_HOOKS} black-hole webhooks; black hole reached ${hang} time(s) after $(( $(date +%s) - start ))s"
if [ "${hang:-0}" -lt 1 ] 2>/dev/null; then
  fail_g "the black hole never received a delivery, so the backlog was not in flight"
else
  c="$(upload "$R_LIVE" "second.bin")"
  is_2xx "$c" || fail_g "the live upload answered ${c}"
  if wait_live "$LIVE_PATH" 2 "$LIVE_WAIT"; then
    note "live delivery behind the backlog after ${WAITED}s (bound ${LIVE_BOUND}s); black hole reached $(sink_count 81 /hook/dead) time(s)"
    [ "$WAITED" -le "$LIVE_BOUND" ] || fail_g "the live delivery took ${WAITED}s, over the ${LIVE_BOUND}s bound"
  else
    note "black hole reached $(sink_count 81 /hook/dead) time(s)"
    fail_g "no live delivery within ${LIVE_WAIT}s behind the backlog (pre-#5749 the worker sends the oldest due rows one at a time with a 30 s timeout)"
  fi
fi
finish_case "one unreachable receiver starves every other webhook"

end_suite
