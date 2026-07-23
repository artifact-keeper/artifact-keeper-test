#!/usr/bin/env bash
# =============================================================================
# tiers/f7qf-peer-authz/oracle.sh — peer data-plane authorization gap (GHSA-f7qf)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# The bug (GHSA-f7qf): the /api/v1/peers/* MUTATING data-plane routes had
# authentication (auth_middleware) but NO authorization. Any authenticated
# non-admin could mutate federation transfer/chunk/connection state. The fix
# adds `auth.require_admin()?` to the 9 mutating handlers -> non-admin 403.
#
# Discriminating gates, ALL must hold on the FIXED image:
#   (BOUNDARY) a NON-admin token on each mutating peer route -> 403. On the
#              vulnerable baseline the request reaches the handler (2xx/404/500,
#              never 403) = the authz bypass. 403 == GREEN, anything else == RED.
#   (CONTROL)  admin on the same route -> NOT 403 (authz passes);
#              non-admin read GET /:id/connections -> 200 (not over-restricted);
#              anon on a mutating route -> 401.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
USER="f7qf-user-${DTF_SLOT:-x}-${SUF}"
USER_PASS="F7qf_${SUF}_Aa1!"

# Fresh UUIDs — no peer/artifact need exist; the authz guard fires ahead of the
# handler body, so existence is irrelevant to the boundary.
PEER_ID="$(cat /proc/sys/kernel/random/uuid)"
TARGET_ID="$(cat /proc/sys/kernel/random/uuid)"
ARTIFACT_ID="$(cat /proc/sys/kernel/random/uuid)"

# --- curl helpers -----------------------------------------------------------
# http_code METHOD URL AUTH_HEADER [JSON_BODY]
#   AUTH_HEADER may be empty for the anonymous probe.
http_code() {
  local m="$1" url="$2" hdr="$3" body="${4:-}"
  local args=(-s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m")
  [ -n "$hdr" ] && args+=(-H "$hdr")
  if [ -n "$body" ]; then
    args+=(-H 'Content-Type: application/json' --data-binary "$body")
  fi
  curl "${args[@]}" "$url" 2>/dev/null || echo 000
}

begin_suite "f7qf-peer-data-plane-authz"

# --- setup: admin token, one plain non-admin user + token -------------------
auth_admin   # sets ADMIN_TOKEN

USER_ID="$(create_test_user_with_retry "$USER" "$USER_PASS" "${USER}@t.test")" || true
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  begin_test "setup: create non-admin user"
  fail "could not create non-admin user ${USER}"
  end_suite
fi

USER_TOKEN="$(login_as "$USER" "$USER_PASS")" || true
if [ -z "$USER_TOKEN" ]; then
  begin_test "setup: login non-admin user"
  fail "could not log in as ${USER}"
  end_suite
fi

NONADMIN_HDR="Authorization: Bearer ${USER_TOKEN}"
ADMIN_HDR="Authorization: Bearer ${ADMIN_TOKEN}"

# The 3 representative mutating routes (one per data-plane family):
#   name | METHOD | URL | JSON body
INIT_URL="${BASE_URL}/api/v1/peers/${PEER_ID}/transfer/init"
INIT_BODY="{\"artifact_id\":\"${ARTIFACT_ID}\",\"chunk_size\":1024}"
UNREACH_URL="${BASE_URL}/api/v1/peers/${PEER_ID}/connections/${TARGET_ID}/unreachable"
CHUNK_URL="${BASE_URL}/api/v1/peers/${PEER_ID}/chunks/${ARTIFACT_ID}"
CHUNK_BODY="{\"chunk_bitmap\":[1],\"total_chunks\":1}"

# ---------------------------------------------------------------------------
# (BOUNDARY) non-admin on each mutating route -> 403 (GREEN); baseline reaches
#            the handler (non-403) = the authz bypass this tier catches.
# ---------------------------------------------------------------------------
boundary_case() { # NAME METHOD URL [BODY]
  local name="$1" m="$2" url="$3" body="${4:-}"
  begin_test "BOUNDARY: non-admin ${m} ${name} -> 403 (require_admin authz denies before handler)"
  local code
  code="$(http_code "$m" "$url" "$NONADMIN_HDR" "$body")"
  if [ "$code" = "403" ]; then
    pass
  elif [ "$code" = "401" ]; then
    fail "non-admin ${name} returned 401 (unauthenticated) — the token should authenticate; expected 403 authz-denied" \
         "route=${name} code=${code}"
  else
    fail "AUTHZ BYPASS (GHSA-f7qf): non-admin ${m} ${name} returned ${code}, expected 403. A non-admin reached the peer data-plane handler (baseline had NO require_admin on this route)." \
         "route=${name} code=${code} user=${USER}"
  fi
}

boundary_case "/:id/transfer/init"                      POST "$INIT_URL"    "$INIT_BODY"
boundary_case "/:id/connections/:target/unreachable"    POST "$UNREACH_URL" ""
boundary_case "/:id/chunks/:artifact_id"                PUT  "$CHUNK_URL"   "$CHUNK_BODY"

# ---------------------------------------------------------------------------
# (CONTROL) admin on the same routes -> NOT 403 (authz passes; handler may
#           404/500 on the synthetic ids, but never authz-denies an admin).
# ---------------------------------------------------------------------------
control_admin() { # NAME METHOD URL [BODY]
  local name="$1" m="$2" url="$3" body="${4:-}"
  begin_test "CONTROL: admin ${m} ${name} -> passes authz (not 403)"
  local code
  code="$(http_code "$m" "$url" "$ADMIN_HDR" "$body")"
  if [ "$code" = "403" ]; then
    fail "admin ${name} returned 403 — the admin guard must let admins through; over-restriction regression" \
         "route=${name} code=${code}"
  elif [ "$code" = "401" ]; then
    fail "admin ${name} returned 401 — admin token should authenticate" "route=${name} code=${code}"
  else
    pass
  fi
}

control_admin "/:id/transfer/init"                   POST "$INIT_URL"    "$INIT_BODY"
control_admin "/:id/connections/:target/unreachable" POST "$UNREACH_URL" ""
control_admin "/:id/chunks/:artifact_id"             PUT  "$CHUNK_URL"   "$CHUNK_BODY"

# ---------------------------------------------------------------------------
# (CONTROL) non-admin READ GET /:id/connections -> 200. The fix gates only the
#           9 mutating handlers; the read list must stay non-admin readable
#           (proves the boundary isn't a blanket admin-only on /peers).
# ---------------------------------------------------------------------------
begin_test "CONTROL: non-admin GET /:id/connections -> 200 (read not over-restricted by the fix)"
GET_CODE="$(http_code GET "${BASE_URL}/api/v1/peers/${PEER_ID}/connections" "$NONADMIN_HDR")"
if [ "$GET_CODE" = "200" ]; then
  pass
else
  fail "non-admin GET /:id/connections returned ${GET_CODE}, expected 200 (the read list must remain non-admin accessible)" \
       "code=${GET_CODE}"
fi

# ---------------------------------------------------------------------------
# (CONTROL) anonymous on a mutating route -> 401 (auth_middleware still guards
#           the whole /peers surface; authz sits on top of authn, not instead).
# ---------------------------------------------------------------------------
begin_test "CONTROL: anonymous POST /:id/transfer/init -> 401 (auth_middleware guards /peers)"
ANON_CODE="$(http_code POST "$INIT_URL" "" "$INIT_BODY")"
if [ "$ANON_CODE" = "401" ]; then
  pass
else
  fail "anonymous transfer/init returned ${ANON_CODE}, expected 401 (auth_middleware must reject anon)" \
       "code=${ANON_CODE}"
fi

end_suite
