#!/usr/bin/env bash
# =============================================================================
# tiers/debian-encoded-separator/oracle.sh — Debian proxy encoded-separator
# rejection gate (#2562 / PR #2838), filesystem storage.
# =============================================================================
# Discriminating oracle for the Debian remote-proxy encoded-separator belt.
#
# Background (debian.rs::normalized_debian_relpath): the proxy normalizes each
# request before deciding what to fetch upstream. #2562 adds a default-on belt
# that refuses any request whose (once-decoded) path carries a percent-encoded
# path separator — %2f/%2F ('/') or %5c/%5C ('\') — mirroring the existing
# control-byte belt, so gate/fetch parity never depends on how a nonstandard
# upstream decodes the sequence.
#
# Topology: a Debian REMOTE repo with NO P2 filter (empty allowlist permits
# everything) pointing at a non-resolving `.invalid` upstream. With an empty
# filter the ONLY thing that can reject the encoded probe is the #2562 belt, so:
#   * a request the belt REJECTS returns 404 (debian_filter_denied);
#   * a request the belt LETS THROUGH reaches the fetch and fails fast with
#     502 Bad Gateway on the unreachable upstream.
#
# axum percent-decodes the catch-all segment once, so the client DOUBLE-encodes
# (%252f/%255c) to land a literal %2f/%5c at the belt.
#
# Asserts:
#   ENCODED %2f — GET .../binary-amd64/probe%252fx.gz -> 404 (belt deny).
#                 Pre-#2562: 502 (no belt; fetch attempted) -> FAIL.
#   ENCODED %5c — GET .../binary-amd64/probe%255cx.gz -> 404 (belt deny).
#                 Pre-#2562: 502 -> FAIL.
#   LEGIT       — GET .../binary-amd64/Packages.gz -> NOT 404 (reaches fetch;
#                 502 on the dead upstream). Positive control: the belt does not
#                 blanket-reject, so the encoded 404s above are the belt.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SUF="$RANDOM$RANDOM"
REPO="debenc$SUF"
UPSTREAM="http://debian-upstream-dtf-$SUF.invalid/"   # never resolves -> fast 502

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }

begin_suite "debian-encoded-separator-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

# Remote debian repo with an unreachable upstream and no P2 filter.
CR=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"debian\",\"repo_type\":\"remote\",\"upstream_url\":\"$UPSTREAM\"}")
echo "-- create remote debian repo '$REPO' (upstream $UPSTREAM) -> HTTP $CR"

DPATH="dists/bookworm/main/binary-amd64"
probe(){ curl -s --max-time 25 -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/debian/$REPO/$1"; }

SETUP_OK=1
if [ "$CR" != "200" ] && [ "$CR" != "201" ]; then
  SETUP_OK=0
fi

# ---------------------------------------------------------------------------
begin_test "LEGIT dists path is NOT rejected by the belt (reaches the fetch; 502 on the dead upstream) — control"
if [ "$SETUP_OK" != "1" ]; then
  fail "skipped: remote debian repo create failed (HTTP $CR)"
else
  LEGIT=$(probe "$DPATH/Packages.gz")
  echo "-- legit  $DPATH/Packages.gz -> HTTP $LEGIT (expect NOT 404; typically 502)"
  if [ "$LEGIT" != "404" ] && [ "$LEGIT" != "000" ]; then
    pass
  else
    fail "legit dists path returned HTTP $LEGIT; the belt must not blanket-reject (and the upstream must be reachable enough to 502, not hang)"
  fi
fi

# ---------------------------------------------------------------------------
begin_test "ENCODED %2f (double-encoded %252f) dists path is REJECTED by the belt -> 404 (#2562)"
if [ "$SETUP_OK" != "1" ]; then
  fail "skipped: remote debian repo create failed (HTTP $CR)"
else
  ENC2F=$(probe "$DPATH/probe%252fx.gz")
  echo "-- %2f    $DPATH/probe%252fx.gz -> HTTP $ENC2F (fixed=404 belt; pre-#2562=502 fetch)"
  if [ "$ENC2F" = "404" ]; then
    pass
  else
    fail "encoded-separator (%2f) path returned HTTP $ENC2F, expected 404 (belt deny). Pre-#2562 the belt is absent and the request reaches the upstream fetch -> 502"
  fi
fi

# ---------------------------------------------------------------------------
begin_test "ENCODED %5c (double-encoded %255c) dists path is REJECTED by the belt -> 404 (#2562)"
if [ "$SETUP_OK" != "1" ]; then
  fail "skipped: remote debian repo create failed (HTTP $CR)"
else
  ENC5C=$(probe "$DPATH/probe%255cx.gz")
  echo "-- %5c    $DPATH/probe%255cx.gz -> HTTP $ENC5C (fixed=404 belt; pre-#2562=502 fetch)"
  if [ "$ENC5C" = "404" ]; then
    pass
  else
    fail "encoded-separator (%5c) path returned HTTP $ENC5C, expected 404 (belt deny). Pre-#2562 the belt is absent and the request reaches the upstream fetch -> 502"
  fi
fi

end_suite
