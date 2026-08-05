#!/usr/bin/env bash
# =============================================================================
# tiers/nuget-remote-search/oracle.sh — NuGet remote-repo search proxy gate
# (discussion #3130), filesystem storage + mocknuget-search upstream.
# =============================================================================
# Discriminating oracle: a REMOTE NuGet repo points at a mock upstream that
# advertises SearchQueryService and really filters on `q`. Searching the remote
# repo through AK must return the upstream's hits.
#
# Background (api/handlers/nuget.rs::search_packages): a remote NuGet repo
# advertises SearchQueryService in ITS OWN service index but pre-fix answered
# from the local `artifacts` table only (`effective_local_repo_ids` returns just
# the repo for a non-Virtual repo, and filters Remote members out of a Virtual
# one). `NugetUpstreamResources` never parsed SearchQueryService at all, so
# there was no search analogue of `proxy_v3_registration`. A proxy repo with
# nothing cached therefore answered every query `{"totalHits":0,"data":[]}` —
# "No packages found" in Visual Studio — while `dotnet restore` against the SAME
# repo worked, because registration/flat-container DO proxy upstream.
#
# The upstream is `mock-nuget-search` on the slot's private subnet (see
# profiles/upstreams.mocknuget-search.yml). It is NOT loopback: pointing
# upstream_url at 127.0.0.1 is refused by the connect-time SSRF guard
# (is_blocked_resolved_ip, #1832/#2570), and a private IP needs the profile's
# UPSTREAM_ALLOW_PRIVATE_IPS escape hatch even to be accepted at repo-create.
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

# Upstream as seen FROM THE BACKEND CONTAINER (compose service name).
UPSTREAM="http://mock-nuget-search/v3/index.json"

# Fixture ids served by fixtures/mock_nuget_search.py.
MARKER="dtf.searchmarker"        # matches 2 catalogue entries
UNRELATED="unrelated.package"    # matches 1, and NOT the marker query

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }

REPO="nugetproxy$SUF"

FAILS=0
pass(){ echo "     => $1 PASS"; }
fail(){ FAILS=$((FAILS+1)); echo "     => $1 FAIL -- $2" >&2; }

# --- setup -------------------------------------------------------------------
TOK="$(login admin "$ADMIN_PASS")"
[ -n "$TOK" ] || { echo "admin login failed" >&2; exit 1; }
AUTH="Authorization: Bearer $TOK"

code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"nuget\",\"repo_type\":\"remote\",\"upstream_url\":\"$UPSTREAM\",\"is_public\":true}")"
case "$code" in
  200|201) ;;
  *) echo "could not create remote nuget repo $REPO against $UPSTREAM (HTTP $code)" >&2
     echo "hint: needs profile upstreams.mocknuget-search (private-IP escape hatch)" >&2
     exit 1 ;;
esac

# raw <query-string> -> the raw search response body
raw(){ curl -s --max-time 60 "$BASE/nuget/$REPO/v3/search?$1"; }

# ids_for <query-string> -> newline-separated lowercased ids, or the token
# BADJSON if the response was not parseable
ids_for(){
  local body; body="$(raw "$1")"
  printf '%s' "$body" | jq -e . >/dev/null 2>&1 || { echo "BADJSON"; return; }
  printf '%s' "$body" | jq -r '[.data[]?.id // empty] | map(ascii_downcase) | .[]' 2>/dev/null
}

# total_for <query-string> -> totalHits (falls back to data length), -1 if unusable
total_for(){
  local body; body="$(raw "$1")"
  printf '%s' "$body" | jq -e . >/dev/null 2>&1 || { echo "-1"; return; }
  printf '%s' "$body" | jq -r '.totalHits // (.data|length) // -1' 2>/dev/null || echo "-1"
}

echo "=== #3130 NuGet remote search: repo=$REPO upstream=$UPSTREAM ==="

# --- P1: the repo advertises SearchQueryService -------------------------------
# AK advertising search but serving nothing is the shape of the bug, so pin the
# advertisement explicitly rather than assuming it.
adv="$(curl -s --max-time 60 "$BASE/nuget/$REPO/v3/index.json" \
  | jqr '[.resources[]? | select(."@type"=="SearchQueryService") | ."@id"][0]')"
if [ -n "$adv" ] && [ "$adv" != "null" ]; then pass "P1 (repo advertises SearchQueryService)"
else fail "P1" "remote repo advertises no SearchQueryService (@id=$adv)"; fi

# --- P2: a matching query returns the upstream's hits (THE GATE) --------------
mapfile -t got < <(ids_for "q=${MARKER}&take=20")
if [ "${got[0]:-}" = "BADJSON" ]; then
  fail "P2" "search response was not valid JSON"
elif printf '%s\n' "${got[@]}" | grep -qi "^${MARKER}$"; then
  pass "P2 (remote search proxied upstream: ${#got[@]} hit(s))"
else
  fail "P2" "query q=${MARKER} returned [${got[*]:-<none>}] -- search is NOT proxied upstream (#3130)"
fi

# --- P3: a non-matching query returns zero ------------------------------------
# A fix that forwards the request but drops `q`, or blanket-returns the upstream
# catalogue, must not pass.
t="$(total_for "q=nomatch${SUF}&take=20")"
if [ "$t" = "0" ]; then pass "P3 (non-matching query returns 0)"
else fail "P3" "q=nomatch${SUF} returned totalHits=$t (expected 0)"; fi

# --- P4: distinct queries must not share a cached response --------------------
# The proxied response is fetched through the proxy cache. A cache key that does
# not encode the query parameters serves query A's payload for query B — silent
# cross-query corruption, worse than the bug being fixed. Issue a DIFFERENT
# real query, then re-issue the marker query and require the results to still
# differ appropriately.
mapfile -t other < <(ids_for "q=${UNRELATED}&take=20")
mapfile -t again < <(ids_for "q=${MARKER}&take=20")
if [ "${other[0]:-}" = "BADJSON" ] || [ "${again[0]:-}" = "BADJSON" ]; then
  fail "P4" "search response was not valid JSON on the cache-key probe"
elif printf '%s\n' "${other[@]}" | grep -qi "^${MARKER}$"; then
  fail "P4" "q=${UNRELATED} returned the marker [${other[*]}] -- proxied search cache key does not encode query params"
elif ! printf '%s\n' "${again[@]}" | grep -qi "^${MARKER}$"; then
  fail "P4" "after a different query, q=${MARKER} returned [${again[*]:-<none>}] -- cached response leaked across queries"
else
  pass "P4 (per-query cache key holds)"
fi

echo "=== #3130 result: $FAILS failure(s) ==="
[ "$FAILS" -eq 0 ] || exit 1
exit 0
