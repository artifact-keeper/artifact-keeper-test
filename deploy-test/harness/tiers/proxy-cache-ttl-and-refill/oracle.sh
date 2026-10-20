#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-cache-ttl-and-refill/oracle.sh
#   #3832 lowering a Remote's cache TTL applies to entries already cached
#   #4120 Go @v/<ver>.info/.mod/.zip are cached immutable; @v/list stays mutable
#   #4298 requests landing while an expired entry is being refilled send no
#         second upstream request
#   #4339 Cargo pull-through fetches a crate under its canonical (mixed-case)
#         name
#   #4431 an age-gated npm packument with mixed numeric / hash prereleases is
#         served (the version sort no longer panics)
#   #4432 the age gate keeps the publisher's npm `latest` when it is allowed,
#         and repoints a blocked one to the newest allowed release below it
# See the manifest for the bugs, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH, DTF_DIR.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- mock upstream control (profiles/upstreams.mock-files.yml) -----------------
mock_put(){ # <path> <file> [content-type] -> stored byte count
  curl -s --max-time 30 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}
# up_n <path>: total upstream requests (GET + HEAD) seen for <path>
up_n(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '(.get // 0) + (.head // 0)'; }
up_get(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get // empty'; }
up_head(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.head // empty'; }

auth(){ printf 'Authorization: Bearer %s' "$TOK"; }
# fetch <url> <out> -> http code ("000" on a dropped connection)
fetch(){
  local c
  rm -f "$2"
  c="$(curl -s --max-time 60 -o "$2" -w '%{http_code}' -H "$(auth)" "$1" 2>/dev/null || true)"
  [ -f "$2" ] || : > "$2"
  echo "${c:-000}"
}
set_ttl(){ # <repo> <secs> -> echoed cache_ttl_seconds
  curl -s -X PUT -H "$(auth)" -H 'Content-Type: application/json' \
    -d "{\"cache_ttl_seconds\":$2}" "$BASE/api/v1/repositories/$1/cache-ttl" | jqr '.cache_ttl_seconds // empty'
}

# =============================================================================
begin_suite "proxy-cache-ttl-and-refill"

begin_test "setup: admin login, upstream files on the mock, generic / Go / Cargo / npm Remotes"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
R_TTL="pct-ttl-${SUF}"      # generic Remote, TTL 3600 then lowered to 2
R_REF="pct-refill-${SUF}"   # generic Remote, TTL 5, the refill burst
R_GO="pct-go-${SUF}"        # Go Remote, TTL 1
R_CARGO="pct-cargo-${SUF}"  # Cargo Remote
R_NPM="pct-npm-${SUF}"      # npm Remote with a 7-day age gate
mk(){ # <key> <format> <upstream> -> key
  curl -s -X POST "$BASE/api/v1/repositories" -H "$(auth)" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg f "$2" --arg u "$3" '{key:$k,name:$k,format:$f,repo_type:"remote",is_public:false,upstream_url:$u}')" \
    | jqr '.key // empty'
}
SETUP_ERR=""
# generic files
printf '{"index":"v1","dtf":"%s"}\n' "$SUF" > "$W/index.json"
[ -n "$(mock_put "/g/i/index-${SUF}.json" "$W/index.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:index"
REFILL_BYTES=40000000   # big enough that the refill's tail (fsync, rename, sidecar) is a real window
head -c "$REFILL_BYTES" /dev/urandom > "$W/refill.v1"
head -c "$REFILL_BYTES" /dev/urandom > "$W/refill.v2"
[ "$(mock_put "/g/r/blob-${SUF}.bin" "$W/refill.v1")" = "$REFILL_BYTES" ] || SETUP_ERR="${SETUP_ERR} mock:refill"
# Go module files (lowercase module path: no case-encoding involved)
MOD="example.com/dtf/m${DTF_SLOT}x$$"
printf '{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}\n' > "$W/go.info"
printf 'v1.0.0\n' > "$W/go.list"
[ -n "$(mock_put "/go/${MOD}/@v/v1.0.0.info" "$W/go.info" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:go.info"
[ -n "$(mock_put "/go/${MOD}/@v/list" "$W/go.list" text/plain)" ] || SETUP_ERR="${SETUP_ERR} mock:go.list"
# Cargo: crates.io serves a crate only under its canonical name since 2023-12-18,
# so the mock holds Inflector under its canonical spelling and nothing under the
# lowercase one; dtfcrate is the all-lowercase control.
head -c 2000 /dev/urandom > "$W/inflector.crate"
head -c 2000 /dev/urandom > "$W/lower.crate"
[ -n "$(mock_put "/cargo/api/v1/crates/Inflector/0.11.4/download" "$W/inflector.crate")" ] || SETUP_ERR="${SETUP_ERR} mock:Inflector"
[ -n "$(mock_put "/cargo/api/v1/crates/dtfcrate/1.0.0/download" "$W/lower.crate")" ] || SETUP_ERR="${SETUP_ERR} mock:dtfcrate"
# npm packuments (fixtures/packuments.py)
P_MIXED="dtfmixed${DTF_SLOT}x$$"; P_KEEP="dtfkeep${DTF_SLOT}x$$"; P_REPOINT="dtfrepoint${DTF_SLOT}x$$"
for kind in mixed keep repoint; do
  case "$kind" in mixed) n="$P_MIXED";; keep) n="$P_KEEP";; *) n="$P_REPOINT";; esac
  python3 -I "${HERE}/fixtures/packuments.py" "$kind" "$n" "$UP" > "$W/${kind}.json" 2>/dev/null || true
  [ -n "$(mock_put "/npm/${n}" "$W/${kind}.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:${kind}"
done

[ "$(mk "$R_TTL" generic "${UP}/g/")" = "$R_TTL" ] || SETUP_ERR="${SETUP_ERR} ${R_TTL}"
[ "$(mk "$R_REF" generic "${UP}/g/")" = "$R_REF" ] || SETUP_ERR="${SETUP_ERR} ${R_REF}"
[ "$(mk "$R_GO" go "${UP}/go/")" = "$R_GO" ] || SETUP_ERR="${SETUP_ERR} ${R_GO}"
[ "$(mk "$R_CARGO" cargo "${UP}/cargo/")" = "$R_CARGO" ] || SETUP_ERR="${SETUP_ERR} ${R_CARGO}"
[ "$(mk "$R_NPM" npm "${UP}/npm/")" = "$R_NPM" ] || SETUP_ERR="${SETUP_ERR} ${R_NPM}"
[ "$(set_ttl "$R_TTL" 3600)" = "3600" ] || SETUP_ERR="${SETUP_ERR} ttl:${R_TTL}"
[ "$(set_ttl "$R_REF" 5)" = "5" ] || SETUP_ERR="${SETUP_ERR} ttl:${R_REF}"
[ "$(set_ttl "$R_GO" 1)" = "1" ] || SETUP_ERR="${SETUP_ERR} ttl:${R_GO}"
gate="$(curl -s -X PUT -H "$(auth)" -H 'Content-Type: application/json' -d '{"enabled":true,"min_age_days":7}' \
  "$BASE/api/v1/repositories/${R_NPM}/age-gate" | jqr '.enabled // empty')"
[ "$gate" = "true" ] || SETUP_ERR="${SETUP_ERR} age-gate"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- upstream ${UP}; remotes ${R_TTL} ${R_REF} ${R_GO} ${R_CARGO} ${R_NPM}"
pass

# =============================================================================
# #3832: TTL lowered after caching.
# =============================================================================
IDX="/g/i/index-${SUF}.json"
IDX_URL="$BASE/api/v1/repositories/${R_TTL}/download/i/index-${SUF}.json"
begin_test "CONTROL: under a 3600 s TTL a cached generic entry is served from cache (no upstream request)"
reset_case
code="$(fetch "$IDX_URL" "$W/o.json")"
[ "$code" = "200" ] || fail_g "cold GET answered ${code}"
[ "$(sha_of "$W/o.json")" = "$(sha_of "$W/index.json")" ] || fail_g "cold GET body is not the upstream's"
sleep 2
before="$(up_n "$IDX")"
code="$(fetch "$IDX_URL" "$W/o.json")"
after="$(up_n "$IDX")"
[ "$code" = "200" ] || fail_g "warm GET answered ${code}"
[ "$before" = "$after" ] || fail_g "warm GET under a 3600 s TTL reached upstream (${before} -> ${after})"
note "upstream requests ${before} -> ${after}"
finish_case "the warm-cache control did not hold"

begin_test "FIX #3832: lowering the TTL to 2 s makes the already-cached entry revalidate upstream; the revalidation re-anchors it"
reset_case
[ "$(set_ttl "$R_TTL" 2)" = "2" ] || fail_g "PUT cache-ttl 2 was not applied"
sleep 4
before="$(up_n "$IDX")"
code="$(fetch "$IDX_URL" "$W/o.json")"
mid="$(up_n "$IDX")"
code2="$(fetch "$IDX_URL" "$W/o2.json")"
after="$(up_n "$IDX")"
note "upstream requests: ${before} -> ${mid} (read after lowering) -> ${after} (next read)"
[ "$code" = "200" ] && [ "$(sha_of "$W/o.json")" = "$(sha_of "$W/index.json")" ] || fail_g "read after lowering answered ${code} or the wrong body"
[ "$((${mid:-0} - ${before:-0}))" = "1" ] || fail_g "the read after lowering the TTL made $((${mid:-0} - ${before:-0})) upstream requests, expected 1 revalidation (1.10.0 trusts the stamped 3600 s expiry: #3832)"
[ "$code2" = "200" ] || fail_g "the next read answered ${code2}"
[ "$mid" = "$after" ] || fail_g "the read right after the revalidation reached upstream again (${mid} -> ${after}); the 304 did not re-anchor the entry"
finish_case "a lowered TTL is not applied to an already-cached entry"

# =============================================================================
# #4120: Go immutable vs mutable.
# =============================================================================
GO_URL="$BASE/go/${R_GO}/${MOD}/@v"
begin_test "CONTROL: a Go Remote serves @v/v1.0.0.info and @v/list, and a mutable @v/list is revalidated after the 1 s TTL"
reset_case
code="$(fetch "${GO_URL}/v1.0.0.info" "$W/go.info.o")"
[ "$code" = "200" ] && [ "$(sha_of "$W/go.info.o")" = "$(sha_of "$W/go.info")" ] || fail_g "@v/v1.0.0.info answered ${code} or the wrong body"
code="$(fetch "${GO_URL}/list" "$W/go.list.o")"
[ "$code" = "200" ] && [ "$(sha_of "$W/go.list.o")" = "$(sha_of "$W/go.list")" ] || fail_g "@v/list answered ${code} or the wrong body"
sleep 3
before="$(up_n "/go/${MOD}/@v/list")"
code="$(fetch "${GO_URL}/list" "$W/go.list.o")"
after="$(up_n "/go/${MOD}/@v/list")"
note "@v/list upstream requests ${before} -> ${after}"
[ "$code" = "200" ] || fail_g "@v/list after the TTL answered ${code}"
[ "$((${after:-0} - ${before:-0}))" -ge 1 ] || fail_g "@v/list after the 1 s TTL was not revalidated upstream (${before} -> ${after})"
finish_case "the Go mutable-path control did not hold"

begin_test "FIX #4120: a canonical-version @v/v1.0.0.info is cached immutable: past the 1 s TTL it is not re-fetched upstream"
reset_case
before="$(up_n "/go/${MOD}/@v/v1.0.0.info")"
code="$(fetch "${GO_URL}/v1.0.0.info" "$W/go.info.o")"
after="$(up_n "/go/${MOD}/@v/v1.0.0.info")"
note "@v/v1.0.0.info upstream requests ${before} -> ${after} (first fetch was > 3 s ago)"
[ "$code" = "200" ] && [ "$(sha_of "$W/go.info.o")" = "$(sha_of "$W/go.info")" ] || fail_g "@v/v1.0.0.info answered ${code} or the wrong body"
[ "$before" = "$after" ] || fail_g "@v/v1.0.0.info went upstream again after the TTL (${before} -> ${after}); 1.10.0 stamps it with the mutable TTL (#4120)"
finish_case "a versioned Go module file is treated as mutable"

# =============================================================================
# #4298: the expired refill.
# =============================================================================
REF="/g/r/blob-${SUF}.bin"
REF_URL="$BASE/api/v1/repositories/${R_REF}/download/r/blob-${SUF}.bin"
begin_test "CONTROL: an expired entry whose upstream bytes changed is refetched and the new bytes are served"
reset_case
code="$(fetch "$REF_URL" "$W/ref.o")"
[ "$code" = "200" ] && [ "$(sha_of "$W/ref.o")" = "$(sha_of "$W/refill.v1")" ] || fail_g "prime GET answered ${code} or the wrong body"
[ "$(mock_put "$REF" "$W/refill.v2")" = "$REFILL_BYTES" ] || fail_g "could not replace the upstream bytes"
sleep 7   # past the 5 s TTL
g0="$(up_get "$REF")"; h0="$(up_head "$REF")"
# The refilling GET, then AT ONCE (no probe in between: the window is the
# refill's tail, a few hundred ms after the client has its last byte) a burst
# of 15 concurrent GETs. The FIX case below judges the burst.
code="$(fetch "$REF_URL" "$W/ref.o")"
for i in $(seq 2 16); do
  ( fetch "$REF_URL" "$W/burst.${i}" > "$W/burst.${i}.code" ) &
done
wait
[ "$code" = "200" ] && [ "$(sha_of "$W/ref.o")" = "$(sha_of "$W/refill.v2")" ] || fail_g "the read after expiry answered ${code} or did not carry the new upstream bytes"
note "upstream GET ${g0} HEAD ${h0} before the refill"
finish_case "an expired, changed entry was not refetched"

begin_test "FIX #4298: 15 concurrent GETs fired as the refill returns add no upstream request beyond the one refetch, and all get the new bytes"
reset_case
sleep 1
g2="$(up_get "$REF")"; h2="$(up_head "$REF")"
bad=0
for i in $(seq 2 16); do
  if [ "$(cat "$W/burst.${i}.code" 2>/dev/null)" != "200" ] || [ "$(sha_of "$W/burst.${i}")" != "$(sha_of "$W/refill.v2")" ]; then
    bad=$((bad+1))
  fi
done
dg=$((${g2:-0} - ${g0:-0})); dh=$((${h2:-0} - ${h0:-0}))
note "refill + burst of 15: upstream GET ${g0} -> ${g2} (+${dg}), HEAD ${h0} -> ${h2} (+${dh}); bad responses ${bad}/15"
[ "$dg" = "1" ] || fail_g "refill + burst made ${dg} upstream GETs, expected exactly 1 (the refetch); a request in the refill's tail saw the expired sidecar and fetched again (#4298)"
[ "$dh" -le 1 ] || fail_g "refill + burst made ${dh} upstream HEADs, expected at most the refill's one revalidation (#4298)"
[ "$bad" = "0" ] || fail_g "${bad} of 15 burst responses were not 200 with the new bytes"
finish_case "a request during the expired refill went upstream a second time"

# =============================================================================
# #4339: Cargo canonical crate name.
# =============================================================================
begin_test "CONTROL: a lowercase-named crate downloads through the Cargo Remote"
reset_case
code="$(fetch "$BASE/cargo/${R_CARGO}/api/v1/crates/dtfcrate/1.0.0/download" "$W/lower.o")"
[ "$code" = "200" ] && [ "$(sha_of "$W/lower.o")" = "$(sha_of "$W/lower.crate")" ] || fail_g "dtfcrate download answered ${code} or the wrong body"
finish_case "the lowercase crate control did not hold"

begin_test "FIX #4339: a crate with a mixed-case canonical name (Inflector) is fetched upstream under that name and served"
reset_case
code="$(fetch "$BASE/cargo/${R_CARGO}/api/v1/crates/Inflector/0.11.4/download" "$W/infl.o")"
canon="$(up_n "/cargo/api/v1/crates/Inflector/0.11.4/download")"
lower="$(up_n "/cargo/api/v1/crates/inflector/0.11.4/download")"
note "HTTP ${code}; upstream requests canonical=${canon} lowercase=${lower}"
[ "$code" = "200" ] && [ "$(sha_of "$W/infl.o")" = "$(sha_of "$W/inflector.crate")" ] || fail_g "Inflector download answered ${code} or the wrong body (1.10.0 asks upstream for 'inflector' and gets 404: #4339)"
[ "${canon:-0}" -ge 1 ] || fail_g "upstream was never asked for /api/v1/crates/Inflector/0.11.4/download"
[ "${lower:-0}" = "0" ] || fail_g "upstream was asked for the lowercase spelling ${lower} time(s)"
finish_case "a mixed-case crate cannot be pulled through"

# =============================================================================
# #4431 / #4432: npm age gate.
# =============================================================================
begin_test "CONTROL: the 7-day age gate removes a version published today and keeps an allowed dist-tag"
reset_case
code="$(fetch "$BASE/npm/${R_NPM}/${P_KEEP}" "$W/keep.o")"
[ "$code" = "200" ] || fail_g "gated packument answered ${code}"
vers="$(jq -c '.versions | keys' "$W/keep.o" 2>/dev/null || true)"
nxt="$(jqr '.["dist-tags"].next // empty' < "$W/keep.o")"
note "versions ${vers}; next=${nxt}"
[ "$vers" = '["1.0.0","1.1.0","2.0.0-beta.1"]' ] || fail_g "versions after the gate = ${vers}, expected 1.2.0 (published today) removed"
[ "$nxt" = "2.0.0-beta.1" ] || fail_g "the allowed 'next' tag was not kept (got '${nxt}')"
finish_case "the age gate control did not hold"

begin_test "FIX #4432: the gate keeps the publisher's allowed latest (1.1.0), not the newer allowed prerelease"
reset_case
lat="$(jqr '.["dist-tags"].latest // empty' < "$W/keep.o")"
note "latest=${lat}"
[ "$lat" = "1.1.0" ] || fail_g "dist-tags.latest = '${lat}', expected the publisher's 1.1.0 (1.10.0 overwrites it with the newest allowed version, 2.0.0-beta.1: #4432)"
finish_case "the gate does not keep an allowed latest"

begin_test "FIX #4432: a blocked latest (1.2.0, published today) is repointed to the newest allowed release at or below it (1.1.0)"
reset_case
code="$(fetch "$BASE/npm/${R_NPM}/${P_REPOINT}" "$W/repoint.o")"
lat="$(jqr '.["dist-tags"].latest // empty' < "$W/repoint.o")"
vers="$(jq -c '.versions | keys' "$W/repoint.o" 2>/dev/null || true)"
note "HTTP ${code}; latest=${lat}; versions ${vers}"
[ "$code" = "200" ] || fail_g "gated packument answered ${code}"
[ "$lat" = "1.1.0" ] || fail_g "dist-tags.latest = '${lat}', expected 1.1.0 (1.10.0 picks the newest allowed version, the prerelease 2.0.0-beta.1: #4432)"
finish_case "a blocked latest is repointed to a prerelease"

begin_test "FIX #4431: an age-gated packument with 45 mixed numeric / hash prereleases is served whole"
reset_case
code="$(fetch "$BASE/npm/${R_NPM}/${P_MIXED}" "$W/mixed.o")"
n="$(jq '.versions | length' "$W/mixed.o" 2>/dev/null || true)"
lat="$(jqr '.["dist-tags"].latest // empty' < "$W/mixed.o")"
note "HTTP ${code}; versions ${n:-none}; latest ${lat}"
[ "$code" = "200" ] || fail_g "the packument answered ${code} (000 = connection dropped: 1.10.0's version sort panics, #4431)"
[ "$n" = "45" ] || fail_g "the packument carries ${n:-no} versions, expected all 45 (all published 2020)"
[ "$lat" = "1.0.11" ] || fail_g "dist-tags.latest = '${lat}', expected 1.0.11"
finish_case "a mixed-prerelease packument is not served through the age gate"

end_suite
