#!/usr/bin/env bash
# =============================================================================
# tiers/composer-virtual-packagist-member/oracle.sh - artifact-keeper#4951
# =============================================================================
# See manifest. One non-scanning Composer Remote over the mock's Packagist
# shape, a Virtual with it as the only member; curl checks plus a real
# `composer update --prefer-dist` against a second Virtual alone. Each check
# has its own Remote so no check is answered from a cache another one warmed.
# artifact-keeper#6285: a third Virtual over a Local (one published package)
# and the Remote finds the Local's package through its own search.json.
# artifact-keeper#6332: search.json forwarded to a Remote's upstream only when
# that Remote opts in (composer_upstream_search), one upstream read for a
# burst of identical searches, and the local answer when the upstream is down.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"
source "$COMMON_SH"

begin_suite "composer-virtual-packagist-member (#4951)"
auth_admin
setup_workdir
W="$WORK_DIR"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
R_CTL="cvpm-ctl-${SUF}" # Remote read directly (control); never a member
R="cvpm-r-${SUF}"       # member of V (curl checks)
V="cvpm-v-${SUF}"
R2="cvpm-r2-${SUF}"     # member of V2 (composer client); separate proxy cache
V2="cvpm-v2-${SUF}"
L3="cvpm-l3-${SUF}"     # hosted member of V3 (search.json, #6285)
V3="cvpm-v3-${SUF}"     # Virtual over L3 and R
WORD3="search${SUF//[^a-z0-9]/}"
PKG3="dtf6285/${WORD3}"
REF="0123456789abcdef0123456789abcdef01234567"
DIST="dist/dtf/cleanpkg/1.0.0/${REF}.zip"
R_ON="cvpm-ron-${SUF}"    # Remote opted into upstream search (#6332)
R_OFF="cvpm-roff-${SUF}"  # Remote left at the default (off)
R_DOWN="cvpm-rdn-${SUF}"  # opted in, upstream answers 503 to everything
V4="cvpm-v4-${SUF}"       # Virtual over L3 and R_DOWN
CLIENT="ak-dtf${DTF_SLOT}-client-composer"
INT="http://backend:8080/composer"

cleanup() {
  local k
  for k in "$V4" "$V3" "$L3" "$V" "$V2" "$R" "$R2" "$R_CTL" "$R_ON" "$R_OFF" "$R_DOWN"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
hget() { curl -s --max-time 60 -o "$2" -w '%{http_code}' -H "$(auth_header)" "${BASE_URL}$1" 2>/dev/null || echo 000; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
GOLD=""

begin_test "setup: mock Packagist fixture, a non-scanning Remote and a Virtual over it"
err=""
GOLD="$(golden_sha composer/zipball/cleanpkg.zip)"
[ -n "$GOLD" ] || err+="mock fixture missing; "
for k in "$R_CTL" "$R" "$R2"; do create_repo "$k" composer remote "${UP}/composer" || err+="create ${k}; "; done
create_repo "$V" composer virtual || err+="create V; "
create_repo "$V2" composer virtual || err+="create V2; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\"}" >/dev/null 2>&1 || err+="member V; "
api_post "/api/v1/repositories/${V2}/members" "{\"member_key\":\"${R2}\"}" >/dev/null 2>&1 || err+="member V2; "
if [ -n "$err" ]; then infra_fail "setup did not complete" "$err"; end_suite; fi
pass

P="/composer"

begin_test "control: the Remote alone serves the p2 metadata and the dist archive"
s1=$(hget "${P}/${R_CTL}/p2/dtf/cleanpkg.json" "$W/r_p2.json")
s2=$(hget "${P}/${R_CTL}/${DIST}" "$W/r.zip")
if [ "$s1 $s2" = "200 200" ] && [ "$(sha "$W/r.zip")" = "$GOLD" ]; then pass; else fail "p2=${s1} dist=${s2}"; fi

begin_test "FIX #4951: the Virtual's p2 metadata routes dist.url through the Virtual, not the upstream host"
st=$(hget "${P}/${V}/p2/dtf/cleanpkg.json" "$W/v_p2.json")
url=$(jq -r '.packages["dtf/cleanpkg"][0].dist.url // empty' "$W/v_p2.json" 2>/dev/null || true)
if [ "$st" = "200" ] && [[ "$url" == *"/composer/${V}/dist/dtf/cleanpkg/"* ]]; then pass; else fail "HTTP ${st} dist.url='${url}'"; fi

begin_test "FIX #4951: the Virtual serves the member's real dist bytes (was 404)"
st=$(hget "${P}/${V}/${DIST}" "$W/v.zip")
if [ "$st" = "200" ] && [ "$(sha "$W/v.zip")" = "$GOLD" ]; then pass; else fail "HTTP ${st} $(head -c 120 "$W/v.zip" | tr -c '[:print:]' '.')"; fi

begin_test "CONTROL: a package published to a Local is found by the Local's own search.json"
err=""
create_repo "$L3" composer local || err+="create L3; "
create_repo "$V3" composer virtual || err+="create V3; "
api_post "/api/v1/repositories/${V3}/members" "{\"member_key\":\"${L3}\"}" >/dev/null 2>&1 || err+="member V3 L3; "
api_post "/api/v1/repositories/${V3}/members" "{\"member_key\":\"${R}\"}" >/dev/null 2>&1 || err+="member V3 R; "
python3 -I -c '
import json, sys, zipfile
name, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("composer.json", json.dumps({"name": name, "version": "1.0.0", "type": "library",
               "license": "MIT", "description": "dtf 6285 search probe"}))
    z.writestr("src/A.php", "<?php\n")
' "$PKG3" "$W/pkg3.zip" || err+="build zip; "
up=$(curl -s --max-time 60 -o "$W/up3.json" -w '%{http_code}' -X PUT -H "$(auth_header)" \
  -H 'Content-Type: application/zip' --data-binary "@$W/pkg3.zip" \
  "${BASE_URL}/composer/${L3}/api/packages" 2>/dev/null || echo 000)
[ "$up" = "201" ] || err+="upload HTTP ${up} $(head -c 200 "$W/up3.json" 2>/dev/null); "
if [ -n "$err" ]; then
  infra_fail "search setup did not complete" "$err"
else
  st=$(hget "${P}/${L3}/search.json?q=${WORD3}" "$W/l3_search.json")
  n=$(jq -r --arg p "$PKG3" '[.results[]? | select(.name==$p)] | length' "$W/l3_search.json" 2>/dev/null || true)
  if [ "$st" = "200" ] && [ "$n" = "1" ]; then pass; else fail "HTTP ${st}" "$(head -c 200 "$W/l3_search.json")"; fi
fi

begin_test "FIX #6285: the Virtual's search.json finds the hosted member's package (was an empty result)"
st=$(hget "${P}/${V3}/search.json?q=${WORD3}" "$W/v3_search.json")
hit=$(jq -r --arg p "$PKG3" '[.results[]? | select(.name==$p)][0] | "\(.description)|\(.url)"' "$W/v3_search.json" 2>/dev/null || true)
total=$(jq -r '.total // 0' "$W/v3_search.json" 2>/dev/null || echo 0)
if [ "$st" = "200" ] && [ "$hit" = "dtf 6285 search probe|/composer/${V3}/p2/${PKG3}.json" ] && [ "$total" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "HTTP ${st} hit='${hit}' total='${total}'" "$(head -c 300 "$W/v3_search.json")"
fi

begin_test "CONTROL: the Virtual's search.json answers 0 for a term no member has"
st=$(hget "${P}/${V3}/search.json?q=nomatch${WORD3}" "$W/v3_none.json")
total=$(jq -r '.total // empty' "$W/v3_none.json" 2>/dev/null || true)
if [ "$st" = "200" ] && [ "$total" = "0" ]; then pass; else fail "HTTP ${st}" "$(head -c 200 "$W/v3_none.json")"; fi

# --- #6332: upstream search, opt-in per Remote ------------------------------
# upstream_hits PREFIX: GETs the mock saw whose raw path starts with PREFIX.
upstream_hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$(jq -rn --arg p "$1" '$p|@uri')" | jq -r '.count // -1' 2>/dev/null || echo -1; }
# opt_in KEY: PATCH composer_upstream_search on; prints the HTTP status.
opt_in() {
  curl -s --max-time 30 -o "$W/optin_$1.json" -w '%{http_code}' -X PATCH -H "$(auth_header)" \
    -H 'Content-Type: application/json' -d '{"composer_upstream_search": true}' \
    "${BASE_URL}/api/v1/repositories/$1" 2>/dev/null || echo 000
}
WORD6="on${SUF//[^a-z0-9]/}"
WORD7="off${SUF//[^a-z0-9]/}"
WORD8="burst${SUF//[^a-z0-9]/}"

begin_test "setup: Remotes for upstream search (on, off, down) and a Virtual over the Local and the down one"
err=""
create_repo "$R_ON" composer remote "${UP}/composer" || err+="create R_ON; "
create_repo "$R_OFF" composer remote "${UP}/composer" || err+="create R_OFF; "
create_repo "$R_DOWN" composer remote "${UP}/failing/503/composer" || err+="create R_DOWN; "
create_repo "$V4" composer virtual || err+="create V4; "
api_post "/api/v1/repositories/${V4}/members" "{\"member_key\":\"${L3}\"}" >/dev/null 2>&1 || err+="member V4 L3; "
api_post "/api/v1/repositories/${V4}/members" "{\"member_key\":\"${R_DOWN}\"}" >/dev/null 2>&1 || err+="member V4 R_DOWN; "
if [ -n "$err" ]; then infra_fail "upstream search setup did not complete" "$err"; else pass; fi

begin_test "FIX #6332: with composer_upstream_search on, a Remote's search.json returns the upstream's packages"
st_on=$(opt_in "$R_ON")
st_get=$(hget "/api/v1/repositories/${R_ON}" "$W/ron.json")
flag=$(jq -r '.composer_upstream_search // empty' "$W/ron.json" 2>/dev/null || true)
st=$(hget "${P}/${R_ON}/search.json?q=${WORD6}" "$W/ron_search.json")
hit=$(jq -r --arg n "dtfup6332/${WORD6}" '[.results[]? | select(.name==$n)][0] | "\(.description)|\(.url)"' "$W/ron_search.json" 2>/dev/null || true)
if [ "$st_on $st_get $flag $st" = "200 200 true 200" ] && \
   [ "$hit" = "upstream hit for ${WORD6}|/composer/${R_ON}/p2/dtfup6332/${WORD6}.json" ]; then
  pass
else
  fail "PATCH=${st_on} GET=${st_get} flag='${flag}' search=${st} hit='${hit}'" "$(head -c 300 "$W/ron_search.json")"
fi

begin_test "CONTROL: with the setting off (the default), search.json never reaches the upstream"
st_get=$(hget "/api/v1/repositories/${R_OFF}" "$W/roff.json")
st=$(hget "${P}/${R_OFF}/search.json?q=${WORD7}" "$W/roff_search.json")
n=$(jq -r '[.results[]? | select(.name | startswith("dtfup6332/"))] | length' "$W/roff_search.json" 2>/dev/null || echo x)
asked=$(upstream_hits "/composer/search.json?q=${WORD7}")
if [ "$st" = "200" ] && [ "$n" = "0" ] && [ "$asked" = "0" ]; then
  pass
else
  fail "HTTP ${st} upstream hits in answer=${n} upstream asked=${asked} flag=$(jq -c '.composer_upstream_search' "$W/roff.json" 2>/dev/null)"
fi

begin_test "FIX #6332: a burst of 5 identical searches costs one upstream read"
for _ in 1 2 3 4 5; do hget "${P}/${R_ON}/search.json?q=${WORD8}" "$W/burst.json" >/dev/null; done
asked=$(upstream_hits "/composer/search.json?q=${WORD8}")
n=$(jq -r --arg n "dtfup6332/${WORD8}" '[.results[]? | select(.name==$n)] | length' "$W/burst.json" 2>/dev/null || echo x)
echo "    upstream reads for 5 identical searches: ${asked}"
if [ "$asked" = "1" ] && [ "$n" = "1" ]; then pass; else fail "upstream reads=${asked} hit in last answer=${n}"; fi

begin_test "FIX #6332: with the upstream down, the Virtual's search.json returns the local results, no error"
st_dn=$(opt_in "$R_DOWN")
code=$(curl -s --max-time 60 -D "$W/v4_hdr.txt" -o "$W/v4_search.json" -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}${P}/${V4}/search.json?q=${WORD3}" 2>/dev/null || echo 000)
n=$(jq -r --arg p "$PKG3" '[.results[]? | select(.name==$p)] | length' "$W/v4_search.json" 2>/dev/null || echo x)
partial=$({ grep -i '^x-ak-partial-members:' "$W/v4_hdr.txt" || true; } | tr -d '\r' | cut -d' ' -f2-)
asked=$(upstream_hits "/failing/503/composer/search.json")
if [ "$st_dn $code $n" = "200 200 1" ] && [ "$partial" = "$R_DOWN" ] && [ "$asked" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "PATCH=${st_dn} HTTP ${code} local hit=${n} partial='${partial}' upstream asked=${asked}" "$(head -c 300 "$W/v4_search.json")"
fi

begin_test "FIX #4951: a real composer update --prefer-dist against the Virtual alone installs from dist"
cat > "$W/composer.json" <<JSON
{
  "name": "dtf/consumer",
  "require": { "dtf/cleanpkg": "1.0.0" },
  "repositories": [ { "type": "composer", "url": "${INT}/${V2}" }, { "packagist.org": false } ],
  "config": { "secure-http": false }
}
JSON
docker exec "$CLIENT" sh -c "rm -rf /tmp/cvpm && mkdir -p /tmp/cvpm/home" >/dev/null 2>&1 || true
docker cp "$W/composer.json" "${CLIENT}:/tmp/cvpm/composer.json" >/dev/null 2>&1 || true
rc=0
out=$(docker exec -e COMPOSER_HOME=/tmp/cvpm/home \
  -w /tmp/cvpm "$CLIENT" composer update --no-interaction --prefer-dist --no-progress 2>&1) || rc=$?
docker cp "${CLIENT}:/tmp/cvpm/vendor/composer/installed.json" "$W/installed.json" >/dev/null 2>&1 || true
src=$(jq -r '(.packages // .)[] | select(.name=="dtf/cleanpkg") | .["installation-source"] // empty' "$W/installed.json" 2>/dev/null || true)
if [ "$rc" = 0 ] && [ "$src" = "dist" ]; then
  pass
else
  fail "composer rc=${rc} installation-source='${src}'" "$(printf '%s' "$out" | tail -8)"
fi

end_suite
