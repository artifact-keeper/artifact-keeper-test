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
CLIENT="ak-dtf${DTF_SLOT}-client-composer"
INT="http://backend:8080/composer"

cleanup() {
  local k
  for k in "$V3" "$L3" "$V" "$V2" "$R" "$R2" "$R_CTL"; do
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
