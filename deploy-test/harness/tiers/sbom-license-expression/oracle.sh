#!/usr/bin/env bash
# =============================================================================
# tiers/sbom-license-expression/oracle.sh
#   #3866 CycloneDX compound SPDX licenses are emitted as `expression`
#   #4096 the proxy-cache SBOM marks a partially read inventory
#   #4095 proxy-sbom and package-analysis are in the OpenAPI document
# See the manifest for the fixes and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
SCAN_WAIT=150
BULK=10050        # lockfile entries in the oversized tarball (> the 10000 inventory cap)

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 60 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }
mkrepo(){ # <key> <format> <type> [upstream] -> HTTP code
  api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:true} + (if $u == "" then {} else {upstream_url:$u} end)')"
}
# npm_tarball <name> <lockfile> -> path of the .tgz (package/ with a
# package-lock.json; Grype's directory scan catalogs the lockfile's packages
# with their `license` field)
npm_tarball(){
  local d="$W/pkg-$1"
  rm -rf "$d"; mkdir -p "$d/package"
  jq -nc --arg n "$1" '{name:$n,version:"1.0.0",main:"index.js",license:"MIT"}' > "$d/package/package.json"
  echo 'module.exports = 1;' > "$d/package/index.js"
  cp "$2" "$d/package/package-lock.json"
  tar czf "$W/$1-1.0.0.tgz" -C "$d" package
  echo "$W/$1-1.0.0.tgz"
}
publish_npm(){ # <repo> <name> <tgz> -> HTTP code
  local b64 sz
  b64="$(base64 -w0 < "$3")"; sz="$(wc -c < "$3" | tr -d ' ')"
  jq -nc --arg n "$2" --arg b "$b64" --argjson s "$sz" --arg reg "$BASE/npm/$1/" \
    '{name:$n, "dist-tags":{latest:"1.0.0"},
      versions:{"1.0.0":{name:$n,version:"1.0.0",dist:{tarball:($reg+$n+"/-/"+$n+"-1.0.0.tgz")}}},
      _attachments:{($n+"-1.0.0.tgz"):{content_type:"application/octet-stream",data:$b,length:$s}}}' > "$W/pub.json"
  curl -s --max-time 60 -o "$W/pub.body" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' --data-binary "@$W/pub.json" "$BASE/npm/$1/$2" || echo 000
}
# proxy_pull <name> -> HTTP code; then wait for the inline scan's verdict row
proxy_pull(){
  local code sha t=0
  code="$(curl -s --max-time 120 -o "$W/pull.$1" -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "$BASE/npm/${REMOTE}/$1/-/$1-1.0.0.tgz")" || code=000
  sha="$(sha256sum "$W/pull.$1" | awk '{print $1}')"
  while [ "$t" -lt "$SCAN_WAIT" ]; do
    [ "$(psqlq "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='${sha}'")" -ge 1 ] 2>/dev/null \
      && [ "$(psqlq "SELECT count(*) FROM proxy_scan_packages WHERE checksum_sha256='${sha}'")" -ge 1 ] 2>/dev/null \
      && break
    sleep 2; t=$((t+2))
  done
  echo "$code"
}
proxy_sbom(){ # <name> <format> -> HTTP code; body in $W/psbom.<name>.<format>
  curl -s --max-time 60 -o "$W/psbom.$1.$2" -w '%{http_code}' -G -H "Authorization: Bearer $TOK" \
    "$BASE/api/v1/repositories/${REMOTE}/security/proxy-sbom" \
    --data-urlencode "path=$1/-/$1-1.0.0.tgz" --data-urlencode "format=$2" || echo 000
}
# lic <file> <component> -> that component's licenses[] as compact JSON
lic(){ jq -c --arg n "$2" '[.components[]? | select(.name == $n) | .licenses][0]' "$1" 2>/dev/null || echo null; }

# =============================================================================
begin_suite "sbom-license-expression"

begin_test "setup: admin login, a scanned package-lock in a generic repo, npm hosted + self-proxying Remote with scan_on_proxy"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
GEN="slgen-${SFX}"; HOSTED="slnpm-${SFX}"; REMOTE="slrem-${SFX}"
P_SMALL="dtf-lic-${SFX}"; P_BULK="dtf-bulk-${SFX}"
# The four license shapes, one lockfile entry each.
jq -nc '{name:"app",version:"1.0.0",lockfileVersion:3,requires:true,packages:{
  "":{name:"app",version:"1.0.0"},
  "node_modules/dtf-compound":{version:"1.0.0",license:"MIT AND PSF-2.0"},
  "node_modules/dtf-with":{version:"1.0.0",license:"Apache-2.0 WITH LLVM-exception"},
  "node_modules/dtf-single":{version:"1.0.0",license:"MIT"},
  "node_modules/dtf-free":{version:"1.0.0",license:"Public Domain"}}}' > "$W/lock.json"
jq -nc --argjson n "$BULK" '{name:"app",version:"1.0.0",lockfileVersion:3,
  packages:({"":{name:"app",version:"1.0.0"}} + ([range(0;$n)
    | {key:("node_modules/dtf-bulk-" + tostring), value:{version:"1.0.0",license:"MIT"}}] | from_entries))}' > "$W/biglock.json"
c1="$(mkrepo "$GEN" generic local)"
A_GEN="$(curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/lock.json" \
  "$BASE/api/v1/repositories/${GEN}/artifacts/app/package-lock.json" | jqr '.id // empty')"
c2="$(mkrepo "$HOSTED" npm local)"
p1="$(publish_npm "$HOSTED" "$P_SMALL" "$(npm_tarball "$P_SMALL" "$W/lock.json")")"
p2="$(publish_npm "$HOSTED" "$P_BULK" "$(npm_tarball "$P_BULK" "$W/biglock.json")")"
# The Remote proxies this same backend's hosted repo, at the backend's address
# on the mock-osv network (a private literal the SSRF allowlist admits; the
# name `backend` is refused by the upstream-host check).
BIP="$(docker inspect "$BACKEND_CONTAINER" --format "{{(index .NetworkSettings.Networks \"ak-dtf${DTF_SLOT}-mockosv\").IPAddress}}" 2>/dev/null || true)"
c3="$(mkrepo "$REMOTE" npm remote "http://${BIP}:8080/npm/${HOSTED}/")"
c4="$(api PUT "/api/v1/repositories/${REMOTE}/security" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_open"}')"
if [[ "$c1$c2$c3" =~ ^(20[01]){3}$ ]] && [ -n "$A_GEN" ] && [[ "$p1$p2" =~ ^(20[01]){2}$ ]] && [ "$c4" = "200" ]; then
  pass
else
  infra_fail "setup: generic ${c1} artifact '${A_GEN}' hosted ${c2} publish ${p1}/${p2} remote ${c3} (backend ip '${BIP}') security ${c4}: $(abody | head -c 300)"
  end_suite
fi

# -----------------------------------------------------------------------------
begin_test "setup: scan the package-lock and generate its CycloneDX SBOM"
reset_case
api POST /api/v1/security/scan "{\"artifact_id\":\"${A_GEN}\"}" >/dev/null
t=0
while [ "$t" -lt "$SCAN_WAIT" ]; do
  [ "$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A_GEN}' AND scan_type='grype' AND status='completed'")" -ge 1 ] 2>/dev/null && break
  sleep 2; t=$((t+2))
done
code="$(api POST /api/v1/sbom "{\"artifact_id\":\"${A_GEN}\",\"format\":\"cyclonedx\",\"force_regenerate\":true}")"
SBOM_ID="$(abody | jqr '.id // empty')"
code2="$(api GET "/api/v1/sbom/${SBOM_ID}")"
abody | jq '.content // .' > "$W/hosted.cdx.json" 2>/dev/null || true
note "generate -> ${code}, GET -> ${code2}, components: $(jq '.components | length' "$W/hosted.cdx.json" 2>/dev/null)"
[ "$code" = "200" ] && [ "$code2" = "200" ] || fail_g "SBOM generate/GET failed: $(abody | head -c 300)"
[ "$(jq '[.components[]? | select(.name | startswith("dtf-"))] | length' "$W/hosted.cdx.json" 2>/dev/null)" = "4" ] \
  || fail_g "the SBOM does not carry the four dtf-* lockfile components"
finish_case "hosted SBOM not generated"

begin_test "CONTROL: a single SPDX id stays license.id and free text stays license.name (hosted SBOM)"
reset_case
s="$(lic "$W/hosted.cdx.json" dtf-single)"; f="$(lic "$W/hosted.cdx.json" dtf-free)"
note "dtf-single: ${s}; dtf-free: ${f}"
[ "$s" = '[{"license":{"id":"MIT"}}]' ] || fail_g "dtf-single licenses ${s}, expected [{\"license\":{\"id\":\"MIT\"}}]"
[ "$f" = '[{"license":{"name":"Public Domain"}}]' ] || fail_g "dtf-free licenses ${f}, expected [{\"license\":{\"name\":\"Public Domain\"}}]"
finish_case "license id/name rendering"

begin_test "FIX #3866: compound SPDX licenses are CycloneDX expressions (hosted SBOM)"
reset_case
c="$(lic "$W/hosted.cdx.json" dtf-compound)"; w="$(lic "$W/hosted.cdx.json" dtf-with)"
note "dtf-compound: ${c}; dtf-with: ${w}"
[ "$c" = '[{"expression":"MIT AND PSF-2.0"}]' ] || fail_g "dtf-compound licenses ${c}, expected [{\"expression\":\"MIT AND PSF-2.0\"}]"
[ "$w" = '[{"expression":"Apache-2.0 WITH LLVM-exception"}]' ] || fail_g "dtf-with licenses ${w}, expected [{\"expression\":\"Apache-2.0 WITH LLVM-exception\"}]"
finish_case "compound license written as a free-form name"

# -----------------------------------------------------------------------------
begin_test "CONTROL: a proxied tarball's inline scan inventory is served as an SBOM with no completeness marker"
reset_case
pc="$(proxy_pull "$P_SMALL")"
sc="$(proxy_sbom "$P_SMALL" cyclonedx)"
props="$(jq -c '.metadata.properties // null' "$W/psbom.$P_SMALL.cyclonedx" 2>/dev/null || echo null)"
s="$(lic "$W/psbom.$P_SMALL.cyclonedx" dtf-single)"
note "pull -> ${pc}; proxy-sbom -> ${sc}; components $(jq '.components | length' "$W/psbom.$P_SMALL.cyclonedx" 2>/dev/null); properties ${props}; dtf-single ${s}"
[ "$pc" = "200" ] || fail_g "pull through the Remote -> ${pc}"
[ "$sc" = "200" ] || fail_g "proxy-sbom -> ${sc}: $(head -c 300 "$W/psbom.$P_SMALL.cyclonedx")"
[ "$s" = '[{"license":{"id":"MIT"}}]' ] || fail_g "dtf-single licenses ${s} in the proxy SBOM"
case "$props" in *scan-completeness*) fail_g "a complete inventory carries a completeness marker: ${props}";; esac
finish_case "proxy SBOM"

begin_test "FIX #3866: compound SPDX licenses are CycloneDX expressions (proxy-cache SBOM)"
reset_case
c="$(lic "$W/psbom.$P_SMALL.cyclonedx" dtf-compound)"
note "dtf-compound: ${c}"
[ "$c" = '[{"expression":"MIT AND PSF-2.0"}]' ] || fail_g "dtf-compound licenses ${c}, expected [{\"expression\":\"MIT AND PSF-2.0\"}]"
finish_case "compound license written as a free-form name"

begin_test "FIX #4096: an inventory truncated at the 10000-component cap is marked partial in the proxy SBOM (CycloneDX and SPDX)"
reset_case
pc="$(proxy_pull "$P_BULK")"
sc1="$(proxy_sbom "$P_BULK" cyclonedx)"; sc2="$(proxy_sbom "$P_BULK" spdx)"
props="$(jq -c '.metadata.properties // null' "$W/psbom.$P_BULK.cyclonedx" 2>/dev/null || echo null)"
comment="$(jq -r '.creationInfo.comment // ""' "$W/psbom.$P_BULK.spdx" 2>/dev/null || true)"
n="$(jq '.components | length' "$W/psbom.$P_BULK.cyclonedx" 2>/dev/null || echo 0)"
note "pull -> ${pc}; cyclonedx -> ${sc1} (${n} components) properties ${props}; spdx -> ${sc2} comment '${comment}'"
[ "$sc1" = "200" ] && [ "$sc2" = "200" ] || fail_g "proxy-sbom -> ${sc1}/${sc2}"
[ "$(jq -r '[.metadata.properties[]? | select(.name == "artifact-keeper:scan-completeness") | .value][0] // ""' "$W/psbom.$P_BULK.cyclonedx" 2>/dev/null)" = "partial" ] \
  || fail_g "CycloneDX metadata.properties lacks artifact-keeper:scan-completeness=partial (got ${props})"
[ "$comment" = "artifact-keeper scan-completeness: partial" ] \
  || fail_g "SPDX creationInfo.comment '${comment}', expected 'artifact-keeper scan-completeness: partial'"
finish_case "truncated proxy inventory rendered as authoritative"

# -----------------------------------------------------------------------------
OA_CODE="$(curl -s --max-time 30 -o "$W/openapi.json" -w '%{http_code}' "$BASE/api/v1/openapi.json" || echo 000)"
begin_test "CONTROL: the OpenAPI document is served (ENABLE_SWAGGER) and lists /api/v1/sbom"
reset_case
note "GET /api/v1/openapi.json -> ${OA_CODE}"
[ "$OA_CODE" = "200" ] || fail_g "openapi.json -> ${OA_CODE} (profiles/api.swagger.yml sets ENABLE_SWAGGER)"
[ "$(jq '.paths | has("/api/v1/sbom")' "$W/openapi.json" 2>/dev/null)" = "true" ] || fail_g "/api/v1/sbom missing from paths"
finish_case "OpenAPI document"

begin_test "FIX #4095: proxy-sbom and package-analysis are in the OpenAPI document"
reset_case
for p in "/api/v1/repositories/{key}/security/proxy-sbom" "/api/v1/artifacts/{id}/package-analysis"; do
  has="$(jq --arg p "$p" '.paths | has($p)' "$W/openapi.json" 2>/dev/null || echo false)"
  get="$(jq --arg p "$p" '.paths[$p] | has("get")' "$W/openapi.json" 2>/dev/null || echo false)"
  note "${p}: present=${has} get=${get}"
  [ "$has" = "true" ] && [ "$get" = "true" ] || fail_g "${p} (GET) missing from the OpenAPI paths"
done
finish_case "annotated handlers missing from the spec"

end_suite
