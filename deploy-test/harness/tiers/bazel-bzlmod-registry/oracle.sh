#!/usr/bin/env bash
# =============================================================================
# tiers/bazel-bzlmod-registry/oracle.sh
#   #2858 the Bazel module registry (Bzlmod / BCR layout) at /bazel/{repo}:
#         hosted publish + generated metadata.json, no overwrite; remote
#         proxying of a BCR with immutable versioned files and a mutable
#         metadata.json; virtual merge
#   #4429 a module a hosted member publishes shadows the same module name on
#         every remote member of a virtual
# See the manifest for the behaviour, the primitives and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# Where the BACKEND reaches the mock BCR (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76/bcr"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled for the db service

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

# --- mock BCR (profiles/upstreams.mock-files.yml) ----------------------------
mock_put(){ # <path> <file> [ctype] -> stored byte count
  curl -s --max-time 30 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}
up_n(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '(.get // 0) + (.head // 0)'; }

auth(){ printf 'Authorization: Bearer %s' "$TOK"; }
fetch(){ # <url> <out> -> http code
  local c
  rm -f "$2"
  c="$(curl -s --max-time 60 -o "$2" -w '%{http_code}' -H "$(auth)" "$1" 2>/dev/null || true)"
  [ -f "$2" ] || : > "$2"
  echo "${c:-000}"
}
bput(){ # <repo> <rel path> <file> -> http code (body in $W/put.o)
  curl -s --max-time 60 -o "$W/put.o" -w '%{http_code}' -X PUT -H "$(auth)" \
    --data-binary @"$3" "$BASE/bazel/$1/$2" 2>/dev/null || echo 000
}
versions_of(){ jq -c '.versions' "$1" 2>/dev/null || true; }

# --- proxy-cache sidecar ageing (the github-release-mirror idiom) ------------
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }
sidecar_path(){ fsx "ls -1 /data/storage/proxy-cache/*/$1/$2/__cache_meta__.json 2>/dev/null | head -n1"; }
age_entry(){ # <repo> <path> <secs>: move cached_at and expires_at back <secs>
  local f
  f="$(sidecar_path "$1" "$2")"
  [ -n "$f" ] || return 1
  fsx "cat '$f'" | python3 -I -c '
import json, sys
from datetime import datetime, timedelta
secs = int(sys.argv[1])
def shift(s):
    s = s.rstrip("Z")
    frac = ""
    if "." in s:
        s, frac = s.split(".", 1)
    t = datetime.fromisoformat(s) - timedelta(seconds=secs)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + ("." + frac if frac else "") + "Z"
m = json.load(sys.stdin)
m["cached_at"] = shift(m["cached_at"])
m["expires_at"] = shift(m["expires_at"])
print(json.dumps(m))
' "$3" > "$W/aged.json" 2>/dev/null || return 1
  [ -s "$W/aged.json" ] || return 1
  fsx "o=\$(stat -c %u:%g '$f'); cat > '$f'; chown \"\$o\" '$f'" < "$W/aged.json"
  return 0
}
AGE=900

# =============================================================================
begin_suite "bazel-bzlmod-registry"

begin_test "setup: admin login, a mock BCR, hosted / remote / virtual bazel repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
if ! command -v python3 >/dev/null 2>&1; then infra_fail "python3 is required on the runner (sidecar arithmetic)"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
BH="bzl-h-${SUF}"; BR="bzl-r-${SUF}"; BV="bzl-v-${SUF}"; BG="bzl-g-${SUF}"
SETUP_ERR=""
# The mock BCR: rmod (upstream only, 1.0 and 2.0) and common (upstream 9.0;
# the hosted member will publish its own `common`, which must shadow it).
printf '{"mirrors":["https://mirror.example.invalid/"]}\n' > "$W/registry.json"
printf '{"homepage":"https://example.invalid/rmod","versions":["1.0","2.0"],"yanked_versions":{}}\n' > "$W/rmod.meta"
printf 'module(name = "rmod", version = "1.0")\n# upstream %s\n' "$SUF" > "$W/rmod-1.0.MODULE"
printf '{"url":"https://example.invalid/rmod-1.0.tar.gz","integrity":"sha256-AAAA","strip_prefix":"rmod-1.0"}\n' > "$W/rmod-1.0.source"
printf '{"versions":["9.0"],"yanked_versions":{}}\n' > "$W/common.meta"
printf 'module(name = "common", version = "9.0")\n# upstream\n' > "$W/common-9.0.MODULE"
[ -n "$(mock_put "/bcr/bazel_registry.json" "$W/registry.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:registry"
[ -n "$(mock_put "/bcr/modules/rmod/metadata.json" "$W/rmod.meta" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:rmod.meta"
[ -n "$(mock_put "/bcr/modules/rmod/1.0/MODULE.bazel" "$W/rmod-1.0.MODULE" text/plain)" ] || SETUP_ERR="${SETUP_ERR} mock:rmod.module"
[ -n "$(mock_put "/bcr/modules/rmod/1.0/source.json" "$W/rmod-1.0.source" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:rmod.source"
[ -n "$(mock_put "/bcr/modules/common/metadata.json" "$W/common.meta" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:common.meta"
[ -n "$(mock_put "/bcr/modules/common/9.0/MODULE.bazel" "$W/common-9.0.MODULE" text/plain)" ] || SETUP_ERR="${SETUP_ERR} mock:common.module"
mk(){ # <key> <format> <type> [upstream] -> HTTP code
  curl -s -o "$W/mk.$1" -w '%{http_code}' -X POST "$BASE/api/v1/repositories" -H "$(auth)" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
          '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')" || true
}
member(){ # <virtual> <member> <priority> -> HTTP code
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/$1/members" -H "$(auth)" \
    -H 'Content-Type: application/json' -d "$(jq -n --arg k "$2" --argjson p "$3" '{member_key:$k,priority:$p}')" || true
}
MK_G="$(mk "$BG" generic remote "$UP")"
case "$MK_G" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} ${BG}:${MK_G}";; esac
MK_H="$(mk "$BH" bazel local)"; MK_R="$(mk "$BR" bazel remote "$UP")"; MK_V="$(mk "$BV" bazel virtual)"
MEM_H=""; MEM_R=""
case "$MK_V" in 2*) MEM_H="$(member "$BV" "$BH" 1)"; MEM_R="$(member "$BV" "$BR" 2)";; esac
note "create bazel hosted ${MK_H}, remote ${MK_R}, virtual ${MK_V} (members ${MEM_H:-n/a}/${MEM_R:-n/a}); generic remote ${MK_G}"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
# Hosted module files (published in FIX cases below).
printf 'module(name = "hmod", version = "1.0")\n' > "$W/hmod-1.0.MODULE"
printf 'module(name = "hmod", version = "1.2")\n' > "$W/hmod-1.2.MODULE"
printf 'module(name = "hmod", version = "1.10")\n' > "$W/hmod-1.10.MODULE"
printf 'module(name = "hmod", version = "1.0")\n# a different body\n' > "$W/hmod-1.0.MODULE.v2"
printf '{"url":"https://example.invalid/hmod-1.0.tar.gz","integrity":"sha256-BBBB","strip_prefix":"hmod-1.0"}\n' > "$W/hmod-1.0.source"
printf 'this is { not json' > "$W/bad.source"
printf 'module(name = "common", version = "1.0")\n# hosted %s\n' "$SUF" > "$W/common-1.0.MODULE"
pass

# =============================================================================
# CONTROL (both images): the mock BCR is a sound upstream for AK.
# =============================================================================
begin_test "CONTROL: a generic Remote over the mock BCR serves its files byte-exact and caches them"
reset_case
c1="$(fetch "$BASE/general/${BG}/modules/rmod/1.0/MODULE.bazel" "$W/g1.o")"
c2="$(fetch "$BASE/general/${BG}/modules/rmod/metadata.json" "$W/g2.o")"
n1="$(up_n /bcr/modules/rmod/1.0/MODULE.bazel)"
c3="$(fetch "$BASE/general/${BG}/modules/rmod/1.0/MODULE.bazel" "$W/g3.o")"
n2="$(up_n /bcr/modules/rmod/1.0/MODULE.bazel)"
note "MODULE.bazel ${c1}, metadata.json ${c2}, warm ${c3}; upstream requests ${n1} -> ${n2}"
[ "$c1" = "200" ] && [ "$(sha_of "$W/g1.o")" = "$(sha_of "$W/rmod-1.0.MODULE")" ] || fail_g "MODULE.bazel via the generic Remote answered ${c1} or other bytes"
[ "$c2" = "200" ] && [ "$(versions_of "$W/g2.o")" = '["1.0","2.0"]' ] || fail_g "metadata.json via the generic Remote answered ${c2} / $(head -c 120 "$W/g2.o")"
[ "$c3" = "200" ] && [ "${n2:-x}" = "${n1:-y}" ] || fail_g "the warm read answered ${c3} or went upstream again"
finish_case "the mock BCR or generic proxying is broken (tier would be hollow)"

# =============================================================================
# FIX #2858: hosted registry.
# =============================================================================
begin_test "FIX #2858: hosted publish of MODULE.bazel and source.json; metadata.json is generated and version-sorted"
reset_case
p1="$(bput "$BH" modules/hmod/1.0/MODULE.bazel "$W/hmod-1.0.MODULE")"
p2="$(bput "$BH" modules/hmod/1.0/source.json "$W/hmod-1.0.source")"
p3="$(bput "$BH" modules/hmod/1.10/MODULE.bazel "$W/hmod-1.10.MODULE")"
p4="$(bput "$BH" modules/hmod/1.2/MODULE.bazel "$W/hmod-1.2.MODULE")"
cm="$(fetch "$BASE/bazel/${BH}/modules/hmod/metadata.json" "$W/hmeta.o")"
cf="$(fetch "$BASE/bazel/${BH}/modules/hmod/1.0/MODULE.bazel" "$W/hmod.o")"
cs="$(fetch "$BASE/bazel/${BH}/modules/hmod/1.0/source.json" "$W/hsrc.o")"
cr="$(fetch "$BASE/bazel/${BH}/bazel_registry.json" "$W/hreg.o")"
note "PUT 1.0/MODULE.bazel ${p1}, 1.0/source.json ${p2}, 1.10 ${p3}, 1.2 ${p4}"
note "metadata.json ${cm} $(head -c 160 "$W/hmeta.o"); MODULE.bazel ${cf}; source.json ${cs}; bazel_registry.json ${cr} $(head -c 80 "$W/hreg.o")"
for c in "$p1" "$p2" "$p3" "$p4"; do [ "$c" = "201" ] || fail_g "a hosted module-file PUT answered ${c} (1.10.0: no /bazel route)"; done
[ "$cm" = "200" ] || fail_g "generated metadata.json answered ${cm}"
[ "$(versions_of "$W/hmeta.o")" = '["1.0","1.2","1.10"]' ] || fail_g "metadata.json versions $(versions_of "$W/hmeta.o"), expected [\"1.0\",\"1.2\",\"1.10\"] (component-wise order)"
[ "$(jq -c '.yanked_versions' "$W/hmeta.o" 2>/dev/null || true)" = '{}' ] || fail_g "metadata.json has no empty yanked_versions map"
[ "$cf" = "200" ] && [ "$(sha_of "$W/hmod.o")" = "$(sha_of "$W/hmod-1.0.MODULE")" ] || fail_g "hosted MODULE.bazel answered ${cf} or other bytes"
[ "$cs" = "200" ] && [ "$(sha_of "$W/hsrc.o")" = "$(sha_of "$W/hmod-1.0.source")" ] || fail_g "hosted source.json answered ${cs} or other bytes"
[ "$cr" = "200" ] && [ "$(jq -c '.mirrors' "$W/hreg.o" 2>/dev/null || true)" = '[]' ] || fail_g "hosted bazel_registry.json answered ${cr} without an empty mirrors list"
finish_case "hosted Bazel registry publish / metadata"

begin_test "FIX #2858: a published file cannot be overwritten, metadata.json cannot be published, and source.json must be JSON"
reset_case
o="$(bput "$BH" modules/hmod/1.0/MODULE.bazel "$W/hmod-1.0.MODULE.v2")"; ob="$(head -c 120 "$W/put.o")"
m="$(bput "$BH" modules/hmod/metadata.json "$W/hmeta.o")"; mb="$(head -c 160 "$W/put.o")"
s="$(bput "$BH" modules/hmod/2.0/source.json "$W/bad.source")"; sb="$(head -c 120 "$W/put.o")"
cf="$(fetch "$BASE/bazel/${BH}/modules/hmod/1.0/MODULE.bazel" "$W/hmod2.o")"
note "overwrite ${o} '${ob}'; metadata.json ${m} '${mb}'; bad source.json ${s} '${sb}'"
[ "$o" = "409" ] || fail_g "overwriting a published MODULE.bazel answered ${o}, expected 409"
[ "$(sha_of "$W/hmod2.o")" = "$(sha_of "$W/hmod-1.0.MODULE")" ] || fail_g "the published MODULE.bazel bytes changed after the overwrite attempt"
[ "$m" = "400" ] || fail_g "PUT metadata.json answered ${m}, expected 400 (it is generated)"
[ "$s" = "400" ] || fail_g "a non-JSON source.json answered ${s}, expected 400"
finish_case "hosted Bazel registry write rules"

# =============================================================================
# FIX #2858: remote registry.
# =============================================================================
begin_test "FIX #2858: a remote proxies the BCR; a versioned file is immutable, metadata.json revalidates after the mutable TTL"
reset_case
c1="$(fetch "$BASE/bazel/${BR}/modules/rmod/1.0/MODULE.bazel" "$W/r1.o")"
c2="$(fetch "$BASE/bazel/${BR}/modules/rmod/metadata.json" "$W/r2.o")"
c3="$(fetch "$BASE/bazel/${BR}/bazel_registry.json" "$W/r3.o")"
nf="$(up_n /bcr/modules/rmod/1.0/MODULE.bazel)"; nm="$(up_n /bcr/modules/rmod/metadata.json)"
note "MODULE.bazel ${c1}, metadata.json ${c2} $(head -c 100 "$W/r2.o"), bazel_registry.json ${c3}; upstream file ${nf}, meta ${nm}"
[ "$c1" = "200" ] && [ "$(sha_of "$W/r1.o")" = "$(sha_of "$W/rmod-1.0.MODULE")" ] || fail_g "remote MODULE.bazel answered ${c1} or other bytes (1.10.0: 404)"
[ "$c2" = "200" ] && [ "$(versions_of "$W/r2.o")" = '["1.0","2.0"]' ] || fail_g "remote metadata.json answered ${c2} without the upstream versions"
[ "$c3" = "200" ] && [ "$(jq -c '.mirrors' "$W/r3.o" 2>/dev/null || true)" = '["https://mirror.example.invalid/"]' ] || fail_g "remote bazel_registry.json is not the upstream's"
age_entry "$BR" modules/rmod/1.0/MODULE.bazel "$AGE" || fail_g "could not age the MODULE.bazel sidecar"
age_entry "$BR" modules/rmod/metadata.json "$AGE" || fail_g "could not age the metadata.json sidecar"
c4="$(fetch "$BASE/bazel/${BR}/modules/rmod/1.0/MODULE.bazel" "$W/r4.o")"
c5="$(fetch "$BASE/bazel/${BR}/modules/rmod/metadata.json" "$W/r5.o")"
nf2="$(up_n /bcr/modules/rmod/1.0/MODULE.bazel)"; nm2="$(up_n /bcr/modules/rmod/metadata.json)"
note "15 minutes later: MODULE.bazel ${c4}, upstream ${nf} -> ${nf2}; metadata.json ${c5}, upstream ${nm} -> ${nm2}"
[ "$c4" = "200" ] && [ "${nf2:-x}" = "${nf:-y}" ] || fail_g "a 15-minute-old versioned file went back upstream (it is immutable)"
[ "$c5" = "200" ] && [ "${nm2:-0}" -gt "${nm:-0}" ] 2>/dev/null || fail_g "a 15-minute-old metadata.json was served without revalidation"
finish_case "remote Bazel registry"

# =============================================================================
# FIX #2858 / #4429: virtual merge and shadowing.
# =============================================================================
begin_test "FIX #2858/#4429: a virtual merges members; a hosted module shadows the same name on the remote, which is never asked"
reset_case
ph="$(bput "$BH" modules/common/1.0/MODULE.bazel "$W/common-1.0.MODULE")"
up_before="$(up_n /bcr/modules/common/9.0/MODULE.bazel)"; upm_before="$(up_n /bcr/modules/common/metadata.json)"
c1="$(fetch "$BASE/bazel/${BV}/modules/rmod/metadata.json" "$W/v1.o")"
c2="$(fetch "$BASE/bazel/${BV}/modules/hmod/metadata.json" "$W/v2.o")"
c3="$(fetch "$BASE/bazel/${BV}/modules/common/metadata.json" "$W/v3.o")"
c4="$(fetch "$BASE/bazel/${BV}/modules/common/9.0/MODULE.bazel" "$W/v4.o")"
c5="$(fetch "$BASE/bazel/${BV}/modules/common/1.0/MODULE.bazel" "$W/v5.o")"
c6="$(fetch "$BASE/bazel/${BV}/modules/rmod/1.0/MODULE.bazel" "$W/v6.o")"
up_after="$(up_n /bcr/modules/common/9.0/MODULE.bazel)"; upm_after="$(up_n /bcr/modules/common/metadata.json)"
note "hosted common PUT ${ph}"
note "virtual rmod meta ${c1} $(versions_of "$W/v1.o"); hmod meta ${c2} $(versions_of "$W/v2.o"); common meta ${c3} $(versions_of "$W/v3.o")"
note "virtual common/9.0 ${c4}; common/1.0 ${c5}; rmod/1.0 ${c6}; upstream common/9.0 ${up_before} -> ${up_after}, common meta ${upm_before} -> ${upm_after}"
[ "$ph" = "201" ] || fail_g "hosted PUT of common 1.0 answered ${ph}"
[ "$c1" = "200" ] && [ "$(versions_of "$W/v1.o")" = '["1.0","2.0"]' ] || fail_g "virtual metadata for the remote-only rmod is ${c1} $(versions_of "$W/v1.o")"
[ "$c2" = "200" ] && [ "$(versions_of "$W/v2.o")" = '["1.0","1.2","1.10"]' ] || fail_g "virtual metadata for the hosted-only hmod is ${c2} $(versions_of "$W/v2.o")"
[ "$c3" = "200" ] && [ "$(versions_of "$W/v3.o")" = '["1.0"]' ] || fail_g "virtual metadata for common is ${c3} $(versions_of "$W/v3.o"), expected only the hosted [\"1.0\"] (#4429 shadowing)"
[ "$c4" = "404" ] || fail_g "virtual common/9.0/MODULE.bazel answered ${c4}, expected 404 (the remote's version is shadowed)"
[ "$c5" = "200" ] && [ "$(sha_of "$W/v5.o")" = "$(sha_of "$W/common-1.0.MODULE")" ] || fail_g "virtual common/1.0 answered ${c5} or not the hosted bytes"
[ "$c6" = "200" ] && [ "$(sha_of "$W/v6.o")" = "$(sha_of "$W/rmod-1.0.MODULE")" ] || fail_g "virtual rmod/1.0 answered ${c6} or not the remote bytes"
[ "${up_after:-x}" = "${up_before:-y}" ] || fail_g "the virtual asked the remote for a shadowed module file"
[ "${upm_after:-x}" = "${upm_before:-y}" ] || fail_g "the virtual asked the remote for a shadowed module's metadata.json"
finish_case "virtual Bazel registry merge / shadowing"

end_suite
