#!/usr/bin/env bash
# =============================================================================
# tiers/github-release-mirror/oracle.sh
#   #3657 github / mise / aqua remote formats with a seven-day release cache
#   #3656 a repository's upstream token reaches the release host but is
#         stripped on the cross-origin redirect to the objects host
#   #3658 the GitHub API release-by-tag lookup gets the same seven-day
#         lifetime; releases/latest keeps the five-minute default
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
# Where the BACKEND reaches the mock (profiles/upstreams.mock-recorder.yml):
# :80 plays github.com / api.github.com, :81 the objects host.
UP="http://172.16.${DTF_SLOT}.77"
OBJ="http://172.16.${DTF_SLOT}.77:81"
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

# --- mock control (fixtures/mock_recorder.py) --------------------------------
mock_put(){ # <path> <file> [ctype] -> stored byte count
  curl -s --max-time 30 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}
mock_redirect(){ # <path> <absolute target url> -> status
  curl -s --max-time 30 -X PUT --data-binary '' \
    "${MOCK}/__file?path=$1&location=$2" | jqr '.status // empty'
}
up_field(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr "$2"; }
up_n(){ up_field "$1" '(.get // 0) + (.head // 0)'; }

auth(){ printf 'Authorization: Bearer %s' "$TOK"; }
fetch(){ # <url> <out> -> http code
  local c
  rm -f "$2"
  c="$(curl -s --max-time 60 -o "$2" -w '%{http_code}' -H "$(auth)" "$1" 2>/dev/null || true)"
  [ -f "$2" ] || : > "$2"
  echo "${c:-000}"
}

# --- proxy-cache sidecar access ----------------------------------------------
# The backend image has no shell, so the cache volume is read and written
# through a throwaway container with --volumes-from the backend (the
# storage-integrity / proxy-cache-empty-object idiom). Layout:
#   /data/storage/proxy-cache/<scope>/<repo-key>/<path>/__cache_meta__.json
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }
sidecar_path(){ # <repo> <path> -> absolute sidecar path ("" if absent)
  fsx "ls -1 /data/storage/proxy-cache/*/$1/$2/__cache_meta__.json 2>/dev/null | head -n1"
}
# ttl_of <repo> <path> -> expires_at - cached_at in whole seconds ("" if absent)
ttl_of(){
  local f
  f="$(sidecar_path "$1" "$2")"
  [ -n "$f" ] || return 0
  fsx "cat '$f'" | python3 -I -c '
import json, sys
from datetime import datetime
def ts(s):
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    return datetime.fromisoformat(s)
m = json.load(sys.stdin)
print(int(round((ts(m["expires_at"]) - ts(m["cached_at"])).total_seconds())))
' 2>/dev/null || true
}
# age_entry <repo> <path> <secs>: move cached_at AND expires_at back <secs>,
# keeping the lifetime the backend stamped. The entry then reads as written
# <secs> ago, which is all a TTL can tell apart.
age_entry(){
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

WEEK=604800
AGE=900   # 15 minutes: past the 300 s default, far inside the seven days

# =============================================================================
begin_suite "github-release-mirror"

begin_test "setup: admin login, release host + objects host on the mock, github / mise / aqua / generic Remotes"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-recorder.yml)"; end_suite
fi
if ! command -v python3 >/dev/null 2>&1; then infra_fail "python3 is required on the runner (sidecar arithmetic)"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
R_GH="grm-gh-${SUF}"
R_MISE="grm-mise-${SUF}"
R_AQUA="grm-aqua-${SUF}"
R_GEN="grm-gen-${SUF}"
UPTOKEN="ghp_dtf${DTF_SLOT}x${SUF//-/}"
SETUP_ERR=""

# Release assets: github.com/<o>/<r>/releases/download/<tag>/<asset> answers
# 302 to the objects host, which holds the bytes (the real GitHub flow).
A_GH="o${DTF_SLOT}/tool/releases/download/v1.0.0/tool-gh-${SUF}.tar.gz"
A_MISE="o${DTF_SLOT}/tool/releases/download/v1.0.0/tool-mise-${SUF}.tar.gz"
A_GEN="o${DTF_SLOT}/tool/releases/download/v1.0.0/tool-gen-${SUF}.tar.gz"
for which in gh mise gen; do
  head -c 70000 /dev/urandom > "$W/${which}.bin"
  [ "$(mock_put "/objects/${which}-${SUF}" "$W/${which}.bin")" = "70000" ] || SETUP_ERR="${SETUP_ERR} mock:objects-${which}"
done
[ "$(mock_redirect "/${A_GH}" "${OBJ}/objects/gh-${SUF}")" = "302" ] || SETUP_ERR="${SETUP_ERR} mock:redirect-gh"
[ "$(mock_redirect "/${A_MISE}" "${OBJ}/objects/mise-${SUF}")" = "302" ] || SETUP_ERR="${SETUP_ERR} mock:redirect-mise"
[ "$(mock_redirect "/${A_GEN}" "${OBJ}/objects/gen-${SUF}")" = "302" ] || SETUP_ERR="${SETUP_ERR} mock:redirect-gen"
# GitHub API: the release-by-tag lookup and releases/latest.
T_TAG="repos/o${DTF_SLOT}/tool/releases/tags/v1.0.0"
T_LATEST="repos/o${DTF_SLOT}/tool/releases/latest"
printf '{"tag_name":"v1.0.0","name":"tool %s","assets":[{"name":"tool-gh-%s.tar.gz"}]}\n' "$SUF" "$SUF" > "$W/tag.json"
printf '{"tag_name":"v1.0.0","name":"latest %s"}\n' "$SUF" > "$W/latest.json"
[ -n "$(mock_put "/${T_TAG}" "$W/tag.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:tag"
[ -n "$(mock_put "/${T_LATEST}" "$W/latest.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:latest"

mk(){ # <key> <format> -> HTTP status of the create; the body lands in $W/mk.<key>
  curl -s -o "$W/mk.$1" -w '%{http_code}' -X POST "$BASE/api/v1/repositories" -H "$(auth)" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg f "$2" --arg u "$UP" \
          '{key:$k,name:$k,format:$f,repo_type:"remote",is_public:false,upstream_url:$u}')" || true
}
upauth(){ # <key> -> message
  curl -s -X PUT "$BASE/api/v1/repositories/$1/upstream-auth" -H "$(auth)" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg t "$UPTOKEN" '{auth_type:"bearer",password:$t}')" | jqr '.message // empty'
}
MK_GH="$(mk "$R_GH" github)"; MK_MISE="$(mk "$R_MISE" mise)"; MK_AQUA="$(mk "$R_AQUA" aqua)"
MK_GEN="$(mk "$R_GEN" generic)"
[ "$MK_GEN" = "201" ] || [ "$MK_GEN" = "200" ] || SETUP_ERR="${SETUP_ERR} ${R_GEN}:${MK_GEN}"
[ -n "$(upauth "$R_GEN")" ] || SETUP_ERR="${SETUP_ERR} upstream-auth:${R_GEN}"
# The github remote's token is set only if the format exists (1.10.0: it does not).
case "$MK_GH" in 2*) [ -n "$(upauth "$R_GH")" ] || SETUP_ERR="${SETUP_ERR} upstream-auth:${R_GH}";; esac
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
note "create github=${MK_GH} mise=${MK_MISE} aqua=${MK_AQUA} generic=${MK_GEN}"
pass

# =============================================================================
# CONTROLS (both images): the generic Remote is what every release before
# 1.11.0 offered for GitHub mirroring.
# =============================================================================
begin_test "CONTROL: generic Remote: the upstream token reaches the release host and never the objects host it redirects to"
reset_case
code="$(fetch "$BASE/general/${R_GEN}/${A_GEN}" "$W/gen.o")"
note "HTTP ${code}; sha match: $([ "$(sha_of "$W/gen.o")" = "$(sha_of "$W/gen.bin")" ] && echo yes || echo no)"
[ "$code" = "200" ] || fail_g "GET via the generic Remote answered ${code}"
[ "$(sha_of "$W/gen.o")" = "$(sha_of "$W/gen.bin")" ] || fail_g "served bytes differ from the objects host's"
a_auth="$(up_field "/${A_GEN}" '.auth_values[0] // empty')"
b_with="$(up_field "/objects/gen-${SUF}" '.with_auth // empty')"
b_without="$(up_field "/objects/gen-${SUF}" '.without_auth // empty')"
note "release host saw Authorization '${a_auth:-<none>}'; objects host with_auth=${b_with} without_auth=${b_without}"
[ "$a_auth" = "Bearer ${UPTOKEN}" ] || fail_g "the release host did not receive the repository's bearer token (got '${a_auth:-none}'): the stripping check below would be hollow"
[ "${b_without:-0}" -ge 1 ] 2>/dev/null || fail_g "the objects host was never asked (the redirect was not followed)"
[ "${b_with:-1}" = "0" ] || fail_g "the objects host received an Authorization header on the cross-origin hop (#3656)"
finish_case "generic Remote: Authorization handling on the release redirect is wrong"

begin_test "CONTROL: generic Remote keeps the 300 s default on a release asset, so a 15-minute-old entry is revalidated"
reset_case
ttl="$(ttl_of "$R_GEN" "$A_GEN")"
note "stamped lifetime ${ttl:-<no sidecar>} s"
[ "$ttl" = "300" ] || fail_g "generic release asset lifetime is ${ttl:-unknown} s, expected the 300 s default (generic behaviour must be unchanged by #3657)"
before="$(up_n "/${A_GEN}")"
age_entry "$R_GEN" "$A_GEN" "$AGE" || fail_g "could not age the generic sidecar"
code="$(fetch "$BASE/general/${R_GEN}/${A_GEN}" "$W/gen2.o")"
after="$(up_n "/${A_GEN}")"
note "HTTP ${code}; release-host requests ${before} -> ${after}"
[ "$code" = "200" ] && [ "$(sha_of "$W/gen2.o")" = "$(sha_of "$W/gen.bin")" ] || fail_g "aged generic entry not served intact (HTTP ${code})"
[ "${after:-0}" -gt "${before:-0}" ] 2>/dev/null || fail_g "a 15-minute-old generic entry was served without asking upstream"
finish_case "generic Remote release-asset freshness changed"

# =============================================================================
# FIX #3657: the formats exist.
# =============================================================================
begin_test "FIX #3657: github, mise and aqua Remotes are created and keep their format"
reset_case
for pair in "github:${R_GH}:${MK_GH}" "mise:${R_MISE}:${MK_MISE}" "aqua:${R_AQUA}:${MK_AQUA}"; do
  f="${pair%%:*}"; rest="${pair#*:}"; k="${rest%%:*}"; c="${rest##*:}"
  got="$(curl -s -H "$(auth)" "$BASE/api/v1/repositories/${k}" | jqr '.format // empty')"
  note "${f}: create HTTP ${c}, stored format '${got}'$( [ "${c#2}" = "$c" ] && printf '; body %s' "$(head -c 160 "$W/mk.${k}" 2>/dev/null)")"
  case "$c" in 2*) ;; *) fail_g "creating the ${f} Remote answered ${c} (1.10.0 has no ${f} format)";; esac
  [ "$got" = "$f" ] || fail_g "the ${f} Remote reads back as format '${got:-none}'"
done
finish_case "the GitHub mirror formats are missing"

# =============================================================================
# FIX #3656 / #3657: through the github mirror.
# =============================================================================
begin_test "FIX #3656: github Remote: the token reaches the release host, is stripped on the redirect, and the bytes are exact"
reset_case
code="$(fetch "$BASE/general/${R_GH}/${A_GH}" "$W/gh.o")"
a_auth="$(up_field "/${A_GH}" '.auth_values[0] // empty')"
b_with="$(up_field "/objects/gh-${SUF}" '.with_auth // empty')"
b_without="$(up_field "/objects/gh-${SUF}" '.without_auth // empty')"
note "HTTP ${code}; release host Authorization '${a_auth:-<none>}'; objects host with_auth=${b_with:-?} without_auth=${b_without:-?}"
[ "$code" = "200" ] || fail_g "GET via the github Remote answered ${code}"
[ "$(sha_of "$W/gh.o")" = "$(sha_of "$W/gh.bin")" ] || fail_g "served bytes differ from the objects host's"
[ "$a_auth" = "Bearer ${UPTOKEN}" ] || fail_g "the release host did not receive the repository's bearer token"
[ "${b_without:-0}" -ge 1 ] 2>/dev/null || fail_g "the objects host was never asked"
[ "${b_with:-1}" = "0" ] || fail_g "the objects host received the repository's token on the cross-origin hop"
finish_case "github Remote release download is wrong"

begin_test "FIX #3657: a release asset on github and mise Remotes is cached for seven days and not revalidated 15 minutes later"
reset_case
code="$(fetch "$BASE/general/${R_MISE}/${A_MISE}" "$W/mise.o")"
[ "$code" = "200" ] && [ "$(sha_of "$W/mise.o")" = "$(sha_of "$W/mise.bin")" ] || fail_g "GET via the mise Remote answered ${code} or wrong bytes"
for pair in "${R_GH}|${A_GH}|gh" "${R_MISE}|${A_MISE}|mise"; do
  r="${pair%%|*}"; rest="${pair#*|}"; a="${rest%%|*}"; which="${rest##*|}"
  ttl="$(ttl_of "$r" "$a")"
  note "${which}: stamped lifetime ${ttl:-<no sidecar>} s"
  [ "$ttl" = "$WEEK" ] || fail_g "${which} release asset lifetime is ${ttl:-unknown} s, expected ${WEEK}"
  before="$(up_n "/${a}")"
  age_entry "$r" "$a" "$AGE" || fail_g "could not age the ${which} sidecar"
  code="$(fetch "$BASE/general/${r}/${a}" "$W/${which}2.o")"
  after="$(up_n "/${a}")"
  note "${which}: HTTP ${code}; release-host requests ${before} -> ${after}"
  [ "$code" = "200" ] && [ "$(sha_of "$W/${which}2.o")" = "$(sha_of "$W/${which}.bin")" ] || fail_g "${which}: aged entry not served intact (HTTP ${code})"
  [ "${after:-x}" = "${before:-y}" ] || fail_g "${which}: a 15-minute-old release asset went back upstream"
done
finish_case "release assets are not given the seven-day lifetime"

# =============================================================================
# FIX #3658: the API release-by-tag lookup; releases/latest stays short.
# =============================================================================
begin_test "FIX #3658: github Remote: releases/tags/<tag> lives seven days and is not revalidated; releases/latest keeps 300 s and is"
reset_case
code_t="$(fetch "$BASE/general/${R_GH}/${T_TAG}" "$W/tag.o")"
code_l="$(fetch "$BASE/general/${R_GH}/${T_LATEST}" "$W/latest.o")"
note "tag HTTP ${code_t} name='$(jqr '.name // empty' < "$W/tag.o")'; latest HTTP ${code_l}"
[ "$code_t" = "200" ] && [ "$(jqr '.tag_name // empty' < "$W/tag.o")" = "v1.0.0" ] || fail_g "the tag lookup answered ${code_t} without the release JSON"
[ "$code_l" = "200" ] || fail_g "releases/latest answered ${code_l}"
ttl_t="$(ttl_of "$R_GH" "$T_TAG")"; ttl_l="$(ttl_of "$R_GH" "$T_LATEST")"
note "stamped lifetimes: tags ${ttl_t:-<none>} s, latest ${ttl_l:-<none>} s"
[ "$ttl_t" = "$WEEK" ] || fail_g "releases/tags lifetime is ${ttl_t:-unknown} s, expected ${WEEK} (#3658)"
[ "$ttl_l" = "300" ] || fail_g "releases/latest lifetime is ${ttl_l:-unknown} s, expected the 300 s default"
bt="$(up_n "/${T_TAG}")"; bl="$(up_n "/${T_LATEST}")"
age_entry "$R_GH" "$T_TAG" "$AGE" || fail_g "could not age the tag sidecar"
age_entry "$R_GH" "$T_LATEST" "$AGE" || fail_g "could not age the latest sidecar"
code_t="$(fetch "$BASE/general/${R_GH}/${T_TAG}" "$W/tag2.o")"
code_l="$(fetch "$BASE/general/${R_GH}/${T_LATEST}" "$W/latest2.o")"
at="$(up_n "/${T_TAG}")"; al="$(up_n "/${T_LATEST}")"
note "after 15 minutes: tag HTTP ${code_t}, upstream ${bt} -> ${at}; latest HTTP ${code_l}, upstream ${bl} -> ${al}"
[ "$code_t" = "200" ] && [ "$code_l" = "200" ] || fail_g "aged API entries not served (tag ${code_t}, latest ${code_l})"
[ "${at:-x}" = "${bt:-y}" ] || fail_g "a 15-minute-old releases/tags answer went back upstream (#3658)"
[ "${al:-0}" -gt "${bl:-0}" ] 2>/dev/null || fail_g "a 15-minute-old releases/latest answer was served without revalidation"
finish_case "the GitHub API tag lookup is not cached for seven days"

end_suite
