#!/usr/bin/env bash
# =============================================================================
# tiers/npm-version-route-dist-tags/oracle.sh
#   artifact-keeper#5063 (PR #5113): the npm version route resolves dist-tags.
# See the manifest for the topology and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
UPSTREAM="http://172.16.${DTF_SLOT}.86/"
LOCAL="dtf-npmtag-local-${SUF}"
REMOTE="dtf-npmtag-remote-${SUF}"
VIRT="dtf-npmtag-virt-${SUF}"
GATED="dtf-npmtag-gated-${SUF}"
GATEDV="dtf-npmtag-gatedv-${SUF}"
PKG="dtf-hosted"

api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
# publish <name> <version> -> HTTP code
publish() {
  local name="$1" ver="$2" src="$W/src-$1-$2"
  mkdir -p "$src/package"
  printf '{"name":"%s","version":"%s"}\n' "$name" "$ver" > "$src/package/package.json"
  tar czf "$src.tgz" -C "$src" package
  base64 < "$src.tgz" | tr -d '\n' > "$src.b64"
  jq -n --arg name "$name" --arg version "$ver" \
    --arg tarball "${BASE_URL}/npm/${LOCAL}/${name}/-/${name}-${ver}.tgz" --rawfile data "$src.b64" \
    --argjson length "$(wc -c < "$src.tgz" | tr -d ' ')" \
    '{name:$name,"dist-tags":{latest:$version},
      versions:{($version):{name:$name,version:$version,dist:{tarball:$tarball}}},
      "_attachments":{("\($name)-\($version).tgz"):{content_type:"application/octet-stream",data:$data,length:$length}}}' \
    > "$src.json"
  curl -s -o "$W/pub.out" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' --data-binary "@$src.json" "${BASE_URL}/npm/${LOCAL}/${name}" 2>/dev/null || echo 000
}
# set_tag <tag> <version> -> HTTP code
set_tag() {
  curl -s -o "$W/tag.out" -w '%{http_code}' --max-time 30 -X PUT -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "\"$2\"" \
    "${BASE_URL}/npm/${LOCAL}/-/package/${PKG}/dist-tags/$1" 2>/dev/null || echo 000
}
# expect_version <label> <repo> <package path> <segment> <want version>
expect_version() {
  local st got name want_name="$3"
  st="$(curl -s -o "$W/v.json" -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" \
    "${BASE_URL}/npm/$2/$3/$4" 2>/dev/null || echo 000)"
  got="$(jq -r '.version // empty' "$W/v.json" 2>/dev/null || true)"
  name="$(jq -r '.name // empty' "$W/v.json" 2>/dev/null || true)"
  begin_test "$1"
  if [ "$st" = "200" ] && [ "$got" = "$5" ] && [ "$name" = "$want_name" ]; then pass
  else fail "HTTP ${st} ${name}@${got}, want 200 ${want_name}@$5" "$(head -c 300 "$W/v.json" 2>/dev/null)"; fi
}
# expect_404 <label> <repo> <package path> <segment>
expect_404() {
  local st
  st="$(curl -s -o "$W/v.json" -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" \
    "${BASE_URL}/npm/$2/$3/$4" 2>/dev/null || echo 000)"
  begin_test "$1"
  if [ "$st" = "404" ]; then pass
  else fail "HTTP ${st}, want 404" "$(head -c 300 "$W/v.json" 2>/dev/null)"; fi
}

begin_suite "npm-version-route-dist-tags"

begin_test "setup: Local, Remote and Virtual repositories, an age-gated Remote and a Virtual over it"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at ${BASE_URL}"; end_suite; fi
cleanup_repos() {
  local r
  for r in "$GATEDV" "$VIRT" "$GATED" "$REMOTE" "$LOCAL"; do api DELETE "/api/v1/repositories/${r}" >/dev/null || true; done
}
add_exit_handler "cleanup_repos"
ERR=""
need2xx() { case "$1" in 2??) ;; *) ERR="${ERR} $2: HTTP $1 $(head -c 200 "$W/api.json");" ;; esac; }
mk() { # <key> <type> [upstream]
  need2xx "$(api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"npm",repo_type:$t,is_public:false} + (if $u != "" then {upstream_url:$u} else {} end)')")" "create $1"
}
mk "$LOCAL" local
mk "$REMOTE" remote "$UPSTREAM"
mk "$GATED" remote "$UPSTREAM"
mk "$VIRT" virtual
mk "$GATEDV" virtual
need2xx "$(api POST "/api/v1/repositories/${VIRT}/members" "$(jq -nc --arg m "$REMOTE" '{member_key:$m}')")" "member of ${VIRT}"
need2xx "$(api POST "/api/v1/repositories/${GATEDV}/members" "$(jq -nc --arg m "$GATED" '{member_key:$m}')")" "member of ${GATEDV}"
need2xx "$(api PUT "/api/v1/repositories/${GATED}/age-gate" '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}')" "age gate"
if [ -z "$ERR" ]; then pass; else infra_fail "$ERR"; end_suite; fi

begin_test "setup: ${PKG} 1.0.0 and 2.0.0 published to Local, tag next -> 1.0.0, a tag named 1.0.0 -> 2.0.0"
a="$(publish "$PKG" 1.0.0)"; b="$(publish "$PKG" 2.0.0)"; c="$(set_tag next 1.0.0)"; d="$(set_tag 1.0.0 2.0.0)"
case "$a$b" in 2??2??) ok=1 ;; *) ok=0 ;; esac
case "$c$d" in 2??2??) ;; *) ok=0 ;; esac
if [ "$ok" = "1" ]; then pass; else infra_fail "publish ${a}/${b}, tags ${c}/${d}: $(head -c 200 "$W/tag.out" 2>/dev/null)"; end_suite; fi

# --- Local --------------------------------------------------------------------
expect_version "CONTROL: Local exact 2.0.0" "$LOCAL" "$PKG" 2.0.0 2.0.0
expect_version "FIX #5063: Local latest resolves to 2.0.0" "$LOCAL" "$PKG" latest 2.0.0
expect_version "FIX #5063: Local stored custom tag next resolves to 1.0.0" "$LOCAL" "$PKG" next 1.0.0
expect_version "CONTROL: Local exact 1.0.0 wins over a stored tag named 1.0.0" "$LOCAL" "$PKG" 1.0.0 1.0.0
expect_404 "CONTROL: Local unknown tag is 404" "$LOCAL" "$PKG" nosuchtag

# --- Remote and Virtual --------------------------------------------------------
for repo in "$REMOTE" "$VIRT"; do
  case "$repo" in "$REMOTE") kind=Remote ;; *) kind=Virtual ;; esac
  expect_version "CONTROL: ${kind} exact 1.0.0" "$repo" dtf-tags 1.0.0 1.0.0
  expect_version "FIX #5063: ${kind} latest resolves to 2.0.0" "$repo" dtf-tags latest 2.0.0
  expect_version "FIX #5063: ${kind} custom tag old resolves to 1.0.0" "$repo" dtf-tags old 1.0.0
  expect_version "FIX #5063: ${kind} scoped latest resolves to 2.0.0" "$repo" @dtf/tags latest 2.0.0
  expect_version "CONTROL: ${kind} scoped exact 1.0.0" "$repo" @dtf/tags 1.0.0 1.0.0
  expect_404 "CONTROL: ${kind} unknown tag is 404" "$repo" dtf-tags nosuchtag
  expect_404 "CONTROL: ${kind} tag naming an unlisted version is 404" "$repo" dtf-tags ghost
done

# --- Age gate: a tag resolves through the gated dist-tags ----------------------
for repo in "$GATED" "$GATEDV"; do
  case "$repo" in "$GATED") kind="age-gated Remote" ;; *) kind="Virtual over the age-gated Remote" ;; esac
  expect_version "FIX #5063: ${kind} latest resolves to the newest allowed version" "$repo" dtf-tags latest 1.0.0
  expect_version "FIX #5063: ${kind} custom tag old resolves" "$repo" dtf-tags old 1.0.0
  expect_404 "CONTROL: ${kind} tag naming a gated version is 404" "$repo" dtf-tags fresh
  expect_version "CONTROL: ${kind} exact gated version is served on this route" "$repo" dtf-tags 2.0.0 2.0.0
done

end_suite
