#!/usr/bin/env bash
# shellcheck disable=SC2015  # A && B || fail_g is intended
# =============================================================================
# tiers/rubygems-remote-bundler/oracle.sh
#   artifact-keeper#5686: a Remote RubyGems repository serves Bundler on
#   /gems/<repo> (Compact Index and quick gemspecs proxied byte for byte, the
#   upstream Content-Encoding kept, no `200 []` from the Dependency API), and a
#   real `bundle lock` / `bundle install` resolves through it. See the
#   manifest for the bug and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$BASE_URL"
SUF="${DTF_SLOT}-${RUN_ID##*-}-$$"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"
RUBY_CTR="ak-dtf${DTF_SLOT}-client-rubygems"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
md5_of(){ md5sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# req <METHOD> <PATH> [JSON body]: sets CODE and BODY (admin bearer).
req(){
  local m="$1" p="$2" d="${3:-}"
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$m" -H "Authorization: Bearer ${TOK}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}${p}" 2>/dev/null)"; [ -n "$CODE" ] || CODE=000
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
# fetch <path> <out>: anonymous GET of a /gems path WITHOUT decoding (no
# --compressed), headers in <out>.h. Echoes the status.
fetch(){
  : >"$2"
  curl -s --max-time 60 -D "$2.h" -o "$2" -w '%{http_code}' "${BASE}$1" 2>/dev/null || echo 000
}
hdr(){ grep -i "^$2:" "$1.h" 2>/dev/null | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
mock_put(){ # <path> <file> <content-type> [content-encoding]
  local q="path=$1&ctype=$3"
  [ -n "${4:-}" ] && q="${q}&cenc=$4"
  curl -s --max-time 10 -X PUT --data-binary @"$2" "${MOCK}/__file?${q}" | jqr '.bytes // empty'
}
mock_gets(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get // empty'; }
ruby_sh(){ docker exec -i "$RUBY_CTR" bash -s 2>&1; }

begin_suite "rubygems-remote-bundler"

# =============================================================================
begin_test "setup: admin session, a rubygems.org-shaped upstream on the mock, Remote and Local RubyGems repositories"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; exit $?; }
docker exec "$RUBY_CTR" bundle --version >/dev/null 2>&1 || { infra_fail "bundler missing in ${RUBY_CTR}"; end_suite; exit 1; }

# Build the upstream tree with the client's own gem library, then copy it out.
docker exec "$RUBY_CTR" rm -rf /work >/dev/null 2>&1
docker exec "$RUBY_CTR" mkdir -p /work >/dev/null 2>&1
docker cp "$HERE/fixtures/gen_upstream.rb" "$RUBY_CTR:/work/gen_upstream.rb" >/dev/null 2>&1
GEN="$(docker exec "$RUBY_CTR" ruby /work/gen_upstream.rb /work/up 2>&1)"
UPD="$W/up"
rm -rf "$UPD"; docker cp "$RUBY_CTR:/work/up" "$UPD" >/dev/null 2>&1
[ -s "$UPD/versions" ] && [ -s "$UPD/gems/dtfbundler-app-1.0.0.gem" ] \
  || { infra_fail "generating the upstream tree failed: ${GEN: -400}"; end_suite; exit 1; }

PUT_FAIL=0
while IFS= read -r f; do
  rel="${f#"$UPD"}"
  case "$rel" in
    /coded/*) continue ;;
    /versions|/names|/info/*) ct="text/plain" ;;
    *) ct="application/octet-stream" ;;
  esac
  [ -n "$(mock_put "$rel" "$f" "$ct")" ] || PUT_FAIL=$((PUT_FAIL+1))
done < <(find "$UPD" -type f | sort)
# A gzip-coded Compact Index document, as a mirror that stores it coded serves it.
[ -n "$(mock_put /info/dtfbundler-coded "$UPD/coded/info-dtfbundler-coded.gz" text/plain gzip)" ] || PUT_FAIL=$((PUT_FAIL+1))
[ "$PUT_FAIL" -eq 0 ] || { infra_fail "storing ${PUT_FAIL} upstream file(s) on the mock failed"; end_suite; exit 1; }

mkrepo(){ # <key> <type> [upstream]
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"rubygems",repo_type:$t,is_public:true} + (if $u == "" then {} else {upstream_url:$u} end)')"
  is_2xx "$CODE" || { infra_fail "creating $2 repo $1 answered ${CODE}: ${BODY:0:200}"; end_suite; exit 1; }
}
R="rgb-remote-${SUF}"; mkrepo "$R" remote "$UP"
L="rgb-local-${SUF}";  mkrepo "$L" local
echo "-- repos: remote ${R} -> ${UP}, local ${L}"
pass

# =============================================================================
# CONTROLS: what already worked on a Remote and on a Local (both images)
# =============================================================================
begin_test "CONTROL: the Remote proxies specs.4.8.gz and a .gem byte for byte"
reset_case
c="$(fetch "/gems/${R}/specs.4.8.gz" "$W/specs")"
[ "$c" = "200" ] && [ "$(sha_of "$W/specs")" = "$(sha_of "$UPD/specs.4.8.gz")" ] \
  || fail_g "specs.4.8.gz answered ${c} or differs from the upstream bytes"
c="$(fetch "/gems/${R}/gems/dtfbundler-dep-1.0.0.gem" "$W/dep.gem")"
[ "$c" = "200" ] && [ "$(sha_of "$W/dep.gem")" = "$(sha_of "$UPD/gems/dtfbundler-dep-1.0.0.gem")" ] \
  || fail_g "gems/dtfbundler-dep-1.0.0.gem answered ${c} or differs from the upstream bytes"
finish_case "a Remote RubyGems repository no longer proxies the specs index or a .gem"

begin_test "CONTROL: a Local repository keeps answering 404 on the Compact Index and serves its own specs.4.8.gz"
reset_case
for p in versions names info/dtfbundler-app; do
  c="$(fetch "/gems/${L}/${p}" "$W/local")"
  [ "$c" = "404" ] || fail_g "Local /${p} answered ${c}, want 404 (Bundler falls back to the Marshal indexes)"
done
c="$(fetch "/gems/${L}/specs.4.8.gz" "$W/lspecs")"
[ "$c" = "200" ] && gzip -t "$W/lspecs" 2>/dev/null || fail_g "Local specs.4.8.gz answered ${c} or is not gzip"
finish_case "a Local RubyGems repository changed its Compact Index or specs index behaviour"

# =============================================================================
# FIX #5686
# =============================================================================
begin_test "FIX #5686: the Remote serves the upstream Compact Index byte for byte, and info/<name> matches its MD5 in versions"
reset_case
for p in versions names info/dtfbundler-app info/dtfbundler-dep; do
  out="$W/ci-$(printf '%s' "$p" | tr '/' '_')"
  c="$(fetch "/gems/${R}/${p}" "$out")"
  if [ "$c" != "200" ]; then fail_g "/${p} answered ${c}, want 200 from upstream"; continue; fi
  [ "$(sha_of "$out")" = "$(sha_of "$UPD/$p")" ] || fail_g "/${p} differs from the upstream bytes"
done
if [ -s "$W/ci-versions" ]; then
  for g in dtfbundler-app dtfbundler-dep; do
    want="$(awk -v g="$g" '$1 == g {print $3}' "$W/ci-versions")"
    got="$(md5_of "$W/ci-info_${g}")"
    [ -n "$want" ] && [ "$want" = "$got" ] || fail_g "info/${g} MD5 ${got:-none} does not match versions (${want:-missing})"
  done
fi
finish_case "a Remote RubyGems repository does not serve the upstream Compact Index"

begin_test "FIX #5686: a gzip-coded upstream info document keeps its Content-Encoding"
reset_case
c="$(fetch "/gems/${R}/info/dtfbundler-coded" "$W/coded")"
if [ "$c" = "200" ]; then
  [ "$(sha_of "$W/coded")" = "$(sha_of "$UPD/coded/info-dtfbundler-coded.gz")" ] || fail_g "the body is not the coded upstream bytes"
  enc="$(hdr "$W/coded" content-encoding)"
  [ "$enc" = "gzip" ] || fail_g "Content-Encoding is '${enc:-absent}', want gzip: the coded bytes would be read as plain text"
  [ "$(hdr "$W/coded" content-length)" = "$(wc -c < "$W/coded" | tr -d ' ')" ] || fail_g "Content-Length is not the coded length"
else
  fail_g "/info/dtfbundler-coded answered ${c}, want 200"
fi
finish_case "a coded Compact Index document is served without its Content-Encoding"

begin_test "FIX #5686: an uncached quick gemspec is served from upstream"
reset_case
spec="quick/Marshal.4.8/dtfbundler-app-1.0.0.gemspec.rz"
c="$(fetch "/gems/${R}/${spec}" "$W/qs")"
[ "$c" = "200" ] && [ "$(sha_of "$W/qs")" = "$(sha_of "$UPD/$spec")" ] \
  || fail_g "/${spec} answered ${c} or differs from the upstream bytes (upstream GETs: $(mock_gets "/${spec}"))"
finish_case "a Remote RubyGems repository does not proxy quick gemspecs"

begin_test "FIX #5686: the Remote Dependency API does not answer 200 [] (no versions) for an upstream gem"
reset_case
c="$(fetch "/gems/${R}/api/v1/dependencies?gems=dtfbundler-app" "$W/deps")"
b="$(tr -d '[:space:]' < "$W/deps" 2>/dev/null)"
if [ "$c" = "200" ] && [ "$b" = "[]" ]; then
  fail_g "api/v1/dependencies answered 200 [] for a gem the upstream has"
fi
note "api/v1/dependencies answered ${c}"
finish_case "a Remote RubyGems repository tells clients an upstream gem has no versions"

begin_test "FIX #5686: a real bundle lock and bundle install resolve dtfbundler-app through the Remote"
reset_case
OUT="$(ruby_sh <<EOF
set -u
rm -rf /work/app /work/bhome /work/vendor
mkdir -p /work/app && cd /work/app
printf 'source "http://backend:8080/gems/${R}"\ngem "dtfbundler-app"\n' > Gemfile
export BUNDLE_USER_HOME=/work/bhome BUNDLE_PATH=/work/vendor BUNDLE_DISABLE_VERSION_CHECK=true
timeout 180 bundle lock; echo "LOCK_RC=\$?"
cat Gemfile.lock 2>/dev/null | sed 's/^/LOCK: /'
timeout 180 bundle install; echo "INSTALL_RC=\$?"
timeout 60 bundle exec ruby -e 'require "dtfbundler_app"; require "dtfbundler_dep"; puts "LOADED=" + DtfBundler::VERSION'
EOF
)"
echo "$OUT" | sed 's/^/   | /' | tail -40
grep -q '^LOCK_RC=0$' <<<"$OUT" || fail_g "bundle lock failed"
grep -Eq '^LOCK: +dtfbundler-app \(1\.0\.0\)$' <<<"$OUT" || fail_g "the lockfile does not pin dtfbundler-app (1.0.0)"
grep -Eq '^LOCK: +dtfbundler-dep \(1\.0\.0\)$' <<<"$OUT" || fail_g "the lockfile does not pin the dependency dtfbundler-dep (1.0.0)"
grep -q '^INSTALL_RC=0$' <<<"$OUT" || fail_g "bundle install failed"
grep -q '^LOADED=' <<<"$OUT" || fail_g "the installed gems do not load"
finish_case "Bundler cannot resolve gems through a Remote RubyGems repository on /gems/<repo>"

end_suite
