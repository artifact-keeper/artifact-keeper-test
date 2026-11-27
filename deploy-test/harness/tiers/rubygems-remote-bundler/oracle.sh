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
mock_put(){ # <path> <file> <content-type> [content-encoding] [extra query]
  local q="path=$1&ctype=$3"
  [ -n "${4:-}" ] && q="${q}&cenc=$4"
  [ -n "${5:-}" ] && q="${q}&$5"
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
    /coded/*|/phase2/*) continue ;;
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

# =============================================================================
# #5974: conditional and range requests on the Remote Compact Index
# =============================================================================
# Two more Remotes over their own copy of the tree on the mock: RE under /e
# (the mock sends an ETag, as rubygems.org does) and RN under /n (no ETag, no
# 304). Cache TTL 1 s, so the proxy goes back to the upstream on each run and
# sees the phase-2 append.
# fetchh <path> <out> [curl args...]: like fetch, with request headers.
fetchh(){
  local p="$1" o="$2"; shift 2
  : >"$o"
  curl -s --max-time 60 -D "$o.h" -o "$o" -w '%{http_code}' "$@" "${BASE}${p}" 2>/dev/null || echo 000
}
# repr_of <file>: the RFC 9530 byte-sequence form of its SHA-256.
repr_of(){ python3 -I -c 'import base64,hashlib,sys; print("sha-256=:" + base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode() + ":")' "$1"; }
# put_tree <prefix> <dir> [extra query]: store a generated tree under <prefix>.
put_tree(){
  local pre="$1" dir="$2" extra="${3:-}" n=0 f rel ct
  while IFS= read -r f; do
    rel="${f#"$dir"}"
    case "$rel" in /coded/*|/phase2/*) continue ;; esac
    case "$rel" in /versions|/names|/info/*) ct="text/plain" ;; *) ct="application/octet-stream" ;; esac
    [ -n "$(mock_put "${pre}${rel}" "$f" "$ct" "" "$extra")" ] || n=$((n+1))
  done < <(find "$dir" -type f | sort)
  echo "$n"
}
set_ttl(){ # <repo> <secs>
  req PUT "/api/v1/repositories/$1/cache-ttl" "{\"cache_ttl_seconds\":$2}"
  jqr '.cache_ttl_seconds // empty' <<<"$BODY"
}
# bundler_run <repo> <app dir> <command...>: run a Bundler command in its own
# app dir and Bundler home with --verbose (one "HTTP <code> <msg> <uri>" line
# per request). Sets RUN_OUT, RUN_RC, RUN_VERSIONS (the statuses of its
# /versions requests, in order) and RUN_LOCK_DEP (the locked dtfbundler-dep).
bundler_run(){
  local repo="$1" app="$2"; shift 2
  RUN_OUT="$(ruby_sh <<EOF
set -u
mkdir -p /work/${app} && cd /work/${app}
[ -f Gemfile ] || printf 'source "http://backend:8080/gems/${repo}"\ngem "dtfbundler-app"\n' > Gemfile
export BUNDLE_USER_HOME=/work/${app}-home BUNDLE_PATH=/work/${app}-vendor BUNDLE_DISABLE_VERSION_CHECK=true
timeout 180 $* --verbose; echo "RUN_RC=\$?"
sed 's/^/LOCK: /' Gemfile.lock 2>/dev/null
f=\$(find /work/${app}-home -path '*compact_index*' -name versions -type f 2>/dev/null | head -1)
[ -n "\$f" ] && echo "CACHED_VERSIONS_SHA=\$(sha256sum "\$f" | cut -d' ' -f1)"
EOF
)"
  RUN_RC="$(sed -n 's/^RUN_RC=//p' <<<"$RUN_OUT" | tail -1)"
  RUN_VERSIONS="$(grep -F "/gems/${repo}/versions" <<<"$RUN_OUT" | grep -oE 'HTTP [0-9]{3}' | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')"
  # The resolved spec line (`    dtfbundler-dep (1.0.0)`), not the app's
  # requirement line (`      dtfbundler-dep (~> 1.0)`).
  RUN_LOCK_DEP="$(grep -E '^LOCK: +dtfbundler-dep \([0-9][0-9.]*\)$' <<<"$RUN_OUT" | head -1 | sed -E 's/.*\((.*)\).*/\1/')"
  RUN_CACHED="$(sed -n 's/^CACHED_VERSIONS_SHA=//p' <<<"$RUN_OUT" | tail -1)"
  note "$* on ${repo}: rc ${RUN_RC:-none}, /versions answered [${RUN_VERSIONS}], dtfbundler-dep ${RUN_LOCK_DEP:-unlocked}"
}

begin_test "setup #5974: Remotes over an upstream with an ETag (RE) and without one (RN), cache TTL 1 s"
reset_case
RE="rgb-etag-${SUF}"; mkrepo "$RE" remote "${UP}/e"
RN="rgb-noetag-${SUF}"; mkrepo "$RN" remote "${UP}/n"
[ "$(put_tree /e "$UPD")" = "0" ] || fail_g "storing the /e tree failed"
[ "$(put_tree /n "$UPD" noetag=1)" = "0" ] || fail_g "storing the /n tree failed"
[ "$(set_ttl "$RE" 1)" = "1" ] || fail_g "cache-ttl 1 on ${RE} answered ${CODE}"
[ "$(set_ttl "$RN" 1)" = "1" ] || fail_g "cache-ttl 1 on ${RN} answered ${CODE}"
[ -s "$UPD/phase2/versions" ] && cmp -s <(head -c "$(wc -c < "$UPD/versions")" "$UPD/phase2/versions") "$UPD/versions" \
  || fail_g "the phase-2 versions document is not an append to the phase-1 one"
finish_case "the #5974 setup failed"

V1_LEN="$(wc -c < "$UPD/versions" | tr -d ' ')"
TAIL_FROM=$((V1_LEN - 10))

begin_test "FIX #5974: with an upstream ETag, /versions replays it with an RFC 9530 Repr-Digest of the body"
reset_case
c="$(fetchh "/gems/${RE}/versions" "$W/e.v")"
ET="$(hdr "$W/e.v" etag)"
UP_ET="$(curl -s -D - -o /dev/null "${MOCK}/e/versions" | grep -i '^etag:' | cut -d: -f2- | tr -d '\r ')"
note "/versions: ${c}, ETag ${ET:-absent} (upstream ${UP_ET:-absent}), Repr-Digest $(hdr "$W/e.v" repr-digest)"
[ "$c" = "200" ] && cmp -s "$W/e.v" "$UPD/versions" || fail_g "/versions answered ${c} or differs from the upstream bytes"
[ -n "$ET" ] && [ "$ET" = "$UP_ET" ] || fail_g "the ETag is '${ET:-absent}', want the upstream's ${UP_ET:-?}"
[ "$(hdr "$W/e.v" repr-digest)" = "$(repr_of "$UPD/versions")" ] \
  || fail_g "Repr-Digest is '$(hdr "$W/e.v" repr-digest)', want $(repr_of "$UPD/versions")"
[ "$(hdr "$W/e.v" accept-ranges)" = "bytes" ] || fail_g "no Accept-Ranges: bytes on /versions"
finish_case "a Remote's Compact Index carries no upstream validator"

begin_test "FIX #5974: If-None-Match with that ETag answers 304 with no body"
reset_case
c="$(fetchh "/gems/${RE}/versions" "$W/e.304" -H "If-None-Match: ${ET:-\"none\"}")"
[ "$c" = "304" ] && [ ! -s "$W/e.304" ] || fail_g "If-None-Match ${ET:-none} answered ${c} with $(wc -c < "$W/e.304" | tr -d ' ') bytes"
[ "$(hdr "$W/e.304" etag)" = "$ET" ] || fail_g "the 304 carries ETag '$(hdr "$W/e.304" etag)'"
c="$(fetchh "/gems/${RE}/info/dtfbundler-app" "$W/e.i1")"; IET="$(hdr "$W/e.i1" etag)"
c2="$(fetchh "/gems/${RE}/info/dtfbundler-app" "$W/e.i2" -H "If-None-Match: ${IET:-\"none\"}")"
[ "$c" = "200" ] && [ "$c2" = "304" ] || fail_g "info/dtfbundler-app: ${c}, then ${c2} on If-None-Match ${IET:-none}"
c="$(fetchh "/gems/${RE}/versions" "$W/e.nm" -H 'If-None-Match: "something-else"')"
[ "$c" = "200" ] && cmp -s "$W/e.nm" "$UPD/versions" || fail_g "a non-matching If-None-Match answered ${c}"
finish_case "a matching If-None-Match does not answer 304"

begin_test "FIX #5974: a Range on /versions answers 206 with the tail, Content-Range and the full document's Repr-Digest"
reset_case
c="$(fetchh "/gems/${RE}/versions" "$W/e.206" -H "Range: bytes=${TAIL_FROM}-")"
tail -c 10 "$UPD/versions" > "$W/e.tail"
note "Range bytes=${TAIL_FROM}-: ${c}, Content-Range $(hdr "$W/e.206" content-range), Repr-Digest $(hdr "$W/e.206" repr-digest)"
[ "$c" = "206" ] && cmp -s "$W/e.206" "$W/e.tail" || fail_g "Range answered ${c} with $(wc -c < "$W/e.206" | tr -d ' ') bytes, want 206 with the last 10"
[ "$(hdr "$W/e.206" content-range)" = "bytes ${TAIL_FROM}-$((V1_LEN - 1))/${V1_LEN}" ] || fail_g "Content-Range is '$(hdr "$W/e.206" content-range)'"
[ "$(hdr "$W/e.206" repr-digest)" = "$(repr_of "$UPD/versions")" ] || fail_g "the 206 Repr-Digest is not the full document's"
c="$(fetchh "/gems/${RE}/versions" "$W/e.ir" -H "Range: bytes=${TAIL_FROM}-" -H 'If-Range: "stale-validator"')"
[ "$c" = "200" ] && cmp -s "$W/e.ir" "$UPD/versions" || fail_g "a Range with a stale If-Range answered ${c}, want the full 200"
c="$(fetchh "/gems/${RE}/versions" "$W/e.416" -H "Range: bytes=$((V1_LEN + 5))-")"
[ "$c" = "416" ] && [ "$(hdr "$W/e.416" content-range)" = "bytes */${V1_LEN}" ] || fail_g "a Range past the end answered ${c} ($(hdr "$W/e.416" content-range))"
c="$(fetchh "/gems/${RE}/info/dtfbundler-app" "$W/e.ir2" -H 'Range: bytes=2-')"
[ "$c" = "200" ] && cmp -s "$W/e.ir2" "$UPD/info/dtfbundler-app" || fail_g "a Range on info/<name> answered ${c}, want the full 200"
finish_case "a Range on the Remote's /versions is not served as 206 with the full document's Repr-Digest"

begin_test "FIX #5974: real Bundler (ETag upstream): install, then update answers 304, then the released 1.1.0 arrives as a 206 append"
reset_case
note "bundler $(docker exec "$RUBY_CTR" bundle --version 2>/dev/null)"
bundler_run "$RE" app-e bundle install
[ "$RUN_RC" = "0" ] && [ "$RUN_LOCK_DEP" = "1.0.0" ] || fail_g "the cold bundle install failed (rc ${RUN_RC:-none}, dep ${RUN_LOCK_DEP:-unlocked})"
[ "$RUN_VERSIONS" = "200" ] || fail_g "the cold install's /versions requests answered [${RUN_VERSIONS}], want [200]"
bundler_run "$RE" app-e bundle update --all
[ "$RUN_RC" = "0" ] || fail_g "bundle update (no upstream change) failed"
[ "$RUN_VERSIONS" = "304" ] || fail_g "bundle update with an unchanged upstream got /versions [${RUN_VERSIONS}], want [304]"
[ "$(put_tree /e "$UPD/phase2")" = "0" ] || fail_g "storing phase 2 on /e failed"
sleep 2
bundler_run "$RE" app-e bundle update --all
echo "$RUN_OUT" | grep -E 'HTTP [0-9]{3}|RUN_RC|LOCK: +dtfbundler|Bundler::|rror' | sed 's/^/   | /' | tail -25
[ "$RUN_RC" = "0" ] || fail_g "bundle update after the release failed"
[ "$RUN_VERSIONS" = "206" ] || fail_g "bundle update after the append got /versions [${RUN_VERSIONS}], want [206] (a 200 after the 206 means Bundler rejected the Repr-Digest)"
[ "$RUN_LOCK_DEP" = "1.1.0" ] || fail_g "the update locked dtfbundler-dep ${RUN_LOCK_DEP:-nothing}, want 1.1.0"
[ "$RUN_CACHED" = "$(sha_of "$UPD/phase2/versions")" ] || fail_g "Bundler's appended versions cache is not the upstream phase-2 document"
finish_case "Bundler does not get 304 / 206 appends from a Remote whose upstream sends an ETag"

begin_test "GUARD #5974: without an upstream ETag, /versions has no validator and ignores Range and If-None-Match"
reset_case
c="$(fetchh "/gems/${RN}/versions" "$W/n.v")"
[ "$c" = "200" ] && cmp -s "$W/n.v" "$UPD/versions" || fail_g "/versions answered ${c} or differs from the upstream"
[ -z "$(hdr "$W/n.v" etag)" ] || fail_g "an ETag '$(hdr "$W/n.v" etag)' was made up for an upstream that sent none"
[ -z "$(hdr "$W/n.v" accept-ranges)" ] || fail_g "Accept-Ranges '$(hdr "$W/n.v" accept-ranges)' without a validator"
c="$(fetchh "/gems/${RN}/versions" "$W/n.r" -H "Range: bytes=${TAIL_FROM}-")"
[ "$c" = "200" ] && cmp -s "$W/n.r" "$UPD/versions" && [ -z "$(hdr "$W/n.r" content-range)" ] || fail_g "a Range answered ${c} ($(hdr "$W/n.r" content-range)), want the full 200"
for inm in '*' "${ET:-\"x\"}"; do
  c="$(fetchh "/gems/${RN}/versions" "$W/n.c" -H "If-None-Match: ${inm}")"
  [ "$c" = "200" ] && cmp -s "$W/n.c" "$UPD/versions" || fail_g "If-None-Match ${inm} answered ${c}, want the full 200"
done
finish_case "a Remote whose upstream sends no ETag answers conditional or range requests"

begin_test "GUARD #5974: real Bundler (no-ETag upstream): install and both updates get full 200s, never 206 or 304"
reset_case
bundler_run "$RN" app-n bundle install
[ "$RUN_RC" = "0" ] && [ "$RUN_LOCK_DEP" = "1.0.0" ] || fail_g "the cold bundle install failed (rc ${RUN_RC:-none})"
[ "$RUN_VERSIONS" = "200" ] || fail_g "cold install /versions [${RUN_VERSIONS}]"
bundler_run "$RN" app-n bundle update --all
[ "$RUN_RC" = "0" ] && [ "$RUN_VERSIONS" = "200" ] || fail_g "bundle update (unchanged) rc ${RUN_RC:-none}, /versions [${RUN_VERSIONS}], want [200]"
[ "$(put_tree /n "$UPD/phase2" noetag=1)" = "0" ] || fail_g "storing phase 2 on /n failed"
sleep 2
bundler_run "$RN" app-n bundle update --all
[ "$RUN_RC" = "0" ] && [ "$RUN_VERSIONS" = "200" ] || fail_g "bundle update (released) rc ${RUN_RC:-none}, /versions [${RUN_VERSIONS}], want [200]"
[ "$RUN_LOCK_DEP" = "1.1.0" ] || fail_g "the update locked dtfbundler-dep ${RUN_LOCK_DEP:-nothing}, want 1.1.0"
[ "$RUN_CACHED" = "$(sha_of "$UPD/phase2/versions")" ] || fail_g "Bundler's versions cache is not the phase-2 document"
finish_case "Bundler over a no-ETag upstream got a partial or not-modified answer"

end_suite
