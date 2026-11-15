#!/usr/bin/env bash
# =============================================================================
# tiers/scan-proxy-identity-npm-cargo/oracle.sh
#   #5140 a crate whose Cargo.toml says `readme = false` (or true) keeps its
#         identity and is scanned, not withheld 423 forever
#   #5143 a crate is graded on its own coordinate, not on its bundled Cargo.lock
#   #5148 an npm tarball whose package.json sits past the 10000-entry metadata
#         cap still establishes its identity; a refusal names the real cause
#         (scan_identity_unestablished), not a retryable scan_pending
#   #5149 a DefinitelyTyped-shaped tarball (top directory `dtfnode/`, not
#         `package/`) establishes its identity
#   #5231 a burst of first-time pulls does not lose its scans to the permit
#         queue: under record_only every file ends up with a verdict
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the
# mock's published control port), DB_CONTAINER, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test
# that swallows its own failure.

begin_suite "scan-proxy-identity-npm-cargo"
auth_admin
setup_workdir
W="$WORK_DIR"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
BURST="${SPI_BURST:-48}"

NPM_FC="spi-npmfc-${SUF}"     # npm Remote, scan_on_proxy, fail_closed
NPM_RO="spi-npmro-${SUF}"     # npm Remote, scan_on_proxy, record_only (#5231 burst)
NPM_OFF="spi-npmoff-${SUF}"   # npm Remote, no scanning (control)
CR_FC="spi-crfc-${SUF}"       # cargo Remote, scan_on_proxy, fail_closed
CR_OFF="spi-croff-${SUF}"     # cargo Remote, no scanning (control)
ALL_REPOS="$NPM_FC $NPM_RO $NPM_OFF $CR_FC $CR_OFF"

cleanup() {
  local k
  for k in $ALL_REPOS; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
uri() { jq -rn --arg v "$1" '$v|@uri'; }

BODY="${W}/body"
HDR="${W}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 150 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha_of "$BODY")
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
verdict_rows() { psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='$1'"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null || true
}
# The fixture file for an upstream path, and its sha256.
fx() { awk -F'\t' -v p="$1" '$1==p {print $2; exit}' "${W}/fx/files.tsv"; }
fx_sha() { sha_of "$(fx "$1")"; }

N="${BASE_URL}/npm"
C="${BASE_URL}/cargo"
npm_tgz() { echo "$1/-/${1##*/}-$2.tgz"; }           # name version -> path under the repo
crate_dl() { echo "api/v1/crates/$1/$2/download"; }  # name version -> path under the repo

# =============================================================================
# Setup
# =============================================================================
begin_test "Setup: fixtures built and stored in the mock upstream"
err=""
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"
  end_suite
fi
mkdir -p "${W}/fx"
n=$(BURST="$BURST" python3 -I "${HERE}/fixtures/build_fixtures.py" "${W}/fx" "$UP" 2>"${W}/fx.err") || n=""
if [ -z "$n" ]; then
  infra_fail "fixture build failed: $(head -c 300 "${W}/fx.err")"
  end_suite
fi
while IFS=$'\t' read -r p f ct; do
  b=$(curl -s --max-time 20 -X PUT --data-binary @"$f" "${MOCK}/__file?path=$(uri "$p")&ctype=$(uri "$ct")" \
        | jq -r '.bytes // empty' 2>/dev/null) || b=""
  [ "$b" = "$(stat -c %s "$f")" ] || err="${err} ${p}"
done < "${W}/fx/files.tsv"
if [ -z "$err" ]; then
  pass
else
  infra_fail "mock PUT failed for:${err}"
  end_suite
fi

begin_test "Setup: npm and cargo Remotes on the mock (fail_closed, record_only and unscanned)"
ok=1
for k in "$NPM_FC" "$NPM_RO" "$NPM_OFF"; do create_repo "$k" npm remote "${UP}/npm" || ok=0; done
for k in "$CR_FC" "$CR_OFF"; do create_repo "$k" cargo remote "${UP}/cargo" || ok=0; done
a="$(scan_cfg "$NPM_FC" fail_closed) $(scan_cfg "$NPM_RO" record_only) $(scan_cfg "$CR_FC" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed record_only fail_closed" ]; then
  pass
else
  infra_fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
  end_suite
fi

# =============================================================================
# Controls (pass on every image)
# =============================================================================
begin_test "CONTROL: the unscanned Remotes stream every fixture unchanged, no X-AK-Scan"
bad=""
for spec in "npm|dtf-idclean|1.0.0" "npm|dtf-late|1.0.0" "npm|@types/dtfnode|1.0.0" \
            "cargo|dtf-noreadme|1.0.0" "cargo|dtf-withlock|1.0.0"; do
  IFS='|' read -r f name ver <<<"$spec"
  if [ "$f" = npm ]; then
    p="$(npm_tgz "$name" "$ver")"; pull "${N}/${NPM_OFF}/${p}"; want=$(fx_sha "/npm/${p}")
  else
    p="$(crate_dl "$name" "$ver")"; pull "${C}/${CR_OFF}/${p}"; want=$(fx_sha "/cargo/${p}")
  fi
  [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$want" ] || bad="${bad} ${name}=${ST}/${SCAN}"
done
if [ -z "$bad" ]; then pass; else fail "not streamed as upstream sent them:${bad}"; fi

begin_test "CONTROL: an ordinary npm package (package/package.json first) is served 200 X-AK-Scan: clean under fail_closed"
p="$(npm_tgz dtf-idclean 1.0.0)"
pull "${N}/${NPM_FC}/${p}"
d=$(fx_sha "/npm/${p}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "CONTROL: npm lodash 4.17.15 is graded on its own coordinate: 403 scan_blocked under fail_closed"
p="$(npm_tgz lodash 4.17.15)"
pull "${N}/${NPM_FC}/${p}"
d=$(fx_sha "/npm/${p}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "CONTROL: a crate with readme = \"README.md\" is served 200 X-AK-Scan: clean under fail_closed"
p="$(crate_dl dtf-idcrate 1.0.0)"
pull "${C}/${CR_FC}/${p}"
d=$(fx_sha "/cargo/${p}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "CONTROL: crate regex 1.5.4 is graded on its own coordinate: 403 scan_blocked under fail_closed"
p="$(crate_dl regex 1.5.4)"
pull "${C}/${CR_FC}/${p}"
d=$(fx_sha "/cargo/${p}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

# =============================================================================
# #5140 Cargo readme = false / true
# =============================================================================
begin_test "FIX #5140: a crate whose Cargo.toml says readme = false is scanned and served 200 clean (was 423 every time)"
p="$(crate_dl dtf-noreadme 1.0.0)"
pull "${C}/${CR_FC}/${p}"; s1="$ST/$SCAN"; e1="$(body_err)"
d=$(fx_sha "/cargo/${p}")
pull "${C}/${CR_FC}/${p}"
if [ "$s1" = "200/clean" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "first=${s1} ${e1} second=${ST}/${SCAN} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #5140: a crate whose Cargo.toml says readme = true is scanned and served 200 clean"
p="$(crate_dl dtf-readmetrue 1.0.0)"
pull "${C}/${CR_FC}/${p}"
d=$(fx_sha "/cargo/${p}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

# =============================================================================
# #5143 Cargo: a bundled Cargo.lock is not what the crate is graded on
# =============================================================================
for name in dtf-withlock dtf-lockdeep; do
  case "$name" in dtf-withlock) where="at its root";; *) where="at fuzz/Cargo.lock";; esac
  begin_test "FIX #5143: a crate shipping a Cargo.lock ${where} that locks crossbeam-deque 0.7.3 is graded on its own coordinate: 200 clean (was 403)"
  p="$(crate_dl "$name" 1.0.0)"
  pull "${C}/${CR_FC}/${p}"
  d=$(fx_sha "/cargo/${p}")
  if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
    pass
  else
    fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
  fi
done

# =============================================================================
# #5148 npm: late package.json, and what a refusal says
# =============================================================================
begin_test "FIX #5148: an npm tarball whose package/package.json is entry 10051 establishes its identity: 200 clean (was 423 scan_pending forever)"
p="$(npm_tgz dtf-late 1.0.0)"
pull "${N}/${NPM_FC}/${p}"; s1="$ST/$SCAN"; e1="$(body_err)"
d=$(fx_sha "/npm/${p}")
pull "${N}/${NPM_FC}/${p}"
if [ "$s1" = "200/clean" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "first=${s1} ${e1} second=${ST}/${SCAN} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #5148: a late package.json that declares another version is refused 423 scan_identity_unestablished, not a retryable scan_pending; nothing is recorded"
p="$(npm_tgz dtf-late-liar 1.0.0)"
pull "${N}/${NPM_FC}/${p}"
d=$(fx_sha "/npm/${p}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_identity_unestablished" ] && [ "$(verdict_rows "$d")" = "0" ]; then
  pass
else
  fail "status=${ST} error='$(body_err)' body=$(snippet) verdict rows=$(verdict_rows "$d")"
fi

# =============================================================================
# #5149 npm: DefinitelyTyped archive root
# =============================================================================
begin_test "FIX #5149: @types/dtfnode, whose tarball root is dtfnode/ (not package/), establishes its identity: 200 clean (was 423 scan_pending forever)"
p="$(npm_tgz @types/dtfnode 1.0.0)"
pull "${N}/${NPM_FC}/${p}"; s1="$ST/$SCAN"; e1="$(body_err)"
d=$(fx_sha "/npm/${p}")
pull "${N}/${NPM_FC}/${p}"
if [ "$s1" = "200/clean" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "first=${s1} ${e1} second=${ST}/${SCAN} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

# =============================================================================
# #5231 a burst of first-time scans behind one permit
# =============================================================================
# The profile limits the backend to one concurrent scan. BURST packages are
# pulled at once through the record_only Remote (each served 200 at once;
# their scans queue). Before #5242 the 30 s inline budget ran from the
# moment a scan began WAITING for a permit and an over-budget scan was
# killed, so everything queued behind ~30 s of scanning never got a verdict.
# Since #5242 the budget counts from the permit and record_only scans stay
# queued until they run, so every file ends up with a verdict.
begin_test "FIX #5231: ${BURST} first-time npm pulls at once through a record_only Remote: every one is served and every one gets a verdict"
t0=$(date +%s)
for i in $(seq 1 "$BURST"); do
  n=$(printf 'dtf-burst-%02d' "$i")
  ( curl -s -o /dev/null -w '%{http_code}\n' --max-time 150 "${N}/${NPM_RO}/$(npm_tgz "$n" 1.0.0)" > "${W}/burst-${i}.st" 2>/dev/null || echo 000 > "${W}/burst-${i}.st" ) &
done
wait
served=$(cat "${W}"/burst-*.st 2>/dev/null | grep -c '^200$' || true)
digests=""
for i in $(seq 1 "$BURST"); do
  n=$(printf 'dtf-burst-%02d' "$i")
  digests="${digests}${digests:+,}'$(fx_sha "/npm/$(npm_tgz "$n" 1.0.0)")'"
done
with_verdict() { psql_q "SELECT count(DISTINCT checksum_sha256) FROM proxy_scan_results WHERE checksum_sha256 IN (${digests})"; }
# One permit drains the queue at the scanner's pace (~1.5 s a file here);
# allow 5 s a file, and stop early once no verdict has landed for 90 s (the
# pre-fix image drops the scans it cut off, so nothing more arrives).
deadline=$(( t0 + 30 + BURST * 5 ))
got=$(with_verdict); last="${got:-0}"; last_t=$(date +%s)
while [ "${got:-0}" -lt "$BURST" ] 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 5; got=$(with_verdict)
  if [ "${got:-0}" != "$last" ]; then last="${got:-0}"; last_t=$(date +%s);
  elif [ $(( $(date +%s) - last_t )) -ge 90 ]; then break; fi
done
el=$(( $(date +%s) - t0 ))
echo "   burst: ${served}/${BURST} served 200, ${got:-0}/${BURST} with a verdict after ${el}s"
if [ "$served" = "$BURST" ] && [ "${got:-0}" = "$BURST" ]; then
  pass
else
  lost=$(docker logs "ak-dtf${DTF_SLOT}-backend" 2>&1 | grep -c 'exceeded the budget' || true)
  fail "${served}/${BURST} served 200, ${got:-0}/${BURST} with a verdict after ${el}s; backend logged 'exceeded the budget' ${lost} times"
fi

end_suite
