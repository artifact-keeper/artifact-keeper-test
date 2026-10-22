#!/usr/bin/env bash
# =============================================================================
# tiers/cran-remote-packages-index/oracle.sh
#   #4877 a CRAN remote repository serves its upstream's PACKAGES index
#         (records verbatim, plain and gzipped, gzip-only upstreams too) so a
#         real R client can install through it
# See the manifest for THE BUG, THE UPSTREAMS and the gates.
#
# run.sh exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
BASE="${BASE_URL}"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
MOCK_CTR="ak-dtf${SLOT}-mock-multi"
CLIENT="ak-dtf${SLOT}-client-cran"
MOCK="http://172.16.${SLOT}.91"
R_RICH="cranrem-${SLOT}-${SUF}"
R_GZ="cranremgz-${SLOT}-${SUF}"

W="$(mktemp -d -t dtf-cranrem-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
# get <path> <out> -> HTTP code (authenticated GET against the backend)
get() { curl -s -o "$2" -w '%{http_code}' --max-time 60 -u "$AUTH" "${BASE}$1" 2>/dev/null || echo 000; }
# mock_get <path> <out>: fetch straight from the upstream mock (from inside its
# container: the host cannot reach the 172.16 compose subnet under rootless podman).
mock_get() {
  docker exec "$MOCK_CTR" python3 -c \
    "import sys,urllib.request; sys.stdout.buffer.write(urllib.request.urlopen('http://127.0.0.1'+sys.argv[1],timeout=10).read())" \
    "$1" > "$2" 2>/dev/null
}
repo_create() { # key upstream -> key
  local body
  body="$(jq -nc --arg k "$1" --arg u "$2" \
    '{key:$k,name:$k,format:"cran",repo_type:"remote",upstream_url:$u,is_public:true}')"
  curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "${BASE}/api/v1/repositories" 2>/dev/null | tee "$W/create-$1" | jq -r '.key // empty' 2>/dev/null
}
# pairs <dcf>: sorted "Package=Version" of every record.
pairs() {
  awk 'BEGIN{RS=""} { p=""; v=""; n=split($0, L, "\n");
         for (i = 1; i <= n; i++) { if (L[i] ~ /^Package: /) p = substr(L[i], 10); if (L[i] ~ /^Version: /) v = substr(L[i], 10) }
         if (p != "") print p "=" v }' "$1" 2>/dev/null | sort
}
# record <dcf> <pkg> <ver>: the record's exact text (paragraph mode).
record() {
  awk -v want="$2=$3" 'BEGIN{RS=""} { p=""; v=""; n=split($0, L, "\n");
         for (i = 1; i <= n; i++) { if (L[i] ~ /^Package: /) p = substr(L[i], 10); if (L[i] ~ /^Version: /) v = substr(L[i], 10) }
         if (p "=" v == want) print $0 }' "$1" 2>/dev/null
}
field() { record "$1" "$2" "$3" | awk -v f="$4: " 'index($0, f) == 1 { print substr($0, length(f) + 1) }'; }
oneline() { tr '\n' ' ' | cut -c1-"${1:-300}"; }

begin_suite "cran-remote-packages-index"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: the upstream mock serves both CRAN upstreams; two public CRAN remotes on it; the R client is up"
SETUP_ERR=""
mock_get /ok/cranrich/src/contrib/PACKAGES "$W/up-rich" || SETUP_ERR="mock ${MOCK_CTR} did not serve /ok/cranrich PACKAGES;"
mock_get /ok/crangz/src/contrib/PACKAGES.gz "$W/up-gz.gz" || SETUP_ERR="${SETUP_ERR} mock did not serve /ok/crangz PACKAGES.gz;"
gunzip -c "$W/up-gz.gz" > "$W/up-gz" 2>/dev/null || SETUP_ERR="${SETUP_ERR} upstream PACKAGES.gz is not gzip;"
[ "$(pairs "$W/up-rich" | wc -l)" = "4" ] || SETUP_ERR="${SETUP_ERR} upstream index has $(pairs "$W/up-rich" | wc -l) records, want 4 (stale mock_multi.py?);"
[ "$(repo_create "$R_RICH" "${MOCK}/ok/cranrich")" = "$R_RICH" ] \
  || SETUP_ERR="${SETUP_ERR} create ${R_RICH}: $(oneline 200 < "$W/create-${R_RICH}");"
[ "$(repo_create "$R_GZ" "${MOCK}/ok/crangz")" = "$R_GZ" ] \
  || SETUP_ERR="${SETUP_ERR} create ${R_GZ}: $(oneline 200 < "$W/create-${R_GZ}");"
docker exec "$CLIENT" Rscript --version >/dev/null 2>&1 || SETUP_ERR="${SETUP_ERR} Rscript not runnable in ${CLIENT};"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi
echo "-- upstream records: $(pairs "$W/up-rich" | oneline)"

# =============================================================================
# The remote's index (before anything was fetched through it)
# =============================================================================
c_plain="$(get "/cran/${R_RICH}/src/contrib/PACKAGES" "$W/rem-plain")"
c_gz="$(get "/cran/${R_RICH}/src/contrib/PACKAGES.gz" "$W/rem.gz")"
echo "-- remote PACKAGES -> ${c_plain}, $(wc -c < "$W/rem-plain") bytes; PACKAGES.gz -> ${c_gz}"

begin_test "FIX(#4877): the remote's PACKAGES lists exactly the upstream's (Package, Version) pairs"
want="$(pairs "$W/up-rich" | oneline)"; got="$(pairs "$W/rem-plain" | oneline)"
if [ "$c_plain" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass; else
  fail "remote PACKAGES -> HTTP ${c_plain}, pairs [${got}], want [${want}] (an empty 200 is the #4877 bug)" \
    "$(head -c 300 "$W/rem-plain" | oneline)"
fi

begin_test "FIX(#4877): every upstream record comes through verbatim (Depends, Imports with its continuation line, LinkingTo, MD5sum)"
DIFF=""
while IFS='=' read -r p v; do
  [ -n "$p" ] || continue
  [ "$(record "$W/rem-plain" "$p" "$v")" = "$(record "$W/up-rich" "$p" "$v")" ] || DIFF="${DIFF} ${p} ${v};"
done < <(pairs "$W/up-rich")
dep="$(field "$W/rem-plain" dtfcrana 1.2.0 Depends)"
if [ "$c_plain" = "200" ] && [ -z "$DIFF" ] && [ "$dep" = "R (>= 3.5.0), dtfcranb" ] \
   && record "$W/rem-plain" dtfcrana 1.2.0 | grep -qx '        stats'; then
  pass
else
  fail "records that differ from the upstream's:${DIFF:- none}; dtfcrana 1.2.0 Depends='${dep}'" \
    "remote: $(record "$W/rem-plain" dtfcrana 1.2.0 | oneline) | upstream: $(record "$W/up-rich" dtfcrana 1.2.0 | oneline)"
fi

begin_test "FIX(#4877): PACKAGES.gz gunzips to the same document as PACKAGES"
gunzip -c "$W/rem.gz" > "$W/rem-gz" 2>/dev/null; gz_rc=$?
if [ "$c_gz" = "200" ] && [ "$gz_rc" = "0" ] && [ -s "$W/rem-gz" ] && cmp -s "$W/rem-gz" "$W/rem-plain"; then
  pass
else
  fail "PACKAGES.gz -> HTTP ${c_gz}, gunzip rc=${gz_rc}, $(wc -c < "$W/rem-gz" 2>/dev/null || echo 0) bytes vs PACKAGES $(wc -c < "$W/rem-plain") bytes; pairs [$(pairs "$W/rem-gz" | oneline)]"
fi

begin_test "FIX(#4877): a remote on a gzip-only upstream (PACKAGES 404, PACKAGES.gz 200) still yields the index, records verbatim"
c_gzo="$(get "/cran/${R_GZ}/src/contrib/PACKAGES" "$W/remgz-plain")"
want="$(pairs "$W/up-gz" | oneline)"; got="$(pairs "$W/remgz-plain" | oneline)"
if [ "$c_gzo" = "200" ] && [ -n "$want" ] && [ "$got" = "$want" ] \
   && [ "$(record "$W/remgz-plain" dtfcrangz 2.0.0)" = "$(record "$W/up-gz" dtfcrangz 2.0.0)" ] \
   && [ "$(field "$W/remgz-plain" dtfcrangz 2.0.0 Imports)" = "dtfcranc" ]; then
  pass
else
  fail "gzip-only remote PACKAGES -> HTTP ${c_gzo}, pairs [${got}], want [${want}]" "$(head -c 300 "$W/remgz-plain" | oneline)"
fi

# =============================================================================
# Downloads through the remote
# =============================================================================
begin_test "CONTROL: a tarball fetched through the remote is the upstream's bytes (md5 equals the upstream MD5sum)"
c_tb="$(get "/cran/${R_RICH}/src/contrib/dtfcranb_0.9.1.tar.gz" "$W/b.tgz")"
md5_got="$(md5sum "$W/b.tgz" 2>/dev/null | cut -d' ' -f1)"
md5_want="$(field "$W/up-rich" dtfcranb 0.9.1 MD5sum)"
if [ "$c_tb" = "200" ] && [ -n "$md5_want" ] && [ "$md5_got" = "$md5_want" ]; then pass; else
  fail "GET dtfcranb_0.9.1.tar.gz through the remote -> HTTP ${c_tb}, md5 ${md5_got}, want ${md5_want}"
fi

begin_test "FIX(#4877): R install.packages(\"dtfcrana\") through the remote resolves the graph from the index and installs dtfcrana 1.2.0, dtfcranb, dtfcranc"
# The remote is public, so the client needs no credentials; repos= names it
# alone, so nothing can come from anywhere else.
R_OUT="$(docker exec "$CLIENT" Rscript -e "
  lib <- tempfile('rlib'); dir.create(lib)
  options(warn = 1)
  install.packages('dtfcrana', repos = 'http://backend:8080/cran/${R_RICH}', type = 'source', lib = lib)
  ip <- installed.packages(lib.loc = lib)
  cat('INSTALLED', paste(sort(paste(ip[, 'Package'], ip[, 'Version'], sep = '=')), collapse = ' '), '\n')
  if ('dtfcrana' %in% rownames(ip)) { library('dtfcrana', lib.loc = lib, character.only = TRUE); cat('CALL', dtfcrana_hello(), '\n') }
" 2>&1)"
installed="$(printf '%s\n' "$R_OUT" | sed -n 's/^INSTALLED //p' | tail -n 1 | sed 's/ *$//')"
called="$(printf '%s\n' "$R_OUT" | sed -n 's/^CALL //p' | tail -n 1 | sed 's/ *$//')"
echo "-- R: installed [${installed}] call [${called}]"
if [ "$installed" = "dtfcrana=1.2.0 dtfcranb=0.9.1 dtfcranc=0.1.0" ] && [ "$called" = "dtfcrana-1.2.0" ]; then pass; else
  fail "install.packages through the remote installed [${installed}] (want dtfcrana=1.2.0 dtfcranb=0.9.1 dtfcranc=0.1.0), call [${called}]" \
    "$(printf '%s\n' "$R_OUT" | tail -n 12 | oneline 600)"
fi

begin_test "FIX(#4877): after those downloads the index still advertises each pair once and dtfcrana 1.2.0 keeps its Depends"
c_after="$(get "/cran/${R_RICH}/src/contrib/PACKAGES" "$W/rem-after")"
dups="$(awk 'BEGIN{RS=""} { p=""; v=""; n=split($0, L, "\n");
         for (i = 1; i <= n; i++) { if (L[i] ~ /^Package: /) p = substr(L[i], 10); if (L[i] ~ /^Version: /) v = substr(L[i], 10) }
         if (p != "") print p "=" v }' "$W/rem-after" | sort | uniq -d | oneline)"
want="$(pairs "$W/up-rich" | oneline)"; got="$(pairs "$W/rem-after" | sort -u | oneline)"
dep="$(field "$W/rem-after" dtfcrana 1.2.0 Depends)"
if [ "$c_after" = "200" ] && [ -z "$dups" ] && [ "$got" = "$want" ] && [ "$dep" = "R (>= 3.5.0), dtfcranb" ]; then pass; else
  fail "index after downloads -> HTTP ${c_after}, pairs [${got}] want [${want}], duplicated [${dups}], dtfcrana 1.2.0 Depends='${dep}'" \
    "$(record "$W/rem-after" dtfcrana 1.2.0 | oneline)"
fi

end_suite
