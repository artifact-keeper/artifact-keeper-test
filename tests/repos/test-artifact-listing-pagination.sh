#!/usr/bin/env bash
# test-artifact-listing-pagination.sh - GET /api/v1/repositories/{key}/artifacts
# pages reach every item and report totals a client can loop on
# (artifact-keeper#5255).
#
# A client that reads pagination.total_pages from the FIRST response and
# fetches page=1..total_pages must see every artifact, and pagination.total
# must be the real count. Before the fix, without `count=exact`, total and
# total_pages were lower bounds ("rows seen so far, +1 when another page
# exists"): with 10 items and per_page=3, page 1 said total=4 total_pages=2,
# so such a client stopped after 6 items, and a page past the end said
# total=12. A Remote's listing is ordered by path, so the package a client
# never reached looked as if it had not been cached at all.
#
# Two legs, same assertions:
#   local   a hosted generic repo holding 10 uploaded files (no network)
#   remote  an Alpine Remote on ALPINE_MIRROR (default dl-cdn) after pulling
#           its APKINDEX and 9 packages through it (mysql-client, the package
#           named in the report, plus the 8 smallest in the index), so the
#           listing holds 10 cached items. The runner itself needs no
#           internet: the package names come from the index read through the
#           Remote. The backend must reach ALPINE_MIRROR.
#
# Per leg, with per_page=3 and REAL = the item set a per_page=100 walk over
# next_cursor/has_more returns:
#   - every uploaded / proxied item is listed, and q=<name> finds it
#   - count=exact total equals |REAL|
#   - page 1 (no count=exact) reports total == |REAL|
#   - page=1..(page 1's total_pages) reaches every item of REAL
#   - next_cursor while has_more reaches every item of REAL
#   - a page past the end returns no items and total <= |REAL|
#
# Env: BASE_URL ADMIN_USER ADMIN_PASS RUN_ID (common.sh), ALPINE_MIRROR,
#      ALPINE_BRANCH, ALPINE_REPOSITORY, ALPINE_ARCH, KEEP_REPOS=1.
#
# Requires: curl, jq, tar, gzip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "artifact-listing-pagination"
require_cmd jq
require_cmd tar
auth_admin
setup_workdir

ALPINE_MIRROR="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"
ALPINE_BRANCH="${ALPINE_BRANCH:-v3.24}"
ALPINE_REPOSITORY="${ALPINE_REPOSITORY:-main}"
ALPINE_ARCH="${ALPINE_ARCH:-x86_64}"
LAYOUT="${ALPINE_BRANCH}/${ALPINE_REPOSITORY}/${ALPINE_ARCH}"

PER_PAGE=3
LOCAL_KEY="test-listpage-gen-${RUN_ID}"
REMOTE_KEY="test-listpage-apk-${RUN_ID}"

if [ "${KEEP_REPOS:-0}" != "1" ]; then
  for k in "$LOCAL_KEY" "$REMOTE_KEY"; do
    add_exit_handler "curl -s -o /dev/null -X DELETE -H \"\$(auth_header)\" \"\${BASE_URL}/api/v1/repositories/${k}\" || true"
  done
fi

# list_json KEY QUERY -> response body ("" on error)
list_json() {
  curl -sf $CURL_TIMEOUT -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/$1/artifacts?$2" 2>/dev/null || true
}

# cursor_walk KEY PER_PAGE OUT: follow next_cursor while has_more, write the
# sorted paths to OUT. Fails if the walk does not terminate in 200 requests.
cursor_walk() {
  local key="$1" pp="$2" out="$3" q="per_page=$2" body cursor i
  : > "$out.raw"
  for i in $(seq 1 200); do
    body=$(list_json "$key" "$q")
    [ -n "$body" ] || return 1
    jq -r '.items[].path' <<<"$body" >> "$out.raw"
    [ "$(jq -r '.has_more // false' <<<"$body")" = "true" ] || { sort "$out.raw" > "$out"; return 0; }
    cursor=$(jq -r '.next_cursor // empty' <<<"$body")
    [ -n "$cursor" ] || return 1
    q="per_page=${pp}&cursor=$(jq -rn --arg c "$cursor" '$c|@uri')"
  done
  return 1
}

# listing_assertions LABEL KEY EXPECTED_PATHS_FILE QUERY_TERM
listing_assertions() {
  local label="$1" key="$2" expected="$3" term="$4"
  local real="${WORK_DIR}/${key}.real" n missing body total tp walked

  begin_test "${label}: every item is listed"
  if cursor_walk "$key" 100 "$real"; then
    n=$(wc -l < "$real" | tr -d ' ')
    missing=$(comm -23 <(sort "$expected") "$real" | tr '\n' ' ')
    if [ -z "$missing" ]; then
      echo "  ${n} items"
      pass
    else
      fail "not listed: ${missing}" "$(cat "$real")"
    fi
  else
    fail_fatal "per_page=100 cursor walk of ${key} did not complete"
  fi

  begin_test "${label}: q=${term} finds it"
  body=$(list_json "$key" "per_page=100&q=$(jq -rn --arg t "$term" '$t|@uri')")
  if jq -e --arg t "$term" '[.items[].path | select(contains($t))] | length > 0' <<<"$body" >/dev/null 2>&1; then
    pass
  else
    fail "q=${term} returned no item containing it" "${body:0:600}"
  fi

  begin_test "${label}: count=exact total equals the number of listed items"
  total=$(jq -r '.pagination.total // empty' <<<"$(list_json "$key" "per_page=${PER_PAGE}&count=exact")")
  if [ "$total" = "$n" ]; then pass; else fail "count=exact total=${total}, listed ${n}"; fi

  body=$(list_json "$key" "per_page=${PER_PAGE}&page=1")
  total=$(jq -r '.pagination.total // empty' <<<"$body")
  tp=$(jq -r '.pagination.total_pages // empty' <<<"$body")

  begin_test "${label}: page 1 reports pagination.total equal to the real count"
  if [ "$total" = "$n" ]; then
    pass
  else
    fail "page 1 total=${total} total_pages=${tp} per_page=${PER_PAGE}, real count ${n}" "$(jq -c '{pagination,has_more}' <<<"$body" 2>/dev/null)"
  fi

  begin_test "${label}: page=1..total_pages (total_pages from page 1) reaches every item"
  walked="${WORK_DIR}/${key}.paged"
  : > "$walked.raw"
  local p
  if [[ "$tp" =~ ^[0-9]+$ ]] && [ "$tp" -le 200 ]; then
    for p in $(seq 1 "$tp"); do
      list_json "$key" "per_page=${PER_PAGE}&page=${p}" | jq -r '.items[].path' >> "$walked.raw" 2>/dev/null || true
    done
  fi
  sort -u "$walked.raw" > "$walked"
  missing=$(comm -23 "$real" "$walked")
  if [ -z "$missing" ]; then
    pass
  else
    fail "page 1 said total_pages=${tp}; pages 1..${tp} returned $(wc -l < "$walked" | tr -d ' ') of ${n} items; never reached: $(tr '\n' ' ' <<<"$missing")"
  fi

  begin_test "${label}: next_cursor while has_more reaches every item"
  if cursor_walk "$key" "$PER_PAGE" "${WORK_DIR}/${key}.cursor" && cmp -s "$real" "${WORK_DIR}/${key}.cursor"; then
    pass
  else
    fail "per_page=${PER_PAGE} cursor walk differs from the per_page=100 walk" "$(diff "$real" "${WORK_DIR}/${key}.cursor" 2>&1 | head -20)"
  fi

  begin_test "${label}: a page past the end returns no items and total <= real count"
  p=$(( (n + PER_PAGE - 1) / PER_PAGE + 1 ))
  body=$(list_json "$key" "per_page=${PER_PAGE}&page=${p}")
  local cnt
  cnt=$(jq -r '.items | length' <<<"$body" 2>/dev/null || echo "?")
  total=$(jq -r '.pagination.total // empty' <<<"$body")
  if [ "$cnt" = 0 ] && [[ "$total" =~ ^[0-9]+$ ]] && [ "$total" -le "$n" ]; then
    pass
  else
    fail "page ${p}: items=${cnt} total=${total}, real count ${n}" "$(jq -c '{pagination,has_more}' <<<"$body" 2>/dev/null)"
  fi
}

# ===========================================================================
# Leg 1: hosted generic repository
# ===========================================================================

begin_test "local: create a generic repo and upload 10 files"
LOCAL_EXPECTED="${WORK_DIR}/local.expected"
: > "$LOCAL_EXPECTED"
ok=1
if create_local_repo "$LOCAL_KEY" generic; then
  for i in $(seq -w 1 10); do
    echo "listing-${RUN_ID}-${i}" > "${WORK_DIR}/f"
    api_upload "/api/v1/repositories/${LOCAL_KEY}/artifacts/listing/file-${i}.txt" "${WORK_DIR}/f" >/dev/null || ok=0
    echo "listing/file-${i}.txt" >> "$LOCAL_EXPECTED"
  done
else
  ok=0
fi
if [ "$ok" = 1 ]; then pass; else fail_fatal "could not create ${LOCAL_KEY} or upload its files"; fi

listing_assertions "local" "$LOCAL_KEY" "$LOCAL_EXPECTED" "file-07"

# ===========================================================================
# Leg 2: Alpine Remote on the public mirror
# ===========================================================================

begin_test "remote: create an Alpine Remote on ${ALPINE_MIRROR}"
if create_remote_repo "$REMOTE_KEY" alpine "$ALPINE_MIRROR"; then
  pass
else
  fail_fatal "could not create ${REMOTE_KEY}"
fi

REMOTE_EXPECTED="${WORK_DIR}/remote.expected"
A="${BASE_URL}/alpine/${REMOTE_KEY}/${LAYOUT}"

begin_test "remote: pull APKINDEX.tar.gz and 9 packages through the Remote"
st=$(curl -s -o "${WORK_DIR}/APKINDEX.tar.gz" -w '%{http_code}' --max-time 120 \
  -H "$(format_auth_header)" "${A}/APKINDEX.tar.gz") || st=000
remote_ok=0
if [ "$st" = 200 ] && tar -xzOf "${WORK_DIR}/APKINDEX.tar.gz" APKINDEX > "${WORK_DIR}/APKINDEX" 2>/dev/null; then
  # "<size> <P>-<V>.apk" per stanza; mysql-client first, then the 8 smallest.
  awk 'BEGIN{RS="";FS="\n"} {p="";v="";s=""; for(i=1;i<=NF;i++){
         if($i~/^P:/)p=substr($i,3); else if($i~/^V:/)v=substr($i,3); else if($i~/^S:/)s=substr($i,3)}
       if(p!="") print s, p "-" v ".apk", p}' "${WORK_DIR}/APKINDEX" > "${WORK_DIR}/sizes"
  { awk '$3=="mysql-client"{print $2}' "${WORK_DIR}/sizes"
    awk '$3!="mysql-client"' "${WORK_DIR}/sizes" | sort -k1,1n -k2,2 | awk 'NR<=8{print $2}'; } > "${WORK_DIR}/picked"
  echo "${LAYOUT}/APKINDEX.tar.gz" > "$REMOTE_EXPECTED"
  bad=""
  while read -r f; do
    want=$(awk -v f="$f" '$2==f{print $1}' "${WORK_DIR}/sizes")
    got=$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 120 \
      -H "$(format_auth_header)" "${A}/${f}") || got="000 0"
    [ "$got" = "200 ${want}" ] || bad="${bad} ${f}=[${got}]"
    echo "${LAYOUT}/${f}" >> "$REMOTE_EXPECTED"
  done < "${WORK_DIR}/picked"
  if [ "$(wc -l < "${WORK_DIR}/picked")" -eq 9 ] && [ -z "$bad" ]; then
    remote_ok=1
    tr '\n' ' ' < "${WORK_DIR}/picked"; echo
    pass
  else
    infra_fail "could not pull 9 packages through the Remote (expected '200 <S:>'):${bad}"
  fi
else
  infra_fail "GET ${A}/APKINDEX.tar.gz through the Remote returned HTTP ${st}; the backend could not reach ${ALPINE_MIRROR}"
fi

if [ "$remote_ok" = 1 ]; then
  # The cache catalog row is written as the proxied body is committed; give
  # it a few seconds before asserting on the listing.
  remote_cataloged() {
    [ "$(list_json "$REMOTE_KEY" 'per_page=100&count=exact' | jq -r '.pagination.total // 0')" -ge 10 ]
  }
  wait_until "the Remote's cache catalog to list the 10 pulled items" 30 remote_cataloged || true
  listing_assertions "remote" "$REMOTE_KEY" "$REMOTE_EXPECTED" "mysql-client"
fi

end_suite
