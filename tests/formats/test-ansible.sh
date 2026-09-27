#!/usr/bin/env bash
# test-ansible.sh - Ansible Galaxy collection E2E test
# Tests the Galaxy-compatible API at /ansible/{repo_key}/ and, for #3873,
# Galaxy pagination and link prefixes through the generic download URL.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "ansible"
auth_admin
setup_workdir

REPO_KEY="test-ansible-${RUN_ID}"

# -----------------------------------------------------------------------
begin_test "Create Ansible local repository"
# -----------------------------------------------------------------------
if create_local_repo "$REPO_KEY" "ansible"; then
  pass
else
  fail "could not create ansible repo"
fi

# -----------------------------------------------------------------------
begin_test "Upload Ansible collection"
# -----------------------------------------------------------------------
# Build a minimal collection tarball with galaxy.yml and MANIFEST.json
COLL_DIR="${WORK_DIR}/collection"
mkdir -p "${COLL_DIR}/testns/testcoll/plugins/modules"
mkdir -p "${COLL_DIR}/testns/testcoll/meta"

cat > "${COLL_DIR}/testns/testcoll/galaxy.yml" <<'GALAXYEOF'
namespace: testns
name: testcoll
version: "1.0.0"
readme: README.md
description: Test collection for E2E
authors:
  - Tester
license:
  - MIT
GALAXYEOF

cat > "${COLL_DIR}/testns/testcoll/MANIFEST.json" <<'MANIFESTEOF'
{
  "collection_info": {
    "namespace": "testns",
    "name": "testcoll",
    "version": "1.0.0",
    "description": "Test collection for E2E",
    "license": ["MIT"],
    "authors": ["Tester"],
    "dependencies": {}
  }
}
MANIFESTEOF

echo "# Test Collection" > "${COLL_DIR}/testns/testcoll/README.md"

cat > "${COLL_DIR}/testns/testcoll/plugins/modules/hello.py" <<'PYEOF'
#!/usr/bin/python
DOCUMENTATION = """
module: hello
short_description: Test module
"""
PYEOF

tar czf "${WORK_DIR}/testns-testcoll-1.0.0.tar.gz" -C "${COLL_DIR}" testns/testcoll

# Upload as multipart (Galaxy API expects multipart with 'file' field)
UPLOAD_STATUS=$(curl -s -o "${WORK_DIR}/upload-resp.json" -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "file=@${WORK_DIR}/testns-testcoll-1.0.0.tar.gz" \
  -F 'collection={"namespace":"testns","name":"testcoll","version":"1.0.0"};type=application/json' \
  "${BASE_URL}/ansible/${REPO_KEY}/api/v3/artifacts/collections/") || true

if [ "$UPLOAD_STATUS" -ge 200 ] 2>/dev/null && [ "$UPLOAD_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "upload returned HTTP ${UPLOAD_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Query Galaxy-compatible API endpoint"
# -----------------------------------------------------------------------
LIST_RESP=$(curl -sf \
  -H "$(format_auth_header)" \
  "${BASE_URL}/ansible/${REPO_KEY}/api/v3/collections/") || true

if [ -n "$LIST_RESP" ]; then
  if assert_contains "$LIST_RESP" "testcoll" "collection list missing testcoll"; then
    pass
  fi
else
  fail "list collections returned empty response"
fi

# -----------------------------------------------------------------------
begin_test "List artifacts via management API"
# -----------------------------------------------------------------------
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "testcoll" "artifact list should contain collection"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

# -----------------------------------------------------------------------
begin_test "Download and verify collection"
# -----------------------------------------------------------------------
# Download via the management API artifact endpoint
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded-collection.tar.gz" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testns/testcoll/1.0.0/testns-testcoll-1.0.0.tar.gz"; then
  if [ -f "${WORK_DIR}/downloaded-collection.tar.gz" ] && [ -s "${WORK_DIR}/downloaded-collection.tar.gz" ]; then
    pass
  else
    fail "downloaded file is empty"
  fi
else
  # Try the Galaxy download endpoint
  dl_status=$(curl -s -o "${WORK_DIR}/downloaded-collection.tar.gz" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/ansible/${REPO_KEY}/api/v3/collections/testns/testcoll/versions/1.0.0/download/" 2>/dev/null) || true
  if [ "$dl_status" = "200" ] && [ -s "${WORK_DIR}/downloaded-collection.tar.gz" ]; then
    pass
  elif [ "$dl_status" = "404" ] || [ "$dl_status" = "405" ]; then
    skip "download endpoint not available for this format (status: ${dl_status})"
  else
    fail "download failed (status: ${dl_status})"
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload second version"
# -----------------------------------------------------------------------
# Update version in galaxy.yml and MANIFEST.json for v2
cat > "${COLL_DIR}/testns/testcoll/galaxy.yml" <<'GALAXYEOF2'
namespace: testns
name: testcoll
version: "2.0.0"
readme: README.md
description: Test collection for E2E v2
authors:
  - Tester
license:
  - MIT
GALAXYEOF2

cat > "${COLL_DIR}/testns/testcoll/MANIFEST.json" <<'MANIFESTEOF2'
{
  "collection_info": {
    "namespace": "testns",
    "name": "testcoll",
    "version": "2.0.0",
    "description": "Test collection for E2E v2",
    "license": ["MIT"],
    "authors": ["Tester"],
    "dependencies": {}
  }
}
MANIFESTEOF2

tar czf "${WORK_DIR}/testns-testcoll-2.0.0.tar.gz" -C "${COLL_DIR}" testns/testcoll

V2_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "file=@${WORK_DIR}/testns-testcoll-2.0.0.tar.gz" \
  -F 'collection={"namespace":"testns","name":"testcoll","version":"2.0.0"};type=application/json' \
  "${BASE_URL}/ansible/${REPO_KEY}/api/v3/artifacts/collections/") || true

if [ "$V2_STATUS" -ge 200 ] 2>/dev/null && [ "$V2_STATUS" -lt 300 ] 2>/dev/null; then
  pass
elif [ "$V2_STATUS" = "404" ] || [ "$V2_STATUS" = "405" ]; then
  skip "version upload endpoint not available for this format (status: ${V2_STATUS})"
else
  fail "v2 upload returned HTTP ${V2_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Delete collection and verify removal"
# -----------------------------------------------------------------------
# Delete v1 via management API
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testns/testcoll/1.0.0/testns-testcoll-1.0.0.tar.gz" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testns/testcoll/1.0.0/testns-testcoll-1.0.0.tar.gz" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
elif [ "$status" = "404" ] || [ "$status" = "405" ]; then
  skip "delete not supported for this format (status: ${status})"
else
  fail "delete returned ${status}"
fi

# =======================================================================
# #3873: Galaxy pagination links keep the repository URL prefix
# =======================================================================
# Operators point ansible-galaxy at the GENERIC download URL of a Galaxy
# repository (/api/v1/repositories/{key}/download/). Every Galaxy link the
# backend hands out on that mount (first/previous/next/last, href,
# download_url) must stay under that same prefix, list endpoints must honour
# DRF limit/offset, and following `next` must advance (never re-serve page
# one). The dedicated /ansible/{key}/ mount must do the same with its own
# prefix. For a Remote repository the upstream's root-relative links
# (/api/v3/plugin/ansible/...) must never be forwarded.

# build_galaxy_collection NAMESPACE NAME VERSION OUT_TARBALL
# Writes a minimal but installable collection artifact: MANIFEST.json and
# FILES.json at the tarball root, with FILES.json checksummed from MANIFEST
# and every file checksummed in FILES.json (what ansible-galaxy verifies).
build_galaxy_collection() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import hashlib, io, json, sys, tarfile, time
ns, name, version, out = sys.argv[1:5]
sha = lambda b: hashlib.sha256(b).hexdigest()
readme = f"# {ns}.{name} {version}\n".encode()
module = b'#!/usr/bin/python\nDOCUMENTATION = """\nmodule: hello\nshort_description: test\n"""\n'
files = {"README.md": readme, "plugins/modules/hello.py": module}
entries = [{"name": ".", "ftype": "dir", "chksum_type": None, "chksum_sha256": None, "format": 1}]
for d in ("plugins", "plugins/modules"):
    entries.append({"name": d, "ftype": "dir", "chksum_type": None, "chksum_sha256": None, "format": 1})
for p, b in files.items():
    entries.append({"name": p, "ftype": "file", "chksum_type": "sha256", "chksum_sha256": sha(b), "format": 1})
files_json = json.dumps({"files": entries, "format": 1}, indent=2).encode()
manifest = json.dumps({
    "collection_info": {
        "namespace": ns, "name": name, "version": version,
        "authors": ["Tester"], "readme": "README.md", "tags": [],
        "description": "pagination test collection", "license": ["MIT"],
        "license_file": None, "dependencies": {}, "repository": None,
        "documentation": None, "homepage": None, "issues": None,
    },
    "file_manifest_file": {"name": "FILES.json", "ftype": "file", "chksum_type": "sha256",
                           "chksum_sha256": sha(files_json), "format": 1},
    "format": 1,
}, indent=2).encode()
now = int(time.time())
with tarfile.open(out, "w:gz") as tf:
    def add_dir(p):
        ti = tarfile.TarInfo(p); ti.type = tarfile.DIRTYPE; ti.mode = 0o755; ti.mtime = now; tf.addfile(ti)
    def add_file(p, b):
        ti = tarfile.TarInfo(p); ti.size = len(b); ti.mode = 0o644; ti.mtime = now; tf.addfile(ti, io.BytesIO(b))
    add_file("MANIFEST.json", manifest)
    add_file("FILES.json", files_json)
    add_dir("plugins"); add_dir("plugins/modules")
    for p, b in files.items():
        add_file(p, b)
PY
}

# strip_origin URL -> prints URL with a leading ${BASE_URL} origin removed, so
# links can be compared whether the backend spells them root-relative or
# absolute.
strip_origin() {
  local u="$1"
  printf '%s' "${u#"${BASE_URL}"}"
}

# walk_galaxy_versions PREFIX NS NAME LIMIT EXPECTED_SORTED_CSV AUTH_HEADER
# Pages PREFIX/api/v3/collections/NS/NAME/versions/?limit=LIMIT by following
# links.next. Checks on every page: HTTP 200 JSON; next equals
# PREFIX/.../versions/?limit=LIMIT&offset=<offset+LIMIT> (or null on the last
# page); every non-null first/previous/next/last link and every data[].href is
# under PREFIX; a followed page never repeats an already-seen version. At the
# end the union of versions must equal EXPECTED_SORTED_CSV with no duplicates.
# Prints "OK" or the list of problems on stdout.
walk_galaxy_versions() {
  local prefix="$1" ns="$2" name="$3" limit="$4" expected="$5" hdr="$6"
  local list_path="${prefix}/api/v3/collections/${ns}/${name}/versions/"
  local url="${BASE_URL}${list_path}?limit=${limit}"
  local offset=0 page=0 errs="" seen="" body status next exp_next link lk v href
  local body_file="${WORK_DIR}/walk-$$.json"
  while [ "$page" -lt 10 ]; do
    page=$((page + 1))
    status=$(curl -s -o "$body_file" -w '%{http_code}' --max-time 60 -H "$hdr" "$url") || status="000"
    body=$(cat "$body_file" 2>/dev/null || true)
    if [ "$status" != "200" ] || ! jq -e '.data | type == "array"' >/dev/null 2>&1 <<<"$body"; then
      errs="${errs}page ${page} (${url#"${BASE_URL}"}): HTTP ${status} body=$(head -c 200 <<<"$body"); "
      break
    fi
    for lk in first previous next last; do
      link=$(jq -r --arg k "$lk" '.links[$k] // empty' <<<"$body" 2>/dev/null || true)
      [ -z "$link" ] && continue
      link=$(strip_origin "$link")
      case "$link" in
        "${list_path}?"*) ;;
        *) errs="${errs}page ${page} links.${lk}='${link}' is not under ${list_path}; " ;;
      esac
    done
    while IFS= read -r href; do
      [ -z "$href" ] && continue
      href=$(strip_origin "$href")
      case "$href" in
        "${prefix}/"*) ;;
        *) errs="${errs}page ${page} data[].href='${href}' is not under ${prefix}/; " ;;
      esac
    done < <(jq -r '.data[].href // empty' <<<"$body" 2>/dev/null || true)
    local page_versions
    page_versions=$(jq -r '.data[].version' <<<"$body" 2>/dev/null || true)
    if [ -z "$page_versions" ]; then
      errs="${errs}page ${page} has empty data; "
    fi
    local pv_count
    pv_count=$(grep -c . <<<"$page_versions" || true)
    if [ "$pv_count" -gt "$limit" ]; then
      errs="${errs}page ${page} returned ${pv_count} versions for limit=${limit} (limit ignored); "
    fi
    while IFS= read -r v; do
      [ -z "$v" ] && continue
      if grep -qxF "$v" <<<"$seen"; then
        errs="${errs}page ${page} repeats version ${v} (page loop or overlap); "
      fi
      seen="${seen}${v}
"
    done <<<"$page_versions"
    next=$(jq -r '.links.next // empty' <<<"$body" 2>/dev/null || true)
    offset=$((offset + limit))
    [ -z "$next" ] && break
    next=$(strip_origin "$next")
    exp_next="${list_path}?limit=${limit}&offset=${offset}"
    if [ "$next" != "$exp_next" ]; then
      errs="${errs}page ${page} links.next='${next}' want '${exp_next}'; "
      case "$next" in
        "${prefix}/"*) ;;
        *) break ;;  # following it would leave the repository
      esac
    fi
    [ -n "$errs" ] && grep -q "repeats version" <<<"$errs" && break
    url="${BASE_URL}${next}"
  done
  rm -f "$body_file"
  local got
  got=$(grep . <<<"$seen" | sort -V | paste -sd, - || true)
  if [ "$got" != "$expected" ]; then
    errs="${errs}versions walked='${got}' want '${expected}'; "
  fi
  if [ -z "$errs" ]; then echo "OK"; else echo "$errs"; fi
}

# check_galaxy_download PREFIX NS NAME VERSION EXPECTED_SHA256 AUTH_HEADER
# The version detail's href and download_url must be under PREFIX, and the
# download_url must serve the tarball with the expected sha256.
check_galaxy_download() {
  local prefix="$1" ns="$2" name="$3" version="$4" want_sha="$5" hdr="$6"
  local detail status dl got_sha errs=""
  local f="${WORK_DIR}/detail-$$.json" t="${WORK_DIR}/dl-$$.tar.gz"
  status=$(curl -s -o "$f" -w '%{http_code}' --max-time 60 -H "$hdr" \
    "${BASE_URL}${prefix}/api/v3/collections/${ns}/${name}/versions/${version}/") || status="000"
  detail=$(cat "$f" 2>/dev/null || true)
  if [ "$status" != "200" ]; then
    echo "version detail HTTP ${status} body=$(head -c 200 <<<"$detail")"; rm -f "$f"; return
  fi
  local href
  href=$(strip_origin "$(jq -r '.href // empty' <<<"$detail" 2>/dev/null || true)")
  dl=$(strip_origin "$(jq -r '.download_url // empty' <<<"$detail" 2>/dev/null || true)")
  case "$href" in "${prefix}/"*) ;; *) errs="${errs}href='${href}' not under ${prefix}/; " ;; esac
  case "$dl" in
    "${prefix}/download/"*) ;;
    *) errs="${errs}download_url='${dl}' not under ${prefix}/download/; " ;;
  esac
  if [ -n "$dl" ]; then
    case "$dl" in http*) status="skipped-absolute" ;; *)
      status=$(curl -s -o "$t" -w '%{http_code}' --max-time 60 -H "$hdr" "${BASE_URL}${dl}") || status="000" ;;
    esac
    if [ "$status" = "200" ]; then
      got_sha=$(sha256sum "$t" | cut -d' ' -f1)
      [ "$got_sha" = "$want_sha" ] || errs="${errs}download sha256 ${got_sha} want ${want_sha}; "
    else
      errs="${errs}GET download_url HTTP ${status}; "
    fi
  fi
  rm -f "$f" "$t"
  if [ -z "$errs" ]; then echo "OK"; else echo "$errs"; fi
}

PG_REPO="test-ansible-pg-${RUN_ID}"
PG_NS="pagens"
PG_NAME="pagecoll"
PG_GENERIC="/api/v1/repositories/${PG_REPO}/download"
PG_MOUNT="/ansible/${PG_REPO}"
PG_READY=false

# -----------------------------------------------------------------------
begin_test "#3873: local repo holds 3 versions of pagens.pagecoll"
# -----------------------------------------------------------------------
if ! create_local_repo "$PG_REPO" "ansible"; then
  fail "could not create ansible repo ${PG_REPO}"
else
  pg_errs=""
  for v in 1.0.0 2.0.0 3.0.0; do
    tb="${WORK_DIR}/${PG_NS}-${PG_NAME}-${v}.tar.gz"
    build_galaxy_collection "$PG_NS" "$PG_NAME" "$v" "$tb"
    st=$(curl -s -o "${WORK_DIR}/pg-up.json" -w '%{http_code}' -X POST \
      -H "$(format_auth_header)" \
      -F "file=@${tb};filename=${PG_NS}-${PG_NAME}-${v}.tar.gz" \
      -F "sha256=$(sha256sum "$tb" | cut -d' ' -f1)" \
      "${BASE_URL}${PG_MOUNT}/api/v3/artifacts/collections/") || st="000"
    if [ "$st" -lt 200 ] 2>/dev/null || [ "$st" -ge 300 ] 2>/dev/null || [ "$st" = "000" ]; then
      pg_errs="${pg_errs}upload ${v}: HTTP ${st} $(head -c 200 "${WORK_DIR}/pg-up.json"); "
    fi
  done
  if [ -z "$pg_errs" ]; then PG_READY=true; pass; else fail "$pg_errs"; fi
fi

# -----------------------------------------------------------------------
begin_test "#3873: generic URL pages a local version list with links under the repository"
# -----------------------------------------------------------------------
if [ "$PG_READY" != true ]; then
  skip "local fixture repo not ready"
else
  # Page 1 of limit=2 must advertise exactly {generic}/...?limit=2&offset=2,
  # page 2 must be the last (next null), and 3 versions come back once each.
  r=$(walk_galaxy_versions "$PG_GENERIC" "$PG_NS" "$PG_NAME" 2 "1.0.0,2.0.0,3.0.0" "$(auth_header)")
  d=$(check_galaxy_download "$PG_GENERIC" "$PG_NS" "$PG_NAME" 2.0.0 \
    "$(sha256sum "${WORK_DIR}/${PG_NS}-${PG_NAME}-2.0.0.tar.gz" | cut -d' ' -f1)" "$(auth_header)")
  if [ "$r" = "OK" ] && [ "$d" = "OK" ]; then pass; else fail "walk: ${r} | detail: ${d}"; fi
fi

# -----------------------------------------------------------------------
begin_test "#3873: /ansible mount pages the same list with /ansible links"
# -----------------------------------------------------------------------
if [ "$PG_READY" != true ]; then
  skip "local fixture repo not ready"
else
  r=$(walk_galaxy_versions "$PG_MOUNT" "$PG_NS" "$PG_NAME" 2 "1.0.0,2.0.0,3.0.0" "$(format_auth_header)")
  d=$(check_galaxy_download "$PG_MOUNT" "$PG_NS" "$PG_NAME" 1.0.0 \
    "$(sha256sum "${WORK_DIR}/${PG_NS}-${PG_NAME}-1.0.0.tar.gz" | cut -d' ' -f1)" "$(format_auth_header)")
  if [ "$r" = "OK" ] && [ "$d" = "OK" ]; then pass; else fail "walk: ${r} | detail: ${d}"; fi
fi

# -----------------------------------------------------------------------
# Remote: the upstream answers like galaxy.ansible.com, with ROOT-RELATIVE
# links into its own /api/v3/plugin/... URL space. The mock ignores query
# strings, so it serves the whole 3-version list for every page request while
# advertising a limit=1 `next`; that is exactly the document the old generic
# route streamed back verbatim.
# -----------------------------------------------------------------------
RG_REPO="test-ansible-pgrem-${RUN_ID}"
RG_NS="upns"
RG_NAME="remcoll"
RG_GENERIC="/api/v1/repositories/${RG_REPO}/download"
RG_READY=false
RG_PLUGIN="/api/v3/plugin/ansible/content/published/collections/index"

begin_test "#3873: remote Galaxy repo over an upstream with root-relative links"
if [ -z "${MOCK_UPSTREAM_HOSTNAME:-}" ]; then
  skip "needs MOCK_UPSTREAM_HOSTNAME reachable from the backend pod"
elif ! start_mock_upstream "$(mktemp -d "$WORK_DIR/mock-galaxy.XXXXXX")"; then
  fail "mock upstream did not start"
else
  MF="${MOCK_STATE_DIR}/files"
  mkdir -p "${MF}/download" "${MF}/api/v3/collections/${RG_NS}/${RG_NAME}/versions"
  json_dir() {  # json_dir DIR JSON -> DIR/index.html served as application/json
    mkdir -p "$1"; printf '%s' "$2" > "$1/index.html"
    echo "Content-Type: application/json" > "$1/index.html.headers"
  }
  vdata='[]'
  for v in 3.0.0 2.0.0 1.0.0; do
    tb="${MF}/download/${RG_NS}-${RG_NAME}-${v}.tar.gz"
    build_galaxy_collection "$RG_NS" "$RG_NAME" "$v" "$tb"
    sha=$(sha256sum "$tb" | cut -d' ' -f1); size=$(stat -c %s "$tb")
    vdata=$(jq -c --arg v "$v" --arg p "$RG_PLUGIN" --arg ns "$RG_NS" --arg n "$RG_NAME" \
      '. + [{version:$v, href:($p + "/" + $ns + "/" + $n + "/versions/" + $v + "/"), created_at:"2026-01-01T00:00:00Z", updated_at:"2026-01-01T00:00:00Z", requires_ansible:">=2.14"}]' <<<"$vdata")
    json_dir "${MF}/api/v3/collections/${RG_NS}/${RG_NAME}/versions/${v}" "$(jq -nc \
      --arg v "$v" --arg ns "$RG_NS" --arg n "$RG_NAME" --arg sha "$sha" --argjson size "$size" \
      --arg p "$RG_PLUGIN" --arg up "${MOCK_BASE_URL}" \
      '{version:$v, namespace:{name:$ns}, name:$n,
        href:($p + "/" + $ns + "/" + $n + "/versions/" + $v + "/"),
        download_url:($up + "/api/v3/plugin/ansible/content/published/collections/artifacts/" + $ns + "-" + $n + "-" + $v + ".tar.gz"),
        artifact:{filename:($ns + "-" + $n + "-" + $v + ".tar.gz"), sha256:$sha, size:$size},
        collection:{name:$n}, requires_ansible:">=2.14", metadata:{dependencies:{}}, manifest:{}, files:{}}')"
  done
  json_dir "${MF}/api/v3/collections/${RG_NS}/${RG_NAME}/versions" "$(jq -nc --argjson d "$vdata" \
    --arg next "${RG_PLUGIN}/${RG_NS}/${RG_NAME}/versions/?limit=1&offset=1" \
    --arg first "${RG_PLUGIN}/${RG_NS}/${RG_NAME}/versions/?limit=1&offset=0" \
    --arg last "${RG_PLUGIN}/${RG_NS}/${RG_NAME}/versions/?limit=1&offset=2" \
    '{meta:{count:3}, links:{first:$first, previous:null, next:$next, last:$last}, data:$d}')"
  json_dir "${MF}/api/v3/collections/${RG_NS}/${RG_NAME}" "$(jq -nc --arg ns "$RG_NS" --arg n "$RG_NAME" --arg p "$RG_PLUGIN" \
    '{namespace:$ns, name:$n, href:($p + "/" + $ns + "/" + $n + "/"), versions_url:($p + "/" + $ns + "/" + $n + "/versions/"),
      highest_version:{version:"3.0.0", href:($p + "/" + $ns + "/" + $n + "/versions/3.0.0/")}, deprecated:false}')"
  json_dir "${MF}/api/v3/collections" "$(jq -nc --arg ns "$RG_NS" --arg n "$RG_NAME" --arg p "$RG_PLUGIN" \
    '{meta:{count:2}, links:{first:($p + "/?limit=1&offset=0"), previous:null, next:($p + "/?limit=1&offset=1"), last:($p + "/?limit=1&offset=1")},
      data:[{namespace:$ns, name:$n, href:($p + "/" + $ns + "/" + $n + "/"), highest_version:{version:"3.0.0", href:($p + "/" + $ns + "/" + $n + "/versions/3.0.0/")}}]}')"
  json_dir "${MF}/api" '{"available_versions":{"v3":"v3/"},"current_version":"v3"}'
  json_dir "${MF}/api/v3" "$(jq -nc --arg p "$RG_PLUGIN" '{collections:($p + "/")}')"
  if create_remote_repo "$RG_REPO" "ansible" "${MOCK_BASE_URL}"; then
    RG_READY=true; pass
  else
    fail "could not create remote ansible repo ${RG_REPO}"
  fi
fi

# -----------------------------------------------------------------------
begin_test "#3873: generic URL pages a remote version list inside the repository"
# -----------------------------------------------------------------------
if [ "$RG_READY" != true ]; then
  skip "remote fixture not ready"
else
  # limit=1 over 3 upstream versions: next must be {generic}/...?limit=1&offset=1
  # (not the upstream's /api/v3/plugin/... link), and following it must return
  # page 2 rather than re-serving page 1.
  r=$(walk_galaxy_versions "$RG_GENERIC" "$RG_NS" "$RG_NAME" 1 "1.0.0,2.0.0,3.0.0" "$(auth_header)")
  body=$(curl -s --max-time 60 -H "$(auth_header)" \
    "${BASE_URL}${RG_GENERIC}/api/v3/collections/${RG_NS}/${RG_NAME}/versions/?limit=1") || body=""
  if grep -q "/api/v3/plugin/" <<<"$body"; then
    r="${r}; response carries upstream /api/v3/plugin/ links"
  fi
  if [ "$r" = "OK" ]; then pass; else fail "$r"; fi
fi

# -----------------------------------------------------------------------
begin_test "#3873: remote download_url stays under the repository and serves the tarball"
# -----------------------------------------------------------------------
if [ "$RG_READY" != true ]; then
  skip "remote fixture not ready"
else
  d=$(check_galaxy_download "$RG_GENERIC" "$RG_NS" "$RG_NAME" 2.0.0 \
    "$(sha256sum "${MF}/download/${RG_NS}-${RG_NAME}-2.0.0.tar.gz" | cut -d' ' -f1)" "$(auth_header)")
  if [ "$d" = "OK" ]; then pass; else fail "$d"; fi
fi

# -----------------------------------------------------------------------
begin_test "#3873: remote collection list via generic URL carries no upstream-root links"
# -----------------------------------------------------------------------
if [ "$RG_READY" != true ]; then
  skip "remote fixture not ready"
else
  st=$(curl -s -o "${WORK_DIR}/rg-list.json" -w '%{http_code}' --max-time 60 -H "$(auth_header)" \
    "${BASE_URL}${RG_GENERIC}/api/v3/collections/?limit=1") || st="000"
  body=$(cat "${WORK_DIR}/rg-list.json" 2>/dev/null || true)
  errs=""
  [ "$st" = "200" ] || errs="HTTP ${st}; "
  for lk in first previous next last; do
    link=$(strip_origin "$(jq -r --arg k "$lk" '.links[$k] // empty' <<<"$body" 2>/dev/null || true)")
    [ -z "$link" ] && continue
    case "$link" in
      "${RG_GENERIC}/api/v3/collections/?"*) ;;
      *) errs="${errs}links.${lk}='${link}' not under ${RG_GENERIC}/api/v3/collections/; " ;;
    esac
  done
  if [ -z "$errs" ]; then pass; else fail "$errs"; fi
fi

# -----------------------------------------------------------------------
begin_test "#3873: ansible-galaxy collection install through the generic URL"
# -----------------------------------------------------------------------
if ! command -v ansible-galaxy >/dev/null 2>&1; then
  skip "ansible-galaxy CLI not installed"
elif [ "$PG_READY" != true ]; then
  skip "local fixture repo not ready"
else
  AG_HOME="${WORK_DIR}/ansible-home"
  mkdir -p "$AG_HOME"
  ag_errs=""
  targets="${PG_GENERIC}|${PG_NS}.${PG_NAME}:==2.0.0|${PG_NS}/${PG_NAME}"
  if [ "$RG_READY" = true ]; then
    targets="${targets} ${RG_GENERIC}|${RG_NS}.${RG_NAME}:==3.0.0|${RG_NS}/${RG_NAME}"
  fi
  for t in $targets; do
    IFS='|' read -r prefix req dir <<<"$t"
    out=$(ANSIBLE_HOME="$AG_HOME" ANSIBLE_LOCAL_TEMP="$AG_HOME/tmp" \
      ANSIBLE_GALAXY_CACHE_DIR="$AG_HOME/cache" ANSIBLE_GALAXY_DISABLE_GPG_VERIFY=1 \
      timeout 300 ansible-galaxy collection install "$req" \
        -s "${BASE_URL}${prefix}/" -p "${WORK_DIR}/collections" --force 2>&1) || \
      ag_errs="${ag_errs}install ${req} from ${prefix}/ failed: $(tail -c 400 <<<"$out"); "
    [ -f "${WORK_DIR}/collections/ansible_collections/${dir}/MANIFEST.json" ] || \
      ag_errs="${ag_errs}${req} not present under ${WORK_DIR}/collections; "
  done
  if [ -z "$ag_errs" ]; then pass; else fail "$ag_errs"; fi
fi

end_suite
