#!/usr/bin/env bash
# test-pypi-jupyterlab-extension-manager.sh - JupyterLab Extension Manager E2E
#
# JupyterLab 4's Extension Manager sidebar (jupyterlab/extensions/pypi.py,
# class PyPIExtensionManager) discovers and describes prebuilt extensions
# through two PyPI APIs that pip never touches, and installs through the one
# pip does:
#
#   discovery  POST {base_url}                    XML-RPC browse([classifier])
#   metadata   GET  {base_url}/{name}/json        legacy PyPI JSON API
#              GET  {base_url}/{name}/{version}/json
#   install    pip install name==version          PEP 503 {repo}/simple/
#
# with `c.PyPIExtensionManager.base_url = "<ak>/pypi/<repo>/pypi"` in the
# Jupyter server config. artifact-keeper#3783 adds the first two routes to
# the PyPI handler for hosted, remote and virtual repositories.
#
# This suite replays the manager's exact requests (verified against
# jupyterlab 4.6.3 source) against all three repository types, then runs
# the real manager class on top when AK_TEST_JUPYTERLAB=1.
#
# Fixture: two hand-built wheels, no build backend needed.
#   extension  Classifier: Framework :: Jupyter :: JupyterLab :: Extensions :: Prebuilt
#   control    no Jupyter classifier at all
# so every browse assertion has a package that MUST be listed and one that
# MUST NOT be. Matching is on exact "<normalised-name>==<version>" lines and
# exact wheel filenames (grep -qF / -qxF), never on a bare version string:
# every simple-index anchor carries a 64-char sha256 fragment, and a random
# hex digest contains "1.0.<digits>"-shaped substrings often enough to turn
# a negative assertion into a coin flip (see index_has_version in
# tests/pullthrough/test-ttl-expiry-refetch.sh).
#
# AK_TEST_JUPYTERLAB=1 additionally pip-installs jupyterlab==4.6.3 into the
# throwaway venv and calls PyPIExtensionManager.list_packages() against the
# hosted repository. format-tests.yml turns it on; the release gate leaves it
# off (it pulls ~100 MB of wheels from pypi.org per run and adds minutes to
# the python batch). The replayed requests cover the same wire contract in
# both, so the gate loses nothing that the manager would notice.
#
# AK_TEST_UPSTREAM_BASE_URL overrides the address the remote repository uses
# to reach the hosted one (default BASE_URL); see the note at its definition.
#
# Requires: python3 (venv, zipfile), curl, jq, sha256sum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-jupyterlab-extension-manager"
auth_admin
setup_workdir
require_cmd python3
require_cmd jq
require_cmd sha256sum

AK_TEST_JUPYTERLAB="${AK_TEST_JUPYTERLAB:-0}"
# Pinned: the driver below was written against this version's
# jupyterlab/extensions/pypi.py. No floating specifier (suite convention).
JUPYTERLAB_VERSION="4.6.3"
PREBUILT_CLASSIFIER="Framework :: Jupyter :: JupyterLab :: Extensions :: Prebuilt"

HOSTED_KEY="test-pypi-jlab-hosted-${RUN_ID}"
REMOTE_KEY="test-pypi-jlab-remote-${RUN_ID}"
VIRTUAL_KEY="test-pypi-jlab-virtual-${RUN_ID}"

# The Python module and wheel filename use underscores; the PEP 503
# normalised project name uses dashes. RUN_ID is folded to [a-z0-9_] so the
# module stays importable and normalisation cannot bite the exact-match
# assertions below.
RUN_TAG="$(printf '%s' "$RUN_ID" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_')"
EXT_MODULE="ak_jlab_ext_${RUN_TAG}"
CTL_MODULE="ak_jlab_ctl_${RUN_TAG}"
EXT_NAME="${EXT_MODULE//_/-}"
CTL_NAME="${CTL_MODULE//_/-}"
PKG_VERSION="1.0.$(date +%s)"
EXT_WHEEL_BASENAME="${EXT_MODULE}-${PKG_VERSION}-py3-none-any.whl"
CTL_WHEEL_BASENAME="${CTL_MODULE}-${PKG_VERSION}-py3-none-any.whl"

HOSTED_URL="${BASE_URL}/pypi/${HOSTED_KEY}"
REMOTE_URL="${BASE_URL}/pypi/${REMOTE_KEY}"
VIRTUAL_URL="${BASE_URL}/pypi/${VIRTUAL_KEY}"
# What c.PyPIExtensionManager.base_url is set to for each repository. The
# manager POSTs XML-RPC to this URL and appends /{name}/json to it.
HOSTED_BASE="${HOSTED_URL}/pypi"
REMOTE_BASE="${REMOTE_URL}/pypi"
VIRTUAL_BASE="${VIRTUAL_URL}/pypi"

TRUSTED_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||' | cut -d: -f1)

# The remote repository's upstream is the hosted repository on this same
# backend, addressed by BASE_URL like the pullthrough suites do. The backend
# resolves the upstream host and refuses loopback/private targets unless the
# deploy relaxes that (helm/values-test*.yaml sets UPSTREAM_ALLOW_PRIVATE_IPS
# / AK_SSRF_ALLOW_PRIVATE_CIDRS), and it refuses the literal "localhost" by
# name. A local run against http://127.0.0.1:PORT can point the upstream at
# an address the backend accepts with AK_TEST_UPSTREAM_BASE_URL.
UPSTREAM_BASE_URL="${AK_TEST_UPSTREAM_BASE_URL:-$BASE_URL}"

# The repositories are created is_public, and the manager sends whatever
# base_url carries: a bare URL means anonymous requests. Every replay below
# is therefore unauthenticated, exactly like the sidebar with the one-line
# config from the issue. Upload is the only authenticated call.

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# build_wheel MODULE VERSION OUT_PATH [CLASSIFIER ...]
#
# Writes a minimal but valid wheel (PEP 427): a one-file package plus
# METADATA / WHEEL / RECORD with real sha256 RECORD entries. Hand-built so
# the fixture needs no build backend from any index and so the classifier
# list is exactly what we say it is.
build_wheel() {
  local module="$1" version="$2" out="$3"
  shift 3
  python3 - "$module" "$version" "$out" "$@" <<'PY'
import base64, hashlib, sys, zipfile

module, version, out, *classifiers = sys.argv[1:]
dist_info = f"{module}-{version}.dist-info"
metadata = [
    "Metadata-Version: 2.1",
    f"Name: {module}",
    f"Version: {version}",
    f"Summary: Artifact Keeper JupyterLab Extension Manager fixture ({module})",
    "Home-page: https://github.com/artifact-keeper/artifact-keeper-test",
    "Author: artifact-keeper-test",
    "License: MIT",
    "Requires-Python: >=3.8",
]
metadata += [f"Classifier: {c}" for c in classifiers]
metadata += [
    "",
    "Fixture wheel for tests/formats/test-pypi-jupyterlab-extension-manager.sh.",
    "",
]
files = {
    f"{module}/__init__.py": f'__version__ = "{version}"\n',
    f"{dist_info}/METADATA": "\n".join(metadata),
    f"{dist_info}/WHEEL": (
        "Wheel-Version: 1.0\n"
        "Generator: test-pypi-jupyterlab-extension-manager\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ),
}
record = []
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for name, text in files.items():
        data = text.encode("utf-8")
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        zf.writestr(name, data)
        record.append(f"{name},sha256={digest},{len(data)}")
    record.append(f"{dist_info}/RECORD,,")
    zf.writestr(f"{dist_info}/RECORD", "\n".join(record) + "\n")
PY
}

# upload_wheel REPO_URL NAME VERSION WHEEL_PATH [CLASSIFIER ...] -> HTTP status
#
# Twine's multipart form. Twine sends every classifier as a repeated
# `classifiers` field next to the file, so we do too; the wheel's METADATA
# carries the same lines, so a backend that reads either source sees them.
upload_wheel() {
  local repo_url="$1" name="$2" version="$3" wheel="$4"
  shift 4
  local sha
  sha=$(sha256sum "$wheel" | awk '{print $1}')
  local -a classifier_fields=()
  local c
  for c in "$@"; do
    classifier_fields+=(-F "classifiers=${c}")
  done
  local status
  # shellcheck disable=SC2086  # CURL_TIMEOUT is deliberately word-split
  status=$(curl -s -o "${WORK_DIR}/upload.out" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "${repo_url}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "protocol_version=1" \
    -F "metadata_version=2.1" \
    -F "name=${name}" \
    -F "version=${version}" \
    -F "filetype=bdist_wheel" \
    -F "pyversion=py3" \
    -F "sha256_digest=${sha}" \
    "${classifier_fields[@]}" \
    -F "content=@${wheel};filename=$(basename "$wheel")" 2>/dev/null) || status="000"
  printf '%s' "$status"
}

# xml_text STRING -> STRING with &, <, > escaped for XML character data.
#
# sed rather than bash ${s//</&lt;}: bash 5.2 enables patsub_replacement by
# default, which turns the "&" in "&lt;" into the matched text.
xml_text() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# xmlrpc_call_body METHOD [STRING ...]
#
# Exactly what xmlrpc.client.dumps(([args],), "browse") puts on the wire for
# ServerProxy(base_url).browse([...]): one <array> param of <string>s. Extra
# STRINGs land in the same array (browse ANDs its classifiers).
xmlrpc_call_body() {
  local method="$1"
  shift
  local body
  body="<?xml version=\"1.0\"?><methodCall><methodName>$(xml_text "$method")</methodName><params><param><value><array><data>"
  local arg
  for arg in "$@"; do
    body="${body}<value><string>$(xml_text "$arg")</string></value>"
  done
  printf '%s</data></array></value></param></params></methodCall>' "$body"
}

# xmlrpc_post ENDPOINT BODY_FILE OUT_FILE -> HTTP status
#
# Same headers Python's xmlrpc.client Transport sends.
xmlrpc_post() {
  local endpoint="$1" body_file="$2" out="$3"
  local status
  # shellcheck disable=SC2086
  status=$(curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "$endpoint" \
    -H "Content-Type: text/xml" \
    -H "User-Agent: Python-xmlrpc/3.12" \
    --data-binary "@${body_file}" 2>/dev/null) || status="000"
  printf '%s' "$status"
}

# http_get ENDPOINT OUT_FILE -> HTTP status (anonymous GET)
http_get() {
  local url="$1" out="$2"
  local status
  # shellcheck disable=SC2086
  status=$(curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -H "Accept: application/json" "$url" 2>/dev/null) || status="000"
  printf '%s' "$status"
}

# browse_pairs RESPONSE_FILE
#
# Decodes an XML-RPC methodResponse with the stdlib client (the same parser
# JupyterLab uses) and prints one "<normalised-name>==<version>\t<raw-name>"
# line per [name, version] entry. Exit 2 on a <fault>, 3 on anything the
# parser rejects, 4/5 when the payload is not a list of 2-element lists.
browse_pairs() {
  python3 - "$1" <<'PY'
import re, sys, xmlrpc.client

with open(sys.argv[1], "rb") as fh:
    raw = fh.read()
try:
    (result,), _method = xmlrpc.client.loads(raw)
except xmlrpc.client.Fault as fault:
    print(f"FAULT {fault.faultCode}: {fault.faultString}", file=sys.stderr)
    sys.exit(2)
except Exception as exc:  # noqa: BLE001 - report the parser's own words
    print(f"MALFORMED: {exc}", file=sys.stderr)
    sys.exit(3)
if not isinstance(result, list):
    print(f"NOT A LIST: {type(result).__name__}", file=sys.stderr)
    sys.exit(4)
for entry in result:
    if not (isinstance(entry, (list, tuple)) and len(entry) == 2):
        print(f"BAD ENTRY: {entry!r}", file=sys.stderr)
        sys.exit(5)
    name, version = entry
    norm = re.sub(r"[-_.]+", "-", str(name)).lower()
    print(f"{norm}=={version}\t{name}")
PY
}

# pairs_have PAIRS NAME VERSION -> 0 if the exact "NAME==VERSION" line is present
pairs_have() {
  printf '%s\n' "$1" | cut -f1 | grep -qxF -- "${2}==${3}"
}

# normalise_name NAME -> PEP 503 normalised form
normalise_name() {
  printf '%s' "$1" | sed -E 's/[-_.]+/-/g' | tr '[:upper:]' '[:lower:]'
}

# check_release_entry JSON_FILE JQ_FILTER FILENAME SHA256 URL_PREFIX LABEL [DIGESTS]
#
# JQ_FILTER must select one file object from the legacy JSON document. Checks
# the legacy keys, the exact filename, the sha256 digest against the bytes
# we uploaded, packagetype, yanked, and that `url` points back into
# URL_PREFIX (absolute URL or absolute path). On success sets RESOLVED_URL to
# something curl can fetch.
#
# DIGESTS is "exact" (default) or "relay". "exact" pins the artifact-keeper#3783
# scope decision for documents AK builds itself (hosted, virtual over hosted):
# only the digest AK computed on ingest is emitted, so the key set is exactly
# sha256; pypi.org's md5/blake2b_256 are neither stored nor synthesised. A
# remote relays the upstream document, digests included (a pypi.org upstream
# yields blake2b_256+md5+sha256), so its callers pass "relay" and only the
# sha256 value is checked.
check_release_entry() {
  local json="$1" filter="$2" filename="$3" sha="$4" url_prefix="$5" label="$6"
  local digests="${7:-exact}"
  local entry
  entry=$(jq -c "$filter" "$json" 2>/dev/null) || entry=""
  if [ -z "$entry" ] || [ "$entry" = "null" ]; then
    fail "${label}: no file entry matched ${filter}" "$(head -c 1200 "$json")"
    return 1
  fi
  local missing
  missing=$(jq -r '(["filename","url","digests","packagetype","requires_python","yanked"] - keys) | join(",")' <<<"$entry")
  if [ -n "$missing" ]; then
    fail "${label}: file entry is missing legacy JSON keys: ${missing}" "$entry"
    return 1
  fi
  local got_filename got_sha got_type got_yanked got_url
  got_filename=$(jq -r '.filename' <<<"$entry")
  got_sha=$(jq -r '.digests.sha256 // empty' <<<"$entry")
  got_type=$(jq -r '.packagetype' <<<"$entry")
  got_yanked=$(jq -r '.yanked' <<<"$entry")
  got_url=$(jq -r '.url' <<<"$entry")
  if [ "$got_filename" != "$filename" ]; then
    fail "${label}: filename '${got_filename}' != '${filename}'" "$entry"
    return 1
  fi
  if [ "$got_sha" != "$sha" ]; then
    fail "${label}: digests.sha256 '${got_sha}' != sha256sum of uploaded wheel '${sha}'" "$entry"
    return 1
  fi
  if [ "$digests" = "exact" ]; then
    local digest_keys
    digest_keys=$(jq -r '.digests | keys | join(",")' <<<"$entry")
    if [ "$digest_keys" != "sha256" ]; then
      fail "${label}: digests keys are '${digest_keys}', expected exactly 'sha256'" "$entry"
      return 1
    fi
  fi
  if [ "$got_type" != "bdist_wheel" ]; then
    fail "${label}: packagetype '${got_type}' != 'bdist_wheel'" "$entry"
    return 1
  fi
  if [ "$got_yanked" != "false" ]; then
    fail "${label}: yanked '${got_yanked}' != false" "$entry"
    return 1
  fi
  case "$got_url" in
    "${url_prefix}"*)
      RESOLVED_URL="$got_url"
      ;;
    "${url_prefix#"${BASE_URL}"}"*)
      # Path-absolute rewrite (same shape the simple index uses).
      RESOLVED_URL="${BASE_URL}${got_url}"
      ;;
    *)
      fail "${label}: url '${got_url}' is not rewritten under ${url_prefix}" "$entry"
      return 1
      ;;
  esac
  return 0
}

# download_matches URL SHA256 LABEL -> 0 when the bytes at URL hash to SHA256
download_matches() {
  local url="$1" sha="$2" label="$3"
  local out="${WORK_DIR}/download.$$.whl"
  local status
  # shellcheck disable=SC2086
  status=$(curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT -L "$url" 2>/dev/null) || status="000"
  if [ "$status" != "200" ]; then
    fail "${label}: GET ${url} returned HTTP ${status}" "$(head -c 400 "$out" 2>/dev/null)"
    return 1
  fi
  local got
  got=$(sha256sum "$out" | awk '{print $1}')
  rm -f "$out"
  if [ "$got" != "$sha" ]; then
    fail "${label}: downloaded bytes hash to ${got}, expected ${sha}"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Section 1: hosted repository + fixtures
# ---------------------------------------------------------------------------

begin_test "Create hosted PyPI repository"
if create_local_repo "$HOSTED_KEY" "pypi"; then
  pass
else
  fail "could not create hosted PyPI repository ${HOSTED_KEY}"
fi

begin_test "Build extension and control wheels"
EXT_WHEEL="${WORK_DIR}/${EXT_WHEEL_BASENAME}"
CTL_WHEEL="${WORK_DIR}/${CTL_WHEEL_BASENAME}"
build_wheel "$EXT_MODULE" "$PKG_VERSION" "$EXT_WHEEL" \
  "$PREBUILT_CLASSIFIER" "Programming Language :: Python :: 3"
build_wheel "$CTL_MODULE" "$PKG_VERSION" "$CTL_WHEEL" \
  "Programming Language :: Python :: 3"
if [ -s "$EXT_WHEEL" ] && [ -s "$CTL_WHEEL" ] \
   && python3 -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).testzip(); zipfile.ZipFile(sys.argv[2]).testzip()" \
        "$EXT_WHEEL" "$CTL_WHEEL" 2>/dev/null; then
  pass
else
  fail "wheel fixtures were not built"
fi
EXT_SHA256=$(sha256sum "$EXT_WHEEL" | awk '{print $1}')
CTL_SHA256=$(sha256sum "$CTL_WHEEL" | awk '{print $1}')

begin_test "Upload extension wheel (Prebuilt classifier) via twine protocol"
status=$(upload_wheel "$HOSTED_URL" "$EXT_MODULE" "$PKG_VERSION" "$EXT_WHEEL" \
  "$PREBUILT_CLASSIFIER" "Programming Language :: Python :: 3")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "upload of ${EXT_WHEEL_BASENAME} returned HTTP ${status}" "$(head -c 400 "${WORK_DIR}/upload.out")"
fi

begin_test "Upload control wheel (no Jupyter classifier) via twine protocol"
status=$(upload_wheel "$HOSTED_URL" "$CTL_MODULE" "$PKG_VERSION" "$CTL_WHEEL" \
  "Programming Language :: Python :: 3")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "upload of ${CTL_WHEEL_BASENAME} returned HTTP ${status}" "$(head -c 400 "${WORK_DIR}/upload.out")"
fi

begin_test "Simple index lists both wheels by exact filename"
sleep 1
simple_ext=$(curl -sf --max-time 30 "${HOSTED_URL}/simple/${EXT_NAME}/" 2>/dev/null) || simple_ext=""
simple_ctl=$(curl -sf --max-time 30 "${HOSTED_URL}/simple/${CTL_NAME}/" 2>/dev/null) || simple_ctl=""
if printf '%s' "$simple_ext" | grep -qF -- "$EXT_WHEEL_BASENAME" \
   && printf '%s' "$simple_ctl" | grep -qF -- "$CTL_WHEEL_BASENAME"; then
  pass
else
  fail "simple index does not list ${EXT_WHEEL_BASENAME} and ${CTL_WHEEL_BASENAME}" \
    "ext: $(head -c 400 <<<"$simple_ext")
ctl: $(head -c 400 <<<"$simple_ctl")"
fi

# ---------------------------------------------------------------------------
# Section 2: XML-RPC browse (discovery) on the hosted repository
# ---------------------------------------------------------------------------

BROWSE_BODY="${WORK_DIR}/browse.xml"
xmlrpc_call_body "browse" "$PREBUILT_CLASSIFIER" > "$BROWSE_BODY"

# Name the manager will use for the JSON routes: whatever browse returned.
# Falls back to the normalised name if browse fails so later sections still
# report their own verdicts instead of cascading.
EXT_JSON_NAME="$EXT_NAME"

begin_test "XML-RPC browse([Prebuilt]) lists the extension and not the control"
status=$(xmlrpc_post "$HOSTED_BASE" "$BROWSE_BODY" "${WORK_DIR}/browse-hosted.out")
if [ "$status" != "200" ]; then
  fail "POST ${HOSTED_BASE} browse returned HTTP ${status}" "$(head -c 600 "${WORK_DIR}/browse-hosted.out")"
elif ! pairs=$(browse_pairs "${WORK_DIR}/browse-hosted.out" 2>"${WORK_DIR}/browse-hosted.err"); then
  fail "browse response did not decode as an XML-RPC array of [name, version]: $(cat "${WORK_DIR}/browse-hosted.err")" \
    "$(head -c 600 "${WORK_DIR}/browse-hosted.out")"
elif ! pairs_have "$pairs" "$EXT_NAME" "$PKG_VERSION"; then
  fail "browse result lacks ${EXT_NAME}==${PKG_VERSION}" "$pairs"
elif pairs_have "$pairs" "$CTL_NAME" "$PKG_VERSION"; then
  fail "browse result lists the control package ${CTL_NAME}==${PKG_VERSION}, which has no Prebuilt classifier" "$pairs"
else
  EXT_JSON_NAME=$(printf '%s\n' "$pairs" | grep -F -- "${EXT_NAME}==${PKG_VERSION}"$'\t' | head -n1 | cut -f2)
  [ -n "$EXT_JSON_NAME" ] || EXT_JSON_NAME="$EXT_NAME"
  pass
fi

begin_test "XML-RPC browse requires every requested classifier (AND semantics)"
xmlrpc_call_body "browse" "$PREBUILT_CLASSIFIER" "Framework :: Jupyter :: ak-test-nonexistent-${RUN_TAG}" \
  > "${WORK_DIR}/browse-and.xml"
status=$(xmlrpc_post "$HOSTED_BASE" "${WORK_DIR}/browse-and.xml" "${WORK_DIR}/browse-and.out")
if [ "$status" != "200" ]; then
  fail "browse with an unmatched second classifier returned HTTP ${status}" "$(head -c 600 "${WORK_DIR}/browse-and.out")"
elif ! pairs=$(browse_pairs "${WORK_DIR}/browse-and.out" 2>"${WORK_DIR}/browse-and.err"); then
  fail "response did not decode as an XML-RPC array: $(cat "${WORK_DIR}/browse-and.err")" \
    "$(head -c 600 "${WORK_DIR}/browse-and.out")"
elif pairs_have "$pairs" "$EXT_NAME" "$PKG_VERSION"; then
  fail "extension listed although it lacks the second requested classifier (browse must AND classifiers)" "$pairs"
else
  pass
fi

begin_test "xmlrpc.client.ServerProxy(base_url).browse() agrees with the replay"
# The literal call from PyPIExtensionManager.__get_all_extensions, stdlib
# only, so this runs everywhere the replay runs.
if proxy_out=$(python3 - "$HOSTED_BASE" "$PREBUILT_CLASSIFIER" 2>"${WORK_DIR}/serverproxy.err" <<'PY'
import re, sys, xmlrpc.client
base_url, classifier = sys.argv[1:]
for name, version in xmlrpc.client.ServerProxy(base_url).browse([classifier]):
    print(f"{re.sub(r'[-_.]+', '-', str(name)).lower()}=={version}")
PY
); then
  if printf '%s\n' "$proxy_out" | grep -qxF -- "${EXT_NAME}==${PKG_VERSION}" \
     && ! printf '%s\n' "$proxy_out" | grep -qxF -- "${CTL_NAME}==${PKG_VERSION}"; then
    pass
  else
    fail "ServerProxy.browse() result differs from expectation" "$proxy_out"
  fi
else
  fail "xmlrpc.client.ServerProxy(${HOSTED_BASE}).browse() raised" "$(cat "${WORK_DIR}/serverproxy.err")"
fi

# ---------------------------------------------------------------------------
# Section 3: legacy JSON API on the hosted repository
# ---------------------------------------------------------------------------

begin_test "GET /{name}/json returns the legacy shape with classifiers and releases"
EXT_JSON="${WORK_DIR}/ext-hosted.json"
status=$(http_get "${HOSTED_BASE}/${EXT_JSON_NAME}/json" "$EXT_JSON")
if [ "$status" != "200" ]; then
  fail "GET ${HOSTED_BASE}/${EXT_JSON_NAME}/json returned HTTP ${status}" "$(head -c 600 "$EXT_JSON")"
elif ! jq -e '.info and .releases and .urls' "$EXT_JSON" >/dev/null 2>&1; then
  fail "document lacks top-level info/releases/urls" "$(head -c 1200 "$EXT_JSON")"
else
  info_name=$(normalise_name "$(jq -r '.info.name // empty' "$EXT_JSON")")
  info_version=$(jq -r '.info.version // empty' "$EXT_JSON")
  info_missing=$(jq -r '(["name","version","summary","classifiers","requires_python"] - (.info | keys)) | join(",")' "$EXT_JSON")
  if [ "$info_name" != "$EXT_NAME" ]; then
    fail "info.name normalises to '${info_name}', expected '${EXT_NAME}'" "$(jq -c .info "$EXT_JSON")"
  elif [ "$info_version" != "$PKG_VERSION" ]; then
    fail "info.version '${info_version}' != '${PKG_VERSION}'" "$(jq -c .info "$EXT_JSON")"
  elif [ -n "$info_missing" ]; then
    fail "info is missing keys the manager reads: ${info_missing}" "$(jq -c .info "$EXT_JSON")"
  elif ! jq -e --arg c "$PREBUILT_CLASSIFIER" 'any(.info.classifiers[]?; . == $c)' "$EXT_JSON" >/dev/null 2>&1; then
    fail "info.classifiers does not contain the exact string '${PREBUILT_CLASSIFIER}'" "$(jq -c .info.classifiers "$EXT_JSON")"
  elif ! jq -e --arg v "$PKG_VERSION" '.releases | has($v)' "$EXT_JSON" >/dev/null 2>&1; then
    fail "releases has no '${PKG_VERSION}' key" "$(jq -c '.releases | keys' "$EXT_JSON")"
  elif check_release_entry "$EXT_JSON" \
         "first(.releases[\"${PKG_VERSION}\"][]? | select(.filename == \"${EXT_WHEEL_BASENAME}\"))" \
         "$EXT_WHEEL_BASENAME" "$EXT_SHA256" "${HOSTED_URL}/" "releases[${PKG_VERSION}]"; then
    pass
  fi
fi

begin_test "releases[version].url downloads the uploaded bytes from this repository"
if [ -z "${RESOLVED_URL:-}" ]; then
  skip "no resolvable url from the previous test"
elif download_matches "$RESOLVED_URL" "$EXT_SHA256" "hosted releases url"; then
  pass
fi
RESOLVED_URL=""

begin_test "GET /{name}/{version}/json returns the requested version with urls[]"
EXT_VJSON="${WORK_DIR}/ext-hosted-version.json"
status=$(http_get "${HOSTED_BASE}/${EXT_JSON_NAME}/${PKG_VERSION}/json" "$EXT_VJSON")
if [ "$status" != "200" ]; then
  fail "GET ${HOSTED_BASE}/${EXT_JSON_NAME}/${PKG_VERSION}/json returned HTTP ${status}" "$(head -c 600 "$EXT_VJSON")"
elif [ "$(jq -r '.info.version // empty' "$EXT_VJSON")" != "$PKG_VERSION" ]; then
  fail "info.version is not ${PKG_VERSION}" "$(jq -c .info "$EXT_VJSON")"
elif ! jq -e --arg c "$PREBUILT_CLASSIFIER" 'any(.info.classifiers[]?; . == $c)' "$EXT_VJSON" >/dev/null 2>&1; then
  fail "info.classifiers on the version route lacks the Prebuilt classifier" "$(jq -c .info.classifiers "$EXT_VJSON")"
elif check_release_entry "$EXT_VJSON" \
       "first(.urls[]? | select(.filename == \"${EXT_WHEEL_BASENAME}\"))" \
       "$EXT_WHEEL_BASENAME" "$EXT_SHA256" "${HOSTED_URL}/" "urls[]"; then
  pass
fi
RESOLVED_URL=""

begin_test "Control package JSON carries its own digest and no Prebuilt classifier"
CTL_JSON="${WORK_DIR}/ctl-hosted.json"
status=$(http_get "${HOSTED_BASE}/${CTL_NAME}/json" "$CTL_JSON")
if [ "$status" != "200" ]; then
  fail "GET ${HOSTED_BASE}/${CTL_NAME}/json returned HTTP ${status}" "$(head -c 600 "$CTL_JSON")"
elif jq -e --arg c "$PREBUILT_CLASSIFIER" 'any(.info.classifiers[]?; . == $c)' "$CTL_JSON" >/dev/null 2>&1; then
  fail "control package reports the Prebuilt classifier it was never given" "$(jq -c .info.classifiers "$CTL_JSON")"
elif check_release_entry "$CTL_JSON" \
       "first(.releases[\"${PKG_VERSION}\"][]? | select(.filename == \"${CTL_WHEEL_BASENAME}\"))" \
       "$CTL_WHEEL_BASENAME" "$CTL_SHA256" "${HOSTED_URL}/" "control releases[${PKG_VERSION}]"; then
  pass
fi
RESOLVED_URL=""

# ---------------------------------------------------------------------------
# Section 4: negative paths
# ---------------------------------------------------------------------------

begin_test "Unknown package on the JSON route returns 404"
status=$(http_get "${HOSTED_BASE}/ak-jlab-missing-${RUN_TAG}/json" "${WORK_DIR}/missing.json")
if assert_eq "$status" "404" "expected 404 for an unknown package, got HTTP ${status}"; then
  pass
fi

begin_test "Unknown XML-RPC method returns an XML-RPC fault, not a 500"
xmlrpc_call_body "no_such_method_${RUN_TAG}" "x" > "${WORK_DIR}/badmethod.xml"
status=$(xmlrpc_post "$HOSTED_BASE" "${WORK_DIR}/badmethod.xml" "${WORK_DIR}/badmethod.out")
if [ "$status" != "200" ]; then
  fail "unknown method returned HTTP ${status}; XML-RPC reports errors as a 200 with a <fault>" \
    "$(head -c 600 "${WORK_DIR}/badmethod.out")"
elif ! grep -qF -- "<fault>" "${WORK_DIR}/badmethod.out"; then
  fail "response body has no <fault> element" "$(head -c 600 "${WORK_DIR}/badmethod.out")"
else
  browse_pairs "${WORK_DIR}/badmethod.out" >/dev/null 2>"${WORK_DIR}/badmethod.err" && rc=0 || rc=$?
  if [ "$rc" = "2" ]; then
    pass
  else
    fail "xmlrpc.client did not decode the body as a Fault (decoder exit ${rc}): $(cat "${WORK_DIR}/badmethod.err")" \
      "$(head -c 600 "${WORK_DIR}/badmethod.out")"
  fi
fi

# ---------------------------------------------------------------------------
# Section 5: pip install through the same repository
# ---------------------------------------------------------------------------

begin_test "Bootstrap throwaway venv"
VENV_DIR="${WORK_DIR}/venv"
VENV_PY=""
if python3 -m venv "$VENV_DIR" >"${WORK_DIR}/venv.log" 2>&1 && [ -x "${VENV_DIR}/bin/python" ]; then
  VENV_PY="${VENV_DIR}/bin/python"
  pass
else
  infra_fail "python3 -m venv failed; the runner image needs python3-venv" "$(tail -n 5 "${WORK_DIR}/venv.log" | tr '\n' ' ')"
fi

begin_test "pip install --index-url .../simple/ installs the extension wheel"
if [ -z "$VENV_PY" ]; then
  skip "no venv"
else
  install_log="${WORK_DIR}/pip-install.log"
  # --only-binary keeps pip on the wheel we uploaded; there is nothing else
  # on this index to fall back to. --no-cache-dir keeps a warm runner cache
  # out of the verdict.
  if "$VENV_PY" -m pip install --quiet --disable-pip-version-check --no-cache-dir \
       --index-url "${HOSTED_URL}/simple/" \
       --trusted-host "$TRUSTED_HOST" \
       --only-binary=:all: \
       "${EXT_NAME}==${PKG_VERSION}" >"$install_log" 2>&1; then
    installed_version=$("$VENV_PY" -c "import ${EXT_MODULE}; print(${EXT_MODULE}.__version__)" 2>&1) || installed_version="import failed: ${installed_version}"
    if assert_eq "$installed_version" "$PKG_VERSION" "installed module reports '${installed_version}', expected ${PKG_VERSION}"; then
      pass
    fi
  else
    fail "pip install failed" "$(tail -n 20 "$install_log")"
  fi
fi

# ---------------------------------------------------------------------------
# Section 6: remote repository over the hosted one
#
# The remote's upstream is the hosted repository on this same instance
# (the pull-through pattern the suite already uses), so the JSON route is
# proxied through {upstream}/pypi/{name}/json and the answer must come back
# with urls rewritten to the REMOTE key, never leaking the hosted key.
# ---------------------------------------------------------------------------

begin_test "Create remote PyPI repository over the hosted one"
if create_remote_repo "$REMOTE_KEY" "pypi" "${UPSTREAM_BASE_URL}/pypi/${HOSTED_KEY}"; then
  pass
else
  fail "could not create remote PyPI repository ${REMOTE_KEY} with upstream ${UPSTREAM_BASE_URL}/pypi/${HOSTED_KEY}"
fi

begin_test "Remote JSON route answers through the proxy with urls rewritten to the remote"
REMOTE_JSON="${WORK_DIR}/ext-remote.json"
sleep 1
status=$(http_get "${REMOTE_BASE}/${EXT_JSON_NAME}/json" "$REMOTE_JSON")
if [ "$status" != "200" ]; then
  fail "GET ${REMOTE_BASE}/${EXT_JSON_NAME}/json returned HTTP ${status}" "$(head -c 600 "$REMOTE_JSON")"
elif [ "$(jq -r '.info.version // empty' "$REMOTE_JSON")" != "$PKG_VERSION" ]; then
  fail "remote info.version is not ${PKG_VERSION}" "$(jq -c .info "$REMOTE_JSON")"
elif ! jq -e --arg c "$PREBUILT_CLASSIFIER" 'any(.info.classifiers[]?; . == $c)' "$REMOTE_JSON" >/dev/null 2>&1; then
  fail "remote info.classifiers lacks the Prebuilt classifier" "$(jq -c .info.classifiers "$REMOTE_JSON")"
elif grep -qF -- "/pypi/${HOSTED_KEY}/" "$REMOTE_JSON"; then
  fail "remote JSON leaks upstream urls (/pypi/${HOSTED_KEY}/); expected rewriting to /pypi/${REMOTE_KEY}/" \
    "$(jq -c '.urls' "$REMOTE_JSON")"
elif check_release_entry "$REMOTE_JSON" \
       "first(.releases[\"${PKG_VERSION}\"][]? | select(.filename == \"${EXT_WHEEL_BASENAME}\"))" \
       "$EXT_WHEEL_BASENAME" "$EXT_SHA256" "${REMOTE_URL}/" "remote releases[${PKG_VERSION}]" relay; then
  pass
fi

begin_test "Remote rewritten url downloads the uploaded bytes through the proxy"
if [ -z "${RESOLVED_URL:-}" ]; then
  skip "no resolvable url from the previous test"
elif download_matches "$RESOLVED_URL" "$EXT_SHA256" "remote releases url"; then
  pass
fi
RESOLVED_URL=""

begin_test "Remote /{name}/{version}/json answers through the proxy"
status=$(http_get "${REMOTE_BASE}/${EXT_JSON_NAME}/${PKG_VERSION}/json" "${WORK_DIR}/ext-remote-version.json")
if [ "$status" != "200" ]; then
  fail "GET ${REMOTE_BASE}/${EXT_JSON_NAME}/${PKG_VERSION}/json returned HTTP ${status}" \
    "$(head -c 600 "${WORK_DIR}/ext-remote-version.json")"
elif [ "$(jq -r '.info.version // empty' "${WORK_DIR}/ext-remote-version.json")" != "$PKG_VERSION" ]; then
  fail "remote version route info.version is not ${PKG_VERSION}" "$(jq -c .info "${WORK_DIR}/ext-remote-version.json")"
elif check_release_entry "${WORK_DIR}/ext-remote-version.json" \
       "first(.urls[]? | select(.filename == \"${EXT_WHEEL_BASENAME}\"))" \
       "$EXT_WHEEL_BASENAME" "$EXT_SHA256" "${REMOTE_URL}/" "remote urls[]" relay; then
  pass
fi
RESOLVED_URL=""

begin_test "Remote XML-RPC browse is a well-formed XML-RPC response (forwarded or cache-only)"
# artifact-keeper#3783 leaves the remote browse policy to the implementation:
# forward to the upstream, or answer from cached metadata only. Both are
# valid; a 500 or a non-XML-RPC body is not. When it does return entries,
# they must respect the classifier filter.
status=$(xmlrpc_post "$REMOTE_BASE" "$BROWSE_BODY" "${WORK_DIR}/browse-remote.out")
if [ "$status" != "200" ]; then
  fail "POST ${REMOTE_BASE} browse returned HTTP ${status}" "$(head -c 600 "${WORK_DIR}/browse-remote.out")"
else
  pairs=$(browse_pairs "${WORK_DIR}/browse-remote.out" 2>"${WORK_DIR}/browse-remote.err") && rc=0 || rc=$?
  case "$rc" in
    0)
      if pairs_have "$pairs" "$CTL_NAME" "$PKG_VERSION"; then
        fail "remote browse lists the control package, which has no Prebuilt classifier" "$pairs"
      elif [ -n "$pairs" ] && ! pairs_have "$pairs" "$EXT_NAME" "$PKG_VERSION"; then
        fail "remote browse returned entries but not ${EXT_NAME}==${PKG_VERSION}" "$pairs"
      else
        if [ -z "$pairs" ]; then
          echo "  note: remote browse returned an empty array (cache-only policy)"
        else
          echo "  note: remote browse forwarded to the upstream"
        fi
        pass
      fi
      ;;
    2)
      echo "  note: remote browse answered with an XML-RPC fault: $(cat "${WORK_DIR}/browse-remote.err")"
      pass
      ;;
    *)
      fail "remote browse body is not XML-RPC (decoder exit ${rc}): $(cat "${WORK_DIR}/browse-remote.err")" \
        "$(head -c 600 "${WORK_DIR}/browse-remote.out")"
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# Section 7: virtual repository over hosted + remote
# ---------------------------------------------------------------------------

begin_test "Create virtual PyPI repository over hosted and remote"
if create_virtual_repo "$VIRTUAL_KEY" "pypi" "${HOSTED_KEY},${REMOTE_KEY}"; then
  pass
else
  fail "could not create virtual PyPI repository ${VIRTUAL_KEY} with members ${HOSTED_KEY},${REMOTE_KEY}"
fi

begin_test "Virtual XML-RPC browse lists the extension and not the control"
sleep 1
status=$(xmlrpc_post "$VIRTUAL_BASE" "$BROWSE_BODY" "${WORK_DIR}/browse-virtual.out")
if [ "$status" != "200" ]; then
  fail "POST ${VIRTUAL_BASE} browse returned HTTP ${status}" "$(head -c 600 "${WORK_DIR}/browse-virtual.out")"
elif ! pairs=$(browse_pairs "${WORK_DIR}/browse-virtual.out" 2>"${WORK_DIR}/browse-virtual.err"); then
  fail "virtual browse did not decode as an XML-RPC array: $(cat "${WORK_DIR}/browse-virtual.err")" \
    "$(head -c 600 "${WORK_DIR}/browse-virtual.out")"
elif ! pairs_have "$pairs" "$EXT_NAME" "$PKG_VERSION"; then
  fail "virtual browse lacks ${EXT_NAME}==${PKG_VERSION}" "$pairs"
elif pairs_have "$pairs" "$CTL_NAME" "$PKG_VERSION"; then
  fail "virtual browse lists the control package" "$pairs"
else
  pass
fi

begin_test "Virtual JSON route answers with an in-instance url whose bytes match"
VIRTUAL_JSON="${WORK_DIR}/ext-virtual.json"
status=$(http_get "${VIRTUAL_BASE}/${EXT_JSON_NAME}/json" "$VIRTUAL_JSON")
if [ "$status" != "200" ]; then
  fail "GET ${VIRTUAL_BASE}/${EXT_JSON_NAME}/json returned HTTP ${status}" "$(head -c 600 "$VIRTUAL_JSON")"
elif [ "$(jq -r '.info.version // empty' "$VIRTUAL_JSON")" != "$PKG_VERSION" ]; then
  fail "virtual info.version is not ${PKG_VERSION}" "$(jq -c .info "$VIRTUAL_JSON")"
elif ! jq -e --arg c "$PREBUILT_CLASSIFIER" 'any(.info.classifiers[]?; . == $c)' "$VIRTUAL_JSON" >/dev/null 2>&1; then
  fail "virtual info.classifiers lacks the Prebuilt classifier" "$(jq -c .info.classifiers "$VIRTUAL_JSON")"
elif check_release_entry "$VIRTUAL_JSON" \
       "first(.releases[\"${PKG_VERSION}\"][]? | select(.filename == \"${EXT_WHEEL_BASENAME}\"))" \
       "$EXT_WHEEL_BASENAME" "$EXT_SHA256" "${BASE_URL}/pypi/" "virtual releases[${PKG_VERSION}]"; then
  # The contract says "first member that answers", so the url may name the
  # virtual repository or the member; either way it must be on this
  # instance and serve the same bytes.
  if download_matches "$RESOLVED_URL" "$EXT_SHA256" "virtual releases url"; then
    pass
  fi
fi
RESOLVED_URL=""

begin_test "Virtual /{name}/{version}/json answers"
status=$(http_get "${VIRTUAL_BASE}/${EXT_JSON_NAME}/${PKG_VERSION}/json" "${WORK_DIR}/ext-virtual-version.json")
if [ "$status" != "200" ]; then
  fail "GET ${VIRTUAL_BASE}/${EXT_JSON_NAME}/${PKG_VERSION}/json returned HTTP ${status}" \
    "$(head -c 600 "${WORK_DIR}/ext-virtual-version.json")"
elif [ "$(jq -r '.info.version // empty' "${WORK_DIR}/ext-virtual-version.json")" != "$PKG_VERSION" ]; then
  fail "virtual version route info.version is not ${PKG_VERSION}" \
    "$(jq -c .info "${WORK_DIR}/ext-virtual-version.json")"
elif ! jq -e --arg f "$EXT_WHEEL_BASENAME" 'any(.urls[]?; .filename == $f)' "${WORK_DIR}/ext-virtual-version.json" >/dev/null 2>&1; then
  fail "virtual version route urls[] lacks ${EXT_WHEEL_BASENAME}" "$(jq -c .urls "${WORK_DIR}/ext-virtual-version.json")"
else
  pass
fi

begin_test "Virtual unknown package returns 404"
status=$(http_get "${VIRTUAL_BASE}/ak-jlab-missing-${RUN_TAG}/json" "${WORK_DIR}/missing-virtual.json")
if assert_eq "$status" "404" "expected 404 for an unknown package on the virtual repo, got HTTP ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# Section 8: the real manager (AK_TEST_JUPYTERLAB=1)
# ---------------------------------------------------------------------------

begin_test "Real PyPIExtensionManager(base_url=hosted).list_packages() lists the extension"
if [ "$AK_TEST_JUPYTERLAB" != "1" ]; then
  skip "AK_TEST_JUPYTERLAB=${AK_TEST_JUPYTERLAB}; the manager's requests are replayed above"
elif [ -z "$VENV_PY" ]; then
  skip "no venv"
elif ! curl -sf --max-time 10 "https://pypi.org/simple/jupyterlab/" >/dev/null 2>&1; then
  skip "pypi.org unreachable; cannot install jupyterlab==${JUPYTERLAB_VERSION}"
else
  jlab_log="${WORK_DIR}/pip-jupyterlab.log"
  if ! "$VENV_PY" -m pip install --quiet --disable-pip-version-check \
         "jupyterlab==${JUPYTERLAB_VERSION}" >"$jlab_log" 2>&1; then
    infra_fail "pip install jupyterlab==${JUPYTERLAB_VERSION} from pypi.org failed" "$(tail -n 15 "$jlab_log")"
  else
    # base_url is read in __init__ (it builds the ServerProxy there), so it
    # has to arrive through traitlets config, the same way
    # c.PyPIExtensionManager.base_url does from jupyter_server_config.py.
    # list_packages("", 1, N) is what the sidebar's first page calls; it
    # browses, then GETs /{name}/{version}/json per entry (and /{pack}/json
    # for ~40 known language packs, whose 404s it swallows).
    if driver_out=$("$VENV_PY" - "$HOSTED_BASE" 2>"${WORK_DIR}/driver.err" <<'PY'
import asyncio, re, sys
from traitlets.config import Config, Configurable
from jupyterlab.extensions.pypi import PyPIExtensionManager

base_url = sys.argv[1]
c = Config()
c.PyPIExtensionManager.base_url = base_url
mgr = PyPIExtensionManager(parent=Configurable(config=c))
assert mgr.base_url == base_url, mgr.base_url


async def main():
    packages, last_page = await mgr.list_packages("", 1, 500)
    for name, pkg in packages.items():
        norm = re.sub(r"[-_.]+", "-", str(name)).lower()
        print(f"{norm}=={pkg.latest_version}\t{pkg.pkg_type}\t{pkg.description}")


asyncio.run(main())
PY
    ); then
      if ! printf '%s\n' "$driver_out" | cut -f1 | grep -qxF -- "${EXT_NAME}==${PKG_VERSION}"; then
        fail "manager did not list ${EXT_NAME}==${PKG_VERSION}" "$driver_out"
      elif printf '%s\n' "$driver_out" | cut -f1 | grep -qxF -- "${CTL_NAME}==${PKG_VERSION}"; then
        fail "manager listed the control package" "$driver_out"
      elif ! printf '%s\n' "$driver_out" | grep -F -- "${EXT_NAME}==${PKG_VERSION}"$'\t' | grep -qF -- $'\tprebuilt\t'; then
        fail "manager did not classify the extension as prebuilt" "$driver_out"
      elif ! printf '%s\n' "$driver_out" | grep -F -- "${EXT_NAME}==${PKG_VERSION}"$'\t' | grep -qF -- "Artifact Keeper JupyterLab Extension Manager fixture"; then
        fail "manager description does not carry info.summary from the JSON route" "$driver_out"
      else
        pass
      fi
    else
      fail "PyPIExtensionManager driver raised" "$(tail -n 30 "${WORK_DIR}/driver.err")"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${HOSTED_KEY}" >/dev/null 2>&1 || true

end_suite
