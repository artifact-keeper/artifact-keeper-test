#!/usr/bin/env bash
# GitHub/mise/aqua aliases, authenticated downloads and a cold locked install.
# The fixture is a real jq release, pinned by the committed mise.lock. A private
# hosted repo supplies a controlled upstream; deleting it proves warm mirrors
# serve cached bytes without relying on GitHub availability. The backend must
# permit the test upstream address (as for the other pullthrough suites).
# For a feature branch whose version still predates 1.11.0, set
# AK_TEST_GITHUB_MIRROR=1 to run the assertions rather than the version gate.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "github-mirror"
begin_test "Backend supports GitHub mirror formats"
if [ "${AK_TEST_GITHUB_MIRROR:-0}" != 1 ]; then
  require_feature "github_mirror_formats" || { end_suite; exit 0; }
fi
pass

auth_admin
setup_workdir
FIXTURES="$(cd "$(dirname "$0")/../fixtures/github-mirror" && pwd)"
RUN_TAG=$(printf '%s' "$RUN_ID" | tr '[:upper:]_' '[:lower:]-' | tr -cd 'a-z0-9-' | cut -c1-30)
SOURCE_KEY="test-gh-source-${RUN_TAG}"
REPO_KEYS=("test-gh-github-${RUN_TAG}" "test-gh-mise-${RUN_TAG}" "test-gh-aqua-${RUN_TAG}")
UPSTREAM_BASE="${AK_TEST_UPSTREAM_BASE_URL:-$BASE_URL}"
_SUITE_ENDED=0
cleanup_github_mirrors() {
  local key
  for key in "${REPO_KEYS[@]}" "$SOURCE_KEY"; do
    # shellcheck disable=SC2086
    curl -s $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${key}" >/dev/null 2>&1 || true
  done
  if [ "$_SUITE_ENDED" != 1 ]; then
    begin_test "suite aborted before end_suite"
    infra_fail "GitHub mirror suite aborted; temporary repositories cleaned up"
    (end_suite) >/dev/null 2>&1 || true
  fi
}
add_exit_handler cleanup_github_mirrors

begin_test "Required native client and fixture parser are available"
if ! command -v mise >/dev/null || ! python3 -c 'import tomllib' 2>/dev/null; then
  infra_fail "mise 2026.9.0 and Python 3.11+ are required"
  _SUITE_ENDED=1
  end_suite
fi
pass

# Read the platform URL and pinned digest from the committed lock, not from an
# upstream checksum downloaded alongside a possibly replaced asset.
python3 - "$FIXTURES/mise.lock" > "$WORK_DIR/asset.json" <<'PY'
import json, platform, sys, tomllib
os_name = {'Linux': 'linux', 'Darwin': 'macos'}[platform.system()]
arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine().lower()]
with open(sys.argv[1], 'rb') as stream:
    lock = tomllib.load(stream)
entry = lock['tools']['aqua:jqlang/jq'][0]['platforms.' + os_name + '-' + arch]
print(json.dumps(entry))
PY
ASSET_URL=$(jq -r .url "$WORK_DIR/asset.json")
ASSET_PATH="${ASSET_URL#https://github.com/}"
EXPECTED_SHA=$(jq -r '.checksum | sub("^sha256:"; "")' "$WORK_DIR/asset.json")

begin_test "Download the real jq fixture and verify its pinned digest"
if ! curl -fsSL --retry 3 --max-time 120 "$ASSET_URL" -o "$WORK_DIR/jq-asset"; then
  infra_fail "could not download pinned fixture from GitHub"
  _SUITE_ENDED=1
  end_suite
fi
ACTUAL_SHA=$(shasum -a 256 "$WORK_DIR/jq-asset" | awk '{print $1}')
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  fail "fixture differs from the committed lockfile digest"
  _SUITE_ENDED=1
  end_suite
fi
pass

begin_test "Create a private controlled upstream and upload jq"
api_post /api/v1/repositories "$(jq -n --arg key "$SOURCE_KEY" \
  '{key:$key,name:$key,format:"generic",repo_type:"local",is_public:false}')" >/dev/null
# shellcheck disable=SC2086
curl -fsS $CURL_TIMEOUT -X PUT -H "$(auth_header)" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$WORK_DIR/jq-asset" \
  "${BASE_URL}/api/v1/repositories/${SOURCE_KEY}/artifacts/${ASSET_PATH}" >/dev/null
pass

index=0
for format in github mise aqua; do
  key="${REPO_KEYS[$index]}"
  begin_test "Create and round-trip the ${format} format"
  api_post /api/v1/repositories "$(jq -n --arg key "$key" --arg format "$format" \
    --arg upstream "${UPSTREAM_BASE}/general/${SOURCE_KEY}" \
    '{key:$key,name:$key,format:$format,repo_type:"remote",upstream_url:$upstream,is_public:false}')" >/dev/null
  actual_format=$(api_get "/api/v1/repositories/${key}" | jq -r .format)
  if assert_eq "$actual_format" "$format"; then pass; fi
  api_put "/api/v1/repositories/${key}/upstream-auth" "$(jq -n \
    --arg user "$ADMIN_USER" --arg password "$ADMIN_PASS" \
    '{auth_type:"basic",username:$user,password:$password}')" >/dev/null

  begin_test "${format}: anonymous cold-cache download is rejected"
  # shellcheck disable=SC2086
  status=$(curl -s $CURL_TIMEOUT -o /dev/null -w '%{http_code}' "${BASE_URL}/general/${key}/${ASSET_PATH}")
  if [ "$status" = 401 ] || [ "$status" = 403 ] || [ "$status" = 404 ]; then pass; else fail "anonymous request returned ${status}"; fi

  begin_test "${format}: authenticated download matches the lockfile"
  # shellcheck disable=SC2086
  curl -fsS $CURL_TIMEOUT -H "$(auth_header)" "${BASE_URL}/general/${key}/${ASSET_PATH}" -o "$WORK_DIR/${format}.asset"
  if assert_eq "$(shasum -a 256 "$WORK_DIR/${format}.asset" | awk '{print $1}')" "$EXPECTED_SHA"; then pass; fi

  begin_test "${format}: anonymous warm-cache download is rejected"
  # shellcheck disable=SC2086
  status=$(curl -s $CURL_TIMEOUT -o /dev/null -w '%{http_code}' "${BASE_URL}/general/${key}/${ASSET_PATH}")
  if [ "$status" = 401 ] || [ "$status" = 403 ] || [ "$status" = 404 ]; then pass; else fail "anonymous cached request returned ${status}"; fi
  index=$((index + 1))
done

# Each invocation has independent configuration, data and cache directories.
# Never change HOME or consult the developer's global mise configuration.
run_locked_install() {
  local stage="$1" project="$WORK_DIR/$1"
  mkdir -p "$project"
  cp "$FIXTURES/mise.toml" "$FIXTURES/mise.lock" "$project/"
  AK_MIRROR_KEY="${REPO_KEYS[1]}" python3 - "$project/global.toml" <<'PY'
import json, os, sys, urllib.parse
base = urllib.parse.urlsplit(os.environ['BASE_URL'])
credentials = urllib.parse.quote(os.environ['ADMIN_USER'], safe='') + ':' + urllib.parse.quote(os.environ['ADMIN_PASS'], safe='')
url = urllib.parse.urlunsplit((base.scheme, credentials + '@' + base.netloc, base.path, '', ''))
replacement = url + '/general/' + os.environ['AK_MIRROR_KEY'] + '/$1/$2/releases/download/$3'
with open(sys.argv[1], 'w') as stream:
    stream.write('[settings.url_replacements]\n')
    stream.write(json.dumps(r'regex:^https://github\.com/([^/]+)/([^/]+)/releases/download/(.+)') + ' = ' + json.dumps(replacement) + '\n')
    # Locked installs must not fall back to tag/asset API lookups.
    stream.write('"https://api.github.com/" = "http://127.0.0.1:1/"\n')
os.chmod(sys.argv[1], 0o600)
PY
  if ! env MISE_GLOBAL_CONFIG_FILE="$project/global.toml" MISE_SYSTEM_CONFIG_DIR="$project/system" \
    MISE_DATA_DIR="$project/data" MISE_CACHE_DIR="$project/cache" MISE_CONFIG_DIR="$project/config" \
    MISE_TRUSTED_CONFIG_PATHS="$project" MISE_YES=1 \
    mise -C "$project" install --locked > "$WORK_DIR/${stage}.log" 2>&1; then
    # mise may include a request URL in diagnostics. Never publish userinfo.
    sed -E 's#(https?://)[^ /]*@#\1[REDACTED]@#g' "$WORK_DIR/${stage}.log" >&2
    return 1
  fi
  local binary
  binary=$(find "$project/data/installs" -type f -name jq | head -1)
  [ -n "$binary" ] && [ "$("$binary" --version)" = "jq-1.7.1" ]
}

mirror_download_count() {
  api_get "/api/v1/repositories/${REPO_KEYS[1]}/artifacts" | \
    jq -er --arg path "$ASSET_PATH" '.items[] | select(.path == $path) | .download_count'
}

begin_test "mise performs an authenticated locked installation"
before=$(mirror_download_count)
if run_locked_install online && [ "$(mirror_download_count)" -gt "$before" ]; then
  pass
else
  fail "locked installation failed or bypassed the mirror"
fi

begin_test "Make the controlled upstream unavailable"
api_delete "/api/v1/repositories/${SOURCE_KEY}" >/dev/null
# shellcheck disable=SC2086
status=$(curl -s $CURL_TIMEOUT -H "$(auth_header)" -o /dev/null -w '%{http_code}' "${BASE_URL}/general/${SOURCE_KEY}/${ASSET_PATH}")
if assert_eq "$status" 404; then pass; fi

for key in "${REPO_KEYS[@]}"; do
  begin_test "${key}: warm mirror serves bytes after upstream removal"
  # shellcheck disable=SC2086
  curl -fsS $CURL_TIMEOUT -H "$(auth_header)" "${BASE_URL}/general/${key}/${ASSET_PATH}" -o "$WORK_DIR/cached.asset"
  if assert_eq "$(shasum -a 256 "$WORK_DIR/cached.asset" | awk '{print $1}')" "$EXPECTED_SHA"; then pass; fi
done

begin_test "mise installs from the warm mirror with a cold client and unavailable upstream"
before=$(mirror_download_count)
if run_locked_install outage && [ "$(mirror_download_count)" -gt "$before" ]; then
  pass
else
  fail "cold-client outage install failed or bypassed the mirror"
fi

_SUITE_ENDED=1
end_suite
