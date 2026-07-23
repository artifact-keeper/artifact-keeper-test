#!/usr/bin/env bash
# =============================================================================
# tiers/ondemand-index-formats/oracle.sh — bare-path on-demand metadata
# download-URL coherence gate (#2589), filesystem storage.
# =============================================================================
# Discriminating oracle: an Ansible collection and a Puppet module pushed
# through the generic (bare-path) chunked-upload flow must advertise a
# RESOLVABLE download URL in their name-addressed metadata responses.
#
# Background (ansible.rs::collection_info, puppet.rs::module_info via
# proxy_helpers::served_download_filename): a bare-path generic upload is stored
# with the whole basename as `name` and a `sha256-<prefix>` fallback `version`.
# Reconstructing `{namespace}-{name}-{version}.tar.gz` /
# `{owner}-{name}-{version}.tar.gz` from those raw columns yields a URL the
# suffix-resolving download route can never serve. #2589 re-derives the
# advertised filename from the stored object path so it matches the served
# route (the analogue of the rpm primary.xml #2587 and cran/rubygems #2754
# fixes for the remaining suffix-resolved formats).
#
# Method (per format): generic chunked upload at a BARE filename path, read the
# served metadata JSON, extract the advertised download URL, GET it.
#   Fixed:     advertised URL = stored basename -> 200.
#   Pre-#2589: advertised URL = {name}-{version} (name=basename, version=sha256
#              fallback) -> 404.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SUF="$RANDOM$RANDOM"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

if command -v sha256sum >/dev/null 2>&1; then sha(){ sha256sum "$1" | awk '{print $1}'; }
else sha(){ shasum -a 256 "$1" | awk '{print $1}'; }; fi

# generic_chunked_upload <token> <repo_key> <artifact_path> <file>
# Bare-path generic upload (NO artifact_name / artifact_version -> the server
# stores the whole basename as `name` and derives the sha256-<prefix> fallback
# `version` that is the #2589 bug condition). Echoes finalize HTTP code.
generic_chunked_upload(){
  local tok="$1" repo="$2" path="$3" src="$4"
  local size csum sess body last
  size=$(wc -c <"$src"); csum=$(sha "$src")
  body=$(curl -s -X POST "$BASE/api/v1/uploads" -H "Authorization: Bearer $tok" \
    -H 'Content-Type: application/json' -d "{
      \"repository_key\":\"$repo\",
      \"artifact_path\":\"$path\",
      \"total_size\":$size,
      \"checksum_sha256\":\"$csum\",
      \"chunk_size\":1048576
    }")
  sess=$(echo "$body" | jqr '.session_id // .id // empty')
  if [ -z "$sess" ]; then echo "SESSION-FAIL: $body" >&2; echo "000"; return; fi
  last=$((size-1))
  curl -s -o /dev/null -X PATCH "$BASE/api/v1/uploads/$sess" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes 0-$last/$size" --data-binary "@$src" >/dev/null
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/uploads/$sess/complete" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json'
}

begin_suite "ondemand-index-formats-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

# ===========================================================================
# Ansible Galaxy — collection_info `.download_url`
# ===========================================================================
begin_test "Ansible: bare-path generic upload advertises a resolvable collection download_url (#2589)"

ANS_REPO="ansbf$SUF"
ANS_NS="ansns$SUF"
ANS_COLL="anscoll"
# Bare filename `{namespace}-{name}.tar.gz`; stored name = whole basename.
ANS_FILE="${ANS_NS}-${ANS_COLL}.tar.gz"
curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$ANS_REPO\",\"name\":\"$ANS_REPO\",\"format\":\"ansible\",\"repo_type\":\"local\"}" >/dev/null

ATGZ="$(mktemp --suffix=.tar.gz)"
ATMP="$(mktemp -d)"; echo "ansible payload $SUF" >"$ATMP/MANIFEST.json"
tar -czf "$ATGZ" -C "$ATMP" MANIFEST.json 2>/dev/null

AFIN=$(generic_chunked_upload "$TOK" "$ANS_REPO" "$ANS_FILE" "$ATGZ")
echo "-- Ansible bare-path upload finalize -> HTTP $AFIN"

if [ "$AFIN" != "200" ] && [ "$AFIN" != "201" ]; then
  fail "Ansible generic upload did not finalize (HTTP $AFIN); cannot evaluate the gate"
else
  # collection_info is keyed on {namespace}/{name}; the stored basename is
  # `{namespace}-{name}.tar.gz`, so the URL name segment is `{name}.tar.gz`.
  META=$(curl -s "${AUTH[@]}" "$BASE/ansible/$ANS_REPO/api/v3/collections/$ANS_NS/$ANS_COLL.tar.gz/")
  echo "-- served collection_info:"; echo "$META" | sed 's/^/     /'
  DURL=$(echo "$META" | jqr '.download_url // empty')
  echo "-- advertised download_url: '$DURL'"
  if [ -z "$DURL" ]; then
    fail "Ansible collection_info returned no download_url (metadata lookup failed): $META"
  else
    DL=$(code "${AUTH[@]}" "$BASE$DURL")
    echo "-- GET advertised download_url -> HTTP $DL"
    if [ "$DL" = "200" ]; then
      pass
    else
      fail "Ansible advertised download_url '$DURL' -> HTTP $DL (expected 200). Pre-#2589 the URL is reconstructed {namespace}-{name}-{sha256-…}.tar.gz -> 404"
    fi
  fi
fi
rm -rf "$ATGZ" "$ATMP"

# ===========================================================================
# Puppet Forge — module_info `.current_release.file_uri`
# ===========================================================================
begin_test "Puppet: bare-path generic upload advertises a resolvable module file_uri (#2589)"

PUP_REPO="pupbf$SUF"
PUP_OWNER="pupown$SUF"
PUP_MOD="pupmod"
# Bare filename `{owner}-{name}.tar.gz`; stored name = whole basename.
PUP_FILE="${PUP_OWNER}-${PUP_MOD}.tar.gz"
curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$PUP_REPO\",\"name\":\"$PUP_REPO\",\"format\":\"puppet\",\"repo_type\":\"local\"}" >/dev/null

PTGZ="$(mktemp --suffix=.tar.gz)"
PTMP="$(mktemp -d)"; echo "puppet payload $SUF" >"$PTMP/metadata.json"
tar -czf "$PTGZ" -C "$PTMP" metadata.json 2>/dev/null

PFIN=$(generic_chunked_upload "$TOK" "$PUP_REPO" "$PUP_FILE" "$PTGZ")
echo "-- Puppet bare-path upload finalize -> HTTP $PFIN"

if [ "$PFIN" != "200" ] && [ "$PFIN" != "201" ]; then
  fail "Puppet generic upload did not finalize (HTTP $PFIN); cannot evaluate the gate"
else
  # module_info is keyed on the single `{owner}-{name}` segment; the stored
  # basename is `{owner}-{name}.tar.gz` (parse splits on the first hyphen).
  META=$(curl -s "${AUTH[@]}" "$BASE/puppet/$PUP_REPO/v3/modules/$PUP_OWNER-$PUP_MOD.tar.gz")
  echo "-- served module_info:"; echo "$META" | sed 's/^/     /'
  FURI=$(echo "$META" | jqr '.current_release.file_uri // empty')
  echo "-- advertised file_uri: '$FURI'"
  if [ -z "$FURI" ]; then
    fail "Puppet module_info returned no file_uri (metadata lookup failed): $META"
  else
    DL=$(code "${AUTH[@]}" "$BASE$FURI")
    echo "-- GET advertised file_uri -> HTTP $DL"
    if [ "$DL" = "200" ]; then
      pass
    else
      fail "Puppet advertised file_uri '$FURI' -> HTTP $DL (expected 200). Pre-#2589 the URL is reconstructed {owner}-{name}-{sha256-…}.tar.gz -> 404"
    fi
  fi
fi
rm -rf "$PTGZ" "$PTMP"

end_suite
