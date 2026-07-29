#!/usr/bin/env bash
# =============================================================================
# tiers/suffix-format-index-paths/oracle.sh — bare-path JSON-metadata download-URL
# coherence gate (#2589, follow-up to #2587), filesystem storage.
# =============================================================================
# Discriminating oracle: for the suffix-resolved formats whose JSON metadata
# advertises an EXPLICIT, directly-followed download URL — RubyGems
# (gem_info/versions `gem_uri`), Ansible Galaxy (`download_url`), Puppet Forge
# (`file_uri`) — an artifact pushed through the generic (bare-path) upload flow
# must advertise a RESOLVABLE download URL.
#
# Background (rubygems.rs::gem_download_uri, ansible.rs::collection_download_url,
# puppet.rs::release_file_uri): these endpoints reconstructed the download URL
# from the coordinates `{name}(-{version}).ext`. A generic upload stored at a
# bare/arbitrary path whose basename differs from that canonical filename was
# then advertised under a path the suffix-resolving download route (the #2587
# exact-path fallback) can never serve. #2589 advertises the artifact's ACTUAL
# stored basename so the advertised URL matches the served route — the RPM
# `<location>` fix (#2587) generalized to these formats.
#
# Method (per format): create the format repo, generic chunked-upload at a BARE
# path (explicit name/version metadata so the by-name endpoint lists it, but a
# basename that is NOT the canonical `{name}(-{version}).ext`), read the served
# metadata, extract the advertised URL VERBATIM, GET it.
#   Fixed (#2589): advertised URL == stored basename -> 200.
#   Pre-#2589:     advertised URL == reconstructed canonical filename -> 404.
# Companion: the canonical reconstructed path (what a pre-fix build advertised)
# must 404, pinning that only the fixed build makes advertised == served.
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

# named_chunked_upload <token> <repo_key> <artifact_path> <name> <version> <file>
# Generic (bare-path) upload carrying EXPLICIT name/version so the by-name JSON
# metadata endpoints list the row, but stored at <artifact_path> whose basename
# is deliberately NOT the canonical {name}(-{version}).ext. Echoes finalize code.
named_chunked_upload(){
  local tok="$1" repo="$2" path="$3" name="$4" ver="$5" src="$6"
  local size csum sess body last
  size=$(wc -c <"$src"); csum=$(sha "$src")
  body=$(curl -s -X POST "$BASE/api/v1/uploads" -H "Authorization: Bearer $tok" \
    -H 'Content-Type: application/json' -d "{
      \"repository_key\":\"$repo\",
      \"artifact_path\":\"$path\",
      \"artifact_name\":\"$name\",
      \"artifact_version\":\"$ver\",
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

mk_repo(){ # token key format
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$2\",\"name\":\"$2\",\"format\":\"$3\",\"repo_type\":\"local\"}" >/dev/null
}

# check_advertised <label> <advertised_url> <canonical_url>
# GREEN when the advertised URL resolves 200; also records that the canonical
# reconstruction (the pre-fix advertisement) 404s.
check_advertised(){
  local label="$1" adv="$2" canon="$3" dl canondl
  echo "-- $label advertised='$adv'"
  if [ -z "$adv" ] || [ "$adv" = "null" ]; then
    fail "$label: metadata advertised no download URL"
    return
  fi
  dl=$(code "${AUTH[@]}" "$BASE$adv")
  canondl=$(code "${AUTH[@]}" "$BASE$canon")
  echo "-- $label advertised '$adv' -> HTTP $dl ; canonical '$canon' -> HTTP $canondl"
  if [ "$dl" = "200" ] && [ "$adv" != "$canon" ]; then
    pass
  else
    fail "$label advertised '$adv' -> HTTP $dl (want 200 AND != canonical '$canon'). Pre-#2589 the metadata advertises the canonical reconstruction, which the bare-path artifact is not stored under -> 404"
  fi
}

begin_suite "suffix-format-index-paths-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

# Payload bytes are irrelevant to a suffix-resolved download; a tiny tar stands
# in for a plausible gem/collection/module envelope.
BLOB="$(mktemp)"; printf 'suffix-format-index-paths payload %s' "$SUF" >"$BLOB"

# ===========================================================================
# RubyGems — gem_info / gem_versions `gem_uri`
# ===========================================================================
begin_test "RubyGems: bare-path upload advertises a resolvable gem_uri in gem/version JSON (#2589)"
RG_REPO="rgbf$SUF"; RG_NAME="rubypkg$SUF"; RG_VER="1.2.3"
RG_BARE="generic-blob-rg-$SUF.gem"                       # != ${RG_NAME}-${RG_VER}.gem
RG_CANON="/gems/$RG_REPO/gems/${RG_NAME}-${RG_VER}.gem"
mk_repo "$TOK" "$RG_REPO" rubygems
RGFIN=$(named_chunked_upload "$TOK" "$RG_REPO" "$RG_BARE" "$RG_NAME" "$RG_VER" "$BLOB")
echo "-- RubyGems bare-path upload finalize -> HTTP $RGFIN"
if [ "$RGFIN" != "200" ] && [ "$RGFIN" != "201" ]; then
  fail "RubyGems generic upload did not finalize (HTTP $RGFIN); cannot evaluate the gate"
else
  GJSON=$(curl -s "${AUTH[@]}" "$BASE/gems/$RG_REPO/api/v1/gems/$RG_NAME.json")
  echo "-- gem_info: $GJSON"
  check_advertised "RubyGems gem_info" "$(echo "$GJSON" | jqr '.gem_uri')" "$RG_CANON"
fi

begin_test "RubyGems: versions JSON gem_uri resolves for the bare-path upload (#2589)"
if [ "$RGFIN" = "200" ] || [ "$RGFIN" = "201" ]; then
  VJSON=$(curl -s "${AUTH[@]}" "$BASE/gems/$RG_REPO/api/v1/versions/$RG_NAME.json")
  check_advertised "RubyGems versions" "$(echo "$VJSON" | jqr '.[0].gem_uri')" "$RG_CANON"
else
  fail "skipped: RubyGems upload did not finalize"
fi

# ===========================================================================
# Ansible Galaxy — collection_info / version_info `download_url`
# ===========================================================================
begin_test "Ansible: bare-path upload advertises a resolvable download_url in collection JSON (#2589)"
AN_REPO="anbf$SUF"; AN_NS="community"; AN_NAME="general$SUF"; AN_VER="3.4.5"
AN_COLL="${AN_NS}-${AN_NAME}"
AN_BARE="generic-blob-an-$SUF.tar.gz"                    # != ${AN_NS}-${AN_NAME}-${AN_VER}.tar.gz
AN_CANON="/ansible/$AN_REPO/download/${AN_NS}-${AN_NAME}-${AN_VER}.tar.gz"
mk_repo "$TOK" "$AN_REPO" ansible
ANFIN=$(named_chunked_upload "$TOK" "$AN_REPO" "$AN_BARE" "$AN_COLL" "$AN_VER" "$BLOB")
echo "-- Ansible bare-path upload finalize -> HTTP $ANFIN"
if [ "$ANFIN" != "200" ] && [ "$ANFIN" != "201" ]; then
  fail "Ansible generic upload did not finalize (HTTP $ANFIN); cannot evaluate the gate"
else
  CJSON=$(curl -s "${AUTH[@]}" "$BASE/ansible/$AN_REPO/api/v3/collections/$AN_NS/$AN_NAME/")
  echo "-- collection_info: $CJSON"
  check_advertised "Ansible collection_info" "$(echo "$CJSON" | jqr '.download_url')" "$AN_CANON"
fi

begin_test "Ansible: version_info download_url resolves for the bare-path upload (#2589)"
if [ "$ANFIN" = "200" ] || [ "$ANFIN" = "201" ]; then
  VIJSON=$(curl -s "${AUTH[@]}" "$BASE/ansible/$AN_REPO/api/v3/collections/$AN_NS/$AN_NAME/versions/$AN_VER/")
  check_advertised "Ansible version_info" "$(echo "$VIJSON" | jqr '.download_url')" "$AN_CANON"
else
  fail "skipped: Ansible upload did not finalize"
fi

# ===========================================================================
# Puppet Forge — module_info / release_list / release_info `file_uri`
# ===========================================================================
begin_test "Puppet: bare-path upload advertises a resolvable file_uri in module/release JSON (#2589)"
PP_REPO="ppbf$SUF"; PP_OWNER="puppetlabs"; PP_NAME="stdlib$SUF"; PP_VER="9.0.0"
PP_MOD="${PP_OWNER}-${PP_NAME}"
PP_BARE="generic-blob-pp-$SUF.tar.gz"                    # != ${PP_MOD}-${PP_VER}.tar.gz
PP_CANON="/puppet/$PP_REPO/v3/files/${PP_MOD}-${PP_VER}.tar.gz"
mk_repo "$TOK" "$PP_REPO" puppet
PPFIN=$(named_chunked_upload "$TOK" "$PP_REPO" "$PP_BARE" "$PP_MOD" "$PP_VER" "$BLOB")
echo "-- Puppet bare-path upload finalize -> HTTP $PPFIN"
if [ "$PPFIN" != "200" ] && [ "$PPFIN" != "201" ]; then
  fail "Puppet generic upload did not finalize (HTTP $PPFIN); cannot evaluate the gate"
else
  MJSON=$(curl -s "${AUTH[@]}" "$BASE/puppet/$PP_REPO/v3/modules/$PP_MOD")
  echo "-- module_info: $MJSON"
  check_advertised "Puppet module_info" "$(echo "$MJSON" | jqr '.current_release.file_uri')" "$PP_CANON"
fi

begin_test "Puppet: release_info file_uri resolves for the bare-path upload (#2589)"
if [ "$PPFIN" = "200" ] || [ "$PPFIN" = "201" ]; then
  RIJSON=$(curl -s "${AUTH[@]}" "$BASE/puppet/$PP_REPO/v3/releases/${PP_MOD}-${PP_VER}")
  check_advertised "Puppet release_info" "$(echo "$RIJSON" | jqr '.file_uri')" "$PP_CANON"
else
  fail "skipped: Puppet upload did not finalize"
fi

rm -f "$BLOB"
end_suite
