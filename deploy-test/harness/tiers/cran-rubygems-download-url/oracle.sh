#!/usr/bin/env bash
# =============================================================================
# tiers/cran-rubygems-download-url/oracle.sh — bare-path index download-URL
# coherence gate (#2754 / PR #2839), filesystem storage.
# =============================================================================
# Discriminating oracle: a CRAN tarball and a RubyGems gem pushed through the
# generic (bare-path) chunked-upload flow must advertise a RESOLVABLE download
# path in their respective indices.
#
# Background (cran.rs::source_index_coordinates, rubygems.rs::spec_index_
# coordinates): a bare-path generic upload is stored with the whole basename as
# `name` and a `sha256-<prefix>` fallback `version`. Emitting those raw columns
# in the index makes the client reconstruct `{basename}_{sha256-…}.tar.gz` /
# `{basename}-{sha256-…}.gem`, which the suffix-resolving download route can
# never serve. #2754 re-derives the advertised coordinates from the stored
# filename so the reconstructed path matches the served route.
#
# Method (per format): generic chunked upload at a BARE filename path, read the
# served index, reconstruct the client download path FROM THE INDEX, GET it.
#   Fixed:     reconstructed path -> 200.
#   Pre-#2754: index advertises basename + sha256 -> reconstructed path -> 404.
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
# Bare-path generic upload (NO artifact_version -> the server derives the
# sha256-<prefix> fallback that is the #2754 bug condition). Echoes finalize
# HTTP code on the last line.
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

begin_suite "cran-rubygems-download-url-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

# ===========================================================================
# CRAN
# ===========================================================================
begin_test "CRAN: bare-path generic upload advertises a resolvable PACKAGES download path (#2754)"

CRAN_REPO="cranbf$SUF"
CRAN_PKG="cranpkg$SUF"
CRAN_FILE="${CRAN_PKG}_1.0.0.tar.gz"     # {name}_{version}.tar.gz convention
curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$CRAN_REPO\",\"name\":\"$CRAN_REPO\",\"format\":\"cran\",\"repo_type\":\"local\"}" >/dev/null

TGZ="$(mktemp --suffix=.tar.gz)"
TMPD="$(mktemp -d)"; echo "cran payload $SUF" >"$TMPD/DESCRIPTION"
tar -czf "$TGZ" -C "$TMPD" DESCRIPTION 2>/dev/null

# BARE path (just the filename) -> stored name = basename, version = sha256 fallback.
CFIN=$(generic_chunked_upload "$TOK" "$CRAN_REPO" "$CRAN_FILE" "$TGZ")
echo "-- CRAN bare-path upload finalize -> HTTP $CFIN"

CRAN_OK=1
if [ "$CFIN" != "200" ] && [ "$CFIN" != "201" ]; then
  CRAN_OK=0
  fail "CRAN generic upload did not finalize (HTTP $CFIN); cannot evaluate the gate"
else
  PKGS=$(curl -s "${AUTH[@]}" "$BASE/cran/$CRAN_REPO/src/contrib/PACKAGES")
  echo "-- served PACKAGES index:"; echo "$PKGS" | sed 's/^/     /'
  ADV_PKG=$(echo "$PKGS" | awk -F': *' '/^Package:/{print $2; exit}' | tr -d '\r')
  ADV_VER=$(echo "$PKGS" | awk -F': *' '/^Version:/{print $2; exit}' | tr -d '\r')
  echo "-- advertised coordinates: Package='$ADV_PKG' Version='$ADV_VER'"
  # Client reconstructs {Package}_{Version}.tar.gz from the index.
  RECON="${ADV_PKG}_${ADV_VER}.tar.gz"
  DL=$(code "${AUTH[@]}" "$BASE/cran/$CRAN_REPO/src/contrib/$RECON")
  echo "-- reconstructed download '$RECON' -> HTTP $DL"
  if [ "$DL" = "200" ]; then
    pass
  else
    CRAN_OK=0
    fail "CRAN index-reconstructed download '$RECON' -> HTTP $DL (expected 200). Pre-#2754 the index advertises the bare basename + sha256 fallback -> 404"
  fi
fi
rm -rf "$TGZ" "$TMPD"

# ===========================================================================
# RubyGems
# ===========================================================================
begin_test "RubyGems: bare-path generic upload advertises a resolvable specs.4.8.gz download path (#2754)"

GEM_REPO="gembf$SUF"
GEM_NAME="rubypkg$SUF"
GEM_FILE="${GEM_NAME}-1.0.0.gem"          # {name}-{version}.gem convention
curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"$GEM_REPO\",\"name\":\"$GEM_REPO\",\"format\":\"rubygems\",\"repo_type\":\"local\"}" >/dev/null

# A .gem is a tar; content is irrelevant to suffix-resolved download. Build a
# small tar so the bytes are a plausible gem envelope.
GEM="$(mktemp --suffix=.gem)"
GTMP="$(mktemp -d)"; echo "gem payload $SUF" >"$GTMP/metadata.gz"
tar -cf "$GEM" -C "$GTMP" metadata.gz 2>/dev/null

GFIN=$(generic_chunked_upload "$TOK" "$GEM_REPO" "$GEM_FILE" "$GEM")
echo "-- RubyGems bare-path upload finalize -> HTTP $GFIN"

if [ "$GFIN" != "200" ] && [ "$GFIN" != "201" ]; then
  fail "RubyGems generic upload did not finalize (HTTP $GFIN); cannot evaluate the gate"
else
  SPECS="$(mktemp)"
  curl -s "${AUTH[@]}" "$BASE/gems/$GEM_REPO/specs.4.8.gz" -o "$SPECS"
  # Marshal 4.8 embeds the name/version strings as literal bytes; decompress and
  # read them. Order per triple is: <name> "Gem::Version" <version> "ruby".
  DEC=$(gunzip -c "$SPECS" 2>/dev/null | strings -n 3)
  echo "-- decompressed specs tokens:"; echo "$DEC" | sed 's/^/     /'
  # Advertised name: the token beginning with our unique gem-name prefix.
  # `strings` may merge the Marshal length byte onto the name line when that
  # byte is printable (longer names), so extract the token rather than the line.
  ADV_NAME=$(echo "$DEC" | grep -oE "${GEM_NAME}[A-Za-z0-9._-]*" | head -1)
  # Advertised version: the token on the line AFTER the "Gem::Version" marker.
  ADV_GVER=$(echo "$DEC" | awk '/Gem::Version/{getline; print; exit}')
  echo "-- advertised coordinates: name='$ADV_NAME' version='$ADV_GVER'"
  RECON="${ADV_NAME}-${ADV_GVER}.gem"
  DL=$(code "${AUTH[@]}" "$BASE/gems/$GEM_REPO/gems/$RECON")
  echo "-- reconstructed download '$RECON' -> HTTP $DL"
  if [ "$DL" = "200" ] && ! echo "$ADV_GVER" | grep -q 'sha256-'; then
    pass
  else
    fail "RubyGems index-reconstructed download '$RECON' -> HTTP $DL (expected 200, version must not be a sha256 fallback). Pre-#2754 the index advertises the bare basename + sha256 -> 404"
  fi
  rm -f "$SPECS"
fi
rm -rf "$GEM" "$GTMP"

end_suite
