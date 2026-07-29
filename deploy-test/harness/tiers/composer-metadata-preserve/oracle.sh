#!/usr/bin/env bash
# =============================================================================
# tiers/composer-metadata-preserve/oracle.sh — Composer metadata preservation
# gate (#2846), filesystem storage.
# =============================================================================
# Discriminating oracle: two versions of a composer-plugin package, each with
# valid composer.json properties beyond the old nine-key allowlist (`bin`,
# `extra`, `scripts`, `minimum-stability`), are published to a hosted Composer
# repo. The served packages.json must then advertise BOTH versions AND retain
# `bin` + `extra.class` on each entry.
#
# Background (formats/composer.rs::ComposerJson, api/handlers/composer.rs::
# merge_composer_metadata): pre-#2846 the parse struct dropped every unmodelled
# composer.json field, and the version-entry merge copied only a fixed nine-key
# allowlist. So an uploaded package lost `bin`/`extra`/`scripts`/... on the wire
# — breaking composer-plugin installs ("composer-plugin packages should have a
# class defined in their extra key") and vendor/bin symlinks. The fix preserves
# every valid property end-to-end.
#
# Method: publish v1.0.0, publish v2.0.0, GET packages.json, assert:
#   * both "1.0.0" and "2.0.0" entries are present (a new upload preserves the
#     prior version), AND
#   * every entry carries `bin` (["bin/dummy"]) and `extra.class`.
#   Fixed:     both present + bin + extra retained -> PASS.
#   Pre-#2846: bin + extra stripped               -> FAIL.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SUF="$RANDOM$RANDOM"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }

WORK="$(mktemp -d)"
cleanup(){ rm -rf "$WORK"; }
trap cleanup EXIT

REPO="composerbf$SUF"
VENDOR="snsconsulting"
PKG="dummy-package$SUF"
FULL="$VENDOR/$PKG"

# build_and_upload <token> <version> -> echoes finalize HTTP code
# Writes a composer.json carrying properties BEYOND the legacy allowlist
# (`bin`, `extra`, `scripts`, `minimum-stability`), zips it, and PUTs the
# archive to the Composer publish endpoint.
build_and_upload(){
  local tok="$1" ver="$2"
  local d="$WORK/pkg-$ver"
  rm -rf "$d"; mkdir -p "$d/src"
  cat >"$d/composer.json" <<EOF
{
  "name": "$FULL",
  "type": "composer-plugin",
  "license": "proprietary",
  "version": "$ver",
  "bin": ["bin/dummy"],
  "extra": { "class": "SNSConsulting\\\\DummyPackage\\\\Plugin" },
  "scripts": { "post-install-cmd": "echo installed-$ver" },
  "require": { "php": ">=8.4", "composer-plugin-api": "^2.0" },
  "minimum-stability": "dev",
  "prefer-stable": true
}
EOF
  echo "<?php" >"$d/src/Plugin.php"
  ( cd "$d" && zip -qr "$WORK/arc-$ver.zip" . )
  curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/zip' \
    --data-binary "@$WORK/arc-$ver.zip" \
    "$BASE/composer/$REPO/api/packages"
}

begin_suite "composer-metadata-preserve-2846"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi
AUTH=(-H "Authorization: Bearer $TOK")

# ---------------------------------------------------------------------------
# Setup: hosted composer repo + two published versions.
# ---------------------------------------------------------------------------
begin_test "publish two composer-plugin versions with bin + extra (#2846)"

curl -s -o /dev/null -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"composer\",\"repo_type\":\"local\"}"

U1=$(build_and_upload "$TOK" "1.0.0")
echo "-- upload v1.0.0 finalize -> HTTP $U1"
U2=$(build_and_upload "$TOK" "2.0.0")
echo "-- upload v2.0.0 finalize -> HTTP $U2"

if { [ "$U1" = "200" ] || [ "$U1" = "201" ]; } && { [ "$U2" = "200" ] || [ "$U2" = "201" ]; }; then
  pass
else
  fail "composer uploads did not finalize (v1=$U1 v2=$U2); cannot evaluate the gate"
  end_suite; exit 1
fi

# ---------------------------------------------------------------------------
# Gate: served packages.json must keep BOTH versions AND their bin + extra.
# ---------------------------------------------------------------------------
begin_test "packages.json preserves every version's bin + extra.class (#2846)"

PKGS=$(curl -s "${AUTH[@]}" "$BASE/composer/$REPO/packages.json")
echo "-- served packages.json:"; echo "$PKGS" | jq . 2>/dev/null | sed 's/^/     /'

ENTRIES="$PKGS"

VERS=$(echo "$ENTRIES" | jq -r --arg f "$FULL" '.packages[$f][].version' 2>/dev/null | sort -u | tr '\n' ',')
echo "-- advertised versions: $VERS"

# Count entries that carry bin==["bin/dummy"] AND extra.class present.
GOOD=$(echo "$ENTRIES" | jq --arg f "$FULL" \
  '[.packages[$f][] | select((.bin == ["bin/dummy"]) and (.extra.class != null))] | length' 2>/dev/null)
TOTAL=$(echo "$ENTRIES" | jq --arg f "$FULL" '.packages[$f] | length' 2>/dev/null)
HAS_V1=$(echo "$ENTRIES" | jq --arg f "$FULL" '[.packages[$f][] | select(.version=="1.0.0")] | length' 2>/dev/null)
HAS_V2=$(echo "$ENTRIES" | jq --arg f "$FULL" '[.packages[$f][] | select(.version=="2.0.0")] | length' 2>/dev/null)
echo "-- total entries=$TOTAL  with-bin+extra=$GOOD  v1=$HAS_V1 v2=$HAS_V2"

if [ "${HAS_V1:-0}" -ge 1 ] && [ "${HAS_V2:-0}" -ge 1 ] \
   && [ "${TOTAL:-0}" -ge 2 ] && [ "${GOOD:-0}" = "${TOTAL:-0}" ]; then
  pass
else
  fail "packages.json dropped composer metadata: total=$TOTAL bin+extra=$GOOD v1=$HAS_V1 v2=$HAS_V2 (expected both versions present with bin + extra.class on every entry). Pre-#2846 the struct + nine-key allowlist strip bin/extra."
fi

end_suite
