# =============================================================================
# plugins/pub.sh — format-conformance plugin
# FC_FORMAT: pub
# FC_MOUNT: pub
# FC_REPO_FORMAT: pub
# FC_PROFILE: client.pub
# FC_SERVICE: client-pub
# FC_ENABLED: 1
# =============================================================================
# Dart pub hosted publish->consume conformance. Routes (handlers/pub_registry.rs):
# nest /pub; upload flow GET /:repo/api/packages/versions/new (#1997 — MUST be
# GET) -> POST .../newUpload -> GET .../newUploadFinish; package info
# GET /:repo/api/packages/:name; version info .../:name/versions/:version;
# archive GET /:repo/packages/*archive_path.
#
# The REAL client is `dart` (dart:stable, arm64). fc_publish scaffolds a package
# with our marker lib, `publish_to`s AK, and runs `dart pub publish --force`
# through the real upload flow (the #1997 GET-verb regression is exercised by
# the SDK itself). fc_consume runs `dart pub get` on a consumer whose ONLY
# source is a `hosted` dep pointing at AK: pub reads /api/packages/<name>,
# FOLLOWS the advertised absolute `archive_url`, and VERIFIES the advertised
# `archive_sha256` against the fetched bytes (Dart >= 2.19 enforces this, so a
# mismatch fails `pub get`). fc_assert proves the marker lib was unpacked into
# the pub cache and a consumer imports it.
# =============================================================================
FC_CASES="archive_sha256 republish_conflict upload_flow_verbs"

PUB_NAME="dtf_marker"
PUB_VER="1.0.0"
PUB_MARKER="DTF-PUB-INSTALLED-1.0.0"
PUB_MARKER_SRC="${DTF_DIR}/fixtures/pub/dtf_marker.dart"
PUB_TOKEN=""   # minted in fc_publish; persists to later hooks (same subshell)

# ---------------------------------------------------------------------------
# fc_publish — mint a write-scoped API token, scaffold the package with our
# marker lib + publish_to=AK, register the hosted token, and `dart pub publish`
# through the real GET-versions/new -> POST-newUpload -> GET-finish flow.
# ---------------------------------------------------------------------------
fc_publish() {
  local uid
  uid="$(resolve_user_id_by_username "${ADMIN_USER}")" \
    || { echo "cannot resolve admin user id to mint a token"; return 1; }
  PUB_TOKEN="$(api_post "/api/v1/users/${uid}/tokens" \
    "{\"name\":\"dtf-pub-${RUN_ID}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"]}" | jq -r '.token // empty')"
  [ -n "$PUB_TOKEN" ] || { echo "token mint returned no token"; return 1; }
  echo "  minted write token prefix=${PUB_TOKEN:0:8}..."

  # A publishable package needs a LICENSE (hard requirement even under --force)
  # plus README/CHANGELOG and a repository field to clear pub's validators.
  nc_exec "rm -rf /work/pkg && mkdir -p /work/pkg/lib && cd /work/pkg
cat > pubspec.yaml <<EOF
name: ${PUB_NAME}
description: DTF marker package for Artifact Keeper format-conformance testing of the pub registry.
version: ${PUB_VER}
publish_to: ${FC_INT_URL}
repository: https://example.com/dtf/marker
environment:
  sdk: '>=3.0.0 <4.0.0'
EOF
printf 'MIT License\n\nCopyright (c) 2026 DTF\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.\n' > LICENSE
printf '# dtf_marker\n\nMarker package for Artifact Keeper format-conformance testing.\n' > README.md
printf '## 1.0.0\n\n- Initial marker release.\n' > CHANGELOG.md
cat pubspec.yaml" || return 1
  nc_copy_to_ctr "$PUB_MARKER_SRC" /work/pkg/lib/dtf_marker.dart \
    || { echo "copy marker lib failed"; return 1; }

  # Register the hosted token by writing pub-tokens.json directly. `dart pub
  # token add` refuses non-https URLs ("insecure repositories cannot use
  # authentication"), but the token FILE is the real credential mechanism and
  # pub sends it over http at request time — the rig backend is plain-http, so
  # this is the http-equivalent of swift's TLS caveat, not a softening.
  # pipefail so a failed `dart pub publish` (piped to tail) is not masked.
  nc_exec -t 240 "set -o pipefail; cd /work/pkg
export HOME=/root
mkdir -p /root/.config/dart
cat > /root/.config/dart/pub-tokens.json <<EOF
{\"version\":1,\"hosted\":[{\"url\":\"${FC_INT_URL}\",\"token\":\"${PUB_TOKEN}\"}]}
EOF
dart pub publish --force 2>&1 | tail -30" \
    || { echo "dart pub publish failed"; return 1; }

  nc_expect_code 200 "${FC_URL}/api/packages/${PUB_NAME}" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — build a consumer whose ONLY dependency source is the AK
# hosted repo (no pub.dev fallback), pointing at $FC_INT_URL.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec "command -v dart >/dev/null 2>&1 && dart --version" \
    || { echo "dart missing inside the provisioned pub client"; return 1; }
  nc_exec "rm -rf /work/consumer && mkdir -p /work/consumer/bin && cd /work/consumer
cat > pubspec.yaml <<EOF
name: dtf_consumer
description: Consumer resolving dtf_marker ONLY from the AK hosted pub repo.
version: 0.0.1
publish_to: none
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  ${PUB_NAME}:
    hosted:
      name: ${PUB_NAME}
      url: ${FC_INT_URL}
    version: ^${PUB_VER}
EOF
cat pubspec.yaml" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client, EMPTY cache. `dart pub get` resolves the hosted
# dep from AK, follows archive_url, and verifies archive_sha256 (a mismatch
# fails here — the built-in #2580 + integrity oracle).
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "set -o pipefail; export HOME=/root
rm -rf /root/.pub-cache/hosted /work/consumer/.dart_tool
cd /work/consumer && dart pub get 2>&1 | tail -30" \
    || { echo "dart pub get failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker lib was unpacked into the pub cache
# AND a consumer program imports the package and prints the marker.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "d=\$(find /root/.pub-cache/hosted -maxdepth 3 -type d -name '${PUB_NAME}-${PUB_VER}' 2>/dev/null | head -1)
test -n \"\$d\" && grep -q '${PUB_MARKER}' \"\$d/lib/dtf_marker.dart\" && echo \"unpacked at \$d\"" \
    || { echo "marker lib not found in pub cache after get"; return 1; }
  nc_exec -t 150 "export HOME=/root
cd /work/consumer
cat > bin/main.dart <<EOF
import 'package:${PUB_NAME}/dtf_marker.dart' as m;
void main() { print(m.marker()); }
EOF
dart run bin/main.dart 2>&1 | tail -5 | grep -q '${PUB_MARKER}'" \
    || { echo "consumer 'dart run' did not print the marker"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. /api/packages/<name> advertises
# an ABSOLUTE archive_url that 200s AND an archive_sha256 equal to the served
# bytes (a relative/wrong url or drifted sha would break a real client).
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local list="${WORK_DIR}/pub-pkg.json"
  nc_fetch "${FC_URL}/api/packages/${PUB_NAME}" "$list" || return 1
  local aurl adv served dl="${WORK_DIR}/pub-archive.tar.gz"
  aurl="$(jq -r '.latest.archive_url // (.versions[0].archive_url) // empty' "$list")"
  adv="$(jq -r '.latest.archive_sha256 // (.versions[0].archive_sha256) // empty' "$list")"
  [ -n "$aurl" ] || { echo "no archive_url advertised: $(cat "$list")"; return 1; }
  echo "  archive_url=${aurl}"
  case "$aurl" in
    http://*|https://*) : ;;
    *) echo "archive_url is not absolute (relative dist would fall back off-proxy)"; return 1 ;;
  esac
  nc_expect_code 200 "$aurl" || return 1
  # negative: a non-existent version archive must 404, not serve stale bytes
  nc_expect_code 404 "${FC_URL}/packages/${PUB_NAME}/versions/9.9.9.tar.gz" || return 1
  # advertised sha must equal the served bytes (pub enforces this on get)
  [ -n "$adv" ] || { echo "no archive_sha256 advertised"; return 1; }
  nc_fetch "$aurl" "$dl" || return 1
  served="$(nc_sha256 "$dl")"
  nc_assert_sha_eq "$adv" "$served" "advertised archive_sha256 != served bytes" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# archive_sha256 — explicit host-side equality of the advertised sha vs the
# served archive bytes (its own case per §4.12). Bug class: checksum drift.
fc_case_archive_sha256() {
  local list="${WORK_DIR}/pub-pkg2.json" dl="${WORK_DIR}/pub-archive2.tar.gz"
  nc_fetch "${FC_URL}/api/packages/${PUB_NAME}" "$list" || return 1
  local adv aurl served
  adv="$(jq -r '.latest.archive_sha256 // (.versions[0].archive_sha256) // empty' "$list")"
  aurl="$(jq -r '.latest.archive_url // (.versions[0].archive_url) // empty' "$list")"
  [ -n "$adv" ] && [ -n "$aurl" ] || { echo "no archive_sha256/url advertised"; return 1; }
  nc_fetch "$aurl" "$dl" || return 1
  served="$(nc_sha256 "$dl")"
  nc_assert_sha_eq "$adv" "$served" "archive_sha256 advertised != served bytes"
}

# republish_conflict — re-publishing the SAME version must be rejected (409),
# never a silent overwrite. Bug class: version immutability (#1997 sibling).
fc_case_republish_conflict() {
  local out rc
  out="$(nc_exec -t 180 "set -o pipefail; cd /work/pkg
export HOME=/root
dart pub publish --force 2>&1 | tail -25")"
  rc=$?
  echo "$out"
  # dart exits non-zero and prints "Failed to upload the package." when the
  # server rejects the duplicate (409 "Package version already exists").
  if [ "$rc" -eq 0 ]; then echo "republish SUCCEEDED (expected a conflict)"; return 1; fi
  echo "$out" | grep -qiE 'failed to upload|already exists|conflict|409' \
    || { echo "republish failed but not with a conflict diagnostic"; return 1; }
  # confirm the store was NOT overwritten: still exactly one version
  local nver
  nver="$(curl -s -H "$(format_auth_header)" "${FC_URL}/api/packages/${PUB_NAME}" | jq -r '.versions | length')"
  [ "$nver" = "1" ] || { echo "expected 1 stored version after rejected republish, got ${nver}"; return 1; }
  echo "  republish correctly rejected (version immutable; 1 version retained)"
}

# upload_flow_verbs — #1997 regression: `versions/new` MUST be GET-served (a 405
# on GET was the old bug that aborted `dart pub publish`). Positive: GET 200;
# negative: POST to the GET-only endpoint is 405.
fc_case_upload_flow_verbs() {
  local vnew="${FC_URL}/api/packages/versions/new"
  nc_expect_code 200 "$vnew" || return 1          # GET is served (auth ok)
  local pc
  pc="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X POST \
    -H "$(format_auth_header)" "$vnew" 2>/dev/null)"
  [ "$pc" = "405" ] || { echo "POST ${vnew} -> ${pc} (wanted 405 on the GET-only verb)"; return 1; }
  echo "  versions/new: GET 200 / POST 405 (#1997 held)"
  # the finalize step is also GET-served
  nc_expect_code 200 "${FC_URL}/api/packages/versions/newUploadFinish" || return 1
}
