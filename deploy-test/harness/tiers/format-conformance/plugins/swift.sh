# =============================================================================
# plugins/swift.sh — format-conformance plugin (Swift Package Registry, SE-0292)
# FC_FORMAT: swift
# FC_MOUNT: swift
# FC_REPO_FORMAT: swift
# FC_PROFILE: client.swift
# FC_SERVICE: client-swift
# FC_ENABLED: 1
# =============================================================================
# Swift routes (backend handlers/swift.rs): nest /swift; identifiers
# `GET /:repo/identifiers?url=`; release list `GET /:repo/:scope/:name`;
# wildcard version path `GET|PUT /:repo/:scope/:name/*version_path` which
# dispatches to release metadata (`/1.0.0`), source archive (`/1.0.0.zip`), and
# the Package.swift MANIFEST (`/1.0.0/Package.swift`, #1100). Identity
# `dtf.marker` maps to scope=`dtf`, name=`marker`.
#
# Publish is a raw authenticated PUT of a SwiftPM source archive to
# `/dtf/marker/1.0.0` (the backend extracts Package.swift from the zip so the
# manifest endpoint serves it — #1100). The DISCRIMINATING consume is the real
# `swift package resolve`, which follows releases -> metadata -> manifest ->
# archive and verifies the source-archive checksum end to end.
#
# STRICTNESS (game-plan §4.13 / §6): SwiftPM wants HTTPS. `--allow-insecure-http`
# is a `swift package-registry set` GUARD-RAIL (validated at set time, NOT
# persisted as a resolve flag); once the plaintext registry URL is in
# registries.json, `swift package resolve` uses it directly — so we write the
# config file and resolve needs no flag. A permissive local signing policy
# (onUnsigned=silentAllow, scoped to THIS registry only) is a real posture for a
# private unsigned registry. If a future toolchain refuses the plaintext registry
# or rejects the protocol shape, the affected case stays RED with a `# KNOWN-RED`
# note + a finding in rig/results/format-conformance/swift-finding.md — never
# softened to pass. (Verified GREEN on swift 6.0.3 / ak-backend:v158-4fix.)
# =============================================================================
FC_CASES="manifest_first content_version_header identifiers_lookup"

SWIFT_SCOPE="dtf"
SWIFT_NAME="marker"
SWIFT_ID="${SWIFT_SCOPE}.${SWIFT_NAME}"
SWIFT_VER="1.0.0"
SWIFT_MARKER_TOKEN="DTF-SWIFT-INSTALLED-${SWIFT_VER}"
SWIFT_PROD="/tmp/dtf-swift-producer"
SWIFT_CONS="/tmp/dtf-swift-consumer"
SWIFT_ZIP="/tmp/dtf-swift-${SWIFT_NAME}-${SWIFT_VER}.zip"

# ---------------------------------------------------------------------------
# fc_publish — build a canonical SwiftPM source archive in-container (with a
# grep-able marker source + a real Package.swift), copy it to the host, and PUT
# it on the native publish route. `swift package archive-source` guarantees a
# SwiftPM-consumable archive whose sha256 the registry advertises as the
# source-archive checksum (byte-identical to what the consumer downloads).
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v swift >/dev/null 2>&1 && swift --version' \
    || { echo "swift toolchain missing inside the provisioned client"; return 1; }
  # `swift package archive-source` shells out to `zip`, which the swift:6.0
  # (Ubuntu) image does not ship. Install it at publish time so a network blip
  # fails loudly here in one test rather than mysteriously later.
  nc_exec -t 180 'command -v zip >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq zip >/dev/null 2>&1; }
command -v zip >/dev/null 2>&1' \
    || { echo "could not provision zip for swift archive-source"; return 1; }
  nc_exec -t 300 "set -e
rm -rf '${SWIFT_PROD}' '${SWIFT_ZIP}'
mkdir -p '${SWIFT_PROD}' && cd '${SWIFT_PROD}'
swift package init --type library --name ${SWIFT_NAME} >/dev/null
mkdir -p Sources/${SWIFT_NAME}
cat > Sources/${SWIFT_NAME}/Marker.swift <<EOF
public let dtfMarker = \"${SWIFT_MARKER_TOKEN}\"
public func dtfMarkerPing() -> String { return dtfMarker }
EOF
swift package archive-source -o '${SWIFT_ZIP}'
ls -l '${SWIFT_ZIP}'" || { echo "swift package archive-source failed"; return 1; }

  local host_zip="${WORK_DIR}/swift-${SWIFT_NAME}-${SWIFT_VER}.zip"
  nc_copy_from_ctr "$SWIFT_ZIP" "$host_zip" || { echo "could not copy archive from ctr"; return 1; }
  [ -s "$host_zip" ] || { echo "empty archive copied from ctr"; return 1; }
  SWIFT_PUB_SHA="$(nc_sha256 "$host_zip")"
  echo "  archive=${host_zip} sha256=${SWIFT_PUB_SHA}"
  # Publish (raw PUT to the wildcard version path -> 201 CREATED).
  nc_put_file "$host_zip" "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}" "200 201" || return 1
  # The release must now be listed by the registry.
  nc_expect_code 200 "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real client, then create a consumer package and
# configure it to use ONLY the AK registry (default registry, insecure http).
# A permissive local signing policy is a legitimate posture for a private,
# unsigned registry; it points ONLY at the AK registry, not at any default.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec -t 240 "set -e
rm -rf '${SWIFT_CONS}'
mkdir -p '${SWIFT_CONS}' && cd '${SWIFT_CONS}'
swift package init --type executable --name consumer >/dev/null
cat > Package.swift <<EOF
// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: \"consumer\",
    dependencies: [
        .package(id: \"${SWIFT_ID}\", from: \"${SWIFT_VER}\")
    ],
    targets: [
        .executableTarget(name: \"consumer\")
    ]
)
EOF
mkdir -p .swiftpm/configuration
cat > .swiftpm/configuration/registries.json <<EOF
{
  \"authentication\": {},
  \"registries\": {
    \"[default]\": { \"url\": \"${FC_INT_URL}\" }
  },
  \"security\": {
    \"default\": {
      \"signing\": {
        \"onUnsigned\": \"silentAllow\",
        \"onUntrustedCertificate\": \"silentAllow\"
      }
    }
  },
  \"version\": 1
}
EOF
cat .swiftpm/configuration/registries.json" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `swift package resolve` follows the registry
# protocol against AK ONLY (the default registry in registries.json): releases
# -> metadata -> Package.swift -> archive, verifying the source-archive checksum.
# The plaintext registry is honored from the config (see the set-time
# guard-rail note in the header). Non-zero exit = fail.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 300 "cd '${SWIFT_CONS}'
swift package resolve --disable-sandbox 2>&1" \
    || { echo "swift package resolve failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: Package.resolved pins the registry identity at
# 1.0.0 (only possible if resolution followed AK end to end), and the fetched
# source carries the grep-able marker token.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "cd '${SWIFT_CONS}' && test -f Package.resolved && cat Package.resolved" \
    | grep -q "${SWIFT_ID}" \
    || { echo "Package.resolved does not pin ${SWIFT_ID}"; return 1; }
  nc_exec "cd '${SWIFT_CONS}' && grep -q '\"${SWIFT_VER}\"' Package.resolved" \
    || { echo "Package.resolved does not pin version ${SWIFT_VER}"; return 1; }
  # The resolved registry source (unpacked under .build) must carry the marker.
  nc_exec "grep -rq '${SWIFT_MARKER_TOKEN}' '${SWIFT_CONS}/.build' 2>/dev/null" \
    || { echo "marker token not found in the resolved source under .build"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator, plus #1100. The release list
# advertises 1.0.0; the metadata resource points at the checksummed archive; the
# manifest endpoint (fetched BEFORE the archive) 200s; a never-published version
# 404s cleanly (not 500/empty-200).
# ---------------------------------------------------------------------------
fc_advertised_check() {
  # Positive: release list advertises the version, mapping to its metadata url.
  local url
  url="$(nc_advertised "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}" \
    "jq -r '.releases[\"${SWIFT_VER}\"].url // empty'")" || return 1
  echo "  releases advertise ${SWIFT_VER} -> ${url}"
  # Positive: the manifest endpoint resolves (SwiftPM fetches it before the zip).
  nc_expect_code 200 "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}/Package.swift" || return 1
  # Positive: the source archive resolves.
  nc_expect_code 200 "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}.zip" || return 1
  # Positive: the advertised metadata checksum equals the served archive bytes.
  local adv_sha
  adv_sha="$(nc_advertised "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}" \
    "jq -r '.resources[] | select(.name==\"source-archive\") | .checksum // empty'")" || return 1
  local dl="${WORK_DIR}/swift-served.zip"
  nc_fetch "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}.zip" "$dl" || return 1
  nc_assert_sha_eq "$adv_sha" "$(nc_sha256 "$dl")" "advertised checksum != served archive bytes" || return 1
  # Negative: a never-published version 404s (not 500/empty-200).
  nc_expect_code 404 "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/9.9.9" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# manifest_first (#1100) — SwiftPM fetches Package.swift BEFORE the archive; a
# 404 here breaks resolution even with a valid archive. Assert the manifest 200s
# AND parses as a real manifest (carries swift-tools-version), while a manifest
# request for a never-published version 404s.
fc_case_manifest_first() {
  local m="${WORK_DIR}/swift-Package.swift"
  nc_fetch "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}/Package.swift" "$m" || return 1
  [ -s "$m" ] || { echo "empty manifest response"; return 1; }
  grep -q 'swift-tools-version' "$m" \
    || { echo "manifest endpoint did not return a real Package.swift"; head -c 200 "$m"; return 1; }
  echo "  manifest endpoint served a real Package.swift"
  # Negative: manifest for a never-published version must 404.
  nc_expect_code 404 "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/9.9.9/Package.swift" || return 1
}

# content_version_header (SE-0292) — every registry response must carry
# `Content-Version: 1`; SwiftPM validates it. Bug class: a missing/incorrect
# Content-Version that makes a strict client reject the registry.
fc_case_content_version_header() {
  local hdrs="${WORK_DIR}/swift-headers.txt"
  curl -s -D "$hdrs" -o /dev/null --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}" 2>/dev/null
  grep -iq '^Content-Version:[[:space:]]*1' "$hdrs" \
    || { echo "release-list response missing 'Content-Version: 1'"; cat "$hdrs"; return 1; }
  echo "  release list carries Content-Version: 1"
  # The metadata response must carry it too.
  curl -s -D "$hdrs" -o /dev/null --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/${SWIFT_SCOPE}/${SWIFT_NAME}/${SWIFT_VER}" 2>/dev/null
  grep -iq '^Content-Version:[[:space:]]*1' "$hdrs" \
    || { echo "release-metadata response missing 'Content-Version: 1'"; cat "$hdrs"; return 1; }
  echo "  release metadata carries Content-Version: 1"
}

# identifiers_lookup (:39) — the identifiers endpoint is protocol-conformant:
# a missing `url` query param is a 400; a present `url` returns 200 with a valid
# `identifiers` array and the Content-Version header. (A POSITIVE identifier
# match requires publish-with-metadata that records repository_url; a raw PUT
# cannot set it, so this case asserts the protocol contract, not a match.)
fc_case_identifiers_lookup() {
  # Negative: missing url param -> 400.
  nc_expect_code 400 "${FC_URL}/identifiers" || return 1
  echo "  identifiers without url -> 400"
  # Positive: present url -> 200 JSON with an identifiers array + Content-Version.
  local out="${WORK_DIR}/swift-identifiers.json" hdrs="${WORK_DIR}/swift-id-headers.txt"
  local code
  code="$(curl -s -D "$hdrs" -o "$out" -w '%{http_code}' --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/identifiers?url=https://example.invalid/dtf/marker.git" 2>/dev/null)"
  [ "$code" = "200" ] || { echo "identifiers lookup -> HTTP ${code} (wanted 200)"; cat "$out"; return 1; }
  jq -e '.identifiers | type == "array"' "$out" >/dev/null \
    || { echo "identifiers response is not a JSON array under .identifiers"; cat "$out"; return 1; }
  grep -iq '^Content-Version:[[:space:]]*1' "$hdrs" \
    || { echo "identifiers response missing Content-Version: 1"; cat "$hdrs"; return 1; }
  echo "  identifiers lookup returns a conformant JSON array + Content-Version"
}
