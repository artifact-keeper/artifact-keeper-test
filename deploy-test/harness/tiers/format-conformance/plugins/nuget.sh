# =============================================================================
# plugins/nuget.sh — format-conformance plugin
# FC_FORMAT: nuget
# FC_MOUNT: nuget
# FC_REPO_FORMAT: nuget
# FC_PROFILE: client.nuget
# FC_SERVICE: client-nuget
# FC_ENABLED: 1
# =============================================================================
# NuGet v3 protocol (backend handlers/nuget.rs): nest /nuget; service index
# `GET /:repo/v3/index.json`; search `/v3/search`; registration
# `/v3/registration/:id/index.json`; flatcontainer versions
# `/v3/flatcontainer/:id/index.json` + download `/v3/flatcontainer/:id/:ver/:file`;
# push `PUT /:repo/api/v2/package[/]` (trailing slash both registered — dotnet
# appends one to the PackagePublish URL it discovers from the service index).
#
# The publish is a REAL `dotnet nuget push --source .../v3/index.json`: the
# client DISCOVERS the PackagePublish/2.0.0 resource from the service index and
# PUTs there (that discovery IS part of the test). The consume is a REAL
# `dotnet restore` whose nuget.config has ONLY the AK source (`<clear/>`), so the
# restore reads the service index -> PackageBaseAddress(flatcontainer), FOLLOWS
# the advertised location to fetch `dtf.marker/1.0.0/dtf.marker.1.0.0.nupkg`, and
# caches it (the #2580 path). Framework reference packs resolve from the SDK's
# bundled NuGetFallback folder, so AK can be the ONLY configured source.
# =============================================================================
FC_CASES="id_case_normalization version_normalization republish_conflict search_service"

NUGET_ID="Dtf.Marker"
NUGET_ID_LC="dtf.marker"                 # protocol lowercases flatcontainer paths
NUGET_VER="1.0.0"
NUGET_WS="/tmp/dtf-nuget"
NUGET_PROJ="${NUGET_WS}/${NUGET_ID}"
NUGET_CONSUMER="${NUGET_WS}/consumer"
NUGET_PKG_CACHE="/root/.nuget/packages/${NUGET_ID_LC}"

# Write a credentialed push-side nuget.config as `<dir>/nuget.config` (dotnet
# nuget push reads the AMBIENT config from its working dir; it has no
# --configfile flag). AK's write-visibility middleware authenticates via the
# standard `Authorization` header (Basic/Bearer/ApiKey), NOT NuGet's
# `X-NuGet-ApiKey` — so an authorized push needs a credentialed source, exactly
# how real authenticated NuGet feeds (GitHub Packages, Azure Artifacts) are
# consumed by dotnet. The client still DISCOVERS the PackagePublish/2.0.0
# resource from the v3 service index (that discovery IS part of the test).
_nuget_write_pushcfg() {
  local dir="$1"
  nc_exec "mkdir -p '${dir}' && cat > '${dir}/nuget.config' <<EOF
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<configuration>
  <packageSources>
    <clear />
    <add key=\"ak\" value=\"${FC_INT_URL}/v3/index.json\" protocolVersion=\"3\" allowInsecureConnections=\"true\" />
  </packageSources>
  <packageSourceCredentials>
    <ak>
      <add key=\"Username\" value=\"${ADMIN_USER}\" />
      <add key=\"ClearTextPassword\" value=\"${ADMIN_PASS}\" />
    </ak>
  </packageSourceCredentials>
</configuration>
EOF"
}

# ---------------------------------------------------------------------------
# fc_publish — `dotnet new classlib` + `dotnet pack` a dependency-free package,
# then `dotnet nuget push` it: the client discovers PackagePublish from the v3
# service index and PUTs the .nupkg (the accepted brick-3 publish; the
# discriminating value is the client-side CONSUME below).
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v dotnet >/dev/null 2>&1 && dotnet --version' \
    || { echo "dotnet missing inside the provisioned nuget client"; return 1; }

  nc_exec -t 300 "set -e
rm -rf '${NUGET_WS}'; mkdir -p '${NUGET_PROJ}'
cd '${NUGET_PROJ}'
dotnet new classlib -n '${NUGET_ID}' -o . >/dev/null
dotnet pack -c Release -p:Version='${NUGET_VER}' -p:PackageId='${NUGET_ID}' -o '${NUGET_WS}/out' >/dev/null
test -s '${NUGET_WS}/out/${NUGET_ID}.${NUGET_VER}.nupkg'" \
    || { echo "dotnet new/pack failed"; return 1; }

  NUGET_PUB_SHA="$(nc_sha256_in_ctr "${NUGET_WS}/out/${NUGET_ID}.${NUGET_VER}.nupkg")"
  echo "  packed nupkg sha256=${NUGET_PUB_SHA}"

  # REAL client push against the credentialed AK source: dotnet resolves the
  # PackagePublish/2.0.0 URL from the v3 service index (that discovery IS part
  # of the test) and PUTs there with Basic auth from the source credentials.
  _nuget_write_pushcfg "${NUGET_WS}/out" || { echo "could not write push nuget.config"; return 1; }
  nc_exec -t 240 "cd '${NUGET_WS}/out' && dotnet nuget push '${NUGET_ID}.${NUGET_VER}.nupkg' \
    --source ak --api-key '${ADMIN_USER}:${ADMIN_PASS}' 2>&1" \
    || { echo "dotnet nuget push failed"; return 1; }

  # The advertised flatcontainer versions index must now list it.
  nc_expect_code 200 "${FC_URL}/v3/flatcontainer/${NUGET_ID_LC}/index.json" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify dotnet + write a consumer project whose nuget.config
# clears ALL default sources and adds ONLY the AK v3 index (so a restore can
# succeed only via AK), plus a PackageReference on the pushed package.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v dotnet >/dev/null 2>&1' \
    || { echo "dotnet missing inside the provisioned nuget client"; return 1; }
  nc_exec "set -e
mkdir -p '${NUGET_CONSUMER}'
cat > '${NUGET_CONSUMER}/nuget.config' <<EOF
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<configuration>
  <packageSources>
    <clear />
    <add key=\"ak\" value=\"${FC_INT_URL}/v3/index.json\" protocolVersion=\"3\" allowInsecureConnections=\"true\" />
  </packageSources>
</configuration>
EOF
cat > '${NUGET_CONSUMER}/consumer.csproj' <<EOF
<Project Sdk=\"Microsoft.NET.Sdk\">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include=\"${NUGET_ID}\" Version=\"${NUGET_VER}\" />
  </ItemGroup>
</Project>
EOF
cat '${NUGET_CONSUMER}/nuget.config'" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. A fresh restore (global cache for this id wiped)
# reads the v3 index -> flatcontainer and downloads the advertised nupkg from
# AK ONLY.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 300 "rm -rf '${NUGET_PKG_CACHE}'
cd '${NUGET_CONSUMER}' && dotnet restore --no-cache --force 2>&1" \
    || { echo "dotnet restore failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the nupkg landed in the global-packages cache
# and its bytes are byte-identical to the packed+pushed package.
# ---------------------------------------------------------------------------
fc_assert() {
  local cached="${NUGET_PKG_CACHE}/${NUGET_VER}/${NUGET_ID_LC}.${NUGET_VER}.nupkg"
  nc_exec "test -s '${cached}'" || { echo "restored nupkg missing at ${cached}"; return 1; }
  local got
  got="$(nc_sha256_in_ctr "$cached")"
  nc_assert_sha_eq "$NUGET_PUB_SHA" "$got" "restored nupkg != pushed nupkg" || return 1
}

# ---------------------------------------------------------------------------
# fc_advertised_check — #2580 discriminator. The service index advertises a
# PackageBaseAddress/3.0.0 resource; its URL prefix must ACTUALLY serve the
# flatcontainer versions index + the nupkg (positive), while a never-published
# coordinate under the same prefix 404s (negative — the route discriminates real
# content, it is not a blanket 200).
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local base
  base="$(nc_advertised "${FC_URL}/v3/index.json" \
    "jq -r '.resources[] | select(.\"@type\"==\"PackageBaseAddress/3.0.0\") | .\"@id\"'")" || return 1
  base="${base%/}"
  echo "  advertised PackageBaseAddress=${base}"
  # positive: the advertised prefix serves the versions index + the nupkg
  nc_expect_code 200 "${base}/${NUGET_ID_LC}/index.json" || return 1
  nc_expect_code 200 "${base}/${NUGET_ID_LC}/${NUGET_VER}/${NUGET_ID_LC}.${NUGET_VER}.nupkg" || return 1
  # the versions index advertises 1.0.0
  local adv_ver
  adv_ver="$(nc_advertised "${base}/${NUGET_ID_LC}/index.json" "jq -r '.versions[]' | head -1")" || return 1
  case "$adv_ver" in "$NUGET_VER") : ;; *) echo "  flatcontainer versions mismatch (${adv_ver})"; return 1 ;; esac
  # negative: a never-published version under the SAME prefix must 404
  nc_expect_code 404 "${base}/${NUGET_ID_LC}/9.9.9/${NUGET_ID_LC}.9.9.9.nupkg" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# id_case_normalization — the package was pushed as `Dtf.Marker`; NuGet's
# flatcontainer protocol is lowercase-normalized. Both the lowercase and the
# mixed-case id path must resolve to the same versions index (client tolerance),
# while a DIFFERENT (prefix-only) id must 404 (not a substring match).
# Bug class: id casing / partial-match resolution drift.
fc_case_id_case_normalization() {
  # positive: canonical lowercase path resolves + lists the version
  local v
  v="$(nc_advertised "${FC_URL}/v3/flatcontainer/${NUGET_ID_LC}/index.json" "jq -r '.versions[]' | head -1")" || return 1
  case "$v" in "$NUGET_VER") : ;; *) echo "  lowercase path version mismatch (${v})"; return 1 ;; esac
  # positive: the mixed-case id path also resolves (backend lowercases)
  nc_expect_code 200 "${FC_URL}/v3/flatcontainer/${NUGET_ID}/index.json" || return 1
  # negative: a prefix-only id (never published) must 404 — not a LIKE/substring hit
  nc_expect_code 404 "${FC_URL}/v3/flatcontainer/${NUGET_ID_LC%?}/index.json" || return 1
  echo "  ${NUGET_ID} and ${NUGET_ID_LC} both resolve; prefix-only id 404s"
}

# version_normalization — pack a 4-part version `1.2.3.0`; NuGet de-zeros the
# trailing segment. The flatcontainer versions index + a real restore must
# agree on the normalized form: a restore requesting `1.2.3` resolves, while an
# unpublished `1.2.4` does not.
# Bug class: version-shape disagreement between registration/flatcontainer/client.
fc_case_version_normalization() {
  local nid="Dtf.Norm" nlc="dtf.norm" packver="1.2.3.0"
  nc_exec -t 300 "set -e
rm -rf '${NUGET_WS}/norm'; mkdir -p '${NUGET_WS}/norm'
cd '${NUGET_WS}/norm'
dotnet new classlib -n '${nid}' -o . >/dev/null
dotnet pack -c Release -p:Version='${packver}' -p:PackageId='${nid}' -o '${NUGET_WS}/norm-out' >/dev/null
ls '${NUGET_WS}/norm-out'" \
    || { echo "norm package pack failed"; return 1; }
  _nuget_write_pushcfg "${NUGET_WS}/norm-out" || return 1
  nc_exec -t 240 "cd '${NUGET_WS}/norm-out' && dotnet nuget push *.nupkg \
  --source ak --api-key '${ADMIN_USER}:${ADMIN_PASS}' 2>&1" \
    || { echo "norm package push failed"; return 1; }
  # the flatcontainer index must list SOME normalized version; capture it
  local listed
  listed="$(nc_advertised "${FC_URL}/v3/flatcontainer/${nlc}/index.json" "jq -r '.versions[]' | head -1")" || return 1
  echo "  ${nid} indexed version=${listed} (packed as ${packver})"
  # positive: a real restore requesting the de-zeroed 1.2.3 resolves
  nc_exec "set -e
mkdir -p '${NUGET_WS}/normcons'
cat > '${NUGET_WS}/normcons/nuget.config' <<EOF
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<configuration><packageSources><clear />
<add key=\"ak\" value=\"${FC_INT_URL}/v3/index.json\" protocolVersion=\"3\" allowInsecureConnections=\"true\" />
</packageSources></configuration>
EOF
cat > '${NUGET_WS}/normcons/normcons.csproj' <<EOF
<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<ItemGroup><PackageReference Include=\"${nid}\" Version=\"1.2.3\" /></ItemGroup></Project>
EOF
rm -rf /root/.nuget/packages/${nlc}
cd '${NUGET_WS}/normcons' && dotnet restore --no-cache --force 2>&1" \
    || { echo "restore of de-zeroed 1.2.3 failed (normalization disagreement)"; return 1; }
  # negative: an unpublished 1.2.4 must NOT resolve
  nc_expect_code 404 "${FC_URL}/v3/flatcontainer/${nlc}/1.2.4/${nlc}.1.2.4.nupkg" || return 1
  echo "  restore of normalized 1.2.3 succeeded; unpublished 1.2.4 404s"
}

# republish_conflict — re-pushing the SAME id+version must be rejected (409 via
# the release-immutability backstop), never a silent overwrite.
# Bug class: mutable-release / silent clobber of a published coordinate.
fc_case_republish_conflict() {
  # pull the already-pushed nupkg to the host and re-PUT it on the push route
  local local_nupkg="${WORK_DIR}/${NUGET_ID}.${NUGET_VER}.nupkg"
  nc_copy_from_ctr "${NUGET_WS}/out/${NUGET_ID}.${NUGET_VER}.nupkg" "$local_nupkg" \
    || { echo "could not copy nupkg from client for re-push"; return 1; }
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 120 \
    -X PUT -H "$(format_auth_header)" --data-binary "@${local_nupkg}" \
    "${FC_URL}/api/v2/package" 2>/dev/null)"
  case "$code" in
    409) echo "  duplicate id+version re-push rejected (HTTP 409)" ;;
    *) echo "  duplicate re-push returned HTTP ${code} (expected 409; a 2xx = silent clobber)"; return 1 ;;
  esac
}

# search_service — the SearchQueryService the index advertises must return the
# package for a matching query and nothing for a non-matching one.
# Bug class: search index not populated / advertised search URL not servable.
fc_case_search_service() {
  local search
  search="$(nc_advertised "${FC_URL}/v3/index.json" \
    "jq -r '[.resources[] | select(.\"@type\"==\"SearchQueryService\") | .\"@id\"][0]'")" || return 1
  echo "  advertised SearchQueryService=${search}"
  # positive: a query matching our id finds it
  local hit
  hit="$(curl -s --max-time 60 -H "$(format_auth_header)" "${search}?q=${NUGET_ID_LC}" 2>/dev/null \
    | jq -r --arg id "$NUGET_ID_LC" '.data[]? | select((.id|ascii_downcase)==$id) | .id' | head -1)"
  [ -n "$hit" ] || { echo "search did not return ${NUGET_ID_LC}"; return 1; }
  # negative: a query that cannot match returns zero hits
  local miss
  miss="$(curl -s --max-time 60 -H "$(format_auth_header)" "${search}?q=nomatch-${RUN_ID}" 2>/dev/null \
    | jq -r '.totalHits // (.data|length)')"
  case "$miss" in 0) : ;; *) echo "  non-matching search returned ${miss} hits (expected 0)"; return 1 ;; esac
  echo "  search finds ${NUGET_ID_LC}; non-matching query returns 0"
}
