# =============================================================================
# plugins/composer.sh — format-conformance plugin
# FC_FORMAT: composer
# FC_MOUNT: composer
# FC_REPO_FORMAT: composer
# FC_PROFILE: client.composer
# FC_SERVICE: client-composer
# FC_ENABLED: 1
# =============================================================================
# Composer/Packagist v2 protocol (backend handlers/composer.rs): nest /composer;
# root index `GET /:repo/packages.json`; v2 metadata `GET /:repo/p2/:vendor/:pkg`;
# dist download `GET /:repo/dist/:vendor/:pkg/:version/:reference`; search
# `GET /:repo/search.json`; upload `PUT|POST /:repo/api/packages`.
#
# The consume is a REAL `composer update --prefer-dist` whose composer.json pins
# the AK repo as the ONLY source AND sets `"packagist.org": false`, so the
# install can succeed ONLY via AK. It reads `packages.json` -> `metadata-url`
# (p2) -> `dist.url`, FOLLOWS the ABSOLUTE dist URL back to AK, downloads the
# archive, and extracts it into `vendor/` — then the assertion checks
# `installed.json` records `installation-source: dist` (NOT a `source` git
# clone). That dist-vs-source distinction is the #2361/#2370/#2421 regression
# class (a root-relative dist.url silently made Composer fall back to source and
# bypass the proxy) — invisible to upload-only curl tests.
# =============================================================================
FC_CASES="dist_not_source dev_metadata_shape search_json"

COMPOSER_VENDOR="dtf"
COMPOSER_PKG="marker"
COMPOSER_NAME="${COMPOSER_VENDOR}/${COMPOSER_PKG}"
COMPOSER_VER="1.0.0"
COMPOSER_MARKER_TOKEN="DTF-COMPOSER-INSTALLED-${COMPOSER_VER}"
COMPOSER_BUILDSH="${DTF_DIR}/fixtures/composer/build.sh"
COMPOSER_CONSUMER="/tmp/dtf-composer/consumer"

# ---------------------------------------------------------------------------
# fc_publish — host-craft the package zip and PUT it on the native upload route.
# (host curl PUT is the accepted brick-3 deviation; the discriminating value is
# the client-side CONSUME following the advertised absolute dist.url.)
# ---------------------------------------------------------------------------
fc_publish() {
  COMPOSER_FIXTURE="$(bash "$COMPOSER_BUILDSH" "$WORK_DIR" "$COMPOSER_VENDOR" "$COMPOSER_PKG" "$COMPOSER_VER" "$COMPOSER_MARKER_TOKEN")" || return 1
  [ -s "$COMPOSER_FIXTURE" ] || { echo "fixture build produced no file"; return 1; }
  echo "  fixture=${COMPOSER_FIXTURE}"
  nc_put_file "$COMPOSER_FIXTURE" "${FC_URL}/api/packages" || return 1
  # The root index + p2 metadata must now list it.
  nc_expect_code 200 "${FC_URL}/packages.json" || return 1
  nc_expect_code 200 "${FC_URL}/p2/${COMPOSER_VENDOR}/${COMPOSER_PKG}.json" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify composer is present (no silent skip) and write a
# consumer composer.json INSIDE the container pointing ONLY at $FC_INT_URL, with
# packagist.org disabled and secure-http off (plain-HTTP cluster-internal AK).
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v composer >/dev/null 2>&1 && composer --version' \
    || { echo "composer missing inside the provisioned composer client"; return 1; }
  nc_exec "set -e
rm -rf '${COMPOSER_CONSUMER}'; mkdir -p '${COMPOSER_CONSUMER}'
cat > '${COMPOSER_CONSUMER}/composer.json' <<EOF
{
  \"repositories\": [
    { \"type\": \"composer\", \"url\": \"${FC_INT_URL}\" },
    { \"packagist.org\": false }
  ],
  \"require\": { \"${COMPOSER_NAME}\": \"${COMPOSER_VER}\" },
  \"config\": { \"secure-http\": false },
  \"minimum-stability\": \"stable\"
}
EOF
cat '${COMPOSER_CONSUMER}/composer.json'" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `composer update --prefer-dist` resolves via the
# AK repo only, following packages.json -> p2 -> the absolute dist.url.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "cd '${COMPOSER_CONSUMER}' && \
COMPOSER_HOME=/tmp/dtf-composer/home composer update --no-interaction --prefer-dist --no-progress 2>&1" \
    || { echo "composer update failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the marker source was extracted into vendor/
# from the dist archive, AND installed.json records installation-source: dist.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "test -f '${COMPOSER_CONSUMER}/vendor/${COMPOSER_NAME}/src/Marker.php' && \
grep -q '${COMPOSER_MARKER_TOKEN}' '${COMPOSER_CONSUMER}/vendor/${COMPOSER_NAME}/src/Marker.php'" \
    || { echo "marker source not extracted into vendor/"; return 1; }
  # The composer image has no jq; pull installed.json to the host and parse there.
  local src
  src="$(_composer_installation_source)" || return 1
  echo "  installed.json installation-source=${src}"
  case "$src" in
    dist) : ;;
    *) echo "  package installed from '${src}' (expected 'dist'; 'source' = the #2361 proxy-bypass regression)"; return 1 ;;
  esac
}

# Copy the consumer's installed.json to the host and echo our package's
# installation-source (host has jq; the composer client image does not).
_composer_installation_source() {
  local out="${WORK_DIR}/installed.json"
  nc_copy_from_ctr "${COMPOSER_CONSUMER}/vendor/composer/installed.json" "$out" \
    || { echo "could not copy installed.json from client"; return 1; }
  jq -r --arg n "$COMPOSER_NAME" '.packages[]? | select(.name==$n) | ."installation-source"' "$out"
}

# ---------------------------------------------------------------------------
# fc_advertised_check — #2361/#2580 discriminator. The p2 dist.url MUST be an
# absolute URL back to this AK (a root-relative dist.url is the regression that
# made Composer fall back to source) and MUST 200; the download route matches on
# the real reference, so a corrupted reference under the same path 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local dist_url
  dist_url="$(nc_advertised "${FC_URL}/p2/${COMPOSER_VENDOR}/${COMPOSER_PKG}.json" \
    "jq -r --arg n '${COMPOSER_NAME}' --arg v '${COMPOSER_VER}' '.packages[\$n][] | select(.version==\$v) | .dist.url'")" || return 1
  echo "  advertised dist.url=${dist_url}"
  # absoluteness (#2361): must be an absolute http(s) URL routing back to AK
  case "$dist_url" in
    http://*/composer/*/dist/*|https://*/composer/*/dist/*) : ;;
    *) echo "  dist.url is NOT absolute-to-AK (root-relative = the #2361 regression): ${dist_url}"; return 1 ;;
  esac
  # positive: the advertised absolute dist.url resolves
  nc_expect_code 200 "$dist_url" || return 1
  # negative: the download route matches on the real reference (sha256) — a
  # corrupted reference under the same path must 404 (not a blanket 200)
  local bogus="${dist_url%/*}/0000000000000000000000000000000000000000000000000000000000000000.zip"
  nc_expect_code 404 "$bogus" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# dist_not_source (#2361/#2370/#2421) — the installed.json installation-source
# must be exactly "dist" for our package, proving Composer followed the absolute
# dist.url and did NOT fall back to a `source` git clone (proxy bypass). A
# `source` value here is the regression this whole tier exists to catch.
# Bug class: relative-dist-url -> composer source fallback / proxy bypass.
fc_case_dist_not_source() {
  local out="${WORK_DIR}/installed.json"
  nc_copy_from_ctr "${COMPOSER_CONSUMER}/vendor/composer/installed.json" "$out" \
    || { echo "could not copy installed.json"; return 1; }
  # positive: installed from dist
  local src
  src="$(jq -r --arg n "$COMPOSER_NAME" '.packages[]? | select(.name==$n) | ."installation-source"' "$out")"
  case "$src" in dist) : ;; *) echo "  installation-source=${src} (expected dist)"; return 1 ;; esac
  # negative: there must be NO source-installed entry for our package
  local as_source
  as_source="$(jq -r --arg n "$COMPOSER_NAME" '[.packages[]? | select(.name==$n and ."installation-source"=="source")] | length' "$out")"
  case "$as_source" in 0) echo "  installation-source=dist, no source fallback" ;; *) echo "  package ALSO/ONLY installed from source (${as_source})"; return 1 ;; esac
}

# dev_metadata_shape — Composer 2 probes `p2/<vendor>/<pkg>~dev.json` for dev
# branches. The endpoint must return valid JSON (200) OR a CLEAN 404 (no dev
# versions) — never a 500 that aborts `composer install`, never an empty-200.
# Bug class: metadata endpoint 500/garbage on the ~dev probe (#2250 neighbourhood).
fc_case_dev_metadata_shape() {
  local body="${WORK_DIR}/composer-dev.json"
  local code
  code="$(curl -s -o "$body" -w '%{http_code}' --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/p2/${COMPOSER_VENDOR}/${COMPOSER_PKG}~dev.json" 2>/dev/null)"
  echo "  p2 ~dev probe -> HTTP ${code}"
  case "$code" in
    200)
      jq . "$body" >/dev/null 2>&1 || { echo "  ~dev returned 200 but not valid JSON"; head -c 200 "$body"; return 1; }
      echo "  ~dev returned valid JSON (200)" ;;
    404)
      echo "  ~dev returned a clean 404 (no dev versions — Composer continues)" ;;
    *)
      echo "  ~dev returned HTTP ${code} (a 500/empty-200 aborts composer install)"; return 1 ;;
  esac
  # negative: an entirely bogus vendor ~dev probe must ALSO be clean (never 500)
  local bad
  bad="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/p2/nonexistent-${RUN_ID}/ghost~dev.json" 2>/dev/null)"
  case "$bad" in 404|200) echo "  bogus ~dev probe -> HTTP ${bad} (clean)" ;; *) echo "  bogus ~dev probe -> HTTP ${bad} (expected clean 404/200)"; return 1 ;; esac
}

# search_json — the `/search.json` endpoint must list the package for a matching
# query and return zero results for a non-matching one.
# Bug class: search index not populated / advertised search URL not servable.
fc_case_search_json() {
  local hit
  hit="$(curl -s --max-time 60 -H "$(format_auth_header)" "${FC_URL}/search.json?q=${COMPOSER_PKG}" 2>/dev/null \
    | jq -r --arg n "$COMPOSER_NAME" '.results[]? | select(.name==$n) | .name' | head -1)"
  [ -n "$hit" ] || { echo "search.json did not return ${COMPOSER_NAME}"; return 1; }
  local total
  total="$(curl -s --max-time 60 -H "$(format_auth_header)" "${FC_URL}/search.json?q=nomatch-${RUN_ID}" 2>/dev/null \
    | jq -r '.total // (.results|length)')"
  case "$total" in 0) : ;; *) echo "  non-matching search returned total=${total} (expected 0)"; return 1 ;; esac
  echo "  search.json finds ${COMPOSER_NAME}; non-matching query returns 0"
}
