# =============================================================================
# plugins/rubygems.sh — format-conformance plugin (RubyGems)
# FC_FORMAT: rubygems
# FC_MOUNT: gems
# FC_REPO_FORMAT: rubygems
# FC_PROFILE: client.rubygems
# FC_SERVICE: client-rubygems
# FC_ENABLED: 0
# =============================================================================
# RubyGems routes (backend handlers/rubygems.rs): nest **/gems** (routes.rs:73 —
# NOT /rubygems). push `POST /:repo/api/v1/gems`; gem info `GET
# /:repo/api/v1/gems/:name`; deps `GET /:repo/api/v1/dependencies`; specs
# `GET /:repo/specs.4.8.gz` + `latest_specs.4.8.gz`; download `GET /:repo/gems/*`.
#
# This ports the orphaned tests/formats/test-rubygems-native-client.sh verbs
# (gem build/push/fetch, never wired anywhere) onto the DTF topology and adds a
# REAL consume: `gem fetch --clear-sources --source $FC_INT_URL` + `gem install`.
# `--clear-sources` disables rubygems.org so the install can ONLY succeed via
# the AK source (the discriminator) — the client resolves the gem from
# specs.4.8.gz / the /api/v1/dependencies API and FOLLOWS `/gems/<file>` to it.
#
# KNOWN-RED (FC_ENABLED: 0 — the CORE consume is blocked by a real backend gap):
# AK serves `specs.4.8.gz` (and `latest_specs.4.8.gz`) as gzipped **JSON**
# (`specs_to_gzip_response` -> `serde_json::to_vec`), but a real gem/bundler
# client hard-requires a gzipped Ruby **Marshal 4.8** stream. RubyGems 3.5 fails
# immediately: `Gem::SafeMarshal::Reader::UnsupportedVersionError: Unsupported
# marshal version 91.91, expected 4.8` (91.91 == the ASCII "[[" of the JSON
# array). So `gem fetch/install/bundle install` against ANY hosted AK rubygems
# repo cannot even parse the spec index. The push verb (`gem push`) works — this
# is purely the consume-side index format. The curl-based corpus test-rubygems.sh
# only greps the JSON body, so it never surfaced this. See
# rig/results/format-conformance/rubygems-finding.md.
#
# The plugin below is fully implemented and left registered so flipping
# FC_ENABLED: 1 re-tests the whole real-client flow the moment the backend emits
# Marshal-4.8 spec indices.
# =============================================================================
FC_CASES="dependency_resolution latest_specs auth_push"

GEM_NAME="dtf-marker"
GEM_VER="1.0.0"
GEM_FILE="${GEM_NAME}-${GEM_VER}.gem"

# base64 of admin:pass for the gem `~/.gem/credentials` API-key (RubyGems sends
# the api_key verbatim as the Authorization header; the backend accepts Basic).
_gem_auth() {
  printf 'AUTHB64=$(printf "%%s:%%s" "%s" "%s" | base64 -w0); ' "$ADMIN_USER" "$ADMIN_PASS"
}

# Emit a gemspec + lib file for <name> <version> [dep_name dep_version] into
# /tmp/src/<name>, then `gem build`. The gem carries a grep-able marker constant.
_gem_build() {
  local name="$1" ver="$2" dep="${3:-}" depver="${4:-}"
  local libname; libname="$(printf '%s' "$name" | tr '-' '_')"
  local depline=""
  [ -n "$dep" ] && depline="  s.add_runtime_dependency \"${dep}\", \"= ${depver}\""
  nc_exec "set -e
mkdir -p /tmp/src/${name}/lib
cat > /tmp/src/${name}/lib/${libname}.rb <<EOF
module $(printf '%s' "$libname" | sed -E 's/(^|_)([a-z])/\U\2/g')
  VERSION = \"${ver}\"
  MARKER  = \"DTF-RUBYGEMS-INSTALLED-${ver}\"
end
EOF
cat > /tmp/src/${name}/${name}.gemspec <<EOF
Gem::Specification.new do |s|
  s.name        = \"${name}\"
  s.version     = \"${ver}\"
  s.summary     = \"DTF format-conformance marker gem\"
  s.authors     = [\"dtf\"]
  s.files       = [\"lib/${libname}.rb\"]
  s.require_paths = [\"lib\"]
  s.license     = \"MIT\"
${depline}
end
EOF
cd /tmp/src/${name} && gem build ${name}.gemspec >/dev/null
test -f /tmp/src/${name}/${name}-${ver}.gem"
}

# Push a built gem (in-ctr path) with admin credentials; expects HTTP success.
_gem_push() {
  local gempath="$1"
  nc_exec "$(_gem_auth) set -e
mkdir -p /root/.gem && chmod 700 /root/.gem
cat > /root/.gem/credentials <<EOF
---
:rubygems_api_key: Basic \${AUTHB64}
${FC_INT_URL}: Basic \${AUTHB64}
EOF
chmod 600 /root/.gem/credentials
gem push --host '${FC_INT_URL}' '${gempath}'"
}

# ---------------------------------------------------------------------------
# fc_publish — build the marker gem in-ctr, copy it out for the byte-identity
# proof, and `gem push` it (the real native publish verb, ported from the
# orphaned script).
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v gem >/dev/null && gem --version' \
    || { echo "gem CLI missing inside the provisioned rubygems client"; return 1; }
  _gem_build "$GEM_NAME" "$GEM_VER" || { echo "gem build failed"; return 1; }
  nc_copy_from_ctr "/tmp/src/${GEM_NAME}/${GEM_FILE}" "${WORK_DIR}/${GEM_FILE}" || return 1
  GEM_PUB_SHA="$(nc_sha256 "${WORK_DIR}/${GEM_FILE}")"
  echo "  gem=${GEM_FILE} sha256=${GEM_PUB_SHA}"
  _gem_push "/tmp/src/${GEM_NAME}/${GEM_FILE}" || { echo "gem push failed"; return 1; }
  nc_expect_code 200 "${FC_URL}/specs.4.8.gz" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — isolate a fresh GEM_HOME and confirm the client is present.
# The consume forces `--clear-sources --source $FC_INT_URL`, so the ONLY source
# the resolver can use is the AK repo (no rubygems.org fallback).
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'rm -rf /tmp/gh /tmp/consume && mkdir -p /tmp/gh /tmp/consume && gem --version' \
    || { echo "could not prepare isolated GEM_HOME"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `gem fetch --clear-sources --source` resolves
# the gem via specs/dependency metadata and FOLLOWS `/gems/<file>` to download
# it; `gem install --local` then installs it into the isolated GEM_HOME.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 180 "export GEM_HOME=/tmp/gh GEM_PATH=/tmp/gh; set -e
cd /tmp/consume
gem fetch ${GEM_NAME} --version ${GEM_VER} --clear-sources --source '${FC_INT_URL}'
test -f /tmp/consume/${GEM_FILE}
gem install ./${GEM_FILE} --local --no-document" \
    || { echo "gem fetch/install (following advertised /gems/<file>) failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: fetched .gem is byte-identical to what we
# pushed AND the installed gem is requirable with its marker constant.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_copy_from_ctr "/tmp/consume/${GEM_FILE}" "${WORK_DIR}/fetched-${GEM_FILE}" || return 1
  nc_assert_sha_eq "$GEM_PUB_SHA" "$(nc_sha256 "${WORK_DIR}/fetched-${GEM_FILE}")" \
    "fetched .gem != pushed .gem" || return 1
  nc_exec "export GEM_HOME=/tmp/gh GEM_PATH=/tmp/gh
gem list -l | grep -E '^${GEM_NAME} ' && \
ruby -e 'require \"dtf_marker\"; exit(DtfMarker::MARKER.include?(\"DTF-RUBYGEMS-INSTALLED\") ? 0 : 1)'" \
    || { echo "installed gem not requirable / marker missing"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. specs.4.8.gz (Marshal+gzip)
# advertises the [name,version,platform] tuple; the advertised `/gems/<file>`
# 200s while the bare-basename shape at the repo root (no /gems/ prefix) 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local adv
  adv="$(nc_advertised "${FC_URL}/specs.4.8.gz" \
    "gunzip -c 2>/dev/null | grep -a -o '${GEM_NAME}' | head -1")" || return 1
  echo "  specs.4.8.gz advertises ${adv}"
  nc_expect_code 200 "${FC_URL}/gems/${GEM_FILE}" || return 1
  # bare-basename at the repo root must NOT resolve (real path is /gems/<file>)
  nc_expect_code 404 "${FC_URL}/${GEM_FILE}" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# dependency_resolution — gem B (dtf-app) depends on A (dtf-dep). A fresh
# `gem install dtf-app --clear-sources --source` must pull A THROUGH the
# /api/v1/dependencies API (:51). Bug class: broken dependency API (a client
# that cannot resolve transitive deps from the registry).
fc_case_dependency_resolution() {
  _gem_build "dtf-dep" "1.0.0" || { echo "build dtf-dep failed"; return 1; }
  _gem_build "dtf-app" "1.0.0" "dtf-dep" "1.0.0" || { echo "build dtf-app failed"; return 1; }
  _gem_push "/tmp/src/dtf-dep/dtf-dep-1.0.0.gem" || { echo "push dtf-dep failed"; return 1; }
  _gem_push "/tmp/src/dtf-app/dtf-app-1.0.0.gem" || { echo "push dtf-app failed"; return 1; }
  # fresh GEM_HOME so dtf-dep is provably NOT pre-present
  nc_exec -t 180 "export GEM_HOME=/tmp/gh-dep GEM_PATH=/tmp/gh-dep; set -e
rm -rf /tmp/gh-dep && mkdir -p /tmp/gh-dep
gem install dtf-app --clear-sources --source '${FC_INT_URL}' --no-document
gem list -l | grep -E '^dtf-app ' && gem list -l | grep -E '^dtf-dep '" \
    || { echo "transitive dep dtf-dep not resolved via /api/v1/dependencies"; return 1; }
  echo "  gem install dtf-app pulled dtf-dep transitively (dependency API works)"
}

# latest_specs — with 1.0.0 + 1.1.0 published, latest_specs.4.8.gz (:54) must
# list ONLY 1.1.0 for dtf-marker while the full specs.4.8.gz lists both. Bug
# class: latest-index staleness / divergence. Parsed with real Marshal (ruby)
# so we assert the exact per-gem version set, not a coarse byte grep.
fc_case_latest_specs() {
  _gem_build "$GEM_NAME" "1.1.0" || { echo "build ${GEM_NAME} 1.1.0 failed"; return 1; }
  _gem_push "/tmp/src/${GEM_NAME}/${GEM_NAME}-1.1.0.gem" || { echo "push 1.1.0 failed"; return 1; }
  nc_exec "set -e
cd /tmp
curl -fsS -o ls.gz  '${FC_INT_URL}/latest_specs.4.8.gz'
curl -fsS -o all.gz '${FC_INT_URL}/specs.4.8.gz'
ruby -rzlib -e '
  def load_specs(f); Marshal.load(Zlib::GzipReader.open(f).read); end
  latest = load_specs(\"ls.gz\").select{|n,v,p| n==\"${GEM_NAME}\"}.map{|n,v,p| v.to_s}.sort
  all    = load_specs(\"all.gz\").select{|n,v,p| n==\"${GEM_NAME}\"}.map{|n,v,p| v.to_s}.sort
  STDERR.puts \"latest=#{latest.inspect} all=#{all.inspect}\"
  abort(\"latest_specs must list only 1.1.0\") unless latest == [\"1.1.0\"]
  abort(\"specs must list both 1.0.0 and 1.1.0\") unless all.include?(\"1.0.0\") && all.include?(\"1.1.0\")
'" \
    || { echo "latest_specs did not reflect only the newest version"; return 1; }
  echo "  latest_specs.4.8.gz -> [1.1.0] only; specs.4.8.gz -> [1.0.0, 1.1.0]"
}

# auth_push — push WITHOUT credentials must be rejected (401/403), not silently
# accepted (no anonymous-write fall-open); an AUTHENTICATED push reaches the app
# (200/201/409-dup, proving auth passed). Bug class: anonymous-write fall-open.
fc_case_auth_push() {
  local anon
  anon="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -X POST --data-binary "@${WORK_DIR}/${GEM_FILE}" "${FC_URL}/api/v1/gems" 2>/dev/null)"
  case "$anon" in
    401|403) echo "  anonymous push rejected (HTTP ${anon})" ;;
    *) echo "  anonymous push returned HTTP ${anon} (expected 401/403; anything 2xx = fall-open)"; return 1 ;;
  esac
  local authd
  authd="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -X POST -H "$(format_auth_header)" --data-binary "@${WORK_DIR}/${GEM_FILE}" \
    "${FC_URL}/api/v1/gems" 2>/dev/null)"
  case "$authd" in
    200|201|409|422) echo "  authenticated push reached the app (HTTP ${authd})" ;;
    401|403) echo "  authenticated push was rejected (HTTP ${authd}) — auth path broken"; return 1 ;;
    *) echo "  authenticated push returned unexpected HTTP ${authd}"; return 1 ;;
  esac
}
