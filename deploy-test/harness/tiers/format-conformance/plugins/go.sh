# =============================================================================
# plugins/go.sh — format-conformance plugin (GOPROXY publish -> consume)
# FC_FORMAT: go
# FC_MOUNT: go
# FC_REPO_FORMAT: go
# FC_PROFILE: client.go
# FC_SERVICE: client-go
# FC_ENABLED: 1
# =============================================================================
# Closes the go consume half. The corpus test-go.sh uploads a module zip and
# then SKIPS the real `go mod download` ("may require exact zip layout") — an
# upload-only check that never proves a real client can resolve the module. This
# plugin makes the consume GATING: it publishes a module whose zip uses the
# strict `<module>@<version>/` internal prefix (fixtures/go/build.sh), then runs
# `GOPROXY=<AK> go mod download` + `go build` in a real golang:1.24 client. The
# go toolchain verifies the zip prefix / go.mod consistency itself, so a wrong
# advertised location or a malformed zip fails instead of being silently skipped.
#
# Go routes (backend handlers/goproxy.rs:37): nest /go; single wildcard
# `GET/PUT /:repo_key/*path`; protocol paths `<module>/@v/list|<ver>.info|
# <ver>.mod|<ver>.zip` and `<module>/@latest`; capital letters in the module
# path are `!`-encoded (goproxy.rs:47-75) — the GOPROXY URL is bang-encoded, but
# the zip's internal prefix uses the CANONICAL (decoded) module path.
#
# Consume via the advertised path: the client resolves `@v/<ver>.info` (time) ->
# `@v/<ver>.mod` (go.mod) -> `@v/<ver>.zip` (bytes), all discovered from the
# proxy. GOPROXY=<AK-only> + GOSUMDB=off disables every other source so the
# resolution can ONLY succeed via the AK proxy (the discriminator).
# =============================================================================
FC_CASES="at_latest case_encoding incompatible_version missing_mod_404"

GO_MODULE="example.com/dtf/marker"
GO_VERSION="v1.0.0"
GO_MARKER_TOKEN="DTF-GO-INSTALLED-${GO_VERSION}"
GO_BUILDSH="${DTF_DIR}/fixtures/go/build.sh"

# go_encode <module-path> -> GOPROXY !-encoding (capital X -> !x). The proxy URL
# uses this; the zip prefix and go.mod use the canonical path.
go_encode() {
  local s="$1" out="" i c
  for (( i=0; i<${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [A-Z]) out+="!$(printf '%s' "$c" | tr '[:upper:]' '[:lower:]')" ;;
      *)     out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

# The env every go invocation needs: the AK proxy ONLY (no ,direct fallback),
# checksum-db off, module mode, writable GOPATH/HOME. Sourced inline per exec.
# GOSUMDB=off disables checksum-db verification; GOPROXY is the AK proxy ONLY
# (no ,direct). We deliberately do NOT set GOPRIVATE (that would bypass the
# proxy and go direct — the opposite of what we want to prove).
_go_env() {
  echo "export GOPROXY='${1:-$FC_INT_URL}' GOSUMDB=off GOFLAGS=-mod=mod GOPATH=/root/go HOME=/root GOTOOLCHAIN=local;"
}

# go_publish_module <module> <version> [pkg] [token] — host-craft the zip+mod
# and PUT both on the native route (bang-encoded URL). Echoes the published zip
# path so callers can capture its sha.
go_publish_module() {
  local module="$1" version="$2" pkg="${3:-}" token="${4:-DTF-GO-INSTALLED-$2}"
  local zip mod enc
  zip="$(bash "$GO_BUILDSH" "$WORK_DIR" "$module" "$version" "$pkg" "$token")" || return 1
  mod="${zip%.zip}.mod"
  [ -s "$zip" ] && [ -s "$mod" ] || { echo "fixture build produced no zip/mod"; return 1; }
  enc="$(go_encode "$module")"
  # NB: redirect nc_put_file's informational stdout to stderr (still captured in
  # the step log) so command-substitution of this function captures ONLY the zip
  # path — not the "nc_put_file OK" chatter.
  nc_put_file "$mod" "${FC_URL}/${enc}/@v/${version}.mod" >&2 || return 1
  nc_put_file "$zip" "${FC_URL}/${enc}/@v/${version}.zip" 201 >&2 || return 1
  printf '%s' "$zip"
}

# ---------------------------------------------------------------------------
# fc_publish — publish the base module (host-craft + native-route PUT).
# ---------------------------------------------------------------------------
fc_publish() {
  GO_ZIP="$(go_publish_module "$GO_MODULE" "$GO_VERSION" marker "$GO_MARKER_TOKEN")" || return 1
  GO_PUB_ZIP_SHA="$(nc_sha256 "$GO_ZIP")"
  echo "  published ${GO_MODULE}@${GO_VERSION} zip=${GO_ZIP} sha256=${GO_PUB_ZIP_SHA}"
  # The advertised version list must now include it (served from the DB).
  local enc; enc="$(go_encode "$GO_MODULE")"
  nc_expect_code 200 "${FC_URL}/${enc}/@v/list" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real toolchain is present (no silent skip) and
# stage a consumer module that imports the published module ONLY via GOPROXY.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec 'command -v go >/dev/null 2>&1 && go version' \
    || { echo "go toolchain missing inside the provisioned go client"; return 1; }
  nc_exec "$(_go_env) rm -rf /work/consumer && mkdir -p /work/consumer && cat > /work/consumer/go.mod <<EOF
module dtfconsumer

go 1.21

require ${GO_MODULE} ${GO_VERSION}
EOF
cat > /work/consumer/main.go <<EOF
package main

import (
	\"fmt\"

	marker \"${GO_MODULE}\"
)

func main() { fmt.Println(marker.Marker()) }
EOF
cat /work/consumer/go.mod" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `go mod download` resolves .info -> .mod -> .zip
# from the AK proxy, verifies the `<module>@<version>/` zip layout, and `go
# build` compiles a consumer that imports the module. GOPROXY=<AK-only> +
# GOSUMDB=off => the AK proxy is the ONLY possible source (the discriminator).
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 240 "$(_go_env) cd /work/consumer && \
go clean -modcache 2>/dev/null; \
go mod download -x -json ${GO_MODULE}@${GO_VERSION} 2>&1" \
    || { echo "go mod download failed"; return 1; }
  nc_exec -t 240 "$(_go_env) cd /work/consumer && \
go build -o /work/consumer.bin . 2>&1" \
    || { echo "go build of the consumer failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the cached zip bytes match the published bytes
# (module cache uses the !-encoded path) AND the built binary prints the marker
# token (the module was actually compiled + linked, not merely downloaded).
# ---------------------------------------------------------------------------
fc_assert() {
  local enc; enc="$(go_encode "$GO_MODULE")"
  local cached="/root/go/pkg/mod/cache/download/${enc}/@v/${GO_VERSION}.zip"
  local got
  got="$(nc_sha256_in_ctr "$cached")"
  nc_assert_sha_eq "$GO_PUB_ZIP_SHA" "$got" "cached zip sha != published zip sha" || return 1
  nc_exec "/work/consumer.bin | grep -q '${GO_MARKER_TOKEN}'" \
    || { echo "built consumer did not print the marker token"; return 1; }
  echo "  consumer built + ran; cached zip byte-identical to published"
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. The proxy advertises the module
# via @v/list + <ver>.info; the advertised .zip resolves (200) while an
# unpublished version's .info returns a clean 404 (not 500 / empty-200 — the
# "advertised metadata that does not resolve" bug class).
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local enc; enc="$(go_encode "$GO_MODULE")"
  # advertised: @v/list must name the version
  local listed
  listed="$(nc_advertised "${FC_URL}/${enc}/@v/list" "grep -E '^v[0-9]' | head -1")" || return 1
  echo "  @v/list advertises ${listed}"
  [ "$listed" = "$GO_VERSION" ] || { echo "list head ${listed} != ${GO_VERSION}"; return 1; }
  # advertised: <ver>.info JSON Version matches
  local infover
  infover="$(nc_advertised "${FC_URL}/${enc}/@v/${GO_VERSION}.info" "jq -r '.Version'")" || return 1
  [ "$infover" = "$GO_VERSION" ] || { echo ".info Version ${infover} != ${GO_VERSION}"; return 1; }
  # positive: the advertised .zip resolves
  nc_expect_code 200 "${FC_URL}/${enc}/@v/${GO_VERSION}.zip" || return 1
  # negative: an unpublished version must 404 cleanly (not 500 / empty-200)
  nc_expect_code 404 "${FC_URL}/${enc}/@v/v9.9.9.info" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# at_latest — GET <module>/@latest (goproxy.rs:140) resolves to the newest
# published version, and a real `go mod download <module>@latest` returns it.
# Bug class: @latest resolving to nothing / the wrong version.
fc_case_at_latest() {
  local enc; enc="$(go_encode "$GO_MODULE")"
  # positive: @latest advertises v1.0.0
  local latest
  latest="$(nc_advertised "${FC_URL}/${enc}/@latest" "jq -r '.Version'")" || return 1
  echo "  @latest -> ${latest}"
  [ "$latest" = "$GO_VERSION" ] || { echo "@latest ${latest} != ${GO_VERSION}"; return 1; }
  # positive: the real client resolves the version-less form via @latest
  local out
  out="$(nc_exec "$(_go_env) cd /work/consumer && go mod download -json ${GO_MODULE}@latest 2>&1")" || {
    echo "  go mod download @latest failed: ${out}"; return 1; }
  echo "$out" | jq -e --arg v "$GO_VERSION" '.Version == $v' >/dev/null 2>&1 \
    || { echo "  @latest download did not resolve ${GO_VERSION}"; return 1; }
  # negative: @latest for a never-published module must 404
  nc_expect_code 404 "${FC_URL}/${enc}-nope/@latest" || return 1
}

# case_encoding — a module with capital letters (example.com/DTF/Upper) must be
# published + consumed through the GOPROXY !-encoding round-trip
# (example.com/!d!t!f/!upper). The zip prefix + go.mod carry the CANONICAL path.
# Bug class: !-encoding not round-tripping (uppercase module unreachable).
fc_case_case_encoding() {
  local module="example.com/DTF/Upper" version="v1.0.0" tok="DTF-GO-UPPER-1.0.0"
  local zip enc lower_enc
  zip="$(go_publish_module "$module" "$version" upper "$tok")" || return 1
  enc="$(go_encode "$module")"          # example.com/!d!t!f/!upper
  echo "  published ${module} at encoded path ${enc}"
  # positive: the !-encoded .info resolves and reports the canonical version
  local infover
  infover="$(nc_advertised "${FC_URL}/${enc}/@v/${version}.info" "jq -r '.Version'")" || return 1
  [ "$infover" = "$version" ] || { echo ".info ${infover} != ${version}"; return 1; }
  # positive: the REAL client (which !-encodes itself) downloads it
  local out
  out="$(nc_exec "$(_go_env) cd /work/consumer && go mod download -json ${module}@${version} 2>&1")" || {
    echo "  go mod download of uppercase module failed: ${out}"; return 1; }
  echo "$out" | jq -e --arg v "$version" '.Version == $v' >/dev/null 2>&1 \
    || { echo "  uppercase module did not resolve"; return 1; }
  # negative: the lowercased path is a DIFFERENT module and must NOT resolve
  nc_expect_code 404 "${FC_URL}/example.com/dtf/upper/@v/${version}.info" || return 1
}

# incompatible_version — a v2+ module WITHOUT a /v2 path suffix must be
# published + resolved as `v2.0.0+incompatible` (the go pre-modules bridge).
# Bug class: `+incompatible` metadata mangled / unresolvable.
fc_case_incompatible_version() {
  local version="v2.0.0+incompatible" tok="DTF-GO-INCOMPAT-2.0.0"
  local zip enc
  zip="$(go_publish_module "$GO_MODULE" "$version" marker "$tok")" || return 1
  enc="$(go_encode "$GO_MODULE")"
  # positive: .info echoes the exact +incompatible version string
  local infover
  infover="$(nc_advertised "${FC_URL}/${enc}/@v/${version}.info" "jq -r '.Version'")" || return 1
  [ "$infover" = "$version" ] || { echo ".info ${infover} != ${version}"; return 1; }
  # positive: the real client downloads the +incompatible version
  local out
  out="$(nc_exec "$(_go_env) cd /work/consumer && go mod download -json ${GO_MODULE}@${version} 2>&1")" || {
    echo "  go mod download of +incompatible failed: ${out}"; return 1; }
  echo "$out" | jq -e --arg v "$version" '.Version == $v' >/dev/null 2>&1 \
    || { echo "  +incompatible did not resolve"; return 1; }
  # negative: the base v2.0.0 (no +incompatible) was never published -> 404
  nc_expect_code 404 "${FC_URL}/${enc}/@v/v2.0.0.info" || return 1
}

# missing_mod_404 — metadata for a never-published version must 404, not 500 or
# an empty 200 (a real go client treats empty-200 as a corrupt module).
# Bug class: not-found masked as 200/500.
fc_case_missing_mod_404() {
  local enc; enc="$(go_encode "$GO_MODULE")"
  # negative: unpublished .info and .mod both 404
  nc_expect_code 404 "${FC_URL}/${enc}/@v/v7.7.7.info" || return 1
  nc_expect_code 404 "${FC_URL}/${enc}/@v/v7.7.7.mod" || return 1
  # positive: the published version's .mod resolves (proves 404 is specific)
  nc_expect_code 200 "${FC_URL}/${enc}/@v/${GO_VERSION}.mod" || return 1
}
