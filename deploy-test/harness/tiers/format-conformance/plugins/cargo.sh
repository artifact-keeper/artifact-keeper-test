# =============================================================================
# plugins/cargo.sh — format-conformance plugin (sparse registry publish->consume)
# FC_FORMAT: cargo
# FC_MOUNT: cargo
# FC_REPO_FORMAT: cargo
# FC_PROFILE: client.cargo
# FC_SERVICE: client-cargo
# FC_ENABLED: 1
# =============================================================================
# Closes the cargo consume half. The corpus test-cargo.sh curl-checks that
# `config.json` carries a `dl` field but never makes a real client FOLLOW it.
# This plugin runs a REAL `cargo publish` and then a REAL `cargo build` in a
# consumer crate: cargo reads the sparse `config.json`, resolves the index file
# (`dt/f-/dtf-marker`), FOLLOWS the `dl` template to download the `.crate`, and
# links it — the exact #2580 analogue (advertised `dl` location != servable
# download route) that upload-only curl tests structurally cannot catch.
#
# Cargo routes (backend handlers/cargo.rs): nest /cargo; `config.json` :189
# (advertises `dl` + `auth-required`); publish `PUT /api/v1/crates/new` :193;
# download `/api/v1/crates/:name/:version/download` :196; root-level sparse
# index `/:repo/{1,2,3/:p,:p1/:p2}/:name` :210-217. config.json `dl` =
# `{base}/cargo/{repo}/api/v1/crates`; cargo (no `{...}` markers) appends
# `/{crate}/{version}/download`.
#
# Consume via the advertised path: the consumer's config.toml points ONLY at the
# AK sparse index (`sparse+http://backend:8080/cargo/<repo>/`), a fresh
# CARGO_HOME with an empty registry cache => the `.crate` can ONLY come from AK
# following config.json -> index -> dl (the discriminator).
# =============================================================================
FC_CASES="short_name_index republish_conflict search_api auth_required_index"

CARGO_NAME="dtf-marker"
CARGO_VER="1.0.0"
CARGO_MARKER_TOKEN="DTF-CARGO-INSTALLED-${CARGO_VER}"
# rust:1.85-slim runs as root; CARGO_HOME + /work are writable as-is.

# The cargo registry token cargo sends verbatim as the Authorization header.
# `Basic <b64(user:pass)>` matches the backend's format-native Basic auth.
_cargo_token() {
  printf 'Basic %s' "$(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64 | tr -d '\n')"
}

# _cargo_reg_config <cargo-home> <index-url> — emit a script that writes a
# registry-only config.toml (no crates.io, no default registry leak).
_cargo_reg_config() {
  local home="$1" index="$2"
  echo "mkdir -p '${home}' && cat > '${home}/config.toml' <<EOF
[registries.dtf]
index = \"sparse+${index}/\"
EOF"
}

# cargo_put_payload <repo-api-base> <name> <version> [expect-codes] [--noauth]
#   Host-craft the cargo publish binary payload (LE u32 json len | json | LE u32
#   crate len | crate bytes) and PUT it to /api/v1/crates/new. Used by the
#   conflict + private-index cases where a real build is not needed — the
#   backend hashes+stores the crate bytes opaquely (parse_publish_payload).
#   Echoes the HTTP status code.
cargo_put_payload() {
  local api="$1" name="$2" version="$3"
  local payload="${WORK_DIR}/cargo-payload-${name}-${version}.bin"
  name="$name" version="$version" PAYLOAD="$payload" python3 - <<'PY'
import os, struct, io, tarfile, gzip
name = os.environ["name"]; version = os.environ["version"]
# A minimal but real gzip-tar .crate (Cargo.toml only) so stored bytes are a
# plausible crate; the backend stores them opaquely and records their sha256.
inner = io.BytesIO()
with tarfile.open(fileobj=inner, mode="w") as tf:
    data = f'[package]\nname = "{name}"\nversion = "{version}"\n'.encode()
    ti = tarfile.TarInfo(f"{name}-{version}/Cargo.toml"); ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data))
crate = gzip.compress(inner.getvalue())
meta = ('{"name":"%s","vers":"%s","deps":[],"features":{},"authors":["dtf"],'
        '"description":"dtf conformance","license":"MIT","readme":null,'
        '"repository":null,"links":null}' % (name, version)).encode()
with open(os.environ["PAYLOAD"], "wb") as f:
    f.write(struct.pack("<I", len(meta))); f.write(meta)
    f.write(struct.pack("<I", len(crate))); f.write(crate)
PY
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -X PUT -H "$(format_auth_header)" -H "Content-Type: application/octet-stream" \
    --data-binary "@${payload}" "${api}/api/v1/crates/new" 2>/dev/null
}

# ---------------------------------------------------------------------------
# fc_publish — REAL `cargo publish` of the marker crate (needs a valid .crate
# with a correct index cksum so the consumer can fetch + BUILD it). Host curl
# PUT would not produce a buildable crate, so publish is done by the client —
# still the accepted brick-3 deviation (the discriminating value is consume).
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec 'command -v cargo >/dev/null 2>&1 && cargo --version' \
    || { echo "cargo missing inside the provisioned cargo client"; return 1; }
  # NB: the rust image bakes CARGO_HOME=/usr/local/cargo; pin it to /root/.cargo
  # so the registry-only config.toml we write is the one cargo reads.
  nc_exec "export CARGO_HOME=/root/.cargo
$(_cargo_reg_config /root/.cargo "$FC_INT_URL")
mkdir -p /work/${CARGO_NAME}/src
cat > /work/${CARGO_NAME}/Cargo.toml <<EOF
[package]
name = \"${CARGO_NAME}\"
version = \"${CARGO_VER}\"
edition = \"2021\"
description = \"DTF cargo conformance marker crate\"
license = \"MIT\"

[lib]
name = \"dtf_marker\"
path = \"src/lib.rs\"
EOF
cat > /work/${CARGO_NAME}/src/lib.rs <<EOF
/// Grep-able marker proving the REAL cargo client followed config.json -> index
/// -> dl, downloaded the .crate, and LINKED it (not merely that the index
/// listed the crate).
pub fn marker() -> &'static str { \"${CARGO_MARKER_TOKEN}\" }
EOF
export CARGO_REGISTRIES_DTF_TOKEN='$(_cargo_token)'
cd /work/${CARGO_NAME} && cargo publish --registry dtf --no-verify --allow-dirty 2>&1" \
    || { echo "cargo publish failed"; return 1; }
  # Record the published .crate bytes so fc_assert can prove byte-identity.
  CARGO_PUB_SHA="$(nc_sha256_in_ctr "/work/${CARGO_NAME}/target/package/${CARGO_NAME}-${CARGO_VER}.crate")"
  echo "  published ${CARGO_NAME}-${CARGO_VER}.crate sha256=${CARGO_PUB_SHA}"
  # The advertised config.json + index must now resolve (index served from DB).
  nc_expect_code 200 "${FC_URL}/config.json" || return 1
  nc_expect_code 200 "${FC_URL}/dt/f-/${CARGO_NAME}" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — stage a fresh consumer crate whose CARGO_HOME points ONLY
# at the AK sparse index (no crates.io), with an empty registry cache so the
# .crate can only be obtained by FOLLOWING the advertised dl location.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec "$(_cargo_reg_config /work/cargo-consumer "$FC_INT_URL")
rm -rf /work/cargo-consumer/registry /work/consumer
mkdir -p /work/consumer/src
cat > /work/consumer/Cargo.toml <<EOF
[package]
name = \"dtfconsumer\"
version = \"0.1.0\"
edition = \"2021\"

[dependencies]
${CARGO_NAME} = { version = \"${CARGO_VER}\", registry = \"dtf\" }
EOF
cat > /work/consumer/src/main.rs <<EOF
fn main() { println!(\"{}\", dtf_marker::marker()); }
EOF
cat /work/consumer/Cargo.toml" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. `cargo build` reads config.json, resolves the
# sparse index entry, FOLLOWS `dl` to download dtf-marker-1.0.0.crate into the
# fresh CARGO_HOME, and compiles the consumer against it. AK is the ONLY
# configured source (the discriminator).
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 300 "export CARGO_HOME=/work/cargo-consumer
cd /work/consumer && rm -rf target && cargo build 2>&1" \
    || { echo "cargo build (fetch+link) failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — client-side proof: the fetched .crate bytes match the published
# bytes AND the consumer binary prints the marker token (compiled + linked).
# ---------------------------------------------------------------------------
fc_assert() {
  local cached
  cached="$(nc_exec "ls /work/cargo-consumer/registry/cache/*/${CARGO_NAME}-${CARGO_VER}.crate 2>/dev/null | head -1" | tail -1 | tr -d '\r')"
  [ -n "$cached" ] || { echo "no cached .crate under consumer CARGO_HOME"; return 1; }
  local got
  got="$(nc_sha256_in_ctr "$cached")"
  nc_assert_sha_eq "$CARGO_PUB_SHA" "$got" "fetched .crate sha != published .crate sha" || return 1
  nc_exec "/work/consumer/target/debug/dtfconsumer | grep -q '${CARGO_MARKER_TOKEN}'" \
    || { echo "built consumer did not print the marker token"; return 1; }
  echo "  consumer built + ran; fetched .crate byte-identical to published"
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the #2580 discriminator. Parse config.json.`dl`; the
# substituted download URL resolves (200), while a `dl`-shape missing the
# `api/v1/crates` prefix 404s (the pre-fix generic shape a naive client would
# emit). This is the exact path test-cargo.sh only curl-checks.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local dl
  dl="$(nc_advertised "${FC_URL}/config.json" "jq -r '.dl'")" || return 1
  echo "  advertised dl=${dl}"
  # positive: the advertised dl template resolves to servable bytes
  nc_expect_code 200 "${dl}/${CARGO_NAME}/${CARGO_VER}/download" || return 1
  # negative: the api/v1/crates-less shape must NOT resolve (no such route)
  nc_expect_code 404 "${FC_URL}/${CARGO_NAME}/${CARGO_VER}/download" || return 1
}

# ===========================================================================
# Edge cases (each a positive + negative discriminator tied to a bug class)
# ===========================================================================

# short_name_index — a 3-char crate (`dtm`) must land at the sparse `3/d/dtm`
# path (cargo.rs:212) and be fetchable via dl. Bug class: name-length bucketing
# wrong (short crates unreachable by a real client).
fc_case_short_name_index() {
  local status
  status="$(cargo_put_payload "$FC_URL" dtm "$CARGO_VER")"
  case "$status" in 200|201) : ;; *) echo "publish dtm -> HTTP ${status}"; return 1 ;; esac
  # positive: the 3-char bucket path resolves and names the crate
  local body
  body="$(nc_advertised "${FC_URL}/3/d/dtm" "grep -o '\"name\":\"dtm\"' | head -1")" || return 1
  echo "  3/d/dtm advertises ${body}"
  # positive: the advertised dl download resolves
  local dl; dl="$(curl -s --max-time 60 -H "$(format_auth_header)" "${FC_URL}/config.json" | jq -r '.dl')"
  nc_expect_code 200 "${dl}/dtm/${CARGO_VER}/download" || return 1
  # negative: a genuinely-unpublished 3-char crate at its bucket must 404 (the
  # index is not a blanket-200 — it resolves by real crate existence). NB the
  # backend serves by crate name irrespective of the numeric length bucket, so
  # a wrong-bucket path for an EXISTING crate still resolves; the discriminator
  # is crate existence, not bucket arithmetic.
  nc_expect_code 404 "${FC_URL}/3/z/zzz" || return 1
}

# republish_conflict — publishing the SAME name+version twice must be rejected
# (4xx), never silently overwritten. Bug class: republish fall-open (mutable
# releases). check_duplicate_crate enforces this.
fc_case_republish_conflict() {
  # positive (rejection): a second publish of dtf-marker 1.0.0 must 4xx
  local status
  status="$(cargo_put_payload "$FC_URL" "$CARGO_NAME" "$CARGO_VER")"
  echo "  republish ${CARGO_NAME}@${CARGO_VER} -> HTTP ${status}"
  case "$status" in
    409|400|403|422) : ;;
    200|201) echo "  FALL-OPEN: republish accepted (HTTP ${status}) — mutable release"; return 1 ;;
    *) echo "  unexpected republish status ${status}"; return 1 ;;
  esac
  # negative check: the index still lists exactly ONE 1.0.0 line (not duplicated)
  local n
  n="$(curl -s --max-time 60 -H "$(format_auth_header)" "${FC_URL}/dt/f-/${CARGO_NAME}" \
       | grep -c "\"vers\":\"${CARGO_VER}\"")"
  [ "$n" = "1" ] || { echo "  index has ${n} entries for ${CARGO_VER} (expected 1)"; return 1; }
  echo "  index still lists exactly one ${CARGO_VER} entry"
}

# search_api — `cargo search` hits /api/v1/crates :191 and finds the crate.
# Bug class: search endpoint not wired to the registry contents.
fc_case_search_api() {
  local out
  out="$(nc_exec "export CARGO_HOME=/root/.cargo
cargo search ${CARGO_NAME} --registry dtf 2>&1")" || { echo "  cargo search errored: ${out}"; return 1; }
  echo "$out" | grep -q "${CARGO_NAME}" || { echo "  cargo search did not find ${CARGO_NAME}: ${out}"; return 1; }
  echo "  cargo search found ${CARGO_NAME}"
  # negative: a bogus query returns no false positive for our crate
  local out2
  out2="$(nc_exec "export CARGO_HOME=/root/.cargo
cargo search zzz-nonexistent-${RUN_ID} --registry dtf 2>&1")" || true
  echo "$out2" | grep -q "${CARGO_NAME}" && { echo "  search for a bogus term leaked ${CARGO_NAME}"; return 1; }
  echo "  bogus-term search does not list ${CARGO_NAME}"
}

# auth_required_index — a PRIVATE repo must advertise `auth-required:true`
# (cargo.rs:374) and its index must reject anonymous reads (401), while
# authenticated reads succeed. Bug class: private-registry index fall-open.
fc_case_auth_required_index() {
  local prepo="dtf-cargo-priv-${RUN_ID}"
  local purl="${BASE_URL}/cargo/${prepo}"
  # create a PRIVATE cargo repo (create_repo forces public; POST directly)
  api_post "/api/v1/repositories" \
    "{\"key\":\"${prepo}\",\"name\":\"${prepo}\",\"format\":\"cargo\",\"repo_type\":\"local\",\"is_public\":false}" \
    >/dev/null 2>&1 || { echo "could not create private cargo repo"; return 1; }
  add_exit_handler "api_delete '/api/v1/repositories/${prepo}' >/dev/null 2>&1 || true"
  local status
  status="$(cargo_put_payload "$purl" priv-crate "$CARGO_VER")"
  case "$status" in 200|201) : ;; *) echo "publish to private repo -> HTTP ${status}"; return 1 ;; esac
  # positive: config.json advertises auth-required:true
  local ar
  ar="$(curl -s --max-time 60 -H "$(format_auth_header)" "${purl}/config.json" | jq -r '.["auth-required"]')"
  [ "$ar" = "true" ] || { echo "  private config.json auth-required=${ar} (expected true)"; return 1; }
  echo "  private config.json advertises auth-required:true"
  # negative: an UNAUTHENTICATED index read must be rejected (not served)
  local anon
  anon="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 "${purl}/pr/iv/priv-crate" 2>/dev/null)"
  case "$anon" in
    401|403) echo "  anon index read rejected (HTTP ${anon})" ;;
    *) echo "  FALL-OPEN: anon index read -> HTTP ${anon} (expected 401/403)"; return 1 ;;
  esac
  # positive: an AUTHENTICATED index read succeeds
  nc_expect_code 200 "${purl}/pr/iv/priv-crate" || return 1
}
