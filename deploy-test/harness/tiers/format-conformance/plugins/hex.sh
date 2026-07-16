# =============================================================================
# plugins/hex.sh — format-conformance plugin (EXPECTED-RED candidate, §4.11/§6)
# FC_FORMAT: hex
# FC_MOUNT: hex
# FC_REPO_FORMAT: hex
# FC_PROFILE: client.hex
# FC_SERVICE: client-hex
# FC_ENABLED: 0
# =============================================================================
# Elixir/Hex hosted publish->consume conformance. Routes (handlers/hex.rs): nest
# /hex; publish POST /:repo/publish; package info GET /:repo/packages/:name;
# list GET /:repo/names + /:repo/versions; tarballs GET /:repo/tarballs/*.
#
# The REAL client is `mix` (elixir:1.17, arm64). fc_publish builds a valid hex
# tarball with the real tool (`mix hex.build`) and publishes it via the native
# POST /publish route (the brick-3 publish deviation). fc_consume runs the REAL
# `mix hex.repo add` + `mix deps.get`, which resolve the dep by reading the hex
# REGISTRY resources (`/versions`, `/packages/<name>`).
#
# ============================ KNOWN-RED (protocol) ===========================
# The hex protocol requires the registry resources to be a GZIPPED, ECC-SIGNED
# PROTOBUF payload (hex_core Registry) verified against the repo's public key;
# `mix` HARD-VERIFIES them and refuses a repo whose signature/public-key cannot
# be validated. The backend source (handlers/hex.rs) only emits protocol-shaped
# bytes on the REMOTE proxy path (pass-through of upstream hex.pm bytes,
# hex.rs:508/599); a HOSTED repo returns PLAIN JSON from `/versions` and
# `/packages/:name`, and serves NO repo public key. A real `mix deps.get`
# therefore cannot consume a hosted AK hex repo.
#
# Per game-plan §6 this is a BACKEND FINDING, not a plugin bug: fc_consume runs
# the real client, captures the protocol evidence (the plain-JSON registry
# bytes + the mix verification error), and returns non-zero. The suite is RED
# BY DESIGN. Do NOT soften it into passing. Triage record + reproduction:
#   rig/results/format-conformance/hex-finding.md
#
# FC_CASES is intentionally EMPTY: the edge cases (checksum_verify /
# versions_listing / republish) all sit BEHIND a working `mix deps.get`, which
# is blocked at the registry-protocol layer. Re-add them once the hosted hex
# registry emits signed-protobuf resources + a repo public key.
# =============================================================================
FC_CASES=""

HEX_NAME="dtf_marker"
HEX_VER="1.0.0"
HEX_MARKER="DTF-HEX-INSTALLED-1.0.0"
HEX_MARKER_SRC="${DTF_DIR}/fixtures/hex/marker.ex"

# pipefail so a failed `mix ...` piped to `tail` is not masked by tail's exit 0
# (critical: the KNOWN-RED depends on fc_consume seeing mix's real non-zero exit
# when `:zlib.gunzip/1` chokes on the plain-JSON registry resource).
_hex_env() { echo 'set -o pipefail; export HOME=/root MIX_HOME=/root/.mix HEX_HOME=/root/.hex;'; }

# ---------------------------------------------------------------------------
# fc_publish — build a real hex tarball with `mix hex.build` and publish it via
# the native POST /publish route (Basic admin). This exercises the hosted store
# and should PASS: it isolates the KNOWN-RED to the registry-protocol layer.
# ---------------------------------------------------------------------------
fc_publish() {
  nc_exec -t 300 "$(_hex_env)
mix local.hex --force >/dev/null 2>&1
mix local.rebar --force >/dev/null 2>&1
rm -rf /work/pkg && mkdir -p /work/pkg/lib && cd /work/pkg
cat > mix.exs <<'EOF'
defmodule DtfMarker.MixProject do
  use Mix.Project
  def project do
    [
      app: :dtf_marker,
      version: \"${HEX_VER}\",
      elixir: \"~> 1.14\",
      description: \"DTF marker package for Artifact Keeper format-conformance testing.\",
      package: package(),
      deps: []
    ]
  end
  def application, do: []
  defp package do
    [licenses: [\"MIT\"], links: %{\"AK\" => \"http://backend:8080\"}, files: [\"lib\", \"mix.exs\"]]
  end
end
EOF
echo mixexs-written" || { echo "mix/hex setup failed"; return 1; }

  nc_copy_to_ctr "$HEX_MARKER_SRC" /work/pkg/lib/dtf_marker.ex \
    || { echo "copy marker lib failed"; return 1; }

  # Build the tarball with the real tool, then publish via the native route.
  nc_exec -t 240 "$(_hex_env) cd /work/pkg
mix hex.build 2>&1 | tail -10
ls -1 ${HEX_NAME}-${HEX_VER}.tar" || { echo "mix hex.build failed"; return 1; }

  nc_exec -t 120 "cd /work/pkg
code=\$(curl -s -o /tmp/pub.out -w '%{http_code}' -u '${ADMIN_USER}:${ADMIN_PASS}' \
  -X POST --data-binary @${HEX_NAME}-${HEX_VER}.tar '${FC_INT_URL}/publish')
echo \"publish HTTP \$code\"; head -c 300 /tmp/pub.out; echo
case \"\$code\" in 200|201) exit 0 ;; *) exit 1 ;; esac" \
    || { echo "native hex publish (POST /publish) failed"; return 1; }

  # Sanity: the artifact is registered (plain-JSON /versions lists it).
  nc_expect_code 200 "${FC_URL}/versions" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — verify the real client is present and scaffold a consumer
# whose ONLY dep source is the AK hex repo (repo: "dtf").
# ---------------------------------------------------------------------------
fc_client_setup() {
  # Verify the real client is present WITHOUT a `| head` (which would SIGPIPE
  # under pipefail and false-fail). The KNOWN-RED belongs at fc_consume, so this
  # gate must pass cleanly when mix is installed.
  nc_exec "$(_hex_env) mix --version >/dev/null 2>&1 && command -v mix >/dev/null && echo mix-present" \
    || { echo "mix missing inside the provisioned hex client"; return 1; }
  nc_exec "rm -rf /work/consumer && mkdir -p /work/consumer/lib && cd /work/consumer
cat > mix.exs <<'EOF'
defmodule Consumer.MixProject do
  use Mix.Project
  def project do
    [app: :consumer, version: \"0.0.1\", elixir: \"~> 1.14\", deps: deps()]
  end
  def application, do: []
  defp deps do
    [{:${HEX_NAME}, \"~> 1.0\", repo: \"dtf\"}]
  end
end
EOF
cat mix.exs" || return 1
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. KNOWN-RED: `mix hex.repo add` + `mix deps.get`
# hard-verify the hex registry (gzipped signed protobuf + repo public key); the
# hosted backend serves plain JSON and no public key, so this fails on a
# protocol-true basis. We capture the registry-byte evidence + the mix error,
# then return non-zero (a BACKEND FINDING, not a plugin bug — §6).
# ---------------------------------------------------------------------------
fc_consume() {
  echo "== protocol evidence: hosted hex registry resources are plain JSON, not signed protobuf =="
  echo "-- GET /versions --"
  curl -s -D - -H "$(format_auth_header)" "${FC_URL}/versions" -o /tmp/hexv.bin 2>/dev/null | grep -i '^content-type' || true
  echo "   first bytes: $(head -c 120 /tmp/hexv.bin | tr -d '\0')"
  file /tmp/hexv.bin 2>/dev/null || true
  echo "-- GET /packages/${HEX_NAME} --"
  curl -s -D - -H "$(format_auth_header)" "${FC_URL}/packages/${HEX_NAME}" -o /tmp/hexp.bin 2>/dev/null | grep -i '^content-type' || true
  echo "   first bytes: $(head -c 120 /tmp/hexp.bin | tr -d '\0')"
  echo "-- GET /public_key (mix needs one to trust the repo) --"
  echo "   $(curl -s -o /dev/null -w 'HTTP %{http_code}' -H "$(format_auth_header)" "${FC_URL}/public_key")"

  echo "== real client attempt: mix hex.repo add + mix deps.get =="
  local out rc
  out="$(nc_exec -t 180 "$(_hex_env)
mix hex.repo add dtf '${FC_INT_URL}' 2>&1 | tail -8
cd /work/consumer
mix deps.get 2>&1 | tail -30")"
  rc=$?
  echo "$out"
  if [ "$rc" -eq 0 ]; then
    # If a future backend serves conformant signed-protobuf resources this will
    # start passing — at which point flip FC_CASES back on and delete the
    # KNOWN-RED banner. Until then, a green here is a surprise worth inspecting.
    echo "UNEXPECTED-GREEN: mix deps.get succeeded against a hosted hex repo — re-audit the registry format"
    return 0
  fi
  echo "KNOWN-RED: mix could not verify/consume the hosted hex registry (see hex-finding.md)"
  return 1
}

# fc_assert / fc_advertised_check are unreachable once fc_consume returns the
# KNOWN-RED (the driver short-circuits later core steps). They are defined so a
# post-fix flip only needs FC_CASES + the deps.get gate, and to document the
# advertised-path the client WOULD follow once the protocol is conformant.
fc_assert() {
  nc_exec "$(_hex_env) test -f /work/consumer/deps/${HEX_NAME}/lib/dtf_marker.ex && \
grep -q '${HEX_MARKER}' /work/consumer/deps/${HEX_NAME}/lib/dtf_marker.ex" \
    || { echo "dep not fetched / marker missing (blocked upstream by the registry-protocol KNOWN-RED)"; return 1; }
}

fc_advertised_check() {
  # Once the registry is conformant, /packages/<name> parses as a hex payload
  # and the advertised tarball URL 200s.
  nc_expect_code 200 "${FC_URL}/tarballs/${HEX_NAME}-${HEX_VER}.tar" || return 1
}
