#!/usr/bin/env bash
# test-wasm-plugin-roundtrip.sh -- WASM plugin loads and handles a
# format request after the wasmtime 24 -> 36 jump (issue #101,
# backend PRs #861 / #971).
#
# Why this test exists
# --------------------
# wasmtime 36.0.7 closes RUSTSEC-2026-0096 (aarch64 Cranelift sandbox
# escape, CVSS 9.0). Host-side unit tests in
# backend/src/services/wasm_runtime.rs cover the API port (WasiCtxView
# changes, usize table_growing, p2 linker). What is NOT covered is a
# real plugin roundtrip: load a built *.wasm and exercise a request
# through the FormatHandler WIT contract.
#
# The WIT contract is unchanged across the bump, so a standard
# wasi-p2 guest "should" keep working. "Should" is exactly the kind
# of claim that needs a test in the gate before tagging stable.
#
# What this script tests
# ----------------------
# 1. /api/v1/plugins lists at least one loaded plugin (positive
#    control that the plugin runtime is up). If no plugins are
#    loaded, the suite skips gracefully -- the test deploy may not
#    have a plugin overlay enabled.
#
# 2. Pick a loaded plugin from the list, look up the format it
#    claims to handle, and exercise that format's resolution path
#    end to end:
#       a. Create a local repo of the plugin's format.
#       b. Upload a small artifact.
#       c. Fetch it back through the format-native endpoint.
#       d. Assert bytes round-trip.
#    If the WIT bindings regressed across the wasmtime bump, the
#    upload OR fetch step would crash the plugin sandbox and we'd
#    see a 5xx instead of bytes.
#
# 3. Negative: POST a clearly-malformed plugin manifest to the
#    plugin-load endpoint and assert the backend rejects it with 4xx
#    without crashing the existing plugins. The "without crashing"
#    half is checked by re-doing the positive control (step 1) after
#    the negative attempt -- if the rejection panicked the runtime,
#    the plugin list goes empty / 5xx.
#
# Out of scope
# ------------
# Building a fresh plugin from source. That requires the
# wasm32-wasip1 toolchain + wit-bindgen + cargo, which the runner
# pod does not have. The plugin under test must already be loaded
# by the test deploy (helm/values-test.yaml's plugin overlay).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "wasm-plugin-roundtrip"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Step 1: positive control -- /api/v1/plugins lists at least one
# loaded plugin.
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/plugins returns a non-empty plugin list"
plugin_resp=""
list_paths=(
  "/api/v1/plugins"
  "/api/v1/admin/plugins"
  "/api/v1/format-plugins"
)
for path in "${list_paths[@]}"; do
  if plugin_resp=$(api_get "$path" 2>/dev/null) && [ -n "$plugin_resp" ]; then
    break
  fi
done

if [ -z "$plugin_resp" ]; then
  skip_suite "no plugin list endpoint responded; backend deploy may not include the plugin overlay (helm/values-test.yaml plugins.enabled?)"
fi

plugin_count=0
if echo "$plugin_resp" | jq -e '.items' >/dev/null 2>&1; then
  plugin_count=$(echo "$plugin_resp" | jq '.items | length // 0' 2>/dev/null || echo 0)
elif echo "$plugin_resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
  plugin_count=$(echo "$plugin_resp" | jq 'length // 0' 2>/dev/null || echo 0)
fi

if ! [[ "$plugin_count" =~ ^[0-9]+$ ]]; then plugin_count=0; fi
if [ "$plugin_count" -ge 1 ]; then
  pass
else
  skip_suite "plugin list is empty; no plugin loaded against this backend deploy"
fi

# Pick the first plugin and read its claimed format. The shape
# varies across versions: {items: [{name, format, ...}]} or just an
# array of objects. Try both.
plugin_name=""
plugin_format=""
plugin_obj=$(echo "$plugin_resp" | jq -c '.items[0] // .[0] // empty' 2>/dev/null || echo "")
if [ -n "$plugin_obj" ]; then
  plugin_name=$(echo "$plugin_obj" | jq -r '.name // .id // .key // empty' 2>/dev/null || echo "")
  plugin_format=$(echo "$plugin_obj" | jq -r '.format // .format_name // .handler_format // empty' 2>/dev/null || echo "")
fi

# ---------------------------------------------------------------------------
# Step 2: roundtrip an artifact through the plugin's format.
#
# If the plugin doesn't expose a format name in the list response,
# fall back to "generic" -- the example plugin (unity_format_plugin)
# wraps a generic format and most custom plugins do the same. A
# format that's truly mis-named here means the plugin is wired in a
# non-standard way and we skip the roundtrip half.
# ---------------------------------------------------------------------------

format="${plugin_format:-generic}"
repo_key="wpr-${RUN_ID}"
artifact_path="probe/1.0.0/probe.bin"
payload="${WORK_DIR}/probe.bin"
echo "wasm-plugin-roundtrip ${RUN_ID}" > "$payload"

begin_test "Create local repo of plugin-claimed format '${format}'"
if create_local_repo "$repo_key" "$format" 2>/dev/null; then
  pass
else
  skip "could not create '${format}' repo; plugin's format may not be CRUD-creatable from the API"
  end_suite
  exit 0
fi

begin_test "Upload through plugin-handled format"
if api_upload "/api/v1/repositories/${repo_key}/artifacts/${artifact_path}" \
    "$payload" "application/octet-stream" >/dev/null 2>&1; then
  pass
else
  fail "upload failed for plugin format '${format}'; likely the plugin's FormatHandler regressed under wasmtime 36"
fi

begin_test "Fetch through plugin-handled format roundtrips bytes"
fetched="${WORK_DIR}/probe-back.bin"
http_status=$(curl -s -o "$fetched" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${repo_key}/artifacts/${artifact_path}" \
    2>/dev/null) || http_status="000"
case "$http_status" in
  200)
    if cmp -s "$payload" "$fetched"; then
      pass
    else
      fail "fetched bytes do not match uploaded bytes for plugin format '${format}'; plugin FormatHandler corruption under wasmtime 36"
    fi
    ;;
  5*|000)
    fail "fetch returned HTTP ${http_status}; plugin sandbox may have crashed under wasmtime 36"
    ;;
  *)
    fail "fetch returned HTTP ${http_status}; unexpected"
    ;;
esac

# ---------------------------------------------------------------------------
# Step 3: negative control -- malformed plugin manifest must be
# rejected cleanly. Then re-check the plugin list to confirm the
# rejection didn't crash the runtime.
#
# The plugin-load endpoint shape varies; many backends do NOT expose
# runtime plugin loading via the API (plugins ship via config + pod
# restart). If we can't find a load endpoint, we skip the negative
# control rather than fabricate a positive result.
# ---------------------------------------------------------------------------

begin_test "Negative: malformed plugin manifest is rejected (or endpoint absent)"
malformed_payload='{"name":"","wasm_blob":"not-base64","manifest_version":"???"}'
load_status=""
for path in \
    "/api/v1/admin/plugins" \
    "/api/v1/plugins" \
    "/api/v1/admin/format-plugins"; do
  load_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$malformed_payload" "${BASE_URL}${path}" 2>/dev/null) || load_status="000"
  if [ "$load_status" != "404" ] && [ "$load_status" != "405" ]; then
    break
  fi
done

case "$load_status" in
  404|405)
    # No runtime plugin-load endpoint on this backend; cannot run
    # the negative control. Skip rather than fabricate a positive
    # result. Must come BEFORE the broader 4* arm (which would
    # otherwise swallow these statuses).
    skip "no runtime plugin-load endpoint exposed; negative-control deferred"
    ;;
  4*)
    # Any other 4xx is the expected outcome: backend recognized the
    # manifest as invalid and rejected without loading.
    pass
    ;;
  5*|000)
    fail "malformed plugin payload returned HTTP ${load_status}; sandbox isolation regressed under wasmtime 36 (this is the RUSTSEC-2026-0096 risk class)"
    ;;
  *)
    fail "unexpected status ${load_status} from plugin-load with malformed payload"
    ;;
esac

# Re-list plugins; the negative control must not have nuked them.
begin_test "Plugin list still non-empty after malformed-manifest rejection"
plugin_resp_after=""
for path in "${list_paths[@]}"; do
  if plugin_resp_after=$(api_get "$path" 2>/dev/null) && [ -n "$plugin_resp_after" ]; then
    break
  fi
done

plugin_count_after=0
if echo "$plugin_resp_after" | jq -e '.items' >/dev/null 2>&1; then
  plugin_count_after=$(echo "$plugin_resp_after" | jq '.items | length // 0' 2>/dev/null || echo 0)
elif echo "$plugin_resp_after" | jq -e 'type == "array"' >/dev/null 2>&1; then
  plugin_count_after=$(echo "$plugin_resp_after" | jq 'length // 0' 2>/dev/null || echo 0)
fi
if [ "$plugin_count_after" -ge 1 ]; then
  pass
else
  fail "plugin list went empty after malformed-manifest rejection; the negative control corrupted the runtime"
fi

api_delete "/api/v1/repositories/${repo_key}" >/dev/null 2>&1 || true

end_suite
