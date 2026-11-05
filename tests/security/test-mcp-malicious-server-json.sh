#!/usr/bin/env bash
# test-mcp-malicious-server-json.sh - hostile publish bodies against
# POST /mcp/<repo>/v0.1/publish (artifact-keeper#5253; docs/mcp-registry.md
# "Routes" choices, "Security notes").
#
# Contract under test:
#   - bodies are capped at 256 KiB: exactly 262144 bytes is not 413 (it may
#     still be refused for its content), 262145 is 413 mcp_too_large, answered
#     (not a connection reset).
#   - documents nest at most 32 levels (400); a pathological 2000-deep body is
#     refused without hurting the backend (/health still 200).
#   - every vector in tests/fixtures/mcp/server-json/invalid/cases.tsv answers
#     its status and error code.
#   - stored text is data: a <script> description is stored and served
#     byte-exact as application/json with X-Content-Type-Options: nosniff.
#   - the publisher cannot write registry state: a submitted
#     io.modelcontextprotocol.registry/official block is ignored (status comes
#     back active) and unknown _meta keys are dropped; only publisher-provided
#     survives (inside server._meta).
#   - a version is write-once under a race: 10 concurrent publishes of the
#     same name@version give exactly one 200 and nine 409 mcp_version_exists,
#     and the served document is the winner's.
#
# Pinned from the backend (not documented):
#   - duplicate JSON keys are refused: 400 mcp_invalid_server_json
#     ("duplicate field"), for a plain field and for `name`.
#   - invalid UTF-8, a non-JSON body and an empty body are 400
#     mcp_invalid_server_json.
#   - the publish route ignores Content-Type: text/plain,
#     application/x-www-form-urlencoded and no Content-Type all publish (200).
#
# The big-body tests run last so a backend that falls over on them cannot
# mask the earlier verdicts.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-malicious-server-json"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry

KEY="sec-mcpmal-${RUN_ID}"
NS="com.mal-${RUN_ID}"
REMOTE='[{"type":"streamable-http","url":"https://mcp.example.invalid/mcp"}]'
INVALID_DIR="${MCP_FIXTURES_DIR}/server-json/invalid"

expect_problem() {
  local why
  if why=$(mcp_check_problem "$1" "$2"); then
    pass
  else
    fail "$3: ${why}"
  fi
}

# doc NAME VERSION [DESCRIPTION] > file
doc() {
  mcp_server_json "$1" "$2" "" "$REMOTE" "${3:-Release-gate MCP fixture server}"
}

# nested_doc NAME VERSION TOTAL_DEPTH: a valid document whose deepest bracket
# sits at TOTAL_DEPTH (root object = 1, _meta = 2, publisher-provided = 3,
# then TOTAL_DEPTH-3 nested objects).
nested_doc() {
  doc "$1" "$2" | python3 -c '
import json, sys
d = json.load(sys.stdin)
inner = {}
cur = inner
for _ in range(int(sys.argv[1]) - 3):
    cur["a"] = {}
    cur = cur["a"]
d["_meta"] = {"io.modelcontextprotocol.registry/publisher-provided": inner}
print(json.dumps(d))
' "$3"
}

# padded_doc NAME VERSION BYTES: a valid document padded with insignificant
# whitespace to exactly BYTES bytes.
padded_doc() {
  doc "$1" "$2" | python3 -c '
import sys
s = sys.stdin.read().strip()
n = int(sys.argv[1])
s = s[:-1] + " " * (n - len(s)) + "}"
assert len(s.encode()) == n
sys.stdout.write(s)
' "$3"
}

health_ok() {
  local st
  st=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$(mcp_base "$KEY")/health" 2>/dev/null) || st="000"
  [ "$st" = "200" ]
}

begin_test "Create the MCP repository"
if mcp_create_repo "$KEY"; then
  pass
else
  fail_fatal "MCP repository creation failed: ${MCP_CREATE_ERROR:-}"
fi

# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

n=0
while IFS=$'\t' read -r file want_status want_error; do
  case "$file" in ''|'#'*) continue ;; esac
  n=$(( n + 1 ))
  begin_test "Invalid corpus: ${file} -> ${want_status} ${want_error}"
  out="${WORK_DIR}/invalid-${n}.json"
  mcp_render_fixture "${INVALID_DIR}/${file}" "$out" SLUG="mal${n}-${RUN_ID}"
  mcp_publish "$KEY" "$out"
  expect_problem "$want_status" "$want_error" "$file"
done < "${INVALID_DIR}/cases.tsv"

begin_test "Invalid corpus: none of the refused vectors was stored"
mcp_get "$KEY" "servers?limit=100"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.servers | length')" = "0" ]; then
  pass
else
  fail "after the invalid corpus the listing holds $(mcp_json '.servers | length') entries (HTTP ${MCP_STATUS}): $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Nesting
# ---------------------------------------------------------------------------

begin_test "Nesting: 32 levels is accepted (boundary control)"
nested_doc "${NS}/depth" 32.0.0 32 > "${WORK_DIR}/d32.json"
mcp_publish "$KEY" "${WORK_DIR}/d32.json"
if [ "$MCP_STATUS" = "200" ]; then
  pass
else
  fail "a 32-deep document was refused: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Nesting: 33 levels is 400"
nested_doc "${NS}/depth" 33.0.0 33 > "${WORK_DIR}/d33.json"
mcp_publish "$KEY" "${WORK_DIR}/d33.json"
expect_problem 400 mcp_invalid_server_json "33-deep document"

begin_test "Nesting: 2000 levels of [ is 400"
python3 -c 'import sys; sys.stdout.write("[" * 2000 + "]" * 2000)' > "${WORK_DIR}/d2000.json"
mcp_publish "$KEY" "${WORK_DIR}/d2000.json"
expect_problem 400 mcp_invalid_server_json "2000-deep body"

begin_test "Nesting: 2000 levels of objects inside a valid document is 400"
nested_doc "${NS}/depth" 34.0.0 2000 > "${WORK_DIR}/d2000o.json"
mcp_publish "$KEY" "${WORK_DIR}/d2000o.json"
expect_problem 400 mcp_invalid_server_json "2000-deep document"

begin_test "Backend /health is 200 after the nesting bodies"
if health_ok; then pass; else fail "the MCP /health route did not answer 200 after the deep bodies"; fi

# ---------------------------------------------------------------------------
# Stored text is data
# ---------------------------------------------------------------------------

XSS_DESC='<script>alert(1)</script><img src=x onerror=alert(2)>&"'"'"
XSS_NAME="${NS}/xss"
begin_test "A <script> description is accepted"
doc "$XSS_NAME" 1.0.0 "$XSS_DESC" > "${WORK_DIR}/xss.json"
mcp_publish "$KEY" "${WORK_DIR}/xss.json"
if [ "$MCP_STATUS" = "200" ]; then pass; else fail "publish with a <script> description: HTTP ${MCP_STATUS}: $(mcp_snip)"; fi

for tail in "$(mcp_version_path "$XSS_NAME" 1.0.0)" "servers?search=${NS}/xss"; do
  begin_test "GET ${tail%%\?*}: description byte-exact, application/json, nosniff"
  mcp_get "$KEY" "$tail" anon
  got=$(mcp_json '(.server // .servers[0].server).description')
  ct=$(mcp_header content-type)
  ns=$(mcp_header x-content-type-options)
  if [ "$MCP_STATUS" != "200" ]; then
    fail "HTTP ${MCP_STATUS}: $(mcp_snip)"
  elif [ "$got" != "$XSS_DESC" ]; then
    fail "description changed in storage: got '${got}'"
  elif [ "${ct%%;*}" != "application/json" ]; then
    fail "content-type is '${ct}', expected application/json"
  elif [ "$ns" != "nosniff" ]; then
    fail "X-Content-Type-Options is '${ns}', expected nosniff"
  elif ! grep -qF '<script>alert(1)</script>' "$MCP_BODY"; then
    fail "the raw JSON does not carry the description bytes verbatim (escaped differently): $(mcp_snip)"
  else
    pass
  fi
done

# ---------------------------------------------------------------------------
# _meta reduction
# ---------------------------------------------------------------------------

META_NAME="${NS}/meta"
begin_test "Publisher-submitted official status and unknown _meta keys are not honoured"
doc "$META_NAME" 1.0.0 | jq -c '. + {"_meta": {
    "io.modelcontextprotocol.registry/official": {"status": "deleted", "isLatest": false, "publishedAt": "2000-01-01T00:00:00Z"},
    "com.artifactkeeper.registry/source": {"repository": "forged", "packagePolicy": "open"},
    "com.evil.injected/x": {"a": 1},
    "io.modelcontextprotocol.registry/publisher-provided": {"tool": "release-gate"}}}' > "${WORK_DIR}/meta.json"
mcp_publish "$KEY" "${WORK_DIR}/meta.json"
if [ "$MCP_STATUS" != "200" ]; then
  fail "publish with a forged _meta: HTTP ${MCP_STATUS}: $(mcp_snip)"
else
  mcp_get "$KEY" "$(mcp_version_path "$META_NAME" 1.0.0)" anon
  off_status=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
  off_pub=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].publishedAt')
  src_repo=$(mcp_json '._meta["com.artifactkeeper.registry/source"].repository')
  src_pol=$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')
  server_meta_keys=$(mcp_json '(.server._meta // {}) | keys | join(",")')
  evil=$(mcp_json '[.. | objects | keys[]? | select(. == "com.evil.injected/x")] | length')
  pp=$(mcp_json '.server._meta["io.modelcontextprotocol.registry/publisher-provided"].tool')
  if [ "$MCP_STATUS" != "200" ]; then
    fail "the version with a submitted status=deleted is not served: HTTP ${MCP_STATUS}: $(mcp_snip)"
  elif [ "$off_status" != "active" ] || [ "$off_pub" = "2000-01-01T00:00:00Z" ]; then
    fail "publisher wrote registry state: official.status='${off_status}' publishedAt='${off_pub}'"
  elif [ "$src_repo" != "$KEY" ] || [ "$src_pol" != "own-repos" ]; then
    fail "publisher forged the source block: repository='${src_repo}' packagePolicy='${src_pol}'"
  elif [ "$evil" != "0" ]; then
    fail "an unknown _meta key survived: $(mcp_snip)"
  elif [ "$server_meta_keys" != "io.modelcontextprotocol.registry/publisher-provided" ] || [ "$pp" != "release-gate" ]; then
    fail "server._meta keys '${server_meta_keys}' (publisher-provided tool '${pp}'); expected only publisher-provided"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Duplicate keys, bad encodings, Content-Type (pinned)
# ---------------------------------------------------------------------------

begin_test "Duplicate JSON keys (description twice) are 400 (pinned)"
printf '{"$schema":"%s","name":"%s/dup","description":"first","description":"second","version":"1.0.0","remotes":%s}' \
  "$MCP_SCHEMA_URL" "$NS" "$REMOTE" > "${WORK_DIR}/dup.json"
mcp_publish "$KEY" "${WORK_DIR}/dup.json"
expect_problem 400 mcp_invalid_server_json "duplicate description"

begin_test "Duplicate JSON keys (name twice, second a reserved name) are 400 (pinned)"
printf '{"$schema":"%s","name":"%s/dup","name":"io.modelcontextprotocol/dup","description":"d","version":"1.0.1","remotes":%s}' \
  "$MCP_SCHEMA_URL" "$NS" "$REMOTE" > "${WORK_DIR}/dup2.json"
mcp_publish "$KEY" "${WORK_DIR}/dup2.json"
expect_problem 400 mcp_invalid_server_json "duplicate name"

begin_test "Invalid UTF-8 in the body is 400 problem"
printf '{"$schema":"%s","name":"%s/utf","description":"\xff\xfe\xc0\xaf","version":"1.0.0","remotes":%s}' \
  "$MCP_SCHEMA_URL" "$NS" "$REMOTE" > "${WORK_DIR}/badutf8.json"
mcp_publish "$KEY" "${WORK_DIR}/badutf8.json"
expect_problem 400 mcp_invalid_server_json "invalid UTF-8"

begin_test "A non-JSON body is 400 problem"
printf 'name=x&version=1.0.0' > "${WORK_DIR}/nonjson.txt"
mcp_publish "$KEY" "${WORK_DIR}/nonjson.txt"
expect_problem 400 mcp_invalid_server_json "non-JSON body"

begin_test "An empty body is 400 problem"
: > "${WORK_DIR}/empty.json"
mcp_publish "$KEY" "${WORK_DIR}/empty.json"
expect_problem 400 mcp_invalid_server_json "empty body"

begin_test "A JSON array body is 400 problem"
printf '[]' > "${WORK_DIR}/array.json"
mcp_publish "$KEY" "${WORK_DIR}/array.json"
expect_problem 400 mcp_invalid_server_json "array body"

v=0
for ct in "text/plain" "application/x-www-form-urlencoded" "application/json; charset=utf-8" ""; do
  v=$(( v + 1 ))
  begin_test "Content-Type '${ct:-<none>}' is ignored: a valid document publishes (pinned)"
  doc "${NS}/ctype" "1.0.${v}" > "${WORK_DIR}/ct-${v}.json"
  mcp_req POST "$(mcp_base "$KEY")/publish" admin -H "Content-Type: ${ct}" --data-binary "@${WORK_DIR}/ct-${v}.json"
  if [ "$MCP_STATUS" = "200" ]; then
    pass
  else
    fail "publish with Content-Type '${ct}': HTTP ${MCP_STATUS}: $(mcp_snip)"
  fi
done

# ---------------------------------------------------------------------------
# Concurrent publishes of one name@version
# ---------------------------------------------------------------------------

RACE_NAME="${NS}/race"
begin_test "10 concurrent publishes of ${RACE_NAME}@1.0.0: one 200, nine 409"
pids=()
for i in $(seq 1 10); do
  doc "$RACE_NAME" 1.0.0 "racer ${i}" > "${WORK_DIR}/race-${i}.json"
done
for i in $(seq 1 10); do
  curl -s -o "${WORK_DIR}/race-${i}.out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X POST \
    -H "$(auth_header)" -H "Content-Type: application/json" --data-binary "@${WORK_DIR}/race-${i}.json" \
    "$(mcp_base "$KEY")/publish" > "${WORK_DIR}/race-${i}.status" 2>/dev/null &
  pids+=("$!")
done
for p in "${pids[@]}"; do wait "$p" || true; done
ok=0; conflict=0; other=""; winner=""
for i in $(seq 1 10); do
  st=$(cat "${WORK_DIR}/race-${i}.status" 2>/dev/null || echo 000)
  case "$st" in
    200) ok=$(( ok + 1 )); winner="$i" ;;
    409)
      if [ "$(jq -r '.error // empty' "${WORK_DIR}/race-${i}.out" 2>/dev/null)" = "mcp_version_exists" ]; then
        conflict=$(( conflict + 1 ))
      else
        other="${other} ${i}:409/$(jq -r '.error // empty' "${WORK_DIR}/race-${i}.out" 2>/dev/null)"
      fi
      ;;
    *) other="${other} ${i}:${st}" ;;
  esac
done
if [ "$ok" = "1" ] && [ "$conflict" = "9" ]; then
  pass
else
  fail "race outcome: ${ok} x 200, ${conflict} x 409 mcp_version_exists, other:${other:- none}" \
    "A version is write-once: exactly one publisher may win."
fi

begin_test "The served race version is the winner's document"
mcp_get "$KEY" "$(mcp_version_path "$RACE_NAME" 1.0.0)" anon
if [ -n "$winner" ] && [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.description')" = "racer ${winner}" ]; then
  pass
else
  fail "served description '$(mcp_json '.server.description')' (HTTP ${MCP_STATUS}), winner was racer ${winner:-none}"
fi

begin_test "The race left exactly one version"
mcp_get "$KEY" "servers/$(mcp_encode_name "$RACE_NAME")/versions" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.servers | length')" = "1" ]; then
  pass
else
  fail "versions after the race: HTTP ${MCP_STATUS}, $(mcp_json '.servers | length') entries"
fi

# ---------------------------------------------------------------------------
# Body size (last)
# ---------------------------------------------------------------------------

begin_test "A body of exactly 256 KiB (262144 bytes) is not 413"
padded_doc "${NS}/size" 1.0.0 262144 > "${WORK_DIR}/s0.json"
mcp_publish "$KEY" "${WORK_DIR}/s0.json"
case "$MCP_STATUS" in
  200) pass ;;
  400)
    if [ "$(mcp_json '.error')" = "mcp_invalid_server_json" ]; then
      pass
    else
      fail "262144-byte body: 400 with error '$(mcp_json '.error')'"
    fi
    ;;
  *) fail "262144-byte body: HTTP ${MCP_STATUS} (expected 200, or 400 for content): $(mcp_snip)" ;;
esac

begin_test "A body of 256 KiB + 1 (262145 bytes) is 413 mcp_too_large, answered not reset"
padded_doc "${NS}/size" 1.0.1 262145 > "${WORK_DIR}/s1.json"
mcp_publish "$KEY" "${WORK_DIR}/s1.json"
if [ "$MCP_STATUS" = "000" ]; then
  fail "the 262145-byte publish got no HTTP answer (connection reset or timeout)"
else
  expect_problem 413 mcp_too_large "262145-byte body"
fi

begin_test "A 4 MiB body is 413 mcp_too_large"
python3 -c 'import sys; sys.stdout.write("{\"a\":\"" + "x" * (4 * 1024 * 1024) + "\"}")' > "${WORK_DIR}/s4m.json"
mcp_publish "$KEY" "${WORK_DIR}/s4m.json"
if [ "$MCP_STATUS" = "000" ]; then
  fail "the 4 MiB publish got no HTTP answer (connection reset or timeout)"
else
  expect_problem 413 mcp_too_large "4 MiB body"
fi

begin_test "The oversized version was not stored"
mcp_get "$KEY" "$(mcp_version_path "${NS}/size" 1.0.1)" anon
if why=$(mcp_check_plain_404); then pass; else fail "262145-byte version: ${why}"; fi

begin_test "Backend /health is 200 after the big bodies"
if health_ok; then pass; else fail "the MCP /health route did not answer 200 after the oversized bodies"; fi

end_suite
