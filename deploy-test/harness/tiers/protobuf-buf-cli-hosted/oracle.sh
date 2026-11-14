#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/protobuf-buf-cli-hosted/oracle.sh
#   The real buf CLI against a hosted (local) protobuf repository, through a
#   host-root reverse proxy (profiles/client.buf.yml): push a module, push a
#   module that depends on it, resolve the chain from a consumer (buf verifies
#   every commit's b5 digest) and build it. Plus the JSON codec controls.
#   artifact-keeper#5066 / #5117 (fix PR #5074). See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
REPO="pb-buf"                       # fixed: fixtures/Caddyfile maps bsr.dtf.local/ onto it
REGISTRY="bsr.dtf.local"
BUFC="ak-dtf${DTF_SLOT}-client-buf"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }
body(){ head -c "${2:-400}" "$1" 2>/dev/null | tr -d '\n' || true; }

# http <METHOD> <PATH> <OUT> [curl args...] -> HTTP code (admin bearer)
http(){
  local m="$1" u="$2" o="$3"; shift 3
  rm -f "$o"
  curl -s --max-time 60 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer ${TOK}" "$@" "${BASE}${u}" 2>/dev/null || true
  [ -f "$o" ] || : >"$o"
}
post_json(){ http POST "$1" "$2" -H 'Content-Type: application/json' -d "$3"; }

# bx <dir> <shell> -> runs <shell> in the buf container, in /work/<dir>, with
# TLS off (buf's own config) and the admin token read from a file (never on a
# command line). stdout+stderr go to $W/bx.out; returns the exit status.
bx(){
  docker exec -e HOME=/work -e BUF_CONFIG_DIR=/work/bufcfg -e BUF_CACHE_DIR=/work/cache \
    -w "/work/$1" "$BUFC" sh -c "export BUF_TOKEN=\"\$(cat /work/token)\"; $2" >"$W/bx.out" 2>&1
}
# put <container path> < local content
put(){ docker exec -i "$BUFC" sh -c "mkdir -p \"\$(dirname '$1')\" && cat > '$1'"; }
out(){ sed 's/^/      | /' "$W/bx.out" | head -c "${1:-1500}"; }

# A module dir: buf.yaml naming <owner/module> under $REGISTRY, optional dep.
write_module(){ # <dir> <owner/module or ""> [dep owner/module]
  local dir="$1" name="$2" dep="${3:-}"
  {
    echo "version: v2"
    echo "modules:"
    echo "  - path: ."
    [ -n "$name" ] && echo "    name: ${REGISTRY}/${name}"
    if [ -n "$dep" ]; then echo "deps:"; echo "  - ${REGISTRY}/${dep}"; fi
  } | put "/work/$dir/buf.yaml"
}

begin_suite "protobuf-buf-cli-hosted"

# =============================================================================
begin_test "setup: admin session, hosted protobuf repo ${REPO}, buf CLI and the host-root proxy"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // .token // empty')"
SETUP_ERR=""
[ -n "$TOK" ] || SETUP_ERR="${SETUP_ERR} login"
C="$(post_json /api/v1/repositories "$W/repo.json" "$(jq -nc --arg k "$REPO" \
  '{key:$k,name:$k,format:"protobuf",repo_type:"local",is_public:true}')")"
case "$C" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} repo(${C}: $(body "$W/repo.json" 200))";; esac
printf '%s' "$TOK" | put /work/token || SETUP_ERR="${SETUP_ERR} token-file"
printf 'version: v1\ntls:\n  use: false\n' | put /work/bufcfg/config.yaml || SETUP_ERR="${SETUP_ERR} buf-config"
bx . 'buf --version' && BUF_VERSION="$(tr -d '\n' <"$W/bx.out")" || SETUP_ERR="${SETUP_ERR} buf(--version: $(body "$W/bx.out" 200))"
# The proxy is up and maps its root onto the repository: a BSR write method
# is answered by the backend (its /proto write gate, 401 without a token), not
# with a proxy error. Recorded, not gated.
docker exec "$BUFC" sh -c "wget -q -O - --header 'Content-Type: application/json' --post-data '{}' \
  http://${REGISTRY}/buf.registry.module.v1.ModuleService/DeleteModules" >"$W/probe.out" 2>&1
PROXY_PROBE="$(body "$W/probe.out" 200)"
echo "-- buf ${BUF_VERSION:-?}; proxy probe (expect the backend's own answer): ${PROXY_PROBE}"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
# CONTROL (both images): the JSON codec the hosted endpoints have always
# served answers exactly as before -- upload, GetModules by name (`name` is
# `owner/module`), a missing module left out of a 200, and Download by label.
# =============================================================================
PROTO_JSON='syntax = "proto3";
package acme.jsononly.v1;
message Ping { string id = 1; }
'
UP_BODY="$(jq -nc --arg c "$(printf '%s' "$PROTO_JSON" | base64 | tr -d '\n')" '{contents:[{moduleRef:{owner:"acme",module:"jsononly"},
  files:[{path:"acme/jsononly/v1/ping.proto",content:$c}],labelRefs:[{name:"main"}]}]}')"
JU="$(post_json "/proto/${REPO}/buf.registry.module.v1beta1.UploadService/Upload" "$W/json.up" "$UP_BODY")"
JM="$(post_json "/proto/${REPO}/buf.registry.module.v1.ModuleService/GetModules" "$W/json.mods" \
  '{"moduleRefs":[{"owner":"acme","module":"jsononly"},{"owner":"acme","module":"never-pushed"}]}')"
JD="$(post_json "/proto/${REPO}/buf.registry.module.v1beta1.DownloadService/Download" "$W/json.dl" \
  '{"values":[{"resourceRef":{"owner":"acme","module":"jsononly","label":"main"}}]}')"
JDIGEST="$(jqr '.commits[0].digest.value // empty' <"$W/json.up")"
echo "-- JSON upload=${JU} digest=${JDIGEST:-?} GetModules=${JM} Download=${JD}"

begin_test "CONTROL: JSON codec: Upload, GetModules (name owner/module, a missing module omitted from a 200) and Download by label answer as before"
reset_fail=""
[ "$JU" = "200" ] && [ "$(jqr '.commits[0].digest.type // empty' <"$W/json.up")" = "sha256" ] \
  || reset_fail="${reset_fail} upload=${JU}:$(body "$W/json.up" 200);"
[ "$JM" = "200" ] && [ "$(jqr '.modules | length' <"$W/json.mods")" = "1" ] \
  && [ "$(jqr '.modules[0].name // empty' <"$W/json.mods")" = "acme/jsononly" ] \
  || reset_fail="${reset_fail} GetModules=${JM}:$(body "$W/json.mods" 300);"
[ "$JD" = "200" ] && [ "$(jqr '.contents[0].commit.digest.value // empty' <"$W/json.dl")" = "$JDIGEST" ] \
  && [ -n "$JDIGEST" ] \
  || reset_fail="${reset_fail} Download=${JD}:$(body "$W/json.dl" 200);"
if [ -z "$reset_fail" ]; then pass; else fail "the JSON codec changed:${reset_fail}"; fi

# =============================================================================
# FIX #5066: a binary-codec Connect call on a hosted repository is served, not
# refused by the JSON extractor with a bare 415.
# =============================================================================
begin_test "FIX #5066: a binary Connect GetModules (application/proto) on a hosted repo answers 200 application/proto, not 415"
BC="$(curl -s --max-time 30 -o "$W/bin.mods" -D "$W/bin.hdr" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/proto' -H 'Connect-Protocol-Version: 1' \
  --data-binary '' "${BASE}/proto/${REPO}/buf.registry.module.v1.ModuleService/GetModules" 2>/dev/null || true)"
BCT="$(tr -d '\r' <"$W/bin.hdr" 2>/dev/null | sed -n 's/^[Cc]ontent-[Tt]ype: //p' | head -1)"
echo "-- binary GetModules: HTTP ${BC} content-type '${BCT}' body $(body "$W/bin.mods" 160)"
if [ "$BC" = "200" ] && [ "$BCT" = "application/proto" ]; then pass
else fail "binary GetModules answered HTTP ${BC} (content-type '${BCT}'); pre-#5074 the hosted handlers took only JSON and answered 415" "$(body "$W/bin.mods")"; fi

# =============================================================================
# FIX #5117: buf push --create of a module with no dependencies.
# =============================================================================
write_module payments acme/payments
put /work/payments/acme/payments/v1/payments.proto <<'EOF'
syntax = "proto3";

package acme.payments.v1;

message PaymentRequest {
  string order_id = 1;
  int64 amount_cents = 2;
}
EOF
bx payments 'buf push --create --create-visibility public'; RC1=$?
PAYMENTS="$(tail -n 1 "$W/bx.out" | sed 's/.*://' | tr -d '[:space:]')"
echo "-- buf push acme/payments: exit ${RC1}, commit '${PAYMENTS}'"; out 1200; echo

begin_test "FIX #5117: buf push --create of acme/payments succeeds and reports a commit id (tuuid)"
if [ "$RC1" -eq 0 ] && printf '%s' "$PAYMENTS" | grep -Eq '^[0-9a-f]{32}$'; then pass
else fail "buf push exited ${RC1}, last line '$(tail -n 1 "$W/bx.out")'" "$(head -c 1500 "$W/bx.out")"; fi

# =============================================================================
# FIX #5117: a module that depends on it: buf dep update pins the commit, and
# the push records the dependency as that commit id.
# =============================================================================
write_module orders acme/orders acme/payments
put /work/orders/acme/orders/v1/orders.proto <<'EOF'
syntax = "proto3";

package acme.orders.v1;

import "acme/payments/v1/payments.proto";

message Order {
  string id = 1;
  acme.payments.v1.PaymentRequest payment = 2;
}
EOF
bx orders 'buf dep update && cat buf.lock && buf push --create --create-visibility public'; RC2=$?
ORDERS="$(tail -n 1 "$W/bx.out" | sed 's/.*://' | tr -d '[:space:]')"
echo "-- buf dep update + push acme/orders: exit ${RC2}, commit '${ORDERS}'"; out 1500; echo

begin_test "FIX #5117: buf dep update pins acme/payments' commit with a b5 digest, and acme/orders pushes"
if [ "$RC2" -eq 0 ] && [ -n "$PAYMENTS" ] && grep -q "commit: ${PAYMENTS}" "$W/bx.out" \
   && grep -q 'digest: b5:' "$W/bx.out" && printf '%s' "$ORDERS" | grep -Eq '^[0-9a-f]{32}$'; then pass
else fail "dep update/push exited ${RC2}; payments '${PAYMENTS}' orders '${ORDERS}'" "$(head -c 1500 "$W/bx.out")"; fi

# =============================================================================
# FIX #5117: a consumer of acme/orders resolves the whole chain (GetGraph's
# closure, the dependency recorded as a commit id), buf verifies both b5
# digests against what it downloaded, and the consumer builds.
# =============================================================================
write_module consumer "" acme/orders
put /work/consumer/acme/checkout/v1/checkout.proto <<'EOF'
syntax = "proto3";

package acme.checkout.v1;

import "acme/orders/v1/orders.proto";

message Checkout {
  acme.orders.v1.Order order = 1;
}
EOF
bx consumer 'buf dep update && cat buf.lock && buf build -o /work/consumer/image.binpb && echo BUILD-OK'; RC3=$?
echo "-- consumer dep update + build: exit ${RC3}"; out 1500; echo

begin_test "FIX #5117: a consumer resolves acme/orders and acme/payments (both commits and b5 digests in buf.lock) and buf build succeeds"
if [ "$RC3" -eq 0 ] && [ -n "$ORDERS" ] && [ -n "$PAYMENTS" ] \
   && grep -q "commit: ${ORDERS}" "$W/bx.out" && grep -q "commit: ${PAYMENTS}" "$W/bx.out" \
   && [ "$(grep -c 'digest: b5:' "$W/bx.out")" -eq 2 ] && grep -q 'BUILD-OK' "$W/bx.out"; then pass
else fail "consumer dep update/build exited ${RC3}" "$(head -c 1500 "$W/bx.out")"; fi

# =============================================================================
# FIX #5117: what buf pushed is still served to a JSON caller in the JSON
# shape (name owner/module, sha256 digest type).
# =============================================================================
JM2="$(post_json "/proto/${REPO}/buf.registry.module.v1.ModuleService/GetModules" "$W/json.mods2" \
  '{"moduleRefs":[{"owner":"acme","module":"payments"}]}')"
JC2="$(post_json "/proto/${REPO}/buf.registry.module.v1.CommitService/GetCommits" "$W/json.commits2" \
  '{"resourceRefs":[{"owner":"acme","module":"payments","label":"main"}]}')"
echo "-- JSON GetModules(acme/payments)=${JM2} $(body "$W/json.mods2" 200); GetCommits=${JC2} $(body "$W/json.commits2" 200)"

begin_test "FIX #5117: a module buf pushed is answered to a JSON caller in the JSON shape (name acme/payments, digest type sha256)"
if [ "$JM2" = "200" ] && [ "$(jqr '.modules[0].name // empty' <"$W/json.mods2")" = "acme/payments" ] \
   && [ "$JC2" = "200" ] && [ "$(jqr '.commits[0].digest.type // empty' <"$W/json.commits2")" = "sha256" ]; then pass
else fail "JSON GetModules=${JM2} GetCommits=${JC2}" "$(body "$W/json.mods2") / $(body "$W/json.commits2")"; fi

end_suite
