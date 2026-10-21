#!/usr/bin/env bash
# =============================================================================
# tiers/k8s-sa-pull-token/oracle.sh
#   Kubernetes ServiceAccount token image pulls (artifact-keeper#1246, 1.11.0):
#   a `kubernetes` CI OIDC provider with a static JWKS verifies a pod-shaped
#   ServiceAccount assertion offline, matches a JSON-Pointer claim filter and
#   mints a pull-only, non-renewable credential. See the manifest.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, TRIVY_PORT (the mock issuer's control port),
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
MOCK_PY="${DTF_DIR}/harness/tiers/ci-oidc-exchange/fixtures/mock_ci_oidc.py"
BACKEND_CTR="ak-dtf${SLOT}-backend"

# The kubernetes provider's issuer is the in-cluster name a kubeadm cluster
# uses; nothing on the DTF network resolves it, so only the static JWKS can
# verify. Its audience is a dedicated one (never the API server's, #4133).
K8S_ISS="https://kubernetes.default.svc.cluster.local"
K8S_AUD="ak-k8s-${SUF}"
KID="dtf-k8s-kid-${SUF}"
NS="payments"
SA_NAME="image-puller"
GEN_ISS="https://mock-ci-oidc/gen-${SUF}"
GEN_AUD="ak-gen-${SUF}"
GEN_REPO_CLAIM="dtf/gen-${SUF}"

GREPO="k8s-gen-${SLOT}-${SUF}"     # generic, private
OREPO="k8s-oci-${SLOT}-${SUF}"     # docker (OCI), private
IMG="app"
BYTES="k8s-bytes-${SUF}"

WORK="$(mktemp -d -t dtf-k8s-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code; body in $WORK/body, headers in $WORK/hdr.
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -D "$WORK/hdr" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"; : > "$WORK/hdr"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
# raw METHOD URL TOKEN CONTENT_TYPE FILE -> HTTP code (registry calls).
raw() {
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$1" -o "$WORK/body" -D "$WORK/hdr" -w '%{http_code}')
  [ -n "$3" ] && args+=(-H "Authorization: Bearer $3")
  [ -n "$4" ] && args+=(-H "Content-Type: $4")
  [ -n "${5:-}" ] && args+=(--data-binary "@$5")
  : > "$WORK/body"; : > "$WORK/hdr"
  curl "${args[@]}" "$2" 2>/dev/null || echo 000
}
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 300 | tr '\n' ' ' || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
is_denied() { case "$1" in 401|403|404) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
now() { date +%s; }

# jwt CLAIMS [KID] -> compact RS256 JWS signed by the mock's fixed key.
jwt() {
  jq -cn --argjson c "$1" --arg kid "${2:-$KID}" '{claims:$c, key:"good", kid:$kid}' > "$WORK/mintreq"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X POST "${MOCK}/mint" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/mintreq" 2>/dev/null || true
}
# xchg JWT -> HTTP code of POST /auth/ci/token (no body: provider from iss).
xchg() { req POST /api/v1/auth/ci/token "$1"; }
# sa_claims NAMESPACE [EXP_OFFSET] -> a projected ServiceAccount token's claims,
# shaped like the kubelet's (pod-bound, with the kubernetes.io member).
sa_claims() {
  local n; n="$(now)"
  jq -cn --arg iss "$K8S_ISS" --arg aud "$K8S_AUD" --arg ns "$1" --arg sa "$SA_NAME" \
    --argjson iat "$n" --argjson exp "$((n + ${2:-300}))" \
    '{iss:$iss, aud:[$aud], sub:("system:serviceaccount:"+$ns+":"+$sa), iat:$iat, nbf:$iat, exp:$exp,
      "kubernetes.io":{namespace:$ns, serviceaccount:{name:$sa, uid:"0b6d6a52-1111-4c1e-9b1e-5a1f2c3d4e5f"},
                       pod:{name:"puller-7d9f", uid:"9a8b7c6d-2222-4e5f-8a9b-0c1d2e3f4a5b"},
                       node:{name:"worker-1", uid:"1f2e3d4c-3333-4b5a-9c8d-7e6f5a4b3c2d"}}}'
}
gen_claims() {
  local n; n="$(now)"
  jq -cn --arg iss "$GEN_ISS" --arg aud "$GEN_AUD" --arg repo "$GEN_REPO_CLAIM" \
    --argjson iat "$n" --argjson exp "$((n + 300))" \
    '{iss:$iss, aud:$aud, sub:("repo:"+$repo+":ref:refs/heads/main"), repository:$repo, iat:$iat, exp:$exp}'
}
# jwt_payload TOKEN -> the decoded payload JSON of an AK access token.
jwt_payload() {
  local p; p="$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')"
  while [ $(( ${#p} % 4 )) -ne 0 ]; do p="${p}="; done
  printf '%s' "$p" | base64 -d 2>/dev/null || true
}
# The mock's public key as a JWK (n/e read from the fixture's constants; the
# file is parsed, never imported). With "private", the JWK also carries d.
jwk() {
  python3 -I - "$MOCK_PY" "$KID" "${1:-public}" <<'PY'
import base64, json, re, sys
src = open(sys.argv[1], encoding="utf-8").read()
def const(name):
    return int(re.search(r"^%s = (\d+)$" % name, src, re.M).group(1))
def b64(v):
    return base64.urlsafe_b64encode(v.to_bytes((v.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
k = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": sys.argv[2], "n": b64(const("GOOD_N")), "e": b64(const("GOOD_E"))}
if sys.argv[3] == "private":
    k["d"] = b64(const("GOOD_D"))
print(json.dumps({"keys": [k]}, separators=(",", ":")))
PY
}
mk_provider() { # JSON -> HTTP code
  req POST /api/v1/admin/ci-oidc "$ADMIN_TOKEN" "$1"
}
mk_mapping() { req POST "/api/v1/admin/ci-oidc/$1/mappings" "$ADMIN_TOKEN" "$2"; }
grant_rw() { # USER_ID REPO_ID -> HTTP code
  req POST /api/v1/permissions "$ADMIN_TOKEN" "$(jq -nc --arg u "$1" --arg r "$2" \
    '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read","write"]}')"
}
put_obj() { # TOKEN PATH BYTES -> HTTP code
  printf '%s' "$3" > "$WORK/up"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $1" --data-binary "@$WORK/up" \
    "${BASE_URL}/api/v1/repositories/${GREPO}/artifacts/$2" 2>/dev/null || echo 000
}
dl() { req GET "/api/v1/repositories/${GREPO}/download/$2" "$1"; }

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# =============================================================================
begin_suite "k8s-sa-pull-token"

begin_test "setup: mock signer up, a private generic and a private OCI repository with content, an image pushed by admin"
auth_admin
SETUP_ERR=""
[ "$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${MOCK}/__readyz" 2>/dev/null)" = "ok" ] || SETUP_ERR="${SETUP_ERR} mock"
JWKS_PUBLIC="$(jwk public || true)"; JWKS_PRIVATE="$(jwk private || true)"
[ "$(printf '%s' "$JWKS_PUBLIC" | jq -r '.keys[0].kid' 2>/dev/null)" = "$KID" ] || SETUP_ERR="${SETUP_ERR} jwks"
for spec in "$GREPO:generic" "$OREPO:docker"; do
  code="$(req POST /api/v1/repositories "$ADMIN_TOKEN" "$(jq -nc --arg k "${spec%%:*}" --arg f "${spec##*:}" \
    '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')")"
  is_2xx "$code" || SETUP_ERR="${SETUP_ERR} repo(${spec}:${code})"
done
GREPO_ID="$(db "SELECT id FROM repositories WHERE key = '${GREPO}'")"
OREPO_ID="$(db "SELECT id FROM repositories WHERE key = '${OREPO}'")"
is_2xx "$(put_obj "$ADMIN_TOKEN" obj.txt "$BYTES")" || SETUP_ERR="${SETUP_ERR} upload"
# Minimal image: config blob + one layer + a v2 manifest, pushed with admin.
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' > "$WORK/cfg"
printf 'k8s-layer-%s' "$SUF" > "$WORK/layer"
CFG_D="sha256:$(sha256sum "$WORK/cfg" | cut -d' ' -f1)"; CFG_S="$(wc -c < "$WORK/cfg" | tr -d ' ')"
LAY_D="sha256:$(sha256sum "$WORK/layer" | cut -d' ' -f1)"; LAY_S="$(wc -c < "$WORK/layer" | tr -d ' ')"
MCT='application/vnd.docker.distribution.manifest.v2+json'
printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"%s"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":%s,"digest":"%s"}]}' \
  "$MCT" "$CFG_S" "$CFG_D" "$LAY_S" "$LAY_D" > "$WORK/manifest"
UPL="${BASE_URL}/v2/${OREPO}/${IMG}/blobs/uploads/"
for b in "cfg:$CFG_D" "layer:$LAY_D"; do
  c="$(raw POST "${UPL}?digest=${b#*:}" "$ADMIN_TOKEN" application/octet-stream "$WORK/${b%%:*}")"
  [ "$c" = "201" ] || SETUP_ERR="${SETUP_ERR} blob(${b%%:*}:${c}:$(snip | head -c 80))"
done
c="$(raw PUT "${BASE_URL}/v2/${OREPO}/${IMG}/manifests/v1" "$ADMIN_TOKEN" "$MCT" "$WORK/manifest")"
[ "$c" = "201" ] || SETUP_ERR="${SETUP_ERR} manifest(${c}:$(snip | head -c 80))"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- repos ${GREPO} (${GREPO_ID}) ${OREPO} (${OREPO_ID}); kid ${KID}; k8s aud ${K8S_AUD}"
pass

# =============================================================================
# CONTROLS (every image): the generic, discovery-based CI exchange
# =============================================================================
begin_test "CONTROL: a generic provider (discovery) exchanges; its token reads and writes a granted repository; a refresh-token JTI is stored"
reset_case
code="$(mk_provider "$(jq -nc --arg n "k8s-gen-${SUF}" --arg i "$GEN_ISS" --arg a "$GEN_AUD" \
  '{name:$n,provider_type:"generic",issuer_url:$i,audience:$a}')")"; GEN_P="$(jr '.id // empty')"
is_2xx "$code" && [ -n "$GEN_P" ] || gate "generic provider create answered ${code}: $(snip)"
code="$(mk_mapping "$GEN_P" "$(jq -nc --arg n "k8s-genmap-${SUF}" --arg r "$GEN_REPO_CLAIM" '{name:$n,claim_filters:{repository:$r}}')")"
is_2xx "$code" || gate "generic mapping create answered ${code}: $(snip)"
code="$(xchg "$(jwt "$(gen_claims)" dtf-ci-oidc-key-1)")"; GEN_TOK="$(jr '.access_token // empty')"
note "generic exchange: ${code} username=$(jr '.username')"
[ "$code" = "200" ] && [ -n "$GEN_TOK" ] || gate "generic exchange answered ${code}: $(snip)"
req GET /api/v1/auth/me "$GEN_TOK" >/dev/null; GEN_UID="$(jr '.id // empty')"
[ -n "$GEN_UID" ] || gate "/auth/me with the generic CI token: $(snip)"
is_2xx "$(grant_rw "$GEN_UID" "$GREPO_ID")" || gate "granting the generic CI account read/write: $(snip)"
code="$(xchg "$(jwt "$(gen_claims)" dtf-ci-oidc-key-1)")"; GEN_TOK="$(jr '.access_token // empty')"
code="$(put_obj "$GEN_TOK" "gen-${SUF}.txt" "gen-${SUF}")"; note "generic token PUT: ${code}"
is_2xx "$code" || gate "the generic CI token could not write a granted repository (${code}: $(snip))"
code="$(dl "$GEN_TOK" obj.txt)"; note "generic token GET: ${code}"
[ "$code" = "200" ] && [ "$(body)" = "$BYTES" ] || gate "the generic CI token could not read (${code})"
jtis="$(db "SELECT count(*) FROM refresh_token_jti WHERE user_id = '${GEN_UID}'")"
note "refresh_token_jti rows for the generic account: ${jtis}"
{ [ "$jtis" != "?" ] && [ "$jtis" -ge 1 ]; } || gate "no refresh-token JTI stored for a generic exchange (${jtis})"
finish_case "the generic CI exchange baseline is broken"

begin_test "CONTROL: an assertion for a different audience is refused 401"
reset_case
c="$(gen_claims | jq -c '.aud = "someone-else"')"
code="$(xchg "$(jwt "$c" dtf-ci-oidc-key-1)")"; note "wrong audience: ${code}"
[ "$code" = "401" ] && [ -z "$(jr '.access_token // empty')" ] || gate "wrong audience answered ${code}: $(snip)"
finish_case "audience is not enforced"

# =============================================================================
# FIX #1246 (RED on 1.10.0)
# =============================================================================
begin_test "FIX #1246: provider_type 'kubernetes' with key_source static and a public static_jwks is stored as such"
reset_case
code="$(mk_provider "$(jq -nc --arg n "k8s-p-${SUF}" --arg i "$K8S_ISS" --arg a "$K8S_AUD" --argjson j "$JWKS_PUBLIC" \
  '{name:$n,provider_type:"Kubernetes",issuer_url:$i,audience:$a,key_source:"static",static_jwks:$j}')")"
K8S_P="$(jr '.id // empty')"
note "create: ${code} provider_type=$(jr '.provider_type') key_source=$(jr '.key_source // "absent"')"
is_2xx "$code" && [ -n "$K8S_P" ] || gate "create answered ${code}: $(snip)"
[ "$(jr '.provider_type')" = "kubernetes" ] || gate "provider_type '$(jr '.provider_type')' is not the normalised 'kubernetes'"
[ "$(jr '.key_source')" = "static" ] || gate "response key_source is '$(jr '.key_source')'"
row="$(db "SELECT provider_type || '|' || key_source || '|' || (static_jwks->'keys'->0->>'kid') FROM ci_oidc_providers WHERE id = '${K8S_P:-00000000-0000-0000-0000-000000000000}'")"
note "db row: ${row}"
[ "$row" = "kubernetes|static|${KID}" ] || gate "stored row is '${row}', expected kubernetes|static|${KID}"
finish_case "a static-JWKS kubernetes provider cannot be configured"

begin_test "FIX #1246: a pod's ServiceAccount assertion exchanges offline against the static JWKS through a /kubernetes.io/namespace pointer mapping"
reset_case
code="$(mk_mapping "${K8S_P:-none}" "$(jq -nc --arg n "k8s-m-${SUF}" --arg ns "$NS" '{name:$n,claim_filters:{"/kubernetes.io/namespace":$ns}}')")"
note "pointer mapping: ${code} $(jr '.service_account_username // empty')"
is_2xx "$code" || gate "pointer mapping answered ${code}: $(snip)"
code="$(xchg "$(jwt "$(sa_claims "$NS")")")"
K8S_TOK="$(jr '.access_token // empty')"; K8S_USER="$(jr '.username // empty')"
note "exchange: ${code} username=${K8S_USER} expires_in=$(jr '.expires_in') refresh_token=$(jr '.refresh_token // "absent"')"
[ "$code" = "200" ] && [ -n "$K8S_TOK" ] || gate "SA assertion answered ${code}: $(snip)"
case "$K8S_USER" in ci-*) ;; *) gate "username '${K8S_USER}' is not a ci- service account";; esac
[ -z "$(jr '.refresh_token // empty')" ] || gate "the exchange response carries a refresh_token"
K8S_UID=""
if [ -n "$K8S_TOK" ]; then req GET /api/v1/auth/me "$K8S_TOK" >/dev/null; K8S_UID="$(jr '.id // empty')"; fi
[ -n "$K8S_UID" ] || gate "/auth/me with the kubernetes token failed: $(snip)"
finish_case "the ServiceAccount token does not exchange"

begin_test "FIX #1246: the kubernetes credential is pull-only (scopes) and not renewable (no refresh-token JTI)"
reset_case
scopes="$(jwt_payload "$K8S_TOK" | jq -c '.scopes // null' 2>/dev/null || echo '?')"
jtis="$(db "SELECT count(*) FROM refresh_token_jti WHERE user_id = '${K8S_UID:-00000000-0000-0000-0000-000000000000}'")"
note "token scopes=${scopes}; refresh_token_jti rows=${jtis}"
[ "$(printf '%s' "$scopes" | jq -c 'sort' 2>/dev/null)" = '["read:artifacts","read:repositories"]' ] \
  || gate "scopes are ${scopes}, expected exactly [read:artifacts, read:repositories]"
[ -n "$K8S_UID" ] && [ "$jtis" = "0" ] || gate "kubernetes account ${K8S_UID:-(none: the exchange failed)} has ${jtis} refresh-token JTI row(s), expected 0"
finish_case "the kubernetes exchange mints a renewable or push-capable credential"

begin_test "FIX #1246: with read+write granted to its account, the kubernetes token pulls (REST and OCI) but cannot push"
reset_case
if [ -n "$K8S_UID" ]; then
  is_2xx "$(grant_rw "$K8S_UID" "$GREPO_ID")" || gate "grant rw on ${GREPO}: $(snip)"
  is_2xx "$(grant_rw "$K8S_UID" "$OREPO_ID")" || gate "grant rw on ${OREPO}: $(snip)"
  code="$(xchg "$(jwt "$(sa_claims "$NS")")")"; K8S_TOK="$(jr '.access_token // empty')"
fi
code="$(dl "$K8S_TOK" obj.txt)"; note "REST GET: ${code}"
[ "$code" = "200" ] && [ "$(body)" = "$BYTES" ] || gate "REST pull answered ${code}"
code="$(raw GET "${BASE_URL}/v2/${OREPO}/${IMG}/manifests/v1" "$K8S_TOK" "" "")"
note "OCI manifest GET: ${code} digest=$(grep -i '^docker-content-digest:' "$WORK/hdr" | tr -d '\r' | cut -d' ' -f2)"
[ "$code" = "200" ] && [ "$(body | jq -r '.config.digest' 2>/dev/null)" = "$CFG_D" ] || gate "OCI manifest pull answered ${code}: $(snip | head -c 120)"
code="$(raw GET "${BASE_URL}/v2/${OREPO}/${IMG}/blobs/${LAY_D}" "$K8S_TOK" "" "")"; note "OCI blob GET: ${code}"
[ "$code" = "200" ] && [ "$(body)" = "k8s-layer-${SUF}" ] || gate "OCI blob pull answered ${code}"
code="$(put_obj "$K8S_TOK" "k8s-push-${SUF}.txt" "x")"; note "REST PUT: ${code} $(snip | head -c 120)"
is_denied "$code" || gate "REST push with the kubernetes token answered ${code}"
[ "$(db "SELECT count(*) FROM artifacts WHERE path LIKE '%k8s-push-${SUF}%'")" = "0" ] || gate "the refused REST push left an artifact row"
code="$(raw POST "$UPL" "$K8S_TOK" "" "")"; note "OCI blob upload init: ${code} $(snip | head -c 120)"
is_denied "$code" || gate "OCI push (blob upload init) with the kubernetes token answered ${code}"
finish_case "a kubernetes pull credential can push"

begin_test "FIX #1246: the namespace pointer excludes a ServiceAccount of another namespace (401)"
reset_case
code="$(xchg "$(jwt "$(sa_claims billing)")")"; note "namespace billing: ${code} $(jr '.message')"
[ "$code" = "401" ] && [ -z "$(jr '.access_token // empty')" ] || gate "another namespace answered ${code}"
finish_case "the JSON Pointer filter does not constrain the namespace"

begin_test "FIX #1246: a token whose kid is not in the static JWKS is refused 401 naming the kid"
reset_case
code="$(xchg "$(jwt "$(sa_claims "$NS")" "rotated-${SUF}")")"; msg="$(jr '.message // .error // empty')"
note "unknown kid: ${code} ${msg}"
[ "$code" = "401" ] && [ -z "$(jr '.access_token // empty')" ] || gate "unknown kid answered ${code}"
body | grep -q "rotated-${SUF}" || gate "the refusal does not name the kid: $(snip)"
finish_case "an unknown kid is not refused precisely"

begin_test "FIX #1246: a static JWKS with a private member (d) is refused 400 and nothing is stored"
reset_case
code="$(mk_provider "$(jq -nc --arg n "k8s-priv-${SUF}" --arg a "${K8S_AUD}-p" --argjson j "$JWKS_PRIVATE" \
  '{name:$n,provider_type:"kubernetes",issuer_url:"https://k8s-priv.invalid",audience:$a,key_source:"static",static_jwks:$j}')")"
note "private JWKS: ${code} $(jr '.message')"
[ "$code" = "400" ] || gate "a JWKS with private key material answered ${code}"
body | grep -q "'d'" || gate "the refusal does not name the private member: $(snip)"
[ "$(db "SELECT count(*) FROM ci_oidc_providers WHERE name = 'k8s-priv-${SUF}'")" = "0" ] || gate "a provider row was stored"
finish_case "private key material is accepted into a static JWKS"

begin_test "FIX #1246: provider_type 'k8s' is refused 400 on create and nothing is stored"
reset_case
code="$(mk_provider "$(jq -nc --arg n "k8s-typo-${SUF}" --arg a "${K8S_AUD}-t" --arg i "${GEN_ISS}-typo" \
  '{name:$n,provider_type:"k8s",issuer_url:$i,audience:$a}')")"
note "k8s: ${code} $(jr '.message')"
[ "$code" = "400" ] || gate "provider_type k8s answered ${code} (a typo yields a push-capable generic provider)"
[ "$(db "SELECT count(*) FROM ci_oidc_providers WHERE name = 'k8s-typo-${SUF}'")" = "0" ] || gate "a provider row was stored"
finish_case "an unknown provider_type is accepted"

begin_test "FIX #1246: a claim_filters pointer key with a bad escape (/a~2b) is refused 400"
reset_case
code="$(mk_mapping "${K8S_P:-$GEN_P}" "$(jq -nc --arg n "k8s-badptr-${SUF}" '{name:$n,claim_filters:{"/a~2b":"x"}}')")"
note "/a~2b: ${code} $(jr '.message')"
[ "$code" = "400" ] || gate "malformed pointer answered ${code}"
body | grep -q "a~2b" || gate "the refusal does not name the key: $(snip)"
[ "$(db "SELECT count(*) FROM ci_oidc_identity_mappings WHERE name = 'k8s-badptr-${SUF}'")" = "0" ] || gate "a mapping row was stored"
finish_case "a malformed JSON Pointer is saved and silently never matches"

begin_test "FIX #1246: the exchange's security log line records the workload's namespace and ServiceAccount"
reset_case
logs="$(docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep 'CI OIDC token exchange' | grep -F "${K8S_USER:-none}" | tail -n1 || true)"
note "log: $(printf '%s' "$logs" | head -c 400)"
printf '%s' "$logs" | grep -Eq "k8s_namespace=\"?${NS}\"?( |$)" || gate "no k8s_namespace=${NS} on the exchange line"
printf '%s' "$logs" | grep -Eq "k8s_serviceaccount=\"?${SA_NAME}\"?( |$)" || gate "no k8s_serviceaccount=${SA_NAME} on the exchange line"
finish_case "the pulling workload is not attributed"

end_suite
