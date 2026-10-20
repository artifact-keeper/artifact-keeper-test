#!/usr/bin/env bash
# =============================================================================
# tiers/terraform-origin-registry/oracle.sh
#   #4356 / #4357 a hosted Terraform repository is an OpenTofu/Terraform
#   ORIGIN provider registry: host-level /.well-known/terraform.json (opt-in via
#   TERRAFORM_DEFAULT_REPO), a deterministic SHA256SUMS, a binary detached
#   OpenPGP SHA256SUMS.sig made with the repository's signing key, the package
#   document advertising shasums_url / shasums_signature_url / gpg_public_keys,
#   fail-closed without a key, and single-use path-bound tickets on the three
#   package-document URLs of a private repository.
# See the manifest for the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# BACKEND_IMAGE, RATE_LIMIT_ENABLED and the slot port block, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"; : "${BACKEND_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
TF_CLIENT="ak-dtf${DTF_SLOT}-client-terraform"
TF_CADDY="ak-dtf${DTF_SLOT}-caddy-terraform"
TF_HOST="tf.dtf.local"            # caddy's network alias (profiles/client.terraform.yml)
NS="acme"
VER="1.2.3"

setup_workdir
W="$WORK_DIR"
GNUPGHOME="$(mktemp -d "${TMPDIR:-/tmp}/dtf-tfo-gpg.XXXXXX")"
chmod 700 "$GNUPGHOME"
add_exit_handler "gpgconf --homedir \"$GNUPGHOME\" --kill all >/dev/null 2>&1; rm -rf \"$GNUPGHOME\""
export GNUPGHOME

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# get <outfile> <url-or-path> [curl args...] -> http code (body in outfile)
get(){
  local out="$1" url="$2" code
  shift 2
  case "$url" in http*) ;; *) url="${BASE}${url}" ;; esac
  rm -f "$out"
  code="$(curl -s --max-time 30 -o "$out" -w '%{http_code}' "$@" "$url" 2>/dev/null)" || true
  [ -f "$out" ] || : > "$out"
  echo "${code:-000}"
}
aget(){ local out="$1" url="$2"; shift 2; get "$out" "$url" -H "Authorization: Bearer $TOK" "$@"; }

# recreate_backend <TERRAFORM_DEFAULT_REPO value|""> — recreate ONLY the backend
# on the harness-owned compose project with a tier-local override (the
# qcmj-webhook-authz pattern), health-gated. The database volume survives, so
# the repositories and uploads made before are still there.
recreate_backend(){
  local override rc
  override="$(mktemp "${TMPDIR:-/tmp}/dtf-tfo-${DTF_SLOT}.XXXXXX.yml")"
  if [ -n "$1" ]; then
    printf 'services:\n  backend:\n    environment:\n      TERRAFORM_DEFAULT_REPO: "%s"\n' "$1" > "$override"
  else
    printf 'services:\n  backend: {}\n' > "$override"
  fi
  docker compose -p "ak-dtf${DTF_SLOT}" \
    -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "${DTF_DIR}/profiles/client.terraform.yml" \
    -f "$override" \
    up -d --wait backend >/dev/null 2>&1
  rc=$?
  rm -f "$override"
  [ "$rc" -eq 0 ] || return "$rc"
  curl -sf --max-time 10 "${BASE}/health" >/dev/null 2>&1
}

admin_login(){
  curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty'
}

mk_repo(){ # <key> <format> <is_public>
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"local\",\"is_public\":$3}" \
    | jqr '.key // empty'
}
repo_id(){ curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/$1" | jqr '.id // empty'; }

# attach_gpg_key <repo_key> -> writes $W/key-<repo>.json, echoes the key id
attach_gpg_key(){
  local rid kid code
  rid="$(repo_id "$1")"
  [ -n "$rid" ] || return 1
  curl -s -X POST "$BASE/api/v1/signing/keys" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' \
    -d "{\"repository_id\":\"${rid}\",\"name\":\"tfo-$1\",\"key_type\":\"gpg\",\"algorithm\":\"rsa2048\",\"uid_name\":\"DTF Terraform\",\"uid_email\":\"tfo@dtf.invalid\"}" \
    > "$W/key-$1.json" 2>/dev/null || true
  kid="$(jqr '.id // empty' < "$W/key-$1.json")"
  [ -n "$kid" ] || return 1
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/signing/repositories/${rid}/config" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"signing_key_id\":\"${kid}\",\"sign_metadata\":true,\"sign_packages\":false,\"require_signatures\":false}")" || true
  [ "$code" = "200" ] || return 1
  echo "$kid"
}

# put_provider <repo> <type> <os> <arch> -> http code; zip at $W/<type>_<os>_<arch>.zip
put_provider(){
  local zip
  zip="$(bash "${DTF_DIR}/fixtures/terraform/build.sh" "$W" "$2" "$VER" "$3" "$4" "DTF-TFO-$2-$3-$4" 2>/dev/null)" || true
  [ -s "$zip" ] || { echo "nozip"; return 0; }
  cp "$zip" "$W/$2_$3_$4.zip"
  curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    --data-binary "@${zip}" "$BASE/terraform/$1/v1/providers/${NS}/$2/${VER}/$3/$4" || true
}

pv(){ echo "/terraform/$1/v1/providers/${NS}/$2/${VER}"; }   # provider version prefix

# gpg_verify <sig> <data> -> echoes the VALIDSIG fingerprint ("" when it does not verify)
gpg_verify(){ gpg --batch --status-fd 1 --verify "$1" "$2" 2>/dev/null | awk '$2=="VALIDSIG"{print tolower($3)}' | head -1 || true; }

# =============================================================================
begin_suite "terraform-origin-registry"

begin_test "setup: admin login, hosted Terraform repos (public, private, no-key), a generic repo, provider uploads"
TOK="$(admin_login)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
for c in gpg zip jq; do command -v "$c" >/dev/null 2>&1 || { infra_fail "$c missing on the harness host"; end_suite; }; done
SUF="${RUN_ID##*-}"
R_PUB="tfo-pub-${DTF_SLOT}-${SUF}"
R_PRIV="tfo-priv-${DTF_SLOT}-${SUF}"
R_NOKEY="tfo-nokey-${DTF_SLOT}-${SUF}"
R_GEN="tfo-gen-${DTF_SLOT}-${SUF}"
SETUP_ERR=""
[ "$(mk_repo "$R_PUB" terraform true)" = "$R_PUB" ] || SETUP_ERR="${SETUP_ERR} public"
[ "$(mk_repo "$R_PRIV" terraform false)" = "$R_PRIV" ] || SETUP_ERR="${SETUP_ERR} private"
[ "$(mk_repo "$R_NOKEY" terraform true)" = "$R_NOKEY" ] || SETUP_ERR="${SETUP_ERR} nokey"
[ "$(mk_repo "$R_GEN" generic true)" = "$R_GEN" ] || SETUP_ERR="${SETUP_ERR} generic"
for spec in "$R_PUB demo linux amd64" "$R_PUB demo darwin arm64" "$R_PRIV sec linux amd64" "$R_NOKEY plain linux amd64"; do
  # shellcheck disable=SC2086
  set -- $spec
  c="$(put_provider "$1" "$2" "$3" "$4")"
  [ "$c" = "201" ] || SETUP_ERR="${SETUP_ERR} upload($1/$2/$3_$4)=${c}"
done
attach_gpg_key "$R_PUB" >/dev/null || SETUP_ERR="${SETUP_ERR} key(public)"
attach_gpg_key "$R_PRIV" >/dev/null || SETUP_ERR="${SETUP_ERR} key(private)"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
FPR_PUB="$(jqr '.fingerprint // empty' < "$W/key-${R_PUB}.json" | tr 'A-F' 'a-f')"
KEYID_PUB="$(jqr '.key_id // empty' < "$W/key-${R_PUB}.json")"
FPR_PRIV="$(jqr '.fingerprint // empty' < "$W/key-${R_PRIV}.json" | tr 'A-F' 'a-f')"
SHA_LIN="$(sha_of "$W/demo_linux_amd64.zip")"
SHA_DAR="$(sha_of "$W/demo_darwin_arm64.zip")"
SHA_SEC="$(sha_of "$W/sec_linux_amd64.zip")"
echo "-- repos: ${R_PUB} (key ${KEYID_PUB}), ${R_PRIV}, ${R_NOKEY}, ${R_GEN}"
pass

# =============================================================================
# CONTROL (both images): the pre-existing Terraform surface.
# =============================================================================
begin_test "CONTROL: module upload, versions, download (X-Terraform-Get) and archive bytes; per-repo discovery"
reset_case
mkdir -p "$W/mod" && printf 'variable "x" {}\n' > "$W/mod/main.tf"
tar -czf "$W/mod.tgz" -C "$W/mod" main.tf
c="$(aget "$W/m.put" "/terraform/${R_PUB}/v1/modules/${NS}/net/aws/0.1.0" -X PUT --data-binary "@$W/mod.tgz")"
[ "$c" = "201" ] || fail_g "module upload HTTP ${c}: $(head -c 200 "$W/m.put")"
c="$(get "$W/m.ver" "/terraform/${R_PUB}/v1/modules/${NS}/net/aws/versions")"
[ "$c" = "200" ] && [ "$(jqr '.modules[0].versions[0].version' < "$W/m.ver")" = "0.1.0" ] \
  || fail_g "module versions HTTP ${c}: $(head -c 200 "$W/m.ver")"
loc="$(curl -s -D - -o /dev/null --max-time 30 "$BASE/terraform/${R_PUB}/v1/modules/${NS}/net/aws/0.1.0/download" \
  | awk 'tolower($1)=="x-terraform-get:"{print $2}' | tr -d '\r')" || true
note "X-Terraform-Get: ${loc}"
[ -n "$loc" ] || fail_g "module download carried no X-Terraform-Get"
c="$(get "$W/m.arc" "${loc:-/nonexistent}")"
[ "$c" = "200" ] && [ "$(sha_of "$W/m.arc")" = "$(sha_of "$W/mod.tgz")" ] \
  || fail_g "module archive HTTP ${c}, sha $(sha_of "$W/m.arc") != uploaded $(sha_of "$W/mod.tgz")"
c="$(get "$W/disc" "/terraform/${R_PUB}/.well-known/terraform.json")"
[ "$c" = "200" ] && [ "$(jqr '."providers.v1"' < "$W/disc")" = "/terraform/${R_PUB}/v1/providers/" ] \
  || fail_g "per-repo discovery HTTP ${c}: $(head -c 200 "$W/disc")"
finish_case "the existing Terraform module / per-repo discovery routes regressed"

begin_test "CONTROL: provider versions list and package document core fields; download_url streams the uploaded zip"
reset_case
c="$(get "$W/vers" "/terraform/${R_PUB}/v1/providers/${NS}/demo/versions")"
note "versions: HTTP ${c} $(head -c 300 "$W/vers")"
[ "$c" = "200" ] || fail_g "versions HTTP ${c}"
[ "$(jqr '.versions[0].version' < "$W/vers")" = "$VER" ] || fail_g "versions[0].version != ${VER}"
[ "$(jqr '[.versions[0].platforms[] | "\(.os)_\(.arch)"] | sort | join(",")' < "$W/vers")" = "darwin_arm64,linux_amd64" ] \
  || fail_g "versions[0].platforms is not {darwin_arm64, linux_amd64}"
[ "$(jqr '.versions[0].protocols | join(",")' < "$W/vers")" = "5.0" ] || fail_g "versions[0].protocols != [\"5.0\"]"
c="$(get "$W/doc.nokey" "$(pv "$R_NOKEY" plain)/download/linux/amd64")"
[ "$c" = "200" ] || fail_g "no-key package document HTTP ${c}"
[ "$(jqr '.filename' < "$W/doc.nokey")" = "terraform-provider-plain_${VER}_linux_amd64.zip" ] || fail_g "filename wrong: $(head -c 300 "$W/doc.nokey")"
[ "$(jqr '.shasum' < "$W/doc.nokey")" = "$(sha_of "$W/plain_linux_amd64.zip")" ] || fail_g "shasum != uploaded zip sha"
[ "$(jqr '.os + "_" + .arch' < "$W/doc.nokey")" = "linux_amd64" ] || fail_g "os/arch wrong"
u="$(jqr '.download_url // empty' < "$W/doc.nokey")"
c="$(get "$W/bin.nokey" "${u:-/nonexistent}")"
note "download_url ${u} -> HTTP ${c}"
[ "$c" = "200" ] && [ "$(sha_of "$W/bin.nokey")" = "$(sha_of "$W/plain_linux_amd64.zip")" ] \
  || fail_g "download_url did not stream the uploaded zip (HTTP ${c})"
# No key configured: the legacy, unsigned shape is kept on both images.
[ "$(jqr '.signing_keys.gpg_public_keys | length' < "$W/doc.nokey")" = "0" ] || fail_g "no-key document advertises a public key"
[ -z "$(jqr '.shasums_url // empty' < "$W/doc.nokey")" ] || fail_g "no-key document advertises shasums_url"
finish_case "the existing provider registry routes regressed"

# 1.11.3 has no such route and its auth middleware answers 401 for the
# unknown path; the fixed image answers the generic 404. Neither serves a
# document, which is what this control holds on both images.
begin_test "CONTROL: host-level /.well-known/terraform.json serves no document while TERRAFORM_DEFAULT_REPO is unset"
reset_case
c="$(get "$W/hd.unset" "/.well-known/terraform.json")"
note "unset: HTTP ${c} body: $(head -c 120 "$W/hd.unset")"
echo "$c" > "$W/hd.unset.code"
case "$c" in 401|404) ;; *) fail_g "host discovery answered HTTP ${c} with no default repo configured (expected 404, or 401 on a pre-#4357 image)" ;; esac
[ -z "$(jqr '."providers.v1" // empty' < "$W/hd.unset")" ] || fail_g "host discovery advertised a providers.v1 with no default repo"
finish_case "host discovery must stay off unless TERRAFORM_DEFAULT_REPO is set"

# =============================================================================
# FIX (#4356): host-level discovery.
# =============================================================================
begin_test "setup: recreate the backend with TERRAFORM_DEFAULT_REPO=${R_PUB}"
if recreate_backend "$R_PUB"; then
  TOK="$(admin_login)"
  if [ -n "$TOK" ]; then pass; else infra_fail "admin login failed after the backend recreate"; end_suite; fi
else
  infra_fail "could not recreate the backend with TERRAFORM_DEFAULT_REPO"; end_suite
fi

begin_test "FIX #4356: GET /.well-known/terraform.json at the host root names the default repo's providers endpoint (anonymous)"
reset_case
hd_hdr="$W/hd.hdr"
c="$(get "$W/hd" "/.well-known/terraform.json" -D "$hd_hdr")"
note "HTTP ${c} body: $(head -c 200 "$W/hd")"
[ "$c" = "200" ] || fail_g "host discovery HTTP ${c}, expected 200"
[ "$(jqr '."providers.v1" // empty' < "$W/hd")" = "/terraform/${R_PUB}/v1/providers/" ] \
  || fail_g "providers.v1 != /terraform/${R_PUB}/v1/providers/"
grep -qi '^content-type: application/json' "$hd_hdr" || fail_g "content-type is not application/json"
finish_case "host-level service discovery (#4356) is not served"

# =============================================================================
# FIX (#4356): signed package document, SHA256SUMS, SHA256SUMS.sig.
# =============================================================================
begin_test "FIX #4356: the package document advertises shasums_url, shasums_signature_url and the repo's OpenPGP public key"
reset_case
c="$(get "$W/doc.pub" "$(pv "$R_PUB" demo)/download/linux/amd64")"
note "HTTP ${c} $(jq -c '.signing_keys.gpg_public_keys |= map(del(.ascii_armor))' < "$W/doc.pub" 2>/dev/null | head -c 600)"
[ "$c" = "200" ] || fail_g "package document HTTP ${c}"
[ "$(jqr '.shasums_url // empty' < "$W/doc.pub")" = "$(pv "$R_PUB" demo)/SHA256SUMS" ] || fail_g "shasums_url missing or wrong"
[ "$(jqr '.shasums_signature_url // empty' < "$W/doc.pub")" = "$(pv "$R_PUB" demo)/SHA256SUMS.sig" ] || fail_g "shasums_signature_url missing or wrong"
[ "$(jqr '.signing_keys.gpg_public_keys | length' < "$W/doc.pub")" = "1" ] || fail_g "gpg_public_keys does not hold exactly one key"
[ "$(jqr '.signing_keys.gpg_public_keys[0].key_id // empty' < "$W/doc.pub" | tr 'A-F' 'a-f')" = "$(echo "$KEYID_PUB" | tr 'A-F' 'a-f')" ] \
  || fail_g "gpg_public_keys[0].key_id != the repo key's key_id ${KEYID_PUB}"
jqr '.signing_keys.gpg_public_keys[0].ascii_armor // empty' < "$W/doc.pub" > "$W/pub.asc"
grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$W/pub.asc" || fail_g "ascii_armor is not an armored public key"
grep -q 'PRIVATE KEY' "$W/pub.asc" && fail_g "ascii_armor carries PRIVATE key material"
[ "$(jqr '.download_url' < "$W/doc.pub")" = "$(pv "$R_PUB" demo)/binary/linux/amd64" ] \
  || fail_g "anonymous public-repo download_url is not the plain binary path"
finish_case "the package document does not advertise the signed checksum list (#4356)"

begin_test "FIX #4356: SHA256SUMS lists every platform's real sha256, sorted, and is byte-identical across requests"
reset_case
exp="$W/sums.expected"
{ printf '%s  terraform-provider-demo_%s_darwin_arm64.zip\n' "$SHA_DAR" "$VER"
  printf '%s  terraform-provider-demo_%s_linux_amd64.zip\n' "$SHA_LIN" "$VER"; } > "$exp"
c1="$(get "$W/sums.1" "$(pv "$R_PUB" demo)/SHA256SUMS")"
c2="$(get "$W/sums.2" "$(pv "$R_PUB" demo)/SHA256SUMS")"
note "HTTP ${c1}/${c2}; body:"; note "$(head -c 400 "$W/sums.1")"
[ "$c1" = "200" ] && [ "$c2" = "200" ] || fail_g "SHA256SUMS HTTP ${c1}/${c2}"
cmp -s "$W/sums.1" "$exp" || fail_g "SHA256SUMS != the expected two lines (real sha256 of each uploaded zip, sorted by filename)"
cmp -s "$W/sums.1" "$W/sums.2" || fail_g "SHA256SUMS differs between two requests"
finish_case "SHA256SUMS is missing or wrong (#4356)"

begin_test "FIX #4356: SHA256SUMS.sig is a binary detached signature that gpg verifies against the served public key; tampering breaks it"
reset_case
sh="$W/sig.hdr"
c="$(get "$W/sums.sig" "$(pv "$R_PUB" demo)/SHA256SUMS.sig" -D "$sh")"
note "HTTP ${c}, $(wc -c < "$W/sums.sig" | tr -d ' ') bytes"
[ "$c" = "200" ] || fail_g "SHA256SUMS.sig HTTP ${c}"
grep -qi '^content-type: application/pgp-signature' "$sh" || fail_g "content-type is not application/pgp-signature"
head -c 5 "$W/sums.sig" | grep -q -- '-----' && fail_g "signature is ASCII-armored; Terraform/OpenTofu read binary packets"
gpg --batch --import "$W/pub.asc" >/dev/null 2>&1 || true
vs="$(gpg_verify "$W/sums.sig" "$W/sums.1")"
note "VALIDSIG ${vs:-<none>}, repo key fingerprint ${FPR_PUB}"
[ -n "$vs" ] && [ "$vs" = "$FPR_PUB" ] || fail_g "SHA256SUMS.sig does not verify with the served key (fingerprint ${FPR_PUB})"
sed 's/^./0/' "$W/sums.1" > "$W/sums.tampered"
[ -z "$(gpg_verify "$W/sums.sig" "$W/sums.tampered")" ] || fail_g "the signature also verified a tampered SHA256SUMS"
c="$(get "$W/sums.sig2" "$(pv "$R_PUB" demo)/SHA256SUMS.sig")"
[ "$c" = "200" ] && [ -n "$(gpg_verify "$W/sums.sig2" "$W/sums.2")" ] || fail_g "a second .sig fetch did not verify (HTTP ${c})"
finish_case "SHA256SUMS.sig is missing or does not verify (#4356)"

begin_test "FIX #4356: with no signing key the checksum routes fail closed (404 naming the missing key), never unsigned data"
reset_case
c1="$(get "$W/nk.sums" "$(pv "$R_NOKEY" plain)/SHA256SUMS")"
c2="$(get "$W/nk.sig" "$(pv "$R_NOKEY" plain)/SHA256SUMS.sig")"
note "SHA256SUMS HTTP ${c1}: $(head -c 120 "$W/nk.sums")"
note "SHA256SUMS.sig HTTP ${c2}: $(head -c 120 "$W/nk.sig")"
[ "$c1" = "404" ] && [ "$c2" = "404" ] || fail_g "no-key checksum routes answered ${c1}/${c2}, expected 404/404"
grep -qi 'signing key' "$W/nk.sums" || fail_g "SHA256SUMS 404 does not name the missing signing key (route absent?)"
grep -qi 'signing key' "$W/nk.sig" || fail_g "SHA256SUMS.sig 404 does not name the missing signing key (route absent?)"
grep -q "$(sha_of "$W/plain_linux_amd64.zip")" "$W/nk.sums" && fail_g "the no-key SHA256SUMS response carried the checksum list unsigned"
finish_case "the checksum routes do not fail closed without a signing key (#4356)"

# =============================================================================
# FIX (#4357 maintainer change): single-use path-bound tickets, private repo.
# =============================================================================
begin_test "FIX #4357: private repo, authenticated caller: download/shasums/signature URLs carry single-use path-bound tickets"
reset_case
c="$(aget "$W/doc.priv" "$(pv "$R_PRIV" sec)/download/linux/amd64")"
note "authenticated package document HTTP ${c}"
[ "$c" = "200" ] || fail_g "authenticated private package document HTTP ${c}"
U_BIN="$(jqr '.download_url // empty' < "$W/doc.priv")"
U_SUM="$(jqr '.shasums_url // empty' < "$W/doc.priv")"
U_SIG="$(jqr '.shasums_signature_url // empty' < "$W/doc.priv")"
for pair in "download_url|$U_BIN|$(pv "$R_PRIV" sec)/binary/linux/amd64" \
            "shasums_url|$U_SUM|$(pv "$R_PRIV" sec)/SHA256SUMS" \
            "shasums_signature_url|$U_SIG|$(pv "$R_PRIV" sec)/SHA256SUMS.sig"; do
  IFS='|' read -r f u p <<<"$pair"
  note "${f}: ${u:0:120}"
  case "$u" in "${p}?ticket="?*) ;; *) fail_g "${f} is not ${p}?ticket=<t>" ;; esac
done
# Cross-path: the shasums ticket must not open the signature path. Use a fresh document so
# the first-use checks below still hold their own tickets.
aget "$W/doc.priv.x" "$(pv "$R_PRIV" sec)/download/linux/amd64" >/dev/null
xt="$(jqr '.shasums_url // empty' < "$W/doc.priv.x")"; xt="${xt#*ticket=}"
if [ -n "$xt" ] && [ "$xt" != "$(jqr '.shasums_url // empty' < "$W/doc.priv.x")" ]; then
  c="$(get "$W/x.sig" "$(pv "$R_PRIV" sec)/SHA256SUMS.sig?ticket=${xt}")"
  note "shasums ticket presented on the .sig path: HTTP ${c}"
  case "$c" in 401|403|404) ;; *) fail_g "a SHA256SUMS ticket opened SHA256SUMS.sig (HTTP ${c})" ;; esac
fi
# First use (no credentials) works and serves the right bytes; the second is refused.
c="$(get "$W/t.bin" "${U_BIN:-/nonexistent}")"; c_b2="$(get "$W/t.bin2" "${U_BIN:-/nonexistent}")"
c_s="$(get "$W/t.sum" "${U_SUM:-/nonexistent}")"; c_s2="$(get "$W/t.sum2" "${U_SUM:-/nonexistent}")"
c_g="$(get "$W/t.sig" "${U_SIG:-/nonexistent}")"; c_g2="$(get "$W/t.sig2" "${U_SIG:-/nonexistent}")"
note "unauthenticated first/second use: binary ${c}/${c_b2}, SHA256SUMS ${c_s}/${c_s2}, .sig ${c_g}/${c_g2}"
[ "$c" = "200" ] && [ "$(sha_of "$W/t.bin")" = "$SHA_SEC" ] || fail_g "ticketed download_url first use: HTTP ${c}, not the uploaded zip"
[ "$c_s" = "200" ] && [ "$(cat "$W/t.sum" 2>/dev/null)" = "${SHA_SEC}  terraform-provider-sec_${VER}_linux_amd64.zip" ] \
  || fail_g "ticketed shasums_url first use: HTTP ${c_s}, body $(head -c 120 "$W/t.sum")"
[ "$c_g" = "200" ] || fail_g "ticketed shasums_signature_url first use: HTTP ${c_g}"
jqr '.signing_keys.gpg_public_keys[0].ascii_armor // empty' < "$W/doc.priv" > "$W/priv.asc"
gpg --batch --import "$W/priv.asc" >/dev/null 2>&1 || true
[ "$c_g" = "200" ] && [ "$(gpg_verify "$W/t.sig" "$W/t.sum")" = "$FPR_PRIV" ] || fail_g "ticketed .sig does not verify the ticketed SHA256SUMS with the private repo's key"
for pc in "binary:$c_b2" "SHA256SUMS:$c_s2" ".sig:$c_g2"; do
  case "${pc#*:}" in 401|403|404) ;; *) fail_g "second use of the ${pc%%:*} ticket answered HTTP ${pc#*:}, expected a refusal" ;; esac
done
finish_case "private-repo package document URLs are not ticketed, or tickets are reusable (#4357)"

begin_test "CONTROL: private repo, anonymous caller: the package document and the plain binary/checksum paths are refused"
reset_case
c="$(get "$W/a.doc" "$(pv "$R_PRIV" sec)/download/linux/amd64")"
note "anonymous package document HTTP ${c}"
case "$c" in 401|403|404) ;; *) fail_g "anonymous private package document HTTP ${c}" ;; esac
grep -q "ticket=" "$W/a.doc" && fail_g "an anonymous caller was handed a ticket"
for s in binary/linux/amd64 SHA256SUMS SHA256SUMS.sig; do
  c="$(get "$W/a.x" "$(pv "$R_PRIV" sec)/${s}")"
  note "anonymous ${s}: HTTP ${c}"
  case "$c" in 401|403|404) ;; *) fail_g "anonymous plain ${s} on a private repo answered HTTP ${c}" ;; esac
  grep -q "$SHA_SEC" "$W/a.x" && fail_g "anonymous ${s} leaked the checksum"
done
finish_case "a private repository's provider routes are reachable anonymously"

# =============================================================================
# FIX (#4356): a real Terraform client installs from the origin registry.
# =============================================================================
begin_test "FIX #4356: real terraform 'providers lock' resolves ${TF_HOST}/${NS}/demo via host discovery and verifies the signature"
reset_case
ca="$W/caddy-root.crt"
if ! docker cp "${TF_CADDY}:/data/caddy/pki/authorities/local/root.crt" "$ca" >/dev/null 2>&1 \
   || ! docker cp "$ca" "${TF_CLIENT}:/usr/local/share/ca-certificates/dtf-caddy-root.crt" >/dev/null 2>&1; then
  infra_fail "could not install caddy's internal CA into ${TF_CLIENT}"
else
  docker exec -u root "$TF_CLIENT" sh -c 'update-ca-certificates >/dev/null 2>&1 || true'
  docker exec -u root "$TF_CLIENT" sh -c "rm -rf /root/tfo /root/.terraformrc && mkdir -p /root/tfo && cat > /root/tfo/main.tf <<EOF
terraform {
  required_providers {
    demo = { source = \"${TF_HOST}/${NS}/demo\", version = \"${VER}\" }
  }
}
EOF" >/dev/null 2>&1 || true
  rc=0
  out="$(docker exec -u root -w /root/tfo "$TF_CLIENT" timeout 180 terraform providers lock -no-color \
    -platform=linux_amd64 -platform=darwin_arm64 2>&1)" || rc=$?
  note "terraform rc ${rc}:"; note "$(echo "$out" | head -12)"
  lock="$(docker exec "$TF_CLIENT" cat /root/tfo/.terraform.lock.hcl 2>/dev/null || true)"
  [ "$rc" -eq 0 ] || fail_g "terraform providers lock failed"
  echo "$out" | grep -Eqi "signed, key ID $(echo "$KEYID_PUB" | tr 'a-f' 'A-F')" \
    || fail_g "terraform did not report the provider as signed by key ${KEYID_PUB}"
  echo "$lock" | grep -q "zh:${SHA_LIN}" || fail_g "lock file lacks zh:${SHA_LIN} (linux_amd64)"
  echo "$lock" | grep -q "zh:${SHA_DAR}" || fail_g "lock file lacks zh:${SHA_DAR} (darwin_arm64)"
fi
finish_case "a real Terraform client cannot use the hosted repo as an origin registry (#4356)"

# =============================================================================
# CONTROL (both images): an unusable default repo answers the same generic 404.
# =============================================================================
begin_test "CONTROL: TERRAFORM_DEFAULT_REPO naming a non-Terraform repo serves no document, the same response as unset"
reset_case
if recreate_backend "$R_GEN"; then
  c="$(get "$W/hd.gen" "/.well-known/terraform.json")"
  note "default=${R_GEN} (generic): HTTP ${c} body: $(head -c 120 "$W/hd.gen")"
  [ "$c" = "$(cat "$W/hd.unset.code" 2>/dev/null)" ] || fail_g "host discovery answered HTTP ${c} for a non-Terraform default repo, unset answered $(cat "$W/hd.unset.code" 2>/dev/null)"
  cmp -s "$W/hd.gen" "$W/hd.unset" || fail_g "404 body differs from the unset case (probe oracle for repo keys/formats)"
  grep -q "$R_GEN" "$W/hd.gen" && fail_g "404 body names the configured repository"
else
  fail_g "could not recreate the backend with TERRAFORM_DEFAULT_REPO=${R_GEN}"
fi
finish_case "host discovery leaks or misbehaves for an unusable default repo"

end_suite
