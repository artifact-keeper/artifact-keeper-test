#!/usr/bin/env bash
# =============================================================================
# tiers/conda-allowlist-hosted-members/oracle.sh: a virtual conda channel's
#   package allowlist applies to its HOSTED members too (artifact-keeper#5055)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda client.conda` and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. The mock channel
# publishes dtfup-alpha 1.0 + 2.0 and dtfup-blocked 1.0 (noarch).
#
# Topology (keys suffixed per run):
#   H  public hosted channel: dtfal-listed 1.0 (on the list), dtfal-hidden 1.0
#      (not on the list), dtfup-alpha 0.5 (not on the list; the upstream also
#      publishes the name, so H owns it)
#   R  remote -> mock         V  virtual {H, R}
#   V's allowlist admits dtfal-listed and dtfup-blocked.
#
# Every FIX case is RED on 1.11.8 (hosted members pass the list unfiltered;
# `scope` is an unknown field) and GREEN on the fix; every CONTROL holds on
# both. The `micromamba` cases are a real client solving against the channel.
#
# The other surfaces #5058 filters (RED on sha-b2d0bcc, the parent of the fix
# on main): the CEP-16 shard index and the shards it addresses, run_exports.json
# and the CEP-50 `.sigs` / `.sigs.<sha256>` sidecars of a hosted package. For
# the sidecars the backend is recreated at the start of setup with a P-256 key
# the oracle generates (fixtures/attestation-key.yml); the listed and the
# hidden hosted package each get one bundle signed with it (the signer is
# conda-attestation-trust/fixtures/sign_bundle.py). The `.msgpack.zst`
# documents are decoded by conda-sharded-remote-virtual/fixtures/cep16.py in a
# throwaway python:3.14-slim container.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on it
# explicitly, so a non-zero helper must not end the suite before its assertion.
set +e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
UPSTREAM="http://172.16.${SLOT}.70/"
CLIENT_CTR="ak-dtf${SLOT}-client-conda"

H="cah-host-${SUF}"
R="cah-remote-${SUF}"
V="cah-virt-${SUF}"

LISTED="dtfal-listed-1.0-0.tar.bz2"
HIDDEN="dtfal-hidden-1.0-0.tar.bz2"
OWNED="dtfup-alpha-0.5-0.tar.bz2"       # hosted, not listed, name owned by H
UP_ALPHA="dtfup-alpha-2.0-0.tar.bz2"    # upstream record of the owned name
UP_BLOCKED="dtfup-blocked-1.0-0.tar.bz2" # upstream record the list admits

PROJECT="ak-dtf${SLOT}"
SIGNER="${DTF_DIR}/harness/tiers/conda-attestation-trust/fixtures/sign_bundle.py"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
DECODER_IMAGE="docker.io/library/python:3.14-slim"
IDX="/noarch/repodata_shards.msgpack.zst"

WORK="$(mktemp -d -t dtf-cah-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# hget PATH OUTFILE [curl args...] -> HTTP status; headers in OUTFILE.hdr
hget() {
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -D "${out}.hdr" -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
conda_put() {  # conda_put <repo> <file> <filename> -> status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$2" \
    "${BASE_URL}/conda/$1/noarch/$3" 2>/dev/null || echo 000
}
# put_allowlist <json> -> status; body in $WORK/allowlist.json
put_allowlist() {
  curl -s --max-time 30 -o "$WORK/allowlist.json" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" -H 'Content-Type: application/json' -d "$1" \
    "${BASE_URL}/api/v1/repositories/${V}/allowlist" 2>/dev/null || echo 000
}
# keys FILE -> the record filenames of a repodata-shaped document, as JSON
keys() { jq -c '[(.packages // {}), (.["packages.conda"] // {})] | add | keys' "$1" 2>/dev/null; }
# has FILE NAME... -> 0 when the repodata-shaped FILE lists every NAME
has() {
  local f="$1"; shift
  local n
  for n in "$@"; do
    jq -e --arg n "$n" '[(.packages // {}), (.["packages.conda"] // {})] | add | has($n)' "$f" >/dev/null 2>&1 || return 1
  done
}
lacks() {
  local f="$1"; shift
  local n
  for n in "$@"; do
    jq -e --arg n "$n" '[(.packages // {}), (.["packages.conda"] // {})] | add | has($n) | not' "$f" >/dev/null 2>&1 || return 1
  done
}
# recreate_backend: recreate only the backend with the trusted-key override
# (postgres, the data volume, the mock and the client stay), wait for health.
recreate_backend() {
  local -a files=(-f "${DTF_DIR}/compose.base.yml")
  local prof
  for prof in storage.filesystem upstreams.mock-conda client.conda; do
    files+=(-f "${DTF_DIR}/profiles/${prof}.yml")
  done
  files+=(-f "${HERE}/fixtures/attestation-key.yml")
  docker compose -p "$PROJECT" "${files[@]}" \
    up -d --no-deps --force-recreate --wait backend >"$WORK/recreate.log" 2>&1
}
# att_put <repo> <pkg filename> <bundle file> -> status; body in $WORK/att.out
att_put() {
  curl -s --max-time 60 -o "$WORK/att.out" -w '%{http_code}' -X PUT -H "$(auth_header)" \
    -H 'Content-Type: application/json' --data-binary "@$3" \
    "${BASE_URL}/conda/$1/noarch/$2/attestation" 2>/dev/null || echo 000
}
# decode <file> -> 0 when the CEP-16 document decodes; JSON report in <file>.json
decode() {
  docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
    "$DECODER_IMAGE" python3 -I /app/cep16.py < "$1" > "$1.json" 2>/dev/null \
    && jq -e 'has("doc")' "$1.json" >/dev/null 2>&1
}
# shard_names <decoded index json> -> the package names the index lists, as JSON
shard_names() { jq -c '.doc.shards // {} | keys' "$1" 2>/dev/null; }
# shard_addr <decoded index json> <name> -> the hex address of that name's shard
shard_addr() { jq -r --arg n "$2" '.doc.shards[$n].bin // empty' "$1" 2>/dev/null; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# mm_install <tag> <spec> -> micromamba's exit status; output in $WORK/mm-<tag>.log.
# A fresh root prefix per call, so no repodata cache carries over between calls.
mm_install() {
  docker exec -u root "$CLIENT_CTR" sh -c "export MAMBA_ROOT_PREFIX=/tmp/mamba-$1 HOME=/tmp CONDA_ALLOW_INSECURE=1; \
micromamba create -y -p /tmp/env-$1 --no-rc --override-channels -c 'http://backend:8080/conda/${V}' '$2'" \
    >"$WORK/mm-$1.log" 2>&1
}

begin_suite "conda-allowlist-hosted-members (#5055)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: trusted key, admin auth, repositories, uploads, attestations, client"
setup_err=""
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/k.key" 2>/dev/null \
  && openssl pkey -in "$WORK/k.key" -pubout -out "$WORK/k.pub" 2>/dev/null \
  || setup_err+="generate signing key; "
DTF_CAH_KEYS="dtf-cah=$(cat "$WORK/k.pub" 2>/dev/null)"
export DTF_CAH_KEYS
if [ -z "$setup_err" ] && ! recreate_backend; then
  setup_err+="recreate backend with the trusted key: $(tail -5 "$WORK/recreate.log" | tr '\n' ' '); "
fi
auth_admin
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$R" conda remote "$UPSTREAM" || setup_err+="create remote; "
create_repo "$V" conda virtual || setup_err+="create virtual; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${H}\"}" >/dev/null || setup_err+="add H to V; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\"}" >/dev/null || setup_err+="add R to V; "
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
bash "$BUILD" "$WORK" dtfal-listed 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${LISTED}; "
bash "$BUILD" "$WORK" dtfal-hidden 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build ${HIDDEN}; "
bash "$BUILD" "$WORK" dtfup-alpha 0.5 0 noarch >/dev/null 2>&1 || setup_err+="build ${OWNED}; "
for f in "$LISTED" "$HIDDEN" "$OWNED"; do
  st="$(conda_put "$H" "$WORK/$f" "$f")"
  [ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="upload ${f} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); "
done
for f in "$LISTED" "$HIDDEN"; do
  python3 -I "$SIGNER" --key "$WORK/k.key" --hint-pub "$WORK/k.pub" --name "$f" \
    --sha256 "$(sha_of "$WORK/$f")" --out "$WORK/$f.bundle.json" >/dev/null 2>"$WORK/sign.err" \
    || setup_err+="sign ${f}: $(head -c 200 "$WORK/sign.err"); "
  st="$(att_put "$H" "$f" "$WORK/$f.bundle.json")"
  [ "$st" = "201" ] || [ "$st" = "200" ] || setup_err+="attest ${f} -> HTTP ${st} $(head -c 200 "$WORK/att.out"); "
done
docker image inspect "$DECODER_IMAGE" >/dev/null 2>&1 || docker pull -q "$DECODER_IMAGE" >/dev/null 2>&1 \
  || setup_err+="pull ${DECODER_IMAGE}; "
docker exec "$CLIENT_CTR" sh -c 'command -v micromamba' >/dev/null 2>&1 || setup_err+="micromamba client missing; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# Before any list: the virtual serves the hosted packages and the remote's.
hget "/conda/${V}/noarch/repodata.json" "$WORK/v_pre.json" >/dev/null

begin_test "CONTROL: an allowlist without scope is accepted on the virtual"
st="$(put_allowlist "{\"enabled\":true,\"entries\":[{\"name\":\"dtfal-listed\"},{\"name\":\"dtfup-blocked\"}]}")"
if [ "$st" = "200" ] && jq -e '.enabled == true and .entry_count == 2' "$WORK/allowlist.json" >/dev/null 2>&1; then
  pass
else
  fail "PUT allowlist: HTTP ${st}" "$(head -c 300 "$WORK/allowlist.json")"
fi

# =============================================================================
# The index, every form
# =============================================================================
st_rd="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_rd.json")"

begin_test "CONTROL: virtual repodata.json lists the listed hosted package and the admitted remote one"
if [ "$st_rd" = "200" ] && has "$WORK/v_rd.json" "$LISTED" "$UP_BLOCKED"; then
  pass
else
  fail "admitted records missing (HTTP ${st_rd})" "keys=$(keys "$WORK/v_rd.json")"
fi

begin_test "FIX #5055: virtual repodata.json does not list a hosted package the allowlist does not admit"
if [ "$st_rd" = "200" ] && lacks "$WORK/v_rd.json" "$HIDDEN"; then
  pass
else
  fail "the virtual serves hosted ${HIDDEN} outside its allowlist (HTTP ${st_rd})" "keys=$(keys "$WORK/v_rd.json")"
fi

begin_test "FIX #5055: an unlisted hosted package is dropped and still owns its name (no upstream dtfup-alpha either)"
if [ "$st_rd" = "200" ] \
   && jq -e '[(.packages // {}), (.["packages.conda"] // {})] | add | [.[] | select(.name == "dtfup-alpha")] | length == 0' \
        "$WORK/v_rd.json" >/dev/null 2>&1; then
  pass
else
  fail "dtfup-alpha records in the virtual: the hosted one is not on the list, the upstream's are owned out" \
    "keys=$(keys "$WORK/v_rd.json")"
fi

begin_test "FIX #5055: repodata.json.zst does not list the unlisted hosted package"
st="$(hget "/conda/${V}/noarch/repodata.json.zst" "$WORK/v_rd.zst")"
if [ "$st" = "200" ] && zstd -dcq "$WORK/v_rd.zst" >"$WORK/v_rd_zst.json" 2>/dev/null \
   && has "$WORK/v_rd_zst.json" "$LISTED" && lacks "$WORK/v_rd_zst.json" "$HIDDEN"; then
  pass
else
  fail "repodata.json.zst: HTTP ${st}" "keys=$(keys "$WORK/v_rd_zst.json")"
fi

begin_test "FIX #5055: repodata.json.bz2 does not list the unlisted hosted package"
st="$(hget "/conda/${V}/noarch/repodata.json.bz2" "$WORK/v_rd.bz2")"
if [ "$st" = "200" ] && bzip2 -dc "$WORK/v_rd.bz2" >"$WORK/v_rd_bz2.json" 2>/dev/null \
   && has "$WORK/v_rd_bz2.json" "$LISTED" && lacks "$WORK/v_rd_bz2.json" "$HIDDEN"; then
  pass
else
  fail "repodata.json.bz2: HTTP ${st}" "keys=$(keys "$WORK/v_rd_bz2.json")"
fi

begin_test "FIX #5055: current_repodata.json does not list the unlisted hosted package"
st="$(hget "/conda/${V}/noarch/current_repodata.json" "$WORK/v_cur.json")"
if [ "$st" = "200" ] && has "$WORK/v_cur.json" "$LISTED" && lacks "$WORK/v_cur.json" "$HIDDEN"; then
  pass
else
  fail "current_repodata.json: HTTP ${st}" "keys=$(keys "$WORK/v_cur.json")"
fi

begin_test "FIX #5055: channeldata.json names only admitted packages"
st="$(hget "/conda/${V}/channeldata.json" "$WORK/v_cd.json")"
if [ "$st" = "200" ] \
   && jq -e '.packages | has("dtfal-listed") and (has("dtfal-hidden") | not) and (has("dtfup-alpha") | not)' \
        "$WORK/v_cd.json" >/dev/null 2>&1; then
  pass
else
  fail "channeldata.json: HTTP ${st}" "$(jq -c '.packages | keys' "$WORK/v_cd.json" 2>/dev/null)"
fi

# =============================================================================
# The CEP-16 shard index and its shards, run_exports.json
# =============================================================================
# The hosted repository's own shard index gives the address of each hosted
# package's shard: a name the list admits whole keeps that shard in the virtual.
st_hidx="$(hget "/conda/${H}${IDX}" "$WORK/h_idx.bin")"
decode "$WORK/h_idx.bin"
A_LISTED="$(shard_addr "$WORK/h_idx.bin.json" dtfal-listed)"
A_HIDDEN="$(shard_addr "$WORK/h_idx.bin.json" dtfal-hidden)"
A_OWNED="$(shard_addr "$WORK/h_idx.bin.json" dtfup-alpha)"
st_vidx="$(hget "/conda/${V}${IDX}" "$WORK/v_idx.bin")"
decode "$WORK/v_idx.bin"

begin_test "CONTROL: the virtual's shard index lists the listed hosted package"
if [ "$st_hidx" = "200" ] && [ -n "$A_LISTED" ] && [ -n "$A_HIDDEN" ] && [ -n "$A_OWNED" ] \
   && [ "$st_vidx" = "200" ] && [ -n "$(shard_addr "$WORK/v_idx.bin.json" dtfal-listed)" ]; then
  pass
else
  fail "shard index: hosted HTTP ${st_hidx} names=$(shard_names "$WORK/h_idx.bin.json"); virtual HTTP ${st_vidx}" \
    "virtual names=$(shard_names "$WORK/v_idx.bin.json") $(head -c 200 "$WORK/v_idx.bin" | tr -dc '[:print:]')"
fi

begin_test "FIX #5055: the virtual's shard index does not list a hosted package the allowlist does not admit, nor its owned name"
if [ "$st_vidx" = "200" ] \
   && jq -e '.doc.shards | type == "object" and (has("dtfal-hidden") | not) and (has("dtfup-alpha") | not)' \
        "$WORK/v_idx.bin.json" >/dev/null 2>&1; then
  pass
else
  fail "the virtual's shard index lists hosted names outside its allowlist (HTTP ${st_vidx})" \
    "names=$(shard_names "$WORK/v_idx.bin.json")"
fi

begin_test "CONTROL: the listed hosted package's shard is served through the virtual by its address"
st="$(hget "/conda/${V}/noarch/shards/${A_LISTED:-none}.msgpack.zst" "$WORK/v_shard_listed.bin")"
if [ "$st" = "200" ] && [ "$(sha_of "$WORK/v_shard_listed.bin")" = "$A_LISTED" ]; then
  pass
else
  fail "listed shard ${A_LISTED:-none} through the virtual: HTTP ${st}" "$(head -c 200 "$WORK/v_shard_listed.bin" | tr -dc '[:print:]')"
fi

begin_test "FIX #5055: the shard of an unlisted hosted package (and of its owned name) is not served through the virtual"
st_h="$(hget "/conda/${V}/noarch/shards/${A_HIDDEN:-none}.msgpack.zst" "$WORK/v_shard_hidden.bin")"
st_o="$(hget "/conda/${V}/noarch/shards/${A_OWNED:-none}.msgpack.zst" "$WORK/v_shard_owned.bin")"
st_d="$(hget "/conda/${H}/noarch/shards/${A_HIDDEN:-none}.msgpack.zst" "$WORK/h_shard_hidden.bin")"
if [ -n "$A_HIDDEN" ] && [ -n "$A_OWNED" ] && [ "$st_h" = "404" ] && [ "$st_o" = "404" ] && [ "$st_d" = "200" ]; then
  pass
else
  fail "unlisted hosted shards through the virtual: dtfal-hidden HTTP ${st_h}, dtfup-alpha HTTP ${st_o} (want 404; the hosted repository itself: HTTP ${st_d})"
fi

st_re="$(hget "/conda/${V}/noarch/run_exports.json" "$WORK/v_re.json")"

begin_test "CONTROL: the virtual's run_exports.json lists the listed hosted package"
if [ "$st_re" = "200" ] && has "$WORK/v_re.json" "$LISTED"; then
  pass
else
  fail "run_exports.json: HTTP ${st_re}" "keys=$(keys "$WORK/v_re.json") $(head -c 200 "$WORK/v_re.json")"
fi

begin_test "FIX #5055: the virtual's run_exports.json does not list the unlisted hosted package nor the owned name"
if [ "$st_re" = "200" ] && lacks "$WORK/v_re.json" "$HIDDEN" "$OWNED" "$UP_ALPHA"; then
  pass
else
  fail "run_exports.json lists records outside the allowlist (HTTP ${st_re})" "keys=$(keys "$WORK/v_re.json")"
fi

# =============================================================================
# Downloads through the virtual
# =============================================================================
begin_test "FIX #5055: downloading the unlisted hosted package through the virtual is 404"
st="$(hget "/conda/${V}/noarch/${HIDDEN}" "$WORK/v_hidden.bin")"
st_none="$(hget "/conda/${V}/noarch/dtfal-nosuch-1.0-0.tar.bz2" "$WORK/v_none.bin")"
if [ "$st" = "404" ] && cmp -s "$WORK/v_hidden.bin" "$WORK/v_none.bin"; then
  pass
else
  fail "the virtual serves hosted ${HIDDEN} outside its allowlist: HTTP ${st} (absent package: HTTP ${st_none})"
fi

begin_test "CONTROL: the listed hosted package downloads through the virtual, byte for byte"
st="$(hget "/conda/${V}/noarch/${LISTED}" "$WORK/v_listed.bin")"
if [ "$st" = "200" ] && cmp -s "$WORK/v_listed.bin" "$WORK/${LISTED}"; then
  pass
else
  fail "listed hosted package through the virtual: HTTP ${st}"
fi

begin_test "CONTROL: the hosted repository itself still lists and serves the unlisted package"
st="$(hget "/conda/${H}/noarch/repodata.json" "$WORK/h_rd.json")"
st_dl="$(hget "/conda/${H}/noarch/${HIDDEN}" "$WORK/h_hidden.bin")"
if [ "$st" = "200" ] && has "$WORK/h_rd.json" "$HIDDEN" "$LISTED" "$OWNED" \
   && [ "$st_dl" = "200" ] && cmp -s "$WORK/h_hidden.bin" "$WORK/${HIDDEN}"; then
  pass
else
  fail "direct hosted read changed: repodata HTTP ${st}, download HTTP ${st_dl}" "keys=$(keys "$WORK/h_rd.json")"
fi

begin_test "CONTROL: the listed hosted package's .sigs sidecar is served through the virtual as the hosted one"
st_h="$(hget "/conda/${H}/noarch/${LISTED}.sigs" "$WORK/h_listed.sigs")"
st_v="$(hget "/conda/${V}/noarch/${LISTED}.sigs" "$WORK/v_listed.sigs")"
if [ "$st_h" = "200" ] && [ "$st_v" = "200" ] && cmp -s "$WORK/h_listed.sigs" "$WORK/v_listed.sigs" \
   && jq -e 'type == "array" and length == 1' "$WORK/v_listed.sigs" >/dev/null 2>&1; then
  pass
else
  fail "listed .sigs: hosted HTTP ${st_h}, virtual HTTP ${st_v}" "$(head -c 300 "$WORK/v_listed.sigs")"
fi

begin_test "CONTROL: the hosted repository itself serves the unlisted package's sidecars"
st="$(hget "/conda/${H}/noarch/${HIDDEN}.sigs" "$WORK/h_hidden.sigs")"
HIDDEN_SIGS_SHA="$(sha_of "$WORK/h_hidden.sigs")"
st_c="$(hget "/conda/${H}/noarch/${HIDDEN}.sigs.${HIDDEN_SIGS_SHA}" "$WORK/h_hidden.sigs_ca")"
if [ "$st" = "200" ] && [ "$st_c" = "200" ] && cmp -s "$WORK/h_hidden.sigs" "$WORK/h_hidden.sigs_ca"; then
  pass
else
  fail "direct hosted sidecars of ${HIDDEN}: .sigs HTTP ${st}, .sigs.<sha256> HTTP ${st_c}"
fi

begin_test "FIX #5055: the unlisted hosted package's .sigs and .sigs.<sha256> sidecars are 404 through the virtual"
st="$(hget "/conda/${V}/noarch/${HIDDEN}.sigs" "$WORK/v_hidden.sigs")"
st_c="$(hget "/conda/${V}/noarch/${HIDDEN}.sigs.${HIDDEN_SIGS_SHA}" "$WORK/v_hidden.sigs_ca")"
if [ "$st" = "404" ] && [ "$st_c" = "404" ]; then
  pass
else
  fail "the virtual serves the sidecars of hosted ${HIDDEN} outside its allowlist: .sigs HTTP ${st}, .sigs.<sha256> HTTP ${st_c}"
fi

# =============================================================================
# A real client
# =============================================================================
begin_test "CONTROL: micromamba installs the listed hosted package from the virtual"
if mm_install listed dtfal-listed \
   && docker exec "$CLIENT_CTR" test -f /tmp/env-listed/share/dtfal-listed/marker.txt; then
  pass
else
  fail "micromamba create dtfal-listed failed" "$(tail -c 600 "$WORK/mm-listed.log")"
fi

begin_test "FIX #5055: micromamba cannot resolve the unlisted hosted package from the virtual"
if ! mm_install hidden dtfal-hidden \
   && ! docker exec "$CLIENT_CTR" test -e /tmp/env-hidden/share/dtfal-hidden/marker.txt; then
  pass
else
  fail "micromamba installed ${HIDDEN} through a channel whose allowlist does not admit it" \
    "$(tail -c 600 "$WORK/mm-hidden.log")"
fi

# =============================================================================
# The opt-out and cache invalidation
# =============================================================================
begin_test "FIX #5055: scope remote_only is accepted and reported"
st="$(put_allowlist "{\"enabled\":true,\"scope\":\"remote_only\",\"entries\":[{\"name\":\"dtfal-listed\"},{\"name\":\"dtfup-blocked\"}]}")"
if [ "$st" = "200" ] && jq -e '.scope == "remote_only"' "$WORK/allowlist.json" >/dev/null 2>&1; then
  pass
else
  fail "PUT allowlist with scope remote_only: HTTP ${st}" "$(head -c 300 "$WORK/allowlist.json")"
fi

begin_test "FIX #5055: remote_only restores hosted pass-through at once (the kept merge is not served)"
st="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_opt.json")"
st_dl="$(hget "/conda/${V}/noarch/${HIDDEN}" "$WORK/v_opt_hidden.bin")"
if [ "$st" = "200" ] && has "$WORK/v_opt.json" "$HIDDEN" "$LISTED" "$OWNED" && lacks "$WORK/v_opt.json" "$UP_ALPHA" \
   && [ "$st_dl" = "200" ] && cmp -s "$WORK/v_opt_hidden.bin" "$WORK/${HIDDEN}"; then
  pass
else
  fail "after remote_only: repodata HTTP ${st}, hidden download HTTP ${st_dl}" "keys=$(keys "$WORK/v_opt.json")"
fi

begin_test "CONTROL: under remote_only the virtual lists and serves the hosted shard, run_exports record and sidecar of the unlisted package"
st_i="$(hget "/conda/${V}${IDX}" "$WORK/v_opt_idx.bin")"
decode "$WORK/v_opt_idx.bin"
st_s="$(hget "/conda/${V}/noarch/shards/${A_HIDDEN:-none}.msgpack.zst" "$WORK/v_opt_shard.bin")"
st_r="$(hget "/conda/${V}/noarch/run_exports.json" "$WORK/v_opt_re.json")"
st_g="$(hget "/conda/${V}/noarch/${HIDDEN}.sigs" "$WORK/v_opt_hidden.sigs")"
if [ "$st_i" = "200" ] && [ -n "$(shard_addr "$WORK/v_opt_idx.bin.json" dtfal-hidden)" ] \
   && [ "$st_s" = "200" ] && [ "$st_r" = "200" ] && has "$WORK/v_opt_re.json" "$HIDDEN" \
   && [ "$st_g" = "200" ] && cmp -s "$WORK/v_opt_hidden.sigs" "$WORK/h_hidden.sigs"; then
  pass
else
  fail "remote_only: shard index HTTP ${st_i} names=$(shard_names "$WORK/v_opt_idx.bin.json"); shard HTTP ${st_s}; run_exports HTTP ${st_r}; .sigs HTTP ${st_g}" \
    "run_exports keys=$(keys "$WORK/v_opt_re.json")"
fi

begin_test "FIX #5055: micromamba installs the unlisted hosted package once the channel is remote_only"
if mm_install optout dtfal-hidden \
   && docker exec "$CLIENT_CTR" test -f /tmp/env-optout/share/dtfal-hidden/marker.txt; then
  pass
else
  fail "micromamba create dtfal-hidden failed under remote_only" "$(tail -c 600 "$WORK/mm-optout.log")"
fi

begin_test "FIX #5055: a PUT without scope keeps the stored remote_only scope"
st="$(put_allowlist "{\"enabled\":true,\"entries\":[{\"name\":\"dtfal-listed\"},{\"name\":\"dtfup-blocked\"}]}")"
st_rd="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_keep.json")"
if [ "$st" = "200" ] && jq -e '.scope == "remote_only"' "$WORK/allowlist.json" >/dev/null 2>&1 \
   && [ "$st_rd" = "200" ] && has "$WORK/v_keep.json" "$HIDDEN"; then
  pass
else
  fail "scope after a PUT without it: HTTP ${st}" "$(head -c 300 "$WORK/allowlist.json") keys=$(keys "$WORK/v_keep.json")"
fi

begin_test "FIX #5055: scope all_members and a widened list each take effect at once"
st1="$(put_allowlist "{\"enabled\":true,\"scope\":\"all_members\",\"entries\":[{\"name\":\"dtfal-listed\"},{\"name\":\"dtfup-blocked\"}]}")"
hget "/conda/${V}/noarch/repodata.json" "$WORK/v_back.json" >/dev/null
st2="$(put_allowlist "{\"enabled\":true,\"scope\":\"all_members\",\"entries\":[{\"name\":\"dtfal-*\"},{\"name\":\"dtfup-blocked\"}]}")"
hget "/conda/${V}/noarch/repodata.json" "$WORK/v_wide.json" >/dev/null
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && lacks "$WORK/v_back.json" "$HIDDEN" && has "$WORK/v_back.json" "$LISTED" \
   && has "$WORK/v_wide.json" "$HIDDEN" "$LISTED"; then
  pass
else
  fail "list/scope changes did not re-merge (HTTP ${st1}/${st2})" \
    "back=$(keys "$WORK/v_back.json") wide=$(keys "$WORK/v_wide.json")"
fi

begin_test "CONTROL: deleting the list restores the unfiltered channel"
api_delete "/api/v1/repositories/${V}/allowlist" >/dev/null 2>&1
st="$(hget "/conda/${V}/noarch/repodata.json" "$WORK/v_del.json")"
if [ "$st" = "200" ] && has "$WORK/v_del.json" "$HIDDEN" "$LISTED" "$OWNED" "$UP_BLOCKED"; then
  pass
else
  fail "after DELETE allowlist: HTTP ${st}" "keys=$(keys "$WORK/v_del.json")"
fi

end_suite
