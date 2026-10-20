#!/usr/bin/env bash
# =============================================================================
# tiers/conda-sharded-remote-virtual/oracle.sh: CEP-16 sharded repodata on
#   remote and virtual conda channels (artifact-keeper#4577)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-conda-sharded` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH. The mock serves upstream
# channels at http://172.16.<slot>.71/<channel>/ (fixtures/mock_conda_sharded.py)
# and its own `/__manifest` (every shard address it lists), `/__requests`
# (upstream hits per path) and `/__heal`. It is reached with `docker exec`, and
# every `.msgpack.zst` the registry serves is decoded by fixtures/cep16.py
# inside that container (Python 3.14 `compression.zstd`), so the host needs
# neither zstd nor msgpack.
#
# Topology (keys suffixed per run):
#   H  hosted conda channel: dtfsh-owned 1.0 (the name the upstream also has)
#   R  remote -> /main/  (shards under ./shards/; alpha, blocked, owned,
#                         tampered, smuggle)
#   B  remote -> /beside/ (shards_base_url "": shards beside the index)
#   V  virtual [H, R]
#   A  virtual [R] with an allowlist admitting dtfsh-alpha only
#   P  PRIVATE hosted channel: dtfsh-secret 1.0; U is a user with no grant
#
# Gates (#4577, 1.11.0; RED on 1.10.0, where a remote or virtual channel
# answered 404 "Sharded repodata (CEP-16) is only available for local/hosted
# conda repositories"):
#   R's index is the upstream's rewritten onto the registry (base_url "./",
#   shards_base_url "./shards/") with the upstream's 32-byte addresses; a shard
#   by address is the upstream's bytes, immutable, fetched upstream once; the
#   "beside" layout resolves; a shard whose bytes do not hash to its address is
#   502, never served. V lists the hosted shard for a hosted-owned name, serves
#   it, refuses the remote's shard for that name and a shard whose records
#   smuggle in that name (404), and answers a member's tampered shard 502
#   naming the member. A drops non-admitted names (X-AK-Allowlist-Dropped) and
#   refuses their shards.
# CONTROL (both images): hosted index lists the upload; remote and virtual
#   repodata.json carry the upstream records; P's repodata.json, shard index
#   and shards are refused to anonymous and ungranted callers and served to
#   the admin.
# KNOWN-RED pin (artifact-keeper#4829): a shard that failed its address check
#   is kept in the proxy cache as immutable, so it still answers 502 after the
#   upstream serves the right bytes.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MOCK="ak-dtf${SLOT}-mock-conda-sharded"
UP="http://172.16.${SLOT}.71"

H="csrv-host-${SUF}"
R="csrv-remote-${SUF}"
B="csrv-beside-${SUF}"
V="csrv-virt-${SUF}"
A="csrv-allow-${SUF}"
P="csrv-priv-${SUF}"
U="csrvuser${SUF//-/}"
U_PASS="Dtf-csrv-${SUF}-pw1!"

WORK="$(mktemp -d -t dtf-csrv-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------

# fetch <tag> <path> [curl args...] -> HTTP status; body $WORK/<tag>.body,
# headers $WORK/<tag>.hdr (raw bytes: no --compressed, so a zstd frame stays
# a zstd frame whatever Content-Encoding says)
fetch() {
  local tag="$1" path="$2"; shift 2
  curl -s --max-time 60 -D "$WORK/${tag}.hdr" -o "$WORK/${tag}.body" -w '%{http_code}' \
    "$@" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
# header <tag> <name> -> value of the last such header (trimmed), or empty
header() {
  { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
body_text() { head -c "${2:-300}" "$WORK/$1.body" 2>/dev/null | tr -dc '[:print:]' || true; }
# decode <tag> -> writes $WORK/<tag>.json (cep16.py report) and returns 0 when
# it decoded
decode() {
  docker exec -i "$MOCK" python3 /app/cep16.py < "$WORK/$1.body" > "$WORK/$1.json" 2>/dev/null \
    && jq -e 'has("doc")' "$WORK/$1.json" >/dev/null 2>&1
}
jqd() { jq -r "$2" "$WORK/$1.json" 2>/dev/null || true; }
mock_get() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://127.0.0.1'+sys.argv[1]).read().decode())" \
    "$1" 2>/dev/null || true
}
mock_hits() { mock_get /__requests | jq -r --arg p "$1" '.[$p] // 0' 2>/dev/null || echo 0; }
addr() { jq -r --arg c "$1" --arg n "$2" '.[$c].shards[$n] // empty' "$WORK/manifest.json" 2>/dev/null || true; }
sha_of() { { sha256sum "$WORK/$1.body" 2>/dev/null || echo none; } | cut -d' ' -f1; }
anon_denied() { case "$1" in 401|403|404) return 0 ;; *) return 1 ;; esac; }
authz_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }

begin_suite "conda-sharded-remote-virtual (#4577)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, mock manifest, repositories, uploads, user"
auth_admin
setup_err=""
mock_get /__manifest > "$WORK/manifest.json"
jq -e '.main.shards["dtfsh-alpha"]' "$WORK/manifest.json" >/dev/null 2>&1 \
  || setup_err+="mock manifest unreadable; "
create_repo "$H" conda local || setup_err+="create hosted; "
create_repo "$R" conda remote "${UP}/main" || setup_err+="create remote main; "
create_repo "$B" conda remote "${UP}/beside/" || setup_err+="create remote beside; "
create_repo "$V" conda virtual || setup_err+="create virtual V; "
create_repo "$A" conda virtual || setup_err+="create virtual A; "
for m in "$H" "$R"; do
  api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${m}\"}" >/dev/null \
    || setup_err+="add ${m} to V; "
done
api_post "/api/v1/repositories/${A}/members" "{\"member_key\":\"${R}\"}" >/dev/null \
  || setup_err+="add R to A; "
# Not a setup error: an image without the allowlist API fails the A cases.
ALLOW_ST="$(curl -s --max-time 30 -o "$WORK/allow.out" -w '%{http_code}' -X PUT \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"entries":[{"name":"dtfsh-alpha"}]}' \
  "${BASE_URL}/api/v1/repositories/${A}/allowlist" 2>/dev/null || echo 000)"
st="$(curl -s --max-time 30 -o "$WORK/priv.out" -w '%{http_code}' -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${P}\",\"name\":\"${P}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":false}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
case "$st" in 200|201) ;; *) setup_err+="create private hosted -> HTTP ${st}; " ;; esac
create_test_user "$U" "$U_PASS" "${U}@dtf.invalid" >/dev/null || setup_err+="create user; "

BUILD="${DTF_DIR}/fixtures/conda/build.sh"
bash "$BUILD" "$WORK" dtfsh-owned 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build dtfsh-owned; "
bash "$BUILD" "$WORK" dtfsh-secret 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build dtfsh-secret; "
for pair in "${H}:dtfsh-owned-1.0-0.tar.bz2" "${P}:dtfsh-secret-1.0-0.tar.bz2"; do
  repo="${pair%%:*}"; file="${pair#*:}"
  st="$(curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$WORK/${file}" \
    "${BASE_URL}/conda/${repo}/noarch/${file}" 2>/dev/null || echo 000)"
  case "$st" in 200|201) ;; *) setup_err+="upload ${file} to ${repo} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); " ;; esac
done
U_TOKEN="$(login_as "$U" "$U_PASS" 2>/dev/null)" || setup_err+="login as ${U}; "

if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

A_ALPHA="$(addr main dtfsh-alpha)"
A_BLOCKED="$(addr main dtfsh-blocked)"
A_OWNED_UP="$(addr main dtfsh-owned)"
A_TAMPERED="$(addr main dtfsh-tampered)"
A_SMUGGLE="$(addr main dtfsh-smuggle)"
A_BESIDE="$(addr beside dtfsh-alpha)"
IDX="/noarch/repodata_shards.msgpack.zst"

# =============================================================================
# CONTROLS (true on both images)
# =============================================================================
begin_test "CONTROL: the hosted channel's shard index answers and lists its upload"
st="$(fetch h_idx "/conda/${H}${IDX}")"
if [ "$st" = "200" ] && decode h_idx && [ "$(jqd h_idx '.doc.shards | has("dtfsh-owned")')" = "true" ]; then
  pass
else
  fail "hosted shard index did not list dtfsh-owned" "HTTP ${st}: $(jq -c '.error // (.doc.shards|keys)' "$WORK/h_idx.json" 2>/dev/null)"
fi
H_OWNED="$(jqd h_idx '.doc.shards["dtfsh-owned"] | if type == "object" then .bin else . end | values')"

begin_test "CONTROL: remote and virtual repodata.json carry the upstream records"
st1="$(fetch r_rd "/conda/${R}/noarch/repodata.json")"
st2="$(fetch v_rd "/conda/${V}/noarch/repodata.json")"
if [ "$st1" = "200" ] && [ "$st2" = "200" ] \
   && jq -e '.packages | has("dtfsh-alpha-2.0-0.tar.bz2")' "$WORK/r_rd.body" >/dev/null 2>&1 \
   && jq -e '.packages | has("dtfsh-alpha-2.0-0.tar.bz2") and has("dtfsh-owned-1.0-0.tar.bz2")' "$WORK/v_rd.body" >/dev/null 2>&1; then
  pass
else
  fail "remote/virtual repodata.json lost records" \
    "remote HTTP ${st1} $(jq -c '.packages|keys' "$WORK/r_rd.body" 2>/dev/null); virtual HTTP ${st2} $(jq -c '.packages|keys' "$WORK/v_rd.body" 2>/dev/null)"
fi

begin_test "CONTROL: the private channel's repodata.json is refused anonymously and served to the admin"
st1="$(fetch p_rd_anon "/conda/${P}/noarch/repodata.json")"
st2="$(fetch p_rd_admin "/conda/${P}/noarch/repodata.json" -H "$(auth_header)")"
if anon_denied "$st1" && [ "$st2" = "200" ] \
   && jq -e '.packages | has("dtfsh-secret-1.0-0.tar.bz2")' "$WORK/p_rd_admin.body" >/dev/null 2>&1; then
  pass
else
  fail "private repodata.json access is not as before" "anonymous HTTP ${st1}; admin HTTP ${st2} $(body_text p_rd_admin 200)"
fi

# =============================================================================
# #4577 REMOTE: the upstream's index, rewritten; shards by address
# =============================================================================
begin_test "#4577: remote shard index is the upstream's, rewritten onto the registry (base_url ./, shards ./shards/)"
st="$(fetch r_idx "/conda/${R}${IDX}")"
want_names='["dtfsh-alpha","dtfsh-blocked","dtfsh-owned","dtfsh-smuggle","dtfsh-tampered"]'
if [ "$st" = "200" ] && decode r_idx \
   && [ "$(jqd r_idx '.doc.info.base_url')" = "./" ] \
   && [ "$(jqd r_idx '.doc.info.shards_base_url')" = "./shards/" ] \
   && [ "$(jq -c '.doc.shards | keys' "$WORK/r_idx.json")" = "$want_names" ] \
   && [ "$(jqd r_idx '.doc.shards["dtfsh-alpha"].bin')" = "$A_ALPHA" ] \
   && [ "$(jqd r_idx '.doc.shards["dtfsh-alpha"].len')" = "32" ]; then
  pass
else
  fail "remote ${R} does not serve the upstream shard index rewritten onto the registry" \
    "HTTP ${st}: $(body_text r_idx 200) decoded=$(jq -c '{error, info: .doc.info, names: (.doc.shards // {} | keys)}' "$WORK/r_idx.json" 2>/dev/null)"
fi

begin_test "#4577: a remote shard by address is the upstream's bytes, immutable, fetched upstream once"
p_alpha="/main/noarch/shards/${A_ALPHA}.msgpack.zst"
hits0="$(mock_hits "$p_alpha")"
st1="$(fetch r_alpha "/conda/${R}/noarch/shards/${A_ALPHA}.msgpack.zst")"
st2="$(fetch r_alpha2 "/conda/${R}/noarch/shards/${A_ALPHA}.msgpack.zst")"
cc="$(header r_alpha Cache-Control)"; ce="$(header r_alpha Content-Encoding)"
hits=$(( $(mock_hits "$p_alpha") - hits0 ))
if [ "$st1" = "200" ] && [ "$st2" = "200" ] && [ "$(sha_of r_alpha)" = "$A_ALPHA" ] \
   && [ "$(sha_of r_alpha2)" = "$A_ALPHA" ] && [[ "$cc" == *immutable* ]] && [ -z "$ce" ] \
   && [ "$hits" = "1" ] && decode r_alpha \
   && [ "$(jq -c '.doc.packages | keys' "$WORK/r_alpha.json")" = '["dtfsh-alpha-1.0-0.tar.bz2","dtfsh-alpha-2.0-0.tar.bz2"]' ]; then
  pass
else
  fail "remote shard ${A_ALPHA:0:12} is not served as the upstream's immutable bytes" \
    "HTTP ${st1}/${st2} sha=$(sha_of r_alpha) Cache-Control=[${cc}] Content-Encoding=[${ce}] upstream hits=${hits} body=$(body_text r_alpha 120)"
fi

begin_test "#4577: the 'shards beside the index' layout (shards_base_url \"\") resolves"
hits0="$(mock_hits "/beside/noarch/${A_BESIDE}.msgpack.zst")"
st="$(fetch b_alpha "/conda/${B}/noarch/shards/${A_BESIDE}.msgpack.zst")"
hits=$(( $(mock_hits "/beside/noarch/${A_BESIDE}.msgpack.zst") - hits0 ))
if [ "$st" = "200" ] && [ "$(sha_of b_alpha)" = "$A_BESIDE" ] && [ "$hits" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "remote ${B} could not serve a shard published beside its index" \
    "HTTP ${st}: $(body_text b_alpha 200); upstream hits on /beside/noarch/<hash>=${hits}"
fi

begin_test "#4577: a remote shard whose bytes do not hash to its address is refused with 502"
st="$(fetch r_tamp "/conda/${R}/noarch/shards/${A_TAMPERED}.msgpack.zst")"
served_sha="$(sha_of r_tamp)"
if [ "$st" = "502" ] && grep -q "does not match its content address" "$WORK/r_tamp.body" \
   && [ "$served_sha" != "$(jq -r '.main.tampered_served_sha256' "$WORK/manifest.json")" ]; then
  pass
else
  fail "a tampered upstream shard was not refused" "HTTP ${st}: $(body_text r_tamp 200) (served sha ${served_sha:0:12})"
fi

# =============================================================================
# #4577 VIRTUAL: hosted first, ownership guard, member failure
# =============================================================================
begin_test "#4577: virtual shard index lists the hosted shard for a hosted-owned name and the remote's others"
st="$(fetch v_idx "/conda/${V}${IDX}")"
if [ "$st" = "200" ] && decode v_idx \
   && [ "$(jqd v_idx '.doc.shards["dtfsh-owned"].bin')" = "$H_OWNED" ] \
   && [ "$H_OWNED" != "$A_OWNED_UP" ] \
   && [ "$(jqd v_idx '.doc.shards["dtfsh-alpha"].bin')" = "$A_ALPHA" ] \
   && [ "$(jqd v_idx '.doc.info.base_url')" = "./" ]; then
  pass
else
  fail "virtual ${V} shard index is not the hosted-first merge" \
    "HTTP ${st}: $(body_text v_idx 200) owned=$(jqd v_idx '.doc.shards["dtfsh-owned"]' | head -c 120) hosted=${H_OWNED:0:12} upstream=${A_OWNED_UP:0:12} names=$(jq -c '.doc.shards // {} | keys' "$WORK/v_idx.json" 2>/dev/null)"
fi

begin_test "#4577: virtual serves the hosted shard and refuses the remote's shard for the owned name and a name-smuggling shard"
st1="$(fetch v_hown "/conda/${V}/noarch/shards/${H_OWNED}.msgpack.zst")"
st2="$(fetch v_rown "/conda/${V}/noarch/shards/${A_OWNED_UP}.msgpack.zst")"
st3="$(fetch v_smug "/conda/${V}/noarch/shards/${A_SMUGGLE}.msgpack.zst")"
st4="$(fetch v_alpha "/conda/${V}/noarch/shards/${A_ALPHA}.msgpack.zst")"
ok=1
{ [ "$st1" = "200" ] && decode v_hown \
  && [ "$(jq -c '.doc.packages | keys' "$WORK/v_hown.json")" = '["dtfsh-owned-1.0-0.tar.bz2"]' ]; } || ok=0
{ [ "$st2" = "404" ] && grep -q "Shard not found" "$WORK/v_rown.body"; } || ok=0
{ [ "$st3" = "404" ] && grep -q "Shard not found" "$WORK/v_smug.body"; } || ok=0
{ [ "$st4" = "200" ] && [ "$(sha_of v_alpha)" = "$A_ALPHA" ]; } || ok=0
if [ "$ok" = "1" ]; then
  pass
else
  fail "virtual ${V} shard routing does not honour hosted ownership" \
    "hosted owned HTTP ${st1} $(jq -c '.doc.packages // .error | keys? // .' "$WORK/v_hown.json" 2>/dev/null); remote owned HTTP ${st2} $(body_text v_rown 120); smuggle HTTP ${st3} $(body_text v_smug 120); alpha HTTP ${st4}"
fi

begin_test "#4577: a member's tampered shard through the virtual is 502 naming the member"
st="$(fetch v_tamp "/conda/${V}/noarch/shards/${A_TAMPERED}.msgpack.zst")"
if [ "$st" = "502" ] && grep -q "$R" "$WORK/v_tamp.body"; then
  pass
else
  fail "virtual ${V} did not refuse a member's tampered shard naming ${R}" "HTTP ${st}: $(body_text v_tamp 300)"
fi

# =============================================================================
# #4577 ALLOWLIST on the sharded view
# =============================================================================
begin_test "#4577: allowlisted virtual lists only admitted names, reports the drop, refuses a dropped shard"
st1="$(fetch a_idx "/conda/${A}${IDX}")"
dropped="$(header a_idx X-AK-Allowlist-Dropped)"
st2="$(fetch a_blocked "/conda/${A}/noarch/shards/${A_BLOCKED}.msgpack.zst")"
st3="$(fetch a_alpha "/conda/${A}/noarch/shards/${A_ALPHA}.msgpack.zst")"
if [ "$ALLOW_ST" = "200" ] && [ "$st1" = "200" ] && decode a_idx \
   && [ "$(jq -c '.doc.shards | keys' "$WORK/a_idx.json")" = '["dtfsh-alpha"]' ] \
   && [ "$dropped" = "4" ] && [ "$st2" = "404" ] && [ "$st3" = "200" ] \
   && [ "$(sha_of a_alpha)" = "$A_ALPHA" ]; then
  pass
else
  fail "allowlist not applied to virtual ${A}'s sharded view" \
    "allowlist PUT HTTP ${ALLOW_ST}; index HTTP ${st1} names=$(jq -c '.doc.shards // {} | keys' "$WORK/a_idx.json" 2>/dev/null) X-AK-Allowlist-Dropped=[${dropped}]; blocked shard HTTP ${st2}; alpha shard HTTP ${st3}"
fi

# =============================================================================
# CONTROL (#4577 read access): a private hosted channel's sharded endpoints
# =============================================================================
# #4577 made the sharded handlers call check_read_access. On 1.10.0 the same
# requests are already refused (the auth layer answers 401 to an anonymous read
# of a private repository, and the ungranted user gets 404), so this holds on
# both images and is kept as a control that the sharded routes never leak a
# private channel.
begin_test "CONTROL: a private channel's shard index and shards follow read access (anonymous and ungranted user refused)"
st_admin="$(fetch p_idx "/conda/${P}${IDX}" -H "$(auth_header)")"
P_SECRET=""
if [ "$st_admin" = "200" ] && decode p_idx; then
  P_SECRET="$(jqd p_idx '.doc.shards["dtfsh-secret"] | if type == "object" then .bin else . end | values')"
fi
st_anon_i="$(fetch p_idx_anon "/conda/${P}${IDX}")"
st_user_i="$(fetch p_idx_user "/conda/${P}${IDX}" -H "Authorization: Bearer ${U_TOKEN}")"
st_anon_s="$(fetch p_sh_anon "/conda/${P}/noarch/shards/${P_SECRET:-0000000000000000000000000000000000000000000000000000000000000000}.msgpack.zst")"
st_user_s="$(fetch p_sh_user "/conda/${P}/noarch/shards/${P_SECRET:-0000000000000000000000000000000000000000000000000000000000000000}.msgpack.zst" -H "Authorization: Bearer ${U_TOKEN}")"
st_admin_s="$(fetch p_sh_admin "/conda/${P}/noarch/shards/${P_SECRET:-0000000000000000000000000000000000000000000000000000000000000000}.msgpack.zst" -H "$(auth_header)")"
if [ -n "$P_SECRET" ] && anon_denied "$st_anon_i" && anon_denied "$st_anon_s" \
   && authz_denied "$st_user_i" && authz_denied "$st_user_s" && [ "$st_admin_s" = "200" ] \
   && [ "$(sha_of p_sh_admin)" = "$P_SECRET" ]; then
  pass
else
  fail "private channel ${P}'s CEP-16 documents leak past read access" \
    "admin index HTTP ${st_admin} (secret shard ${P_SECRET:0:12}); anonymous index HTTP ${st_anon_i} shard HTTP ${st_anon_s}; ungranted user index HTTP ${st_user_i} shard HTTP ${st_user_s}; admin shard HTTP ${st_admin_s}"
fi

# =============================================================================
# KNOWN-RED pin artifact-keeper#4829: a refused shard is kept in the proxy cache
# =============================================================================
# fetch_upstream_shard reads the shard through the proxy cache, which stores
# the upstream's bytes under the shard's path BEFORE the handler checks them
# against the address. The cache classifies `<sha256>.msgpack.zst` as
# immutable, so the stored wrong bytes are never revalidated: once the
# upstream serves the right shard, the remote still answers 502 (and never
# asks the upstream again). Reported, not failed; when it passes, turn it into
# an assertion.
begin_test "KNOWN-RED pin #4829: after the upstream serves the right bytes, the once-tampered shard is served"
mock_get /__heal >/dev/null
hits0="$(mock_hits "/main/noarch/shards/${A_TAMPERED}.msgpack.zst")"
st="$(fetch r_tamp_healed "/conda/${R}/noarch/shards/${A_TAMPERED}.msgpack.zst")"
hits=$(( $(mock_hits "/main/noarch/shards/${A_TAMPERED}.msgpack.zst") - hits0 ))
cached="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc \
  "SELECT checksum_sha256 FROM proxy_cache_artifacts c JOIN repositories r ON r.id = c.repository_id
    WHERE r.key = '${R}' AND c.path = 'noarch/shards/${A_TAMPERED}.msgpack.zst'" 2>/dev/null || true)"
if [ "$st" = "200" ] && [ "$(sha_of r_tamp_healed)" = "$A_TAMPERED" ]; then
  echo "   KNOWN-RED (artifact-keeper#4829) NOW PASSES: the healed shard is served (upstream asked again ${hits}x). Turn this pin into an assertion."
else
  echo "   KNOWN-RED (artifact-keeper#4829): after /__heal the shard still answers HTTP ${st} ($(body_text r_tamp_healed 80)); upstream asked again ${hits}x; proxy_cache_artifacts holds checksum ${cached:-<none>} under address ${A_TAMPERED:0:12}"
fi
pass

end_suite
