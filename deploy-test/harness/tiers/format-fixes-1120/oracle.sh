#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/format-fixes-1120/oracle.sh
#   Ten 1.12.0 format fixes, each through the format's native routes: #5227
#   cargo renamed deps, #5277 helm versionless upstream deps, #5278 rpm source
#   packages, #5197 protobuf latest commit, #5198 debian non-OpenPGP key,
#   #5723 PEP 440, #5739 conda allowlist literal '*', #5167 conda empty-subdir
#   bz2 permit, #5267 agentplugins per-repository keys, #5716 linear glob.
#   See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"
: "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SFX="${DTF_SLOT}${RUN_ID##*-}$$"
SFX="$(printf '%s' "$SFX" | tr -cd 'a-z0-9' | tail -c 10)"
# mock-files (profiles/upstreams.mock-files.yml): control API from the host,
# and the address the backend dials.
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"
AUTH="admin:${ADMIN_PASS}"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
body(){ head -c "${2:-300}" "$1" 2>/dev/null | tr -d '\n' || true; }

# http <METHOD> <PATH> <OUT> [curl args...] -> HTTP code (admin bearer)
http(){
  local m="$1" u="$2" o="$3"; shift 3
  rm -f "$o"
  curl -s --max-time 60 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer ${TOK}" "$@" "${BASE}${u}" 2>/dev/null || true
  [ -f "$o" ] || : >"$o"
}
# anon <PATH> <OUT> [curl args...] -> HTTP code (no credentials)
anon(){
  local u="$1" o="$2"; shift 2
  rm -f "$o"
  curl -s --max-time 60 -o "$o" -w '%{http_code}' "$@" "${BASE}${u}" 2>/dev/null || true
  [ -f "$o" ] || : >"$o"
}
post_json(){ http POST "$1" "$2" -H 'Content-Type: application/json' -d "$3"; }
mkrepo(){ # <key> <format> [repo_type] [upstream_url] -> id ("" on failure); response in $W/mkrepo.json
  local c
  c="$(post_json /api/v1/repositories "$W/mkrepo.json" "$(jq -nc --arg k "$1" --arg f "$2" --arg t "${3:-local}" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:true} + (if $u == "" then {} else {upstream_url:$u} end)')")"
  case "$c" in 2??) jqr '.id // empty' <"$W/mkrepo.json";; *) echo "   mkrepo $1 ($2) answered ${c}: $(body "$W/mkrepo.json")" >&2;; esac
}
mock_put(){ # <path> <file> [content-type] -> bytes stored
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}

begin_suite "format-fixes-1120"

# =============================================================================
begin_test "setup: admin session, mock upstream reachable"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // .token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
ADMIN_TOKEN="$TOK"; export ADMIN_TOKEN
curl -sf --max-time 5 "${MOCK}/__readyz" >/dev/null 2>&1 \
  || { infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite; }
VER="$(curl -s --max-time 10 "${BASE}/health" | jqr '.version // empty')"
echo "-- backend ${VER:-unknown}, suffix ${SFX}"
pass

# =============================================================================
# #5227 cargo: renamed dependency in the sparse index
# =============================================================================
R_CARGO="ff-cargo-${SFX}"
mkrepo "$R_CARGO" cargo >/dev/null
mkdir -p "$W/c/rdep-1.0.0/src"
printf '[package]\nname = "rdep"\nversion = "1.0.0"\n\n[dependencies]\nrenamed = { package = "rbase", version = "=1.0.0" }\nplain = "1"\n' >"$W/c/rdep-1.0.0/Cargo.toml"
: >"$W/c/rdep-1.0.0/src/lib.rs"
tar -czf "$W/rdep.crate" -C "$W/c" rdep-1.0.0
python3 -I - "$W/rdep.crate" "$W/rdep.pay" <<'PY'
import json, struct, sys
def dep(n, r, e):
    return {"name": n, "version_req": r, "features": [], "optional": False, "default_features": True,
            "target": None, "kind": "normal", "registry": None, "explicit_name_in_toml": e}
m = json.dumps({"name": "rdep", "vers": "1.0.0",
                "deps": [dep("rbase", "=1.0.0", "renamed"), dep("plain", "^1", None)],
                "features": {}, "authors": ["dtf"], "description": "d", "license": "MIT"}).encode()
c = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(struct.pack("<I", len(m)) + m + struct.pack("<I", len(c)) + c)
PY
C_PUB="$(http PUT "/cargo/${R_CARGO}/api/v1/crates/new" "$W/cargo.pub" --data-binary "@$W/rdep.pay")"
C_IDX="$(anon "/cargo/${R_CARGO}/rd/ep/rdep" "$W/cargo.idx.all")"
tail -n1 "$W/cargo.idx.all" >"$W/cargo.idx"
echo "-- cargo publish=${C_PUB} index=${C_IDX}: $(body "$W/cargo.idx" 600)"

begin_test "CONTROL: cargo: a plain dependency is listed with req ^1"
if [ "$C_PUB" = "200" ] && [ "$C_IDX" = "200" ] \
   && jq -e '[.deps[] | select(.name == "plain" and .req == "^1" and (has("version_req") | not))] | length == 1' "$W/cargo.idx" >/dev/null 2>&1; then
  pass
else
  fail "publish=${C_PUB} index=${C_IDX}" "$(body "$W/cargo.pub") / $(body "$W/cargo.idx" 600)"
fi

begin_test "FIX #5227: cargo: a renamed dependency is listed as name=renamed, package=rbase"
if jq -e '[.deps[] | select(.name == "renamed" and .package == "rbase" and .req == "=1.0.0")] | length == 1' "$W/cargo.idx" >/dev/null 2>&1 \
   && jq -e '[.deps[] | has("explicit_name_in_toml")] | any | not' "$W/cargo.idx" >/dev/null 2>&1; then
  pass
else
  fail "the renamed dependency is not {name:renamed, package:rbase}; pre-#5227 it was listed as name=rbase with explicit_name_in_toml" \
    "deps=$(jq -c '.deps' "$W/cargo.idx" 2>/dev/null | head -c 600)"
fi

# =============================================================================
# #5278 rpm: source packages carry arch src
# =============================================================================
R_RPM="ff-rpm-${SFX}"
mkrepo "$R_RPM" rpm >/dev/null
FX_RPM="${DTF_DIR}/fixtures/rpm"
U_SRC="$(http PUT "/rpm/${R_RPM}/packages/ak-srpm-test-1.0-1.src.rpm" "$W/rpm.up1" --upload-file "${FX_RPM}/ak-srpm-test-1.0-1.src.rpm")"
U_BIN="$(http PUT "/rpm/${R_RPM}/packages/akdep-lib-1.0-1.noarch.rpm" "$W/rpm.up2" --upload-file "${FX_RPM}/akdep-lib-1.0-1.noarch.rpm")"
U_RB="$(http POST "/api/v1/repositories/${R_RPM}/rpm/repodata/rebuild?wait=true" "$W/rpm.rb")"
anon "/rpm/${R_RPM}/repodata/primary.xml.gz" "$W/primary.gz" >/dev/null
anon "/rpm/${R_RPM}/repodata/other.xml.gz" "$W/other.gz" >/dev/null
gunzip -c "$W/primary.gz" >"$W/primary.xml" 2>/dev/null
gunzip -c "$W/other.gz" >"$W/other.xml" 2>/dev/null
# pkg_arch <file> <name> -> the <arch> of that package's <package> block
pkg_arch(){ awk -v n="<name>$2</name>" '/<package /{p=""; hit=0} {p=p $0 "\n"; if (index($0, n)) hit=1} /<\/package>/{ if (hit) print p }' "$1" \
  | grep -o '<arch>[^<]*</arch>' | head -n1 | sed 's/<[^>]*>//g'; }
A_SRC="$(pkg_arch "$W/primary.xml" ak-srpm-test)"
A_BIN="$(pkg_arch "$W/primary.xml" akdep-lib)"
O_SRC="$(grep -o 'name="ak-srpm-test" arch="[^"]*"' "$W/other.xml" | head -n1 | sed 's/.*arch="//; s/"//')"
echo "-- rpm uploads src=${U_SRC} bin=${U_BIN} rebuild=${U_RB} ($(body "$W/rpm.rb" 120)); primary arch src=${A_SRC:-?} bin=${A_BIN:-?}; other arch src=${O_SRC:-?}"

begin_test "CONTROL: rpm: a binary noarch package is listed with arch noarch"
if [ "$U_BIN" = "201" ] || [ "$U_BIN" = "200" ]; then
  if [ "$A_BIN" = "noarch" ]; then pass; else fail "akdep-lib arch='${A_BIN}' (want noarch)" "rebuild=${U_RB} $(body "$W/rpm.rb")"; fi
else
  fail "binary upload answered ${U_BIN}" "$(body "$W/rpm.up2")"
fi

begin_test "FIX #5278: rpm: a source RPM is listed with arch src in primary.xml and other.xml"
if { [ "$U_SRC" = "201" ] || [ "$U_SRC" = "200" ]; } && [ "$A_SRC" = "src" ] && [ "$O_SRC" = "src" ]; then
  pass
else
  fail "source package arch primary='${A_SRC}' other='${O_SRC}' (want src); pre-#5278 the header ARCH (x86_64) won" \
    "upload=${U_SRC} $(body "$W/rpm.up1" 200)"
fi

# =============================================================================
# #5723 pypi: PEP 440 per packaging's grammar
# =============================================================================
R_PYPI="ff-pypi-${SFX}"
mkrepo "$R_PYPI" pypi >/dev/null
py_up(){ # <project> <version> -> HTTP code
  local d="$W/py/$1-$2"
  mkdir -p "$d"
  printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: dtf\n' "$1" "$2" >"$d/PKG-INFO"
  tar -czf "$W/py/$1-$2.tar.gz" -C "$W/py" "$1-$2"
  http POST "/pypi/${R_PYPI}/" "$W/py.up" -F ':action=file_upload' -F protocol_version=1 \
    -F "name=$1" -F "version=$2" -F filetype=sdist -F "content=@$W/py/$1-$2.tar.gz"
}
P1="$(py_up dtfpepctl 1.0b2)"; P2="$(py_up dtfpepctl 1.0)"
P3="$(py_up dtfpep 1.0)"; P4="$(py_up dtfpep 1.0beta2.postdev1)"
py_state(){ # <project> -> "info.version|versions"
  anon "/pypi/${R_PYPI}/pypi/$1/json" "$W/py.json" >/dev/null
  anon "/pypi/${R_PYPI}/simple/$1/" "$W/py.simple" -H 'Accept: application/vnd.pypi.simple.v1+json' >/dev/null
  echo "$(jqr '.info.version // empty' <"$W/py.json")|$(jq -c '.versions // empty' "$W/py.simple" 2>/dev/null)"
}
S_CTL="$(py_state dtfpepctl)"; S_FIX="$(py_state dtfpep)"
echo "-- pypi uploads ${P1}/${P2}/${P3}/${P4}; ctl=${S_CTL} fix=${S_FIX}"

begin_test "CONTROL: pypi: 1.0b2 is a pre-release (info.version 1.0; versions [1.0b2, 1.0])"
if [ "$S_CTL" = '1.0|["1.0b2","1.0"]' ]; then pass; else fail "dtfpepctl state '${S_CTL}' uploads=${P1}/${P2}"; fi

begin_test "FIX #5723: pypi: 1.0beta2.postdev1 is a pre-release ordered before 1.0"
if [ "$S_FIX" = '1.0|["1.0beta2.postdev1","1.0"]' ]; then
  pass
else
  fail "dtfpep state '${S_FIX}' (want 1.0|[\"1.0beta2.postdev1\",\"1.0\"]); pre-#5723 the version did not parse and counted as the newest final" \
    "uploads=${P3}/${P4}"
fi

# =============================================================================
# #5197 protobuf: Download with no ref resolves the latest commit
# =============================================================================
R_PB="ff-pb-${SFX}"
mkrepo "$R_PB" protobuf >/dev/null
OWNER="acme"
rpc(){ # <method> <json> <out> -> HTTP code
  rm -f "$3"
  curl -s --max-time 60 -o "$3" -w '%{http_code}' -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -H 'Connect-Protocol-Version: 1' -d "$2" "${BASE}/proto/${R_PB}/$1" 2>/dev/null || true
}
upload_body(){ # module proto-text [label]
  local b64; b64="$(printf '%s' "$2" | base64 | tr -d '\n')"
  jq -nc --arg o "$OWNER" --arg m "$1" --arg p "${OWNER}/$1/v1/x.proto" --arg c "$b64" --arg l "${3:-}" \
    '{contents:[{moduleRef:{owner:$o,module:$m},files:[{path:$p,content:$c}]} + (if $l == "" then {} else {labelRefs:[{name:$l}]} end)]}'
}
MOD="m${SFX}"
PROTO=$'syntax = "proto3";\nmessage One {}\n'
PB_UP="$(rpc buf.registry.module.v1beta1.UploadService/Upload "$(upload_body "$MOD" "$PROTO")" "$W/pb.up")"
CID="$(jqr '.commits[0].id // empty' <"$W/pb.up")"
dl_body(){ jq -nc --arg o "$OWNER" --arg m "$MOD" --arg l "${1:-}" '{values:[{resourceRef:({owner:$o,module:$m} + (if $l == "" then {} else {label:$l} end))}]}'; }
PB_L="$(rpc buf.registry.module.v1beta1.DownloadService/Download "$(dl_body main)" "$W/pb.dl.label")"
PB_N="$(rpc buf.registry.module.v1beta1.DownloadService/Download "$(dl_body)" "$W/pb.dl.none")"
echo "-- protobuf upload=${PB_UP} commit=${CID:-?} download(label main)=${PB_L} download(no ref)=${PB_N}"
pb_ok(){ # <file> -> 0 when it carries the pushed commit and proto text
  [ -n "$CID" ] || return 1
  [ "$(jqr '.contents[0].commit.id // empty' <"$1")" = "$CID" ] || return 1
  # $(...) drops the text's trailing newline
  [ "$(jqr '.contents[0].files[0].content // empty | @base64d' <"$1")" = "${PROTO%$'\n'}" ]
}

begin_test "CONTROL: protobuf: Download with label main returns the pushed commit"
if [ "$PB_UP" = "200" ] && [ "$PB_L" = "200" ] && pb_ok "$W/pb.dl.label"; then pass
else fail "upload=${PB_UP} download=${PB_L}" "$(body "$W/pb.up") / $(body "$W/pb.dl.label")"; fi

begin_test "FIX #5197: protobuf: Download with no ref returns the latest commit"
if [ "$PB_N" = "200" ] && pb_ok "$W/pb.dl.none"; then pass
else fail "download with no ref answered ${PB_N} (want 200 with commit ${CID}); pre-#5197 it resolved the _labels row" "$(body "$W/pb.dl.none")"; fi

# =============================================================================
# #5198 debian: a non-OpenPGP signing key answers 409
# =============================================================================
mkkey(){ # <name> <key_type> <algorithm> -> id
  post_json /api/v1/signing/keys "$W/key.json" "$(jq -nc --arg n "$1" --arg t "$2" --arg a "$3" '{name:$n,key_type:$t,algorithm:$a}')" >/dev/null
  jqr '.id // empty' <"$W/key.json"
}
bind(){ post_json "/api/v1/signing/repositories/$1/config" "$W/bind.json" "$(jq -nc --arg k "$2" '{signing_key_id:$k,sign_metadata:true}')"; }
R_DEB="ff-deb-${SFX}"; R_DEBG="ff-debg-${SFX}"
ID_DEB="$(mkrepo "$R_DEB" debian)"; ID_DEBG="$(mkrepo "$R_DEBG" debian)"
K_RSA="$(mkkey "ff-rsa-${SFX}" rsa rsa2048)"
K_GPG="$(mkkey "ff-gpg-${SFX}" gpg rsa2048)"
B1="$(bind "$ID_DEB" "$K_GPG")"; B2="$(bind "$ID_DEBG" "$K_GPG")"
SWAP=no
[ "$B1" = "200" ] && [ -n "$K_RSA" ] \
  && psql_x "UPDATE repository_signing_config SET signing_key_id='${K_RSA}' WHERE repository_id='${ID_DEB}';" && SWAP=yes
D_REL="$(anon "/debian/${R_DEB}/dists/stable/Release" "$W/deb.rel")"
D_IN="$(anon "/debian/${R_DEB}/dists/stable/InRelease" "$W/deb.in")"
D_GPG="$(anon "/debian/${R_DEB}/dists/stable/Release.gpg" "$W/deb.gpg")"
D_KEY="$(anon "/debian/${R_DEB}/gpg-key.asc" "$W/deb.key")"
D_GIN="$(anon "/debian/${R_DEBG}/dists/stable/InRelease" "$W/debg.in")"
echo "-- debian keys rsa=${K_RSA:-?} gpg=${K_GPG:-?} bind=${B1}/${B2} swap=${SWAP}; rsa repo Release=${D_REL} InRelease=${D_IN} Release.gpg=${D_GPG} gpg-key.asc=${D_KEY}; gpg repo InRelease=${D_GIN}"

begin_test "CONTROL: debian: Release with an rsa key bound is 200, a gpg-bound repo serves InRelease"
if [ "$SWAP" != "yes" ]; then
  infra_fail "could not stage the rsa binding (bind=${B1}, rsa key=${K_RSA})" "$(body "$W/bind.json") $(body "$W/key.json")"
elif [ "$D_REL" = "200" ] && [ "$D_GIN" = "200" ] && grep -q 'BEGIN PGP SIGNED MESSAGE' "$W/debg.in"; then
  pass
else
  fail "Release=${D_REL} gpg-repo InRelease=${D_GIN}" "$(body "$W/deb.rel") / $(body "$W/debg.in")"
fi

begin_test "FIX #5198: debian: InRelease, Release.gpg and gpg-key.asc answer 409 naming key_type='gpg'"
reset_case
for pair in "InRelease:${D_IN}:deb.in" "Release.gpg:${D_GPG}:deb.gpg" "gpg-key.asc:${D_KEY}:deb.key"; do
  n="${pair%%:*}"; rest="${pair#*:}"; c="${rest%%:*}"; f="${rest#*:}"
  if [ "$c" = "409" ] && grep -q "key_type='gpg'" "$W/$f"; then note "${n}: 409 ok"
  else fail_g "${n} answered ${c} (want 409 naming key_type='gpg'): $(body "$W/$f" 200)"; fi
done
finish_case "pre-#5198 a non-OpenPGP key gave 500 or a PEM labelled pgp-keys"

# =============================================================================
# #5267 agentplugins: per-repository storage keys on a shared bucket
# =============================================================================
R_AP1="ff-ap1-${SFX}"; R_AP2="ff-ap2-${SFX}"
ID_AP1="$(mkrepo "$R_AP1" agentplugins)"; AP1_BODY="$(body "$W/mkrepo.json")"
ID_AP2="$(mkrepo "$R_AP2" agentplugins)"
python3 -I - "$W/ap.zip" <<'PY'
import sys, zipfile
files = {
    ".claude-plugin/plugin.json": '{"name":"ffplug","version":"1.0.0","description":"d","author":{"name":"x"},"license":"MIT","keywords":["x"]}',
    "commands/deploy.md": "# deploy\n",
    "skills/deploy/SKILL.md": "# skill\n",
    "hooks/hooks.json": "{}\n",
}
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for n, c in files.items():
        i = zipfile.ZipInfo(n, date_time=(2020, 1, 1, 0, 0, 0)); i.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(i, c)
PY
ap_put(){ # <repo> -> HTTP code
  rm -f "$W/ap.put"
  curl -s --max-time 60 -o "$W/ap.put" -w '%{http_code}' -u "$AUTH" -X PUT -H 'Content-Type: application/zip' \
    --data-binary "@$W/ap.zip" "${BASE}/agentplugins/$1/ffplug/1.0.0/ffplug-1.0.0.zip" 2>/dev/null || true
}
ap_get(){ # <repo> -> "<code>:<sha256>"
  local c; c="$(curl -s --max-time 60 -o "$W/ap.get" -w '%{http_code}' -u "$AUTH" "${BASE}/agentplugins/$1/ffplug/1.0.0/ffplug-1.0.0.zip" 2>/dev/null || true)"
  echo "${c}:$(sha256sum "$W/ap.get" 2>/dev/null | cut -d' ' -f1)"
}
AP_SHA="$(sha256sum "$W/ap.zip" | cut -d' ' -f1)"
AP_P1=""; AP_P2=""; AP_P1B=""; AP_P2B=""
if [ -n "$ID_AP1" ] && [ -n "$ID_AP2" ]; then
  AP_P1="$(ap_put "$R_AP1")"; AP_P1B="$(body "$W/ap.put")"
  AP_P2="$(ap_put "$R_AP2")"; AP_P2B="$(body "$W/ap.put")"
fi
AP_G1="$(ap_get "$R_AP1")"; AP_G2="$(ap_get "$R_AP2")"
echo "-- agentplugins repos ${ID_AP1:-none}/${ID_AP2:-none}; publish A=${AP_P1} B=${AP_P2}; get A=${AP_G1%%:*} B=${AP_G2%%:*}"

begin_test "FIX #5267: agentplugins: two repositories publish the same plugin version on S3 and both serve it"
reset_case
if [ -z "$ID_AP1" ]; then
  fail_g "no agentplugins format on this image (create answered: ${AP1_BODY})"
else
  [ "$AP_P1" = "201" ] || [ "$AP_P1" = "200" ] || fail_g "publish into A answered ${AP_P1}: ${AP_P1B}"
  [ "$AP_P2" = "201" ] || [ "$AP_P2" = "200" ] || fail_g "publish into B answered ${AP_P2} (pre-#5267: 409, the flat key is owned by A): ${AP_P2B}"
  [ "$AP_G1" = "200:${AP_SHA}" ] || fail_g "A serves ${AP_G1} (want 200:${AP_SHA})"
  [ "$AP_G2" = "200:${AP_SHA}" ] || fail_g "B serves ${AP_G2} (want 200:${AP_SHA})"
fi
finish_case "the second repository could not publish the same plugin version"

# =============================================================================
# #5277 helm: a Remote accepts upstream dependencies without a version
# =============================================================================
helm_idx(){ # <dir> <with-version: yes|no>
  {
    echo "apiVersion: v1"
    echo "entries:"
    echo "  ffhelm:"
    echo "  - apiVersion: v2"
    echo "    name: ffhelm"
    echo "    version: 1.0.0"
    echo "    dependencies:"
    echo "    - name: sub"
    [ "$2" = yes ] && echo "      version: 0.1.0"
    echo "      repository: file://./charts/sub"
    echo "    urls:"
    echo "    - ${UP}/$1/ffhelm-1.0.0.tgz"
    echo "    digest: \"0000000000000000000000000000000000000000000000000000000000000000\""
    echo "generated: \"2026-11-01T00:00:00Z\""
  } >"$W/$1.index.yaml"
  mock_put "/$1/index.yaml" "$W/$1.index.yaml" application/x-yaml
}
HB="hb${SFX}"; HC="hc${SFX}"
helm_idx "$HB" no >/dev/null; helm_idx "$HC" yes >/dev/null
R_HB="ff-helmb-${SFX}"; R_HC="ff-helmc-${SFX}"
mkrepo "$R_HB" helm remote "${UP}/${HB}" >/dev/null
mkrepo "$R_HC" helm remote "${UP}/${HC}" >/dev/null
H_B="$(anon "/helm/${R_HB}/index.yaml" "$W/helmb.yaml")"
H_C="$(anon "/helm/${R_HC}/index.yaml" "$W/helmc.yaml")"
echo "-- helm versionless=${H_B} ($(body "$W/helmb.yaml" 120)); versioned=${H_C}"

begin_test "CONTROL: helm: a Remote whose upstream index pins dependency versions serves index.yaml"
if [ "$H_C" = "200" ] && grep -q 'name: ffhelm' "$W/helmc.yaml" && grep -q 'version: 0.1.0' "$W/helmc.yaml"; then pass
else fail "versioned upstream index answered ${H_C}" "$(body "$W/helmc.yaml")"; fi

begin_test "FIX #5277: helm: a Remote whose upstream index has a versionless dependency serves index.yaml"
if [ "$H_B" = "200" ] && grep -q 'name: ffhelm' "$W/helmb.yaml" && grep -q 'name: sub' "$W/helmb.yaml"; then pass
else fail "versionless-dependency upstream index answered ${H_B} (want 200); pre-#5277 the whole index failed to parse" "$(body "$W/helmb.yaml")"; fi

# =============================================================================
# #5739 conda: allowlist '*' against a name with a literal '*'
# =============================================================================
N5739="$(tr -dc a-z0-9 </dev/urandom 2>/dev/null | head -c6)"
STAR="dtfst*r${N5739}"; PLAIN="dtfstxr${N5739}"
CCH="cc${SFX}"
python3 -I - "$W/cch.json" "$STAR" "$PLAIN" <<'PY'
import json, sys
out, *names = sys.argv[1:]
pk = {}
for n in names:
    pk[f"{n}-1.0-0.tar.bz2"] = {"name": n, "version": "1.0", "build": "0", "build_number": 0,
        "depends": [], "license": "MIT", "subdir": "noarch", "noarch": "generic",
        "md5": "0" * 32, "sha256": "0" * 64, "size": 1, "timestamp": 1700000000000}
json.dump({"info": {"subdir": "noarch"}, "packages": pk, "packages.conda": {}, "removed": [], "repodata_version": 1}, open(out, "w"))
PY
bzip2 -kc "$W/cch.json" >"$W/cch.json.bz2"
zstd -q -c "$W/cch.json" >"$W/cch.json.zst"
printf '{"info":{"subdir":"linux-64"},"packages":{},"packages.conda":{},"removed":[],"repodata_version":1}' >"$W/cch.empty.json"
mock_put "/${CCH}/noarch/repodata.json" "$W/cch.json" application/json >/dev/null
mock_put "/${CCH}/noarch/repodata.json.bz2" "$W/cch.json.bz2" application/x-bzip2 >/dev/null
mock_put "/${CCH}/noarch/repodata.json.zst" "$W/cch.json.zst" application/zstd >/dev/null
mock_put "/${CCH}/linux-64/repodata.json" "$W/cch.empty.json" application/json >/dev/null
R_CR="ff-condar-${SFX}"; R_CV="ff-condav-${SFX}"
mkrepo "$R_CR" conda remote "${UP}/${CCH}/" >/dev/null
mkrepo "$R_CV" conda virtual >/dev/null
CM="$(post_json "/api/v1/repositories/${R_CV}/members" "$W/cmem.json" "$(jq -nc --arg k "$R_CR" '{member_key:$k}')")"
CA="$(http PUT "/api/v1/repositories/${R_CV}/allowlist" "$W/callow.json" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"entries":[{"name":"dtfst*"}]}')"
CR_C="$(anon "/conda/${R_CR}/noarch/repodata.json" "$W/cr.json")"
CV_C="$(anon "/conda/${R_CV}/noarch/repodata.json" "$W/cv.json")"
c_has(){ jq -e --arg n "$2" '[(.packages // {}), (.["packages.conda"] // {})] | add | has($n)' "$1" >/dev/null 2>&1; }
c_keys(){ jq -c '[(.packages // {}), (.["packages.conda"] // {})] | add | keys' "$1" 2>/dev/null | head -c 300; }
echo "-- conda member=${CM} allowlist=${CA}; remote=${CR_C} $(c_keys "$W/cr.json"); virtual=${CV_C} $(c_keys "$W/cv.json")"

begin_test "CONTROL: conda: the Remote lists both upstream records, the allowlisted virtual lists the ordinary name"
if [ "$CR_C" = "200" ] && c_has "$W/cr.json" "${STAR}-1.0-0.tar.bz2" && c_has "$W/cr.json" "${PLAIN}-1.0-0.tar.bz2" \
   && [ "$CV_C" = "200" ] && c_has "$W/cv.json" "${PLAIN}-1.0-0.tar.bz2"; then
  pass
else
  fail "remote=${CR_C} $(c_keys "$W/cr.json") virtual=${CV_C} $(c_keys "$W/cv.json") member=${CM} allowlist=${CA}" \
    "$(body "$W/cr.json") / $(body "$W/cv.json") / $(body "$W/callow.json")"
fi

begin_test "FIX #5739: conda: allowlist entry dtfst* admits a record whose name contains a literal '*'"
if [ "$CV_C" = "200" ] && c_has "$W/cv.json" "${STAR}-1.0-0.tar.bz2"; then pass
else fail "the virtual dropped ${STAR} (pre-#5739 the pattern '*' was consumed as a literal against the name's '*')" "virtual keys $(c_keys "$W/cv.json")"; fi

# =============================================================================
# #5167 conda: the empty-subdir .bz2 answers without a regen permit
# =============================================================================
R_CH="ff-condah-${SFX}"
mkrepo "$R_CH" conda >/dev/null
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
CH_UP=""
for sd in noarch linux-64; do
  f="$(bash "$BUILD" "$W/conda-$sd" "ffpermit" 1.0 0 "$sd" 2>/dev/null | tail -n1)"
  c="$(http PUT "/conda/${R_CH}/${sd}/$(basename "$f")" "$W/ch.put" --data-binary "@$f")"
  CH_UP="${CH_UP}${sd}=${c} "
done
LOCKQ="BEGIN; LOCK TABLE conda_repodata_jlap IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(40); COMMIT;"
lock_release(){ psql_x "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%LOCK TABLE conda_repodata_jlap%' AND pid <> pg_backend_pid();"; }
docker exec -d "$DBC" psql -U registry -d artifact_registry -c "$LOCKQ" >/dev/null 2>&1
HELD=0
for _ in $(seq 1 40); do
  HELD="$(psql_q "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE c.relname='conda_repodata_jlap' AND l.granted AND l.mode='AccessExclusiveLock'")"
  [ "${HELD:-0}" -ge 1 ] 2>/dev/null && break
  sleep 0.25
done
# Two named-subdir renders take both permits and stall on the held lock.
( curl -s -o /dev/null --max-time 60 "${BASE}/conda/${R_CH}/noarch/repodata.json" ) &
BG1=$!
( curl -s -o /dev/null --max-time 60 "${BASE}/conda/${R_CH}/linux-64/repodata.json" ) &
BG2=$!
WAITING=0
for _ in $(seq 1 40); do
  WAITING="$(psql_q "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE c.relname='conda_repodata_jlap' AND NOT l.granted")"
  [ "${WAITING:-0}" -ge 2 ] 2>/dev/null && break
  sleep 0.25
done
t_get(){ # <path> <out> -> "<code> <seconds>"
  local s e c; s="$(date +%s.%N)"
  c="$(curl -s --max-time 10 -o "$2" -w '%{http_code}' "${BASE}$1" 2>/dev/null || true)"
  e="$(date +%s.%N)"; printf '%s %.1f' "${c:-000}" "$(awk -v a="$s" -v b="$e" 'BEGIN{print b-a}')"
}
E_JSON="$(t_get "/conda/${R_CH}/osx-arm64/repodata.json" "$W/e.json")"
E_ZST="$(t_get "/conda/${R_CH}/osx-arm64/repodata.json.zst" "$W/e.zst")"
E_BZ2="$(t_get "/conda/${R_CH}/osx-arm64/repodata.json.bz2" "$W/e.bz2")"
lock_release
wait "$BG1" "$BG2" 2>/dev/null
echo "-- conda uploads ${CH_UP}; lock held=${HELD} waiters=${WAITING}; empty subdir json=${E_JSON} zst=${E_ZST} bz2=${E_BZ2}"

begin_test "CONTROL: conda: empty-subdir repodata.json and .zst answer while both regen permits are held"
if [ "${HELD:-0}" -lt 1 ] 2>/dev/null || [ "${WAITING:-0}" -lt 2 ] 2>/dev/null; then
  infra_fail "could not saturate the regen permits (lock held=${HELD}, renders waiting=${WAITING}, uploads ${CH_UP})"
elif [ "${E_JSON%% *}" = "200" ] && [ "${E_ZST%% *}" = "200" ]; then
  pass
else
  fail "json=${E_JSON} zst=${E_ZST}" "$(body "$W/e.json")"
fi

begin_test "FIX #5167: conda: empty-subdir repodata.json.bz2 answers without a regen permit"
if [ "${E_BZ2%% *}" = "200" ] && bzip2 -dc "$W/e.bz2" 2>/dev/null | jq -e '.info.subdir == "osx-arm64" or (.packages == {})' >/dev/null 2>&1; then
  pass
else
  fail "empty-subdir .bz2 answered '${E_BZ2}' (code seconds) while the permits were held; pre-#5167 it queued for a permit" "$(body "$W/e.bz2")"
fi

# =============================================================================
# #5716 glob: curation pattern matching is linear
# =============================================================================
R_CUR="ff-cur-${SFX}"
ID_CUR="$(mkrepo "$R_CUR" rpm)"
CURQ(){ psql_x "INSERT INTO curation_packages (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, status)
  VALUES ('${ID_CUR}', '${ID_CUR}', 'rpm', '$1', '1.0', '/$1', 'pending')"; }
cur_status(){ psql_q "SELECT status FROM curation_packages WHERE staging_repo_id='${ID_CUR}' AND package_name='$1'"; }
reeval(){ # -> "<code> <seconds>"
  local s e c; s="$(date +%s.%N)"
  c="$(curl -s --max-time 30 -o "$W/reeval.json" -w '%{http_code}' -X POST -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg s "$ID_CUR" '{staging_repo_id:$s,default_action:"allow"}')" \
    "${BASE}/api/v1/curation/packages/re-evaluate" 2>/dev/null || true)"
  e="$(date +%s.%N)"; printf '%s %.1f' "${c:-000}" "$(awk -v a="$s" -v b="$e" 'BEGIN{print b-a}')"
}
CR1="$(post_json /api/v1/curation/rules "$W/rule1.json" "$(jq -nc --arg s "$ID_CUR" '{staging_repo_id:$s,package_pattern:"telnet*",action:"block",reason:"ff control"}')")"
CURQ telnet-server
RE1="$(reeval)"; ST1="$(cur_status telnet-server)"
echo "-- curation control rule=${CR1} re-evaluate=${RE1} telnet-server=${ST1}"

begin_test "CONTROL: curation: a pattern rule blocks a matching pending package on re-evaluate"
if [ "$CR1" = "201" ] && [ "${RE1%% *}" = "200" ] && [ "$ST1" = "blocked" ]; then pass
else fail "rule=${CR1} re-evaluate=${RE1} status=${ST1}" "$(body "$W/rule1.json") / $(body "$W/reeval.json")"; fi

PAT="$(printf '*a%.0s' $(seq 1 8))b"
NAME="$(printf 'a%.0s' $(seq 1 80))"
CR2="$(post_json /api/v1/curation/rules "$W/rule2.json" "$(jq -nc --arg s "$ID_CUR" --arg p "$PAT" '{staging_repo_id:$s,package_pattern:$p,action:"block",reason:"ff glob"}')")"
CURQ "$NAME"
RE2="$(reeval)"; ST2="$(cur_status "$NAME")"
echo "-- glob rule ${PAT} create=${CR2}; re-evaluate=${RE2} (code seconds) status=${ST2}"

begin_test "FIX #5716: curation: re-evaluating a many-wildcard pattern against a long name returns in under 2 s"
SECS="${RE2#* }"
if [ "$CR2" != "201" ]; then
  fail "creating the pattern rule answered ${CR2}" "$(body "$W/rule2.json")"
elif [ "${RE2%% *}" = "200" ] && awk -v s="$SECS" 'BEGIN{exit !(s < 2.0)}' && [ -n "$ST2" ] && [ "$ST2" != "blocked" ] && [ "$ST2" != "pending" ]; then
  pass
else
  fail "re-evaluate answered '${RE2}' (code seconds; want 200 in < 2 s, the 30 s cap means 000), status=${ST2}; pre-#5716 the glob backtracked through every split" "$(body "$W/reeval.json")"
fi

end_suite
