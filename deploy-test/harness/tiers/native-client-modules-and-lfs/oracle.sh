#!/usr/bin/env bash
# =============================================================================
# tiers/native-client-modules-and-lfs/oracle.sh
#   #4590 terraform init installs hosted modules: X-Terraform-Get carries
#         ?archive=zip|tar.gz, /archive is served with the matching type, a
#         plain tar upload is refused
#   #4598 terraform init through a virtual Terraform repository: union
#         /versions, 204 + X-Terraform-Get to the virtual's own /archive
#   #4570 git lfs pull from a PRIVATE repository completes: download actions
#         carry the caller's Authorization, batch answers Cache-Control: no-store
#   #4528 a NuGet Remote's flat-container download lowercases the whole path
#   #4476 a Maven snapshot redeploy to the same timestamped path is accepted
# See the manifest for THE BUGS, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, TRIVY_PORT (mock-files control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit. A client that fails (terraform init, git lfs pull)
# is an observation this oracle records and judges, never a reason to abort.
set +e

BASE="$BASE_URL"
ADMIN="${ADMIN_USER:-admin}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
MOCK_INT="http://172.16.${DTF_SLOT}.76"   # the address the BACKEND reaches mock-files at
TF_CLIENT="ak-dtf${DTF_SLOT}-client-terraform"
TF_CADDY="ak-dtf${DTF_SLOT}-caddy-tfmod"
TF_HOST="tfm.dtf.local"
LFS_CLIENT="ak-dtf${DTF_SLOT}-client-gitlfs"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
BASIC="Basic $(printf '%s:%s' "$ADMIN" "$ADMIN_PASS" | base64 | tr -d '\n')"

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# aput <outfile> <path> <file> [curl args...] -> http code (admin bearer)
aput(){
  local out="$1" p="$2" f="$3"; shift 3
  curl -s --max-time 60 -o "$out" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    --data-binary "@$f" "$@" "$BASE$p" || true
}
# hdr <path> -> response headers of an anonymous GET (body discarded)
hdr(){ curl -s --max-time 30 -D - -o /dev/null "$BASE$1" | tr -d '\r' || true; }
hval(){ awk -v k="$(echo "$1" | tr '[:upper:]' '[:lower:]')" 'BEGIN{FS=": "} tolower($1)==k {sub(/^[^:]*: /,""); print; exit}'; }

mk_repo(){ # <key> <format> <type> <public> [upstream]
  local body
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --argjson p "$4" --arg u "${5:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:$p} + (if $u == "" then {} else {upstream_url:$u} end)')"
  curl -s --max-time 30 -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty'
}
add_member(){ # <virtual> <member>
  curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/$1/members" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$2" '{member_key:$k}')" || true
}

# make_module <zip|tgz|tar> <marker> <outfile>: a one-file module whose
# main.tf outputs <marker>. Built with the host's python3 (stdlib only).
make_module(){
  python3 -I - "$1" "$2" "$3" <<'PY'
import io, sys, tarfile, zipfile
kind, marker, out = sys.argv[1], sys.argv[2], sys.argv[3]
src = ('output "marker" {\n  value = "%s"\n}\n' % marker).encode()
if kind == "zip":
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("main.tf", src)
else:
    mode = "w:gz" if kind == "tgz" else "w"
    with tarfile.open(out, mode) as t:
        ti = tarfile.TarInfo("main.tf"); ti.size = len(src); ti.mtime = 1700000000
        t.addfile(ti, io.BytesIO(src))
PY
}

# =============================================================================
begin_suite "native-client-modules-and-lfs"

begin_test "setup: admin login, repositories, mock NuGet feed, client containers"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN}\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock-files not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${RUN_ID##*-}"
R_TFA="tfa-${SUF}"; R_TFB="tfb-${SUF}"; R_TFV="tfv-${SUF}"
R_LFS="lfs-${SUF}"; R_NUG="nug-${SUF}"; R_MVN="mvn-${SUF}"
SETUP_ERR=""
[ "$(mk_repo "$R_TFA" terraform local true)" = "$R_TFA" ] || SETUP_ERR="${SETUP_ERR} ${R_TFA}"
[ "$(mk_repo "$R_TFB" terraform local true)" = "$R_TFB" ] || SETUP_ERR="${SETUP_ERR} ${R_TFB}"
[ "$(mk_repo "$R_TFV" terraform virtual true)" = "$R_TFV" ] || SETUP_ERR="${SETUP_ERR} ${R_TFV}"
[ "$(mk_repo "$R_LFS" gitlfs local false)" = "$R_LFS" ] || SETUP_ERR="${SETUP_ERR} ${R_LFS}"
[ "$(mk_repo "$R_MVN" maven local false)" = "$R_MVN" ] || SETUP_ERR="${SETUP_ERR} ${R_MVN}"
for m in "$R_TFA" "$R_TFB"; do
  c="$(add_member "$R_TFV" "$m")"
  case "$c" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} member:${m}=${c}";; esac
done

# Mock NuGet V3 feed on mock-files: a service index whose PackageBaseAddress is
# on the same host, and ONE package stored at its all-lowercase flat-container
# path. mock-files matches paths exactly (case-sensitive), as nuget.org does.
NUPKG="$W/newtonsoft.json.13.0.3.nupkg"
python3 -I - "$NUPKG" "$SUF" <<'PY'
import sys, zipfile
out, marker = sys.argv[1], sys.argv[2]
nuspec = ('<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
          '<metadata><id>Newtonsoft.Json</id><version>13.0.3</version><authors>dtf</authors>'
          '<description>dtf %s</description></metadata></package>' % marker)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("Newtonsoft.Json.nuspec", nuspec)
    z.writestr("lib/netstandard2.0/_._", "")
PY
NIDX="$(jq -n --arg b "${MOCK_INT}/nuget/flat/" '{version:"3.0.0",resources:[{"@id":$b,"@type":"PackageBaseAddress/3.0.0"}]}')"
c1="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X PUT --data-binary "$NIDX" \
  "${MOCK}/__file?path=/nuget/v3/index.json&ctype=application/json" || true)"
c2="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X PUT --data-binary "@$NUPKG" \
  "${MOCK}/__file?path=/nuget/flat/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg&ctype=application/octet-stream" || true)"
c3="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X PUT --data-binary '{"versions":["13.0.3"]}' \
  "${MOCK}/__file?path=/nuget/flat/newtonsoft.json/index.json&ctype=application/json" || true)"
[ "$c1$c2$c3" = "200200200" ] || SETUP_ERR="${SETUP_ERR} mock-nuget-files(${c1},${c2},${c3})"
[ "$(mk_repo "$R_NUG" nuget remote true "${MOCK_INT}/nuget/v3/index.json")" = "$R_NUG" ] || SETUP_ERR="${SETUP_ERR} ${R_NUG}"

for ctr in "$TF_CLIENT" "$TF_CADDY" "$LFS_CLIENT"; do
  [ "$(docker inspect -f '{{.State.Running}}' "$ctr" 2>/dev/null)" = "true" ] || SETUP_ERR="${SETUP_ERR} container:${ctr}"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- repos: ${R_TFA} ${R_TFB} -> virtual ${R_TFV}; ${R_LFS} (private); ${R_NUG} -> ${MOCK_INT}; ${R_MVN}"
pass

# =============================================================================
# Terraform modules. Module coordinates live under the AK namespace `dtf`
# (the Caddyfile maps the registry namespace onto the repository key).
#   R_TFA: zipmod 1.0.0 (ZIP)      vmod 1.0.0 (ZIP)
#   R_TFB: tgzmod 1.0.0 (tar.gz)   vmod 2.0.0 (tar.gz)
#   R_TFV: virtual over both -> vmod lists 1.0.0 and 2.0.0
# =============================================================================
MOD="/terraform"
make_module zip "zip-${SUF}" "$W/zipmod.zip"
make_module tgz "tgz-${SUF}" "$W/tgzmod.tgz"
make_module zip "vzip-${SUF}" "$W/vmod1.zip"
make_module tgz "vtgz-${SUF}" "$W/vmod2.tgz"
make_module tar "tar-${SUF}" "$W/plain.tar"

begin_test "CONTROL: hosted module upload, /versions and the bytes behind X-Terraform-Get"
reset_case
c="$(aput "$W/u1" "$MOD/${R_TFA}/v1/modules/dtf/zipmod/dtf/1.0.0" "$W/zipmod.zip")"; note "PUT zipmod 1.0.0 (zip): ${c}"
case "$c" in 2*) ;; *) fail_g "zip module upload answered ${c}: $(head -c 200 "$W/u1")";; esac
c="$(aput "$W/u2" "$MOD/${R_TFB}/v1/modules/dtf/tgzmod/dtf/1.0.0" "$W/tgzmod.tgz")"; note "PUT tgzmod 1.0.0 (tar.gz): ${c}"
case "$c" in 2*) ;; *) fail_g "tar.gz module upload answered ${c}: $(head -c 200 "$W/u2")";; esac
c="$(aput "$W/u3" "$MOD/${R_TFA}/v1/modules/dtf/vmod/dtf/1.0.0" "$W/vmod1.zip")"; note "PUT vmod 1.0.0 (zip) to ${R_TFA}: ${c}"
case "$c" in 2*) ;; *) fail_g "vmod 1.0.0 upload answered ${c}";; esac
c="$(aput "$W/u4" "$MOD/${R_TFB}/v1/modules/dtf/vmod/dtf/2.0.0" "$W/vmod2.tgz")"; note "PUT vmod 2.0.0 (tar.gz) to ${R_TFB}: ${c}"
case "$c" in 2*) ;; *) fail_g "vmod 2.0.0 upload answered ${c}";; esac
vers="$(curl -s --max-time 30 "$BASE$MOD/${R_TFA}/v1/modules/dtf/zipmod/dtf/versions" | jqr '[.modules[0].versions[].version]|join(",")')"
note "hosted zipmod /versions: [${vers}]"
[ "$vers" = "1.0.0" ] || fail_g "hosted /versions lists [${vers}], expected [1.0.0]"
H="$(hdr "$MOD/${R_TFA}/v1/modules/dtf/zipmod/dtf/1.0.0/download")"
loc="$(echo "$H" | hval X-Terraform-Get)"
note "hosted zipmod /download: $(echo "$H" | head -1) X-Terraform-Get: ${loc}"
echo "$H" | head -1 | grep -q ' 204' || fail_g "hosted /download did not answer 204"
[ -n "$loc" ] || fail_g "hosted /download carried no X-Terraform-Get"
if [ -n "$loc" ]; then
  # The location is relative to the server; strip any go-getter query.
  curl -s --max-time 30 -o "$W/zipmod.got" "$BASE${loc%%\?*}" || true
  [ "$(sha_of "$W/zipmod.got")" = "$(sha_of "$W/zipmod.zip")" ] \
    || fail_g "the advertised archive is not the uploaded bytes ($(sha_of "$W/zipmod.got") vs $(sha_of "$W/zipmod.zip"))"
fi
finish_case "hosted Terraform module control failed"

begin_test "FIX #4590: X-Terraform-Get names the archive type, /archive serves the matching Content-Type, plain tar is refused"
reset_case
for spec in "${R_TFA}:zipmod:zip:application/zip" "${R_TFB}:tgzmod:tar.gz:application/gzip"; do
  IFS=: read -r repo name hint ctype <<<"$spec"
  H="$(hdr "$MOD/${repo}/v1/modules/dtf/${name}/dtf/1.0.0/download")"
  loc="$(echo "$H" | hval X-Terraform-Get)"
  note "${name}: X-Terraform-Get: ${loc}"
  case "$loc" in
    *"/archive?archive=${hint}") ;;
    *) fail_g "${name}: X-Terraform-Get '${loc}' does not end in /archive?archive=${hint}";;
  esac
  AH="$(hdr "$MOD/${repo}/v1/modules/dtf/${name}/dtf/1.0.0/archive")"
  act="$(echo "$AH" | hval Content-Type)"; disp="$(echo "$AH" | hval Content-Disposition)"
  note "${name}: /archive Content-Type: ${act}; Content-Disposition: ${disp}"
  case "$act" in "$ctype"*) ;; *) fail_g "${name}: /archive Content-Type '${act}', expected ${ctype}";; esac
  ext="${hint}"
  case "$disp" in *".${ext}"*) ;; *) fail_g "${name}: /archive filename '${disp}' does not end in .${ext}";; esac
done
c="$(aput "$W/u5" "$MOD/${R_TFA}/v1/modules/dtf/plainmod/dtf/1.0.0" "$W/plain.tar")"
note "PUT plain (uncompressed) tar: ${c} $(head -c 160 "$W/u5")"
[ "$c" = "400" ] || fail_g "an uncompressed tar module upload answered ${c}, expected 400"
grep -qi 'tar' "$W/u5" || fail_g "the 400 body does not explain the refused archive type"
finish_case "#4590 archive-type advertisement failed"

begin_test "FIX #4598: a virtual Terraform repository lists the union of versions and answers /download with its own /archive"
reset_case
vers="$(curl -s --max-time 30 "$BASE$MOD/${R_TFV}/v1/modules/dtf/vmod/dtf/versions" | jqr '[.modules[0].versions[].version]|sort|join(",")')"
note "virtual vmod /versions: [${vers}]"
[ "$vers" = "1.0.0,2.0.0" ] || fail_g "virtual /versions lists [${vers}], expected the union [1.0.0,2.0.0]"
for spec in "1.0.0:zip" "2.0.0:tar.gz"; do
  IFS=: read -r v hint <<<"$spec"
  H="$(hdr "$MOD/${R_TFV}/v1/modules/dtf/vmod/dtf/${v}/download")"
  st="$(echo "$H" | head -1)"; loc="$(echo "$H" | hval X-Terraform-Get)"
  note "virtual vmod ${v} /download: ${st}; X-Terraform-Get: ${loc}"
  echo "$st" | grep -q ' 204' || fail_g "virtual /download ${v} answered '${st}', expected 204"
  case "$loc" in
    "$MOD/${R_TFV}/v1/modules/dtf/vmod/dtf/${v}/archive?archive=${hint}"|*"://"*"$MOD/${R_TFV}/v1/modules/dtf/vmod/dtf/${v}/archive?archive=${hint}") ;;
    *) fail_g "virtual /download ${v}: X-Terraform-Get '${loc}' is not the virtual's own /archive?archive=${hint}";;
  esac
  if [ -n "$loc" ]; then
    curl -s --max-time 30 -o "$W/v${v}.got" "$BASE${loc%%\?*}" || true
    want="$W/vmod1.zip"; [ "$v" = "2.0.0" ] && want="$W/vmod2.tgz"
    [ "$(sha_of "$W/v${v}.got")" = "$(sha_of "$want")" ] || fail_g "virtual /archive ${v} is not the member's uploaded bytes"
  fi
done
finish_case "#4598 virtual module protocol failed"

begin_test "FIX #4590/#4598: a real 'terraform init' installs a hosted ZIP and tar.gz module and both versions through the virtual"
reset_case
ca="$W/caddy-root.crt"
ok_ca=0
for _i in $(seq 1 20); do
  docker cp "${TF_CADDY}:/data/caddy/pki/authorities/local/root.crt" "$ca" >/dev/null 2>&1 && ok_ca=1 && break
  # caddy mints its internal CA on the first TLS handshake it serves.
  docker exec "$TF_CLIENT" sh -c "wget -q -O /dev/null --no-check-certificate https://${TF_HOST}/.well-known/terraform.json" >/dev/null 2>&1 || true
  sleep 1
done
if [ "$ok_ca" != 1 ] || ! docker cp "$ca" "${TF_CLIENT}:/usr/local/share/ca-certificates/dtf-caddy-tfmod.crt" >/dev/null 2>&1; then
  infra_fail "could not install caddy-tfmod's internal CA into ${TF_CLIENT}"
else
  docker exec -u root "$TF_CLIENT" sh -c 'update-ca-certificates >/dev/null 2>&1 || cat /usr/local/share/ca-certificates/dtf-caddy-tfmod.crt >> /etc/ssl/certs/ca-certificates.crt'
  docker exec -u root "$TF_CLIENT" sh -c "rm -rf /root/tfm && mkdir -p /root/tfm && cat > /root/tfm/main.tf <<EOF
module \"hosted_zip\" {
  source  = \"${TF_HOST}/${R_TFA}/zipmod/dtf\"
  version = \"1.0.0\"
}
module \"hosted_tgz\" {
  source  = \"${TF_HOST}/${R_TFB}/tgzmod/dtf\"
  version = \"1.0.0\"
}
module \"virtual_v1\" {
  source  = \"${TF_HOST}/${R_TFV}/vmod/dtf\"
  version = \"1.0.0\"
}
module \"virtual_v2\" {
  source  = \"${TF_HOST}/${R_TFV}/vmod/dtf\"
  version = \"2.0.0\"
}
output \"all\" {
  value = join(\",\", [module.hosted_zip.marker, module.hosted_tgz.marker, module.virtual_v1.marker, module.virtual_v2.marker])
}
EOF"
  out="$(docker exec -u root -w /root/tfm "$TF_CLIENT" timeout 180 terraform init -no-color -input=false 2>&1)"; rc=$?
  note "terraform init rc ${rc}:"; note "$(echo "$out" | grep -v '^$' | tail -16)"
  [ "$rc" -eq 0 ] || fail_g "terraform init failed"
  if [ "$rc" -eq 0 ]; then
    out2="$(docker exec -u root -w /root/tfm "$TF_CLIENT" sh -c 'timeout 120 terraform apply -no-color -input=false -auto-approve >/dev/null 2>&1 && terraform output -raw all' 2>&1)"
    note "terraform output all: ${out2}"
    want="zip-${SUF},tgz-${SUF},vzip-${SUF},vtgz-${SUF}"
    [ "$out2" = "$want" ] || fail_g "the installed modules output '${out2}', expected '${want}'"
  fi
fi
finish_case "real terraform init of hosted and virtual modules failed"

# =============================================================================
# Git LFS on a PRIVATE repository
# =============================================================================
lfs_batch(){ # <op> <outfile> <headers-file> -> http code (basic auth)
  local body
  body="$(jq -n --arg op "$1" --arg oid "$LFS_OID" --argjson sz "$LFS_SIZE" \
    '{operation:$op,transfers:["basic"],objects:[{oid:$oid,size:$sz}]}')"
  curl -s --max-time 30 -o "$2" -D "$3" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/vnd.git-lfs+json' -H 'Accept: application/vnd.git-lfs+json' \
    -H "Authorization: ${BASIC}" --data-binary "$body" "$BASE/lfs/${R_LFS}/objects/batch" || true
}

begin_test "CONTROL: a real git push uploads an LFS object to a PRIVATE repo; upload actions carry Authorization; anonymous object GET is refused"
reset_case
LFS_OID=""; LFS_SIZE=0
ready=0
for _i in $(seq 1 60); do
  docker exec "$LFS_CLIENT" sh -c 'command -v git-lfs && command -v bash' >/dev/null 2>&1 && ready=1 && break
  sleep 2
done
if [ "$ready" != 1 ]; then
  infra_fail "git/git-lfs never appeared in ${LFS_CLIENT}"
else
  out="$(docker exec "$LFS_CLIENT" bash -c "set -e
git config --global user.email dtf@example.invalid
git config --global user.name 'DTF Rig'
git config --global credential.helper store
git config --global init.defaultBranch main
printf 'http://%s:%s@backend:8080\n' '${ADMIN}' '$(printf '%s' "$ADMIN_PASS" | jq -sRr @uri)' > /root/.git-credentials
git lfs install --skip-repo >/dev/null
rm -rf /srv/bare /srv/work /srv/pull
git init -q --bare /srv/bare
git init -q /srv/work && cd /srv/work
printf '[lfs]\n\turl = http://backend:8080/lfs/${R_LFS}\n' > .lfsconfig
git lfs track '*.bin' >/dev/null
head -c 524288 /dev/urandom > blob.bin
git add .gitattributes .lfsconfig blob.bin
git commit -qm blob
git remote add origin file:///srv/bare
timeout 120 git push -q -u origin main 2>&1
git lfs pointer --file blob.bin 2>/dev/null | sed -n 's#^oid sha256:##p'
stat -c %s blob.bin" 2>&1)"; rc=$?
  LFS_OID="$(echo "$out" | grep -E '^[0-9a-f]{64}$' | tail -1)"
  LFS_SIZE="$(echo "$out" | tail -1 | tr -cd '0-9')"
  note "git push rc ${rc}; oid=${LFS_OID} size=${LFS_SIZE}"
  [ "$rc" -eq 0 ] && [ -n "$LFS_OID" ] || { fail_g "git push (LFS upload) to the private repo failed"; note "$(echo "$out" | tail -8)"; }
  if [ -n "$LFS_OID" ]; then
    c="$(curl -s --max-time 30 -o "$W/lfs.anon" -w '%{http_code}' "$BASE/lfs/${R_LFS}/objects/${LFS_OID}" || true)"
    note "anonymous object GET: ${c}"
    case "$c" in 401|403|404) ;; *) fail_g "anonymous GET of a private LFS object answered ${c}";; esac
    c="$(curl -s --max-time 30 -o "$W/lfs.authd" -w '%{http_code}' -H "Authorization: ${BASIC}" "$BASE/lfs/${R_LFS}/objects/${LFS_OID}" || true)"
    note "authenticated object GET: ${c}, sha $(sha_of "$W/lfs.authd")"
    [ "$c" = "200" ] && [ "$(sha_of "$W/lfs.authd")" = "$LFS_OID" ] || fail_g "authenticated object GET did not return the object bytes"
    # A fresh OID (not stored) negotiates an upload: its actions carry the header on both images.
    body="$(jq -n '{operation:"upload",transfers:["basic"],objects:[{oid:("ab"*32),size:3}]}')"
    curl -s --max-time 30 -o "$W/lfs.up" -X POST -H 'Content-Type: application/vnd.git-lfs+json' \
      -H "Authorization: ${BASIC}" --data-binary "$body" "$BASE/lfs/${R_LFS}/objects/batch" || true
    up_hdr="$(jqr '.objects[0].actions.upload.header.Authorization // empty' < "$W/lfs.up")"
    [ "$up_hdr" = "$BASIC" ] || fail_g "upload action header.Authorization is not the caller's credential"
  fi
fi
finish_case "private LFS upload control failed"

begin_test "FIX #4570: download actions carry the caller's Authorization, authenticated only with it, Cache-Control: no-store"
reset_case
if [ -z "$LFS_OID" ]; then
  fail_g "no LFS object to negotiate (the upload control failed)"
else
  c="$(lfs_batch download "$W/lfs.dl" "$W/lfs.dl.h")"
  dl_hdr="$(jqr '.objects[0].actions.download.header.Authorization // empty' < "$W/lfs.dl")"
  authd="$(jqr '.objects[0].authenticated' < "$W/lfs.dl")"
  cc="$(tr -d '\r' < "$W/lfs.dl.h" | hval Cache-Control)"
  hdr_state="absent"; [ -n "$dl_hdr" ] && hdr_state="present"
  note "download batch: ${c}; header.Authorization ${hdr_state}; authenticated=${authd}; Cache-Control=${cc}"
  [ "$c" = "200" ] || fail_g "download batch answered ${c}"
  [ "$dl_hdr" = "$BASIC" ] || fail_g "download action header.Authorization is ${hdr_state}; expected the caller's own credential"
  [ "$authd" = "true" ] || fail_g "an authenticated caller's download object is not marked authenticated (${authd})"
  case "$cc" in *no-store*) ;; *) fail_g "batch response Cache-Control '${cc}' lacks no-store";; esac
fi
finish_case "#4570 batch download action shape failed"

begin_test "FIX #4570: a real 'git lfs pull' from the PRIVATE repo completes with the published bytes"
reset_case
if [ -z "$LFS_OID" ]; then
  fail_g "no LFS object to pull (the upload control failed)"
else
  out="$(docker exec "$LFS_CLIENT" bash -c "set -e
rm -rf /srv/pull
GIT_LFS_SKIP_SMUDGE=1 git clone -q file:///srv/bare /srv/pull
cd /srv/pull && rm -rf .git/lfs
timeout 60 git lfs pull 2>&1
sha256sum blob.bin | cut -d' ' -f1" 2>&1)"; rc=$?
  got="$(echo "$out" | grep -E '^[0-9a-f]{64}$' | tail -1)"
  note "git lfs pull rc ${rc} (124 = hung until the 60 s timeout); pulled sha ${got:-none}"
  [ "$rc" -eq 0 ] || { fail_g "git lfs pull from the private repository did not complete"; note "$(echo "$out" | tail -6)"; }
  [ "$got" = "$LFS_OID" ] || fail_g "the pulled blob sha ${got:-none} != the published OID"
fi
finish_case "#4570 private git lfs pull failed"

# =============================================================================
# NuGet Remote flat-container casing
# =============================================================================
NFLAT="/nuget/${R_NUG}/v3/flatcontainer"
LOWER_PATH="/nuget/flat/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
nuget_get(){ curl -s --max-time 60 -o "$2" -w '%{http_code}' "$BASE$1" || true; }

begin_test "FIX #4528: a mixed-case flat-container download reaches the lowercase upstream path"
reset_case
before="$(curl -s --max-time 5 "${MOCK}/__requests?path=${LOWER_PATH}" | jqr '.get')"
c="$(nuget_get "${NFLAT}/Newtonsoft.Json/13.0.3/Newtonsoft.Json.13.0.3.nupkg" "$W/n.mixed")"
note "mixed-case GET: ${c}, sha $(sha_of "$W/n.mixed")"
[ "$c" = "200" ] || fail_g "mixed-case flat-container GET answered ${c}, expected 200"
[ "$(sha_of "$W/n.mixed")" = "$(sha_of "$NUPKG")" ] || fail_g "mixed-case GET did not return the .nupkg bytes"
mixed_up="$(curl -s --max-time 5 "${MOCK}/__log" | grep -c 'Newtonsoft.Json.13.0.3.nupkg' || true)"
after="$(curl -s --max-time 5 "${MOCK}/__requests?path=${LOWER_PATH}" | jqr '.get')"
note "upstream: mixed-case file-name requests=${mixed_up}; lowercase path GETs ${before} -> ${after}"
[ "${after:-0}" -eq $(( ${before:-0} + 1 )) ] || fail_g "the cold mixed-case GET did not fetch the lowercase upstream path once (${before} -> ${after})"
[ "${mixed_up:-0}" -eq 0 ] || fail_g "the proxy asked the upstream for a mixed-case file name (${mixed_up} request(s))"
finish_case "#4528 NuGet Remote mixed-case download failed"

begin_test "CONTROL: a NuGet Remote serves the all-lowercase flat-container path with the upstream bytes"
reset_case
c="$(nuget_get "${NFLAT}/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg" "$W/n.lower")"
note "lowercase GET: ${c}, sha $(sha_of "$W/n.lower")"
[ "$c" = "200" ] || fail_g "lowercase flat-container GET answered ${c}"
[ "$(sha_of "$W/n.lower")" = "$(sha_of "$NUPKG")" ] || fail_g "lowercase GET did not return the upstream .nupkg bytes"
finish_case "NuGet Remote lowercase control failed"

# =============================================================================
# Maven snapshot redeploy
# =============================================================================
MV="/maven/${R_MVN}/com/dtf/obj"
mput(){ # <path> <content> -> code
  printf '%s' "$2" > "$W/mput.bin"
  curl -s --max-time 30 -o "$W/mput.out" -w '%{http_code}' -X PUT -H "Authorization: ${BASIC}" \
    --data-binary "@$W/mput.bin" "$BASE$1" || true
}
mget(){ curl -s --max-time 30 -H "Authorization: ${BASIC}" "$BASE$1" || true; }

begin_test "CONTROL: Maven release coordinates and a '-SNAPSHOT-rc1' version stay immutable (second PUT 409)"
reset_case
c1="$(mput "$MV/1.0/obj-1.0.jar" "rel-one")"; c2="$(mput "$MV/1.0/obj-1.0.jar" "rel-two")"
note "release obj-1.0.jar: first ${c1}, second ${c2} $(head -c 120 "$W/mput.out")"
case "$c1" in 2*) ;; *) fail_g "first release PUT answered ${c1}";; esac
[ "$c2" = "409" ] || fail_g "release redeploy answered ${c2}, expected 409"
[ "$(mget "$MV/1.0/obj-1.0.jar")" = "rel-one" ] || fail_g "release bytes changed after the refused redeploy"
c1="$(mput "$MV/1.0-SNAPSHOT-rc1/obj-1.0-SNAPSHOT-rc1.jar" "rc-one")"; c2="$(mput "$MV/1.0-SNAPSHOT-rc1/obj-1.0-SNAPSHOT-rc1.jar" "rc-two")"
note "1.0-SNAPSHOT-rc1: first ${c1}, second ${c2}"
case "$c1" in 2*) ;; *) fail_g "first 1.0-SNAPSHOT-rc1 PUT answered ${c1}";; esac
[ "$c2" = "409" ] || fail_g "a version that only contains the SNAPSHOT token is a release: second PUT answered ${c2}, expected 409"
finish_case "Maven release immutability control failed"

begin_test "FIX #4476: the same timestamped snapshot file PUT twice is accepted and replaced"
reset_case
TS="$MV/1.0-SNAPSHOT/obj-1.0-20261006.124037-3-clear.jar"
c1="$(mput "$TS" "snap-one-${SUF}")"; c2="$(mput "$TS" "snap-two-${SUF}")"
note "timestamped snapshot: first ${c1}, second ${c2} $(head -c 160 "$W/mput.out")"
case "$c1" in 2*) ;; *) fail_g "first timestamped snapshot PUT answered ${c1}";; esac
case "$c2" in 2*) ;; *) fail_g "redeploy of the same timestamped snapshot answered ${c2}, expected 2xx";; esac
got="$(mget "$TS")"
note "GET after redeploy: '${got}'"
[ "$got" = "snap-two-${SUF}" ] || fail_g "the redeployed snapshot serves '${got}', expected the second upload's bytes"
finish_case "#4476 snapshot redeploy failed"

end_suite
