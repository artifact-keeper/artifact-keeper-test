#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-member-gates-1120/oracle.sh
#   #5146 an empty hosted member does not tighten a Docker virtual's blob gate
#   #5147 a NuGet virtual resolves a mixed-case stored package name
#   #5150 an age-gated npm / PyPI member that does not host a version cannot
#         veto it through a virtual
#   #5151 a simple-index-only PyPI upstream: min_age_days 0 always passes, and
#         data-upload-time dates the files
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DB_CONTAINER:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"   # where the BACKEND reaches the mock
DBC="$DB_CONTAINER"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha256_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mock_put(){ # <path> <file> [content-type]
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}

# get <path> <out> [accept] -> ST; headers in <out>.h
get(){
  local a=()
  [ -n "${3:-}" ] && a=(-H "Accept: $3")
  ST="$(curl -s --max-time 120 -D "$2.h" -o "$2" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "${a[@]}" "${BASE}$1" || true)"
}
snip(){ head -c 200 "$1" 2>/dev/null | tr -c '[:print:]' ' ' || true; }

api(){ # <method> <path> [json] -> HTTP code, body in $W/api.json
  local args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer $TOK")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE}$2" 2>/dev/null || echo 000
}
mk(){ # <key> <format> <type> [upstream]
  local body c
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  c="$(api POST /api/v1/repositories "$body")"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} create:$1:${c}:$(snip "$W/api.json")";; esac
}
virt(){ # <key> <format> <member>...
  local key="$1" fmt="$2" prio=1 m c; shift 2
  mk "$key" "$fmt" virtual
  for m in "$@"; do
    c="$(api POST "/api/v1/repositories/${key}/members" "{\"member_key\":\"${m}\",\"priority\":${prio}}")"
    case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} member:${key}<-${m}:${c}";; esac
    prio=$((prio + 1))
  done
}
age_gate(){ # <key> <min days>
  local c
  c="$(api PUT "/api/v1/repositories/$1/age-gate" "{\"enabled\":true,\"min_age_days\":$2,\"mode\":\"upstream_publish_time\"}")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} age-gate:$1:${c}:$(snip "$W/api.json")"
}
reviews_on(){ psql_q "SELECT count(*) FROM age_gate_reviews g JOIN repositories r ON r.id=g.repository_id WHERE r.key='$1'"; }

# =============================================================================
begin_suite "virtual-member-gates-1120"

begin_test "setup: admin login, upstream documents, Remote / hosted / virtual repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
P="vmg${SUF}"
SETUP_ERR=""

# --- OCI: a one-layer image served as static registry paths ------------------
IMG="dtf/app${SUF}"
python3 -I - "$W/oci" "$SUF" <<'PY'
import gzip, hashlib, io, json, os, sys, tarfile
out, suf = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
raw = io.BytesIO()
# One inert npm package, so the scanner grades a non-empty catalog: a scan
# that catalogs nothing is inconclusive (423 under fail_closed), not clean.
with tarfile.open(fileobj=raw, mode="w") as t:
    for name, data in (("etc/os-release", b'ID="dtf"\nVERSION_ID="1"\n'),
                       ("app/node_modules/dtf-inert/package.json",
                        ('{"name":"dtf-inert","version":"1.0.0","description":"%s"}\n' % suf).encode())):
        ti = tarfile.TarInfo(name); ti.size = len(data); ti.mtime = 0
        t.addfile(ti, io.BytesIO(data))
layer = gzip.compress(raw.getvalue(), mtime=0)
diff_id = "sha256:" + hashlib.sha256(raw.getvalue()).hexdigest()
config = json.dumps({"architecture": "amd64", "os": "linux",
    "config": {"Cmd": ["/bin/true"]}, "created": "2020-01-01T00:00:00Z",
    "rootfs": {"type": "layers", "diff_ids": [diff_id]}}, sort_keys=True).encode()
d = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
manifest = json.dumps({"schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": d(config), "size": len(config)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d(layer), "size": len(layer)}]},
    sort_keys=True).encode()
for name, b in (("config", config), ("layer", layer), ("manifest", manifest)):
    open(os.path.join(out, name), "wb").write(b)
    open(os.path.join(out, name + ".digest"), "w").write(d(b))
PY
D_MAN="$(cat "$W/oci/manifest.digest" 2>/dev/null || true)"
D_CFG="$(cat "$W/oci/config.digest" 2>/dev/null || true)"
D_LAY="$(cat "$W/oci/layer.digest" 2>/dev/null || true)"
[ -n "$D_MAN" ] && [ -n "$D_CFG" ] && [ -n "$D_LAY" ] || SETUP_ERR="${SETUP_ERR} oci-build"
printf '{}' > "$W/oci/ping"
OCI_MT="application/vnd.oci.image.manifest.v1+json"
[ -n "$(mock_put "/v2/" "$W/oci/ping" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:/v2/"
[ -n "$(mock_put "/v2/${IMG}/manifests/1.0" "$W/oci/manifest" "$OCI_MT")" ] || SETUP_ERR="${SETUP_ERR} mock:manifest-tag"
[ -n "$(mock_put "/v2/${IMG}/manifests/${D_MAN}" "$W/oci/manifest" "$OCI_MT")" ] || SETUP_ERR="${SETUP_ERR} mock:manifest-digest"
[ -n "$(mock_put "/v2/${IMG}/blobs/${D_CFG}" "$W/oci/config")" ] || SETUP_ERR="${SETUP_ERR} mock:config"
[ -n "$(mock_put "/v2/${IMG}/blobs/${D_LAY}" "$W/oci/layer")" ] || SETUP_ERR="${SETUP_ERR} mock:layer"
D_R="vmg-dr-${SUF}"; D_L="vmg-dl-${SUF}"; DV_A="vmg-dva-${SUF}"; DV_B="vmg-dvb-${SUF}"
mk "$D_R" docker remote "${UP}/"
mk "$D_L" docker local
virt "$DV_A" docker "$D_R"
virt "$DV_B" docker "$D_L" "$D_R"
SEC='{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true,"severity_threshold":"high"}'
for k in "$D_R" "$DV_A" "$DV_B"; do
  c="$(api PUT "/api/v1/repositories/${k}/security" "$SEC")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} security:${k}:${c}:$(snip "$W/api.json")"
done

# --- NuGet: a hosted package whose stored name becomes mixed-case ------------
NU_MIXED="Dtf.Mixed${SUF}"; NU_NATIVE="Dtf.Native${SUF}"
nupkg(){ # <id> <version> <out>
  python3 -I - "$3" "$1" "$2" <<'PY'
import sys, zipfile
out, pid, ver = sys.argv[1:4]
nuspec = ('<?xml version="1.0" encoding="utf-8"?>\n'
          '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>'
          f'<id>{pid}</id><version>{ver}</version><authors>dtf</authors>'
          '<description>dtf virtual-member-gates</description></metadata></package>\n')
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr(f"{pid}.nuspec", nuspec)
    z.writestr("lib/net8.0/placeholder.txt", f"dtf {pid} {ver}\n")
PY
}
nupkg "$NU_MIXED" 1.0.2 "$W/mixed.nupkg"
nupkg "$NU_NATIVE" 1.0.2 "$W/native.nupkg"
N_H="vmg-nh-${SUF}"; N_V="vmg-nv-${SUF}"
mk "$N_H" nuget local
virt "$N_V" nuget "$N_H"
for f in mixed native; do
  c="$(curl -s --max-time 60 -o "$W/push.out" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -F "package=@$W/${f}.nupkg;type=application/octet-stream" "${BASE}/nuget/${N_H}/api/v2/package" || true)"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} nuget-push:${f}:${c}:$(snip "$W/push.out")";; esac
done
# Rewrite the first package's row the way the Artifactory importer stores it:
# the original-case id in artifacts.name and artifacts.path. storage_key (the
# bytes) is untouched.
ML="$(printf '%s' "$NU_MIXED" | tr '[:upper:]' '[:lower:]')"
NL="$(printf '%s' "$NU_NATIVE" | tr '[:upper:]' '[:lower:]')"
MIXED_PATH="${NU_MIXED}/1.0.2/${NU_MIXED}.1.0.2.nupkg"
n="$(psql_q "UPDATE artifacts a SET name='${NU_MIXED}', path='${MIXED_PATH}' FROM repositories r
  WHERE r.id=a.repository_id AND r.key='${N_H}' AND lower(a.name)='${ML}' AND a.path LIKE '%.nupkg' RETURNING a.id" | wc -c)"
[ "$n" -gt 1 ] || SETUP_ERR="${SETUP_ERR} nuget-row-rewrite"

# --- npm: one member hosts an old version, the other does not host it -------
NPKG="dtfnpm${SUF}"
mkdir -p "$W/npm/package"
printf '{"name":"%s","version":"1.0.0"}\n' "$NPKG" > "$W/npm/package/package.json"
tar -czf "$W/npm.tgz" -C "$W/npm" package
NSHA1="$(sha1sum "$W/npm.tgz" | awk '{print $1}')"
NINT="sha512-$(openssl dgst -sha512 -binary "$W/npm.tgz" | base64 | tr -d '\n')"
jq -n --arg n "$NPKG" --arg u "${UP}/${P}/npma/${NPKG}/-/${NPKG}-1.0.0.tgz" --arg s "$NSHA1" --arg i "$NINT" \
  '{name:$n,"dist-tags":{latest:"1.0.0"},
    time:{created:"2020-01-01T00:00:00.000Z",modified:"2020-01-01T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z"},
    versions:{"1.0.0":{name:$n,version:"1.0.0",dist:{tarball:$u,shasum:$s,integrity:$i}}}}' > "$W/packument.json"
[ -n "$(mock_put "/${P}/npma/${NPKG}" "$W/packument.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:packument"
[ -n "$(mock_put "/${P}/npma/${NPKG}/-/${NPKG}-1.0.0.tgz" "$W/npm.tgz")" ] || SETUP_ERR="${SETUP_ERR} mock:npm-tgz"
NP_A="vmg-npa-${SUF}"; NP_B="vmg-npb-${SUF}"; NP_V="vmg-npv-${SUF}"
mk "$NP_A" npm remote "${UP}/${P}/npma/"
mk "$NP_B" npm remote "${UP}/${P}/npmb/"
virt "$NP_V" npm "$NP_B" "$NP_A"
age_gate "$NP_A" 7; age_gate "$NP_B" 7

# --- PyPI ---------------------------------------------------------------------
# A hosting member (JSON API + simple index, both dated 2020), a member that
# hosts nothing, and a simple-index-only upstream (no /pypi/<p>/json).
PPKG="dtfpy${SUF}"; SPKG="dtfsimple${SUF}"
pywheel(){ printf 'dtf wheel %s\n' "$1" > "$2"; }
PFILE="${PPKG}-1.0-py3-none-any.whl"
pywheel "$PFILE" "$W/$PFILE"; PSHA="$(sha256_of "$W/$PFILE")"
printf '<!DOCTYPE html><html><body><a href="%s/%s/pya/packages/%s#sha256=%s" data-upload-time="2020-01-01T00:00:00Z">%s</a></body></html>\n' \
  "$UP" "$P" "$PFILE" "$PSHA" "$PFILE" > "$W/pya.html"
jq -n --arg n "$PPKG" --arg f "$PFILE" --arg u "${UP}/${P}/pya/packages/${PFILE}" --arg s "$PSHA" \
  '{info:{name:$n,version:"1.0"},
    releases:{"1.0":[{filename:$f,url:$u,digests:{sha256:$s},packagetype:"bdist_wheel",
      upload_time:"2020-01-01T00:00:00",upload_time_iso_8601:"2020-01-01T00:00:00.000000Z"}]},
    urls:[{filename:$f,url:$u,digests:{sha256:$s},packagetype:"bdist_wheel",
      upload_time:"2020-01-01T00:00:00",upload_time_iso_8601:"2020-01-01T00:00:00.000000Z"}]}' > "$W/pya.json"
for p in "/${P}/pya/simple/${PPKG}/" "/${P}/pya/simple/${PPKG}"; do
  [ -n "$(mock_put "$p" "$W/pya.html" text/html)" ] || SETUP_ERR="${SETUP_ERR} mock:${p}"
done
[ -n "$(mock_put "/${P}/pya/pypi/${PPKG}/json" "$W/pya.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:pya-json"
[ -n "$(mock_put "/${P}/pya/packages/${PFILE}" "$W/$PFILE")" ] || SETUP_ERR="${SETUP_ERR} mock:pya-file"

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
S_OLD="${SPKG}-1.0-py3-none-any.whl"; S_NEW="${SPKG}-2.0-py3-none-any.whl"; S_UND="${SPKG}-3.0-py3-none-any.whl"
: > "$W/pys.html"
printf '<!DOCTYPE html><html><body>\n' >> "$W/pys.html"
for spec in "${S_OLD}|2020-01-01T00:00:00Z" "${S_NEW}|${NOW}" "${S_UND}|"; do
  f="${spec%%|*}"; t="${spec#*|}"
  pywheel "$f" "$W/$f"
  [ -n "$(mock_put "/${P}/pys/packages/${f}" "$W/$f")" ] || SETUP_ERR="${SETUP_ERR} mock:pys:${f}"
  if [ -n "$t" ]; then
    printf '<a href="%s/%s/pys/packages/%s#sha256=%s" data-upload-time="%s">%s</a><br/>\n' "$UP" "$P" "$f" "$(sha256_of "$W/$f")" "$t" "$f" >> "$W/pys.html"
  else
    printf '<a href="%s/%s/pys/packages/%s#sha256=%s">%s</a><br/>\n' "$UP" "$P" "$f" "$(sha256_of "$W/$f")" "$f" >> "$W/pys.html"
  fi
done
printf '</body></html>\n' >> "$W/pys.html"
for p in "/${P}/pys/simple/${SPKG}/" "/${P}/pys/simple/${SPKG}"; do
  [ -n "$(mock_put "$p" "$W/pys.html" text/html)" ] || SETUP_ERR="${SETUP_ERR} mock:${p}"
done
PY_A="vmg-pya-${SUF}"; PY_B="vmg-pyb-${SUF}"; PY_V="vmg-pyv-${SUF}"
PY_S7="vmg-pys7-${SUF}"; PY_S0="vmg-pys0-${SUF}"
mk "$PY_A" pypi remote "${UP}/${P}/pya/"
mk "$PY_B" pypi remote "${UP}/${P}/pyb/"
virt "$PY_V" pypi "$PY_B" "$PY_A"
mk "$PY_S7" pypi remote "${UP}/${P}/pys/"
mk "$PY_S0" pypi remote "${UP}/${P}/pys/"
age_gate "$PY_A" 7; age_gate "$PY_B" 7; age_gate "$PY_S7" 7; age_gate "$PY_S0" 0

if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
# #5146: OCI blob gate with an empty hosted member
# =============================================================================
begin_test "setup: pull the image through the remote-only virtual (inline scan), then re-grade its verdict to vulnerable / medium (below the high threshold)"
get "/v2/${DV_A}/${IMG}/manifests/1.0" "$W/m0" "$OCI_MT"
s0="$ST"
VROWS="$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='${D_MAN#sha256:}'")"
psql_q "UPDATE proxy_scan_results SET verdict='vulnerable', findings_count=1, medium_count=1, max_severity='medium'
        WHERE checksum_sha256='${D_MAN#sha256:}'" >/dev/null
VNOW="$(psql_q "SELECT verdict||'/'||coalesce(max_severity,'') FROM proxy_scan_results WHERE checksum_sha256='${D_MAN#sha256:}'")"
echo "   first pull ${s0}; verdict rows ${VROWS}; now ${VNOW}"
if [ "$s0" = "200" ] && [ "$VNOW" = "vulnerable/medium" ]; then pass
else infra_fail "first pull ${s0} (want 200 after a clean inline scan), verdict '${VNOW}': $(snip "$W/m0")"; fi

begin_test "CONTROL: a remote-only Docker virtual serves the manifest, config and layer of the below-threshold image"
reset_case
get "/v2/${DV_A}/${IMG}/manifests/1.0" "$W/ma" "$OCI_MT"; [ "$ST" = "200" ] || fail_g "manifest answered ${ST}: $(snip "$W/ma")"
get "/v2/${DV_A}/${IMG}/blobs/${D_CFG}" "$W/ca"; [ "$ST" = "200" ] || fail_g "config blob answered ${ST}: $(snip "$W/ca")"
get "/v2/${DV_A}/${IMG}/blobs/${D_LAY}" "$W/la"; [ "$ST" = "200" ] || fail_g "layer blob answered ${ST}: $(snip "$W/la")"
cmp -s "$W/la" "$W/oci/layer" || fail_g "the layer body is not the upstream's bytes"
finish_case "the remote-only virtual did not serve the below-threshold image"

begin_test "CONTROL: the Docker virtual [empty hosted, Remote] serves the image's manifest (the manifest gate passes it)"
reset_case
get "/v2/${DV_B}/${IMG}/manifests/1.0" "$W/mb" "$OCI_MT"; [ "$ST" = "200" ] || fail_g "manifest answered ${ST}: $(snip "$W/mb")"
get "/v2/${DV_B}/${IMG}/manifests/${D_MAN}" "$W/mbd" "$OCI_MT"; [ "$ST" = "200" ] || fail_g "manifest by digest answered ${ST}: $(snip "$W/mbd")"
finish_case "the manifest gate refused the below-threshold image"

begin_test "FIX #5146: the Docker virtual [empty hosted, Remote] serves the config and layer blobs (200, not 403)"
reset_case
get "/v2/${DV_B}/${IMG}/blobs/${D_CFG}" "$W/cb"; s1="$ST"
get "/v2/${DV_B}/${IMG}/blobs/${D_LAY}" "$W/lb"; s2="$ST"
note "config ${s1}, layer ${s2}"
[ "$s1" = "200" ] || fail_g "config blob answered ${s1}: $(snip "$W/cb")"
[ "$s2" = "200" ] || fail_g "layer blob answered ${s2}: $(snip "$W/lb")"
[ "$s2" = "200" ] && { cmp -s "$W/lb" "$W/oci/layer" || fail_g "the layer body is not the upstream's bytes"; }
finish_case "an empty hosted member tightened the virtual's blob gate"

# =============================================================================
# #5147: NuGet mixed-case stored names through a virtual
# =============================================================================
fc(){ printf '/nuget/%s/v3/flatcontainer/%s/1.0.2/%s.1.0.2.nupkg' "$1" "$2" "$2"; }

begin_test "CONTROL: the hosted repository serves the mixed-case stored package by both spellings, and the virtual lists it"
reset_case
get "$(fc "$N_H" "$ML")" "$W/n1"; [ "$ST" = "200" ] || fail_g "direct lowercase download answered ${ST}: $(snip "$W/n1")"
cmp -s "$W/n1" "$W/mixed.nupkg" || fail_g "direct lowercase body is not the pushed .nupkg"
get "$(fc "$N_H" "$NU_MIXED")" "$W/n2"; [ "$ST" = "200" ] || fail_g "direct mixed-case download answered ${ST}: $(snip "$W/n2")"
get "/nuget/${N_V}/v3/flatcontainer/${ML}/index.json" "$W/n3"
[ "$ST" = "200" ] || fail_g "virtual flatcontainer index answered ${ST}"
grep -q '1.0.2' "$W/n3" || fail_g "virtual flatcontainer index does not list 1.0.2: $(snip "$W/n3")"
finish_case "the hosted mixed-case package was not served directly"

begin_test "CONTROL: a natively pushed package downloads through the virtual"
reset_case
get "$(fc "$N_V" "$NL")" "$W/n4"; [ "$ST" = "200" ] || fail_g "virtual download of the native package answered ${ST}: $(snip "$W/n4")"
cmp -s "$W/n4" "$W/native.nupkg" || fail_g "the body is not the pushed .nupkg"
finish_case "a natively pushed package did not download through the virtual"

begin_test "FIX #5147: the virtual downloads the mixed-case stored package by the lowercase and the mixed-case URL"
reset_case
get "$(fc "$N_V" "$ML")" "$W/n5"; s1="$ST"
get "$(fc "$N_V" "$NU_MIXED")" "$W/n6"; s2="$ST"
note "lowercase ${s1}, mixed-case ${s2}"
[ "$s1" = "200" ] || fail_g "virtual lowercase download answered ${s1}: $(snip "$W/n5")"
[ "$s2" = "200" ] || fail_g "virtual mixed-case download answered ${s2}: $(snip "$W/n6")"
[ "$s1" = "200" ] && { cmp -s "$W/n5" "$W/mixed.nupkg" || fail_g "the body is not the pushed .nupkg"; }
finish_case "the NuGet virtual did not resolve a mixed-case stored name"

# =============================================================================
# #5150: an age-gated member that does not host the version cannot veto it
# =============================================================================
begin_test "CONTROL: each hosting member serves the 2020 version directly (npm tarball, PyPI wheel)"
reset_case
get "/npm/${NP_A}/${NPKG}/-/${NPKG}-1.0.0.tgz" "$W/t1"; [ "$ST" = "200" ] || fail_g "npm member A tarball answered ${ST}: $(snip "$W/t1")"
cmp -s "$W/t1" "$W/npm.tgz" || fail_g "npm body is not the upstream tarball"
get "/pypi/${PY_A}/simple/${PPKG}/${PFILE}" "$W/t2"; [ "$ST" = "200" ] || fail_g "PyPI member A wheel answered ${ST}: $(snip "$W/t2")"
cmp -s "$W/t2" "$W/$PFILE" || fail_g "PyPI body is not the upstream file"
finish_case "a hosting member did not serve its old version"

begin_test "FIX #5150: an npm virtual [gated member without the package, gated member with it] serves the 2020 tarball, no 451, no review on the non-hosting member"
reset_case
get "/npm/${NP_V}/${NPKG}/-/${NPKG}-1.0.0.tgz" "$W/t3"
note "virtual tarball -> ${ST}$([ "$ST" = "200" ] || printf ': %s' "$(snip "$W/t3")")"
[ "$ST" = "200" ] || fail_g "the virtual answered ${ST}, expected 200"
r="$(reviews_on "$NP_B")"
[ "$r" = "0" ] || fail_g "${r} age-gate review row(s) on ${NP_B}, which does not host ${NPKG}"
finish_case "a non-hosting npm member vetoed the download"

begin_test "FIX #5150: a PyPI virtual [gated member without the project, gated member with it] serves the 2020 wheel, no 451, no review on the non-hosting member"
reset_case
get "/pypi/${PY_V}/simple/${PPKG}/${PFILE}" "$W/t4"
note "virtual wheel -> ${ST}: $(snip "$W/t4")"
[ "$ST" = "200" ] || fail_g "the virtual answered ${ST}, expected 200"
r="$(reviews_on "$PY_B")"
[ "$r" = "0" ] || fail_g "${r} age-gate review row(s) on ${PY_B}, which does not host ${PPKG}"
finish_case "a non-hosting PyPI member vetoed the download"

# =============================================================================
# #5151: a simple-index-only PyPI upstream
# =============================================================================
begin_test "CONTROL: on the simple-index-only Remote at min_age_days 7, a file dated today is withheld (451)"
reset_case
get "/pypi/${PY_S7}/simple/${SPKG}/${S_NEW}" "$W/s1"
note "today's file -> ${ST}: $(snip "$W/s1")"
[ "$ST" = "451" ] || fail_g "today's file answered ${ST}, expected 451"
finish_case "a young file was not withheld"

begin_test "FIX #5151: on the simple-index-only Remote at min_age_days 0, an undated file is served (200, not 451)"
reset_case
get "/pypi/${PY_S0}/simple/${SPKG}/${S_UND}" "$W/s2"
note "undated file at 0 days -> ${ST}: $(snip "$W/s2")"
[ "$ST" = "200" ] || fail_g "the undated file answered ${ST}, expected 200"
finish_case "min_age_days 0 blocked a file with no publish time"

begin_test "FIX #5151: on the simple-index-only Remote at min_age_days 7, a file whose data-upload-time is 2020 is served (200, not 451)"
reset_case
get "/pypi/${PY_S7}/simple/${SPKG}/${S_OLD}" "$W/s3"
note "2020 file -> ${ST}: $(snip "$W/s3")"
[ "$ST" = "200" ] || fail_g "the 2020 file answered ${ST}, expected 200"
[ "$ST" = "200" ] && { cmp -s "$W/s3" "$W/$S_OLD" || fail_g "the body is not the upstream file"; }
finish_case "the simple index's data-upload-time was ignored"

end_suite
