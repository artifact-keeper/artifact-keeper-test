#!/usr/bin/env bash
# =============================================================================
# tiers/storage-outage-and-full/oracle.sh: a storage outage answers 503, a full
#   bucket answers 507, a delete job reports the object deletes it could not do,
#   and a database outage on an anonymous pull answers 503, not 401
#   (artifact-keeper#5649, #5650, #5685, #5655, #5476), and an OCI pull of a
#   stored blob or manifest answers 503 with storage down, not 404 (#5894)
# =============================================================================
# run.sh has stood up the `s3` profile-set (MinIO) with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH, DTF_DIR.
#
# Phases (see the manifest for each bug and fix):
#   1. setup + CONTROL: repositories on five routes (generic REST, Maven, OCI,
#      Go, Ivy), a 64 KiB object uploaded and read back on each; an OCI image
#      manifest (img:v1) pushed and pulled, also through a virtual repository;
#      the lookup cut (#5894 database facet): with the lookup's tables locked
#      and the queued backend sessions terminated, blob and manifest GET/HEAD
#      answer 503, and an upload start and a chunked PATCH answer 503 with the
#      fixed message, no database text (#5901); a public pypi repository with
#      a wheel that an anonymous client can read.
#   2. bucket quota (#5650, #5685): a 1 KiB hard quota on this slot's bucket;
#      64 KiB uploads must answer 507 with a neutral body; /health reports
#      storage unhealthy; reads still work; clearing the quota restores uploads.
#   3. MinIO stopped (#5649, #5685, #5655, #5894): uploads and downloads answer
#      503 + Retry-After within a 60 s client timeout, OCI blob and manifest
#      GET/HEAD of stored content included; /readyz lists storage as
#      degraded; a repository delete job ends completed_with_errors. Then MinIO
#      is started and every route works again.
#   4. Postgres stopped (#5476): anonymous GETs on public repositories whose
#      lookup is a visibility-cache miss answer 503, not 401. Then Postgres is
#      started; a missing and a private repository answer 401 again.
#
# Every fault is on this slot's own containers (ak-dtf<slot>-minio / -db) and
# its own bucket. The EXIT trap restarts both, clears the quota and removes the
# transient mc container by its exact name.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

DTF_DIR="${DTF_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
# shellcheck source=/dev/null
source "${DTF_DIR}/harness/lib/repo_delete.sh"

SLOT="${DTF_SLOT:-x}"
SUF="${RUN_ID##*-}$$"
PREFIX="${DB_CONTAINER%-db}"
MINIO_CTR="${PREFIX}-minio"
BACKEND_CTR="${PREFIX}-backend"
MC_CTR="l2-s${SLOT}-mc"
MC_IMAGE="ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z"

GEN="sof-gen-${SUF}"
MVN="sof-mvn-${SUF}"
OCI="sof-oci-${SUF}"
GO="sof-go-${SUF}"
IVY="sof-ivy-${SUF}"
DEL="sof-del-${SUF}"
VOCI="sof-voci-${SUF}"
PYPI="sof-pypi-${SUF}"
PRIV="sof-priv-${SUF}"
PUBGEN="sof-pubgen-${SUF}"
PKG="sofpkg"

FULL_MSG="Storage is full: the storage backend refused the write for lack of space"
UNAVAIL_MSG="Storage backend is temporarily unavailable, retry shortly"

# The client timeout for a probe while a fault is in place. The fix answers a
# dead store in ~10 s (control-plane calls) to ~35 s (bulk PUTs). Pre-fix
# builds answer 500 after 20-45 s here (a stopped container's address times
# out on connect) and hang for minutes when the connect attempts stall. Probes run in parallel, so one outage
# batch costs at most PROBE_TIMEOUT.
PROBE_TIMEOUT=60
# The visibility middleware caches a repository lookup for 60 s; the #5476
# probe must be a cache miss.
REPO_CACHE_TTL=65
DELETE_JOB_TIMEOUT=180

WORK="$(mktemp -d -t dtf-sof-XXXXXX)"
# repo_delete.sh keeps its job polls here (set in this shell, so the job file
# can be read back after repo_delete_wait).
_REPO_DELETE_DIR="${WORK}/repo-delete"; mkdir -p "$_REPO_DELETE_DIR"
MINIO_STOPPED=0
DB_STOPPED=0
QUOTA_SET=0

minio_env() { # NAME -> value of NAME in the minio container's env
  docker inspect "$MINIO_CTR" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | sed -n "s/^$1=//p" | head -1
}
# mc_run 'mc ...': a transient mc container in MinIO's network namespace. The
# credentials are read from the minio container at run time.
mc_run() {
  local u p
  u="$(minio_env MINIO_ROOT_USER)"; p="$(minio_env MINIO_ROOT_PASSWORD)"
  docker rm -f "$MC_CTR" >/dev/null 2>&1
  docker run --rm --name "$MC_CTR" --network "container:${MINIO_CTR}" \
    -e MCU="$u" -e MCP="$p" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 \"\$MCU\" \"\$MCP\" >/dev/null && $1" 2>&1
}

cleanup() {
  # Never leave the slot's MinIO or Postgres stopped or its bucket full:
  # run.sh teardown and --keep both expect a whole stack.
  if [ "$DB_STOPPED" = "1" ]; then docker start "$DB_CONTAINER" >/dev/null 2>&1 || true; fi
  if [ "$MINIO_STOPPED" = "1" ]; then docker start "$MINIO_CTR" >/dev/null 2>&1 || true; fi
  if [ "$QUOTA_SET" = "1" ]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      mc_run "mc quota clear local/${BUCKET}" >/dev/null 2>&1 && break
      sleep 3
    done
  fi
  docker rm -f "$MC_CTR" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

BUCKET="$(docker inspect "$BACKEND_CTR" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -n 's/^S3_BUCKET=//p' | head -1)"
BUCKET="${BUCKET:-ak-artifacts}"

# --- probe helpers ----------------------------------------------------------
# probe LABEL METHOD URL [CURL ARGS...]: one request; status, seconds, headers
# and body land in $WORK/LABEL.*. Safe to run in the background (&).
probe() {
  local l="$1" m="$2" url="$3"; shift 3
  : > "${WORK}/${l}.hdr"; : > "${WORK}/${l}.body"
  curl -s --max-time "$PROBE_TIMEOUT" --connect-timeout 10 -X "$m" \
    -D "${WORK}/${l}.hdr" -o "${WORK}/${l}.body" -w '%{http_code} %{time_total}' \
    "$@" "$url" > "${WORK}/${l}.res" 2>/dev/null
  [ -s "${WORK}/${l}.res" ] || echo "000 ${PROBE_TIMEOUT}" > "${WORK}/${l}.res"
}
code_of() { cut -d' ' -f1 "${WORK}/$1.res" 2>/dev/null; }
secs_of() { cut -d' ' -f2 "${WORK}/$1.res" 2>/dev/null | cut -d. -f1; }
ra_of() { grep -i '^retry-after:' "${WORK}/$1.hdr" 2>/dev/null | head -1 | cut -d: -f2 | tr -d '[:space:]'; }
body_of() { head -c 300 "${WORK}/$1.body" 2>/dev/null | tr -d '\0'; }
ev() { printf '%s: HTTP %s in %ss, Retry-After=%s, body: %s\n' "$1" "$(code_of "$1")" "$(secs_of "$1")" "$(ra_of "$1")" "$(body_of "$1")"; }
same_bytes() { cmp -s "${WORK}/$1.body" "$2"; }

# The body must not carry the object store's own text: the bucket name, an XML
# error document, request ids or MinIO error codes (#5650).
LEAK_RE="${BUCKET}|<\\?xml|<Error|RequestId|HostId|XMinio|x-amz|minio"
leaks() { grep -qiE "$LEAK_RE" "${WORK}/$1.body" 2>/dev/null; }

BEARER="Authorization: Bearer"
auth() { printf '%s %s' "$BEARER" "$ADMIN_TOKEN"; }

# Route URLs for object TAG.
url_gen_put() { echo "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/sof/$1.bin"; }
url_gen_get() { echo "${BASE_URL}/api/v1/repositories/${GEN}/download/sof/$1.bin"; }
url_mvn() { echo "${BASE_URL}/maven/${MVN}/com/example/sof/1.$1/sof-1.$1.jar"; }
url_go() { echo "${BASE_URL}/go/${GO}/example.com/sof$1/@v/v1.0.0.mod"; }
url_ivy() { echo "${BASE_URL}/ivy/${IVY}/com.example/sof_2.13/1.$1/jars/sof_2.13-1.$1.jar"; }
url_oci_post() { echo "${BASE_URL}/v2/${OCI}/img/blobs/uploads/?digest=$(digest_of "$1")"; }
url_oci_get() { echo "${BASE_URL}/v2/${OCI}/img/blobs/$(digest_of "$1")"; }
digest_of() { echo "sha256:$(sha256sum "${WORK}/obj-$1" | cut -d' ' -f1)"; }
mkobj() { head -c 65536 /dev/urandom > "${WORK}/obj-$1"; }

# The pushed image (img:v1) and its config blob (#5894).
url_oci_blob() { echo "${BASE_URL}/v2/${1:-$OCI}/img/blobs/${OCI_CFG_DIGEST}"; }
url_oci_man() { echo "${BASE_URL}/v2/${1:-$OCI}/img/manifests/v1"; }
MAN_ACCEPT="Accept: application/vnd.oci.image.manifest.v1+json"
# oci_pulls PREFIX [REPO]: GET and HEAD of the stored config blob and of
# img:v1 (in REPO, default the hosted one), in parallel.
oci_pulls() {
  oci_blob_pulls "$@" & oci_man_pulls "$@" & wait
}
oci_blob_pulls() {
  local p="$1" r="${2:-$OCI}" a; a="$(auth)"
  probe "${p}-blobget" GET "$(url_oci_blob "$r")" -H "$a" &
  probe "${p}-blobhead" HEAD "$(url_oci_blob "$r")" -H "$a" -I &
  wait
}
oci_man_pulls() {
  local p="$1" r="${2:-$OCI}" a; a="$(auth)"
  probe "${p}-manget" GET "$(url_oci_man "$r")" -H "$a" -H "$MAN_ACCEPT" &
  probe "${p}-manhead" HEAD "$(url_oci_man "$r")" -H "$a" -H "$MAN_ACCEPT" -I &
  wait
}

# --- the #5894 database facet: a lookup the database cannot answer ----------
# A whole-database outage fails the request at authentication or repository
# resolution, before the blob/manifest lookup (both images answer 503 there),
# so the lookup is cut on its own: a session holds ACCESS EXCLUSIVE on the
# lookup's tables, and the backend sessions that queue behind it are
# terminated, as a failover or a dropped connection ends a query in flight
# ("terminating connection due to administrator command").
LOCK_APP="dtf-5894-lock-${SUF}"
psql_db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }
# lookup_cut TABLES PROBE-FN PREFIX REPO: run PROBE-FN PREFIX REPO while TABLES
# are locked, terminating each backend session that waits on the lock until
# the probes have answered; then release the lock.
lookup_cut() {
  local tables="$1" fn="$2" p="$3" r="$4" i pid
  printf 'BEGIN;\nLOCK TABLE %s IN ACCESS EXCLUSIVE MODE;\nSELECT pg_sleep(60);\nROLLBACK;\n' "$tables" \
    | docker exec -i -e PGAPPNAME="$LOCK_APP" "$DB_CONTAINER" psql -U registry -d artifact_registry -q >/dev/null 2>&1 &
  for i in $(seq 1 20); do
    [ "$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}' AND query LIKE '%pg_sleep%'")" = "1" ] && break
    sleep 0.5
  done
  "$fn" "$p" "$r" &
  pid=$!
  for i in $(seq 1 60); do
    psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
      AND datname = 'artifact_registry' AND application_name <> '${LOCK_APP}' AND pid <> pg_backend_pid()" >/dev/null
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  wait "$pid" 2>/dev/null
  psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}'" >/dev/null
}
# oci_pulls_ok PREFIX: all four answered 200; the GETs return the pushed bytes.
oci_pulls_ok() {
  local r bad=""
  for r in blobget blobhead manget manhead; do
    [ "$(code_of "$1-$r")" = "200" ] || bad="${bad}$(ev "$1-$r")"$'\n'
  done
  same_bytes "$1-blobget" "${WORK}/oci-config.json" || bad="${bad}blob GET bytes differ: $(ev "$1-blobget")"$'\n'
  same_bytes "$1-manget" "${WORK}/oci-manifest.json" || bad="${bad}manifest GET bytes differ: $(ev "$1-manget")"$'\n'
  [ -z "$bad" ] || { printf '%s' "$bad"; return 1; }
}
# expect_head_503 LABEL: a HEAD answered 503 with Retry-After (no body to judge).
expect_head_503() {
  if [ "$(code_of "$1")" != "503" ]; then echo "$(ev "$1") (want 503)"; return 1; fi
  if [ -z "$(ra_of "$1")" ]; then echo "$(ev "$1") (no Retry-After on the 503)"; return 1; fi
  return 0
}

# put_all PREFIX TAG: the five uploads of object TAG, in parallel.
put_all() {
  local p="$1" t="$2" f="${WORK}/obj-$2" a; a="$(auth)"
  probe "${p}-gen" PUT "$(url_gen_put "$t")" -H "$a" --data-binary "@$f" &
  probe "${p}-mvn" PUT "$(url_mvn "$t")" -H "$a" --data-binary "@$f" &
  probe "${p}-oci" POST "$(url_oci_post "$t")" -H "$a" -H 'Content-Type: application/octet-stream' --data-binary "@$f" &
  probe "${p}-go" PUT "$(url_go "$t")" -H "$a" --data-binary "@$f" &
  probe "${p}-ivy" PUT "$(url_ivy "$t")" -H "$a" --data-binary "@$f" &
  wait
}
# get_all PREFIX TAG: the five downloads of object TAG, in parallel.
get_all() {
  local p="$1" t="$2" a; a="$(auth)"
  probe "${p}-gen" GET "$(url_gen_get "$t")" -H "$a" &
  probe "${p}-mvn" GET "$(url_mvn "$t")" -H "$a" &
  probe "${p}-oci" GET "$(url_oci_get "$t")" -H "$a" &
  probe "${p}-go" GET "$(url_go "$t")" -H "$a" &
  probe "${p}-ivy" GET "$(url_ivy "$t")" -H "$a" &
  wait
}
# all_put_ok PREFIX: every upload of put_all answered 2xx.
all_put_ok() {
  local r c bad=""
  for r in gen mvn oci go ivy; do
    c="$(code_of "$1-$r")"
    case "$c" in 200|201|202) ;; *) bad="${bad}$(ev "$1-$r")"$'\n' ;; esac
  done
  [ -z "$bad" ] || { printf '%s' "$bad"; return 1; }
}
# all_get_ok PREFIX TAG: every download answered 200 with the exact bytes.
all_get_ok() {
  local r bad=""
  for r in gen mvn oci go ivy; do
    if [ "$(code_of "$1-$r")" != "200" ] || ! same_bytes "$1-$r" "${WORK}/obj-$2"; then
      bad="${bad}$(ev "$1-$r")"$'\n'
    fi
  done
  [ -z "$bad" ] || { printf '%s' "$bad"; return 1; }
}

# expect_app_err LABEL STATUS CODE [want-retry-after]: the AppError JSON body
# {code, message} with the fixed message, no backend text.
expect_app_err() {
  local l="$1" st="$2" cd="$3" ra="${4:-}" msg
  case "$cd" in STORAGE_FULL) msg="$FULL_MSG" ;; *) msg="$UNAVAIL_MSG" ;; esac
  if [ "$(code_of "$l")" != "$st" ]; then echo "$(ev "$l") (want ${st} ${cd})"; return 1; fi
  if [ "$(jq -r '.code // empty' "${WORK}/${l}.body" 2>/dev/null)" != "$cd" ] \
     || [ "$(jq -r '.message // empty' "${WORK}/${l}.body" 2>/dev/null)" != "$msg" ]; then
    echo "$(ev "$l") (want {code: ${cd}, message: '${msg}'})"; return 1
  fi
  if [ -n "$ra" ] && [ -z "$(ra_of "$l")" ]; then echo "$(ev "$l") (no Retry-After on the 503)"; return 1; fi
  if leaks "$l"; then echo "$(ev "$l") (body carries object-store text)"; return 1; fi
  return 0
}
# expect_oci_err LABEL STATUS CODE: the /v2 envelope {errors:[{code, message}]}.
expect_oci_err() {
  local l="$1" st="$2" cd="$3" msg
  case "$cd" in INSUFFICIENT_STORAGE) msg="$FULL_MSG" ;; *) msg="$UNAVAIL_MSG" ;; esac
  if [ "$(code_of "$l")" != "$st" ]; then echo "$(ev "$l") (want ${st} ${cd})"; return 1; fi
  if [ "$(jq -r '.errors[0].code // empty' "${WORK}/${l}.body" 2>/dev/null)" != "$cd" ] \
     || [ "$(jq -r '.errors[0].message // empty' "${WORK}/${l}.body" 2>/dev/null)" != "$msg" ]; then
    echo "$(ev "$l") (want /v2 errors[0] {code: ${cd}, message: '${msg}'})"; return 1
  fi
  if [ "$st" = "503" ] && [ -z "$(ra_of "$l")" ]; then echo "$(ev "$l") (no Retry-After on the 503)"; return 1; fi
  if leaks "$l"; then echo "$(ev "$l") (body carries object-store text)"; return 1; fi
  return 0
}
# expect_plain_err LABEL STATUS: a plain-text body that is exactly the fixed
# message (#5685 native routes); Retry-After on a 503.
expect_plain_err() {
  local l="$1" st="$2" msg
  case "$st" in 507) msg="$FULL_MSG" ;; *) msg="$UNAVAIL_MSG" ;; esac
  if [ "$(code_of "$l")" != "$st" ]; then echo "$(ev "$l") (want ${st})"; return 1; fi
  if [ "$(cat "${WORK}/${l}.body" 2>/dev/null)" != "$msg" ]; then echo "$(ev "$l") (want the body '${msg}')"; return 1; fi
  if [ "$st" = "503" ] && [ -z "$(ra_of "$l")" ]; then echo "$(ev "$l") (no Retry-After on the 503)"; return 1; fi
  return 0
}
# check_cases LABEL...: run each "fn args" spec; pass if all hold.
verdict() { # MSG OUT
  if [ -z "$2" ]; then pass; else fail "$1" "$2"; fi
}

readyz_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${BASE_URL}/readyz" 2>/dev/null || echo 000; }
readyz_degraded_storage() {
  curl -s --max-time 20 "${BASE_URL}/readyz" 2>/dev/null \
    | jq -e '.status == "ready" and ((.degraded // []) | index("storage") != null)' >/dev/null 2>&1
}
health_storage_unhealthy() {
  curl -s --max-time 20 "${BASE_URL}/health" 2>/dev/null | jq -e '.checks.storage.status == "unhealthy"' >/dev/null 2>&1
}
minio_healthy() { [ "$(docker inspect "$MINIO_CTR" --format '{{.State.Health.Status}}' 2>/dev/null)" = "healthy" ]; }
readyz_ready() { [ "$(readyz_code)" = "200" ]; }
readyz_not_ready() { [ "$(readyz_code)" = "503" ]; }

mkrepo() { # KEY FORMAT PUBLIC
  api_post "/api/v1/repositories" \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"local\",\"is_public\":$3}" >/dev/null 2>&1
}
anon_get() { # LABEL URL
  probe "$1" GET "$2"
}

begin_suite "storage-outage-and-full"

# =============================================================================
# 1. SETUP + CONTROL
# =============================================================================
begin_test "setup: admin login, repositories on five routes, a public pypi repo with a wheel"
auth_admin
if [ -z "${ADMIN_TOKEN:-}" ]; then infra_fail "admin login failed"; end_suite; fi
for spec in "$GEN:generic:false" "$MVN:maven:false" "$OCI:docker:false" "$GO:go:false" \
            "$IVY:sbt:false" "$DEL:generic:false" "$PYPI:pypi:true" "$PRIV:pypi:false" \
            "$PUBGEN:generic:true"; do
  IFS=: read -r k f p <<<"$spec"
  if ! mkrepo "$k" "$f" "$p"; then infra_fail "could not create ${f} repo ${k}"; end_suite; fi
done
if [ -z "$(minio_env MINIO_ROOT_USER)" ]; then infra_fail "could not read the MinIO credentials from ${MINIO_CTR}"; end_suite; fi
# A minimal wheel for the anonymous pypi read (#5476), built at run time.
python3 - "${WORK}/${PKG}-1.0-py3-none-any.whl" "$PKG" <<'PY'
import sys, zipfile
path, name = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(path, "w") as z:
    z.writestr(f"{name}/__init__.py", "")
    z.writestr(f"{name}-1.0.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n")
    z.writestr(f"{name}-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: dtf\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    z.writestr(f"{name}-1.0.dist-info/RECORD", "")
PY
probe pypi-up POST "${BASE_URL}/pypi/${PYPI}/" -H "$(auth)" -F ':action=file_upload' -F "name=${PKG}" \
  -F 'version=1.0' -F 'filetype=bdist_wheel' -F "content=@${WORK}/${PKG}-1.0-py3-none-any.whl"
case "$(code_of pypi-up)" in 200|201) ;; *) infra_fail "pypi wheel upload failed" "$(ev pypi-up)"; end_suite ;; esac
# Two objects in the repository the outage will delete (#5655).
for i in 1 2; do
  head -c 4096 /dev/urandom > "${WORK}/del-$i"
  probe "del-up-$i" PUT "${BASE_URL}/api/v1/repositories/${DEL}/artifacts/sof/del-$i.bin" -H "$(auth)" --data-binary "@${WORK}/del-$i"
  case "$(code_of "del-up-$i")" in 200|201) ;; *) infra_fail "upload into ${DEL} failed" "$(ev "del-up-$i")"; end_suite ;; esac
done
pass

begin_test "CONTROL before: a 64 KiB upload and its download work on generic, Maven, OCI, Go and Ivy"
mkobj base
put_all up0 base
OUT="$(all_put_ok up0)"
if [ -z "$OUT" ]; then get_all get0 base; OUT="$(all_get_ok get0 base)"; fi
verdict "an upload or download failed with storage healthy" "$OUT"

begin_test "CONTROL before: an OCI image (config blob + manifest img:v1) pushes, and GET/HEAD of the blob and the manifest answer 200"
# A real config document and a manifest with no layers: the pull that matters
# here is of content the repository records (#5894).
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"dtf":"%s"}' "$SUF" > "${WORK}/oci-config.json"
OCI_CFG_DIGEST="sha256:$(sha256sum "${WORK}/oci-config.json" | cut -d' ' -f1)"
probe oci-cfg POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/?digest=${OCI_CFG_DIGEST}" -H "$(auth)" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/oci-config.json"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%s},"layers":[]}' \
  "$OCI_CFG_DIGEST" "$(stat -c %s "${WORK}/oci-config.json")" > "${WORK}/oci-manifest.json"
probe oci-man PUT "$(url_oci_man)" -H "$(auth)" -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary "@${WORK}/oci-manifest.json"
if [ "$(code_of oci-cfg)" != "201" ] || [ "$(code_of oci-man)" != "201" ]; then
  fail "the OCI image push failed with storage healthy" "$(ev oci-cfg)"$'\n'"$(ev oci-man)"
else
  oci_pulls pull0
  verdict "an OCI pull failed with storage healthy" "$(oci_pulls_ok pull0)"
fi

begin_test "setup: a virtual docker repository over ${OCI}; GET/HEAD of the blob and the manifest through it answer 200"
api_post "/api/v1/repositories" \
  "{\"key\":\"${VOCI}\",\"name\":\"${VOCI}\",\"format\":\"docker\",\"repo_type\":\"virtual\",\"is_public\":false}" >/dev/null 2>&1 \
  && api_post "/api/v1/repositories/${VOCI}/members" "{\"member_key\":\"${OCI}\",\"priority\":1}" >/dev/null 2>&1
oci_pulls vpull0 "$VOCI"
verdict "a pull through the virtual repository failed with the database healthy" "$(oci_pulls_ok vpull0)"

begin_test "FIX #5894 db lookup: a blob/manifest lookup the database cannot answer -> 503 + Retry-After (hosted and virtual), never 404 or 500"
lookup_cut oci_blobs oci_blob_pulls lcb "$OCI"
lookup_cut oci_blobs oci_blob_pulls lcbv "$VOCI"
lookup_cut "oci_tags, oci_manifests" oci_man_pulls lcm "$OCI"
lookup_cut "oci_tags, oci_manifests" oci_man_pulls lcmv "$VOCI"
OUT=""
for l in lcb-blobget lcb-blobhead lcbv-blobget lcbv-blobhead lcm-manget lcm-manhead lcmv-manget lcmv-manhead; do
  echo "  $(ev "$l")"
  if [ "$(code_of "$l")" != "503" ] || [ -z "$(ra_of "$l")" ]; then
    OUT="${OUT}$(ev "$l") (want 503 + Retry-After)"$'\n'
  elif [ "${l%head}" = "$l" ] && [ "$(jq -r '.errors[0].code // empty' "${WORK}/${l}.body" 2>/dev/null)" != "UNAVAILABLE" ]; then
    OUT="${OUT}$(ev "$l") (want the /v2 envelope with code UNAVAILABLE)"$'\n'
  elif grep -qiE 'error returned from database|terminating connection|sqlx|pg_' "${WORK}/${l}.body" 2>/dev/null; then
    OUT="${OUT}$(ev "$l") (the body carries the database's own error text)"$'\n'
  fi
done
verdict "an OCI pull whose lookup the database could not answer did not answer a retryable 503" "$OUT"

begin_test "FIX #5901 db lookup: a push whose session query the database cannot answer -> 503 + Retry-After with the fixed message, no database text"
# The PATCH goes to a session opened while the database works.
probe lcp-open POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/" -H "$(auth)"
LCP_LOC="$(grep -i '^location:' "${WORK}/lcp-open.hdr" | head -1 | cut -d' ' -f2- | tr -d '\r')"
case "$LCP_LOC" in http*) ;; *) LCP_LOC="${BASE_URL}${LCP_LOC}" ;; esac
mkobj lcp
oci_push_probes() {
  local p="$1" a; a="$(auth)"
  probe "${p}-start" POST "${BASE_URL}/v2/${2}/img/blobs/uploads/" -H "$a" &
  probe "${p}-patch" PATCH "$LCP_LOC" -H "$a" -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/obj-lcp" &
  wait
}
if [ "$(code_of lcp-open)" != "202" ] || [ -z "$LCP_LOC" ]; then
  fail "could not open an upload session with the database healthy" "$(ev lcp-open)"
else
  lookup_cut oci_upload_sessions oci_push_probes lcp "$OCI"
  OUT=""
  for l in lcp-start lcp-patch; do
    echo "  $(ev "$l")"
    if [ "$(code_of "$l")" != "503" ] || [ -z "$(ra_of "$l")" ]; then
      OUT="${OUT}$(ev "$l") (want 503 + Retry-After)"$'\n'
    elif [ "$(jq -r '.errors[0].message // empty' "${WORK}/${l}.body" 2>/dev/null)" != "Database is temporarily unavailable, retry shortly" ]; then
      OUT="${OUT}$(ev "$l") (want the fixed database message)"$'\n'
    elif grep -qiE 'error returned from database|terminating connection|sqlx|oci_upload_sessions' "${WORK}/${l}.body" 2>/dev/null; then
      OUT="${OUT}$(ev "$l") (the body carries the database's own error text)"$'\n'
    fi
  done
  verdict "a push whose session query the database could not answer leaked the database error or did not answer a retryable 503" "$OUT"
fi

begin_test "CONTROL: with the lock gone, the pulls answer 200 again (hosted and virtual)"
OUT=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  oci_pulls lcok "$OCI"; oci_pulls lcokv "$VOCI"
  OUT="$(oci_pulls_ok lcok; oci_pulls_ok lcokv)" && break
  sleep 2
done
verdict "a pull did not recover after the lookup cut" "$OUT"

begin_test "CONTROL before: an anonymous GET of /pypi/<public repo>/simple/${PKG}/ answers 200"
anon_get anon0 "${BASE_URL}/pypi/${PYPI}/simple/${PKG}/"
# The visibility middleware caches this lookup for 60 s; the #5476 probe on the
# same repository waits it out.
PYPI_TOUCH="$(date +%s)"
if [ "$(code_of anon0)" = "200" ] && grep -q "$PKG" "${WORK}/anon0.body"; then pass; else fail "anonymous pypi simple GET did not answer 200" "$(ev anon0)"; fi

# =============================================================================
# 2. BUCKET QUOTA (#5650, #5685)
# =============================================================================
begin_test "setup: a 1 KiB hard quota on this slot's bucket (${BUCKET})"
QOUT="$(mc_run "mc quota set local/${BUCKET} --size 1KiB && mc quota info local/${BUCKET}")"
QUOTA_SET=1
if echo "$QOUT" | grep -qi 'hard quota'; then pass; else infra_fail "mc quota set failed" "$QOUT"; end_suite; fi

mkobj full
put_all full full
# A docker push's chunked blob upload: POST starts the session, PATCH sends
# the bytes. The refusal may come at either step (main refuses the session
# start itself once the bucket is full), so the case judges whichever step
# did not answer 202.
probe full-oci-start POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/" -H "$(auth)"
CHUNK=full-oci-start
if [ "$(code_of full-oci-start)" = "202" ]; then
  LOC="$(tr -d '\r' < "${WORK}/full-oci-start.hdr" | sed -n 's/^[Ll]ocation: //p' | head -1)"
  case "$LOC" in http*) ;; *) LOC="${BASE_URL}${LOC}" ;; esac
  probe full-oci-patch PATCH "$LOC" -H "$(auth)" -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/obj-full"
  CHUNK=full-oci-patch
fi
FULL_T="$(date +%s)"

begin_test "FIX #5650 full: generic REST PUT and Maven PUT -> 507 STORAGE_FULL, fixed message, no bucket name or XML (not 500 STORAGE_ERROR)"
OUT="$(expect_app_err full-gen 507 STORAGE_FULL; expect_app_err full-mvn 507 STORAGE_FULL)"
verdict "an upload to a full bucket did not answer the neutral 507" "$OUT"

begin_test "FIX #5650 full: OCI blob upload (monolithic POST and chunked PATCH) -> 507 INSUFFICIENT_STORAGE in the /v2 envelope, no MinIO XML"
OUT="$(expect_oci_err full-oci 507 INSUFFICIENT_STORAGE; expect_oci_err "$CHUNK" 507 INSUFFICIENT_STORAGE)"
verdict "an OCI blob upload to a full bucket did not answer 507 INSUFFICIENT_STORAGE" "$OUT"

begin_test "FIX #5650 full: /health reports storage unhealthy after a write refused for lack of space"
if wait_until "/health checks.storage unhealthy" 30 health_storage_unhealthy; then
  pass
else
  fail "/health still reports storage healthy $(( $(date +%s) - FULL_T ))s after refused writes" \
    "$(curl -s --max-time 20 "${BASE_URL}/health" | jq -c '.checks' 2>/dev/null | head -c 300)"
fi

begin_test "FIX #5685 full: Go .mod PUT and Ivy jar PUT -> 507 with the fixed message (not 500)"
OUT="$(expect_plain_err full-go 507; expect_plain_err full-ivy 507)"
verdict "a native-route upload to a full bucket did not answer 507" "$OUT"

begin_test "CONTROL full: downloads of the stored object still work while the bucket is full"
get_all getfull base
verdict "a download failed while the bucket was full" "$(all_get_ok getfull base)"

begin_test "CONTROL full: after clearing the quota, uploads on all five routes succeed again"
QOUT="$(mc_run "mc quota clear local/${BUCKET}")"
if echo "$QOUT" | grep -qi 'cleared'; then QUOTA_SET=0; fi
mkobj cleared
OUT=""
for _ in 1 2 3 4 5 6; do
  put_all clr cleared
  OUT="$(all_put_ok clr)" && break
  sleep 5
done
if [ "$QUOTA_SET" = "0" ] && [ -z "$OUT" ]; then get_all getclr cleared; OUT="$(all_get_ok getclr cleared)"; fi
[ "$QUOTA_SET" = "0" ] || OUT="mc quota clear failed: ${QOUT}"
verdict "uploads did not recover after the quota was cleared" "$OUT"

# =============================================================================
# 3. MINIO STOPPED (#5649, #5685, #5655)
# =============================================================================
begin_test "setup: stop ${MINIO_CTR}"
if ! docker stop -t 5 "$MINIO_CTR" >/dev/null 2>&1; then infra_fail "docker stop ${MINIO_CTR} failed"; end_suite; fi
MINIO_STOPPED=1
OUT_T0="$(date +%s)"
pass

# The repository delete goes first so its job meets the outage (#5655); the
# probes run in parallel with it, each bounded by PROBE_TIMEOUT.
probe del DELETE "${BASE_URL}/api/v1/repositories/${DEL}" -H "$(auth)" &
DEL_PID=$!
mkobj outage
put_all oput outage &
get_all oget base &
oci_pulls opull &
wait
wait "$DEL_PID" 2>/dev/null
echo "  outage batch took $(( $(date +%s) - OUT_T0 ))s"

begin_test "FIX #5649 outage: generic REST PUT and download -> 503 STORAGE_UNAVAILABLE + Retry-After within ${PROBE_TIMEOUT}s (not 500, not a hang)"
OUT="$(expect_app_err oput-gen 503 STORAGE_UNAVAILABLE ra; expect_app_err oget-gen 503 STORAGE_UNAVAILABLE ra)"
echo "  PUT $(code_of oput-gen) in $(secs_of oput-gen)s, GET $(code_of oget-gen) in $(secs_of oget-gen)s"
verdict "a generic request with storage down did not answer 503 in time (000 = client timeout)" "$OUT"

begin_test "FIX #5649 outage: Maven PUT and GET -> 503 STORAGE_UNAVAILABLE + Retry-After within ${PROBE_TIMEOUT}s"
OUT="$(expect_app_err oput-mvn 503 STORAGE_UNAVAILABLE ra; expect_app_err oget-mvn 503 STORAGE_UNAVAILABLE ra)"
echo "  PUT $(code_of oput-mvn) in $(secs_of oput-mvn)s, GET $(code_of oget-mvn) in $(secs_of oget-mvn)s"
verdict "a Maven request with storage down did not answer 503 in time (000 = client timeout)" "$OUT"

begin_test "FIX #5649 outage: OCI blob upload -> 503 UNAVAILABLE + Retry-After in the /v2 envelope within ${PROBE_TIMEOUT}s"
echo "  POST $(code_of oput-oci) in $(secs_of oput-oci)s"
verdict "an OCI blob upload with storage down did not answer 503 UNAVAILABLE" "$(expect_oci_err oput-oci 503 UNAVAILABLE)"

begin_test "FIX #5894 outage: OCI pull of stored content (blob GET/HEAD, manifest GET/HEAD) -> 503 UNAVAILABLE + Retry-After, not 404 BLOB_UNKNOWN / MANIFEST_UNKNOWN"
for l in oget-oci opull-blobget opull-blobhead opull-manget opull-manhead; do echo "  $(ev "$l")"; done
OUT="$(expect_oci_err oget-oci 503 UNAVAILABLE; expect_oci_err opull-blobget 503 UNAVAILABLE
       expect_head_503 opull-blobhead
       expect_oci_err opull-manget 503 UNAVAILABLE; expect_head_503 opull-manhead)"
verdict "an OCI pull of stored content with storage down did not answer 503 (a 404 tells docker the image does not exist)" "$OUT"

begin_test "FIX #5649 outage: /readyz stays ready and lists storage under degraded"
if wait_until "/readyz degraded: storage" 30 readyz_degraded_storage; then
  pass
else
  fail "/readyz does not report storage as degraded with MinIO stopped" \
    "$(curl -s --max-time 20 "${BASE_URL}/readyz" | head -c 400)"
fi

begin_test "FIX #5685 outage: Go .mod PUT/GET and Ivy jar PUT/GET -> 503 + Retry-After with the fixed message (not 500)"
OUT="$(for l in oput-go oget-go oput-ivy oget-ivy; do expect_plain_err "$l" 503; done)"
verdict "a native-route request with storage down did not answer 503" "$OUT"

begin_test "FIX #5655 outage: a repository DELETE gets a job that ends completed_with_errors with failed_items > 0 and an error summary"
REMAIN=$(( DELETE_JOB_TIMEOUT - ($(date +%s) - OUT_T0) )); [ "$REMAIN" -lt 30 ] && REMAIN=30
repo_delete_wait "$BASE_URL" "$ADMIN_TOKEN" "$(code_of del)" "${WORK}/del.body" "$REMAIN"
JOBF="${_REPO_DELETE_DIR}/job-${REPO_DELETE_JOB_ID}.json"
echo "  DELETE ${REPO_DELETE_CODE}, job ${REPO_DELETE_JOB_ID:-<none>} -> ${REPO_DELETE_JOB_STATUS:-<none>} $(jq -c '{failed_items,error_summary}' "$JOBF" 2>/dev/null | head -c 300)"
if [ "$REPO_DELETE_CODE" != "202" ]; then
  fail "DELETE answered ${REPO_DELETE_CODE} with no job: the object deletes that failed are not reported" "$(ev del)"
elif [ "$REPO_DELETE_JOB_STATUS" != "completed_with_errors" ]; then
  fail "the delete job ended '${REPO_DELETE_JOB_STATUS}' with storage down, expected completed_with_errors" "$(head -c 400 "$JOBF" 2>/dev/null)"
elif ! jq -e '(.failed_items // 0) > 0 and ((.error_summary // "") | length) > 0' "$JOBF" >/dev/null 2>&1; then
  fail "completed_with_errors without failed_items > 0 and an error_summary" "$(head -c 400 "$JOBF")"
else
  pass
fi

begin_test "CONTROL recovery: start ${MINIO_CTR}; uploads and downloads on all five routes and the OCI image pull work again"
docker start "$MINIO_CTR" >/dev/null 2>&1
MINIO_STOPPED=0
wait_until "${MINIO_CTR} healthy" 90 minio_healthy >/dev/null
mkobj back
OUT="not tried"
for _ in $(seq 1 12); do
  put_all back back
  OUT="$(all_put_ok back)" && break
  sleep 5
done
if [ -z "$OUT" ]; then get_all getback back; OUT="$(all_get_ok getback back)"; fi
if [ -z "$OUT" ]; then get_all getbase base; OUT="$(all_get_ok getbase base)"; fi
if [ -z "$OUT" ]; then oci_pulls pullback; OUT="$(oci_pulls_ok pullback)"; fi
verdict "a route did not recover after MinIO came back" "$OUT"

begin_test "CONTROL recovery: the deleted repository is gone"
C="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "$(auth)" "${BASE_URL}/api/v1/repositories/${DEL}")"
if [ "$C" = "404" ]; then pass; else fail "GET /api/v1/repositories/${DEL} answered ${C} after the delete, expected 404"; fi

# =============================================================================
# 4. POSTGRES STOPPED (#5476)
# =============================================================================
begin_test "setup: stop ${DB_CONTAINER} (after the 60 s repository cache entry has expired)"
WAIT_S=$(( REPO_CACHE_TTL - ($(date +%s) - PYPI_TOUCH) ))
if [ "$WAIT_S" -gt 0 ]; then echo "  waiting ${WAIT_S}s for the repository cache entry to expire"; sleep "$WAIT_S"; fi
if ! docker stop -t 10 "$DB_CONTAINER" >/dev/null 2>&1; then infra_fail "docker stop ${DB_CONTAINER} failed"; end_suite; fi
DB_STOPPED=1
if wait_until "/readyz not-ready" 60 readyz_not_ready; then pass; else fail "/readyz never went not-ready with the database stopped"; fi

# Run both probes at once, so neither waits behind the other's pool timeout.
probe anon-pypi GET "${BASE_URL}/pypi/${PYPI}/simple/${PKG}/" &
probe anon-dl GET "${BASE_URL}/api/v1/repositories/${PUBGEN}/download/sof/any.bin" &
wait

begin_test "FIX #5476 db outage: anonymous GET /pypi/<public repo>/simple/${PKG}/ -> 503 + Retry-After: 1 (not 401)"
if [ "$(code_of anon-pypi)" = "503" ] && [ "$(ra_of anon-pypi)" = "1" ]; then pass; else fail "anonymous pypi GET during the database outage did not answer a retryable 503" "$(ev anon-pypi)"; fi

begin_test "FIX #5476 db outage: anonymous GET /api/v1/repositories/<public repo>/download/... -> 503 + Retry-After: 1 (not 401)"
if [ "$(code_of anon-dl)" = "503" ] && [ "$(ra_of anon-dl)" = "1" ]; then pass; else fail "anonymous download during the database outage did not answer a retryable 503" "$(ev anon-dl)"; fi

begin_test "CONTROL db recovery: start ${DB_CONTAINER}; the anonymous pypi GET answers 200 again"
docker start "$DB_CONTAINER" >/dev/null 2>&1
DB_STOPPED=0
if ! wait_until "/readyz ready" 120 readyz_ready; then
  fail_fatal "/readyz did not return to ready after restarting the database"
fi
OK=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  anon_get anon1 "${BASE_URL}/pypi/${PYPI}/simple/${PKG}/"
  [ "$(code_of anon1)" = "200" ] && { OK=1; break; }
  sleep 2
done
if [ "$OK" = "1" ]; then pass; else fail "anonymous pypi GET after recovery" "$(ev anon1)"; fi

begin_test "CONTROL db recovery: an anonymous GET on a missing and on a private repository still answers 401"
anon_get anon-miss "${BASE_URL}/pypi/sof-missing-${SUF}/simple/${PKG}/"
anon_get anon-priv "${BASE_URL}/pypi/${PRIV}/simple/${PKG}/"
if [ "$(code_of anon-miss)" = "401" ] && [ "$(code_of anon-priv)" = "401" ]; then
  pass
else
  fail "missing / private repository did not answer 401" "$(ev anon-miss)
$(ev anon-priv)"
fi

end_suite
