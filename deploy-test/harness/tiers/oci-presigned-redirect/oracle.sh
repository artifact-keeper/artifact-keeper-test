#!/usr/bin/env bash
# =============================================================================
# tiers/oci-presigned-redirect/oracle.sh
#   OCI blob GETs are offloaded with a 307 to a presigned object-store URL
#   (artifact-keeper#2894), and presigned redirects point at
#   S3_PUBLIC_ENDPOINT, whose malformed value stops startup (#4417).
# =============================================================================
# run.sh has stood up `storage.s3 storage.s3-presigned` (MinIO; presigned
# downloads on; S3_PUBLIC_ENDPOINT=http://127.0.0.1:${S3_PORT}) with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, S3_PORT, BACKEND_IMAGE, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the feature and the gates.
#
# The backend reaches MinIO as http://minio:9000; this oracle reaches it only
# at 127.0.0.1:${S3_PORT}. A redirect is "usable" when its Location is on the
# public endpoint and a plain GET of it (no registry credentials, the way
# docker and containerd follow it) returns the exact bytes.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${S3_PORT:?}"; : "${BACKEND_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe below is judged explicitly by the
# assertion that reads it, so a failing probe must not end the oracle early.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
BADPUB_CTR="ak-dtf${SLOT}-badpub-$$"
PUBLIC_HOSTPORT="127.0.0.1:${S3_PORT}"

REPO="ocips-${SLOT}-${SUF}"       # private local docker repo on S3
VREPO="ocipv-${SLOT}-${SUF}"      # private virtual docker repo over REPO
GREPO="ocipg-${SLOT}-${SUF}"      # private generic repo (artifact download leg)
READER="ocipr-${SLOT}-${SUF}"; READER_PASS="Ocipr_${SUF}_Aa1!"
IMG="app"
MT_DOCKER='application/vnd.docker.distribution.manifest.v2+json'

WORK="$(mktemp -d -t dtf-ocips-XXXXXX)"
cleanup() { docker rm -f "$BADPUB_CTR" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" --path-as-is "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
size_of() { wc -c < "$1" 2>/dev/null | tr -d '[:space:]' || true; }
hdr() { grep -i "^${2}:" "$1" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r' || true; }
loc_hostport() { printf '%s' "$1" | sed -E 's#^[a-z]+://([^/]+)/.*#\1#'; }

AUTHZ=()

begin_suite "oci-presigned-redirect"

# ===========================================================================
# SETUP
# ===========================================================================
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
mk() { # KEY TYPE FORMAT -> code
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-${1}.json" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"${3}\",\"repo_type\":\"${2}\",\"is_public\":false}"
}
SF=""
c="$(mk "$REPO" local docker)"; is_2xx "$c" || SF="${SF} local=${c}"
c="$(mk "$VREPO" virtual docker)"; is_2xx "$c" || SF="${SF} virtual=${c}"
c="$(mk "$GREPO" local generic)"; is_2xx "$c" || SF="${SF} generic=${c}"
c="$(code_to_file "${BASE_URL}/api/v1/repositories/${VREPO}/members" /dev/null -X POST "${AUTHZ[@]}" \
      -H 'Content-Type: application/json' -d "{\"member_key\":\"${REPO}\"}")"; is_2xx "$c" || SF="${SF} member=${c}"

# A 64 KiB layer (big enough that a stream and a redirect are unambiguous).
head -c 65536 /dev/urandom > "${WORK}/layer"
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"salt":"%s"}' "$SUF" > "${WORK}/cfg"
LD="sha256:$(sha_of "${WORK}/layer")"; CD="sha256:$(sha_of "${WORK}/cfg")"
for f in cfg layer; do
  d="sha256:$(sha_of "${WORK}/${f}")"
  c="$(code_to_file "${BASE_URL}/v2/${REPO}/${IMG}/blobs/uploads/?digest=${d}" /dev/null -X POST "${AUTHZ[@]}" \
        -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/${f}")"
  is_2xx "$c" || SF="${SF} blob-${f}=${c}"
done
printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"%s"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":%s,"digest":"%s"}]}' \
  "$MT_DOCKER" "$(size_of "${WORK}/cfg")" "$CD" "$(size_of "${WORK}/layer")" "$LD" > "${WORK}/manifest"
c="$(code_to_file "${BASE_URL}/v2/${REPO}/${IMG}/manifests/v1" /dev/null -X PUT "${AUTHZ[@]}" \
      -H "Content-Type: ${MT_DOCKER}" --data-binary "@${WORK}/manifest")"
is_2xx "$c" || SF="${SF} manifest=${c}"

head -c 32768 /dev/urandom > "${WORK}/generic.bin"
c="$(code_to_file "${BASE_URL}/api/v1/repositories/${GREPO}/artifacts/dir/generic-${SUF}.bin" /dev/null -X PUT "${AUTHZ[@]}" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/generic.bin")"
is_2xx "$c" || SF="${SF} generic-upload=${c}"

READER_ID="$(create_test_user_with_retry "$READER" "$READER_PASS" "${READER}@t.test")" || true
READER_TOKEN=""
[ -n "$READER_ID" ] && [ "$READER_ID" != "null" ] && READER_TOKEN="$(login_as "$READER" "$READER_PASS")"
[ -n "$READER_TOKEN" ] || SF="${SF} reader-user"

if [ -n "$SF" ]; then
  begin_test "setup: repositories, image push, generic upload and a non-admin user"
  infra_fail "setup failed:${SF}" "$(head -c 300 "${WORK}/mk-${VREPO}.json" 2>/dev/null)"
  end_suite
fi
# The layer really is in MinIO (not on local disk): the S3 storage profile is live.
S3KEY="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT b.storage_key FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id WHERE r.key='${REPO}' AND b.digest='${LD}';" 2>/dev/null | tr -d '[:space:]')"

blob_get() { # REPO DIGEST TAG [curl args] -> code; headers in $WORK/TAG.h body in $WORK/TAG.b
  local r="$1" d="$2" t="$3"; shift 3
  code_to_file "${BASE_URL}/v2/${r}/${IMG}/blobs/${d}" "${WORK}/${t}.b" -D "${WORK}/${t}.h" "$@"
}
follow() { # LOCATION OUTFILE [curl args] -> code (no registry credentials)
  local l="$1" o="$2"; shift 2
  local c; c="$(curl -s -o "$o" -w '%{http_code}' --max-time 30 "$@" "$l" 2>/dev/null)"
  echo "${c:-000}"
}

# ===========================================================================
# CONTROLS
# ===========================================================================
begin_test "CONTROL: HEAD /v2/<repo>/<img>/blobs/<digest> is never redirected: 200 with Docker-Content-Digest and the exact Content-Length"
c="$(code_to_file "${BASE_URL}/v2/${REPO}/${IMG}/blobs/${LD}" /dev/null -I -D "${WORK}/head.h" "${AUTHZ[@]}")"
HD="$(hdr "${WORK}/head.h" docker-content-digest)"; HL="$(hdr "${WORK}/head.h" content-length)"; HLOC="$(hdr "${WORK}/head.h" location)"
if [ "$c" = "200" ] && [ "$HD" = "$LD" ] && [ "$HL" = "65536" ] && [ -z "$HLOC" ] && [ -n "$S3KEY" ]; then pass; else
  fail "HEAD blob: code=${c} digest=${HD} length=${HL} location='${HLOC}' oci_blobs.storage_key='${S3KEY}' (want 200, ${LD}, 65536, none, a key)"
fi

begin_test "CONTROL: an anonymous blob GET on the private repository is a 401 challenge, never a redirect"
c="$(blob_get "$REPO" "$LD" anon)"
if [ "$c" = "401" ] && [ -n "$(hdr "${WORK}/anon.h" www-authenticate)" ] && [ -z "$(hdr "${WORK}/anon.h" location)" ]; then pass; else
  fail "anonymous GET blob: code=${c} challenge='$(hdr "${WORK}/anon.h" www-authenticate)' location='$(hdr "${WORK}/anon.h" location)' (want 401, a challenge, no Location)"
fi

begin_test "CONTROL: a non-admin with no grant on the private repository is refused (403/404), never redirected"
c="$(blob_get "$REPO" "$LD" noperm -H "Authorization: Bearer ${READER_TOKEN}")"
if { [ "$c" = "403" ] || [ "$c" = "404" ]; } && [ -z "$(hdr "${WORK}/noperm.h" location)" ]; then pass; else
  fail "ungranted GET blob: code=${c} location='$(hdr "${WORK}/noperm.h" location)' (want 403 or 404 and no Location: authorization runs before any redirect)"
fi

begin_test "CONTROL: a generic artifact download answers 302 to a SigV4-presigned object-store URL (presigned downloads are on)"
c="$(code_to_file "${BASE_URL}/api/v1/repositories/${GREPO}/download/dir/generic-${SUF}.bin" /dev/null -D "${WORK}/gen.h" "${AUTHZ[@]}")"
GLOC="$(hdr "${WORK}/gen.h" location)"
if [ "$c" = "302" ] && printf '%s' "$GLOC" | grep -q 'X-Amz-Signature='; then pass; else
  fail "generic download: code=${c} Location='${GLOC:0:160}' (want 302 to a presigned URL)"
fi

# ===========================================================================
# #4417: the presigned URL points at S3_PUBLIC_ENDPOINT
# ===========================================================================
begin_test "#4417: that redirect is signed for S3_PUBLIC_ENDPOINT (${PUBLIC_HOSTPORT}), not the internal minio:9000, and fetching it returns the exact bytes"
GHP="$(loc_hostport "$GLOC")"
gc="$(follow "$GLOC" "${WORK}/gen.out")"
if [ "$GHP" = "$PUBLIC_HOSTPORT" ] && [ "$gc" = "200" ] && [ "$(sha_of "${WORK}/gen.out")" = "$(sha_of "${WORK}/generic.bin")" ]; then pass; else
  fail "presigned Location host=${GHP} (want ${PUBLIC_HOSTPORT}); following it -> ${gc}, sha match=$([ "$(sha_of "${WORK}/gen.out")" = "$(sha_of "${WORK}/generic.bin")" ] && echo yes || echo no). Pre-#4417 the URL named the backend's own S3_ENDPOINT, unreachable from outside the cluster"
fi

# ===========================================================================
# #2894: OCI blob GET -> 307
# ===========================================================================
begin_test "#2894: GET /v2/<repo>/<img>/blobs/<digest> -> 307 to the public object-store URL with Docker-Content-Digest; the URL serves the exact layer"
c="$(blob_get "$REPO" "$LD" get "${AUTHZ[@]}")"
LOC="$(hdr "${WORK}/get.h" location)"; GD="$(hdr "${WORK}/get.h" docker-content-digest)"
fc="$(follow "$LOC" "${WORK}/get.out")"
if [ "$c" = "307" ] && [ "$GD" = "$LD" ] && [ "$(loc_hostport "$LOC")" = "$PUBLIC_HOSTPORT" ] && \
   printf '%s' "$LOC" | grep -q 'X-Amz-Signature=' && [ "$fc" = "200" ] && [ "sha256:$(sha_of "${WORK}/get.out")" = "$LD" ] && \
   [ "$(size_of "${WORK}/get.b")" -lt 65536 ]; then pass; else
  fail "blob GET: code=${c} (want 307) digest header=${GD} Location=${LOC:0:120} -> ${fc}, body sha match=$([ "sha256:$(sha_of "${WORK}/get.out")" = "$LD" ] && echo yes || echo no); bytes streamed by the backend=$(size_of "${WORK}/get.b"). Pre-#2894 the layer streamed through the backend (200)"
fi

begin_test "#2894: a Range blob GET is redirected too, and the object store answers the range (206, exact slice)"
c="$(blob_get "$REPO" "$LD" range "${AUTHZ[@]}" -H 'Range: bytes=100-1123')"
RLOC="$(hdr "${WORK}/range.h" location)"
rc="$(follow "$RLOC" "${WORK}/range.out" -H 'Range: bytes=100-1123')"
WANT="$(tail -c +101 "${WORK}/layer" | head -c 1024 | sha256sum | cut -d' ' -f1)"
if [ "$c" = "307" ] && [ "$rc" = "206" ] && [ "$(sha_of "${WORK}/range.out")" = "$WANT" ]; then pass; else
  fail "Range blob GET: code=${c} (want 307), following with the Range -> ${rc} (want 206), slice match=$([ "$(sha_of "${WORK}/range.out")" = "$WANT" ] && echo yes || echo no)"
fi

begin_test "#2894: a blob of a virtual repository's local member is redirected too"
c="$(blob_get "$VREPO" "$LD" virt "${AUTHZ[@]}")"
VLOC="$(hdr "${WORK}/virt.h" location)"
vc="$(follow "$VLOC" "${WORK}/virt.out")"
if [ "$c" = "307" ] && [ "$vc" = "200" ] && [ "sha256:$(sha_of "${WORK}/virt.out")" = "$LD" ]; then pass; else
  fail "virtual blob GET: code=${c} (want 307), following -> ${vc}, sha match=$([ "sha256:$(sha_of "${WORK}/virt.out")" = "$LD" ] && echo yes || echo no)"
fi

# ===========================================================================
# #4417: a malformed S3_PUBLIC_ENDPOINT stops startup
# ===========================================================================
begin_test "#4417: a second backend with S3_PUBLIC_ENDPOINT=ftp://bad-endpoint exits non-zero at startup and names the variable"
NET="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$BACKEND_CTR" 2>/dev/null | grep -m1 . || true)"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null \
  | grep -E '^(DATABASE_URL|STORAGE_PATH|BACKUP_PATH|PLUGINS_DIR|JWT_SECRET|ADMIN_PASSWORD|RUST_LOG|HOST|PORT|STORAGE_BACKEND|RATE_LIMIT_ENABLED|S3_[A-Z_]+|PRESIGNED_[A-Z_]+)=' \
  | grep -v '^S3_PUBLIC_ENDPOINT=' > "${WORK}/badpub.env"
echo "S3_PUBLIC_ENDPOINT=ftp://bad-endpoint:9000" >> "${WORK}/badpub.env"
STATE="not-started"; EXITC=""
if [ -n "$NET" ] && docker run -d --name "$BADPUB_CTR" --network "$NET" --env-file "${WORK}/badpub.env" "$BACKEND_IMAGE" >/dev/null 2>"${WORK}/badpub.err"; then
  for _ in $(seq 1 45); do
    STATE="$(docker inspect -f '{{.State.Status}}' "$BADPUB_CTR" 2>/dev/null || echo gone)"
    [ "$STATE" = "exited" ] && break
    sleep 1
  done
  EXITC="$(docker inspect -f '{{.State.ExitCode}}' "$BADPUB_CTR" 2>/dev/null || true)"
fi
NAMED="$(docker logs "$BADPUB_CTR" 2>&1 | grep -c 'S3_PUBLIC_ENDPOINT' || true)"
docker rm -f "$BADPUB_CTR" >/dev/null 2>&1
if [ "$STATE" = "exited" ] && [ -n "$EXITC" ] && [ "$EXITC" != "0" ] && [ "${NAMED:-0}" -ge 1 ]; then pass; else
  fail "backend with a malformed S3_PUBLIC_ENDPOINT: state after 45 s=${STATE} exit=${EXITC:-n/a} log lines naming the variable=${NAMED} (want exited, non-zero, >=1). Without #4417 the value is ignored and the backend serves" \
    "run err=$(head -c 200 "${WORK}/badpub.err" 2>/dev/null)"
fi

end_suite
