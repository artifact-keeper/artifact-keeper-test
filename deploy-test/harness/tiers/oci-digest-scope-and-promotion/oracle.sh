#!/usr/bin/env bash
# =============================================================================
# tiers/oci-digest-scope-and-promotion/oracle.sh
#   delete-by-digest is scoped to the image name and survives a restart
#   (artifact-keeper#4466, #4525, #4450, #4449); an anonymous manifest PUT with
#   an unsent body is a 401 challenge (#4568); /v2/token has its own bucket
#   and wrong passwords stay bounded (#4558, #4020); a promoted Docker image is
#   pullable from a promotion_only target (#4578).
# =============================================================================
# run.sh has stood up `storage.filesystem` with the rate limiter ON and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# BACKEND_IMAGE, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest
# for the bugs. Every case names the image it goes red on (1.10.0 unless said).
#
# Gates:
#   (CONTROL) fixture images pull by tag and by digest before any delete; a
#             delete by digest removes the deleted name's tag; an anonymous
#             manifest PUT with a COMPLETE body is a 401; the admin pulls from
#             the staging repo; twelve good /v2/token exchanges never 429 and
#             leave the login budget intact (1.10.0 has no limiter at all).
#   (FIX)     the rest, each with the observable it asserts in its title.
#
# Setup failures use infra_fail(): the candidate is unjudged (exit 11).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe below is judged explicitly by the
# assertion that reads it, so a failing probe must not end the oracle early.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"

REPO="ocidig-${SLOT}-${SUF}"          # local docker repo: the delete legs
STAGE="ocistg-${SLOT}-${SUF}"         # staging docker repo: promotion source
REL="ocirel-${SLOT}-${SUF}"           # local docker repo, promotion_only: target
TOKUSER="ocitok-${SLOT}-${SUF}"
TOKPASS="Ocitok_${SUF}_Aa1!"

MT_DOCKER='application/vnd.docker.distribution.manifest.v2+json'
MT_OCI='application/vnd.oci.image.manifest.v1+json'
MT_INDEX='application/vnd.oci.image.index.v1+json'
ACCEPT_ALL="${MT_DOCKER}, ${MT_OCI}, ${MT_INDEX}"

WORK="$(mktemp -d -t dtf-ocidig-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ----------------------------------------------------------------
# --path-as-is on every /v2 probe: references carry `sha256:` colons.
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" --path-as-is "$@" "$url" 2>/dev/null || echo 000
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }
size_of() { wc -c < "$1" 2>/dev/null | tr -d '[:space:]'; }
db() { { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; } | tr -d '[:space:]'; }
jqr() { jq -r "$1" 2>/dev/null || true; }

AUTHZ=()   # set after auth_admin

# push_blob REPO IMAGE FILE -> http code (monolithic POST ?digest=)
push_blob() {
  local d; d="sha256:$(sha_of "$3")"
  code_to_file "${BASE_URL}/v2/${1}/${2}/blobs/uploads/?digest=${d}" /dev/null -X POST \
    "${AUTHZ[@]}" -H 'Content-Type: application/octet-stream' --data-binary "@${3}"
}
# put_manifest REPO IMAGE REF FILE MEDIATYPE -> http code
put_manifest() {
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/${3}" /dev/null -X PUT \
    "${AUTHZ[@]}" -H "Content-Type: ${5}" --data-binary "@${4}"
}
# get_manifest REPO IMAGE REF OUTFILE [extra curl args] -> http code
get_manifest() {
  local r="$1" i="$2" ref="$3" out="$4"; shift 4
  code_to_file "${BASE_URL}/v2/${r}/${i}/manifests/${ref}" "$out" "${AUTHZ[@]}" -H "Accept: ${ACCEPT_ALL}" "$@"
}
head_manifest() { # REPO IMAGE REF -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/${3}" /dev/null -I "${AUTHZ[@]}" -H "Accept: ${ACCEPT_ALL}"
}
del_manifest() { # REPO IMAGE REF -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/manifests/${3}" /dev/null -X DELETE "${AUTHZ[@]}"
}
head_blob() { # REPO IMAGE DIGEST -> http code
  code_to_file "${BASE_URL}/v2/${1}/${2}/blobs/${3}" /dev/null -I "${AUTHZ[@]}"
}
oci_code() { jqr '.errors[0].code // empty' < "$1"; }

# make_image SALT NLAYERS MEDIATYPE -> writes $WORK/<salt>.{cfg,l1..lN,manifest}
make_image() {
  local salt="$1" n="$2" mt="$3" i cfg layers="" ld ls lmt cmt
  if [ "$mt" = "$MT_OCI" ]; then
    lmt='application/vnd.oci.image.layer.v1.tar+gzip'; cmt='application/vnd.oci.image.config.v1+json'
  else
    lmt='application/vnd.docker.image.rootfs.diff.tar.gzip'; cmt='application/vnd.docker.container.image.v1+json'
  fi
  cfg="${WORK}/${salt}.cfg"
  printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"salt":"%s"}' "$salt" > "$cfg"
  for i in $(seq 1 "$n"); do
    printf 'dtf-ocidig-layer-%s-%s-%s' "$salt" "$i" "$SUF" > "${WORK}/${salt}.l${i}"
    ld="sha256:$(sha_of "${WORK}/${salt}.l${i}")"; ls="$(size_of "${WORK}/${salt}.l${i}")"
    layers="${layers}${layers:+,}{\"mediaType\":\"${lmt}\",\"size\":${ls},\"digest\":\"${ld}\"}"
  done
  printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"%s","size":%s,"digest":"sha256:%s"},"layers":[%s]}' \
    "$mt" "$cmt" "$(size_of "$cfg")" "$(sha_of "$cfg")" "$layers" > "${WORK}/${salt}.manifest"
}
# push_image_blobs REPO IMAGE SALT NLAYERS -> "" or diagnostics
push_image_blobs() {
  local f="" c i
  c="$(push_blob "$1" "$2" "${WORK}/${3}.cfg")"; is_2xx "$c" || f="${f} ${3}.cfg=${c}"
  for i in $(seq 1 "$4"); do
    c="$(push_blob "$1" "$2" "${WORK}/${3}.l${i}")"; is_2xx "$c" || f="${f} ${3}.l${i}=${c}"
  done
  echo "$f"
}
mdigest() { echo "sha256:$(sha_of "${WORK}/${1}.manifest")"; }

tag_rows() { # REPO IMAGE -> oci_tags rows
  db "SELECT count(*) FROM oci_tags t JOIN repositories r ON r.id = t.repository_id WHERE r.key = '${1}' AND t.name = '${2}';"
}
live_manifest_rows() { # REPO IMAGE -> live artifacts rows under v2/IMAGE/manifests/
  db "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
      WHERE r.key = '${1}' AND a.path LIKE 'v2/${2}/manifests/%' AND a.is_deleted = false;"
}
oci_manifest_rows() { # REPO DIGEST -> oci_manifests rows (table is 1.11.0+, so "" on 1.10.0)
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM oci_manifests m JOIN repositories r ON r.id = m.repository_id WHERE r.key = '${1}' AND m.digest = '${2}';" \
    2>/dev/null | tr -d '[:space:]' || true
}

wait_health() { # SECONDS
  local i
  for i in $(seq 1 "$1"); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}/health" 2>/dev/null)" = "200" ] && return 0
    sleep 1
  done
  return 1
}

begin_suite "oci-digest-scope-and-promotion"

# ===========================================================================
# SETUP
# ===========================================================================
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

mk_repo() { # KEY REPO_TYPE EXTRA_JSON -> http code
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-${1}.json" -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"docker\",\"repo_type\":\"${2}\",\"is_public\":false${3}}"
}
SETUP_FAILS=""
C="$(mk_repo "$REPO" local "")"; is_2xx "$C" || SETUP_FAILS="${SETUP_FAILS} repo=${C}"
C="$(mk_repo "$STAGE" staging "")"; is_2xx "$C" || SETUP_FAILS="${SETUP_FAILS} staging=${C}"
C="$(mk_repo "$REL" local ",\"promotion_only\":true")"; is_2xx "$C" || SETUP_FAILS="${SETUP_FAILS} release=${C}"
if [ -n "$SETUP_FAILS" ]; then
  begin_test "setup: create the docker repositories"
  infra_fail "repository create failed:${SETUP_FAILS}" "$(head -c 300 "${WORK}/mk-${REL}.json" 2>/dev/null)"
  end_suite
fi
REL_PO="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${AUTHZ[@]}" "${BASE_URL}/api/v1/repositories/${REL}" | jqr '.promotion_only')"

# --- fixture images in $REPO ---------------------------------------------
# shared: xa:v1 and xb:v1 carry IDENTICAL manifest bytes (one digest, two names)
# solo:  pushed by tag only (#4449)
# pinned: pushed by tag AND by digest (#4449 control: keeps its record)
make_image shared 1 "$MT_DOCKER"
make_image solo 1 "$MT_DOCKER"
make_image pinned 1 "$MT_DOCKER"
PF=""
PF="${PF}$(push_image_blobs "$REPO" xa shared 1)$(push_image_blobs "$REPO" xb shared 1)"
PF="${PF}$(push_image_blobs "$REPO" solo solo 1)$(push_image_blobs "$REPO" pinned pinned 1)"
C="$(put_manifest "$REPO" xa v1 "${WORK}/shared.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} xa:v1=${C}"
C="$(put_manifest "$REPO" xb v1 "${WORK}/shared.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} xb:v1=${C}"
C="$(put_manifest "$REPO" solo v1 "${WORK}/solo.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} solo:v1=${C}"
PIN_D="$(mdigest pinned)"
C="$(put_manifest "$REPO" pinned "$PIN_D" "${WORK}/pinned.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} pinned@d=${C}"
C="$(put_manifest "$REPO" pinned v1 "${WORK}/pinned.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} pinned:v1=${C}"
if [ -n "${PF// /}" ]; then
  begin_test "setup: push the delete-leg fixture images over /v2"
  infra_fail "fixture push failed:${PF}" "repo=${REPO}"
  end_suite
fi
SH_D="$(mdigest shared)"
SOLO_D="$(mdigest solo)"

# ===========================================================================
# DELETE BY DIGEST: scope, resolution, persistence (#4466 #4525 #4450 #4449)
# ===========================================================================
begin_test "CONTROL: xa:v1 and xb:v1 serve the same manifest digest, and xa@<digest> resolves, before any delete"
A="$(get_manifest "$REPO" xa v1 "${WORK}/a.json" -D "${WORK}/a.h")"
B="$(get_manifest "$REPO" xb v1 "${WORK}/b.json")"
AD="$(get_manifest "$REPO" xa "$SH_D" /dev/null)"
if [ "$A" = "200" ] && [ "$B" = "200" ] && [ "$AD" = "200" ] && \
   [ "sha256:$(sha_of "${WORK}/a.json")" = "$SH_D" ] && [ "sha256:$(sha_of "${WORK}/b.json")" = "$SH_D" ]; then pass; else
  fail "fixture not as pushed: xa:v1=${A} xb:v1=${B} xa@digest=${AD} (want 200 x3, both bodies hashing to ${SH_D})"
fi

begin_test "#4466: DELETE /v2/<repo>/xa/manifests/<digest> -> 202 and xb:v1 (same digest) stays pullable by tag and by digest"
DC="$(del_manifest "$REPO" xa "$SH_D")"
B="$(get_manifest "$REPO" xb v1 "${WORK}/b2.json")"
BD="$(get_manifest "$REPO" xb "$SH_D" "${WORK}/bd2.json")"
XB_TAGS="$(tag_rows "$REPO" xb)"
if [ "$DC" = "202" ] && [ "$B" = "200" ] && [ "$BD" = "200" ] && [ "$XB_TAGS" = "1" ] && \
   [ "sha256:$(sha_of "${WORK}/b2.json")" = "$SH_D" ]; then pass; else
  fail "deleting xa@digest took xb with it: delete=${DC} xb:v1=${B} xb@digest=${BD} xb oci_tags=${XB_TAGS} (want 202, 200, 200, 1). Pre-#4466 the delete swept every image name's tags for the digest" \
    "body=$(head -c 200 "${WORK}/b2.json" 2>/dev/null)"
fi

begin_test "CONTROL: after that delete xa:v1 is gone (404) and xa has no oci_tags row"
A="$(get_manifest "$REPO" xa v1 "${WORK}/a3.json")"
XA_TAGS="$(tag_rows "$REPO" xa)"
if [ "$A" = "404" ] && [ "$XA_TAGS" = "0" ]; then pass; else
  fail "the delete did not remove its own name's tag: xa:v1=${A} xa oci_tags=${XA_TAGS} (want 404, 0)"
fi

begin_test "#4525: GET and HEAD xa@<digest> -> 404 MANIFEST_UNKNOWN while xb@<digest> resolves; a repeated DELETE under xa -> 404"
AD="$(get_manifest "$REPO" xa "$SH_D" "${WORK}/ad.json")"
ADC="$(oci_code "${WORK}/ad.json")"
AH="$(head_manifest "$REPO" xa "$SH_D")"
BD="$(get_manifest "$REPO" xb "$SH_D" /dev/null)"
RD="$(del_manifest "$REPO" xa "$SH_D")"
if [ "$AD" = "404" ] && [ "$ADC" = "MANIFEST_UNKNOWN" ] && [ "$AH" = "404" ] && [ "$BD" = "200" ] && [ "$RD" = "404" ]; then pass; else
  fail "digest resolution not scoped to the image name: GET xa@d=${AD} code=${ADC:-none} HEAD xa@d=${AH} GET xb@d=${BD} repeat DELETE xa@d=${RD} (want 404 MANIFEST_UNKNOWN, 404, 200, 404)" \
    "body=$(head -c 200 "${WORK}/ad.json" 2>/dev/null)"
fi

begin_test "#4450: the delete soft-deleted EVERY manifest row of xa (tag row included), so nothing is left for the startup reindex"
XA_LIVE="$(live_manifest_rows "$REPO" xa)"
XB_LIVE="$(live_manifest_rows "$REPO" xb)"
if [ "$XA_LIVE" = "0" ] && [ "${XB_LIVE:-0}" -ge 1 ] 2>/dev/null; then pass; else
  fail "live artifacts rows after the digest delete: xa=${XA_LIVE} (want 0: the tag row v2/xa/manifests/v1 must be soft-deleted too) xb=${XB_LIVE} (want >=1)"
fi

begin_test "#4449: deleting the LAST tag of a tag-only image drops its oci_manifests record and its digest pull; a digest-pushed image keeps both"
SB="$(oci_manifest_rows "$REPO" "$SOLO_D")"
PB="$(oci_manifest_rows "$REPO" "$PIN_D")"
SDC="$(del_manifest "$REPO" solo v1)"
PDC="$(del_manifest "$REPO" pinned v1)"
SA="$(oci_manifest_rows "$REPO" "$SOLO_D")"
PA="$(oci_manifest_rows "$REPO" "$PIN_D")"
SG="$(get_manifest "$REPO" solo "$SOLO_D" /dev/null)"
PG="$(get_manifest "$REPO" pinned "$PIN_D" /dev/null)"
echo "   oci_manifests solo ${SB}->${SA}  pinned ${PB}->${PA}; delete solo:v1=${SDC} pinned:v1=${PDC}; pull solo@d=${SG} pinned@d=${PG}"
if [ "$SB" = "1" ] && [ "$SA" = "0" ] && [ "$PB" = "1" ] && [ "$PA" = "1" ] && is_2xx "$SDC" && is_2xx "$PDC" && \
   [ "$SG" = "404" ] && [ "$PG" = "200" ]; then pass; else
  fail "last-tag delete left the record or the pull wrong: oci_manifests solo ${SB:-<no table>}->${SA:-<no table>} (want 1->0), pinned ${PB:-<no table>}->${PA:-<no table>} (want 1->1); pull solo@d=${SG} (want 404) pinned@d=${PG} (want 200)"
fi

# --- restart: the startup reindex must not revive what was deleted ----------
REINDEX_LINES_BEFORE="$(docker logs "$BACKEND_CTR" 2>&1 | grep -c 'OCI migration reindex' || true)"
RESTART_OK=1
if ! docker restart "$BACKEND_CTR" >/dev/null 2>&1 || ! wait_health 120; then RESTART_OK=0; fi
if [ "$RESTART_OK" != "1" ]; then
  begin_test "setup: restart the backend for the persistence leg"
  infra_fail "backend ${BACKEND_CTR} did not come back healthy within 120 s"
  end_suite
fi
# The reindex runs in the background after the listener is up. Wait (up to
# 30 s) for this boot's "OCI migration reindex" line (1.11.0+ always logs
# "...: complete"; 1.10.0 logs only when it has candidates), then settle.
for _ in $(seq 1 30); do
  n="$(docker logs "$BACKEND_CTR" 2>&1 | grep -c 'OCI migration reindex' || true)"
  [ "${n:-0}" -gt "${REINDEX_LINES_BEFORE:-0}" ] && break
  sleep 1
done
sleep 2
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

begin_test "#4450: after a backend restart xa:v1 and xa@<digest> stay 404 and xa has no tag row; xb:v1 still 200"
A="$(get_manifest "$REPO" xa v1 /dev/null)"
AD="$(get_manifest "$REPO" xa "$SH_D" /dev/null)"
B="$(get_manifest "$REPO" xb v1 /dev/null)"
XA_TAGS="$(tag_rows "$REPO" xa)"
SG="$(get_manifest "$REPO" solo v1 /dev/null)"
if [ "$A" = "404" ] && [ "$AD" = "404" ] && [ "$XA_TAGS" = "0" ] && [ "$B" = "200" ] && [ "$SG" = "404" ]; then pass; else
  fail "the deleted image came back after the restart: xa:v1=${A} xa@d=${AD} xa oci_tags=${XA_TAGS} xb:v1=${B} solo:v1=${SG} (want 404, 404, 0, 200, 404). Pre-#4450 the live tag row was re-registered by the startup OCI reindex"
fi

# ===========================================================================
# ANONYMOUS MANIFEST PUT (#4568)
# ===========================================================================
# A raw socket: send the request head with Content-Length: 1000, then half-close
# without writing a single body byte (crane's spent retry). Prints the status
# code and whether a WWW-Authenticate header came back.
truncated_put() { # PATH -> "<code> <www-auth yes|no>"
  python3 -I - "$BASE_URL" "$1" <<'PY' 2>/dev/null || echo "000 no"
import socket, sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1]); path = sys.argv[2]
s = socket.create_connection((u.hostname, u.port or 80), timeout=20)
s.sendall((f"PUT {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
           "Content-Type: application/vnd.docker.distribution.manifest.v2+json\r\n"
           "Content-Length: 1000\r\nConnection: close\r\n\r\n").encode())
s.shutdown(socket.SHUT_WR)
buf = b""
try:
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
except socket.timeout:
    pass
head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
lines = head.split("\r\n")
code = lines[0].split(" ")[1] if lines and len(lines[0].split(" ")) > 1 else "000"
www = any(l.lower().startswith("www-authenticate:") for l in lines[1:])
print(code, "yes" if www else "no")
PY
}

begin_test "CONTROL: an anonymous manifest PUT with a COMPLETE body -> 401 with a WWW-Authenticate challenge"
C="$(code_to_file "${BASE_URL}/v2/${REPO}/anon/manifests/t1" "${WORK}/anon.json" -X PUT -D "${WORK}/anon.h" \
  -H "Content-Type: ${MT_DOCKER}" --data-binary "@${WORK}/shared.manifest")"
if [ "$C" = "401" ] && grep -qi '^www-authenticate:' "${WORK}/anon.h"; then pass; else
  fail "anonymous complete-body PUT answered ${C}, challenge=$(grep -ci '^www-authenticate:' "${WORK}/anon.h" 2>/dev/null)"
fi

begin_test "#4568: an anonymous manifest PUT that declares Content-Length: 1000 and sends 0 bytes -> 401 + WWW-Authenticate, not 500"
read -r TC TW <<<"$(truncated_put "/v2/${REPO}/anon/manifests/t2")"
if [ "$TC" = "401" ] && [ "$TW" = "yes" ]; then pass; else
  fail "truncated anonymous PUT answered ${TC} (challenge=${TW}); want 401 with WWW-Authenticate. Pre-#4568 the handler read the body before authenticating and failed the read with 500 BLOB_UPLOAD_UNKNOWN"
fi

# ===========================================================================
# PROMOTION (#4578)
# ===========================================================================
# app:1.0   docker image, 2 layers (single promotion)
# multi:1.0 OCI index over two OCI child manifests (single promotion)
# bulk:1.0 and bulk:2.0 (bulk promotion)
# broken:1.0 whose source oci_blobs row for one layer is removed (must refuse)
make_image app 2 "$MT_DOCKER"
make_image ch1 1 "$MT_OCI"
make_image ch2 1 "$MT_OCI"
make_image bk1 1 "$MT_DOCKER"
make_image bk2 1 "$MT_DOCKER"
make_image broken 2 "$MT_DOCKER"
PF=""
PF="${PF}$(push_image_blobs "$STAGE" app app 2)$(push_image_blobs "$STAGE" multi ch1 1)$(push_image_blobs "$STAGE" multi ch2 1)"
PF="${PF}$(push_image_blobs "$STAGE" bulk bk1 1)$(push_image_blobs "$STAGE" bulk bk2 1)$(push_image_blobs "$STAGE" broken broken 2)"
C="$(put_manifest "$STAGE" app 1.0 "${WORK}/app.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} app=${C}"
CH1_D="$(mdigest ch1)"; CH2_D="$(mdigest ch2)"
C="$(put_manifest "$STAGE" multi "$CH1_D" "${WORK}/ch1.manifest" "$MT_OCI")"; is_2xx "$C" || PF="${PF} ch1=${C}"
C="$(put_manifest "$STAGE" multi "$CH2_D" "${WORK}/ch2.manifest" "$MT_OCI")"; is_2xx "$C" || PF="${PF} ch2=${C}"
printf '{"schemaVersion":2,"mediaType":"%s","manifests":[{"mediaType":"%s","size":%s,"digest":"%s","platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"%s","size":%s,"digest":"%s","platform":{"architecture":"arm64","os":"linux"}}]}' \
  "$MT_INDEX" "$MT_OCI" "$(size_of "${WORK}/ch1.manifest")" "$CH1_D" "$MT_OCI" "$(size_of "${WORK}/ch2.manifest")" "$CH2_D" > "${WORK}/multi.manifest"
C="$(put_manifest "$STAGE" multi 1.0 "${WORK}/multi.manifest" "$MT_INDEX")"; is_2xx "$C" || PF="${PF} multi=${C}"
C="$(put_manifest "$STAGE" bulk 1.0 "${WORK}/bk1.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} bulk1=${C}"
C="$(put_manifest "$STAGE" bulk 2.0 "${WORK}/bk2.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} bulk2=${C}"
C="$(put_manifest "$STAGE" broken 1.0 "${WORK}/broken.manifest" "$MT_DOCKER")"; is_2xx "$C" || PF="${PF} broken=${C}"
if [ -n "${PF// /}" ]; then
  begin_test "setup: push the promotion fixture images to the staging repository"
  infra_fail "staging push failed:${PF}" "repo=${STAGE}"
  end_suite
fi
art_id() { # IMAGE REF -> artifacts.id of v2/IMAGE/manifests/REF in $STAGE
  db "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id
      WHERE r.key = '${STAGE}' AND a.path = 'v2/${1}/manifests/${2}' AND a.is_deleted = false
      ORDER BY a.created_at DESC LIMIT 1;"
}
APP_ID="$(art_id app 1.0)"; MULTI_ID="$(art_id multi 1.0)"
BK1_ID="$(art_id bulk 1.0)"; BK2_ID="$(art_id bulk 2.0)"; BROKEN_ID="$(art_id broken 1.0)"
if [ -z "$APP_ID" ] || [ -z "$MULTI_ID" ] || [ -z "$BK1_ID" ] || [ -z "$BK2_ID" ] || [ -z "$BROKEN_ID" ]; then
  begin_test "setup: resolve the staging artifact ids"
  infra_fail "artifact ids missing: app=${APP_ID} multi=${MULTI_ID} bulk1=${BK1_ID} bulk2=${BK2_ID} broken=${BROKEN_ID}"
  end_suite
fi
# Make broken:1.0 an incomplete source image: drop the source repository's
# oci_blobs row for its second layer (the bytes stay; the index says absent).
BROKEN_L2="sha256:$(sha_of "${WORK}/broken.l2")"
db "DELETE FROM oci_blobs b USING repositories r WHERE r.id = b.repository_id AND r.key = '${STAGE}' AND b.digest = '${BROKEN_L2}';" >/dev/null

begin_test "CONTROL: the staging image pulls from the staging repository and the target is promotion_only"
C="$(get_manifest "$STAGE" app 1.0 /dev/null)"
if [ "$C" = "200" ] && [ "$REL_PO" = "true" ]; then pass; else
  fail "staging app:1.0=${C} (want 200), target promotion_only=${REL_PO} (want true)"
fi

promote_one() { # ARTIFACT_ID OUTFILE -> http code
  code_to_file "${BASE_URL}/api/v1/promotion/repositories/${STAGE}/artifacts/${1}/promote" "$2" -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/json' -d "{\"target_repository\":\"${REL}\",\"skip_policy_check\":true}"
}
# pulled_ok IMAGE REF SALT NLAYERS -> "" or diagnostics: target manifest digest
# equals the source digest, and every config and layer blob HEADs 200 in REL.
pulled_ok() {
  local img="$1" ref="$2" salt="$3" n="$4" f="" c i want
  want="$(mdigest "$salt")"
  c="$(get_manifest "$REL" "$img" "$ref" "${WORK}/rel-${salt}.json")"
  [ "$c" = "200" ] || f="${f} manifest=${c}($(oci_code "${WORK}/rel-${salt}.json"))"
  if [ "$c" = "200" ] && [ "sha256:$(sha_of "${WORK}/rel-${salt}.json")" != "$want" ]; then f="${f} digest-mismatch"; fi
  c="$(head_blob "$REL" "$img" "sha256:$(sha_of "${WORK}/${salt}.cfg")")"; [ "$c" = "200" ] || f="${f} config-blob=${c}"
  for i in $(seq 1 "$n"); do
    c="$(head_blob "$REL" "$img" "sha256:$(sha_of "${WORK}/${salt}.l${i}")")"; [ "$c" = "200" ] || f="${f} layer${i}=${c}"
  done
  echo "$f"
}
tags_list() { # IMAGE -> "code tags-json"
  local c; c="$(code_to_file "${BASE_URL}/v2/${REL}/${1}/tags/list" "${WORK}/tl-${1}.json" "${AUTHZ[@]}")"
  echo "${c} $(jq -c '.tags // []' "${WORK}/tl-${1}.json" 2>/dev/null || echo '[]')"
}

begin_test "#4578: single promotion of a 2-layer image -> the target serves the same digest by tag, lists the tag, and holds config+layers"
PC="$(promote_one "$APP_ID" "${WORK}/p-app.json")"
PROM="$(jqr '.promoted' < "${WORK}/p-app.json")"
PF="$(pulled_ok app 1.0 app 2)"
read -r TLC TLJ <<<"$(tags_list app)"
TBLOBS="$(db "SELECT count(*) FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id WHERE r.key = '${REL}' AND b.digest IN ('sha256:$(sha_of "${WORK}/app.cfg")','sha256:$(sha_of "${WORK}/app.l1")','sha256:$(sha_of "${WORK}/app.l2")');")"
if is_2xx "$PC" && [ "$PROM" = "true" ] && [ -z "${PF// /}" ] && [ "$TLC" = "200" ] && echo "$TLJ" | jq -e 'index("1.0")' >/dev/null 2>&1 && [ "$TBLOBS" = "3" ]; then pass; else
  fail "promoted image not pullable from ${REL}: promote=${PC} promoted=${PROM} pull:${PF:- ok} tags/list=${TLC} ${TLJ} target oci_blobs=${TBLOBS}/3. Pre-#4578 only the artifacts row and the manifest object were copied (MANIFEST_UNKNOWN / NAME_UNKNOWN)" \
    "promote body=$(head -c 300 "${WORK}/p-app.json" 2>/dev/null)"
fi

begin_test "#4578: single promotion of an OCI image index -> the index and both child manifests (and their blobs) resolve in the target"
PC="$(promote_one "$MULTI_ID" "${WORK}/p-multi.json")"
IC="$(get_manifest "$REL" multi 1.0 "${WORK}/rel-multi.json")"
IDIG="sha256:$(sha_of "${WORK}/rel-multi.json")"
C1="$(pulled_ok multi "$CH1_D" ch1 1)"; C2="$(pulled_ok multi "$CH2_D" ch2 1)"
if is_2xx "$PC" && [ "$IC" = "200" ] && [ "$IDIG" = "$(mdigest multi)" ] && [ -z "${C1// /}" ] && [ -z "${C2// /}" ]; then pass; else
  fail "promoted index not complete in ${REL}: promote=${PC} index=${IC} digest-match=$([ "$IDIG" = "$(mdigest multi)" ] && echo yes || echo no) child1:${C1:- ok} child2:${C2:- ok}" \
    "promote body=$(head -c 300 "${WORK}/p-multi.json" 2>/dev/null)"
fi

begin_test "#4578: bulk promotion of two tags -> both pullable from the target with their blobs"
BC="$(code_to_file "${BASE_URL}/api/v1/promotion/repositories/${STAGE}/promote" "${WORK}/p-bulk.json" -X POST "${AUTHZ[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"target_repository\":\"${REL}\",\"artifact_ids\":[\"${BK1_ID}\",\"${BK2_ID}\"],\"skip_policy_check\":true}")"
BP="$(jqr '.promoted' < "${WORK}/p-bulk.json")"
B1="$(pulled_ok bulk 1.0 bk1 1)"; B2="$(pulled_ok bulk 2.0 bk2 1)"
read -r TLC TLJ <<<"$(tags_list bulk)"
if is_2xx "$BC" && [ "$BP" = "2" ] && [ -z "${B1// /}" ] && [ -z "${B2// /}" ] && \
   echo "$TLJ" | jq -e 'index("1.0") and index("2.0")' >/dev/null 2>&1; then pass; else
  fail "bulk-promoted tags not pullable: bulk=${BC} promoted=${BP} bulk:1.0:${B1:- ok} bulk:2.0:${B2:- ok} tags/list=${TLC} ${TLJ}" \
    "bulk body=$(head -c 300 "${WORK}/p-bulk.json" 2>/dev/null)"
fi

begin_test "#4578: a source image with a missing layer blob FAILS the promotion and leaves no tag in the target"
PC="$(promote_one "$BROKEN_ID" "${WORK}/p-broken.json")"
PROM="$(jqr '.promoted' < "${WORK}/p-broken.json")"
RC="$(get_manifest "$REL" broken 1.0 /dev/null)"
RT="$(tag_rows "$REL" broken)"
RA="$(live_manifest_rows "$REL" broken)"
if ! is_2xx "$PC" && [ "$PROM" != "true" ] && [ "$RC" = "404" ] && [ "$RT" = "0" ] && [ "$RA" = "0" ]; then pass; else
  fail "an incomplete source image was promoted: promote=${PC} promoted=${PROM} target pull=${RC} target oci_tags=${RT} target live artifacts rows=${RA} (want non-2xx, not true, 404, 0, 0). Pre-#4578 the row was copied and an empty tag reported success" \
    "promote body=$(head -c 300 "${WORK}/p-broken.json" 2>/dev/null)"
fi

# ===========================================================================
# /v2/token RATE LIMITING (#4558 / #4020). LAST: exhausts TOKUSER's bucket.
# ===========================================================================
TOKUSER_ID="$(create_test_user_with_retry "$TOKUSER" "$TOKPASS" "${TOKUSER}@t.test")" || true
if [ -z "$TOKUSER_ID" ] || [ "$TOKUSER_ID" = "null" ]; then
  begin_test "setup: create the token-exchange user"
  infra_fail "could not create user ${TOKUSER}"
  end_suite
fi
token_exchange() { # USER PASS -> http code (body in $WORK/tok.json)
  code_to_file "${BASE_URL}/v2/token?service=artifact-keeper&scope=repository:${REPO}/xb:pull" "${WORK}/tok.json" \
    -u "${1}:${2}"
}

begin_test "CONTROL (#4558 boundary; 1.10.0 has no limiter): twelve successful /v2/token Basic exchanges (above the login budget of 10) never 429, and the same user's POST /auth/login still answers 200"
CODES=""; TOKS=0
for _ in $(seq 1 12); do
  c="$(token_exchange "$TOKUSER" "$TOKPASS")"; CODES="${CODES} ${c}"
  [ -n "$(jqr '.token // .access_token // empty' < "${WORK}/tok.json")" ] && TOKS=$((TOKS+1))
done
LC="$(code_to_file "${BASE_URL}/api/v1/auth/login" "${WORK}/login.json" -X POST -H 'Content-Type: application/json' \
  -d "{\"username\":\"${TOKUSER}\",\"password\":\"${TOKPASS}\"}")"
if ! echo "$CODES" | grep -q 429 && [ "$TOKS" = "12" ] && [ "$LC" = "200" ]; then pass; else
  fail "token exchanges or the login were throttled: exchanges=[${CODES} ] tokens=${TOKS}/12 login=${LC} (want no 429, 12 tokens, 200). Before #4558 the exchange spent the 10-per-15-min login budget and the 11th answered 429" \
    "login body=$(head -c 200 "${WORK}/login.json" 2>/dev/null)"
fi

begin_test "#4558/#4020: the exchange IS bounded by its own bucket: with RATE_LIMIT_TOKEN_EXCHANGE_PER_WINDOW=20 the 21st exchange answers 429 + Retry-After"
FIRST429=0; RA_HDR=""
for i in $(seq 13 26); do
  c="$(code_to_file "${BASE_URL}/v2/token?service=artifact-keeper&scope=repository:${REPO}/xb:pull" /dev/null \
       -D "${WORK}/tl.h" -u "${TOKUSER}:${TOKPASS}")"
  if [ "$c" = "429" ]; then FIRST429=$i; RA_HDR="$(grep -i '^retry-after:' "${WORK}/tl.h" | tr -d '\r' | head -1)"; break; fi
done
if [ "$FIRST429" -ge 19 ] && [ "$FIRST429" -le 22 ] && [ -n "$RA_HDR" ]; then
  echo "   first 429 at exchange ${FIRST429} (${RA_HDR})"; pass
else
  fail "first 429 at exchange ${FIRST429} (0 = none through 26), Retry-After='${RA_HDR}'; want 429 + Retry-After at about the 21st. 1.10.0 does not rate limit /v2/token at all (#4020 is 1.11.0)"
fi

end_suite
