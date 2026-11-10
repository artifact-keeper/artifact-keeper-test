#!/usr/bin/env bash
# roles/devops.sh - Kai Nakamura, DevOps lead at Halcyon Robotics.
#
# ROLES.md "## devops". Kai runs the ops project: the docker local / remote /
# virtual, the generic build store and the quarantined helm chart repo.
#
# Order (barriers, see ROLES.md "Barrier map"; no cycles):
#   push images (docker, or curl over the OCI API without it)
#     -> signal ops-image-pushed pushed|none
#   generic builds + Range work
#   publish chart, 409 + no non-admin release -> signal ops-chart-published
#   wait ops-image-reviewed (security) -> pin the scan-policy outcome
#   wait ops-chart-released (security) -> chart downloads
#
# Persona: OPS_LEAD only (jwt:, basic:, token:HAL_OPS_LEAD_TOKEN). The docker
# client runs with a private DOCKER_CONFIG under $CS_WORK.
#
# Objects this role creates (all named after the role):
#   - images ${HAL}-ops-base:1 (alpine:3.12, known vulnerable) and
#     ${HAL}-ops-clean:1 (busybox, no package database) in ops-docker-local.
#     LEFT IN PLACE: security, ci and auditor read them; a replay overwrites
#     the tags.
#   - chart ${HAL}-ops-app 0.1.0 in ops-helm. LEFT IN PLACE after the run
#     (ci pulls it after ops-chart-released); deleted and re-published at the
#     start of the next run so every run exercises a fresh quarantine hold.
#   - ${HAL}-ops/app-1.0.0.tar.gz in ops-builds: deleted at the end (#14).
#   - probe image ${HAL}-ops-probe:1 (#3e): deleted at the end.
#
# Replay: a previous run leaves ${HAL}-ops-base:1 scan-blocked, and docker
# (containerd image store) cannot push over a blocked tag: its pre-push
# HEAD /v2/.../manifests/<tag> answers 403 and the client aborts (#3e checks
# this). So the start of the run deletes the role's previous manifests as
# Kai (REST DELETE, delete grant on HAL-ops) before pushing again.
#
# Env: AK_REGISTRY (host:port of the OCI endpoint; default BASE_URL's host),
#      CS_BARRIER_TIMEOUT (default 600 s), HAL_DOCKER_VULN_IMAGE (alpine:3.12),
#      HAL_DOCKER_CLEAN_IMAGE (busybox:latest).

source "$(dirname "$0")/../lib.sh"

cs_begin devops
# Barriers this role signals: released as "failed" if it exits early.
cs_signals ops-image-pushed ops-chart-published

BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
SCAN_TIMEOUT="${CS_SCAN_TIMEOUT:-300}"
REG="${AK_REGISTRY:-${BASE_URL#*://}}"
REG="${REG%/}"
LOCAL="$HAL_REPO_OPS_DOCKER_LOCAL"
VIRT="$HAL_REPO_OPS_DOCKER"
BUILDS="$HAL_REPO_OPS_BUILDS"
HELM="$HAL_REPO_OPS_HELM"
VULN_SRC="${HAL_DOCKER_VULN_IMAGE:-alpine:3.12}"
CLEAN_SRC="${HAL_DOCKER_CLEAN_IMAGE:-busybox:latest}"
VULN_IMG="${HAL}-ops-base"
CLEAN_IMG="${HAL}-ops-clean"
PROBE_IMG="${HAL}-ops-probe"
CHART="${HAL}-ops-app"
CHART_VER="0.1.0"
CHART_FILE="${CHART}-${CHART_VER}.tgz"
CHART_PATH="${CHART}/${CHART_VER}/${CHART_FILE}"
BUILD_PATH="${HAL}-ops/app-1.0.0.tar.gz"
POLICY_MSG="Artifact download is blocked by the repository's scan policy"
QUAR_MSG="Artifact is quarantined and pending security review"

_cs_work
export DOCKER_CONFIG="${CS_WORK}/docker"
mkdir -p "$DOCKER_CONFIG"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
HAVE_DOCKER=false
if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
  HAVE_DOCKER=true
fi

# dk ARGS... - run docker with the private config; output in DK_OUT, rc in DK_RC.
DK_OUT="" DK_RC=0
dk() {
  DK_RC=0
  DK_OUT=$(timeout 300 docker "$@" 2>&1) || DK_RC=$?
  return 0
}

# oci_bearer IMAGE_PATH ACTIONS - Bearer token from /v2/token for Kai (Basic
# user:api_token, the form docker uses). Sets OCI_TOKEN.
OCI_TOKEN=""
oci_bearer() {
  OCI_TOKEN=""
  cs_http GET "/v2/token?service=artifact-keeper&scope=repository:$1:$2" basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN
  OCI_TOKEN=$(cs_json '.token // .access_token // empty')
}

MANIFEST_ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'

# oci_get_manifest IMAGE_PATH TAG
oci_get_manifest() {
  oci_bearer "$1" pull
  cs_http GET "/v2/$1/manifests/$2" none -H "Authorization: Bearer ${OCI_TOKEN:-none}" -H "Accept: ${MANIFEST_ACCEPT}"
}

# oci_copy SRC_REPO SRC_TAG DST_IMAGE DST_TAG - copy one image from the
# upstream registry (HAL_UPSTREAM_DOCKER, default Docker Hub) into
# ops-docker-local over the OCI distribution API with curl, as Kai (his
# push,pull token). Used when no docker client is available, so the
# scan-on-upload and scan-policy work still runs (the same transfer as
# tests/release-gate/test-pinned-cve-image.sh). Picks the linux/amd64
# manifest from an index. Sets OCI_COPY_NOTE; returns 0 when the manifest
# PUT answered 201.
OCI_COPY_NOTE=""
oci_copy() {
  local src="$1" stag="$2" dst="${LOCAL}/$3" dtag="$4"
  local up="${HAL_UPSTREAM_DOCKER:-https://registry-1.docker.io}" chal realm svc utok mt d f loc
  local acc='application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
  OCI_COPY_NOTE=""
  chal=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o /dev/null -D - "${up}/v2/" 2>/dev/null | tr -d '\r' | grep -i '^www-authenticate:' || true)
  realm=$(printf '%s' "$chal" | sed -n 's/.*realm="\([^"]*\)".*/\1/p')
  svc=$(printf '%s' "$chal" | sed -n 's/.*service="\([^"]*\)".*/\1/p')
  utok=""
  if [ -n "$realm" ]; then
    utok=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -G "$realm" --data-urlencode "service=${svc}" \
      --data-urlencode "scope=repository:${src}:pull" 2>/dev/null | jq -r '.token // .access_token // empty' 2>/dev/null || true)
  fi
  local -a uh=(); [ -n "$utok" ] && uh=(-H "Authorization: Bearer ${utok}")
  _up_get() { curl -sL "${CURL_TIMEOUT_ARGS[@]}" "${uh[@]}" "$@" 2>/dev/null; }
  f="${CS_WORK}/oci-$3.manifest"
  _up_get -H "Accept: ${acc}" -o "$f" "${up}/v2/${src}/manifests/${stag}"
  mt=$(jq -r '.mediaType // empty' "$f" 2>/dev/null || true)
  if jq -e '.manifests' "$f" >/dev/null 2>&1; then
    d=$(jq -r '[.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64")][0].digest // empty' "$f")
    [ -n "$d" ] || { OCI_COPY_NOTE="no linux/amd64 manifest in ${src}:${stag}"; return 1; }
    _up_get -H "Accept: ${acc}" -o "$f" "${up}/v2/${src}/manifests/${d}"
    mt=$(jq -r '.mediaType // empty' "$f" 2>/dev/null || true)
  fi
  jq -e '.config.digest and (.layers | length > 0)' "$f" >/dev/null 2>&1 \
    || { OCI_COPY_NOTE="upstream manifest for ${src}:${stag} unreadable"; return 1; }
  oci_bearer "$dst" "push,pull"
  for d in $(jq -r '.config.digest, .layers[].digest' "$f"); do
    _up_get -o "${CS_WORK}/blob" "${up}/v2/${src}/blobs/${d}"
    cs_http POST "/v2/${dst}/blobs/uploads/" none -H "Authorization: Bearer ${OCI_TOKEN:-none}"
    loc=$(cs_header Location)
    [ "$CS_STATUS" = "202" ] && [ -n "$loc" ] || { OCI_COPY_NOTE="blob upload start ${CS_STATUS}"; return 1; }
    case "$loc" in *\?*) loc="${loc}&digest=${d}" ;; *) loc="${loc}?digest=${d}" ;; esac
    cs_http PUT "$loc" none -H "Authorization: Bearer ${OCI_TOKEN:-none}" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${CS_WORK}/blob"
    [ "$CS_STATUS" = "201" ] || { OCI_COPY_NOTE="blob ${d:0:19} PUT ${CS_STATUS}"; return 1; }
  done
  cs_http PUT "/v2/${dst}/manifests/${dtag}" none -H "Authorization: Bearer ${OCI_TOKEN:-none}" \
    -H "Content-Type: ${mt:-application/vnd.docker.distribution.manifest.v2+json}" --data-binary "@${f}"
  OCI_COPY_NOTE="manifest PUT ${CS_STATUS} (${mt:-?})"
  [ "$CS_STATUS" = "201" ]
}

# artifact_id REPO PATH - set AID to the artifact id as Kai (empty when not found).
AID=""
artifact_id() {
  AID=""
  cs_http GET "/api/v1/repositories/$1/artifacts/$2" jwt:OPS_LEAD
  [ "$CS_STATUS" = "200" ] && AID=$(cs_json '.id // .artifact.id // empty')
  return 0
}

# wait_scans ARTIFACT_ID - poll the artifact's scans (Kai reads them through
# his project grant, H/security.rs:1593-1597) until at least one exists and
# none is pending/running. Sets SCAN_STATE ("done" / "timeout") and SCAN_SUMMARY.
SCAN_STATE="" SCAN_SUMMARY=""
wait_scans() {
  local aid="$1" waited=0 st
  SCAN_STATE="timeout"; SCAN_SUMMARY=""
  while [ "$waited" -lt "$SCAN_TIMEOUT" ]; do
    cs_http GET "/api/v1/security/scans?artifact_id=${aid}&per_page=100" jwt:OPS_LEAD
    st=$(cs_json '[.items[]?.status] | join(",")')
    SCAN_SUMMARY=$(cs_json '[.items[]? | "\(.scan_type // "scan"):\(.status) c=\(.critical_count // "?") h=\(.high_count // "?") f=\(.findings_count // "?")"] | join("; ")')
    if [ -n "$st" ] && ! printf '%s' "$st" | grep -qE 'pending|running|queued|in_progress'; then
      SCAN_STATE="done"; return 0
    fi
    sleep 5; waited=$((waited + 5))
  done
  return 1
}

# ---------------------------------------------------------------------------
# Morning: sign in
# ---------------------------------------------------------------------------
if cs_login OPS_LEAD; then
  cs_record "Kai signs in" PASS "JWT issued"
else
  cs_record "Kai signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  cs_end
fi

# Leftovers from an earlier run: the build artifact and the chart. A chart
# that survives would make #10 a duplicate and #11 a release from yesterday.
cs_http DELETE "/api/v1/repositories/${BUILDS}/artifacts/${BUILD_PATH}" jwt:OPS_LEAD
cs_http DELETE "/helm/${HELM}/api/charts/${CHART}/${CHART_VER}" basic:OPS_LEAD
echo "  cleanup: leftover chart delete -> HTTP ${CS_STATUS}"
for img in "$VULN_IMG" "$CLEAN_IMG" "$PROBE_IMG"; do
  cs_http DELETE "/api/v1/repositories/${LOCAL}/artifacts/v2/${img}/manifests/1" jwt:OPS_LEAD
  echo "  cleanup: leftover ${img}:1 delete -> HTTP ${CS_STATUS}"
done

# ---------------------------------------------------------------------------
# Tasks 1-4: docker
# ---------------------------------------------------------------------------
VULN_PUSHED=false
CLEAN_PUSHED=false
UP_CODE=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "${HAL_UPSTREAM_DOCKER:-https://registry-1.docker.io}/v2/" 2>/dev/null || echo 000)
if ! $HAVE_DOCKER; then
  for t in "1 docker login" "2 pull busybox via virtual" "4 pull vulnerable via virtual"; do
    cs_record "#${t}" SKIP "docker client not available"
  done
  # 3 without docker: the same two images over the OCI API with curl.
  for pair in "vuln|${VULN_SRC}|${VULN_IMG}" "clean|${CLEAN_SRC}|${CLEAN_IMG}"; do
    IFS='|' read -r kind src img <<<"$pair"
    srepo="${src%%:*}"; stag="${src#*:}"; [ "$stag" = "$src" ] && stag=latest
    case "$srepo" in */*) ;; *) srepo="library/${srepo}" ;; esac
    if [ "$UP_CODE" = "000" ]; then
      cs_record "#3 push ${kind} image ${LOCAL}/${img}:1 over the OCI API (no docker client)" SKIP "upstream registry unreachable"
    elif oci_copy "$srepo" "$stag" "$img" 1; then
      cs_record "#3 push ${kind} image ${LOCAL}/${img}:1 over the OCI API (no docker client)" PASS "copied ${srepo}:${stag}; ${OCI_COPY_NOTE}; scan_on_upload on (found-policies.sh)"
      [ "$kind" = vuln ] && VULN_PUSHED=true || CLEAN_PUSHED=true
    else
      cs_record "#3 push ${kind} image ${LOCAL}/${img}:1 over the OCI API (no docker client)" FAIL "${OCI_COPY_NOTE}" "${CS_BODY:0:400}"
    fi
  done
else
  # 1. docker login with the personal API token as the password.
  rc=0
  printf '%s' "$HAL_OPS_LEAD_TOKEN" | timeout 60 docker login "$REG" -u "$HAL_OPS_LEAD_USER" --password-stdin > "${CS_WORK}/login.out" 2>&1 || rc=$?
  if [ "$rc" = 0 ]; then
    cs_record "#1 docker login ${REG} as ${HAL_OPS_LEAD_USER} with API token" PASS "Login Succeeded (/v2/token Basic user:api_token, H/oci_v2.rs:5785-5790)"
  else
    cs_record "#1 docker login ${REG} as ${HAL_OPS_LEAD_USER} with API token" FAIL "docker login rc=${rc}" "$(head -c 400 "${CS_WORK}/login.out")"
  fi

  # 2. Pull an upstream image through the virtual (needs internet).
  if [ "$UP_CODE" = "000" ]; then
    cs_record "#2 docker pull ${VIRT}/library/busybox:1.36 through the virtual" SKIP "upstream registry unreachable"
  else
    dk rmi "${REG}/${VIRT}/library/busybox:1.36"
    dk pull "${REG}/${VIRT}/library/busybox:1.36"
    if [ "$DK_RC" = 0 ]; then
      cs_record "#2 docker pull ${VIRT}/library/busybox:1.36 through the virtual" PASS "pulled via remote member"
    else
      cs_record "#2 docker pull ${VIRT}/library/busybox:1.36 through the virtual" FAIL "docker pull rc=${DK_RC}" "${DK_OUT: -400}"
    fi
  fi

  # 3. Push a known-vulnerable image (scan_on_upload is on, found-policies.sh)
  #    and a clean one.
  for pair in "vuln|${VULN_SRC}|${VULN_IMG}" "clean|${CLEAN_SRC}|${CLEAN_IMG}"; do
    IFS='|' read -r kind src img <<<"$pair"
    dk image inspect "$src"
    if [ "$DK_RC" != 0 ]; then dk pull "$src"; fi
    dst="${REG}/${LOCAL}/${img}:1"
    dk tag "$src" "$dst"
    dk push "$dst"
    if [ "$DK_RC" = 0 ]; then
      cs_record "#3 docker push ${kind} image ${LOCAL}/${img}:1 (from ${src})" PASS "pushed; scan_on_upload on (found-policies.sh)"
      [ "$kind" = vuln ] && VULN_PUSHED=true || CLEAN_PUSHED=true
    else
      cs_record "#3 docker push ${kind} image ${LOCAL}/${img}:1 (from ${src})" FAIL "docker push rc=${DK_RC}" "${DK_OUT: -400}"
    fi
    dk rmi "$dst"
  done

  # 4. Pull the vulnerable image back through the virtual right away. Either
  #    answer is legitimate here (the upload scan may not have finished); the
  #    outcome is pinned after ops-image-reviewed (#5).
  if $VULN_PUSHED; then
    dk pull "${REG}/${VIRT}/${VULN_IMG}:1"
    if [ "$DK_RC" = 0 ]; then
      cs_record "#4 docker pull ${VIRT}/${VULN_IMG}:1 right after push" PASS "pulled (scan not finished yet, block_unscanned=false)"
    elif printf '%s' "$DK_OUT" | grep -qF "scan policy"; then
      cs_record "#4 docker pull ${VIRT}/${VULN_IMG}:1 right after push" PASS "refused by scan policy (#4510): $(printf '%s' "$DK_OUT" | grep -F 'scan policy' | tail -n1)"
    else
      cs_record "#4 docker pull ${VIRT}/${VULN_IMG}:1 right after push" FAIL "neither success nor a scan-policy refusal (rc=${DK_RC})" "${DK_OUT: -400}"
    fi
    dk rmi "${REG}/${VIRT}/${VULN_IMG}:1"
  else
    cs_record "#4 docker pull ${VIRT}/${VULN_IMG}:1 right after push" SKIP "vulnerable image was not pushed"
  fi
fi
# The outcome travels with the barrier: "pushed" when the vulnerable image is
# in ops-docker-local, "none" otherwise (security, ci and auditor then SKIP
# their image checks instead of looking for an image that is not there).
if $VULN_PUSHED; then cs_signal ops-image-pushed pushed; else cs_signal ops-image-pushed none; fi

# ---------------------------------------------------------------------------
# Tasks 6-9: generic build store
# ---------------------------------------------------------------------------
cs_fixture_bytes "${CS_WORK}/app.tar.gz" 4096 "${HAL}-ops-app-1.0.0"

# 6. Upload with his token as Bearer.
cs_put_generic "$BUILDS" "$BUILD_PATH" "${CS_WORK}/app.tar.gz" token:HAL_OPS_LEAD_TOKEN
cs_expect "#6 PUT ${BUILDS}/${BUILD_PATH} with Bearer API token" 201 "RS:11117-11141"

# 7. Same upload with Basic user:token on REST.
cs_put_generic "$BUILDS" "${HAL}-ops/app-basic-1.0.0.tar.gz" "${CS_WORK}/app.tar.gz" basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN
cs_expect "#7 same upload with Basic user:api_token is refused on REST" 401 "#2806, A:1012-1021"

# 8. Range on the day-0 firmware image.
cs_fixture_bytes "${CS_WORK}/fw.bin" "$HAL_SEED_FW_BIN_SIZE" "halcyon-fw-1.0.0"
FWDL="/api/v1/repositories/${BUILDS}/download/${HAL_SEED_FW_BIN}"
SZ="$HAL_SEED_FW_BIN_SIZE"

# range_check NAME PATH AUTH RANGE START LEN EXPECT_CR
range_check() {
  local name="$1" p="$2" auth="$3" rg="$4" start="$5" len="$6" ecr="$7" cr
  cs_http GET "$p" "$auth" -H "Range: bytes=${rg}"
  cr=$(cs_header Content-Range)
  if [ "$CS_STATUS" != "206" ]; then
    cs_record "$name" FAIL "expected 206, got ${CS_STATUS} (${CS_LAST_REQ}); RN:47 #5502" "${CS_BODY:0:300}"
    return
  fi
  if [ "$cr" != "$ecr" ]; then
    cs_record "$name" FAIL "206 but Content-Range '${cr}', expected '${ecr}'"
    return
  fi
  if cmp -s "$CS_BODY_FILE" <(tail -c +"$((start + 1))" "${CS_WORK}/fw.bin" | head -c "$len"); then
    cs_record "$name" PASS "206, Content-Range ${cr}, ${len} bytes match the fixture"
  else
    cs_record "$name" FAIL "206 ${cr} but body ($(stat -c %s "$CS_BODY_FILE") bytes) differs from fixture bytes ${start}+${len}"
  fi
}

range_check "#8a Range bytes=0-1023 on ${HAL_SEED_FW_BIN}" "$FWDL" jwt:OPS_LEAD "0-1023" 0 1024 "bytes 0-1023/${SZ}"
range_check "#8b Range bytes=-16 (suffix)" "$FWDL" jwt:OPS_LEAD "-16" "$((SZ - 16))" 16 "bytes $((SZ - 16))-$((SZ - 1))/${SZ}"
cs_http GET "$FWDL" jwt:OPS_LEAD -H "Range: bytes=${SZ}-"
cr=$(cs_header Content-Range)
if [ "$CS_STATUS" = "416" ] && [ "$cr" = "bytes */${SZ}" ]; then
  cs_record "#8c Range bytes=${SZ}- (past end) answers 416" PASS "416, Content-Range ${cr} (RS:12880-12950)"
else
  cs_record "#8c Range bytes=${SZ}- (past end) answers 416" FAIL "expected 416 + 'bytes */${SZ}', got ${CS_STATUS} + '${cr}'" "${CS_BODY:0:300}"
fi
ar=$(cs_header Accept-Ranges)
[ "$ar" = "bytes" ] && cs_record "#8d download advertises Accept-Ranges: bytes" PASS "Accept-Ranges ${ar}" \
  || cs_record "#8d download advertises Accept-Ranges: bytes" FAIL "Accept-Ranges '${ar}'"

# 9. Range through /general/.
range_check "#9 Range bytes=100-199 via /general/" "/general/${BUILDS}/${HAL_SEED_FW_BIN}" basic:OPS_LEAD "100-199" 100 100 "bytes 100-199/${SZ}"

# ---------------------------------------------------------------------------
# Tasks 10, 11, 13: helm chart into the quarantined repo
# ---------------------------------------------------------------------------
python3 -I - "$CHART" "$CHART_VER" "${CS_WORK}/${CHART_FILE}" <<'PY'
import io, sys, tarfile
name, ver, out = sys.argv[1:4]
files = {
    f"{name}/Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: {ver}\nappVersion: \"1.0.0\"\ndescription: Halcyon Robotics ops app\ntype: application\n",
    f"{name}/values.yaml": "image:\n  repository: hal-ops-base\n  tag: \"1\"\nreplicaCount: 1\n",
    f"{name}/templates/configmap.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}-ops\ndata:\n  team: devops\n",
}
with tarfile.open(out, "w:gz") as t:
    for p, s in files.items():
        d = s.encode(); ti = tarfile.TarInfo(p); ti.size = len(d); ti.mtime = 1700000000
        t.addfile(ti, io.BytesIO(d))
PY
CHART_SHA=$(sha256sum "${CS_WORK}/${CHART_FILE}" | cut -d' ' -f1)

# 10. Publish (helm cm-push style: Basic user:api_token on the native route).
cs_http POST "/helm/${HELM}/api/charts" basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN \
  -F "chart=@${CS_WORK}/${CHART_FILE};type=application/gzip"
CHART_OK=false
cs_expect "#10 POST /helm/${HELM}/api/charts ${CHART_FILE}" 201 "H/helm.rs:1301-1302" && CHART_OK=true

# 11. Immediately pull it: the upload-period hold answers 409.
cs_http GET "/helm/${HELM}/charts/${CHART_FILE}" basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN
if cs_expect "#11 GET chart right after upload (60 min quarantine)" 409 "S/quarantine_service.rs:270-280"; then
  cs_expect_body "#11b 409 body names the quarantine" "$QUAR_MSG"
fi

# 13. Kai administers the project, but upload-period holds have no
#     non-admin release.
artifact_id "$HELM" "$CHART_PATH"; CHART_AID="$AID"
if [ -z "$CHART_AID" ]; then
  cs_record "#13 find chart artifact id as Kai" FAIL "GET artifacts/${CHART_PATH} -> ${CS_STATUS}" "${CS_BODY:0:300}"
else
  cs_http GET "/api/v1/quarantine/${CHART_AID}" jwt:OPS_LEAD
  cs_expect "#13a Kai reads the chart's quarantine status" 200 "H/quarantine.rs:115-152; status=$(cs_json '.quarantine_status // .status // empty')"
  cs_http POST "/api/v1/quarantine/${CHART_AID}/release" jwt:OPS_LEAD -H 'Content-Type: application/json' -d '{}'
  cs_expect "#13 Kai (project admin) cannot release the upload hold" 403 "require_admin, H/quarantine.rs:315"
fi
# Only now may security release it: #11 and #13 need the chart still held.
cs_signal ops-chart-published

# ---------------------------------------------------------------------------
# Should NOT work
# ---------------------------------------------------------------------------
cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" "${HAL}-ops-crate" "0.1.0" basic:OPS_LEAD
cs_expect "Kai publishes to the firmware cargo registry (read-only there)" 403 "devops has read on HAL-fw, so 403 not 404 (A:2766-2804)"
if [ "$CS_STATUS" = "403" ]; then
  cs_expect_body "cargo refusal text" "You do not have permission to perform this action on this repository"
fi

artifact_id "$BUILDS" "$HAL_SEED_FW_BIN"; FW_AID="$AID"
cs_http POST /api/v1/security/scan jwt:OPS_LEAD -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg a "${FW_AID:-00000000-0000-0000-0000-000000000000}" '{artifact_id:$a}')"
if cs_expect "Kai triggers a scan" 403 "H/security.rs:1455-1463"; then
  cs_expect_body "scan refusal text" "Admin access required"
fi

cs_http PUT "/general/${BUILDS}/${HAL}-ops/x" basic:OPS_LEAD -H 'Content-Type: application/octet-stream' --data-binary 'x'
allow=$(cs_header Allow)
if [ "$CS_STATUS" = "405" ] && [ "$allow" = "GET, HEAD" ]; then
  cs_record "PUT /general/${BUILDS}/... as a writer answers 405" PASS "405, Allow: ${allow} (H/general.rs:22-40)"
else
  cs_record "PUT /general/${BUILDS}/... as a writer answers 405" FAIL "expected 405 + 'Allow: GET, HEAD', got ${CS_STATUS} + '${allow}'" "${CS_BODY:0:300}"
fi

# ---------------------------------------------------------------------------
# 3e. Remediation: push a fixed image over a tag the scan policy blocked.
# The owner of a blocked image ships a patched build under the same tag. The
# push is a write by a writer; the download gate is for pulls (HOLDS, #2912
# "must not be pullable"). Docker 25+ with the containerd store HEADs
# manifests/<tag> before the PUT and aborts on anything but 200/404.
# ---------------------------------------------------------------------------
if $HAVE_DOCKER && $VULN_PUSHED; then
  pr="${REG}/${LOCAL}/${PROBE_IMG}:1"
  dk tag "$VULN_SRC" "$pr"; dk push "$pr"; dk rmi "$pr"
  blocked=false waited=0
  while [ "$waited" -lt "$SCAN_TIMEOUT" ]; do
    oci_get_manifest "${LOCAL}/${PROBE_IMG}" 1
    [ "$CS_STATUS" = "403" ] && { blocked=true; break; }
    sleep 3; waited=$((waited + 3))
  done
  if ! $blocked; then
    cs_record "#3e push a fixed image over a scan-blocked tag" SKIP "probe ${PROBE_IMG}:1 never became blocked (last ${CS_STATUS})"
  else
    dk tag "$CLEAN_SRC" "$pr"; dk push "$pr"
    push_rc="$DK_RC" push_out="$DK_OUT"
    dk rmi "$pr"
    DK_RC="$push_rc" DK_OUT="$push_out"
    if [ "$DK_RC" = 0 ]; then
      cs_record "#3e push a fixed image over a scan-blocked tag" PASS "pushed ${CLEAN_SRC} over blocked ${PROBE_IMG}:1"
    else
      oci_bearer "${LOCAL}/${PROBE_IMG}" "push,pull"
      cs_http HEAD "/v2/${LOCAL}/${PROBE_IMG}/manifests/1" none -I -H "Authorization: Bearer ${OCI_TOKEN:-none}" -H "Accept: ${MANIFEST_ACCEPT}"
      if [ "$CS_STATUS" = "403" ] && printf '%s' "$DK_OUT" | grep -qF "$POLICY_MSG"; then
        # Filed upstream as #5606 (pre-existing: 1.11.12 refuses it too): the
        # pull gate answers the writer's pre-push HEAD with the scan-policy 403.
        cs_record "#3e push a fixed image over a scan-blocked tag (#5606)" WARN "#5606: docker push rc=${DK_RC}: '$(printf '%s' "$DK_OUT" | tail -n1)'; the writer's pre-push HEAD manifests/1 (push,pull token) answers 403" "${DK_OUT: -400}"
      else
        cs_record "#3e push a fixed image over a scan-blocked tag (#5606)" FAIL "docker push failed in a way #5606 does not cover: rc=${DK_RC} '$(printf '%s' "$DK_OUT" | tail -n1)'; pre-push HEAD answers ${CS_STATUS}" "${DK_OUT: -400}"
      fi
    fi
  fi
  cs_http DELETE "/api/v1/repositories/${LOCAL}/artifacts/v2/${PROBE_IMG}/manifests/1" jwt:OPS_LEAD
  cs_expect "#3f Kai deletes the probe image" 200
fi

# ---------------------------------------------------------------------------
# Task 5: the vulnerable image after security's review
# ---------------------------------------------------------------------------
# Security's ops-image-reviewed outcome (ROLES.md security #8): "blocked"
# when criticals stay open (the recommendation; the block stays), "cleared"
# when every finding was acknowledged, "none" when it reviewed no image.
expect_vuln=403
if cs_wait ops-image-reviewed "$BARRIER_TIMEOUT"; then
  rev=$(cs_signal_outcome ops-image-reviewed)
  [ "$rev" = "cleared" ] && expect_vuln=200
  echo "  security outcome: ${rev} -> expect ${expect_vuln}"
else
  cs_record "waited for ops-image-reviewed (security)" FAIL "${CS_WAIT_WHY}; #5 assumes no acknowledgement"
fi

if $VULN_PUSHED; then
  artifact_id "$LOCAL" "v2/${VULN_IMG}/manifests/1"; VULN_AID="$AID"
  if [ -n "$VULN_AID" ]; then
    wait_scans "$VULN_AID"
    if [ "$SCAN_STATE" = "done" ]; then
      cs_record "#3c upload scan of ${VULN_IMG}:1 completed" PASS "${SCAN_SUMMARY}"
    else
      cs_record "#3c upload scan of ${VULN_IMG}:1 completed" FAIL "no completed scan within ${SCAN_TIMEOUT}s: ${SCAN_SUMMARY:-no scans}"
    fi
  fi
  oci_get_manifest "${LOCAL}/${VULN_IMG}" 1
  if cs_expect "#5 GET /v2/${LOCAL}/${VULN_IMG}/manifests/1 after review" "$expect_vuln" "HOLDS:11-19,142-146; RN:48 (#4510)"; then
    [ "$expect_vuln" = 403 ] && cs_expect_body "#5b refusal names the scan policy" "$POLICY_MSG"
  fi
  oci_get_manifest "${VIRT}/${VULN_IMG}" 1
  cs_expect "#5c same image through the virtual ${VIRT}" "$expect_vuln" "member quarantine gate, H/oci_v2.rs:10456-10460"
  if [ "$expect_vuln" = 403 ] && $HAVE_DOCKER; then
    dk pull "${REG}/${VIRT}/${VULN_IMG}:1"
    if [ "$DK_RC" != 0 ] && printf '%s' "$DK_OUT" | grep -qF "scan policy"; then
      cs_record "#4b docker pull ${VIRT}/${VULN_IMG}:1 after review is refused" PASS "$(printf '%s' "$DK_OUT" | grep -F 'scan policy' | tail -n1)"
    else
      cs_record "#4b docker pull ${VIRT}/${VULN_IMG}:1 after review is refused" FAIL "docker pull rc=${DK_RC}" "${DK_OUT: -400}"
    fi
    dk rmi "${REG}/${VIRT}/${VULN_IMG}:1"
  fi
else
  cs_record "#5 vulnerable image blocked after review" SKIP "vulnerable image was not pushed"
fi

if $CLEAN_PUSHED; then
  artifact_id "$LOCAL" "v2/${CLEAN_IMG}/manifests/1"; CLEAN_AID="$AID"
  wait_scans "${CLEAN_AID:-none}"
  if [ "$SCAN_STATE" = "done" ]; then
    cs_record "#3d upload scan of ${CLEAN_IMG}:1 completed" PASS "${SCAN_SUMMARY}"
  else
    cs_record "#3d upload scan of ${CLEAN_IMG}:1 completed" FAIL "no completed scan within ${SCAN_TIMEOUT}s: ${SCAN_SUMMARY:-no scans}"
  fi
  oci_get_manifest "${LOCAL}/${CLEAN_IMG}" 1
  cs_expect "#5d clean image ${CLEAN_IMG}:1 pulls after its scan" 200 "no finding at or above critical (HOLDS)"
  if $HAVE_DOCKER; then
    dk pull "${REG}/${VIRT}/${CLEAN_IMG}:1"
    if [ "$DK_RC" = 0 ]; then
      cs_record "#5e docker pull ${VIRT}/${CLEAN_IMG}:1" PASS "pulled"
    else
      cs_record "#5e docker pull ${VIRT}/${CLEAN_IMG}:1" FAIL "docker pull rc=${DK_RC}" "${DK_OUT: -400}"
    fi
    dk rmi "${REG}/${VIRT}/${CLEAN_IMG}:1"
  fi
fi

# ---------------------------------------------------------------------------
# Task 12: the chart after security releases it
# ---------------------------------------------------------------------------
if $CHART_OK; then
  if cs_wait ops-chart-released "$BARRIER_TIMEOUT"; then
    cs_http GET "/helm/${HELM}/charts/${CHART_FILE}" basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN
    if cs_expect "#12 GET chart after ops-chart-released" 200; then
      got=$(sha256sum "$CS_BODY_FILE" | cut -d' ' -f1)
      [ "$got" = "$CHART_SHA" ] && cs_record "#12b released chart bytes match the upload" PASS "sha256 ${got:0:12}" \
        || cs_record "#12b released chart bytes match the upload" FAIL "sha256 ${got} != ${CHART_SHA}"
    fi
    cs_http GET "/helm/${HELM}/index.yaml" basictoken:OPS_LEAD:HAL_OPS_LEAD_TOKEN
    cs_expect_body "#12c index.yaml lists ${CHART}" "$CHART"
  else
    cs_record "waited for ops-chart-released (security)" FAIL "${CS_WAIT_WHY}; #12 not run"
  fi
fi

# ---------------------------------------------------------------------------
# Task 14: clean up the build artifact
# ---------------------------------------------------------------------------
cs_http DELETE "/api/v1/repositories/${BUILDS}/artifacts/${BUILD_PATH}" jwt:OPS_LEAD
cs_expect "#14 Kai deletes his build artifact" 200 "RS delete_artifact -> Result<()>"
cs_http GET "/api/v1/repositories/${BUILDS}/download/${BUILD_PATH}" jwt:OPS_LEAD
cs_expect "#14b deleted build artifact is gone" 404

cs_end
