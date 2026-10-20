#!/usr/bin/env bash
# test-oci-cross-repo-concurrent-push.sh - one blob digest pushed to two
# repositories at the same time (artifact-keeper#3851)
#
# The OCI upload cleanup journal used to key its rows by storage key alone,
# so two concurrent pushes of the same digest to two DIFFERENT repositories
# shared one journal row. The push that committed first deleted the shared
# row; the other push then had to prove a peer had committed by finding the
# winner's oci_blobs row, and if the winner's blob row was gone by then (its
# repository deleted in the window) the valid push got 503
# BLOB_UPLOAD_INVALID ("blob storage was being reclaimed concurrently").
#
# Part 1 (plain race): for OCI_RACE_ITERATIONS rounds, push a fresh random
# layer with the same digest to repos A and B in parallel (monolithic blob
# upload, then config and manifest), and assert that no request returns 503,
# every blob upload returns 201, and both manifests and layers pull back.
#
# Part 2 (the issue's trigger): per round, stage the same layer in a
# chunked upload session in a fresh repo pair, complete both sessions at
# (nearly) the same time, and delete repository A as soon as its completion
# returns. B's completion must not see 503 and B's image must pull. The
# window is timing dependent, so the round sweeps OCI_RACE_DELAYS_MS (delay
# before B's completion starts) and uses OCI_RACE_BLOB_MB-sized layers so the
# server-side copy keeps B's commit behind A's repository delete.
#
# Environment:
#   OCI_RACE_ITERATIONS     part 1 rounds (default 20)
#   OCI_RACE_BLOB_MB        part 1 layer size in MiB (default 8)
#   OCI_RACE_DELETE_ROUNDS  part 2 rounds per delay (default 5)
#   OCI_RACE_DELETE_BLOB_MB part 2 layer size in MiB (default 256)
#   OCI_RACE_DELAYS_MS      space-separated B delays for part 2 (default
#                           "100 250 500 1000")
#   OCI_STORAGE_BACKEND     storage_backend for the repos (default: "s3" when
#                           that backend is registered, else the deployment
#                           default)
#
# Calibration (grace microk8s, MinIO "s3" backend, unfixed 1.10.0 dev image):
# with 256 MiB layers part 2 returned 503 BLOB_UPLOAD_INVALID in 20/20
# rounds at every delay above; on the repo-isolated filesystem backend with
# 64 MiB layers the completion is too fast (~0.1 s) and 0/20 reproduced.
# Part 1 never reproduced (0/20): without the delete there is always a peer
# oci_blobs row to find. Part 2 moves ~10 GiB through the backend.
#
# Requires: curl, jq, sha256sum or shasum, dd

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-cross-repo-concurrent-push"
auth_admin
setup_workdir

ITER="${OCI_RACE_ITERATIONS:-20}"
P1_BLOB_MB="${OCI_RACE_BLOB_MB:-8}"
P2_ITER="${OCI_RACE_DELETE_ROUNDS:-5}"
P2_BLOB_MB="${OCI_RACE_DELETE_BLOB_MB:-256}"
DELAYS_MS="${OCI_RACE_DELAYS_MS:-100 250 500 1000}"
BLOB_MB="$P1_BLOB_MB"
IMG="race"

_or_sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

_or_ms() { date +%s%3N; }

oci_token() {
  curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" \
    | jq -r '.token // empty'
}

make_repo() {
  local key="$1" payload code
  payload="{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":true"
  [ -n "${OCI_STORAGE_BACKEND:-}" ] && payload="${payload},\"storage_backend\":\"${OCI_STORAGE_BACKEND}\""
  payload="${payload}}"
  code=$(curl -s -o "${WORK_DIR}/repo-${key}.json" -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" -H "Content-Type: application/json" -d "$payload" \
    "${BASE_URL}/api/v1/repositories") || code="000"
  case "$code" in 200|201) return 0 ;; esac
  echo "create repo ${key}: HTTP ${code} $(head -c 200 "${WORK_DIR}/repo-${key}.json")" >&2
  return 1
}

# upload_blob_monolithic REPO FILE DIGEST OUTFILE
# POST /v2/<repo>/<img>/blobs/uploads/?digest=... with the whole body.
upload_blob_monolithic() {
  local repo="$1" file="$2" digest="$3" out="$4"
  curl -s -o "${out}.body" -w '%{http_code}' --max-time 300 -X POST \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/octet-stream" \
    --data-binary "@${file}" \
    "${BASE_URL}/v2/${repo}/${IMG}/blobs/uploads/?digest=${digest}" > "$out" 2>/dev/null \
    || echo "000" > "$out"
}

# stage_session REPO FILE -> prints the absolute upload URL after one PATCH
# carrying the whole layer.
stage_session() {
  local repo="$1" file="$2" loc hdr code
  hdr="${WORK_DIR}/stage-${repo}.hdr"
  curl -s -D "$hdr" -o /dev/null $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL}/v2/${repo}/${IMG}/blobs/uploads/" > /dev/null 2>&1 || return 1
  loc=$(grep -i '^location:' "$hdr" | tail -1 | tr -d '\r' | awk '{print $2}')
  [ -n "$loc" ] || return 1
  [[ "$loc" == http* ]] || loc="${BASE_URL}${loc}"
  code=$(curl -s -D "$hdr" -o /dev/null -w '%{http_code}' --max-time 300 -X PATCH \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/octet-stream" \
    --data-binary "@${file}" "$loc") || return 1
  [ "$code" = "202" ] || { echo "PATCH ${repo}: HTTP ${code}" >&2; return 1; }
  loc=$(grep -i '^location:' "$hdr" | tail -1 | tr -d '\r' | awk '{print $2}')
  [[ "$loc" == http* ]] || loc="${BASE_URL}${loc}"
  echo "$loc"
}

# complete_session URL DIGEST OUTFILE
complete_session() {
  local url="$1" digest="$2" out="$3" sep="?"
  [[ "$url" == *"?"* ]] && sep="&"
  curl -s -o "${out}.body" -w '%{http_code}' --max-time 300 -X PUT \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Length: 0" \
    "${url}${sep}digest=${digest}" > "$out" 2>/dev/null || echo "000" > "$out"
}

# push_manifest REPO TAG CONFIG_FILE CONFIG_DIGEST LAYER_DIGEST LAYER_SIZE -> HTTP
push_manifest() {
  local repo="$1" tag="$2" cfg="$3" cdig="$4" ldig="$5" lsize="$6" csize code
  csize=$(wc -c < "$cfg" | tr -d ' ')
  code=$(upload_status_config "$repo" "$cfg" "$cdig")
  case "$code" in 201) ;; *) echo "config:${code}"; return 0 ;; esac
  cat > "${WORK_DIR}/manifest-${repo}.json" <<EOFM
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
 "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"${cdig}","size":${csize}},
 "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"${ldig}","size":${lsize}}]}
EOFM
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    --data-binary "@${WORK_DIR}/manifest-${repo}.json" \
    "${BASE_URL}/v2/${repo}/${IMG}/manifests/${tag}" || echo "000"
}

upload_status_config() {
  local repo="$1" cfg="$2" cdig="$3"
  upload_blob_monolithic "$repo" "$cfg" "$cdig" "${WORK_DIR}/cfg-${repo}.code"
  cat "${WORK_DIR}/cfg-${repo}.code"
}

# image_pulls REPO TAG LAYER_DIGEST -> rc 0 when manifest GET is 200 and the
# layer GET returns bytes with the layer digest.
image_pulls() {
  local repo="$1" tag="$2" ldig="$3" code got
  code=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${repo}/${IMG}/manifests/${tag}") || code="000"
  [ "$code" = "200" ] || { echo "manifest ${repo}:${tag} HTTP ${code}"; return 1; }
  code=$(curl -s -L -o "${WORK_DIR}/pulled-${repo}.bin" -w '%{http_code}' --max-time 300 \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL}/v2/${repo}/${IMG}/blobs/${ldig}") || code="000"
  [ "$code" = "200" ] || { echo "layer ${repo} HTTP ${code}"; return 1; }
  got="sha256:$(_or_sha256 "${WORK_DIR}/pulled-${repo}.bin")"
  [ "$got" = "$ldig" ] || { echo "layer ${repo} digest ${got} != ${ldig}"; return 1; }
  return 0
}

new_layer() {
  dd if=/dev/urandom of="${WORK_DIR}/layer.bin" bs=1048576 count="$BLOB_MB" 2>/dev/null
  LAYER_DIGEST="sha256:$(_or_sha256 "${WORK_DIR}/layer.bin")"
  LAYER_SIZE=$(wc -c < "${WORK_DIR}/layer.bin" | tr -d ' ')
  printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["%s"]},"config":{},"akt":"%s"}' \
    "$LAYER_DIGEST" "$(date +%s%N)" > "${WORK_DIR}/config.json"
  CONFIG_DIGEST="sha256:$(_or_sha256 "${WORK_DIR}/config.json")"
}

TOKEN=$(oci_token)
if [ -z "$TOKEN" ]; then
  echo "FATAL: could not obtain an OCI token"
  exit 1
fi

if [ -z "${OCI_STORAGE_BACKEND+x}" ]; then
  if api_get "/api/v1/admin/storage-backends" 2>/dev/null | jq -e '
      (if type == "array" then . elif (.backends | type == "array") then .backends
       elif (.items | type == "array") then .items else [] end)
      | map(if type == "string" then . else (.name // .key // .backend_type // "") end)
      | index("s3") != null' > /dev/null 2>&1; then
    OCI_STORAGE_BACKEND="s3"
  fi
fi
echo "  storage backend: ${OCI_STORAGE_BACKEND:-<deployment default>}"

RACE_SFX="$(date +%s)"
REPO_A="oci-race-a-${RUN_ID}-${RACE_SFX}"
REPO_B="oci-race-b-${RUN_ID}-${RACE_SFX}"

drop_repo() {
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${1}" > /dev/null 2>&1 || true
}

begin_test "Create two OCI repositories"
if make_repo "$REPO_A" && make_repo "$REPO_B"; then
  pass
else
  fail "could not create ${REPO_A}/${REPO_B}"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Part 1: plain concurrent cross-repo pushes of one digest
# ---------------------------------------------------------------------------

P1_503=0
P1_BAD=""
P1_PULL_FAIL=""
for i in $(seq 1 "$ITER"); do
  new_layer
  upload_blob_monolithic "$REPO_A" "${WORK_DIR}/layer.bin" "$LAYER_DIGEST" "${WORK_DIR}/p1a.code" &
  pa=$!
  upload_blob_monolithic "$REPO_B" "${WORK_DIR}/layer.bin" "$LAYER_DIGEST" "${WORK_DIR}/p1b.code" &
  pb=$!
  wait "$pa" "$pb"
  ca=$(cat "${WORK_DIR}/p1a.code"); cb=$(cat "${WORK_DIR}/p1b.code")
  ma=$(push_manifest "$REPO_A" "r${i}" "${WORK_DIR}/config.json" "$CONFIG_DIGEST" "$LAYER_DIGEST" "$LAYER_SIZE")
  mb=$(push_manifest "$REPO_B" "r${i}" "${WORK_DIR}/config.json" "$CONFIG_DIGEST" "$LAYER_DIGEST" "$LAYER_SIZE")
  echo "  round ${i}: blob A=${ca} B=${cb} manifest A=${ma} B=${mb}"
  for c in "$ca" "$cb" "$ma" "$mb"; do
    [ "$c" = "503" ] || [ "$c" = "config:503" ] && P1_503=$(( P1_503 + 1 ))
  done
  if [ "$ca" != "201" ] || [ "$cb" != "201" ]; then
    P1_BAD="${P1_BAD} r${i}:A=${ca},B=${cb}($(head -c 160 "${WORK_DIR}/p1a.code.body" 2>/dev/null)|$(head -c 160 "${WORK_DIR}/p1b.code.body" 2>/dev/null))"
  fi
  if ! o=$(image_pulls "$REPO_A" "r${i}" "$LAYER_DIGEST") || ! o=$(image_pulls "$REPO_B" "r${i}" "$LAYER_DIGEST"); then
    P1_PULL_FAIL="${P1_PULL_FAIL} r${i}:${o}"
  fi
done

begin_test "#3851 concurrent cross-repo pushes of one digest never return 503 (${ITER} rounds)"
if [ "$P1_503" = "0" ]; then
  pass
else
  fail "${P1_503} request(s) returned 503 over ${ITER} rounds"
fi

begin_test "#3851 every concurrent blob upload returns 201"
if [ -z "$P1_BAD" ]; then
  pass
else
  fail "non-201 blob uploads:${P1_BAD}"
fi

begin_test "#3851 both images pull back after every round"
if [ -z "$P1_PULL_FAIL" ]; then
  pass
else
  fail "pull failures:${P1_PULL_FAIL}"
fi

# ---------------------------------------------------------------------------
# Part 2: concurrent completions with the winner's repository deleted
# ---------------------------------------------------------------------------

P2_503=0
P2_ROUNDS=0
P2_BAD=""
P2_PULL_FAIL=""
P2_503_DETAIL=""
BLOB_MB="$P2_BLOB_MB"
for i in $(seq 1 "$P2_ITER"); do
  for d in $DELAYS_MS; do
    P2_ROUNDS=$(( P2_ROUNDS + 1 ))
    ra="oci-race2-a-${RUN_ID}-${RACE_SFX}-${i}-${d}"
    rb="oci-race2-b-${RUN_ID}-${RACE_SFX}-${i}-${d}"
    new_layer
    if ! make_repo "$ra" || ! make_repo "$rb"; then
      P2_BAD="${P2_BAD} r${i}/${d}:repo-create"
      drop_repo "$ra"; drop_repo "$rb"
      continue
    fi
    ua=$(stage_session "$ra" "${WORK_DIR}/layer.bin") || { P2_BAD="${P2_BAD} r${i}/${d}:stage-A"; drop_repo "$ra"; drop_repo "$rb"; continue; }
    ub=$(stage_session "$rb" "${WORK_DIR}/layer.bin") || { P2_BAD="${P2_BAD} r${i}/${d}:stage-B"; drop_repo "$ra"; drop_repo "$rb"; continue; }
    (
      complete_session "$ua" "$LAYER_DIGEST" "${WORK_DIR}/p2a.code"
      # A committed (or failed): delete its repository at once so its
      # oci_blobs row cascades away while B is still between registration
      # and its commit-time claim.
      curl -s -o /dev/null $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
        "${BASE_URL}/api/v1/repositories/${ra}" > /dev/null 2>&1 || true
    ) &
    pa=$!
    (
      [ "$d" -gt 0 ] && sleep "$(awk -v ms="$d" 'BEGIN{printf "%.3f", ms/1000}')"
      complete_session "$ub" "$LAYER_DIGEST" "${WORK_DIR}/p2b.code"
    ) &
    pb=$!
    wait "$pa" "$pb"
    ca=$(cat "${WORK_DIR}/p2a.code"); cb=$(cat "${WORK_DIR}/p2b.code")
    if [ "$cb" = "503" ]; then
      P2_503=$(( P2_503 + 1 ))
      P2_503_DETAIL="${P2_503_DETAIL} r${i}/${d}ms:$(head -c 200 "${WORK_DIR}/p2b.code.body")"
    fi
    if [ "$cb" = "201" ]; then
      mb=$(push_manifest "$rb" "r${i}" "${WORK_DIR}/config.json" "$CONFIG_DIGEST" "$LAYER_DIGEST" "$LAYER_SIZE")
      if [ "$mb" != "201" ] && [ "$mb" != "200" ]; then
        P2_PULL_FAIL="${P2_PULL_FAIL} r${i}/${d}:manifest=${mb}"
      elif ! o=$(image_pulls "$rb" "r${i}" "$LAYER_DIGEST"); then
        P2_PULL_FAIL="${P2_PULL_FAIL} r${i}/${d}:${o}"
      fi
    else
      P2_BAD="${P2_BAD} r${i}/${d}ms:A=${ca},B=${cb}"
    fi
    echo "  round ${i} delay ${d}ms: complete A=${ca} B=${cb}"
    drop_repo "$rb"
  done
done

begin_test "#3851 completion racing the peer repository's delete never returns 503 (${P2_ROUNDS} rounds)"
if [ "$P2_503" = "0" ]; then
  pass
else
  fail "${P2_503}/${P2_ROUNDS} completions returned 503:${P2_503_DETAIL}"
fi

begin_test "#3851 the surviving repository's completion returns 201 every round"
if [ -z "$P2_BAD" ]; then
  pass
else
  fail "rounds without a 201 for B:${P2_BAD}"
fi

begin_test "#3851 the surviving repository's image pulls back"
if [ -z "$P2_PULL_FAIL" ]; then
  pass
else
  fail "pull failures:${P2_PULL_FAIL}"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_B}" > /dev/null 2>&1 || true

end_suite
