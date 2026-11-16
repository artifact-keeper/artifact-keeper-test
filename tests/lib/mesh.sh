#!/usr/bin/env bash
# mesh.sh - helpers for multi-instance (hub + peers) mesh suites
# (artifact-keeper/artifact-keeper#6120)
#
# Source AFTER tests/lib/common.sh. common.sh's api_* helpers talk to
# BASE_URL with ADMIN_TOKEN; these helpers switch both per call, so one script
# can drive the hub and every peer without hand-saving and restoring them.
#
#   mesh_login URL                        admin JWT for URL (cached per URL)
#   mesh_on URL CMD...                    run CMD with BASE_URL/ADMIN_TOKEN set for URL
#   mesh_peer_key PEER_URL NAME           create an API token ON the peer for a
#                                         hub's sync worker to push/delete with
#   mesh_link SRC_URL DST_URL NAME        register DST on SRC with a real key;
#                                         prints the peer id on SRC
#   mesh_wait_peer_status SRC_URL ID STATUS SECS
#   mesh_artifact_state URL REPO PATH     present / absent (404) / error:<code>
#   mesh_wait_artifact URL REPO PATH SECS [present|absent]
#   mesh_wait_all SECS STATE REPO PATH URL...  one shared deadline for all URLs
#   mesh_download_sha URL REPO PATH       sha256 of the bytes URL serves
#
# How a hub reaches a peer (backend services/sync_worker.rs): the hub's sync
# worker pushes with `Authorization: Bearer <api_key>`, the api_key the peer
# was REGISTERED with on the hub, and the peer authenticates that bearer as an
# ordinary token of its own. So the key must be a token minted on the peer,
# with write and delete scope, or every push is refused. The heartbeat probe
# (GET /api/v1/peers on the peer with the same key) needs only a 2xx, which
# any valid token gets, and is what keeps the peer `online` on the hub.

declare -A _MESH_TOKENS=()

mesh_login() {
  local url="$1"
  if [ -n "${_MESH_TOKENS[$url]:-}" ]; then
    printf '%s' "${_MESH_TOKENS[$url]}"
    return 0
  fi
  local saved_base="$BASE_URL" saved_tok="${ADMIN_TOKEN:-}" tok
  export BASE_URL="$url"
  auth_admin >/dev/null || return 1
  tok="$ADMIN_TOKEN"
  export BASE_URL="$saved_base" ADMIN_TOKEN="$saved_tok"
  _MESH_TOKENS[$url]="$tok"
  printf '%s' "$tok"
}

# mesh_init URL... : log in to every instance once, in the CALLING shell, so
# the token cache is inherited by the $(...) subshells the other helpers run
# in. Without it each poll would log in again (a bcrypt verify per call on a
# 100m-CPU backend).
mesh_init() {
  local u
  for u in "$@"; do
    mesh_login "$u" >/dev/null
  done
}

# mesh_on URL CMD... : run CMD against URL as admin; restores context after.
mesh_on() {
  local url="$1"; shift
  local saved_base="$BASE_URL" saved_tok="${ADMIN_TOKEN:-}" tok rc
  mesh_login "$url" >/dev/null
  tok="${_MESH_TOKENS[$url]}"
  export BASE_URL="$url" ADMIN_TOKEN="$tok"
  rc=0
  "$@" || rc=$?
  export BASE_URL="$saved_base" ADMIN_TOKEN="$saved_tok"
  return $rc
}

# mesh_peer_key PEER_URL NAME : prints a new API token minted on the peer.
mesh_peer_key() {
  local peer_url="$1" name="$2" resp key
  resp=$(mesh_on "$peer_url" api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${name}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\",\"delete:artifacts\"]}") || {
    echo "mesh_peer_key: POST /api/v1/auth/tokens on ${peer_url} failed" >&2
    return 1
  }
  key=$(printf '%s' "$resp" | jq -r '.token // empty')
  if [ -z "$key" ]; then
    echo "mesh_peer_key: token response from ${peer_url} has no .token: ${resp:0:200}" >&2
    return 1
  fi
  printf '%s' "$key"
}

# mesh_link SRC_URL DST_URL NAME : register DST as a peer on SRC with a key
# minted on DST, mark it online with one heartbeat, print its id on SRC.
mesh_link() {
  local src="$1" dst="$2" name="$3" key resp id
  key=$(mesh_peer_key "$dst" "${name}-key") || return 1
  resp=$(mesh_on "$src" api_post "/api/v1/peers" \
    "{\"name\":\"${name}\",\"endpoint_url\":\"${dst}\",\"api_key\":\"${key}\"}") || {
    echo "mesh_link: registering ${dst} on ${src} failed" >&2
    return 1
  }
  id=$(printf '%s' "$resp" | jq -r '.id // empty')
  if [ -z "$id" ]; then
    echo "mesh_link: peer registration on ${src} returned no id: ${resp:0:200}" >&2
    return 1
  fi
  # A new peer row starts `offline`; the worker's own probe flips it within
  # PEER_HEARTBEAT_INTERVAL_SECS, a manual heartbeat does it now.
  mesh_on "$src" api_post "/api/v1/peers/${id}/heartbeat" '{"cache_used_bytes":0}' >/dev/null 2>&1 || true
  printf '%s' "$id"
}

# mesh_peer_status SRC_URL ID : prints the peer row's status on SRC.
mesh_peer_status() {
  mesh_on "$1" api_get "/api/v1/peers/$2" 2>/dev/null | jq -r '.status // "unknown"'
}

# mesh_wait_peer_status SRC_URL ID STATUS SECS
mesh_wait_peer_status() {
  local src="$1" id="$2" want="$3" secs="$4" deadline st=""
  deadline=$(( $(date +%s) + secs ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st=$(mesh_peer_status "$src" "$id") || st="unknown"
    [ "$st" = "$want" ] && return 0
    sleep 3
  done
  echo "  peer ${id} on ${src}: status '${st}', wanted '${want}' within ${secs}s" >&2
  return 1
}

# mesh_artifact_state URL REPO PATH : prints present (HTTP 200), absent
# (HTTP 404) or error:<code> (anything else: timeout, 401, 5xx). An error is
# never read as "absent": a peer that is down must not pass a delete check.
mesh_artifact_state() {
  local url="$1" repo="$2" path="$3" tok code
  tok=$(mesh_login "$url")
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "Authorization: Bearer ${tok}" \
    "${url}/api/v1/repositories/${repo}/artifacts/${path}" 2>/dev/null) || code=000
  case "$code" in
    200) echo present ;;
    404) echo absent ;;
    *)   echo "error:${code}" ;;
  esac
}

# mesh_has_artifact URL REPO PATH : 0 only when the artifact resolves (200).
mesh_has_artifact() {
  [ "$(mesh_artifact_state "$@")" = present ]
}

# mesh_lacks_artifact URL REPO PATH : 0 only on a definite 404.
mesh_lacks_artifact() {
  [ "$(mesh_artifact_state "$@")" = absent ]
}

# mesh_wait_artifact URL REPO PATH SECS [present|absent] : poll until the
# state is reached (0) or SECS pass (1). Errors keep polling; on timeout the
# last state is printed to stderr.
mesh_wait_artifact() {
  local url="$1" repo="$2" path="$3" secs="$4" want="${5:-present}" deadline st=""
  deadline=$(( $(date +%s) + secs ))
  while :; do
    st=$(mesh_artifact_state "$url" "$repo" "$path")
    [ "$st" = "$want" ] && return 0
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "  ${url} ${repo}/${path}: '${st}' after ${secs}s, wanted '${want}'" >&2
      return 1
    fi
    sleep 3
  done
}

# mesh_wait_all SECS STATE REPO PATH URL... : wait for STATE on every URL
# within ONE shared deadline (the peers are checked in turn, but the total
# wait is SECS, not SECS per peer). Prints each URL that missed it.
mesh_wait_all() {
  local secs="$1" want="$2" repo="$3" path="$4" deadline left u rc=0
  shift 4
  deadline=$(( $(date +%s) + secs ))
  for u in "$@"; do
    left=$(( deadline - $(date +%s) ))
    [ "$left" -lt 1 ] && left=1
    mesh_wait_artifact "$u" "$repo" "$path" "$left" "$want" || { echo "  ${path} not ${want} on ${u}"; rc=1; }
  done
  return $rc
}

# mesh_download_sha URL REPO PATH : sha256 of the downloaded bytes.
mesh_download_sha() {
  local url="$1" repo="$2" path="$3" tok
  tok=$(mesh_login "$url")
  curl -sf --max-time 30 -H "Authorization: Bearer ${tok}" \
    "${url}/api/v1/repositories/${repo}/download/${path}" | sha256sum | awk '{print $1}'
}

# mesh_upload URL REPO PATH FILE
mesh_upload() {
  mesh_on "$1" api_upload "/api/v1/repositories/$2/artifacts/$3" "$4" "application/octet-stream" >/dev/null
}

# mesh_subscribe SRC_URL PEER_ID REPO_KEY MODE [SCHEDULE]
# Subscribe the peer to a repo on SRC (POST /peers/{id}/repositories).
mesh_subscribe() {
  local src="$1" peer="$2" repo="$3" mode="$4" sched="${5:-}" rid body
  rid=$(mesh_on "$src" api_get "/api/v1/repositories/${repo}" | jq -r '.id // empty')
  [ -n "$rid" ] || { echo "mesh_subscribe: no id for repo ${repo} on ${src}" >&2; return 1; }
  if [ -n "$sched" ]; then
    body="{\"repository_id\":\"${rid}\",\"replication_mode\":\"${mode}\",\"replication_schedule\":\"${sched}\",\"sync_enabled\":true}"
  else
    body="{\"repository_id\":\"${rid}\",\"replication_mode\":\"${mode}\",\"sync_enabled\":true}"
  fi
  mesh_on "$src" api_post "/api/v1/peers/${peer}/repositories" "$body" >/dev/null || {
    echo "mesh_subscribe: POST /peers/${peer}/repositories on ${src} failed" >&2
    return 1
  }
  printf '%s' "$rid"
}

# mesh_tag : a short, unique, DNS-safe tag for resource names: the last 16
# characters of RUN_ID (alphanumerics only), the epoch and this shell's pid.
# Peer names are unique per instance (peer_instances_name_key), so two
# scripts on one hub must never derive the same name.
mesh_tag() {
  local t="${RUN_ID//[^a-zA-Z0-9]/}"
  t=$(printf '%s' "$t" | tail -c 16)
  printf '%s-%s-%s' "${t:-run}" "$(date +%s)" "$$"
}
