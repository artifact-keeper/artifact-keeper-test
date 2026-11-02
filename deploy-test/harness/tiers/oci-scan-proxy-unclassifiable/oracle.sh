#!/usr/bin/env bash
# =============================================================================
# tiers/oci-scan-proxy-unclassifiable/oracle.sh
#   artifact-keeper#5097 (PR #5099): OCI scan-on-proxy withholds a manifest it
#   cannot classify under fail_closed and marks it pending under fail_open.
# See the manifest for the shapes and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's control port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
MOCK_CTL="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${DTF_SLOT}.83/"
CLOSED="dtf-occ-closed-${SUF}"
OPEN="dtf-occ-open-${SUF}"
RECORD="dtf-occ-record-${SUF}"
VIRT="dtf-occ-virt-${SUF}"
SHAPES=(case-keys dup-config manifests-null layer-case non-ascii-key unknown-config)
NON_IMAGES=(pure-index helm-chart flux-artifact cosign-attestation)
ACCEPT='application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws'

api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
# pull <repo> <reference> -> HTTP code; headers in $W/pull.hdr, body in $W/pull.body
pull() {
  : > "$W/pull.hdr"; : > "$W/pull.body"
  curl -s -o "$W/pull.body" -D "$W/pull.hdr" -w '%{http_code}' --max-time 120 -u "admin:${ADMIN_PASS}" \
    -H "Accept: ${ACCEPT}" "${BASE_URL}/v2/$1/app/manifests/$2" 2>/dev/null || echo 000
}
scan_hdr() { grep -i '^x-ak-scan:' "$W/pull.hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
snip() { printf 'scan=%s body=%s' "$(scan_hdr)" "$(head -c 200 "$W/pull.body" 2>/dev/null | tr -d '\n')"; }
mock_digest() { jq -r --arg t "$1" '.[$t] // empty' "$W/digests.json" 2>/dev/null || true; }
make_remote() { # <key> <action>
  local st
  st="$(api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg u "$UPSTREAM" \
    '{key:$k,name:$k,format:"docker",repo_type:"remote",upstream_url:$u,is_public:false}')")"
  case "$st" in 2??) ;; *) echo "create $1: HTTP ${st} $(head -c 200 "$W/api.json")"; return 1 ;; esac
  st="$(api PUT "/api/v1/repositories/$1/security" "$(jq -nc --arg a "$2" \
    '{scan_enabled:true,scan_on_proxy:true,proxy_scan_action:$a,block_on_policy_violation:true}')")"
  [ "$st" = "200" ] || { echo "security $1: HTTP ${st} $(head -c 200 "$W/api.json")"; return 1; }
}

begin_suite "oci-scan-proxy-unclassifiable"

begin_test "setup: admin login, fail_closed, fail_open and record_only Remotes, a Virtual over fail_closed"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at ${BASE_URL}"; end_suite; fi
cleanup_repos() {
  local r
  for r in "$VIRT" "$CLOSED" "$OPEN" "$RECORD"; do api DELETE "/api/v1/repositories/${r}" >/dev/null || true; done
}
add_exit_handler "cleanup_repos"
ERR="$(make_remote "$CLOSED" fail_closed; make_remote "$OPEN" fail_open; make_remote "$RECORD" record_only)"
st="$(api POST /api/v1/repositories "$(jq -nc --arg k "$VIRT" '{key:$k,name:$k,format:"docker",repo_type:"virtual",is_public:false}')")"
case "$st" in 2??) ;; *) ERR="${ERR} virtual create: HTTP ${st} $(head -c 200 "$W/api.json")" ;; esac
st="$(api POST "/api/v1/repositories/${VIRT}/members" "$(jq -nc --arg m "$CLOSED" '{member_key:$m,priority:1}')")"
case "$st" in 2??) ;; *) ERR="${ERR} virtual member: HTTP ${st} $(head -c 200 "$W/api.json")" ;; esac
curl -s --max-time 10 -o "$W/digests.json" "${MOCK_CTL}/__digests" || true
[ -n "$(mock_digest case-keys)" ] || ERR="${ERR} mock digests unreadable"
if [ -z "$ERR" ]; then pass; else infra_fail "$ERR"; end_suite; fi

# --- Controls ---------------------------------------------------------------
for tag in "${NON_IMAGES[@]}"; do
  begin_test "CONTROL: ${tag} (positively not an image) is 200 with no X-AK-Scan under fail_closed"
  st="$(pull "$CLOSED" "$tag")"
  if [ "$st" = "200" ] && [ -z "$(scan_hdr)" ]; then pass
  else fail "HTTP ${st}, want 200 with no scan header" "$(snip)"; fi
done

begin_test "CONTROL: a Docker schema1 manifest is 403 on the fail_closed Remote"
st="$(pull "$CLOSED" schema1)"
if [ "$st" = "403" ]; then pass; else fail "HTTP ${st}, want 403" "$(snip)"; fi

begin_test "CONTROL: a runnable image goes through the scan and is served with a clean verdict"
st="$(pull "$CLOSED" runnable)"
want="$(mock_digest runnable)"; hex="${want#sha256:}"
verdicts="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc \
  "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256 = '${hex}';" 2>/dev/null || true)"
if [ "$st" = "200" ] && [ -z "$(scan_hdr)" ] && printf '%s\n' "$verdicts" | grep -qx clean; then pass
else fail "HTTP ${st}, verdict rows '${verdicts}', want 200 and a clean row for ${want}" "$(snip)"; fi

# --- FIX: fail_closed withholds, first GET and repeat, by tag and by digest ---
for tag in "${SHAPES[@]}"; do
  begin_test "FIX #5097: ${tag} is withheld (423) under fail_closed"
  st1="$(pull "$CLOSED" "$tag")"; d1="$(snip)"
  st2="$(pull "$CLOSED" "$tag")"
  if [ "$st1" = "423" ] && [ "$st2" = "423" ]; then pass
  else fail "first GET HTTP ${st1}, repeat HTTP ${st2}, want 423 both" "$d1"; fi

  begin_test "FIX #5097: ${tag} by digest is withheld (423) under fail_closed"
  st="$(pull "$CLOSED" "$(mock_digest "$tag")")"
  if [ "$st" = "423" ]; then pass; else fail "HTTP ${st}, want 423" "$(snip)"; fi

  begin_test "FIX #5097: ${tag} is withheld (423) through a Virtual over the fail_closed Remote"
  st="$(pull "$VIRT" "$tag")"
  if [ "$st" = "423" ]; then pass; else fail "HTTP ${st}, want 423" "$(snip)"; fi

  for repo in "$OPEN" "$RECORD"; do
    case "$repo" in "$OPEN") action=fail_open ;; *) action=record_only ;; esac
    begin_test "FIX #5097: ${tag} is served marked X-AK-Scan: pending under ${action}"
    st="$(pull "$repo" "$tag")"
    if [ "$st" = "200" ] && [ "$(scan_hdr)" = "pending" ]; then pass
    else fail "HTTP ${st}, want 200 with X-AK-Scan: pending" "$(snip)"; fi
  done
done

begin_test "FIX #5097: a Docker schema1 manifest is refused (403) through the Virtual as on the Remote"
st="$(pull "$VIRT" schema1)"
if [ "$st" = "403" ]; then pass; else fail "HTTP ${st}, want 403" "$(snip)"; fi

end_suite
