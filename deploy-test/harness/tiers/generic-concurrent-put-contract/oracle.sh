#!/usr/bin/env bash
# =============================================================================
# tiers/generic-concurrent-put-contract/oracle.sh: concurrent generic PUTs to
#   one path have exactly one winner (artifact-keeper#4832)
# =============================================================================
# run.sh has stood up `storage.filesystem` and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug.
#
# Topology (keys suffixed per run):
#   G    generic hosted
#   GV   generic hosted, versioning_enabled=true
#
# The FIX case is RED on 1.11.0-1.11.3 and GREEN on the fix; every CONTROL
# holds on both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SUF="${RUN_ID##*-}$$"
G="gcp-g-${SUF}"; GV="gcp-v-${SUF}"
RACERS=16
CONFLICT_MSG="Artifact version already exists and is immutable"

WORK="$(mktemp -d -t dtf-gcp-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
send() {  # send METHOD PATH [JSON] -> HTTP status, body in $WORK/send.out
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
put() {  # put KEY PATH FILE OUT -> HTTP status, body in OUT
  curl -s --max-time 120 -o "$4" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null || echo 000
}
download() {  # download KEY PATH OUT -> HTTP status
  curl -s --max-time 60 -o "$3" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/$1/download/$2" 2>/dev/null || echo 000
}
sha() { sha256sum "$1" | cut -d' ' -f1; }
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
is_conflict_body() {
  jq -e --arg m "$CONFLICT_MSG" '.code == "CONFLICT" and .message == $m' "$1" >/dev/null 2>&1
}
live_rows() {  # live_rows KEY PATH -> "<count>|<checksum>"
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) || '|' || coalesce(max(a.checksum_sha256), '') FROM artifacts a \
     JOIN repositories r ON r.id = a.repository_id \
     WHERE r.key = '$1' AND a.path = '$2' AND NOT a.is_deleted" 2>/dev/null | tr -d '[:space:]'
}
mkbody() { head -c 65536 /dev/urandom > "$1"; }

begin_suite "generic-concurrent-put-contract (#4832)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: a generic hosted repository, a versioning-enabled one, ${RACERS} distinct 64 KiB bodies"
auth_admin
err=""
st="$(send POST /api/v1/repositories "{\"key\":\"${G}\",\"name\":\"${G}\",\"format\":\"generic\",\"repo_type\":\"local\"}")"
ok2xx "$st" || err+="create ${G} -> ${st} $(head -c 160 "$WORK/send.out"); "
st="$(send POST /api/v1/repositories "{\"key\":\"${GV}\",\"name\":\"${GV}\",\"format\":\"generic\",\"repo_type\":\"local\",\"versioning_enabled\":true}")"
ok2xx "$st" || err+="create ${GV} -> ${st} $(head -c 160 "$WORK/send.out"); "
for i in $(seq 1 "$RACERS"); do mkbody "$WORK/body$i"; done
if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass

# =============================================================================
# FIX: concurrent PUTs to one free path
# =============================================================================
begin_test "FIX #4832: ${RACERS} concurrent PUTs of distinct bodies to one path: exactly one 201, the rest 409 with the documented body, the stored bytes are the winner's"
for i in $(seq 1 "$RACERS"); do
  ( put "$G" race/blob.bin "$WORK/body$i" "$WORK/race$i.out" > "$WORK/race$i.code" ) &
done
wait
created=0; conflicts=0; other=""; winner=""; bad_body=""
for i in $(seq 1 "$RACERS"); do
  code="$(cat "$WORK/race$i.code")"
  case "$code" in
    201) created=$((created + 1)); winner="$i" ;;
    409) conflicts=$((conflicts + 1)); is_conflict_body "$WORK/race$i.out" || bad_body+="#$i:$(head -c 120 "$WORK/race$i.out") " ;;
    *) other+="#$i:${code} " ;;
  esac
done
st="$(download "$G" race/blob.bin "$WORK/race.dl")"
stored_sha="$(sha "$WORK/race.dl")"
rows="$(live_rows "$G" race/blob.bin)"
want_sha=""; [ -n "$winner" ] && want_sha="$(sha "$WORK/body$winner")"
echo "  201: ${created}, 409: ${conflicts}, other: ${other:-none}; download HTTP ${st} sha ${stored_sha:0:12}; live rows ${rows}"
if [ "$created" -eq 1 ] && [ "$conflicts" -eq $((RACERS - 1)) ] && [ -z "$bad_body" ] \
   && [ "$st" = "200" ] && [ "$stored_sha" = "$want_sha" ] && [ "$rows" = "1|${want_sha}" ]; then
  pass
else
  fail "want 1x201 and $((RACERS - 1))x409 {code: CONFLICT, message: ${CONFLICT_MSG}}, and the download and the live row holding the 201 body; got ${created}x201, ${conflicts}x409 (other: ${other:-none}, wrong 409 bodies: ${bad_body:-none}), download ${st} ${stored_sha:0:12}, row ${rows}, winner sha ${want_sha:0:12}"
fi

# =============================================================================
# CONTROLS
# =============================================================================
begin_test "CONTROL: a sequential second PUT to an occupied path is 409 with the documented body and the first bytes stay"
mkbody "$WORK/seq1"; mkbody "$WORK/seq2"
st1="$(put "$G" seq/blob.bin "$WORK/seq1" "$WORK/seq1.out")"
st2="$(put "$G" seq/blob.bin "$WORK/seq2" "$WORK/seq2.out")"
dl="$(download "$G" seq/blob.bin "$WORK/seq.dl")"
if [ "$st1" = "201" ] && [ "$st2" = "409" ] && is_conflict_body "$WORK/seq2.out" \
   && [ "$dl" = "200" ] && [ "$(sha "$WORK/seq.dl")" = "$(sha "$WORK/seq1")" ]; then
  pass
else
  fail "want 201, then 409 CONFLICT, download = first body; got ${st1}, ${st2} $(head -c 160 "$WORK/seq2.out"), download ${dl}"
fi

begin_test "CONTROL: ${RACERS} concurrent PUTs to ${RACERS} distinct paths are all 201 and each path holds its own bytes"
for i in $(seq 1 "$RACERS"); do
  ( put "$G" "spread/blob$i.bin" "$WORK/body$i" "$WORK/spread$i.out" > "$WORK/spread$i.code" ) &
done
wait
bad=""
for i in $(seq 1 "$RACERS"); do
  code="$(cat "$WORK/spread$i.code")"
  dl="$(download "$G" "spread/blob$i.bin" "$WORK/spread$i.dl")"
  if [ "$code" != "201" ] || [ "$dl" != "200" ] || [ "$(sha "$WORK/spread$i.dl")" != "$(sha "$WORK/body$i")" ]; then
    bad+="#$i:${code}/${dl} "
  fi
done
if [ -z "$bad" ]; then
  pass
else
  fail "every distinct path must be 201 and serve its own bytes; failing: ${bad}"
fi

begin_test "CONTROL: a versioning-enabled repository accepts a second PUT to one path and records two revisions"
mkbody "$WORK/v1"; mkbody "$WORK/v2"
st1="$(put "$GV" tool/tool.bin "$WORK/v1" "$WORK/v1.out")"
st2="$(put "$GV" tool/tool.bin "$WORK/v2" "$WORK/v2.out")"
dl="$(download "$GV" tool/tool.bin "$WORK/v.dl")"
vst="$(send GET "/api/v1/repositories/${GV}/versions/tool/tool.bin")"
revs="$(jq -c '[.items[].checksum_sha256] | length' "$WORK/send.out" 2>/dev/null)"
if [ "$st1" = "201" ] && [ "$st2" = "201" ] && [ "$dl" = "200" ] \
   && [ "$(sha "$WORK/v.dl")" = "$(sha "$WORK/v2")" ] && [ "$vst" = "200" ] && [ "$revs" = "2" ]; then
  pass
else
  fail "want 201, 201, download = second body, 2 revisions; got ${st1}, ${st2} $(head -c 120 "$WORK/v2.out"), download ${dl}, versions HTTP ${vst} revisions ${revs:-?}" \
    "$(head -c 300 "$WORK/send.out")"
fi

end_suite
