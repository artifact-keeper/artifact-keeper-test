#!/usr/bin/env bash
# =============================================================================
# tiers/generic-conditional-put/oracle.sh: conditional generic PUTs
#   (If-Match / If-None-Match) have one winner and 412 for the rest
#   (artifact-keeper#4186)
# =============================================================================
# run.sh has stood up `storage.filesystem` and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the
# feature.
#
# Topology (keys suffixed per run):
#   GC   generic hosted
#   GCV  generic hosted, versioning_enabled=true
#
# The FIX cases are RED on 1.11.5 and GREEN on 1.12.0. The malformed-header
# CONTROL is 400 on 1.12.0 (409 on 1.11.5, where the header is ignored).
# Split out of generic-concurrent-put-contract (#4832), which keeps gating
# 1.11.x.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SUF="${RUN_ID##*-}$$"
GC="gcp-c-${SUF}"; GCV="gcp-cv-${SUF}"
RACERS=16

WORK="$(mktemp -d -t dtf-gcp-cond-XXXXXX)"
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
put_cond() {  # put_cond KEY PATH FILE OUT HEADER -> HTTP status, body in OUT (#4186)
  curl -s --max-time 120 -o "$4" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/octet-stream' \
    -H "$5" --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null || echo 000
}
is_precondition_body() {
  jq -e '.code == "PRECONDITION_FAILED"' "$1" >/dev/null 2>&1
}
download() {  # download KEY PATH OUT -> HTTP status
  curl -s --max-time 60 -o "$3" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/$1/download/$2" 2>/dev/null || echo 000
}
sha() { sha256sum "$1" | cut -d' ' -f1; }
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
live_rows() {  # live_rows KEY PATH -> "<count>|<checksum>"
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) || '|' || coalesce(max(a.checksum_sha256), '') FROM artifacts a \
     JOIN repositories r ON r.id = a.repository_id \
     WHERE r.key = '$1' AND a.path = '$2' AND NOT a.is_deleted" 2>/dev/null | tr -d '[:space:]'
}
mkbody() { head -c 65536 /dev/urandom > "$1"; }

begin_suite "generic-conditional-put (#4186)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup #4186: a generic hosted repository and a versioning-enabled one for conditional PUTs, ${RACERS} distinct 64 KiB bodies"
auth_admin
err=""
st="$(send POST /api/v1/repositories "{\"key\":\"${GC}\",\"name\":\"${GC}\",\"format\":\"generic\",\"repo_type\":\"local\"}")"
ok2xx "$st" || err+="create ${GC} -> ${st} $(head -c 160 "$WORK/send.out"); "
st="$(send POST /api/v1/repositories "{\"key\":\"${GCV}\",\"name\":\"${GCV}\",\"format\":\"generic\",\"repo_type\":\"local\",\"versioning_enabled\":true}")"
ok2xx "$st" || err+="create ${GCV} -> ${st} $(head -c 160 "$WORK/send.out"); "
for i in $(seq 1 "$RACERS"); do mkbody "$WORK/body$i"; done
mkbody "$WORK/base"; mkbody "$WORK/seq1"; mkbody "$WORK/seq2"
st="$(put "$GC" index.yaml "$WORK/base" "$WORK/base.out")"
[ "$st" = "201" ] || err+="seed index.yaml -> ${st}; "
st="$(put "$GCV" index.yaml "$WORK/base" "$WORK/basev.out")"
[ "$st" = "201" ] || err+="seed versioned index.yaml -> ${st}; "
if [ -n "$err" ]; then
  infra_fail "conditional setup did not complete" "$err"
  end_suite
fi
pass

# =============================================================================
# FIX: ETag and conditional PUTs
# =============================================================================
begin_test "FIX #4186: the 201 and the download carry ETag \"<sha256>\""
put_etag="$(curl -s --max-time 60 -o /dev/null -D - -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/body1" \
  "${BASE_URL}/api/v1/repositories/${GC}/artifacts/etag/one.bin" 2>/dev/null \
  | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"
dl_etag="$(curl -s --max-time 60 -o /dev/null -D - -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${GC}/download/index.yaml" 2>/dev/null \
  | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"
want_put="\"$(sha "$WORK/body1")\""; want_dl="\"$(sha "$WORK/base")\""
if [ "$put_etag" = "$want_put" ] && [ "$dl_etag" = "$want_dl" ]; then
  pass
else
  fail "want PUT ETag ${want_put:0:14}... and download ETag ${want_dl:0:14}...; got PUT '${put_etag}', download '${dl_etag}'"
fi

begin_test "FIX #4186: ${RACERS} concurrent PUTs with If-Match on the current ETag: exactly one 201, the rest 412 PRECONDITION_FAILED, the stored bytes are the winner's"
etag="\"$(sha "$WORK/base")\""
for i in $(seq 1 "$RACERS"); do
  ( put_cond "$GC" index.yaml "$WORK/body$i" "$WORK/im$i.out" "If-Match: ${etag}" > "$WORK/im$i.code" ) &
done
wait
created=0; refused=0; other=""; winner=""; bad_body=""
for i in $(seq 1 "$RACERS"); do
  code="$(cat "$WORK/im$i.code")"
  case "$code" in
    201) created=$((created + 1)); winner="$i" ;;
    412) refused=$((refused + 1)); is_precondition_body "$WORK/im$i.out" || bad_body+="#$i:$(head -c 120 "$WORK/im$i.out") " ;;
    *) other+="#$i:${code} " ;;
  esac
done
st="$(download "$GC" index.yaml "$WORK/im.dl")"
stored_sha="$(sha "$WORK/im.dl")"
want_sha=""; [ -n "$winner" ] && want_sha="$(sha "$WORK/body$winner")"
rows="$(live_rows "$GC" index.yaml)"
echo "  201: ${created}, 412: ${refused}, other: ${other:-none}; download HTTP ${st} sha ${stored_sha:0:12}; live rows ${rows}"
if [ "$created" -eq 1 ] && [ "$refused" -eq $((RACERS - 1)) ] && [ -z "$bad_body" ] \
   && [ "$st" = "200" ] && [ "$stored_sha" = "$want_sha" ] && [ "$rows" = "1|${want_sha}" ]; then
  pass
else
  fail "want 1x201 and $((RACERS - 1))x412 {code: PRECONDITION_FAILED} with the download and live row holding the 201 body; got ${created}x201, ${refused}x412 (other: ${other:-none}, wrong 412 bodies: ${bad_body:-none}), download ${st} ${stored_sha:0:12}, row ${rows}"
fi

begin_test "FIX #4186: a stale If-Match is 412 and changes nothing"
before="$(live_rows "$GC" index.yaml)"
st="$(put_cond "$GC" index.yaml "$WORK/seq1" "$WORK/stale.out" "If-Match: ${etag}")"
after="$(live_rows "$GC" index.yaml)"
if [ "$st" = "412" ] && is_precondition_body "$WORK/stale.out" && [ "$before" = "$after" ]; then
  pass
else
  fail "want 412 PRECONDITION_FAILED and the row unchanged; got ${st} $(head -c 160 "$WORK/stale.out"), row ${before} -> ${after}"
fi

begin_test "FIX #4186: ${RACERS} concurrent PUTs with If-None-Match: * to one free path: exactly one 201, the rest 412"
for i in $(seq 1 "$RACERS"); do
  ( put_cond "$GC" lock/lock.json "$WORK/body$i" "$WORK/inm$i.out" "If-None-Match: *" > "$WORK/inm$i.code" ) &
done
wait
created=0; refused=0; other=""
for i in $(seq 1 "$RACERS"); do
  case "$(cat "$WORK/inm$i.code")" in
    201) created=$((created + 1)) ;;
    412) refused=$((refused + 1)) ;;
    *) other+="#$i:$(cat "$WORK/inm$i.code") " ;;
  esac
done
echo "  201: ${created}, 412: ${refused}, other: ${other:-none}"
if [ "$created" -eq 1 ] && [ "$refused" -eq $((RACERS - 1)) ]; then
  pass
else
  fail "want 1x201 and $((RACERS - 1))x412; got ${created}x201, ${refused}x412, other: ${other:-none}"
fi

begin_test "FIX #4186: on a versioning-enabled repository, ${RACERS} If-Match racers append exactly one revision"
for i in $(seq 1 "$RACERS"); do
  ( put_cond "$GCV" index.yaml "$WORK/body$i" "$WORK/vm$i.out" "If-Match: ${etag}" > "$WORK/vm$i.code" ) &
done
wait
created=0; refused=0; other=""
for i in $(seq 1 "$RACERS"); do
  case "$(cat "$WORK/vm$i.code")" in
    201) created=$((created + 1)) ;;
    412) refused=$((refused + 1)) ;;
    *) other+="#$i:$(cat "$WORK/vm$i.code") " ;;
  esac
done
vst="$(send GET "/api/v1/repositories/${GCV}/versions/index.yaml")"
revs="$(jq -c '[.items[]] | length' "$WORK/send.out" 2>/dev/null)"
echo "  201: ${created}, 412: ${refused}, other: ${other:-none}; revisions ${revs:-?}"
if [ "$created" -eq 1 ] && [ "$refused" -eq $((RACERS - 1)) ] && [ "$vst" = "200" ] && [ "$revs" = "2" ]; then
  pass
else
  fail "want 1x201, $((RACERS - 1))x412 and 2 revisions; got ${created}x201, ${refused}x412 (other: ${other:-none}), versions HTTP ${vst} revisions ${revs:-?}"
fi

# =============================================================================
# CONTROL
# =============================================================================
begin_test "CONTROL #4186: a malformed If-Match is 400, not ignored"
st="$(put_cond "$GC" index.yaml "$WORK/seq2" "$WORK/bad.out" "If-Match: not-a-quoted-tag")"
if [ "$st" = "400" ]; then pass; else fail "want 400; got ${st} $(head -c 160 "$WORK/bad.out")"; fi

end_suite
