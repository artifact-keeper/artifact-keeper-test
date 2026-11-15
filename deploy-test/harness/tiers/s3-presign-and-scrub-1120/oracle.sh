#!/usr/bin/env bash
# =============================================================================
# tiers/s3-presign-and-scrub-1120/oracle.sh
#   #5015 a Terraform Remote's mirror archive download redirects to a
#         presigned URL on a fresh cache hit
#   #4985 storage scrub accounting: unknown-key audit, repair-donor reads in
#         bytes_read, findings of hard-deleted rows pruned
#   #5168 the scrub byte budget is checked between repair donors
#   #5078 reindex-storage / backfill-debian audit a `started` row before the
#         work and a completion row with the counts, tied by run_id; an
#         unknown key is audited
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# S3_PORT, TRIVY_PORT (the mock's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DB_CONTAINER:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"; : "${S3_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"         # the mock, as the backend reaches it
MINIO_CTR="ak-dtf${DTF_SLOT}-minio"
MC_IMAGE="${SPS_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
MC_CTR="l2-s${DTF_SLOT}-mc"               # transient mc client, removed by name
BUCKET="ak-artifacts"
N=$((256 * 1024))                         # scrub object size (bytes)

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# mcx <script>: run an mc command in a transient client on MinIO's network.
mcx(){
  docker rm -f "$MC_CTR" >/dev/null 2>&1
  docker run --rm -i --name "$MC_CTR" --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}
add_exit_handler 'docker rm -f "'"$MC_CTR"'" >/dev/null 2>&1'
obj_put(){ mcx "mc pipe 'local/${BUCKET}/$1' >/dev/null" < "$2"; }   # <key> <file>
obj_sha(){ mcx "mc cat 'local/${BUCKET}/$1'" 2>/dev/null | sha256sum | awk '{print $1}'; }
# corrupt <key> <original>: rewrite the stored object with one byte flipped
# (same length), and confirm MinIO now holds different bytes.
corrupt(){
  local bad="$W/bad.bin"
  cp "$2" "$bad"
  printf '\377' | dd of="$bad" bs=1 seek=1000 conv=notrunc 2>/dev/null
  cmp -s "$bad" "$2" && printf '\000' | dd of="$bad" bs=1 seek=1000 conv=notrunc 2>/dev/null
  obj_put "$1" "$bad" && [ "$(obj_sha "$1")" = "$(sha_of "$bad")" ]
}

api(){ # <METHOD> <path> [json] -> body on stdout, code in $W/code
  local d="${3:-}"
  if [ -n "$d" ]; then
    curl -s --max-time 170 -o "$W/api.out" -w '%{http_code}' -X "$1" "$BASE$2" -H "$AH" \
      -H 'Content-Type: application/json' -d "$d" > "$W/code" || true
  else
    curl -s --max-time 170 -o "$W/api.out" -w '%{http_code}' -X "$1" "$BASE$2" -H "$AH" > "$W/code" || true
  fi
  cat "$W/api.out"
}
code(){ cat "$W/code" 2>/dev/null; }
mk(){ # <key> <format> [type] [upstream] -> repository id
  api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "${3:-local}" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:true} + (if $u == "" then {} else {upstream_url:$u} end)')" \
    | jqr '.id // empty'
}
put_generic(){ curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$1/artifacts/$2" -H "$AH" --data-binary "@$3" || true; }
put_maven(){ curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$1/$2" -H "$AH" --data-binary "@$3" || true; }
art(){ # <repo-id> <path> <column>
  psql_q "SELECT $3 FROM artifacts WHERE repository_id='$1' AND path='$2' AND NOT is_deleted LIMIT 1"
}
scrub(){ api POST /api/v1/admin/storage-scrub "$1"; }
findings_for(){ # <object-id> -> number of findings listed for it
  api GET "/api/v1/admin/storage-scrub/findings?limit=1000" \
    | jq -r --arg id "$1" '[(if type=="array" then . else (.items // .findings // []) end)[] | select(.object_id==$id)] | length' 2>/dev/null
}
finding_detail(){ # <object-id>
  api GET "/api/v1/admin/storage-scrub/findings?limit=1000" \
    | jq -r --arg id "$1" '[(if type=="array" then . else (.items // .findings // []) end)[] | select(.object_id==$id)][0] | "\(.status) \(.detail)"' 2>/dev/null
}
# audit_rows <action>: the audit rows of an action, newest first, as JSON lines
audit_rows(){
  api GET "/api/v1/admin/audit?action=$1&per_page=200" | jq -c '(.items // .logs // .data // [])[]' 2>/dev/null
}

# =============================================================================
begin_suite "s3-presign-and-scrub-1120"

begin_test "setup: admin login, the mock upstream, repositories"
TOK="$(curl -s --max-time 20 -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // .token // empty')"
AH="Authorization: Bearer ${TOK}"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK}"; end_suite
fi
if ! mcx "mc ls local/${BUCKET} >/dev/null"; then infra_fail "mc client cannot reach ${MINIO_CTR}"; end_suite; fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
TF="sps-tf-${SUF}"
G1="sps-g1-${SUF}"; G2="sps-g2-${SUF}"; G3="sps-g3-${SUF}"
M1="sps-m1-${SUF}"; M2="sps-m2-${SUF}"; M3="sps-m3-${SUF}"
DEB="sps-deb-${SUF}"
SETUP_ERR=""
TF_ID="$(mk "$TF" terraform remote "${UP}/")"; [ -n "$TF_ID" ] || SETUP_ERR="${SETUP_ERR} ${TF}:$(code)"
for k in G1 G2 G3; do id="$(mk "${!k}" generic)"; [ -n "$id" ] || SETUP_ERR="${SETUP_ERR} ${!k}"; printf -v "${k}_ID" '%s' "$id"; done
for k in M1 M2 M3; do id="$(mk "${!k}" maven)"; [ -n "$id" ] || SETUP_ERR="${SETUP_ERR} ${!k}"; printf -v "${k}_ID" '%s' "$id"; done
DEB_ID="$(mk "$DEB" debian)"; [ -n "$DEB_ID" ] || SETUP_ERR="${SETUP_ERR} ${DEB}"
if [ -n "$SETUP_ERR" ]; then infra_fail "repository create failed:${SETUP_ERR} ($(head -c 300 "$W/api.out"))"; end_suite; fi
pass "repositories created; mock at ${UP}"

# -----------------------------------------------------------------------------
# #5015: a provider archive behind a Provider Registry upstream (the mock).
# The Remote reads `download_url` from /v1/providers/.../download/<os>/<arch>
# and fetches the archive there.
NS="dtfacme"; TYPE="null${SUF//x/}"; VER="1.0.0"
python3 -I - "$W/provider.zip" <<'PY'
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_STORED) as z:
    z.writestr("terraform-provider-null_v1.0.0", os.urandom(2 * 1024 * 1024))
PY
ZIP="terraform-provider-${TYPE}_${VER}_linux_amd64.zip"
ZIP_SHA="$(sha_of "$W/provider.zip")"
mput(){ curl -s --max-time 10 -X PUT --data-binary @"$2" "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" >/dev/null; }
mput "/dl/${ZIP}" "$W/provider.zip" application/zip
jq -nc --arg u "${UP}/dl/${ZIP}" --arg f "$ZIP" --arg s "$ZIP_SHA" \
  '{protocols:["5.0"],os:"linux",arch:"amd64",filename:$f,download_url:$u,shasum:$s}' > "$W/dl.json"
mput "/v1/providers/${NS}/${TYPE}/${VER}/download/linux/amd64" "$W/dl.json" application/json
jq -nc --arg v "$VER" '{versions:[{version:$v,protocols:["5.0"],platforms:[{os:"linux",arch:"amd64"}]}]}' > "$W/versions.json"
mput "/v1/providers/${NS}/${TYPE}/versions" "$W/versions.json" application/json
MIRROR="$BASE/terraform/${TF}/registry.terraform.io/${NS}/${TYPE}/${VER}/download/linux/amd64"
mock_gets(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get // empty'; }

begin_test "CONTROL #5015: the first (cold) mirror archive download from the Terraform Remote is 200 with the exact archive"
reset_case
c="$(curl -s --max-time 60 -o "$W/a1.zip" -w '%{http_code}' -H "$AH" "$MIRROR" || true)"
note "cold GET -> ${c}, $(stat -c %s "$W/a1.zip" 2>/dev/null) bytes; upstream archive GETs $(mock_gets "/dl/${ZIP}")"
[ "$c" = "200" ] && [ "$(sha_of "$W/a1.zip")" = "$ZIP_SHA" ] || fail_g "cold mirror download answered ${c}, bytes $( [ "$(sha_of "$W/a1.zip")" = "$ZIP_SHA" ] && echo match || echo differ)"
finish_case "the cold mirror download failed"

begin_test "FIX #5015: a fresh-cache mirror archive download answers 302 to a presigned object-store URL whose bytes are the archive"
reset_case
# The cache publish of the first download completes asynchronously: poll.
loc=""; c=""
for i in $(seq 1 20); do
  : > "$W/h2"
  c="$(curl -s --max-time 60 -D "$W/h2" -o "$W/a2.zip" -w '%{http_code}' -H "$AH" "$MIRROR" || true)"
  [ "$c" = "302" ] || [ "$c" = "307" ] && break
  sleep 0.5
done
loc="$(tr -d '\r' < "$W/h2" | awk 'tolower($1)=="location:"{print $2}' | head -n1)"
xas="$(tr -d '\r' < "$W/h2" | awk 'tolower($1)=="x-artifact-storage:"{print $2}' | head -n1)"
note "warm GET -> ${c} (after ${i} tries) X-Artifact-Storage '${xas}' Location '${loc%%\?*}'"
if [ "$c" != "302" ] && [ "$c" != "307" ]; then
  fail_g "a fresh cache hit answered ${c} with $(stat -c %s "$W/a2.zip" 2>/dev/null) body bytes streamed through the backend, expected a redirect to the object store"
else
  case "$loc" in "http://127.0.0.1:${S3_PORT}/"*) ;; *) fail_g "redirect Location '${loc%%\?*}' is not the public S3 endpoint 127.0.0.1:${S3_PORT}" ;; esac
  c3="$(curl -s --max-time 60 -o "$W/a3.zip" -w '%{http_code}' "$loc" || true)"
  note "presigned GET -> ${c3}"
  [ "$c3" = "200" ] && [ "$(sha_of "$W/a3.zip")" = "$ZIP_SHA" ] || fail_g "the presigned URL answered ${c3}, bytes not the archive"
fi
g="$(mock_gets "/dl/${ZIP}")"
note "upstream archive GETs after the warm download: ${g}"
[ "$g" = "1" ] || fail_g "the upstream archive was fetched ${g} times, expected 1 (the warm GET must be a cache hit)"
finish_case "fresh-cache mirror archives are streamed instead of redirected"

# -----------------------------------------------------------------------------
begin_test "FIX #4985: a scrub requested for an unknown repository key is 404 and is audited (started + failed rows with the key)"
reset_case
NOPE="sps-nope-${SUF}"
scrub "$(jq -nc --arg r "$NOPE" '{repair:false,repository:$r}')" >/dev/null
c="$(code)"
note "scrub {repository:${NOPE}} -> ${c}"
[ "$c" = "404" ] || fail_g "unknown repository key answered ${c}, expected 404"
rows="$(audit_rows STORAGE_SCRUB_RUN | jq -c --arg r "$NOPE" 'select((.details.params.repository // .details.repository // "") == $r)' 2>/dev/null)"
phases="$(echo "$rows" | jq -r '.details.phase // "none"' 2>/dev/null | sort | tr '\n' ' ')"
note "STORAGE_SCRUB_RUN rows naming ${NOPE}: phases [ ${phases}]"
echo "$rows" | jq -e 'select(.details.phase=="started")' >/dev/null 2>&1 || fail_g "no 'started' audit row for the refused scrub of ${NOPE}"
echo "$rows" | jq -e 'select(.details.phase=="failed")' >/dev/null 2>&1 || fail_g "no 'failed' audit row for the refused scrub of ${NOPE}"
finish_case "a scrub of an unknown repository key is not audited"

# -----------------------------------------------------------------------------
# Scrub fixtures: random objects of N bytes. On S3 a generic artifact lives at
# its content-addressed key; the same bytes uploaded to a Maven repository are
# stored under maven/<repo_id>/<path>, a separate copy the repair can use.
head -c "$N" /dev/urandom > "$W/s1.bin"
head -c "$N" /dev/urandom > "$W/s2.bin"
head -c "$N" /dev/urandom > "$W/s3.bin"
SETUP_ERR=""
[ "$(put_generic "$G1" data/s1.bin "$W/s1.bin")" = "201" ] || SETUP_ERR="${SETUP_ERR} g1"
[ "$(put_maven "$M1" com/dtf/s1/1.0/s1-1.0.jar "$W/s1.bin")" = "201" ] || SETUP_ERR="${SETUP_ERR} m1"
[ "$(put_generic "$G2" data/s2.bin "$W/s2.bin")" = "201" ] || SETUP_ERR="${SETUP_ERR} g2"
[ "$(put_generic "$G3" data/s3.bin "$W/s3.bin")" = "201" ] || SETUP_ERR="${SETUP_ERR} g3"
[ "$(put_maven "$M2" com/dtf/s3/1.0/s3-1.0.jar "$W/s3.bin")" = "201" ] || SETUP_ERR="${SETUP_ERR} m2"
[ "$(put_maven "$M3" com/dtf/s3/1.0/s3-1.0.jar "$W/s3.bin")" = "201" ] || SETUP_ERR="${SETUP_ERR} m3"
K1="$(art "$G1_ID" data/s1.bin storage_key)"; A1="$(art "$G1_ID" data/s1.bin id)"
K2="$(art "$G2_ID" data/s2.bin storage_key)"; A2="$(art "$G2_ID" data/s2.bin id)"
K3="$(art "$G3_ID" data/s3.bin storage_key)"; A3="$(art "$G3_ID" data/s3.bin id)"
D2K="maven/${M2_ID}/com/dtf/s3/1.0/s3-1.0.jar"; D3K="maven/${M3_ID}/com/dtf/s3/1.0/s3-1.0.jar"
for k in "$K1" "$K2" "$K3"; do [ -n "$k" ] || SETUP_ERR="${SETUP_ERR} storage_key"; done
[ "$(obj_sha "maven/${M1_ID}/com/dtf/s1/1.0/s1-1.0.jar")" = "$(sha_of "$W/s1.bin")" ] || SETUP_ERR="${SETUP_ERR} donor-key-m1"

begin_test "CONTROL: a scoped scrub (repair=false) reports a same-length corrupted object as corrupt"
reset_case
if [ -n "$SETUP_ERR" ]; then infra_fail "scrub fixtures:${SETUP_ERR}"; end_suite; fi
corrupt "$K2" "$W/s2.bin" || fail_g "could not corrupt ${K2} in MinIO"
r="$(scrub "$(jq -nc --arg r "$G2" '{repair:false,repository:$r}')")"
note "scrub ${G2} -> $(code): $(echo "$r" | jq -c '{objects_checked,bytes_read,corrupt,repaired}' 2>/dev/null)"
[ "$(code)" = "200" ] && [ "$(echo "$r" | jqr '.corrupt')" = "1" ] || fail_g "the corrupted object was not reported corrupt"
[ "$(findings_for "$A2")" = "1" ] || fail_g "the findings list does not show the corrupt object ${A2}"
finish_case "the scrub did not find a corrupted object"

begin_test "FIX #4985: a repair run counts the donor read and the verifying re-read in bytes_read (3 x ${N} bytes, not ${N})"
reset_case
corrupt "$K1" "$W/s1.bin" || fail_g "could not corrupt ${K1} in MinIO"
r="$(scrub "$(jq -nc --arg r "$G1" '{repair:true,repository:$r}')")"
br="$(echo "$r" | jqr '.bytes_read')"
note "repair scrub ${G1} -> $(code): $(echo "$r" | jq -c '{objects_checked,bytes_read,corrupt,repaired}' 2>/dev/null)"
[ "$(echo "$r" | jqr '.repaired')" = "1" ] || fail_g "the corrupt object was not repaired from the Maven copy (repaired '$(echo "$r" | jqr '.repaired')')"
[ "$(obj_sha "$K1")" = "$(sha_of "$W/s1.bin")" ] || fail_g "the stored object is not the original bytes after the repair"
[ "${br:-0}" -ge $(( 3 * N )) ] 2>/dev/null || fail_g "bytes_read ${br}, expected at least $(( 3 * N )) (target + donor + re-check): repair reads escape the byte budget"
finish_case "repair-donor reads are not counted in bytes_read"

begin_test "FIX #4985: a finding of a hard-deleted artifact row is pruned by the next scrub run"
reset_case
before="$(findings_for "$A2")"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qc "DELETE FROM artifacts WHERE id='${A2}'" >/dev/null 2>&1
gone="$(psql_q "SELECT count(*) FROM artifacts WHERE id='${A2}'")"
scrub '{"repair":false}' >/dev/null
after="$(findings_for "$A2")"
note "artifact ${A2}: findings before ${before}, row count after delete ${gone}, findings after the next run ${after} (scrub $(code))"
[ "$gone" = "0" ] || fail_g "could not hard-delete the artifact row"
[ "$after" = "0" ] || fail_g "the finding of the hard-deleted artifact is still listed after the next scrub run"
finish_case "findings of hard-deleted rows are listed forever"

begin_test "FIX #5168: with both repair donors corrupt and the byte budget spent by the target, the repair stops between donors"
reset_case
corrupt "$K3" "$W/s3.bin" || fail_g "could not corrupt ${K3}"
corrupt "$D2K" "$W/s3.bin" || fail_g "could not corrupt ${D2K}"
corrupt "$D3K" "$W/s3.bin" || fail_g "could not corrupt ${D3K}"
r="$(scrub "$(jq -nc --arg r "$G3" --argjson b "$N" '{repair:true,repository:$r,max_bytes:$b}')")"
br="$(echo "$r" | jqr '.bytes_read')"
det="$(finding_detail "$A3")"
note "repair scrub ${G3} max_bytes=${N} -> $(code): $(echo "$r" | jq -c '{objects_checked,bytes_read,corrupt,repaired}' 2>/dev/null)"
note "finding: ${det}"
[ "${br:-0}" -le $(( 2 * N )) ] 2>/dev/null || fail_g "bytes_read ${br} with max_bytes ${N}: every donor was read past the budget (expected at most target + one donor = $(( 2 * N )))"
case "$det" in *budget*) ;; *) fail_g "the finding does not say the repair stopped at the byte budget (detail '${det}')" ;; esac
finish_case "the scrub byte budget is not checked between repair donors"

# -----------------------------------------------------------------------------
begin_test "FIX #5078: reindex-storage and backfill-debian audit a started row before the work and a completed row with the counts, tied by run_id"
reset_case
api POST "/api/v1/admin/repositories/${M1}/reindex-storage" '{"dry_run":true}' >/dev/null
note "reindex-storage ${M1} -> $(code): $(head -c 200 "$W/api.out")"
api POST "/api/v1/admin/repositories/${DEB}/backfill-debian" '{"dry_run":true}' >/dev/null
note "backfill-debian ${DEB} -> $(code): $(head -c 200 "$W/api.out")"
sleep 1
for pair in "STORAGE_REINDEX_RUN:${M1}:scanned" "DEBIAN_BACKFILL_RUN:${DEB}:artifacts_scanned"; do
  IFS=: read -r act key count <<<"$pair"
  rows="$(audit_rows "$act" | jq -c --arg r "$key" 'select((.details.repository // "") == $r)' 2>/dev/null)"
  st="$(echo "$rows" | jq -c 'select(.details.phase=="started")' 2>/dev/null | head -n1)"
  co="$(echo "$rows" | jq -c 'select(.details.phase=="completed")' 2>/dev/null | head -n1)"
  note "${act} ${key}: $(echo "$rows" | grep -c . ) rows; started run_id '$(echo "$st" | jqr '.details.run_id // empty')', completed run_id '$(echo "$co" | jqr '.details.run_id // empty')' ${count}='$(echo "$co" | jqr ".details.${count} // empty")'"
  [ -n "$st" ] || fail_g "${act} ${key}: no 'started' audit row"
  [ -n "$co" ] || fail_g "${act} ${key}: no 'completed' audit row"
  if [ -n "$st" ] && [ -n "$co" ]; then
    rid="$(echo "$st" | jqr '.details.run_id // empty')"
    [ -n "$rid" ] && [ "$rid" = "$(echo "$co" | jqr '.details.run_id // empty')" ] || fail_g "${act} ${key}: started and completed rows do not share a run_id"
    [ -n "$(echo "$co" | jqr ".details.${count} // empty")" ] || fail_g "${act} ${key}: the completed row carries no '${count}' count"
  fi
done
finish_case "repair endpoints write their audit row only on return"

begin_test "FIX #5078: a reindex-storage request for an unknown repository key is 404 and is audited"
reset_case
api POST "/api/v1/admin/repositories/${NOPE}/reindex-storage" '{"dry_run":true}' >/dev/null
c="$(code)"
sleep 1
rows="$(audit_rows STORAGE_REINDEX_RUN | jq -c --arg r "$NOPE" 'select((.details.repository // "") == $r)' 2>/dev/null)"
note "reindex-storage ${NOPE} -> ${c}; audit rows naming it: phases [ $(echo "$rows" | jq -r '.details.phase // "none"' 2>/dev/null | sort | tr '\n' ' ')]"
[ "$c" = "404" ] || fail_g "unknown key answered ${c}, expected 404"
echo "$rows" | jq -e 'select(.details.phase=="started")' >/dev/null 2>&1 || fail_g "no 'started' audit row for the unknown key"
echo "$rows" | jq -e 'select(.details.phase=="failed")' >/dev/null 2>&1 || fail_g "no 'failed' audit row for the unknown key"
finish_case "a repair call for an unknown repository key is not audited"

end_suite
