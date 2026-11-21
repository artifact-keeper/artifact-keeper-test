#!/usr/bin/env bash
# =============================================================================
# tiers/generic-concurrent-put-contract/oracle.sh: concurrent generic PUTs to
#   one path have exactly one winner (artifact-keeper#4832); a stored upload
#   is never answered with an error, and an upload answered with an error
#   stored nothing (artifact-keeper#6317)
# =============================================================================
# run.sh has stood up `storage.filesystem` and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug.
#
# Topology (keys suffixed per run):
#   G    generic hosted
#   GV   generic hosted, versioning_enabled=true
#   P    pypi hosted (#6317)
#
# The #4832 FIX case is RED on 1.11.0-1.11.3 and GREEN on the fix; the #6317
# FIX cases are RED on main before artifact-keeper#6317 was fixed. Every
# CONTROL holds on both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SUF="${RUN_ID##*-}$$"
G="gcp-g-${SUF}"; GV="gcp-v-${SUF}"; P="gcp-p-${SUF}"
RACERS=16
CONFLICT_MSG="Artifact version already exists and is immutable"

WORK="$(mktemp -d -t dtf-gcp-XXXXXX)"
# #6317 fault injection (see the manifest). Each fault lives only in this
# slot's own database and is removed right after its probe; the EXIT trap
# removes any that an interrupted run left behind.
PY_MOD="dtf_gcp_${SUF}"; PY_PROJECT="${PY_MOD//_/-}"
FAULT_FN="dtf_gcp_6317_${SUF}"
psqlq() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" 2>&1
}
clear_faults() {
  psqlq "DROP TRIGGER IF EXISTS ${FAULT_FN} ON artifact_metadata; DROP FUNCTION IF EXISTS ${FAULT_FN}()" >/dev/null
  psqlq "DO \$\$ BEGIN IF to_regclass('download_statistics_dtf6317') IS NOT NULL THEN ALTER TABLE download_statistics_dtf6317 RENAME TO download_statistics; END IF; END \$\$" >/dev/null
}
trap 'clear_faults; rm -rf "$WORK"' EXIT

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

# =============================================================================
# #6317: post-commit work never turns a stored upload into an error
# =============================================================================
# Each probe injects a database fault that hits exactly one step of the
# upload. In production that step failed on a pool acquire timeout (503
# POOL_EXHAUSTED) when the pool was saturated; the fault makes the same
# failure deterministic.
begin_test "setup #6317: a pypi hosted repository and a wheel"
err=""
st="$(send POST /api/v1/repositories "{\"key\":\"${P}\",\"name\":\"${P}\",\"format\":\"pypi\",\"repo_type\":\"local\"}")"
ok2xx "$st" || err+="create ${P} -> ${st} $(head -c 160 "$WORK/send.out"); "
WHEEL="${PY_MOD}-1.0.0-py3-none-any.whl"
python3 -I - "$WORK/$WHEEL" "$PY_MOD" <<'PY' || err+="wheel fixture; "
import base64, hashlib, sys, zipfile
path, py = sys.argv[1], sys.argv[2]
di = f"{py}-1.0.0.dist-info"
files = {f"{py}/__init__.py": "",
         f"{di}/METADATA": f"Metadata-Version: 2.1\nName: {py}\nVersion: 1.0.0\nSummary: dtf 6317\n\n",
         f"{di}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
rec = []
with zipfile.ZipFile(path, "w") as z:
    for n, t in files.items():
        d = t.encode(); z.writestr(n, d)
        rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}")
    rec.append(f"{di}/RECORD,,"); z.writestr(f"{di}/RECORD", "\n".join(rec) + "\n")
PY
if [ -n "$err" ]; then
  infra_fail "setup #6317 did not complete" "$err"
  end_suite
fi
pass

pypi_upload() {  # pypi_upload OUT -> HTTP status, body in OUT
  curl -s --max-time 120 -o "$1" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/pypi/${P}/" \
    -F ':action=file_upload' -F 'protocol_version=1' -F 'metadata_version=2.1' \
    -F "name=${PY_MOD}" -F 'version=1.0.0' -F 'filetype=bdist_wheel' -F 'pyversion=py3' \
    -F "content=@$WORK/${WHEEL};filename=${WHEEL}" 2>/dev/null || echo 000
}
pypi_rows() {  # -> "<live rows>|<pypi metadata rows>"
  psqlq "SELECT count(*) || '|' || count(am.id) FROM artifacts a \
         JOIN repositories r ON r.id = a.repository_id \
         LEFT JOIN artifact_metadata am ON am.artifact_id = a.id AND am.format = 'pypi' \
         WHERE r.key = '${P}' AND a.path = '${PY_PROJECT}/1.0.0/${WHEEL}' AND NOT a.is_deleted" | tr -d '[:space:]'
}

begin_test "FIX #6317: PyPI upload whose metadata write fails: an error stores nothing, and the retry is 200 with the package indexed (not 409, not a package without metadata)"
fault="$(psqlq "CREATE FUNCTION ${FAULT_FN}() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN RAISE EXCEPTION 'dtf #6317 injected metadata write failure'; END \$\$; \
  CREATE TRIGGER ${FAULT_FN} BEFORE INSERT OR UPDATE ON artifact_metadata FOR EACH ROW \
  WHEN (NEW.metadata->>'normalized_name' = '${PY_PROJECT}') EXECUTE FUNCTION ${FAULT_FN}()")"
st1="$(pypi_upload "$WORK/py1.out")"
rows1="$(pypi_rows)"
clear_faults
st2="$(pypi_upload "$WORK/py2.out")"
rows2="$(pypi_rows)"
idx="$(curl -s --max-time 60 -o "$WORK/simple.out" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/pypi/${P}/simple/${PY_PROJECT}/" 2>/dev/null || echo 000)"
listed=no; grep -q "$WHEEL" "$WORK/simple.out" 2>/dev/null && listed=yes
echo "  with the fault: HTTP ${st1}, rows ${rows1}; retry: HTTP ${st2}, rows ${rows2}; simple index HTTP ${idx}, lists the wheel: ${listed}"
if ! printf '%s' "$fault" | grep -q 'CREATE TRIGGER'; then
  infra_fail "could not install the metadata-write fault" "$fault"
elif { ok2xx "$st1" || [ "$rows1" = "0|0" ]; } && [ "$st2" = "200" ] && [ "$rows2" = "1|1" ] \
     && [ "$idx" = "200" ] && [ "$listed" = "yes" ]; then
  pass
else
  fail "an upload answered with an error must have stored nothing, and the retry must be 200 with one live row and its pypi metadata; got HTTP ${st1} with rows ${rows1} (live|metadata), retry HTTP ${st2} $(head -c 120 "$WORK/py2.out") rows ${rows2}, simple index ${idx} listed=${listed}" \
    "first response: $(head -c 200 "$WORK/py1.out")"
fi

begin_test "FIX #6317: generic PUT whose response-only download-count read fails after the commit is still 201 with the stored bytes"
mkbody "$WORK/pc"
fault="$(psqlq "ALTER TABLE download_statistics RENAME TO download_statistics_dtf6317")"
st="$(put "$G" postcommit/blob.bin "$WORK/pc" "$WORK/pc.out")"
clear_faults
rows="$(live_rows "$G" postcommit/blob.bin)"
dl="$(download "$G" postcommit/blob.bin "$WORK/pc.dl")"
echo "  with the fault: HTTP ${st}; live rows ${rows}; download HTTP ${dl}"
if ! printf '%s' "$fault" | grep -q 'ALTER TABLE'; then
  infra_fail "could not install the download-count fault" "$fault"
elif [ "$st" = "201" ] && [ "$(jq -r '.checksum_sha256 // empty' "$WORK/pc.out" 2>/dev/null)" = "$(sha "$WORK/pc")" ] \
     && [ "$rows" = "1|$(sha "$WORK/pc")" ] && [ "$dl" = "200" ] && [ "$(sha "$WORK/pc.dl")" = "$(sha "$WORK/pc")" ]; then
  pass
else
  fail "the upload committed, so it must be answered 201 with its checksum; got HTTP ${st} $(head -c 200 "$WORK/pc.out"), live rows ${rows}, download ${dl}"
fi

begin_test "CONTROL #6317: with no fault a PyPI upload is 200 and a duplicate is still refused, and a generic PUT reports download_count 0"
mkbody "$WORK/pc2"
st="$(put "$G" postcommit/ok.bin "$WORK/pc2" "$WORK/pc2.out")"
cnt="$(jq -r '.download_count' "$WORK/pc2.out" 2>/dev/null)"
dup="$(pypi_upload "$WORK/py3.out")"
if [ "$st" = "201" ] && [ "$cnt" = "0" ] && [ "$dup" != "200" ] && ! ok2xx "$dup"; then
  pass
else
  fail "want generic 201 with download_count 0 and a non-2xx duplicate PyPI upload; got ${st} (download_count ${cnt:-?}), duplicate ${dup} $(head -c 120 "$WORK/py3.out")"
fi

end_suite
