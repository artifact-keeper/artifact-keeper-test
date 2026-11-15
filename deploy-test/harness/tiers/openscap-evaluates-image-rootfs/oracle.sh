#!/usr/bin/env bash
# =============================================================================
# tiers/openscap-evaluates-image-rootfs/oracle.sh
#   #6000 an OpenSCAP scan evaluates the image it is recorded against, not
#         the OpenSCAP sidecar's own filesystem; what it cannot evaluate is
#         not_applicable, never a pass
# See the manifest for the fix and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIDECAR="ak-dtf${DTF_SLOT}-openscap"
# How the sidecar is expected to root oscap's probes in the unpacked tree:
# `userns` (this tier: a non-root sidecar allowed user namespaces) or `root`
# (openscap-root-mode: OPENSCAP_RUN_AS_ROOT with user namespaces blocked).
EXPECT_ISOLATION="${OSCAP_EXPECT_ISOLATION:-userns}"
SUITE_NAME="${OSCAP_SUITE_NAME:-openscap-evaluates-image-rootfs}"
SCAN_WAIT=300
R_SHADOW="xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow"
R_GID0="xccdf_org.ssgproject.content_rule_groups_no_zero_gid_except_root"

setup_workdir
W="$WORK_DIR"
require_cmd python3

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '\r' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

SFX="$(printf '%s' "${RUN_ID##*-}" | tr -cd '0-9' | tail -c 8)"
REPO="oscap${DTF_SLOT}-${SFX}"
GREPO="oscapg${DTF_SLOT}-${SFX}"
REG_TOKEN=""

put_blob(){ # name file digest -> 0 on success
  local name="$1" file="$2" dg="$3" loc code
  loc="$(curl -s --max-time 30 -D - -o /dev/null -X POST -H "Authorization: Bearer ${REG_TOKEN}" \
    "${BASE_URL}/v2/${REPO}/${name}/blobs/uploads/" | grep -i '^location:' | head -1 | tr -d '\r' | sed 's/^[Ll]ocation: *//')"
  [ -n "$loc" ] || return 1
  [[ "$loc" == http* ]] || loc="${BASE_URL}${loc}"
  if [[ "$loc" == *"?"* ]]; then loc="${loc}&digest=${dg}"; else loc="${loc}?digest=${dg}"; fi
  code="$(curl -s --max-time 120 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${REG_TOKEN}" \
    -H 'Content-Type: application/octet-stream' --data-binary "@${file}" "$loc")" || code=000
  [[ "$code" =~ ^20[01]$ ]]
}

# push_image <variant>: build the variant and push it; echoes the manifest
# artifact id (empty on failure).
push_image(){
  local v="$1" d="$W/img-$1" dg i code
  dg="$(python3 -I "$HERE/fixtures/mkimage.py" "$d" "$v" "${RUN_ID}-${v}" "$W/base.tar")" || return 0
  i=0
  while read -r ldg; do
    put_blob "$v" "$d/l$i" "$ldg" || return 0
    i=$((i+1))
  done < "$d/layers"
  put_blob "$v" "$d/config" "$(cat "$d/config_digest")" || return 0
  code="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${REG_TOKEN}" \
    -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$d/manifest" \
    "${BASE_URL}/v2/${REPO}/${v}/manifests/1.0")" || code=000
  [[ "$code" =~ ^20[01]$ ]] || return 0
  psqlq "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id
         WHERE r.key='${REPO}' AND a.checksum_sha256='${dg#sha256:}' AND NOT a.is_deleted ORDER BY a.created_at DESC LIMIT 1"
}
trigger(){ # artifact_id -> HTTP code
  curl -s --max-time 30 -o "$W/trig.out" -w '%{http_code}' -X POST "${BASE_URL}/api/v1/security/scan" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"artifact_id\":\"$1\",\"bypass_dedup\":true}" || echo 000
}
# oscap_row <artifact_id>: "status|findings|error" of the latest openscap scan
oscap_row(){
  psqlq "SELECT status||'|'||findings_count||'|'||COALESCE(left(regexp_replace(error_message, '\s+', ' ', 'g'),240),'')
         FROM scan_results WHERE artifact_id='$1' AND scan_type='openscap' ORDER BY created_at DESC LIMIT 1"
}
# oscap_rules <artifact_id>: the rule ids of the latest openscap scan's findings
oscap_rules(){
  psqlq "SELECT f.affected_component FROM scan_findings f
         WHERE f.scan_result_id = (SELECT id FROM scan_results WHERE artifact_id='$1' AND scan_type='openscap'
                                   ORDER BY created_at DESC LIMIT 1)
         ORDER BY 1"
}
wait_settled(){ # artifact_id timeout
  local t=0 n p
  while [ "$t" -lt "$2" ]; do
    n="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='openscap'")"
    p="$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='$1' AND scan_type='openscap' AND status IN ('pending','running')")"
    [ "${n:-0}" -ge 1 ] 2>/dev/null && [ "${p:-1}" = "0" ] && return 0
    sleep 2; t=$((t+2))
  done
  return 1
}
scan_now(){ # artifact_id -> prints the row after the scan settles
  local c
  c="$(trigger "${1:-none}")"
  [ "$c" = "200" ] || note "trigger ${1:-none} -> ${c} $(head -c 200 "$W/trig.out")"
  wait_settled "${1:-none}" "$SCAN_WAIT" || note "openscap scan of ${1:-none} did not settle in ${SCAN_WAIT}s"
}
has_rule(){ grep -qx "$2" <<<"$1"; }

begin_suite "$SUITE_NAME"
auth_admin

# =============================================================================
begin_test "setup: OpenSCAP registered, docker and generic repositories, registry token, base RHEL 9 export"
reset_case
enabled="$(curl -s --max-time 10 -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/api/v1/system/config" | jqr '.scanners.openscap_enabled')"
[ "$enabled" = "true" ] || fail_g "system/config scanners.openscap_enabled=${enabled:-none}, expected true (OPENSCAP_URL wired by scanners.openscap)"
create_repo "$REPO" docker local || fail_g "create docker repository ${REPO}"
create_repo "$GREPO" generic local || fail_g "create generic repository ${GREPO}"
REG_TOKEN="$(curl -s --max-time 30 -u "${ADMIN_USER:-admin}:${ADMIN_PASS}" "${BASE_URL}/v2/token" | jqr '.token // .access_token // empty')"
[ -n "$REG_TOKEN" ] || fail_g "no registry token from /v2/token"
# The base layer is the sidecar's own /etc and rpmdb (a UBI 9 system), taken
# from the running container so the tier needs no registry pull.
docker export "$SIDECAR" > "$W/base.tar" 2>/dev/null || fail_g "docker export ${SIDECAR} failed"
[ -s "$W/base.tar" ] || fail_g "empty export of ${SIDECAR}"
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || end_suite

A_CLEAN="$(push_image clean)"
A_BAD="$(push_image noncompliant)"
A_DEB="$(push_image debian)"

# =============================================================================
begin_test "CONTROL: three images push; the clean RHEL 9 image gets a terminal OpenSCAP row without the two rules the noncompliant image breaks"
reset_case
note "artifacts clean=${A_CLEAN:-none} noncompliant=${A_BAD:-none} debian=${A_DEB:-none}"
[ -n "$A_CLEAN" ] || fail_g "clean image push failed"
[ -n "$A_BAD" ] || fail_g "noncompliant image push failed"
[ -n "$A_DEB" ] || fail_g "debian image push failed"
scan_now "$A_CLEAN"
ROW_CLEAN="$(oscap_row "${A_CLEAN:-none}")"
RULES_CLEAN="$(oscap_rules "${A_CLEAN:-none}")"
note "clean: status|findings|error = ${ROW_CLEAN:-none}"
note "clean rules: $(echo "$RULES_CLEAN" | sed 's/.*content_rule_//' | tr '\n' ' ')"
case "${ROW_CLEAN%%|*}" in
  completed|failed|not_applicable) ;;
  *) fail_g "no terminal openscap row for the clean image (${ROW_CLEAN:-none})" ;;
esac
has_rule "$RULES_CLEAN" "$R_SHADOW" && fail_g "clean image reported ${R_SHADOW#*content_rule_}, but its /etc/shadow is 0000"
has_rule "$RULES_CLEAN" "$R_GID0" && fail_g "clean image reported ${R_GID0#*content_rule_}, but only root has GID 0"
finish_case "OpenSCAP did not scan the clean image"

# =============================================================================
begin_test "FIX #6000: the noncompliant image's findings name its own /etc/shadow mode and GID-0 group"
reset_case
scan_now "$A_BAD"
row="$(oscap_row "${A_BAD:-none}")"
rules="$(oscap_rules "${A_BAD:-none}")"
note "noncompliant: status|findings|error = ${row:-none}"
note "noncompliant rules: $(echo "$rules" | sed 's/.*content_rule_//' | tr '\n' ' ')"
[ "${ROW_CLEAN%%|*}" = "completed" ] || fail_g "clean image openscap row '${ROW_CLEAN:-none}', expected completed"
[ "${row%%|*}" = "completed" ] || fail_g "noncompliant image openscap row '${row:-none}', expected completed"
has_rule "$rules" "$R_SHADOW" || fail_g "no ${R_SHADOW#*content_rule_} finding: the image's /etc/shadow is 0644 (pre-fix: the sidecar's own /etc was evaluated)"
has_rule "$rules" "$R_GID0" || fail_g "no ${R_GID0#*content_rule_} finding: the image's /etc/group has dtfroot:x:0 (pre-fix: the sidecar's own /etc was evaluated)"
[ -n "$rules" ] && [ "$rules" = "$RULES_CLEAN" ] && fail_g "the noncompliant and clean images have identical findings: the scan does not depend on the image"
finish_case "OpenSCAP findings do not describe the image"

# =============================================================================
begin_test "FIX #6000: an image of an OS no shipped datastream describes is not_applicable, not a pass"
reset_case
scan_now "$A_DEB"
row="$(oscap_row "${A_DEB:-none}")"
note "debian: status|findings|error = ${row:-none}"
[ "${row%%|*}" = "not_applicable" ] || fail_g "debian image openscap row '${row:-none}', expected not_applicable (pre-fix: completed with the sidecar's findings)"
echo "$row" | grep -qi "debian" || fail_g "the not_applicable reason does not name the image's OS: '${row:-none}'"
finish_case "OpenSCAP graded an image it cannot evaluate"

# =============================================================================
begin_test "FIX #6000: an RPM package is not_applicable (a package is not a root filesystem)"
reset_case
printf '\xed\xab\xee\xdb\x03\x00dtf-%s' "$RUN_ID" > "$W/hello.rpm"
code="$(curl -s --max-time 30 -o "$W/up.out" -w '%{http_code}' -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/x-rpm' --data-binary "@$W/hello.rpm" \
  "${BASE_URL}/api/v1/repositories/${GREPO}/artifacts/pkgs/hello-1.0-1.x86_64.rpm")" || code=000
A_RPM="$(psqlq "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id
                WHERE r.key='${GREPO}' AND a.path LIKE '%hello-1.0-1.x86_64.rpm' AND NOT a.is_deleted
                ORDER BY a.created_at DESC LIMIT 1")"
note "upload -> ${code}; artifact ${A_RPM:-none}"
[ -n "$A_RPM" ] || fail_g "RPM upload failed (${code}) $(head -c 200 "$W/up.out")"
scan_now "$A_RPM"
row="$(oscap_row "${A_RPM:-none}")"
note "rpm: status|findings|error = ${row:-none}"
[ "${row%%|*}" = "not_applicable" ] || fail_g "RPM openscap row '${row:-none}', expected not_applicable (pre-fix: completed with the sidecar's findings)"
finish_case "OpenSCAP graded an RPM package"

# openscap-root-mode sources this oracle with OSCAP_SOURCED=1 and asserts
# the isolation case itself, so its own FIX case is in its own tier dir.
[ -n "${OSCAP_SOURCED:-}" ] && return 0

# =============================================================================
begin_test "FIX #6000: the sidecar evaluated the images with isolation=${EXPECT_ISOLATION}"
reset_case
health="$(docker exec "$SIDECAR" python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8091/health').read().decode())" 2>/dev/null || true)"
n="$(jqr ".evaluations.${EXPECT_ISOLATION} // 0" <<<"$health")"
note "sidecar /health evaluations: $(jqr '.evaluations // "none"' <<<"$health" | tr -d '\n ') run_as_root=$(jqr '.run_as_root' <<<"$health")"
[ "${n:-0}" -ge 2 ] 2>/dev/null || fail_g "expected at least two scans evaluated with isolation=${EXPECT_ISOLATION} (the two RHEL images); the pre-fix wrapper never enters the image and reports no evaluations"
finish_case "the sidecar did not evaluate the images the expected way"

end_suite
