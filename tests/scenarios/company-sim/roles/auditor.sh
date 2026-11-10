#!/usr/bin/env bash
# roles/auditor.sh - Ellen Shaw, external auditor at Halcyon Robotics.
#
# Ellen holds read on every department project through group ${HAL}-auditors
# and nothing else (README "Grants"). She inventories the instance, reads
# listings, metadata, SBOMs, scan results, promotion history and the storage
# tree, downloads one artifact per format, and checks the traces other roles
# leave during the day (firmware's SDK 1.1.0, devops' scanned image).
#
# Should NOT work: every write (native publish, REST upload, delete, PATCH,
# SBOM generation), the age-gate config, the permission table, the audit log
# and the admin settings. Each refusal is re-read as `admin` to prove nothing
# was written (ROLES.md, auditor). The audit log refusal is the headline gap:
# Artifact Keeper has no auditor role (H/admin.rs:64, 238-240).
#
# Barriers: waits `fw-sdk-1.1.0` (firmware; FAIL on timeout),
# `ops-image-pushed` (devops; SKIP on timeout, ROLES.md auditor #7) and
# `ops-image-reviewed` (security; optional, SKIP on timeout: the scan has
# then finished). Signals nothing. Timeouts: CS_BARRIER_TIMEOUT (default 600 s).
#
# Uses `admin` only to read back state (refusals wrote nothing; the denied
# admin-route calls left PERMISSION_DENIED audit rows, A:2027-2050).
# Creates nothing, so there is nothing to clean up.

source "$(dirname "$0")/../lib.sh"

cs_begin auditor
auth_admin

BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
START_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# Morning: sign in
# ---------------------------------------------------------------------------
if cs_login AUDITOR; then
  cs_record "AUDITOR signs in" PASS "JWT issued"
else
  cs_record "AUDITOR signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  cs_end
fi

ALL_REPOS=(FW_CARGO_LOCAL FW_CARGO_REMOTE FW_CARGO FW_MAVEN_LOCAL FW_MAVEN_REMOTE FW_MAVEN
           WEB_NPM_LOCAL WEB_NPM_REMOTE WEB_NPM
           DATA_PYPI_LOCAL DATA_PYPI_REMOTE DATA_PYPI DATA_CONDA_LOCAL DATA_CONDA_REMOTE DATA_CONDA
           OPS_DOCKER_LOCAL OPS_DOCKER_REMOTE OPS_DOCKER OPS_BUILDS OPS_HELM HANDBOOK)
HOSTED_REPOS=(FW_CARGO_LOCAL FW_MAVEN_LOCAL WEB_NPM_LOCAL DATA_PYPI_LOCAL DATA_CONDA_LOCAL
              OPS_DOCKER_LOCAL OPS_BUILDS OPS_HELM HANDBOOK)
repo_key() { local v="HAL_REPO_$1"; printf '%s' "${!v}"; }
repo_id()  { local v="HAL_REPO_$1_ID"; printf '%s' "${!v}"; }

MVN_PATH="${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/${HAL_SEED_MAVEN_VERSION}/${HAL_SEED_MAVEN_ARTIFACT}-${HAL_SEED_MAVEN_VERSION}.jar"
CRATE_PATH="${HAL_SEED_CRATE}/${HAL_SEED_CRATE_VERSION}/${HAL_SEED_CRATE}-${HAL_SEED_CRATE_VERSION}.crate"

# ---------------------------------------------------------------------------
# Task 1: inventory. Read on all four projects plus the internal handbook
# (README "Grants"; S/repository_service.rs:800-837).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories?per_page=100" jwt:AUDITOR
if cs_expect "auditor lists repositories" 200; then
  missing=()
  for r in "${ALL_REPOS[@]}"; do
    k=$(repo_key "$r")
    cs_json '.items[]?.key' | grep -qxF -- "$k" || missing+=("$k")
  done
  if [ ${#missing[@]} -eq 0 ]; then
    cs_record "inventory has all 21 Halcyon repositories" PASS "$(cs_json "[.items[]?.key | select(startswith(\"${HAL}-\"))] | length") ${HAL}-* repos listed"
  else
    cs_record "inventory has all 21 Halcyon repositories" FAIL "missing: ${missing[*]}" "${CS_BODY:0:600}"
  fi
fi

# Repository metadata, every repository (RS:573-648 require_visible).
meta_bad=()
for r in "${ALL_REPOS[@]}"; do
  cs_http GET "/api/v1/repositories/$(repo_key "$r")" jwt:AUDITOR
  [ "$CS_STATUS" = "200" ] && [ "$(cs_json '.key')" = "$(repo_key "$r")" ] || meta_bad+=("$(repo_key "$r")=${CS_STATUS}")
done
if [ ${#meta_bad[@]} -eq 0 ]; then
  cs_record "auditor reads metadata of all 21 repositories" PASS "HTTP 200 x21"
else
  cs_record "auditor reads metadata of all 21 repositories" FAIL "expected 200 each; got ${meta_bad[*]}"
fi

# ---------------------------------------------------------------------------
# Task 2: artifact listing of every hosted repository, and the day-0 content.
# ---------------------------------------------------------------------------
for r in "${HOSTED_REPOS[@]}"; do
  cs_http GET "/api/v1/repositories/$(repo_key "$r")/artifacts?per_page=100" jwt:AUDITOR
  cs_expect "auditor lists artifacts of $(repo_key "$r")" 200 "$(cs_json '.pagination.total // empty') artifacts"
  case "$r" in
    FW_MAVEN_LOCAL)  cs_expect_body "day-0 SDK jar listed in ${HAL_REPO_FW_MAVEN_LOCAL}" "$MVN_PATH" ;;
    FW_CARGO_LOCAL)  cs_expect_body "day-0 crate listed in ${HAL_REPO_FW_CARGO_LOCAL}" "$CRATE_PATH" ;;
    OPS_BUILDS)      cs_expect_body "day-0 firmware image listed in ${HAL_REPO_OPS_BUILDS}" "$HAL_SEED_FW_BIN" ;;
    HANDBOOK)        cs_expect_body "day-0 handbook page listed in ${HAL_REPO_HANDBOOK}" "$HAL_SEED_HANDBOOK" ;;
    WEB_NPM_LOCAL)   cs_expect_body "day-0 npm package listed in ${HAL_REPO_WEB_NPM_LOCAL}" "$HAL_SEED_NPM" ;;
    DATA_PYPI_LOCAL) cs_expect_body "day-0 pypi project listed in ${HAL_REPO_DATA_PYPI_LOCAL}" "$HAL_SEED_PYPI" ;;
  esac
done

# Seed crate id, used for the SBOM checks below.
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts?per_page=100" jwt:AUDITOR
CRATE_ID=$(cs_json ".items[]? | select(.path==\"${CRATE_PATH}\") | .id" | head -n1)

# ---------------------------------------------------------------------------
# Task 3: virtual member listing. She reads both members, so no notice header
# (VIS, #4690).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_WEB_NPM}/members" jwt:AUDITOR
if cs_expect "auditor lists members of ${HAL_REPO_WEB_NPM}" 200; then
  n=$(cs_json '[(.members // .items // [])[]?.member_repo_key] | length')
  if [ "$n" = "2" ] && cs_json '(.members // [])[]?.member_repo_key' | grep -qxF "$HAL_REPO_WEB_NPM_LOCAL" \
     && cs_json '(.members // [])[]?.member_repo_key' | grep -qxF "$HAL_REPO_WEB_NPM_REMOTE"; then
    cs_record "virtual shows both members to the auditor" PASS "local@1, remote@2"
  else
    cs_record "virtual shows both members to the auditor" FAIL "expected 2 members (local, remote), got ${n}" "${CS_BODY:0:600}"
  fi
  notice=$(cs_header X-AK-Virtual-Members-Notice)
  if [ -z "$notice" ]; then
    cs_record "no X-AK-Virtual-Members-Notice header (she reads every member, #4690)" PASS "header absent"
  else
    cs_record "no X-AK-Virtual-Members-Notice header (she reads every member, #4690)" FAIL "header present: ${notice}"
  fi
fi

# ---------------------------------------------------------------------------
# Task 4: one download per format through the virtuals (native routes,
# Basic user:password; A:2887 repo_visibility_middleware, read via project).
# ---------------------------------------------------------------------------
cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${MVN_PATH}" basic:AUDITOR
cs_expect "auditor downloads day-0 SDK jar through ${HAL_REPO_FW_MAVEN}" 200

cs_http GET "/cargo/${HAL_REPO_FW_CARGO}/api/v1/crates/${HAL_SEED_CRATE}/${HAL_SEED_CRATE_VERSION}/download" basic:AUDITOR
cs_expect "auditor downloads day-0 crate through ${HAL_REPO_FW_CARGO}" 200

cs_http GET "/npm/${HAL_REPO_WEB_NPM}/${HAL_SEED_NPM}/-/${HAL_SEED_NPM}-${HAL_SEED_NPM_VERSION}.tgz" basic:AUDITOR
cs_expect "auditor downloads day-0 npm tarball through ${HAL_REPO_WEB_NPM}" 200

cs_http GET "/pypi/${HAL_REPO_DATA_PYPI}/simple/${HAL_SEED_PYPI}/" basic:AUDITOR
if cs_expect "auditor reads the PEP 503 page of ${HAL_SEED_PYPI} through ${HAL_REPO_DATA_PYPI}" 200; then
  href=$(printf '%s' "$CS_BODY" | grep -o 'href="[^"]*"' | sed -e 's/^href="//' -e 's/"$//' -e 's/#.*$//' \
         | grep -F "${HAL_SEED_PYPI_VERSION}" | head -n1 || true)
  if [ -z "$href" ]; then
    cs_record "auditor downloads day-0 sdist through ${HAL_REPO_DATA_PYPI}" FAIL "no ${HAL_SEED_PYPI_VERSION} link on the simple page" "${CS_BODY:0:600}"
  else
    case "$href" in
      http://*|https://*) url="$href" ;;
      /*) url="${BASE_URL}${href}" ;;
      *) url="${BASE_URL}/pypi/${HAL_REPO_DATA_PYPI}/simple/${HAL_SEED_PYPI}/${href}" ;;
    esac
    cs_http GET "$url" basic:AUDITOR -L
    cs_expect "auditor downloads day-0 sdist through ${HAL_REPO_DATA_PYPI}" 200 "${href}"
  fi
fi

# ---------------------------------------------------------------------------
# Task 5: the firmware image's bytes match the founder's sha256.
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/download/${HAL_SEED_FW_BIN}" jwt:AUDITOR
if cs_expect "auditor downloads ${HAL_SEED_FW_BIN}" 200; then
  got=$(sha256sum "$CS_BODY_FILE" | cut -d' ' -f1)
  if [ "$got" = "$HAL_SEED_FW_BIN_SHA256" ]; then
    cs_record "firmware image sha256 matches HAL_SEED_FW_BIN_SHA256" PASS "${got}"
  else
    cs_record "firmware image sha256 matches HAL_SEED_FW_BIN_SHA256" FAIL "expected ${HAL_SEED_FW_BIN_SHA256}, got ${got} ($(stat -c %s "$CS_BODY_FILE") bytes)"
  fi
fi

# ---------------------------------------------------------------------------
# Task 6: repository security config (H/security.rs:2540-2548 require_visible).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_OPS_DOCKER_LOCAL}/security" jwt:AUDITOR
if cs_expect "auditor reads security config of ${HAL_REPO_OPS_DOCKER_LOCAL}" 200; then
  if [ "$(cs_json '.config.scan_on_upload')" = "true" ] && [ "$(cs_json '.config.instance_locked')" = "true" ]; then
    cs_record "security config shows the founding scan-on-upload policy" PASS "scan_on_upload, instance_locked, threshold $(cs_json '.config.severity_threshold')"
  else
    cs_record "security config shows the founding scan-on-upload policy" FAIL "found-policies.sh set scan_on_upload + instance_locked" "${CS_BODY:0:600}"
  fi
fi

# SBOMs: listing by repository is visibility-gated (H/sbom.rs:885-886, #3174).
for r in FW_MAVEN_LOCAL FW_CARGO_LOCAL OPS_DOCKER_LOCAL; do
  cs_http GET "/api/v1/sbom?repository_id=$(repo_id "$r")" jwt:AUDITOR
  cs_expect "auditor lists SBOMs of $(repo_key "$r")" 200 "$(cs_json 'length') SBOMs"
done
if [ -n "$CRATE_ID" ]; then
  cs_http GET "/api/v1/sbom?artifact_id=${CRATE_ID}" jwt:AUDITOR
  cs_expect "auditor lists SBOMs of the day-0 crate by artifact_id" 200 "$(cs_json 'length') SBOMs"
fi

# ---------------------------------------------------------------------------
# Task 8: promotion history (H/promotion.rs:2191 require_visible).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/promotion/repositories/${HAL_REPO_FW_MAVEN_LOCAL}/promotion-history" jwt:AUDITOR
cs_expect "auditor reads promotion history of ${HAL_REPO_FW_MAVEN_LOCAL}" 200

# ---------------------------------------------------------------------------
# Task 9: storage tree (H/tree.rs:55-80, query `repository_key`).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/tree?repository_key=${HAL_REPO_OPS_BUILDS}" jwt:AUDITOR
if cs_expect "auditor reads the storage tree of ${HAL_REPO_OPS_BUILDS}" 200; then
  cs_expect_body "tree shows the firmware folder" "\"name\":\"firmware\""
fi

# ---------------------------------------------------------------------------
# Task 10: webhooks, filtered to readable repos (H/webhooks.rs:521, 534).
# The founder creates none, so the list is empty.
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/webhooks" jwt:AUDITOR
if cs_expect "auditor lists webhooks" 200; then
  n=$(cs_json '(.items // []) | length')
  if [ "$n" = "0" ]; then
    cs_record "webhook list is empty (none on Halcyon repos)" PASS "0 webhooks"
  else
    cs_record "webhook list is empty (none on Halcyon repos)" FAIL "expected 0 webhooks, got ${n}" "${CS_BODY:0:600}"
  fi
fi

# ---------------------------------------------------------------------------
# Should NOT work. Each refusal is followed by an admin read-back.
# ---------------------------------------------------------------------------

# Headline gap: no auditor role. admin_middleware answers plain text 403
# (H/admin.rs:64, 238-240; A:2027-2050).
cs_http GET "/api/v1/admin/audit?per_page=10" jwt:AUDITOR
if cs_expect "GAP: auditor cannot read the audit log (no auditor role; H/admin.rs:64, 238-240)" 403; then
  cs_expect_body "audit log refusal says Admin access required" "Admin access required"
fi
cs_http GET "/api/v1/admin/settings" jwt:AUDITOR
if cs_expect "auditor cannot read admin settings (admin_middleware, H/admin.rs:41)" 403; then
  cs_expect_body "admin settings refusal says Admin access required" "Admin access required"
fi

# Permission table (H/permissions.rs:268-269, require_admin JSON).
cs_http GET "/api/v1/permissions" jwt:AUDITOR
cs_expect "auditor cannot read the permission table (H/permissions.rs:268-269)" 403

# Age-gate config needs repository admin (H/age_gate.rs:257-265); she reads
# the repository, so 403, not 404.
cs_http GET "/api/v1/repositories/${HAL_REPO_WEB_NPM_REMOTE}/age-gate" jwt:AUDITOR
cs_expect "auditor cannot read the age-gate config of ${HAL_REPO_WEB_NPM_REMOTE} (repo admin, H/age_gate.rs:257-265)" 403

# Native publish into a repo she can read: 403 text (A:2710).
AUDIT_PKG="${HAL}-audit-x"
cs_http GET "/api/v1/repositories/${HAL_REPO_WEB_NPM_LOCAL}/artifacts?per_page=100&q=${AUDIT_PKG}" admin
pre_npm=$(cs_json "[.items[]? | select(.name==\"${AUDIT_PKG}\")] | length")
cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" "$AUDIT_PKG" 0.0.1 basic:AUDITOR
if cs_expect "auditor cannot publish npm ${AUDIT_PKG} to ${HAL_REPO_WEB_NPM_LOCAL} (can read, so 403; A:2710)" 403; then
  cs_expect_body "npm refusal names the permission" "You do not have permission"
fi
cs_http GET "/npm/${HAL_REPO_WEB_NPM_LOCAL}/${AUDIT_PKG}" admin
cs_expect "admin read-back: no ${AUDIT_PKG} packument was written" 404 "pre-existing rows: ${pre_npm:-?}"

# REST upload into a repo she can read: 403 JSON (RS:251-274).
_cs_work
printf 'audit probe\n' > "${CS_WORK}/audit-probe.txt"
AUDIT_PATH="audit/${HAL}-auditor-probe.txt"
cs_put_generic "$HAL_REPO_OPS_BUILDS" "$AUDIT_PATH" "${CS_WORK}/audit-probe.txt" jwt:AUDITOR
cs_expect "auditor cannot upload ${AUDIT_PATH} to ${HAL_REPO_OPS_BUILDS} via REST (RS:251-274)" 403
cs_http GET "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/download/${AUDIT_PATH}" admin
cs_expect "admin read-back: ${AUDIT_PATH} was not written" 404

# Delete the day-0 crate via REST: 403 (she can read).
cs_http DELETE "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts/${CRATE_PATH}" jwt:AUDITOR
cs_expect "auditor cannot delete the day-0 crate (RS delete, can read so 403)" 403
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts?per_page=100" admin
cs_expect_body "admin read-back: day-0 crate still present" "$CRATE_PATH"

# Change a repository: repo admin required (RS:6130-6186).
cs_http GET "/api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}" admin
pre_desc=$(cs_json '.description')
cs_http PATCH "/api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}" jwt:AUDITOR \
  -H 'Content-Type: application/json' -d '{"description":"x"}'
cs_expect "auditor cannot PATCH ${HAL_REPO_DATA_PYPI_LOCAL} (repo admin, RS:6130-6186)" 403
cs_http GET "/api/v1/repositories/${HAL_REPO_DATA_PYPI_LOCAL}" admin
post_desc=$(cs_json '.description')
if [ "$post_desc" = "$pre_desc" ] && [ "$post_desc" != "x" ]; then
  cs_record "admin read-back: ${HAL_REPO_DATA_PYPI_LOCAL} description unchanged" PASS "description=${post_desc}"
else
  cs_record "admin read-back: ${HAL_REPO_DATA_PYPI_LOCAL} description unchanged" FAIL "before '${pre_desc}', after '${post_desc}'"
fi

# Generate an SBOM: a write (GHSA-ww52-pmcg-f53c, H/sbom.rs:790-809).
if [ -n "$CRATE_ID" ]; then
  cs_http GET "/api/v1/sbom?artifact_id=${CRATE_ID}" admin
  pre_sbom=$(cs_json 'length')
  cs_http POST /api/v1/sbom jwt:AUDITOR -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$CRATE_ID" '{artifact_id:$a,format:"cyclonedx",force_regenerate:false}')"
  cs_expect "auditor cannot generate an SBOM for the day-0 crate (repo write, H/sbom.rs:809)" 403
  cs_http GET "/api/v1/sbom?artifact_id=${CRATE_ID}" admin
  post_sbom=$(cs_json 'length')
  if [ "$pre_sbom" = "$post_sbom" ]; then
    cs_record "admin read-back: no SBOM was written for the day-0 crate" PASS "${post_sbom} before and after"
  else
    cs_record "admin read-back: no SBOM was written for the day-0 crate" FAIL "SBOM count ${pre_sbom} -> ${post_sbom}"
  fi
else
  cs_record "auditor cannot generate an SBOM for the day-0 crate (repo write, H/sbom.rs:809)" FAIL "day-0 crate id not found in ${HAL_REPO_FW_CARGO_LOCAL} listing"
fi

# The denied admin-route calls are themselves audited (#2366, A:2027-2050):
# what she cannot read records that she tried. Fire-and-forget, so poll.
# Two checks: the rows exist (one per denied admin route), and each carries
# the path she requested. A:2043 records `request.uri().path()`, which inside
# the `/api/v1/admin` nest is the stripped suffix (`/audit`); the same
# function reads `OriginalUri` for its own gate (A:2057-2062), as
# auth_middleware does (A:1056-1070), so the full path is the intended record.
audit_rows() {
  cs_http GET "/api/v1/admin/audit?user_id=${HAL_AUDITOR_ID}&action=PERMISSION_DENIED&from=${START_TS}&per_page=200" admin
  paths=$(cs_json '[.items[]? | .details.path // empty] | join(" ")')
}
has_path() { printf ' %s ' "$paths" | grep -qE " (/api/v1/admin)?$1 "; }
deadline=$(( $(date +%s) + 30 ))
paths=""
while :; do
  audit_rows
  if has_path /audit && has_path /settings; then break; fi
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 2
done
if [ "$CS_STATUS" = "200" ] && has_path /audit && has_path /settings; then
  cs_record "admin read-back: her denied audit-log and settings reads left PERMISSION_DENIED rows (#2366)" PASS \
    "$(cs_json '.items | length') rows since ${START_TS}; paths: ${paths}"
  full=true
  for want in /api/v1/admin/audit /api/v1/admin/settings; do
    printf ' %s ' "$paths" | grep -qF " ${want} " || full=false
  done
  if $full; then
    cs_record "PERMISSION_DENIED rows record the full request path" PASS "${paths}"
  else
    # Filed upstream as #5603.
    cs_record "PERMISSION_DENIED rows record the full request path (#5603)" WARN \
      "#5603: expected /api/v1/admin/audit and /api/v1/admin/settings, rows say: ${paths} (A:2043 uses the nest-stripped request.uri().path(); A:2057-2062 uses OriginalUri)"
  fi
else
  cs_record "admin read-back: her denied audit-log and settings reads left PERMISSION_DENIED rows (#2366)" FAIL \
    "HTTP ${CS_STATUS}; rows for ${HAL_AUDITOR_ID} since ${START_TS}: ${paths:-none}" "${CS_BODY:0:600}"
fi

# ---------------------------------------------------------------------------
# Traces of the day: firmware ships SDK 1.1.0 (barrier fw-sdk-1.1.0).
# ---------------------------------------------------------------------------
SDK11="${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/1.1.0/${HAL_SEED_MAVEN_ARTIFACT}-1.1.0.jar"
if cs_wait fw-sdk-1.1.0 "$BARRIER_TIMEOUT"; then
  cs_http GET "/api/v1/repositories/${HAL_REPO_FW_MAVEN_LOCAL}/artifacts?per_page=100" jwt:AUDITOR
  if cs_expect "auditor re-lists ${HAL_REPO_FW_MAVEN_LOCAL} after fw-sdk-1.1.0" 200; then
    who=$(cs_json ".items[]? | select(.path==\"${SDK11}\") | .uploaded_by_username" | head -n1)
    if [ "$who" = "$HAL_FW_DEV_USER" ]; then
      cs_record "SDK 1.1.0 is listed and attributed to ${HAL_FW_DEV_USER}" PASS "${SDK11} uploaded_by ${who}"
    else
      cs_record "SDK 1.1.0 is listed and attributed to ${HAL_FW_DEV_USER}" FAIL "uploaded_by='${who:-<not listed>}' for ${SDK11}" "${CS_BODY:0:600}"
    fi
  fi
  cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${SDK11}" basic:AUDITOR
  cs_expect "auditor downloads SDK 1.1.0 through ${HAL_REPO_FW_MAVEN}" 200
else
  cs_record "waited for fw-sdk-1.1.0" FAIL "${CS_WAIT_WHY} (firmware)"
fi

# ---------------------------------------------------------------------------
# Task 7: scan results of the devops image (barrier ops-image-pushed, then
# optionally ops-image-reviewed once the security lead has looked at it).
# GET /api/v1/security/scans?repository_id= is require_visible (H/security.rs:1593-1611).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/security/scans?repository_id=${HAL_REPO_OPS_DOCKER_LOCAL_ID}&status=completed&per_page=100" jwt:AUDITOR
if cs_expect "auditor lists scans of ${HAL_REPO_OPS_DOCKER_LOCAL}" 200 "$(cs_json '.total // empty') scans"; then
  # Any completed scan already there (an earlier run's image): its findings
  # are readable through the repository grant (scan_visible_to, H/security.rs:1679-1713).
  sid0=$(cs_json '[.items[]? | select(.status=="completed")][0].id // empty')
  if [ -n "$sid0" ]; then
    cs_http GET "/api/v1/security/scans/${sid0}/findings" jwt:AUDITOR
    cs_expect "auditor reads findings of an existing ${HAL_REPO_OPS_DOCKER_LOCAL} scan" 200
  fi
fi

if cs_wait ops-image-pushed "$BARRIER_TIMEOUT" && [ "$(cs_signal_outcome ops-image-pushed)" = "none" ]; then
  cs_record "scan results of the devops image" SKIP "devops pushed no image this run (ops-image-pushed outcome 'none'; ROLES.md auditor #7)"
elif [ -z "$CS_WAIT_WHY" ]; then
  cs_http GET "/api/v1/repositories/${HAL_REPO_OPS_DOCKER_LOCAL}/artifacts?per_page=100" jwt:AUDITOR
  if cs_expect "auditor re-lists ${HAL_REPO_OPS_DOCKER_LOCAL} after ops-image-pushed" 200; then
    cs_expect_body "devops image ${HAL}-ops-base is listed" "${HAL}-ops-base"
  fi
  if cs_wait ops-image-reviewed "$BARRIER_TIMEOUT"; then
    # The image's own scans, by artifact_id (artifact visibility, H/security.rs:1593-1611).
    img_id=$(cs_json "[.items[]? | select(.path==\"v2/${HAL}-ops-base/manifests/1\")][0].id // empty")
    if [ -z "$img_id" ]; then
      cs_record "a completed scan of ${HAL}-ops-base:1 is visible to the auditor" FAIL "v2/${HAL}-ops-base/manifests/1 not in the ${HAL_REPO_OPS_DOCKER_LOCAL} listing"
    else
      # status=completed: every re-push of the same image adds a not_applicable
      # row, which the list folds into one (#2471) while still paging over
      # them, so an unfiltered first page can hold no completed scan at all.
      cs_http GET "/api/v1/security/scans?artifact_id=${img_id}&status=completed&per_page=100" jwt:AUDITOR
      if cs_expect "auditor lists scans of ${HAL}-ops-base:1 after ops-image-reviewed" 200; then
        sid=$(cs_json '[.items[]? | select(.status=="completed")] | sort_by(.findings_count) | last | .id // empty')
        if [ -n "$sid" ]; then
          cs_record "a completed scan of ${HAL}-ops-base:1 is visible to the auditor" PASS \
            "$(cs_json "[.items[]? | select(.id==\"${sid}\")][0] | \"\\(.findings_count) findings (\\(.critical_count) critical)\"")"
          cs_http GET "/api/v1/security/scans/${sid}/findings" jwt:AUDITOR
          cs_expect "auditor reads the findings of the ${HAL}-ops-base:1 scan (scan_visible_to, H/security.rs:1801)" 200
        else
          cs_record "a completed scan of ${HAL}-ops-base:1 is visible to the auditor" FAIL \
            "no completed scan for artifact ${img_id} (scan_on_upload is on)" "${CS_BODY:0:600}"
        fi
      fi
    fi
  else
    cs_record "scan results of the devops image after review" SKIP "${CS_WAIT_WHY}"
  fi
else
  cs_record "scan results of the devops image" SKIP "${CS_WAIT_WHY} (ROLES.md auditor #7)"
fi

cs_end
