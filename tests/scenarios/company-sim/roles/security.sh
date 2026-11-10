#!/usr/bin/env bash
# roles/security.sh - Rhea Collins (security lead, instance admin) and Omar
# Haddad (security analyst, read only) at Halcyon Robotics.
#
# ROLES.md "## security". Rhea owns policy: she reads the founded scan
# policy, reviews the devops image the scanner flagged, acknowledges one
# non-critical finding (criticals stay open, so the scan-policy block holds),
# releases the devops helm chart from upload-period quarantine, decides an
# age-gate review on the instance-locked firmware Maven remote, and restores
# that gate after firmware tightened it. Omar reads findings through the
# security group's project grants and is refused every write.
#
# Barriers:
#   waits   ops-image-pushed (devops), ops-chart-published (devops),
#           web-age-gate-review (web, optional: a timeout is a SKIP),
#           fw-age-gate-relax-refused (firmware, after its #11; see #10 below)
#   signals ops-image-reviewed, ops-chart-released
#
# Timeouts: CS_BARRIER_TIMEOUT (default 600 s) for every barrier,
# SEC_SCAN_TIMEOUT (default 300 s) for the upload scan to settle.
# SEC_IMAGE_NAME / SEC_IMAGE_TAG / SEC_CHART_NAME override what devops
# publishes (defaults ${HAL}-ops-base:1 and ${HAL}-ops-app), for dev runs.
#
# Left behind on purpose (the founder does not undo these; ROLES.md "Replay
# notes"):
#   - the age-gate review of the newest software.amazon.awssdk:bom on
#     ${HAL}-fw-maven-remote, left `rejected` by Rhea (a re-run reopens and
#     rejects it again);
#   - the release of devops' chart (the chart is devops' object);
#   - audit rows.
# Removed before cs_end: the ${HAL}-sec-tmp policy, Rhea's acknowledgement.

source "$(dirname "$0")/../lib.sh"

cs_begin security
# Barriers this role signals: released as "failed" if it exits early.
cs_signals ops-image-reviewed ops-chart-released

BT="${CS_BARRIER_TIMEOUT:-600}"
SCAN_TIMEOUT="${SEC_SCAN_TIMEOUT:-300}"
IMAGE_NAME="${SEC_IMAGE_NAME:-${HAL}-ops-base}"
IMAGE_TAG="${SEC_IMAGE_TAG:-1}"
CHART_NAME="${SEC_CHART_NAME:-${HAL}-ops-app}"
START_TS=$(date +%s)
REPO_DL="$HAL_REPO_OPS_DOCKER_LOCAL"
REPO_DL_ID="$HAL_REPO_OPS_DOCKER_LOCAL_ID"
MANIFEST_ACCEPT='Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'

# _status_is CODE - true when the last cs_http answered CODE.
_status_is() { [ "$CS_STATUS" = "$1" ]; }
_body() { printf '%s' "$CS_BODY" | head -c 400; }

# ---------------------------------------------------------------------------
# Morning: both sign in
# ---------------------------------------------------------------------------
for p in SEC_LEAD SEC_ANALYST; do
  if cs_login "$p"; then
    cs_record "$(cs_user "$p") signs in" PASS "JWT issued"
  else
    cs_record "$(cs_user "$p") signs in" FAIL "login HTTP ${CS_STATUS}" "$(_body)"
    cs_end
  fi
done

cs_http GET /api/v1/users/me jwt:SEC_LEAD
if _status_is 200 && [ "$(cs_json '.is_admin')" = "true" ]; then
  cs_record "Rhea is an instance admin (GET /users/me)" PASS "HTTP 200, is_admin true (README: security lead is admin)"
else
  cs_record "Rhea is an instance admin (GET /users/me)" FAIL "HTTP ${CS_STATUS} is_admin=$(cs_json '.is_admin')" "$(_body)"
fi
cs_http GET /api/v1/users/me jwt:SEC_ANALYST
if _status_is 200 && [ "$(cs_json '.is_admin')" = "false" ]; then
  cs_record "Omar is not an admin (GET /users/me)" PASS "HTTP 200, is_admin false"
else
  cs_record "Omar is not an admin (GET /users/me)" FAIL "HTTP ${CS_STATUS} is_admin=$(cs_json '.is_admin')" "$(_body)"
fi

# ---------------------------------------------------------------------------
# 1. Rhea opens the dashboard (require_admin, H/security.rs:1138)
# ---------------------------------------------------------------------------
cs_http GET /api/v1/security/dashboard jwt:SEC_LEAD
if cs_expect "#1 Rhea opens the security dashboard (H/security.rs:1138)" 200; then
  rws=$(cs_json '.repos_with_scanning // 0')
  if [ "${rws:-0}" -ge 1 ] 2>/dev/null; then
    cs_record "#1 dashboard counts at least one repo with scanning" PASS "repos_with_scanning=${rws} (ops-docker-local scans on upload)"
  else
    cs_record "#1 dashboard counts at least one repo with scanning" FAIL "repos_with_scanning=${rws}" "$(_body)"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Rhea reads the founded policy (H/security.rs:983-997, 2435)
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/security/policies/${HAL_SCAN_POLICY_ID}" jwt:SEC_LEAD
if cs_expect "#2 Rhea reads policy ${HAL_SCAN_POLICY} (GET /security/policies/{id})" 200; then
  got=$(cs_json '[.max_severity, .repository_id, .block_on_fail, .block_unscanned, .is_enabled] | map(tostring) | join(",")')
  want="critical,${REPO_DL_ID},true,false,true"
  if [ "$got" = "$want" ]; then
    cs_record "#2 policy is max_severity critical, ops-docker-local, block_on_fail, enabled" PASS "${got}"
  else
    cs_record "#2 policy is max_severity critical, ops-docker-local, block_on_fail, enabled" FAIL "got ${got}, want ${want} (found-policies.sh)" "$(_body)"
  fi
fi

cs_http GET "/api/v1/repositories/${REPO_DL}/security" jwt:SEC_LEAD
if cs_expect "#2 Rhea reads ops-docker-local scan config (H/security.rs:2540)" 200; then
  got=$(cs_json '.config | [.scan_enabled, .scan_on_upload, .block_on_policy_violation, .severity_threshold, .instance_locked] | map(tostring) | join(",")')
  want="true,true,true,critical,true"
  if [ "$got" = "$want" ]; then
    cs_record "#2 scan on upload, threshold critical, instance_locked (admin write locks)" PASS "${got}"
  else
    cs_record "#2 scan on upload, threshold critical, instance_locked (admin write locks)" FAIL "got ${got}, want ${want} (found-policies.sh, H/security.rs:1098-1107)" "$(_body)"
  fi
fi

# ---------------------------------------------------------------------------
# 12. Observation: scan configs and policies have no gate beyond
#     authentication (H/security.rs:1407-1422 list_scan_configs, 2371-2380
#     list_policies, 2435 get_policy: `Extension(_auth)` only). Omar's answer
#     is compared with the admin's to show it is not filtered per caller.
# ---------------------------------------------------------------------------
cs_http GET /api/v1/security/configs jwt:SEC_LEAD
admin_cfg_n=$(cs_json 'length')
cs_http GET /api/v1/security/configs jwt:SEC_ANALYST
if cs_expect "#12 Omar lists every scan config (GET /security/configs)" 200 \
     "OBSERVATION: any authenticated user can read every repository's scan config (H/security.rs:1407-1422)"; then
  omar_cfg_n=$(cs_json 'length')
  has=$(cs_json 'any(.[]?; .repository_id == "'"$REPO_DL_ID"'")')
  if [ "$omar_cfg_n" = "$admin_cfg_n" ] && [ "$has" = "true" ]; then
    cs_record "#12 Omar's config list is the unfiltered instance-wide list" PASS \
      "OBSERVATION: ${omar_cfg_n} configs, same as the admin's ${admin_cfg_n}; includes ops-docker-local. No per-caller filter: a user with no grant sees them too"
  else
    cs_record "#12 Omar's config list is the unfiltered instance-wide list" FAIL \
      "Omar sees ${omar_cfg_n}, admin ${admin_cfg_n}, ops-docker-local present=${has}" "$(_body)"
  fi
fi

cs_http GET /api/v1/security/policies jwt:SEC_LEAD
admin_pol_n=$(cs_json 'length')
cs_http GET /api/v1/security/policies jwt:SEC_ANALYST
if cs_expect "#12 Omar lists every scan policy (GET /security/policies)" 200 \
     "OBSERVATION: any authenticated user can read every policy (H/security.rs:2371-2380)"; then
  omar_pol_n=$(cs_json 'length')
  has=$(cs_json 'any(.[]?; .id == "'"$HAL_SCAN_POLICY_ID"'")')
  if [ "$omar_pol_n" = "$admin_pol_n" ] && [ "$has" = "true" ]; then
    cs_record "#12 Omar's policy list is the unfiltered instance-wide list" PASS \
      "OBSERVATION: ${omar_pol_n} policies, same as the admin's ${admin_pol_n}; includes ${HAL_SCAN_POLICY}"
  else
    cs_record "#12 Omar's policy list is the unfiltered instance-wide list" FAIL \
      "Omar sees ${omar_pol_n}, admin ${admin_pol_n}, ${HAL_SCAN_POLICY} present=${has}" "$(_body)"
  fi
fi
cs_http GET "/api/v1/security/policies/${HAL_SCAN_POLICY_ID}" jwt:SEC_ANALYST
cs_expect "#12 Omar reads one policy by id (GET /security/policies/{id})" 200 \
  "OBSERVATION: no gate beyond authentication (H/security.rs:2435)"

# ---------------------------------------------------------------------------
# 13. Rhea creates a temporary policy for the conda local, then deletes it
#     (require_admin, H/security.rs:2400, 2510). Omar may neither update nor
#     delete it (2467, 2510).
# ---------------------------------------------------------------------------
TMP_POLICY="${HAL}-sec-tmp"
cs_http GET /api/v1/security/policies jwt:SEC_LEAD
for old in $(cs_json '.[]? | select(.name=="'"$TMP_POLICY"'") | .id'); do
  cs_http DELETE "/api/v1/security/policies/${old}" jwt:SEC_LEAD   # leftover of an earlier run
done
cs_http POST /api/v1/security/policies jwt:SEC_LEAD -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$TMP_POLICY" --arg r "$HAL_REPO_DATA_CONDA_LOCAL_ID" \
        '{name:$n,repository_id:$r,max_severity:"high",block_unscanned:false,block_on_fail:false}')"
tmp_pol_id=""
if cs_expect "#13 Rhea creates policy ${TMP_POLICY} on data-conda-local (H/security.rs:2400)" 200; then
  tmp_pol_id=$(cs_json '.id // empty')
fi
if [ -n "$tmp_pol_id" ]; then
  cs_http PUT "/api/v1/security/policies/${tmp_pol_id}" jwt:SEC_ANALYST -H 'Content-Type: application/json' \
    -d '{"is_enabled":false}'
  cs_expect "Omar cannot update a policy (H/security.rs:2467)" 403
  cs_http DELETE "/api/v1/security/policies/${tmp_pol_id}" jwt:SEC_ANALYST
  cs_expect "Omar cannot delete a policy (H/security.rs:2510)" 403
  cs_http GET "/api/v1/security/policies/${tmp_pol_id}" jwt:SEC_LEAD
  if _status_is 200 && [ "$(cs_json '.is_enabled')" = "true" ]; then
    cs_record "Omar's refused update and delete wrote nothing" PASS "policy still present and enabled"
  else
    cs_record "Omar's refused update and delete wrote nothing" FAIL "HTTP ${CS_STATUS} is_enabled=$(cs_json '.is_enabled')" "$(_body)"
  fi
  cs_http DELETE "/api/v1/security/policies/${tmp_pol_id}" jwt:SEC_LEAD
  if cs_expect "#13 Rhea deletes ${TMP_POLICY} (H/security.rs:2510)" 200; then
    cs_http GET "/api/v1/security/policies/${tmp_pol_id}" jwt:SEC_LEAD
    cs_expect "#13 deleted policy is gone" 404
  fi
else
  cs_record "#13 policy update/delete checks" SKIP "no temporary policy was created"
fi

# ---------------------------------------------------------------------------
# Should NOT work (Omar, read only). Each refusal is re-read by Rhea where a
# write could have landed.
# ---------------------------------------------------------------------------
OMAR_POLICY="${HAL}-sec-omar"
cs_http POST /api/v1/security/policies jwt:SEC_ANALYST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$OMAR_POLICY" --arg r "$REPO_DL_ID" \
        '{name:$n,repository_id:$r,max_severity:"low",block_unscanned:false,block_on_fail:false}')"
cs_expect "Omar cannot create a policy (POST /security/policies, H/security.rs:2400)" 403
cs_http GET /api/v1/security/policies jwt:SEC_LEAD
cs_expect_no_body "Omar's refused policy was not written" "\"${OMAR_POLICY}\""

cs_http PUT "/api/v1/repositories/${REPO_DL}/security" jwt:SEC_ANALYST -H 'Content-Type: application/json' \
  -d '{"scan_enabled":false,"scan_on_upload":false}'
if cs_expect "Omar cannot change ops-docker-local scan settings: 403 not 404, he can read it (H/security.rs:2596-2607)" 403; then
  cs_expect_body "Omar's scan-settings refusal names the repo-admin requirement" \
    "Repository admin permission is required for this operation"
fi
cs_http GET "/api/v1/repositories/${REPO_DL}/security" jwt:SEC_LEAD
if [ "$(cs_json '.config | [.scan_enabled, .scan_on_upload] | map(tostring) | join(",")')" = "true,true" ]; then
  cs_record "Omar's refused scan-settings write changed nothing" PASS "scan_enabled and scan_on_upload still true"
else
  cs_record "Omar's refused scan-settings write changed nothing" FAIL "config now $(cs_json '.config')" "$(_body)"
fi

cs_http GET "/api/v1/admin/audit?per_page=5" jwt:SEC_ANALYST
if cs_expect "Omar cannot read the audit log (admin_middleware, H/admin.rs:64)" 403; then
  cs_expect_body "Omar's audit refusal is 'Admin access required' (A:2027-2050)" "Admin access required"
fi

cs_http GET /api/v1/security/dashboard jwt:SEC_ANALYST
cs_expect "Omar cannot open the dashboard (require_admin, H/security.rs:1138)" 403
cs_http GET /api/v1/security/acknowledgements jwt:SEC_ANALYST
cs_expect "Omar cannot list acknowledgements (require_unscoped_admin, H/security.rs:2302)" 403
cs_http GET /api/v1/admin/holds/policy-blocks jwt:SEC_ANALYST
cs_expect "Omar cannot read the policy-blocks queue (admin_middleware, H/download_holds.rs:89-90)" 403
cs_http GET /api/v1/admin/holds/quarantine jwt:SEC_ANALYST
cs_expect "Omar cannot read the quarantine queue (admin_middleware, H/download_holds.rs)" 403
cs_http GET /api/v1/admin/age-gate/reviews jwt:SEC_ANALYST
cs_expect "Omar cannot read the instance-wide age-gate queue (R:1428, H/age_gate.rs:38-45)" 403
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate" jwt:SEC_ANALYST
cs_expect "Omar cannot read the firmware remote's age gate: 403, he reads the repo (H/age_gate.rs:257-265)" 403

# ---------------------------------------------------------------------------
# 3. The devops image: wait, find it, let the upload scan settle.
# ---------------------------------------------------------------------------
img_id=""
if cs_wait ops-image-pushed "$BT" && [ "$(cs_signal_outcome ops-image-pushed)" = "none" ]; then
  cs_record "#3 Rhea finds ${IMAGE_NAME}:${IMAGE_TAG} in ops-docker-local" SKIP \
    "devops pushed no image this run (ops-image-pushed outcome 'none'; see devops #3); #3-#8 image checks skipped"
elif [ -z "$CS_WAIT_WHY" ]; then
  cs_http GET "/api/v1/repositories/${REPO_DL}/artifacts?per_page=100&path_prefix=v2/${IMAGE_NAME}/manifests/" jwt:SEC_LEAD
  img_id=$(cs_json '.items[]? | select(.path=="v2/'"${IMAGE_NAME}"'/manifests/'"${IMAGE_TAG}"'") | .id' | head -n1)
  if [ -n "$img_id" ]; then
    cs_record "#3 Rhea finds ${IMAGE_NAME}:${IMAGE_TAG} in ops-docker-local" PASS "artifact ${img_id}"
  else
    cs_record "#3 Rhea finds ${IMAGE_NAME}:${IMAGE_TAG} in ops-docker-local" FAIL \
      "devops signalled ops-image-pushed but no manifest artifact v2/${IMAGE_NAME}/manifests/${IMAGE_TAG} (HTTP ${CS_STATUS})" "$(_body)"
  fi
else
  cs_record "waited for devops to push the image (ops-image-pushed)" FAIL "${CS_WAIT_WHY}"
fi

# _scans_state - list scans of the image as Rhea; sets SC_TOTAL, SC_OPEN
# (pending/running) and SC_CRIT (criticals over completed scans).
SC_TOTAL=0; SC_OPEN=0; SC_CRIT=0
_scans_state() {
  cs_http GET "/api/v1/security/scans?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
  SC_TOTAL=$(cs_json '.items | length')
  SC_OPEN=$(cs_json '[.items[]? | select(.status=="pending" or .status=="running" or .status=="queued")] | length')
  SC_CRIT=$(cs_json '[.items[]? | select(.status=="completed") | .critical_count] | add // 0')
  SC_TOTAL=${SC_TOTAL:-0}; SC_OPEN=${SC_OPEN:-0}; SC_CRIT=${SC_CRIT:-0}
}

scan_ok=false
if [ -n "$img_id" ]; then
  deadline=$(( $(date +%s) + SCAN_TIMEOUT ))
  triggered=false
  while :; do
    _scans_state
    if [ "$SC_TOTAL" -gt 0 ] && [ "$SC_OPEN" -eq 0 ]; then break; fi
    # No scan row a minute after the push: scan-on-upload did not fire, so
    # trigger it (admin only, H/security.rs:1455-1463).
    if [ "$SC_TOTAL" -eq 0 ] && ! $triggered && [ $(( $(date +%s) - START_TS )) -gt 60 ]; then
      cs_http POST /api/v1/security/scan jwt:SEC_LEAD -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg a "$img_id" '{artifact_id:$a}')"
      cs_expect "#3 Rhea triggers a scan, the upload scan never appeared (H/security.rs:1455)" 200
      triggered=true
    fi
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 5
  done
  if [ "$SC_TOTAL" -gt 0 ] && [ "$SC_OPEN" -eq 0 ] && [ "$SC_CRIT" -gt 0 ]; then
    cs_record "#3 upload scans completed with critical findings (alpine 3.12)" PASS \
      "${SC_TOTAL} scan rows, ${SC_CRIT} criticals across completed scans"
    scan_ok=true
  else
    cs_record "#3 upload scans completed with critical findings (alpine 3.12)" FAIL \
      "after ${SCAN_TIMEOUT}s: ${SC_TOTAL} scans, ${SC_OPEN} still pending/running, ${SC_CRIT} criticals" "$(_body)"
  fi
fi

# Pick the completed scan with the most criticals and its findings, reading
# the copy that belongs to this artifact (?artifact_id=, H/security.rs:733-737:
# a reused scan is listed under its source's id).
scan_id=""; fid_ack=""; crit_open=0
if $scan_ok; then
  cs_http GET "/api/v1/security/scans?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
  scan_id=$(cs_json '[.items[]? | select(.status=="completed" and .critical_count>0)] | sort_by(-.critical_count) | .[0].id // empty')
fi

# ---------------------------------------------------------------------------
# 4. Omar reads the scans and findings (scan_visible_to ->
#    check_artifact_visibility, H/security.rs:1679-1713, 1801-1802)
# ---------------------------------------------------------------------------
if [ -n "$scan_id" ]; then
  cs_http GET "/api/v1/security/scans?artifact_id=${img_id}" jwt:SEC_ANALYST
  cs_expect "#4 Omar lists the image's scans (read via HAL-security project grant, H/security.rs:1593-1611)" 200
  cs_http GET "/api/v1/security/scans/${scan_id}/findings?artifact_id=${img_id}&per_page=100" jwt:SEC_ANALYST
  if cs_expect "#4 Omar reads the findings (GET /security/scans/{id}/findings)" 200; then
    n=$(cs_json '.items | length')
    if [ "${n:-0}" -gt 0 ]; then
      cs_record "#4 Omar sees the image's findings" PASS "${n} findings on scan ${scan_id}, total $(cs_json '.total')"
    else
      cs_record "#4 Omar sees the image's findings" FAIL "empty findings list" "$(_body)"
    fi
  fi

  # A non-critical, not yet acknowledged finding (criticals stay open, #8).
  cs_http GET "/api/v1/security/scans/${scan_id}/findings?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
  fid_ack=$(cs_json '[.items[]? | select(.severity!="critical" and (.is_acknowledged|not))] | sort_by(if .severity=="high" then 0 elif .severity=="medium" then 1 else 2 end) | .[0].id // empty')
  if [ -z "$fid_ack" ]; then
    cs_http GET "/api/v1/security/scans?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
    for s in $(cs_json '.items[]? | select(.status=="completed" and .findings_count>.critical_count) | .id'); do
      cs_http GET "/api/v1/security/scans/${s}/findings?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
      fid_ack=$(cs_json '[.items[]? | select(.severity!="critical" and (.is_acknowledged|not))] | .[0].id // empty')
      [ -n "$fid_ack" ] && { scan_id="$s"; break; }
    done
  fi

  # -------------------------------------------------------------------------
  # 5. Omar tries to acknowledge it (require_admin, H/security.rs:2236)
  # -------------------------------------------------------------------------
  if [ -n "$fid_ack" ]; then
    cs_http POST "/api/v1/security/findings/${fid_ack}/acknowledge" jwt:SEC_ANALYST -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg r "$REPO_DL_ID" '{reason:"false positive",repository_id:$r}')"
    cs_expect "#5 Omar cannot acknowledge a finding (require_admin, H/security.rs:2236)" 403
    cs_http GET "/api/v1/security/scans/${scan_id}/findings?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
    if [ "$(cs_json '.items[]? | select(.id=="'"$fid_ack"'") | .is_acknowledged')" = "false" ]; then
      cs_record "#5 Omar's refused acknowledgement wrote nothing" PASS "finding ${fid_ack} still open"
    else
      cs_record "#5 Omar's refused acknowledgement wrote nothing" FAIL "finding ${fid_ack} is_acknowledged=$(cs_json '.items[]? | select(.id=="'"$fid_ack"'") | .is_acknowledged')"
    fi

    # -----------------------------------------------------------------------
    # 6. Rhea acknowledges it in ops-docker-local (HOLDS:137, #5153)
    # -----------------------------------------------------------------------
    cs_http POST "/api/v1/security/findings/${fid_ack}/acknowledge" jwt:SEC_LEAD -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg r "$REPO_DL_ID" '{reason:"Halcyon security review: not reachable in ops-base, accepted for today",repository_id:$r}')"
    if cs_expect "#6 Rhea acknowledges a non-critical finding with repository_id (H/security.rs:2236, #5153)" 200; then
      if [ "$(cs_json '.is_acknowledged')" = "true" ] && [ "$(cs_json '.acknowledged_by')" = "$HAL_SEC_LEAD_ID" ]; then
        cs_record "#6 finding is acknowledged by Rhea" PASS "finding ${fid_ack} ($(cs_json '.severity') $(cs_json '.cve_id')), acknowledgement $(cs_json '.acknowledgement_id')"
      else
        cs_record "#6 finding is acknowledged by Rhea" FAIL "is_acknowledged=$(cs_json '.is_acknowledged') acknowledged_by=$(cs_json '.acknowledged_by')" "$(_body)"
      fi
    else
      fid_ack=""
    fi
  else
    cs_record "#5/#6 acknowledge checks" FAIL "no open non-critical finding on ${IMAGE_NAME}:${IMAGE_TAG} to acknowledge"
  fi

  # Criticals still open after the acknowledgement.
  crit_open=0
  cs_http GET "/api/v1/security/scans?artifact_id=${img_id}&per_page=100" jwt:SEC_LEAD
  for s in $(cs_json '.items[]? | select(.status=="completed" and .critical_count>0) | .id'); do
    cs_http GET "/api/v1/security/scans/${s}/findings?artifact_id=${img_id}&severity=critical&per_page=100" jwt:SEC_LEAD
    c=$(cs_json '[.items[]? | select(.is_acknowledged|not)] | length')
    crit_open=$(( crit_open + ${c:-0} ))
  done

  # The block holds while a critical is open (HOLDS:11-19, 142-146; #4510).
  cs_http GET "/v2/${REPO_DL}/${IMAGE_NAME}/manifests/${IMAGE_TAG}" jwt:SEC_LEAD -H "$MANIFEST_ACCEPT"
  if cs_expect "#6 the image stays blocked with criticals open (scan-policy hold, #4510)" 403; then
    cs_expect_body "#6 the refusal is the scan-policy message (S/quarantine_service.rs:175-176)" \
      "Artifact download is blocked by the repository's scan policy"
  fi
elif [ -n "$img_id" ]; then
  cs_record "#4-#6 findings review" SKIP "no completed scan with criticals (see #3)"
fi

# ---------------------------------------------------------------------------
# 7. Policy-blocks queue (admin_middleware + require_unscoped_admin,
#    H/download_holds.rs:89-90, #4510)
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/admin/holds/policy-blocks?repository_key=${REPO_DL}&per_page=200" jwt:SEC_LEAD
if cs_expect "#7 Rhea reads the policy-blocks queue (H/download_holds.rs:89-90)" 200 && [ -n "$img_id" ]; then
  row=$(cs_json '.items[]? | select(.artifact_id=="'"$img_id"'") | [.hold_source, (.violations|join(";"))] | join("|")')
  if [ -n "$row" ] && printf '%s' "$row" | grep -qF "$HAL_SCAN_POLICY"; then
    cs_record "#7 the queue lists the blocked image under ${HAL_SCAN_POLICY}" PASS "$(printf '%s' "$row" | cut -c1-200)"
  else
    cs_record "#7 the queue lists the blocked image under ${HAL_SCAN_POLICY}" FAIL "artifact ${img_id} row='${row}'" "$(_body)"
  fi
fi

# ---------------------------------------------------------------------------
# 8. Signal ops-image-reviewed with the outcome devops #5 and ci #10 pin:
#    "blocked" (criticals left open, the scan-policy block stays: a pull
#    answers 403), "cleared" (every finding acknowledged: 200; this role never
#    does that), "none" (no image reviewed: they SKIP).
# ---------------------------------------------------------------------------
review_outcome=none
if [ -n "$img_id" ] && [ -n "$scan_id" ]; then
  review_outcome=blocked
  if [ "$crit_open" -gt 0 ]; then
    cs_record "#8 review outcome for devops: NOT every finding acknowledged" PASS \
      "${crit_open} critical findings left open; one non-critical acknowledged; the scan-policy block stays: a pull of ${IMAGE_NAME}:${IMAGE_TAG} must answer 403"
  else
    cs_record "#8 review outcome for devops: NOT every finding acknowledged" FAIL \
      "no open critical finding counted; the block may be released (HOLDS:142-146)"
  fi
else
  cs_record "#8 review outcome for devops" SKIP "no reviewed image; signalling 'none' so devops, ci and auditor skip their image checks"
fi
cs_signal ops-image-reviewed "$review_outcome"

# ---------------------------------------------------------------------------
# 9. The devops chart: list the quarantine queue and release it
#    (H/quarantine.rs:315, H/download_holds.rs list_quarantine)
# ---------------------------------------------------------------------------
if cs_wait ops-chart-published "$BT"; then
  cs_http GET "/api/v1/admin/holds/quarantine?repository_key=${HAL_REPO_OPS_HELM}&per_page=100" jwt:SEC_LEAD
  chart_id=""; chart_path=""
  if cs_expect "#9 Rhea lists the quarantine queue for ops-helm" 200; then
    chart_id=$(cs_json '[.items[]? | select(.name=="'"$CHART_NAME"'" and .kind=="active")] | sort_by(.created_at) | last | .artifact_id // empty')
    chart_path=$(cs_json '[.items[]? | select(.name=="'"$CHART_NAME"'" and .kind=="active")] | sort_by(.created_at) | last | .path // empty')
    if [ -n "$chart_id" ]; then
      cs_record "#9 the queue holds ${CHART_NAME} (hold_source upload)" PASS \
        "artifact ${chart_id}, $(cs_json '[.items[]? | select(.artifact_id=="'"$chart_id"'")][0] | "\(.hold_source) remaining \(.remaining_seconds)s"')"
    else
      cs_record "#9 the queue holds ${CHART_NAME} (hold_source upload)" FAIL "no active hold for ${CHART_NAME} in ops-helm" "$(_body)"
    fi
  fi
  if [ -n "$chart_id" ]; then
    chart_file="${chart_path##*/}"
    cs_http GET "/helm/${HAL_REPO_OPS_HELM}/charts/${chart_file}" jwt:SEC_LEAD
    if cs_expect "#9 before release the chart answers 409 even to an admin (S/quarantine_service.rs:270-280)" 409; then
      cs_expect_body "#9 hold message" "Artifact is quarantined and pending security review"
    fi
    cs_http POST "/api/v1/quarantine/${chart_id}/release" jwt:SEC_ANALYST
    cs_expect "Omar cannot release a quarantined chart (require_admin, H/quarantine.rs:315)" 403
    cs_http POST "/api/v1/quarantine/${chart_id}/release" jwt:SEC_LEAD
    if cs_expect "#9 Rhea releases the chart (POST /quarantine/{id}/release)" 200; then
      cs_http GET "/api/v1/quarantine/${chart_id}" jwt:SEC_LEAD
      if _status_is 200 && [ "$(cs_json '[.quarantine_status, .is_blocked] | map(tostring) | join(",")')" = "released,false" ]; then
        cs_record "#9 the chart's status is released and unblocked" PASS "GET /quarantine/{id}"
      else
        cs_record "#9 the chart's status is released and unblocked" FAIL "HTTP ${CS_STATUS}" "$(_body)"
      fi
      cs_http GET "/helm/${HAL_REPO_OPS_HELM}/charts/${chart_file}" jwt:SEC_LEAD
      cs_expect "#9 after release the chart downloads" 200
    fi
  fi
else
  cs_record "waited for devops to publish the chart (ops-chart-published)" FAIL "${CS_WAIT_WHY}"
fi
cs_signal ops-chart-released

# ---------------------------------------------------------------------------
# 11. Instance-wide age-gate queue (admin_middleware R:1428, require_admin
#     H/age_gate.rs:504). Web's review is optional: a timeout is a SKIP.
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/admin/age-gate/reviews?per_page=100" jwt:SEC_LEAD
cs_expect "#11 Rhea reads the instance-wide age-gate queue (H/age_gate.rs:38-45)" 200
web_wait=$(( BT < 300 ? BT : 300 ))
if cs_wait web-age-gate-review "$web_wait"; then
  cs_http GET "/api/v1/admin/age-gate/reviews?repository_key=${HAL_REPO_WEB_NPM_REMOTE}&per_page=100" jwt:SEC_LEAD
  n=$(cs_json '.items | length')
  if _status_is 200 && [ "${n:-0}" -gt 0 ]; then
    cs_record "#11 the instance-wide queue shows web's review" PASS \
      "${n} reviews on ${HAL_REPO_WEB_NPM_REMOTE}, newest $(cs_json '[.items[]] | sort_by(.requested_at) | last | "\(.package_name)@\(.package_version) \(.status)"')"
  else
    cs_record "#11 the instance-wide queue shows web's review" FAIL "HTTP ${CS_STATUS}, ${n:-0} reviews on ${HAL_REPO_WEB_NPM_REMOTE}" "$(_body)"
  fi
else
  cs_record "#11 the instance-wide queue shows web's review" SKIP "${CS_WAIT_WHY} (optional barrier)"
fi

# ---------------------------------------------------------------------------
# Age-gate review decision on the instance-locked firmware Maven remote.
# Rhea pulls the newest software.amazon.awssdk:bom (released almost daily)
# through ${HAL}-fw-maven-remote; it is younger than 7 days, so the gate
# answers 451 and files a review (H/proxy_helpers.rs:9496-9541). Rhea rejects
# it from the instance queue: the decision is instance-locked (H/age_gate.rs
# AgeGateReviewResponse.instance_locked), a second reject is 400 "Review is
# already rejected" (S/age_gate_service.rs:555-563), and the version stays
# blocked with 451 (decide_age_gate_check BlockRejected, :379-387).
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}" jwt:SEC_LEAD
mvn_up=$(cs_json '.upstream_url // empty'); mvn_up="${mvn_up%/}"
BOM=software/amazon/awssdk/bom
bom_ver=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" "${mvn_up}/${BOM}/maven-metadata.xml" 2>/dev/null \
  | tr -d '\n' | sed -n -e 's:.*<release>\([^<]*\)</release>.*:\1:p' -e 't' -e 's:.*<latest>\([^<]*\)</latest>.*:\1:p' | head -n1 || true)
if [ -z "$mvn_up" ] || [ -z "$bom_ver" ]; then
  cs_record "age-gate decision on the locked firmware remote" SKIP "upstream ${mvn_up:-?} metadata unreadable (no internet?)"
else
  bom_path="/maven/${HAL_REPO_FW_MAVEN_REMOTE}/${BOM}/${bom_ver}/bom-${bom_ver}.pom"
  cs_http GET "$bom_path" basic:SEC_LEAD
  if _status_is 200; then
    cs_record "age-gate decision on the locked firmware remote" SKIP "awssdk bom ${bom_ver} is already older than the gate (HTTP 200)"
  elif cs_expect "Rhea's pull of awssdk bom ${bom_ver} through the locked fw remote is age-gated (H/proxy_helpers.rs:9496-9541)" 451; then
    rid=$(cs_json '.review_id // empty')
    cs_http GET "/api/v1/admin/age-gate/reviews/${rid}" jwt:SEC_LEAD
    cs_expect "Rhea opens review ${rid} in the instance queue" 200
    st=$(cs_json '.status')
    if [ "$st" != "pending" ]; then
      # A previous run's decision on the same version: reopen it first.
      cs_http POST "/api/v1/admin/age-gate/reviews/${rid}/reopen" jwt:SEC_LEAD -H 'Content-Type: application/json' \
        -d '{"reason":"re-review on replay"}'
      cs_expect "Rhea reopens the earlier ${st} decision (replay)" 200
    fi
    cs_http POST "/api/v1/admin/age-gate/reviews/${rid}/approve" jwt:SEC_ANALYST -H 'Content-Type: application/json' \
      -d '{"reason":"looks fine"}'
    cs_expect "Omar cannot approve a review in the instance queue (admin_middleware, H/age_gate.rs:545)" 403
    cs_http POST "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate/reviews/${rid}/approve" jwt:SEC_ANALYST \
      -H 'Content-Type: application/json' -d '{"reason":"looks fine"}'
    cs_expect "Omar cannot approve it through the repo queue: 403, he reads the repo but is not its admin (H/age_gate.rs:257-265)" 403
    cs_http POST "/api/v1/admin/age-gate/reviews/${rid}/reject" jwt:SEC_LEAD -H 'Content-Type: application/json' \
      -d '{"reason":"Halcyon policy: no AWS SDK in firmware builds without a 7-day soak"}'
    if cs_expect "Rhea rejects the review (POST /admin/age-gate/reviews/{id}/reject)" 200; then
      got=$(cs_json '[.status, .instance_locked, .reviewed_by_username] | map(tostring) | join(",")')
      if [ "$got" = "rejected,true,${HAL_SEC_LEAD_USER}" ]; then
        cs_record "the rejection is instance-locked and attributed to Rhea (#4238)" PASS "$got"
      else
        cs_record "the rejection is instance-locked and attributed to Rhea (#4238)" FAIL "got ${got}" "$(_body)"
      fi
      cs_http POST "/api/v1/admin/age-gate/reviews/${rid}/reject" jwt:SEC_LEAD -H 'Content-Type: application/json' -d '{}'
      if cs_expect "rejecting it twice is refused (S/age_gate_service.rs:555-563)" 400; then
        cs_expect_body "second reject message" "Review is already rejected"
      fi
      cs_http GET "$bom_path" basic:SEC_LEAD
      if cs_expect "the rejected version stays blocked (BlockRejected, S/age_gate_service.rs:379-387)" 451; then
        if [ "$(cs_json '.review_id')" = "$rid" ]; then
          cs_record "the 451 names the same review" PASS "review ${rid}"
        else
          cs_record "the 451 names the same review" FAIL "review_id $(cs_json '.review_id'), want ${rid}" "$(_body)"
        fi
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 10. Restore the firmware Maven gate that firmware #10 tightened to 14 days.
#     Firmware #11 (Mara's relax to 7, expected 403) must run first, or her
#     PUT would no longer be a relaxation. Wait for fw-age-gate-relax-refused
#     (firmware signals it after #11), then PUT 7 days locked
#     (H/age_gate.rs:709-714).
# ---------------------------------------------------------------------------
fw_seen="barrier fw-age-gate-relax-refused"
cs_wait fw-age-gate-relax-refused "$BT" || fw_seen="no"
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate" jwt:SEC_LEAD
before="$(cs_json '"\(.min_age_days) days, locked=\(.instance_locked)"')"
if [ "$fw_seen" = "no" ]; then
  cs_record "waited for fw-age-gate-relax-refused (firmware #11)" FAIL \
    "${CS_WAIT_WHY}; restoring anyway (gate was ${before})"
fi
cs_http PUT "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate" jwt:SEC_LEAD -H 'Content-Type: application/json' \
  -d '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time","instance_locked":true}'
if cs_expect "#10 Rhea restores the firmware Maven gate to 7 days, locked (H/age_gate.rs:709-714)" 200 \
     "was ${before}; after ${fw_seen}"; then
  cs_http GET "/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate" jwt:SEC_LEAD
  got=$(cs_json '[.enabled, .min_age_days, .mode, .instance_locked] | map(tostring) | join(",")')
  if [ "$got" = "true,7,upstream_publish_time,true" ]; then
    cs_record "#10 the gate reads back as founded" PASS "$got"
  else
    cs_record "#10 the gate reads back as founded" FAIL "got ${got}" "$(_body)"
  fi
fi

# ---------------------------------------------------------------------------
# End of day: revoke Rhea's acknowledgement so a replay starts from an open
# finding (DELETE /security/findings/{id}/acknowledge, H/security.rs:2274).
# ---------------------------------------------------------------------------
if [ -n "$fid_ack" ]; then
  cs_http DELETE "/api/v1/security/findings/${fid_ack}/acknowledge?repository_id=${REPO_DL_ID}" jwt:SEC_LEAD
  if cs_expect "Rhea revokes her acknowledgement at the end of the day (H/security.rs:2274)" 200; then
    if [ "$(cs_json '.is_acknowledged')" = "false" ]; then
      cs_record "the finding is open again" PASS "finding ${fid_ack}"
    else
      cs_record "the finding is open again" FAIL "is_acknowledged=$(cs_json '.is_acknowledged')" "$(_body)"
    fi
  fi
fi

cs_end
