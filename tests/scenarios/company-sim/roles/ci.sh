#!/usr/bin/env bash
# roles/ci.sh - svc-${HAL}-ci, the Halcyon Robotics CI/CD service account.
#
# A merge pipeline: build -> publish (cargo, npm, pypi, maven, generic, OCI)
# -> resolve through the virtuals it is scoped to -> try to promote (refused,
# no promote:artifacts) -> the deploy token pulls the released chart and the
# image. Spec: ROLES.md "## ci".
#
# Credentials (personas.env): HAL_CI_TOKEN (read+write:artifacts, the 12 repos
# of HAL_CI_TOKEN_REPOS), HAL_DEPLOY_TOKEN (read:artifacts on ops-docker,
# ops-docker-local, ops-helm), HAL_CI_SA_USER. Persona key CI_SA resolves to
# HAL_CI_SA_USER, so "basictoken:CI_SA:HAL_CI_TOKEN" is Basic svc-...:<token>.
#
# The bootstrap admin is used only to (a) read back the token list for the
# expiry check, (b) mint and revoke a throwaway "${HAL}-ci-rotate" token on
# the service account for the revocation check (the CI cannot mint its own:
# /service-accounts/* is require_admin), and (c) delete CI's build artifacts
# after the CI token is refused (ROLES.md ci #12).
#
# Barriers awaited: fw-sdk-1.1.0 (firmware), ops-chart-released (security),
# then ops-image-pushed (devops) and ops-image-reviewed (security; both
# already reached by then). Their outcomes decide #10: SKIP when devops
# pushed no image, 403 when security left the block, 200 when it cleared it.
#
# Leftovers when the admin cleanup fails: artifacts named ${HAL}-ci-* in the
# CI publish repos (versions carry CI_BUILD, an epoch, so replays never clash).

source "$(dirname "$0")/../lib.sh"

cs_begin ci
auth_admin

CI_BUILD="${CI_BUILD:-$(date +%s)}"
CI_VER="1.0.${CI_BUILD}"
BARRIER_TIMEOUT="${CS_BARRIER_TIMEOUT:-600}"
_cs_work
REG_HOST="${BASE_URL#http://}"; REG_HOST="${REG_HOST#https://}"; REG_HOST="${REG_HOST%%/*}"

# Every artifact CI created, for the cleanup at the end: "KEY<TAB>PATH-QUERY".
declare -a CI_CREATED=()

body_code() { cs_json '.code // empty'; }

# The registry's token service name, from the /v2/ challenge (/v2/token
# answers 400 "service mismatch" for any other value, H/oci_v2.rs:5526-5530).
cs_http GET /v2/ none
OCI_SERVICE=$(cs_header www-authenticate | sed -n 's/.*service="\([^"]*\)".*/\1/p')
OCI_SERVICE="${OCI_SERVICE:-artifact-keeper}"

# ---------------------------------------------------------------------------
# 1. Token identity
# ---------------------------------------------------------------------------
cs_http GET /api/v1/users/me token:HAL_CI_TOKEN
if cs_expect "1 CI token identifies the service account (GET /users/me)" 200; then
  u=$(cs_json '.username'); sa=$(cs_json '.is_service_account')
  if [ "$u" = "$HAL_CI_SA_USER" ] && [ "$sa" = "true" ]; then
    cs_record "1 /users/me is ${HAL_CI_SA_USER}, is_service_account=true" PASS "username ${u}"
  else
    cs_record "1 /users/me is ${HAL_CI_SA_USER}, is_service_account=true" FAIL "username=${u} is_service_account=${sa}" "${CS_BODY:0:400}"
  fi
fi

# X-API-Key works on REST too (A:948, 600-607).
cs_http GET /api/v1/users/me none -H "X-API-Key: ${HAL_CI_TOKEN}"
cs_expect "1 X-API-Key header accepted on REST /users/me (A:948)" 200

# ---------------------------------------------------------------------------
# 2-3. Publish the merge build in every native format
# ---------------------------------------------------------------------------
CRATE="${HAL}-ci-build"
cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" "$CRATE" "$CI_VER" token:HAL_CI_TOKEN
cs_expect "2 publish crate ${CRATE} ${CI_VER} to fw-cargo-local (Bearer token)" 200 && CI_CREATED+=("${HAL_REPO_FW_CARGO_LOCAL}|${CRATE}")

NPM_PKG="${HAL}-ci-web"
cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" "$NPM_PKG" "$CI_VER" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "3 publish npm ${NPM_PKG}@${CI_VER} (Basic svc:token on native, A:1487-1508; npm publish answers 200)" 200 && CI_CREATED+=("${HAL_REPO_WEB_NPM_LOCAL}|${NPM_PKG}")

PYPI_PKG="${HAL}-ci-data"
cs_publish_pypi "$HAL_REPO_DATA_PYPI_LOCAL" "$PYPI_PKG" "$CI_VER" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "3 publish pypi ${PYPI_PKG} ${CI_VER} (Basic svc:token on native; H/pypi.rs upload answers 200)" 200 && CI_CREATED+=("${HAL_REPO_DATA_PYPI_LOCAL}|${PYPI_PKG//-/_}")

MVN_ART="${HAL}-ci-lib"
cs_put_maven "$HAL_REPO_FW_MAVEN_LOCAL" com/halcyon/ci "$MVN_ART" "$CI_VER" basictoken:CI_SA:HAL_CI_TOKEN
jar_status="$CS_STATUS"
if [ "$CS_POM_STATUS" = "201" ] && [ "$jar_status" = "201" ]; then
  cs_record "3 publish maven com.halcyon.ci:${MVN_ART}:${CI_VER} pom+jar (Basic svc:token)" PASS "pom 201, jar 201"
  CI_CREATED+=("${HAL_REPO_FW_MAVEN_LOCAL}|${MVN_ART}")
else
  cs_record "3 publish maven com.halcyon.ci:${MVN_ART}:${CI_VER} pom+jar (Basic svc:token)" FAIL \
    "expected pom 201 and jar 201, got pom ${CS_POM_STATUS} jar ${jar_status}" "${CS_BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# 4-5. Generic build artifacts over REST: Bearer, then X-API-Key
# ---------------------------------------------------------------------------
BIN="${CS_WORK}/ci-build.bin"
cs_fixture_bytes "$BIN" 65536 "${HAL}-ci-${CI_BUILD}"
BIN_SHA=$(sha256sum "$BIN" | cut -d' ' -f1)
GEN1="${HAL}-ci/build-${CI_BUILD}.bin"
GEN2="${HAL}-ci/build-${CI_BUILD}-apikey.bin"
GEN1_ID=""

cs_put_generic "$HAL_REPO_OPS_BUILDS" "$GEN1" "$BIN" token:HAL_CI_TOKEN
if cs_expect "4 REST upload ${GEN1} to ops-builds (Bearer token)" 201; then
  GEN1_ID=$(cs_json '.id // .artifact.id // empty')
  CI_CREATED+=("${HAL_REPO_OPS_BUILDS}|${GEN1}")
fi

cs_http PUT "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/artifacts/${GEN2}" none \
  -H "X-API-Key: ${HAL_CI_TOKEN}" -H 'Content-Type: application/octet-stream' --data-binary "@${BIN}"
cs_expect "5 REST upload ${GEN2} with X-API-Key (A:948, 600-607)" 201 && CI_CREATED+=("${HAL_REPO_OPS_BUILDS}|${GEN2}")

# Download it back: Basic svc:token is accepted on the REST download route.
cs_http GET "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/download/${GEN1}" basictoken:CI_SA:HAL_CI_TOKEN
if cs_expect "5 download ${GEN1} with Basic svc:token (download route accepts it, A:1890-1897)" 200; then
  got=$(sha256sum "$CS_BODY_FILE" | cut -d' ' -f1)
  if [ "$got" = "$BIN_SHA" ]; then
    cs_record "5 downloaded build bytes match the upload (sha256)" PASS "${got:0:16}"
  else
    cs_record "5 downloaded build bytes match the upload (sha256)" FAIL "sha256 ${got} != ${BIN_SHA}"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Resolve through the virtuals the token is scoped to (VIS "Tokens scoped
#    to a virtual"): the day-0 seeds and this build's own packages.
# ---------------------------------------------------------------------------
MVN_SEED="/maven/${HAL_REPO_FW_MAVEN}/${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/${HAL_SEED_MAVEN_VERSION}/${HAL_SEED_MAVEN_ARTIFACT}-${HAL_SEED_MAVEN_VERSION}.jar"
cs_http GET "$MVN_SEED" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "6 resolve day-0 hal-sdk 1.0.0 jar through fw-maven virtual" 200

cs_http GET "/npm/${HAL_REPO_WEB_NPM}/${HAL_SEED_NPM}" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "6 resolve day-0 ${HAL_SEED_NPM} metadata through web-npm virtual" 200 && \
  cs_expect_body "6 web-npm virtual metadata lists ${HAL_SEED_NPM_VERSION}" "\"${HAL_SEED_NPM_VERSION}\""

cs_http GET "/pypi/${HAL_REPO_DATA_PYPI}/simple/${HAL_SEED_PYPI}/" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "6 resolve day-0 ${HAL_SEED_PYPI} simple index through data-pypi virtual" 200 && \
  cs_expect_body "6 data-pypi virtual simple index lists ${HAL_SEED_PYPI_VERSION}" "${HAL_SEED_PYPI_VERSION}"

cs_http GET "/cargo/${HAL_REPO_FW_CARGO}/api/v1/crates/${CRATE}/${CI_VER}/download" token:HAL_CI_TOKEN
cs_expect "6 download this build's crate through fw-cargo virtual" 200

cs_http GET "/npm/${HAL_REPO_WEB_NPM}/${NPM_PKG}" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "6 this build's npm package visible through web-npm virtual" 200 && \
  cs_expect_body "6 web-npm virtual lists ${NPM_PKG}@${CI_VER}" "\"${CI_VER}\""

cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/com/halcyon/ci/${MVN_ART}/${CI_VER}/${MVN_ART}-${CI_VER}.pom" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "6 this build's pom through fw-maven virtual" 200

# ---------------------------------------------------------------------------
# Promote: the token has no promote:artifacts (admin-only to mint), so the
# staging -> release step is refused (H/promotion.rs:551-559, 681-686).
# ---------------------------------------------------------------------------
if [ -n "$GEN1_ID" ]; then
  cs_http POST "/api/v1/promotion/repositories/${HAL_REPO_OPS_BUILDS}/artifacts/${GEN1_ID}/promote" token:HAL_CI_TOKEN \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg t "$HAL_REPO_HANDBOOK" '{target_repository:$t}')"
  cs_expect "promote build without promote:artifacts is refused (H/promotion.rs:551-559)" 403 && \
    cs_expect_body "promote refusal names promote:artifacts" "promote:artifacts"
else
  cs_record "promote build without promote:artifacts is refused" SKIP "no artifact id from the upload in #4"
fi

# ---------------------------------------------------------------------------
# 8. Push an image with docker login svc-... + token
# ---------------------------------------------------------------------------
IMG="${REG_HOST}/${HAL_REPO_OPS_DOCKER_LOCAL}/${HAL}-ci-app:${CI_BUILD}"
IMG_PUSHED=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  export DOCKER_CONFIG="${CS_WORK}/docker"
  mkdir -p "$DOCKER_CONFIG" "${CS_WORK}/img"
  printf 'halcyon ci build %s\n' "$CI_BUILD" > "${CS_WORK}/img/build.txt"
  printf 'FROM scratch\nCOPY build.txt /build.txt\n' > "${CS_WORK}/img/Dockerfile"
  if printf '%s' "$HAL_CI_TOKEN" | docker login "$REG_HOST" -u "$HAL_CI_SA_USER" --password-stdin >"${CS_WORK}/dl.log" 2>&1; then
    cs_record "8 docker login ${REG_HOST} as ${HAL_CI_SA_USER} with the CI token" PASS "/v2/token Basic svc:token (H/oci_v2.rs:5785-5790)"
    if docker build -q -t "$IMG" "${CS_WORK}/img" >"${CS_WORK}/db.log" 2>&1 && \
       docker push "$IMG" >"${CS_WORK}/dp.log" 2>&1; then
      IMG_PUSHED=true
      cs_record "8 docker push ${HAL}-ci-app:${CI_BUILD} to ops-docker-local" PASS "H/oci_v2.rs:638-660"
      CI_CREATED+=("${HAL_REPO_OPS_DOCKER_LOCAL}|${HAL}-ci-app")
    else
      cs_record "8 docker push ${HAL}-ci-app:${CI_BUILD} to ops-docker-local" FAIL "build/push failed" \
        "$(tail -n 5 "${CS_WORK}/db.log" "${CS_WORK}/dp.log" 2>/dev/null)"
    fi
    docker rmi "$IMG" >/dev/null 2>&1 || true
  else
    cs_record "8 docker login ${REG_HOST} as ${HAL_CI_SA_USER} with the CI token" FAIL "docker login failed" "$(tail -n 5 "${CS_WORK}/dl.log")"
  fi
else
  cs_record "8 docker push with the CI token" SKIP "docker client/daemon not available"
fi

# OCI pull of CI's own image through the docker virtual with the CI token.
if $IMG_PUSHED; then
  cs_http GET "/v2/token?service=${OCI_SERVICE}&scope=repository:${HAL_REPO_OPS_DOCKER}/${HAL}-ci-app:pull" basictoken:CI_SA:HAL_CI_TOKEN
  tok=$(cs_json '.token // .access_token // empty')
  cs_http GET "/v2/${HAL_REPO_OPS_DOCKER}/${HAL}-ci-app/manifests/${CI_BUILD}" none \
    -H "Authorization: Bearer ${tok}" \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
  cs_expect "8 CI reads its image manifest back through the ops-docker virtual" 200
fi

# ---------------------------------------------------------------------------
# 11. Repository listing with the CI token is exactly its scoped set
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories?per_page=100" token:HAL_CI_TOKEN
if cs_expect "11 list repositories with the CI token" 200; then
  want=$(for n in $HAL_CI_TOKEN_REPOS; do v="HAL_REPO_${n}"; printf '%s\n' "${!v}"; done | sort | jq -R . | jq -sc .)
  have=$(cs_json '[(.items // .)[]?.key] | sort | tostring')
  if [ "$have" = "$want" ]; then
    cs_record "11 listing is exactly the 12 repos of HAL_CI_TOKEN_REPOS (handbook drops out, RS:351-356)" PASS "$(jq -r 'length' <<<"$have") repos"
  else
    extra=$(jq -nc --argjson h "$have" --argjson w "$want" '$h - $w')
    missing=$(jq -nc --argjson h "$have" --argjson w "$want" '$w - $h')
    cs_record "11 listing is exactly the 12 repos of HAL_CI_TOKEN_REPOS (handbook drops out, RS:351-356)" FAIL \
      "extra ${extra} missing ${missing}"
  fi
fi

# ---------------------------------------------------------------------------
# 7. Wait for firmware's SDK 1.1.0 and resolve it through the virtual
# ---------------------------------------------------------------------------
if cs_wait fw-sdk-1.1.0 "$BARRIER_TIMEOUT"; then
  cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/1.1.0/${HAL_SEED_MAVEN_ARTIFACT}-1.1.0.jar" basictoken:CI_SA:HAL_CI_TOKEN
  cs_expect "7 resolve hal-sdk 1.1.0 jar through fw-maven virtual" 200
  cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${HAL_SEED_MAVEN_GROUP}/${HAL_SEED_MAVEN_ARTIFACT}/1.1.0/${HAL_SEED_MAVEN_ARTIFACT}-1.1.0.pom" basictoken:CI_SA:HAL_CI_TOKEN
  cs_expect "7 resolve hal-sdk 1.1.0 pom through fw-maven virtual" 200
else
  cs_record "waited for fw-sdk-1.1.0 (firmware publishes hal-sdk 1.1.0)" FAIL "${CS_WAIT_WHY}"
fi

# ---------------------------------------------------------------------------
# Should NOT work
# ---------------------------------------------------------------------------
# Conda local is deliberately outside the CI token's list: 404, not 403.
printf 'not a real conda package\n' > "${CS_WORK}/ci.tar.bz2"
cs_put_generic "$HAL_REPO_DATA_CONDA_LOCAL" "noarch/${HAL}-ci-leak-${CI_BUILD}.tar.bz2" "${CS_WORK}/ci.tar.bz2" token:HAL_CI_TOKEN
cs_expect "NOT: CI token REST PUT to data-conda-local (outside token list) is 404 (RS:99-107, 149-178)" 404 && \
  { [ "$(body_code)" = "NOT_FOUND" ] && cs_record "NOT: conda-local refusal body is code NOT_FOUND" PASS "${CS_BODY:0:120}" \
    || cs_record "NOT: conda-local refusal body is code NOT_FOUND" FAIL "code=$(body_code)" "${CS_BODY:0:300}"; }

# Same on the native conda route.
cs_http PUT "/conda/${HAL_REPO_DATA_CONDA_LOCAL}/noarch/${HAL}-ci-leak-${CI_BUILD}.tar.bz2" basictoken:CI_SA:HAL_CI_TOKEN \
  -H 'Content-Type: application/octet-stream' --data-binary "@${CS_WORK}/ci.tar.bz2"
cs_expect "NOT: CI token native conda PUT to data-conda-local is 404 Repository not found (A:3324-3335)" 404

# Basic svc:token on REST is refused (#2806).
cs_put_generic "$HAL_REPO_OPS_BUILDS" "${HAL}-ci/basic-${CI_BUILD}.bin" "$BIN" basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "NOT: Basic svc:token on REST PUT .../artifacts is 401 (#2806, A:1012-1021)" 401
cs_http GET /api/v1/users/me basictoken:CI_SA:HAL_CI_TOKEN
cs_expect "NOT: Basic svc:token on REST GET /users/me is 401 (#2806)" 401

# Deploy token is read-only.
cs_put_generic "$HAL_REPO_OPS_HELM" "${HAL}-ci/deploy-write-${CI_BUILD}.tgz" "$BIN" token:HAL_DEPLOY_TOKEN
cs_expect "NOT: deploy token REST PUT to ops-helm is 403 (read:artifacts only)" 403 && \
  cs_expect_body "NOT: deploy token ops-helm refusal names write:artifacts" "Token does not have required scope: write:artifacts"
cs_put_generic "$HAL_REPO_OPS_BUILDS" "${HAL}-ci/deploy-write-${CI_BUILD}.bin" "$BIN" token:HAL_DEPLOY_TOKEN
cs_expect "NOT: deploy token REST PUT to ops-builds (outside its list) is 403, scope check first (checked live on dev)" 403 && \
  cs_expect_body "NOT: deploy token ops-builds refusal names write:artifacts" "Token does not have required scope: write:artifacts"
printf 'apiVersion: v2\n' > "${CS_WORK}/deploy-chart.tgz"
cs_http POST "/helm/${HAL_REPO_OPS_HELM}/api/charts" basictoken:CI_SA:HAL_DEPLOY_TOKEN -F "chart=@${CS_WORK}/deploy-chart.tgz"
cs_expect "NOT: deploy token native helm upload to ops-helm is 403 (A:425-441)" 403 && \
  cs_expect_body "NOT: deploy token native helm refusal names write:artifacts" "write:artifacts"

# Members are reachable only through the scoped virtual.
cs_http GET "/cargo/${HAL_REPO_FW_CARGO_REMOTE}/config.json" token:HAL_CI_TOKEN
cs_expect "NOT: CI token reads fw-cargo-remote directly (member outside its list) is 404 (VIS)" 404

# No bare 'write' scope: group creation refused.
cs_http POST /api/v1/groups token:HAL_CI_TOKEN -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "${HAL}-ci-group" '{name:$n,description:"should not exist"}')"
cs_expect "NOT: CI token creates a group is 403 (bare write scope, H/groups.rs:369)" 403

# ---------------------------------------------------------------------------
# Token expiry and revocation
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/service-accounts/${HAL_CI_SA_ID}/tokens" admin
if cs_expect "expiry: admin reads back the CI service account's tokens" 200; then
  for tn in "${HAL}-ci-publish" "${HAL}-deploy-pull"; do
    row=$(cs_json "[.items[]? | select(.name==\"${tn}\")] | sort_by(.created_at) | last // empty")
    if [ -z "$row" ]; then
      cs_record "expiry: ${tn} expires 30 days after creation" FAIL "token ${tn} not in the list"
      continue
    fi
    days=$(jq -r '((.expires_at // "" | sub("\\.[0-9]+";"") | fromdateiso8601? ) // 0) as $e
                  | ((.created_at | sub("\\.[0-9]+";"") | fromdateiso8601?) // 0) as $c
                  | if $e == 0 then "none" else (($e - $c) / 86400 | round) end' <<<"$row")
    exp=$(jq -r '.is_expired' <<<"$row")
    if [ "$days" = "30" ] && [ "$exp" = "false" ]; then
      cs_record "expiry: ${tn} expires 30 days after creation, not expired" PASS "expires_at $(jq -r .expires_at <<<"$row")"
    else
      cs_record "expiry: ${tn} expires 30 days after creation, not expired" FAIL "days=${days} is_expired=${exp}" "$row"
    fi
  done
fi

ROT_TOKEN=""
# Priya (the platform admin) mints and revokes the short-lived token: service
# account tokens are an instance-admin operation, not something CI does.
cs_http POST "/api/v1/service-accounts/${HAL_CI_SA_ID}/tokens" jwt:PADMIN -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "${HAL}-ci-rotate" --arg r "$HAL_REPO_OPS_BUILDS_ID" \
        '{name:$n,scopes:["read:artifacts"],repository_ids:[$r],expires_in_days:1}')"
ROT_ID=$(cs_json '.id // empty'); ROT_TOKEN=$(cs_json '.token // empty')
if [ -n "$ROT_TOKEN" ]; then
  cs_http GET /api/v1/users/me token:ROT_TOKEN
  cs_expect "revocation: fresh rotate token works before revocation" 200
  cs_http DELETE "/api/v1/service-accounts/${HAL_CI_SA_ID}/tokens/${ROT_ID}" jwt:PADMIN
  cs_expect "revocation: Priya revokes ${HAL}-ci-rotate (204 No Content)" 204
  cs_http GET /api/v1/users/me token:ROT_TOKEN
  cs_expect "revocation: revoked token on REST /users/me is 401 (A:1807-1817)" 401
  cs_http GET "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/download/${GEN1}" token:ROT_TOKEN
  cs_expect "revocation: revoked token on REST download is 401, no anonymous downgrade (#1371)" 401
  cs_http GET "/general/${HAL_REPO_OPS_BUILDS}/${GEN1}" basictoken:CI_SA:ROT_TOKEN
  cs_expect "revocation: revoked token (Basic) on native /general is 401 (A:3203-3207)" 401
  cs_http GET "/v2/token?service=${OCI_SERVICE}&scope=repository:${HAL_REPO_OPS_DOCKER}/x:pull" basictoken:CI_SA:ROT_TOKEN
  cs_expect "revocation: revoked token on /v2/token is 401 (H/oci_v2.rs)" 401
else
  cs_record "revocation: mint throwaway rotate token" FAIL "HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
fi
# A token that never existed is 401 too, never anonymous.
# shellcheck disable=SC2034  # read through cs_http token:BOGUS_TOKEN
BOGUS_TOKEN="akt_$(printf '%s' "$CI_BUILD" | sha256sum | cut -c1-40)"
cs_http GET "/cargo/${HAL_REPO_FW_CARGO_LOCAL}/config.json" token:BOGUS_TOKEN
cs_expect "revocation: unknown token on a native route is 401 (A:3203-3207)" 401

# ---------------------------------------------------------------------------
# 9-10. Deploy: wait for the released chart, pull chart and image
# ---------------------------------------------------------------------------
if cs_wait ops-chart-released "$BARRIER_TIMEOUT"; then
  cs_http GET "/helm/${HAL_REPO_OPS_HELM}/index.yaml" basictoken:CI_SA:HAL_DEPLOY_TOKEN
  if cs_expect "9 deploy token reads ops-helm index.yaml" 200; then
    chart_url=$(printf '%s\n' "$CS_BODY" | grep -E "^\s*-\s*\S*${HAL}-ops-app-[^/]*\.tgz" | head -n1 | sed -E 's/^\s*-\s*//; s/["'\'' ]//g')
    if [ -z "$chart_url" ]; then
      cs_record "9 index.yaml lists the released ${HAL}-ops-app chart" FAIL "no ${HAL}-ops-app url in index" "${CS_BODY:0:600}"
    else
      cs_record "9 index.yaml lists the released ${HAL}-ops-app chart" PASS "$chart_url"
      case "$chart_url" in
        http://*|https://*) cpath="$chart_url" ;;
        /*) cpath="$chart_url" ;;
        *) cpath="/helm/${HAL_REPO_OPS_HELM}/${chart_url}" ;;
      esac
      cs_http GET "$cpath" basictoken:CI_SA:HAL_DEPLOY_TOKEN
      cs_expect "9 deploy token downloads the released chart" 200
    fi
  fi
else
  cs_record "waited for ops-chart-released (security releases devops's chart)" FAIL "${CS_WAIT_WHY}"
fi

# 10: the image devops pushed, read with the deploy token through the virtual.
# Security's ops-image-reviewed outcome says whether every finding was
# acknowledged (ROLES.md security #8), as for devops.sh #5. Security
# signals it before it releases the chart, so after ops-chart-released this
# wait returns at once. devops deletes and re-pushes the image at the start
# of every run, so ci waits for this run's ops-image-pushed first.
if cs_wait ops-image-pushed "$BARRIER_TIMEOUT" && [ "$(cs_signal_outcome ops-image-pushed)" = "none" ]; then
  cs_record "10 deploy token reads the devops image" SKIP "devops pushed no image this run (ops-image-pushed outcome 'none')"
elif [ -z "$CS_WAIT_WHY" ]; then
  want=403; why="criticals left open"
  if cs_wait ops-image-reviewed "$BARRIER_TIMEOUT"; then
    # Security's outcome (ROLES.md security #8): blocked | cleared | none.
    [ "$(cs_signal_outcome ops-image-reviewed)" = "cleared" ] && { want=200; why="security acknowledged every finding"; }
    echo "  security outcome: $(cs_signal_outcome ops-image-reviewed) -> expect ${want}"
  else
    cs_record "waited for ops-image-reviewed (security)" FAIL "${CS_WAIT_WHY}; #10 assumes no acknowledgement"
  fi
  cs_http GET "/v2/token?service=${OCI_SERVICE}&scope=repository:${HAL_REPO_OPS_DOCKER}/${HAL}-ops-base:pull" basictoken:CI_SA:HAL_DEPLOY_TOKEN
  cs_expect "10 deploy token obtains a /v2/token pull token" 200
  tok=$(cs_json '.token // .access_token // empty')
  cs_http GET "/v2/${HAL_REPO_OPS_DOCKER}/${HAL}-ops-base/manifests/1" none \
    -H "Authorization: Bearer ${tok}" \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
  if cs_expect "10 deploy token reads ${HAL}-ops-base:1 through ops-docker virtual (${why}; #4510)" "$want" && [ "$want" = 403 ]; then
    cs_expect_body "10 refusal is the scan-policy hold (HOLDS:11-19)" "blocked by the repository's scan policy"
  fi
else
  cs_record "waited for ops-image-pushed (devops)" FAIL "${CS_WAIT_WHY}; #10 not run"
fi

# Deploy token on CI's own image (read:artifacts on the docker virtual).
if $IMG_PUSHED; then
  cs_http GET "/v2/token?service=${OCI_SERVICE}&scope=repository:${HAL_REPO_OPS_DOCKER}/${HAL}-ci-app:pull" basictoken:CI_SA:HAL_DEPLOY_TOKEN
  tok=$(cs_json '.token // .access_token // empty')
  cs_http GET "/v2/${HAL_REPO_OPS_DOCKER}/${HAL}-ci-app/manifests/${CI_BUILD}" none \
    -H "Authorization: Bearer ${tok}" \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
  cs_expect "10 deploy token pulls CI's clean image through ops-docker virtual" 200
fi

# ---------------------------------------------------------------------------
# 12. Clean up: the CI token cannot delete; the admin does it
# ---------------------------------------------------------------------------
if [ -n "$GEN1_ID" ] || printf '%s\n' "${CI_CREATED[@]}" | grep -qF "$GEN1"; then
  cs_http DELETE "/api/v1/repositories/${HAL_REPO_OPS_BUILDS}/artifacts/${GEN1}" token:HAL_CI_TOKEN
  cs_expect "12 CI token deletes its build artifact: 403 (no delete:artifacts)" 403 && \
    cs_expect_body "12 refusal is 'Token does not have required scope: delete:artifacts'" "Token does not have required scope: delete:artifacts"
fi

clean_fail=""
for entry in "${CI_CREATED[@]}"; do
  key="${entry%%|*}"; q="${entry#*|}"
  cs_http GET "/api/v1/repositories/${key}/artifacts?q=$(jq -rn --arg q "$q" '$q|@uri')&per_page=200" admin
  mapfile -t paths < <(cs_json '.items[]?.path' | grep -F -- "$q" || true)
  if [ "${#paths[@]}" -eq 0 ]; then clean_fail+=" ${key}:${q}(not listed)"; continue; fi
  for p in "${paths[@]}"; do
    cs_http DELETE "/api/v1/repositories/${key}/artifacts/${p}" admin
    [ "${CS_STATUS:0:1}" = "2" ] || clean_fail+=" ${key}/${p}=${CS_STATUS}"
  done
done
if [ -z "$clean_fail" ]; then
  cs_record "12 admin deletes CI's build artifacts" PASS "${#CI_CREATED[@]} packages"
else
  cs_record "12 admin deletes CI's build artifacts" FAIL "not deleted:${clean_fail}"
fi

cs_end
