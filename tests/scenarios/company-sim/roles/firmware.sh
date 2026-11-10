#!/usr/bin/env bash
# roles/firmware.sh - Mara Okafor (firmware lead) and Tomas Berg (firmware
# engineer) at Halcyon Robotics. ROLES.md "## firmware".
#
# Tomas ships SDK 1.1.0 (maven) and a crate (cargo) with his personal token.
# Mara administers the department through her project admin grant: she
# operates the instance-locked Maven age gate, lists, deletes and creates
# department repositories.
#
# Barriers: signals `fw-sdk-1.1.0` (contractor, ci and auditor wait on it)
# and `fw-age-gate-relax-refused` after #11 (security #10 waits on it).
# Waits on nothing.
#
# Real clients (optional, each block SKIPs when the client is missing):
#   cargo  resolves the new crate through the cargo virtual (sparse index,
#          raw-token Authorization) and publishes a second crate;
#   mvn    deploys a fresh coordinate with deploy:deploy-file and resolves
#          hal-sdk 1.1.0 through the maven virtual with dependency:get.
#
# Replays: a run stamp (FW_STAMP, seconds since the epoch) goes into every
# version this role publishes except hal-sdk 1.1.0, which other roles consume
# by that exact version. hal-sdk 1.1.0 is check-then-publish: a released
# Maven coordinate is immutable and a non-admin cannot delete it
# (repositories.rs delete_blocked_by_immutability), so on a replay the
# publish check SKIPs and the re-deploy check (#4) still runs.
#
# Left behind on purpose (Mara may not delete released Maven artifacts):
#   com/halcyon/fw/hal-sdk/1.1.0           (shared with other roles)
#   com/halcyon/fw/hal-fw-tools/1.0.<stamp> (curl deploy, one per run)
#   com/halcyon/fw/hal-fw-cli/1.0.<stamp>   (mvn deploy-file, one per run)
# The age gate on fw-maven-remote is left at 14 days: only an instance admin
# may relax a locked gate; security #10 restores it to 7.
#
# Run alone (after the founder):
#   bash tests/scenarios/company-sim/run-roles.sh --only firmware

source "$(dirname "$0")/../lib.sh"

cs_begin firmware
# Barriers this role signals: released as "failed" if it exits early.
cs_signals fw-sdk-1.1.0 fw-age-gate-relax-refused

FW_STAMP="${FW_STAMP:-$(date +%s)}"
G="com/halcyon/fw"
UP_MAVEN="${HAL_UPSTREAM_MAVEN:-https://repo1.maven.org/maven2}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# _fw_sparse_path NAME - cargo sparse index path for a crate name.
_fw_sparse_path() {
  local n="$1"
  case ${#n} in
    1|2) printf '%s/%s' "${#n}" "$n" ;;
    3)   printf '3/%s/%s' "${n:0:1}" "$n" ;;
    *)   printf '%s/%s/%s' "${n:0:2}" "${n:2:2}" "$n" ;;
  esac
}

# _fw_body_sha - sha256 of the exact bytes of the last cs_http body.
_fw_body_sha() { sha256sum "$CS_BODY_FILE" 2>/dev/null | cut -d' ' -f1; }

# _fw_upstream_up URL - can this runner reach the upstream at all?
_fw_upstream_up() {
  local c
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$1" 2>/dev/null || true)
  [ "$c" = "200" ]
}

# _fw_list_repo_keys AUTH - every repository key the caller can list (all pages).
_fw_list_repo_keys() {
  local auth="$1" page=1 pages=1 out=""
  FW_LIST_STATUS=""
  while [ "$page" -le "$pages" ]; do
    cs_http GET "/api/v1/repositories?per_page=100&page=${page}" "$auth"
    FW_LIST_STATUS="$CS_STATUS"
    [ "$CS_STATUS" = "200" ] || break
    out+=$(cs_json '.items[]?.key')$'\n'
    pages=$(cs_json '.pagination.total_pages // 1')
    [[ "$pages" =~ ^[0-9]+$ ]] || pages=1
    page=$(( page + 1 ))
    [ "$page" -le 50 ] || break
  done
  FW_LIST_KEYS=$(printf '%s' "$out" | sed '/^$/d' | sort -u)
}

# ---------------------------------------------------------------------------
# Morning: both sign in
# ---------------------------------------------------------------------------
for p in FW_DEV FW_LEAD; do
  if cs_login "$p"; then
    cs_record "$(cs_user "$p") signs in" PASS "JWT issued"
  else
    cs_record "$(cs_user "$p") signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
    cs_end
  fi
done

# ---------------------------------------------------------------------------
# 1. Tomas resolves the day-0 SDK through the virtual (group read on all three
#    through the project grant; repository-visibility.md "Reading through a
#    virtual").
# ---------------------------------------------------------------------------
cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${G}/hal-sdk/1.0.0/hal-sdk-1.0.0.jar" basic:FW_DEV
if cs_expect "1 Tomas resolves day-0 hal-sdk 1.0.0 jar through ${HAL_REPO_FW_MAVEN}" 200; then
  want=$(printf 'PK-halcyon-hal-sdk-1.0.0\n' | sha256sum | cut -d' ' -f1)
  if [ "$(_fw_body_sha)" = "$want" ]; then
    cs_record "1 the jar through the virtual is the day-0 bytes" PASS "sha256 ${want:0:12}"
  else
    cs_record "1 the jar through the virtual is the day-0 bytes" FAIL \
      "sha256 $(_fw_body_sha) != ${want} (${CS_LAST_REQ})" "${CS_BODY:0:200}"
  fi
fi

# ---------------------------------------------------------------------------
# 2. An old upstream pom through the virtual (not age-gated: published 2021).
# ---------------------------------------------------------------------------
UPSTREAM_OK=false
_fw_upstream_up "${UP_MAVEN}/junit/junit/4.13.2/junit-4.13.2.pom" && UPSTREAM_OK=true
if $UPSTREAM_OK; then
  cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/junit/junit/4.13.2/junit-4.13.2.pom" basic:FW_DEV
  cs_expect "2 Tomas pulls upstream junit 4.13.2 pom through ${HAL_REPO_FW_MAVEN}" 200 \
    && cs_expect_body "2 the proxied pom is junit's" "<artifactId>junit</artifactId>"
else
  cs_record "2 Tomas pulls upstream junit 4.13.2 pom through ${HAL_REPO_FW_MAVEN}" SKIP \
    "upstream ${UP_MAVEN} unreachable from this runner"
fi

# ---------------------------------------------------------------------------
# 3. Tomas publishes hal-sdk 1.1.0 with his personal token (Basic user:token
#    on the native route; maven.rs:4606 requires write:artifacts).
#    Check-then-publish: see the header comment.
# ---------------------------------------------------------------------------
SDK11="/maven/${HAL_REPO_FW_MAVEN_LOCAL}/${G}/hal-sdk/1.1.0/hal-sdk-1.1.0"
SDK11_SHA=$(printf 'PK-halcyon-hal-sdk-1.1.0\n' | sha256sum | cut -d' ' -f1)
cs_http GET "${SDK11}.jar" basic:FW_DEV
if [ "$CS_STATUS" = "200" ]; then
  if [ "$(_fw_body_sha)" = "$SDK11_SHA" ]; then
    cs_record "3 Tomas publishes hal-sdk 1.1.0 (pom + jar 201)" SKIP \
      "already published by an earlier run with the same bytes; a released Maven version is immutable and only an admin may delete it (repositories.rs:13845-13856), so a replay cannot publish it again"
  else
    cs_record "3 Tomas publishes hal-sdk 1.1.0 (pom + jar 201)" FAIL \
      "hal-sdk 1.1.0 already exists with bytes this scenario did not write (sha256 $(_fw_body_sha))" "${CS_BODY:0:200}"
  fi
elif [ "$CS_STATUS" = "404" ]; then
  cs_put_maven "$HAL_REPO_FW_MAVEN_LOCAL" "$G" hal-sdk 1.1.0 basictoken:FW_DEV:HAL_FW_DEV_TOKEN
  if [ "$CS_POM_STATUS" = "201" ] && [ "$CS_STATUS" = "201" ]; then
    cs_record "3 Tomas publishes hal-sdk 1.1.0 (pom + jar 201)" PASS "pom ${CS_POM_STATUS}, jar ${CS_STATUS} (maven.rs:4704-4707)"
  else
    cs_record "3 Tomas publishes hal-sdk 1.1.0 (pom + jar 201)" FAIL \
      "pom ${CS_POM_STATUS}, jar ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:400}"
  fi
else
  cs_record "3 Tomas publishes hal-sdk 1.1.0 (pom + jar 201)" FAIL \
    "pre-check GET answered ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:300}"
fi
cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${G}/hal-sdk/1.1.0/hal-sdk-1.1.0.jar" basic:FW_DEV
cs_expect "3 hal-sdk 1.1.0 resolves through ${HAL_REPO_FW_MAVEN}" 200
cs_signal "fw-sdk-1.1.0"

# A fresh coordinate every run, so the deploy path is exercised on replays too.
TOOLS_VER="1.0.${FW_STAMP}"
cs_put_maven "$HAL_REPO_FW_MAVEN_LOCAL" "$G" hal-fw-tools "$TOOLS_VER" basictoken:FW_DEV:HAL_FW_DEV_TOKEN
if [ "$CS_POM_STATUS" = "201" ] && [ "$CS_STATUS" = "201" ]; then
  cs_record "3 Tomas deploys a fresh coordinate hal-fw-tools ${TOOLS_VER} (pom + jar 201)" PASS "pom ${CS_POM_STATUS}, jar ${CS_STATUS}"
else
  cs_record "3 Tomas deploys a fresh coordinate hal-fw-tools ${TOOLS_VER} (pom + jar 201)" FAIL \
    "pom ${CS_POM_STATUS}, jar ${CS_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:400}"
fi

# ---------------------------------------------------------------------------
# 4. Re-deploying a released version. VERIFY pinned: maven.rs:4801-4805, a
#    non-SNAPSHOT coordinate with a live row answers 409
#    AppError::Conflict("Artifact already exists").
# ---------------------------------------------------------------------------
_cs_work
printf 'PK-halcyon-hal-sdk-1.1.0\n' > "${CS_WORK}/sdk-redeploy.jar"
cs_http PUT "${SDK11}.jar" basictoken:FW_DEV:HAL_FW_DEV_TOKEN \
  -H 'Content-Type: application/octet-stream' --data-binary "@${CS_WORK}/sdk-redeploy.jar"
cs_expect "4 re-deploying released hal-sdk-1.1.0.jar is refused (maven.rs:4803-4805)" 409 \
  && cs_expect_body "4 the refusal says the artifact already exists" "Artifact already exists"

# Extra: Mara (project admin, delete grant) cannot delete a released Maven
# jar. Non-admin deletes of immutable coordinates answer 409
# (repositories.rs:13845-13856 delete_blocked_by_immutability).
cs_http DELETE "/api/v1/repositories/${HAL_REPO_FW_MAVEN_LOCAL}/artifacts/${G}/hal-fw-tools/${TOOLS_VER}/hal-fw-tools-${TOOLS_VER}.jar" jwt:FW_LEAD
cs_expect "4 Mara cannot delete a released Maven jar (immutable, repositories.rs:13852)" 409 \
  && cs_expect_body "4 the refusal names immutability" "Cannot delete an immutable/released artifact"

# ---------------------------------------------------------------------------
# 5-8. The crate. cs_publish_cargo builds a new gzip each run (gzip mtime), so
#      the version carries the run stamp: a soft-deleted crate version cannot
#      be re-published with different bytes (handlers/mod.rs:206-218).
# ---------------------------------------------------------------------------
CRATE="${HAL}-fw-motor-ctl"
CRATE_VER="0.1.${FW_STAMP}"
CRATE_PATH="${CRATE}/${CRATE_VER}/${CRATE}-${CRATE_VER}.crate"
cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" "$CRATE" "$CRATE_VER" token:HAL_FW_DEV_TOKEN
CRATE_OK=false
if cs_expect "5 Tomas publishes crate ${CRATE} ${CRATE_VER} with his token as Bearer (cargo.rs:1865-1961)" 200; then
  CRATE_OK=true
  if [ "$(cs_json '.warnings | type')" = "object" ]; then
    cs_record "5 the publish answer carries a warnings object" PASS "$(cs_json '.warnings | keys | join(",")')"
  else
    cs_record "5 the publish answer carries a warnings object" FAIL "body: ${CS_BODY:0:200}" "$CS_BODY"
  fi
fi

INDEX_PATH="/cargo/${HAL_REPO_FW_CARGO}/index/$(_fw_sparse_path "$CRATE")"
cs_http GET "$INDEX_PATH" token:HAL_FW_DEV_TOKEN
CKSUM=""
if cs_expect "6 crate is in the sparse index through ${HAL_REPO_FW_CARGO}" 200; then
  cs_expect_body "6 the index entry has \"vers\":\"${CRATE_VER}\"" "\"vers\":\"${CRATE_VER}\""
  CKSUM=$(printf '%s\n' "$CS_BODY" | jq -r --arg v "$CRATE_VER" 'select(.vers==$v) | .cksum' 2>/dev/null | head -n1)
fi

cs_http GET "/cargo/${HAL_REPO_FW_CARGO}/api/v1/crates/${CRATE}/${CRATE_VER}/download" token:HAL_FW_DEV_TOKEN
if cs_expect "7 Tomas downloads the crate through ${HAL_REPO_FW_CARGO}" 200; then
  if [ -n "$CKSUM" ] && [ "$(_fw_body_sha)" = "$CKSUM" ]; then
    cs_record "7 downloaded .crate matches the index cksum" PASS "sha256 ${CKSUM:0:12}"
  else
    cs_record "7 downloaded .crate matches the index cksum" FAIL \
      "download sha256 $(_fw_body_sha), index cksum '${CKSUM}'" ""
  fi
fi

# 8. VERIFY pinned: cargo.rs:1684-1716 check_duplicate_crate answers 409 with
#    the cargo error body {"errors":[{"detail":"crate version `n@v` already exists"}]}.
if $CRATE_OK; then
  cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" "$CRATE" "$CRATE_VER" token:HAL_FW_DEV_TOKEN
  cs_expect "8 publishing the same crate version again is refused (cargo.rs:1701-1712)" 409 \
    && cs_expect_body "8 the refusal is the cargo error body" "\"detail\":\"crate version \`${CRATE}@${CRATE_VER}\` already exists\""
else
  cs_record "8 publishing the same crate version again is refused (cargo.rs:1701-1712)" SKIP "the first publish (5) failed"
fi

# ---------------------------------------------------------------------------
# Real cargo client (optional). cargo sends the raw token as Authorization
# (auth.rs:576-577 accepts a scheme-less single-word value).
# ---------------------------------------------------------------------------
CLI_CRATE="${HAL}-fw-motor-cli"
CLI_OK=false
if command -v cargo >/dev/null 2>&1 && cargo --version >/dev/null 2>&1; then
  _cs_work
  CH="${CS_WORK}/cargo-home"; mkdir -p "$CH"
  cat > "${CH}/config.toml" <<EOF
[registries.halcyon]
index = "sparse+${BASE_URL}/cargo/${HAL_REPO_FW_CARGO}/"
[registries.halcyon-local]
index = "sparse+${BASE_URL}/cargo/${HAL_REPO_FW_CARGO_LOCAL}/"
[registry]
global-credential-providers = ["cargo:token"]
[net]
retry = 1
EOF
  _fw_cargo() {
    ( cd "$1" && shift && CARGO_HOME="$CH" \
        CARGO_REGISTRIES_HALCYON_TOKEN="$HAL_FW_DEV_TOKEN" \
        CARGO_REGISTRIES_HALCYON_LOCAL_TOKEN="$HAL_FW_DEV_TOKEN" \
        CARGO_TERM_COLOR=never timeout 300 cargo "$@" ) > "${CS_WORK}/cargo.log" 2>&1
  }
  # cargo fetch resolves the crate published in 5 through the virtual.
  if $CRATE_OK; then
    app="${CS_WORK}/fw-app"; mkdir -p "${app}/src"
    printf '[package]\nname = "fw-app"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s = { version = "=%s", registry = "halcyon" }\n' \
      "$CRATE" "$CRATE_VER" > "${app}/Cargo.toml"
    echo 'fn main() {}' > "${app}/src/main.rs"
    if _fw_cargo "$app" fetch && ls "${CH}"/registry/cache/*/"${CRATE}-${CRATE_VER}.crate" >/dev/null 2>&1; then
      cs_record "cargo client: cargo fetch resolves ${CRATE} ${CRATE_VER} through ${HAL_REPO_FW_CARGO}" PASS "$(cargo --version)"
    else
      cs_record "cargo client: cargo fetch resolves ${CRATE} ${CRATE_VER} through ${HAL_REPO_FW_CARGO}" FAIL \
        "cargo fetch failed: $(tail -n 5 "${CS_WORK}/cargo.log")" "$(tail -n 30 "${CS_WORK}/cargo.log")"
    fi
  else
    cs_record "cargo client: cargo fetch resolves ${CRATE} through ${HAL_REPO_FW_CARGO}" SKIP "the publish (5) failed"
  fi
  # cargo publish of a second crate to the local.
  lib="${CS_WORK}/fw-cli"; mkdir -p "${lib}/src"
  printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\nlicense = "MIT"\ndescription = "Halcyon motor CLI"\npublish = ["halcyon-local"]\n' \
    "$CLI_CRATE" "$CRATE_VER" > "${lib}/Cargo.toml"
  echo 'pub fn cli() -> u8 { 1 }' > "${lib}/src/lib.rs"
  if _fw_cargo "$lib" publish --no-verify --allow-dirty --registry halcyon-local; then
    CLI_OK=true
    cs_record "cargo client: cargo publish ${CLI_CRATE} ${CRATE_VER} to ${HAL_REPO_FW_CARGO_LOCAL}" PASS "exit 0"
  else
    cs_record "cargo client: cargo publish ${CLI_CRATE} ${CRATE_VER} to ${HAL_REPO_FW_CARGO_LOCAL}" FAIL \
      "cargo publish failed: $(tail -n 5 "${CS_WORK}/cargo.log")" "$(tail -n 30 "${CS_WORK}/cargo.log")"
  fi
else
  cs_record "cargo client: fetch and publish through the firmware registries" SKIP "cargo not installed on this runner"
fi

# ---------------------------------------------------------------------------
# Real Maven client (optional): deploy-file a fresh coordinate to the local,
# then dependency:get hal-sdk 1.1.0 through the virtual (every plugin download
# goes through the virtual's remote member too).
# ---------------------------------------------------------------------------
if command -v mvn >/dev/null 2>&1 && mvn -v >/dev/null 2>&1; then
  if $UPSTREAM_OK; then
    _cs_work
    MW="${CS_WORK}/mvn"; mkdir -p "$MW"
    cat > "${MW}/settings.xml" <<EOF
<settings>
  <servers>
    <server><id>halcyon</id><username>${HAL_FW_DEV_USER}</username><password>${HAL_FW_DEV_TOKEN}</password></server>
    <server><id>halcyon-local</id><username>${HAL_FW_DEV_USER}</username><password>${HAL_FW_DEV_TOKEN}</password></server>
  </servers>
  <mirrors>
    <mirror><id>halcyon</id><mirrorOf>*</mirrorOf><url>${BASE_URL}/maven/${HAL_REPO_FW_MAVEN}</url></mirror>
  </mirrors>
</settings>
EOF
    _fw_mvn() {
      ( cd "$MW" && timeout 400 mvn -B -ntp -s "${MW}/settings.xml" -Dmaven.repo.local="${MW}/m2" "$@" ) > "${MW}/mvn.log" 2>&1
    }
    CLI_VER="1.0.${FW_STAMP}"
    printf 'PK-halcyon-hal-fw-cli-%s\n' "$CLI_VER" > "${MW}/hal-fw-cli.jar"
    if _fw_mvn org.apache.maven.plugins:maven-deploy-plugin:3.1.2:deploy-file \
        -Dfile="${MW}/hal-fw-cli.jar" -DgroupId=com.halcyon.fw -DartifactId=hal-fw-cli \
        -Dversion="$CLI_VER" -Dpackaging=jar -DgeneratePom=true \
        -DrepositoryId=halcyon-local -Durl="${BASE_URL}/maven/${HAL_REPO_FW_MAVEN_LOCAL}"; then
      cs_http GET "/maven/${HAL_REPO_FW_MAVEN}/${G}/hal-fw-cli/${CLI_VER}/hal-fw-cli-${CLI_VER}.pom" basic:FW_DEV
      cs_expect "mvn client: deploy:deploy-file hal-fw-cli ${CLI_VER}, pom then resolves through ${HAL_REPO_FW_MAVEN}" 200
    else
      cs_record "mvn client: deploy:deploy-file hal-fw-cli ${CLI_VER} to ${HAL_REPO_FW_MAVEN_LOCAL}" FAIL \
        "mvn failed: $(grep -E 'ERROR' "${MW}/mvn.log" | head -n 3)" "$(tail -n 30 "${MW}/mvn.log")"
    fi
    if _fw_mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get \
        -Dartifact=com.halcyon.fw:hal-sdk:1.1.0 -Dtransitive=false \
        && [ -f "${MW}/m2/com/halcyon/fw/hal-sdk/1.1.0/hal-sdk-1.1.0.jar" ] \
        && [ "$(sha256sum "${MW}/m2/com/halcyon/fw/hal-sdk/1.1.0/hal-sdk-1.1.0.jar" | cut -d' ' -f1)" = "$SDK11_SHA" ]; then
      cs_record "mvn client: dependency:get hal-sdk 1.1.0 through ${HAL_REPO_FW_MAVEN}" PASS "$(mvn -v 2>/dev/null | head -n1)"
    else
      cs_record "mvn client: dependency:get hal-sdk 1.1.0 through ${HAL_REPO_FW_MAVEN}" FAIL \
        "mvn failed or wrong bytes: $(grep -E 'ERROR' "${MW}/mvn.log" | head -n 3)" "$(tail -n 30 "${MW}/mvn.log")"
    fi
  else
    cs_record "mvn client: deploy-file and dependency:get through the firmware registries" SKIP \
      "upstream ${UP_MAVEN} unreachable (mvn needs its plugins through the virtual)"
  fi
else
  cs_record "mvn client: deploy-file and dependency:get through the firmware registries" SKIP "mvn not installed on this runner"
fi

# ---------------------------------------------------------------------------
# 9-11. Mara operates the instance-locked Maven age gate (age_gate.rs:257-265
#       repo admin via the project admin grant; age_gate_service.rs:1681-1687
#       a repository admin may tighten a locked policy, never relax it).
# ---------------------------------------------------------------------------
GATE="/api/v1/repositories/${HAL_REPO_FW_MAVEN_REMOTE}/age-gate"
cs_http GET "$GATE" jwt:FW_LEAD
if cs_expect "9 Mara reads the locked Maven age gate (age_gate.rs:631-650)" 200; then
  lk=$(cs_json '.instance_locked'); md=$(cs_json '.min_age_days'); en=$(cs_json '.enabled')
  if [ "$lk" = "true" ] && [ "$md" = "7" ] && [ "$en" = "true" ]; then
    cs_record "9 the gate is enabled, 7 days, instance_locked" PASS "mode $(cs_json '.mode')"
  else
    cs_record "9 the gate is enabled, 7 days, instance_locked" FAIL \
      "enabled=${en} min_age_days=${md} instance_locked=${lk} (a previous run's 14 days not restored by security #10?)" "$CS_BODY"
  fi
fi

cs_http PUT "$GATE" jwt:FW_LEAD -H 'Content-Type: application/json' \
  -d '{"enabled":true,"min_age_days":14,"mode":"upstream_publish_time"}'
if cs_expect "10 Mara tightens the locked gate to 14 days" 200; then
  if [ "$(cs_json '.min_age_days')" = "14" ] && [ "$(cs_json '.instance_locked')" = "true" ]; then
    cs_record "10 the gate is now 14 days and still instance_locked" PASS ""
  else
    cs_record "10 the gate is now 14 days and still instance_locked" FAIL \
      "min_age_days=$(cs_json '.min_age_days') instance_locked=$(cs_json '.instance_locked')" "$CS_BODY"
  fi
fi

cs_http PUT "$GATE" jwt:FW_LEAD -H 'Content-Type: application/json' \
  -d '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}'
cs_expect "11 Mara cannot relax the locked gate back to 7 days (age_gate_service.rs:1681-1687)" 403 \
  "gate left at 14 days on ${HAL_REPO_FW_MAVEN_REMOTE}; security #10 restores 7" \
  && cs_expect_body "11 the refusal says only an instance administrator may lower it" "only an instance administrator can disable it, lower its minimum age"
# Mara is done with the gate: security #10 may now restore it to 7 days.
# Signalled whatever #11 answered, so security never waits on a FAIL here.
cs_signal fw-age-gate-relax-refused

# Tomas (group read+write, no admin) cannot read the gate: he can read the
# repository, so 403, not 404.
cs_http GET "$GATE" jwt:FW_DEV
cs_expect "NOT: Tomas reads the age gate config (403, age_gate.rs:257-265)" 403

# ---------------------------------------------------------------------------
# 12. Mara lists her department's repositories.
# ---------------------------------------------------------------------------
_fw_list_repo_keys jwt:FW_LEAD
if [ "$FW_LIST_STATUS" = "200" ]; then
  want=$(printf '%s\n' "$HAL_REPO_FW_CARGO_LOCAL" "$HAL_REPO_FW_CARGO_REMOTE" "$HAL_REPO_FW_CARGO" \
    "$HAL_REPO_FW_MAVEN_LOCAL" "$HAL_REPO_FW_MAVEN_REMOTE" "$HAL_REPO_FW_MAVEN" "$HAL_REPO_HANDBOOK" | sort -u)
  # Halcyon keys she sees, minus her own scratch repos from item 14 (an
  # earlier run's may still be draining its delete job).
  have=$(printf '%s\n' "$FW_LIST_KEYS" | grep -E "^${HAL}-" | grep -v -E "^${HAL}-fw-scratch-" | sort -u)
  missing=$(comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$have") | tr '\n' ' ')
  extra=$(comm -13 <(printf '%s\n' "$want") <(printf '%s\n' "$have") | tr '\n' ' ')
  if [ -z "${missing// /}" ] && [ -z "${extra// /}" ]; then
    cs_record "12 Mara lists exactly the 6 firmware repos and the handbook (RS:348-360)" PASS "$(printf '%s' "$have" | wc -l) Halcyon repos"
  else
    cs_record "12 Mara lists exactly the 6 firmware repos and the handbook (RS:348-360)" FAIL \
      "missing: ${missing:-none}; unexpected: ${extra:-none}" "$have"
  fi
else
  cs_record "12 Mara lists exactly the 6 firmware repos and the handbook (RS:348-360)" FAIL \
    "list answered ${FW_LIST_STATUS} (${CS_LAST_REQ})" "${CS_BODY:0:300}"
fi

# ---------------------------------------------------------------------------
# 13. Deleting the crate version: Tomas's token cannot (no delete:artifacts,
#     and he may not mint it); Mara's JWT session can (project grant has delete).
# ---------------------------------------------------------------------------
cs_http DELETE "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts/${CRATE_PATH}" token:HAL_FW_DEV_TOKEN
cs_expect "NOT: Tomas deletes the crate with his personal token (403, repositories.rs delete_artifact scope)" 403 \
  && cs_expect_body "NOT: the refusal names the missing scope" "Token does not have required scope: delete:artifacts"

cs_http POST /api/v1/users/me/tokens jwt:FW_DEV -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "${HAL}-fw-delete-probe" '{name:$n,scopes:["delete:artifacts"],expires_in_days:1}')"
cs_expect "NOT: Tomas mints a delete:artifacts token (403, token_service.rs:160-170)" 403
if [ "${CS_STATUS:0:1}" = "2" ]; then
  tid=$(cs_json '.id // empty')
  [ -n "$tid" ] && cs_http DELETE "/api/v1/users/me/tokens/${tid}" jwt:FW_DEV
fi

if $CRATE_OK; then
  cs_http DELETE "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts/${CRATE_PATH}" jwt:FW_LEAD
  if cs_expect "13 Mara deletes Tomas's crate version (RS delete_artifact, project delete grant)" 200; then
    cs_http GET "/cargo/${HAL_REPO_FW_CARGO_LOCAL}/api/v1/crates/${CRATE}/${CRATE_VER}/download" token:HAL_FW_DEV_TOKEN
    cs_expect "13 the deleted crate version no longer downloads from the local" 404
  fi
else
  cs_record "13 Mara deletes Tomas's crate version" SKIP "the publish (5) failed"
fi
if $CLI_OK; then
  cs_http DELETE "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}/artifacts/${CLI_CRATE}/${CRATE_VER}/${CLI_CRATE}-${CRATE_VER}.crate" jwt:FW_LEAD
  cs_expect "13 Mara deletes the cargo-client crate ${CLI_CRATE} ${CRATE_VER}" 200
fi

# ---------------------------------------------------------------------------
# 14. Mara creates a department repository herself (project admin, #2473),
#     then deletes it (202 with a job, #4311).
# ---------------------------------------------------------------------------
SCRATCH="${HAL}-fw-scratch-${FW_STAMP}"
cs_http POST /api/v1/repositories jwt:FW_LEAD -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$SCRATCH" --arg p "$HAL_PROJECT_FW_ID" \
        '{key:$k,name:$k,format:"generic",repo_type:"local",visibility:"private",project_id:$p}')"
if cs_expect "14 Mara creates ${SCRATCH} in the firmware project (RS:4643-4656)" 200; then
  cs_http DELETE "/api/v1/repositories/${SCRATCH}" jwt:FW_LEAD
  if cs_expect "14 Mara deletes ${SCRATCH} (202 with a job, #4311)" 202; then
    gone=false
    for _ in $(seq 1 15); do
      cs_http GET "/api/v1/repositories/${SCRATCH}" jwt:FW_LEAD
      [ "$CS_STATUS" = "404" ] && { gone=true; break; }
      sleep 2
    done
    if $gone; then
      cs_record "14 the deleted key stops resolving" PASS "GET 404"
    else
      cs_record "14 the deleted key stops resolving" FAIL "GET still ${CS_STATUS} after 30 s" "${CS_BODY:0:300}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Should NOT work
# ---------------------------------------------------------------------------
# Tomas publishes to the web registry he cannot read: 404, not 403 (#5458).
cs_publish_npm "$HAL_REPO_WEB_NPM_LOCAL" "${HAL}-fw-leak" 0.0.1 basic:FW_DEV
cs_expect "NOT: Tomas publishes to ${HAL_REPO_WEB_NPM_LOCAL} (404, #5458)" 404 \
  && cs_expect_body "NOT: the npm refusal reads Repository not found" "Repository not found"

# Mara creates a repository in the web project: she is not its admin.
cs_http POST /api/v1/repositories jwt:FW_LEAD -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "${HAL}-web-fw-mara-${FW_STAMP}" --arg p "$HAL_PROJECT_WEB_ID" \
        '{key:$k,name:$k,format:"generic",repo_type:"local",visibility:"private",project_id:$p}')"
cs_expect "NOT: Mara creates a repo in the web project (403, RS:4648-4655)" 403 \
  && cs_expect_body "NOT: the refusal says insufficient permissions" "Insufficient permissions to create repositories"
if [ "$CS_STATUS" = "200" ]; then
  cs_http DELETE "/api/v1/repositories/${HAL}-web-fw-mara-${FW_STAMP}" jwt:FW_LEAD
fi

cs_end
