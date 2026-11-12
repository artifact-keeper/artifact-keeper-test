#!/usr/bin/env bash
# =============================================================================
# tiers/push-sync-oci-and-plugin-metadata/oracle.sh
#   #4790 an OCI image and an image index pushed to a hosted docker repo reach
#         a push peer with their blob closure
#   #4916 a group-level Maven plugin-prefix maven-metadata.xml reaches a push
#         peer and is merged into the peer's own mapping
# See the manifest for THE PEER and the gates.
#
# run.sh exported BASE_URL (instance A), DB_CONTAINER (A's postgres),
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (instance B's published
# HTTP port, profiles/peer.second-instance.yml), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
: "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
R_OCI="l6-psoci-${SLOT}-${SUF}"
R_MVN="l6-psmvn-${SLOT}-${SUF}"
R_GEN="l6-psgen-${SLOT}-${SUF}"
setup_workdir
W="$WORK_DIR"
DELIVERY_SECS=120

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
size_of() { wc -c < "$1" | tr -d ' '; }
digest_of() { echo "sha256:$(sha_of "$1")"; }

repo_create() { # base key format -> id
  local body
  body="$(jq -nc --arg k "$2" --arg f "$3" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}
push_blob() { # file -> HTTP code (monolithic POST with ?digest=)
  code -u "$AUTH" -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$1" \
    "${A}/v2/${R_OCI}/l6img/blobs/uploads/?digest=$(digest_of "$1")"
}
push_manifest() { # reference media-type file -> HTTP code
  code -u "$AUTH" -X PUT -H "Content-Type: $2" --data-binary "@$3" "${A}/v2/${R_OCI}/l6img/manifests/$1"
}
make_image() { # prefix marker: writes PREFIX.cfg, PREFIX.l1, PREFIX.l2, PREFIX.man
  head -c 2048 /dev/urandom > "$1.l1"
  printf 'l6 layer two %s\n' "$2" > "$1.l2"
  jq -nc --arg m "$2" '{architecture:"amd64",os:"linux",config:{Env:["MARKER=\($m)"]},
    rootfs:{type:"layers",diff_ids:[]},history:[{created_by:"RUN true # \($m)"}]}' | tr -d '\n' > "$1.cfg"
  jq -nc --arg cd "$(digest_of "$1.cfg")" --argjson cs "$(size_of "$1.cfg")" \
    --arg l1 "$(digest_of "$1.l1")" --argjson s1 "$(size_of "$1.l1")" \
    --arg l2 "$(digest_of "$1.l2")" --argjson s2 "$(size_of "$1.l2")" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$l1,size:$s1},
              {mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$l2,size:$s2}]}' | tr -d '\n' > "$1.man"
}
# get_b PATH: "<http>:<sha256 of the body>" of B's answer (Accept all
# manifest types).
get_b() {
  local c
  c="$(curl -s -o "$W/getb" -w '%{http_code}' --max-time 60 -u "$AUTH" \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "${B}$1" 2>/dev/null || echo 000)"
  if [ "$c" = "200" ]; then echo "${c}:$(sha_of "$W/getb")"; else echo "${c}:-"; fi
}
await_b() { # path want secs
  local end=$(( $(date +%s) + $3 ))
  while [ "$(get_b "$1")" != "$2" ] && [ "$(date +%s)" -lt "$end" ]; do sleep 3; done
  [ "$(get_b "$1")" = "$2" ]
}

begin_suite "push-sync-oci-and-plugin-metadata"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: instance B is up, docker, maven and generic repositories on A and B, B registered on A as a push peer"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
declare -A RID=()
for spec in "$R_OCI:docker" "$R_MVN:maven" "$R_GEN:generic"; do
  k="${spec%%:*}"; f="${spec##*:}"
  RID[$k]="$(repo_create "$A" "$k" "$f")"
  [ -n "${RID[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on A failed;"
  [ -n "$(repo_create "$B" "$k" "$f")" ] || SETUP_ERR="${SETUP_ERR} create ${k} on B failed;"
done
B_KEY="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"l6-peer-a-${SUF}\",\"scopes\":[\"*\"]}" "${B}/api/v1/auth/tokens" 2>/dev/null | jq -r '.token // empty' 2>/dev/null)"
[ -n "$B_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint an API key on B;"
PEER_ID="$(curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "l6-peer-b-${SLOT}-${SUF}" --arg k "$B_KEY" '{name:$n,endpoint_url:"http://peer-backend:8080",api_key:$k}')" \
  "${A}/api/v1/peers" 2>/dev/null | jq -r '.id // empty' 2>/dev/null)"
if [ -z "$PEER_ID" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration on A failed;"
else
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL WHERE id = '${PEER_ID}'" >/dev/null
  for k in "$R_OCI" "$R_MVN" "$R_GEN"; do
    c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
      -d "{\"repository_id\":\"${RID[$k]:-x}\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
      "${A}/api/v1/peers/${PEER_ID}/repositories")"
    [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe ${k} -> ${c};"
  done
fi
if [ -n "$SETUP_ERR" ]; then infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?; fi
echo "-- peer ${PEER_ID}; repos ${R_OCI} ${R_MVN} ${R_GEN}"
pass

# =============================================================================
# B's own plugin-prefix mapping, written before A publishes one (#4916)
# =============================================================================
G_PATH="org/l6/s${SUF//[^0-9]/}"
plugins_xml() { # out prefix:artifactId...
  local out="$1" e
  shift
  { printf '<?xml version="1.0" encoding="UTF-8"?>\n<metadata>\n  <plugins>\n'
    for e in "$@"; do
      printf '    <plugin>\n      <name>%s</name>\n      <prefix>%s</prefix>\n      <artifactId>%s</artifactId>\n    </plugin>\n' "${e##*:}" "${e%%:*}" "${e##*:}"
    done
    printf '  </plugins>\n</metadata>\n'; } > "$out"
}
plugins_xml "$W/b-plugins.xml" "l6b:l6b-maven-plugin"
plugins_xml "$W/a-plugins.xml" "l6a:l6a-maven-plugin" "l6shared:l6shared-maven-plugin"
c_bplug="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/xml' --data-binary @"$W/b-plugins.xml" "${B}/maven/${R_MVN}/${G_PATH}/maven-metadata.xml")"

# =============================================================================
# Uploads on A
# =============================================================================
printf 'l6 generic %s\n' "$SUF" > "$W/gen"
GEN_PATH="l6/${SUF}/control.txt"
make_image "$W/img" "img-${SUF}"
make_image "$W/c1" "c1-${SUF}"
make_image "$W/c2" "c2-${SUF}"
jq -nc --arg d1 "$(digest_of "$W/c1.man")" --argjson s1 "$(size_of "$W/c1.man")" \
  --arg d2 "$(digest_of "$W/c2.man")" --argjson s2 "$(size_of "$W/c2.man")" \
  '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",
    manifests:[{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$d1,size:$s1,platform:{architecture:"amd64",os:"linux"}},
               {mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$d2,size:$s2,platform:{architecture:"arm64",os:"linux"}}]}' \
  | tr -d '\n' > "$W/index.json"
MVN_GAV_PATH="org/l6/l6lib-${SUF//[^0-9]/}/1.0.0"
MVN_A="l6lib-${SUF//[^0-9]/}"
printf 'PK l6 jar %s\n' "$SUF" > "$W/lib.jar"
printf '<project><modelVersion>4.0.0</modelVersion><groupId>org.l6</groupId><artifactId>%s</artifactId><version>1.0.0</version></project>\n' "$MVN_A" > "$W/lib.pom"

begin_test "CONTROL: uploads on A succeed: generic PUT, an OCI image and an image index over /v2 (they pull back from A), a Maven jar and pom"
reset_case
c="$(code -u "$AUTH" -X PUT --data-binary @"$W/gen" "${A}/api/v1/repositories/${R_GEN}/artifacts/${GEN_PATH}")"
[[ "$c" == 20? ]] || fail_g "generic PUT answered ${c}"
for p in img c1 c2; do for part in cfg l1 l2; do
  c="$(push_blob "$W/$p.$part")"; [ "$c" = "201" ] || fail_g "blob ${p}.${part} answered ${c}: $(head -c 160 "$W/last")"
done; done
c="$(push_manifest "v1" application/vnd.oci.image.manifest.v1+json "$W/img.man")"
[ "$c" = "201" ] || fail_g "manifest l6img:v1 answered ${c}: $(head -c 160 "$W/last")"
for p in c1 c2; do
  c="$(push_manifest "$(digest_of "$W/$p.man")" application/vnd.oci.image.manifest.v1+json "$W/$p.man")"
  [ "$c" = "201" ] || fail_g "child manifest ${p} answered ${c}: $(head -c 160 "$W/last")"
done
c="$(push_manifest "multi" application/vnd.oci.image.index.v1+json "$W/index.json")"
[ "$c" = "201" ] || fail_g "index l6img:multi answered ${c}: $(head -c 160 "$W/last")"
pa="$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" -H 'Accept: application/vnd.oci.image.manifest.v1+json' "${A}/v2/${R_OCI}/l6img/manifests/v1")"
pi="$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" -H 'Accept: application/vnd.oci.image.index.v1+json' "${A}/v2/${R_OCI}/l6img/manifests/multi")"
note "A serves l6img:v1 ${pa}, l6img:multi ${pi}"
{ [ "$pa" = "200" ] && [ "$pi" = "200" ]; } || fail_g "A does not serve the pushed image (${pa}) or index (${pi})"
c="$(code -u "$AUTH" -X PUT --data-binary @"$W/lib.pom" "${A}/maven/${R_MVN}/${MVN_GAV_PATH}/${MVN_A}-1.0.0.pom")"
[[ "$c" == 20? ]] || fail_g "Maven pom PUT answered ${c}"
c="$(code -u "$AUTH" -X PUT --data-binary @"$W/lib.jar" "${A}/maven/${R_MVN}/${MVN_GAV_PATH}/${MVN_A}-1.0.0.jar")"
[[ "$c" == 20? ]] || fail_g "Maven jar PUT answered ${c}"
note "B's own plugin-prefix mapping PUT on B: ${c_bplug}"
[[ "$c_bplug" == 20? ]] || fail_g "the plugin-prefix PUT on B answered ${c_bplug}"
if [ "$FAILS" -ne 0 ]; then infra_fail "upload precondition failed" "$DETAIL"; end_suite; exit $?; fi
pass
c_aplug="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/xml' --data-binary @"$W/a-plugins.xml" "${A}/maven/${R_MVN}/${G_PATH}/maven-metadata.xml")"

begin_test "CONTROL: the generic upload and the Maven jar and pom reach B"
reset_case
if await_b "/api/v1/repositories/${R_GEN}/download/${GEN_PATH}" "200:$(sha_of "$W/gen")" "$DELIVERY_SECS"; then note "generic: on B"; else
  fail_g "the generic upload never reached B within ${DELIVERY_SECS} s ($(get_b "/api/v1/repositories/${R_GEN}/download/${GEN_PATH}"))"
fi
for f in jar pom; do
  if await_b "/maven/${R_MVN}/${MVN_GAV_PATH}/${MVN_A}-1.0.0.${f}" "200:$(sha_of "$W/lib.${f}")" 60; then note "maven ${f}: on B"; else
    fail_g "the Maven ${f} never reached B ($(get_b "/maven/${R_MVN}/${MVN_GAV_PATH}/${MVN_A}-1.0.0.${f}"))"
  fi
done
finish_case "the push peer does not receive generic or Maven uploads"
# The worker claims every pending task of the peer per tick; one more tick
# for anything queued after the controls.
sleep 20

begin_test "FIX #4790: an OCI image pushed to a hosted docker repository reaches B with its manifest and every blob"
reset_case
want="200:$(sha_of "$W/img.man")"
await_b "/v2/${R_OCI}/l6img/manifests/v1" "$want" 30
got="$(get_b "/v2/${R_OCI}/l6img/manifests/v1")"
note "B l6img:v1 -> ${got}"
[ "$got" = "$want" ] || fail_g "B answers ${got} for l6img:v1, expected A's manifest (${want})"
got="$(get_b "/v2/${R_OCI}/l6img/manifests/$(digest_of "$W/img.man")")"
[ "$got" = "$want" ] || fail_g "B answers ${got} for the manifest by digest"
for part in cfg l1 l2; do
  got="$(get_b "/v2/${R_OCI}/l6img/blobs/$(digest_of "$W/img.$part")")"
  note "B blob ${part} -> ${got%%:*}"
  [ "$got" = "200:$(sha_of "$W/img.$part")" ] || fail_g "B answers ${got} for blob ${part} ($(digest_of "$W/img.$part"))"
done
finish_case "hosted OCI pushes are not replicated to push peers"

begin_test "FIX #4790: an image index pushed to a hosted docker repository reaches B with both child manifests and their blobs"
reset_case
want="200:$(sha_of "$W/index.json")"
got="$(get_b "/v2/${R_OCI}/l6img/manifests/multi")"
note "B l6img:multi -> ${got}"
[ "$got" = "$want" ] || fail_g "B answers ${got} for the index l6img:multi, expected A's index (${want})"
for p in c1 c2; do
  got="$(get_b "/v2/${R_OCI}/l6img/manifests/$(digest_of "$W/$p.man")")"
  [ "$got" = "200:$(sha_of "$W/$p.man")" ] || fail_g "B answers ${got} for child manifest ${p}"
  for part in cfg l1 l2; do
    got="$(get_b "/v2/${R_OCI}/l6img/blobs/$(digest_of "$W/$p.$part")")"
    [ "$got" = "200:$(sha_of "$W/$p.$part")" ] || fail_g "B answers ${got} for blob ${p}.${part}"
  done
done
finish_case "hosted OCI image indexes are not replicated to push peers"

begin_test "FIX #4916: a group-level plugin-prefix maven-metadata.xml on A reaches B and is merged into B's own mapping"
reset_case
note "plugin-prefix PUT on A: ${c_aplug}"
[[ "$c_aplug" == 20? ]] || fail_g "the plugin-prefix PUT on A answered ${c_aplug}: $(head -c 160 "$W/last")"
end=$(( $(date +%s) + 60 ))
while :; do
  curl -s -o "$W/bplug" --max-time 30 -u "$AUTH" "${B}/maven/${R_MVN}/${G_PATH}/maven-metadata.xml"
  grep -q '<prefix>l6a</prefix>' "$W/bplug" 2>/dev/null && break
  [ "$(date +%s)" -ge "$end" ] && break
  sleep 3
done
prefixes="$(grep -o '<prefix>[^<]*</prefix>' "$W/bplug" 2>/dev/null | sed 's#</*prefix>##g' | sort | paste -sd, -)"
note "B's plugin prefixes at ${G_PATH}: ${prefixes:-none}"
for p in l6a l6shared; do
  [[ ",${prefixes}," == *",${p},"* ]] || fail_g "B's mapping has no prefix ${p} from A"
done
[[ ",${prefixes}," == *",l6b,"* ]] || fail_g "B's own prefix l6b is gone: the push replaced the mapping instead of merging"
finish_case "group-level plugin-prefix metadata is not replicated"

end_suite
