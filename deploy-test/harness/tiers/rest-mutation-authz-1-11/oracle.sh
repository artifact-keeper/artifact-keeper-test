#!/usr/bin/env bash
# =============================================================================
# tiers/rest-mutation-authz-1-11/oracle.sh - the REST mutation routes that
#   1.11.0 put behind the repository action gate (GHSA-mvmh-g8wm-r3cp, #4588)
#   and the artifact label writes (#4193)
# =============================================================================
# run.sh has stood up `storage.filesystem` + `imagebuild.non-admin` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Principals (all interactive sessions, which pass every token-scope check):
#   N   signed-in user with no role and no grant anywhere
#   R   `reader` on the private repository Q
#   D   `developer` on P, C and on the build it creates
#   O   `repository-owner` role on P and on the staging repository S
#   G   fine-grained grant {read,write,admin} on P and S (POST /permissions)
#   admin
#
# For each route the exploit (N, or R on Q, or a non-creator on a build) is
# refused 403/404 and a DB read proves nothing changed; the legitimate
# principal still succeeds and the DB shows its change. On 1.10.0 every
# exploit case returns 2xx (or the handler's own 404/400 past the missing gate)
# and the DB shows the attacker's write. See the manifest for the case list.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"

P="rma11-pub-${SLOT}-${SUF}"        # public generic local
Q="rma11-priv-${SLOT}-${SUF}"       # private generic local (R reads it)
S="rma11-stg-${SLOT}-${SUF}"        # public generic staging
L1="rma11-rel1-${SLOT}-${SUF}"      # public generic local, release target
L2="rma11-rel2-${SLOT}-${SUF}"      # public generic local, the attacker's target
C="rma11-oci-${SLOT}-${SUF}"        # public docker local (image builds)
PW="Rma11_${SUF}_Aa1!"
N_USER="rma11-n-${SLOT}-${SUF}"
R_USER="rma11-r-${SLOT}-${SUF}"
D_USER="rma11-d-${SLOT}-${SUF}"
O_USER="rma11-o-${SLOT}-${SUF}"
G_USER="rma11-g-${SLOT}-${SUF}"
PEER_A="rma11-peer-a-${SLOT}-${SUF}"
PEER_B="rma11-peer-b-${SLOT}-${SUF}"
OWNER_ISSUE="4818"

WORK="$(mktemp -d -t dtf-rma11-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code; body in $WORK/body.
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
# upload KEY PATH CONTENT TOKEN -> HTTP code; body in $WORK/body.
upload() {
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -X PUT -o "$WORK/body" -w '%{http_code}' \
    -H "Authorization: Bearer ${4}" -H 'Content-Type: application/octet-stream' \
    --data-binary "$3" "${BASE_URL}/api/v1/repositories/${1}/artifacts/${2}" 2>/dev/null || echo 000
}
body() { head -c 300 "$WORK/body" 2>/dev/null || true; }
jb() { jq -r "$1" "$WORK/body" 2>/dev/null || true; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null | tr -d '[:space:]' || echo "?"; }
denied() { [ "$1" = "403" ] || [ "$1" = "404" ]; }
# known_red ISSUE TEXT OK: a real backend defect this tier found (see the
# manifest). It is reported and never failed, so the cases around it stay a
# usable gate; when OK=1 the line says the pin should become an assertion.
known_red() {
  if [ "$3" = "1" ]; then
    echo "   KNOWN-RED (artifact-keeper#$1) NOW PASSES: $2. Turn this pin into an assertion."
  else
    echo "   KNOWN-RED (artifact-keeper#$1): $2"
  fi
}

setup_ok() { # WHAT CODE
  if [ "${2:0:1}" != "2" ]; then
    begin_test "setup: ${1}"
    infra_fail "${1}: HTTP ${2}" "$(body)"
    end_suite
  fi
}

begin_suite "rest-mutation-authz-1-11"

# =============================================================================
# SETUP
# =============================================================================
auth_admin
AT="$ADMIN_TOKEN"

for u in "$N_USER" "$R_USER" "$D_USER" "$O_USER" "$G_USER"; do
  if ! create_test_user_with_retry "$u" "$PW" "${u}@t.test" >/dev/null; then
    begin_test "setup: create user ${u}"; infra_fail "could not create user ${u}"; end_suite
  fi
done
NT="$(login_as "$N_USER" "$PW")" || true
RT="$(login_as "$R_USER" "$PW")" || true
DT="$(login_as "$D_USER" "$PW")" || true
OT="$(login_as "$O_USER" "$PW")" || true
GT="$(login_as "$G_USER" "$PW")" || true
if [ -z "$NT" ] || [ -z "$RT" ] || [ -z "$DT" ] || [ -z "$OT" ] || [ -z "$GT" ]; then
  begin_test "setup: log in the five test users"; infra_fail "a login returned no token"; end_suite
fi

mkrepo() { # KEY FORMAT TYPE PUBLIC
  req POST /api/v1/repositories "$AT" \
    "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --argjson p "$4" '{key:$k,name:$k,format:$f,repo_type:$t,is_public:$p}')"
}
c="$(mkrepo "$P" generic local true)";    setup_ok "create public repo ${P}" "$c"
c="$(mkrepo "$Q" generic local false)";   setup_ok "create private repo ${Q}" "$c"
c="$(mkrepo "$S" generic staging true)";  setup_ok "create staging repo ${S}" "$c"
c="$(mkrepo "$L1" generic local true)";   setup_ok "create release repo ${L1}" "$c"
c="$(mkrepo "$L2" generic local true)";   setup_ok "create release repo ${L2}" "$c"
c="$(mkrepo "$C" docker local true)";     setup_ok "create docker repo ${C}" "$c"

assign() { # USER ROLE REPO
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
    INSERT INTO role_assignments (user_id, role_id, repository_id)
    SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
    WHERE u.username='${1}' AND r.name='${2}' AND repo.key='${3}'
    ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true
}
assign "$R_USER" reader "$Q"
assign "$D_USER" developer "$P"
assign "$D_USER" developer "$C"
assign "$O_USER" repository-owner "$P"
assign "$O_USER" repository-owner "$S"
ROLES="$(db "SELECT count(*) FROM role_assignments ra JOIN users u ON u.id=ra.user_id
  WHERE u.username IN ('${R_USER}','${D_USER}','${O_USER}');")"
if [ "$ROLES" != "5" ]; then
  begin_test "setup: role assignments"; infra_fail "expected 5 role assignments, found ${ROLES}"; end_suite
fi

G_ID="$(db "SELECT id FROM users WHERE username='${G_USER}';")"
for k in "$P" "$S"; do
  c="$(req POST /api/v1/permissions "$AT" "$(jq -nc --arg u "$G_ID" --arg t "$(db "SELECT id FROM repositories WHERE key='${k}';")" \
    '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$t,actions:["read","write","admin"]}')")"
  setup_ok "grant ${G_USER} read,write,admin on ${k}" "$c"
done

c="$(upload "$P" "rma/a-1.0.bin" "rma-artifact-p-${SUF}" "$AT")"; setup_ok "upload artifact to ${P}" "$c"
A_P="$(db "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${P}' AND a.path='rma/a-1.0.bin';")"
c="$(upload "$Q" "rma/b-1.0.bin" "rma-artifact-q-${SUF}" "$AT")"; setup_ok "upload artifact to ${Q}" "$c"
A_Q="$(db "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${Q}' AND a.path='rma/b-1.0.bin';")"
c="$(upload "$S" "rma/s-1.0.bin" "rma-artifact-s-${SUF}" "$AT")"; setup_ok "upload artifact to ${S}" "$c"
A_S="$(db "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${S}' AND a.path='rma/s-1.0.bin';")"
if [ "${#A_P}" != "36" ] || [ "${#A_Q}" != "36" ] || [ "${#A_S}" != "36" ]; then
  begin_test "setup: resolve artifact ids"; infra_fail "artifact ids P='${A_P}' Q='${A_Q}' S='${A_S}'"; end_suite
fi

# =============================================================================
# #4193 - artifact label writes need the repository `write` action
# =============================================================================
art_label_rows() { db "SELECT count(*) FROM artifact_labels WHERE artifact_id='${1}' AND label_key='${2}';"; }

begin_test "#4193 control: developer member PUT /artifacts/{id}/labels on the public repo -> 200, row written"
c="$(req PUT "/api/v1/artifacts/${A_P}/labels" "$DT" '{"labels":[{"key":"rma-dev","value":"ok"}]}')"
if [ "$c" = "200" ] && [ "$(art_label_rows "$A_P" rma-dev)" = "1" ]; then pass
else fail "developer label PUT: HTTP ${c}, rows=$(art_label_rows "$A_P" rma-dev)" "$(body)"; fi

begin_test "#4193 fix: non-member PUT /artifacts/{id}/labels on the public repo -> 403, labels unchanged"
c="$(req PUT "/api/v1/artifacts/${A_P}/labels" "$NT" '{"labels":[{"key":"rma-evil","value":"x"}]}')"
if denied "$c" && [ "$(art_label_rows "$A_P" rma-evil)" = "0" ] && [ "$(art_label_rows "$A_P" rma-dev)" = "1" ]; then pass
else fail "non-member replaced the label set of an artifact it cannot write: HTTP ${c}, rma-evil rows=$(art_label_rows "$A_P" rma-evil), rma-dev rows=$(art_label_rows "$A_P" rma-dev)" "$(body)"; fi

begin_test "#4193 fix: non-member DELETE /artifacts/{id}/labels/{key} -> 403, label kept"
c="$(req DELETE "/api/v1/artifacts/${A_P}/labels/rma-dev" "$NT")"
if denied "$c" && [ "$(art_label_rows "$A_P" rma-dev)" = "1" ]; then pass
else fail "non-member deleted a label: HTTP ${c}, rma-dev rows=$(art_label_rows "$A_P" rma-dev)" "$(body)"; fi

begin_test "#4193 fix: read-only member POST /artifacts/{id}/labels/{key} on the private repo -> 403, no row"
c="$(req POST "/api/v1/artifacts/${A_Q}/labels/rma-reader" "$RT" '{"value":"x"}')"
if denied "$c" && [ "$(art_label_rows "$A_Q" rma-reader)" = "0" ]; then pass
else fail "reader added a label on a private artifact: HTTP ${c}, rows=$(art_label_rows "$A_Q" rma-reader)" "$(body)"; fi

begin_test "#4193 control: read-only member still lists the private artifact's labels (reads unchanged)"
c="$(req GET "/api/v1/artifacts/${A_Q}/labels" "$RT")"
if [ "$c" = "200" ]; then pass; else fail "reader label list: HTTP ${c}" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 2 - repository labels need `write` + write:repositories
# =============================================================================
repo_label_rows() { db "SELECT count(*) FROM repository_labels l JOIN repositories r ON r.id=l.repository_id WHERE r.key='${1}' AND l.label_key='${2}';"; }

begin_test "mvmh labels control: developer member PUT /repositories/{P}/labels -> 200, row written"
c="$(req PUT "/api/v1/repositories/${P}/labels" "$DT" '{"labels":[{"key":"rma-sync","value":"yes"}]}')"
if [ "$c" = "200" ] && [ "$(repo_label_rows "$P" rma-sync)" = "1" ]; then pass
else fail "developer repo label PUT: HTTP ${c}, rows=$(repo_label_rows "$P" rma-sync)" "$(body)"; fi

begin_test "mvmh labels fix: non-member PUT /repositories/{public}/labels -> 403, labels unchanged"
c="$(req PUT "/api/v1/repositories/${P}/labels" "$NT" '{"labels":[{"key":"rma-evil","value":"x"}]}')"
if denied "$c" && [ "$(repo_label_rows "$P" rma-evil)" = "0" ] && [ "$(repo_label_rows "$P" rma-sync)" = "1" ]; then pass
else fail "non-member rewrote repository labels (sync-policy selectors): HTTP ${c}, rma-evil=$(repo_label_rows "$P" rma-evil) rma-sync=$(repo_label_rows "$P" rma-sync)" "$(body)"; fi

begin_test "mvmh labels fix: non-member DELETE /repositories/{public}/labels/{key} -> 403, label kept"
c="$(req DELETE "/api/v1/repositories/${P}/labels/rma-sync" "$NT")"
if denied "$c" && [ "$(repo_label_rows "$P" rma-sync)" = "1" ]; then pass
else fail "non-member deleted a repository label: HTTP ${c}, rows=$(repo_label_rows "$P" rma-sync)" "$(body)"; fi

begin_test "mvmh labels fix: read-only member POST /repositories/{private}/labels/{key} -> 403, no row"
c="$(req POST "/api/v1/repositories/${Q}/labels/rma-reader" "$RT" '{"value":"x"}')"
if denied "$c" && [ "$(repo_label_rows "$Q" rma-reader)" = "0" ]; then pass
else fail "reader added a repository label on a private repository: HTTP ${c}, rows=$(repo_label_rows "$Q" rma-reader)" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 4 - email subscriptions need the repository `admin` action
# =============================================================================
sub_rows() { db "SELECT count(*) FROM email_subscriptions s JOIN repositories r ON r.id=s.repository_id WHERE r.key='${1}' AND '${2}' = ANY(s.recipients);"; }
O_MAIL="rma-owner-${SUF}@t.test"
N_MAIL="rma-attacker-${SUF}@t.test"
R_MAIL="rma-reader-${SUF}@t.test"

begin_test "mvmh email control: repository admin (grant) POST /repositories/{P}/email-subscriptions -> 2xx, row written"
c="$(req POST "/api/v1/repositories/${P}/email-subscriptions" "$GT" \
  "$(jq -nc --arg m "$O_MAIL" '{recipients:[$m],event_types:["artifact.uploaded"]}')")"
SUB_ID="$(jb '.id // empty')"
if [ "${c:0:1}" = "2" ] && [ -n "$SUB_ID" ] && [ "$(sub_rows "$P" "$O_MAIL")" = "1" ]; then pass
else fail "repository-admin subscription create: HTTP ${c}, rows=$(sub_rows "$P" "$O_MAIL")" "$(body)"; fi

begin_test "mvmh email control: repository admin (grant) lists the subscription with its recipient"
c="$(req GET "/api/v1/repositories/${P}/email-subscriptions" "$GT")"
if [ "$c" = "200" ] && grep -qF "$O_MAIL" "$WORK/body"; then pass
else fail "repository-admin list: HTTP ${c}" "$(body)"; fi

begin_test "mvmh email fix: non-member GET /repositories/{public}/email-subscriptions -> 403, no recipient disclosed"
c="$(req GET "/api/v1/repositories/${P}/email-subscriptions" "$NT")"
if denied "$c" && ! grep -qF "$O_MAIL" "$WORK/body"; then pass
else fail "non-member listed subscription recipients: HTTP ${c}" "$(body)"; fi

begin_test "mvmh email fix: non-member POST /repositories/{public}/email-subscriptions -> 403, no row"
c="$(req POST "/api/v1/repositories/${P}/email-subscriptions" "$NT" \
  "$(jq -nc --arg m "$N_MAIL" '{recipients:[$m],event_types:["artifact.uploaded"]}')")"
if denied "$c" && [ "$(sub_rows "$P" "$N_MAIL")" = "0" ]; then pass
else fail "non-member made the instance mail an arbitrary address: HTTP ${c}, rows=$(sub_rows "$P" "$N_MAIL")" "$(body)"; fi

begin_test "mvmh email fix: non-member DELETE another user's subscription -> 403, row kept"
c="$(req DELETE "/api/v1/repositories/${P}/email-subscriptions/${SUB_ID:-00000000-0000-0000-0000-000000000000}" "$NT")"
if denied "$c" && [ "$(sub_rows "$P" "$O_MAIL")" = "1" ]; then pass
else fail "non-member deleted a subscription: HTTP ${c}, rows=$(sub_rows "$P" "$O_MAIL")" "$(body)"; fi

begin_test "mvmh email fix: read-only member POST /repositories/{private}/email-subscriptions -> 403, no row"
c="$(req POST "/api/v1/repositories/${Q}/email-subscriptions" "$RT" \
  "$(jq -nc --arg m "$R_MAIL" '{recipients:[$m],event_types:["artifact.uploaded"]}')")"
if denied "$c" && [ "$(sub_rows "$Q" "$R_MAIL")" = "0" ]; then pass
else fail "reader created a subscription on a private repository: HTTP ${c}, rows=$(sub_rows "$Q" "$R_MAIL")" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 1 - release-target PUT needs `admin` on the staging repo
# =============================================================================
L1_ID="$(db "SELECT id FROM repositories WHERE key='${L1}';")"
L2_ID="$(db "SELECT id FROM repositories WHERE key='${L2}';")"
link_of() { db "SELECT coalesce((SELECT c.value FROM repository_config c JOIN repositories r ON r.id=c.repository_id WHERE r.key='${S}' AND c.key='release_repository_id'),'NONE');"; }

begin_test "mvmh release-target control: repository admin (grant) PUT links the staging repo -> 200, link stored"
c="$(req PUT "/api/v1/promotion/repositories/${S}/release-target" "$GT" "$(jq -nc --arg k "$L1" '{release_repository_key:$k}')")"
if [ "$c" = "200" ] && [ "$(jb '.release_repository_key')" = "$L1" ] && [ "$(link_of)" = "$L1_ID" ]; then pass
else fail "repository-admin release-target PUT: HTTP ${c}, link=$(link_of)" "$(body)"; fi

begin_test "mvmh release-target fix: non-member PUT relinks the staging repo -> 403, link unchanged"
c="$(req PUT "/api/v1/promotion/repositories/${S}/release-target" "$NT" "$(jq -nc --arg k "$L2" '{release_repository_key:$k}')")"
if denied "$c" && [ "$(link_of)" = "$L1_ID" ]; then pass
else fail "non-member redirected release promotions: HTTP ${c}, link=$(link_of) (L1=${L1_ID} L2=${L2_ID})" "$(body)"; fi

begin_test "mvmh release-target fix: non-member PUT null (unlink) -> 403, link unchanged"
c="$(req PUT "/api/v1/promotion/repositories/${S}/release-target" "$NT" '{"release_repository_key":null}')"
if denied "$c" && [ "$(link_of)" = "$L1_ID" ]; then pass
else fail "non-member unlinked the release target: HTTP ${c}, link=$(link_of)" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 3 - reject needs the promotion capability
# =============================================================================
rejections() { db "SELECT count(*) FROM promotion_history WHERE artifact_id='${A_S}' AND status='rejected' AND promoted_by=(SELECT id FROM users WHERE username='${1}');"; }

begin_test "mvmh reject fix: non-member POST .../artifacts/{id}/reject on the public staging repo -> 403, no history row"
c="$(req POST "/api/v1/promotion/repositories/${S}/artifacts/${A_S}/reject" "$NT" '{"reason":"rma-forged"}')"
if denied "$c" && [ "$(rejections "$N_USER")" = "0" ]; then pass
else fail "non-member wrote an attributed rejection: HTTP ${c}, rows=$(rejections "$N_USER")" "$(body)"; fi

begin_test "mvmh reject control: admin POST .../reject -> 200, history row written"
c="$(req POST "/api/v1/promotion/repositories/${S}/artifacts/${A_S}/reject" "$AT" '{"reason":"rma-legit"}')"
if [ "$c" = "200" ] && [ "$(rejections "$ADMIN_USER")" = "1" ]; then pass
else fail "admin reject: HTTP ${c}, rows=$(rejections "$ADMIN_USER")" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 5 - image builds need `write` when AK_IMAGE_BUILD_ADMIN_ONLY=false
# =============================================================================
SPEC='{"spec":{"base_image":"alpine:3.20","packages":[],"env":{"RMA":"1"}}}'
builds_rows() { db "SELECT count(*) FROM image_builds b JOIN repositories r ON r.id=b.repository_id WHERE r.key='${C}';"; }

begin_test "mvmh image-builds control: developer member POST /repositories/{C}/image-builds/render -> 200 Containerfile"
c="$(req POST "/api/v1/repositories/${C}/image-builds/render" "$DT" "$SPEC")"
if [ "$c" = "200" ] && jb '.containerfile' | grep -q '^FROM alpine:3.20'; then pass
else fail "developer render: HTTP ${c}" "$(body)"; fi

begin_test "mvmh image-builds fix: non-member POST /repositories/{public}/image-builds/render -> 403"
c="$(req POST "/api/v1/repositories/${C}/image-builds/render" "$NT" "$SPEC")"
if denied "$c" && [ "$(jb '.containerfile // empty')" = "" ]; then pass
else fail "non-member rendered a build into a repository it cannot write: HTTP ${c}" "$(body)"; fi

begin_test "mvmh image-builds fix: non-member POST /repositories/{public}/image-builds -> 403, no build row"
c="$(req POST "/api/v1/repositories/${C}/image-builds" "$NT" \
  "$(jq -nc --argjson s "$SPEC" '{image:"rma/app",tag:"1"} + $s')")"
if denied "$c" && [ "$(builds_rows)" = "0" ]; then pass
else fail "non-member queue build: HTTP ${c} (expected 403, any other answer means the request got past authorization), rows=$(builds_rows)" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 7 - builds PUT / artifacts limited to creator and admins
# =============================================================================
c="$(req POST /api/v1/builds "$DT" "$(jq -nc --arg n "rma-build-${SUF}" '{name:$n,build_number:1}')")"
setup_ok "developer creates a build" "$c"
B_ID="$(jb '.id // empty')"
[ "${#B_ID}" = "36" ] || { begin_test "setup: build id"; infra_fail "no build id" "$(body)"; end_suite; }
build_status() { db "SELECT status FROM builds WHERE id='${B_ID}';"; }
build_arts() { db "SELECT count(*) FROM build_artifacts WHERE build_id='${B_ID}';"; }
ORIG_STATUS="$(build_status)"
ART_JSON='{"artifacts":[{"name":"rma.bin","path":"rma/rma.bin","checksum_sha256":"0000000000000000000000000000000000000000000000000000000000000000","size_bytes":1}]}'

begin_test "mvmh builds fix: non-creator PUT /builds/{id} -> 403, status unchanged"
c="$(req PUT "/api/v1/builds/${B_ID}" "$NT" '{"status":"failed"}')"
if denied "$c" && [ "$(build_status)" = "$ORIG_STATUS" ]; then pass
else fail "non-creator overwrote a build: HTTP ${c}, status ${ORIG_STATUS} -> $(build_status)" "$(body)"; fi

begin_test "mvmh builds fix: non-creator POST /builds/{id}/artifacts -> 403, no artifact attached"
c="$(req POST "/api/v1/builds/${B_ID}/artifacts" "$NT" "$ART_JSON")"
if denied "$c" && [ "$(build_arts)" = "0" ]; then pass
else fail "non-creator attached artifacts to a build: HTTP ${c}, rows=$(build_arts)" "$(body)"; fi

begin_test "mvmh builds control: creator PUT /builds/{id} and POST artifacts -> 200, DB updated"
ARTS_BEFORE="$(build_arts)"
c1="$(req PUT "/api/v1/builds/${B_ID}" "$DT" '{"status":"success"}')"
c2="$(req POST "/api/v1/builds/${B_ID}/artifacts" "$DT" "$ART_JSON")"
if [ "$c1" = "200" ] && [ "$c2" = "200" ] && [ "$(build_status)" = "success" ] && [ "$(build_arts)" = "$((ARTS_BEFORE + 1))" ]; then pass
else fail "creator build update: PUT ${c1}, artifacts ${c2}, status=$(build_status), rows=$(build_arts)" "$(body)"; fi

# =============================================================================
# KNOWN-RED: a `repository-owner` ROLE member is refused the two routes that
# moved to the repository `admin` action, although the 1.11.0 CHANGELOG says
# repository-owner members are unaffected. require_repo_admin asks
# PermissionService::check_permission, which reads fine-grained `permissions`
# rows only and never `role_assignments`; the role carries {read,write,delete,
# admin} and check_repository_action honours it. Reported, not failed
# (artifact-keeper#4818).
# =============================================================================
begin_test "KNOWN-RED pin: repository-owner role on email-subscriptions and release-target"
c1="$(req POST "/api/v1/repositories/${P}/email-subscriptions" "$OT" \
  "$(jq -nc --arg m "rma-ownerrole-${SUF}@t.test" '{recipients:[$m],event_types:["artifact.uploaded"]}')")"
b1="$(body)"
c2="$(req PUT "/api/v1/promotion/repositories/${S}/release-target" "$OT" "$(jq -nc --arg k "$L1" '{release_repository_key:$k}')")"
b2="$(body)"
if [ "${c1:0:1}" = "2" ] && [ "$c2" = "200" ]; then ok=1; else ok=0; fi
known_red "${OWNER_ISSUE}" "repository-owner role member: email-subscriptions POST -> ${c1} ${b1}, release-target PUT -> ${c2} ${b2} (expected 2xx/200)" "$ok"
pass

# =============================================================================
# GHSA-mvmh finding 8 - peers probe is admin-only
# =============================================================================
PA_ID="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc \
  "INSERT INTO peer_instances (name, endpoint_url) VALUES ('${PEER_A}', 'http://peer-a.invalid') RETURNING id;" 2>/dev/null | head -n1 | tr -d '[:space:]')"
PB_ID="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc \
  "INSERT INTO peer_instances (name, endpoint_url) VALUES ('${PEER_B}', 'http://peer-b.invalid') RETURNING id;" 2>/dev/null | head -n1 | tr -d '[:space:]')"
if [ "${#PA_ID}" != "36" ] || [ "${#PB_ID}" != "36" ]; then
  begin_test "setup: seed two peer instances"; infra_fail "peer ids A='${PA_ID}' B='${PB_ID}'"; end_suite
fi
probe_latency() { db "SELECT coalesce((SELECT latency_ms::text FROM peer_connections WHERE source_peer_id='${PA_ID}' AND target_peer_id='${PB_ID}'),'NONE');"; }

begin_test "mvmh peers fix: non-admin POST /peers/{id}/connections/probe -> 403, no connection metrics"
c="$(req POST "/api/v1/peers/${PA_ID}/connections/probe" "$NT" "$(jq -nc --arg t "$PB_ID" '{target_peer_id:$t,latency_ms:1}')")"
if denied "$c" && [ "$(probe_latency)" = "NONE" ]; then pass
else fail "non-admin wrote peer connection metrics: HTTP ${c}, latency=$(probe_latency)" "$(body)"; fi

begin_test "mvmh peers control: admin POST /peers/{id}/connections/probe -> 200, metrics recorded"
c="$(req POST "/api/v1/peers/${PA_ID}/connections/probe" "$AT" "$(jq -nc --arg t "$PB_ID" '{target_peer_id:$t,latency_ms:42}')")"
if [ "$c" = "200" ] && [ "$(probe_latency)" = "42" ]; then pass
else fail "admin probe: HTTP ${c}, latency=$(probe_latency)" "$(body)"; fi

# =============================================================================
# GHSA-mvmh finding 9 - proxy-scans/rescan needs `write`
# =============================================================================
# No path is cached in P, so a caller who gets past authorization meets the
# handler's own 404 "not in the proxy cache". The fix answers 403 before it.
RESCAN='{"path":"rma/not-cached.bin"}'

begin_test "mvmh rescan control: developer member passes authorization (handler's not-cached 404, not 403)"
c="$(req POST "/api/v1/repositories/${P}/security/proxy-scans/rescan" "$DT" "$RESCAN")"
if [ "$c" = "404" ] && ! jb '.message // ""' | grep -qi 'repository not found'; then pass
else fail "developer rescan: HTTP ${c} (expected the handler's not-cached 404)" "$(body)"; fi

begin_test "mvmh rescan fix: non-member POST /repositories/{public}/security/proxy-scans/rescan -> 403"
c="$(req POST "/api/v1/repositories/${P}/security/proxy-scans/rescan" "$NT" "$RESCAN")"
if [ "$c" = "403" ]; then pass
else fail "non-member reached the rescan handler: HTTP ${c} (expected 403 ahead of the cache lookup)" "$(body)"; fi

end_suite
