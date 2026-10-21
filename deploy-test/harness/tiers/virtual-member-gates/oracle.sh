#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-member-gates/oracle.sh: a virtual applies each member's own
#   gates (artifact-keeper#4098/#4343, #4286, #4346)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-npm` and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bugs.
#
# Topology (keys suffixed per run):
#   A  #4098  R1, R2  npm remotes -> mock (/m1, /m2), scan-on-proxy fail_open;
#                     R1 holds new packages 60 min (quarantine)
#             V       npm virtual {R1 (prio 1), R2 (prio 2)}
#   B  #4286  HN      npm hosted, dtf-gated 1.0.0       NV  npm virtual {HN}
#             HM      maven hosted, release jar + SNAPSHOT (timestamped)
#             MV      maven virtual {HM}
#             block_unscanned policies on HN and HM, attached after the
#             pre-policy controls and deleted before the post-policy ones
#   C  #4346  RA      rpm hosted PUBLIC  (akdep-lib)    RB  rpm hosted PRIVATE (akdep-app)
#             RV      rpm virtual PUBLIC {RA, RB}
#             RI      rpm hosted INTERNAL; RV2 rpm virtual; DU a user holding
#                     repository:admin on RV2 only (delegated virtual admin)
#
# Every FIX case is RED on 1.10.0 and GREEN on 1.11.0+; every CONTROL holds on
# both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly, so a non-zero helper (grep with no match, jq on a
# non-JSON error body) must not end the suite before the assertion runs.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:?}"
MOCK="http://172.16.${SLOT}.90"
MOCK_CTR="ak-dtf${SLOT}-mock-npm"

R1="vmg-r1-${SUF}";  R2="vmg-r2-${SUF}";  V="vmg-v-${SUF}"
HN="vmg-hn-${SUF}";  NV="vmg-nv-${SUF}"
HM="vmg-hm-${SUF}";  MV="vmg-mv-${SUF}"
RA="vmg-ra-${SUF}";  RB="vmg-rb-${SUF}";  RV="vmg-rv-${SUF}"
RI="vmg-ri-${SUF}";  RV2="vmg-rv2-${SUF}"
DU="vmg-du-${SUF//-/}"; DU_PASS="VmgDelegate_${SUF//-/}_Aa1!"

HELD_TGZ="dtf-held/-/dtf-held-1.0.0.tgz"
GATED_PKG="dtf-gated-${SUF//-/}"
GATED_VER="1.0.0"
GATED_TGZ="${GATED_PKG}/-/${GATED_PKG}-${GATED_VER}.tgz"
MGROUP="com/dtf/vmg${SUF//-/}"
REL_JAR="${MGROUP}/gated/1.0/gated-1.0.jar"
SNAP_DIR="${MGROUP}/snap/1.0-SNAPSHOT"
SNAP_TS="20261018.120000"
SNAP_TS_JAR="${SNAP_DIR}/snap-1.0-${SNAP_TS}-1.jar"
SNAP_ALIAS="${SNAP_DIR}/snap-1.0-SNAPSHOT.jar"
RPM_DIR="${DTF_DIR}/fixtures/rpm"
RPM_PUB="akdep-lib-1.0-1.noarch.rpm"
RPM_PRIV="akdep-app-2.0-1.noarch.rpm"

WORK="$(mktemp -d -t dtf-vmg-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# get PATH OUT [curl args...] -> HTTP status (body in OUT)
get() {
  local p="$1" out="$2"; shift 2
  curl -s --max-time 60 -o "$out" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}
AUTH=()
# send METHOD PATH JSON [token] -> HTTP status (body in $WORK/send.out)
send() {
  local tok="${4:-$ADMIN_TOKEN}"
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
put_file() {  # put_file PATH FILE CONTENT_TYPE -> HTTP status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: $3" \
    --data-binary "@$2" "${BASE_URL}$1" 2>/dev/null || echo 000
}
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null; }
mock_hits() { docker logs "$MOCK_CTR" 2>&1 | grep -c "MOCKNPM GET /$1 " || true; }
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
is_denied() { [ "$1" = "403" ] || [ "$1" = "404" ]; }

begin_suite "virtual-member-gates (#4098 #4343 #4286 #4346)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: repositories, members, uploads, delegated admin"
auth_admin
AUTH=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
err=""
mkrepo() {  # mkrepo JSON
  local st; st="$(send POST /api/v1/repositories "$1")"
  ok2xx "$st" || err+="create $(echo "$1" | jq -r .key) -> ${st} $(head -c 160 "$WORK/send.out"); "
}
mkrepo "{\"key\":\"${R1}\",\"name\":\"${R1}\",\"format\":\"npm\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"${MOCK}/m1\"}"
mkrepo "{\"key\":\"${R2}\",\"name\":\"${R2}\",\"format\":\"npm\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"${MOCK}/m2\"}"
for r in "$R1" "$R2"; do
  st="$(send PUT "/api/v1/repositories/${r}/security" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_open"}')"
  ok2xx "$st" || err+="scan-on-proxy ${r} -> ${st}; "
done
st="$(send PATCH "/api/v1/repositories/${R1}" '{"quarantine_enabled":true,"quarantine_duration_minutes":60}')"
ok2xx "$st" || err+="quarantine ${R1} -> ${st} $(head -c 160 "$WORK/send.out"); "
mkrepo "{\"key\":\"${V}\",\"name\":\"${V}\",\"format\":\"npm\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[{\"repo_key\":\"${R1}\",\"priority\":1},{\"repo_key\":\"${R2}\",\"priority\":2}]}"

mkrepo "{\"key\":\"${HN}\",\"name\":\"${HN}\",\"format\":\"npm\",\"repo_type\":\"local\",\"is_public\":true}"
mkrepo "{\"key\":\"${NV}\",\"name\":\"${NV}\",\"format\":\"npm\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[{\"repo_key\":\"${HN}\",\"priority\":1}]}"
mkdir -p "$WORK/npmsrc/package"
printf '{"name":"%s","version":"%s"}\n' "$GATED_PKG" "$GATED_VER" > "$WORK/npmsrc/package/package.json"
printf 'module.exports = "vmg-%s";\n' "$SUF" > "$WORK/npmsrc/package/index.js"
tar czf "$WORK/gated.tgz" -C "$WORK/npmsrc" package
base64 < "$WORK/gated.tgz" | tr -d '\n' > "$WORK/gated.b64"
jq -n --arg name "$GATED_PKG" --arg version "$GATED_VER" \
  --arg tarball "${BASE_URL}/npm/${HN}/${GATED_TGZ}" --rawfile data "$WORK/gated.b64" \
  --argjson length "$(wc -c < "$WORK/gated.tgz" | tr -d ' ')" \
  '{name: $name, "dist-tags": {latest: $version},
    versions: {($version): {name: $name, version: $version, dist: {tarball: $tarball}}},
    "_attachments": {("\($name)-\($version).tgz"): {content_type: "application/octet-stream", data: $data, length: $length}}}' \
  > "$WORK/gated.json"
st="$(put_file "/npm/${HN}/${GATED_PKG}" "$WORK/gated.json" application/json)"
ok2xx "$st" || err+="npm publish -> ${st} $(head -c 160 "$WORK/put.out"); "

mkrepo "{\"key\":\"${HM}\",\"name\":\"${HM}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}"
mkrepo "{\"key\":\"${MV}\",\"name\":\"${MV}\",\"format\":\"maven\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[{\"repo_key\":\"${HM}\",\"priority\":1}]}"
printf 'vmg-release-jar-%s' "$SUF" > "$WORK/rel.jar"
printf 'vmg-snapshot-jar-%s' "$SUF" > "$WORK/snap.jar"
cat > "$WORK/snap-meta.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<metadata modelVersion="1.1.0">
  <groupId>${MGROUP//\//.}</groupId>
  <artifactId>snap</artifactId>
  <version>1.0-SNAPSHOT</version>
  <versioning>
    <snapshot><timestamp>${SNAP_TS}</timestamp><buildNumber>1</buildNumber></snapshot>
    <lastUpdated>${SNAP_TS//./}</lastUpdated>
    <snapshotVersions>
      <snapshotVersion><extension>jar</extension><value>1.0-${SNAP_TS}-1</value><updated>${SNAP_TS//./}</updated></snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>
XML
for spec in "${REL_JAR}|$WORK/rel.jar|application/java-archive" \
            "${SNAP_TS_JAR}|$WORK/snap.jar|application/java-archive" \
            "${SNAP_DIR}/maven-metadata.xml|$WORK/snap-meta.xml|application/xml"; do
  IFS='|' read -r p f ct <<<"$spec"
  st="$(put_file "/maven/${HM}/${p}" "$f" "$ct")"
  ok2xx "$st" || err+="maven PUT ${p} -> ${st}; "
done

mkrepo "{\"key\":\"${RA}\",\"name\":\"${RA}\",\"format\":\"rpm\",\"repo_type\":\"local\",\"is_public\":true}"
mkrepo "{\"key\":\"${RB}\",\"name\":\"${RB}\",\"format\":\"rpm\",\"repo_type\":\"local\",\"is_public\":false}"
mkrepo "{\"key\":\"${RV}\",\"name\":\"${RV}\",\"format\":\"rpm\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[{\"repo_key\":\"${RA}\",\"priority\":1},{\"repo_key\":\"${RB}\",\"priority\":2}]}"
st="$(put_file "/rpm/${RA}/packages/${RPM_PUB}" "${RPM_DIR}/${RPM_PUB}" application/x-rpm)"
ok2xx "$st" || err+="rpm upload ${RPM_PUB} -> ${st}; "
st="$(put_file "/rpm/${RB}/packages/${RPM_PRIV}" "${RPM_DIR}/${RPM_PRIV}" application/x-rpm)"
ok2xx "$st" || err+="rpm upload ${RPM_PRIV} -> ${st}; "

mkrepo "{\"key\":\"${RI}\",\"name\":\"${RI}\",\"format\":\"rpm\",\"repo_type\":\"local\",\"is_public\":false,\"visibility\":\"internal\"}"
mkrepo "{\"key\":\"${RV2}\",\"name\":\"${RV2}\",\"format\":\"rpm\",\"repo_type\":\"virtual\",\"is_public\":true}"
DU_ID="$(create_test_user_with_retry "$DU" "$DU_PASS" "${DU}@t.test" 2>/dev/null || true)"
# Delegated virtual admin: the fine-grained repository:admin grant on RV2 that
# authorize_virtual_member_mutation checks, and nothing on any member.
RV2_ID="$(psql_q "SELECT id FROM repositories WHERE key='${RV2}'")"
st="$(send POST /api/v1/permissions "{\"principal_type\":\"user\",\"principal_id\":\"${DU_ID}\",\"target_type\":\"repository\",\"target_id\":\"${RV2_ID}\",\"actions\":[\"read\",\"admin\"]}")"
ok2xx "$st" || err+="grant repository:admin on ${RV2} -> ${st} $(head -c 160 "$WORK/send.out"); "
DU_TOK=""
[ -n "$DU_ID" ] && [ "$DU_ID" != "null" ] && DU_TOK="$(login_as "$DU" "$DU_PASS" 2>/dev/null || true)"
[ -n "$DU_TOK" ] || err+="delegated admin user/login; "

if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass

# =============================================================================
# A. #4098/#4343: a member's quarantine hold is final for the virtual walk
# =============================================================================
begin_test "CONTROL: the npm virtual's packument lists dtf-held 1.0.0 from its members"
st="$(get "/npm/${V}/dtf-held" "$WORK/v_pack.json" "${AUTH[@]}")"
if [ "$st" = "200" ] && jq -e '.versions["1.0.0"]' "$WORK/v_pack.json" >/dev/null 2>&1; then
  pass
else
  fail "virtual packument: HTTP ${st}" "$(head -c 300 "$WORK/v_pack.json")"
fi

begin_test "FIX #4098/#4343: the tarball through the virtual answers the first member's 409 hold, and the second member never fetches it"
m2_before="$(mock_hits "m2/${HELD_TGZ}")"
st="$(get "/npm/${V}/${HELD_TGZ}" "$WORK/v_held.tgz" "${AUTH[@]}")"
m2_after="$(mock_hits "m2/${HELD_TGZ}")"
if [ "$st" = "409" ] && [ "$m2_after" = "$m2_before" ]; then
  pass
else
  fail "the virtual walked past the quarantine hold: HTTP ${st}, second member's upstream tarball GETs ${m2_before}->${m2_after}" \
    "body: $(head -c 300 "$WORK/v_held.tgz" | tr -cd '[:alnum:][:space:]{}":,._-' | head -c 200)"
fi

begin_test "CONTROL: the quarantined member answers 409 directly; the other member serves the upstream tarball"
st1="$(get "/npm/${R1}/${HELD_TGZ}" "$WORK/r1_held.tgz" "${AUTH[@]}")"
get "/npm/${R2}/dtf-held" "$WORK/r2_pack.json" "${AUTH[@]}" >/dev/null
st2="$(get "/npm/${R2}/${HELD_TGZ}" "$WORK/r2_held.tgz" "${AUTH[@]}")"
if [ "$st1" = "409" ] && [ "$st2" = "200" ] && tar tzf "$WORK/r2_held.tgz" 2>/dev/null | grep -q "package/package.json"; then
  pass
else
  fail "member behaviour changed: R1 HTTP ${st1} (want 409), R2 HTTP ${st2} (want 200 + tarball)"
fi

# =============================================================================
# B. #4286: the scan policy of a hosted member applies through the virtual
# =============================================================================
begin_test "CONTROL: before any policy, npm and Maven content is served directly and through the virtuals"
c1="$(get "/npm/${NV}/${GATED_TGZ}" "$WORK/nv_pre.tgz" "${AUTH[@]}")"
c2="$(get "/maven/${MV}/${REL_JAR}" "$WORK/mv_pre.jar" "${AUTH[@]}")"
c3="$(get "/maven/${HM}/${SNAP_ALIAS}" "$WORK/hm_alias_pre.jar" "${AUTH[@]}")"
c4="$(get "/maven/${MV}/${SNAP_ALIAS}" "$WORK/mv_alias_pre.jar" "${AUTH[@]}")"
if [ "$c1" = "200" ] && cmp -s "$WORK/nv_pre.tgz" "$WORK/gated.tgz" && [ "$c2" = "200" ] \
   && [ "$c3" = "200" ] && cmp -s "$WORK/hm_alias_pre.jar" "$WORK/snap.jar" && [ "$c4" = "200" ]; then
  pass
else
  fail "pre-policy reads: npm virtual tarball ${c1}, maven virtual jar ${c2}, hosted SNAPSHOT alias ${c3}, virtual SNAPSHOT alias ${c4} (all want 200)"
fi

POL_IDS=""
for r in "$HN" "$HM"; do
  rid="$(psql_q "SELECT id FROM repositories WHERE key='${r}'")"
  st="$(send POST /api/v1/security/policies "{\"name\":\"vmg-${r}\",\"repository_id\":\"${rid}\",\"max_severity\":\"critical\",\"block_unscanned\":true,\"block_on_fail\":false}")"
  pid="$(jq -r '.id // empty' "$WORK/send.out" 2>/dev/null)"
  POL_IDS+="${pid} "
  ok2xx "$st" || echo "  policy create for ${r} -> HTTP ${st}: $(head -c 200 "$WORK/send.out")"
done

begin_test "CONTROL: with block_unscanned on the hosted repos, the direct hosted reads are refused 403"
d1="$(get "/maven/${HM}/${REL_JAR}" "$WORK/hm_rel.jar" "${AUTH[@]}")"
if [ "$d1" = "403" ] && grep -qi "scan policy" "$WORK/hm_rel.jar"; then
  pass
else
  fail "direct hosted maven jar under block_unscanned: HTTP ${d1} (want 403 scan-policy)" "$(head -c 200 "$WORK/hm_rel.jar")"
fi

begin_test "FIX #4286: the npm virtual does not serve the hosted tarball its member's policy blocks (403), packument still 200"
p="$(get "/npm/${NV}/${GATED_PKG}" "$WORK/nv_pack.json" "${AUTH[@]}")"
t="$(get "/npm/${NV}/${GATED_TGZ}" "$WORK/nv_post.tgz" "${AUTH[@]}")"
if [ "$p" = "200" ] && [ "$t" = "403" ] && ! cmp -s "$WORK/nv_post.tgz" "$WORK/gated.tgz"; then
  pass
else
  fail "npm virtual served a scan-policy-blocked hosted tarball: packument ${p}, tarball ${t} (want 403)"
fi

# The direct hosted npm and Maven reads were already gated before #4286 (they
# pass on the pre-fix image too); the bug was the virtual's fallback lookup.
begin_test "CONTROL: the npm hosted route refuses the blocked tarball (403)"
t="$(get "/npm/${HN}/${GATED_TGZ}" "$WORK/hn_post.tgz" "${AUTH[@]}")"
if [ "$t" = "403" ]; then
  pass
else
  fail "npm hosted tarball under block_unscanned: HTTP ${t} (want 403)"
fi

begin_test "CONTROL: the Maven virtual refuses the blocked release jar (403)"
t="$(get "/maven/${MV}/${REL_JAR}" "$WORK/mv_post.jar" "${AUTH[@]}")"
if [ "$t" = "403" ] && ! cmp -s "$WORK/mv_post.jar" "$WORK/rel.jar"; then
  pass
else
  fail "maven virtual served a scan-policy-blocked hosted jar: HTTP ${t} (want 403)"
fi

begin_test "FIX #4286: the -SNAPSHOT alias is gated on the hosted route and through the virtual (403)"
a1="$(get "/maven/${HM}/${SNAP_ALIAS}" "$WORK/hm_alias.jar" "${AUTH[@]}")"
a2="$(get "/maven/${MV}/${SNAP_ALIAS}" "$WORK/mv_alias.jar" "${AUTH[@]}")"
if [ "$a1" = "403" ] && [ "$a2" = "403" ]; then
  pass
else
  fail "SNAPSHOT alias bypasses the download gate: hosted ${a1}, virtual ${a2} (want 403 both)"
fi

for pid in $POL_IDS; do send DELETE "/api/v1/security/policies/${pid}" >/dev/null; done
begin_test "CONTROL: after the policies are deleted, the virtuals serve again"
c1="$(get "/npm/${NV}/${GATED_TGZ}" "$WORK/nv_after.tgz" "${AUTH[@]}")"
c2="$(get "/maven/${MV}/${SNAP_ALIAS}" "$WORK/mv_alias_after.jar" "${AUTH[@]}")"
if [ "$c1" = "200" ] && cmp -s "$WORK/nv_after.tgz" "$WORK/gated.tgz" && [ "$c2" = "200" ] && cmp -s "$WORK/mv_alias_after.jar" "$WORK/snap.jar"; then
  pass
else
  fail "post-policy reads: npm virtual tarball ${c1}, maven virtual SNAPSHOT alias ${c2} (want 200 + bytes)"
fi

# =============================================================================
# C. #4346: RPM virtual repodata lists only members the caller may read
# =============================================================================
gunzip_names() { gzip -dc "$1" 2>/dev/null | grep -o '<name>[^<]*</name>' | sort -u | tr '\n' ' '; }
sa="$(get "/rpm/${RV}/repodata/primary.xml.gz" "$WORK/rv_admin.xml.gz" "${AUTH[@]}")"
ADMIN_NAMES="$(gunzip_names "$WORK/rv_admin.xml.gz")"
get "/rpm/${RV}/repodata/repomd.xml" "$WORK/rv_admin_repomd.xml" "${AUTH[@]}" >/dev/null
sn="$(get "/rpm/${RV}/repodata/primary.xml.gz" "$WORK/rv_anon.xml.gz")"
ANON_NAMES="$(gunzip_names "$WORK/rv_anon.xml.gz")"
get "/rpm/${RV}/repodata/repomd.xml" "$WORK/rv_anon_repomd.xml" >/dev/null

begin_test "CONTROL: the admin's virtual primary.xml.gz lists both members' packages; the private member refuses anonymous reads"
spriv="$(get "/rpm/${RB}/repodata/primary.xml.gz" "$WORK/rb_anon.xml.gz")"
if [ "$sa" = "200" ] && [[ "$ADMIN_NAMES" == *"<name>akdep-lib</name>"* ]] && [[ "$ADMIN_NAMES" == *"<name>akdep-app</name>"* ]] \
   && { [ "$spriv" = "401" ] || is_denied "$spriv"; }; then
  pass
else
  fail "admin view or private member visibility wrong: admin HTTP ${sa} names=[${ADMIN_NAMES}], anonymous private member HTTP ${spriv}"
fi

begin_test "FIX #4346: an anonymous caller's virtual primary.xml.gz lists the public member's package and NOT the private member's"
if [ "$sn" = "200" ] && [[ "$ANON_NAMES" == *"<name>akdep-lib</name>"* ]] && [[ "$ANON_NAMES" != *"akdep-app"* ]]; then
  pass
else
  fail "the public virtual leaks the private member's package metadata to an anonymous caller: HTTP ${sn} names=[${ANON_NAMES}]"
fi

begin_test "FIX #4346: the anonymous and admin repomd.xml are different documents (render cache keyed per member set)"
if [ -s "$WORK/rv_anon_repomd.xml" ] && [ -s "$WORK/rv_admin_repomd.xml" ] && ! cmp -s "$WORK/rv_anon_repomd.xml" "$WORK/rv_admin_repomd.xml"; then
  pass
else
  fail "anonymous and admin callers were served the same repomd.xml for different member sets"
fi

# =============================================================================
# D. #4346: attaching an internal repository needs a read grant
# =============================================================================
begin_test "CONTROL: the delegated admin of a virtual attaches a public repository (2xx, persisted)"
st="$(send POST "/api/v1/repositories/${RV2}/members" "{\"member_key\":\"${RA}\"}" "$DU_TOK")"
n="$(psql_q "SELECT count(*) FROM virtual_repo_members m JOIN repositories v ON v.id=m.virtual_repo_id
  JOIN repositories r ON r.id=m.member_repo_id WHERE v.key='${RV2}' AND r.key='${RA}'")"
if ok2xx "$st" && [ "$n" = "1" ]; then
  pass
else
  fail "delegated admin could not attach a public member: HTTP ${st}, rows=${n}" "$(head -c 300 "$WORK/send.out")"
fi

begin_test "FIX #4346: the same delegated admin attaching an INTERNAL repository without a read grant is refused 403 naming the grant"
VIS="$(api_get "/api/v1/repositories/${RI}" 2>/dev/null | jq -r '.visibility // empty' 2>/dev/null)"
st="$(send POST "/api/v1/repositories/${RV2}/members" "{\"member_key\":\"${RI}\"}" "$DU_TOK")"
n="$(psql_q "SELECT count(*) FROM virtual_repo_members m JOIN repositories v ON v.id=m.virtual_repo_id
  JOIN repositories r ON r.id=m.member_repo_id WHERE v.key='${RV2}' AND r.key='${RI}'")"
if [ "$VIS" = "internal" ] && [ "$st" = "403" ] && grep -q "requires a read grant" "$WORK/send.out" && [ "$n" = "0" ]; then
  pass
else
  fail "internal member attach not refused: visibility='${VIS}', HTTP ${st}, rows=${n}" "$(head -c 300 "$WORK/send.out")"
fi

end_suite
