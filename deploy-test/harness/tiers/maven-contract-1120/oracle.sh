#!/usr/bin/env bash
# =============================================================================
# tiers/maven-contract-1120/oracle.sh
#   Maven native-protocol contracts fixed for 1.12.0:
#   #5668 empty hosted repo prefix file, unreachable Remote upstream status;
#   #5678 identical checksum-sidecar re-upload; #5693 plugin-prefix path for
#   non-group-level metadata; #5713 Maven ComparableVersion ordering.
#   See the manifest for the gates. Every request is a native /maven/ PUT or
#   GET except repository creation and the #5693 artifact listing read.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}${RUN_ID##*-}$$"
SFX="$(printf '%s' "$SFX" | tr -cd 'a-z0-9')"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# req <METHOD> <URL-PATH> [JSON body]: admin bearer; sets CODE, BODY, HDRS.
req(){
  local m="$1" p="$2" d="${3:-}"
  local -a ca=(-s -o "${W}/body" -D "${W}/hdrs" -w '%{http_code}' --max-time 60 -X "$m"
               -H "Authorization: Bearer ${TOK}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"; : >"${W}/hdrs"
  CODE="$(curl "${ca[@]}" "${BASE}${p}")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
  HDRS="$(tr -d '\r' <"${W}/hdrs" 2>/dev/null || true)"
}
# mput <repo> <path> <body> -> native Maven PUT; sets CODE, BODY.
mput(){
  printf '%s' "$3" >"${W}/put"
  CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 60 -X PUT \
    -H "Authorization: Bearer ${TOK}" --data-binary "@${W}/put" "${BASE}/maven/$1/$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
mget(){ req GET "/maven/$1/$2"; }
hdr(){ printf '%s\n' "$HDRS" | grep -i "^$1:" | head -1 | cut -d: -f2- | sed 's/^ *//'; }
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
mk_repo(){ # <key> <type> [upstream]
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"maven",repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')"
}
sha1_of(){ printf '%s' "$1" | sha1sum | cut -d' ' -f1; }
# xml_list <xml> -> the <version> entries, space separated, in document order
xml_list(){ printf '%s' "$1" | tr -d '\n' | grep -o '<version>[^<]*</version>' \
  | sed 's/<[^>]*>//g' | tr '\n' ' ' | sed 's/ $//'; }
xml_tag(){ printf '%s' "$1" | tr -d '\n' | grep -o "<$2>[^<]*</$2>" | head -1 | sed 's/<[^>]*>//g'; }

begin_suite "maven-contract-1120"

# =============================================================================
begin_test "setup: admin session and hosted Maven repositories"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
R_EMPTY="mc12empty${SFX}"   # #5668 prefixes (stays empty until the control publishes)
R_SIDE="mc12side${SFX}"     # #5678 sidecars
R_PLUG="mc12plug${SFX}"     # #5693 metadata
R_VER="mc12ver${SFX}"       # #5713 ordering
for r in "$R_EMPTY" "$R_SIDE" "$R_PLUG" "$R_VER"; do
  mk_repo "$r" local
  is_2xx "$CODE" || { infra_fail "creating ${r} answered ${CODE}: ${BODY:0:200}"; end_suite; }
done
pass

# =============================================================================
# #5668 empty prefix file
# =============================================================================
begin_test "FIX #5668: an empty hosted repo answers 404 (no-store), not a header-only allowlist, for .meta/prefixes.txt"
reset_case
mget "$R_EMPTY" .meta/prefixes.txt
CC="$(hdr cache-control)"
note "GET .meta/prefixes.txt (no artifacts): ${CODE} cache-control='${CC}' body='$(printf '%s' "$BODY" | head -c 120 | tr '\n' '|')'"
[ "$CODE" = "404" ] || fail_g "an empty repo's prefix file answered ${CODE}, not 404 (a header-only file denies every path to Maven Resolver)"
[ "$CC" = "no-store" ] || fail_g "the answer carries Cache-Control '${CC}', not no-store"
mget "$R_EMPTY" .meta/prefixes.txt.sha1
note "GET .meta/prefixes.txt.sha1: ${CODE}"
[ "$CODE" = "404" ] || fail_g "the prefix file's .sha1 answered ${CODE}, not 404"
finish_case "an empty hosted repository serves an empty .meta/prefixes.txt"

begin_test "CONTROL: after the first publish the prefix file is 200 and lists the group"
reset_case
G5668="com/acme/pfx${SFX}"
mput "$R_EMPTY" "${G5668}/lib/1.0/lib-1.0.jar" "prefix control jar ${SFX}"
note "PUT jar: ${CODE}"
[ "$CODE" = "201" ] || fail_g "PUT jar answered ${CODE}: ${BODY:0:200}"
mget "$R_EMPTY" .meta/prefixes.txt
note "GET .meta/prefixes.txt: ${CODE} body='$(printf '%s' "$BODY" | tr '\n' '|')'"
[ "$CODE" = "200" ] || fail_g "prefix file answered ${CODE} after a publish"
printf '%s\n' "$BODY" | grep -qx "/${G5668}" || fail_g "prefix file does not list /${G5668}"
finish_case "the prefix file is wrong after a publish"

# =============================================================================
# #5668 unreachable Remote upstream
# =============================================================================
begin_test "FIX #5668: a Remote whose upstream does not resolve answers 502, not 500 STORAGE_ERROR"
reset_case
R_REM="mc12rem${SFX}"
mk_repo "$R_REM" remote "http://mvn-upstream-${SFX}.invalid/maven2"
note "create remote: ${CODE}"
if is_2xx "$CODE"; then
  mget "$R_REM" "org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.pom"
  note "GET pom through the remote: ${CODE} body='${BODY:0:200}'"
  [ "$CODE" = "502" ] || fail_g "an unreachable upstream answered ${CODE}, not 502"
  case "$BODY" in *STORAGE_ERROR*) fail_g "the body names STORAGE_ERROR";; esac
else
  fail_g "creating the remote answered ${CODE}: ${BODY:0:200}"
fi
finish_case "an unreachable upstream is reported as a storage error"

# =============================================================================
# #5678 checksum sidecars
# =============================================================================
G5678="com/acme/side${SFX}/lib"
JAR_A="sidecar jar A ${SFX}"
SHA_A="$(sha1_of "$JAR_A")"

begin_test "CONTROL: a released jar and its correct .sha1 are stored and served"
reset_case
mput "$R_SIDE" "${G5678}/1.0/lib-1.0.jar" "$JAR_A"; note "PUT jar: ${CODE}"
[ "$CODE" = "201" ] || fail_g "PUT jar answered ${CODE}: ${BODY:0:200}"
mput "$R_SIDE" "${G5678}/1.0/lib-1.0.jar.sha1" "$SHA_A"; note "PUT .sha1: ${CODE}"
[ "$CODE" = "201" ] || fail_g "first PUT .sha1 answered ${CODE}: ${BODY:0:200}"
mget "$R_SIDE" "${G5678}/1.0/lib-1.0.jar"
[ "$CODE" = "200" ] && [ "$BODY" = "$JAR_A" ] || fail_g "GET jar answered ${CODE} (bytes match: $([ "$BODY" = "$JAR_A" ] && echo yes || echo no))"
mget "$R_SIDE" "${G5678}/1.0/lib-1.0.jar.sha1"
note "GET .sha1: ${CODE} '${BODY:0:60}'"
[ "$CODE" = "200" ] && [ "${BODY%% *}" = "$SHA_A" ] || fail_g "GET .sha1 does not serve ${SHA_A}"
finish_case "a released jar and its .sha1 do not round-trip"

begin_test "FIX #5678: re-uploading the identical .sha1 of a released jar succeeds (a retried deploy PUT)"
reset_case
mput "$R_SIDE" "${G5678}/1.0/lib-1.0.jar.sha1" "$SHA_A"
note "identical .sha1 again: ${CODE} ${BODY:0:200}"
is_2xx "$CODE" || fail_g "an identical .sha1 re-upload answered ${CODE}, not 200/201"
UP_A="$(printf '%s  lib-1.0.jar' "$SHA_A" | tr 'a-f' 'A-F')"
mput "$R_SIDE" "${G5678}/1.0/lib-1.0.jar.sha1" "$UP_A"
note "same digest, upper case two-field form: ${CODE}"
is_2xx "$CODE" || fail_g "the same digest in '<HEX>  <file>' form answered ${CODE}, not 200/201"
mput "$R_SIDE" "${G5678}/1.0/lib-1.0.jar.sha1" "$(sha1_of "something else")"
note "a different .sha1: ${CODE}"
[ "$CODE" = "409" ] || fail_g "a different .sha1 for the released jar answered ${CODE}, not 409"
mget "$R_SIDE" "${G5678}/1.0/lib-1.0.jar.sha1"
[ "${BODY%% *}" = "$SHA_A" ] || fail_g "the served .sha1 changed to '${BODY:0:60}'"
finish_case "an identical checksum-sidecar re-upload is refused"

begin_test "FIX #5678: the deploy's correct .sha1 replaces a wrong one stored before its jar"
reset_case
JAR_B="sidecar jar B ${SFX}"
SHA_B="$(sha1_of "$JAR_B")"
mput "$R_SIDE" "${G5678}/2.0/lib-2.0.jar.sha1" "$(sha1_of "not the jar")"; note "wrong .sha1 before its jar: ${CODE}"
mput "$R_SIDE" "${G5678}/2.0/lib-2.0.jar" "$JAR_B"; note "PUT jar: ${CODE}"
[ "$CODE" = "201" ] || fail_g "PUT jar answered ${CODE}: ${BODY:0:200}"
mput "$R_SIDE" "${G5678}/2.0/lib-2.0.jar.sha1" "$SHA_B"
note "the jar's own .sha1: ${CODE} ${BODY:0:200}"
is_2xx "$CODE" || fail_g "the jar's correct .sha1 answered ${CODE}: a wrong sidecar uploaded first locked the release"
mget "$R_SIDE" "${G5678}/2.0/lib-2.0.jar.sha1"
note "GET .sha1: ${CODE} '${BODY:0:60}'"
[ "${BODY%% *}" = "$SHA_B" ] || fail_g "the served .sha1 is not the jar's digest ${SHA_B}"
finish_case "a wrong sidecar stored before its artifact cannot be corrected"

# =============================================================================
# #5693 plugin-prefix detection
# =============================================================================
G5693="com/acme/plug${SFX}"
listed_meta(){ # how many listed artifacts of R_PLUG are a maven-metadata.xml
  req GET "/api/v1/repositories/${R_PLUG}/artifacts?per_page=200"
  jqr '[(.items // .)[]? | select((.path // "") | endswith("maven-metadata.xml")) | .path] | join(",")' <<<"$BODY"
}

begin_test "CONTROL: artifact-level and version-level maven-metadata.xml with a <plugins> block are stored and served"
reset_case
ART_META="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata><groupId>${G5693//\//.}</groupId><artifactId>lib</artifactId><versioning><latest>1.0</latest><release>1.0</release><versions><version>1.0</version></versions><lastUpdated>20260101000000</lastUpdated></versioning><plugins><plugin><name>marker-${SFX}</name><prefix>marker</prefix><artifactId>lib</artifactId></plugin></plugins></metadata>"
VER_META="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata><groupId>${G5693//\//.}</groupId><artifactId>lib</artifactId><version>2.0-SNAPSHOT</version><plugins><plugin><name>vmarker-${SFX}</name><prefix>vmarker</prefix><artifactId>lib</artifactId></plugin></plugins></metadata>"
mput "$R_PLUG" "${G5693}/lib/1.0/lib-1.0.jar" "plug jar ${SFX}"; note "PUT jar: ${CODE}"
[ "$CODE" = "201" ] || fail_g "PUT jar answered ${CODE}: ${BODY:0:200}"
mput "$R_PLUG" "${G5693}/lib/maven-metadata.xml" "$ART_META"; note "PUT artifact-level metadata: ${CODE}"
[ "$CODE" = "201" ] || fail_g "PUT artifact-level metadata answered ${CODE}: ${BODY:0:200}"
mput "$R_PLUG" "${G5693}/lib/2.0-SNAPSHOT/maven-metadata.xml" "$VER_META"; note "PUT version-level metadata: ${CODE}"
[ "$CODE" = "201" ] || fail_g "PUT version-level metadata answered ${CODE}: ${BODY:0:200}"
mget "$R_PLUG" "${G5693}/lib/maven-metadata.xml"
note "GET artifact-level metadata: ${CODE}"
[ "$CODE" = "200" ] && [[ "$BODY" == *"<version>1.0</version>"* ]] || fail_g "artifact-level metadata answered ${CODE}: ${BODY:0:200}"
mget "$R_PLUG" "${G5693}/lib/2.0-SNAPSHOT/maven-metadata.xml"
note "GET version-level metadata: ${CODE}"
[ "$CODE" = "200" ] && [[ "$BODY" == *"vmarker-${SFX}"* ]] || fail_g "version-level metadata answered ${CODE}: ${BODY:0:200}"
finish_case "Maven metadata uploads do not round-trip"

begin_test "FIX #5693: artifact-level and version-level metadata with <plugins> get no artifact row"
reset_case
L="$(listed_meta)"
note "artifact listing (${CODE}) maven-metadata.xml rows: '${L}'"
[ "$CODE" = "200" ] || fail_g "the artifact listing answered ${CODE}"
[ -z "$L" ] || fail_g "non-group-level metadata was published as a plugin-prefix artifact: ${L}"
finish_case "non-group-level metadata with <plugins> takes the plugin-prefix path"

# =============================================================================
# #5713 Maven ComparableVersion ordering
# =============================================================================
G5713="com/acme/ver${SFX}"
publish_versions(){ # <artifactId> <versions...>
  local a="$1"; shift
  local v
  for v in "$@"; do
    mput "$R_VER" "${G5713}/${a}/${v}/${a}-${v}.jar" "jar ${a} ${v}"
    note "PUT ${a} ${v}: ${CODE}"
    [ "$CODE" = "201" ] || fail_g "PUT ${a}-${v}.jar answered ${CODE}: ${BODY:0:200}"
  done
}
# check_order <artifactId> <expected versions order> <latest> <release>
check_order(){
  mget "$R_VER" "${G5713}/$1/maven-metadata.xml"
  local got latest release
  got="$(xml_list "$BODY")"; latest="$(xml_tag "$BODY" latest)"; release="$(xml_tag "$BODY" release)"
  note "GET $1 maven-metadata.xml: ${CODE} versions='${got}' latest='${latest}' release='${release}'"
  [ "$CODE" = "200" ] || { fail_g "metadata answered ${CODE}"; return; }
  [ "$got" = "$2" ] || fail_g "<versions> order '${got}', Maven orders '$2'"
  [ "$latest" = "$3" ] || fail_g "<latest> is '${latest}', Maven picks '$3'"
  [ "$release" = "$4" ] || fail_g "<release> is '${release}', Maven picks '$4'"
}

begin_test "CONTROL: conventional versions are ordered and latest/release picked as Maven does"
reset_case
publish_versions plain 1.10 2.0 1.2 2.0-rc-1 3.0-SNAPSHOT
check_order plain "1.2 1.10 2.0-rc-1 2.0 3.0-SNAPSHOT" 3.0-SNAPSHOT 2.0
finish_case "conventional Maven version ordering is wrong"

begin_test "FIX #5713: a version number past u64 orders above a small one (it parsed as 0)"
reset_case
publish_versions big 1.99999999999999999999 1.1
check_order big "1.1 1.99999999999999999999" 1.99999999999999999999 1.99999999999999999999
finish_case "maven-metadata.xml does not follow Maven's ComparableVersion for a large number"

begin_test "FIX #5713: a bare 'a' qualifier is not 'alpha' (Maven orders 1.0-a above 1.0)"
reset_case
publish_versions qual 1.0-a 1.0
check_order qual "1.0 1.0-a" 1.0-a 1.0-a
finish_case "maven-metadata.xml does not follow Maven's ComparableVersion for a bare qualifier letter"

end_suite
