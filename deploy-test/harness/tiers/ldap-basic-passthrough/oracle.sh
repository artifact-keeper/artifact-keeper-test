#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/ldap-basic-passthrough/oracle.sh
#   LDAP/AD Basic-auth passthrough on package routes (#3830) and its
#   follow-ups (#4933): guest-guard binds, one LOGIN_FAILED row, deactivation
#   wins over web login. See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${RUN_ID##*-}$$"
SFX="${SFX: -8}"
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

LDAP_CONTAINER="ak-dtf${DTF_SLOT}-ldap"
LDAP_BASE="dc=dtf,dc=local"
LDAP_PEOPLE="ou=people,${LDAP_BASE}"
LDAP_ADMIN_DN="cn=admin,${LDAP_BASE}"
# The sso.ldap admin password, assembled at run time (no credential literal).
LDAP_ADMIN_PW="$(printf '%s%s' admin pass)"

rand_pw(){ printf 'Dtf-%s-%s' "$(openssl rand -hex 6)" "$(openssl rand -hex 4)"; }

# areq <METHOD> <PATH> [JSON]: admin bearer call, sets CODE and BODY.
areq(){
  local -a ca=(-s -o "${W}/abody" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/abody"
  CODE="$(curl "${ca[@]}" "${BASE}$2" 2>/dev/null)"
  BODY="$(cat "${W}/abody" 2>/dev/null || true)"
}
# basic <user> <password> <PATH> [out-file]: GET with Basic, echoes the status.
basic(){
  curl -s -o "${4:-/dev/null}" -w '%{http_code}' --max-time 60 -u "$1:$2" "${BASE}$3" 2>/dev/null || echo 000
}
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
sqlq(){ printf '%s' "$1" | sed "s/'/''/g"; }
# dir_hits <uid>: slapd SRCH lines for (uid=<uid>) plus BIND lines for its DN.
dir_hits(){
  docker logs "$LDAP_CONTAINER" 2>&1 | grep -cE "filter=\"\\(uid=$1\\)\"|BIND dn=\"uid=$1,"
}
dir_binds(){
  docker logs "$LDAP_CONTAINER" 2>&1 | grep -c "BIND dn=\"uid=$1,"
}
audit_count(){ # <action> <username> [extra SQL predicate]
  psqlq "SELECT COUNT(*) FROM audit_log WHERE action = '$1' AND details->>'username' = '$(sqlq "$2")' ${3:-}"
}
# Audit rows are written fire-and-forget: give them a moment to land.
settle(){ sleep 2; }
web_login(){ # <user> <password>: echoes the status of the web LDAP login
  curl -s -o "${W}/weblogin" -w '%{http_code}' --max-time 30 -X POST -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" \
    "${BASE}/api/v1/auth/sso/ldap/${PROVIDER_ID}/login" 2>/dev/null || echo 000
}

begin_suite "ldap-basic-passthrough"

# =============================================================================
begin_test "setup: directory users, an LDAP provider, internal-visibility Maven and PyPI repos with one package each"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "${ADMIN_USER:-admin}" --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }

# One directory user per case, each with a random password. Usernames are
# lowercase alphanumerics so they need no escaping in slapd's log lines.
U_WEB="ptw${SFX}";  P_WEB="$(rand_pw)"
U_PKG="ptp${SFX}";  P_PKG="$(rand_pw)"
U_BAD="ptb${SFX}";  P_BAD="$(rand_pw)"
U_MGT="ptm${SFX}";  P_MGT="$(rand_pw)"
U_DEA="ptd${SFX}";  P_DEA="$(rand_pw)"
U_LOC="ptl${SFX}";  P_LOC="$(rand_pw)"
{
  printf 'dn: %s\nobjectClass: organizationalUnit\nou: people\n\n' "$LDAP_PEOPLE"
  for pair in "$U_WEB:$P_WEB" "$U_PKG:$P_PKG" "$U_BAD:$P_BAD" "$U_MGT:$P_MGT" "$U_DEA:$P_DEA" "$U_LOC:$P_LOC"; do
    u="${pair%%:*}"; p="${pair#*:}"
    printf 'dn: uid=%s,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: DTF\nmail: %s@dtf.local\nuserPassword: %s\n\n' \
      "$u" "$LDAP_PEOPLE" "$u" "$u" "$u" "$p"
  done
} > "${W}/seed.ldif"
seed_out="$(docker exec -i "$LDAP_CONTAINER" ldapadd -c -x -H ldap://localhost:389 -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" < "${W}/seed.ldif" 2>&1)"
rm -f "${W}/seed.ldif"
n_added="$(grep -c 'adding new entry "uid=' <<<"$seed_out")"
[ "$n_added" = "6" ] || { infra_fail "ldapadd seeded ${n_added} of 6 users" "$seed_out"; end_suite; }

areq POST /api/v1/admin/sso/ldap "$(jq -nc --arg n "dtf-pt-${SFX}" --arg b "$LDAP_ADMIN_DN" --arg bp "$LDAP_ADMIN_PW" --arg base "$LDAP_PEOPLE" \
  '{name:$n, server_url:"ldap://ldap.dtf.local:389", bind_dn:$b, bind_password:$bp, user_base_dn:$base,
    user_filter:"(uid={0})"}')"
PROVIDER_ID="$(jqr '.id // empty' <<<"$BODY")"
[ -n "$PROVIDER_ID" ] || { infra_fail "creating the LDAP provider answered ${CODE}: ${BODY:0:300}"; end_suite; }

# The local account whose username also exists in the directory.
areq POST /api/v1/users "$(jq -nc --arg u "$U_LOC" --arg p "$P_LOC" '{username:$u,email:($u+"@local.dtf"),password:$p}')"
case "$CODE" in 2??) ;; *) infra_fail "creating local user ${U_LOC} answered ${CODE}: ${BODY:0:200}"; end_suite;; esac

R_MVN="ptmvn-${SFX}"; R_PY="ptpy-${SFX}"
for spec in "$R_MVN:maven" "$R_PY:pypi"; do
  areq POST /api/v1/repositories "$(jq -nc --arg k "${spec%%:*}" --arg f "${spec#*:}" '{key:$k,name:$k,format:$f,repo_type:"local",visibility:"internal"}')"
  case "$CODE" in 2??) ;; *) infra_fail "creating ${spec} answered ${CODE}: ${BODY:0:200}"; end_suite;; esac
done
MVN_PATH="com/dtf/pt/lib/1.0/lib-1.0.jar"
printf 'ldap-basic-passthrough %s\n' "$SFX" > "${W}/lib.jar"
c="$(curl -s -o "${W}/up" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
  --data-binary "@${W}/lib.jar" "${BASE}/maven/${R_MVN}/${MVN_PATH}")"
case "$c" in 2??) ;; *) infra_fail "maven PUT answered ${c}: $(head -c 200 "${W}/up")"; end_suite;; esac

PY_MOD="dtf_pt_${SFX}"; PY_NAME="${PY_MOD//_/-}"; WHL="${PY_MOD}-1.0.0-py3-none-any.whl"
python3 - "$PY_MOD" "1.0.0" "${W}/${WHL}" <<'PY'
import base64, hashlib, sys, zipfile
module, version, out = sys.argv[1:]
di = f"{module}-{version}.dist-info"
files = {f"{module}/__init__.py": "",
         f"{di}/METADATA": f"Metadata-Version: 2.1\nName: {module}\nVersion: {version}\nSummary: dtf\n\n",
         f"{di}/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
rec = []
with zipfile.ZipFile(out, "w") as zf:
    for n, t in files.items():
        d = t.encode(); zf.writestr(n, d)
        rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}")
    rec.append(f"{di}/RECORD,,"); zf.writestr(f"{di}/RECORD", "\n".join(rec) + "\n")
PY
c="$(curl -s -o "${W}/up" -w '%{http_code}' --max-time 60 -X POST "${BASE}/pypi/${R_PY}/" -H "Authorization: Bearer ${TOK}" \
  -F ":action=file_upload" -F "protocol_version=1" -F "metadata_version=2.1" -F "name=${PY_MOD}" -F "version=1.0.0" \
  -F "filetype=bdist_wheel" -F "pyversion=py3" -F "sha256_digest=$(sha256sum "${W}/${WHL}" | awk '{print $1}')" \
  -F "content=@${W}/${WHL};filename=${WHL}")"
case "$c" in 2??) ;; *) infra_fail "wheel upload answered ${c}: $(head -c 200 "${W}/up")"; end_suite;; esac
echo "-- provider ${PROVIDER_ID}; repos ${R_MVN} ${R_PY}; directory users *${SFX}"
pass

# fetch_packages <user> <password>: GET the jar, the simple index and the
# wheel it links. Sets FP_JAR FP_IDX FP_WHL (statuses) and FP_OK=1 when all
# three are 200 with the published bytes / filename.
fetch_packages(){
  local u="$1" p="$2" href
  FP_OK=0; FP_WHL="-"
  FP_JAR="$(basic "$u" "$p" "/maven/${R_MVN}/${MVN_PATH}" "${W}/got.jar")"
  FP_IDX="$(basic "$u" "$p" "/pypi/${R_PY}/simple/${PY_NAME}/" "${W}/idx.html")"
  if [ "$FP_IDX" = "200" ]; then
    href="$(python3 -c 'import re,sys,urllib.parse; h=open(sys.argv[1]).read(); m=re.search(r"href=\"([^\"]+)\"", h); print(urllib.parse.urljoin(sys.argv[2], m.group(1).split("#")[0]) if m else "")' \
      "${W}/idx.html" "${BASE}/pypi/${R_PY}/simple/${PY_NAME}/")"
    [ -n "$href" ] && FP_WHL="$(curl -s -o "${W}/got.whl" -w '%{http_code}' --max-time 60 -u "$u:$p" "$href" 2>/dev/null)"
  fi
  if [ "$FP_JAR" = "200" ] && cmp -s "${W}/got.jar" "${W}/lib.jar" && [ "$FP_IDX" = "200" ] \
     && grep -qF "$WHL" "${W}/idx.html" && [ "$FP_WHL" = "200" ] && cmp -s "${W}/got.whl" "${W}/${WHL}"; then
    FP_OK=1
  fi
}

# =============================================================================
begin_test "CONTROL: a directory user logs in through the web LDAP endpoint"
reset_case
c="$(web_login "$U_WEB" "$P_WEB")"
note "web LDAP login ${U_WEB}: ${c}"
[ "$c" = "200" ] && [ -n "$(jqr '.access_token // empty' "${W}/weblogin")" ] || fail_g "web LDAP login answered ${c}: $(head -c 200 "${W}/weblogin")"
finish_case "the directory fixture or the LDAP provider does not work"

# =============================================================================
begin_test "CONTROL: with guest access off, anonymous reads are 401 and the admin's local password over Basic reads both packages"
reset_case
a_jar="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${BASE}/maven/${R_MVN}/${MVN_PATH}")"
a_idx="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${BASE}/pypi/${R_PY}/simple/${PY_NAME}/")"
note "anonymous: jar ${a_jar}, simple index ${a_idx}"
[ "$a_jar" = "401" ] && [ "$a_idx" = "401" ] || fail_g "anonymous reads answered ${a_jar}/${a_idx}, expected 401/401 (guest access is off)"
fetch_packages "${ADMIN_USER:-admin}" "$ADMIN_PASS"
note "admin Basic: jar ${FP_JAR}, simple index ${FP_IDX}, wheel ${FP_WHL}"
[ "$FP_OK" = "1" ] || fail_g "the admin's local Basic credential did not read both packages"
finish_case "local Basic auth on the package routes is broken"

# =============================================================================
begin_test "CONTROL: a local account's username is never searched or bound in the directory"
reset_case
c1="$(basic "$U_LOC" "Wrong-$(rand_pw)" "/maven/${R_MVN}/${MVN_PATH}")"
c2="$(basic "$U_LOC" "$P_LOC" "/maven/${R_MVN}/${MVN_PATH}")"
sleep 1
h="$(dir_hits "$U_LOC")"
note "local ${U_LOC}: wrong password ${c1}, local password ${c2}; directory SRCH/BIND lines ${h}"
[ "$c1" = "401" ] || fail_g "a wrong password for the local account answered ${c1}, expected 401"
[ "$c2" = "200" ] || fail_g "the local account's own password answered ${c2}, expected 200"
[ "$h" = "0" ] || fail_g "the directory saw the local account's username ${h} time(s)"
finish_case "a local account's credential reached the directory"

# =============================================================================
begin_test "FIX #3830: a directory user with no local account fetches a Maven jar and a PyPI wheel with the directory password"
reset_case
before="$(psqlq "SELECT COUNT(*) FROM users WHERE lower(username) = '${U_PKG}'")"
fetch_packages "$U_PKG" "$P_PKG"
note "directory Basic ${U_PKG}: jar ${FP_JAR}, simple index ${FP_IDX}, wheel ${FP_WHL}"
prov="$(psqlq "SELECT auth_provider::text FROM users WHERE lower(username) = '${U_PKG}'")"
note "local rows before: ${before}; auth_provider after: ${prov:-none}"
[ "$before" = "0" ] || fail_g "${U_PKG} already had a local account"
[ "$FP_OK" = "1" ] || fail_g "the directory password did not read both packages (jar ${FP_JAR}, index ${FP_IDX}, wheel ${FP_WHL}); pre-#3830 a directory user needs a personal API token"
[ "$prov" = "ldap" ] || fail_g "the passthrough did not provision an ldap account (got '${prov:-none}')"
finish_case "LDAP Basic credentials are not passed through on package routes"

# =============================================================================
begin_test "FIX #3830: a wrong directory password is bound once and audited once, then refused from the failure window without a second bind"
reset_case
# Provision the account first so the failure is a bad password, not a miss.
p0="$(basic "$U_BAD" "$P_BAD" "/maven/${R_MVN}/${MVN_PATH}")"
settle
bad="Wrong-$(rand_pw)"
b0="$(dir_binds "$U_BAD")"; f0="$(audit_count LOGIN_FAILED "$U_BAD")"
c1="$(basic "$U_BAD" "$bad" "/maven/${R_MVN}/${MVN_PATH}")"
settle; b1="$(dir_binds "$U_BAD")"; f1="$(audit_count LOGIN_FAILED "$U_BAD")"
c2="$(basic "$U_BAD" "$bad" "/maven/${R_MVN}/${MVN_PATH}")"
settle; b2="$(dir_binds "$U_BAD")"; f2="$(audit_count LOGIN_FAILED "$U_BAD")"
note "${U_BAD}: right password ${p0}; wrong password ${c1} then ${c2}; user BIND lines ${b0} -> ${b1} -> ${b2}; LOGIN_FAILED rows ${f0} -> ${f1} -> ${f2}"
[ "$p0" = "200" ] || fail_g "the right directory password answered ${p0}, expected 200 (pre-#3830 the directory is never consulted)"
[ "$c1" = "401" ] && [ "$c2" = "401" ] || fail_g "wrong password answered ${c1}/${c2}, expected 401/401"
[ "$((b1 - b0))" = "1" ] || fail_g "the first wrong password caused $((b1 - b0)) directory BIND(s), expected exactly 1"
[ "$((b2 - b1))" = "0" ] || fail_g "the repeated wrong password was bound again ($((b2 - b1)) new BIND(s)) inside the failure window"
# #4933 item 2 (one LOGIN_FAILED row per rejected request) rides here: through
# the real router sha-8d0e6e2 also writes one row, so it is a guard rail, not
# a discriminating #4933 case.
[ "$((f1 - f0))" = "1" ] && [ "$((f2 - f1))" = "1" ] || fail_g "the two rejected requests wrote $((f1 - f0)) and $((f2 - f1)) LOGIN_FAILED rows, expected one each"
finish_case "the package-route passthrough does not bind and audit a wrong directory password exactly once"

# =============================================================================
begin_test "FIX #4933: management API and /v2 Basic requests never reach the directory"
reset_case
h0="$(dir_hits "$U_MGT")"
m1="$(basic "$U_MGT" "$P_MGT" "/api/v1/repositories")"
m2="$(basic "$U_MGT" "$P_MGT" "/v2/")"
sleep 1; settle
h1="$(dir_hits "$U_MGT")"
# Directory (passthrough) rows only: the local resolver's own LOGIN_FAILED
# row for an unknown local password is expected on every image.
l_ok="$(audit_count LOGIN "$U_MGT")"; l_bad="$(audit_count LOGIN_FAILED "$U_MGT" "AND details->>'provider' = 'ldap'")"
note "${U_MGT}: /api/v1/repositories ${m1}, /v2/ ${m2}; directory SRCH/BIND lines ${h0} -> ${h1}; LOGIN ${l_ok}, LDAP LOGIN_FAILED ${l_bad}"
[ "$m1" = "401" ] || fail_g "/api/v1/repositories with a directory Basic credential answered ${m1}, expected 401"
[ "$m2" = "401" ] || fail_g "/v2/ with a directory Basic credential answered ${m2}, expected 401"
[ "$((h1 - h0))" = "0" ] || fail_g "the directory saw ${U_MGT} $((h1 - h0)) time(s) for management/OCI requests (pre-#5010 the guest guard ran the passthrough)"
[ "${l_ok:-0}" = "0" ] && [ "${l_bad:-0}" = "0" ] || fail_g "management/OCI requests wrote LOGIN=${l_ok} LDAP LOGIN_FAILED=${l_bad} rows for ${U_MGT}, expected none"
finish_case "the guest-access guard binds Basic credentials against the directory"

# =============================================================================
begin_test "FIX #4933: web LDAP login does not reactivate a directory account an administrator deactivated"
reset_case
c0="$(web_login "$U_DEA" "$P_DEA")"
uid="$(psqlq "SELECT id FROM users WHERE lower(username) = '${U_DEA}'")"
note "first web login ${c0}; user id ${uid:-none}"
if [ "$c0" != "200" ] || [ -z "$uid" ]; then
  fail_g "the first web login answered ${c0} and provisioned no account"
else
  areq PATCH "/api/v1/users/${uid}" '{"is_active":false}'
  note "admin PATCH is_active=false: ${CODE}"
  case "$CODE" in 2??) ;; *) fail_g "deactivation answered ${CODE}: ${BODY:0:200}";; esac
  p1="$(basic "$U_DEA" "$P_DEA" "/maven/${R_MVN}/${MVN_PATH}")"
  c1="$(web_login "$U_DEA" "$P_DEA")"
  act="$(psqlq "SELECT is_active FROM users WHERE id = '${uid}'")"
  p2="$(basic "$U_DEA" "$P_DEA" "/maven/${R_MVN}/${MVN_PATH}")"
  note "after deactivation: passthrough ${p1}; web login ${c1} $(head -c 160 "${W}/weblogin"); is_active=${act}; passthrough again ${p2}"
  [ "$p1" = "401" ] || fail_g "the passthrough served the deactivated account (${p1})"
  [ "$c1" != "200" ] || fail_g "web LDAP login answered 200 for the deactivated account"
  [ "$act" = "f" ] || fail_g "the account is is_active=${act} after the web login (the login reactivated it)"
  [ "$p2" = "401" ] || fail_g "after the web login the passthrough served the account (${p2})"
fi
finish_case "web LDAP login reactivates an account an administrator deactivated"

end_suite
