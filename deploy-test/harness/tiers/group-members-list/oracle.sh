#!/usr/bin/env bash
# =============================================================================
# tiers/group-members-list/oracle.sh
#   #4027 GET /api/v1/groups/{id}/members: a stable, paged member list for an
#         LDAP-synced group whose members share one join time; outsiders 404;
#         membership writes on a synced group stay 409
# See the manifest for THE FEATURE, THE FIXTURE and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
: "${DB_CONTAINER:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
TAG="${SUF//-/}"
N_MEMBERS=7
GROUP_NAME="dtf-ldap-synced-${SLOT}-${SUF}"
PROVIDER_NAME="dtf-gml-ldap-${SLOT}-${SUF}"

W="$(mktemp -d -t dtf-gml-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# HTTP code of a request; body -> $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 30 "$@" 2>/dev/null || echo 000; }
body() { cat "$W/last" 2>/dev/null; }

gen_pass() { echo "Dtf-$(openssl rand -hex 10 2>/dev/null || date +%s%N)-q9"; }

# GET /members as $1 (a bearer token), query $2; code -> stdout, body -> $W/last.
members_as() { code -H "Authorization: Bearer $1" "${BASE_URL}/api/v1/groups/${GID}/members?$2"; }

# Concatenated user_ids of pages of size $2 for token $1 until an empty page.
# Echoes "ids|totals" where ids is comma separated and totals the distinct
# members_total values seen; echoes ERR:<code> on a non-200 page.
walk_pages() {
  local tok="$1" size="$2" off=0 c ids="" totals="" n
  while [ "$off" -le 50 ]; do
    c="$(members_as "$tok" "member_limit=${size}&member_offset=${off}")"
    [ "$c" = "200" ] || { echo "ERR:${c}@${off}"; return; }
    n="$(body | jq '.members | length' 2>/dev/null)"
    totals="${totals} $(body | jq -r '.members_total' 2>/dev/null)"
    [ "${n:-0}" -eq 0 ] && break
    ids="${ids}${ids:+,}$(body | jq -r '[.members[].user_id] | join(",")' 2>/dev/null)"
    off=$((off + size))
  done
  echo "${ids}|$(echo "$totals" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ $//')"
}

begin_suite "group-members-list"
auth_admin
ADMIN_TOKEN="$(login_as "${ADMIN_USER:-admin}" "$ADMIN_PASS" 2>/dev/null)" || true

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: an LDAP provider, a group synced from it, ${N_MEMBERS} members sharing one joined_at, an outsider"
SETUP_ERR=""
[ -n "$ADMIN_TOKEN" ] || SETUP_ERR="admin login failed;"
MEMBER_IDS=()
for i in $(seq 1 "$N_MEMBERS"); do
  u="gml-m${i}-${SLOT}-${TAG}"
  p="$(gen_pass)"
  id="$(create_test_user_with_retry "$u" "$p" "${u}@t.test" 2>/dev/null)" || true
  [ -n "$id" ] || { SETUP_ERR="${SETUP_ERR} create ${u} failed;"; continue; }
  MEMBER_IDS+=("$id")
  if [ "$i" = "1" ]; then READER="$u"; READER_PASS="$p"; fi
done
OUTSIDER="gml-out-${SLOT}-${TAG}"; OUTSIDER_PASS="$(gen_pass)"
OUT_ID="$(create_test_user_with_retry "$OUTSIDER" "$OUTSIDER_PASS" "${OUTSIDER}@t.test" 2>/dev/null)" || true
[ -n "$OUT_ID" ] || SETUP_ERR="${SETUP_ERR} create outsider failed;"

# Sessions first: once an SSO provider is enabled the backend refuses local
# password login for non-admins (break-glass is admin only), which is the
# behaviour of a directory-backed deployment. Sessions issued before stay valid.
READER_TOKEN=""; OUT_TOKEN=""
[ -n "${READER:-}" ] && READER_TOKEN="$(login_as "$READER" "$READER_PASS" 2>/dev/null)" || true
[ -n "$OUT_ID" ] && OUT_TOKEN="$(login_as "$OUTSIDER" "$OUTSIDER_PASS" 2>/dev/null)" || true
[ -n "$READER_TOKEN" ] || SETUP_ERR="${SETUP_ERR} member login failed;"
[ -n "$OUT_TOKEN" ] || SETUP_ERR="${SETUP_ERR} outsider login failed;"

c="$(code -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' -X POST \
  -d "$(jq -nc --arg n "$PROVIDER_NAME" '{name:$n,server_url:"ldap://ldap.dtf.invalid:389",user_base_dn:"ou=people,dc=dtf,dc=invalid"}')" \
  "${BASE_URL}/api/v1/admin/sso/ldap")"
PID="$(body | jq -r '.id // empty' 2>/dev/null)"
case "$c" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} creating LDAP provider -> ${c} $(body | head -c 160);" ;; esac


c="$(code -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' -X POST \
  -d "$(jq -nc --arg n "$GROUP_NAME" '{name:$n,description:"dtf group-members-list"}')" "${BASE_URL}/api/v1/groups")"
GID="$(body | jq -r '.id // empty' 2>/dev/null)"
[ -n "$GID" ] || SETUP_ERR="${SETUP_ERR} create group -> ${c} $(body | head -c 160);"

if [ -z "$SETUP_ERR" ]; then
  # Attach the group to the provider the way the directory sync records it,
  # then insert every membership in ONE statement (one now() for all rows),
  # in descending user_id order so insertion order is not the expected order.
  psql_q "UPDATE groups SET external_source = 'ldap', external_provider_id = '${PID}' WHERE id = '${GID}'" >/dev/null
  ARR="$(printf "'%s'," "${MEMBER_IDS[@]}")"; ARR="ARRAY[${ARR%,}]::uuid[]"
  psql_q "INSERT INTO user_group_members (user_id, group_id)
          SELECT u, '${GID}'::uuid FROM unnest(${ARR}) AS u ORDER BY u DESC" >/dev/null
  SRC="$(psql_q "SELECT external_source FROM groups WHERE id = '${GID}'")"
  NROWS="$(psql_q "SELECT count(*) FROM user_group_members WHERE group_id = '${GID}'")"
  NTIMES="$(psql_q "SELECT count(DISTINCT joined_at) FROM user_group_members WHERE group_id = '${GID}'")"
  [ "$SRC" = "ldap" ] || SETUP_ERR="${SETUP_ERR} group external_source='${SRC}';"
  [ "$NROWS" = "$N_MEMBERS" ] || SETUP_ERR="${SETUP_ERR} ${NROWS} membership rows;"
  [ "$NTIMES" = "1" ] || SETUP_ERR="${SETUP_ERR} ${NTIMES} distinct joined_at values (want 1);"
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# The contract: oldest joined_at first, user_id breaks the tie. With one
# shared joined_at that is plain user_id order.
EXPECTED="$(printf '%s\n' "${MEMBER_IDS[@]}" | LC_ALL=C sort | paste -sd, -)"
MEMBERSHIP() { psql_q "SELECT string_agg(user_id::text, ',' ORDER BY user_id) FROM user_group_members WHERE group_id = '${GID}'"; }

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: the group detail shows the synced group (external_source ldap) with members_total ${N_MEMBERS}"
c="$(code -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/api/v1/groups/${GID}")"
src="$(body | jq -r '.external_source // empty' 2>/dev/null)"; tot="$(body | jq -r '.members_total // .member_count // empty' 2>/dev/null)"
if [ "$c" = "200" ] && [ "$src" = "ldap" ] && [ "$tot" = "$N_MEMBERS" ]; then pass; else
  fail "GET /groups/${GID} -> ${c} external_source=${src:-none} members_total=${tot:-none} (want 200 ldap ${N_MEMBERS})"
fi

begin_test "CONTROL: the outsider gets 404 on the group detail"
c="$(code -H "Authorization: Bearer ${OUT_TOKEN}" "${BASE_URL}/api/v1/groups/${GID}")"
if [ "$c" = "404" ]; then pass; else fail "outsider GET /groups/${GID} -> ${c} $(body | head -c 160) (want 404)"; fi

begin_test "CONTROL: POST and DELETE /groups/{id}/members on the synced group are 409 and the membership is unchanged"
before="$(MEMBERSHIP)"
c_post="$(code -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' -X POST \
  -d "{\"user_ids\":[\"${OUT_ID}\"]}" "${BASE_URL}/api/v1/groups/${GID}/members")"
c_del="$(code -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' -X DELETE \
  -d "{\"user_ids\":[\"${MEMBER_IDS[0]}\"]}" "${BASE_URL}/api/v1/groups/${GID}/members")"
after="$(MEMBERSHIP)"
if [ "$c_post" = "409" ] && [ "$c_del" = "409" ] && [ "$after" = "$before" ] && [ "$after" = "$EXPECTED" ]; then pass; else
  fail "POST -> ${c_post}, DELETE -> ${c_del} (want 409 both); membership changed: $([ "$after" = "$before" ] && echo no || echo yes)"
fi

# =============================================================================
# FIX: GET /groups/{id}/members
# =============================================================================
begin_test "FIX(#4027): admin GET /members?member_limit=200 lists all ${N_MEMBERS} members in (joined_at, user_id) order with members_total"
c="$(members_as "$ADMIN_TOKEN" "member_limit=200")"
got="$(body | jq -r '[.members[]?.user_id] | join(",")' 2>/dev/null)"
tot="$(body | jq -r '.members_total // empty' 2>/dev/null)"
shape="$(body | jq -r '[.members[0] | has("user_id","username","display_name","joined_at")] | all' 2>/dev/null)"
if [ "$c" = "200" ] && [ "$got" = "$EXPECTED" ] && [ "$tot" = "$N_MEMBERS" ] && [ "$shape" = "true" ]; then pass; else
  fail "GET /groups/${GID}/members -> ${c} total=${tot:-none} shape=${shape:-?} ids=${got:-none} $(body | head -c 120) (want 200, ${N_MEMBERS}, ids ${EXPECTED})"
fi

for size in 2 3; do
  begin_test "FIX(#4027): pages of member_limit=${size} cover every member exactly once, in the same order, members_total ${N_MEMBERS} on every page"
  r="$(walk_pages "$ADMIN_TOKEN" "$size")"
  ids="${r%%|*}"; totals="${r#*|}"
  dups="$(echo "$ids" | tr ',' '\n' | sed '/^$/d' | sort | uniq -d | paste -sd, -)"
  if [[ "$r" != ERR:* ]] && [ "$ids" = "$EXPECTED" ] && [ "$totals" = "$N_MEMBERS" ]; then pass; else
    fail "member_limit=${size}: ${r%%|*} (totals '${totals}', repeated: ${dups:-none}); want ${EXPECTED}"
  fi
done

begin_test "FIX(#4027): an offset past the end is an empty page with members_total ${N_MEMBERS}"
c="$(members_as "$ADMIN_TOKEN" "member_limit=5&member_offset=$((N_MEMBERS + 3))")"
n="$(body | jq '.members | length' 2>/dev/null)"; tot="$(body | jq -r '.members_total // empty' 2>/dev/null)"
if [ "$c" = "200" ] && [ "$n" = "0" ] && [ "$tot" = "$N_MEMBERS" ]; then pass; else
  fail "offset past the end -> ${c} members=${n:-?} total=${tot:-none} $(body | head -c 120)"
fi

begin_test "FIX(#4027): a non-admin member of the synced group gets the same member list"
c="$(members_as "$READER_TOKEN" "member_limit=200")"
got="$(body | jq -r '[.members[]?.user_id] | join(",")' 2>/dev/null)"
if [ "$c" = "200" ] && [ "$got" = "$EXPECTED" ]; then pass; else
  fail "member GET /members -> ${c} ids=${got:-none} $(body | head -c 120) (want 200 ${EXPECTED})"
fi

begin_test "FIX(#4027): the outsider gets 404 on /members, the same as for a group that does not exist"
c="$(members_as "$OUT_TOKEN" "member_limit=200")"; b_g="$(body | jq -cS '{code}' 2>/dev/null)"
leak="$(body | grep -c "${MEMBER_IDS[0]}" || true)"
RANDOM_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
c_r="$(code -H "Authorization: Bearer ${OUT_TOKEN}" "${BASE_URL}/api/v1/groups/${RANDOM_ID}/members")"; b_r="$(body | jq -cS '{code}' 2>/dev/null)"
if [ "$c" = "404" ] && [ "$c_r" = "404" ] && [ "$b_g" = "$b_r" ] && [ "$leak" = "0" ]; then pass; else
  fail "outsider GET /members -> ${c} ${b_g}; random id -> ${c_r} ${b_r}; member id in body: ${leak} (want 404 both, same code, nothing leaked)"
fi

begin_test "FIX(#4027): anonymous GET /members is 401"
c="$(code "${BASE_URL}/api/v1/groups/${GID}/members")"
if [ "$c" = "401" ]; then pass; else fail "anonymous GET /members -> ${c} $(body | head -c 120) (want 401)"; fi

end_suite
