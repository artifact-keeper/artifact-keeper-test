#!/usr/bin/env bash
# =============================================================================
# tiers/debian-virtual-local-members/oracle.sh (artifact-keeper#6548)
# =============================================================================
# See manifest for the bug and the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

CAPT="ak-dtf${DTF_SLOT}-client-apt"
INT="http://backend:8080"
SUF="$(echo "${RUN_ID##*-}" | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9' | tail -c 8)$$"
MA="dvla-${DTF_SLOT}-${SUF}"
MB="dvlb-${DTF_SLOT}-${SUF}"
VIRT="dvlv-${DTF_SLOT}-${SUF}"
EMPTY="dvle-${DTF_SLOT}-${SUF}"
DIST="stable"
PKG_PATH="dists/${DIST}/main/binary-all/Packages"

WORK="$(mktemp -d -t dtf-dvl-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

AUTHZ=()
call() { # METHOD PATH BODY -> http code
  local c
  c="$(curl -s --max-time 60 -o "$WORK/call.out" -w '%{http_code}' -X "$1" "${AUTHZ[@]}" \
        -H 'Content-Type: application/json' -d "$3" "${BASE_URL}$2" 2>/dev/null)"
  echo "${c:-000}"
}
mkrepo() { # KEY TYPE -> http code
  call POST /api/v1/repositories \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"debian\",\"repo_type\":\"$2\",\"is_public\":true}"
}
build_deb() { # NAME -> file name in $WORK
  local deb="$1_1.0-${SUF}_all.deb" out
  out="$(docker exec "$CAPT" bash -c "set -e; umask 0022
rm -rf /tmp/$1 && mkdir -p /tmp/$1/DEBIAN /tmp/$1/usr/share/$1
echo 'DTF-$1-${SUF}' > /tmp/$1/usr/share/$1/marker.txt
printf 'Package: $1\nVersion: 1.0-${SUF}\nArchitecture: all\nMaintainer: DTF <dtf@example.invalid>\nDescription: DTF virtual member marker\n' > /tmp/$1/DEBIAN/control
dpkg-deb --root-owner-group --build /tmp/$1 /tmp/${deb} >/dev/null" 2>&1)" \
    && docker cp "${CAPT}:/tmp/${deb}" "$WORK/${deb}" >/dev/null 2>&1
  [ -s "$WORK/${deb}" ] && echo "$deb"
}
get() { # PATH OUT [curl args...] -> http code
  local p="$1" o="$2"; shift 2
  curl -s --max-time 60 -o "$o" -w '%{http_code}' "$@" "${BASE_URL}${p}" 2>/dev/null || echo 000
}

begin_suite "debian-virtual-local-members"
auth_admin >/dev/null 2>&1
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

begin_test "SETUP: two Local members with one .deb each, a Virtual over both, an empty Virtual"
ERR=""
for spec in "$MA:local" "$MB:local" "$VIRT:virtual" "$EMPTY:virtual"; do
  c="$(mkrepo "${spec%%:*}" "${spec##*:}")"; case "$c" in 200|201) ;; *) ERR="${ERR} create ${spec} -> ${c};" ;; esac
done
for m in "$MA" "$MB"; do
  c="$(call POST "/api/v1/repositories/${VIRT}/members" "{\"member_key\":\"${m}\"}")"
  case "$c" in 200|201|204) ;; *) ERR="${ERR} member ${m} -> ${c};" ;; esac
done
DEB_A="$(build_deb dtf-vla)"; DEB_B="$(build_deb dtf-vlb)"
[ -n "$DEB_A" ] && [ -n "$DEB_B" ] || ERR="${ERR} dpkg-deb build in ${CAPT} failed;"
for pair in "$MA:dtf-vla:$DEB_A" "$MB:dtf-vlb:$DEB_B"; do
  IFS=: read -r repo pkg deb <<<"$pair"
  c="$(curl -s --max-time 60 -o /dev/null -w '%{http_code}' -X PUT "${AUTHZ[@]}" --upload-file "$WORK/${deb}" \
        "${BASE_URL}/debian/${repo}/pool/main/d/${pkg}/${deb}" 2>/dev/null)"
  case "$c" in 200|201) ;; *) ERR="${ERR} upload ${deb} -> ${c};" ;; esac
done
if [ -z "$ERR" ]; then pass; else infra_fail "setup could not complete:${ERR}"; end_suite; exit $?; fi

begin_test "CONTROL: each Local member's own Packages lists its package"
ca="$(get "/debian/${MA}/${PKG_PATH}" "$WORK/a.pk")"; cb="$(get "/debian/${MB}/${PKG_PATH}" "$WORK/b.pk")"
if [ "$ca" = "200" ] && grep -q '^Package: dtf-vla$' "$WORK/a.pk" \
   && [ "$cb" = "200" ] && grep -q '^Package: dtf-vlb$' "$WORK/b.pk"; then
  pass
else
  fail "member A ${ca}: $(head -c 200 "$WORK/a.pk"); member B ${cb}: $(head -c 200 "$WORK/b.pk")"
fi

begin_test "FIX #6548: the Virtual's Packages lists both members' packages and its Release vouches for it"
cv="$(get "/debian/${VIRT}/${PKG_PATH}" "$WORK/v.pk")"
cr="$(get "/debian/${VIRT}/dists/${DIST}/Release" "$WORK/v.rel")"
line=" $(sha256sum "$WORK/v.pk" | cut -d' ' -f1) $(wc -c < "$WORK/v.pk" | tr -d ' ') main/binary-all/Packages"
if [ "$cv" = "200" ] && grep -q '^Package: dtf-vla$' "$WORK/v.pk" && grep -q '^Package: dtf-vlb$' "$WORK/v.pk" \
   && [ "$cr" = "200" ] && grep -qxF -- "$line" "$WORK/v.rel"; then
  pass
else
  fail "Virtual Packages ${cv} ($(grep -c '^Package:' "$WORK/v.pk" 2>/dev/null) packages), Release ${cr}, want line '${line}'" \
    "$(head -c 600 "$WORK/v.rel")"
fi

begin_test "FIX #6548: a real apt-get install through the Virtual installs the second member's package"
out="$(docker exec "$CAPT" bash -c "set -e
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
echo 'deb [trusted=yes] ${INT}/debian/${VIRT} ${DIST} main' > /etc/apt/sources.list.d/dtf-vl.list
timeout 120 apt-get update 2>&1 | tail -4
timeout 120 apt-get -y install dtf-vlb 2>&1 | tail -3
cat /usr/share/dtf-vlb/marker.txt" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && echo "$out" | grep -q "DTF-dtf-vlb-${SUF}"; then pass; else
  fail "apt through the Virtual (rc ${rc})" "$(echo "$out" | tail -10)"
fi

begin_test "FIX #6548: a Virtual with no members answers 404 instead of an empty index"
# As admin: an anonymous caller facing no readable member may get a challenge
ce="$(get "/debian/${EMPTY}/${PKG_PATH}" "$WORK/e.pk" "${AUTHZ[@]}")"
if [ "$ce" = "404" ]; then pass; else fail "empty Virtual Packages answered ${ce}: $(head -c 200 "$WORK/e.pk")"; fi

end_suite
