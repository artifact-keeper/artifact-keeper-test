#!/usr/bin/env bash
# =============================================================================
# tiers/push-sync-echo-and-sidecars/oracle.sh
#   #4792 a peer write to the NuGet or nested-RPM route is not echoed back
#         to the other peers, and a pacman .sig uploaded after its package
#         reaches a peer that already has the package
# See the manifest for THE BUGS, THE PEERS and the gates.
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

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_DB="ak-dtf${SLOT}-peer-db"
CLIENT="ak-dtf${SLOT}-client-pacman"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
NIL="00000000-0000-0000-0000-000000000000"

R_NU="psenuget-${SLOT}-${SUF}"
R_RPM="pserpm-${SLOT}-${SUF}"
R_PAC="psepac-${SLOT}-${SUF}"

W="$(mktemp -d -t dtf-pushecho-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
# cx <script>: run in the client container (fixtures live in /work there).
cx() { docker exec -i "$CLIENT" bash -c "$1" 2>&1 || true; }

# HTTP code of a request; the body goes to $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }

repo_create() { # base key format -> id
  local body
  body="$(jq -nc --arg k "$2" --arg f "$3" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}
depth_one() { # base key -> http code
  code -u "$AUTH" -X PATCH -H 'Content-Type: application/json' -d '{"repodata_depth":1}' \
    "$1/api/v1/repositories/$2"
}
mint_key() { # base -> token
  curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"dtf-echo-${SUF}-$RANDOM\",\"scopes\":[\"*\"]}" "$1/api/v1/auth/tokens" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
register_peer() { # base name endpoint key -> id (the response body lands in $W/peer-$2)
  curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\",\"endpoint_url\":\"$3\",\"api_key\":\"$4\"}" \
    "$1/api/v1/peers" 2>/dev/null | tee "$W/peer-$2" | jq -r '.id // empty' 2>/dev/null || true
}
subscribe() { # base peer repo_id -> http code
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"repository_id\":\"$3\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
    "$1/api/v1/peers/$2/repositories"
}

# "<status>|<rows>" of the push rows on one side for one live artifact path.
push_rows() { # a|b peer repo path
  local q="SELECT coalesce(max(st.status::text),'none') || '|' || count(st.id) \
          FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          LEFT JOIN sync_tasks st ON st.artifact_id = a.id AND st.task_type = 'push' \
               AND st.peer_instance_id = '${2:-$NIL}' \
          WHERE r.key = '$3' AND a.path = '$4' AND a.is_deleted = false"
  if [ "$1" = a ]; then psql_a "$q"; else psql_b "$q"; fi
}
# Every push row on B for peer A (any artifact).
b_rows_for_a() { psql_b "SELECT count(*) FROM sync_tasks WHERE task_type = 'push' AND peer_instance_id = '${PEER_A_ON_B:-$NIL}'"; }
sha_a() { psql_a "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '$1' AND a.path = '$2' AND a.is_deleted = false"; }
sha_b() { psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '$1' AND a.path = '$2' AND a.is_deleted = false"; }
# "<http>:<sha256>" of what B serves at a URL.
served_b() {
  local c
  c="$(curl -s -o "$W/servedb" -w '%{http_code}' --max-time 60 -u "$AUTH" "$1" 2>/dev/null || echo 000)"
  echo "${c}:$(sha256sum "$W/servedb" 2>/dev/null | cut -d' ' -f1)"
}
wait_sha_b() { # repo path want secs
  local deadline=$(( $(date +%s) + $4 ))
  while [ "$(sha_b "$1" "$2")" != "$3" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 3; done
}
# Copy a fixture out of the client container.
fetch() { docker cp "${CLIENT}:/work/out/$1" "$W/$1" >/dev/null 2>&1; }
sha() { sha256sum "$W/$1" 2>/dev/null | cut -d' ' -f1; }

begin_suite "push-sync-echo-and-sidecars"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: B up, fixtures built, same repos on A and B, B a push peer of A and A a push peer of B"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
[ "$(docker inspect -f '{{.State.Running}}' "$CLIENT" 2>/dev/null)" = "true" ] \
  || SETUP_ERR="${SETUP_ERR} client container ${CLIENT} not running;"

# Fixtures: two .nupkg (client push to A, peer write to B), two RPM payloads,
# one pacman package and its detached signature (throwaway key, made now).
# shellcheck disable=SC2016  # the script runs in the client container
build_out="$(cx '
set -e
rm -rf /work && mkdir -p /work/out
nupkg(){ # id version
  d=$(mktemp -d)
  cat > "$d/$1.nuspec" <<N
<?xml version="1.0"?>
<package><metadata><id>$1</id><version>$2</version><authors>DTF</authors><description>DTF echo fixture</description></metadata></package>
N
  ( cd "$d" && bsdtar --format zip -cf "/work/out/$1.$2.nupkg" "$1.nuspec" )
}
nupkg DtfEcho 1.0.0
nupkg DtfEcho 2.0.0
printf "dtf nested rpm client %s\n" "'"$SUF"'" > /work/out/dtf-echo-1.0-1.noarch.rpm
printf "dtf nested rpm peer %s\n" "'"$SUF"'" > /work/out/dtf-echo-2.0-1.noarch.rpm
d=$(mktemp -d); mkdir -p "$d/usr/share/dtf-sig"
echo "dtf-sig '"$SUF"'" > "$d/usr/share/dtf-sig/sig.txt"
cat > "$d/.PKGINFO" <<P
pkgname = dtf-sig
pkgbase = dtf-sig
pkgver = 1.0-1
pkgdesc = DTF push-sync signature fixture
url = https://example.invalid/dtf-sig
builddate = 1700000000
packager = DTF <dtf@example.invalid>
size = 64
arch = any
license = MIT
P
( cd "$d" && bsdtar -czf .MTREE --format=mtree --options="!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link" .PKGINFO usr \
    && bsdtar --zstd -cf /work/out/dtf-sig-1.0-1-any.pkg.tar.zst .MTREE .PKGINFO usr )
export GNUPGHOME=/work/key; mkdir -p -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase "" --quick-gen-key "DTF packager <dtf@example.invalid>" ed25519 sign never
gpg --batch --quiet --detach-sign /work/out/dtf-sig-1.0-1-any.pkg.tar.zst
ls /work/out
')"
NU1="DtfEcho.1.0.0.nupkg"; NU2="DtfEcho.2.0.0.nupkg"
RPM1="dtf-echo-1.0-1.noarch.rpm"; RPM2="dtf-echo-2.0-1.noarch.rpm"
PKG="dtf-sig-1.0-1-any.pkg.tar.zst"; SIG="${PKG}.sig"
for f in "$NU1" "$NU2" "$RPM1" "$RPM2" "$PKG" "$SIG"; do
  fetch "$f"
  [ -s "$W/$f" ] || SETUP_ERR="${SETUP_ERR} fixture ${f} not built ($(printf '%s' "$build_out" | tail -n 2 | tr '\n' '|'));"
done

declare -A RID_A=() RID_B=()
for spec in "$R_NU:nuget" "$R_RPM:rpm" "$R_PAC:pacman"; do
  IFS=: read -r k f <<<"$spec"
  RID_A[$k]="$(repo_create "$A" "$k" "$f")"
  RID_B[$k]="$(repo_create "$B" "$k" "$f")"
  [ -n "${RID_A[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on A failed;"
  [ -n "${RID_B[$k]}" ] || SETUP_ERR="${SETUP_ERR} create ${k} on B failed;"
done
for base in "$A" "$B"; do
  c="$(depth_one "$base" "$R_RPM")"
  [[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} repodata_depth 1 on ${base} -> ${c};"
done

B_KEY="$(mint_key "$B")"; A_KEY="$(mint_key "$A")"
[ -n "$B_KEY" ] && [ -n "$A_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint API keys;"
PEER_B_ON_A="$(register_peer "$A" "dtf-peer-b-${SLOT}-${SUF}" "http://peer-backend:8080" "$B_KEY")"
# B reaches A by its container name: the bare `backend` service alias is on
# the peer endpoint host blocklist (an internal name), the container name is not.
PEER_A_ON_B="$(register_peer "$B" "dtf-peer-a-${SLOT}-${SUF}" "http://ak-dtf${SLOT}-backend:8080" "$A_KEY")"
if [ -z "$PEER_B_ON_A" ] || [ -z "$PEER_A_ON_B" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration failed (B on A '${PEER_B_ON_A}', A on B '${PEER_A_ON_B}': $(cat "$W"/peer-* 2>/dev/null | tr '\n' ' ' | cut -c1-300));"
else
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_B_ON_A}'" >/dev/null
  psql_b "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_A_ON_B}'" >/dev/null
  for k in "$R_NU" "$R_RPM" "$R_PAC"; do
    c="$(subscribe "$A" "$PEER_B_ON_A" "${RID_A[$k]:-x}")"
    [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe B to ${k} on A -> ${c};"
  done
  # The return path the echo would travel: B pushes these repos to A.
  for k in "$R_NU" "$R_RPM"; do
    c="$(subscribe "$B" "$PEER_A_ON_B" "${RID_B[$k]:-x}")"
    [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe A to ${k} on B -> ${c};"
  done
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

NU1_PATH="dtfecho/1.0.0/dtfecho.1.0.0.nupkg"; NU2_PATH="dtfecho/2.0.0/dtfecho.2.0.0.nupkg"
RPM1_PATH="build-a/${RPM1}"; RPM2_PATH="build-a/${RPM2}"
PKG_PATH="any/${PKG}"

# =============================================================================
# Client uploads on A: NuGet push, nested RPM PUT, pacman package (no .sig yet)
# =============================================================================
begin_test "CONTROL: a NuGet push, a nested RPM PUT and a pacman upload on A succeed and each queue one push row for B"
c_nu="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$W/$NU1" "${A}/nuget/${R_NU}/api/v2/package")"
c_rpm="$(code -u "$AUTH" -X PUT --data-binary @"$W/$RPM1" "${A}/rpm/${R_RPM}/${RPM1_PATH}")"
c_pac="$(code -u "$AUTH" -X PUT --data-binary @"$W/$PKG" "${A}/pacman/${R_PAC}/${PKG}")"
st_nu="$(push_rows a "$PEER_B_ON_A" "$R_NU" "$NU1_PATH")"
st_rpm="$(push_rows a "$PEER_B_ON_A" "$R_RPM" "$RPM1_PATH")"
st_pac="$(push_rows a "$PEER_B_ON_A" "$R_PAC" "$PKG_PATH")"
re='^(pending|in_progress|completed)\|1$'
if [[ "$c_nu" == 20? && "$c_rpm" == 20? && "$c_pac" == 20? ]] \
   && [[ "$st_nu" =~ $re && "$st_rpm" =~ $re && "$st_pac" =~ $re ]] \
   && [ "$(sha_a "$R_NU" "$NU1_PATH")" = "$(sha "$NU1")" ] && [ "$(sha_a "$R_RPM" "$RPM1_PATH")" = "$(sha "$RPM1")" ]; then
  pass
else
  infra_fail "uploads on A: nuget=${c_nu} rpm=${c_rpm} pacman=${c_pac}; push rows nuget=${st_nu} rpm=${st_rpm} pacman=${st_pac}"
  end_suite; exit $?
fi

begin_test "CONTROL: the worker delivers each to B exactly once (row on B, sha256 equal, B serves the bytes, one completed push row on A)"
wait_sha_b "$R_NU" "$NU1_PATH" "$(sha "$NU1")" 90
wait_sha_b "$R_RPM" "$RPM1_PATH" "$(sha "$RPM1")" 30
wait_sha_b "$R_PAC" "$PKG_PATH" "$(sha "$PKG")" 30
DELIV_ERR=""
for spec in "nuget|$R_NU|$NU1_PATH|$NU1" "rpm|$R_RPM|$RPM1_PATH|$RPM1" "pacman|$R_PAC|$PKG_PATH|$PKG"; do
  IFS='|' read -r label repo path f <<<"$spec"
  want="$(sha "$f")"
  rows_b="$(psql_b "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${repo}' AND a.path = '${path}'")"
  got="$(served_b "${B}/api/v1/repositories/${repo}/download/${path}")"
  st="$(push_rows a "$PEER_B_ON_A" "$repo" "$path")"
  [ "$(sha_b "$repo" "$path")" = "$want" ] && [ "$rows_b" = "1" ] && [ "$got" = "200:${want}" ] && [ "$st" = "completed|1" ] \
    || DELIV_ERR="${DELIV_ERR} ${label}: B rows=${rows_b} sha=$(sha_b "$repo" "$path") GET=${got} A push=${st};"
done
if [ -z "$DELIV_ERR" ]; then pass; else
  fail "client uploads did not reach B cleanly:${DELIV_ERR}" \
       "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_B_ON_A}'")"
fi

begin_test "CONTROL: B queued nothing back to A for the writes A delivered"
n="$(b_rows_for_a)"
if [ "$n" = "0" ]; then pass; else
  fail "B holds ${n} push row(s) for A after receiving A's replication: the delivery itself echoed"
fi

# =============================================================================
# #4792-1: a peer write to B's native NuGet / nested RPM routes
# =============================================================================
# The writes a peer delivers carry X-Artifact-Keeper-Replication: true. B
# must store them without fanning them out to its own push peers (A here).
c_nu2="$(code -u "$AUTH" -X PUT -H 'Content-Type: application/octet-stream' -H 'X-Artifact-Keeper-Replication: true' \
  --data-binary @"$W/$NU2" "${B}/nuget/${R_NU}/api/v2/package")"
c_rpm2="$(code -u "$AUTH" -X PUT -H 'X-Artifact-Keeper-Replication: true' \
  --data-binary @"$W/$RPM2" "${B}/rpm/${R_RPM}/${RPM2_PATH}")"
st_nu2="$(push_rows b "$PEER_A_ON_B" "$R_NU" "$NU2_PATH")"
st_rpm2="$(push_rows b "$PEER_A_ON_B" "$R_RPM" "$RPM2_PATH")"

begin_test "FIX(#4792): a NuGet push arriving at B as a peer write stores and queues no push row back to A"
if [[ "$c_nu2" == 20? ]] && [ "$st_nu2" = "none|0" ]; then pass; else
  fail "replicated NuGet push on B -> ${c_nu2}, B push rows for A ${st_nu2} (want 2xx and none|0): the handler queued a peer write again"
fi
begin_test "FIX(#4792): a nested-layout RPM PUT arriving at B as a peer write stores and queues no push row back to A"
if [[ "$c_rpm2" == 20? ]] && [ "$st_rpm2" = "none|0" ]; then pass; else
  fail "replicated nested RPM PUT on B -> ${c_rpm2}, B push rows for A ${st_rpm2} (want 2xx and none|0): the depth > 0 branch queued a peer write again"
fi

# =============================================================================
# #4792-2: a pacman .sig uploaded to A after the package already reached B
# =============================================================================
c_sig="$(code -u "$AUTH" -X PUT --data-binary @"$W/$SIG" "${A}/pacman/${R_PAC}/${SIG}")"
want_sig="$(sha "$SIG")"
deadline=$(( $(date +%s) + 60 ))
got_sig="$(served_b "${B}/pacman/${R_PAC}/any/${SIG}")"
while [ "$got_sig" != "200:${want_sig}" ] && [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 3; got_sig="$(served_b "${B}/pacman/${R_PAC}/any/${SIG}")"
done
a_sig="$(curl -s -o "$W/asig" -w '%{http_code}' --max-time 30 -u "$AUTH" "${A}/pacman/${R_PAC}/any/${SIG}" 2>/dev/null):$(sha256sum "$W/asig" | cut -d' ' -f1)"

begin_test "CONTROL: the .sig upload on A succeeds and A serves it"
if [ "$c_sig" = "201" ] && [ "$a_sig" = "200:${want_sig}" ]; then pass; else
  fail "PUT ${SIG} on A -> ${c_sig}; A GET .sig -> ${a_sig} (want 201 and 200:${want_sig})"
fi

begin_test "FIX(#4792): B serves the signature attached on A after the package was delivered (bytes equal, within 60 s)"
st_pac="$(push_rows a "$PEER_B_ON_A" "$R_PAC" "$PKG_PATH")"
if [ "$got_sig" = "200:${want_sig}" ]; then pass; else
  fail "B GET ${R_PAC}/any/${SIG} -> ${got_sig} 60 s after the .sig landed on A (want 200:${want_sig}); A push row ${st_pac}" \
       "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_B_ON_A}'")"
fi

# --- settle, then the echo end state -----------------------------------------
sleep 25
begin_test "FIX(#4792): the peer writes on B never reached A and B holds no push row for A"
n="$(b_rows_for_a)"; a_nu2="$(sha_a "$R_NU" "$NU2_PATH")"; a_rpm2="$(sha_a "$R_RPM" "$RPM2_PATH")"
if [ "$n" = "0" ] && [ -z "$a_nu2" ] && [ -z "$a_rpm2" ]; then pass; else
  fail "B push rows for A=${n}; A rows for the peer writes: nuget=${a_nu2:-none} rpm=${a_rpm2:-none} (want 0, none, none): a replicated write was pushed back out"
fi

begin_test "CONTROL: A's push rows for B end completed, one per artifact (the signature re-used the package's row)"
rows="$(psql_a "SELECT count(*) FILTER (WHERE status = 'completed') || '/' || count(*) FROM sync_tasks \
                WHERE peer_instance_id = '${PEER_B_ON_A}' AND task_type = 'push'")"
if [ "$rows" = "3/3" ]; then pass; else
  fail "A push rows for B completed/total=${rows} (want 3/3: nuget, nested rpm, pacman)" \
       "$(psql_a "SELECT status || ' ' || coalesce(error_message,'') FROM sync_tasks WHERE peer_instance_id = '${PEER_B_ON_A}'")"
fi

end_suite
