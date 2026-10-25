#!/usr/bin/env bash
# =============================================================================
# tiers/oci-manifests-reconcile-populated/oracle.sh
#   artifact-keeper#1683 (1.12.0): on a populated repository the oci_manifests
#   reconcile adds and removes exactly the expected rows and removes no row of
#   a manifest a client can still pull by digest.
# See the manifest for the population and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
GROUPS_N="${OLP_GROUPS:-30}"
INTERVAL=15        # OCI_MANIFESTS_RECONCILE_INTERVAL_SECS in profiles/gc.oci-manifests-reconcile-fast.yml
MAX_WAIT=240

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

OCI_AUTH=()
MT='application/vnd.oci.image.manifest.v1+json'
IT='application/vnd.oci.image.index.v1+json'
ERR=""
blob_push(){ # <image> <file>
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$2" "$BASE/v2/$REPO/$1/blobs/uploads/?digest=sha256:$(sha_of "$2")" || true)"
  [ "$c" = "201" ] || ERR="${ERR} blob ${1}=${c};"
}
put_man(){ # <image> <reference> <media type> <file>
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X PUT -H "Content-Type: $3" \
    --data-binary "@$4" "$BASE/v2/$REPO/$1/manifests/$2" || true)"
  [ "$c" = "201" ] || ERR="${ERR} PUT ${1}:${2}=${c};"
}
del_man(){ # <image> <reference>
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X DELETE "$BASE/v2/$REPO/$1/manifests/$2" || true)"
  case "$c" in 200|202|204) ;; *) ERR="${ERR} DELETE ${1}:${2}=${c};";; esac
}
# mk_image <name> [subject digest]: config + layer blobs pushed under img-<g>;
# body in $W/m/<name>.json, digest printed.
mk_image(){
  local n="$1" subj="${2:-}" cfg="$W/b/$1.cfg" layer="$W/b/$1.layer" man="$W/m/$1.json"
  printf '{"dtf":"%s","n":"%s"}' "$SUF" "$n" > "$cfg"
  printf 'olp-%s-%s\n' "$n" "$SUF" > "$layer"
  blob_push "$IMG" "$cfg"; blob_push "$IMG" "$layer"
  jq -nc --arg cd "sha256:$(sha_of "$cfg")" --argjson cs "$(wc -c < "$cfg" | tr -d ' ')" \
         --arg ld "sha256:$(sha_of "$layer")" --argjson ls "$(wc -c < "$layer" | tr -d ' ')" --arg subj "$subj" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$ld,size:$ls}]}
     + (if $subj != "" then {artifactType:"application/vnd.example.sig",subject:{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$subj,size:10}} else {} end)' \
    | tr -d '\n' > "$man"
  echo "sha256:$(sha_of "$man")"
}
mk_index(){ # <name> <child media type> <child digest>...
  local n="$1" ct="$2"; shift 2
  printf '%s\n' "$@" | jq -R . | jq -sc --arg ct "$ct" '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",
    manifests:[.[] | {mediaType:$ct,digest:.,size:10,platform:{architecture:"amd64",os:"linux"}}]}' \
    | tr -d '\n' > "$W/m/$n.json"
  echo "sha256:$(sha_of "$W/m/$n.json")"
}
# record <digest> <image to GET under> <case> <expectation>
record(){ printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$W/universe.tsv"; }
get_status(){ # <image> <digest>
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${OCI_AUTH[@]}" -H "Accept: $MT, $IT" \
    "$BASE/v2/$REPO/$1/manifests/$2" || true
}
rows_snapshot(){ psql_q "SELECT digest FROM oci_manifests WHERE repository_id='${REPO_ID}' ORDER BY digest;" | tr -d ' ' | sed '/^$/d'; }
statuses(){ # -> "<digest>\t<status>" for the universe
  while IFS=$'\t' read -r d img _ _; do printf '%s\t%s\n' "$d" "$(get_status "$img" "$d")"; done < "$W/universe.tsv"
}

# =============================================================================
begin_suite "oci-manifests-reconcile-populated"

begin_test "setup: a docker repository populated with ${GROUPS_N} groups of images, indexes, untagged children and referrers"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
# Bearer, not basic: a basic credential is a password hash per request,
# which would stretch the population past the reconcile's 600 s row age.
OCI_AUTH=(-H "Authorization: Bearer $TOK")
SUF="${RUN_ID##*-}-$$"
REPO="olp-${DTF_SLOT}-${SUF}"
REPO_ID="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"docker",repo_type:"local",is_public:false}')" | jqr '.id // empty')"
[ -n "$REPO_ID" ] || { infra_fail "could not create the docker repository ${REPO}"; end_suite; }
mkdir -p "$W/b" "$W/m"; : > "$W/universe.tsv"
SQL_K=""; SQL_L=""; SQL_G=""
T_SETUP=$(date +%s)
for g in $(seq 1 "$GROUPS_N"); do
  IMG="img-$g"; SCR="scr-$g"
  # A, and its signature H
  a="$(mk_image "a$g")"; put_man "$IMG" a "$MT" "$W/m/a$g.json"; record "$a" "$IMG" A keep
  h="$(mk_image "h$g" "$a")"; put_man "$IMG" "$h" "$MT" "$W/m/h$g.json"; record "$h" "$IMG" H keep
  # B
  b="$(mk_image "b$g")"; put_man "$IMG" b "$MT" "$W/m/b$g.json"; del_man "$IMG" b; record "$b" "$IMG" B absent
  # C
  c1="$(mk_image "c1$g")"; put_man "$IMG" c "$MT" "$W/m/c1$g.json"
  c2="$(mk_image "c2$g")"; put_man "$IMG" c "$MT" "$W/m/c2$g.json"
  record "$c1" "$IMG" C1 keep; record "$c2" "$IMG" C2 keep
  # D
  d1="$(mk_image "d1$g")"; d2="$(mk_image "d2$g")"
  put_man "$IMG" "$d1" "$MT" "$W/m/d1$g.json"; put_man "$IMG" "$d2" "$MT" "$W/m/d2$g.json"
  di="$(mk_index "di$g" "$MT" "$d1" "$d2")"; put_man "$IMG" d "$IT" "$W/m/di$g.json"
  record "$d1" "$IMG" D-child keep; record "$d2" "$IMG" D-child keep; record "$di" "$IMG" D-index keep
  # E
  e1="$(mk_image "e1$g")"; e2="$(mk_image "e2$g")"
  put_man "$IMG" e1 "$MT" "$W/m/e1$g.json"; put_man "$IMG" e2 "$MT" "$W/m/e2$g.json"
  ei="$(mk_index "ei$g" "$MT" "$e1" "$e2")"; put_man "$IMG" e "$IT" "$W/m/ei$g.json"
  del_man "$IMG" e1; del_man "$IMG" e2
  record "$e1" "$IMG" E-child keep; record "$e2" "$IMG" E-child keep; record "$ei" "$IMG" E-index keep
  # F
  fl="$(mk_image "fl$g")"; put_man "$SCR" l "$MT" "$W/m/fl$g.json"
  fm="$(mk_index "fm$g" "$MT" "$fl")"; put_man "$SCR" m "$IT" "$W/m/fm$g.json"
  ft="$(mk_index "ft$g" "$IT" "$fm")"; put_man "$IMG" f "$IT" "$W/m/ft$g.json"
  del_man "$SCR" l; del_man "$SCR" m
  record "$fl" "$IMG" F-leaf keep; record "$fm" "$IMG" F-middle keep; record "$ft" "$IMG" F-top keep
  # G (the SQL half runs after the loop)
  gc="$(mk_image "gc$g")"; put_man "$IMG" "$gc" "$MT" "$W/m/gc$g.json"
  gi="$(mk_index "gi$g" "$MT" "$gc")"; put_man "$IMG" g "$IT" "$W/m/gi$g.json"
  record "$gc" "$IMG" G-child keep; record "$gi" "$IMG" G-index keep
  SQL_G="${SQL_G} ('${gi}','${gc}','${IMG}'),"
  # J
  j="$(mk_image "j$g")"; put_man "$IMG" j "$MT" "$W/m/j$g.json"; del_man "$IMG" "$j"; record "$j" "$IMG" J absent
  # K
  k="$(mk_image "k$g")"; put_man "$IMG" k "$MT" "$W/m/k$g.json"; del_man "$IMG" k; record "$k" "$IMG" K remove
  SQL_K="${SQL_K} ('${k}', $(wc -c < "$W/m/k$g.json" | tr -d ' ')),"
  # L
  l="$(mk_image "l$g")"; put_man "$IMG" l "$MT" "$W/m/l$g.json"; record "$l" "$IMG" L add
  SQL_L="${SQL_L}'${l}',"
done
[ -z "$ERR" ] || { infra_fail "population failed:${ERR:0:600}"; end_suite; }
# R0: the rows the pushes and deletes left. The SQL below makes the K and L
# drift; a correct pass restores exactly R0.
rows_snapshot > "$W/r0.rows"
# G: the index becomes a pre-#2457 migrated manifest (generic CAS key, no
# tag); its child keeps no tag and no artifacts row, only the index edge.
psql_x "WITH g(idx, child, img) AS (VALUES ${SQL_G%,})
  , moved AS (
      UPDATE artifacts a SET storage_key = 'cas/' || SUBSTRING(g.idx FROM 8),
                             path = g.img || '/g/list.manifest.json'
      FROM g WHERE a.repository_id='${REPO_ID}' AND a.path = 'v2/' || g.img || '/manifests/g' RETURNING 1)
  , t AS (DELETE FROM oci_tags ot USING g WHERE ot.repository_id='${REPO_ID}'
          AND ot.manifest_digest IN (g.idx, g.child) RETURNING 1)
  DELETE FROM artifacts a USING g WHERE a.repository_id='${REPO_ID}' AND a.path = 'v2/' || g.img || '/manifests/' || g.child;" \
  || { infra_fail "could not make the G indexes migrated"; end_suite; }
# K: the row a 1.11.0-era last-tag delete left behind.
psql_x "INSERT INTO oci_manifests (repository_id, digest, content_type, size_bytes)
  SELECT '${REPO_ID}', k.d, '${MT}', k.n FROM (VALUES ${SQL_K%,}) AS k(d, n) ON CONFLICT DO NOTHING;" \
  || { infra_fail "could not put the K rows back"; end_suite; }
# L: a push served by a pre-268 replica recorded no row.
psql_x "DELETE FROM oci_manifests WHERE repository_id='${REPO_ID}' AND digest IN (${SQL_L%,});" \
  || { infra_fail "could not delete the L rows"; end_suite; }
N_DIG="$(wc -l < "$W/universe.tsv" | tr -d ' ')"
echo "-- repo ${REPO}: ${N_DIG} manifest digests, $(wc -l < "$W/r0.rows" | tr -d ' ') oci_manifests rows after the pushes, $(( $(date +%s) - T_SETUP ))s"
pass

# What clients are served before the pass; then age every row and let the
# reconcile run until K is gone, L is back and two windows change nothing.
statuses > "$W/before.status"
psql_x "UPDATE oci_manifests SET last_referenced_at = NOW() - interval '1 hour' WHERE repository_id='${REPO_ID}';" \
  || { infra_fail "could not age the rows"; end_suite; }
awk -F'\t' '$4=="remove"{print $1}' "$W/universe.tsv" | sort > "$W/exp.removed"
awk -F'\t' '$4=="add"{print $1}' "$W/universe.tsv" | sort > "$W/exp.added"
T0=$(date +%s); prev=""; stable=0
while :; do
  sleep "$INTERVAL"
  rows_snapshot > "$W/now.rows"
  cur="$(sha256sum < "$W/now.rows" | awk '{print $1}')"
  if [ "$cur" = "$prev" ]; then stable=$((stable+1)); else stable=0; fi
  prev="$cur"
  k_left="$(comm -12 "$W/now.rows" "$W/exp.removed" | wc -l | tr -d ' ')"
  l_missing="$(comm -13 "$W/now.rows" "$W/exp.added" | wc -l | tr -d ' ')"
  [ "$stable" -ge 2 ] && [ "$k_left" = "0" ] && [ "$l_missing" = "0" ] && break
  [ $(( $(date +%s) - T0 )) -ge "$MAX_WAIT" ] && break
done
WAITED=$(( $(date +%s) - T0 ))
rows_snapshot > "$W/after.rows"
statuses > "$W/after.status"
METRICS="$(curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/metrics" | grep -E '^ak_oci_manifests_reconcile_(rows_added|rows_removed|failures)_total' | tr '\n' ' ' || true)"

# Removed: rows of the population (R0) or of the K drift gone after the
# pass. Added: rows present after the pass that R0 did not have, plus the L
# rows restored.
sort -u "$W/r0.rows" "$W/exp.removed" > "$W/before.rows"
comm -23 "$W/before.rows" "$W/after.rows" > "$W/removed"
comm -13 "$W/r0.rows" "$W/after.rows" > "$W/added.new"
comm -12 "$W/exp.added" "$W/after.rows" > "$W/added.l"
sort -u "$W/added.new" "$W/added.l" > "$W/added"
case_of(){ awk -F'\t' -v d="$1" '$1==d{print $3; exit}' "$W/universe.tsv"; }
st_of(){ awk -F'\t' -v d="$1" '$1==d{print $2; exit}' "$2"; }
by_case(){ while read -r d; do [ -n "$d" ] && case_of "$d"; done < "$1" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}'; }

begin_test "the reconcile removes exactly the rows of manifests that are no longer addressable (K)"
reset_case
note "after ${WAITED}s: rows $(wc -l < "$W/before.rows" | tr -d ' ') -> $(wc -l < "$W/after.rows" | tr -d ' '); ${METRICS}"
note "removed $(wc -l < "$W/removed" | tr -d ' ') [$(by_case "$W/removed")], expected $(wc -l < "$W/exp.removed" | tr -d ' ') [K]"
extra="$(comm -23 "$W/removed" "$W/exp.removed")"; missing="$(comm -13 "$W/removed" "$W/exp.removed")"
[ -z "$extra" ] || fail_g "removed rows that were not expected: $(echo "$extra" | while read -r d; do printf '%s(%s) ' "${d:7:12}" "$(case_of "$d")"; done)"
[ -z "$missing" ] || fail_g "expected removals that did not happen: $(echo "$missing" | wc -l | tr -d ' ')"
finish_case "the reconcile removed the wrong set of rows"

begin_test "the reconcile adds exactly the rows of tagged manifests that had none (L)"
reset_case
note "added $(wc -l < "$W/added" | tr -d ' ') [$(by_case "$W/added")], expected $(wc -l < "$W/exp.added" | tr -d ' ') [L]"
extra="$(comm -23 "$W/added" "$W/exp.added")"; missing="$(comm -13 "$W/added" "$W/exp.added")"
[ -z "$extra" ] || fail_g "added rows that were not expected: $(echo "$extra" | wc -l | tr -d ' ')"
[ -z "$missing" ] || fail_g "expected additions that did not happen: $(echo "$missing" | wc -l | tr -d ' ')"
finish_case "the reconcile added the wrong set of rows"

begin_test "no removed row belongs to a manifest that answered 200 by digest before the pass"
reset_case
bad=""
while read -r d; do
  [ -n "$d" ] || continue
  [ "$(st_of "$d" "$W/before.status")" = "200" ] && bad="${bad} ${d:7:12}($(case_of "$d"))"
done < "$W/removed"
note "removed rows whose digest pulled before the pass:${bad:- none}"
[ -z "$bad" ] || fail_g "the reconcile removed rows of manifests a client could still pull:${bad}"
finish_case "the reconcile removed rows of pullable manifests"

begin_test "the pass changes no answer a client sees: every digest's GET status is the same before and after"
reset_case
changed=""
while IFS=$'\t' read -r d s; do
  a="$(st_of "$d" "$W/after.status")"
  [ "$s" = "$a" ] || changed="${changed} ${d:7:12}($(case_of "$d") ${s}->${a})"
done < "$W/before.status"
note "status before: $(cut -f2 "$W/before.status" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}'); per case: $(paste "$W/universe.tsv" "$W/before.status" | awk -F'\t' '{print $3":"$6}' | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')"
note "changed:${changed:- none}"
[ -z "$changed" ] || fail_g "GET by digest answered differently after the reconcile:${changed}"
finish_case "the reconcile changed what clients are served"

end_suite
