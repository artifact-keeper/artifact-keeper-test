#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/catalog-backfill-liveness/oracle.sh
#   #4168  the admin catalog backfill skips quarantined and rejected artifacts
#   #4191  a Go module's backfilled catalog size is the .zip's, never the
#          go.mod sidecar's
#   #4305  an npm Remote's cached packuments are not listed (or counted) as
#          cached artifacts; its tarballs are
# See the manifest for the gates and which image each case goes red on.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
NPM_UP="http://172.16.${DTF_SLOT}.90/m1"   # profiles/upstreams.mock-npm.yml

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }

# req <METHOD> <PATH> [JSON body]: admin call, sets CODE and BODY.
req(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
put_file(){ # <path> <file>
  : >"${W}/body"
  CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$2" "${BASE}$1")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format> <type> [upstream]
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')"
  is_2xx "$CODE" || { infra_fail "creating ${1} answered ${CODE}: ${BODY:0:200}"; end_suite; }
}
sha_of(){ sha256sum "$1" | cut -d' ' -f1; }
size_of(){ wc -c <"$1" | tr -d ' '; }
art_id(){ psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1' AND a.path = '$2' AND NOT a.is_deleted"; }
# catalog <repo>: "name@version=size" per catalog version row, sorted.
catalog(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT p.name || '@' || pv.version || '=' || pv.size_bytes FROM packages p JOIN package_versions pv ON pv.package_id = p.id JOIN repositories r ON r.id = p.repository_id WHERE r.key = '$1' ORDER BY 1" 2>/dev/null | sed '/^$/d' | paste -sd' ' -; }
# empty_and_backfill <repo>: drop the repo's catalog, run the admin backfill.
empty_and_backfill(){
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "DELETE FROM packages WHERE repository_id = (SELECT id FROM repositories WHERE key = '$1')" >/dev/null 2>&1
  req POST /api/v1/admin/packages/backfill
  note "backfill: ${CODE} $(jqr -c '{artifacts_scanned,packages_registered,artifacts_skipped}' <<<"$BODY")"
  is_2xx "$CODE" || fail_g "the admin backfill answered ${CODE}: ${BODY:0:200}"
}
# go_put <repo> <module> <version> <ext> <file>
go_put(){ put_file "/go/$1/$2/@v/$3.$4" "$5"; }
# mk_zip <module> <version> <out>: a module zip whose sha256 starts at or
# above '8', so a go.mod crafted below can sort before it.
mk_zip(){
  python3 -I - "$1" "$2" "$3" <<'PY'
import hashlib, io, sys, zipfile
mod, ver, out = sys.argv[1:4]
n = 0
while True:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo(f"{mod}@{ver}/go.mod", (2020, 1, 1, 0, 0, 0)), f"module {mod}\n")
        z.writestr(zipfile.ZipInfo(f"{mod}@{ver}/lib.go", (2020, 1, 1, 0, 0, 0)),
                   f"package lib\n\n// pad {n}\nconst Payload = \"{'x' * 4096}\"\n")
    data = buf.getvalue()
    if hashlib.sha256(data).hexdigest()[0] >= "8":
        open(out, "wb").write(data)
        break
    n += 1
PY
}
# mk_mod <module> <out>: a go.mod whose sha256 starts with '0' (sorts first).
mk_mod(){
  python3 -I - "$1" "$2" <<'PY'
import hashlib, sys
mod, out = sys.argv[1:3]
n = 0
while True:
    data = f"module {mod}\n\ngo 1.21\n// {n}\n".encode()
    if hashlib.sha256(data).hexdigest()[0] == "0":
        open(out, "wb").write(data)
        break
    n += 1
PY
}

begin_suite "catalog-backfill-liveness"

# =============================================================================
begin_test "setup: admin session, a hosted Go repo, an npm Remote on the mock registry"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
R_GO="cb-go-${SFX}"; R_NPM="cb-npm-${SFX}"
mk_repo "$R_GO" go local
mk_repo "$R_NPM" npm remote "$NPM_UP"
MOD="example.test/dtf${DTF_SLOT}x$$"
echo "-- go repo ${R_GO} (module ${MOD}); npm remote ${R_NPM} -> ${NPM_UP}"
pass

# =============================================================================
begin_test "CONTROL: a backfill of a Go module whose only rows are .zip archives catalogues each version at the zip's size"
reset_case
mk_zip "$MOD" v0.9.0 "${W}/v090.zip"
go_put "$R_GO" "$MOD" v0.9.0 zip "${W}/v090.zip"
note "PUT v0.9.0.zip: ${CODE}"
is_2xx "$CODE" || fail_g "the Go zip publish answered ${CODE}: ${BODY:0:200}"
CTL_SIZE="$(size_of "${W}/v090.zip")"
empty_and_backfill "$R_GO"
cat0="$(catalog "$R_GO")"
note "catalog after backfill: ${cat0:-empty}"
grep -q "@v0.9.0=${CTL_SIZE}\( \|$\)" <<<"$cat0" || fail_g "v0.9.0 is not catalogued at the zip's ${CTL_SIZE} bytes"
finish_case "the backfill does not catalogue a plain Go module"

begin_test "#4191: with a go.mod sidecar beside the zip, the backfilled version size is still the zip's"
reset_case
mk_zip "$MOD" v1.0.0 "${W}/v100.zip"; mk_mod "$MOD" "${W}/v100.mod"
go_put "$R_GO" "$MOD" v1.0.0 zip "${W}/v100.zip"; c1="$CODE"
go_put "$R_GO" "$MOD" v1.0.0 mod "${W}/v100.mod"; c2="$CODE"
ZIP_SIZE="$(size_of "${W}/v100.zip")"; MOD_SIZE="$(size_of "${W}/v100.mod")"
note "PUT zip ${c1} (${ZIP_SIZE} B, sha $(sha_of "${W}/v100.zip" | cut -c1-8)); PUT mod ${c2} (${MOD_SIZE} B, sha $(sha_of "${W}/v100.mod" | cut -c1-8))"
{ is_2xx "$c1" && is_2xx "$c2"; } || fail_g "the Go publishes answered ${c1}/${c2}"
note "artifact rows: zip=$(art_id "$R_GO" "${MOD}/v1.0.0/v1.0.0.zip" | cut -c1-8) go.mod=$(art_id "$R_GO" "${MOD}/v1.0.0/go.mod" | cut -c1-8)"
[ -n "$(art_id "$R_GO" "${MOD}/v1.0.0/go.mod")" ] || fail_g "the go.mod upload left no artifact row (nothing for the backfill to mis-count)"
empty_and_backfill "$R_GO"
cat1="$(catalog "$R_GO")"
note "catalog after backfill: ${cat1:-empty}"
# The catalog keeps the version row with the smallest (checksum, size); the
# go.mod's checksum is crafted to sort first, so a backfill that considers it
# at all records its size.
grep -q "@v1.0.0=${ZIP_SIZE}\( \|$\)" <<<"$cat1" || fail_g "v1.0.0 is not catalogued at the zip's ${ZIP_SIZE} bytes"
grep -q "@v1.0.0=${MOD_SIZE}\( \|$\)" <<<"$cat1" && fail_g "v1.0.0 is catalogued at the go.mod sidecar's ${MOD_SIZE} bytes"
finish_case "the backfill lets a go.mod sidecar define a Go module version"

begin_test "#4168: the backfill does not catalogue a quarantined or a rejected artifact"
reset_case
for v in v2.0.0 v3.0.0; do
  mk_zip "$MOD" "$v" "${W}/${v}.zip"
  go_put "$R_GO" "$MOD" "$v" zip "${W}/${v}.zip"
  is_2xx "$CODE" || fail_g "PUT ${v}.zip answered ${CODE}"
done
Q_ID="$(art_id "$R_GO" "${MOD}/v2.0.0/v2.0.0.zip")"; R_ID="$(art_id "$R_GO" "${MOD}/v3.0.0/v3.0.0.zip")"
req POST "/api/v1/quarantine/${Q_ID}/quarantine" '{"reason":"dtf catalog-backfill-liveness"}'
note "quarantine v2.0.0 (${Q_ID:0:8}): ${CODE}"
is_2xx "$CODE" || fail_g "quarantining v2.0.0 answered ${CODE}: ${BODY:0:200}"
req POST "/api/v1/quarantine/${R_ID}/quarantine" '{"reason":"dtf catalog-backfill-liveness"}'
req POST "/api/v1/quarantine/${R_ID}/reject" '{"reason":"dtf catalog-backfill-liveness"}'
note "reject v3.0.0 (${R_ID:0:8}): ${CODE}"
is_2xx "$CODE" || fail_g "rejecting v3.0.0 answered ${CODE}: ${BODY:0:200}"
qs="$(psql_q "SELECT string_agg(a.path || ':' || COALESCE(a.quarantine_status, 'null'), ',') FROM artifacts a WHERE a.id IN ('${Q_ID}', '${R_ID}')")"
note "quarantine_status: ${qs}"
case "$qs" in *v2.0.0.zip:quarantined*) : ;; *) fail_g "v2.0.0 is not quarantined (${qs})";; esac
case "$qs" in *v3.0.0.zip:rejected*) : ;; *) fail_g "v3.0.0 is not rejected (${qs})";; esac
empty_and_backfill "$R_GO"
cat2="$(catalog "$R_GO")"
note "catalog after backfill: ${cat2:-empty}"
grep -q "@v2.0.0=" <<<"$cat2" && fail_g "the quarantined v2.0.0 was catalogued"
grep -q "@v3.0.0=" <<<"$cat2" && fail_g "the rejected v3.0.0 was catalogued"
grep -q "@v0.9.0=" <<<"$cat2" || fail_g "the clean v0.9.0 is missing from the catalog (the backfill ran nothing)"
finish_case "the backfill catalogues artifacts the registry refuses to serve"

begin_test "#4305: an npm Remote lists and counts its cached tarball but not the cached packument"
reset_case
req GET "/npm/${R_NPM}/dtf-held"
note "GET packument: ${CODE} name=$(jqr '.name // empty' <<<"$BODY")"
[ "$CODE" = "200" ] || fail_g "the packument fetch answered ${CODE}"
curl -s -o "${W}/t.tgz" -w '' --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/npm/${R_NPM}/dtf-held/-/dtf-held-1.0.0.tgz"
note "GET tarball: $(size_of "${W}/t.tgz") bytes"
[ "$(size_of "${W}/t.tgz")" -gt 0 ] 2>/dev/null || fail_g "the tarball fetch returned nothing"
paths=""; total=""
for _i in $(seq 1 20); do
  req GET "/api/v1/repositories/${R_NPM}/artifacts?count=exact&per_page=100"
  paths="$(jqr -c '[.items[]? | .path] | sort' <<<"$BODY")"
  total="$(jqr '.pagination.total // .total // empty' <<<"$BODY")"
  grep -q 'dtf-held-1.0.0.tgz' <<<"$paths" && break
  sleep 1
done
note "cached listing: ${CODE} paths=${paths} total=${total:-?}"
grep -q '"dtf-held/-/dtf-held-1.0.0.tgz"' <<<"$paths" || fail_g "the cached tarball is not listed"
grep -q '"dtf-held"' <<<"$paths" && fail_g "the cached packument is listed as an artifact"
[ "$total" = "1" ] || fail_g "the cached-artifact count is ${total:-absent}, expected 1 (the tarball)"
finish_case "an npm Remote lists its cached packuments as artifacts"

end_suite
