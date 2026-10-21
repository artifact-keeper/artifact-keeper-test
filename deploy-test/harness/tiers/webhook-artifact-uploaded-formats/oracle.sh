#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/webhook-artifact-uploaded-formats/oracle.sh
#   #3939  artifact.uploaded fires exactly once, carrying the new artifact's
#          id and the uploader, for CRAN, Hex, Ansible, Puppet and RubyGems
#          publishes, single and bulk promotion, approved promotion, Git LFS
#          uploads and chunked-upload completion; a promotion's event belongs
#          to the target repository; the native publishes appear in
#          /api/v1/packages.
# See the manifest for the gates and which image each case goes red on.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock receiver's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${TRIVY_PORT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
MOCK_IN="http://172.16.${DTF_SLOT}.78"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
P="wu-${SFX}"

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

# req <METHOD> <PATH> [JSON body]: admin call, sets CODE and BODY.
req(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
# raw <curl args...>: admin call with arbitrary curl args, sets CODE and BODY.
raw(){
  : >"${W}/body"
  CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" "$@")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format> <type>
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}')"
  is_2xx "$CODE" || { infra_fail "creating ${1} (${2} ${3}) answered ${CODE}: ${BODY:0:200}"; end_suite; }
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
repo_id(){ psql_q "SELECT id FROM repositories WHERE key = '$1'"; }
# arts <repo_key>: live artifact ids in the repo, comma-separated, sorted.
arts(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1' AND NOT a.is_deleted ORDER BY a.id" 2>/dev/null | tr -d ' ' | grep -v '^$' | paste -sd, -; }
# rows <artifact_id> [webhook_id]: artifact_uploaded rows enqueued for it.
rows(){
  local extra=""
  [ -n "${2:-}" ] && extra=" AND webhook_id = '$2'"
  psql_q "SELECT count(*) FROM webhook_deliveries WHERE event = 'artifact_uploaded' AND payload->>'entity_id' = '$1'${extra}"
}
actor_of(){ psql_q "SELECT DISTINCT payload->>'actor' FROM webhook_deliveries WHERE event = 'artifact_uploaded' AND payload->>'entity_id' = '$1' AND webhook_id = '${WH_ALL}'"; }
# expect_one <label> <repo_key> <before ids>: the publish added exactly one
# live artifact to <repo_key>, and exactly one artifact_uploaded delivery was
# enqueued for it on the global webhook, attributed to the admin.
NEW_ID=""
expect_one(){
  local label="$1" key="$2" before="$3" want_actor="${4:-$ADMIN_ID}" after n a
  after="$(arts "$key")"
  NEW_ID="$(comm -13 <(tr ',' '\n' <<<"$before" | sed '/^$/d') <(tr ',' '\n' <<<"$after" | sed '/^$/d') | head -1)"
  if [ -z "$NEW_ID" ]; then
    fail_g "${label}: no new artifact row in ${key}"; return
  fi
  n="$(wait_rows "$NEW_ID" "$WH_ALL")"; a="$(actor_of "$NEW_ID")"
  note "${label}: artifact ${NEW_ID}; artifact_uploaded deliveries enqueued: ${n}; actor ${a:-none}"
  [ "$n" = "1" ] || fail_g "${label}: ${n} artifact_uploaded deliveries for ${NEW_ID}, expected exactly 1"
  [ "$n" = "0" ] || [ "$a" = "$want_actor" ] || fail_g "${label}: delivery actor ${a:-none}, expected ${want_actor}"
  SEEN_IDS="${SEEN_IDS} ${NEW_ID}"
}
# wait_rows <artifact_id> <webhook_id>: the row count once it has settled
# (the producer enqueues from an EventBus subscriber, a moment after the 2xx).
wait_rows(){
  local n="" prev="x" i
  for i in $(seq 1 10); do
    n="$(rows "$1" "$2")"
    [ "$n" != "0" ] && [ "$n" = "$prev" ] && break
    prev="$n"; sleep 0.5
    [ "$i" -ge 6 ] && [ "$n" = "0" ] && break
  done
  echo "${n:-0}"
}
SEEN_IDS=""

begin_suite "webhook-artifact-uploaded-formats"

# =============================================================================
begin_test "setup: admin session, mock receiver up, a global artifact_uploaded webhook, the repositories"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || { infra_fail "mock receiver not reachable on ${MOCK}"; end_suite; }
ADMIN_ID="$(psql_q "SELECT id FROM users WHERE username = 'admin'")"
req POST /api/v1/webhooks "$(jq -nc --arg u "${MOCK_IN}/hook/all-${SFX}" '{name:"wu-all",url:$u,events:["artifact_uploaded"]}')"
WH_ALL="$(jqr '.id // empty' <<<"$BODY")"
[ -n "$WH_ALL" ] || { infra_fail "creating the global webhook answered ${CODE}: ${BODY:0:200}"; end_suite; }
# Approval enforces separation of duties: a second admin approves.
R_NAME="wu-rev-${SFX}"; R_PASS="WuRev!${SFX}x9Q"
req POST /api/v1/users "$(jq -nc --arg u "$R_NAME" --arg p "$R_PASS" '{username:$u,password:$p,email:"\($u)@example.test",is_admin:true}')"
REV_ID="$(jqr '.user.id // .id // empty' <<<"$BODY")"
REV_TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$R_NAME" --arg p "$R_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
{ [ -n "$REV_ID" ] && [ -n "$REV_TOK" ]; } || { infra_fail "could not create/log in the reviewer admin (${CODE}: ${BODY:0:200})"; end_suite; }
for f in generic cran hex ansible puppet rubygems gitlfs; do mk_repo "${P}-${f}" "$f" local; done
mk_repo "${P}-stg" generic staging
mk_repo "${P}-rel" generic local
REL_ID="$(repo_id "${P}-rel")"
# Promotion checks tenant ownership of both repositories independently of
# is_admin (a grant, not the flag), so the reviewer gets a grant on each.
for rk in "${P}-stg" "${P}-rel"; do
  req POST /api/v1/permissions "$(jq -nc --arg u "$REV_ID" --arg r "$(repo_id "$rk")" '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read","write","delete","admin"]}')"
  is_2xx "$CODE" || { infra_fail "granting the reviewer ${rk} answered ${CODE}: ${BODY:0:200}"; end_suite; }
done
req POST /api/v1/webhooks "$(jq -nc --arg u "${MOCK_IN}/hook/rel-${SFX}" --arg r "$REL_ID" '{name:"wu-rel",url:$u,events:["artifact_uploaded"],repository_id:$r}')"
WH_REL="$(jqr '.id // empty' <<<"$BODY")"
[ -n "$WH_REL" ] || { infra_fail "creating the release-repo webhook answered ${CODE}: ${BODY:0:200}"; end_suite; }
echo "-- admin ${ADMIN_ID}; reviewer ${REV_ID}; global webhook ${WH_ALL}; release-repo webhook ${WH_REL} (repo ${REL_ID})"
pass

# =============================================================================
begin_test "CONTROL: a direct generic upload enqueues exactly one artifact_uploaded delivery, and the receiver gets it"
reset_case
before="$(arts "${P}-generic")"
printf 'generic %s\n' "$SFX" > "${W}/g.txt"
raw -X PUT --data-binary "@${W}/g.txt" "${BASE}/api/v1/repositories/${P}-generic/artifacts/g/g.txt"
note "PUT generic: ${CODE}"
is_2xx "$CODE" || fail_g "generic upload answered ${CODE}"
expect_one "generic upload" "${P}-generic" "$before"
CTL_ID="$NEW_ID"
finish_case "the webhook producer does not enqueue the generic upload event"

# =============================================================================
begin_test "#3939: a CRAN source package publish emits one artifact_uploaded and lists the package"
reset_case
d="${W}/cran/wuhello"; mkdir -p "${d}/R"
printf 'Package: wuhello\nTitle: DTF\nVersion: 1.0.0\nAuthors@R: person("D", "T", email = "d@example.test", role = c("aut", "cre"))\nDescription: DTF webhook tier.\nLicense: MIT\nEncoding: UTF-8\n' > "${d}/DESCRIPTION"
printf 'export(hello)\n' > "${d}/NAMESPACE"; printf 'hello <- function() "hi"\n' > "${d}/R/hello.R"
tar czf "${W}/wuhello_1.0.0.tar.gz" -C "${W}/cran" wuhello
before="$(arts "${P}-cran")"
raw -X PUT -H 'Content-Type: application/gzip' --data-binary "@${W}/wuhello_1.0.0.tar.gz" "${BASE}/cran/${P}-cran/src/contrib/wuhello_1.0.0.tar.gz"
note "CRAN publish: ${CODE}"
is_2xx "$CODE" || fail_g "CRAN publish answered ${CODE}: ${BODY:0:200}"
expect_one "CRAN" "${P}-cran" "$before"
req GET "/api/v1/packages?repository_key=${P}-cran"
note "packages in ${P}-cran: $(jqr -c '[.items[]? | .name]' <<<"$BODY")"
[ "$(jqr '[.items[]? | select(.name == "wuhello")] | length' <<<"$BODY")" = "1" ] || fail_g "CRAN package not listed in /api/v1/packages"
finish_case "CRAN publish produced no (or more than one) artifact_uploaded event"

begin_test "#3939: a Hex publish emits one artifact_uploaded"
reset_case
h="${W}/hex"; mkdir -p "${h}/pkg/lib"
printf 'defmodule WuHello do\n  def hi, do: 1\nend\n' > "${h}/pkg/lib/wu_hello.ex"
tar czf "${h}/contents.tar.gz" -C "${h}/pkg" lib
printf '{<<"name">>, <<"wu_hello">>}.\n{<<"version">>, <<"1.0.0">>}.\n{<<"description">>, <<"DTF">>}.\n{<<"app">>, <<"wu_hello">>}.\n{<<"build_tools">>, [<<"mix">>]}.\n{<<"requirements">>, []}.\n' > "${h}/metadata.config"
echo "3" > "${h}/VERSION"
cat "${h}/VERSION" "${h}/metadata.config" "${h}/contents.tar.gz" | sha256sum | awk '{printf "%s", toupper($1)}' > "${h}/CHECKSUM"
tar cf "${h}/wu_hello-1.0.0.tar" -C "$h" VERSION CHECKSUM metadata.config contents.tar.gz
before="$(arts "${P}-hex")"
raw -X POST -H 'Content-Type: application/octet-stream' --data-binary "@${h}/wu_hello-1.0.0.tar" "${BASE}/hex/${P}-hex/publish"
note "Hex publish: ${CODE}"
is_2xx "$CODE" || fail_g "Hex publish answered ${CODE}: ${BODY:0:200}"
expect_one "Hex" "${P}-hex" "$before"
finish_case "Hex publish produced no (or more than one) artifact_uploaded event"

begin_test "#3939: an Ansible collection publish emits one artifact_uploaded"
reset_case
a="${W}/ans/wuns/wucoll"; mkdir -p "${a}/plugins/modules"
printf 'namespace: wuns\nname: wucoll\nversion: "1.0.0"\nreadme: README.md\nauthors:\n  - DTF\n' > "${a}/galaxy.yml"
printf '{"collection_info":{"namespace":"wuns","name":"wucoll","version":"1.0.0","description":"DTF","license":["MIT"],"authors":["DTF"],"dependencies":{}}}\n' > "${a}/MANIFEST.json"
echo "# wucoll" > "${a}/README.md"; printf '#!/usr/bin/python\n' > "${a}/plugins/modules/hello.py"
tar czf "${W}/wuns-wucoll-1.0.0.tar.gz" -C "${W}/ans" wuns/wucoll
before="$(arts "${P}-ansible")"
raw -X POST -F "file=@${W}/wuns-wucoll-1.0.0.tar.gz" \
  -F 'collection={"namespace":"wuns","name":"wucoll","version":"1.0.0"};type=application/json' \
  "${BASE}/ansible/${P}-ansible/api/v3/artifacts/collections/"
note "Ansible publish: ${CODE}"
is_2xx "$CODE" || fail_g "Ansible publish answered ${CODE}: ${BODY:0:200}"
expect_one "Ansible" "${P}-ansible" "$before"
finish_case "Ansible publish produced no (or more than one) artifact_uploaded event"

begin_test "#3939: a Puppet module publish emits one artifact_uploaded"
reset_case
m="${W}/pup/wuauth-wumod-1.0.0"; mkdir -p "${m}/manifests"
printf '{"name":"wuauth-wumod","version":"1.0.0","author":"wuauth","summary":"DTF","license":"MIT","source":"https://example.test/wumod","dependencies":[]}\n' > "${m}/metadata.json"
printf 'class wumod {}\n' > "${m}/manifests/init.pp"
tar czf "${W}/wuauth-wumod-1.0.0.tar.gz" -C "${W}/pup" wuauth-wumod-1.0.0
before="$(arts "${P}-puppet")"
raw -X POST -F "file=@${W}/wuauth-wumod-1.0.0.tar.gz" -F 'module={"owner":"wuauth","name":"wumod","version":"1.0.0"}' \
  "${BASE}/puppet/${P}-puppet/v3/releases"
note "Puppet publish: ${CODE}"
is_2xx "$CODE" || fail_g "Puppet publish answered ${CODE}: ${BODY:0:200}"
expect_one "Puppet" "${P}-puppet" "$before"
finish_case "Puppet publish produced no (or more than one) artifact_uploaded event"

begin_test "#3939: a RubyGems push emits one artifact_uploaded and lists the gem"
reset_case
gd="${W}/gem"; mkdir -p "${gd}/lib"
printf 'module WuGem; end\n' > "${gd}/lib/wugem.rb"
tar czf "${gd}/data.tar.gz" -C "$gd" lib
cat > "${gd}/metadata" <<GEMSPEC
--- !ruby/object:Gem::Specification
name: wugem
version: !ruby/object:Gem::Version
  version: '1.0.0'
platform: ruby
authors:
- DTF
bindir: bin
cert_chain: []
date: '2026-01-01'
dependencies: []
description: DTF
email: d@example.test
executables: []
extensions: []
extra_rdoc_files: []
files:
- lib/wugem.rb
homepage: https://example.test
licenses:
- MIT
metadata: {}
rdoc_options: []
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubygems_version: 3.0.0
specification_version: 4
summary: DTF
test_files: []
GEMSPEC
gzip -c "${gd}/metadata" > "${gd}/metadata.gz"
tar cf "${W}/wugem-1.0.0.gem" -C "$gd" metadata.gz data.tar.gz
before="$(arts "${P}-rubygems")"
raw -X POST -H 'Content-Type: application/octet-stream' --data-binary "@${W}/wugem-1.0.0.gem" "${BASE}/gems/${P}-rubygems/api/v1/gems"
note "gem push: ${CODE}"
is_2xx "$CODE" || fail_g "gem push answered ${CODE}: ${BODY:0:200}"
expect_one "RubyGems" "${P}-rubygems" "$before"
req GET "/api/v1/packages?repository_key=${P}-rubygems"
note "packages in ${P}-rubygems: $(jqr -c '[.items[]? | .name]' <<<"$BODY")"
[ "$(jqr '[.items[]? | select(.name == "wugem")] | length' <<<"$BODY")" = "1" ] || fail_g "gem not listed in /api/v1/packages"
finish_case "gem push produced no (or more than one) artifact_uploaded event"

begin_test "#3939: a Git LFS object upload emits one artifact_uploaded"
reset_case
head -c 4096 /dev/urandom > "${W}/lfs.bin"
OID="$(sha256sum "${W}/lfs.bin" | cut -d' ' -f1)"
raw -X POST -H 'Content-Type: application/vnd.git-lfs+json' -H 'Accept: application/vnd.git-lfs+json' \
  -d "{\"operation\":\"upload\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OID}\",\"size\":4096}]}" "${BASE}/lfs/${P}-gitlfs/objects/batch"
note "LFS batch: ${CODE}"
before="$(arts "${P}-gitlfs")"
raw -X PUT -H 'Content-Type: application/octet-stream' --data-binary "@${W}/lfs.bin" "${BASE}/lfs/${P}-gitlfs/objects/${OID}"
note "LFS PUT: ${CODE}"
is_2xx "$CODE" || fail_g "LFS PUT answered ${CODE}: ${BODY:0:200}"
expect_one "Git LFS" "${P}-gitlfs" "$before"
finish_case "Git LFS upload produced no (or more than one) artifact_uploaded event"

begin_test "#3939: a chunked-upload completion emits one artifact_uploaded"
reset_case
printf 'chunked %s\n' "$SFX" > "${W}/c.txt"
CS="$(sha256sum "${W}/c.txt" | cut -d' ' -f1)"; CN="$(wc -c <"${W}/c.txt" | tr -d ' ')"
before="$(arts "${P}-generic")"
req POST /api/v1/uploads "$(jq -nc --arg r "${P}-generic" --arg s "$CS" --argjson n "$CN" '{repository_key:$r,artifact_path:"c/c.txt",total_size:$n,checksum_sha256:$s}')"
SID="$(jqr '.session_id // empty' <<<"$BODY")"
raw -X PATCH -H 'Content-Type: application/octet-stream' -H "Content-Range: bytes 0-$((CN-1))/${CN}" --data-binary "@${W}/c.txt" "${BASE}/api/v1/uploads/${SID}"
req PUT "/api/v1/uploads/${SID}/complete"
note "chunked session ${SID:-none}; complete: ${CODE}"
is_2xx "$CODE" || fail_g "chunked completion answered ${CODE}: ${BODY:0:200}"
expect_one "chunked upload" "${P}-generic" "$before"
finish_case "chunked-upload completion produced no (or more than one) artifact_uploaded event"

begin_test "#3939: single, bulk and approved promotions each emit one artifact_uploaded that belongs to the target repository"
reset_case
for n in 1 2 3; do
  printf 'staged %s %s\n' "$n" "$SFX" > "${W}/s${n}.txt"
  raw -X PUT --data-binary "@${W}/s${n}.txt" "${BASE}/api/v1/repositories/${P}-stg/artifacts/s/s${n}.txt"
  is_2xx "$CODE" || fail_g "staging upload ${n} answered ${CODE}"
done
S1="$(psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${P}-stg' AND a.path = 's/s1.txt' AND NOT a.is_deleted")"
S2="$(psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${P}-stg' AND a.path = 's/s2.txt' AND NOT a.is_deleted")"
S3="$(psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${P}-stg' AND a.path = 's/s3.txt' AND NOT a.is_deleted")"
for leg in single bulk approved; do
  before="$(arts "${P}-rel")"
  case "$leg" in
    single) req POST "/api/v1/promotion/repositories/${P}-stg/artifacts/${S1}/promote" "{\"target_repository\":\"${P}-rel\"}";;
    bulk)   req POST "/api/v1/promotion/repositories/${P}-stg/promote" "{\"target_repository\":\"${P}-rel\",\"artifact_ids\":[\"${S2}\"]}";;
    approved)
      req POST /api/v1/approval/request "{\"source_repository\":\"${P}-stg\",\"target_repository\":\"${P}-rel\",\"artifact_id\":\"${S3}\"}"
      AP="$(jqr '.id // empty' <<<"$BODY")"
      note "approval request: ${CODE} id=${AP:-none}"
      : >"${W}/body"
      CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 60 -X POST -H "Authorization: Bearer ${REV_TOK}" \
        -H 'Content-Type: application/json' -d '{"notes":"dtf"}' "${BASE}/api/v1/approval/${AP}/approve")"
      BODY="$(cat "${W}/body")";;
  esac
  note "${leg} promotion: ${CODE} ${BODY:0:160}"
  is_2xx "$CODE" || fail_g "${leg} promotion answered ${CODE}"
  if [ "$leg" = "approved" ]; then expect_one "${leg} promotion" "${P}-rel" "$before" "$REV_ID"
  else expect_one "${leg} promotion" "${P}-rel" "$before"; fi
  if [ -n "$NEW_ID" ]; then
    r="$(rows "$NEW_ID" "$WH_REL")"
    note "${leg} promotion: deliveries on the release-repo webhook: ${r}"
    [ "$r" = "1" ] || fail_g "${leg} promotion: the target repository's webhook got ${r} deliveries, expected 1"
  fi
done
finish_case "a promotion produced no (or more than one) artifact_uploaded event for the target repository"

# =============================================================================
begin_test "CONTROL: the receiver gets each enqueued delivery, one POST per artifact, entity_id = the artifact id"
reset_case
# The retry scheduler posts enqueued rows on a 30-second tick.
want=0
for id in $SEEN_IDS; do [ "$(rows "$id" "$WH_ALL")" = "0" ] || want=$((want+1)); done
pending=""
for _i in $(seq 1 30); do
  pending="$(psql_q "SELECT count(*) FROM webhook_deliveries WHERE webhook_id = '${WH_ALL}' AND NOT success")"
  [ "$pending" = "0" ] && break
  sleep 3
done
got="$(curl -s --max-time 10 "${MOCK}/__log" | jq --arg p "/hook/all-${SFX}" '[.[] | select(.path == $p)] | length' 2>/dev/null || echo 0)"
curl -s --max-time 10 "${MOCK}/__log" | jq -r --arg p "/hook/all-${SFX}" '.[] | select(.path == $p) | .body_b64 | @base64d | fromjson | .entity_id' 2>/dev/null | sort > "${W}/delivered"
note "enqueued for ${want} of the tier's artifacts; rows still pending: ${pending}; receiver got ${got} POST(s) in all (staging uploads included)"
[ "$pending" = "0" ] || fail_g "${pending} enqueued deliveries were never delivered"
# Every artifact that got an enqueued row is delivered exactly once (on an
# image that enqueues nothing for a path, there is nothing to deliver).
for id in $SEEN_IDS; do
  [ "$(rows "$id" "$WH_ALL")" = "0" ] && continue
  c="$(grep -c "^${id}$" "${W}/delivered")"
  [ "$c" = "1" ] || fail_g "artifact ${id}: ${c} deliveries at the receiver, expected 1"
done
grep -q "^${CTL_ID}$" "${W}/delivered" || fail_g "the generic upload's event never reached the receiver"
finish_case "enqueued deliveries were not delivered exactly once"

end_suite
