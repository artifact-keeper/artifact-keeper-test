#!/usr/bin/env bash
# =============================================================================
# tiers/promotion-gate-results-and-origin/oracle.sh
#   #4556 a promotion reports every gate rule it applied, passed or not, as
#         gate_results[{rule,passed,reason}]; a predicate that held is a
#         passed `policy-predicate` entry carrying its token
#   #4557 bulk items carry the same per-rule gate_results; promotion copies
#         the source's artifact_metadata (conda depends/license/md5 survive);
#         a staging upload is recorded with origin kind `hosted`
#   #4152 the promoted copy carries the SOURCE origin verbatim
#   #4558 a second scan policy with the same name (any case) on the same
#         repository is a 409
#   #3977 bulk promotion runs the quality gate and the policy per item, a
#         `warn` gate's violations ride on the successful response, and the
#         bulk promotion_history.policy_result records the real evaluation
#   #4147 / #4160 promotion evaluates the scan-policy predicates; the conda
#         channel allowlist fails closed on an unknown channel
#   #1758 artifact responses carry last_promotion {target_repo_key,
#         promoted_at, status}, with the target hidden from a caller who
#         cannot read it
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

DBC="$DB_CONTAINER"
setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# call METHOD PATH BODY OUTFILE [TOKEN] -> http code
call(){
  local method="$1" path="$2" body="$3" out="$4" tok="${5:-$ADMIN_TOKEN}" code
  rm -f "$out"
  if [ -n "$body" ]; then
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null)"
  else
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer ${tok}" "${BASE_URL}${path}" 2>/dev/null)"
  fi
  [ -f "$out" ] || : > "$out"
  echo "${code:-000}"
}

# Every resource name carries the slot and the run id.
P="pg${DTF_SLOT}-$(echo "$RUN_ID" | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-' | tail -c 12)"
S_N="${P}-stg-none"      # generic staging, no gate, no policy
S_P="${P}-stg-pol"       # policy: origin.allowed_kinds=[hosted]  (passes)
S_D="${P}-stg-deny"      # policy: origin.allowed_kinds=[proxy]   (refuses)
S_W="${P}-stg-warn"      # quality gate action=warn
S_B="${P}-stg-block"     # quality gate action=block
S_DUP="${P}-stg-dup"     # duplicate-name policy target
S_DUP2="${P}-stg-dup2"   # same name on another repository (control)
R="${P}-rel"             # generic release, public
R_PRIV="${P}-rel-priv"   # generic release, private
C_L="${P}-cstg-lic"      # conda staging, conda.denied_licenses (passes)
C_A="${P}-cstg-allow"    # conda staging, conda.allowed_channels=[elsewhere]
C_U="${P}-cstg-unk"      # conda staging, allowlist names itself, channel stripped
RC="${P}-crel"           # conda release
U_RO="${P}-reader"
U_RO_PASS="Rd-${RUN_ID}-Passw0rd!x"

repo_id(){ psql_q "SELECT id FROM repositories WHERE key='$1'" | tr -d '[:space:]'; }
mkrepo(){ # key format type public -> id
  call POST /api/v1/repositories \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"$3\",\"is_public\":$4}" "$W/mk.json" >/dev/null
  repo_id "$1"
}
upload(){ # repo path file -> artifact id
  curl -s --max-time 60 -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" | jqr '.id // empty'
}
conda_put(){ # repo file -> http code
  curl -s --max-time 60 -o "$W/cput.out" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" --data-binary "@$W/$2" \
    "${BASE_URL}/conda/$1/noarch/$2" 2>/dev/null || echo 000
}
art_in(){ psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.path='$2' AND NOT a.is_deleted" | head -1 | tr -d '[:space:]'; }
policy(){ # name repo_id predicates_json -> http code
  call POST /api/v1/security/policies \
    "{\"name\":\"$1\",\"repository_id\":\"$2\",\"max_severity\":\"critical\",\"block_unscanned\":false,\"block_on_fail\":false,\"predicates\":$3}" "$W/pol.json"
}
gate(){ # name repo_id action -> http code
  call POST /api/v1/quality/gates \
    "{\"name\":\"$1\",\"repository_id\":\"$2\",\"min_health_score\":50,\"enforce_on_promotion\":true,\"action\":\"$3\"}" "$W/gate.json"
}
promote(){ # src artifact_id target out -> http code
  call POST "/api/v1/promotion/repositories/$1/artifacts/$2/promote" "{\"target_repository\":\"$3\"}" "$4"
}
bulk(){ # src target out id...
  local src="$1" tgt="$2" out="$3" ids
  shift 3
  ids="$(printf '"%s",' "$@")"
  call POST "/api/v1/promotion/repositories/${src}/promote" \
    "{\"target_repository\":\"${tgt}\",\"artifact_ids\":[${ids%,}]}" "$out"
}
mkconda(){ # name -> file name (noarch tar.bz2 with depends + license)
  local d="$W/cb-$1" fn="$1-1.0-0.tar.bz2"
  mkdir -p "$d/info"
  printf '{"name":"%s","version":"1.0","build":"0","build_number":0,"noarch":"generic","platform":null,"subdir":"noarch","depends":["python >=3.8","zlib"],"license":"MIT"}\n' "$1" > "$d/info/index.json"
  tar -cjf "$W/$fn" -C "$d" info
  echo "$fn"
}

begin_suite "promotion-gate-results-and-origin"
auth_admin

# =============================================================================
begin_test "setup: repositories, policies, gates, uploads"
reset_case
# shellcheck disable=SC2034  # checked through ${!v} below
ID_N="$(mkrepo "$S_N" generic staging true)"
ID_P="$(mkrepo "$S_P" generic staging true)"
ID_D="$(mkrepo "$S_D" generic staging true)"
ID_W="$(mkrepo "$S_W" generic staging true)"
ID_B="$(mkrepo "$S_B" generic staging true)"
ID_DUP="$(mkrepo "$S_DUP" generic staging true)"
ID_DUP2="$(mkrepo "$S_DUP2" generic staging true)"
ID_R="$(mkrepo "$R" generic local true)"
# shellcheck disable=SC2034  # checked through ${!v} below
ID_RP="$(mkrepo "$R_PRIV" generic local false)"
ID_CL="$(mkrepo "$C_L" conda staging true)"
ID_CA="$(mkrepo "$C_A" conda staging true)"
ID_CU="$(mkrepo "$C_U" conda staging true)"
ID_RC="$(mkrepo "$RC" conda local true)"
for v in ID_N ID_P ID_D ID_W ID_B ID_DUP ID_DUP2 ID_R ID_RP ID_CL ID_CA ID_CU ID_RC; do
  [ -n "${!v}" ] || fail_g "repository for ${v} was not created ($(head -c 200 "$W/mk.json"))"
done

for f in n1 n2 p1 p2 p3 d1 d2 w1 w2 b1 b2; do printf '%s-%s\n' "$P" "$f" > "$W/$f.txt"; done
A_N1="$(upload "$S_N" "n/n1.txt" "$W/n1.txt")"
A_N2="$(upload "$S_N" "n/n2.txt" "$W/n2.txt")"
A_P1="$(upload "$S_P" "p/p1.txt" "$W/p1.txt")"
A_P2="$(upload "$S_P" "p/p2.txt" "$W/p2.txt")"
A_P3="$(upload "$S_P" "p/p3.txt" "$W/p3.txt")"
A_D1="$(upload "$S_D" "d/d1.txt" "$W/d1.txt")"
A_D2="$(upload "$S_D" "d/d2.txt" "$W/d2.txt")"
A_W1="$(upload "$S_W" "w/w1.txt" "$W/w1.txt")"
A_W2="$(upload "$S_W" "w/w2.txt" "$W/w2.txt")"
A_B1="$(upload "$S_B" "b/b1.txt" "$W/b1.txt")"
A_B2="$(upload "$S_B" "b/b2.txt" "$W/b2.txt")"
for v in A_N1 A_N2 A_P1 A_P2 A_P3 A_D1 A_D2 A_W1 A_W2 A_B1 A_B2; do
  [ -n "${!v}" ] || fail_g "upload for ${v} returned no artifact id"
done

PKG_L="$(mkconda "${P}-lic")"; PKG_A="$(mkconda "${P}-allow")"; PKG_U="$(mkconda "${P}-unk")"
for pair in "$C_L:$PKG_L" "$C_A:$PKG_A" "$C_U:$PKG_U"; do
  st="$(conda_put "${pair%%:*}" "${pair#*:}")"
  [ "$st" = "201" ] || [ "$st" = "200" ] || fail_g "conda upload ${pair} -> HTTP ${st} $(head -c 200 "$W/cput.out")"
done
A_CL="$(art_in "$C_L" "noarch/${PKG_L}")"; A_CA="$(art_in "$C_A" "noarch/${PKG_A}")"; A_CU="$(art_in "$C_U" "noarch/${PKG_U}")"
for v in A_CL A_CA A_CU; do [ -n "${!v}" ] || fail_g "conda artifact ${v} not found in the DB"; done

# Policies (block_unscanned=false: no scanner runs here, the predicates are
# the only gate the policy applies). On 1.10.0 the predicates field is
# ignored and the policies are inert.
st="$(policy "${P}-pol-hosted" "$ID_P" '{"origin":{"allowed_kinds":["hosted"]}}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "policy on ${S_P} -> HTTP ${st} $(head -c 200 "$W/pol.json")"
st="$(policy "${P}-pol-proxy" "$ID_D" '{"origin":{"allowed_kinds":["proxy"]}}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "policy on ${S_D} -> HTTP ${st} $(head -c 200 "$W/pol.json")"
st="$(policy "${P}-pol-lic" "$ID_CL" '{"conda":{"denied_licenses":["GPL-3.0"]}}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "policy on ${C_L} -> HTTP ${st} $(head -c 200 "$W/pol.json")"
st="$(policy "${P}-pol-allow" "$ID_CA" '{"conda":{"allowed_channels":["conda-forge"]}}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "policy on ${C_A} -> HTTP ${st} $(head -c 200 "$W/pol.json")"
st="$(policy "${P}-pol-unk" "$ID_CU" "{\"conda\":{\"allowed_channels\":[\"${C_U}\"]}}")"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "policy on ${C_U} -> HTTP ${st} $(head -c 200 "$W/pol.json")"
# The C_U package's identity loses its channel qualifier: the state of a row
# ingested without one. #4058 never substitutes the repository key, so the
# allowlist (which names this very repository) must fail closed.
psql_q "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{identity,purl}', to_jsonb(regexp_replace(metadata->'identity'->>'purl', '&?channel=[^&]*', '', 'g'))) WHERE artifact_id='${A_CU}' AND metadata ? 'identity'" >/dev/null

# Quality gates. A generic file's computed health score is 0 (grade F), so a
# min_health_score of 50 fails it; wait until the scores exist.
st="$(gate "${P}-gate-warn" "$ID_W" warn)"; [ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "warn gate -> HTTP ${st}"
st="$(gate "${P}-gate-block" "$ID_B" block)"; [ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "block gate -> HTTP ${st}"
hs_ready(){ [ "$(psql_q "SELECT count(*) FROM artifact_health_scores WHERE artifact_id IN ('${A_W1}','${A_W2}','${A_B1}','${A_B2}')" | tr -d '[:space:]')" = "4" ]; }
wait_until "health scores" 30 hs_ready || fail_g "health scores for the gated artifacts never appeared"
finish_case "setup failed"

# =============================================================================
begin_test "CONTROL: an ungated promotion copies the bytes and records history"
reset_case
st="$(promote "$S_N" "$A_N1" "$R" "$W/n1.json")"
[ "$st" = "200" ] || fail_g "promote -> HTTP ${st} $(head -c 300 "$W/n1.json")"
[ "$(jqr '.promoted' < "$W/n1.json")" = "true" ] || fail_g "promoted != true: $(head -c 300 "$W/n1.json")"
src_sha="$(psql_q "SELECT checksum_sha256 FROM artifacts WHERE id='${A_N1}'" | tr -d '[:space:]')"
tgt_sha="$(psql_q "SELECT a.checksum_sha256 FROM artifacts a WHERE a.repository_id='${ID_R}' AND a.path='n/n1.txt'" | tr -d '[:space:]')"
[ -n "$src_sha" ] && [ "$src_sha" = "$tgt_sha" ] || fail_g "target row sha '${tgt_sha}' != source '${src_sha}'"
got="$(curl -s --max-time 30 -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE_URL}/api/v1/repositories/${R}/download/n/n1.txt")"
[ "$got" = "$(cat "$W/n1.txt")" ] || fail_g "target download returned '${got:0:80}'"
[ "$(psql_q "SELECT count(*) FROM promotion_history WHERE artifact_id='${A_N1}' AND status='promoted'" | tr -d '[:space:]')" = "1" ] \
  || fail_g "no promoted promotion_history row"
finish_case "the plain promotion path is broken"

begin_test "CONTROL: a block quality gate refuses a single promotion with 409 naming the gate"
reset_case
st="$(promote "$S_B" "$A_B1" "$R" "$W/b1s.json")"
[ "$st" = "409" ] || fail_g "single promote under a block gate -> HTTP ${st} (want 409)"
grep -q "${P}-gate-block" "$W/b1s.json" || fail_g "409 body does not name the gate: $(head -c 300 "$W/b1s.json")"
[ -z "$(art_in "$R" "b/b1.txt")" ] || fail_g "a refused artifact landed in the target"
finish_case "the single-route gate block regressed"

begin_test "CONTROL: a same-named scan policy on ANOTHER repository is accepted"
reset_case
st="$(policy "${P}-dup" "$ID_DUP" '{}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "first policy -> HTTP ${st}"
st="$(policy "${P}-dup" "$ID_DUP2" '{}')"
[ "$st" = "200" ] || [ "$st" = "201" ] || fail_g "same name on another repo -> HTTP ${st} $(head -c 200 "$W/pol.json")"
finish_case "duplicate-name scoping is wrong"

# =============================================================================
begin_test "FIX #4558: a second policy with the same name (other case) on the same repository -> 409"
reset_case
st="$(policy "$(echo "${P}-dup" | tr '[:lower:]' '[:upper:]')" "$ID_DUP" '{}')"
[ "$st" = "409" ] || fail_g "duplicate name -> HTTP ${st} (want 409) $(head -c 200 "$W/pol.json")"
grep -qi "already exists" "$W/pol.json" || fail_g "409 body does not say the name is taken: $(head -c 200 "$W/pol.json")"
n="$(psql_q "SELECT count(*) FROM scan_policies WHERE repository_id='${ID_DUP}' AND lower(name)=lower('${P}-dup')" | tr -d '[:space:]')"
[ "$n" = "1" ] || fail_g "${n} same-named policies on the repository (want 1)"
# Renaming another policy on that repository into the taken name is refused too.
st="$(policy "${P}-dup-other" "$ID_DUP" '{}')"; other="$(jqr '.id // empty' < "$W/pol.json")"
st="$(call PUT "/api/v1/security/policies/${other}" "{\"name\":\"${P}-DUP\"}" "$W/ren.json")"
[ "$st" = "409" ] || fail_g "rename into a taken name -> HTTP ${st} (want 409) $(head -c 200 "$W/ren.json")"
finish_case "#4558 duplicate scan-policy names are accepted"

# =============================================================================
begin_test "FIX #4556/#4557: a single promotion reports a passed policy-predicate gate_result with its token"
reset_case
st="$(promote "$S_P" "$A_P1" "$R" "$W/p1.json")"
[ "$st" = "200" ] || fail_g "promote -> HTTP ${st}"
[ "$(jqr '.promoted' < "$W/p1.json")" = "true" ] || fail_g "promoted != true: $(head -c 300 "$W/p1.json")"
jq -e --arg p "Policy '${P}-pol-hosted'" '.gate_results | type == "array" and any(.[]; .rule == "policy-predicate" and .passed == true
  and (.reason | contains($p)) and (.reason | contains("[origin.kind]")) and (.reason | contains("hosted")))' \
  "$W/p1.json" >/dev/null 2>&1 || fail_g "no passed [origin.kind] policy-predicate entry: gate_results=$(jq -c '.gate_results' "$W/p1.json" 2>/dev/null)"
jq -e '.gate_results | all(.[]; has("rule") and has("passed") and has("reason"))' "$W/p1.json" >/dev/null 2>&1 \
  || fail_g "gate_results entries are not {rule,passed,reason}"
finish_case "#4556 gate_results are missing from a passing promotion"

begin_test "FIX #4557: bulk items carry per-rule gate_results"
reset_case
st="$(bulk "$S_P" "$R" "$W/pbulk.json" "$A_P2" "$A_P3")"
[ "$st" = "200" ] || fail_g "bulk -> HTTP ${st}"
[ "$(jqr '.promoted' < "$W/pbulk.json")" = "2" ] || fail_g "bulk promoted != 2: $(head -c 300 "$W/pbulk.json")"
jq -e '[.results[] | .gate_results // [] | any(.[]; .rule == "policy-predicate" and .passed == true and (.reason | contains("[origin.kind]")))] | length == 2 and all' \
  "$W/pbulk.json" >/dev/null 2>&1 || fail_g "bulk items lack the passed predicate entry: $(jq -c '[.results[].gate_results]' "$W/pbulk.json" 2>/dev/null)"
finish_case "#4557 bulk gate_results missing"

begin_test "FIX #4557/#4152: staging upload origin is hosted and the promoted copy keeps the source origin"
reset_case
o_src="$(psql_q "SELECT origin->>'kind' || '|' || (origin->>'repository_key') FROM artifacts WHERE id='${A_P1}'" | tr -d '[:space:]')"
o_tgt="$(psql_q "SELECT origin->>'kind' || '|' || (origin->>'repository_key') FROM artifacts WHERE repository_id='${ID_R}' AND path='p/p1.txt'" | tr -d '[:space:]')"
o_bulk="$(psql_q "SELECT origin->>'kind' || '|' || (origin->>'repository_key') FROM artifacts WHERE repository_id='${ID_R}' AND path='p/p2.txt'" | tr -d '[:space:]')"
[ "$o_src" = "hosted|${S_P}" ] || fail_g "staging upload origin '${o_src}' (want hosted|${S_P})"
[ "$o_tgt" = "hosted|${S_P}" ] || fail_g "single-promoted copy origin '${o_tgt}' (want the source origin hosted|${S_P}, not the target ${R})"
[ "$o_bulk" = "hosted|${S_P}" ] || fail_g "bulk-promoted copy origin '${o_bulk}' (want hosted|${S_P})"
finish_case "#4152 / #4557 origin is wrong or absent"

begin_test "FIX #4147: promotion evaluates origin predicates (allowed_kinds=[proxy] refuses a hosted upload)"
reset_case
st="$(promote "$S_D" "$A_D1" "$R" "$W/d1.json")"
[ "$(jqr '.promoted' < "$W/d1.json")" = "false" ] || fail_g "promoted under a refusing predicate (HTTP ${st}): $(head -c 300 "$W/d1.json")"
jq -e '.policy_violations | any(.[]; .rule == "policy-predicate" and (.message | contains("[origin.kind]")))' "$W/d1.json" >/dev/null 2>&1 \
  || fail_g "no [origin.kind] policy-predicate violation: $(jq -c '.policy_violations' "$W/d1.json" 2>/dev/null)"
jq -e '.gate_results | any(.[]; .rule == "policy-predicate" and .passed == false)' "$W/d1.json" >/dev/null 2>&1 \
  || fail_g "no failed policy-predicate gate_result"
[ -z "$(art_in "$R" "d/d1.txt")" ] || fail_g "the refused artifact landed in the target"
finish_case "#4147 origin predicate ignored by promotion"

begin_test "FIX #4147/#4160: the conda channel allowlist refuses a foreign channel and fails closed on an unknown one"
reset_case
st="$(promote "$C_A" "$A_CA" "$RC" "$W/ca.json")"
[ "$(jqr '.promoted' < "$W/ca.json")" = "false" ] || fail_g "foreign-channel package promoted (HTTP ${st}): $(head -c 300 "$W/ca.json")"
jq -e --arg c "$C_A" '.policy_violations | any(.[]; .rule == "policy-predicate" and (.message | contains("[conda.channel]")) and (.message | contains($c)))' \
  "$W/ca.json" >/dev/null 2>&1 || fail_g "no [conda.channel] violation naming '${C_A}': $(jq -c '.policy_violations' "$W/ca.json" 2>/dev/null)"
st="$(promote "$C_U" "$A_CU" "$RC" "$W/cu.json")"
[ "$(jqr '.promoted' < "$W/cu.json")" = "false" ] || fail_g "unknown-channel package promoted (HTTP ${st}): $(head -c 300 "$W/cu.json")"
jq -e '.policy_violations | any(.[]; .rule == "policy-predicate" and (.message | contains("[conda.channel]")) and (.message | contains("unknown")))' \
  "$W/cu.json" >/dev/null 2>&1 || fail_g "no fail-closed [conda.channel] 'unknown' violation: $(jq -c '.policy_violations' "$W/cu.json" 2>/dev/null)"
[ -z "$(art_in "$RC" "noarch/${PKG_A}")" ] && [ -z "$(art_in "$RC" "noarch/${PKG_U}")" ] \
  || fail_g "a refused conda package landed in the release channel"
finish_case "#4147/#4160 conda channel allowlist not enforced on promotion"

begin_test "FIX #4556/#4557: a conda promotion reports the passed [conda.license] predicate and copies the package metadata"
reset_case
st="$(promote "$C_L" "$A_CL" "$RC" "$W/cl.json")"
[ "$(jqr '.promoted' < "$W/cl.json")" = "true" ] || fail_g "conda promote failed (HTTP ${st}): $(head -c 300 "$W/cl.json")"
jq -e '.gate_results | any(.[]; .rule == "policy-predicate" and .passed == true and (.reason | contains("[conda.license]")) and (.reason | contains("mit")))' \
  "$W/cl.json" >/dev/null 2>&1 || fail_g "no passed [conda.license] entry: $(jq -c '.gate_results' "$W/cl.json" 2>/dev/null)"
st="$(call GET "/conda/${RC}/noarch/repodata.json" "" "$W/rc_rd.json")"
jq -e --arg f "$PKG_L" '.packages[$f] | (.depends == ["python >=3.8","zlib"]) and (.license == "MIT") and ((.md5 // "") | length == 32)' \
  "$W/rc_rd.json" >/dev/null 2>&1 || fail_g "release repodata record lost the metadata (HTTP ${st}): $(jq -c --arg f "$PKG_L" '.packages[$f]' "$W/rc_rd.json" 2>/dev/null)"
tgt_meta="$(psql_q "SELECT m.metadata->'depends' FROM artifacts a JOIN artifact_metadata m ON m.artifact_id=a.id WHERE a.repository_id='${ID_RC}' AND a.path='noarch/${PKG_L}'" | tr -d '[:space:]')"
[ "$tgt_meta" = '["python>=3.8","zlib"]' ] || fail_g "promoted copy's artifact_metadata depends '${tgt_meta}'"
finish_case "#4557 conda promotion drops metadata or predicate passes"

# =============================================================================
begin_test "FIX #3977: bulk promotion runs the block quality gate per item"
reset_case
st="$(bulk "$S_B" "$R" "$W/bb.json" "$A_B1" "$A_B2")"
[ "$st" = "200" ] || fail_g "bulk -> HTTP ${st}"
[ "$(jqr '.promoted' < "$W/bb.json")" = "0" ] && [ "$(jqr '.failed' < "$W/bb.json")" = "2" ] \
  || fail_g "gate-blocked bulk: promoted=$(jqr '.promoted' < "$W/bb.json") failed=$(jqr '.failed' < "$W/bb.json") (want 0/2)"
jq -e --arg g "${P}-gate-block" '[.results[] | (.message // "") | contains($g)] | length == 2 and all' "$W/bb.json" >/dev/null 2>&1 \
  || fail_g "bulk item messages do not name the gate: $(jq -c '[.results[].message]' "$W/bb.json" 2>/dev/null)"
jq -e '[.results[] | .gate_results // [] | any(.[]; .rule == "quality-gate" and .passed == false)] | length == 2 and all' "$W/bb.json" >/dev/null 2>&1 \
  || fail_g "bulk items lack a failed quality-gate gate_result"
[ -z "$(art_in "$R" "b/b1.txt")" ] && [ -z "$(art_in "$R" "b/b2.txt")" ] || fail_g "gate-blocked bulk items landed in the target"
finish_case "#3977 bulk promotion bypasses the quality gate"

begin_test "FIX #3977: bulk promotion runs the policy per item (refusing predicate)"
reset_case
st="$(bulk "$S_D" "$R" "$W/db.json" "$A_D2")"
[ "$(jqr '.results[0].promoted' < "$W/db.json")" = "false" ] || fail_g "policy-refused bulk item promoted (HTTP ${st}): $(head -c 300 "$W/db.json")"
jq -e '.results[0].policy_violations | any(.[]; .rule == "policy-predicate")' "$W/db.json" >/dev/null 2>&1 \
  || fail_g "bulk item lacks the policy-predicate violation"
[ -z "$(art_in "$R" "d/d2.txt")" ] || fail_g "policy-refused bulk item landed in the target"
finish_case "#3977 bulk promotion bypasses the policy"

begin_test "FIX #3977: a warn gate's violations ride on successful single and bulk promotions"
reset_case
st="$(promote "$S_W" "$A_W1" "$R" "$W/w1.json")"
[ "$(jqr '.promoted' < "$W/w1.json")" = "true" ] || fail_g "warn-gated single promote not promoted (HTTP ${st})"
jq -e '.policy_violations | any(.[]; .rule == "min_health_score" and (.message | test("below minimum 50")))' "$W/w1.json" >/dev/null 2>&1 \
  || fail_g "single: warn violations missing: $(jq -c '.policy_violations' "$W/w1.json" 2>/dev/null)"
st="$(bulk "$S_W" "$R" "$W/wb.json" "$A_W2")"
[ "$(jqr '.results[0].promoted' < "$W/wb.json")" = "true" ] || fail_g "warn-gated bulk item not promoted (HTTP ${st})"
jq -e '.results[0].policy_violations | any(.[]; .rule == "min_health_score")' "$W/wb.json" >/dev/null 2>&1 \
  || fail_g "bulk: warn violations missing: $(jq -c '.results[0].policy_violations' "$W/wb.json" 2>/dev/null)"
finish_case "#3977 warn violations are dropped"

begin_test "FIX #3977: bulk promotion_history.policy_result records the real evaluation"
reset_case
pr="$(psql_q "SELECT policy_result FROM promotion_history WHERE artifact_id='${A_P2}' AND status='promoted'")"
echo "$pr" | jq -e 'has("action") and has("cve_summary") and .passed == true' >/dev/null 2>&1 \
  || fail_g "bulk policy_result is not an evaluation record: ${pr:0:200}"
finish_case "#3977 bulk policy_result is a placeholder"

# =============================================================================
begin_test "FIX #1758: artifact responses carry last_promotion; refused and never-promoted artifacts carry null"
reset_case
st="$(call GET "/api/v1/artifacts/${A_N1}" "" "$W/lp1.json")"
jq -e --arg r "$R" '.last_promotion | .target_repo_key == $r and .status == "promoted" and ((.promoted_at // "") | length > 0)' "$W/lp1.json" >/dev/null 2>&1 \
  || fail_g "GET artifact last_promotion (HTTP ${st}): $(jq -c '.last_promotion' "$W/lp1.json" 2>/dev/null)"
st="$(call GET "/api/v1/repositories/${S_N}/artifacts" "" "$W/lpl.json")"
jq -e --arg id "$A_N1" --arg r "$R" '(.items // .) | any(.[]; .id == $id and .last_promotion.target_repo_key == $r)' "$W/lpl.json" >/dev/null 2>&1 \
  || fail_g "listing does not carry last_promotion for the promoted artifact (HTTP ${st})"
jq -e --arg id "$A_N2" '(.items // .) | any(.[]; .id == $id and has("last_promotion") and .last_promotion == null)' "$W/lpl.json" >/dev/null 2>&1 \
  || fail_g "never-promoted artifact: last_promotion not present-and-null"
st="$(call GET "/api/v1/artifacts/${A_D1}" "" "$W/lpd.json")"
jq -e 'has("last_promotion") and .last_promotion == null' "$W/lpd.json" >/dev/null 2>&1 \
  || fail_g "refused promotion reported as last_promotion: $(jq -c '.last_promotion' "$W/lpd.json" 2>/dev/null)"
finish_case "#1758 last_promotion missing or wrong"

begin_test "FIX #1758: last_promotion hides a target the caller cannot read"
reset_case
st="$(promote "$S_N" "$A_N2" "$R_PRIV" "$W/n2.json")"
[ "$(jqr '.promoted' < "$W/n2.json")" = "true" ] || fail_g "promote into the private release -> HTTP ${st} $(head -c 200 "$W/n2.json")"
create_test_user "$U_RO" "$U_RO_PASS" "${U_RO}@example.com" >/dev/null 2>&1 || true
RTOK="$(login_as "$U_RO" "$U_RO_PASS" 2>/dev/null || true)"
[ -n "$RTOK" ] || fail_g "could not log in as ${U_RO}"
st="$(call GET "/api/v1/artifacts/${A_N2}" "" "$W/lpu.json" "$RTOK")"
[ "$st" = "200" ] || fail_g "reader GET of the public staging artifact -> HTTP ${st}"
jq -e '.last_promotion != null and .last_promotion.target_repo_key == null and .last_promotion.status == "promoted"' "$W/lpu.json" >/dev/null 2>&1 \
  || fail_g "reader sees last_promotion $(jq -c '.last_promotion' "$W/lpu.json" 2>/dev/null) (want the promotion with target_repo_key null)"
st="$(call GET "/api/v1/artifacts/${A_N2}" "" "$W/lpa.json")"
jq -e --arg r "$R_PRIV" '.last_promotion.target_repo_key == $r' "$W/lpa.json" >/dev/null 2>&1 \
  || fail_g "admin does not see the private target key"
finish_case "#1758 last_promotion target visibility wrong"

end_suite
