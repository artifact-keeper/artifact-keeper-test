#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/upstream-probe-egress/oracle.sh
#   The test-upstream probe (#5079) and the curation sync (#5089) follow the
#   Remote's upstream URL validation and egress-proxy route, and the probe's
#   502 text carries no request URL. See the manifest for the gates.
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

PROXY_CTR="ak-dtf${DTF_SLOT}-egress-proxy"
LOOP_CTR="ak-dtf${DTF_SLOT}-egress-loopback"
PROXY_URL="http://172.16.${DTF_SLOT}.93:3128"
LOOP_URL="http://127.0.0.1:18099"

# api <METHOD> <PATH> [JSON]: admin bearer call, sets CODE and BODY.
api(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 90 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2" 2>/dev/null)"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
# rec_log <container> <port>: the recorder's request log (JSON list).
rec_log(){
  docker exec "$1" python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:$2/__log', timeout=5).read().decode())" 2>/dev/null || echo '[]'
}
# rec_hits <container> <port> <substring>: requests whose target contains it.
rec_hits(){ rec_log "$1" "$2" | jq --arg s "$3" '[.[] | select(.target | contains($s))] | length' 2>/dev/null || echo "?"; }
rec_show(){ rec_log "$1" "$2" | jq -c --arg s "$3" '[.[] | select(.target | contains($s)) | (.method + " " + .target)]' 2>/dev/null; }
mk_remote(){ # <key> <format> <upstream>
  api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg u "$3" '{key:$k,name:$k,format:$f,repo_type:"remote",upstream_url:$u}')"
  is_2xx "$CODE"
}
# Stand-in for an upstream URL that was stored before the deployment's
# validation refused it (an older allowlist, a DNS change): the create/update
# API refuses the loopback URL, so it is written to the row directly.
store_upstream(){ psqlq "UPDATE repositories SET upstream_url='$2' WHERE key='$1' RETURNING key" >/dev/null; }
set_explicit_proxy(){
  api PUT "/api/v1/repositories/$1/egress-proxy" "$(jq -nc --arg p "$PROXY_URL" '{mode:"explicit",proxy_url:$p}')"
  is_2xx "$CODE"
}

begin_suite "upstream-probe-egress"

# =============================================================================
begin_test "setup: admin session; the recorders answer inside their own namespaces"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "${ADMIN_USER:-admin}" --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(rec_log "$PROXY_CTR" 3128 | jqr 'type')" = "array" ] || { infra_fail "the egress-proxy recorder does not answer"; end_suite; }
[ "$(rec_log "$LOOP_CTR" 18099 | jqr 'type')" = "array" ] || { infra_fail "the loopback recorder does not answer"; end_suite; }
pass

# =============================================================================
begin_test "CONTROL: a Remote on an admitted upstream probes 200; a loopback upstream URL is refused when saved"
reset_case
R_OK="upe-ok-${SFX}"
if mk_remote "$R_OK" generic "${PROXY_URL}/ok-${SFX}/"; then
  api POST "/api/v1/repositories/${R_OK}/test-upstream"
  note "probe of ${PROXY_URL}/ok-${SFX}/: ${CODE} ${BODY:0:200}"
  is_2xx "$CODE" || fail_g "the probe of an admitted upstream answered ${CODE}"
  [ "$(rec_hits "$PROXY_CTR" 3128 "/ok-${SFX}/")" -ge 1 ] 2>/dev/null || fail_g "the admitted upstream received no probe request"
else
  fail_g "creating ${R_OK} answered ${CODE}: ${BODY:0:200}"
fi
api POST /api/v1/repositories "$(jq -nc --arg k "upe-lo-${SFX}" --arg u "${LOOP_URL}/x/" '{key:$k,name:$k,format:"generic",repo_type:"remote",upstream_url:$u}')"
note "create with upstream ${LOOP_URL}/x/: ${CODE} ${BODY:0:160}"
case "$CODE" in 400|422) ;; *) fail_g "saving a loopback upstream URL answered ${CODE}, expected 400/422";; esac
finish_case "the probe or the save-time upstream URL validation is broken"

# =============================================================================
begin_test "FIX #5079: the probe refuses a stored upstream URL the validation refuses, without a request"
reset_case
R_PL="upe-plo-${SFX}"
if mk_remote "$R_PL" generic "${PROXY_URL}/plo-${SFX}/" && store_upstream "$R_PL" "${LOOP_URL}/probe-${SFX}/"; then
  api POST "/api/v1/repositories/${R_PL}/test-upstream"
  sleep 1
  hits="$(rec_hits "$LOOP_CTR" 18099 "/probe-${SFX}/")"
  note "probe of stored ${LOOP_URL}/probe-${SFX}/: ${CODE} ${BODY:0:200}; loopback requests ${hits} $(rec_show "$LOOP_CTR" 18099 "/probe-${SFX}/")"
  [ "$CODE" = "400" ] || fail_g "the probe answered ${CODE}, expected 400 (the upstream URL is not allowed)"
  [ "$hits" = "0" ] || fail_g "the probe dialled the loopback upstream (${hits} request(s)); pre-#5080 it skipped the upstream URL validation"
else
  fail_g "could not create ${R_PL} or store its upstream URL (${CODE})"
fi
finish_case "the test-upstream probe does not apply the upstream URL validation"

# =============================================================================
begin_test "FIX #5079: the probe goes out on the Remote's explicit egress proxy"
reset_case
R_PX="upe-px-${SFX}"
PX_UP="http://probe-${SFX}.upstream.dtf.invalid/px-${SFX}/"
if mk_remote "$R_PX" generic "$PX_UP" && set_explicit_proxy "$R_PX"; then
  api POST "/api/v1/repositories/${R_PX}/test-upstream"
  sleep 1
  hits="$(rec_hits "$PROXY_CTR" 3128 "$PX_UP")"
  note "probe of ${PX_UP} via ${PROXY_URL}: ${CODE} ${BODY:0:200}; proxy absolute-form requests ${hits} $(rec_show "$PROXY_CTR" 3128 "/px-${SFX}/")"
  [ "$hits" -ge 1 ] 2>/dev/null || fail_g "the egress proxy saw no absolute-form request for ${PX_UP}; pre-#5080 the probe ignored the egress setting and went direct"
  is_2xx "$CODE" || fail_g "the probe answered ${CODE}, expected 2xx (the proxy answers 200)"
else
  fail_g "could not create ${R_PX} or set its explicit egress proxy (${CODE}: ${BODY:0:200})"
fi
finish_case "the test-upstream probe does not use the repository's egress route"

# =============================================================================
begin_test "FIX #5079: the probe's 502 message does not carry the request URL or its credentials"
reset_case
R_ER="upe-er-${SFX}"
ER_SECRET="s$(openssl rand -hex 10)"
ER_HOST="unreach-${SFX}.upstream.dtf.invalid"
ER_UP="http://dtfprobe:${ER_SECRET}@${ER_HOST}/er-${SFX}/"
if mk_remote "$R_ER" generic "$ER_UP"; then
  api POST "/api/v1/repositories/${R_ER}/test-upstream"
  note "probe of an unresolvable upstream with userinfo: ${CODE}"
  # The body is not echoed into the report: on a red image it holds the secret.
  safe="$(printf '%s' "$BODY" | sed "s/${ER_SECRET}/<secret>/g")"
  note "body: ${safe:0:240}"
  [ "$CODE" = "502" ] || fail_g "the probe answered ${CODE}, expected 502"
  case "$BODY" in *"$ER_SECRET"*) fail_g "the 502 message carries the upstream password";; esac
  case "$BODY" in *"dtfprobe:"*) fail_g "the 502 message carries the upstream userinfo";; esac
  case "$BODY" in *"/er-${SFX}/"*|*"$ER_HOST"*) fail_g "the 502 message carries the request URL";; esac
else
  fail_g "creating ${R_ER} answered ${CODE}: ${BODY:0:200}"
fi
finish_case "the test-upstream probe's error text includes the request URL"

# =============================================================================
# Curation: an rpm staging repository curating an rpm Remote. The wiring is
# DB-side, as the other curation tiers seed it.
mk_curation(){ # <staging-key> <remote-key>
  api POST /api/v1/repositories "$(jq -nc --arg k "$1" '{key:$k,name:$k,format:"rpm",repo_type:"staging"}')"
  is_2xx "$CODE" || return 1
  psqlq "UPDATE repositories SET curation_enabled=true, curation_allow_unverified=true,
           curation_source_repo_id=(SELECT id FROM repositories WHERE key='$2') WHERE key='$1' RETURNING key" | grep -q .
}

begin_test "FIX #5089: a curation sync fetches the source Remote's index through that Remote's explicit egress proxy"
reset_case
R_CU="upe-cu-${SFX}"; R_CS="upe-cs-${SFX}"
CU_UP="http://curation-${SFX}.upstream.dtf.invalid/rpm-${SFX}"
if mk_remote "$R_CU" rpm "$CU_UP" && set_explicit_proxy "$R_CU" && mk_curation "$R_CS" "$R_CU"; then
  api POST "/api/v1/curation/repos/${R_CS}/sync"
  sleep 1
  hits="$(rec_hits "$PROXY_CTR" 3128 "${CU_UP}/repodata/repomd.xml")"
  note "sync ${R_CS}: ${CODE} ${BODY:0:200}; proxy requests for ${CU_UP}/repodata/repomd.xml: ${hits} $(rec_show "$PROXY_CTR" 3128 "/rpm-${SFX}/")"
  [ "$hits" -ge 1 ] 2>/dev/null || fail_g "the egress proxy saw no repomd.xml request; pre-#5090 the sweep's shared client ignored the Remote's egress setting"
else
  fail_g "could not set up the curation pair ${R_CS} <- ${R_CU} (${CODE}: ${BODY:0:200})"
fi
finish_case "curation sync does not use the source Remote's egress route"

# =============================================================================
begin_test "FIX #5089: a curation sync skips a stored source URL the validation refuses: no request, not stamped"
reset_case
R_CL="upe-cl-${SFX}"; R_CLS="upe-cls-${SFX}"
if mk_remote "$R_CL" rpm "${PROXY_URL}/cl-${SFX}" && store_upstream "$R_CL" "${LOOP_URL}/curation-${SFX}" && mk_curation "$R_CLS" "$R_CL"; then
  api POST "/api/v1/curation/repos/${R_CLS}/sync"
  sleep 1
  hits="$(rec_hits "$LOOP_CTR" 18099 "/curation-${SFX}/")"
  stamped="$(psqlq "SELECT curation_last_synced_at IS NOT NULL FROM repositories WHERE key='${R_CLS}'")"
  note "sync ${R_CLS}: ${CODE} ${BODY:0:200}; loopback requests ${hits} $(rec_show "$LOOP_CTR" 18099 "/curation-${SFX}/"); stamped=${stamped}"
  [ "$hits" = "0" ] || fail_g "the sync dialled the loopback source URL (${hits} request(s)); pre-#5090 the stored URL was not validated"
  [ "$stamped" = "f" ] || fail_g "the staging repository was stamped as synced (${stamped})"
else
  fail_g "could not set up the curation pair ${R_CLS} <- ${R_CL} (${CODE}: ${BODY:0:200})"
fi
finish_case "curation sync does not apply the upstream URL validation to the source URL"

end_suite
