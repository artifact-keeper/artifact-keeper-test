#!/usr/bin/env bash
# =============================================================================
# tiers/conda-cep47-coverage/oracle.sh: CEP 47 indexed_timestamp across
# encodings, shards, promotion, remote/virtual pass-through and a real pixi
# exclude-newer solve (artifact-keeper#6530). See the manifest.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${DTF_SLOT}x${RUN_ID##*-}"
L="dtf-c47-l-${SUF}"; ST="dtf-c47-st-${SUF}"; RL="dtf-c47-rl-${SUF}"
P="dtf-c47-p-${SUF}"; R="dtf-c47-r-${SUF}"; V="dtf-c47-v-${SUF}"
UPSTREAM="http://172.16.${DTF_SLOT}.70/gate/"
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-conda"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
PIXI_CTR="ak-dtf${DTF_SLOT}-c47-pixi"
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
REC="${DTF_DIR}/harness/tiers/conda-age-gate/fixtures/repodata_records.py"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
PY_IMAGE="docker.io/library/python:3.14-slim"
PIXI_IMAGE="ghcr.io/prefix-dev/pixi:0.81.0"
WORK="$(mktemp -d -t dtf-c47-XXXXXX)"
cleanup() {
  docker rm -f "$PIXI_CTR" >/dev/null 2>&1 || true
  for k in "$V" "$R" "$P" "$RL" "$ST" "$L"; do api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
get() { curl -s --max-time 120 -o "$WORK/$1" -w '%{http_code}' -H "$(auth_header)" "${BASE_URL}$2" 2>/dev/null || echo 000; }
put() { curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT -H "$(auth_header)" --data-binary "@$3" "${BASE_URL}/conda/$1/noarch/$2" 2>/dev/null || echo 000; }
ts_of() { # TAG ENC FILE -> indexed_timestamp ("absent" / "null")
  docker run --rm -i --security-opt label=disable -v "${REC}:/app/r.py:ro" "$PY_IMAGE" python3 -I /app/r.py "$2" < "$WORK/$1" 2>/dev/null \
    | jq -r --arg f "$3" '.records | if has($f) then (.[$f] // "null" | tostring) else "absent" end' 2>/dev/null || echo absent
}
cep16() { docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" "$PY_IMAGE" python3 -I /app/cep16.py < "$WORK/$1" 2>/dev/null; }
shard_ts() { # REPO NAME FILE -> indexed_timestamp in the record's CEP-16 shard
  local hex
  get "idx.$1" "/conda/$1/noarch/repodata_shards.msgpack.zst" >/dev/null
  hex="$(cep16 "idx.$1" | jq -r --arg n "$2" '.doc.shards[$n].bin // empty' 2>/dev/null)"
  [ -n "$hex" ] || { echo absent; return; }
  get "sh.$1" "/conda/$1/noarch/shards/${hex}.msgpack.zst" >/dev/null
  cep16 "sh.$1" | jq -r --arg f "$3" '[(.doc.packages // {}), (.doc["packages.conda"] // {})] | add | if has($f) then (.[$f].indexed_timestamp // "null" | tostring) else "absent" end' 2>/dev/null || echo absent
}
now_ms() { echo $(( $(date +%s) * 1000 )); }

begin_suite "conda-cep47-coverage (#6530)"

begin_test "setup: hosted, staging, promotion target, pixi channel, remote and virtual; packages uploaded"
auth_admin
setup_err=""
for spec in "$L:local" "$ST:staging" "$RL:local" "$P:local"; do create_repo "${spec%%:*}" conda "${spec#*:}" >/dev/null 2>&1 || setup_err+="create ${spec}; "; done
create_repo "$R" conda remote "$UPSTREAM" >/dev/null 2>&1 || setup_err+="create R; "
create_repo "$V" conda virtual >/dev/null 2>&1 || setup_err+="create V; "
api_post "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\",\"priority\":1}" >/dev/null 2>&1 || setup_err+="member; "
for pkg in "dtfc47 1.0" "dtfc47prom 1.0"; do
  # shellcheck disable=SC2086
  set -- $pkg; bash "$BUILD" "$WORK" "$1" "$2" 0 noarch >/dev/null 2>&1 || setup_err+="build $1 $2; "
done
for img in "$PY_IMAGE" "$PIXI_IMAGE"; do docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null 2>&1 || setup_err+="pull ${img}; "; done
T_UP="$(now_ms)"; sleep 1
st="$(put "$L" dtfc47-1.0-0.tar.bz2 "$WORK/dtfc47-1.0-0.tar.bz2")"; case "$st" in 200|201) ;; *) setup_err+="upload L ${st}; " ;; esac
st="$(put "$ST" dtfc47prom-1.0-0.tar.bz2 "$WORK/dtfc47prom-1.0-0.tar.bz2")"; case "$st" in 200|201) ;; *) setup_err+="upload ST ${st}; " ;; esac
# dtfcool 1.0 and 2.0 are built and uploaded either side of T_MID, so the
# builder timestamp and the indexed_timestamp both order them the same way.
CONDA_PKG_TIMESTAMP="$(now_ms)" bash "$BUILD" "$WORK" dtfcool 1.0 0 noarch >/dev/null 2>&1 || setup_err+="build dtfcool 1.0; "
st="$(put "$P" dtfcool-1.0-0.tar.bz2 "$WORK/dtfcool-1.0-0.tar.bz2")"; case "$st" in 200|201) ;; *) setup_err+="upload P1 ${st}; " ;; esac
sleep 3; T_MID="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 3
CONDA_PKG_TIMESTAMP="$(now_ms)" bash "$BUILD" "$WORK" dtfcool 2.0 0 noarch >/dev/null 2>&1 || setup_err+="build dtfcool 2.0; "
st="$(put "$P" dtfcool-2.0-0.tar.bz2 "$WORK/dtfcool-2.0-0.tar.bz2")"; case "$st" in 200|201) ;; *) setup_err+="upload P2 ${st}; " ;; esac
if [ -n "$setup_err" ]; then infra_fail "setup did not complete" "$setup_err"; end_suite; fi
pass

# --- hosted: every encoding, current_repodata and the shard -----------------
F="dtfc47-1.0-0.tar.bz2"
get h.json "/conda/${L}/noarch/repodata.json" >/dev/null; get h.bz2 "/conda/${L}/noarch/repodata.json.bz2" >/dev/null
get h.zst "/conda/${L}/noarch/repodata.json.zst" >/dev/null; get h.cur "/conda/${L}/noarch/current_repodata.json" >/dev/null
J="$(ts_of h.json json "$F")"; B="$(ts_of h.bz2 bz2 "$F")"; Z="$(ts_of h.zst zst "$F")"; C="$(ts_of h.cur json "$F")"; S="$(shard_ts "$L" dtfc47 "$F")"
begin_test "CONTROL #6530: hosted repodata.json, .bz2, .zst, current_repodata.json and the shard carry one indexed_timestamp, at or after the upload"
if [[ "$J" =~ ^[0-9]+$ ]] && [ "$J" -ge "$T_UP" ] && [ "$B" = "$J" ] && [ "$Z" = "$J" ] && [ "$C" = "$J" ] && [ "$S" = "$J" ]; then pass
else fail "indexed_timestamp json=${J} bz2=${B} zst=${Z} current=${C} shard=${S} (upload at ${T_UP})"; fi

# --- promotion ---------------------------------------------------------------
PF="dtfc47prom-1.0-0.tar.bz2"
SID="$(psql_q "SELECT r.id FROM repositories r WHERE r.key='${ST}'")"
AID="$(psql_q "SELECT a.id FROM artifacts a WHERE a.repository_id='${SID}' AND a.path LIKE '%${PF}' AND NOT a.is_deleted")"
T_PROMO="$(now_ms)"
pr="$(curl -s --max-time 60 -o "$WORK/promo" -w '%{http_code}' -X POST -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"target_repository\":\"${RL}\"}" "${BASE_URL}/api/v1/promotion/repositories/${ST}/artifacts/${AID}/promote" 2>/dev/null || echo 000)"
get rl.json "/conda/${RL}/noarch/repodata.json" >/dev/null
PT="$(ts_of rl.json json "$PF")"
begin_test "CONTROL #6530: a package promoted into a local channel is listed there with an indexed_timestamp"
if [ "$pr" = "200" ] && [[ "$PT" =~ ^[0-9]+$ ]] && [ "$PT" -ge "$T_UP" ]; then pass
else fail "promote HTTP ${pr} ($(head -c 200 "$WORK/promo")); promoted record indexed_timestamp ${PT}"; fi
echo "  promoted indexed_timestamp ${PT}, promotion started ${T_PROMO}"

# --- pass-through: remote and virtual ---------------------------------------
UP_TS="$(docker exec "$MOCK_CTR" python3 -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1/gate/noarch/repodata.json'))['packages']['dtfgate-old-1.0-0.tar.bz2']['indexed_timestamp'])" 2>/dev/null)"
for repo in "$R" "$V"; do
  get "p.$repo" "/conda/${repo}/noarch/repodata.json" >/dev/null
  o="$(ts_of "p.$repo" json dtfgate-old-1.0-0.tar.bz2)"; n="$(ts_of "p.$repo" json dtfgate-noidx-1.0-0.tar.bz2)"
  begin_test "CONTROL #6530: ${repo} passes the upstream indexed_timestamp through and injects none"
  if [ -n "$UP_TS" ] && [ "$o" = "$UP_TS" ] && [ "$n" = "null" ]; then pass
  else fail "dtfgate-old ${o} (upstream ${UP_TS:-?}), dtfgate-noidx ${n} (want null)"; fi
done
S="$(shard_ts "$R" dtfgate-old dtfgate-old-1.0-0.tar.bz2)"
begin_test "CONTROL #6530: the remote's synthesised shard keeps the upstream indexed_timestamp"
if [ "$S" = "$UP_TS" ]; then pass; else fail "shard indexed_timestamp ${S}, upstream ${UP_TS:-?}"; fi

# --- a real client: pixi exclude-newer -----------------------------------------
docker rm -f "$PIXI_CTR" >/dev/null 2>&1 || true
docker run -d --name "$PIXI_CTR" --network "container:${BACKEND_CTR}" --entrypoint sleep "$PIXI_IMAGE" infinity >/dev/null 2>&1
lock_with() { # TAG EXCLUDE -> the dtfcool version pixi locks
  local ex=""
  [ -n "$2" ] && ex="exclude-newer = \"$2\""
  docker exec "$PIXI_CTR" sh -c "rm -rf /w-$1 && mkdir -p /w-$1 && cat > /w-$1/pixi.toml <<TOML
[workspace]
name = \"c47\"
channels = [\"http://127.0.0.1:8080/conda/${P}\"]
platforms = [\"linux-64\"]
${ex}

[dependencies]
dtfcool = \"*\"
TOML
cd /w-$1 && PIXI_CACHE_DIR=/tmp/pc-$1 RATTLER_CACHE_DIR=/tmp/pc-$1 pixi lock" > "$WORK/pixi.$1" 2>&1
  docker exec "$PIXI_CTR" cat "/w-$1/pixi.lock" 2>/dev/null | grep -oE 'dtfcool-[0-9.]+-0\.tar\.bz2' | head -1 | sed -E 's/dtfcool-([0-9.]+)-0.*/\1/'
}
echo "  client: $(docker exec "$PIXI_CTR" pixi --version 2>&1 | tail -1)"
v_all="$(lock_with all "")"
v_old="$(lock_with ex "$T_MID")"
# pixi 0.81 dates a record by its builder `timestamp` (it does not read
# indexed_timestamp yet), so both are set on the same side of T_MID here.
begin_test "CONTROL #6530: pixi exclude-newer (${T_MID}) against a hosted channel locks dtfcool 1.0; without it 2.0"
if [ "$v_all" = "2.0" ] && [ "$v_old" = "1.0" ]; then pass
else fail "pixi locked '${v_all:-none}' without exclude-newer and '${v_old:-none}' with it" "$(tail -c 600 "$WORK/pixi.ex")"; fi

end_suite
