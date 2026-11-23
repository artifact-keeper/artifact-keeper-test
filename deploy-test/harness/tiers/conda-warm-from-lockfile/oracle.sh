#!/usr/bin/env bash
# =============================================================================
# tiers/conda-warm-from-lockfile/oracle.sh: warm a conda Remote's proxy cache
# from an ingested 1k lockfile, then a fleet install makes no upstream package
# fetch and a held package stays held (artifact-keeper#4184); the scale
# fixture generator behind it (artifact-keeper#4187)
# =============================================================================
# run.sh has stood up storage.filesystem + upstreams.mock-conda + client.conda
# + conda.warm-fast and exported BASE_URL, DB_CONTAINER, COMMON_SH, DTF_DIR,
# DTF_SLOT, RUN_ID. See the manifest for the design.
#
# Layout:
#   upstream  ak-dtf<slot>-mock-conda-scale on 172.16.<slot>.71: the generated
#             3,000-name channel, counting package GETs (fixtures/
#             mock_channel_dir.py). One package of the 1k lock is served with
#             Last-Modified = now, so the Remote's 60-minute hold applies to
#             it alone.
#   R         Remote -> the upstream, quarantine (age hold) 60 minutes
#   V         Virtual = [R]; the 1k lock pins ${BASE_URL}/conda/V/... URLs,
#             the channel a fleet installs from
#   R2        a second Remote -> the same upstream, warmed directly from the
#             2k lock pinned at the upstream's own URLs, with a backend
#             restart mid-warm (resume)
#   F         hosted: the stored environments, and the #4187 50-name upload
#             that micromamba installs
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DTF_SLOT:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq
require_cmd python3
require_cmd sha256sum

GEN="${DTF_DIR}/fixtures/conda/gen-channel.sh"
UPLOAD="${DTF_DIR}/fixtures/conda/upload-channel.sh"
MOCK_PY="${DTF_DIR}/harness/tiers/conda-warm-from-lockfile/fixtures/mock_channel_dir.py"
MOCK_IMAGE="python:3.12-slim"   # pulled by upstreams.mock-conda
MOCK_CTR="ak-dtf${DTF_SLOT}-mock-conda-scale"
MOCK_NET="ak-dtf${DTF_SLOT}-mockconda"
MOCK_IP="172.16.${DTF_SLOT}.71"
UPSTREAM="http://${MOCK_IP}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
CLIENT_CTR="ak-dtf${DTF_SLOT}-client-conda"
# conda.warm-fast.yml
WARM_RPS=100
WARM_CONC=8
# The release gate shares one cache per CI run (see gen-channel.sh).
export CONDA_FIXTURE_CACHE="${CONDA_FIXTURE_CACHE:-$(dtf_work_parent)/conda-fixtures}"

SUF="$(printf '%s' "${RUN_ID}" | tr -cd '[:alnum:]' | tail -c 8)"
F="cw-f-${SUF}"
R="cw-r-${SUF}"
R2="cw-r2-${SUF}"
V="cw-v-${SUF}"
R3="cw-r3-${SUF}"

dtf_mktemp_dir W dtf-conda-warm
CH="$W/channel"

# --- helpers -------------------------------------------------------------------
req() { # <label> <method> <path> [curl args...] -> $W/<label>.{body,code}
  local l="$1" m="$2" p="$3" mflag; shift 3
  # --head, not -X HEAD: with -X HEAD curl waits for the Content-Length body.
  if [ "$m" = HEAD ]; then mflag=(--head); else mflag=(-X "$m"); fi
  curl -s --max-time 120 "${mflag[@]}" -o "$W/$l.body" -w '%{http_code}' "$@" "${BASE_URL}$p" \
    > "$W/$l.code" 2>/dev/null || echo 000 > "$W/$l.code"
}
code_of() { cat "$W/$1.code" 2>/dev/null || echo 000; }
json_of() { jq -r "$2 // empty" "$W/$1.body" 2>/dev/null || true; }
body_of() { head -c 400 "$W/$1.body" 2>/dev/null | tr -d '\0'; }
areq() { local l="$1" m="$2" p="$3"; shift 3; req "$l" "$m" "$p" -H "$(auth_header)" "$@"; }
jpost() { areq "$1" POST "$2" -H 'Content-Type: application/json' -d "$3"; }
mock() { # <path> [curl args] -> body (from inside the mock's network namespace)
  docker exec "$MOCK_CTR" python3 -c "
import sys, urllib.request
r = urllib.request.Request('http://127.0.0.1' + sys.argv[1], method=sys.argv[2])
print(urllib.request.urlopen(r, timeout=10).read().decode())" "$1" "${2:-GET}" 2>/dev/null || true
}
mock_packages() { mock /__stats | jq -r '.packages // "x"'; }
mock_reset() { mock /__reset POST >/dev/null; }
create() { # <key> <json extra>
  jpost "create-$1" /api/v1/repositories \
    "$(jq -nc --arg k "$1" --argjson x "$2" '{key:$k,name:$k,format:"conda",is_public:true} + $x')"
  case "$(code_of "create-$1")" in 200|201) return 0 ;; esac
  SETUP_ERR+=" create $1: HTTP $(code_of "create-$1") $(body_of "create-$1");"
}
wait_job() { # <label> <repo> <job id> <timeout s> -> final body in $W/<label>.body
  local _
  for _ in $(seq 1 "$4"); do
    areq "$1" GET "/api/v1/conda/$2/warm/$3"
    case "$(json_of "$1" .status)" in completed|cancelled|budget_exceeded|failed) return 0 ;; esac
    sleep 1
  done
  return 1
}
cnt() { json_of "$1" ".counts.$2"; }
counts_line() { jq -c '{status, total, done, counts: (.counts | with_entries(select(.value > 0)))}' "$W/$1.body" 2>/dev/null; }
backend_up() { curl -s --max-time 3 -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null | grep -q 200; }

begin_suite "conda-warm-from-lockfile (#4184, fixtures #4187)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: generate the 3,000-name channel, start its upstream, repositories R, V=[R], R2, F"
SETUP_ERR=""
auth_admin
t0=$(date +%s)
GEN_SUMMARY="$(bash "$GEN" --names 3000 --versions 5 --builds 2 --subdirs linux-64,noarch \
  --deps-per-package 3 --seed 4187 --locks 1000,2000,3000 --out "$CH" 2>"$W/gen.err" | tail -1)" || true
GEN_WALL=$(( $(date +%s) - t0 ))
GEN_CACHE_HIT=0; grep -q 'cache hit' "$W/gen.err" && GEN_CACHE_HIT=1
[ -f "$CH/MANIFEST.sha256" ] || SETUP_ERR+=" generator failed: $(tail -c 300 "$W/gen.err");"
assert_bind_mount_visible "$CH" "$MOCK_IMAGE"
# The held package: one pinned file in the middle of the 1k lock.
HELD_REL="$(sed -n 500p "$CH/locks/env-1k/urls.tsv" 2>/dev/null | cut -f1 | awk -F/ '{print $(NF-1)"/"$NF}')"
printf '%s\n' "$HELD_REL" > "$CH/.fresh"
docker rm -f "$MOCK_CTR" >/dev/null 2>&1 || true
add_exit_handler "docker rm -f $MOCK_CTR >/dev/null 2>&1 || true"
docker run -d --name "$MOCK_CTR" --network "$MOCK_NET" --ip "$MOCK_IP" --security-opt label=disable \
  -e MOCK_PORT=80 -e MOCK_ROOT=/srv -e MOCK_DELAY_MS=30 \
  -v "$CH:/srv:ro" -v "$MOCK_PY:/app/mock.py:ro" "$MOCK_IMAGE" python3 -u /app/mock.py >/dev/null 2>"$W/mock.err" \
  || SETUP_ERR+=" mock start: $(head -c 200 "$W/mock.err");"
for _ in $(seq 1 30); do [ "$(mock /__readyz)" = "ok" ] && break; sleep 1; done
[ "$(mock /__readyz)" = "ok" ] || SETUP_ERR+=" mock not ready;"
create "$F" '{"repo_type":"local"}'
create "$R" "$(jq -nc --arg u "${UPSTREAM}/" '{repo_type:"remote",upstream_url:$u}')"
create "$R2" "$(jq -nc --arg u "${UPSTREAM}/" '{repo_type:"remote",upstream_url:$u}')"
create "$R3" "$(jq -nc --arg u "${UPSTREAM}/" '{repo_type:"remote",upstream_url:$u}')"
create "$V" '{"repo_type":"virtual"}'
jpost addm "/api/v1/repositories/${V}/members" "{\"member_key\":\"${R}\"}"
case "$(code_of addm)" in 200|201|204) ;; *) SETUP_ERR+=" add member: HTTP $(code_of addm) $(body_of addm);" ;; esac
areq hold PATCH "/api/v1/repositories/${R}" -H 'Content-Type: application/json' \
  -d '{"quarantine_enabled":true,"quarantine_duration_minutes":60}'
case "$(code_of hold)" in 200|204) ;; *) SETUP_ERR+=" age hold on R: HTTP $(code_of hold) $(body_of hold);" ;; esac
# The fleet's lock: the 1k environment pinned at the Virtual's channel URL.
bash "$GEN" locks --channel "$CH" --sizes 1000 --channel-url "${BASE_URL}/conda/${V}" --out "$W/locks-v" >/dev/null 2>&1 \
  || SETUP_ERR+=" relock for V failed;"
# R2's lock: the 2k environment pinned at the upstream's own URLs, as a lock
# solved against the upstream channel records them.
bash "$GEN" locks --channel "$CH" --sizes 2000 --channel-url "${UPSTREAM}" --out "$W/locks-up" >/dev/null 2>&1 \
  || SETUP_ERR+=" relock for the upstream failed;"
LOCK_V="$W/locks-v/env-1k/pixi.lock"
URLS_V="$W/locks-v/env-1k/urls.tsv"
ingest() { # <label> <lock> <name> -> environment id
  areq "$1" POST "/api/v1/repositories/${F}/environments?filename=pixi.lock&name=$3" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$2"
  json_of "$1" .id
}
ENV_1K="$(ingest ing1 "$LOCK_V" env-1k)"
[ -n "$ENV_1K" ] || SETUP_ERR+=" ingest env-1k: HTTP $(code_of ing1) $(body_of ing1);"
ENV_2K="$(ingest ing2 "$W/locks-up/env-2k/pixi.lock" env-2k-upstream)"
[ -n "$ENV_2K" ] || SETUP_ERR+=" ingest env-2k: HTTP $(code_of ing2) $(body_of ing2);"
if [ -z "$SETUP_ERR" ]; then
  pass "channel ${GEN_WALL}s (cache hit: ${GEN_CACHE_HIT}), held=${HELD_REL}, env-1k=${ENV_1K}, env-2k=${ENV_2K}"
else
  infra_fail "setup failed:${SETUP_ERR}"
  end_suite
fi

# =============================================================================
# FIXTURE #4187: the generator
# =============================================================================
begin_test "FIXTURE #4187: gen-channel.sh writes 3,000 names x 10 artifacts, .conda and .tar.bz2, with dependency edges, in under two minutes"
gen_ok=$(printf '%s' "$GEN_SUMMARY" | jq -r 'select(.artifacts == 30000 and .conda > 0 and .tar_bz2 > 0
  and .edges > 0 and (.locks["env-1k"] == 1000) and (.locks["env-3k"] == 3000)) | .seconds' 2>/dev/null)
n_files=$(grep -cE '\.(conda|tar\.bz2)$' "$CH/MANIFEST.sha256" 2>/dev/null || echo 0)
if [ -n "$gen_ok" ] && [ "$n_files" = "30000" ] && awk -v s="$gen_ok" 'BEGIN{exit !(s < 120)}'; then
  pass "$(printf '%s' "$GEN_SUMMARY" | jq -c '{artifacts, conda, tar_bz2, edges, seconds}') (this run: ${GEN_WALL}s, cache hit ${GEN_CACHE_HIT})"
else
  fail "generator summary: ${GEN_SUMMARY:-<none>}; ${n_files} package files" "$(tail -c 600 "$W/gen.err")"
fi

begin_test "FIXTURE #4187: the same seed reproduces the same bytes; another seed does not"
CONDA_FIXTURE_CACHE="" bash "$GEN" --names 200 --seed 7 --locks 100 --out "$W/s1" >/dev/null 2>&1
CONDA_FIXTURE_CACHE="" bash "$GEN" --names 200 --seed 7 --locks 100 --jobs 1 --out "$W/s2" >/dev/null 2>&1
CONDA_FIXTURE_CACHE="" bash "$GEN" --names 200 --seed 8 --locks 100 --out "$W/s3" >/dev/null 2>&1
m() { grep -v '^#' "$1/MANIFEST.sha256" 2>/dev/null | sha256sum | cut -c1-16; }
if [ -s "$W/s1/MANIFEST.sha256" ] && [ "$(m "$W/s1")" = "$(m "$W/s2")" ] && [ "$(m "$W/s1")" != "$(m "$W/s3")" ]; then
  pass "seed 7 twice (parallel and --jobs 1): $(m "$W/s1"); seed 8: $(m "$W/s3")"
else
  fail "manifests: seed7=$(m "$W/s1") seed7/jobs1=$(m "$W/s2") seed8=$(m "$W/s3")"
fi

begin_test "FIXTURE #4187: env-1k/2k/3k pin 1,000/2,000/3,000 packages in both formats, each closed under its dependency edges"
lock_check="$(python3 -I - "$CH/locks" <<'PY'
import json, re, sys, os
out = {}
for label in ("env-1k", "env-2k", "env-3k"):
    text = open(os.path.join(sys.argv[1], label, "pixi.lock")).read()
    urls = re.findall(r"^- conda: (\S+)$", text, re.M)
    names = {u.rsplit("/", 1)[1].rsplit("-", 2)[0] for u in urls}
    deps = re.findall(r'^  - "([^ "]+) ', text, re.M)
    fmts = {("conda" if u.endswith(".conda") else "tar.bz2") for u in urls}
    out[label] = {"packages": len(urls), "names": len(names), "edges": len(deps),
                  "dangling": len(set(deps) - names), "formats": sorted(fmts)}
print(json.dumps(out, sort_keys=True))
PY
)" || true
if printf '%s' "$lock_check" | jq -e '
    .["env-1k"].packages == 1000 and .["env-2k"].packages == 2000 and .["env-3k"].packages == 3000
    and ([.[] | .dangling] | add) == 0 and ([.[] | .edges > 0] | all)
    and ([.[] | .formats == ["conda","tar.bz2"]] | all)' >/dev/null 2>&1; then
  pass "$lock_check"
else
  fail "lock check: ${lock_check:-<none>}"
fi

begin_test "FIXTURE #4187: upload-channel.sh uploads a closed 50-name subset in parallel, and a re-run uploads nothing"
bash "$GEN" locks --channel "$CH" --sizes 50 --channel-url "${BASE_URL}/conda/${F}" --out "$W/locks-50" >/dev/null 2>&1
cut -f1 "$W/locks-50/env-50/urls.tsv" | awk -F/ '{print $(NF-1)"/"$NF}' > "$W/subset50"
export AUTH_HEADER; AUTH_HEADER="$(auth_header)"
up1="$(UPLOAD_ONLY="$W/subset50" bash "$UPLOAD" "$CH" "$F" 2>"$W/up1.err" | tail -1)" || true
up2="$(UPLOAD_ONLY="$W/subset50" bash "$UPLOAD" "$CH" "$F" 2>"$W/up2.err" | tail -1)" || true
if [ "$up1" = "uploaded=50 present=0 failed=0" ] && [ "$up2" = "uploaded=0 present=50 failed=0" ]; then
  pass "first: ${up1}; re-run: ${up2}"
else
  fail "first: '${up1}'; re-run: '${up2}'" "$(tail -c 400 "$W/up1.err") $(tail -c 400 "$W/up2.err")"
fi

begin_test "FIXTURE #4187: micromamba solves the 50 names' dependency edges from the hosted channel and links every marker"
names50="$(cut -f1 "$W/locks-50/env-50/urls.tsv" | awk -F/ '{print $NF}' | sed -E 's/-[^-]+-[^-]+$//' | sort -u | tr '\n' ' ')"
docker exec -u root "$CLIENT_CTR" sh -c "export MAMBA_ROOT_PREFIX=/tmp/mamba-cw HOME=/tmp CONDA_ALLOW_INSECURE=1; \
micromamba create -y -p /tmp/env-cw --no-rc --override-channels --platform linux-64 -c 'http://backend:8080/conda/${F}' ${names50}" \
  > "$W/mm.log" 2>&1
mm_rc=$?
linked=$(docker exec "$CLIENT_CTR" sh -c 'ls /tmp/env-cw/share/*/marker.txt 2>/dev/null | wc -l' 2>/dev/null | tr -d ' ')
if [ "$mm_rc" = "0" ] && [ "${linked:-0}" = "50" ]; then
  pass "micromamba exit 0, ${linked}/50 markers linked"
else
  fail "micromamba exit ${mm_rc}, ${linked:-0}/50 markers linked" "$(tail -c 800 "$W/mm.log")"
fi

# =============================================================================
# FIX #4184: warm V's Remote from the 1k lock
# =============================================================================
mock_reset
begin_test "FIX #4184: POST /api/v1/conda/{virtual}/warm with the ingested 1k environment starts a warm job (202)"
jpost warm1 "/api/v1/conda/${V}/warm" "{\"environmentId\":\"${ENV_1K}\"}"
JOB1="$(json_of warm1 .id)"
if [ "$(code_of warm1)" = "202" ] && [ -n "$JOB1" ] && [ "$(json_of warm1 .total)" = "1000" ]; then
  pass "job ${JOB1}, total 1000, status $(json_of warm1 .status)"
else
  fail "HTTP $(code_of warm1): $(body_of warm1) (want 202 with id and total 1000)"
fi

begin_test "FIX #4184: asking again while the job runs returns the same job (200): one active warm per environment"
jpost warm1b "/api/v1/conda/${V}/warm" "{\"environmentId\":\"${ENV_1K}\"}"
if [ -n "$JOB1" ] && [ "$(code_of warm1b)" = "200" ] && [ "$(json_of warm1b .id)" = "$JOB1" ]; then
  pass "200, same id, status $(json_of warm1b .status)"
else
  fail "HTTP $(code_of warm1b) id $(json_of warm1b .id) (want 200 and ${JOB1:-<no job>}): $(body_of warm1b)"
fi

begin_test "FIX #4184: the warm completes: 999 fetched, the held package recorded held, nothing failed"
done1=0; [ -n "$JOB1" ] && wait_job job1 "$V" "$JOB1" 300 && done1=1
if [ "$done1" = 1 ] && [ "$(json_of job1 .status)" = completed ] && [ "$(cnt job1 fetched)" = 999 ] \
   && [ "$(cnt job1 held)" = 1 ] && [ "$(json_of job1 .done)" = 1000 ]; then
  pass "$(counts_line job1), bytes $(json_of job1 .bytesFetched)"
else
  fail "job: $(counts_line job1 || body_of job1)" "$(jq -c '.problems[:5]' "$W/job1.body" 2>/dev/null)"
fi

begin_test "FIX #4184: the upstream saw each package once, at most ${WARM_CONC} at a time and at most ${WARM_RPS} per second"
stats="$(mock /__stats)"
s_pk=$(printf '%s' "$stats" | jq -r '.packages // 0')
s_max=$(printf '%s' "$stats" | jq -r '[.per_path[]] | max // 0')
s_inflight=$(printf '%s' "$stats" | jq -r '.max_in_flight // 0')
s_rate=$(printf '%s' "$stats" | jq -r '[.per_second[]] | max // 0')
# 1,000 requests: 999 served plus the held one (fetched once, cached under its hold).
if [ "$s_pk" = 1000 ] && [ "$s_max" = 1 ] && [ "$s_inflight" -le "$WARM_CONC" ] && [ "$s_rate" -le $(( WARM_RPS + WARM_RPS / 10 )) ]; then
  pass "upstream package GETs ${s_pk}, max per path ${s_max}, max in flight ${s_inflight}, peak ${s_rate}/s"
else
  fail "upstream package GETs ${s_pk} (want 1000), max per path ${s_max} (want 1), in flight ${s_inflight} (<= ${WARM_CONC}), peak ${s_rate}/s (<= $(( WARM_RPS + WARM_RPS / 10 )))"
fi

begin_test "FIX #4184: a second warm after completion fetches nothing: 999 cached, 1 held, 0 upstream requests"
mock_reset
jpost warm2 "/api/v1/conda/${V}/warm" "{\"environmentId\":\"${ENV_1K}\"}"
JOB2="$(json_of warm2 .id)"
[ -n "$JOB2" ] && wait_job job2 "$V" "$JOB2" 120
if [ "$(code_of warm2)" = 202 ] && [ "$JOB2" != "$JOB1" ] && [ "$(cnt job2 cached)" = 999 ] \
   && [ "$(cnt job2 held)" = 1 ] && [ "$(mock_packages)" = 0 ]; then
  pass "new job ${JOB2}: $(counts_line job2); upstream package GETs 0"
else
  fail "HTTP $(code_of warm2) job ${JOB2:-<none>}: $(counts_line job2 || body_of warm2); upstream GETs $(mock_packages)"
fi

# fleet <tag> <urls.tsv>: 8 installers, each fetching every URL 8 at a time,
# checking each body against the lock's sha256. Lines in $W/fleet-<tag>.res:
# "<installer> <code> match|differ <url>"; wall seconds in FLEET_WALL.
cat > "$W/get-one.sh" <<'SH'
#!/usr/bin/env bash
url="$1" want="$2"
f=$(mktemp -p "$FLEET_DIR")
code=$(curl -s --max-time 120 -o "$f" -w '%{http_code}' "$url" 2>/dev/null || echo 000)
got=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1); rm -f "$f"
echo "$code $([ "$got" = "$want" ] && echo match || echo differ) $url"
SH
mkdir -p "$W/fleet"
export FLEET_DIR="$W/fleet"
fleet() {
  local tag="$1" urls="$2" inst t0
  t0=$(date +%s.%N)
  for inst in 1 2 3 4 5 6 7 8; do
    ( cut -f1,2 "$urls" | xargs -P 8 -n 2 bash "$W/get-one.sh" 2>/dev/null \
        | sed "s/^/${inst} /" ) > "$W/fleet-${tag}.$inst" &
  done
  wait
  cat "$W"/fleet-"${tag}".[1-8] > "$W/fleet-${tag}.res"
  FLEET_WALL=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
}

begin_test "CONTROL (before): the same fleet against a cold Remote sends every package upstream"
mock_reset
sed "s#/conda/${V}/#/conda/${R3}/#" "$URLS_V" > "$W/urls-r3.tsv"
fleet cold "$W/urls-r3.tsv"
c_ok=$(grep -c ' 200 match ' "$W/fleet-cold.res" || true)
c_up=$(mock_packages)
COLD_WALL="$FLEET_WALL"
echo "  measured: cold fleet 8 x 1,000 wall ${COLD_WALL}s, upstream package GETs ${c_up}"
if [ "$c_ok" = 8000 ] && [ "$c_up" -ge 1000 ] 2>/dev/null; then
  pass "8 installers x 1,000 from cold Remote ${R3}: ${c_ok} served, upstream package GETs ${c_up}, wall ${COLD_WALL}s"
else
  fail "served+matching ${c_ok} (want 8000), upstream package GETs ${c_up} (want >= 1000), wall ${COLD_WALL}s" \
    "$(grep -v ' 200 match ' "$W/fleet-cold.res" | head -5)"
fi

begin_test "FIX #4184: a fleet of 8 parallel installers downloads the 999 servable packages through the virtual with 0 upstream package fetches, bytes matching the lock"
mock_reset
fleet warm "$URLS_V"
f_total=$(wc -l < "$W/fleet-warm.res" | tr -d ' ')
f_ok=$(grep -c ' 200 match ' "$W/fleet-warm.res" || true)
f_held=$(grep -c ' 409 ' "$W/fleet-warm.res" || true)
f_up=$(mock_packages)
echo "  measured: warmed fleet 8 x 1,000 wall ${FLEET_WALL}s, upstream package GETs ${f_up}"
if [ "$f_total" = 8000 ] && [ "$f_ok" = 7992 ] && [ "$f_held" = 8 ] && [ "$f_up" = 0 ]; then
  pass "8 installers x 1,000: ${f_ok} served with the pinned sha256, ${f_held} refused 409 (the held package), upstream package GETs ${f_up}, wall ${FLEET_WALL}s (cold Remote: ${COLD_WALL:-?}s)"
else
  fail "requests ${f_total} (want 8000), served+matching ${f_ok} (want 7992), 409 ${f_held} (want 8), upstream package GETs ${f_up} (want 0)" \
    "$(grep -v ' 200 match ' "$W/fleet-warm.res" | grep -v ' 409 ' | head -5)"
fi

begin_test "FIX #4184: the held package stays held after warming: 409 through the virtual and the Remote, and it is not served"
HELD_URL_V="$(sed -n 500p "$URLS_V" | cut -f1)"
req held-v GET "${HELD_URL_V#"$BASE_URL"}"
req held-r GET "/conda/${R}/${HELD_REL}"
req held-r-head HEAD "/conda/${R}/${HELD_REL}"
if [ "$(code_of held-v)" = 409 ] && [ "$(code_of held-r)" = 409 ] && [ "$(code_of held-r-head)" = 409 ] \
   && [ "$(mock_packages)" = 0 ]; then
  pass "virtual GET 409, Remote GET 409, Remote HEAD 409; upstream not asked"
else
  fail "virtual GET $(code_of held-v), Remote GET $(code_of held-r), HEAD $(code_of held-r-head) (want 409 each); upstream GETs $(mock_packages): $(body_of held-r)"
fi

begin_test "FIX #4184: progress names the held package, and ak_conda_warm_items_total counts the outcomes"
areq job1p GET "/api/v1/conda/${V}/warm/${JOB1:-none}"
held_listed="$(jq -r --arg f "${HELD_REL##*/}" '[.problems[]? | select(.status == "held" and (.url | endswith($f)))] | length' "$W/job1p.body" 2>/dev/null)"
areq metrics GET /api/v1/admin/metrics
m_fetched="$(grep -E '^ak_conda_warm_items_total\{[^}]*outcome="fetched"' "$W/metrics.body" | awk '{print $2}' | head -1)" || true
m_cached="$(grep -E '^ak_conda_warm_items_total\{[^}]*outcome="cached"' "$W/metrics.body" | awk '{print $2}' | head -1)" || true
m_held="$(grep -E '^ak_conda_warm_items_total\{[^}]*outcome="held"' "$W/metrics.body" | awk '{print $2}' | head -1)" || true
areq list GET "/api/v1/conda/${V}/warm"
n_jobs="$(jq -r '.jobs | length' "$W/list.body" 2>/dev/null)"
if [ "$held_listed" = 1 ] && [ "${m_fetched%.*}" -ge 999 ] 2>/dev/null && [ "${m_cached%.*}" -ge 999 ] 2>/dev/null \
   && [ "${m_held%.*}" -ge 2 ] 2>/dev/null && [ "${n_jobs:-0}" -ge 2 ]; then
  pass "problems lists the held file; metrics fetched=${m_fetched} cached=${m_cached} held=${m_held}; ${n_jobs} jobs listed"
else
  fail "held in problems: ${held_listed:-?}; metrics fetched=${m_fetched:-<absent>} cached=${m_cached:-<absent>} held=${m_held:-<absent>}; jobs listed ${n_jobs:-?}"
fi

begin_test "FIX #4184: only repo writers may warm: anonymous 401, a reader without write 403; a finished job cannot be cancelled (409)"
RU="cw-reader-${SUF}"; RP="Reader!${SUF}x9"
create_test_user "$RU" "$RP" "${RU}@example.test" >/dev/null 2>&1 || true
RT="$(login_as "$RU" "$RP" 2>/dev/null || true)"
req anon POST "/api/v1/conda/${V}/warm" -H 'Content-Type: application/json' -d "{\"environmentId\":\"${ENV_1K}\"}"
req rdr POST "/api/v1/conda/${V}/warm" -H "Authorization: Bearer ${RT}" -H 'Content-Type: application/json' -d "{\"environmentId\":\"${ENV_1K}\"}"
req rdr-get GET "/api/v1/conda/${V}/warm/${JOB1:-none}" -H "Authorization: Bearer ${RT}"
areq cancel DELETE "/api/v1/conda/${V}/warm/${JOB1:-none}"
if [ -n "$RT" ] && [ "$(code_of anon)" = 401 ] && [ "$(code_of rdr)" = 403 ] && [ "$(code_of rdr-get)" = 403 ] \
   && [ "$(code_of cancel)" = 409 ]; then
  pass "anonymous 401, reader POST 403 and GET 403, cancel of a completed job 409"
else
  fail "reader token: ${RT:+yes}; anonymous $(code_of anon) (want 401), reader POST $(code_of rdr) GET $(code_of rdr-get) (want 403), cancel $(code_of cancel) (want 409)"
fi

# =============================================================================
# FIX #4184 (review): not_remote, a pin the upstream bytes do not match, and a
# warm through a Virtual that scans when its member does not
# =============================================================================
R5="cw-r5-${SUF}"; R6="cw-r6-${SUF}"; V2="cw-v2-${SUF}"
create "$R5" "$(jq -nc --arg u "${UPSTREAM}/" '{repo_type:"remote",upstream_url:$u}')"
create "$R6" "$(jq -nc --arg u "${UPSTREAM}/" '{repo_type:"remote",upstream_url:$u}')"
create "$V2" '{"repo_type":"virtual"}'
jpost addm2 "/api/v1/repositories/${V2}/members" "{\"member_key\":\"${R6}\"}"
# Small locks: 50 packages pinned at R5's route, at another host, and at V2's route.
bash "$GEN" locks --channel "$CH" --sizes 50 --channel-url "${BASE_URL}/conda/${R5}" --out "$W/locks-r5" >/dev/null 2>&1 || true
bash "$GEN" locks --channel "$CH" --sizes 50 --channel-url "https://elsewhere.example/ch" --out "$W/locks-else" >/dev/null 2>&1 || true
bash "$GEN" locks --channel "$CH" --sizes 50 --channel-url "${BASE_URL}/conda/${V2}" --out "$W/locks-v2" >/dev/null 2>&1 || true
# Pin one R5 file at bytes the upstream does not serve.
BAD_SHA="$(printf '0%.0s' $(seq 1 64))"
python3 -I - "$W/locks-r5/env-50/pixi.lock" "$BAD_SHA" <<'PY' >/dev/null 2>&1 || true
import re, sys
p, bad = sys.argv[1], sys.argv[2]
s = open(p).read()
s = re.sub(r"(sha256: )[0-9a-f]{64}", lambda m: m.group(1) + bad, s, count=1)
open(p, "w").write(s)
PY
ENV_R5="$(ingest ing5 "$W/locks-r5/env-50/pixi.lock" env-50-r5)"
ENV_ELSE="$(ingest ing6 "$W/locks-else/env-50/pixi.lock" env-50-elsewhere)"
ENV_V2="$(ingest ing7 "$W/locks-v2/env-50/pixi.lock" env-50-v2)"

begin_test "FIX #4184: a lock pinned at another host warms nothing: 50 not_remote, 0 upstream requests"
mock_reset
jpost warm5 "/api/v1/conda/${R5}/warm" "{\"environmentId\":\"${ENV_ELSE}\"}"
JOB5="$(json_of warm5 .id)"
[ -n "$JOB5" ] && wait_job job5 "$R5" "$JOB5" 60
if [ "$(code_of warm5)" = 202 ] && [ "$(cnt job5 not_remote)" = 50 ] && [ "$(mock_packages)" = 0 ]; then
  pass "$(counts_line job5); upstream GETs 0"
else
  fail "HTTP $(code_of warm5): $(counts_line job5 || body_of warm5); upstream GETs $(mock_packages)"
fi

begin_test "FIX #4184: bytes that differ from the lock's pin are reported checksum_mismatch and not left cached: a rerun fetches that file again"
mock_reset
jpost warm6 "/api/v1/conda/${R5}/warm" "{\"environmentId\":\"${ENV_R5}\"}"
JOB6="$(json_of warm6 .id)"
[ -n "$JOB6" ] && wait_job job6 "$R5" "$JOB6" 120
up6=$(mock_packages)
mock_reset
jpost warm6b "/api/v1/conda/${R5}/warm" "{\"environmentId\":\"${ENV_R5}\"}"
JOB6B="$(json_of warm6b .id)"
[ -n "$JOB6B" ] && wait_job job6b "$R5" "$JOB6B" 120
up6b=$(mock_packages)
if [ "$(cnt job6 checksum_mismatch)" = 1 ] && [ "$(cnt job6 fetched)" = 49 ] && [ "$up6" = 50 ] \
   && [ "$(cnt job6b checksum_mismatch)" = 1 ] && [ "$(cnt job6b cached)" = 49 ] && [ "$up6b" = 1 ]; then
  pass "first: $(counts_line job6), upstream ${up6}; rerun: $(counts_line job6b), upstream ${up6b}"
else
  fail "first: $(counts_line job6 || body_of warm6), upstream ${up6} (want 49 fetched, 1 mismatch, 50); rerun: $(counts_line job6b || body_of warm6b), upstream ${up6b} (want 49 cached, 1 mismatch, 1)" \
    "$(jq -c '.problems[:2]' "$W/job6.body" 2>/dev/null)"
fi

begin_test "FIX #4184: a warm through a Virtual that scans on proxy (its member does not) goes through the scan gate: nothing is cached unscanned"
st="$(curl -s --max-time 30 -o "$W/sc.out" -w '%{http_code}' -X PUT -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true,"severity_threshold":"high"}' \
  "${BASE_URL}/api/v1/repositories/${V2}/security" 2>/dev/null || echo 000)"
mock_reset
jpost warm7 "/api/v1/conda/${V2}/warm" "{\"environmentId\":\"${ENV_V2}\"}"
JOB7="$(json_of warm7 .id)"
[ -n "$JOB7" ] && wait_job job7 "$V2" "$JOB7" 180
# The inline gate records one verdict per scanned file in proxy_scan_results
# (keyed by sha256). Every file the warm reports `fetched` must have one: the
# gate ran, so nothing was cached unscanned. (Before the review fix the warm
# took R6's own policy, which does not scan, and recorded none.) A gate that
# refuses a file reports it blocked or failed instead.
shas="$(cut -f2 "$W/locks-v2/env-50/urls.tsv" 2>/dev/null | grep -E '^[0-9a-f]{64}$' | sed "s/.*/'&'/" | paste -sd, -)"
scanned="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT count(DISTINCT checksum_sha256) FROM proxy_scan_results WHERE checksum_sha256 IN (${shas:-''})" 2>/dev/null | tr -d ' ' || true)"
f7="$(cnt job7 fetched)"
echo "  measured: scan-config PUT ${st}; $(counts_line job7); proxy_scan_results verdicts for the lock's files: ${scanned:-?}; upstream GETs $(mock_packages)"
if [ "$st" = 200 ] && [ "$(json_of job7 .done)" = 50 ] && [ "${scanned:-0}" -ge "${f7:-1}" ] 2>/dev/null; then
  pass "$(counts_line job7); scan verdicts ${scanned:-0}"
else
  fail "scan-config PUT ${st}: $(counts_line job7 || body_of warm7); fetched ${f7:-?} with ${scanned:-?} scan verdicts" \
    "$(jq -c '.problems[:3]' "$W/job7.body" 2>/dev/null)"
fi

# =============================================================================
# FIX #4184: a Remote warmed directly from upstream URLs, across a restart
# =============================================================================
begin_test "FIX #4184: warming R2 from the 2k lock pinned at the upstream's own URLs survives a backend restart mid-run and completes"
mock_reset
jpost warm3 "/api/v1/conda/${R2}/warm" "{\"environmentId\":\"${ENV_2K}\",\"platform\":\"linux-64\"}"
JOB3="$(json_of warm3 .id)"
restarted=0
if [ "$(code_of warm3)" = 202 ] && [ -n "$JOB3" ]; then
  for _ in $(seq 1 60); do
    areq job3 GET "/api/v1/conda/${R2}/warm/${JOB3}"
    [ "$(json_of job3 .done)" -ge 300 ] 2>/dev/null && break
    sleep 1
  done
  before="$(json_of job3 .done)"
  docker restart -t 2 "$BACKEND_CTR" >/dev/null 2>&1 && restarted=1
  for _ in $(seq 1 90); do backend_up && break; sleep 1; done
  auth_admin >/dev/null 2>&1 || true
  # Claims the killed process held lapse after CONDA_WARM_ITEM_LEASE_SECS=30.
  wait_job job3 "$R2" "$JOB3" 240
fi
up3=$(mock_packages)
max3=$(mock /__stats | jq -r '[.per_path[]] | max // 0')
if [ "$restarted" = 1 ] && [ "$(json_of job3 .status)" = completed ] \
   && [ "$(( $(cnt job3 fetched) + $(cnt job3 cached) ))" = 2000 ] && [ "${before:-0}" -lt 2000 ] \
   && [ "$up3" -ge 2000 ] && [ "$up3" -le $(( 2000 + WARM_CONC * 4 )) ] && [ "$max3" -le 2 ]; then
  pass "restart at ${before}/2000; $(counts_line job3); upstream GETs ${up3} (re-fetched in flight at the kill: $(( up3 - 2000 )))"
else
  fail "HTTP $(code_of warm3), restarted=${restarted} at ${before:-?}: $(counts_line job3 || body_of job3); upstream GETs ${up3}, max per path ${max3}" \
    "$(jq -c '.problems[:5]' "$W/job3.body" 2>/dev/null)"
fi

end_suite
