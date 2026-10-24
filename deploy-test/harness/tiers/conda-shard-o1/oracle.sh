#!/usr/bin/env bash
# =============================================================================
# tiers/conda-shard-o1/oracle.sh: a hosted conda channel's CEP-16 shard
#   request costs the same whatever the size of the channel, reads no catalog
#   rows, and one upload rewrites one stored shard (artifact-keeper#4173)
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1,
# COMMON_SH.
#
# Topology (keys suffixed per run), seeded straight into the slot's Postgres
# (a shard is built from rows only, so no package bytes are needed):
#   S  hosted conda channel,   300 names x 10 versions (3,000 rows)
#   L  hosted conda channel, 3,000 names x 10 versions (30,000 rows)
#
# Gates (1.12.0; RED on 1.11.5):
#   #4173 O(1)    shard GET latency does not grow with the channel: p95 over
#                 interleaved samples of L is within 10 % of S (plus a 5 ms
#                 jitter floor), and p95 on L is at most 25 ms. 1.11.5
#                 rebuilds shards per request: L costs ~10x S.
#   #4173 rows    a burst of 20 shard GETs on L reads no `artifacts` rows
#                 (pg_stat_user_tables seq_tup_read + idx_tup_fetch; at least
#                 one of two windows exactly 0, so a scheduled job touching
#                 the table cannot fail it). 1.11.5 reads every row per GET.
#   #4173 write   one upload to L rewrites exactly one stored shard row (the
#                 uploaded name's) and leaves the other 2,999 untouched
#                 (1.11.5 stores no shards).
# CONTROL (both images): both indexes decode and list every seeded name; a
#   shard hashes to its address, is served immutable, and lists the name's
#   ten records; after the upload the name's shard lists the new file.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
S="o1-small-${SUF}"
L="o1-large-${SUF}"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
DECODER_IMAGE="docker.io/library/python:3.14-slim"
IDX="noarch/repodata_shards.msgpack.zst"
SAMPLES="${O1_SAMPLES:-60}"

WORK="$(mktemp -d -t dtf-o1-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -Atc "$1" 2>&1 || true
}
fetch() {
  local tag="$1" path="$2"; shift 2
  curl -s --max-time 120 -D "$WORK/${tag}.hdr" -o "$WORK/${tag}.body" -w '%{http_code}' \
    "$@" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
header() {
  { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
decode() {
  docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
    "$DECODER_IMAGE" python3 -I /app/cep16.py < "$WORK/$1.body" > "$WORK/$1.json" 2>/dev/null \
    && jq -e 'has("doc")' "$WORK/$1.json" >/dev/null 2>&1
}
sha_of() { { sha256sum "$1" 2>/dev/null || echo none; } | cut -d' ' -f1; }
# addr <decoded index tag> <name> -> the shard address as hex
addr() { jq -r --arg n "$2" '.doc.shards[$n] | if type == "object" then .bin else . end // empty' "$WORK/$1.json" 2>/dev/null || true; }
# time_get <url path> -> seconds as printed by curl, or "fail"
time_get() {
  local out
  out="$(curl -s --max-time 120 -o /dev/null -w '%{http_code} %{time_total}' "${BASE_URL}$1" 2>/dev/null || echo "000 0")"
  case "$out" in 200\ *) echo "${out#* }" ;; *) echo fail ;; esac
}
p95() { sort -n | awk '{a[NR]=$1} END { if (NR==0) {print "nan"; exit} i=int(NR*0.95+0.999); if (i>NR) i=NR; printf "%.6f\n", a[i] }'; }
artifact_rows_read() {
  psql_q "SELECT COALESCE(seq_tup_read,0) + COALESCE(idx_tup_fetch,0) FROM pg_stat_user_tables WHERE relname = 'artifacts'"
}
# seed <repo key> <names>: <names> x 10 versions of `o1p<i>` into noarch.
seed() {
  local key="$1" names="$2"
  psql_q "
WITH r AS (SELECT id FROM repositories WHERE key = '${key}'),
v AS (SELECT i, j FROM generate_series(1, ${names}) AS i, generate_series(1, 10) AS j),
ins AS (
  INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256,
                         content_type, storage_key)
  SELECT r.id, 'noarch/o1p' || i || '-1.' || j || '-0.tar.bz2', 'o1p' || i, '1.' || j, 1000 + j,
         encode(sha256(convert_to('${key}/o1p' || i || '-' || j, 'UTF8')), 'hex'),
         'application/x-tar', 'seed/${key}/o1p' || i || '-1.' || j
    FROM r, v
  RETURNING id, name, version)
INSERT INTO artifact_metadata (artifact_id, format, metadata)
SELECT id, 'conda', jsonb_build_object(
         'name', name, 'version', version, 'build', '0', 'build_number', 0,
         'subdir', 'noarch', 'noarch', 'generic', 'license', 'MIT',
         'depends', jsonb_build_array('python >=3.10'), 'constrains', jsonb_build_array(),
         'md5', md5(name || version))
  FROM ins;
SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${key}';"
}

begin_suite "conda-shard-o1 (#4173)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, two hosted channels seeded with 3,000 and 30,000 rows, decoder image"
auth_admin
setup_err=""
for key in "$S" "$L"; do
  st="$(curl -s --max-time 30 -o "$WORK/create.out" -w '%{http_code}' -X POST \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":true}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
  case "$st" in 200|201) ;; *) setup_err+="create ${key} -> HTTP ${st} $(head -c 160 "$WORK/create.out"); " ;; esac
done
n_s="$(seed "$S" 300 | tail -1)"
n_l="$(seed "$L" 3000 | tail -1)"
[ "$n_s" = "3000" ] || setup_err+="seed ${S}: ${n_s}; "
[ "$n_l" = "30000" ] || setup_err+="seed ${L}: ${n_l}; "
docker image inspect "$DECODER_IMAGE" >/dev/null 2>&1 || docker pull -q "$DECODER_IMAGE" >/dev/null 2>&1 \
  || setup_err+="pull ${DECODER_IMAGE}; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# CONTROLS (true on both images)
# =============================================================================
begin_test "CONTROL: both shard indexes decode and list every seeded name"
st_s="$(fetch idx_s "/conda/${S}/${IDX}")"
st_l="$(fetch idx_l "/conda/${L}/${IDX}")"
c_s="$(decode idx_s && jq '.doc.shards | length' "$WORK/idx_s.json" || true)"
c_l="$(decode idx_l && jq '.doc.shards | length' "$WORK/idx_l.json" || true)"
if [ "$st_s" = "200" ] && [ "$st_l" = "200" ] && [ "$c_s" = "300" ] && [ "$c_l" = "3000" ]; then
  pass
else
  fail "shard indexes unreadable" "S HTTP ${st_s} names=${c_s}; L HTTP ${st_l} names=${c_l}"
fi

begin_test "CONTROL: a shard hashes to its address, is immutable, and lists the name's ten records"
A7="$(addr idx_l o1p7)"
st="$(fetch shard7 "/conda/${L}/noarch/shards/${A7:-0}.msgpack.zst")"
cc="$(header shard7 Cache-Control)"
recs="$(decode shard7 && jq '.doc.packages | length' "$WORK/shard7.json" || true)"
if [ "$st" = "200" ] && [ "$(sha_of "$WORK/shard7.body")" = "$A7" ] \
   && [ "$cc" = "public, max-age=31536000, immutable" ] && [ "$recs" = "10" ]; then
  pass
else
  fail "shard o1p7 not as expected" "HTTP ${st} sha=$(sha_of "$WORK/shard7.body" | head -c 12) addr=${A7:0:12} cache-control=[${cc}] records=${recs}"
fi

# Addresses to sample: 20 names spread over each channel.
S_ADDRS=(); L_ADDRS=()
for i in $(seq 1 15 300); do S_ADDRS+=("$(addr idx_s "o1p${i}")"); done
for i in $(seq 1 150 3000); do L_ADDRS+=("$(addr idx_l "o1p${i}")"); done

# =============================================================================
# #4173: shard latency independent of the channel size
# =============================================================================
begin_test "#4173: shard GET p95 on 3,000 names is within 10% of 300 names and at most 25 ms"
: > "$WORK/t_s"; : > "$WORK/t_l"; fails=0
# Warm both paths once, then interleave so drift hits both series alike.
time_get "/conda/${S}/noarch/shards/${S_ADDRS[0]}.msgpack.zst" >/dev/null
time_get "/conda/${L}/noarch/shards/${L_ADDRS[0]}.msgpack.zst" >/dev/null
for k in $(seq 0 $((SAMPLES - 1))); do
  ts="$(time_get "/conda/${S}/noarch/shards/${S_ADDRS[$((k % ${#S_ADDRS[@]}))]}.msgpack.zst")"
  tl="$(time_get "/conda/${L}/noarch/shards/${L_ADDRS[$((k % ${#L_ADDRS[@]}))]}.msgpack.zst")"
  [ "$ts" = fail ] && fails=$((fails + 1)) || echo "$ts" >> "$WORK/t_s"
  [ "$tl" = fail ] && fails=$((fails + 1)) || echo "$tl" >> "$WORK/t_l"
done
P_S="$(p95 < "$WORK/t_s")"; P_L="$(p95 < "$WORK/t_l")"
verdict="$(python3 -I -c '
import sys
s, l = float(sys.argv[1]), float(sys.argv[2])
print("ok" if l <= s * 1.10 + 0.005 and l <= 0.025 else "no")' "$P_S" "$P_L" 2>/dev/null || echo no)"
detail="$(python3 -I -c '
import sys
print("p95 S=%.1f ms, p95 L=%.1f ms" % (float(sys.argv[1]) * 1000, float(sys.argv[2]) * 1000))' "$P_S" "$P_L" 2>/dev/null), over ${SAMPLES} interleaved samples each, ${fails} non-200"
echo "  ${detail}"
if [ "$fails" = "0" ] && [ "$verdict" = "ok" ]; then
  pass
else
  fail "shard latency grows with the channel" "$detail"
fi

# =============================================================================
# #4173: a shard GET reads no catalog rows
# =============================================================================
begin_test "#4173: 20 shard GETs on the 30,000-row channel read 0 artifacts rows"
windows=""; zero=0
for w in 1 2; do
  sleep 12   # let every session's table statistics reach pg_stat (idle flush)
  before="$(artifact_rows_read)"
  for k in $(seq 0 19); do
    time_get "/conda/${L}/noarch/shards/${L_ADDRS[$k]}.msgpack.zst" >/dev/null
  done
  sleep 12
  after="$(artifact_rows_read)"
  delta=$(( ${after:-0} - ${before:-0} ))
  windows+="window ${w}: ${delta} rows; "
  [ "$delta" = "0" ] && zero=$((zero + 1))
done
echo "  ${windows}"
if [ "$zero" -ge 1 ]; then
  pass
else
  fail "the shard route reads catalog rows" "$windows (1.11.5 reads every row of the repository per GET)"
fi

# =============================================================================
# #4173: one upload rewrites one stored shard
# =============================================================================
begin_test "#4173: one upload rewrites exactly the uploaded name's stored shard row"
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
pkg="$(bash "$BUILD" "$WORK" o1p7 9.9 0 noarch 2>/dev/null | tail -1 || true)"
mark="$(psql_q "SELECT now()")"
st="$(curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
  -H "$(auth_header)" --data-binary "@${pkg}" \
  "${BASE_URL}/conda/${L}/noarch/o1p7-9.9-0.tar.bz2" 2>/dev/null || echo 000)"
# The upload route rebuilds the shard right after its write; a read would
# rebuild anything left marked.
fetch idx_after "/conda/${L}/${IDX}" >/dev/null
rewritten="$(psql_q "SELECT string_agg(package_name, ',') || '|' || count(*) FROM conda_shard_index i \
  JOIN repositories r ON r.id = i.repository_id WHERE r.key = '${L}' AND i.updated_at >= '${mark}'")"
total="$(psql_q "SELECT count(*) FROM conda_shard_index i JOIN repositories r ON r.id = i.repository_id WHERE r.key = '${L}'")"
if [ "$st" = "201" ] || [ "$st" = "200" ]; then
  if [ "$rewritten" = "o1p7|1" ] && [ "$total" = "3000" ]; then
    pass
  else
    fail "the upload did not rewrite exactly one stored shard" "rewritten since upload: [${rewritten}]; stored rows: [${total}]"
  fi
else
  infra_fail "upload failed" "HTTP ${st} $(head -c 200 "$WORK/put.out")"
fi

begin_test "CONTROL: after the upload the name's shard lists the new file"
decode idx_after >/dev/null || true
A7B="$(addr idx_after o1p7)"
st="$(fetch shard7b "/conda/${L}/noarch/shards/${A7B:-0}.msgpack.zst")"
if [ "$st" = "200" ] && decode shard7b \
   && jq -e '.doc.packages | has("o1p7-9.9-0.tar.bz2")' "$WORK/shard7b.json" >/dev/null 2>&1 \
   && [ "$(jq '.doc.packages | length' "$WORK/shard7b.json")" = "11" ] && [ "$A7B" != "$A7" ]; then
  pass
else
  fail "the new version is not in its shard" "HTTP ${st} address ${A7B:0:12} (was ${A7:0:12}) records=$(jq -c '.doc.packages | keys | length' "$WORK/shard7b.json" 2>/dev/null)"
fi

end_suite
