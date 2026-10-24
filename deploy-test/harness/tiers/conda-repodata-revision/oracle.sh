#!/usr/bin/env bash
# =============================================================================
# tiers/conda-repodata-revision/oracle.sh: a hosted conda subdir's repodata is
#   rendered once per revision and kept, and a withdrawal leaves every
#   encoding (artifact-keeper#4174)
# =============================================================================
# run.sh has stood up `storage.filesystem` with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, RUN_ID, DTF_SLOT, DTF_DIR, RELEASE_GATE=1,
# COMMON_SH.
#
# Topology (key suffixed per run):
#   H  public hosted conda channel: 30,000 noarch rows seeded in SQL
#      (3,000 names x 10 versions), then rev-probe 1.0 and 2.0 uploaded.
#
# Gates (1.12.0; RED on 1.11.5):
#   #4174 single flight  after one upload, 24 concurrent cold
#                 `repodata.json.zst` GETs are all 200 with ONE ETag and move
#                 ak_repo_metadata_regenerations_total{format="conda",
#                 scope="subdir"} by exactly 1 (1.11.5: no such counter, and
#                 each request renders on its own).
#   #4174 warm    p95 of 20 warm `.zst` GETs at most 200 ms with 30,000
#                 records in the subdir, the same ETag each time, and the
#                 counter unmoved (1.11.5 re-renders every request).
#   #4174 revision a withdrawal moves the counter by exactly 1 more across
#                 every encoding read after it.
# CONTROL (both images): the withdrawn file is absent from repodata.json,
#   .zst, .bz2, current_repodata.json, run_exports.json and its CEP-16 shard,
#   and named in `removed`; the kept version is still listed; .bz2 is one
#   bzip2 stream holding the same records as repodata.json.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
H="rev-host-${SUF}"
TIER_DIR="${DTF_DIR}/harness/tiers/conda-repodata-revision"
CHECK="${TIER_DIR}/fixtures/repodata_check.py"
CEP16="${DTF_DIR}/harness/tiers/conda-sharded-remote-virtual/fixtures/cep16.py"
DECODER_IMAGE="docker.io/library/python:3.14-slim"
FN1="rev-probe-1.0-0.tar.bz2"
FN2="rev-probe-2.0-0.tar.bz2"
COUNTER="ak_repo_metadata_regenerations_total"

WORK="$(mktemp -d -t dtf-rev-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -Atc "$1" 2>&1 || true
}
fetch() {
  local tag="$1" path="$2"; shift 2
  curl -s --max-time 180 -D "$WORK/${tag}.hdr" -o "$WORK/${tag}.body" -w '%{http_code}' \
    "$@" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
header() {
  { grep -i "^$2:" "$WORK/$1.hdr" 2>/dev/null || true; } | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
# check <tag> <encoding> -> JSON report on the document in $WORK/<tag>.body
check() {
  docker run --rm -i --security-opt label=disable -v "${CHECK}:/app/check.py:ro" \
    "$DECODER_IMAGE" python3 -I /app/check.py "$2" "$FN2" < "$WORK/$1.body" 2>/dev/null \
    || echo '{"error":"decoder did not run"}'
}
METRICS="$WORK/metrics.txt"
scrape_metrics() {
  curl -s --max-time 30 -o "$METRICS" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}
# regenerations -> the conda subdir counter, "absent" when not exported
regenerations() {
  scrape_metrics >/dev/null
  python3 -I - "$METRICS" "$COUNTER" <<'PY'
import re, sys
path, name = sys.argv[1], sys.argv[2]
for line in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r'^([A-Za-z_:][\w:]*)\{(.*)\}\s+(\S+)', line)
    if not m or m.group(1) != name:
        continue
    labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2)))
    if labels.get("format") == "conda" and labels.get("scope") == "subdir":
        print(int(float(m.group(3))))
        break
else:
    print("absent")
PY
}
delta() { [ "$1" = absent ] || [ "$2" = absent ] && echo absent || echo $(( $2 - $1 )); }
p95() { sort -n | awk '{a[NR]=$1} END { if (NR==0) {print "nan"; exit} i=int(NR*0.95+0.999); if (i>NR) i=NR; printf "%.6f\n", a[i] }'; }
put_pkg() {
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" --data-binary "@$WORK/$1" \
    "${BASE_URL}/conda/${H}/noarch/$1" 2>/dev/null || echo 000
}

begin_suite "conda-repodata-revision (#4174)"

# =============================================================================
# SETUP (infra on failure)
# =============================================================================
begin_test "setup: admin auth, hosted channel with 30,000 seeded rows, decoder image, metrics"
auth_admin
setup_err=""
st="$(curl -s --max-time 30 -o "$WORK/create.out" -w '%{http_code}' -X POST \
  -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${H}\",\"name\":\"${H}\",\"format\":\"conda\",\"repo_type\":\"local\",\"is_public\":true}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
case "$st" in 200|201) ;; *) setup_err+="create ${H} -> HTTP ${st}; " ;; esac
seeded="$(psql_q "
WITH r AS (SELECT id FROM repositories WHERE key = '${H}'),
v AS (SELECT i, j FROM generate_series(1, 3000) AS i, generate_series(1, 10) AS j),
ins AS (
  INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256,
                         content_type, storage_key)
  SELECT r.id, 'noarch/revp' || i || '-1.' || j || '-0.tar.bz2', 'revp' || i, '1.' || j, 1000 + j,
         encode(sha256(convert_to('${H}/revp' || i || '-' || j, 'UTF8')), 'hex'),
         'application/x-tar', 'seed/${H}/revp' || i || '-1.' || j
    FROM r, v
  RETURNING id, name, version)
INSERT INTO artifact_metadata (artifact_id, format, metadata)
SELECT id, 'conda', jsonb_build_object(
         'name', name, 'version', version, 'build', '0', 'build_number', 0,
         'subdir', 'noarch', 'noarch', 'generic', 'license', 'MIT',
         'depends', jsonb_build_array('python >=3.10', 'zlib >=1.2'),
         'constrains', jsonb_build_array(), 'md5', md5(name || version),
         'timestamp', 1700000000000)
  FROM ins;
SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${H}';" | tail -1)"
[ "$seeded" = "30000" ] || setup_err+="seed: ${seeded}; "
BUILD="${DTF_DIR}/fixtures/conda/build.sh"
for v in 1.0 2.0; do
  bash "$BUILD" "$WORK" rev-probe "$v" 0 noarch >/dev/null 2>&1 || setup_err+="build rev-probe ${v}; "
done
st="$(put_pkg "$FN1")"
case "$st" in 200|201) ;; *) setup_err+="upload ${FN1} -> HTTP ${st} $(head -c 200 "$WORK/put.out"); " ;; esac
docker image inspect "$DECODER_IMAGE" >/dev/null 2>&1 || docker pull -q "$DECODER_IMAGE" >/dev/null 2>&1 \
  || setup_err+="pull ${DECODER_IMAGE}; "
mst="$(scrape_metrics)"
[ "$mst" = "200" ] || setup_err+="metrics -> HTTP ${mst}; "
# Warm the subdir once at this revision (the burst below starts cold at the
# next one).
st="$(fetch warm0 "/conda/${H}/noarch/repodata.json.zst")"
[ "$st" = "200" ] || setup_err+="first repodata.json.zst -> HTTP ${st}; "
if [ -n "$setup_err" ]; then
  infra_fail "setup did not complete" "$setup_err"
  end_suite
fi
pass

# =============================================================================
# #4174: 24 concurrent cold requests after one upload render once
# =============================================================================
begin_test "#4174: after one upload, 24 concurrent cold .zst GETs render once and carry one ETag"
st="$(put_pkg "$FN2")"
before="$(regenerations)"
seq 1 24 | xargs -P 24 -I{} curl -s --max-time 180 -D "$WORK/burst{}.hdr" -o "$WORK/burst{}.body" \
  -w '%{http_code}\n' "${BASE_URL}/conda/${H}/noarch/repodata.json.zst" > "$WORK/burst.codes" 2>/dev/null || true
after="$(regenerations)"
oks="$(grep -c '^200$' "$WORK/burst.codes" 2>/dev/null || true)"
etags="$(for i in $(seq 1 24); do header "burst${i}" ETag; done | sort -u | grep -c . || true)"
BURST_ETAG="$(header burst1 ETag)"
d="$(delta "$before" "$after")"
detail="upload HTTP ${st}; ${oks}/24 answered 200; ${etags} distinct ETag(s); ${COUNTER}{format=conda,scope=subdir} ${before} -> ${after}"
echo "  ${detail}"
if { [ "$st" = "201" ] || [ "$st" = "200" ]; } && [ "$oks" = "24" ] && [ "$etags" = "1" ] && [ "$d" = "1" ]; then
  pass
else
  fail "24 cold requests of one revision did not share one render" "$detail"
fi

# =============================================================================
# #4174: warm requests are served the kept bytes
# =============================================================================
begin_test "#4174: 20 warm .zst GETs on 30,000 records: p95 at most 200 ms, same ETag, no render"
before="$(regenerations)"
: > "$WORK/warm.t"; : > "$WORK/warm.etag"; bad=0
for k in $(seq 1 20); do
  out="$(curl -s --max-time 180 -D "$WORK/w.hdr" -o /dev/null -w '%{http_code} %{time_total}' \
    "${BASE_URL}/conda/${H}/noarch/repodata.json.zst" 2>/dev/null || echo "000 0")"
  [ "${out%% *}" = "200" ] || bad=$((bad + 1))
  echo "${out#* }" >> "$WORK/warm.t"
  { grep -i '^etag:' "$WORK/w.hdr" || true; } | tr -d '\r' | cut -d: -f2- | sed 's/^ *//' >> "$WORK/warm.etag"
done
after="$(regenerations)"
P="$(p95 < "$WORK/warm.t")"
same="$(sort -u "$WORK/warm.etag" | grep -c . || true)"
d="$(delta "$before" "$after")"
ms="$(python3 -I -c 'import sys; print("%.1f" % (float(sys.argv[1]) * 1000))' "$P" 2>/dev/null || echo nan)"
detail="p95 ${ms} ms; ${bad} non-200; ${same} distinct ETag(s), burst ETag ${BURST_ETAG:0:14}; counter ${before} -> ${after}"
echo "  ${detail}"
if [ "$bad" = "0" ] && [ "$same" = "1" ] && [ "$(sort -u "$WORK/warm.etag")" = "$BURST_ETAG" ] \
   && [ "$d" = "0" ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= 0.200 else 1)' "$P"; then
  pass
else
  fail "warm requests are not served kept bytes" "$detail"
fi

# =============================================================================
# Withdrawal: one revision, absent from every encoding
# =============================================================================
begin_test "setup: withdraw ${FN2}"
before_wd="$(regenerations)"
wd_st="$(curl -s --max-time 60 -o "$WORK/wd.json" -w '%{http_code}' -X DELETE \
  -H "$(auth_header)" -H 'Content-Type: application/json' -d '{"reason":"dtf conda-repodata-revision"}' \
  "${BASE_URL}/conda/${H}/noarch/${FN2}" 2>/dev/null || echo 000)"
if [ "$wd_st" = "200" ]; then pass; else infra_fail "withdrawal failed" "HTTP ${wd_st} $(head -c 200 "$WORK/wd.json")"; fi

begin_test "CONTROL: the withdrawn file is absent from every encoding, named in removed; the kept version stays"
report=""; ok=1
for spec in "json:repodata.json" "zst:repodata.json.zst" "bz2:repodata.json.bz2" \
            "json:current_repodata.json" "json:run_exports.json"; do
  enc="${spec%%:*}"; doc="${spec#*:}"; tag="$(echo "$doc" | tr '.' '_')"
  st="$(fetch "$tag" "/conda/${H}/noarch/${doc}")"
  r="$(check "$tag" "$enc")"
  report+="${doc}: HTTP ${st} ${r}; "
  listed="$(echo "$r" | jq -r 'if has("listed") then (.listed | tostring) else "err" end' 2>/dev/null || echo err)"
  removed="$(echo "$r" | jq -r 'if has("removed") then (.removed | tostring) else "err" end' 2>/dev/null || echo err)"
  [ "$st" = "200" ] && [ "$listed" = "false" ] || ok=0
  case "$doc" in
    run_exports.json) ;;
    *) [ "$removed" = "true" ] || ok=0 ;;
  esac
  if [ "$enc" = "bz2" ]; then
    [ "$(echo "$r" | jq -r '.trailing_bytes' 2>/dev/null || true)" = "0" ] || ok=0
  fi
done
# FN1 still listed in repodata.json.
grep -q "\"${FN1}\"" "$WORK/repodata_json.body" || { ok=0; report+="${FN1} missing; "; }
# The CEP-16 shard of rev-probe lists only the kept version.
st="$(fetch idx "/conda/${H}/noarch/repodata_shards.msgpack.zst")"
docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
  "$DECODER_IMAGE" python3 -I /app/cep16.py < "$WORK/idx.body" > "$WORK/idx.json" 2>/dev/null || true
A="$(jq -r '.doc.shards["rev-probe"] | if type == "object" then .bin else . end // empty' "$WORK/idx.json" 2>/dev/null || true)"
st2="$(fetch shard "/conda/${H}/noarch/shards/${A:-0}.msgpack.zst")"
docker run --rm -i --security-opt label=disable -v "${CEP16}:/app/cep16.py:ro" \
  "$DECODER_IMAGE" python3 -I /app/cep16.py < "$WORK/shard.body" > "$WORK/shard.json" 2>/dev/null || true
shard_keys="$(jq -c '.doc.packages | keys' "$WORK/shard.json" 2>/dev/null || true)"
report+="shard index HTTP ${st}, shard HTTP ${st2} ${shard_keys}"
[ "$shard_keys" = "[\"${FN1}\"]" ] || ok=0
echo "  ${report}"
if [ "$ok" = "1" ]; then pass; else fail "a withdrawn package is still served" "$report"; fi

begin_test "#4174: the withdrawal moved the subdir to exactly one new revision across every encoding"
after_wd="$(regenerations)"
d="$(delta "$before_wd" "$after_wd")"
if [ "$d" = "1" ]; then
  pass
else
  fail "the withdrawal did not render one new revision" "${COUNTER}{format=conda,scope=subdir} ${before_wd} -> ${after_wd} over json, zst, bz2, current, run_exports"
fi

end_suite
