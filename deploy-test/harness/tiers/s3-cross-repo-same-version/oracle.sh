#!/usr/bin/env bash
# =============================================================================
# tiers/s3-cross-repo-same-version/oracle.sh
#   Two hosted repositories of one format publish the same version on S3
#   storage (artifact-keeper#5662).
# =============================================================================
# run.sh has stood up `storage.s3` with RATE_LIMIT_ENABLED=false and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Per format: create hosted repositories A and B, publish one version into A
# (CONTROL: 2xx, downloads byte-exact), publish the same version (same bytes)
# into B (#5662: 2xx), then download from both and compare bytes. Before the
# fix the flat cloud key `<format>/<name>/<version>/<file>` was already owned
# by A, so B's publish answered 409 "refusing cross-repository overwrite".
# Fixtures are generated at run time (tar/gzip only).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it.
set +e

SUF="${RANDOM}${RANDOM}"
WORK="$(mktemp -d -t dtf-s3xr-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

AUTHZ=()
code_to_file() { # URL OUTFILE [curl args...] -> http code
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' --max-time 60 "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
snip() { head -c 240 "$1" 2>/dev/null | tr '\n\r' '  '; }
mk_repo() { # KEY FORMAT -> code
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-$1.json" -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
}

# --- fixtures ---------------------------------------------------------------
# Each builder writes $WORK/<fmt>.pkg (the bytes that are published and must
# come back) plus whatever side files its publish needs.
CRAN_PKG="xrcran${SUF}"
HELM_CHART="xrchart${SUF}"
CHEF_CB="xrcb${SUF}"
PUPPET_OWNER="dtf"; PUPPET_NAME="xrmod${SUF}"
GEM_NAME="xrgem${SUF}"
HEX_NAME="xrhex${SUF}"

build_fixtures() {
  local d
  d="${WORK}/src-cran/${CRAN_PKG}"; mkdir -p "$d"
  printf 'Package: %s\nVersion: 1.0.0\nTitle: DTF #5662 fixture\n' "$CRAN_PKG" > "$d/DESCRIPTION"
  tar -czf "${WORK}/cran.pkg" -C "${WORK}/src-cran" "$CRAN_PKG"

  d="${WORK}/src-helm/${HELM_CHART}"; mkdir -p "$d"
  printf 'apiVersion: v2\nname: %s\nversion: 0.1.0\ndescription: DTF #5662 fixture\n' "$HELM_CHART" > "$d/Chart.yaml"
  tar -czf "${WORK}/helm.pkg" -C "${WORK}/src-helm" "$HELM_CHART"

  d="${WORK}/src-chef/${CHEF_CB}"; mkdir -p "$d"
  printf "name '%s'\nversion '1.0.0'\n" "$CHEF_CB" > "$d/metadata.rb"
  tar -czf "${WORK}/chef.pkg" -C "${WORK}/src-chef" "$CHEF_CB"
  jq -nc --arg n "$CHEF_CB" '{cookbook_name:$n,cookbook_version:"1.0.0"}' > "${WORK}/chef.meta"

  d="${WORK}/src-puppet/${PUPPET_OWNER}-${PUPPET_NAME}-1.0.0"; mkdir -p "$d"
  jq -nc --arg o "$PUPPET_OWNER" --arg n "$PUPPET_NAME" \
    '{name:($o+"-"+$n),version:"1.0.0",author:$o,summary:"DTF #5662 fixture",dependencies:[]}' > "$d/metadata.json"
  tar -czf "${WORK}/puppet.pkg" -C "${WORK}/src-puppet" "${PUPPET_OWNER}-${PUPPET_NAME}-1.0.0"
  jq -nc --arg o "$PUPPET_OWNER" --arg n "$PUPPET_NAME" \
    '{owner:$o,name:$n,version:"1.0.0",summary:"DTF #5662 fixture",dependencies:[]}' > "${WORK}/puppet.meta"

  d="${WORK}/src-gem"; mkdir -p "$d"
  printf -- '--- !ruby/object:Gem::Specification\nname: %s\nversion: !ruby/object:Gem::Version\n  version: 1.0.0\nplatform: ruby\nsummary: DTF #5662 fixture\n' "$GEM_NAME" \
    | gzip -c > "$d/metadata.gz"
  tar -cf "${WORK}/rubygems.pkg" -C "$d" metadata.gz

  d="${WORK}/src-hex"; mkdir -p "$d"
  printf '{<<"name">>, <<"%s">>}.\n{<<"version">>, <<"1.0.0">>}.\n' "$HEX_NAME" > "$d/metadata.config"
  printf 'DTF #5662 fixture %s\n' "$HEX_NAME" > "$d/lib.ex"
  tar -czf "$d/contents.tar.gz" -C "$d" lib.ex
  printf '3' > "$d/VERSION"
  # The outer CHECKSUM is the sha256 of VERSION + metadata.config + contents.tar.gz.
  cat "$d/VERSION" "$d/metadata.config" "$d/contents.tar.gz" | sha256sum | awk '{print toupper($1)}' | tr -d '\n' > "$d/CHECKSUM"
  tar -cf "${WORK}/hex.pkg" -C "$d" VERSION CHECKSUM metadata.config contents.tar.gz
}

# --- per-format publish (REPO OUTFILE -> code) and download path (REPO) -------
pub_cran() { code_to_file "${BASE_URL}/cran/$1/src/contrib/${CRAN_PKG}_1.0.0.tar.gz" "$2" -X PUT "${AUTHZ[@]}" \
  -H 'Content-Type: application/gzip' --data-binary "@${WORK}/cran.pkg"; }
dl_cran() { echo "${BASE_URL}/cran/$1/src/contrib/${CRAN_PKG}_1.0.0.tar.gz"; }

pub_helm() { code_to_file "${BASE_URL}/helm/$1/api/charts" "$2" -X POST "${AUTHZ[@]}" \
  -F "chart=@${WORK}/helm.pkg;filename=${HELM_CHART}-0.1.0.tgz;type=application/octet-stream"; }
dl_helm() { echo "${BASE_URL}/helm/$1/charts/${HELM_CHART}-0.1.0.tgz"; }

pub_chef() { code_to_file "${BASE_URL}/chef/$1/api/v1/cookbooks" "$2" -X POST "${AUTHZ[@]}" \
  -F "cookbook=<${WORK}/chef.meta" \
  -F "tarball=@${WORK}/chef.pkg;filename=${CHEF_CB}-1.0.0.tar.gz;type=application/gzip"; }
dl_chef() { echo "${BASE_URL}/chef/$1/api/v1/cookbooks/${CHEF_CB}/versions/1.0.0/download"; }

pub_puppet() { code_to_file "${BASE_URL}/puppet/$1/v3/releases" "$2" -X POST "${AUTHZ[@]}" \
  -F "module=<${WORK}/puppet.meta" \
  -F "file=@${WORK}/puppet.pkg;filename=${PUPPET_OWNER}-${PUPPET_NAME}-1.0.0.tar.gz;type=application/octet-stream"; }
dl_puppet() { echo "${BASE_URL}/puppet/$1/v3/files/${PUPPET_OWNER}-${PUPPET_NAME}-1.0.0.tar.gz"; }

pub_rubygems() { code_to_file "${BASE_URL}/gems/$1/api/v1/gems" "$2" -X POST "${AUTHZ[@]}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/rubygems.pkg"; }
dl_rubygems() { echo "${BASE_URL}/gems/$1/gems/${GEM_NAME}-1.0.0.gem"; }

pub_hex() { code_to_file "${BASE_URL}/hex/$1/publish" "$2" -X POST "${AUTHZ[@]}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/hex.pkg"; }
dl_hex() { echo "${BASE_URL}/hex/$1/tarballs/${HEX_NAME}-1.0.0.tar"; }

FORMATS="cran helm chef puppet rubygems hex"

begin_suite "s3-cross-repo-same-version"
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

build_fixtures
SF=""
for f in $FORMATS; do
  [ -s "${WORK}/${f}.pkg" ] || SF="${SF} fixture-${f}"
  for side in a b; do
    c="$(mk_repo "xr-${f}-${side}-${DTF_SLOT}-${SUF}" "$f")"; is_2xx "$c" || SF="${SF} repo-${f}-${side}=${c}"
  done
done
if [ -n "$SF" ]; then
  begin_test "setup: two hosted repositories per format and generated fixtures"
  infra_fail "setup failed:${SF}" "$(snip "$(ls "${WORK}"/mk-*.json 2>/dev/null | head -1)")"
  end_suite
fi

for f in $FORMATS; do
  A="xr-${f}-a-${DTF_SLOT}-${SUF}"; B="xr-${f}-b-${DTF_SLOT}-${SUF}"
  PKG="${WORK}/${f}.pkg"

  begin_test "CONTROL ${f}: publishing version 1.0.0 into the first repository is 2xx and downloads byte-exact"
  pa="$("pub_${f}" "$A" "${WORK}/${f}-pa.out")"
  da="$(code_to_file "$("dl_${f}" "$A")" "${WORK}/${f}-da.bin" "${AUTHZ[@]}" -L)"
  if is_2xx "$pa" && [ "$da" = "200" ] && cmp -s "${WORK}/${f}-da.bin" "$PKG"; then pass; else
    fail "${f}: publish A=${pa} download A=${da} byte-exact=$(cmp -s "${WORK}/${f}-da.bin" "$PKG" && echo yes || echo no)" \
      "publish: $(snip "${WORK}/${f}-pa.out") download: $(snip "${WORK}/${f}-da.bin")"
  fi

  begin_test "#5662 ${f}: publishing the same version into a second repository on S3 is 2xx (not 409 cross-repository overwrite)"
  pb="$("pub_${f}" "$B" "${WORK}/${f}-pb.out")"
  if is_2xx "$pb"; then pass; else
    fail "${f}: publish B=${pb} (want 2xx). Pre-#5662 the flat cloud key was owned by repository A and the publish answered 409" \
      "$(snip "${WORK}/${f}-pb.out")"
  fi

  begin_test "#5662 ${f}: both repositories serve the published bytes after the second publish"
  da2="$(code_to_file "$("dl_${f}" "$A")" "${WORK}/${f}-da2.bin" "${AUTHZ[@]}" -L)"
  db="$(code_to_file "$("dl_${f}" "$B")" "${WORK}/${f}-db.bin" "${AUTHZ[@]}" -L)"
  ea="$(cmp -s "${WORK}/${f}-da2.bin" "$PKG" && echo yes || echo no)"
  eb="$(cmp -s "${WORK}/${f}-db.bin" "$PKG" && echo yes || echo no)"
  if [ "$da2" = "200" ] && [ "$db" = "200" ] && [ "$ea" = yes ] && [ "$eb" = yes ]; then pass; else
    fail "${f}: download A=${da2} byte-exact=${ea}; download B=${db} byte-exact=${eb}" "B: $(snip "${WORK}/${f}-db.bin")"
  fi
done

end_suite
