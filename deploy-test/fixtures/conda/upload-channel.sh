#!/usr/bin/env bash
# =============================================================================
# fixtures/conda/upload-channel.sh: upload a gen-channel.sh channel to a
# hosted conda repository with the native PUT route (artifact-keeper#4187)
# =============================================================================
# Usage: upload-channel.sh DIR REPO
#   env: BASE_URL (required); AUTH_HEADER (a full "Authorization: ..." line)
#        or ADMIN_USER/ADMIN_PASS for Basic; UPLOAD_JOBS (default 8);
#        UPLOAD_ONLY (optional file of "<subdir>/<file>" lines to upload).
#
# PUT ${BASE_URL}/conda/REPO/<subdir>/<file> for every package in DIR, in
# parallel. Idempotent: the repository's <subdir>/repodata.json is read first
# and a package it already lists with the same sha256 is skipped, so a re-run
# after a partial upload sends only what is missing. Prints
# "uploaded=<n> present=<n> failed=<n>" and exits non-zero on any failure,
# listing the failures on stderr. Needs curl, jq, xargs.
# =============================================================================
set -euo pipefail

DIR="${1:?usage: upload-channel.sh DIR REPO}"
REPO="${2:?usage: upload-channel.sh DIR REPO}"
: "${BASE_URL:?upload-channel.sh: set BASE_URL}"
JOBS="${UPLOAD_JOBS:-8}"
if [ -z "${AUTH_HEADER:-}" ]; then
  : "${ADMIN_USER:?upload-channel.sh: set AUTH_HEADER or ADMIN_USER/ADMIN_PASS}"
  AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$ADMIN_USER" "${ADMIN_PASS:?}" | base64 | tr -d '\n')"
fi
export BASE_URL REPO AUTH_HEADER DIR

[ -f "${DIR}/MANIFEST.sha256" ] || { echo "upload-channel.sh: ${DIR} has no MANIFEST.sha256" >&2; exit 2; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# "<sha256> <subdir>/<file>" for every package.
grep -E '^[0-9a-f]{64}  [^/]+/[^/]+\.(conda|tar\.bz2)$' "${DIR}/MANIFEST.sha256" | awk '{print $1, $2}' > "$tmp/all"
if [ -n "${UPLOAD_ONLY:-}" ]; then
  awk 'FILENAME == ARGV[1] {want[$1]=1; next} ($2 in want)' "$UPLOAD_ONLY" "$tmp/all" > "$tmp/f" && mv "$tmp/f" "$tmp/all"
fi

# What the repository already holds: "<sha256> <subdir>/<file>" from each
# subdir's repodata.json (both package maps). The awk filters key on
# FILENAME, not NR==FNR: the first file is empty for a new repository, and
# NR==FNR would then read the second file as the first.
: > "$tmp/have"
for sd in $(cut -d' ' -f2 "$tmp/all" | cut -d/ -f1 | sort -u); do
  curl -s --max-time 120 -H "$AUTH_HEADER" "${BASE_URL}/conda/${REPO}/${sd}/repodata.json" 2>/dev/null \
    | jq -r --arg sd "$sd" '[(.packages // {}), (.["packages.conda"] // {})] | add // {}
        | to_entries[] | "\(.value.sha256 // "") \($sd)/\(.key)"' 2>/dev/null >> "$tmp/have" || true
done
awk 'FILENAME == ARGV[1] {have[$0]=1; next} !($0 in have)' "$tmp/have" "$tmp/all" > "$tmp/todo"
present=$(( $(wc -l < "$tmp/all") - $(wc -l < "$tmp/todo") ))

one() {
  local rel="$2" url code attempt
  url="${BASE_URL}/conda/${REPO}/${rel}"
  for attempt in 1 2 3; do
    code="$(curl -s --max-time 120 -o /dev/null -w '%{http_code}' -X PUT -H "$AUTH_HEADER" \
      -H 'Content-Type: application/octet-stream' --data-binary "@${DIR}/${rel}" "$url" 2>/dev/null || echo 000)"
    case "$code" in
      2??) echo "uploaded ${rel}"; return 0 ;;
      000|5??|429) sleep "$attempt" ;;
      *) echo "failed ${rel} HTTP ${code}"; return 0 ;;
    esac
  done
  echo "failed ${rel} HTTP ${code} after retries"
}
export -f one

xargs -r -P "$JOBS" -n 2 bash -c 'one "$0" "$1"' < "$tmp/todo" > "$tmp/res"
up="$(grep -c '^uploaded ' "$tmp/res" || true)"
fl="$(grep -c '^failed ' "$tmp/res" || true)"
echo "uploaded=${up} present=${present} failed=${fl}"
if [ "$fl" != "0" ]; then grep '^failed ' "$tmp/res" | head -20 >&2; exit 1; fi
