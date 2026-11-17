#!/usr/bin/env bash
# The stub scripts are single-quoted on purpose: they expand when run.
# shellcheck disable=SC2016
#
# Self-test for tests/lib/storage-class.sh (artifact-keeper/artifact-keeper#6081).
#
# Every helm install of the chart into a throwaway test namespace must put its
# PVCs on AK_TEST_STORAGE_CLASS (default local-path-home), not on rocky's
# default class whose volumes sit on the node's root filesystem. This pins:
#
#   unset AK_TEST_STORAGE_CLASS        -> every key set to local-path-home
#   AK_TEST_STORAGE_CLASS=other        -> every key set to other
#   AK_TEST_STORAGE_CLASS= (empty)     -> nothing set (cluster default)
#   class NotFound on the cluster      -> return 1, nothing appended
#   kubectl Forbidden on storageclass  -> warn, keys still set
#   no kubectl on PATH                 -> keys still set
#   existing array entries             -> kept, keys appended after them
#   every script that runs `helm install` / `helm upgrade --install` calls
#   ak_test_storage_class_append (so a new install site cannot skip it)
#
# No cluster needed: kubectl is a stub.
# Run from repo root: bash tests/lib/selftest-storage-class.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="${REPO_ROOT}/tests/lib/storage-class.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/nokubectl"

cat > "$TMP/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
case "${SC_STUB:-found}" in
  found)     echo "storageclass.storage.k8s.io/$3"; exit 0 ;;
  notfound)  echo "Error from server (NotFound): storageclasses.storage.k8s.io \"$3\" not found" >&2; exit 1 ;;
  forbidden) echo 'Error from server (Forbidden): storageclasses.storage.k8s.io is forbidden' >&2; exit 1 ;;
esac
STUB
chmod +x "$TMP/bin/kubectl"
# A PATH with bash and grep but no kubectl, whatever the host has installed.
for tool in bash grep; do ln -s "$(command -v "$tool")" "$TMP/nokubectl/$tool"; done

FAILS=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; FAILS=$((FAILS + 1)); }

# run_case PATH ENV... : sources the lib in a clean bash, appends to an
# array that already holds two entries, prints rc then one arg per line.
run_case() {
  local path="$1"; shift
  env -i PATH="${path}" "$@" bash --noprofile --norc -c '
    source "$1"
    ARGS=(helm upgrade)
    ak_test_storage_class_append ARGS >/dev/null 2>"$2/stderr"
    echo "rc=$?"
    printf "%s\n" "${ARGS[@]}"
  ' _ "$LIB" "$TMP"
}

# expect_all OUT CLASS: the two seed entries, then --set-string KEY=CLASS for
# every key in the lib's list, in order.
expect_all() {
  local got="$1" sc="$2" want key
  # shellcheck source=storage-class.sh
  want="$(source "$LIB"; echo "rc=0"; printf '%s\n' helm upgrade
    for key in "${AK_TEST_STORAGE_CLASS_KEYS[@]}"; do printf '%s\n' --set-string "${key}=${sc}"; done)"
  [ "$got" = "$want" ]
}

echo "storage-class.sh"

out="$(run_case "$TMP/bin:/usr/bin:/bin")"
if expect_all "$out" local-path-home; then ok "unset -> local-path-home on every key"; else bad "unset -> local-path-home"; echo "$out"; fi

out="$(run_case "$TMP/bin:/usr/bin:/bin" AK_TEST_STORAGE_CLASS=fast-ssd)"
if expect_all "$out" fast-ssd; then ok "override -> that class on every key"; else bad "override"; echo "$out"; fi

out="$(run_case "$TMP/bin:/usr/bin:/bin" AK_TEST_STORAGE_CLASS=)"
if [ "$out" = "$(printf 'rc=0\nhelm\nupgrade')" ]; then ok "empty -> nothing set"; else bad "empty -> nothing set"; echo "$out"; fi

out="$(run_case "$TMP/bin:/usr/bin:/bin" SC_STUB=notfound)"
if [ "$out" = "$(printf 'rc=1\nhelm\nupgrade')" ] && grep -q "does not exist" "$TMP/stderr"; then
  ok "NotFound -> rc 1, nothing appended"
else bad "NotFound"; echo "$out"; cat "$TMP/stderr"; fi

out="$(run_case "$TMP/bin:/usr/bin:/bin" SC_STUB=forbidden)"
if expect_all "$out" local-path-home && grep -q "WARN" "$TMP/stderr"; then ok "Forbidden -> warn, keys set"; else bad "Forbidden"; echo "$out"; fi

out="$(run_case "$TMP/nokubectl")"
if expect_all "$out" local-path-home; then ok "no kubectl -> keys set"; else bad "no kubectl"; echo "$out"; fi

# Contract: every script that installs the chart goes through the helper.
missing=()
while IFS= read -r f; do
  grep -q 'ak_test_storage_class_append' "$f" || missing+=("${f#"$REPO_ROOT"/}")
done < <(grep -rlE '^[^#]*helm (upgrade --install|install) ' "$REPO_ROOT/scripts" "$REPO_ROOT/tests" "$REPO_ROOT/deploy-test" 2>/dev/null \
  | grep -E '\.sh$' | grep -v '/selftest-')
if [ "${#missing[@]}" -eq 0 ]; then
  ok "every helm install site calls ak_test_storage_class_append"
else
  bad "helm install without ak_test_storage_class_append: ${missing[*]}"
fi

if [ "$FAILS" -ne 0 ]; then
  echo "storage-class self-test: ${FAILS} failure(s)"
  exit 1
fi
echo "storage-class self-test: all passed"
