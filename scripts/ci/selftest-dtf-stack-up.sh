#!/usr/bin/env bash
# selftest-dtf-stack-up.sh - pins what the DTF harness does when a tier's
# compose stack does not come up healthy (artifact-keeper-test#890).
#
# The 1.12.0 candidate lost a tier to the OpenLDAP fixture exiting 1 at start,
# and the log held nothing but "stack failed to come up healthy": the fixture's
# output went with `down -v`. Pinned here, against the real run-tiers.sh,
# run.sh and lib/stack_diag.sh with a stub docker (no daemon, no network):
#
#   1. Before teardown, every unhealthy container's state line, inspect
#      ExitCode/Error/OOMKilled and `docker logs --tail` are printed; healthy
#      containers get a state line only.
#   2. A fixture that exited non-zero while every candidate container was
#      still `created` is retried once from a clean slot (down, then up). A
#      retry that comes up runs the oracle; the tier's summary line says it
#      was retried.
#   3. The same crash on the retry exits 11 (INFRA), never 7 or 1.
#   4. A candidate (by image ref or by its backend* compose service) that ran,
#      unhealthy or exited, is NOT retried and stays exit 7, as is a crash
#      seen on the retry after the candidate ran, and anything under --keep.
#
# Usage: scripts/ci/selftest-dtf-stack-up.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

ok()  { echo "  PASS  $1"; }
bad() { echo "  FAIL  $1"; fails=$((fails + 1)); }

# A private copy of the harness with one fake tier whose oracle passes.
DT="$WORK/deploy-test"
mkdir -p "$DT/profiles" "$DT/harness/tiers/t" "$WORK/bin" "$WORK/state"
cp -R "$ROOT/deploy-test/harness/lib" "$DT/harness/lib"
cp "$ROOT/deploy-test/harness/run.sh" "$ROOT/deploy-test/harness/run-tiers.sh" "$DT/harness/"
cp "$ROOT/deploy-test/compose.base.yml" "$DT/"
cp "$ROOT/deploy-test/profiles/storage.filesystem.yml" "$DT/profiles/"
printf 'PROFILES="storage.filesystem"\nORACLE="oracle.sh"\n' > "$DT/harness/tiers/t/manifest"
printf '#!/usr/bin/env bash\necho ORACLE-RAN\nexit 0\n' > "$DT/harness/tiers/t/oracle.sh"
chmod +x "$DT/harness/run.sh" "$DT/harness/run-tiers.sh"

# Stub docker. `compose ... up` number N exits word N of STUB_UP_RCS; after
# it, the project's containers are $STATE/ctrs.N ("name|status|health|exit|
# image" per line). inspect/logs answer from the current attempt's table.
cat > "$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
S="$STUB_STATE"
n=$(cat "$S/ups" 2>/dev/null || echo 0)
row() { grep "^$1|" "$S/ctrs.$n" 2>/dev/null; }
case "$1" in
  pull) exit 0 ;;
  compose)
    for a in "$@"; do
      case "$a" in
        up) n=$((n + 1)); echo "$n" > "$S/ups"; echo "up $n" >> "$S/calls"
            read -r -a rcs <<< "$STUB_UP_RCS"; exit "${rcs[$((n-1))]:-0}" ;;
        down) echo "down" >> "$S/calls"; exit 0 ;;
      esac
    done
    exit 0 ;;
  ps)
    case "$*" in
      *label=com.docker.compose.project=*) cut -d'|' -f1 "$S/ctrs.$n" 2>/dev/null ;;
    esac
    exit 0 ;;
  inspect)
    fmt="$3"; name="$4"
    IFS='|' read -r _ st he ex im <<< "$(row "$name")"
    [ -n "$st" ] || exit 1
    case "$fmt" in
      '{{.State.Status}}|'*) echo "${st}|${he}|${ex}|${im}|${name#ak-dtf1-}" ;;
      'status='*) echo "status=${st} health=${he} exit=${ex} oom=false error=" ;;
      '{{.State.ExitCode}} '*) echo "${ex}  false" ;;
      *Health.Log*) echo "1: HEALTHCHECK-OUTPUT ${name}" ;;
      *) echo "bridge" ;;
    esac
    exit 0 ;;
  logs) echo "LOG-TAIL ${*: -1}"; exit 0 ;;
esac
exit 0
EOF
chmod +x "$WORK/bin/docker"

IMG="img:cand"
LDAP_CRASH="ak-dtf1-ldap|exited|none|1|osixia/openldap:1.5.0
ak-dtf1-db|running|healthy|0|postgres:16
ak-dtf1-backend|created|none|0|${IMG}"
BACKEND_SICK="ak-dtf1-ldap|running|healthy|0|osixia/openldap:1.5.0
ak-dtf1-db|running|healthy|0|postgres:16
ak-dtf1-backend|running|unhealthy|0|${IMG}"
BACKEND_RAN_LDAP_CRASH="ak-dtf1-ldap|exited|none|1|osixia/openldap:1.5.0
ak-dtf1-backend|exited|none|101|${IMG}"
INIT_DONE="ak-dtf1-mkbucket|exited|none|0|minio/mc
ak-dtf1-backend|created|none|0|${IMG}"
NO_CANDIDATE="ak-dtf1-ldap|exited|none|1|osixia/openldap:1.5.0"
# The candidate's image ref recorded differently: its compose service still
# marks it as the candidate.
RESPELLED_RAN="ak-dtf1-ldap|exited|none|1|osixia/openldap:1.5.0
ak-dtf1-backend|running|unhealthy|0|docker.io/library/${IMG}"

# scenario <label> <want rc> <want calls> <STUB_UP_RCS> <ctrs.1> <ctrs.2> <regex>... [-- <driver args>]
# Runs run-tiers.sh on tier t (or run.sh with the args after --); every regex
# must match the output, a regex starting with '!' must not.
scenario() {
  local label="$1" want="$2" want_calls="$3" rcs="$4" c1="$5" c2="$6"; shift 6
  local res=() drv=("$DT/harness/run-tiers.sh" --backend-image "$IMG" t)
  while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then shift; drv=("$DT/harness/run.sh" "$@"); break; fi
    res+=("$1"); shift
  done
  rm -rf "$WORK/state"; mkdir -p "$WORK/state"
  printf '%s\n' "$c1" > "$WORK/state/ctrs.1"
  printf '%s\n' "$c2" > "$WORK/state/ctrs.2"
  local out rc calls r miss=""
  out="$(env -i PATH="$WORK/bin:$PATH" HOME="$WORK" STUB_STATE="$WORK/state" STUB_UP_RCS="$rcs" \
    AK_TEST_ROOT="$ROOT" DTF_SLOT_PIN=1 "${drv[@]}" 2>&1)"; rc=$?
  calls="$(paste -sd';' "$WORK/state/calls" 2>/dev/null)"
  for r in "${res[@]}"; do
    if [ "${r#!}" != "$r" ]; then
      grep -Eq -- "${r#!}" <<< "$out" && miss="$miss [matched $r]"
    else
      grep -Eq -- "$r" <<< "$out" || miss="$miss [no $r]"
    fi
  done
  if [ "$rc" = "$want" ] && [ "$calls" = "$want_calls" ] && [ -z "$miss" ]; then
    ok "$label"
  else
    bad "$label: exit $rc (want $want), calls '$calls' (want '$want_calls')$miss"
    printf '%s\n' "$out" | tail -n 40 | sed 's/^/        /'
  fi
}

echo "stack-up failure: diagnostics, fixture retry, classification"
scenario "fixture crash, retry comes up: oracle runs, PASS notes the retry" 0 "up 1;down;up 2;down" "1 0" \
  "$LDAP_CRASH" "" \
  'status=exited health=none exit=1' '^1  false$' 'LOG-TAIL ak-dtf1-ldap' \
  'never started \(compose did not start it' '!LOG-TAIL ak-dtf1-db' \
  '::warning title=DTF fixture retry::t: .*ak-dtf1-ldap exited 1' 'ORACLE-RAN' \
  'PASS  t \[fixture crash at stack-up \(ak-dtf1-ldap exited 1\), retried once\]'
scenario "fixture crash twice: INFRA (11), oracle never runs" 11 "up 1;down;up 2;down" "1 1" \
  "$LDAP_CRASH" "$LDAP_CRASH" \
  'INFRA t \(INFRA/SETUP.*\[fixture crash at stack-up \(ak-dtf1-ldap exited 1\), again on the one retry\]' \
  '!ORACLE-RAN' '!FAIL  t'
scenario "candidate unhealthy: no retry, stack-up FAIL (7), backend logs and healthcheck printed" 1 "up 1;down" "1" \
  "$BACKEND_SICK" "" \
  'LOG-TAIL ak-dtf1-backend' 'HEALTHCHECK-OUTPUT ak-dtf1-backend' '!LOG-TAIL ak-dtf1-ldap' \
  'FAIL  t \(stack-up: candidate/sidecar never healthy, rc=7\)$' '!retry'
scenario "fixture crash but the candidate ran too: no retry (7)" 1 "up 1;down" "1" \
  "$BACKEND_RAN_LDAP_CRASH" "" 'LOG-TAIL ak-dtf1-ldap' 'LOG-TAIL ak-dtf1-backend' 'rc=7\)$'
scenario "fixture crash, then the candidate fails on the retry: 7, retry noted" 1 "up 1;down;up 2;down" "1 1" \
  "$LDAP_CRASH" "$BACKEND_SICK" \
  'FAIL  t \(stack-up: candidate/sidecar never healthy, rc=7\) \[fixture crash at stack-up \(ak-dtf1-ldap exited 1\), retried once\]'
scenario "candidate found by compose service, not image ref: it ran, no retry (7)" 1 "up 1;down" "1" \
  "$RESPELLED_RAN" "" 'LOG-TAIL ak-dtf1-backend' 'rc=7\)$'
scenario "a one-shot that exited 0 is not a crash: no retry (7)" 1 "up 1;down" "1" \
  "$INIT_DONE" "" '!LOG-TAIL ak-dtf1-mkbucket' 'rc=7\)$'
scenario "no candidate container in the project: no retry (7)" 1 "up 1;down" "1" \
  "$NO_CANDIDATE" "" 'LOG-TAIL ak-dtf1-ldap' 'rc=7\)$'
scenario "--keep: diagnostics printed, no retry, no teardown (run.sh 7)" 7 "up 1" "1" \
  "$LDAP_CRASH" "" 'LOG-TAIL ak-dtf1-ldap' '!retry' \
  -- t --backend-image "$IMG" --keep

if [ "$fails" -ne 0 ]; then
  echo "dtf stack-up selftest: $fails case(s) FAILED"
  exit 1
fi
echo "dtf stack-up selftest: all cases passed"
