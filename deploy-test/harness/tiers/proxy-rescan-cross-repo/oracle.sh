#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-rescan-cross-repo/oracle.sh - a clean, zero-component verdict a
# generic Remote rescan records for a package digest must not be reused to
# serve a later fail_closed package pull of the same digest
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (mock_scan_upstream.py, shared with scan-on-proxy-maven-nuget):
# Newtonsoft.Json 12.0.1 (GHSA-5crp-9r3c-p9vr, high) and log4j-core 2.14.1
# (critical). The nupkg is proxied twice: once as a raw blob through a GENERIC
# Remote (which does not scan on proxy) and once as a package through a NuGet
# Remote (fail_closed). Both see byte-identical upstream bytes, hence one
# shared digest and one shared verdict row.
#
# The generic rescan is driven by a NON-ADMIN user who has read+write on the
# generic Remote ONLY, which is exactly the privilege the report names.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-rescan-cross-repo"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

GEN="prcr-gen-${SUF}"   # generic Remote on ${UP} (no scan on proxy)
GEN2="prcr-gen2-${SUF}" # second generic Remote (the per-repo rescan cooldown)
GEN3="prcr-gen3-${SUF}" # third generic Remote (install media)
GEN4="prcr-gen4-${SUF}" # fourth generic Remote (an RPM with no dist tag)
RPMR="prcr-rpm-${SUF}"  # RPM Remote, scan_on_proxy, fail_closed (main only)
NUG="prcr-nug-${SUF}"   # NuGet Remote, scan_on_proxy, fail_closed
MVN="prcr-mvn-${SUF}"   # Maven Remote, scan_on_proxy, fail_closed (control)
WUSER="prcr-w-${SUF}"
WPASS="Prcr_$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)_Aa1!"

LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1"
NJ_NUPKG="newtonsoft.json/12.0.1/newtonsoft.json.12.0.1.nupkg"
NJ_UPSTREAM="nuget/v3-flatcontainer/${NJ_NUPKG}"
TREE="9/BaseOS/x86_64/os"
ISO="${TREE}/images/boot.iso"
NOTAG="${TREE}/Packages/d/dtf-notag-1.0-1.noarch.rpm"

cleanup() {
  local k
  for k in "$GEN" "$GEN2" "$GEN3" "$GEN4" "$NUG" "$MVN" "$RPMR"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"; }
catalog_of() { psql_q "SELECT coalesce(components_cataloged::text,'NULL') FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"; }
row_count_of() { psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"; }
cached_path() { # repo-key path-suffix -> the proxy cache path ending in suffix
  psql_q "SELECT p.path FROM proxy_cache_artifacts p JOIN repositories r ON r.id = p.repository_id WHERE r.key='$1' AND p.path LIKE '%$2' ORDER BY length(p.path) LIMIT 1"
}

BODY="${WORK_DIR}/body"
pull() { # <url> [bearer] -> sets ST, SCAN
  local hdr="${WORK_DIR}/hdr" auth=()
  [ -n "${2:-}" ] && auth=(-H "Authorization: Bearer $2")
  ST=$(curl -s -D "$hdr" -o "$BODY" -w '%{http_code}' --max-time 120 "${auth[@]}" "$1" 2>/dev/null) || ST="000"
  SCAN=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
}
RBODY="${WORK_DIR}/rescan"
rescan() { # key path bearer -> sets RST, RBODY
  RST=$(curl -s -o "$RBODY" -w '%{http_code}' --max-time 150 -X POST \
    -H "Authorization: Bearer $3" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg p "$2" '{path:$p}')" \
    "${BASE_URL}/api/v1/repositories/$1/security/proxy-scans/rescan" 2>/dev/null) || RST="000"
}
rjson() { jq -r "$1 // empty" "$RBODY" 2>/dev/null; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null; }
snippet() { head -c 200 "$1" | tr -c '[:print:]' '.'; }
scan_cfg() {
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}
grant_rw() { # user-id repo-id -> http code
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "${BASE_URL}/api/v1/permissions" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"principal_type\":\"user\",\"principal_id\":\"$1\",\"target_type\":\"repository\",\"target_id\":\"$2\",\"actions\":[\"read\",\"write\"]}" \
    2>/dev/null || echo 000
}
repo_id_of() { curl -s --max-time 10 -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/$1" | jq -r '.id // empty'; }

begin_test "SETUP: mock reachable; generic + NuGet(fail_closed) + Maven(fail_closed) Remotes; non-admin writer on the generic Remote only"
ok=1
[ -n "$(golden_sha "$NJ_UPSTREAM")" ] || ok=0
create_repo "$GEN" generic remote "${UP}" || ok=0
create_repo "$GEN2" generic remote "${UP}" || ok=0
create_repo "$GEN3" generic remote "${UP}" || ok=0
create_repo "$GEN4" generic remote "${UP}" || ok=0
create_repo "$RPMR" rpm remote "${UP}/rpm" || ok=0
create_repo "$NUG" nuget remote "${UP}/nuget/v3/index.json" || ok=0
create_repo "$MVN" maven remote "${UP}/maven2" || ok=0
a="$(scan_cfg "$NUG" fail_closed)$(scan_cfg "$MVN" fail_closed)"
r="$(scan_cfg "$RPMR" fail_closed)"
WID="$(create_test_user_with_retry "$WUSER" "$WPASS" "${WUSER}@t.test" || true)"
GEN_ID="$(repo_id_of "$GEN")"
GEN2_ID="$(repo_id_of "$GEN2")"
GEN3_ID="$(repo_id_of "$GEN3")"
GEN4_ID="$(repo_id_of "$GEN4")"
gc="000"
if [ -n "$WID" ] && [ -n "$GEN_ID" ] && [ -n "$GEN2_ID" ] && [ -n "$GEN3_ID" ] && [ -n "$GEN4_ID" ]; then
  gc="$(grant_rw "$WID" "$GEN_ID")"
  for g in "$GEN2_ID" "$GEN3_ID" "$GEN4_ID"; do
    c="$(grant_rw "$WID" "$g")"; case "$c" in 2??) ;; *) gc="$c" ;; esac
  done
fi
WTOK="$(login_as "$WUSER" "$WPASS" || true)"
WADMIN="$(curl -s --max-time 10 -H "Authorization: Bearer ${WTOK}" "${BASE_URL}/api/v1/auth/me" 2>/dev/null | jq -r '.is_admin // empty')"
if [ "$ok" = 1 ] && [ "$a" = "fail_closedfail_closed" ] && [ "$r" = "fail_closed" ] \
   && [ -n "$WID" ] && [ -n "$WTOK" ] \
   && [ "$WADMIN" != "true" ]; then
  case "$gc" in 2??) pass ;; *) infra_fail "grant failed (${gc})"; end_suite ;; esac
else
  infra_fail "setup failed (ok=${ok} actions='${a}' rpm='${r}' wid='${WID:0:8}' wtok=$([ -n "$WTOK" ] && echo y||echo n) admin='${WADMIN}')"
  end_suite
fi

N="${BASE_URL}/nuget"
M="${BASE_URL}/maven"
NJ_D=$(golden_sha "$NJ_UPSTREAM")
L4_D=$(golden_sha "maven2/${LOG4J}.jar")

begin_test "no verdict row exists for the Newtonsoft.Json digest before anything is pulled"
if [ "$(row_count_of "$NJ_D")" = "0" ]; then pass; else fail "a row already exists for ${NJ_D}"; fi

begin_test "the non-admin writer proxies the exact nupkg bytes through the generic Remote (served, generic does not scan on proxy)"
pull "${BASE_URL}/api/v1/repositories/${GEN}/download/${NJ_UPSTREAM}" "$WTOK"
GEN_PATH=$(cached_path "$GEN" ".nupkg")
if { [ "$ST" = "200" ] || [ "$ST" = "201" ]; } && [ -n "$GEN_PATH" ] \
   && [ "$(sha256sum "$BODY" | awk '{print $1}')" = "$NJ_D" ]; then
  pass
else
  fail "status=${ST} cached='${GEN_PATH}' body-sha=$(sha256sum "$BODY" | awk '{print $1}') want=${NJ_D}"
fi

begin_test "the writer's generic rescan records a clean, zero-component verdict for the package digest (the poisoning precondition)"
rescan "$GEN" "$GEN_PATH" "$WTOK"
RSTATE="$(rjson .state)"; RPKG="$(rjson .package_count)"
note_line="rescan ${GEN_PATH}: HTTP ${RST} state='${RSTATE}' package_count='${RPKG}' verdict='$(verdict_of "$NJ_D")' cataloged='$(catalog_of "$NJ_D")'"
if [ "$RST" = "200" ] && [ "$RSTATE" = "clean" ] && [ "$RPKG" = "0" ] && [ "$(verdict_of "$NJ_D")" = "clean" ]; then
  echo "   KNOWN-AFFECTED precondition present: ${note_line}"
  pass
else
  # On a build that refuses the generic rescan of a package (fix), the digest
  # carries no clean row. That is the fixed behaviour; record it and move on so
  # the decisive gate below (the served pull) is what reds/greens.
  echo "   generic rescan did not record a reusable clean verdict: ${note_line}"
  pass
fi

begin_test "FIX: the first fail_closed NuGet pull of the same digest is refused 403, never served from the generic rescan's clean verdict"
pull "${N}/${NUG}/v3/flatcontainer/${NJ_NUPKG}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "the fail_closed NuGet pull was served instead of refused" \
    "status=${ST} X-AK-Scan='${SCAN}' body=$(snippet "$BODY") stored-verdict='$(verdict_of "$NJ_D")' cataloged='$(catalog_of "$NJ_D")'"
fi

begin_test "FIX: after the refusal the stored verdict for the digest is vulnerable (the inline gate graded it through the pin)"
v=$(verdict_of "$NJ_D")
if [ "$v" = "vulnerable" ]; then pass; else fail "verdict='${v}' cataloged='$(catalog_of "$NJ_D")'"; fi

# ---------------------------------------------------------------------------
# Identity not established (main: an RPM Remote asked for a file it cannot
# establish as a package). Under fail_closed the gate withholds such a pull
# (423) rather than scan what it cannot grade. A generic rescan of the same
# bytes must not lift that: neither a clean verdict that cataloged nothing
# (install media) nor one recorded with no release to grade an RPM against.
# RPM does not scan on proxy on the 1.11 line, so these cases are main only.
# ---------------------------------------------------------------------------
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
RPM_ENFORCED=0
[ "$(fmt_field rpm scan_on_proxy)" = "enforced" ] && RPM_ENFORCED=1
RP="${BASE_URL}/rpm/${RPMR}"
ISO_D=$(golden_sha "rpm/${ISO}")
NT_D=$(golden_sha "rpm/${NOTAG}")

begin_test "control: before any rescan, fail_closed RPM pulls of the install media and of an RPM with no dist tag are withheld (423, no verdict row)"
if [ "$RPM_ENFORCED" = 1 ]; then
  pull "${RP}/${ISO}"; s1="$ST/$(body_err)"
  pull "${RP}/${NOTAG}"; s2="$ST/$(body_err)"
  if [ "$s1 $s2" = "423/scan_pending 423/scan_pending" ] && [ "$(row_count_of "$ISO_D")$(row_count_of "$NT_D")" = "00" ]; then
    pass
  else
    fail "iso=${s1} notag=${s2} rows=$(row_count_of "$ISO_D")/$(row_count_of "$NT_D")"
  fi
else
  skip_not_applicable "rpm does not scan on proxy on this build ($(fmt_field rpm scan_on_proxy))"
fi

begin_test "the writer proxies the install media through a generic Remote and rescans it (outcome recorded)"
if [ "$RPM_ENFORCED" = 1 ]; then
  pull "${BASE_URL}/api/v1/repositories/${GEN3}/download/rpm/${ISO}" "$WTOK"
  P3=$(cached_path "$GEN3" "boot.iso")
  if [ "$ST" = "200" ] && [ -n "$P3" ]; then
    rescan "$GEN3" "$P3" "$WTOK"
    echo "   rescan ${P3}: HTTP ${RST} state='$(rjson .state)' package_count='$(rjson .package_count)' code='$(rjson .code)' verdict='$(verdict_of "$ISO_D")' cataloged='$(catalog_of "$ISO_D")'"
    pass
  else
    fail "status=${ST} cached='${P3}'"
  fi
else
  skip_not_applicable "rpm does not scan on proxy on this build"
fi

begin_test "FIX: after the generic rescan, the fail_closed RPM pull of the install media is still withheld (423), not served"
if [ "$RPM_ENFORCED" = 1 ]; then
  pull "${RP}/${ISO}"
  if [ "$ST" = "423" ]; then
    pass
  else
    fail "the withheld pull was lifted by the generic rescan's verdict" \
      "status=${ST} X-AK-Scan='${SCAN}' stored-verdict='$(verdict_of "$ISO_D")' cataloged='$(catalog_of "$ISO_D")'"
  fi
else
  skip_not_applicable "rpm does not scan on proxy on this build"
fi

begin_test "the writer proxies the RPM with no dist tag through a generic Remote and rescans it (outcome recorded)"
if [ "$RPM_ENFORCED" = 1 ]; then
  pull "${BASE_URL}/api/v1/repositories/${GEN4}/download/rpm/${NOTAG}" "$WTOK"
  P4=$(cached_path "$GEN4" ".rpm")
  if [ "$ST" = "200" ] && [ -n "$P4" ]; then
    rescan "$GEN4" "$P4" "$WTOK"
    echo "   rescan ${P4}: HTTP ${RST} state='$(rjson .state)' package_count='$(rjson .package_count)' code='$(rjson .code)' verdict='$(verdict_of "$NT_D")' cataloged='$(catalog_of "$NT_D")'"
    pass
  else
    fail "status=${ST} cached='${P4}'"
  fi
else
  skip_not_applicable "rpm does not scan on proxy on this build"
fi

begin_test "FIX: after the generic rescan, the fail_closed RPM pull of the RPM with no dist tag is still withheld (423), not served"
if [ "$RPM_ENFORCED" = 1 ]; then
  pull "${RP}/${NOTAG}"
  if [ "$ST" = "423" ]; then
    pass
  else
    fail "the withheld pull was lifted by the generic rescan's verdict" \
      "status=${ST} X-AK-Scan='${SCAN}' stored-verdict='$(verdict_of "$NT_D")' cataloged='$(catalog_of "$NT_D")'"
  fi
else
  skip_not_applicable "rpm does not scan on proxy on this build"
fi

begin_test "control: a fail_closed Maven pull of log4j-core-2.14.1.jar that was never poisoned is 403 and records vulnerable"
pull "${M}/${MVN}/${LOG4J}.jar"
if [ "$ST" = "403" ] && [ "$(verdict_of "$L4_D")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} verdict='$(verdict_of "$L4_D")'"
fi

begin_test "FIX: a clean, zero-component row already stored for a package digest (as an earlier release's rescan left it) does not serve a fail_closed Maven pull of it (403)"
CT="org/apache/commons/commons-text/1.9/commons-text-1.9"
CT_D=$(golden_sha "maven2/${CT}.jar")
SV=$(psql_q "SELECT scanner_version FROM proxy_scan_results WHERE checksum_sha256='${L4_D}' AND scan_type='grype'")
if [ -z "$SV" ] || [ -z "$CT_D" ]; then
  infra_fail "no live scanner version (${SV}) or fixture digest (${CT_D})"
else
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "INSERT INTO proxy_scan_results (checksum_sha256, scan_type, verdict, scanner_version, components_cataloged)
       VALUES ('${CT_D}','grype','clean','${SV}',0)
     ON CONFLICT (checksum_sha256, scan_type) DO UPDATE
       SET verdict='clean', findings_count=0, critical_count=0, high_count=0, medium_count=0,
           low_count=0, max_severity=NULL, scanner_version='${SV}', components_cataloged=0,
           scanned_at=now();" >/dev/null 2>&1
  pull "${M}/${MVN}/${CT}.jar"
  if [ "$ST" = "403" ] && [ "$(verdict_of "$CT_D")" = "vulnerable" ]; then
    pass
  else
    fail "the fail_closed Maven pull was served from a clean verdict that graded nothing" \
      "status=${ST} X-AK-Scan='${SCAN}' stored-verdict='$(verdict_of "$CT_D")' cataloged='$(catalog_of "$CT_D")'"
  fi
fi

begin_test "control: a generic rescan of the cached jar (which the engine catalogs as itself) grades it vulnerable on every image"
# proxy the jar through a fresh generic Remote (rescan cooldown is per-repo),
# then rescan it as the writer.
pull "${BASE_URL}/api/v1/repositories/${GEN2}/download/maven2/${LOG4J}.jar" "$WTOK"
GEN_JAR=$(cached_path "$GEN2" ".jar")
rescan "$GEN2" "$GEN_JAR" "$WTOK"
if [ "$RST" = "200" ] && [ "$(rjson .state)" = "vulnerable" ] && [ "$(verdict_of "$L4_D")" = "vulnerable" ]; then
  pass
else
  fail "rescan ${GEN_JAR}: HTTP ${RST} state='$(rjson .state)' verdict='$(verdict_of "$L4_D")' body=$(snippet "$RBODY")"
fi

end_suite
