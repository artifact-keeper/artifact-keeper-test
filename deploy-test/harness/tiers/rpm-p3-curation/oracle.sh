#!/usr/bin/env bash
# =============================================================================
# tiers/rpm-p3-curation/oracle.sh — RPM curation Phase-3 (#2358)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP + repodata flow against the backend.
#
# Gates (discriminating):
#   (CREATE+PUBLISH)  POST /curation/repos/{key}/versions -> 201, then
#                     .../versions/{n}/publish -> 200. Pre-#2358: 404 (RED).
#   (SERVE)           GET /rpm/{key}/@N/repodata/{repomd.xml,.asc,.key} -> 200;
#                     repomd indexes primary; .asc is PGP armor; .key is a PGP
#                     public-key block.
#   (SIG-REAL)        .asc carries a CRC24 armor line; when gpg is present, a
#                     full gpg --verify of the .asc over the served repomd.xml
#                     under the imported .key SUCCEEDS -> not theater.
#   (IMMUTABLE-PUB)   a second publish of the same version -> 409 Conflict.
#   (IMMUTABLE-META)  approve a NEW package into the SAME staging repo AFTER
#                     publish (no new version cut); re-GET @N/primary.xml.gz is
#                     BYTE-IDENTICAL (frozen blob, not re-generated).
#   (FROZEN-IDENTITY) THE SUPPLY-CHAIN GATE. `curation_packages` is LIVE (a
#                     re-sync upserts the same row). After publishing @N, rewrite
#                     the live row's checksum + upstream_path to attacker bytes.
#                     GET @N/packages/{nevra}.rpm must serve the ORIGINAL frozen
#                     bytes (or fail closed) and NEVER the evil bytes; any
#                     X-Checksum-SHA256 must be the FROZEN hash. A serve path
#                     that resolves identity from the live row serves EVIL (RED).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
STAGING="rpm-p3-staging-${DTF_SLOT:-x}-${SUF}"
REMOTE="rpm-p3-remote-${DTF_SLOT:-x}-${SUF}"
MOCK="rpm-p3-mock-${DTF_SLOT:-x}-${SUF}"
MOCK_IMAGE="${RPM_P3_MOCK_IMAGE:-nginx:alpine}"
# Tolerant psql: never let a DB error (e.g. a pre-#2358 baseline missing the
# `primary_metadata` column) abort setup under `set -e` — the discriminating
# signal must come from the route-level assertions below, not a seed crash.
PSQL() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

begin_suite "rpm-p3-curation-2358"

auth_admin   # sets ADMIN_TOKEN

api_call() { # METHOD PATH [BODY] -> sets API_STATUS + API_BODY (no subshell)
  local method="$1" path="$2" body="${3:-}" tmp
  tmp=$(mktemp)
  if [ -n "$body" ]; then
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  else
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  fi
  API_BODY="$(cat "$tmp")"; rm -f "$tmp"
}

WD="$(mktemp -d)"

# --- mock upstream on the DTF network ----------------------------------------
# The @N package path fetches from the CURATION-CONFIG upstream, so we need a
# real HTTP origin the backend container can reach. Serve it from a throwaway
# nginx on the same docker network, addressed by container name.
DTF_NET="$(docker inspect "$DB_CONTAINER" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)"
mkdir -p "$WD/srv/Packages"
printf 'GOOD-RPM-PAYLOAD-%s' "$SUF" > "$WD/srv/Packages/alpha.rpm"
printf 'EVIL-RPM-PAYLOAD-%s' "$SUF" > "$WD/srv/Packages/evil.rpm"
GOOD_SHA="$(sha256sum "$WD/srv/Packages/alpha.rpm" | awk '{print $1}')"
EVIL_SHA="$(sha256sum "$WD/srv/Packages/evil.rpm" | awk '{print $1}')"
chmod -R a+rX "$WD"
docker rm -f "$MOCK" >/dev/null 2>&1 || true
MOCK_UP=0
if [ -n "$DTF_NET" ] && docker run -d --name "$MOCK" --network "$DTF_NET" \
     -v "$WD/srv:/usr/share/nginx/html:ro" "$MOCK_IMAGE" >/dev/null 2>&1; then
  MOCK_UP=1
fi
cleanup_mock() { docker rm -f "$MOCK" >/dev/null 2>&1 || true; rm -rf "$WD"; }
add_exit_handler "cleanup_mock"
UPSTREAM_URL="http://${MOCK}:80"

# --- setup: staging repo + a remote whose upstream is the mock ---------------
create_repo "$STAGING" "rpm" "local"
create_repo "$REMOTE"  "rpm" "remote" "$UPSTREAM_URL"
STAGING_ID="$(PSQL "SELECT id FROM repositories WHERE key='${STAGING}'")"
REMOTE_ID="$(PSQL "SELECT id FROM repositories WHERE key='${REMOTE}'")"

# A GPG (OpenPGP) signing key bound to the staging repo, and metadata signing on.
api_call POST /api/v1/signing/keys \
  "{\"repository_id\":\"${STAGING_ID}\",\"name\":\"rpm-p3-${SUF}\",\"key_type\":\"gpg\",\"algorithm\":\"rsa2048\"}"
KEY_ID="$(echo "$API_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
api_call POST "/api/v1/signing/repositories/${STAGING_ID}/config" \
  "{\"signing_key_id\":\"${KEY_ID}\",\"sign_metadata\":true,\"sign_packages\":false}"

# Seed an APPROVED curation package carrying the STRUCTURED primary metadata the
# A-hardened sync captures (JSONB), so the publish can canonically re-serialize
# it. Direct DB seed mirrors how the sync would land it. The structured checksum
# is the sha256 of the GOOD upstream bytes: that is what the signed primary.xml
# attests and what the snapshot freezes.
seed_pkg() { # NAME CHECKSUM(64hex) UPSTREAM_PATH
  local name="$1" ck="$2" up="$3" meta
  meta=$(cat <<JSON
{"name":"${name}","arch":"x86_64","epoch":"0","version":"1.0","release":"1.el9",
 "summary":"${name} summary","description":"${name} desc",
 "checksum":{"type":"sha256","pkgid":true,"value":"${ck}"},
 "size":{"package":1024,"installed":4096,"archive":4100},
 "time":{"file":1700000000,"build":1699999999},
 "format":{"license":"MIT","provides":[{"name":"${name}"}],
           "requires":[{"name":"glibc","flags":"GE","epoch":"0","ver":"2.34"}]}}
JSON
)
  meta="${meta//$'\n'/}"
  PSQL "INSERT INTO curation_packages
        (staging_repo_id, remote_repo_id, format, package_name, version, release,
         architecture, checksum_sha256, upstream_path, status, primary_metadata)
        VALUES ('${STAGING_ID}','${REMOTE_ID}','rpm','${name}','1.0','1.el9',
         'x86_64','${ck}','${up}','approved',
         '$(echo "$meta" | sed "s/'/''/g")'::jsonb)" >/dev/null
}
seed_pkg "alpha" "$GOOD_SHA" "Packages/alpha.rpm"

# --- (CREATE+PUBLISH) --------------------------------------------------------
begin_test "CREATE+PUBLISH: create a curated snapshot version then publish it"
api_call POST "/api/v1/curation/repos/${STAGING}/versions"
CREATE_STATUS="$API_STATUS"; CREATE_BODY="$API_BODY"
VN="$(echo "$CREATE_BODY" | jq -r '.version_number // empty' 2>/dev/null || true)"
if [ "$CREATE_STATUS" = "201" ] && [ -n "$VN" ]; then
  api_call POST "/api/v1/curation/repos/${STAGING}/versions/${VN}/publish"
  if [ "$API_STATUS" = "200" ] && \
     [ "$(echo "$API_BODY" | jq -r '.published // empty')" = "true" ]; then
    pass
  else
    fail "publish did not return 200/published=true: status=${API_STATUS}" "resp=${API_BODY}"
  fi
else
  fail "create_version did not return 201 (pre-#2358 routes 404): status=${CREATE_STATUS}" \
       "resp=${CREATE_BODY}"
fi

# Keep the rest of the suite meaningful even if the feature is absent.
if [ -z "$VN" ]; then VN=1; fi

# --- (SERVE) -----------------------------------------------------------------
fetch() { # SUBPATH OUTFILE [HEADERFILE] -> sets FETCH_STATUS
  local hdr="${3:-/dev/null}"
  FETCH_STATUS=$(curl -s -o "$2" -D "$hdr" -w '%{http_code}' \
    -H "$(auth_header)" "${BASE_URL}/rpm/${STAGING}/@${VN}/${1}" 2>/dev/null) || FETCH_STATUS=000
}

begin_test "SERVE: @N repomd.xml / .asc / .key are served and well-formed"
fetch "repodata/repomd.xml"     "$WD/repomd.xml"
S_XML="$FETCH_STATUS"
fetch "repodata/repomd.xml.asc" "$WD/repomd.xml.asc"
S_ASC="$FETCH_STATUS"
fetch "repodata/repomd.xml.key" "$WD/repomd.xml.key"
S_KEY="$FETCH_STATUS"
if [ "$S_XML" = "200" ] && [ "$S_ASC" = "200" ] && [ "$S_KEY" = "200" ] \
   && grep -q '"primary"\|<data type="primary"' "$WD/repomd.xml" \
   && head -1 "$WD/repomd.xml.asc" | grep -q 'BEGIN PGP SIGNATURE' \
   && head -1 "$WD/repomd.xml.key" | grep -q 'BEGIN PGP PUBLIC KEY BLOCK'; then
  pass
else
  fail "@N repodata not served/well-formed: xml=${S_XML} asc=${S_ASC} key=${S_KEY}" \
       "repomd_head=$(head -c 200 "$WD/repomd.xml" 2>/dev/null)"
fi

# --- (SIG-REAL) --------------------------------------------------------------
begin_test "SIG-REAL: @N repomd.xml.asc is CRC24-armored OpenPGP that verifies"
CRC_OK=0
if grep -qE '^=[A-Za-z0-9+/]{4}$' "$WD/repomd.xml.asc"; then CRC_OK=1; fi
if command -v gpg >/dev/null 2>&1; then
  GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
  gpg --quiet --import "$WD/repomd.xml.key" >/dev/null 2>&1 || true
  if [ "$CRC_OK" = "1" ] && \
     gpg --quiet --verify "$WD/repomd.xml.asc" "$WD/repomd.xml" >/dev/null 2>&1; then
    pass
  else
    fail "gpg could not verify @N repomd.xml.asc over repomd.xml under the served key (crc=${CRC_OK})" \
         "asc_tail=$(tail -3 "$WD/repomd.xml.asc" 2>/dev/null)"
  fi
  rm -rf "$GNUPGHOME"; unset GNUPGHOME
else
  if [ "$CRC_OK" = "1" ] && tail -n 2 "$WD/repomd.xml.asc" | grep -q 'END PGP SIGNATURE'; then
    pass
  else
    fail "@N .asc missing CRC24 armor line / END marker" \
         "asc_tail=$(tail -3 "$WD/repomd.xml.asc" 2>/dev/null)"
  fi
fi

# --- (IMMUTABLE-PUB) ---------------------------------------------------------
begin_test "IMMUTABLE-PUB: re-publishing a published version is refused (409)"
api_call POST "/api/v1/curation/repos/${STAGING}/versions/${VN}/publish"
if [ "$API_STATUS" = "409" ]; then
  pass
else
  fail "re-publish must be 409 Conflict (immutable @N): status=${API_STATUS}" "resp=${API_BODY}"
fi

# --- (FROZEN-IDENTITY) — the supply-chain gate -------------------------------
# Simulate a POISONED RE-SYNC: curation_service upserts the same curation_packages
# row (ON CONFLICT DO UPDATE), so a compromised upstream can rewrite the LIVE
# checksum + location of a package that an ALREADY-PUBLISHED, SIGNED @N contains.
# @N must keep serving what its signed primary.xml attests.
begin_test "FROZEN-IDENTITY: a poisoned re-sync cannot change what published @N serves"
if [ "$MOCK_UP" != "1" ]; then
  skip "mock upstream container could not start (image ${MOCK_IMAGE} / network ${DTF_NET})"
else
  PSQL "UPDATE curation_packages SET checksum_sha256='${EVIL_SHA}',
        upstream_path='Packages/evil.rpm' WHERE staging_repo_id='${STAGING_ID}'
        AND package_name='alpha'" >/dev/null
  fetch "packages/alpha-1.0-1.el9.x86_64.rpm" "$WD/served.rpm" "$WD/served.hdr"
  SERVED_STATUS="$FETCH_STATUS"
  SERVED_SHA="$(sha256sum "$WD/served.rpm" 2>/dev/null | awk '{print $1}')"
  ADV_SHA="$(grep -i '^X-Checksum-SHA256:' "$WD/served.hdr" 2>/dev/null \
             | tr -d '\r' | awk '{print tolower($2)}' | head -1)"
  if [ "$SERVED_STATUS" = "200" ] && [ "$SERVED_SHA" = "$EVIL_SHA" ]; then
    fail "POISONED: published @${VN} served the EVIL bytes after a live re-sync rewrote the curation row (served sha=${SERVED_SHA})" \
         "advertised=${ADV_SHA} evil=${EVIL_SHA} good=${GOOD_SHA}"
  elif [ "$SERVED_STATUS" = "200" ] && [ "$SERVED_SHA" = "$GOOD_SHA" ] \
       && [ "$ADV_SHA" = "$GOOD_SHA" ]; then
    pass   # served the ORIGINAL frozen bytes, advertising the FROZEN hash
  elif [ "$SERVED_STATUS" = "200" ]; then
    fail "published @${VN} served 200 but not the frozen bytes/checksum: sha=${SERVED_SHA} advertised=${ADV_SHA}" \
         "good=${GOOD_SHA} evil=${EVIL_SHA} (a 200 must carry the frozen bytes AND advertise the frozen hash)"
  elif [ "$SERVED_STATUS" = "404" ] || [ "$SERVED_STATUS" = "409" ] || [ "$SERVED_STATUS" = "502" ]; then
    pass   # failed closed with an integrity error — also acceptable
  else
    fail "published @${VN} package GET returned an unexpected status ${SERVED_STATUS}" \
         "sha=${SERVED_SHA} advertised=${ADV_SHA} good=${GOOD_SHA} evil=${EVIL_SHA}"
  fi
fi

# The cached/frozen re-serve must keep the package response contract: a second
# GET (now a cache hit) must still be application/x-rpm and still advertise the
# FROZEN checksum, not fall through to an opaque octet-stream blob serve.
begin_test "FROZEN-IDENTITY: the cached @N re-serve keeps the package contract"
if [ "$MOCK_UP" != "1" ]; then
  skip "mock upstream container could not start"
else
  fetch "packages/alpha-1.0-1.el9.x86_64.rpm" "$WD/served2.rpm" "$WD/served2.hdr"
  S2_STATUS="$FETCH_STATUS"
  S2_SHA="$(sha256sum "$WD/served2.rpm" 2>/dev/null | awk '{print $1}')"
  S2_ADV="$(grep -i '^X-Checksum-SHA256:' "$WD/served2.hdr" 2>/dev/null \
            | tr -d '\r' | awk '{print tolower($2)}' | head -1)"
  S2_CT="$(grep -i '^Content-Type:' "$WD/served2.hdr" 2>/dev/null \
           | tr -d '\r' | awk '{print tolower($2)}' | head -1)"
  if [ "$S2_STATUS" != "200" ]; then
    pass   # still failing closed is fine
  elif [ "$S2_SHA" = "$GOOD_SHA" ] && [ "$S2_ADV" = "$GOOD_SHA" ] \
       && [ "$S2_CT" = "application/x-rpm" ]; then
    pass
  else
    fail "cached @${VN} re-serve broke the package contract: sha=${S2_SHA} advertised=${S2_ADV} content-type=${S2_CT}" \
         "expected sha/advertised=${GOOD_SHA} content-type=application/x-rpm"
  fi
fi

# --- (IMMUTABLE-META) --------------------------------------------------------
begin_test "IMMUTABLE-META: mutating the approved set does not change published @N"
fetch "repodata/primary.xml.gz" "$WD/primary1.gz"
SUM1="$(sha256sum "$WD/primary1.gz" | awk '{print $1}')"
# Approve a brand-new package into the SAME staging repo, post-publish.
seed_pkg "beta" "$EVIL_SHA" "Packages/evil.rpm"
# The published snapshot must NOT absorb it: the served blob is frozen.
fetch "repodata/primary.xml.gz" "$WD/primary2.gz"
SUM2="$(sha256sum "$WD/primary2.gz" | awk '{print $1}')"
# And the frozen metadata must reflect the 1-package snapshot, not 2.
gunzip -c "$WD/primary1.gz" > "$WD/primary1.xml" 2>/dev/null || true
PKGCOUNT="$(grep -oE 'packages="[0-9]+"' "$WD/primary1.xml" | head -1 | grep -oE '[0-9]+' || echo '?')"
if [ "$FETCH_STATUS" = "200" ] && [ -n "$SUM1" ] && [ "$SUM1" = "$SUM2" ] \
   && [ "$PKGCOUNT" = "1" ] && ! grep -q '<name>beta</name>' "$WD/primary1.xml"; then
  pass
else
  fail "published @N metadata changed after approving a new package (immutability leak): sum1=${SUM1} sum2=${SUM2} pkgcount=${PKGCOUNT}" \
       "contains_beta=$(grep -c '<name>beta</name>' "$WD/primary1.xml" 2>/dev/null)"
fi

end_suite
