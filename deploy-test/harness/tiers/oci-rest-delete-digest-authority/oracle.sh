#!/usr/bin/env bash
# =============================================================================
# tiers/oci-rest-delete-digest-authority/oracle.sh — the REST manifest delete
#                    unwinds only the index rows it owns (artifact-keeper#3475)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# THE BUG. #3475 makes `DELETE /api/v1/repositories/{key}/artifacts/{path}`
# unwind the OCI index for a Docker manifest (#3476: without it a re-push finds
# the surviving tag on its HEAD probe and never resurrects the image). Its first
# cut derived the digest to unwind from the DELETED ROW'S OWN `checksum_sha256`,
# the shared helper's digest branch swept `oci_tags` repo-wide by digest while
# IGNORING the image name, and `classify_oci` treats a `/manifests/` path as
# immutable only when it contains the literal `sha256:`.
#
# Composed, a NON-ADMIN with repo-scoped read+write+delete on ONE repository
# can: read a victim image's manifest bytes, upload them as a decoy artifact
# under an UNRELATED image name at a non-`sha256` digest-SHAPED reference
# (`blake3:00` — mutable to the immutability gate, a digest to the unwind),
# delete the decoy, and take the victim's tags and blob refs with it. `docker
# pull` 404s for everyone while `artifacts.is_deleted` stays false, the REST
# metadata endpoint still reports the image present, and the audit log names
# only the decoy. Two tags sharing one digest both died on a single delete.
#
# THE BASELINE IS THE PR HEAD, NOT main^. `d36cf4fd^1` has no unwind at all, so
# the exploit is inert there AND the CONTROL that a legitimate delete unwinds
# its own index fails there — that unwind is the feature #3475 adds. The
# discriminating baseline is `92fb98e7`, the pre-fix head this was proven on.
#
# Discriminating gates:
#   (CONTROL)  true on BOTH images: the attacker is non-admin; a literal
#              `sha256:` manifest reference is still refused 409 by release
#              immutability; a legitimate REST delete unwinds ITS OWN index and
#              a re-push resurrects the image (#3476); an unrelated image is
#              untouched by that delete; deleting one of two tags sharing a
#              digest removes only the named tag and keeps the sibling's blob
#              pins (#1776). Also — deliberately — the decoy PUT and the decoy
#              DELETE are still ACCEPTED on the fix, because `classify_oci` is
#              out of scope for #3475; if either were refused, the boundary
#              gates below would pass for a reason unrelated to the unwind's
#              authority, and their messages say so.
#   (BOUNDARY) after the decoy sequence the victim's `oci_tags` and
#              `manifest_blob_refs` rows are unchanged, both tags still serve a
#              200 whose bytes hash to the indexed digest, and the REST view and
#              the registry view agree. Repeated with a decoy under the victim's
#              OWN image name at a forged digest reference. RED on `92fb98e7`:
#              tags 2 -> 0, blob refs 2 -> 0, pull 404, `is_deleted` still false,
#              no audit row naming the victim.
#
# --path-as-is on EVERY curl: these probes carry `sha256:`/`blake3:` colons in
# multi-segment artifact paths and curl normalises paths by default.
#
# Setup failures use infra_fail(): a tier that could not be evaluated is RED but
# is NOT a statement about the candidate (harness/lib/exit_codes.sh).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"

REPO="ocidel-${SLOT}-${SUF}"
ATTACKER="ocidel-attacker-${SLOT}-${SUF}"
ATTACKER_PASS="Ocidel_${SUF}_Aa1!"

# The three images all live in the ONE repository the attacker holds delete on:
# the primitive is confined to a repository the attacker can already delete in
# (a same-digest cross-repo probe was run when this was found and every
# statement is genuinely `repository_id = $1`-scoped). What it defeats inside
# that repository is per-path authorization, the immutability gate, the
# deletion record and the audit trail.
VICTIM_IMG="prodimg"          # two tags, one digest — the thing being protected
VICTIM_TAG="1.0.0"
VICTIM_TAG2="stable"
LEGIT_IMG="legit"             # the CONTROL: a delete that SHOULD unwind
LEGIT_TAG="9.9.9"
# The #1776 named-reference control gets its OWN image and its OWN manifest
# digest, deliberately NOT the victim's. On the pre-fix baseline the decoy
# sweep removes every tag pointing at the VICTIM's digest, so running this
# control on the victim would fail there as collateral of the boundary probes
# rather than because named-reference scoping is broken — a control has to be
# true on both images for its own reasons.
TWIN_IMG="twintag"
TWIN_TAG_A="a1.0"
TWIN_TAG_B="b1.0"
DECOY_IMG="attackersandbox"   # unrelated image name — no relation to the victim
DECOY_REF="blake3:00"         # digest-SHAPED, not `sha256:` => mutable to the
                              # immutability gate, a digest to the unwind
DECOY_REF2="blake3:01"        # the same forgery under the victim's OWN name

WORK="$(mktemp -d -t dtf-ocidel-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- curl helpers -----------------------------------------------------------
# EVERY probe passes --path-as-is. See the header.
CURL_RAW="--path-as-is"

code_get() {   # URL [curl args...]
  local url="$1"; shift
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW "$@" "$url" 2>/dev/null || echo 000
}
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW "$@" "$url" 2>/dev/null || echo 000
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }

MANIFEST_CT='application/vnd.docker.distribution.manifest.v2+json'

# --- DB observers -----------------------------------------------------------
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

tag_rows() {   # IMAGE -> number of oci_tags rows for that image in $REPO
  db "SELECT count(*) FROM oci_tags t JOIN repositories r ON r.id = t.repository_id
      WHERE r.key = '${REPO}' AND t.name = '${1}';"
}
tag_digest() { # IMAGE TAG -> the digest the INDEX resolves that reference to
  db "SELECT manifest_digest FROM oci_tags t JOIN repositories r ON r.id = t.repository_id
      WHERE r.key = '${REPO}' AND t.name = '${1}' AND t.tag = '${2}';"
}
blob_refs() {  # DIGEST -> number of manifest_blob_refs rows pinning its blobs
  db "SELECT count(*) FROM manifest_blob_refs b JOIN repositories r ON r.id = b.repository_id
      WHERE r.key = '${REPO}' AND b.manifest_digest = '${1}';"
}
row_deleted() { # ARTIFACT PATH -> t/f from the artifacts ledger
  db "SELECT is_deleted FROM artifacts a JOIN repositories r ON r.id = a.repository_id
      WHERE r.key = '${REPO}' AND a.path = '${1}' ORDER BY a.created_at DESC LIMIT 1;"
}
row_checksum() { # ARTIFACT PATH -> checksum_sha256 of the live row
  db "SELECT checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id
      WHERE r.key = '${REPO}' AND a.path = '${1}' AND a.is_deleted = false;"
}
audit_deletes_naming() { # PATH PREFIX -> ARTIFACT_DELETED audit rows naming it
  db "SELECT count(*) FROM audit_log
      WHERE action = 'ARTIFACT_DELETED' AND details->>'path' LIKE '${1}%';"
}

# --- registry helpers -------------------------------------------------------
V2="${BASE_URL}/v2/${REPO}"
REST="${BASE_URL}/api/v1/repositories/${REPO}/artifacts"

pull_manifest() { # IMAGE REFERENCE OUTFILE BEARER -> http code, body in OUTFILE
  code_to_file "${V2}/${1}/manifests/${2}" "$3" \
    -H "Authorization: Bearer ${4}" -H "Accept: ${MANIFEST_CT}"
}
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

begin_suite "oci-rest-delete-digest-authority-3475"

# ===========================================================================
# SETUP — every failure here is INFRA: the harness could not evaluate the tier.
# ===========================================================================
auth_admin   # sets ADMIN_TOKEN

REPO_ID="$(curl -s $CURL_TIMEOUT $CURL_RAW -X POST "${BASE_URL}/api/v1/repositories" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":false}" \
  2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
if [ -z "$REPO_ID" ]; then
  begin_test "setup: create the private docker repository"
  infra_fail "could not create repository ${REPO}"
  end_suite
fi

ATTACKER_ID="$(create_test_user_with_retry "$ATTACKER" "$ATTACKER_PASS" "${ATTACKER}@t.test")" || true
if [ -z "$ATTACKER_ID" ] || [ "$ATTACKER_ID" = "null" ]; then
  begin_test "setup: create the non-admin actor"
  infra_fail "could not create user ${ATTACKER}"
  end_suite
fi

# Repo actions are deny-by-default at the principal layer (#2603 G1). Grant the
# NON-ADMIN exactly read+write+delete on this ONE repository: that is the whole
# privilege the primitive needs, and it is a grant any operator would issue to
# someone who maintains a repository. Everything the boundary gates below assert
# has to be decided by the unwind's authority, not by missing RBAC.
GRANT_CODE="$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT $CURL_RAW -X POST \
  "${BASE_URL}/api/v1/permissions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"principal_type\":\"user\",\"principal_id\":\"${ATTACKER_ID}\",\"target_type\":\"repository\",\"target_id\":\"${REPO_ID}\",\"actions\":[\"read\",\"write\",\"delete\"]}" \
  2>/dev/null || echo 000)"
if ! is_2xx "$GRANT_CODE"; then
  begin_test "setup: grant the non-admin read+write+delete on the repository"
  infra_fail "the permission grant returned ${GRANT_CODE}" "repo=${REPO} user=${ATTACKER}"
  end_suite
fi

ATTACKER_TOKEN="$(login_as "$ATTACKER" "$ATTACKER_PASS")" || true
if [ -z "$ATTACKER_TOKEN" ]; then
  begin_test "setup: log in the non-admin actor"
  infra_fail "could not log in as ${ATTACKER}"
  end_suite
fi

# --- push the fixture images over the real /v2 wire sequence -----------------
# Pushed BY THE ATTACKER, so the tier also proves the grant is live before any
# boundary is evaluated. No docker daemon: a required dtf-gate leg must not
# depend on an external image pull (the documented native-client flake class).
push_image() { # IMAGE TAG SALT -> "" on success, a diagnostic string on failure
  local img="$1" tag="$2" salt="$3" fails=""
  local cfg="${WORK}/cfg-${salt}" layer="${WORK}/layer-${salt}"
  printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"salt":"%s"}' "$salt" > "$cfg"
  printf 'dtf-ocidel-layer-%s' "$salt" > "$layer"
  local cfgd="sha256:$(sha_of "$cfg")" cfgs layd="sha256:$(sha_of "$layer")" lays c
  cfgs="$(wc -c < "$cfg" | tr -d ' ')"; lays="$(wc -c < "$layer" | tr -d ' ')"
  c="$(code_to_file "${V2}/${img}/blobs/uploads/?digest=${cfgd}" /dev/null -X POST \
        -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H 'Content-Type: application/octet-stream' \
        --data-binary "@${cfg}")"
  is_2xx "$c" || fails="${fails} config-blob=${c}"
  c="$(code_to_file "${V2}/${img}/blobs/uploads/?digest=${layd}" /dev/null -X POST \
        -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H 'Content-Type: application/octet-stream' \
        --data-binary "@${layer}")"
  is_2xx "$c" || fails="${fails} layer-blob=${c}"
  cat > "${WORK}/manifest-${salt}.json" <<EOF
{"schemaVersion":2,"mediaType":"${MANIFEST_CT}","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":${cfgs},"digest":"${cfgd}"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":${lays},"digest":"${layd}"}]}
EOF
  c="$(code_to_file "${V2}/${img}/manifests/${tag}" /dev/null -X PUT \
        -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H "Content-Type: ${MANIFEST_CT}" \
        --data-binary "@${WORK}/manifest-${salt}.json")"
  is_2xx "$c" || fails="${fails} manifest=${c}"
  echo "$fails"
}

PUSH_FAILS="$(push_image "$VICTIM_IMG" "$VICTIM_TAG" victim)"
# The second tag on the SAME manifest bytes: pre-fix, ONE decoy delete removed
# BOTH, because the sweep was `WHERE manifest_digest = $2` with no tag scope.
C="$(code_to_file "${V2}/${VICTIM_IMG}/manifests/${VICTIM_TAG2}" /dev/null -X PUT \
      -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H "Content-Type: ${MANIFEST_CT}" \
      --data-binary "@${WORK}/manifest-victim.json")"
is_2xx "$C" || PUSH_FAILS="${PUSH_FAILS} victim-second-tag=${C}"
PUSH_FAILS="${PUSH_FAILS}$(push_image "$LEGIT_IMG" "$LEGIT_TAG" legit)"
PUSH_FAILS="${PUSH_FAILS}$(push_image "$TWIN_IMG" "$TWIN_TAG_A" twin)"
C="$(code_to_file "${V2}/${TWIN_IMG}/manifests/${TWIN_TAG_B}" /dev/null -X PUT \
      -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H "Content-Type: ${MANIFEST_CT}" \
      --data-binary "@${WORK}/manifest-twin.json")"
is_2xx "$C" || PUSH_FAILS="${PUSH_FAILS} twin-second-tag=${C}"
if [ -n "${PUSH_FAILS// /}" ]; then
  begin_test "setup: push the victim and control images over /v2 as the non-admin"
  infra_fail "the fixture push failed:${PUSH_FAILS}" "repo=${REPO} user=${ATTACKER}"
  end_suite
fi

VICTIM_PATH="v2/${VICTIM_IMG}/manifests/${VICTIM_TAG}"
VICTIM_PATH2="v2/${VICTIM_IMG}/manifests/${VICTIM_TAG2}"
LEGIT_PATH="v2/${LEGIT_IMG}/manifests/${LEGIT_TAG}"
DECOY_PATH="v2/${DECOY_IMG}/manifests/${DECOY_REF}"
DECOY_PATH2="v2/${VICTIM_IMG}/manifests/${DECOY_REF2}"

# Baselines read from the DB BEFORE any probe runs.
VICTIM_DIGEST="$(tag_digest "$VICTIM_IMG" "$VICTIM_TAG")"
VICTIM_TAGS_BEFORE="$(tag_rows "$VICTIM_IMG")"
VICTIM_REFS_BEFORE="$(blob_refs "$VICTIM_DIGEST")"
LEGIT_TAGS_BEFORE="$(tag_rows "$LEGIT_IMG")"
TWIN_DIGEST="$(tag_digest "$TWIN_IMG" "$TWIN_TAG_A")"
TWIN_TAGS_BEFORE="$(tag_rows "$TWIN_IMG")"
TWIN_REFS_BEFORE="$(blob_refs "$TWIN_DIGEST")"
if [ "$VICTIM_TAGS_BEFORE" != "2" ] || [ "$LEGIT_TAGS_BEFORE" != "1" ] || [ "$TWIN_TAGS_BEFORE" != "2" ] || \
   [ -z "$VICTIM_DIGEST" ] || [ -z "$TWIN_DIGEST" ] || [ "$TWIN_DIGEST" = "$VICTIM_DIGEST" ] || \
   ! [[ "$VICTIM_REFS_BEFORE" =~ ^[0-9]+$ ]] || [ "$VICTIM_REFS_BEFORE" -lt 2 ] || \
   ! [[ "$TWIN_REFS_BEFORE" =~ ^[0-9]+$ ]] || [ "$TWIN_REFS_BEFORE" -lt 2 ]; then
  begin_test "setup: read the OCI index baseline for the fixture images"
  infra_fail "expected victim tags=2 legit tags=1 twin tags=2, blob refs>=2 for two DISTINCT digests; saw victim tags=${VICTIM_TAGS_BEFORE}/refs=${VICTIM_REFS_BEFORE}/digest='${VICTIM_DIGEST}' legit tags=${LEGIT_TAGS_BEFORE} twin tags=${TWIN_TAGS_BEFORE}/refs=${TWIN_REFS_BEFORE}/digest='${TWIN_DIGEST}'" \
    "repo=${REPO}"
  end_suite
fi

# ===========================================================================
# (CONTROL) — must hold on BOTH the pre-fix baseline and the fix.
# ===========================================================================
begin_test "CONTROL: the actor driving every probe below is a NON-ADMIN"
# `jq -r '.is_admin // empty'` would be WRONG here: jq's `//` treats `false`
# as an absent value, so the correct answer would read as a missing field.
IS_ADMIN="$(curl -s $CURL_TIMEOUT $CURL_RAW "${BASE_URL}/api/v1/auth/me" \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}" 2>/dev/null \
  | jq -r 'if has("is_admin") then (.is_admin | tostring) else "" end' 2>/dev/null || true)"
if [ "$IS_ADMIN" = "false" ]; then pass; else
  fail "the actor reports is_admin='${IS_ADMIN}' (expected false); an admin-driven sequence would prove nothing about a low-privilege primitive" \
    "user=${ATTACKER} is_admin=${IS_ADMIN}"
fi

begin_test "CONTROL: release immutability still refuses a literal sha256: manifest reference -> 409"
CC="$(code_get "${REST}/v2/${VICTIM_IMG}/manifests/${VICTIM_DIGEST}" -X DELETE \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}")"
if [ "$CC" = "409" ]; then pass; else
  fail "a non-admin DELETE of the digest-pinned manifest reference returned ${CC}, expected 409 'Cannot delete an immutable/released artifact' — the release-immutability gate this attack routes AROUND must itself still work on both images" \
    "code=${CC} path=v2/${VICTIM_IMG}/manifests/${VICTIM_DIGEST}"
fi

begin_test "CONTROL: a legitimate REST delete unwinds ITS OWN index (#3476) — tag row gone and /v2 pull 404"
CC="$(code_get "${REST}/${LEGIT_PATH}" -X DELETE -H "Authorization: Bearer ${ATTACKER_TOKEN}")"
LEGIT_TAGS_AFTER="$(tag_rows "$LEGIT_IMG")"
LEGIT_PULL="$(pull_manifest "$LEGIT_IMG" "$LEGIT_TAG" /dev/null "$ATTACKER_TOKEN")"
if is_2xx "$CC" && [ "$LEGIT_TAGS_AFTER" = "0" ] && [ "$LEGIT_PULL" = "404" ]; then pass; else
  fail "the REST delete of ${LEGIT_PATH} did not unwind its own index: delete=${CC} oci_tags ${LEGIT_TAGS_BEFORE}->${LEGIT_TAGS_AFTER} pull=${LEGIT_PULL} (expected 2xx, 0, 404). This is the feature #3475 delivers; without it a re-push's HEAD probe finds the surviving tag and the image is never resurrected (#3476)" \
    "delete=${CC} tags_before=${LEGIT_TAGS_BEFORE} tags_after=${LEGIT_TAGS_AFTER} pull=${LEGIT_PULL}"
fi

begin_test "CONTROL: that legitimate delete wrote an audit record naming the path it deleted"
LEGIT_AUDIT="$(audit_deletes_naming "$LEGIT_PATH")"
if [ "${LEGIT_AUDIT:-0}" -ge 1 ] 2>/dev/null; then pass; else
  fail "no ARTIFACT_DELETED audit row names ${LEGIT_PATH} (saw ${LEGIT_AUDIT}); the audit trail must record a delete, and this control is what makes the boundary gate below — that a destroyed victim leaves NO such row — meaningful" \
    "rows=${LEGIT_AUDIT} path=${LEGIT_PATH}"
fi

begin_test "CONTROL: an unrelated image in the same repository is untouched by that normal delete"
V_TAGS="$(tag_rows "$VICTIM_IMG")"; V_PULL="$(pull_manifest "$VICTIM_IMG" "$VICTIM_TAG" /dev/null "$ATTACKER_TOKEN")"
if [ "$V_TAGS" = "$VICTIM_TAGS_BEFORE" ] && [ "$V_PULL" = "200" ]; then pass; else
  fail "deleting ${LEGIT_PATH} changed the unrelated image ${VICTIM_IMG}: oci_tags ${VICTIM_TAGS_BEFORE}->${V_TAGS}, pull=${V_PULL} (expected unchanged and 200)" \
    "tags_before=${VICTIM_TAGS_BEFORE} tags_after=${V_TAGS} pull=${V_PULL}"
fi

begin_test "CONTROL: a re-push after that delete RESURRECTS the image (#3476, the reason the unwind exists)"
CC="$(code_to_file "${V2}/${LEGIT_IMG}/manifests/${LEGIT_TAG}" /dev/null -X PUT \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H "Content-Type: ${MANIFEST_CT}" \
  --data-binary "@${WORK}/manifest-legit.json")"
REPUSH_TAGS="$(tag_rows "$LEGIT_IMG")"
REPUSH_PULL="$(pull_manifest "$LEGIT_IMG" "$LEGIT_TAG" /dev/null "$ATTACKER_TOKEN")"
REPUSH_ROW="$(row_deleted "$LEGIT_PATH")"
if is_2xx "$CC" && [ "$REPUSH_TAGS" = "1" ] && [ "$REPUSH_PULL" = "200" ] && [ "$REPUSH_ROW" = "f" ]; then pass; else
  fail "the re-push did not resurrect ${LEGIT_IMG}:${LEGIT_TAG}: push=${CC} oci_tags=${REPUSH_TAGS} pull=${REPUSH_PULL} artifacts.is_deleted='${REPUSH_ROW}' (expected 2xx, 1, 200, f). A fix that simply stopped unwinding would re-open #3476, and this gate is what catches it" \
    "push=${CC} tags=${REPUSH_TAGS} pull=${REPUSH_PULL} is_deleted=${REPUSH_ROW}"
fi

begin_test "CONTROL: deleting ONE of two tags sharing a digest removes only that tag and keeps the sibling's blob pins (#1776)"
CC="$(code_get "${REST}/v2/${TWIN_IMG}/manifests/${TWIN_TAG_B}" -X DELETE -H "Authorization: Bearer ${ATTACKER_TOKEN}")"
TWIN_TAGS_LEFT="$(tag_rows "$TWIN_IMG")"
TWIN_REFS_LEFT="$(blob_refs "$TWIN_DIGEST")"
TWIN_SURVIVOR="$(pull_manifest "$TWIN_IMG" "$TWIN_TAG_A" /dev/null "$ATTACKER_TOKEN")"
TWIN_REMOVED="$(pull_manifest "$TWIN_IMG" "$TWIN_TAG_B" /dev/null "$ATTACKER_TOKEN")"
if is_2xx "$CC" && [ "$TWIN_TAGS_LEFT" = "1" ] && [ "$TWIN_REFS_LEFT" = "$TWIN_REFS_BEFORE" ] && \
   [ "$TWIN_SURVIVOR" = "200" ] && [ "$TWIN_REMOVED" = "404" ]; then
  pass
else
  fail "the named-reference delete of ${TWIN_IMG}:${TWIN_TAG_B} did not behave as #1776 specifies: delete=${CC} oci_tags=${TWIN_TAGS_LEFT} (expected 1) blob refs=${TWIN_REFS_LEFT} (expected ${TWIN_REFS_BEFORE}, the manifest is still tagged by its sibling) survivor pull=${TWIN_SURVIVOR} (expected 200) removed-tag pull=${TWIN_REMOVED} (expected 404). The REST unwind must remove the single (name, tag) entry the path names and nothing else" \
    "delete=${CC} tags=${TWIN_TAGS_LEFT} refs=${TWIN_REFS_LEFT} survivor=${TWIN_SURVIVOR} removed=${TWIN_REMOVED}"
fi

# --- the decoy. Both of these must SUCCEED on both images ---------------------
# `classify_oci` is deliberately untouched by #3475 (arming it would also arm the
# upload-side immutability guard and flip remote proxy cache TTL — three
# subsystems), so `blake3:00` remains MUTABLE to the immutability gate and a
# DIGEST to `is_digest_reference` on the fix too. That is the point: the fix is
# in the unwind's authority, not in refusing the request.
begin_test "CONTROL: the decoy upload is ACCEPTED — an unrelated image name at a digest-shaped, non-sha256 reference"
DECOY_SRC="${WORK}/victim-bytes.json"
PULLED="$(pull_manifest "$VICTIM_IMG" "$VICTIM_TAG" "$DECOY_SRC" "$ATTACKER_TOKEN")"
CC="$(code_to_file "${REST}/${DECOY_PATH}" /dev/null -X PUT \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H 'Content-Type: application/octet-stream' \
  --data-binary "@${DECOY_SRC}")"
DECOY_SUM="$(row_checksum "$DECOY_PATH")"
if [ "$PULLED" = "200" ] && is_2xx "$CC" && [ "sha256:${DECOY_SUM}" = "$VICTIM_DIGEST" ]; then
  pass
else
  fail "the decoy could not be staged: victim read=${PULLED} decoy PUT=${CC} decoy row checksum='sha256:${DECOY_SUM}' vs victim indexed digest='${VICTIM_DIGEST}'. The attack precondition is a row whose OWN content hash equals ANOTHER image's indexed digest; if the upload is refused or the hashes differ, the BOUNDARY gates below are NOT attributable to #3475" \
    "read=${PULLED} put=${CC} decoy_sum=sha256:${DECOY_SUM} victim_digest=${VICTIM_DIGEST} path=${DECOY_PATH}"
fi

begin_test "CONTROL: the decoy DELETE is ACCEPTED (the reference is mutable to the immutability gate)"
DECOY_DEL="$(code_get "${REST}/${DECOY_PATH}" -X DELETE -H "Authorization: Bearer ${ATTACKER_TOKEN}")"
if is_2xx "$DECOY_DEL"; then pass; else
  fail "the decoy DELETE returned ${DECOY_DEL} instead of 2xx. #3475 does not refuse this request — it removes its authority over another image's index rows — so a refusal here means the unwind was never reached and the BOUNDARY gates below are NOT attributable to #3475" \
    "code=${DECOY_DEL} path=${DECOY_PATH}"
fi

# ===========================================================================
# (BOUNDARY) — RED on the pre-fix baseline `92fb98e7`, GREEN on the fix.
# The decoy delete has just run. Nothing about it names the victim.
# ===========================================================================
begin_test "BOUNDARY(DB): the victim's oci_tags rows are UNCHANGED after the decoy delete (baseline: 2 -> 0, both tags)"
VICTIM_TAGS_AFTER="$(tag_rows "$VICTIM_IMG")"
if [ "$VICTIM_TAGS_AFTER" = "$VICTIM_TAGS_BEFORE" ]; then pass; else
  fail "DECOY-DIGEST INDEX DESTRUCTION (#3475): deleting ${DECOY_PATH} removed the index rows of the unrelated image ${VICTIM_IMG} — oci_tags ${VICTIM_TAGS_BEFORE} -> ${VICTIM_TAGS_AFTER}. The unwind resolved its digest from the DELETED ROW'S OWN checksum and then swept oci_tags repo-wide by digest, ignoring the image name, so BOTH tags sharing that digest died on one request" \
    "before=${VICTIM_TAGS_BEFORE} after=${VICTIM_TAGS_AFTER} decoy=${DECOY_PATH} victim=${VICTIM_IMG} digest=${VICTIM_DIGEST}"
fi

begin_test "BOUNDARY(DB): the victim manifest's blob refs are UNCHANGED — its layers are not made GC-eligible (baseline: 2 -> 0)"
VICTIM_REFS_AFTER="$(blob_refs "$VICTIM_DIGEST")"
if [ "$VICTIM_REFS_AFTER" = "$VICTIM_REFS_BEFORE" ]; then pass; else
  fail "DECOY-DIGEST INDEX DESTRUCTION (#3475): the decoy delete dropped the victim manifest's blob refs — manifest_blob_refs ${VICTIM_REFS_BEFORE} -> ${VICTIM_REFS_AFTER} for ${VICTIM_DIGEST}. BLOB_PROTECTED_BY_REFS_SQL consults exactly these rows, so the victim's config and layer blobs are now reclaimable by storage GC" \
    "before=${VICTIM_REFS_BEFORE} after=${VICTIM_REFS_AFTER} digest=${VICTIM_DIGEST}"
fi

begin_test "BOUNDARY: docker pull of the victim tag still returns 200 AND the real manifest bytes (baseline: 404)"
PULLED_OUT="${WORK}/pull-after.json"
PULL_CODE="$(pull_manifest "$VICTIM_IMG" "$VICTIM_TAG" "$PULLED_OUT" "$ATTACKER_TOKEN")"
PULL_SUM="sha256:$(sha_of "$PULLED_OUT")"
if [ "$PULL_CODE" = "200" ] && [ "$PULL_SUM" = "$VICTIM_DIGEST" ]; then pass; else
  fail "DECOY-DIGEST INDEX DESTRUCTION (#3475): after the decoy delete, GET /v2/${REPO}/${VICTIM_IMG}/manifests/${VICTIM_TAG} returned ${PULL_CODE} with body digest ${PULL_SUM} (expected 200 and ${VICTIM_DIGEST}). The image is gone for every consumer, destroyed through a path that bears no relation to it" \
    "code=${PULL_CODE} body_digest=${PULL_SUM} expected=${VICTIM_DIGEST}"
fi

begin_test "BOUNDARY: the SECOND tag sharing the same digest also still resolves (baseline: one decoy delete wiped both)"
PULL2="$(pull_manifest "$VICTIM_IMG" "$VICTIM_TAG2" /dev/null "$ATTACKER_TOKEN")"
if [ "$PULL2" = "200" ]; then pass; else
  fail "DECOY-DIGEST INDEX DESTRUCTION (#3475): the sibling tag ${VICTIM_IMG}:${VICTIM_TAG2}, which shares one manifest digest with ${VICTIM_TAG}, returned ${PULL2} (expected 200). A single decoy delete took every tag pointing at that digest, because the sweep was scoped to the digest and not to the (name, tag) the request named" \
    "code=${PULL2} tag=${VICTIM_TAG2} digest=${VICTIM_DIGEST}"
fi

begin_test "BOUNDARY: the artifacts ledger and the registry AGREE about the victim, and no audit row names it"
LEDGER_DELETED="$(row_deleted "$VICTIM_PATH")"
REST_META="$(code_get "${REST}/${VICTIM_PATH}" -H "Authorization: Bearer ${ATTACKER_TOKEN}")"
PULL_NOW="$(pull_manifest "$VICTIM_IMG" "$VICTIM_TAG" /dev/null "$ATTACKER_TOKEN")"
VICTIM_AUDIT="$(audit_deletes_naming "v2/${VICTIM_IMG}/manifests/")"
if [ "$LEDGER_DELETED" = "f" ] && [ "$REST_META" = "200" ] && [ "$PULL_NOW" = "200" ] && [ "${VICTIM_AUDIT:-0}" = "0" ]; then
  pass
else
  fail "DECOY-DIGEST INDEX DESTRUCTION (#3475): the two views disagree about ${VICTIM_PATH} — artifacts.is_deleted='${LEDGER_DELETED}', REST metadata=${REST_META}, /v2 pull=${PULL_NOW}, ARTIFACT_DELETED audit rows naming the victim=${VICTIM_AUDIT}. On the pre-fix baseline the ledger and the API still report the image PRESENT while the registry 404s it, and the only audit row written names the decoy: a silent, unrecorded destruction" \
    "is_deleted=${LEDGER_DELETED} rest_metadata=${REST_META} pull=${PULL_NOW} audit_rows_naming_victim=${VICTIM_AUDIT}"
fi

begin_test "BOUNDARY: the same forgery under the victim's OWN image name is equally powerless (baseline: destroys it)"
CC="$(code_to_file "${REST}/${DECOY_PATH2}" /dev/null -X PUT \
  -H "Authorization: Bearer ${ATTACKER_TOKEN}" -H 'Content-Type: application/octet-stream' \
  --data-binary "@${DECOY_SRC}")"
DEL2="$(code_get "${REST}/${DECOY_PATH2}" -X DELETE -H "Authorization: Bearer ${ATTACKER_TOKEN}")"
TAGS2="$(tag_rows "$VICTIM_IMG")"
PULL3="$(pull_manifest "$VICTIM_IMG" "$VICTIM_TAG" /dev/null "$ATTACKER_TOKEN")"
if ! is_2xx "$CC" || ! is_2xx "$DEL2"; then
  fail "the same-image decoy could not be staged (PUT=${CC} DELETE=${DEL2}), so this gate did not exercise the unwind and is NOT attributable to #3475" \
    "put=${CC} delete=${DEL2} path=${DECOY_PATH2}"
elif [ "$TAGS2" = "$VICTIM_TAGS_BEFORE" ] && [ "$PULL3" = "200" ]; then
  pass
else
  fail "DECOY-DIGEST INDEX DESTRUCTION (#3475): a decoy under the victim's OWN image name at the forged reference ${DECOY_REF2} destroyed it — oci_tags ${VICTIM_TAGS_BEFORE} -> ${TAGS2}, pull=${PULL3}. The reference has no index row of its own, so there is nothing for it to unwind; resolving the digest from the row's checksum invented one" \
    "tags=${TAGS2} pull=${PULL3} path=${DECOY_PATH2}"
fi

end_suite
