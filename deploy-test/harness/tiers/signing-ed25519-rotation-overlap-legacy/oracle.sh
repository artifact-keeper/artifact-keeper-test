#!/usr/bin/env bash
# =============================================================================
# tiers/signing-ed25519-rotation-overlap-legacy/oracle.sh
#   1.11.0 OpenPGP signing-key features and fixes for Debian/RPM metadata:
#   Ed25519 OpenPGP keys (#1326), the rotation overlap window with dual
#   signatures (#1329), revoke stamping expires_at (#1329), startup migration
#   of legacy keys with SIGNING_AUTO_MIGRATE_LEGACY_KEYS (#1331), and rotating
#   an unscoped key repointing the repositories bound to it (#4416).
# See the manifest for the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, BACKEND_IMAGE and the slot's port block, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
CAPT="ak-dtf${DTF_SLOT}-client-apt"
BACKEND_INTERNAL="http://backend:8080"
OVERLAP_DEFAULT=1209600   # SIGNING_KEY_ROTATION_OVERLAP_SECS default: 14 days

setup_workdir
W="$WORK_DIR"
export GNUPGHOME="$W/gnupg"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

http(){ # <method> <path> <outfile> [curl args...] -> HTTP code (admin bearer)
  local m="$1" u="$2" o="$3"
  shift 3
  rm -f "$o"
  curl -s --max-time 120 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $TOK" "$@" "$BASE$u" || true
  [ -f "$o" ] || : > "$o"
}
body(){ head -c 300 "$1" 2>/dev/null | tr -d '\n' || true; }
post_json(){ http POST "$1" "$2" -H 'Content-Type: application/json' -d "$3"; }
epoch(){ date -d "$1" +%s 2>/dev/null || echo 0; }

mkrepo(){ # <key> <format> -> id (public, so the apt client needs no credentials)
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:true}')" | jqr '.id // empty'
}
mkkey(){ # <name> <key_type> <algorithm> -> sets KCODE and KID; response in $W/key.json
  KCODE="$(post_json /api/v1/signing/keys "$W/key.json" "$(jq -nc --arg n "$1" --arg t "$2" --arg a "$3" '{name:$n,key_type:$t,algorithm:$a}')")"
  KID="$(jqr '.id // empty' < "$W/key.json")"
}
bind(){ # <repo id> <key id> -> HTTP code
  post_json "/api/v1/signing/repositories/$1/config" "$W/bind.json" "$(jq -nc --arg k "$2" '{signing_key_id:$k,sign_metadata:true}')"
}
bound_key(){ psql_q "SELECT signing_key_id FROM repository_signing_config WHERE repository_id='$1';"; }
deb_get(){ http GET "/debian/$1/dists/stable/$2" "$3"; }
rpm_get(){ http GET "/rpm/$1/repodata/$2" "$3"; }

# sig_packets <file> -> "count:keyid,keyid:digest-algos" of the OpenPGP
# signature packets in a detached signature or a clearsigned message.
sig_packets(){
  local f="$1" s="$W/sigblk.asc"
  if grep -q 'BEGIN PGP SIGNED MESSAGE' "$f" 2>/dev/null; then
    sed -n '/-----BEGIN PGP SIGNATURE-----/,/-----END PGP SIGNATURE-----/p' "$f" > "$s"
  else
    cp "$f" "$s" 2>/dev/null || : > "$s"
  fi
  gpg --list-packets "$s" 2>/dev/null | awk '
    function tok(x) { gsub(/,/, "", x); return x }
    /^:signature packet:/ { n++; for (i=1;i<=NF;i++) { if ($i=="keyid") k = k (k?",":"") tok($(i+1)); if ($i=="algo") pk = pk (pk?",":"") tok($(i+1)) } }
    /digest algo/ { d = d (d?",":"") tok($3) }
    END { printf "%d:%s:%s:%s\n", n, k, d, pk }' | tr -d ' ' || true
}
# keyring_keys <armored keyring> -> number of public keys in it
keyring_keys(){ gpg --list-packets "$1" 2>/dev/null | grep -c '^:public key packet:' || true; }
# gpg_verify <keyring.asc> <sig-or-clearsigned> [data] -> 0 when gpgv reports a good signature
gpg_verify(){
  local kr="$W/kr.$RANDOM.gpg"
  gpg --batch --yes --dearmor -o "$kr" < "$1" >/dev/null 2>&1 || return 1
  if [ -n "${3:-}" ]; then gpgv --keyring "$kr" "$2" "$3" >"$W/gpgv.log" 2>&1; else gpgv --keyring "$kr" "$2" >"$W/gpgv.log" 2>&1; fi
}
# apt_update <repo key> <key file on host> -> "rc|first error line" with only that key trusted
apt_update(){
  docker cp "$2" "${CAPT}:/tmp/dtf-trust.asc" >/dev/null 2>&1 || true
  docker exec "$CAPT" bash -c '
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list; rm -rf /etc/apt/sources.list.d/* /var/lib/apt/lists/*
echo "deb [signed-by=/tmp/dtf-trust.asc] '"${BACKEND_INTERNAL}/debian/$1"' stable main" > /etc/apt/sources.list.d/dtf.list
apt-get -o Acquire::Check-Valid-Until=false update > /tmp/dtf-apt.log 2>&1; rc=$?
err="$(grep -E "^(E|W):.*(GPG|NO_PUBKEY|signature|not signed|no longer signed|Release)" /tmp/dtf-apt.log | head -1)"
echo "${rc}|${err}"' 2>/dev/null || echo "exec-failed|"
}
audit_details(){ # <key id> <action> -> details JSON of the latest such signing_key_audit row
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT details FROM signing_key_audit WHERE signing_key_id='$1' AND action='$2' ORDER BY created_at DESC LIMIT 1;" 2>/dev/null | head -1 || true
}

# recreate_backend <ENV=VAL>... : recreate only the backend on this slot's
# project with extra environment (the xff-authz-trust idiom); --wait gates it.
# Same project, same volumes, so the database and stored keys survive.
recreate_backend(){
  local override="$W/override.yml" kv
  # json-file logging: the migration case reads the backend's startup log
  # with `docker logs` (rootless podman otherwise defaults to journald).
  { echo "services:"; echo "  backend:"; echo "    logging:"; echo "      driver: json-file"; echo "    environment:"
    for kv in "$@"; do echo "      ${kv%%=*}: \"${kv#*=}\""; done; } > "$override"
  docker compose -p "ak-dtf${DTF_SLOT}" \
    -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "${DTF_DIR}/profiles/client.apt.yml" \
    -f "$override" \
    up -d --wait backend >"$W/recreate.log" 2>&1
}

# =============================================================================
begin_suite "signing-ed25519-rotation-overlap-legacy"

begin_test "setup: admin login, gpg on the host, Debian and RPM repositories"
{ command -v gpg >/dev/null 2>&1 && command -v gpgv >/dev/null 2>&1; } || { infra_fail "gpg/gpgv not on the host running the oracle"; end_suite; }
docker exec "$CAPT" true >/dev/null 2>&1 || { infra_fail "apt client container ${CAPT} not running (profiles/client.apt.yml)"; end_suite; }
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
[ -n "$TOK" ] || { infra_fail "admin login failed at $BASE"; end_suite; }
SUF="${RUN_ID##*-}-$$"
R_ED="sg-ed-${DTF_SLOT}-${SUF}"; R_ROT="sg-rot-${DTF_SLOT}-${SUF}"; R_RPM="sg-rpm-${DTF_SLOT}-${SUF}"
R_ZERO="sg-zero-${DTF_SLOT}-${SUF}"; R_LEG="sg-leg-${DTF_SLOT}-${SUF}"
ID_ED="$(mkrepo "$R_ED" debian)"; ID_ROT="$(mkrepo "$R_ROT" debian)"; ID_RPM="$(mkrepo "$R_RPM" rpm)"
ID_ZERO="$(mkrepo "$R_ZERO" debian)"; ID_LEG="$(mkrepo "$R_LEG" debian)"
for v in ID_ED ID_ROT ID_RPM ID_ZERO ID_LEG; do [ -n "${!v}" ] || { infra_fail "could not create repository ${v}"; end_suite; }; done
pass

# =============================================================================
# FIX #1326: key_type "ed25519" is refused with a pointer at the gpg form.
# =============================================================================
begin_test "FIX #1326: POST /signing/keys {key_type:\"ed25519\"} is 400 pointing at key_type \"gpg\" + algorithm \"ed25519\""
reset_case
mkkey "sg-bad-${SUF}" ed25519 ed25519
msg="$(jqr '.message // empty' < "$W/key.json")"
note "HTTP ${KCODE}: ${msg}"
[ "$KCODE" = "400" ] || fail_g "key_type=ed25519 was HTTP ${KCODE}, expected 400"
case "$msg" in *"key_type='gpg'"*"algorithm='ed25519'"*) ;; *) fail_g "the refusal does not point at key_type='gpg' with algorithm='ed25519' (1.10.0: 'Unsupported algorithm: ed25519. Use rsa2048 or rsa4096.')";; esac
finish_case "#1326: key_type=ed25519 refusal does not name the gpg form"

# =============================================================================
# FIX #1326: an Ed25519 OpenPGP key signs Debian metadata with EdDSA/SHA-512
# and the served chain verifies.
# =============================================================================
begin_test "FIX #1326: {key_type:gpg, algorithm:ed25519} is an EdDSA v4 key (algo 22, 40-hex fingerprint); InRelease and Release.gpg are EdDSA/SHA-512 signatures gpgv verifies"
reset_case
mkkey "sg-ed-${SUF}" gpg ed25519; K_ED="$KID"
note "create: HTTP ${KCODE} fingerprint $(jqr '.fingerprint' < "$W/key.json")"
if [ -z "$K_ED" ]; then
  fail_g "an Ed25519 OpenPGP key could not be created (HTTP ${KCODE}: $(body "$W/key.json"))"
else
  fp="$(jqr '.fingerprint' < "$W/key.json")"
  [[ "$fp" =~ ^[0-9a-fA-F]{40}$ ]] || fail_g "fingerprint '${fp}' is not 40 hex digits (a v4 OpenPGP fingerprint)"
  c="$(bind "$ID_ED" "$K_ED")"; [ "$c" = "200" ] || fail_g "binding the key to ${R_ED} was HTTP ${c}: $(body "$W/bind.json")"
  for f in InRelease Release Release.gpg gpg-key.asc; do deb_get "$R_ED" "$f" "$W/ed.$f" >/dev/null; done
  pk_algo="$(gpg --list-packets "$W/ed.gpg-key.asc" 2>/dev/null | awk '/^:public key packet:/ {getline; for (i=1;i<=NF;i++) if ($i=="algo") {print $(i+1); exit}}' | tr -d ',' || true)"
  sp_in="$(sig_packets "$W/ed.InRelease")"; sp_rg="$(sig_packets "$W/ed.Release.gpg")"
  note "gpg-key.asc primary key algo ${pk_algo}; InRelease sigs ${sp_in}; Release.gpg sigs ${sp_rg}"
  [ "$pk_algo" = "22" ] || fail_g "the served public key is algo ${pk_algo:-?}, expected 22 (EdDSA)"
  [ "${sp_in%%:*}" = "1" ] && [ "$(cut -d: -f3 <<<"$sp_in")" = "10" ] && [ "$(cut -d: -f4 <<<"$sp_in")" = "22" ] || fail_g "InRelease is not one EdDSA (22) / SHA-512 (10) signature: ${sp_in}"
  [ "$(cut -d: -f3 <<<"$sp_rg")" = "10" ] && [ "$(cut -d: -f4 <<<"$sp_rg")" = "22" ] || fail_g "Release.gpg is not an EdDSA / SHA-512 signature: ${sp_rg}"
  gpg_verify "$W/ed.gpg-key.asc" "$W/ed.InRelease" || fail_g "gpgv does not verify InRelease with the served key: $(tail -2 "$W/gpgv.log" | tr '\n' ' ')"
  gpg_verify "$W/ed.gpg-key.asc" "$W/ed.Release.gpg" "$W/ed.Release" || fail_g "gpgv does not verify Release.gpg over Release: $(tail -2 "$W/gpgv.log" | tr '\n' ' ')"
fi
finish_case "#1326: Ed25519 OpenPGP metadata signing broken"

# =============================================================================
# CONTROL (both images): an unscoped gpg key bound to a Debian and an RPM
# repository through the config route signs both; apt trusting that key
# updates cleanly.
# =============================================================================
begin_test "CONTROL: an unscoped gpg rsa2048 key bound to Debian + RPM repositories: InRelease and repomd.xml.asc verify; apt trusting it updates cleanly"
reset_case
mkkey "sg-rot-${SUF}" gpg rsa2048; K_OLD="$KID"
[ -n "$K_OLD" ] || { infra_fail "gpg rsa2048 key create was HTTP ${KCODE}: $(body "$W/key.json")"; end_suite; }
c1="$(bind "$ID_ROT" "$K_OLD")"; c2="$(bind "$ID_RPM" "$K_OLD")"
[ "$c1" = "200" ] && [ "$c2" = "200" ] || { infra_fail "binding the key was HTTP ${c1}/${c2}"; end_suite; }
deb_get "$R_ROT" gpg-key.asc "$W/old.asc" >/dev/null
deb_get "$R_ROT" InRelease "$W/r0.InRelease" >/dev/null
rpm_get "$R_RPM" repomd.xml "$W/r0.repomd.xml" >/dev/null; rpm_get "$R_RPM" repomd.xml.asc "$W/r0.repomd.xml.asc" >/dev/null
OLD_KEYID="$(gpg --list-packets "$W/old.asc" 2>/dev/null | awk '/keyid:/ {print $2; exit}' || true)"
note "old key ${K_OLD} keyid ${OLD_KEYID}; InRelease sigs $(sig_packets "$W/r0.InRelease"); repomd.xml.asc sigs $(sig_packets "$W/r0.repomd.xml.asc")"
gpg_verify "$W/old.asc" "$W/r0.InRelease" || fail_g "InRelease does not verify with the bound key"
gpg_verify "$W/old.asc" "$W/r0.repomd.xml.asc" "$W/r0.repomd.xml" || fail_g "repomd.xml.asc does not verify with the bound key"
a="$(apt_update "$R_ROT" "$W/old.asc")"
note "apt-get update trusting the key: ${a}"
[ "${a%%|*}" = "0" ] && [ -z "${a#*|}" ] || fail_g "apt-get update was not clean: ${a}"
finish_case "baseline OpenPGP metadata signing / apt trust broken"

# =============================================================================
# FIX #1329 + #4416: rotating the unscoped key repoints both repositories to
# the successor and opens a 14-day overlap: metadata carries old + new
# signatures, the keyring serves both keys, the old key's expires_at is the
# overlap end, and the rotation audit records overlap_ends_at.
# =============================================================================
begin_test "FIX #4416/#1329: rotating the unscoped key repoints both repositories; InRelease, Release.gpg and repomd.xml.asc carry old + new signatures; gpg-key.asc serves both keys; expires_at = now + 14 days; audit overlap_ends_at"
reset_case
c="$(http POST "/api/v1/signing/keys/${K_OLD}/rotate" "$W/rot.json")"
K_NEW="$(jqr '.id // empty' < "$W/rot.json")"; T_ROT="$(date +%s)"
note "rotate: HTTP ${c} new key ${K_NEW}"
[ "$c" = "200" ] && [ -n "$K_NEW" ] || { infra_fail "rotate was HTTP ${c}: $(body "$W/rot.json")"; end_suite; }
b1="$(bound_key "$ID_ROT")"; b2="$(bound_key "$ID_RPM")"
note "bindings after rotate: debian ${b1}, rpm ${b2}"
[ "$b1" = "$K_NEW" ] && [ "$b2" = "$K_NEW" ] || fail_g "the bindings were not repointed to the successor (debian ${b1}, rpm ${b2}; 1.10.0 leaves them on the inactive key)"
ci="$(deb_get "$R_ROT" InRelease "$W/r1.InRelease")"; deb_get "$R_ROT" Release "$W/r1.Release" >/dev/null; deb_get "$R_ROT" Release.gpg "$W/r1.Release.gpg" >/dev/null
deb_get "$R_ROT" gpg-key.asc "$W/r1.keyring.asc" >/dev/null
rpm_get "$R_RPM" repomd.xml "$W/r1.repomd.xml" >/dev/null; cr="$(rpm_get "$R_RPM" repomd.xml.asc "$W/r1.repomd.xml.asc")"
rpm_get "$R_RPM" repomd.xml.key "$W/r1.repomd.key" >/dev/null
sp_in="$(sig_packets "$W/r1.InRelease")"; sp_rg="$(sig_packets "$W/r1.Release.gpg")"; sp_rp="$(sig_packets "$W/r1.repomd.xml.asc")"
note "InRelease HTTP ${ci} sigs ${sp_in}; Release.gpg sigs ${sp_rg}; repomd.xml.asc HTTP ${cr} sigs ${sp_rp}"
note "gpg-key.asc keys $(keyring_keys "$W/r1.keyring.asc"); repomd.xml.key keys $(keyring_keys "$W/r1.repomd.key")"
[ "$ci" = "200" ] || fail_g "InRelease after rotating the unscoped key was HTTP ${ci} (#4416: 404 before the fix)"
for sp in "$sp_in" "$sp_rg" "$sp_rp"; do
  [ "${sp%%:*}" = "2" ] || fail_g "a metadata signature carries ${sp%%:*} signature packet(s), expected 2 (old + new) during the overlap"
  case "$(cut -d: -f2 <<<"$sp")" in *"$OLD_KEYID"*) ;; *) fail_g "the old key ${OLD_KEYID} is not among the signers (${sp})";; esac
done
[ "$(keyring_keys "$W/r1.keyring.asc")" = "2" ] || fail_g "gpg-key.asc serves $(keyring_keys "$W/r1.keyring.asc") key(s), expected 2"
[ "$(keyring_keys "$W/r1.repomd.key")" = "2" ] || fail_g "repomd.xml.key serves $(keyring_keys "$W/r1.repomd.key") key(s), expected 2"
gpg_verify "$W/r1.keyring.asc" "$W/r1.repomd.xml.asc" "$W/r1.repomd.xml" || fail_g "repomd.xml.asc does not verify against the served keyring"
http GET "/api/v1/signing/keys/${K_OLD}" "$W/old.json" >/dev/null
exp="$(jqr '.expires_at // empty' < "$W/old.json")"; gap=$(( $(epoch "$exp") - T_ROT ))
note "old key is_active $(jqr '.is_active' < "$W/old.json"), expires_at ${exp:-null} (now + ${gap}s)"
[ "$(jqr '.is_active' < "$W/old.json")" = "false" ] || fail_g "the old key is still active"
[ "$gap" -ge $(( OVERLAP_DEFAULT - 120 )) ] && [ "$gap" -le $(( OVERLAP_DEFAULT + 120 )) ] || fail_g "old key expires_at is now + ${gap}s, expected about ${OVERLAP_DEFAULT}s (14 days)"
ad="$(audit_details "$K_OLD" rotated)"
note "rotation audit: ${ad}"
[ -n "$(jqr '.overlap_ends_at // empty' <<<"$ad")" ] || fail_g "the rotation audit row has no overlap_ends_at"
case "$(jqr '.repointed_repository_ids | join(",")' <<<"$ad")" in *"$ID_ROT"*"$ID_RPM"*|*"$ID_RPM"*"$ID_ROT"*) ;; *) fail_g "the rotation audit does not list both repointed repositories";; esac
finish_case "#4416/#1329: rotation does not repoint or does not dual-sign"

begin_test "FIX #1329: an apt client that trusts only the OLD key still updates cleanly during the overlap"
reset_case
a="$(apt_update "$R_ROT" "$W/old.asc")"
note "apt-get update with only the old key: ${a}"
[ "${a%%|*}" = "0" ] && [ -z "${a#*|}" ] || fail_g "apt holding only the old key failed during the overlap: ${a}"
finish_case "#1329: clients pinned to the old key break at rotation"

# =============================================================================
# FIX #1329: revoking the predecessor ends its overlap (expires_at <= now);
# metadata is signed by the successor alone and the old-key-only client now
# fails (proves the previous case passed because of the overlap).
# =============================================================================
begin_test "FIX #1329: revoking the old key stamps expires_at <= now and ends the overlap: one signature, and the old-key-only apt client is refused"
reset_case
c="$(http POST "/api/v1/signing/keys/${K_OLD}/revoke" "$W/rv.json")"
http GET "/api/v1/signing/keys/${K_OLD}" "$W/old.json" >/dev/null
exp="$(jqr '.expires_at // empty' < "$W/old.json")"
deb_get "$R_ROT" InRelease "$W/r2.InRelease" >/dev/null
sp="$(sig_packets "$W/r2.InRelease")"
a="$(apt_update "$R_ROT" "$W/old.asc")"
note "revoke HTTP ${c}; old key expires_at ${exp:-null}; InRelease sigs ${sp}; apt with only the old key: ${a}"
[ "$c" = "200" ] || fail_g "revoke was HTTP ${c}"
[ -n "$exp" ] && [ "$(epoch "$exp")" -le $(( $(date +%s) + 5 )) ] || fail_g "revoke left expires_at ${exp:-null}, expected a time <= now"
[ "${sp%%:*}" = "1" ] || fail_g "InRelease carries ${sp%%:*} signatures after the revoke, expected 1"
case "$(cut -d: -f2 <<<"$sp")" in *"$OLD_KEYID"*) fail_g "the revoked key still signs InRelease";; esac
case "${a#*|}" in *NO_PUBKEY*|*GPG*|*signature*) ;; *) fail_g "apt holding only the revoked key was not refused: ${a}";; esac
finish_case "#1329: revoke does not end the overlap"

# =============================================================================
# Phase 2 preparation (#1331): a legacy key_type=rsa key bound to a Debian
# repository's metadata signing. The API refuses that binding now, so it is
# written with SQL onto a binding the API made.
# =============================================================================
mkkey "sg-legacy-${SUF}" rsa rsa2048; K_LEG="$KID"
mkkey "sg-legtmp-${SUF}" gpg rsa2048; K_TMP="$KID"
LEG_PRE=""
if [ -n "$K_LEG" ] && [ -n "$K_TMP" ] && [ "$(bind "$ID_LEG" "$K_TMP")" = "200" ] \
   && psql_x "UPDATE repository_signing_config SET signing_key_id='${K_LEG}' WHERE repository_id='${ID_LEG}';"; then
  LEG_PRE="$(deb_get "$R_LEG" InRelease "$W/leg0.InRelease")"
fi

begin_test "phase 2: recreate the backend with SIGNING_AUTO_MIGRATE_LEGACY_KEYS=true and SIGNING_KEY_ROTATION_OVERLAP_SECS=0"
LOG_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if recreate_backend SIGNING_AUTO_MIGRATE_LEGACY_KEYS=true SIGNING_KEY_ROTATION_OVERLAP_SECS=0; then
  TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
  if [ -n "$TOK" ]; then pass; else infra_fail "admin login failed after the recreate"; fi
else
  infra_fail "backend recreate failed: $(tail -5 "$W/recreate.log" | tr '\n' ' ')"; end_suite
fi

begin_test "FIX #1331: at startup the legacy rsa key bound to Debian metadata is replaced by a new gpg key; the repository is repointed, the old key audited auto_migrated, and InRelease verifies"
reset_case
[ -n "$K_LEG" ] && [ -n "$LEG_PRE" ] || { infra_fail "could not seed the legacy binding (rsa key ${K_LEG:-none})"; end_suite; }
nb=""
for _i in $(seq 1 20); do nb="$(bound_key "$ID_LEG")"; [ -n "$nb" ] && [ "$nb" != "$K_LEG" ] && break; sleep 1; done
ntype="$(psql_q "SELECT key_type FROM signing_keys WHERE id='${nb}';")"
ad="$(audit_details "$K_LEG" auto_migrated)"
ci="$(deb_get "$R_LEG" InRelease "$W/leg1.InRelease")"; deb_get "$R_LEG" gpg-key.asc "$W/leg1.asc" >/dev/null
wl="$(docker logs --since "$LOG_SINCE" "$BACKEND_CTR" 2>&1 | grep -a -c 'SIGNING_AUTO_MIGRATE_LEGACY_KEYS: replaced legacy signing key' || true)"
note "InRelease before the restart: HTTP ${LEG_PRE}; binding now ${nb} (key_type ${ntype:-?}); audit ${ad:-none}; InRelease HTTP ${ci}; migration log lines ${wl}"
[ "$nb" != "$K_LEG" ] && [ "$ntype" = "gpg" ] || fail_g "the repository is still bound to the legacy rsa key (or to a non-gpg key: ${ntype:-none})"
[ "$(jqr '.new_key_id // empty' <<<"$ad")" = "$nb" ] || fail_g "no auto_migrated audit row for the legacy key naming the new key"
{ [ "$ci" = "200" ] && gpg_verify "$W/leg1.asc" "$W/leg1.InRelease"; } || fail_g "InRelease is HTTP ${ci} or does not verify with the served key after the migration"
[ "${wl:-0}" -ge 1 ] 2>/dev/null || fail_g "no startup log line for the migration"
finish_case "#1331: SIGNING_AUTO_MIGRATE_LEGACY_KEYS does not migrate a legacy key"

begin_test "FIX #1329: with SIGNING_KEY_ROTATION_OVERLAP_SECS=0 a rotation retires the old key at once: one signature, expires_at = now, overlap_ends_at null"
reset_case
mkkey "sg-zero-${SUF}" gpg rsa2048; K_Z="$KID"
[ -n "$K_Z" ] && [ "$(bind "$ID_ZERO" "$K_Z")" = "200" ] || { infra_fail "could not create and bind the key (HTTP ${KCODE})"; end_suite; }
deb_get "$R_ZERO" gpg-key.asc "$W/z0.asc" >/dev/null
ZKEYID="$(gpg --list-packets "$W/z0.asc" 2>/dev/null | awk '/keyid:/ {print $2; exit}' || true)"
c="$(http POST "/api/v1/signing/keys/${K_Z}/rotate" "$W/zrot.json")"; T_Z="$(date +%s)"
ci="$(deb_get "$R_ZERO" InRelease "$W/z1.InRelease")"; deb_get "$R_ZERO" gpg-key.asc "$W/z1.asc" >/dev/null
sp="$(sig_packets "$W/z1.InRelease")"
http GET "/api/v1/signing/keys/${K_Z}" "$W/z.json" >/dev/null
exp="$(jqr '.expires_at // empty' < "$W/z.json")"; ad="$(audit_details "$K_Z" rotated)"
note "rotate HTTP ${c}; InRelease HTTP ${ci} sigs ${sp}; keyring keys $(keyring_keys "$W/z1.asc"); old expires_at ${exp:-null}; audit ${ad:-none}"
[ "$ci" = "200" ] || fail_g "InRelease after the rotation was HTTP ${ci}"
[ "${sp%%:*}" = "1" ] || fail_g "InRelease carries ${sp%%:*} signatures, expected 1 (no overlap)"
case "$(cut -d: -f2 <<<"$sp")" in *"$ZKEYID"*) fail_g "the retired key still signs";; esac
[ "$(keyring_keys "$W/z1.asc")" = "1" ] || fail_g "gpg-key.asc serves $(keyring_keys "$W/z1.asc") keys, expected 1"
[ -n "$exp" ] && [ "$(epoch "$exp")" -le $(( T_Z + 5 )) ] || fail_g "the old key's expires_at is ${exp:-null}, expected the rotation time"
[ -n "$ad" ] && [ "$(jqr '.overlap_ends_at' <<<"$ad")" = "null" ] || fail_g "the rotation audit's overlap_ends_at is not null: ${ad:-no row}"
finish_case "#1329: SIGNING_KEY_ROTATION_OVERLAP_SECS=0 does not retire immediately"

end_suite
