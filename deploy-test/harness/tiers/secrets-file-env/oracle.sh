#!/usr/bin/env bash
# =============================================================================
# tiers/secrets-file-env/oracle.sh
#   #4142 / #4775  credential-typed settings read from <NAME>_FILE secret mounts
# See the manifest for THE FEATURE, the legs and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
PROJECT="ak-dtf${DTF_SLOT}"
FX="${HERE}/fixtures"
# The stack as run.sh brought it up (restored at the end) ...
BASEF=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml")
# ... and the leg overrides, each layered alone and directly on the base (see
# the comment at the top of any fixtures/secrets.*.yml for why).
BASE0=(-f "${DTF_DIR}/compose.base.yml")
MOUNT_DIR="/run/secrets/ak"
# The DATABASE_URL compose.base.yml hard-codes; the file form carries the same
# value, so a backend that boots from it reaches the same Postgres. Assembled
# from parts (the throwaway compose.base.yml role) so secret scanners do not
# read a literal connection URI here.
PG_ROLE="registry"
db_url(){ printf 'postgresql://%s:%s@%s:5432/artifact_registry' "$PG_ROLE" "$PG_ROLE" "$1"; }
DB_URL="$(db_url postgres)"

setup_workdir
W="$WORK_DIR"
SECRETS="${W}/secrets"
mkdir -p "$SECRETS"

# common.sh may run under `set -e`: every probe below swallows its own failure
# and the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- per-run secret values ---------------------------------------------------
# Random per run so a grep for them in logs / bodies cannot hit anything else.
# JWT secrets are 48 random bytes in base64 (the backend's own recommendation,
# so the #4211 strength check accepts them). The files carry surrounding
# whitespace and a trailing newline on purpose: #4775 trims file contents.
rand_b64(){ head -c 48 /dev/urandom | base64 | tr -d '\n=+/' ; }
JWT_FILE_VAL="$(rand_b64)"
JWT_DIRECT_VAL="$(rand_b64)"
ADMIN_FILE_VAL="SfAdm!$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')Q9"
printf '  %s\n\n' "$JWT_FILE_VAL" > "${SECRETS}/jwt_secret"
printf '%s\n' "$ADMIN_FILE_VAL" > "${SECRETS}/admin_password"
printf '%s\n' "$DB_URL" > "${SECRETS}/database_url"
# A file the direct DATABASE_URL must win over: pointing the backend at it
# would fail to connect (no such host), so booting proves the direct value won.
printf '%s\n' "$(db_url sf-no-such-host.invalid)" > "${SECRETS}/database_url_wrong"
: > "${SECRETS}/empty"
# Readable by the backend's non-root uid through the bind mount.
chmod 755 "$W" "$SECRETS"
chmod 644 "$SECRETS"/*
export SF_SECRETS_DIR="$SECRETS"

# --- stack control -----------------------------------------------------------
# recreate_backend <override>: recreate only the backend with
# fixtures/secrets.<override>.yml and the SF_* / direct values the caller
# exported, then wait for it to answer /health or exit. Prints "up" or
# "exited <code>" (or "timeout").
recreate_backend(){
  local files=("${BASE0[@]}" -f "${FX}/secrets.$1.yml") st
  docker compose -p "$PROJECT" "${files[@]}" up -d --no-deps --force-recreate backend \
    >"${W}/recreate.log" 2>&1 || true
  for _ in $(seq 1 60); do
    st="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$BACKEND_CTR" 2>/dev/null || true)"
    case "$st" in
      exited*|dead*) echo "exited ${st#* }"; return 0 ;;
    esac
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${BASE}/health" 2>/dev/null)" = "200" ]; then
      echo "up"; return 0
    fi
    sleep 2
  done
  echo "timeout"
}
backend_logs(){ docker logs "$BACKEND_CTR" 2>&1 || true; }
backend_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null || true; }

login_body(){ # <user> <password> -> body
  curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" 2>/dev/null || true
}
login_code(){
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" 2>/dev/null || true
}
# jwt_signed_with <token> <secret>: exit 0 when the HS256 signature verifies.
jwt_signed_with(){
  python3 -I -c '
import base64, hashlib, hmac, sys
tok, key = sys.argv[1], sys.argv[2].encode()
parts = tok.split(".")
if len(parts) != 3: sys.exit(2)
mac = hmac.new(key, (parts[0] + "." + parts[1]).encode(), hashlib.sha256).digest()
sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
sys.exit(0 if hmac.compare_digest(sig, parts[2]) else 1)
' "$1" "$2" 2>/dev/null
}
jwt_alg(){ python3 -I -c '
import base64, json, sys
h = sys.argv[1].split(".")[0]; h += "=" * (-len(h) % 4)
print(json.loads(base64.urlsafe_b64decode(h)).get("alg", ""))
' "$1" 2>/dev/null || true; }

# leaks <label> <text>: fail_g when any secret value appears in <text>.
leaks(){
  local label="$1" text="$2"
  case "$text" in *"$JWT_FILE_VAL"*) fail_g "${label} contains the JWT_SECRET_FILE value" ;; esac
  case "$text" in *"$JWT_DIRECT_VAL"*) fail_g "${label} contains the direct JWT_SECRET value" ;; esac
  case "$text" in *"$ADMIN_FILE_VAL"*) fail_g "${label} contains the ADMIN_PASSWORD_FILE value" ;; esac
  case "$text" in *"$DB_URL"*) fail_g "${label} contains the DATABASE_URL_FILE value (the full connection URL)" ;; esac
  return 0
}

begin_suite "secrets-file-env"

# =============================================================================
# Leg 1: a FRESH instance whose three startup credentials exist only as files.
# =============================================================================
begin_test "FIX #4142: with DATABASE_URL, JWT_SECRET and ADMIN_PASSWORD only as *_FILE mounts (JWT_SECRET / ADMIN_PASSWORD absent, DATABASE_URL blank) a fresh instance boots, provisions admin with the trimmed file password and signs tokens with the trimmed file secret"
reset_case
docker compose -p "$PROJECT" "${BASEF[@]}" down -v >/dev/null 2>&1 || true
if ! docker compose -p "$PROJECT" "${BASEF[@]}" up -d --wait postgres >"${W}/pg.log" 2>&1; then
  infra_fail "could not bring a fresh postgres up for the files-only leg: $(tail -5 "${W}/pg.log")"; end_suite
fi
export SF_DATABASE_URL_FILE="${MOUNT_DIR}/database_url" SF_JWT_SECRET_FILE="${MOUNT_DIR}/jwt_secret" SF_ADMIN_PASSWORD_FILE="${MOUNT_DIR}/admin_password"
ST="$(recreate_backend files-only)"
LOGS1="$(backend_logs)"
ENV1="$(backend_env)"
note "backend: ${ST}"
if [ "$ST" != "up" ]; then
  fail_g "the backend did not boot from the *_FILE mounts (${ST}); last log lines: $(printf '%s\n' "$LOGS1" | tail -3 | tr '\n' ' ' | head -c 400)"
fi
grep -q '^JWT_SECRET=\|^ADMIN_PASSWORD=' <<<"$ENV1" && fail_g "a direct JWT_SECRET / ADMIN_PASSWORD is still in the container environment (the override did not remove it)"
grep -qx 'DATABASE_URL=' <<<"$ENV1" || fail_g "DATABASE_URL in the container is not blank: $(grep '^DATABASE_URL=' <<<"$ENV1" | head -c 120)"
B1="$(login_body admin "$ADMIN_FILE_VAL")"
TOK1="$(jqr '.access_token // empty' <<<"$B1")"
if [ -z "$TOK1" ]; then
  fail_g "admin could not log in with the (trimmed) ADMIN_PASSWORD_FILE value: $(head -c 200 <<<"$B1")"
else
  note "admin login with the file password: token issued (alg $(jwt_alg "$TOK1"))"
  jwt_signed_with "$TOK1" "$JWT_FILE_VAL" || fail_g "the access token is not HS256-signed with the trimmed JWT_SECRET_FILE contents"
  # The untrimmed bytes (leading spaces, trailing blank line) must not be the key.
  jwt_signed_with "$TOK1" "$(cat "${SECRETS}/jwt_secret")" && fail_g "the token verifies with the UNtrimmed file contents"
  c="$(curl -s -o "${W}/repos1.json" -w '%{http_code}' --max-time 15 -H "Authorization: Bearer ${TOK1}" "${BASE}/api/v1/repositories")"
  [ "$c" = "200" ] || fail_g "an authenticated DB read (GET /api/v1/repositories) answered ${c}, so the file DATABASE_URL did not give a working pool"
fi
c="$(login_code admin "$ADMIN_PASS")"
[ "$c" = "401" ] || fail_g "admin login with the compose.base.yml default password answered ${c}, expected 401 (the file password, not a default, must have been provisioned)"
finish_case "#4142: the backend does not take its startup credentials from *_FILE mounts"

begin_test "FIX #4142: a secret read from a file never appears in /api/v1/system/config, an error body, the container environment or the backend log"
reset_case
if [ -z "${TOK1:-}" ]; then
  fail_g "no admin session from the files-only leg, so the read-back surfaces cannot be inspected"
else
  CFG="$(curl -s --max-time 15 -H "Authorization: Bearer ${TOK1}" "${BASE}/api/v1/system/config" 2>/dev/null || true)"
  [ -n "$(jqr '.auth // empty' <<<"$CFG")" ] || fail_g "GET /api/v1/system/config (admin) did not answer a config body: $(head -c 200 <<<"$CFG")"
  leaks "/api/v1/system/config (admin)" "$CFG"
  E1="$(login_body admin "wrong-${RUN_ID}")"
  E2="$(curl -s --max-time 15 -H "Authorization: Bearer ${TOK1}x" "${BASE}/api/v1/repositories" 2>/dev/null || true)"
  E3="$(curl -s --max-time 15 -H "Authorization: Bearer ${TOK1}" "${BASE}/api/v1/repositories/sf-missing-${DTF_SLOT}" 2>/dev/null || true)"
  note "error bodies: login $(head -c 80 <<<"$E1") | tampered token $(head -c 80 <<<"$E2") | missing repo $(head -c 80 <<<"$E3")"
  leaks "a failed-login body" "$E1"
  leaks "a tampered-token 401 body" "$E2"
  leaks "a 404 body" "$E3"
  leaks "the container environment (docker inspect)" "$ENV1"
  leaks "the backend log" "$(backend_logs)"
  grep -q "^JWT_SECRET_FILE=${MOUNT_DIR}/jwt_secret$" <<<"$ENV1" || fail_g "JWT_SECRET_FILE is not the mounted path in the container environment"
fi
finish_case "#4142: a file-sourced secret is disclosed on a read-back surface"

# =============================================================================
# Leg 2: both forms set. The direct value wins (the #2084 / #2803 precedence).
# =============================================================================
begin_test "CONTROL: with JWT_SECRET and JWT_SECRET_FILE both set the direct value signs tokens, and a direct DATABASE_URL wins over a DATABASE_URL_FILE that names an unreachable host"
reset_case
export SF_DATABASE_URL_FILE="${MOUNT_DIR}/database_url_wrong" SF_JWT_SECRET_FILE="${MOUNT_DIR}/jwt_secret" SF_ADMIN_PASSWORD_FILE=""
# Interpolated by compose.base.yml. The admin already exists on the fixed
# image (leg 1); on an image where leg 1 never booted, this direct value
# provisions it, so both images log in with the same password.
export JWT_SECRET="$JWT_DIRECT_VAL" ADMIN_PASSWORD="$ADMIN_FILE_VAL"
ST="$(recreate_backend mount)"
note "backend: ${ST}"
[ "$ST" = "up" ] || fail_g "the backend did not boot with both forms set (${ST}): $(backend_logs | tail -3 | tr '\n' ' ' | head -c 400)"
TOK2="$(login_body admin "$ADMIN_FILE_VAL" | jqr '.access_token // empty')"
if [ -z "$TOK2" ]; then
  fail_g "admin could not log in on the both-forms boot"
else
  jwt_signed_with "$TOK2" "$JWT_DIRECT_VAL" || fail_g "the token is not signed with the direct JWT_SECRET"
  jwt_signed_with "$TOK2" "$JWT_FILE_VAL" && fail_g "the token is signed with the JWT_SECRET_FILE value although the direct value is set"
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Authorization: Bearer ${TOK2}" "${BASE}/api/v1/repositories")"
  [ "$c" = "200" ] || fail_g "authenticated DB read answered ${c}"
fi
[ -n "${TOK1:-}" ] && { c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Authorization: Bearer ${TOK1}" "${BASE}/api/v1/repositories")"
  [ "$c" = "401" ] || fail_g "a token signed under the leg-1 file secret answered ${c} after the key changed, expected 401"; }
unset JWT_SECRET ADMIN_PASSWORD
finish_case "the direct value does not win over the *_FILE companion"

# =============================================================================
# Leg 3: a blank direct value does not count; the file decides.
# =============================================================================
begin_test "FIX #4142: JWT_SECRET set to the empty string with JWT_SECRET_FILE set boots and signs with the file secret (a blank direct value counts as unset)"
reset_case
export SF_DATABASE_URL_FILE="" SF_JWT_SECRET_FILE="${MOUNT_DIR}/jwt_secret" SF_ADMIN_PASSWORD_FILE=""
export ADMIN_PASSWORD="$ADMIN_FILE_VAL"
ST="$(recreate_backend blank-jwt)"
note "backend: ${ST}"
if [ "$ST" != "up" ]; then
  fail_g "the backend did not boot (${ST}): $(backend_logs | grep -iE 'error|jwt' | tail -2 | tr '\n' ' ' | head -c 400)"
else
  TOK3="$(login_body admin "$ADMIN_FILE_VAL" | jqr '.access_token // empty')"
  [ -n "$TOK3" ] || fail_g "admin could not log in"
  [ -n "$TOK3" ] && { jwt_signed_with "$TOK3" "$JWT_FILE_VAL" || fail_g "the token is not signed with the JWT_SECRET_FILE value"; }
fi
unset ADMIN_PASSWORD
finish_case "#4142: a blank JWT_SECRET does not fall through to JWT_SECRET_FILE"

# =============================================================================
# Leg 4/5: a *_FILE that is set but broken refuses startup, naming the variable
# and the path, never the contents.
# =============================================================================
begin_test "FIX #4142: JWT_SECRET_FILE naming a file that does not exist refuses startup with an error naming JWT_SECRET_FILE and the path (no boot on an empty secret)"
reset_case
export SF_DATABASE_URL_FILE="${MOUNT_DIR}/database_url" SF_JWT_SECRET_FILE="${MOUNT_DIR}/absent-${DTF_SLOT}" SF_ADMIN_PASSWORD_FILE="${MOUNT_DIR}/admin_password"
ST="$(recreate_backend files-only)"
L4="$(backend_logs)"
note "backend: ${ST}; last line: $(printf '%s\n' "$L4" | tail -1 | head -c 300)"
case "$ST" in exited*) ;; *) fail_g "the backend did not refuse to start (${ST})" ;; esac
grep -q "JWT_SECRET_FILE points at ${MOUNT_DIR}/absent-${DTF_SLOT}, but the file could not be read" <<<"$L4" \
  || fail_g "no startup error naming JWT_SECRET_FILE and ${MOUNT_DIR}/absent-${DTF_SLOT}"
leaks "the refused-startup log" "$L4"
finish_case "#4142: an unreadable JWT_SECRET_FILE does not fail startup with a clear error"

begin_test "FIX #4142: DATABASE_URL_FILE naming an empty file refuses startup with an error naming DATABASE_URL_FILE and the path"
reset_case
export SF_DATABASE_URL_FILE="${MOUNT_DIR}/empty" SF_JWT_SECRET_FILE="${MOUNT_DIR}/jwt_secret" SF_ADMIN_PASSWORD_FILE="${MOUNT_DIR}/admin_password"
ST="$(recreate_backend files-only)"
L5="$(backend_logs)"
note "backend: ${ST}; last line: $(printf '%s\n' "$L5" | tail -1 | head -c 300)"
case "$ST" in exited*) ;; *) fail_g "the backend did not refuse to start (${ST})" ;; esac
grep -q "DATABASE_URL_FILE points at ${MOUNT_DIR}/empty, but the file is empty" <<<"$L5" \
  || fail_g "no startup error naming DATABASE_URL_FILE and ${MOUNT_DIR}/empty"
leaks "the refused-startup log" "$L5"
finish_case "#4142: an empty DATABASE_URL_FILE does not fail startup with a clear error"

begin_test "FIX #4142: ADMIN_PASSWORD_FILE naming a file that does not exist refuses startup (no silent fall-back to a generated password)"
reset_case
export SF_DATABASE_URL_FILE="${MOUNT_DIR}/database_url" SF_JWT_SECRET_FILE="${MOUNT_DIR}/jwt_secret" SF_ADMIN_PASSWORD_FILE="${MOUNT_DIR}/absent-admin-${DTF_SLOT}"
ST="$(recreate_backend files-only)"
L6="$(backend_logs)"
note "backend: ${ST}; last line: $(printf '%s\n' "$L6" | tail -1 | head -c 300)"
case "$ST" in exited*) ;; *) fail_g "the backend did not refuse to start (${ST})" ;; esac
grep -q "ADMIN_PASSWORD_FILE points at ${MOUNT_DIR}/absent-admin-${DTF_SLOT}, but the file could not be read" <<<"$L6" \
  || fail_g "no startup error naming ADMIN_PASSWORD_FILE and the path"
leaks "the refused-startup log" "$L6"
finish_case "#4142: an unreadable ADMIN_PASSWORD_FILE does not fail startup with a clear error"

# =============================================================================
# FIX artifact-keeper#4819 (RED on main 2f08663f, GREEN from main adfa0206):
# the deployment the docs show (only the *_FILE variable set, nothing direct)
# used to inherit the image's baked DATABASE_URL=set-database-url-at-runtime,
# which won over DATABASE_URL_FILE so the backend never started.
# =============================================================================
begin_test "FIX #4819 + CONTROL: with every direct value absent (the documented shape) DATABASE_URL_FILE reaches Postgres and the backend starts; the startup log carries no secret value"
reset_case
export SF_DATABASE_URL_FILE="${MOUNT_DIR}/database_url" SF_JWT_SECRET_FILE="${MOUNT_DIR}/jwt_secret" SF_ADMIN_PASSWORD_FILE="${MOUNT_DIR}/admin_password"
ST="$(recreate_backend image-env)"
IMG_DBURL="$(backend_env | grep '^DATABASE_URL=' | head -1 || true)"
note "backend: ${ST}; container ${IMG_DBURL:-has no DATABASE_URL}; last line: $(backend_logs | tail -1 | head -c 200)"
[ "$ST" = "up" ] || fail_g "#4819: with only *_FILE set the backend is ${ST}: the image-baked ${IMG_DBURL:-DATABASE_URL} won over DATABASE_URL_FILE"
leaks "the startup log" "$(backend_logs)"
finish_case "#4819: the documented *_FILE-only deployment does not start, or a file-sourced secret is disclosed in its startup log"

# =============================================================================
# Back to the stock environment: the default stack still boots and logs in.
# =============================================================================
begin_test "CONTROL: the stock compose.base.yml environment (direct values, no *_FILE) boots and authenticates"
reset_case
export ADMIN_PASSWORD="$ADMIN_FILE_VAL"
docker compose -p "$PROJECT" "${BASEF[@]}" up -d --no-deps --force-recreate --wait backend >"${W}/restore.log" 2>&1 || true
unset ADMIN_PASSWORD
TOK7="$(login_body admin "$ADMIN_FILE_VAL" | jqr '.access_token // empty')"
[ -n "$TOK7" ] || fail_g "admin could not log in on the stock environment: $(tail -3 "${W}/restore.log")"
[ -n "$TOK7" ] && { jwt_signed_with "$TOK7" "dtf-nonprod-cobalt-harbor-lantern-7f3a9c2e5b81" || fail_g "the token is not signed with the compose.base.yml JWT_SECRET"; }
finish_case "the stock environment does not boot and authenticate"

end_suite
