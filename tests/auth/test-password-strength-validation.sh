#!/usr/bin/env bash
# test-password-strength-validation.sh - Password validation boundaries (Epic 11.15, #76)
#
# Backend reference (read 2026-05-16):
#   - `validate_password` in `backend/src/api/handlers/users.rs:67-107`
#     enforces:
#       len < 8    -> AppError::Validation -> HTTP 400 "at least 8 characters"
#       len > 128  -> AppError::Validation -> HTTP 400 "at most 128 characters"
#       common pw  -> AppError::Validation -> HTTP 400 "too common"
#   - `AppError::Validation` maps to HTTP 400 with code VALIDATION_ERROR
#     (error.rs:94). 422 is NOT used by this handler.
#
# Verifies password validation on user creation (POST /api/v1/users) for the
# edge cases that bypass naive `len(s) < MIN` checks:
#
#   1. Unicode (real multi-byte UTF-8 bytes on the wire) in a valid-length
#      password is accepted -- the backend's char-count check must not over-
#      count multi-byte UTF-8 sequences.
#   2. NUL byte inside the password is rejected -- shell-injected null
#      bytes truncate logs and PAM/LDAP downstream; never store them.
#   3. Empty password ("") is rejected -- below the 8-char minimum.
#   4. 1-character password is rejected -- below the 8-char minimum.
#   5. 8-character acceptable password (the documented lower bound) is
#      accepted.
#   6. 128-character password (the documented upper bound) is accepted.
#   7. 129-character password is rejected -- one over the upper bound.
#   8. 256-character password is rejected -- well over the upper bound;
#      also covers the bcrypt CPU-DoS protection envelope.
#
# All resources use RUN_ID for isolation. Created users are deleted at the
# end so the run is idempotent.
#
# Requires: curl, jq, python3
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-password-strength-validation"
auth_admin
setup_workdir

CREATED_IDS=()

cleanup_created() {
  local uid
  for uid in "${CREATED_IDS[@]:-}"; do
    [ -z "$uid" ] && continue
    [ "$uid" = "null" ] && continue
    curl -s -o /dev/null -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/users/${uid}" >/dev/null 2>&1 || true
  done
}
add_exit_handler 'cleanup_created'

# create_user_with_password <username_suffix> <password>
# Echoes HTTP status on stdout. Captures created id into CREATED_IDS.
create_user_with_password() {
  local suffix="$1"
  local password="$2"
  local username="pwd-${suffix}-${RUN_ID}"
  local email="${username}@test.local"
  local tmp http_status body
  tmp=$(mktemp)
  # jq -nc with --arg quotes the value as a JSON string so any embedded
  # backslashes/quotes/unicode are escaped correctly; this is the only
  # safe way to ship arbitrary strings through curl --data.
  local payload
  payload=$(jq -nc \
    --arg u "$username" \
    --arg p "$password" \
    --arg e "$email" \
    '{username:$u,password:$p,email:$e}')
  http_status=$(curl -s --max-time 10 -o "$tmp" -w '%{http_code}' \
    -X POST "${BASE_URL}/api/v1/users" \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    --data "$payload" 2>/dev/null) || http_status="000"
  body=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"
  if [ "$http_status" = "200" ] || [ "$http_status" = "201" ]; then
    local uid
    uid=$(echo "$body" | jq -r '.user.id // .id // empty' 2>/dev/null)
    if [ -n "$uid" ] && [ "$uid" != "null" ]; then
      CREATED_IDS+=("$uid")
    fi
  fi
  echo "$http_status"
}

# create_user_with_raw_payload <suffix> <payload-file-path>
# Sends a pre-built JSON payload from a file via curl --data-binary @file.
# This is the only way to ship a literal 0x00 NUL byte through to the backend:
# bash strings cannot hold a true NUL, so we serialize JSON with python3 and
# stream the bytes from disk. Echoes HTTP status on stdout.
create_user_with_raw_payload() {
  local payload_file="$1"
  local tmp http_status body
  tmp=$(mktemp)
  http_status=$(curl -s --max-time 10 -o "$tmp" -w '%{http_code}' \
    -X POST "${BASE_URL}/api/v1/users" \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_file}" 2>/dev/null) || http_status="000"
  body=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"
  if [ "$http_status" = "200" ] || [ "$http_status" = "201" ]; then
    local uid
    uid=$(echo "$body" | jq -r '.user.id // .id // empty' 2>/dev/null)
    if [ -n "$uid" ] && [ "$uid" != "null" ]; then
      CREATED_IDS+=("$uid")
    fi
  fi
  echo "$http_status"
}

# -------------------------------------------------------------------------
# 1. Unicode is accepted in a valid-length password
# -------------------------------------------------------------------------

begin_test "Unicode password is accepted"
# Serialize the payload in python3 so we actually put real multi-byte UTF-8
# bytes (umlaut, accented chars, CJK) on the wire. A previous version of
# this test used a pure-ASCII string like "Aeiou", which exercised nothing.
# A byte-count length check on UTF-8 would over-count multi-byte sequences,
# but the backend uses char count; this asserts the multi-byte payload is
# accepted.
unicode_payload="${WORK_DIR}/unicode-payload.json"
python3 - "${RUN_ID}" "$unicode_payload" <<'PY'
import json, sys
run_id, out_path = sys.argv[1], sys.argv[2]
# 27 chars total, all under the 128-char cap. Includes a German umlaut
# (2-byte UTF-8), French accented vowels (2-byte each), and two CJK
# ideographs (3-byte each). Char count = 27, byte count = 34.
password = "Correct-Passwört-éè-中文-2026"
body = {
    "username": f"pwd-unicode-{run_id}",
    "password": password,
    "email":    f"pwd-unicode-{run_id}@test.local",
}
with open(out_path, "wb") as f:
    f.write(json.dumps(body, ensure_ascii=False).encode("utf-8"))
PY
status=$(create_user_with_raw_payload "$unicode_payload")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "unicode password rejected with HTTP ${status} (expected 2xx)"
fi

# -------------------------------------------------------------------------
# 2. NUL byte is rejected
# -------------------------------------------------------------------------

begin_test "NUL byte in password is rejected"
# Bash strings cannot hold a literal 0x00 byte, so we serialize the JSON
# payload in python (which emits a real NUL byte into the binary body)
# and curl --data-binary @file to ship the raw bytes. The backend must
# reject -- NUL bytes truncate C-string downstreams (PAM, LDAP) and break
# HSM signing flows; RFC 8259 sec 7 also allows JSON parsers to reject
# 0x00 outright.
nul_payload="${WORK_DIR}/nul-payload.json"
python3 - "${RUN_ID}" "$nul_payload" <<'PY'
import json, sys
run_id, out_path = sys.argv[1], sys.argv[2]
# Build a JSON object with a sentinel placeholder, then splice in the real
# 0x00 byte after serialization. json.dumps would otherwise emit the NUL as
# the 6-char \u0000 escape, which is not what we want to test (the JSON
# parser would happily decode that to NUL anyway, but we want the bare byte
# on the wire so a parser that rejects raw 0x00 also gets exercised).
SENTINEL = "X_NUL_SENTINEL_X"
body = {
    "username": f"pwd-nul-{run_id}",
    "password": f"Good-Pass-2026-{SENTINEL}-end",
    "email":    f"pwd-nul-{run_id}@test.local",
}
encoded = json.dumps(body).replace(SENTINEL, chr(0))
with open(out_path, "wb") as f:
    f.write(encoded.encode("utf-8"))
PY
status=$(create_user_with_raw_payload "$nul_payload")
# Backend's validate_password raises AppError::Validation -> 400 (error.rs:94).
# A 422 from the axum extractor is also acceptable if the JSON parser rejects
# 0x00 before the handler sees it. Anything else is a regression.
if [ "$status" = "400" ] || [ "$status" = "422" ]; then
  pass
else
  fail "NUL-byte password got HTTP ${status} (expected 400/422)"
fi

# -------------------------------------------------------------------------
# 3. Empty password is rejected
# -------------------------------------------------------------------------

begin_test "Empty password is rejected"
status=$(create_user_with_password "empty" "")
# Note: password is a nullable field in CreateUserRequest (openapi line
# 12340-12343), so the empty string is technically a valid type. But an
# empty literal is not a viable credential; backend must 4xx, never 2xx.
if [ "$status" -ge 400 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
  pass
else
  fail "empty password got HTTP ${status} (expected 4xx)"
fi

# -------------------------------------------------------------------------
# 4. Single-character password is rejected
# -------------------------------------------------------------------------

begin_test "Single-character password is rejected"
status=$(create_user_with_password "onechar" "x")
if [ "$status" -ge 400 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
  pass
else
  fail "1-char password got HTTP ${status} (expected 4xx)"
fi

# -------------------------------------------------------------------------
# 5. 8-character password (documented lower bound) is accepted
# -------------------------------------------------------------------------

begin_test "8-character password is accepted (lower bound)"
# Exactly 8 chars; mixed case + digits + a symbol so the common-password
# blocklist in users.rs (e.g. "12345678", "password") is not triggered.
status=$(create_user_with_password "min8" "Ab1!def2")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "8-char password rejected with HTTP ${status} (expected 2xx)"
fi

# -------------------------------------------------------------------------
# 6. 128-character password (documented upper bound) is accepted
# -------------------------------------------------------------------------

begin_test "128-character password is accepted (upper bound)"
# Exactly 128 chars; the backend (users.rs:74-78) accepts <= 128.
max_pw=$(python3 -c 'print("Ab1!" * 32, end="")' 2>/dev/null)
max_len=${#max_pw}
if [ "$max_len" != "128" ]; then
  fail "fixture build error: max_pw is ${max_len} chars, expected 128"
else
  status=$(create_user_with_password "max128" "$max_pw")
  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    pass
  else
    fail "128-char password rejected with HTTP ${status} (expected 2xx)"
  fi
fi

# -------------------------------------------------------------------------
# 7. 129-character password is rejected (one over the cap)
# -------------------------------------------------------------------------

begin_test "129-character password is rejected (over upper bound)"
# 129 chars: 128 (max accept) + 1 trailing char to cross the boundary.
over_pw=$(python3 -c 'print("Ab1!" * 32 + "X", end="")' 2>/dev/null)
over_len=${#over_pw}
if [ "$over_len" != "129" ]; then
  fail "fixture build error: over_pw is ${over_len} chars, expected 129"
else
  status=$(create_user_with_password "over129" "$over_pw")
  if [ "$status" -ge 400 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
    pass
  else
    fail "129-char password got HTTP ${status} (expected 4xx -- over 128-char cap)"
  fi
fi

# -------------------------------------------------------------------------
# 8. 256-character password is rejected (well over the cap; DoS envelope)
# -------------------------------------------------------------------------

begin_test "256-character password is rejected (DoS envelope)"
# 256 chars is double the cap and also exercises the bcrypt CPU-DoS
# protection envelope -- the upper-bound check in users.rs must fire
# before any bcrypt cost work is done. A 5xx here would mean the cap
# was bypassed.
long_pw=$(python3 -c 'print("Ab1!" * 64, end="")' 2>/dev/null)
long_len=${#long_pw}
if [ "$long_len" != "256" ]; then
  fail "fixture build error: long_pw is ${long_len} chars, expected 256"
else
  status=$(create_user_with_password "long256" "$long_pw")
  if [ "$status" -ge 400 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
    pass
  else
    fail "256-char password got HTTP ${status} (expected 4xx -- over 128-char cap)"
  fi
fi

end_suite
