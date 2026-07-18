#!/usr/bin/env bash
# =============================================================================
# tiers/audit-export/oracle.sh — structured audit-log export oracle (#2413)
# =============================================================================
# run.sh has stood up `storage.filesystem` + `client.jsonschema` on a claimed
# slot. The client.jsonschema profile opts the backend into the audit stream
# (`AUDIT_STREAM=${AUDIT_STREAM:-stdout}`) and adds a python + `jsonschema`
# validator sidecar. run.sh exported BASE_URL, ADMIN_USER/ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, DTF_SLOT, DTF_DIR, COMMON_SH. We source
# common.sh for the assertion + JUnit harness.
#
# The feature: with AUDIT_STREAM=stdout the backend emits ONE NDJSON audit event
# per audited action to its stdout (docker logs) — NOT an HTTP endpoint. Each
# line is an instance of the PUBLISHED contract
# `backend/schemas/audit-event.v1.schema.json` (draft 2020-12), vendored beside
# this oracle. A SIEM ships the audit trail by collecting stdout; `event_id`
# equals the `audit_log` row id (the SIEM <-> admin-API join key).
#
# DISCRIMINATING (all must hold or the tier fails):
#   1. Drive a spread of audited actions (admin LOGIN, REPOSITORY_CREATED,
#      API_TOKEN_CREATED, LOGIN_FAILED, REPOSITORY_DELETED).
#   2. Capture the backend's stdout NDJSON and STRICTLY validate EVERY audit line
#      against the published schema via the jsonschema sidecar. A missing
#      `required` field, a drifted `schema_version`, or a malformed envelope ->
#      validator exits non-zero -> tier red. An ABSENT stream (AUDIT_STREAM=off)
#      -> zero lines -> the class-present assertions below fail -> tier red.
#   3. Assert >=1 valid audit line per driven action class (a silent-drop of one
#      action's audit event fails).
#   4. Assert one exported `event_id` JOINS to the admin audit API row
#      (GET /api/v1/admin/audit) — the SIEM <-> admin-API join contract, not
#      just schema shape.
#   5. Standing discrimination tripwire: feed the strict validator a
#      deliberately schema-nonconformant line (drop `schema_version`) and assert
#      it is REJECTED — proves the validator is not vacuous, so a real schema
#      regression cannot pass silently.
#
# RED reproduction (documented, run in verification):
#   `AUDIT_STREAM=off ./harness/run.sh audit-export --backend-image <img>`
#   -> the backend emits ZERO `category:"audit"` lines; step 2/3 fail; exit != 0.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
VALIDATOR_CTR="ak-dtf${DTF_SLOT}-client-jsonschema"
SCHEMA_SRC="${DTF_DIR}/harness/tiers/audit-export/audit-event.v1.schema.json"

begin_suite "audit-export-2413"
setup_workdir

NDJSON="${WORK_DIR}/audit.ndjson"
VALIDATOR_PY="${WORK_DIR}/validate_ndjson.py"

# ---------------------------------------------------------------------------
# Preconditions: vendored schema + validator sidecar present.
# ---------------------------------------------------------------------------
begin_test "vendored published audit schema is present"
if [ -f "$SCHEMA_SRC" ]; then pass; else
  fail "vendored schema not found: ${SCHEMA_SRC}"
  end_suite
fi

begin_test "jsonschema validator sidecar is up (python + jsonschema import)"
if docker exec "$VALIDATOR_CTR" python -c 'import jsonschema, sys; print(jsonschema.__version__)' >/dev/null 2>&1; then
  pass
else
  fail "validator sidecar ${VALIDATOR_CTR} not usable (python/jsonschema import failed)"
  end_suite
fi

# Stage the strict per-line validator into the sidecar. jsonschema >=4.18 picks
# the draft-2020-12 validator from the schema's $schema; we pin it explicitly.
cat > "$VALIDATOR_PY" <<'PY'
import json, sys
from jsonschema import Draft202012Validator

schema_path, ndjson_path = sys.argv[1], sys.argv[2]
with open(schema_path) as fh:
    schema = json.load(fh)
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)

total = bad = 0
with open(ndjson_path) as fh:
    for i, raw in enumerate(fh, 1):
        line = raw.strip()
        if not line:
            continue
        total += 1
        try:
            obj = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            print(f"  line {i}: NOT VALID JSON: {exc}")
            bad += 1
            continue
        errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path))
        if errors:
            bad += 1
            for err in errors:
                loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
                print(f"  line {i} [{obj.get('action','?')}] INVALID at {loc}: {err.message}")
        else:
            print(f"  line {i} [{obj.get('action','?')}] OK "
                  f"schema_version={obj.get('schema_version')} outcome={obj.get('outcome')}")

print(f"VALIDATED {total - bad}/{total} audit lines against published schema")
# Empty stream OR any nonconformant line -> non-zero (the discriminator).
sys.exit(1 if (bad > 0 or total == 0) else 0)
PY

docker exec "$VALIDATOR_CTR" mkdir -p /work >/dev/null 2>&1 || true
docker cp "$SCHEMA_SRC" "${VALIDATOR_CTR}:/work/schema.json" >/dev/null 2>&1
docker cp "$VALIDATOR_PY" "${VALIDATOR_CTR}:/work/validate_ndjson.py" >/dev/null 2>&1

# ---------------------------------------------------------------------------
# Drive a spread of audited actions.
# ---------------------------------------------------------------------------
# admin LOGIN (success) — also mints ADMIN_TOKEN used by the rest.
auth_admin >/dev/null

REPO="dtf-audit-${RUN_ID}"
TOKNAME="dtf-audit-tok-${RUN_ID}"
BADUSER="dtf-audit-nobody-${RUN_ID}"

begin_test "drive REPOSITORY_CREATED (repo create is audited)"
if create_repo "$REPO" "npm" "local"; then pass; else fail "could not create repo ${REPO}"; fi

begin_test "drive API_TOKEN_CREATED (token mint is audited)"
tok_code=$(curl -s -o "${WORK_DIR}/tok.json" -w '%{http_code}' --max-time 15 \
  -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"name\":\"${TOKNAME}\",\"scopes\":[\"read:artifacts\"]}" 2>/dev/null) || tok_code="000"
if [ "$tok_code" = "200" ] || [ "$tok_code" = "201" ]; then pass; else
  fail "token create returned ${tok_code}" "$(head -c 200 "${WORK_DIR}/tok.json" 2>/dev/null)"
fi

begin_test "drive LOGIN_FAILED (failed login is audited, outcome=failure)"
lf_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
  -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${BADUSER}\",\"password\":\"definitely-wrong\"}" 2>/dev/null) || lf_code="000"
# A failed login is a 401 (or 403/429); anything but a 2xx means the audit event fired.
if [ "$lf_code" != "000" ] && [ "${lf_code:0:1}" != "2" ]; then pass; else
  fail "expected a non-2xx failed-login response, got ${lf_code}"
fi

begin_test "drive REPOSITORY_DELETED (repo delete is audited)"
del_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
  -X DELETE "${BASE_URL}/api/v1/repositories/${REPO}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null) || del_code="000"
if [ "${del_code:0:1}" = "2" ]; then pass; else fail "repo delete returned ${del_code}"; fi

# Give the non-blocking stdout writer thread time to drain the bounded queue.
sleep 4

# ---------------------------------------------------------------------------
# Capture the backend's stdout NDJSON. Every audit line is serialized with
# `schema_version` first (serde field order), so this anchor matches audit
# lines exactly and never a RUST_LOG diagnostic line.
# ---------------------------------------------------------------------------
docker logs "$BACKEND_CTR" >"${WORK_DIR}/backend.stdout" 2>&1 || true
grep -aE '^\{"schema_version":[0-9]' "${WORK_DIR}/backend.stdout" > "$NDJSON" || true
line_count=$(wc -l < "$NDJSON" | tr -d ' ')
echo "  captured ${line_count} candidate audit NDJSON line(s) from ${BACKEND_CTR} stdout"

# ---------------------------------------------------------------------------
# STRICT schema validation of EVERY captured audit line (the load-bearing gate).
# ---------------------------------------------------------------------------
begin_test "every emitted audit line validates against the PUBLISHED v1 schema"
docker cp "$NDJSON" "${VALIDATOR_CTR}:/work/audit.ndjson" >/dev/null 2>&1 || true
# `|| val_rc=$?` keeps the intentionally-nonzero validator exit from tripping the
# `set -e` inherited from common.sh (a failing `var=$(...)` would abort the run).
val_rc=0
val_out="$(docker exec "$VALIDATOR_CTR" python /work/validate_ndjson.py /work/schema.json /work/audit.ndjson 2>&1)" || val_rc=$?
echo "$val_out" | sed 's/^/    /'
if [ "$val_rc" -eq 0 ]; then pass; else
  fail "strict schema validation failed (rc=${val_rc}): a line is missing a required field, has a wrong schema_version, or the stream is absent" \
"With AUDIT_STREAM off (or a pre-#2413 backend that emits nothing) the capture is
empty; a schema regression makes a line nonconformant. Either is a real #2413
break and the tier must go red."
fi

# ---------------------------------------------------------------------------
# >=1 valid audit line per driven action class (silent per-action drop -> red).
# ---------------------------------------------------------------------------
for action in LOGIN REPOSITORY_CREATED API_TOKEN_CREATED LOGIN_FAILED REPOSITORY_DELETED; do
  begin_test "audit line present for action ${action}"
  n=$(jq -rs --arg a "$action" '[.[] | select(.action==$a)] | length' "$NDJSON" 2>/dev/null || echo 0)
  if [ "${n:-0}" -ge 1 ]; then
    echo "  ${n} ${action} audit line(s)"
    pass
  else
    fail "no audit line emitted for ${action}" \
      "the stream must carry one event per audited action; a missing class is a coverage/regression bug (or AUDIT_STREAM is off)."
  fi
done

# ---------------------------------------------------------------------------
# SIEM <-> admin-API join: an exported event_id equals its audit_log row id.
# ---------------------------------------------------------------------------
begin_test "exported event_id joins to the admin audit API row"
repo_eid=$(jq -rs --arg k "$REPO" \
  'first(.[] | select(.action=="REPOSITORY_CREATED") | select((.details.key // "")==$k) | .event_id) // ""' \
  "$NDJSON" 2>/dev/null)
if [ -z "$repo_eid" ]; then
  # Fallback: any REPOSITORY_CREATED from this run (details shape variance).
  repo_eid=$(jq -rs 'first(.[] | select(.action=="REPOSITORY_CREATED") | .event_id) // ""' "$NDJSON" 2>/dev/null)
fi
if [ -z "$repo_eid" ]; then
  fail "no REPOSITORY_CREATED event_id in the exported stream to join on"
else
  echo "  exported REPOSITORY_CREATED event_id=${repo_eid}"
  curl -s -o "${WORK_DIR}/audit_api.json" --max-time 20 \
    "${BASE_URL}/api/v1/admin/audit?action=REPOSITORY_CREATED&per_page=200" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true
  if jq -e --arg id "$repo_eid" '.items[]? | select(.id==$id)' "${WORK_DIR}/audit_api.json" >/dev/null 2>&1; then
    echo "  event_id ${repo_eid} found in GET /api/v1/admin/audit items[].id"
    pass
  else
    fail "exported event_id ${repo_eid} not found in the admin audit API rows" \
"event_id is documented as the audit_log row id (the SIEM<->admin-API join key);
if the stream id does not match the DB row id, the join contract is broken."
  fi
fi

# ---------------------------------------------------------------------------
# Standing discrimination tripwire: the strict validator MUST reject a
# schema-nonconformant line. Take a real emitted line, delete the required
# `schema_version`, and assert the validator rejects it (non-zero). This proves
# the validation above is not vacuous — a schema regression cannot pass silently.
# ---------------------------------------------------------------------------
begin_test "strict validator REJECTS a schema-nonconformant line (discrimination tripwire)"
if [ "${line_count:-0}" -ge 1 ]; then
  head -n 1 "$NDJSON" > "${WORK_DIR}/firstline.ndjson" 2>/dev/null || true
  jq -rc 'del(.schema_version)' "${WORK_DIR}/firstline.ndjson" > "${WORK_DIR}/malformed.ndjson" 2>/dev/null || true
  docker cp "${WORK_DIR}/malformed.ndjson" "${VALIDATOR_CTR}:/work/malformed.ndjson" >/dev/null 2>&1 || true
  # `|| bad_rc=$?` — the validator is EXPECTED to exit non-zero here; capture it
  # as a list so the inherited `set -e` does not abort before we assert on it.
  bad_rc=0
  bad_out="$(docker exec "$VALIDATOR_CTR" python /work/validate_ndjson.py /work/schema.json /work/malformed.ndjson 2>&1)" || bad_rc=$?
  echo "$bad_out" | sed 's/^/    /'
  if [ "${bad_rc:-0}" -ne 0 ]; then
    echo "  validator correctly rejected the malformed line (rc=${bad_rc})"
    pass
  else
    fail "validator ACCEPTED a line with schema_version removed (rc=0)" \
      "the validator is vacuous: a real schema regression would slip through. Fix the validator/schema wiring."
  fi
else
  fail "no captured line to derive a malformed tripwire from (stream absent?)"
fi

end_suite
