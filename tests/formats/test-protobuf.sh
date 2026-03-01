#!/usr/bin/env bash
# Protobuf / BSR format E2E test
# Tests proto descriptor upload and module listing via /proto/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "protobuf"
auth_admin
setup_workdir

REPO_KEY="test-protobuf-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create protobuf local repository"
if create_local_repo "$REPO_KEY" "protobuf"; then
  pass
else
  fail "could not create protobuf repo"
fi

# ---------------------------------------------------------------------------
# Create proto descriptor file
# ---------------------------------------------------------------------------

begin_test "Create proto descriptor file"
cd "$WORK_DIR"

cat > billing.proto <<'PROTOEOF'
syntax = "proto3";
package acme.billing.v1;

message Invoice {
  string invoice_id = 1;
  int64 amount_cents = 2;
  string currency = 3;
}

message InvoiceList {
  repeated Invoice invoices = 1;
}
PROTOEOF

pass

# ---------------------------------------------------------------------------
# Upload proto descriptor via PUT
# ---------------------------------------------------------------------------

begin_test "Upload proto descriptor file"
if resp=$(curl -sf -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/billing.proto" \
  "${BASE_URL}/proto/${REPO_KEY}/acme/billing/v1/billing.proto" 2>&1); then
  pass
else
  fail "upload billing.proto failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query module listing
# ---------------------------------------------------------------------------

begin_test "Query module listing"
sleep 1
if resp=$(curl -sf "${BASE_URL}/proto/${REPO_KEY}/" -H "$(auth_header)"); then
  if assert_contains "$resp" "billing" "module listing should contain billing"; then
    pass
  fi
else
  fail "GET /proto/${REPO_KEY}/ returned error"
fi

# ---------------------------------------------------------------------------
# Download proto descriptor
# ---------------------------------------------------------------------------

begin_test "Download proto descriptor"
if resp=$(curl -sf -H "$(auth_header)" \
  "${BASE_URL}/proto/${REPO_KEY}/acme/billing/v1/billing.proto"); then
  if assert_contains "$resp" "Invoice" "downloaded proto should contain Invoice message"; then
    pass
  fi
else
  fail "download billing.proto failed"
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "billing" "artifact list should contain billing"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
