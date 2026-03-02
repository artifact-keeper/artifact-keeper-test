#!/usr/bin/env bash
# Protobuf / BSR format E2E test
# Tests proto module upload and retrieval via Connect RPC endpoints at /proto/{repo_key}/.
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
# Create proto file and encode as base64
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

PROTO_B64=$(base64 < billing.proto | tr -d '\n')
pass

# ---------------------------------------------------------------------------
# Upload proto module via Connect RPC UploadService
# ---------------------------------------------------------------------------

begin_test "Upload proto module via Connect RPC"
UPLOAD_URL="${BASE_URL}/proto/${REPO_KEY}/buf.registry.module.v1beta1.UploadService/Upload"
UPLOAD_BODY="{\"contents\":[{\"moduleRef\":{\"owner\":\"acme\",\"module\":\"billing\"},\"files\":[{\"path\":\"acme/billing/v1/billing.proto\",\"content\":\"${PROTO_B64}\"}]}]}"

if resp=$(curl -sf -X POST "$UPLOAD_URL" \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d "$UPLOAD_BODY" 2>&1); then
  pass
else
  fail "Connect RPC upload failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query modules via GetModules
# ---------------------------------------------------------------------------

begin_test "Query modules via Connect RPC"
sleep 1
MODULES_URL="${BASE_URL}/proto/${REPO_KEY}/buf.registry.module.v1.ModuleService/GetModules"
if resp=$(curl -sf -X POST "$MODULES_URL" \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"moduleRefs\":[{\"owner\":\"acme\",\"module\":\"billing\"}]}" 2>&1); then
  if assert_contains "$resp" "billing" "modules response should contain billing"; then
    pass
  fi
else
  fail "GetModules returned error"
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
