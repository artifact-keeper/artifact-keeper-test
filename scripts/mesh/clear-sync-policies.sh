#!/usr/bin/env bash
# clear-sync-policies.sh - delete every sync policy on one mesh instance
# (artifact-keeper/artifact-keeper#6120)
#
# Usage: scripts/mesh/clear-sync-policies.sh <backend-url>
#
# tests/mesh/test-artifact-sync.sh leaves a `peer_selector: {all: true}`
# push policy on the instance it drives. Every peer registered on that
# instance afterwards is evaluated against it (POST /peers runs
# evaluate_for_peer) and gets retroactive tasks for a repository that does
# not exist on that peer. Each one is refused with 404, which the sync worker
# counts as a PEER failure and backs the peer row off. So a later tier's
# links would start out in backoff. The namespace belongs to this run, so
# every policy goes.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
url="${1:?usage: $0 <backend-url>}"
export BASE_URL="$url"
# shellcheck source=tests/lib/common.sh
source "${REPO_ROOT}/tests/lib/common.sh"
auth_admin >/dev/null
policy_ids=$(api_get "/api/v1/sync-policies" | jq -r '.items[]?.id')
n=0
for id in $policy_ids; do
  api_delete "/api/v1/sync-policies/${id}" >/dev/null
  n=$(( n + 1 ))
done
left=$(api_get "/api/v1/sync-policies" | jq -r '.items | length')
echo "${url}: deleted ${n} sync polic(ies), ${left} left"
[ "$left" = "0" ]
