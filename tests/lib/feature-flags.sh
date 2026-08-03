#!/usr/bin/env bash
# feature-flags.sh -- Branch-aware feature flags (issue #65).
#
# This file is sourced by tests/lib/common.sh so every test that calls
# `require_feature` gets the fast-path check below before the legacy
# backend-probe fallback runs.
#
# Why branch-aware flags exist (issue #65)
# ----------------------------------------
# The old `require_feature` curl'd ${BASE_URL}/health and parsed the
# version string to decide whether to skip a feature-gated test. Three
# problems with that design:
#
#   1. Soft-skip on probe failure is the worst outcome. If /health was
#      briefly slow during cold start, `get_backend_version` returned
#      "unknown" and every feature-gated test silently skipped. The
#      release gate then went green on a backend that had not even
#      responded. That is the same silent-no-op class customer
#      @Firjens flagged in artifact-keeper#872 (and gate #888).
#
#   2. Setup speed. Every suite that uses `require_feature` blocks on
#      at least one health roundtrip. Across 22 parallel release-gate
#      jobs that adds up.
#
#   3. Branch context is more reliable than runtime probing. When the
#      workflow is testing release/1.1.x we already know it cannot have
#      v1.2.0-only features; no need to ask the backend.
#
# Design
# ------
# Two-tier:
#
#   FAST PATH: tests/lib/feature-flags.sh exports an allowlist via the
#   AK_FEATURES env var (comma-separated). The release-gate workflow
#   sets this once per matrix job from `inputs.backend_tag` (or the
#   triggering branch name). `require_feature` checks the env first.
#   Hit -> return 0 immediately. No HTTP. Deterministic.
#
#   TRUTH PATH: when AK_FEATURES is unset (local dev, ad-hoc runs)
#   `require_feature` falls back to the old backend-version probe via
#   `_feature_min_version`. That keeps interactive workflows working
#   without forcing every developer to remember to export an env var.
#
# Drift detection
# ---------------
# A single diagnostic test in the security suite
# (test-feature-flag-drift.sh) compares AK_FEATURES to the backend's
# self-reported version. If a feature is in AK_FEATURES but the
# backend version says the feature should not exist (or vice versa),
# that test fails the suite. Drift becomes a loud failure in ONE
# place, not a silent skip in dozens.
#
# Usage from a test
# -----------------
# Tests do NOT source this file directly. They source common.sh, which
# in turn calls feature_flags_init() below. Use the existing
# `require_feature "<name>"` helper exactly as before; the new behavior
# is transparent.
#
# Usage from the workflow
# -----------------------
#   env:
#     AK_BACKEND_BRANCH: release/1.1.x   # or 'main', or a tag
#     # Optional explicit override (wins over branch-derived flags):
#     # AK_FEATURES: feature_a,feature_b
#
# The branch -> flag-set mapping below is the single source of truth
# for what the gate considers shipped on each branch. When a feature
# lands on release/1.1.x, add it to the AK_BACKEND_BRANCH_1_1_X set.

# -----------------------------------------------------------------------------
# Branch -> features mapping
# -----------------------------------------------------------------------------

# Features shipped on release/1.1.x. Add an entry here in the SAME PR
# that lands the backend change on the release branch.
#
# Format: space-separated tokens, joined into a CSV at init time.
AK_BACKEND_BRANCH_1_1_X="\
  refresh_token_rotation \
  download_ticket_consumer \
  user_deactivation_token_flush \
"

# Features shipped on release/1.2.x (and that have not yet been
# backported to 1.1.x). When a v1.2.0 feature gets backported to
# 1.1.x, move its token to the 1.1.X bundle and remove it here.
AK_BACKEND_BRANCH_1_2_X="\
  $AK_BACKEND_BRANCH_1_1_X \
  conan_user_channel_scoping \
  conan_virtual_recipe_fanout \
  maven_virtual_snapshot \
  guest_access_toggle \
  opensearch_indexing \
  proxy_stampede_protection \
  virtual_member_strict_contract \
  webhook_event_producer \
  proxy_ttl_eviction_correctness \
  sbom_declared_dependencies \
"

# main: everything 1.2.x has, plus anything in-flight on main.
#
# v1.3.0 release-gate feature tokens (see rig FixSpec
# v130-test-gates-plan.md). Each guards one new gate suite so the same
# main-branch test tree auto-skips it on a 1.2.x backend instead of
# hard-failing on an unshipped feature:
#   metrics_unmatched_path  -> tests/platform/test-metrics-unmatched-cardinality.sh (G7, #2217)
#   streaming_large_artifact-> tests/platform/test-streaming-large-artifact.sh    (G1, #1608)
#                              tests/formats/test-streaming-blob-fallback.sh       (G1, #1608)
#   composer_dist_cache     -> tests/formats/test-composer-dist-cache.sh           (G1, #2204)
#   npm_packument_swr       -> tests/pullthrough/test-npm-packument-swr.sh         (G6, #2166)
#   oci_gc_two_phase        -> tests/lifecycle/test-oci-gc-mark-sweep.sh           (G3, #1660)
#
# Deferred v1.3.0 gates (NOT registered until their infra/endpoints land,
# see v130-test-gates-plan.md Part 2):
#   G2 access_scope_authz  -- no REST endpoint sets an arbitrary AccessScope
#      (repository_scopes list / empty / user-level); the AccessScope enum is
#      covered by backend lib unit tests. Register when a scope-write endpoint ships.
#   G4 sso_oidc_v13        -- happy-path OIDC/SAML login needs a mock IdP (backend
#      e2e #2210/#2214); negative/forged-assertion cases already covered by
#      tests/auth/test-oidc-*.sh + tests/security/test-saml-signature.sh.
#   G5 cross_replica_cache_invalidation -- needs a new 2-replica shared-DB
#      helm/values-test-ha.yaml overlay + deploy job (#2169); no such overlay today.
AK_BACKEND_BRANCH_MAIN="\
  $AK_BACKEND_BRANCH_1_2_X \
  conan_remote_search_forward \
  conan_virtual_search_aggregate \
  conan_error_correctness \
  metrics_unmatched_path \
  streaming_large_artifact \
  composer_dist_cache \
  npm_packument_swr \
  oci_gc_two_phase \
"

# virtual_member_replace_contract: marks a backend whose PUT /:key/members has
# FULL-SET REPLACE semantics. The request body is the complete desired member
# list: members absent from it are removed, listed members are inserted or have
# their priority refreshed, and an empty list clears the membership.
#
# Introduced by artifact-keeper#2795 (merged after v1.6.0, first contained in
# v1.6.1) and ratified as the intended API contract in artifact-keeper#2899.
# It is a MAIN-only token: the 1.1.x and 1.2.x bundles pre-date #2795 and still
# carry the priorities-only update, where the replace assertions are wrong by
# construction. Appending it to MAIN here, rather than editing the MAIN literal
# above, keeps this change off the lines other in-flight branches are editing.
#
# This replaces virtual_member_partial_update_contract, the upper-bounded token
# that used to mark the PRE-#2795 contract. #2899 ratified replace semantics,
# so the suite it gated was rewritten for replace rather than kept pinned to
# the obsolete contract, and the old token has no remaining consumers.
#
# Gates tests/repos/test-virtual-members-concurrent-put.sh.
AK_BACKEND_BRANCH_MAIN="$AK_BACKEND_BRANCH_MAIN virtual_member_replace_contract"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# _normalize_csv: collapse whitespace and join tokens with commas.
# Echoes the cleaned CSV. Idempotent (safe to apply to already-CSV input).
_normalize_csv() {
  # Strip leading/trailing whitespace and collapse internal whitespace
  # into single commas. Tolerates both "a b c" and "a,b,c" input shapes
  # so callers can write either form.
  echo "$1" | tr ',' ' ' | xargs | tr ' ' ','
}

# feature_flags_init: select an active flag set based on AK_BACKEND_BRANCH
# (or honor an explicit AK_FEATURES override). Exports AK_FEATURES so
# `require_feature` can do a string match without re-running this logic.
#
# Precedence:
#   1. If AK_FEATURES is already set non-empty: use it as-is (operator
#      override, useful for testing fix-forward PRs that flip a flag
#      ahead of the branch mapping).
#   2. Else if AK_BACKEND_BRANCH is set: derive from the branch.
#   3. Else: leave AK_FEATURES empty. require_feature will fall back to
#      the backend-probe path (local dev case).
#
# This function is idempotent. Calling it twice in the same process is
# a no-op the second time.
feature_flags_init() {
  if [ -n "${AK_FEATURES:-}" ]; then
    AK_FEATURES=$(_normalize_csv "$AK_FEATURES")
    export AK_FEATURES
    return 0
  fi

  local branch="${AK_BACKEND_BRANCH:-}"
  local raw=""
  case "$branch" in
    "")
      # No branch hint. Leave AK_FEATURES unset so require_feature
      # falls back to the legacy backend probe. Local dev path.
      return 0
      ;;
    main|master)
      raw="$AK_BACKEND_BRANCH_MAIN"
      ;;
    release/1.1.x|release/1.1.*|v1.1.*|1.1.*)
      # Anchored on the third `.` to avoid the moment-1.10-ships footgun:
      # the looser `release/1.1*` form also matches `release/1.10.x` /
      # `release/1.11.x` lexically, so a future 1.10 branch would map to
      # the 1.1.x flag set instead of either main or its own bundle.
      raw="$AK_BACKEND_BRANCH_1_1_X"
      ;;
    release/1.2.x|release/1.2.*|v1.2.*|1.2.*)
      # Same anchoring as 1.1.x above: `release/1.2.*` not `release/1.2*`.
      raw="$AK_BACKEND_BRANCH_1_2_X"
      ;;
    *)
      # Unknown branch label. Don't silently default to the most
      # permissive set (that would falsely "enable" features and pass
      # tests against a backend that lacks them, exactly the silent-
      # success class we're trying to kill). Default to the most
      # restrictive set (1.1.x) so unrecognized branches err toward
      # over-skipping rather than over-running.
      echo "feature_flags_init: unknown AK_BACKEND_BRANCH='${branch}', defaulting to release/1.1.x flag set" >&2
      raw="$AK_BACKEND_BRANCH_1_1_X"
      ;;
  esac

  AK_FEATURES=$(_normalize_csv "$raw")
  export AK_FEATURES
}

# feature_enabled_via_env: fast-path lookup against AK_FEATURES.
#
# Returns 0 if AK_FEATURES is set AND contains $1; returns 2 if
# AK_FEATURES is unset (caller should fall back to backend probe);
# returns 1 if AK_FEATURES is set but does NOT contain $1.
#
# The three-way return is load-bearing: distinguishing "explicitly
# disabled by env" from "no env set, ask the backend" prevents the
# silent-skip class on stale env values. If the workflow sets
# AK_BACKEND_BRANCH=main but forgets to add a new flag to the MAIN
# bundle, this returns 1 and the test skips loudly with a precise
# reason ("not in AK_FEATURES") instead of probing the backend and
# returning a different answer.
feature_enabled_via_env() {
  local feature="$1"
  if [ -z "${AK_FEATURES:-}" ]; then
    return 2
  fi
  case ",${AK_FEATURES}," in
    *,"${feature}",*) return 0 ;;
    *)                return 1 ;;
  esac
}

# Initialize on source. Idempotent.
feature_flags_init
