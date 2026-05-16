# Contributing to artifact-keeper-test

## GitHub Actions pinning convention

Every action reference in `.github/workflows/` must be pinned to a full
40-character commit SHA, with the human-readable version tag as a trailing
comment. Floating tags (`@v4`, `@main`, etc.) are not accepted in this repo
even when the upstream publishes signed releases.

Required form:

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
```

Not accepted:

```yaml
- uses: actions/checkout@v4              # floating tag
- uses: actions/checkout@main            # mutable branch
- uses: actions/checkout@34e114876b0b   # short SHA
```

### Why

The release-gate workflow is the load-bearing supply-chain boundary for
Artifact Keeper releases. A compromised action tag silently substituting
malicious code at action-resolution time would forge the gate's signal.
SHA pins make the published tag opaque to the resolver: a tag rewrite by
the action author or a compromised release line has no effect, because
the workflow only fetches the pinned commit.

The version comment is required so reviewers can see at a glance which
release the SHA refers to without resolving the commit on the action's
repo. The comment is not load-bearing; the SHA is.

### Updating pins

Dependabot opens weekly PRs against `main` that bump each action's SHA to
the latest commit pointed to by its tracked tag (see
`.github/dependabot.yml`). Merge the dependabot PR after CI is green;
no human edit is required to keep the pins fresh.

If you need to manually bump a pin (for example, to adopt a new major
version not yet picked up by the configured tracker), find the SHA on the
action's release page or via `gh api repos/<owner>/<repo>/git/refs/tags/<tag>`,
update both the SHA and the version comment in the same edit, and run
`grep -nE 'uses:.*@' .github/workflows/*.yml` to confirm no floating tags
slipped in.

## Test script contract

See `CLAUDE.md` for the test script contract (sourcing `tests/lib/common.sh`,
RUN_ID hygiene, JUnit output, exit code semantics). This file documents the
workflow-level conventions; that one documents the test-level ones.
