#!/usr/bin/env bash
# selftest-gate-concurrency.sh - pin release-gate.yml's concurrency classes
# (artifact-keeper-test#840).
#
# GitHub keeps one running and ONE pending run per concurrency group, and a new
# arrival cancels whatever is pending. The gate's group used to be the backend
# tag alone, so any two runs on one tag shared it: parallel narrow dispatches
# replaced each other, and a nightly or hand-dispatched full gate could replace
# a Release Candidate's pending gate. This evaluates the group expression of
# the real workflow for the callers that exist and checks:
#
#   1. a Release Candidate's full gate and its only_jobs rerun share one group
#      (never two at once for the same certified tag);
#   2. no other caller lands in that group (nothing else can replace it), and
#      the same holds for release.yml's gate on a stable tag;
#   3. other full gates on one tag share a group (they still serialize);
#   4. two narrow dispatches on one tag get distinct groups, distinct from
#      the full and candidate groups (they never cancel each other);
#   5. distinct tags never share a group.
#
# The evaluator understands the subset of the Actions expression language the
# group uses (&&, ||, ==, parentheses, string literals, inputs.* / github.*,
# startsWith, format) and refuses anything else, so a rewrite of the group into
# a form it cannot read fails here instead of passing unchecked. The checker is
# run against the old tag-only group first and must reject it.
#
# Usage: bash scripts/selftest-gate-concurrency.sh [path/to/release-gate.yml]
# Requires: python3 with PyYAML (preinstalled on GitHub-hosted ubuntu runners).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-${REPO_ROOT}/.github/workflows/release-gate.yml}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "${WORK}/check.py" <<'PY'
import re
import sys

import yaml

RC = "artifact-keeper/artifact-keeper/.github/workflows/release-candidate.yml@refs/heads/main"
RC_LINE = "artifact-keeper/artifact-keeper/.github/workflows/release-candidate.yml@refs/heads/release/1.11.x"
NIGHTLY = "artifact-keeper/artifact-keeper/.github/workflows/nightly-release-gate.yml@refs/heads/main"
RELEASE = "artifact-keeper/artifact-keeper/.github/workflows/release.yml@refs/tags/v1.12.0"
REHEARSAL = "artifact-keeper/artifact-keeper/.github/workflows/release-gate-rehearsal.yml@refs/heads/main"
DIRECT = "artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@refs/heads/main"

TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>&&|\|\||==|!=|\(|\)|,)|(?P<id>[A-Za-z_][A-Za-z0-9_.-]*))")


def tokenize(src):
    pos, out = 0, []
    src = src.strip()
    while pos < len(src):
        m = TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise ValueError(f"unsupported expression syntax at: {src[pos:pos + 30]!r}")
        pos = m.end()
        if m.group("str") is not None:
            out.append(("str", m.group("str")[1:-1].replace("''", "'")))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            out.append(("id", m.group("id")))
    return out


class Parser:
    def __init__(self, toks, ctx):
        self.t, self.i, self.ctx = toks, 0, ctx

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, val=None):
        tok = self.peek()
        if val is not None and tok[1] != val:
            raise ValueError(f"expected {val!r}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self):
        v = self.or_()
        if self.i != len(self.t):
            raise ValueError(f"trailing tokens: {self.t[self.i:]}")
        return v

    def or_(self):
        v = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            r = self.and_()
            v = v if v else r
        return v

    def and_(self):
        v = self.cmp()
        while self.peek() == ("op", "&&"):
            self.take()
            r = self.cmp()
            v = r if v else v
        return v

    def cmp(self):
        v = self.atom()
        if self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]
            r = self.atom()
            eq = str(v).lower() == str(r).lower()  # Actions compares strings case-insensitively
            v = eq if op == "==" else not eq
        return v

    def atom(self):
        kind, val = self.take()
        if kind == "str":
            return val
        if (kind, val) == ("op", "("):
            v = self.or_()
            self.take(")")
            return v
        if kind == "id" and self.peek() == ("op", "("):
            self.take("(")
            args = [self.or_()]
            while self.peek() == ("op", ","):
                self.take()
                args.append(self.or_())
            self.take(")")
            if val == "startsWith" and len(args) == 2:
                return str(args[0]).lower().startswith(str(args[1]).lower())
            if val == "format":
                return re.sub(r"\{(\d+)\}", lambda m: str(args[1 + int(m.group(1))]), args[0])
            raise ValueError(f"unsupported function {val}()")
        if kind == "id" and val.split(".")[0] in ("inputs", "github"):
            head, _, key = val.partition(".")
            if key not in self.ctx[head]:
                raise ValueError(f"the self-test has no value for {val}; add it to the cases")
            return self.ctx[head][key]
        raise ValueError(f"unsupported token {val!r}")


def group(template, ctx):
    def ev(m):
        v = Parser(tokenize(m.group(1)), ctx).parse()
        return "" if v is False or v is None else str(v)
    return re.sub(r"\$\{\{(.*?)\}\}", ev, template, flags=re.S)


def run(tag, wf_ref, run_id, only_jobs="", suite="all"):
    return {
        "inputs": {"backend_tag": tag, "only_jobs": only_jobs, "test_suite": suite},
        "github": {"workflow_ref": wf_ref, "run_id": str(run_id)},
    }


def problems(path):
    with open(path) as fh:
        wf = yaml.safe_load(fh)
    conc = wf.get("concurrency") or {}
    tmpl = conc.get("group")
    if not isinstance(tmpl, str):
        return ["workflow-level concurrency.group is missing"]
    out = []
    if conc.get("cancel-in-progress") is not False:
        out.append("cancel-in-progress must stay false (an in-flight gate must finish its teardown)")
    try:
        g = lambda *a, **k: group(tmpl, run(*a, **k))
        cand_full = g("sha-1111111", RC, 100)
        cand_rerun = g("sha-1111111", RC, 101, only_jobs="repo-tests dtf-gate/oci")
        cand_line = g("sha-1111111", RC_LINE, 102)
        release = g("sha-1111111", RELEASE, 202)
        others_full = [g("sha-1111111", NIGHTLY, 200), g("sha-1111111", DIRECT, 201),
                       g("sha-1111111", REHEARSAL, 203)]
        narrow = [g("sha-1111111", DIRECT, 300, only_jobs="resilience-tests", suite="resilience"),
                  g("sha-1111111", DIRECT, 301, only_jobs="resilience-tests", suite="resilience"),
                  g("sha-1111111", DIRECT, 302, suite="admin"),
                  g("sha-1111111", REHEARSAL, 303, suite="mesh"),
                  g("sha-1111111", NIGHTLY, 304, only_jobs="dtf-gate/oci")]
        cand_other_tag = g("sha-2222222", RC, 400)
        full_other_tag = g("sha-2222222", DIRECT, 401)
    except ValueError as e:
        return [f"cannot evaluate the group expression: {e}"]

    if not (cand_full == cand_rerun == cand_line):
        out.append(f"rule 1: a candidate's full gate ({cand_full}), its only_jobs rerun ({cand_rerun}) and a release-line dispatch ({cand_line}) must share one group")
    for o in others_full + narrow + [release]:
        if o == cand_full:
            out.append(f"rule 2: a non-candidate run joins the candidate's group {cand_full}")
    for o in others_full + narrow:
        if o == release:
            out.append(f"rule 2: another run joins release.yml's group {release}")
    if len(set(others_full)) != 1:
        out.append(f"rule 3: full gates from other callers on one tag must share a group, got {sorted(set(others_full))}")
    if len(set(narrow)) != len(narrow):
        out.append(f"rule 4: narrow dispatches on one tag must each get their own group, got {narrow}")
    for n in narrow:
        if n in others_full:
            out.append(f"rule 4: narrow run shares the full-gate group {n}")
    if cand_other_tag == cand_full or full_other_tag in others_full:
        out.append("rule 5: runs on distinct tags share a group")
    for v in [cand_full, release] + others_full + narrow:
        if "sha-1111111" not in v:
            out.append(f"every group must name the backend tag, got {v!r}")
    return out


path, expect = sys.argv[1], sys.argv[2]
found = problems(path)
if expect == "clean":
    if found:
        print(f"FAIL: {path}:")
        for p in found:
            print(f"  - {p}")
        sys.exit(1)
    print(f"PASS: {path}: candidate, full and narrow gate runs get the intended groups")
else:
    if not found:
        print(f"FAIL: the checker accepted the broken fixture {path} ({expect})")
        sys.exit(1)
    print(f"PASS: the checker rejects {expect}: {found[0]}")
PY

# Fixture: the tag-only group this replaced (artifact-keeper-test#840).
cat > "${WORK}/tag-only.yml" <<'YML'
concurrency:
  group: release-gate-${{ inputs.backend_tag }}
  cancel-in-progress: false
jobs: {}
YML
# Fixture: candidate and narrow classes, but release.yml shares the full group.
cat > "${WORK}/no-release-class.yml" <<'YML'
concurrency:
  group: >-
    release-gate-${{ inputs.backend_tag }}${{
    startsWith(github.workflow_ref, 'artifact-keeper/artifact-keeper/.github/workflows/release-candidate.yml@') && '-candidate'
    || (inputs.only_jobs == '' && inputs.test_suite == 'all') && '-full'
    || format('-narrow-{0}', github.run_id) }}
  cancel-in-progress: false
jobs: {}
YML
# Fixture: narrow runs keyed per run, but the candidate shares the full group.
cat > "${WORK}/no-candidate-class.yml" <<'YML'
concurrency:
  group: >-
    release-gate-${{ inputs.backend_tag }}${{
    (inputs.only_jobs == '' && inputs.test_suite == 'all') && '-full'
    || format('-narrow-{0}', github.run_id) }}
  cancel-in-progress: false
jobs: {}
YML

python3 "${WORK}/check.py" "${WORK}/tag-only.yml" "the tag-only group"
python3 "${WORK}/check.py" "${WORK}/no-candidate-class.yml" "a group without a candidate class"
python3 "${WORK}/check.py" "${WORK}/no-release-class.yml" "a group without a release.yml class"
python3 "${WORK}/check.py" "$TARGET" clean
