#!/usr/bin/env bash
# selftest-gate-needs-closure.sh - a gate job that can be selected can also
# have its prerequisites run (artifact-keeper-test#870).
#
# A job whose `if:` has no always()/!cancelled() runs only when every job in
# its `needs:` succeeded. If a narrow run can select the job (by test_suite or
# by only_jobs) without also selecting a prerequisite, the prerequisite skips,
# the job skips with it, and the run reports nothing for a suite it was asked
# to run. test_suite=admin|platform did exactly that with auth-tests.
#
# For every such job J and prerequisite K, this evaluates both `if:`s of the
# real release-gate.yml for every test_suite choice, with only_jobs empty and
# with only_jobs = J, and fails when J's is true and K's is false. Conditions
# on a prerequisite's outputs (clean-install-smoke's cluster flag, owned by
# gate-selection.sh and its self-test) count as true. A fixture with the old
# auth-tests condition must be rejected first, so a checker that stops
# detecting anything turns this red.
#
# Usage: bash scripts/selftest-gate-needs-closure.sh [path/to/release-gate.yml]
# Requires: python3 with PyYAML.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-${REPO_ROOT}/.github/workflows/release-gate.yml}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "${WORK}/check.py" <<'PY'
import re
import sys

import yaml

TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>&&|\|\||==|!=|\(|\)|,)|(?P<bool>true|false)\b|(?P<id>[A-Za-z_][A-Za-z0-9_.-]*))")


def tokenize(src):
    pos, out, src = 0, [], src.strip()
    while pos < len(src):
        m = TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise ValueError(f"unsupported syntax at {src[pos:pos + 40]!r}")
        pos = m.end()
        if m.group("str") is not None:
            out.append(("str", m.group("str")[1:-1].replace("''", "'")))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        elif m.group("bool") is not None:
            out.append(("lit", m.group("bool") == "true"))
        else:
            out.append(("id", m.group("id")))
    return out


class P:
    def __init__(self, toks, ctx):
        self.t, self.i, self.ctx = toks, 0, ctx

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, v=None):
        tok = self.peek()
        if v is not None and tok[1] != v:
            raise ValueError(f"expected {v!r}, got {tok!r}")
        self.i += 1
        return tok

    def run(self):
        v = self.or_()
        if self.i != len(self.t):
            raise ValueError(f"trailing tokens {self.t[self.i:]}")
        return v

    def or_(self):
        v = self.and_()
        while self.peek() == ("op", "||"):
            self.take(); r = self.and_(); v = v if v else r
        return v

    def and_(self):
        v = self.cmp()
        while self.peek() == ("op", "&&"):
            self.take(); r = self.cmp(); v = r if v else v
        return v

    def cmp(self):
        v = self.atom()
        if self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]; r = self.atom()
            if v is UNKNOWN or r is UNKNOWN:
                return True
            eq = str(v).lower() == str(r).lower()
            v = eq if op == "==" else not eq
        return v

    def atom(self):
        kind, val = self.take()
        if kind in ("str", "lit"):
            return val
        if (kind, val) == ("op", "("):
            v = self.or_(); self.take(")"); return v
        if kind == "id" and self.peek() == ("op", "("):
            self.take("(")
            args = [] if self.peek() == ("op", ")") else [self.or_()]
            while self.peek() == ("op", ","):
                self.take(); args.append(self.or_())
            self.take(")")
            if val == "contains" and len(args) == 2:
                return str(args[1]).lower() in str(args[0]).lower()
            if val == "format":
                return re.sub(r"\{(\d+)\}", lambda m: str(args[1 + int(m.group(1))]), args[0])
            raise ValueError(f"unsupported function {val}()")
        if kind == "id" and val.startswith("inputs."):
            return self.ctx[val.split(".", 1)[1]]
        if kind == "id" and val.startswith("needs."):
            return UNKNOWN
        raise ValueError(f"unsupported token {val!r}")


UNKNOWN = object()


def ev(cond, ctx):
    if cond is None:
        return True
    if isinstance(cond, bool):
        return cond
    src = str(cond).strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", src, flags=re.S)
    if m:
        src = m.group(1)
    v = P(tokenize(src), ctx).run()
    return True if v is UNKNOWN else bool(v)


def tolerant(cond):
    return cond is not None and re.search(r"\b(always|cancelled|failure)\(\)", str(cond)) is not None


def problems(path):
    with open(path) as fh:
        wf = yaml.safe_load(fh)
    jobs = wf["jobs"]
    on = wf.get("on", wf.get(True))
    suites = on["workflow_dispatch"]["inputs"]["test_suite"]["options"]
    out, pairs = [], 0
    for j, d in jobs.items():
        if tolerant(d.get("if")):
            continue
        needs = d.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        for k in needs:
            pairs += 1
            for suite in suites:
                for only in ("", j):
                    ctx = {"test_suite": suite, "only_jobs": only, "run_smoke_with_deps": True,
                           "skip_teardown": False}
                    try:
                        jv, kv = ev(d.get("if"), ctx), ev(jobs[k].get("if"), ctx)
                    except ValueError as e:
                        return [f"cannot evaluate {j} or {k}: {e}"]
                    if jv and not kv:
                        out.append(f"{j} runs for test_suite={suite} only_jobs={only!r} but its prerequisite {k} does not, so {j} would skip")
    if pairs == 0:
        out.append("no job/prerequisite pairs found; the checker read nothing")
    return out


path, expect = sys.argv[1], sys.argv[2]
found = problems(path)
if expect == "clean":
    if found:
        print(f"FAIL: {path}:")
        for p in found:
            print(f"  - {p}")
        sys.exit(1)
    print(f"PASS: {path}: every selectable job's prerequisites are selected with it")
else:
    if not found:
        print(f"FAIL: the checker accepted {expect}")
        sys.exit(1)
    print(f"PASS: the checker rejects {expect}: {found[0]}")
PY

# Fixture: the real workflow with auth-tests' pre-#870 test_suite clause.
sed "s/(inputs.test_suite == 'all' || inputs.test_suite == 'auth' || inputs.test_suite == 'platform' || inputs.test_suite == 'admin')/(inputs.test_suite == 'all' || inputs.test_suite == 'auth')/" \
  "$TARGET" > "${WORK}/old-auth.yml"
# Fixture: auth-tests no longer follows an only_jobs selection of admin-tests.
sed "/' auth-tests '/s/ || contains(format(' {0} ', inputs.only_jobs), ' admin-tests '))/)/" \
  "$TARGET" > "${WORK}/no-admin-closure.yml"

python3 "${WORK}/check.py" "${WORK}/old-auth.yml" "auth-tests skipping for test_suite=admin|platform"
python3 "${WORK}/check.py" "${WORK}/no-admin-closure.yml" "auth-tests skipping for only_jobs=admin-tests"
python3 "${WORK}/check.py" "$TARGET" clean
