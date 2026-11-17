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

TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>&&|\|\||==|!=|!|\(|\)|,)|(?P<bool>true|false)\b|(?P<id>[A-Za-z_][A-Za-z0-9_.-]*))")


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
        if (kind, val) == ("op", "!"):
            v = self.atom()
            return True if v is UNKNOWN else not v
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
            if val in ("always", "success", "failure") and not args:
                return True
            if val == "cancelled" and not args:
                return False
            if val == "contains" and len(args) == 2:
                return str(args[1]).lower() in str(args[0]).lower()
            if val == "format":
                return re.sub(r"\{(\d+)\}", lambda m: str(args[1 + int(m.group(1))]), args[0])
            raise ValueError(f"unsupported function {val}()")
        if kind == "id" and val.startswith("inputs."):
            key = val.split(".", 1)[1]
            if key not in self.ctx:
                raise ValueError(f"no value for inputs.{key}; add it to the checker's context")
            return self.ctx[key]
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
    # Every suite a caller can pass: the dispatch choices plus every literal the
    # workflow compares test_suite with (workflow_call takes a free string).
    suites = sorted(set(suites) | set(re.findall(r"inputs\.test_suite\s*==\s*'([a-z-]+)'", open(path).read())))
    out, pairs = [], 0
    for j, d in jobs.items():
        cond = d.get("if")
        needs = d.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        if tolerant(cond):
            # A tolerant job still depends on the prerequisites it demands
            # succeeded (stress-tests and resilience-tests on deploy).
            needs = [k for k in needs if re.search(r"needs\.%s\.result\s*==\s*'success'" % re.escape(k), str(cond))]
        for k in needs:
            pairs += 1
            for suite in suites:
                for only in ("", j):
                    ctx = {"test_suite": suite, "only_jobs": only, "run_smoke_with_deps": True,
                           "skip_teardown": False}
                    try:
                        jv, kv = ev(cond, ctx), ev(jobs[k].get("if"), ctx)
                    except ValueError as e:
                        return [f"cannot evaluate {j} or {k}: {e}"]
                    if jv and not kv:
                        out.append(f"{j} runs for test_suite={suite} only_jobs={only!r} but its prerequisite {k} does not, so {j} would skip")
    # gate-selection.sh skips clean-install-smoke (and so deploy) when only
    # its NO_CLUSTER jobs are selected: none of them may need the cluster.
    gs = open(sys.argv[3]).read()
    m = re.search(r'^NO_CLUSTER="([^"]*)"', gs, flags=re.M)
    if not m:
        out.append("cannot read NO_CLUSTER from gate-selection.sh")
    else:
        def closure(j, seen):
            n = jobs[j].get("needs") or []
            for k in ([n] if isinstance(n, str) else n):
                if k not in seen:
                    seen.add(k); closure(k, seen)
            return seen
        for j in m.group(1).split():
            if j == "collect-results":
                continue  # always(): reads every result, needs none of them to succeed
            bad = closure(j, set()) & {"clean-install-smoke", "deploy"}
            if bad:
                out.append(f"{j} is a no-cluster job in gate-selection.sh but needs {sorted(bad)}")
    if pairs == 0:
        out.append("no job/prerequisite pairs found; the checker read nothing")
    return out


path, expect = sys.argv[1], sys.argv[2]  # argv[3]: gate-selection.sh
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

# Fixture: only the admin clause removed (admin is reachable by workflow_call
# and by the dispatch choice).
sed "/' auth-tests '/s/ || inputs.test_suite == 'admin')/)/" "$TARGET" > "${WORK}/no-admin-suite.yml"
# Fixture: deploy narrowed so a stress-only run skips it under the tolerant job.
python3 - "$TARGET" "${WORK}/narrow-deploy.yml" <<'NARROW'
import sys
s = open(sys.argv[1]).read()
s = s.replace("  deploy:\n    needs: clean-install-smoke\n", "  deploy:\n    needs: clean-install-smoke\n    if: inputs.test_suite == 'all'\n", 1)
open(sys.argv[2], "w").write(s)
NARROW
GS="${REPO_ROOT}/scripts/gate-selection.sh"
# Fixture: a no-cluster job that needs deploy.
sed 's/^NO_CLUSTER=" /NO_CLUSTER=" admin-tests /' "$GS" > "${WORK}/gs-bad.sh"

python3 "${WORK}/check.py" "${WORK}/old-auth.yml" "auth-tests skipping for test_suite=admin|platform" "$GS"
python3 "${WORK}/check.py" "${WORK}/no-admin-closure.yml" "auth-tests skipping for only_jobs=admin-tests" "$GS"
python3 "${WORK}/check.py" "${WORK}/no-admin-suite.yml" "auth-tests skipping for test_suite=admin" "$GS"
python3 "${WORK}/check.py" "${WORK}/narrow-deploy.yml" "a narrowed deploy if:" "$GS"
python3 "${WORK}/check.py" "$TARGET" "a no-cluster job that needs deploy" "${WORK}/gs-bad.sh"
python3 "${WORK}/check.py" "$TARGET" clean "$GS"
