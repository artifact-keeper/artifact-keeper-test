# Conformance Corpus (vertical slice: pypi + oci)

A format-keyed set of protocol scenarios harvested from specs (PEPs, OCI
distribution-spec) and mature client suites (uv, pip; OCI conformance). One
corpus, two consumers — see `docs/test-framework-2026.md` for the full design.

```
conformance/
  corpus/
    schema.json        # the scenario schema (documented below)
    pypi/*.json         # PyPI scenarios (this slice)
  README.md
```

Runners:
- **DTF runner** (this slice): `harness/tiers/pypi-conformance/oracle.sh` loads
  `corpus/pypi/*.json`, stands each scenario's `mock_variant` up on the
  `mock-pypi-conf` upstream, points an AK remote repo at it, executes `steps`,
  and asserts each `expect`. The `oci-conformance` tier adopts the upstream OCI
  suite directly (its own point-at-server corpus).
- **Unit runner** (next slice): a backend Rust harness reads the SAME JSON and
  drives `given`/`expect` through trait seams (upstream-HTTP, clock, scanner).
  Deliberately out of this PR to keep it single-purpose.

## Scenario schema

```jsonc
{
  "id": "pypi/metadata-advertised-404",   // unique, path-like
  "format": "pypi",
  "spec_refs": ["PEP 658", "PEP 714"],     // the checklist item(s) this pins
  "source": "uv uv-test/pypi_proxy.rs (MIT); AK #3077",
  "mock_variant": "advertised-404",         // route family mock-pypi-conf serves
  "package": "dtfpkg",
  "steps": [
    {
      "desc": "wheel still downloads even though advertised .metadata 404s",
      "request": { "method": "GET", "path": "/pypi/{repo}/simple/{pkg}/" },
      "expect": {
        "status": 200,
        "body_contains": ["dtfpkg-1.0.0-py3-none-any.whl"],
        "body_not_contains": ["files.pythonhosted.org"]   // must be rewritten
      }
    }
  ],
  "runners": ["dtf", "unit"]
}
```

- `{repo}` and `{pkg}` are substituted by the runner (repo is created per-run,
  pkg = `package`).
- `mock_variant` selects a route family on `mock-pypi-conf` (see the fixture
  `harness/tiers/pypi-conformance/fixtures/mock_pypi_conf.py`). Adding a variant
  = one route family + N scenarios; no oracle edits.
- `expect` keys: `status`, `body_contains[]`, `body_not_contains[]`,
  `header` (`{name,equals|contains}`). Assertions are observable-only.

## Adding a scenario

1. If it needs new upstream behavior, add a `mock_variant` route family to
   `mock_pypi_conf.py`.
2. Drop a `corpus/pypi/<id>.json` file.
3. Run `harness/run.sh pypi-conformance`.

## Coverage in this slice (PyPI)

Harvested from the PEP checklist + uv's `pypi_proxy` variants + AK regressions:

| id | spec | vector source |
|----|------|---------------|
| pypi/simple-json-negotiation | PEP 691 | spec |
| pypi/metadata-advertised-404 | PEP 658/714 | uv proxy; AK #3077 |
| pypi/relative-file-url | PEP 503 | uv `/relative/` |
| pypi/yanked-release | PEP 592 | spec |
| pypi/lying-content-type | PEP 691 | uv; AK #2801 |
| pypi/upload-time-field | PEP 700 | uv `/no-upload-time/` |

OCI coverage is the upstream conformance suite (pull + push + content-discovery;
delete opt-in) — see `harness/tiers/oci-conformance/`.
