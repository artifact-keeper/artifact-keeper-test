#!/usr/bin/env python3
"""Mock NuGet V3 upstream that supports SearchQueryService (discussion #3130).

The existing `nuget-cred-scoping` mock deliberately advertises only
PackageBaseAddress + RegistrationsBaseUrl (it exists to prove a credential-leak
property, #2925). This one is separate on purpose: adding a search resource to
that fixture would perturb a live gate for no benefit.

What it serves:

  GET /__readyz                       -> "ok" (compose healthcheck)
  GET /v3/index.json                  -> service index advertising
                                         PackageBaseAddress/3.0.0,
                                         RegistrationsBaseUrl and all three
                                         SearchQueryService @type spellings
  GET /v3/query?q=&skip=&take=&prerelease=
                                      -> NuGet search payload, REALLY filtered
  GET /v3/registration/<id>/index.json-> minimal registration doc

The search really filters on `q` (case-insensitive substring over the package
id) and really honours skip/take/prerelease. That matters: the DTF oracle
asserts a non-matching query returns zero hits and that two different queries
return different payloads, which is what catches a proxy whose response cache
key does not encode the query parameters.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("MOCK_PORT", "80"))
# Host AK addresses us by; used to build absolute resource URLs so the proxy has
# real upstream URLs to rewrite.
SELF_HOST = os.environ.get("SELF_HOST", "mock-nuget-search")
BASE = f"http://{SELF_HOST}"

# Small catalogue. Ids differ enough that a substring query selects a strict
# subset — a proxy that ignores `q` and returns everything fails the oracle.
CATALOGUE = [
    {"id": "Dtf.SearchMarker", "versions": ["1.0.0", "1.1.0"], "description": "DTF #3130 search marker"},
    {"id": "Dtf.SearchMarker.Extras", "versions": ["2.0.0"], "description": "DTF #3130 secondary marker"},
    {"id": "Unrelated.Package", "versions": ["9.9.9"], "description": "must not match the marker query"},
    {"id": "Prerelease.Only", "versions": ["1.0.0-beta1"], "description": "prerelease-only package"},
]


def _stable_versions(versions):
    return [v for v in versions if "-" not in v]


def _latest(versions, prerelease):
    pool = versions if prerelease else (_stable_versions(versions) or versions)
    return pool[-1]


def search_payload(q, skip, take, prerelease):
    term = (q or "").strip().lower()
    matched = []
    for pkg in CATALOGUE:
        if term and term not in pkg["id"].lower():
            continue
        versions = pkg["versions"] if prerelease else (_stable_versions(pkg["versions"]) or [])
        if not versions:
            # A stable-only search must not surface a prerelease-only package.
            continue
        matched.append((pkg, versions))

    total = len(matched)
    window = matched[skip: skip + take]
    data = []
    for pkg, versions in window:
        pid = pkg["id"]
        reg = f"{BASE}/v3/registration/{pid.lower()}/index.json"
        latest = _latest(versions, prerelease)
        data.append(
            {
                "@id": reg,
                "@type": "Package",
                "registration": reg,
                "id": pid,
                "version": latest,
                "description": pkg["description"],
                "totalDownloads": 0,
                "versions": [
                    {"version": v, "@id": f"{BASE}/v3/registration/{pid.lower()}/{v}.json"}
                    for v in versions
                ],
            }
        )
    return {"totalHits": total, "data": data}


def index_payload():
    return {
        "version": "3.0.0",
        "resources": [
            {"@id": f"{BASE}/v3/flatcontainer", "@type": "PackageBaseAddress/3.0.0"},
            {"@id": f"{BASE}/v3/registration", "@type": "RegistrationsBaseUrl"},
            {"@id": f"{BASE}/v3/registration", "@type": "RegistrationsBaseUrl/3.6.0"},
            {"@id": f"{BASE}/v3/query", "@type": "SearchQueryService"},
            {"@id": f"{BASE}/v3/query", "@type": "SearchQueryService/3.0.0-beta"},
            {"@id": f"{BASE}/v3/query", "@type": "SearchQueryService/3.0.0-rc"},
        ],
    }


def registration_payload(pid):
    return {
        "@id": f"{BASE}/v3/registration/{pid}/index.json",
        "count": 1,
        "items": [],
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if path == "/v3/index.json":
            return self._send(200, index_payload())
        if path == "/v3/query":
            def _int(name, default):
                try:
                    return int(qs.get(name, [str(default)])[0])
                except (TypeError, ValueError):
                    return default
            q = qs.get("q", [""])[0]
            skip = max(0, _int("skip", 0))
            take = max(0, min(100, _int("take", 20)))
            pre = qs.get("prerelease", ["false"])[0].lower() in ("1", "true", "yes")
            return self._send(200, search_payload(q, skip, take, pre))
        if path.startswith("/v3/registration/") and path.endswith("/index.json"):
            pid = path[len("/v3/registration/"):-len("/index.json")]
            return self._send(200, registration_payload(pid))

        return self._send(404, {"error": "not found", "path": path})

    def log_message(self, fmt, *args):  # keep compose logs readable
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
