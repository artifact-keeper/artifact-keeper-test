#!/usr/bin/env python3
# =============================================================================
# mock_nexus.py: a scripted Nexus 3-shaped migration SOURCE that counts its
#                listing requests (artifact-keeper#6360, #6260)
# =============================================================================
# The Nexus listing fixes in 1.13.0 are about upstream work, not output: a real
# Nexus cannot tell the oracle how many `/assets` pages a migration walked or
# how far one listing call ran before the worker saw a cancel. This mock serves
# the endpoints `NexusClient` calls and counts every listing request per
# endpoint and repository, which is the deterministic proxy the gates read.
#
#   GET /service/rest/v1/status/writable     connection test (ping)
#   GET /service/rest/v1/status              version (soft)
#   GET /service/rest/v1/repositories        repository list
#   GET /service/rest/v1/components          component listing, 10 per page
#   GET /service/rest/v1/assets              asset listing, 10 per page
#   GET /repository/{repo}/{path}            download
#   GET /__stats                             {"components:<repo>": n, ...}
#   GET /__readyz                            container healthcheck
#
# CATALOGUE (fixed; the oracle's constants must match)
#   nx-npm      npm, 25 components with one tarball each. Its asset listing
#               holds the 25 tarballs and 5 packuments (3 pages). Nothing in
#               it is listed by the asset walk, so a migration must not walk
#               it (#6360).
#   nx-raw      raw, 5 components plus 2 files no component owns (the asset
#               walk must still run here and find exactly those 2).
#   nx-wide     npm, WIDE_PAGES pages of 10 components modified in 2020, then
#               one page with one component modified 2026-06-01. With a
#               date_from of 2025 every page but the last is empty (#6260).
#   nx-wide-ok  the same shape with WIDE_OK_PAGES pages: the control that a
#               walk through many empty budgeted pages still finds the one
#               in-window component.
#
# Listing requests of the nx-wide* repositories are delayed by
# MOCK_LIST_DELAY_MS so a walk of them takes long enough to cancel into.
# Stdlib only, single file, stock python image.
# =============================================================================
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("MOCK_PORT", "80"))
WIDE_PAGES = int(os.environ.get("WIDE_PAGES", "400"))
WIDE_OK_PAGES = int(os.environ.get("WIDE_OK_PAGES", "120"))
LIST_DELAY_MS = int(os.environ.get("MOCK_LIST_DELAY_MS", "20"))
PAGE = 10
OLD = "2020-01-01T00:00:00.000+00:00"
NEW = "2026-06-01T00:00:00.000+00:00"

STATS = {}
STATS_LOCK = threading.Lock()


def blob(repo, path):
    seed = f"{repo}/{path}".encode()
    return (hashlib.sha256(seed).hexdigest() * 4).encode()[:200]


def asset(repo, fmt, path, modified=NEW):
    body = blob(repo, path)
    return {
        "id": f"{repo}:{path}",
        "path": path,
        "downloadUrl": f"http://mock-nexus/repository/{repo}/{path}",
        "format": fmt,
        "checksum": {
            "sha1": hashlib.sha1(body).hexdigest(),
            "sha256": hashlib.sha256(body).hexdigest(),
        },
        "contentType": "application/octet-stream",
        "fileSize": len(body),
        "lastModified": modified,
    }


def component(repo, fmt, name, a):
    return {
        "id": f"{repo}:{name}",
        "repository": repo,
        "format": fmt,
        "group": None,
        "name": name,
        "version": "1.0.0",
        "assets": [a],
    }


def npm_component(repo, i, modified=NEW):
    name = f"pkg{i}"
    return component(repo, "npm", name, asset(repo, "npm", f"{name}/-/{name}-1.0.0.tgz", modified))


# repo -> (format, components, assets); built lazily for the wide repos
def build():
    cat = {}
    comps = [npm_component("nx-npm", i) for i in range(25)]
    assets = [c["assets"][0] for c in comps] + [
        asset("nx-npm", "npm", f"pkg{i}") for i in range(5)
    ]
    cat["nx-npm"] = ("npm", comps, assets)

    comps = [
        component("nx-raw", "raw", f"c{i}", asset("nx-raw", "raw", f"comp/c{i}.bin"))
        for i in range(5)
    ]
    loose = [asset("nx-raw", "raw", f"loose/l{i}.bin") for i in range(2)]
    cat["nx-raw"] = ("raw", comps, [c["assets"][0] for c in comps] + loose)

    for repo, pages in (("nx-wide", WIDE_PAGES), ("nx-wide-ok", WIDE_OK_PAGES)):
        comps = [npm_component(repo, i, OLD) for i in range(pages * PAGE)]
        comps.append(npm_component(repo, pages * PAGE, NEW))
        cat[repo] = ("npm", comps, [c["assets"][0] for c in comps])
    return cat


CATALOGUE = build()
BLOBS = {
    (repo, a["path"]): blob(repo, a["path"])
    for repo, (_, _, assets) in CATALOGUE.items()
    for a in assets
}


def count(key):
    with STATS_LOCK:
        STATS[key] = STATS.get(key, 0) + 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def not_found(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def listing(self, endpoint, q):
        repo = (q.get("repository") or [""])[0]
        if repo not in CATALOGUE:
            return self.not_found()
        count(f"{endpoint}:{repo}")
        if repo.startswith("nx-wide") and LIST_DELAY_MS > 0:
            time.sleep(LIST_DELAY_MS / 1000.0)
        _, comps, assets = CATALOGUE[repo]
        items = comps if endpoint == "components" else assets
        page = int((q.get("continuationToken") or ["0"])[0] or 0)
        chunk = items[page * PAGE:(page + 1) * PAGE]
        nxt = str(page + 1) if (page + 1) * PAGE < len(items) else None
        self.send_json({"items": chunk, "continuationToken": nxt})

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        if p == "/__readyz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif p == "/__stats":
            with STATS_LOCK:
                snap = dict(STATS)
            self.send_json(snap)
        elif p == "/service/rest/v1/status/writable":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif p == "/service/rest/v1/status":
            self.send_json({"edition": "OSS", "version": "3.68.1-02"})
        elif p == "/service/rest/v1/repositories":
            self.send_json(
                [
                    {"name": r, "format": f, "type": "hosted",
                     "url": f"http://mock-nexus/repository/{r}"}
                    for r, (f, _, _) in CATALOGUE.items()
                ]
            )
        elif p == "/service/rest/v1/components":
            self.listing("components", q)
        elif p == "/service/rest/v1/assets":
            self.listing("assets", q)
        elif p.startswith("/repository/"):
            repo, _, path = p[len("/repository/"):].partition("/")
            body = BLOBS.get((repo, path))
            if body is None:
                return self.not_found()
            count(f"download:{repo}")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.not_found()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
