#!/usr/bin/env python3
# =============================================================================
# mock_artifactory.py - an Artifactory-shaped migration SOURCE with per-item
#                       properties and scripted per-item failures
# =============================================================================
# Copied from harness/tiers/migration-package-catalog/fixtures/ and extended
# for the migration-items-filters tier (artifact-keeper#4787 / #4778 and
# #4797 / #4740). That copy serves real files with no properties and every
# download succeeding; this one also reads a control document,
# MOCK_CATALOG_DIR/_mock.json, written by the oracle next to the files:
#
#   {
#     "properties": { "<repo>/<path>": { "deb.component": ["contrib"], ... } },
#     "bad_sha256": [ "<repo>/<path>", ... ],
#     "phantom":    [ "<repo>/<path>", ... ]
#   }
#
#   properties  served by GET /api/storage/{repo}/{path}?properties, the call
#               the importer makes to read an item's `deb.component` (#4740).
#               An item with no entry answers 404, as before.
#   bad_sha256  the AQL row advertises a sha256/sha1 that do not match the
#               bytes, so a checksum-verifying migration FAILS that item.
#   phantom     listed by AQL but 404 on download. For a Debian index path (not
#               under dists/, which the importer drops unrecorded) in
#               a repository whose key contains "debian" the importer marks
#               such an item SKIPPED (cache metadata, eligible on a re-run).
#
# Endpoints (unchanged from the sibling mock):
#   GET  /api/system/ping, /api/system/version, /api/repositories
#   POST /api/search/aql                        artifact enumeration (paged)
#   GET  /{repo}/{path}                         artifact download
#   GET  /api/storage/{repo}/{path}[?properties] properties / download fallback
#   GET  /__readyz                              container healthcheck
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT          listen port (default 80)
#   MOCK_REPOS         `key:packageType[,key:packageType...]`
#   MOCK_CATALOG_DIR   root holding one directory per repository key
# =============================================================================
import hashlib
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
SPEC = os.environ.get("MOCK_REPOS", "dtfmi-debian:debian,dtfmi-gen:generic")
ROOT = os.path.realpath(os.environ.get("MOCK_CATALOG_DIR", "/srv/catalog"))

REPOS = {}
for part in SPEC.split(","):
    part = part.strip()
    if not part:
        continue
    key, _, ptype = part.partition(":")
    REPOS[key] = ptype or "generic"

os.makedirs(ROOT, exist_ok=True)
for key in REPOS:
    os.makedirs(os.path.join(ROOT, key), exist_ok=True)

# A digest no fixture file has: what a `bad_sha256` row advertises.
WRONG_SHA256 = hashlib.sha256(b"dtf: not the bytes you will download").hexdigest()
WRONG_SHA1 = hashlib.sha1(b"dtf: not the bytes you will download").hexdigest()


def control():
    """The oracle's control document, re-read on every request."""
    try:
        with open(os.path.join(ROOT, "_mock.json"), "rb") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        doc = {}
    return {
        "properties": doc.get("properties") or {},
        "bad_sha256": set(doc.get("bad_sha256") or []),
        "phantom": list(doc.get("phantom") or []),
    }


def repo_file(repo, rel):
    """The on-disk file for `repo`/`rel`, or None (never escapes the repo)."""
    base = os.path.realpath(os.path.join(ROOT, repo))
    full = os.path.realpath(os.path.join(base, rel))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        return None
    return full


def row(repo, rel_dir, name, body, bad):
    return {
        "repo": repo,
        # Artifactory reports a root-level file's path as ".".
        "path": rel_dir if rel_dir else ".",
        "name": name,
        "size": len(body),
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "sha256": WRONG_SHA256 if bad else hashlib.sha256(body).hexdigest(),
        "actual_sha1": WRONG_SHA1 if bad else hashlib.sha1(body).hexdigest(),
        "actual_md5": hashlib.md5(body).hexdigest(),
    }


def entries(repo):
    """The AQL rows for one repository, in a stable order."""
    ctl = control()
    base = os.path.join(ROOT, repo)
    rows = []
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(dirpath, name)
            rel_dir = os.path.relpath(dirpath, base)
            rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
            key = f"{repo}/{rel_dir + '/' if rel_dir else ''}{name}"
            with open(full, "rb") as fh:
                body = fh.read()
            rows.append(row(repo, rel_dir, name, body, key in ctl["bad_sha256"]))
    for key in ctl["phantom"]:
        prepo, _, rel = key.partition("/")
        if prepo != repo or not rel:
            continue
        rel_dir, _, name = rel.rpartition("/")
        rows.append(row(repo, rel_dir, name, b"phantom: listed, never served\n", False))
    rows.sort(key=lambda r: (r["path"], r["name"]))
    return rows


AQL_REPO = re.compile(r'"repo"\s*:\s*"([^"]+)"')
AQL_OFFSET = re.compile(r"\.offset\((\d+)\)")
AQL_LIMIT = re.compile(r"\.limit\((\d+)\)")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[mock-artifactory] " + (fmt % args), flush=True)

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")

        if path == "/__readyz":
            return self._send(200, "ok", "text/plain")
        if path == "/api/system/ping":
            return self._send(200, "OK", "text/plain")
        if path == "/api/system/version":
            return self._send(
                200,
                {"version": "7.77.7", "revision": "dtf-mock", "addons": [], "license": "dtf-mock"},
            )
        if path == "/api/repositories":
            return self._send(
                200,
                [
                    {
                        "key": key,
                        "type": "LOCAL",
                        "packageType": ptype,
                        "url": f"http://mock-artifactory/{key}",
                        "description": f"DTF migration-items-filters fixture ({ptype})",
                    }
                    for key, ptype in REPOS.items()
                ],
            )
        if path.startswith("/api/storage/"):
            item = path[len("/api/storage/"):]
            props = control()["properties"].get(item)
            if "properties" in query.split("&") and props:
                return self._send(
                    200,
                    {"properties": props, "uri": f"http://mock-artifactory/api/storage/{item}"},
                )
            # No properties recorded, or a storage-info (download fallback)
            # lookup: answer 404, as the sibling mock does.
            return self._send(404, {"errors": [{"status": 404}]})

        parts = path.lstrip("/").split("/", 1)
        if len(parts) == 2 and parts[0] in REPOS:
            full = repo_file(parts[0], parts[1])
            if full:
                with open(full, "rb") as fh:
                    return self._send(200, fh.read(), "application/octet-stream")
        return self._send(404, {"errors": [{"status": 404, "message": path}]})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        if path != "/api/search/aql":
            return self._send(404, {"errors": [{"status": 404, "message": path}]})

        repo_m = AQL_REPO.search(body)
        repo = repo_m.group(1) if repo_m else ""
        off_m = AQL_OFFSET.search(body)
        lim_m = AQL_LIMIT.search(body)
        offset = int(off_m.group(1)) if off_m else 0
        limit = int(lim_m.group(1)) if lim_m else 1000

        rows = entries(repo)[offset : offset + limit] if repo in REPOS else []
        return self._send(
            200,
            {
                "results": rows,
                # AQL reports the CURRENT PAGE's row count as `total`.
                "range": {"start_pos": offset, "end_pos": offset + len(rows), "total": len(rows)},
            },
        )


if __name__ == "__main__":
    print(f"[mock-artifactory] repos={REPOS} root={ROOT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
