#!/usr/bin/env python3
# =============================================================================
# mock_artifactory.py — an Artifactory-shaped migration SOURCE serving REAL files
# =============================================================================
# Copied from harness/tiers/migration-progress-monotonic/fixtures/ and adapted
# for the migration-package-catalog tier (artifact-keeper#4691 / #4657). That
# copy serves a synthetic `generic` catalogue of deterministic noise; this one
# serves whatever real files sit under MOCK_CATALOG_DIR, each repository
# reporting the `packageType` the oracle names, so the migration provisions a
# native `maven` / `debian` destination and runs the format-specific import
# (catalog registration, control-file parse) the two fixes changed.
#
# The oracle BUILDS the files (a jar + pom + sidecars + maven-metadata.xml, and
# two real `.deb` archives) on the host and `docker cp`s them into this
# container after it is up, so the bytes are known to the oracle exactly and
# nothing binary is committed. The listing is read from disk on every request.
#
#   GET  /api/system/ping                       connection test
#   GET  /api/system/version                    connection test (soft)
#   GET  /api/repositories                      destination provisioning
#   POST /api/search/aql                        artifact enumeration (paged)
#   GET  /{repo}/{path}                         artifact download
#   GET  /api/storage/{repo}/{path}[?properties] properties / download fallback
#   GET  /__readyz                              container healthcheck
#   GET  /api/docker/{repo}/v2/{image}/blobs/sha256:{hex}
#                                               Docker registry API blob fetch
#                                               (the OCI import pulls a
#                                               manifest's blobs this way); it
#                                               serves the repository's
#                                               `<image>/.../sha256__{hex}` file
#
# Source-fidelity additions (artifact-keeper#3926, #4740/#4797):
#   * a file whose name starts with `slow-` is streamed over MOCK_SLOW_SECS
#     seconds (a slow source link), so a client with a whole-request timeout
#     shorter than that fails mid-body;
#   * `GET /api/storage/{repo}/{path}?properties` answers the item's
#     Artifactory properties from MOCK_CATALOG_DIR/__props/{repo}/{path}.json
#     when that file exists (404 otherwise, as before).
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT          listen port (default 80)
#   MOCK_REPOS         `key:packageType[,key:packageType...]`
#   MOCK_CATALOG_DIR   root holding one directory per repository key
#   MOCK_SLOW_SECS     how long a `slow-*` file takes to stream (default 36)
#   MOCK_REQUEST_LOG   every request line is appended here (default
#                      /tmp/mock-requests.log)
# =============================================================================
import hashlib
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
SPEC = os.environ.get("MOCK_REPOS", "dtfcat-mvn:maven,dtfcat-deb:debian")
ROOT = os.path.realpath(os.environ.get("MOCK_CATALOG_DIR", "/srv/catalog"))
SLOW_SECS = float(os.environ.get("MOCK_SLOW_SECS", "36"))
PROPS = os.path.join(ROOT, "__props")
REQUEST_LOG = os.environ.get("MOCK_REQUEST_LOG", "/tmp/mock-requests.log")

# repo key -> Artifactory packageType
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


def repo_file(repo, rel):
    """The on-disk file for `repo`/`rel`, or None (never escapes the repo)."""
    base = os.path.realpath(os.path.join(ROOT, repo))
    full = os.path.realpath(os.path.join(base, rel))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        return None
    return full


def entries(repo):
    """The AQL rows for one repository, in a stable order."""
    base = os.path.join(ROOT, repo)
    rows = []
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(dirpath, name)
            rel_dir = os.path.relpath(dirpath, base)
            with open(full, "rb") as fh:
                body = fh.read()
            rows.append(
                {
                    "repo": repo,
                    # Artifactory reports a root-level file's path as ".".
                    "path": "." if rel_dir == "." else rel_dir.replace(os.sep, "/"),
                    "name": name,
                    "size": len(body),
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "actual_sha1": hashlib.sha1(body).hexdigest(),
                    "actual_md5": hashlib.md5(body).hexdigest(),
                }
            )
    rows.sort(key=lambda r: (r["path"], r["name"]))
    return rows


AQL_REPO = re.compile(r'"repo"\s*:\s*"([^"]+)"')
AQL_OFFSET = re.compile(r"\.offset\((\d+)\)")
AQL_LIMIT = re.compile(r"\.limit\((\d+)\)")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the container log readable
        line = "[mock-artifactory] " + (fmt % args)
        print(line, flush=True)
        # Also kept in a file: the container log is size-capped and rotates,
        # and the oracle counts source GETs (REQUEST_LOG) after the jobs run.
        try:
            with open(REQUEST_LOG, "a") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

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

    def _send_slowly(self, body):
        """Stream `body` in 12 pieces spread over SLOW_SECS (#3926): the
        headers arrive at once and the link never goes idle for more than
        SLOW_SECS/12 seconds, but the whole body takes SLOW_SECS."""
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        pieces = 12
        step = max(1, -(-len(body) // pieces))
        for i in range(0, len(body), step):
            self.wfile.write(body[i : i + step])
            self.wfile.flush()
            time.sleep(SLOW_SECS / pieces)

    # -- GET ----------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/__readyz":
            return self._send(200, "ok", "text/plain")
        if path == "/api/system/ping":
            return self._send(200, "OK", "text/plain")
        if path == "/api/system/version":
            return self._send(
                200,
                {
                    "version": "7.77.7",
                    "revision": "dtf-mock",
                    "addons": [],
                    "license": "dtf-mock",
                },
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
                        "description": f"DTF migration-package-catalog fixture ({ptype})",
                    }
                    for key, ptype in REPOS.items()
                ],
            )
        if path.startswith("/api/docker/"):
            # /api/docker/{repo}/v2/{image...}/blobs/sha256:{hex}
            m = re.match(r"^/api/docker/([^/]+)/v2/(.+)/blobs/sha256:([0-9a-f]{64})$", path)
            if m and m.group(1) in REPOS:
                repo, image, hexd = m.groups()
                base = os.path.realpath(os.path.join(ROOT, repo, image))
                if base.startswith(os.path.realpath(os.path.join(ROOT, repo)) + os.sep):
                    for dirpath, _dirs, files in os.walk(base):
                        if "sha256__" + hexd in files:
                            with open(os.path.join(dirpath, "sha256__" + hexd), "rb") as fh:
                                return self._send(200, fh.read(), "application/octet-stream")
            return self._send(404, {"errors": [{"status": 404, "message": path}]})
        if path.startswith("/api/storage/"):
            # Properties lookups and the download fallback. Only an item with
            # a fixture properties document has properties (#4740); every
            # other lookup answers 404, as a property-less item does.
            rest = path[len("/api/storage/"):]
            repo, _, rel = rest.partition("/")
            if "properties" in self.path.split("?", 1)[-1] and repo in REPOS:
                base = os.path.realpath(os.path.join(PROPS, repo))
                doc = os.path.realpath(os.path.join(base, rel + ".json"))
                if doc.startswith(base + os.sep) and os.path.isfile(doc):
                    with open(doc, "rb") as fh:
                        props = json.load(fh)
                    return self._send(
                        200,
                        {
                            "properties": props,
                            "uri": f"http://mock-artifactory/api/storage/{repo}/{rel}",
                        },
                    )
            return self._send(404, {"errors": [{"status": 404}]})

        # Direct artifact download: /{repo}/{path}
        parts = path.lstrip("/").split("/", 1)
        if len(parts) == 2 and parts[0] in REPOS:
            full = repo_file(parts[0], parts[1])
            if full:
                with open(full, "rb") as fh:
                    body = fh.read()
                if os.path.basename(full).startswith("slow-"):
                    return self._send_slowly(body)
                return self._send(200, body, "application/octet-stream")
        return self._send(404, {"errors": [{"status": 404, "message": path}]})

    # -- POST ---------------------------------------------------------------
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
                "range": {
                    "start_pos": offset,
                    "end_pos": offset + len(rows),
                    # AQL reports the CURRENT PAGE's row count here, not the
                    # result-set total (see the original mock).
                    "total": len(rows),
                },
            },
        )


if __name__ == "__main__":
    print(f"[mock-artifactory] repos={REPOS} root={ROOT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
