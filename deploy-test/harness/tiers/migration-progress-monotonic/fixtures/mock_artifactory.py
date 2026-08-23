#!/usr/bin/env python3
# =============================================================================
# mock_artifactory.py — a scripted Artifactory-shaped migration SOURCE
# =============================================================================
# The migration-progress-monotonic tier (artifact-keeper#3510 / #3511) needs a
# migration to pause, resume, re-pause and cancel at moments the oracle
# chooses. A real Nexus/Artifactory cannot be steered like that, so this serves
# the four endpoints `ArtifactoryClient` actually calls, over a synthetic
# catalogue whose size and LISTING LATENCY are configuration:
#
#   GET  /api/system/ping                       connection test
#   GET  /api/system/version                    connection test (soft)
#   GET  /api/repositories                      destination provisioning
#   POST /api/search/aql                        artifact enumeration (paged)
#   GET  /{repo}/{path}                         artifact download
#   GET  /api/storage/{repo}/{path}             download fallback (unused here)
#   GET  /__readyz                              container healthcheck
#
# WHY THE LATENCY KNOB IS THE WHOLE POINT
# `process_job` checks for a pause only BETWEEN artifacts, after the page has
# been listed. So the deterministic place to catch a resumed run "mid-listing"
# — before it has re-accounted for a single item — is while it is waiting for
# its first AQL page. Repositories whose key ends in the SLOW_SUFFIX delay that
# response by MOCK_LIST_DELAY_MS, which gives the oracle a wide, reliable
# window to issue its second pause. Without it the oracle would be racing a
# sub-millisecond loop and the tier would be flaky in BOTH directions.
#
# Catalogue: `MOCK_REPOS` is `key:count[,key:count...]`. Repository `r` holds
# `count` files at `dtf/<r>/file-NNNN.bin`, each with deterministic content, so
# sizes and sha256 digests are stable across runs and across the two images
# under comparison, and the destination can be diffed exactly.
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT           listen port (default 80)
#   MOCK_REPOS          catalogue spec (default "dtfmig-int:24,dtfmig-full:6")
#   MOCK_LIST_DELAY_MS  AQL delay for slow repos (default 9000)
#   MOCK_SLOW_REPOS     comma-separated repo keys whose AQL listing is slow
#   MOCK_FILE_BYTES     bytes per artifact (default 512)
# =============================================================================
import hashlib
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
SPEC = os.environ.get("MOCK_REPOS", "dtfmig-int:24,dtfmig-full:6")
LIST_DELAY_MS = int(os.environ.get("MOCK_LIST_DELAY_MS", "9000"))
SLOW_REPOS = {r.strip() for r in os.environ.get("MOCK_SLOW_REPOS", "").split(",") if r.strip()}
FILE_BYTES = int(os.environ.get("MOCK_FILE_BYTES", "512"))

# repo key -> file count
CATALOGUE = {}
for part in SPEC.split(","):
    part = part.strip()
    if not part:
        continue
    key, _, count = part.partition(":")
    CATALOGUE[key] = int(count or "1")


def blob(repo, idx):
    """Deterministic body for one artifact: same bytes on every run."""
    seed = f"{repo}/{idx}".encode()
    out = bytearray()
    while len(out) < FILE_BYTES:
        seed = hashlib.sha256(seed).digest()
        out.extend(seed)
    return bytes(out[:FILE_BYTES])


def entries(repo):
    """The AQL rows for one repository, in a stable order."""
    rows = []
    for i in range(CATALOGUE.get(repo, 0)):
        body = blob(repo, i)
        rows.append(
            {
                "repo": repo,
                "path": f"dtf/{repo}",
                "name": f"file-{i:04d}.bin",
                "size": len(body),
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "sha256": hashlib.sha256(body).hexdigest(),
                "actual_sha1": hashlib.sha1(body).hexdigest(),
            }
        )
    return rows


AQL_REPO = re.compile(r'"repo"\s*:\s*"([^"]+)"')
AQL_OFFSET = re.compile(r"\.offset\((\d+)\)")
AQL_LIMIT = re.compile(r"\.limit\((\d+)\)")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the container log readable
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
                        "packageType": "generic",
                        "url": f"http://mock-artifactory/{key}",
                        "description": f"DTF migration fixture ({count} files)",
                    }
                    for key, count in CATALOGUE.items()
                ],
            )
        if path.startswith("/api/storage/"):
            # download fallback; the direct download below never 404s, so the
            # client should not reach this. Answer honestly anyway.
            return self._send(404, {"errors": [{"status": 404}]})

        # Direct artifact download: /{repo}/{path}
        parts = path.lstrip("/").split("/")
        if len(parts) >= 2 and parts[0] in CATALOGUE:
            repo = parts[0]
            name = parts[-1]
            m = re.fullmatch(r"file-(\d+)\.bin", name)
            if m and int(m.group(1)) < CATALOGUE[repo]:
                return self._send(
                    200, blob(repo, int(m.group(1))), "application/octet-stream"
                )
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
        offset = int(AQL_OFFSET.search(body).group(1)) if AQL_OFFSET.search(body) else 0
        limit = int(AQL_LIMIT.search(body).group(1)) if AQL_LIMIT.search(body) else 1000

        # The steering knob. See the header: this is what makes "pause the
        # resumed run before it has re-accounted for anything" deterministic
        # instead of a race.
        if repo in SLOW_REPOS and LIST_DELAY_MS > 0:
            time.sleep(LIST_DELAY_MS / 1000.0)

        rows = entries(repo)[offset : offset + limit]
        return self._send(
            200,
            {
                "results": rows,
                "range": {
                    "start_pos": offset,
                    "end_pos": offset + len(rows),
                    # AQL reports the CURRENT PAGE's row count here, not the
                    # result-set total. The worker decides termination from the
                    # page shape, so reproduce Artifactory's actual semantics.
                    "total": len(rows),
                },
            },
        )


if __name__ == "__main__":
    print(
        f"[mock-artifactory] catalogue={CATALOGUE} slow_repos={sorted(SLOW_REPOS)} "
        f"list_delay_ms={LIST_DELAY_MS} file_bytes={FILE_BYTES}",
        flush=True,
    )
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
