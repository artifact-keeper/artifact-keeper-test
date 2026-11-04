#!/usr/bin/env python3
"""mock-mcp-upstream.py - query-aware mock of the official MCP registry.

tests/lib/mock-upstream.py strips query strings before it looks a file up, so
it cannot serve the registry API, whose pages depend on cursor, limit,
version, search and updated_since. This mock implements those semantics the
way registry.modelcontextprotocol.io does (API v0.1, also under /v0), from a
directory of fixture entries, deterministically.

State directory (MOCK_STATE_DIR, required; port MOCK_PORT, required):

  servers/*.json        one registry entry per file, in the upstream list
                        envelope's entry shape:
                          {"server": {<server.json>},
                           "_meta": {"io.modelcontextprotocol.registry/official":
                                     {"status": "active", "publishedAt": "...",
                                      "updatedAt": "..."}}}
                        A file holding a bare server.json is accepted too
                        (status active, timestamps from the file's mtime).
                        Files are re-read on every request, so a test mutates
                        the catalog by editing them.
  request-log.txt       one line per request: "<unix_ts> <METHOD> <path?query>"
  request-count.<key>   per-path counter, <key> = path (no query) with "/" ->
                        "_" and only [A-Za-z0-9_.-] kept, the same rule as
                        mock-upstream.py so mock_counter_key works unchanged
  request-count         total counter
  error-status          optional integer: every request answers that status
  delay-ms              optional per-request delay
  page-size             optional integer: cap every page at this size,
                        whatever limit the caller asked for (an upstream whose
                        page size differs from Artifact Keeper's)

Semantics (pinned to upstream):

  GET /v0.1/servers     cursor (opaque, from a previous nextCursor), limit
                        (default 30, max 100, <1 or non-numeric -> 400),
                        search (case-insensitive substring of the name, < 3
                        chars -> 422), version (latest | exact), updated_since
                        (RFC 3339; implies include_deleted), include_deleted.
                        Order: name, then version as text. isLatest is the
                        newest non-deleted version by SemVer precedence.
  GET /v0.1/servers/{name}/versions
  GET /v0.1/servers/{name}/versions/{version|latest}   ?include_deleted=true
                        {name} URL-encoded (%2F) or with a literal slash.
  GET /v0.1/health      {"status": "ok"}
  GET /__readyz         readiness probe, not logged or counted

Anything that is not a GET answers 405: a Remote must never write upstream.
"""

import base64
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

STATE = os.environ.get("MOCK_STATE_DIR")
PORT = os.environ.get("MOCK_PORT")
if not STATE or not PORT:
    sys.stderr.write("mock-mcp-upstream: MOCK_STATE_DIR and MOCK_PORT are required\n")
    sys.exit(2)
STATE_DIR = Path(STATE)
SERVERS_DIR = STATE_DIR / "servers"
SERVERS_DIR.mkdir(parents=True, exist_ok=True)
LOCK = threading.Lock()
OFFICIAL = "io.modelcontextprotocol.registry/official"
KEY_SAFE = re.compile(r"[^A-Za-z0-9_.-]")
SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def counter_key(path):
    key = path.split("?", 1)[0].lstrip("/").replace("/", "_")
    return KEY_SAFE.sub("", key)[:128] or "root"


def bump(name):
    path = STATE_DIR / name
    try:
        n = int(path.read_text().strip() or "0")
    except (FileNotFoundError, ValueError):
        n = 0
    tmp = STATE_DIR / (name + ".tmp")
    tmp.write_text(str(n + 1))
    os.replace(tmp, path)


def read_int(name):
    try:
        return int((STATE_DIR / name).read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text):
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def semver_key(version):
    m = SEMVER.match(version or "")
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    # Pre-releases rank below the release; compare identifiers numerically
    # where they are numeric.
    if pre is None:
        pre_key = (1,)
    else:
        parts = []
        for ident in pre.split("."):
            parts.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
        pre_key = (0, tuple(parts))
    return (int(major), int(minor), int(patch), pre_key)


def load_entries():
    entries = []
    for path in sorted(SERVERS_DIR.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if "server" in doc:
            server = doc["server"]
            meta = doc.get("_meta") or {}
        else:
            server, meta = doc, {}
        official = dict(meta.get(OFFICIAL) or {})
        stamp = iso(path.stat().st_mtime)
        official.setdefault("status", "active")
        official.setdefault("publishedAt", stamp)
        official.setdefault("updatedAt", official["publishedAt"])
        entries.append({"server": server, "official": official, "extra": {k: v for k, v in meta.items() if k != OFFICIAL}})
    latest = {}
    for e in entries:
        if e["official"]["status"] == "deleted":
            continue
        name = e["server"].get("name")
        cur = latest.get(name)
        if cur is None or rank(e) > rank(cur):
            latest[name] = e
    for e in entries:
        e["official"]["isLatest"] = latest.get(e["server"].get("name")) is e
    entries.sort(key=lambda e: (e["server"].get("name", ""), e["server"].get("version", "")))
    return entries


def rank(entry):
    key = semver_key(entry["server"].get("version"))
    published = entry["official"].get("publishedAt", "")
    # A SemVer version always ranks above a non-SemVer one; two non-SemVer
    # versions rank by publishedAt (the upstream rule).
    return (1, key, published) if key is not None else (0, (), published)


def render(entry):
    meta = dict(entry["extra"])
    meta[OFFICIAL] = entry["official"]
    return {"server": entry["server"], "_meta": meta}


def encode_cursor(entry):
    raw = "%s:%s" % (entry["server"].get("name", ""), entry["server"].get("version", ""))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(text):
    try:
        pad = "=" * (-len(text) % 4)
        raw = base64.urlsafe_b64decode(text + pad).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    name, sep, version = raw.rpartition(":")
    return (name, version) if sep else None


def problem(status, detail):
    return status, {"title": http.HTTPStatus(status).phrase, "status": status, "detail": detail}


def list_servers(query):
    q = {k: v[-1] for k, v in query.items()}
    limit_text = q.get("limit", "30")
    try:
        limit = int(limit_text)
    except ValueError:
        return problem(400, "limit must be an integer")
    if limit < 1:
        return problem(400, "limit must be at least 1")
    limit = min(limit, 100)
    cap = read_int("page-size")
    if cap:
        limit = min(limit, cap)
    search = q.get("search")
    if search is not None and len(search) < 3:
        return problem(422, "search must be at least 3 characters")
    since = None
    include_deleted = q.get("include_deleted", "false").lower() == "true"
    if "updated_since" in q:
        since = parse_time(q["updated_since"])
        if since is None:
            return problem(400, "updated_since must be RFC 3339")
        include_deleted = True
    version = q.get("version")
    entries = load_entries()
    picked = []
    for e in entries:
        name = e["server"].get("name", "")
        if search and search.lower() not in name.lower():
            continue
        if e["official"]["status"] == "deleted" and not include_deleted:
            continue
        if version == "latest" and not e["official"]["isLatest"]:
            continue
        if version and version != "latest" and e["server"].get("version") != version:
            continue
        if since is not None:
            updated = parse_time(e["official"].get("updatedAt"))
            if updated is None or updated <= since:
                continue
        picked.append(e)
    if "cursor" in q:
        after = decode_cursor(q["cursor"])
        if after is None:
            return problem(400, "invalid cursor")
        picked = [e for e in picked if (e["server"].get("name", ""), e["server"].get("version", "")) > after]
    page = picked[:limit]
    metadata = {"count": len(page)}
    if len(picked) > limit and page:
        metadata["nextCursor"] = encode_cursor(page[-1])
    return 200, {"servers": [render(e) for e in page], "metadata": metadata}


def server_versions(name, version, query):
    include_deleted = (query.get("include_deleted", ["false"])[-1]).lower() == "true"
    mine = [e for e in load_entries() if e["server"].get("name") == name]
    if version is None:
        visible = [e for e in mine if e["official"]["status"] != "deleted"]
        if not visible:
            return problem(404, "Server not found")
        return 200, {"servers": [render(e) for e in visible], "metadata": {"count": len(visible)}}
    if version == "latest":
        hit = [e for e in mine if e["official"]["isLatest"]]
    else:
        hit = [e for e in mine if e["server"].get("version") == version]
        if hit and hit[0]["official"]["status"] == "deleted" and not include_deleted:
            hit = []
    if not hit:
        return problem(404, "Server not found")
    return 200, render(hit[0])


ROUTE = re.compile(r"^/(v0\.1|v0)(/.*)$")


def route(path, query):
    m = ROUTE.match(path)
    if not m:
        return problem(404, "not found")
    tail = m.group(2)
    if tail == "/servers":
        return list_servers(query)
    if tail in ("/health", "/ping"):
        return 200, {"status": "ok"}
    if tail.startswith("/servers/"):
        rest = tail[len("/servers/"):]
        parts = rest.split("/")
        # {enc}/versions[/{v}] or {ns}/{name}/versions[/{v}]
        if len(parts) >= 2 and parts[1] == "versions":
            name = urllib.parse.unquote(parts[0])
            ver = parts[2] if len(parts) > 2 else None
        elif len(parts) >= 3 and parts[2] == "versions":
            name = urllib.parse.unquote(parts[0]) + "/" + urllib.parse.unquote(parts[1])
            ver = parts[3] if len(parts) > 3 else None
        else:
            return problem(404, "not found")
        if ver is not None:
            ver = urllib.parse.unquote(ver)
        return server_versions(name, ver, query)
    return problem(404, "not found")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _write(self, status, payload, ctype="application/json"):
        body = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload
        self.send_response(status)
        self.send_header("Content-Type", ctype if status < 400 or ctype != "application/json" else "application/problem+json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _record(self):
        with LOCK:
            with open(STATE_DIR / "request-log.txt", "a", encoding="utf-8") as fh:
                fh.write("%d %s %s\n" % (int(time.time()), self.command, self.path))
            bump("request-count")
            bump("request-count." + counter_key(self.path))

    def _serve(self):
        if self.path == "/__readyz":
            self._write(200, b"ok", "text/plain")
            return
        self._record()
        delay = read_int("delay-ms")
        if delay:
            time.sleep(delay / 1000.0)
        forced = read_int("error-status")
        if forced:
            self._write(forced, b"forced error from mock-mcp-upstream\n", "text/plain")
            return
        if self.command not in ("GET", "HEAD"):
            self._write(*problem(405, "the official registry mock is read-only"))
            return
        parsed = urllib.parse.urlsplit(self.path)
        status, payload = route(parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        self._write(status, payload)

    do_GET = _serve
    do_HEAD = _serve
    do_POST = _serve
    do_PUT = _serve
    do_PATCH = _serve
    do_DELETE = _serve


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", int(PORT)), Handler).serve_forever()
