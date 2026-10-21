#!/usr/bin/env python3
"""Stdlib-only multi-format upstream for the virtual-member DTF tiers.

One server stands in for every Remote member the virtual-member tiers
(virtual-member-failure-policy, virtual-member-metadata-timeout,
npm-virtual-isolate-disttag-feed, nuget-protocol-translation) put behind a
virtual repository. The first path segment picks how the "upstream" behaves,
so one container serves healthy, failing and blackholed members at once:

  /ok/...  /ok2/...   healthy; documents name the mode (`ok` / `ok2`) so a
                      merge of two healthy members is visible in the output
  /fail/...           every request answers 500
  /hang/...           the request is accepted and never answered (the
                      handler sleeps HANG_SECS), i.e. a blackholed upstream

Under a healthy mode:
  helm/index.yaml                     one chart `dtfhelm-<mode>` 1.0.0
  cran/src/contrib/PACKAGES           one package `dtfcran<mode>` 1.0.0
  gems/specs.4.8.gz (+ latest_, prerelease_)
                                      gzipped Ruby Marshal 4.8, as
                                      rubygems.org serves it:
                                      [["dtfgem-<mode>", Gem::Version("1.0.0"),
                                      "ruby"]] (prerelease: empty array)
  npm/<name>                          packument: <name> 1.0.1 (any name)
  npm/<name>/-/<name>-1.0.1.tgz       its tarball

NuGet feeds (no mode prefix):
  /nuget/v2/api/v2/...      V2 OData feed; index.json -> 404 (the usual
                            "no V3 here" answer)
  /nuget/v2err/api/v2/...   the same feed, but index.json -> 403 (#4327: many
                            V2 servers answer the V3 probe with an error)
  /nuget/v3/...             V3 feed: index.json, paged registration (index
                            links its page, page carries the leaves), flat
                            container, search, autocomplete
  /nuget/v3down/index.json  503 (a V3 feed in a transient outage)
  Every id has versions 1.0.0 and 2.0.0; the .nupkg is a real zip whose
  nuspec description is `dtf-upstream-<feed>`.

  /nuget/v2paged/api/v2/... a V2 feed whose FindPackagesById() is PAGED like
                            nuget.org's V2 API (#4856): page 1 holds 1.0.0
                            and a feed-level <link rel="next"> to
                            `$skiptoken=page-2` (absolute); page 2 holds
                            1.0.0 again, 2.0.0 and 2.1.0 and a RELATIVE next
                            link to page 3; page 3 holds 3.0.0. Other verbs
                            answer as /nuget/v2 does.
  /nuget/v2pagedforeign/api/v2/...
                            the same page 1, but its next link points at
                            this container's FOREIGN_PORT (another origin),
                            which serves the v2paged pages and logs every
                            request as `MOCKMULTI-FOREIGN <METHOD> <path>`.

Every request is printed as `MOCKMULTI <METHOD> <path> <status>` so an oracle
can count, from `docker logs`, which member fetched what. GET /__readyz -> ok.
"""
import datetime
import gzip
import io
import json
import os
import re
import sys
import tarfile
import threading
import time
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
HANG_SECS = int(os.environ.get("HANG_SECS", "180"))
FOREIGN_PORT = int(os.environ.get("FOREIGN_PORT", "8081"))
HEALTHY = ("ok", "ok2")
NUGET_VERSIONS = ("1.0.0", "2.0.0")
# #4856: FindPackagesById() pages of the v2paged feeds, keyed by $skiptoken.
PAGED_VERSIONS = {
    None: ("1.0.0",),
    "page-2": ("1.0.0", "2.0.0", "2.1.0"),
    "page-3": ("3.0.0",),
}


# --- Ruby Marshal 4.8 (mirrors backend formats/rubygems.rs MarshalWriter) ---
class Marshal:
    def __init__(self):
        self.out = bytearray(b"\x04\x08")
        self.symbols = []

    def long(self, n):
        if n == 0:
            self.out.append(0)
        elif 0 < n < 123:
            self.out.append(n + 5)
        elif -123 <= n < 0:
            self.out.append((n - 5) & 0xFF)
        else:
            raw = n.to_bytes(8, "little", signed=True).rstrip(b"\x00")
            self.out.append(len(raw))
            self.out.extend(raw)

    def symbol(self, s):
        if s in self.symbols:
            self.out.append(ord(";"))
            self.long(self.symbols.index(s))
        else:
            self.out.append(ord(":"))
            self.long(len(s))
            self.out.extend(s.encode())
            self.symbols.append(s)

    def string(self, s):
        b = s.encode()
        self.out.extend(b'I"')
        self.long(len(b))
        self.out.extend(b)
        self.long(1)
        self.symbol("E")
        self.out.append(ord("T"))

    def gem_version(self, v):
        self.out.append(ord("U"))
        self.symbol("Gem::Version")
        self.out.append(ord("["))
        self.long(1)
        self.string(v)


def specs_gz(triples):
    m = Marshal()
    m.out.append(ord("["))
    m.long(len(triples))
    for name, version, platform in triples:
        m.out.append(ord("["))
        m.long(3)
        m.string(name)
        m.gem_version(version)
        m.string(platform)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(bytes(m.out))
    return buf.getvalue()


# --- npm -----------------------------------------------------------------
NPM_VER = "1.0.1"


def npm_tarball(name):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fname, data in (
            ("package/package.json", json.dumps({"name": name, "version": NPM_VER}).encode()),
            ("package/index.js", f"module.exports = 'upstream {name}';\n".encode()),
        ):
            info = tarfile.TarInfo(fname)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def npm_packument(name, base):
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    short = name.split("/")[-1]
    return {
        "name": name,
        "dist-tags": {"latest": NPM_VER},
        "time": {"created": ts, "modified": ts, NPM_VER: ts},
        "versions": {
            NPM_VER: {
                "name": name,
                "version": NPM_VER,
                "description": "dtf-upstream",
                "dist": {"tarball": f"{base}/{name}/-/{short}-{NPM_VER}.tgz"},
            }
        },
    }


# --- NuGet ---------------------------------------------------------------
def nupkg(pid, version, feed):
    nuspec = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
        f"<metadata><id>{pid}</id><version>{version}</version><authors>mock</authors>"
        f"<description>dtf-upstream-{feed}</description></metadata></package>\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, data in (
            (f"{pid}.nuspec", nuspec),
            ("lib/net8.0/placeholder.txt", f"dtf-upstream-{feed} {pid} {version}\n"),
        ):
            info = zipfile.ZipInfo(fname, date_time=(2020, 1, 1, 0, 0, 0))
            z.writestr(info, data)
    return buf.getvalue()


def odata_arg(query, key):
    m = re.search(key + r"='([^']*)'", urllib.parse.unquote(query))
    return m.group(1) if m else None


def v2_entry(base, pid, version, feed):
    return (
        "<entry>"
        f"<id>{base}/Packages(Id='{pid}',Version='{version}')</id>"
        f'<title type="text">{pid}</title>'
        f'<content type="application/zip" src="{base}/package/{pid}/{version}"/>'
        "<m:properties>"
        f"<d:Id>{pid}</d:Id><d:Version>{version}</d:Version>"
        f"<d:Description>dtf-upstream-{feed}</d:Description><d:Authors>mock</d:Authors>"
        "</m:properties></entry>"
    )


def v2_feed(base, entries, next_href=None):
    link = ""
    if next_href:
        link = '<link rel="next" href="' + next_href.replace("&", "&amp;") + '"/>'
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<feed xml:base="' + base + '" xmlns="http://www.w3.org/2005/Atom" '
        'xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" '
        'xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">'
        '<title type="text">Packages</title>' + "".join(entries) + link + "</feed>"
    )


def paged_find_by_id(base, query, feed, foreign_base=None):
    """One page of a paged FindPackagesById() (#4856), chosen by $skiptoken.

    Page 1 links page 2 absolutely (on `foreign_base` when given, i.e. another
    origin), page 2 links page 3 relatively, page 3 is the last.
    """
    args = urllib.parse.parse_qs(query)
    token = args.get("$skiptoken", [None])[0]
    pid = odata_arg(query, "id") or ""
    if token not in PAGED_VERSIONS or not pid:
        return v2_feed(base, [])
    entries = [v2_entry(base, pid, v, feed) for v in PAGED_VERSIONS[token]]
    verb = f"FindPackagesById()?id='{pid}'"
    if token is None:
        nxt = f"{foreign_base or base}/{verb}&$skiptoken=page-2"
    elif token == "page-2":
        nxt = f"{verb}&$skiptoken=page-3"
    else:
        nxt = None
    return v2_feed(base, entries, nxt)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _log(self, code):
        sys.stdout.write(f"MOCKMULTI {self.command} {self.path} {code}\n")
        sys.stdout.flush()

    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode()
        self._log(code)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, doc):
        self._send(code, "application/json", json.dumps(doc))

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):  # noqa: C901 (one dispatcher, by design)
        host = self.headers.get("Host", "mock")
        origin = f"http://{host}"
        url = urllib.parse.urlsplit(self.path)
        path, query = url.path, url.query
        if path == "/__readyz":
            return self._send(200, "text/plain", "ok")
        parts = path.strip("/").split("/")
        if parts and parts[0] == "nuget":
            return self._nuget(parts[1:], query, origin)
        if not parts or parts[0] not in HEALTHY + ("fail", "hang"):
            return self._send(404, "text/plain", "not found")
        mode, rest = parts[0], parts[1:]
        if mode == "fail":
            return self._send(500, "text/plain", "dtf mock upstream failure")
        if mode == "hang":
            self._log("HANG")
            time.sleep(HANG_SECS)
            return
        if not rest:
            return self._send(404, "text/plain", "not found")
        fmt, sub = rest[0], "/".join(rest[1:])
        if fmt == "helm" and sub == "index.yaml":
            name = f"dtfhelm-{mode}"
            body = (
                "apiVersion: v1\n"
                "entries:\n"
                f"  {name}:\n"
                f"  - apiVersion: v2\n"
                f"    name: {name}\n"
                "    version: 1.0.0\n"
                "    created: \"2026-01-01T00:00:00Z\"\n"
                "    digest: \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
                f"    urls:\n    - {origin}/{mode}/helm/charts/{name}-1.0.0.tgz\n"
                "generated: \"2026-01-01T00:00:00Z\"\n"
            )
            return self._send(200, "application/x-yaml", body)
        if fmt == "cran" and sub == "src/contrib/PACKAGES":
            body = f"Package: dtfcran{mode}\nVersion: 1.0.0\nLicense: MIT\n\n"
            return self._send(200, "text/plain", body)
        if fmt == "gems" and sub in ("specs.4.8.gz", "latest_specs.4.8.gz"):
            return self._send(200, "application/octet-stream",
                              specs_gz([(f"dtfgem-{mode}", "1.0.0", "ruby")]))
        if fmt == "gems" and sub == "prerelease_specs.4.8.gz":
            return self._send(200, "application/octet-stream", specs_gz([]))
        if fmt == "npm" and sub:
            base = f"{origin}/{mode}/npm"
            name = urllib.parse.unquote(sub)
            if "/-/" in name:
                pkg, fname = name.split("/-/", 1)
                if fname == f"{pkg.split('/')[-1]}-{NPM_VER}.tgz":
                    return self._send(200, "application/octet-stream", npm_tarball(pkg))
                return self._send(404, "application/json", '{"error":"not found"}')
            return self._json(200, npm_packument(name, base))
        return self._send(404, "text/plain", "not found")

    def _nuget(self, parts, query, origin):
        if not parts:
            return self._send(404, "text/plain", "not found")
        feed, rest = parts[0], parts[1:]
        if feed in ("v2paged", "v2pagedforeign") and rest[:2] == ["api", "v2"]:
            verb = urllib.parse.unquote("/".join(rest[2:]))
            if verb.lower().startswith("findpackagesbyid()"):
                base = f"{origin}/nuget/{feed}/api/v2"
                foreign = None
                if feed == "v2pagedforeign":
                    host = urllib.parse.urlsplit(origin).hostname
                    foreign = f"http://{host}:{FOREIGN_PORT}/nuget/v2paged/api/v2"
                body = paged_find_by_id(base, query, "v2paged", foreign)
                return self._send(200, "application/atom+xml", body)
            feed = "v2"
        if feed in ("v2", "v2err"):
            if rest[:2] != ["api", "v2"]:
                return self._send(404, "text/plain", "not found")
            sub = rest[2:]
            base = f"{origin}/nuget/{feed}/api/v2"
            if sub == ["index.json"]:
                code = 404 if feed == "v2" else 403
                return self._send(code, "text/plain", "no V3 service index here")
            if sub and sub[0] == "package" and len(sub) == 3:
                return self._send(200, "application/zip", nupkg(sub[1], sub[2], feed))
            verb = urllib.parse.unquote("/".join(sub))
            if verb.lower().startswith("findpackagesbyid()"):
                pid = odata_arg(query, "id") or ""
                entries = [v2_entry(base, pid, v, feed) for v in NUGET_VERSIONS] if pid else []
                return self._send(200, "application/atom+xml", v2_feed(base, entries))
            if verb.startswith("Packages("):
                pid = odata_arg(verb, "Id")
                ver = odata_arg(verb, "Version")
                entries = [v2_entry(base, pid, ver, feed)] if pid and ver in NUGET_VERSIONS else []
                return self._send(200, "application/atom+xml", v2_feed(base, entries))
            if verb.lower().startswith("search()") or verb.lower().startswith("packages()"):
                term = odata_arg(query, "searchTerm") or "dtfnu-search"
                entries = [v2_entry(base, term, "2.0.0", feed)]
                return self._send(200, "application/atom+xml", v2_feed(base, entries))
            return self._send(404, "text/plain", "not found")
        if feed == "v3down":
            return self._send(503, "text/plain", "service unavailable")
        if feed != "v3":
            return self._send(404, "text/plain", "not found")
        base = f"{origin}/nuget/v3"
        reg, flat = f"{base}/registration", f"{base}/flat"
        if rest == ["index.json"]:
            return self._json(200, {
                "version": "3.0.0",
                "resources": [
                    {"@id": f"{reg}/", "@type": "RegistrationsBaseUrl/3.6.0"},
                    {"@id": f"{flat}/", "@type": "PackageBaseAddress/3.0.0"},
                    {"@id": f"{base}/search", "@type": "SearchQueryService"},
                    {"@id": f"{base}/autocomplete", "@type": "SearchAutocompleteService"},
                ],
            })
        if rest[:1] == ["registration"] and len(rest) >= 3:
            pid = rest[1].lower()
            leaves = [{
                "@id": f"{reg}/{pid}/{v}.json",
                "catalogEntry": {"@id": f"{reg}/{pid}/{v}.json", "id": pid, "version": v,
                                 "description": "dtf-upstream-v3", "listed": True,
                                 "packageContent": f"{flat}/{pid}/{v}/{pid}.{v}.nupkg"},
                "packageContent": f"{flat}/{pid}/{v}/{pid}.{v}.nupkg",
                "registration": f"{reg}/{pid}/index.json",
            } for v in NUGET_VERSIONS]
            page_id = f"{reg}/{pid}/page/{NUGET_VERSIONS[0]}/{NUGET_VERSIONS[-1]}.json"
            if rest[2:] == ["index.json"]:
                # Paged like nuget.org for a package with a long history: the
                # index links the page and carries no leaves (#3870).
                return self._json(200, {
                    "@id": f"{reg}/{pid}/index.json", "count": 1,
                    "items": [{"@id": page_id, "count": len(leaves),
                               "lower": NUGET_VERSIONS[0], "upper": NUGET_VERSIONS[-1]}],
                })
            if rest[2:] == ["page", NUGET_VERSIONS[0], f"{NUGET_VERSIONS[-1]}.json"]:
                return self._json(200, {
                    "@id": page_id, "count": len(leaves), "items": leaves,
                    "lower": NUGET_VERSIONS[0], "upper": NUGET_VERSIONS[-1],
                    "parent": f"{reg}/{pid}/index.json",
                })
            return self._send(404, "text/plain", "not found")
        if rest[:1] == ["flat"] and len(rest) == 3 and rest[2] == "index.json":
            return self._json(200, {"versions": list(NUGET_VERSIONS)})
        if rest[:1] == ["flat"] and len(rest) == 4:
            pid, ver, fname = rest[1], rest[2], rest[3]
            if ver in NUGET_VERSIONS and fname == f"{pid}.{ver}.nupkg":
                return self._send(200, "application/octet-stream", nupkg(pid, ver, "v3"))
            return self._send(404, "text/plain", "not found")
        if rest == ["search"]:
            q = urllib.parse.parse_qs(query).get("q", ["dtfnu-search"])[0] or "dtfnu-search"
            return self._json(200, {"totalHits": 1, "data": [{
                "@id": f"{reg}/{q.lower()}/index.json", "@type": "Package",
                "registration": f"{reg}/{q.lower()}/index.json", "id": q,
                "version": NUGET_VERSIONS[-1], "description": "dtf-upstream-v3",
                "versions": [{"version": v, "@id": f"{reg}/{q.lower()}/{v}.json"}
                             for v in NUGET_VERSIONS]}]})
        if rest == ["autocomplete"]:
            q = urllib.parse.parse_qs(query).get("q", [""])[0]
            return self._json(200, {"totalHits": 1, "data": [f"dtfnu-auto-{q or 'any'}"]})
        return self._send(404, "text/plain", "not found")


class ForeignHandler(Handler):
    """The other origin a v2pagedforeign continuation points at (#4856)."""

    def _log(self, code):
        sys.stdout.write(f"MOCKMULTI-FOREIGN {self.command} {self.path} {code}\n")
        sys.stdout.flush()


def main():
    foreign = ThreadingHTTPServer(("0.0.0.0", FOREIGN_PORT), ForeignHandler)
    foreign.daemon_threads = True
    threading.Thread(target=foreign.serve_forever, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == "__main__":
    main()
