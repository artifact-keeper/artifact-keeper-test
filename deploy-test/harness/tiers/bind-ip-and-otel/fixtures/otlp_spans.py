#!/usr/bin/env python3
"""OTLP/HTTP protobuf trace sink that decodes and records every span (stdlib only).

Used through profiles/telemetry.otlp-spans.yml by bind-ip-and-otel.

POST <any path> with an ExportTraceServiceRequest body (application/x-protobuf,
optionally gzip) -> 200 with an empty body. Each span is appended to
/tmp/otlp/spans.jsonl as one JSON object:
  {"service": <resource service.name>, "trace_id": hex, "span_id": hex,
   "parent_span_id": hex or "", "name": str, "kind": int (1 INTERNAL,
   2 SERVER, 3 CLIENT, ...), "attrs": {key: string|int|bool|float}}
Each POST is appended to /tmp/otlp/posts.log as "<path> <bytes> <spans>".
GET /__readyz -> "ok". The oracle reads both files with `docker exec`.

The decoder is a minimal protobuf wire-format reader covering the fields of
opentelemetry/proto/trace/v1/trace.proto and common/v1/common.proto that the
tier asserts on; unknown fields are skipped.
"""
import gzip
import json
import os
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = "/tmp/otlp"
SPANS = os.path.join(STATE, "spans.jsonl")
POSTS = os.path.join(STATE, "posts.log")
LOCK = threading.Lock()


def varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def fields(buf):
    """Yield (field_number, wire_type, value) for one message."""
    i, n = 0, len(buf)
    while i < n:
        key, i = varint(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(buf, i)
        elif wt == 1:
            v, i = buf[i:i + 8], i + 8
        elif wt == 2:
            ln, i = varint(buf, i)
            v, i = buf[i:i + ln], i + ln
        elif wt == 5:
            v, i = buf[i:i + 4], i + 4
        else:
            raise ValueError("unsupported wire type %d" % wt)
        yield num, wt, v


def any_value(buf):
    for num, wt, v in fields(buf):
        if num == 1:
            return v.decode("utf-8", "replace")
        if num == 2:
            return bool(v)
        if num == 3:
            return v - (1 << 64) if v >= (1 << 63) else v
        if num == 4:
            return struct.unpack("<d", v)[0]
    return None


def key_value(buf):
    k, val = "", None
    for num, wt, v in fields(buf):
        if num == 1:
            k = v.decode("utf-8", "replace")
        elif num == 2:
            val = any_value(v)
    return k, val


def span(buf):
    s = {"trace_id": "", "span_id": "", "parent_span_id": "", "name": "", "kind": 0, "attrs": {}}
    for num, wt, v in fields(buf):
        if num == 1:
            s["trace_id"] = v.hex()
        elif num == 2:
            s["span_id"] = v.hex()
        elif num == 4:
            s["parent_span_id"] = v.hex()
        elif num == 5:
            s["name"] = v.decode("utf-8", "replace")
        elif num == 6:
            s["kind"] = v
        elif num == 9:
            k, val = key_value(v)
            s["attrs"][k] = val
    return s


def decode(body):
    out = []
    for num, wt, rs in fields(body):
        if num != 1:
            continue
        service = ""
        scope_spans = []
        for n2, w2, v2 in fields(rs):
            if n2 == 1:
                for n3, w3, kv in fields(v2):
                    if n3 == 1:
                        k, val = key_value(kv)
                        if k == "service.name":
                            service = val
            elif n2 == 2:
                scope_spans.append(v2)
        for ss in scope_spans:
            for n3, w3, sp in fields(ss):
                if n3 == 2:
                    d = span(sp)
                    d["service"] = service
                    out.append(d)
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=b"", ctype="application/x-protobuf"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        return self._send(404, b"", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if (self.headers.get("Content-Encoding") or "").lower() == "gzip":
            body = gzip.decompress(body)
        try:
            spans = decode(body)
        except Exception as e:  # keep serving; record the failure
            spans = []
            with LOCK:
                with open(POSTS, "a") as f:
                    f.write("%s %d decode-error %s\n" % (self.path, len(body), e))
        with LOCK:
            with open(SPANS, "a") as f:
                for s in spans:
                    f.write(json.dumps(s) + "\n")
            with open(POSTS, "a") as f:
                f.write("%s %d %d\n" % (self.path, len(body), len(spans)))
        self._send(200)


if __name__ == "__main__":
    os.makedirs(STATE, exist_ok=True)
    open(SPANS, "a").close()
    open(POSTS, "a").close()
    ThreadingHTTPServer(("0.0.0.0", 4318), Handler).serve_forever()
