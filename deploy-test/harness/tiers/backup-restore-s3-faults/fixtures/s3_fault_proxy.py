#!/usr/bin/env python3
"""HTTP/1.1-aware TCP proxy in front of MinIO, for backup/restore fault tests.

The backend's S3_ENDPOINT points here (PROXY_PORT); every byte is relayed to
UPSTREAM_HOST:UPSTREAM_PORT. The proxy parses each client request line (and
its Content-Length body) so it knows which S3 request a connection is
serving, and an HTTP control endpoint on CONTROL_PORT changes what it does:

  GET /hold?match=<substr>&nth=<n>   hold the n-th GET whose path contains
                                     <substr> (HEAD and multipart calls never
                                     count) before it reaches MinIO
  GET /release                       let a held GET through
  GET /throttle?match=<substr>&bps=<n>
                                     relay the response of every GET whose
                                     path contains <substr> at <n> bytes/s
  GET /reset                         clear hold, release and throttle
  GET /state                         JSON: held, gets per match, throttled
                                     GETs per path, log tail
  GET /__readyz                      "ok"

Server-to-client bytes of other requests pass through untouched.
"""
import asyncio
import json
import os
import re
import time
import urllib.parse

PROXY_PORT = int(os.environ.get("PROXY_PORT", "9100"))
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "9101"))
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "minio")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "9000"))

STATE = {
    "hold": None,  # (match, nth)
    "held": False,
    "released": asyncio.Event,  # replaced by an instance in main()
    "throttle": None,  # (match, bytes_per_second)
    "gets": {},  # match -> GETs seen
    "throttled": {},  # path -> throttled GETs (Range retries included)
    "log": [],
}


def log(msg):
    STATE["log"].append(f"{time.strftime('%H:%M:%S')} {msg}")
    del STATE["log"][:-200]


def is_object_get(method, target):
    return method == "GET" and "uploads" not in target and "uploadId=" not in target


async def maybe_hold(method, target):
    hold = STATE["hold"]
    if not hold or not is_object_get(method, target) or hold[0] not in target:
        return
    n = STATE["gets"].get(hold[0], 0) + 1
    STATE["gets"][hold[0]] = n
    log(f"GET #{n} of {hold[0]}")
    if n != hold[1]:
        return
    STATE["held"] = True
    log("HOLDING")
    await STATE["released"].wait()
    STATE["held"] = False
    log("RELEASED")


async def pipe_down(reader, writer, conn):
    """Server -> client, throttled while the connection serves a matching GET."""
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            bps = conn.get("bps")
            if bps:
                await asyncio.sleep(len(data) / bps)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def pipe_up(creader, uwriter, conn):
    """Client -> server, request by request."""
    try:
        while True:
            head = await creader.readuntil(b"\r\n\r\n")
            line = head.split(b"\r\n", 1)[0].decode("latin1")
            method, target = (line.split(" ") + ["", ""])[:2]
            m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
            clen = int(m.group(1)) if m else 0
            chunked = re.search(rb"(?im)^transfer-encoding:\s*chunked", head)
            throttle = STATE["throttle"]
            conn["bps"] = (
                throttle[1]
                if throttle and is_object_get(method, target) and throttle[0] in target
                else None
            )
            if conn["bps"]:
                path = target.split("?", 1)[0]
                STATE["throttled"][path] = STATE["throttled"].get(path, 0) + 1
                ranged = bool(re.search(rb"(?im)^range:", head))
                log(f"throttled GET {path[-48:]} #{STATE['throttled'][path]} range={ranged}")
            await maybe_hold(method, target)
            uwriter.write(head)
            if chunked:
                while True:
                    data = await creader.read(65536)
                    if not data:
                        return
                    uwriter.write(data)
                    await uwriter.drain()
            remaining = clen
            while remaining:
                data = await creader.read(min(65536, remaining))
                if not data:
                    return
                uwriter.write(data)
                await uwriter.drain()
                remaining -= len(data)
            await uwriter.drain()
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        try:
            uwriter.close()
        except Exception:
            pass


async def handle(creader, cwriter):
    try:
        ureader, uwriter = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT)
    except OSError:
        cwriter.close()
        return
    conn = {"bps": None}
    down = asyncio.ensure_future(pipe_down(ureader, cwriter, conn))
    await pipe_up(creader, uwriter, conn)
    await down


async def control(reader, writer):
    try:
        head = await reader.readuntil(b"\r\n\r\n")
        target = head.split(b"\r\n", 1)[0].decode("latin1").split(" ")[1]
        url = urllib.parse.urlsplit(target)
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/hold":
            STATE["hold"] = (q["match"], int(q.get("nth", "1")))
            STATE["gets"].pop(q["match"], None)
            STATE["released"].clear()
            out = "ok"
        elif url.path == "/release":
            STATE["released"].set()
            out = "ok"
        elif url.path == "/throttle":
            STATE["throttle"] = (q["match"], int(q["bps"]))
            out = "ok"
        elif url.path == "/reset":
            STATE["hold"] = None
            STATE["throttle"] = None
            STATE["gets"] = {}
            STATE["throttled"] = {}
            STATE["released"].set()
            out = "ok"
        elif url.path == "/state":
            out = json.dumps(
                {
                    "held": STATE["held"],
                    "gets": STATE["gets"],
                    "throttled": STATE["throttled"],
                    "log": STATE["log"][-40:],
                }
            )
        else:
            out = "ok"
        body = out.encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
            + body
        )
        await writer.drain()
    except Exception as e:  # noqa: BLE001 - a bad control call must not kill the proxy
        log(f"control error: {e}")
    finally:
        writer.close()


async def main():
    STATE["released"] = asyncio.Event()
    STATE["released"].set()
    proxy = await asyncio.start_server(handle, "0.0.0.0", PROXY_PORT)
    ctl = await asyncio.start_server(control, "0.0.0.0", CONTROL_PORT)
    log(f"proxy :{PROXY_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}, control :{CONTROL_PORT}")
    async with proxy, ctl:
        await asyncio.gather(proxy.serve_forever(), ctl.serve_forever())


asyncio.run(main())
