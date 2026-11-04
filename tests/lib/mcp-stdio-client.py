#!/usr/bin/env python3
"""mcp-stdio-client.py - stdlib-only MCP client for the release gate.

Drives an MCP server the way an agent host does and prints one JSON document
on stdout describing what it saw, so a shell test can assert on it with jq.
It never talks to Artifact Keeper: the gate resolves a server from the MCP
registry, installs it from an Artifact Keeper repository, and then hands the
launch command (stdio) or the remote URL (streamable HTTP) to this client.

Transports:

  stdio (default)   spawn COMMAND [ARGS...] after `--`, speak newline-delimited
                    JSON-RPC 2.0 on its stdin/stdout. The child runs in its own
                    process group, which is killed on exit.
  http              POST JSON-RPC to --url (MCP streamable HTTP): sends
                    `Accept: application/json, text/event-stream`, accepts a
                    plain JSON body or an SSE stream, and carries the
                    `Mcp-Session-Id` the server assigns.

Sequence: initialize -> notifications/initialized -> tools/list, then
tools/call for each --call NAME=JSON_ARGS.

Output (stdout):

  {"transport": "stdio", "protocolVersion": "...", "serverInfo": {...},
   "tools": [...], "toolNames": ["echo"], "calls": [{"name": "echo",
   "arguments": {...}, "result": {...}, "text": "..."}]}

Exit codes: 0 every step answered; 2 usage error; 3 the server did not answer
in time; 4 the server answered a step with a JSON-RPC error; 5 transport
failure (spawn failed, connection refused, malformed response).

Every request carries `User-Agent: ak-e2e-mcp-client/1` (http transport) so a
test can tell its own requests from anyone else's in a mock server's log.
"""

import argparse
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request

CLIENT_INFO = {"name": "ak-e2e-mcp-client", "version": "1"}
USER_AGENT = "ak-e2e-mcp-client/1"
DEFAULT_PROTOCOL = "2025-06-18"


class StepTimeout(Exception):
    pass


class RpcError(Exception):
    pass


class TransportError(Exception):
    pass


class StdioTransport:
    def __init__(self, argv, timeout, env=None):
        self.timeout = timeout
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=env,
            )
        except OSError as exc:
            raise TransportError("spawn failed: %s" % exc) from exc
        self.lines = queue.Queue()
        self.stderr_lines = []
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self):
        for raw in iter(self.proc.stdout.readline, b""):
            self.lines.put(raw)
        self.lines.put(None)

    def _pump_stderr(self):
        for raw in iter(self.proc.stderr.readline, b""):
            self.stderr_lines.append(raw.decode("utf-8", "replace").rstrip("\n"))

    def send(self, message):
        data = (json.dumps(message) + "\n").encode("utf-8")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError("server closed stdin: %s" % exc) from exc

    def request(self, message):
        self.send(message)
        want = message["id"]
        while True:
            try:
                raw = self.lines.get(timeout=self.timeout)
            except queue.Empty as exc:
                raise StepTimeout("no answer to %s within %ss" % (message["method"], self.timeout)) from exc
            if raw is None:
                raise TransportError("server exited before answering %s" % message["method"])
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                reply = json.loads(text)
            except ValueError as exc:
                raise TransportError("server wrote non-JSON to stdout: %r" % text[:200]) from exc
            if isinstance(reply, dict) and reply.get("id") == want:
                return reply
            # A notification or a server-initiated request: not ours, skip it.

    def notify(self, message):
        self.send(message)

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            self.proc.wait()


class HttpTransport:
    def __init__(self, url, timeout, headers):
        self.url = url
        self.timeout = timeout
        self.session = None
        self.protocol = None
        self.extra = headers

    def _post(self, message, expect_reply):
        body = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("User-Agent", USER_AGENT)
        if self.session:
            req.add_header("Mcp-Session-Id", self.session)
        if self.protocol:
            req.add_header("MCP-Protocol-Version", self.protocol)
        for key, value in self.extra:
            req.add_header(key, value)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            raise TransportError("HTTP %s from %s" % (exc.code, self.url)) from exc
        except (urllib.error.URLError, OSError) as exc:
            if "timed out" in str(exc):
                raise StepTimeout("no answer to %s within %ss" % (message.get("method"), self.timeout)) from exc
            raise TransportError("connection to %s failed: %s" % (self.url, exc)) from exc
        with resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self.session = sid
            if not expect_reply:
                return None
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            raw = resp.read().decode("utf-8", "replace")
        if ctype == "text/event-stream":
            return self._from_sse(raw, message["id"])
        try:
            reply = json.loads(raw)
        except ValueError as exc:
            raise TransportError("non-JSON response: %r" % raw[:200]) from exc
        if isinstance(reply, list):
            for item in reply:
                if isinstance(item, dict) and item.get("id") == message["id"]:
                    return item
            raise TransportError("batch response without id %s" % message["id"])
        return reply

    @staticmethod
    def _from_sse(raw, want):
        data = []
        for line in raw.splitlines() + [""]:
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif line == "" and data:
                try:
                    event = json.loads("\n".join(data))
                except ValueError:
                    event = None
                data = []
                if isinstance(event, dict) and event.get("id") == want:
                    return event
        raise TransportError("SSE stream ended without a response to id %s" % want)

    def request(self, message):
        return self._post(message, True)

    def notify(self, message):
        self._post(message, False)

    def close(self):
        pass


def parse_call(spec):
    name, sep, args = spec.partition("=")
    if not name:
        raise argparse.ArgumentTypeError("--call wants NAME or NAME=JSON")
    if not sep:
        return name, {}
    try:
        parsed = json.loads(args)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--call %s: arguments are not JSON" % name) from exc
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("--call %s: arguments must be a JSON object" % name)
    return name, parsed


def checked(reply, step):
    if "error" in reply:
        raise RpcError("%s answered error %s" % (step, json.dumps(reply["error"])))
    if "result" not in reply:
        raise TransportError("%s answered without result" % step)
    return reply["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--url", help="streamable HTTP endpoint (http transport)")
    parser.add_argument("--header", action="append", default=[], help="extra HTTP header, NAME: VALUE")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-step timeout in seconds")
    parser.add_argument("--protocol-version", default=DEFAULT_PROTOCOL)
    parser.add_argument("--call", action="append", type=parse_call, default=[], metavar="NAME=JSON")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE", help="extra env for the stdio child")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...] (stdio transport)")
    opts = parser.parse_args()

    command = opts.command
    if command and command[0] == "--":
        command = command[1:]
    if opts.transport == "stdio" and not command:
        parser.error("stdio transport needs -- COMMAND [ARGS...]")
    if opts.transport == "http" and not opts.url:
        parser.error("http transport needs --url")

    headers = []
    for item in opts.header:
        key, sep, value = item.partition(":")
        if not sep:
            parser.error("--header wants NAME: VALUE")
        headers.append((key.strip(), value.strip()))

    out = {"transport": opts.transport}
    transport = None
    code = 0
    try:
        if opts.transport == "stdio":
            env = dict(os.environ)
            for item in opts.env:
                key, _, value = item.partition("=")
                env[key] = value
            transport = StdioTransport(command, opts.timeout, env)
        else:
            transport = HttpTransport(opts.url, opts.timeout, headers)

        init = checked(
            transport.request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": opts.protocol_version,
                        "capabilities": {},
                        "clientInfo": CLIENT_INFO,
                    },
                }
            ),
            "initialize",
        )
        out["protocolVersion"] = init.get("protocolVersion")
        out["serverInfo"] = init.get("serverInfo")
        out["instructions"] = init.get("instructions")
        if isinstance(transport, HttpTransport):
            transport.protocol = init.get("protocolVersion")
        transport.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})

        listed = checked(transport.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}), "tools/list")
        tools = listed.get("tools") or []
        out["tools"] = tools
        out["toolNames"] = [t.get("name") for t in tools if isinstance(t, dict)]

        calls = []
        for offset, (name, arguments) in enumerate(opts.call):
            res = checked(
                transport.request(
                    {
                        "jsonrpc": "2.0",
                        "id": 10 + offset,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments},
                    }
                ),
                "tools/call %s" % name,
            )
            text = "".join(
                c.get("text", "") for c in (res.get("content") or []) if isinstance(c, dict) and c.get("type") == "text"
            )
            calls.append({"name": name, "arguments": arguments, "result": res, "text": text})
        out["calls"] = calls
        if isinstance(transport, HttpTransport):
            out["sessionId"] = transport.session
    except StepTimeout as exc:
        out["error"] = str(exc)
        code = 3
    except RpcError as exc:
        out["error"] = str(exc)
        code = 4
    except TransportError as exc:
        out["error"] = str(exc)
        code = 5
    finally:
        if transport is not None:
            transport.close()
            if isinstance(transport, StdioTransport) and transport.stderr_lines:
                out["stderr"] = transport.stderr_lines[-20:]
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
