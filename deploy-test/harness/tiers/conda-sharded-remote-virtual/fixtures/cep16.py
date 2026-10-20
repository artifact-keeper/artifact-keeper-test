#!/usr/bin/env python3
# =============================================================================
# cep16.py: CEP-16 (sharded conda repodata) codec for the DTF conda shard tiers
# =============================================================================
# Stdlib only. Needs Python 3.14 or newer for `compression.zstd`; the tiers run
# it inside the python:3.14-slim mock container (`docker exec`) or a throwaway
# python:3.14-slim container, never on the host, so the host's Python version
# does not matter.
#
# As a library (imported by mock_conda_sharded.py): `packb` encodes the msgpack
# subset a CEP-16 document needs (dict, list, str, bytes, int, bool, None) and
# `zstd_frame` wraps it in a zstd frame.
#
# As a CLI it decodes one `.msgpack.zst` document read from stdin and prints a
# JSON report on stdout:
#
#   {"sha256": "<hex of the raw bytes read>", "size": <n>,
#    "doc": <the decoded document>}            or  {"error": "<why>", ...}
#
# In "doc" every msgpack `bin` value becomes {"bin": "<hex>", "len": <n>} and
# every `str` stays a JSON string, so an oracle can tell a 32-byte binary
# digest (what CEP-16 and rattler require) apart from a 64-character hex
# STRING (what artifact-keeper served before #4555/#4173) with jq alone.
# =============================================================================
import hashlib
import json
import struct
import sys

try:
    from compression import zstd as _zstd  # Python 3.14+
except ImportError:  # pragma: no cover - the tiers always run 3.14
    _zstd = None


# --- msgpack encode ----------------------------------------------------------
def packb(obj):
    out = bytearray()
    _pack(obj, out)
    return bytes(out)


def _pack(obj, out):
    if obj is None:
        out.append(0xC0)
    elif obj is True:
        out.append(0xC3)
    elif obj is False:
        out.append(0xC2)
    elif isinstance(obj, int):
        if 0 <= obj <= 0x7F:
            out.append(obj)
        elif -32 <= obj < 0:
            out.append(obj & 0xFF)
        elif 0 <= obj <= 0xFFFFFFFF:
            out += b"\xce" + struct.pack(">I", obj)
        elif 0 <= obj <= 0xFFFFFFFFFFFFFFFF:
            out += b"\xcf" + struct.pack(">Q", obj)
        else:
            out += b"\xd3" + struct.pack(">q", obj)
    elif isinstance(obj, str):
        raw = obj.encode()
        n = len(raw)
        if n <= 31:
            out.append(0xA0 | n)
        elif n <= 0xFF:
            out += b"\xd9" + bytes([n])
        elif n <= 0xFFFF:
            out += b"\xda" + struct.pack(">H", n)
        else:
            out += b"\xdb" + struct.pack(">I", n)
        out += raw
    elif isinstance(obj, (bytes, bytearray)):
        n = len(obj)
        if n <= 0xFF:
            out += b"\xc4" + bytes([n])
        elif n <= 0xFFFF:
            out += b"\xc5" + struct.pack(">H", n)
        else:
            out += b"\xc6" + struct.pack(">I", n)
        out += obj
    elif isinstance(obj, (list, tuple)):
        n = len(obj)
        if n <= 15:
            out.append(0x90 | n)
        elif n <= 0xFFFF:
            out += b"\xdc" + struct.pack(">H", n)
        else:
            out += b"\xdd" + struct.pack(">I", n)
        for item in obj:
            _pack(item, out)
    elif isinstance(obj, dict):
        out += map_header(len(obj))
        for key, value in obj.items():
            _pack(key, out)
            _pack(value, out)
    else:
        raise TypeError(f"cannot msgpack {type(obj).__name__}")


def map_header(n):
    if n <= 15:
        return bytes([0x80 | n])
    if n <= 0xFFFF:
        return b"\xde" + struct.pack(">H", n)
    return b"\xdf" + struct.pack(">I", n)


def zstd_frame(data, level=3):
    if _zstd is None:
        raise RuntimeError("compression.zstd needs Python 3.14+")
    return _zstd.compress(data, level=level)


# --- msgpack decode ----------------------------------------------------------
class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated msgpack")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def uint(self, n):
        return int.from_bytes(self.take(n), "big")


def _bin(raw):
    return {"bin": raw.hex(), "len": len(raw)}


def _key(value):
    # JSON object keys must be strings; a bin key is reported by its hex.
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "bin" in value:
        return "bin:" + value["bin"]
    return json.dumps(value)


def _unpack(r, depth=0):
    if depth > 64:
        raise ValueError("msgpack nests too deep")
    m = r.uint(1)
    if m <= 0x7F:
        return m
    if m >= 0xE0:
        return m - 0x100
    if 0x80 <= m <= 0x8F:
        return _map(r, m & 0x0F, depth)
    if 0x90 <= m <= 0x9F:
        return [_unpack(r, depth + 1) for _ in range(m & 0x0F)]
    if 0xA0 <= m <= 0xBF:
        return r.take(m & 0x1F).decode("utf-8", "replace")
    if m == 0xC0:
        return None
    if m == 0xC2:
        return False
    if m == 0xC3:
        return True
    if m in (0xC4, 0xC5, 0xC6):
        return _bin(r.take(r.uint({0xC4: 1, 0xC5: 2, 0xC6: 4}[m])))
    if m in (0xC7, 0xC8, 0xC9):
        n = r.uint({0xC7: 1, 0xC8: 2, 0xC9: 4}[m])
        ext_type = r.uint(1)
        return {"$ext": ext_type, "data": r.take(n).hex()}
    if m == 0xCA:
        return struct.unpack(">f", r.take(4))[0]
    if m == 0xCB:
        return struct.unpack(">d", r.take(8))[0]
    if m in (0xCC, 0xCD, 0xCE, 0xCF):
        return r.uint({0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}[m])
    if m in (0xD0, 0xD1, 0xD2, 0xD3):
        n = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}[m]
        return int.from_bytes(r.take(n), "big", signed=True)
    if m in (0xD4, 0xD5, 0xD6, 0xD7, 0xD8):
        n = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}[m]
        ext_type = r.uint(1)
        return {"$ext": ext_type, "data": r.take(n).hex()}
    if m in (0xD9, 0xDA, 0xDB):
        return r.take(r.uint({0xD9: 1, 0xDA: 2, 0xDB: 4}[m])).decode("utf-8", "replace")
    if m in (0xDC, 0xDD):
        n = r.uint({0xDC: 2, 0xDD: 4}[m])
        return [_unpack(r, depth + 1) for _ in range(n)]
    if m in (0xDE, 0xDF):
        return _map(r, r.uint({0xDE: 2, 0xDF: 4}[m]), depth)
    raise ValueError(f"msgpack marker 0x{m:02x} is never used")


def _map(r, n, depth):
    out = {}
    for _ in range(n):
        k = _unpack(r, depth + 1)
        out[_key(k)] = _unpack(r, depth + 1)
    return out


def unpackb(data):
    r = _Reader(data)
    value = _unpack(r)
    if r.pos != len(data):
        raise ValueError(f"{len(data) - r.pos} trailing bytes after the msgpack value")
    return value


def main():
    raw = sys.stdin.buffer.read()
    report = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    try:
        if _zstd is None:
            raise RuntimeError("compression.zstd needs Python 3.14+")
        plain = _zstd.decompress(raw)
        report["doc"] = unpackb(plain)
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["head"] = raw[:120].decode("utf-8", "replace")
    json.dump(report, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
