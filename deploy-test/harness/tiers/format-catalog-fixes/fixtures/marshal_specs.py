#!/usr/bin/env python3
"""Decode a RubyGems specs index (specs.4.8.gz / latest_specs.4.8.gz) and print
one "name<TAB>version<TAB>platform" line per entry.

The index is gzip(Marshal.dump([[name, Gem::Version, platform], ...])). This
is a small Marshal 4.8 reader covering what an index uses: arrays, strings
(with or without the encoding ivar), symbols and symlinks, object links, nil,
true/false, fixnums, and Gem::Version as a user-marshalled ('U') or
_dump ('u') object. Anything else exits 2 so a malformed index is visible.

Usage: marshal_specs.py FILE
"""
import gzip
import sys


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0
        self.symbols = []
        self.objects = []

    def byte(self):
        b = self.d[self.i]
        self.i += 1
        return b

    def raw(self, n):
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def fixnum(self):
        c = self.byte()
        if c > 127:
            c -= 256
        if c == 0:
            return 0
        if 5 < c < 128:
            return c - 5
        if -129 < c < -5:
            return c + 5
        if c > 0:
            n = 0
            for k in range(c):
                n |= self.byte() << (8 * k)
            return n
        n = -1
        for k in range(-c):
            n &= ~(0xFF << (8 * k))
            n |= self.byte() << (8 * k)
        return n

    def symbol_body(self):
        s = self.raw(self.fixnum()).decode("utf-8", "replace")
        self.symbols.append(s)
        return s

    def sym(self):
        t = chr(self.byte())
        if t == ":":
            return self.symbol_body()
        if t == ";":
            return self.symbols[self.fixnum()]
        raise ValueError("expected symbol, got %r" % t)

    def value(self):
        t = chr(self.byte())
        if t == "0":
            return None
        if t == "T":
            return True
        if t == "F":
            return False
        if t == "i":
            return self.fixnum()
        if t == ":":
            return self.symbol_body()
        if t == ";":
            return self.symbols[self.fixnum()]
        if t == "@":
            return self.objects[self.fixnum()]
        if t == '"':
            s = self.raw(self.fixnum()).decode("utf-8", "replace")
            self.objects.append(s)
            return s
        if t == "I":
            v = self.value()
            for _ in range(self.fixnum()):
                self.sym()
                self.value()
            return v
        if t == "[":
            arr = []
            self.objects.append(arr)
            for _ in range(self.fixnum()):
                arr.append(self.value())
            return arr
        if t == "U":
            cls = self.sym()
            slot = len(self.objects)
            self.objects.append(None)
            data = self.value()
            if cls == "Gem::Version" and isinstance(data, list) and data:
                data = data[0]
            self.objects[slot] = data
            return data
        if t == "u":
            self.sym()
            s = self.raw(self.fixnum()).decode("utf-8", "replace")
            self.objects.append(s)
            return s
        raise ValueError("unsupported Marshal type %r at %d" % (t, self.i - 1))


def main():
    with open(sys.argv[1], "rb") as f:
        blob = f.read()
    try:
        data = gzip.decompress(blob)
    except OSError:
        data = blob
    if data[:2] != b"\x04\x08":
        print("not a Marshal 4.8 stream", file=sys.stderr)
        sys.exit(2)
    r = Reader(data)
    r.i = 2
    try:
        index = r.value()
    except (ValueError, IndexError) as e:
        print("decode error: %s" % e, file=sys.stderr)
        sys.exit(2)
    if not isinstance(index, list):
        print("index is not an array", file=sys.stderr)
        sys.exit(2)
    for entry in index:
        if isinstance(entry, list) and len(entry) == 3:
            print("%s\t%s\t%s" % tuple(entry))


if __name__ == "__main__":
    main()
