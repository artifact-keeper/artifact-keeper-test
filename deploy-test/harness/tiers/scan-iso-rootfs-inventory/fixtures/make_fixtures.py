#!/usr/bin/env python3
"""Build the scan-iso-rootfs-inventory fixtures at run time, stdlib only.

Writes into OUT_DIR:
  live.iso     an ISO9660 live medium (Rock Ridge, level 1 names, hybrid MBR
               signature) holding live/filesystem.squashfs, a squashfs 4.0
               rootfs with etc/os-release (Debian 12) and var/lib/dpkg/status
               naming openssl 3.0.11-1~deb12u2, which is vulnerable on
               Debian 12 in the backend image's seeded Grype DB.
  corrupt.iso  the same medium with the squashfs inode table overwritten:
               the squashfs magic and superblock are intact, the tables are
               not, so no package database can be read from it.

Neither xorriso nor squashfs-tools is needed on the runner: the gate runners
do not install them. The squashfs is written with every block stored
uncompressed (the per-block "uncompressed" bits), which every unsquashfs
reads; the ISO is laid out the way `xorriso -as mkisofs -R` lays out a
default level 1 image (8.3 identifier, real name in the Rock Ridge NM entry).

Usage: make_fixtures.py OUT_DIR SUFFIX   (SUFFIX keeps per-run bytes unique,
so hash-based scan reuse never hands a run another run's verdict)
"""
import os
import struct
import sys

# --------------------------------------------------------------------------
# squashfs 4.0
# --------------------------------------------------------------------------
BLOCK_SIZE = 131072
BLOCK_LOG = 17
META_UNCOMPRESSED = 0x8000
DATA_UNCOMPRESSED = 1 << 24
INVALID = 0xFFFFFFFFFFFFFFFF
# UNCOMPRESSED_INODES | UNCOMPRESSED_DATA | UNCOMPRESSED_FRAGMENTS |
# NO_FRAGMENTS | NO_XATTRS | UNCOMPRESSED_IDS
FLAGS = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0200 | 0x0800
GZIP = 1
DIR_T, FILE_T = 1, 2
MTIME = 1_700_000_000


def meta_block(payload):
    assert len(payload) <= 8192
    return struct.pack("<H", META_UNCOMPRESSED | len(payload)) + payload


def build_squashfs(files):
    """files: {"etc/os-release": b"...", ...}; directories are implied."""
    # Tree of directories -> children.
    tree = {"": {}}
    for path in files:
        parts = path.split("/")
        for i in range(1, len(parts)):
            d = "/".join(parts[:i])
            tree.setdefault(d, {})
        for i in range(1, len(parts) + 1):
            parent = "/".join(parts[: i - 1])
            tree.setdefault(parent, {})
            tree[parent][parts[i - 1]] = "/".join(parts[:i])

    # Inode numbers: files first, then directories deepest first, root last
    # (the order mksquashfs uses: a directory's children are numbered first).
    dirs = sorted(tree, key=lambda d: (-d.count("/") if d else 1, d))
    dirs = [d for d in dirs if d] + [""]
    numbers = {}
    n = 1
    for f in sorted(files):
        numbers[f] = n
        n += 1
    for d in dirs:
        numbers[d] = n
        n += 1
    inode_count = n - 1

    out = bytearray(96)  # superblock written last
    data_start = {}
    for f in sorted(files):
        data_start[f] = len(out)
        out += files[f]
        assert len(files[f]) < BLOCK_SIZE

    # Inode table: one metadata block holds every inode (tiny tree).
    inodes = bytearray()
    inode_off = {}

    def header(itype, num):
        return struct.pack("<HHHHII", itype, 0o755 if itype == DIR_T else 0o644, 0, 0, MTIME, num)

    for f in sorted(files):
        inode_off[f] = len(inodes)
        size = len(files[f])
        inodes += header(FILE_T, numbers[f])
        inodes += struct.pack("<IIII", data_start[f], 0xFFFFFFFF, 0, size)
        inodes += struct.pack("<I", size | DATA_UNCOMPRESSED)

    # Directory table: one metadata block, one listing per directory.
    listings = bytearray()
    listing_at = {}
    listing_len = {}
    # Directory inodes reference listings, so build listings first; their
    # contents reference child inode offsets, which need the directory inodes
    # placed. Directories are numbered after files and placed in `dirs` order.
    dir_inode_size = 16 + 16  # header + basic dir body
    off = len(inodes)
    for d in dirs:
        inode_off[d] = off
        off += dir_inode_size
    for d in dirs:
        children = sorted(tree[d].items())
        listing_at[d] = len(listings)
        body = bytearray()
        if children:
            base = min(numbers[c] for _, c in children)
            body += struct.pack("<III", len(children) - 1, 0, base)
            for name, child in children:
                itype = DIR_T if child in tree else FILE_T
                nb = name.encode()
                body += struct.pack("<HhHH", inode_off[child], numbers[child] - base, itype, len(nb) - 1)
                body += nb
        listings += body
        listing_len[d] = len(body)
    assert len(listings) <= 8192

    for d in dirs:
        parent = d.rsplit("/", 1)[0] if "/" in d else ""
        parent_num = inode_count + 1 if d == "" else numbers[parent]
        nlink = 2 + sum(1 for c in tree[d].values() if c in tree)
        inodes += header(DIR_T, numbers[d])
        inodes += struct.pack("<IIHHI", 0, nlink, listing_len[d] + 3, listing_at[d], parent_num)
    assert len(inodes) <= 8192

    inode_table_start = len(out)
    out += meta_block(bytes(inodes))
    directory_table_start = len(out)
    out += meta_block(bytes(listings))
    id_meta = len(out)
    out += meta_block(struct.pack("<I", 0))
    id_table_start = len(out)
    out += struct.pack("<Q", id_meta)
    bytes_used = len(out)

    root_ref = (0 << 16) | inode_off[""]
    sb = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        0x73717368, inode_count, MTIME, BLOCK_SIZE, 0, GZIP, BLOCK_LOG, FLAGS,
        1, 4, 0, root_ref, bytes_used, id_table_start, INVALID,
        inode_table_start, directory_table_start, id_meta, INVALID,
    )
    assert len(sb) == 96
    out[0:96] = sb
    # mksquashfs pads to 4 KiB; unsquashfs does not need it, but keep the
    # usual shape.
    out += b"\0" * (-len(out) % 4096)
    return bytes(out), inode_table_start


# --------------------------------------------------------------------------
# ISO9660 with Rock Ridge
# --------------------------------------------------------------------------
SECTOR = 2048


def both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


def both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def record(lba, size, flags, name, su=b""):
    pad = 1 if len(name) % 2 == 0 else 0
    length = 33 + len(name) + pad + len(su)
    assert length <= 255
    r = bytearray(length)
    r[0] = length
    r[2:10] = both32(lba)
    r[10:18] = both32(size)
    r[18:25] = bytes([123, 1, 1, 0, 0, 0, 0])
    r[25] = flags
    r[28:32] = both16(1)
    r[32] = len(name)
    r[33 : 33 + len(name)] = name
    r[33 + len(name) + pad :] = su
    return bytes(r)


def nm(name):
    return b"NM" + bytes([5 + len(name), 1, 0]) + name


SP = b"SP" + bytes([7, 1, 0xBE, 0xEF, 0])


def er():
    """The Extensions Reference entry naming RRIP, which readers such as
    the Linux kernel and xorriso look for before they trust NM names."""
    ident, desc, src = b"RRIP_1991A", b"ROCK RIDGE", b"DTF"
    return b"ER" + bytes([8 + len(ident) + len(desc) + len(src), 1, len(ident), len(desc), len(src), 1]) + ident + desc + src


def build_iso(dir_name, file_name, payload, volume_id):
    root_lba, dir_lba, data_lba = 18, 19, 20
    sectors = data_lba + (len(payload) + SECTOR - 1) // SECTOR
    img = bytearray(sectors * SECTOR)
    img[0x1FE:0x200] = b"\x55\xaa"  # hybrid: an MBR signature at offset 0

    iso_dir = dir_name.upper()[:8].encode()
    stem, ext = file_name.upper().split(".", 1)
    iso_file = ("%s.%s;1" % (stem[:8], ext[:3])).encode()

    pvd = bytearray(SECTOR)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = b" " * 32
    pvd[40:72] = volume_id.encode().ljust(32)[:32]
    pvd[80:88] = both32(sectors)
    pvd[120:124] = both16(1)
    pvd[124:128] = both16(1)
    pvd[128:132] = both16(SECTOR)
    pvd[156:190] = record(root_lba, SECTOR, 2, b"\x00")
    pvd[881] = 1
    img[16 * SECTOR : 17 * SECTOR] = pvd
    term = bytearray(SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    img[17 * SECTOR : 18 * SECTOR] = term

    root = record(root_lba, SECTOR, 2, b"\x00", SP + er()) + record(root_lba, SECTOR, 2, b"\x01")
    root += record(dir_lba, SECTOR, 2, iso_dir, nm(dir_name.encode()))
    img[root_lba * SECTOR : root_lba * SECTOR + len(root)] = root

    d = record(dir_lba, SECTOR, 2, b"\x00") + record(root_lba, SECTOR, 2, b"\x01")
    d += record(data_lba, len(payload), 0, iso_file, nm(file_name.encode()))
    img[dir_lba * SECTOR : dir_lba * SECTOR + len(d)] = d

    img[data_lba * SECTOR : data_lba * SECTOR + len(payload)] = payload
    return bytes(img)


def main():
    out_dir, suffix = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    os_release = (
        b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        b'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\n'
        b"VERSION_CODENAME=bookworm\nID=debian\n"
    )
    status = (
        b"Package: openssl\nStatus: install ok installed\nPriority: optional\n"
        b"Section: utils\nInstalled-Size: 2300\nMaintainer: Debian OpenSSL Team\n"
        b"Architecture: amd64\nVersion: 3.0.11-1~deb12u2\n"
        b"Description: Secure Sockets Layer toolkit - cryptographic utility\n\n"
    )
    files = {
        "etc/os-release": os_release,
        "etc/debian_version": b"12.7\n",
        "var/lib/dpkg/status": status,
        # Per-run bytes: a unique file outside the package database.
        "etc/dtf-run": ("dtf iso fixture %s\n" % suffix).encode(),
    }
    squashfs, inode_table_start = build_squashfs(files)

    live = build_iso("live", "filesystem.squashfs", squashfs, "DTFLIVE")
    with open(os.path.join(out_dir, "live.iso"), "wb") as fh:
        fh.write(live)

    broken = bytearray(squashfs)
    for i in range(inode_table_start, len(broken)):
        broken[i] = 0xA5
    corrupt = build_iso("live", "filesystem.squashfs", bytes(broken), "DTFBROKEN")
    with open(os.path.join(out_dir, "corrupt.iso"), "wb") as fh:
        fh.write(corrupt)
    print('{"live": %d, "corrupt": %d}' % (len(live), len(corrupt)))


if __name__ == "__main__":
    main()
