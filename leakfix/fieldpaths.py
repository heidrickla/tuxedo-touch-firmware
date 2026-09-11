#!/usr/bin/env python3
"""Resolve the WNMP field table into full URL paths -- the SERVER's routing surface.

docs/TUXEDO-FINDINGS.md lists endpoints taken from the ZIP of Honeywell's own client
embedded in Barracuda. That is what the vendor's client CALLS. This is what the
server ROUTES: WnmpDir_resolveLocation walks the request path segment by segment
against these records, so an endpoint absent here cannot resolve no matter who calls
it, and one present here is reachable whether or not the client mentions it.

Records are 12 bytes at 0x8ab10: {u16 id, u16 parent, u32 name, u32 help}. Parent 0
is the root, so following parents to the root reconstructs the full path.

Usage: fieldpaths.py <binary> [table-addr]
"""
import struct
import sys

TEXT_BIAS = 0x8000
RECORD = 12


def cstr(buf, va, limit=96):
    off = va - TEXT_BIAS
    if off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\0", off, off + limit)
    if end < 0:
        return None
    try:
        return buf[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def main():
    path = sys.argv[1]
    table = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x8AB10
    buf = open(path, "rb").read()

    byid, order = {}, []
    off = table - TEXT_BIAS
    for i in range(400):
        rec = buf[off + i * RECORD: off + i * RECORD + RECORD]
        if len(rec) < RECORD:
            break
        a, b, nameptr, _help = struct.unpack("<HHII", rec)
        if (a & 0xFFF) == 0:
            break
        name = cstr(buf, nameptr)
        if name is None:
            break
        fid, parent = a & 0xFFF, b & 0xFFF
        byid[fid] = (parent, name)
        order.append(fid)

    def full(fid, depth=0):
        if fid not in byid or depth > 12:
            return []
        parent, name = byid[fid]
        return (full(parent, depth + 1) if parent else []) + [name]

    leaves = {f for f in order} - {p for p, _ in byid.values()}
    print("# server-routed WNMP paths, from the field table at 0x%x" % table)
    print("# %d records, %d leaves\n" % (len(order), len(leaves)))
    for fid in order:
        segs = full(fid)
        mark = "" if fid in leaves else "   (container)"
        print("/system_http_api/%s%s" % ("/".join(segs), mark))


if __name__ == "__main__":
    main()
