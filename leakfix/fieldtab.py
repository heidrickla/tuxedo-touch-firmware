#!/usr/bin/env python3
"""Dump the WNMP module's field table -- the URL segments under /system_http_api.

WnmpDir_resolveLocation walks the request path one '/'-separated segment at a time
and matches each against this table (`puVar5 += 6` ushorts, so 12-byte records, with
a char* name at offset 4 and a 12-bit id masked with 0xfff). The names in here ARE
the URL, which is why finding it answers "which URL reaches serviceField".

Table address comes from Test1Module_constructor, which passes it as r1 to
WnmpModule_constructor, where it lands at module+4 -- the field resolveLocation reads.

Usage: fieldtab.py <binary> 0x8ab10 [count]
"""
import struct
import sys

TEXT_BIAS = 0x8000


def cstr(buf, va, limit=64):
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
    table = int(sys.argv[2], 16)
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    buf = open(path, "rb").read()

    print("%-6s %-8s %-8s %-8s %s" % ("#", "id", "parent", "extra", "name"))
    off = table - TEXT_BIAS
    shown = 0
    for i in range(count):
        rec = buf[off + i * 12: off + i * 12 + 12]
        if len(rec) < 12:
            break
        a, b, nameptr, extra = struct.unpack("<HHII", rec)
        if (a & 0xFFF) == 0:
            print("  -- terminator at record %d (id low 12 bits = 0) --" % i)
            break
        name = cstr(buf, nameptr)
        if name is None:
            print("  -- record %d: name ptr 0x%x does not resolve; stopping --"
                  % (i, nameptr))
            break
        print("%-6d 0x%-6x 0x%-6x 0x%-6x %s" % (i, a & 0xFFF, b & 0xFFF, extra, name))
        shown += 1
    print()
    print("%d field(s). Each name is one path segment under /system_http_api/." % shown)


if __name__ == "__main__":
    main()
