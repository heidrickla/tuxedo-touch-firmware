#!/usr/bin/env python3
"""At what INDEX did addSessionItem store the session, and how far does the
reader look?

The record was located by searching for a known session id rather than by
address arithmetic, so its address is trustworthy. The table base comes from the
pointer at guest 0x55b974; the host mapping delta is derived by requiring the
pointer to land in a mapped writable region AND the record we already found to
sit on a 40-byte boundary from it -- two constraints, not one, so a wrong delta
cannot quietly satisfy it.

getCSRFToken1 scans i = 1..getNoOfUsers(). If the record's index exceeds the
number of web accounts, the reader structurally cannot see it.

    sudo python3 slotindex.py <qemu-pid> <record-host-addr-hex>
"""
import re
import struct
import sys

pid = int(sys.argv[1])
rec = int(sys.argv[2], 16)
PTR_VA = 0x55B974

regions = []
for line in open("/proc/%d/maps" % pid, encoding="utf-8"):
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S{4})", line)
    if m:
        regions.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))


def mapped(a, n=4, need_w=False):
    for lo, hi, perms in regions:
        if lo <= a and a + n <= hi and "r" in perms and (not need_w or "w" in perms):
            return True
    return False


mem = open("/proc/%d/mem" % pid, "rb", buffering=0)


def rd(a, n):
    mem.seek(a)
    return mem.read(n)


base = None
for delta in (0x10000, 0x0, 0x20000, -0x10000):
    pa = PTR_VA + delta
    if not mapped(pa):
        continue
    tbl = struct.unpack("<I", rd(pa, 4))[0]
    for tdelta in (delta, 0x10000, 0x0):
        cand = tbl + tdelta
        if not mapped(cand, 40, need_w=True):
            continue
        if (rec - cand) >= 0 and (rec - cand) % 40 == 0:
            base = cand
            print("table base 0x%08x (ptr delta 0x%x, table delta 0x%x)"
                  % (base, delta, tdelta))
            break
    if base:
        break

if base is None:
    print("could not satisfy BOTH constraints; not guessing an index")
    raise SystemExit(2)

idx = (rec - base) // 40
print("the session record is at INDEX %d\n" % idx)

blob = rd(base, 40 * 24)
for i in range(24):
    r = blob[i * 40:(i + 1) * 40]
    sid, flag = struct.unpack_from("<IB", r, 0)
    tok = r[5:].split(b"\x00")[0]
    used = sid != 0xFFFFFFFF
    mark = "  <- OUR SESSION" if i == idx else ""
    if used or i == idx:
        print("  [%2d] id=0x%08x flag=%3d token=%r%s"
              % (i, sid, flag, tok[:26], mark))

print("\ngetCSRFToken1 scans i = 1..getNoOfUsers().")
print("There are 5 web accounts on this unit, so it reads indices 1..5 only.")
print("index %d is %s that range." % (idx, "INSIDE" if 1 <= idx <= 5 else "OUTSIDE"))
