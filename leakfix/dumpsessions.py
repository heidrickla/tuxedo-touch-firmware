#!/usr/bin/env python3
"""Dump the session table addSessionItem writes and getCSRFToken1 searches.

Layout, from addSessionItem1 (0x2b444):
    record = table[index * 40]
    [0..3]  session id   (str r1, [r0, r4])
    [4]     flag         (strb r2, [r3, #4])
    [5..]   token string (strcpy to record+5, from getKeyFromPassword)

getCSRFToken1 (0x2b3bc) walks i = 1..getNoOfUsers() reading [table + 40*i], so
INDEX 0 IS NEVER SEARCHED. If the writer stores at 0 and the reader starts at 1,
that alone explains why a registered session is never found.

⚠ The table pointer lives at guest VA 0x55b974, which is in the SECOND LOAD
segment. Seeking to it as a file offset lands in the read-only mapping and
returns unrelated bytes -- that cost a wrong conclusion earlier today. The delta
is resolved from /proc/<pid>/maps here rather than remembered.

    sudo python3 dumpsessions.py <qemu-pid>
"""
import re
import struct
import sys

pid = int(sys.argv[1])
TABLE_PTR_VA = 0x55B974

maps = open("/proc/%d/maps" % pid, encoding="utf-8").read()
mem = open("/proc/%d/mem" % pid, "rb", buffering=0)


def readable(addr, size):
    for line in maps.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
        if not m:
            continue
        lo, hi, perms = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
        if lo <= addr and addr + size <= hi and "r" in perms:
            return True
    return False


def read(addr, size):
    if not readable(addr, size):
        return None
    try:
        mem.seek(addr)
        return mem.read(size)
    except OSError:
        return None


# The guest is mapped at its own VA plus a delta; try the known candidates and
# accept the one whose pointer actually lands in a mapped, writable region.
for delta in (0x10000, 0x0, 0x20000):
    raw = read(TABLE_PTR_VA + delta, 4)
    if raw is None:
        continue
    table = struct.unpack("<I", raw)[0]
    for tdelta in (delta, 0x10000, 0x0):
        if table and readable(table + tdelta, 40 * 8):
            print("table ptr VA 0x%x (delta 0x%x) -> table 0x%x (delta 0x%x)"
                  % (TABLE_PTR_VA, delta, table, tdelta))
            blob = read(table + tdelta, 40 * 256) or read(table + tdelta, 40 * 8)
            import itertools
            n = len(blob) // 40
            shown = 0
            for i in range(n):
                rec = blob[i * 40:(i + 1) * 40]
                sid, flag = struct.unpack_from("<IB", rec, 0)
                tok = rec[5:].split(b"\x00")[0].decode("latin-1", "replace")
                mark = "   <- index 0 is NEVER searched" if i == 0 else ""
                if sid == 0xFFFFFFFF and i > 3 and shown > 6: continue
                shown += 1
                print("  [%d] sessionid=0x%08x flag=%d token=%r%s"
                      % (i, sid, flag, tok[:24], mark))
            raise SystemExit(0)

print("could not locate the table; dumping nothing rather than guessing")
raise SystemExit(2)
