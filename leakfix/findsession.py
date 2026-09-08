#!/usr/bin/env python3
"""Is the session id actually IN the table addSessionItem writes?

Earlier attempts resolved the table address by "first delta that maps", which is
the weak criterion that has already returned convincing garbage once today. This
does the opposite: it searches the guest's writable memory for a value we KNOW --
the session id the server itself rendered as hidSession -- and reports where it
is found. No address arithmetic to get wrong.

    sudo python3 findsession.py <qemu-pid> <hidSession-as-signed-or-unsigned>

If the id appears on a 40-byte stride with a token string 5 bytes in, the write
landed and the lookup is missing it for another reason. If it appears nowhere,
the write never reached this table.
"""
import re
import struct
import sys

pid = int(sys.argv[1])
raw = int(sys.argv[2])
val = raw & 0xFFFFFFFF
needle = struct.pack("<I", val)
print("searching pid %d for 0x%08x (%d)" % (pid, val, raw))

regions = []
for line in open("/proc/%d/maps" % pid, encoding="utf-8"):
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)", line)
    if not m:
        continue
    lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
    if "w" in perms and "r" in perms:
        regions.append((lo, hi, name.strip()))

mem = open("/proc/%d/mem" % pid, "rb", buffering=0)
hits = 0
for lo, hi, name in regions:
    size = hi - lo
    if size > 64 * 1024 * 1024:
        continue
    try:
        mem.seek(lo)
        blob = mem.read(size)
    except OSError:
        continue
    start = 0
    while True:
        i = blob.find(needle, start)
        if i < 0:
            break
        start = i + 1
        hits += 1
        addr = lo + i
        ctx = blob[max(0, i - 8):i + 40]
        tok = blob[i + 5:i + 37].split(b"\x00")[0]
        printable = all(32 <= c < 127 for c in tok) and len(tok) > 8
        print("  hit at 0x%08x in %-24s  flag=%d token=%r%s"
              % (addr, name or "anon", blob[i + 4] if i + 4 < len(blob) else -1,
                 tok[:36], "  <- looks like a session record" if printable else ""))
        if hits > 40:
            print("  ... stopping at 40")
            raise SystemExit(0)

print("\n%d hit(s)." % hits)
if not hits:
    print("The id is NOT anywhere in writable memory, so addSessionItem never")
    print("stored THIS value -- the registered id differs from the rendered one.")
