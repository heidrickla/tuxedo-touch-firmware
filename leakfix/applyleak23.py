#!/usr/bin/env python3
"""Apply ONLY the LEAK 23 rows to the deployed binary, for a bench A/B.

mkapifix builds the whole P15 set from stock, but the bench runs 62ee361c, which
is stock plus P13/P14 plus the earlier P15 work. So take just the new rows from
mkapifix --tsv and write them onto a copy of the deployed binary. That keeps the
comparison to one variable.

Refuses on any row whose "old" bytes are not already there, which is what stops
this being applied to the wrong build or applied twice.

    python3 applyleak23.py <tsv> <in-binary> <out-binary>
"""
import sys

tsv, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
NEW = ("cave-69580", "cave-69584", "cave-69588", "cave-6958c", "cave-69590",
       "site-34c50")

blob = bytearray(open(src, "rb").read())
applied = 0
for line in open(tsv, encoding="utf-8"):
    if not line.startswith("P15-leakfix-"):
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 5:
        continue
    name, _path, off, old, new = parts[0], parts[1], parts[2], parts[3], parts[4]
    if not any(name.endswith(k) for k in NEW):
        continue
    o = int(off, 16)
    ob = bytes.fromhex(old)
    nb = bytes.fromhex(new)
    if bytes(blob[o:o + 4]) != ob:
        sys.exit("REFUSING: %s at 0x%x holds %s, expected %s"
                 % (name, o, bytes(blob[o:o + 4]).hex(), old))
    blob[o:o + 4] = nb
    print("  %-28s 0x%06x  %s -> %s" % (name, o, old, new))
    applied += 1

if applied != len(NEW):
    sys.exit("REFUSING: applied %d rows, expected %d" % (applied, len(NEW)))
open(dst, "wb").write(bytes(blob))
print("wrote %s (%d rows)" % (dst, applied))
