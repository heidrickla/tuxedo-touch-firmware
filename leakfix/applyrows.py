#!/usr/bin/env python3
"""Apply a NAMED SUBSET of mkapifix --tsv rows onto a binary, for a bench A/B.

mkapifix builds the whole P15 set from stock, but the bench and panel run
62ee361c, which is stock plus P13/P14 plus the earlier P15 work. To test one new
leak fix in isolation, take just its rows and write them onto a copy of the
deployed binary -- that keeps the comparison to a single variable.

Refuses on any row whose "old" bytes are not already present, which is what stops
it being applied to the wrong build or applied twice, and refuses unless every
requested row matched, so a typo in a name cannot silently apply half a fix.

    python3 applyrows.py <tsv> <in-binary> <out-binary> <suffix> [suffix...]

e.g. ... cave-69594 cave-69598 ... site-13b68
"""
import sys

if len(sys.argv) < 5:
    raise SystemExit(__doc__)
tsv, src, dst, wanted = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]

blob = bytearray(open(src, "rb").read())
seen = set()
for line in open(tsv, encoding="utf-8"):
    if not line.startswith("P15-leakfix-"):
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 5:
        continue
    name, off, old, new = parts[0], parts[2], parts[3], parts[4]
    match = [w for w in wanted if name.endswith(w)]
    if not match:
        continue
    o = int(off, 16)
    ob, nb = bytes.fromhex(old), bytes.fromhex(new)
    if bytes(blob[o:o + 4]) != ob:
        sys.exit("REFUSING: %s at 0x%x holds %s, expected %s"
                 % (name, o, bytes(blob[o:o + 4]).hex(), old))
    blob[o:o + 4] = nb
    seen.add(match[0])
    print("  %-28s 0x%06x  %s -> %s" % (name, o, old, new))

missing = [w for w in wanted if w not in seen]
if missing:
    sys.exit("REFUSING: no row matched %s" % ", ".join(missing))
open(dst, "wb").write(bytes(blob))
print("wrote %s (%d rows)" % (dst, len(seen)))
