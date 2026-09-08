#!/usr/bin/env python3
"""Find genuinely dead functions usable as code caves.

A function qualifies only if BOTH hold:
  * no `bl` in the disassembly targets it, and
  * every 4-byte word in the image equal to its address lies in the symbol
    table region, not in .text or .data.

The second test is the one that matters. A function with zero `bl` callers can
still be reached through a function-pointer table or a vtable, and overwriting
one of those is how a cave hunt turns into a crash. Reporting the reference
offsets lets the caller judge rather than trust a boolean.
"""

import argparse
import re
import struct
import subprocess
import sys

BIN = "/work/emu/stock/opt/webserver/Barracuda.orig324209e1"
TEXT_BIAS = 0x8000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dis", default="/tmp/barra.dis")
    ap.add_argument("--min", type=int, default=64)
    ap.add_argument("--symtab-from", default="0x550000",
                    help="file offsets at or above this are symtab/debug tail")
    ap.add_argument("--want", type=int, default=6)
    args = ap.parse_args()

    tail = int(args.symtab_from, 16)
    data = open(BIN, "rb").read()

    out = subprocess.run(["nm", "-S", BIN], capture_output=True, text=True,
                         check=False).stdout
    cands = []
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4 and p[2] in ("t", "T"):
            try:
                addr, size = int(p[0], 16), int(p[1], 16)
            except ValueError:
                continue
            if size >= args.min:
                cands.append((addr, size, p[3]))

    dis = open(args.dis, encoding="utf-8", errors="replace").read()
    # BOTH `bl` and `b`/`bxx`. Collecting only `bl` marks live code dead: a CSP
    # page handler is reached by a TAIL BRANCH from its registration thunk, and
    # `get` reaches getPartitionStatus the same way. Scanning bl alone offered
    # handlerequest_html076EF::service - which demonstrably serves requests - as
    # a free cave.
    called = set(re.findall(r"\bbl?[a-z]{0,2}\s+([0-9a-f]+) <", dis))

    found = 0
    for addr, size, name in sorted(cands, key=lambda c: -c[1]):
        if found >= args.want:
            break
        if f"{addr:x}" in called:
            continue
        pat = struct.pack("<I", addr)
        refs = [i for i in range(0, len(data) - 4, 4) if data[i:i + 4] == pat]
        live = [r for r in refs if r < tail]
        if live:
            continue
        print(f"  0x{addr:06x}  {size:4d} B  {name}")
        print(f"      refs: {[hex(r) for r in refs]}  (all in symtab tail)")
        found += 1

    if not found:
        print("  no candidate passed both tests")


if __name__ == "__main__":
    sys.exit(main())
