#!/usr/bin/env python3
"""Count occurrences of a byte pattern in a live process's memory.

Used to prove retention: send N requests carrying a unique marker, then count
how many copies survive. N copies means one retained buffer per request; 2N
means two.

Reports the mapping each hit lands in, so a hit in the heap can be told apart
from one still sitting in a socket buffer or the emulator's own translation
cache.
"""

import argparse
import re
import sys

MAP_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)$"
)


def readable_maps(pid):
    out = []
    with open(f"/proc/{pid}/maps", encoding="utf-8") as fh:
        for line in fh:
            m = MAP_RE.match(line.rstrip("\n"))
            if not m:
                continue
            start, end, perms, name = m.groups()
            if "r" not in perms:
                continue
            # Skip file-backed executable text: a marker cannot be there, and
            # reading them all is slow.
            if name.startswith("/") and "x" in perms:
                continue
            out.append((int(start, 16), int(end, 16), perms, name.strip()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--pattern", required=True)
    ap.add_argument("--max-mb", type=int, default=4096)
    ap.add_argument("--context", type=int, default=0,
                    help="dump this many bytes either side of the first hits, "
                         "to identify the containing structure and its malloc "
                         "chunk header")
    ap.add_argument("--context-hits", type=int, default=3)
    ap.add_argument("--only-range", default="",
                    help="restrict to one mapping, e.g. 0x56b000-0x6b5000")
    args = ap.parse_args()

    lo = hi = None
    if args.only_range:
        a, b = args.only_range.split("-")
        lo, hi = int(a, 16), int(b, 16)

    pat = args.pattern.encode()
    total = 0
    per_map = []
    scanned = 0

    shown = 0

    with open(f"/proc/{args.pid}/mem", "rb", 0) as mem:
        for start, end, perms, name in readable_maps(args.pid):
            size = end - start
            if size <= 0 or scanned + size > args.max_mb * 1024 * 1024:
                continue
            if lo is not None and not (start >= lo and end <= hi):
                continue
            try:
                mem.seek(start)
                buf = mem.read(size)
            except (OSError, ValueError, OverflowError):
                continue
            scanned += size
            if not buf:
                continue
            c = buf.count(pat)
            if c:
                per_map.append((c, hex(start), hex(end), perms, name or "anon"))
                total += c

            if args.context and c and shown < args.context_hits:
                pos = -1
                while shown < args.context_hits:
                    pos = buf.find(pat, pos + 1)
                    if pos < 0:
                        break
                    shown += 1
                    va = start + pos
                    a = max(0, pos - args.context)
                    b = min(len(buf), pos + args.context)
                    print(f"\n--- hit {shown} at guest 0x{va:08x} "
                          f"(offset {pos - a} into dump) ---")
                    chunk = buf[a:b]
                    for off in range(0, len(chunk), 16):
                        row = chunk[off:off + 16]
                        hexs = " ".join(f"{x:02x}" for x in row)
                        txt = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
                        print(f"  0x{start + a + off:08x}  {hexs:<47}  {txt}")

    print(f"pattern {args.pattern!r}")
    print(f"scanned {scanned / 1048576:.1f} MB of readable mappings")
    print(f"TOTAL occurrences: {total}")
    for c, s, e, p, n in sorted(per_map, reverse=True)[:15]:
        print(f"  {c:6d}  {s}-{e} {p}  {n}")
    if total == 0:
        print("  (zero: either nothing is retained, or the scan missed the "
              "region -- check that a marker known to be live is found)")


if __name__ == "__main__":
    sys.exit(main())
