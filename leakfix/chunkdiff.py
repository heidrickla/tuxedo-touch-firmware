#!/usr/bin/env python3
"""Show the CONTENTS of heap chunks that appeared between two snapshots.

heapwalk says which sizes leak. This says what is in them, which is usually
enough to name the allocation without a full execution trace.

Snapshot the in-use chunk addresses of the sizes of interest, run N requests,
snapshot again, and dump the chunks that are new. A chunk holding a base64 blob,
a JSON fragment, or a pointer pair identifies itself.

In-use is determined from the NEXT chunk's PREV_INUSE bit, not from the chunk's
own - bit 0 of a chunk's size field describes the PREVIOUS chunk.
"""

import argparse
import json
import re
import struct
import sys

MAP_RE = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)$")
MIN_CHUNK = 16
MAX_CHUNK = 1 << 20


def heap_regions(pid):
    out = []
    with open(f"/proc/{pid}/maps", encoding="utf-8") as fh:
        for line in fh:
            m = MAP_RE.match(line.rstrip("\n"))
            if not m:
                continue
            start, end, perms, name = m.groups()
            s, e = int(start, 16), int(end, 16)
            if "rw" not in perms or name.strip():
                continue
            if s < 0x01000000 and (e - s) > 0x10000:
                out.append((s, e))
    return out


def chunks(mem, start, end):
    got = []
    p = start
    bad = 0
    while p + 8 < end:
        try:
            mem.seek(p)
            raw = mem.read(8)
        except OSError:
            break
        if len(raw) < 8:
            break
        _prev, size_field = struct.unpack("<II", raw)
        size = size_field & ~7
        if size < MIN_CHUNK or size > MAX_CHUNK or (p + size) > end:
            bad += 1
            p += 8
            if bad > 64:
                break
            continue
        got.append((p, size))
        p += size

    live = []
    for i, (addr, size) in enumerate(got):
        if i + 1 >= len(got):
            break
        try:
            mem.seek(got[i + 1][0] + 4)
            nraw = mem.read(4)
        except OSError:
            break
        if len(nraw) < 4:
            break
        if struct.unpack("<I", nraw)[0] & 1:
            live.append((addr, size))
    return live


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--sizes", required=True, help="comma-separated chunk sizes")
    ap.add_argument("--save")
    ap.add_argument("--compare")
    ap.add_argument("--dump", type=int, default=6, help="how many new chunks to dump")
    args = ap.parse_args()

    want = {int(x) for x in args.sizes.split(",")}
    found = {}
    with open(f"/proc/{args.pid}/mem", "rb", 0) as mem:
        for s, e in heap_regions(args.pid):
            for addr, size in chunks(mem, s, e):
                if size in want:
                    found[addr] = size

        print(f"  in-use chunks of sizes {sorted(want)}: {len(found)}")

        if args.save:
            with open(args.save, "w", encoding="utf-8") as fh:
                json.dump(sorted(found.items()), fh)
            print(f"  saved {len(found)} addresses")
            return

        if not args.compare:
            return

        with open(args.compare, encoding="utf-8") as fh:
            before = {a for a, _ in json.load(fh)}
        new = [(a, s) for a, s in sorted(found.items()) if a not in before]
        print(f"  NEW since the snapshot: {len(new)}")

        shown = 0
        for addr, size in new:
            if shown >= args.dump:
                break
            shown += 1
            try:
                mem.seek(addr)
                blob = mem.read(size)
            except OSError:
                continue
            print(f"\n--- new {size}B chunk at 0x{addr:08x} "
                  f"(user data from +8) ---")
            for off in range(0, len(blob), 16):
                row = blob[off:off + 16]
                hexs = " ".join(f"{x:02x}" for x in row)
                txt = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
                print(f"  +{off:03x}  {hexs:<47}  {txt}")


if __name__ == "__main__":
    sys.exit(main())
