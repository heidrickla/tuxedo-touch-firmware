#!/usr/bin/env python3
"""Histogram glibc heap chunk sizes in a live process.

Run it before and after N requests: any size whose count grows by about N is
allocated once per request and never freed. That turns "something leaks ~1.2 kB"
into a list of concrete allocation sizes, which map back to call sites.

The guest heap of a qemu-user process sits at the guest's own addresses inside
the qemu process, so it can be read directly from /proc/<pid>/mem.

Chunk layout (32-bit glibc): [prev_size][size|flags] then user data. The next
chunk is at p + (size & ~7). Walking stops on any implausible size rather than
running off into noise.
"""

import argparse
import json
import re
import struct
import sys

MAP_RE = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)$")

MIN_CHUNK = 16
MAX_CHUNK = 1 << 20


def find_heap(pid, want_lo):
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
            # the guest heap: low 32-bit addresses, large anonymous rw mapping
            if s < 0x01000000 and (e - s) > 0x10000:
                out.append((s, e))
    if want_lo:
        out = [x for x in out if x[0] == want_lo]
    return out


def walk(mem, start, end):
    """Histogram IN-USE chunk sizes.

    glibc's bit 0 is PREV_INUSE: it says whether the PREVIOUS chunk is
    allocated, not this one. A chunk is in use iff the NEXT chunk's PREV_INUSE
    is set. Reading bit 0 of the chunk's own size field counts something else
    entirely, and that reads as a plausible histogram right up until frees
    become common - which is exactly when it matters.
    """
    chunks = []
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
        chunks.append((p, size))
        p += size

    sizes = {}
    inuse_count = 0
    for i, (addr, size) in enumerate(chunks):
        if i + 1 >= len(chunks):
            break
        nxt_addr, _ = chunks[i + 1]
        try:
            mem.seek(nxt_addr + 4)
            nraw = mem.read(4)
        except OSError:
            break
        if len(nraw) < 4:
            break
        (nsize_field,) = struct.unpack("<I", nraw)
        if nsize_field & 1:          # next chunk's PREV_INUSE -> this one is live
            sizes[size] = sizes.get(size, 0) + 1
            inuse_count += 1
    return sizes, len(chunks), bad, inuse_count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--save", help="write the histogram to this json file")
    ap.add_argument("--compare", help="compare against a saved histogram")
    ap.add_argument("--expect", type=int, default=0,
                    help="requests made between the two samples; sizes growing "
                         "by about this much are the per-request leaks")
    ap.add_argument("--heap-lo", default="", help="restrict to this mapping start, hex")
    args = ap.parse_args()

    lo = int(args.heap_lo, 16) if args.heap_lo else None
    regions = find_heap(args.pid, lo)
    if not regions:
        sys.exit("no candidate guest heap mapping found")

    total = {}
    with open(f"/proc/{args.pid}/mem", "rb", 0) as mem:
        for s, e in regions:
            sizes, walked, bad, live = walk(mem, s, e)
            print(f"  region 0x{s:x}-0x{e:x}: {walked} chunks walked, "
                  f"{live} in use, {bad} resyncs")
            for k, v in sizes.items():
                total[k] = total.get(k, 0) + v

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump({str(k): v for k, v in total.items()}, fh)
        print(f"  saved {len(total)} distinct sizes")

    if args.compare:
        with open(args.compare, encoding="utf-8") as fh:
            before = {int(k): v for k, v in json.load(fh).items()}
        rows = []
        for size in set(before) | set(total):
            d = total.get(size, 0) - before.get(size, 0)
            if d:
                rows.append((d, size, before.get(size, 0), total.get(size, 0)))
        rows.sort(reverse=True)
        n = args.expect
        print(f"\n  size   delta   before -> after"
              + (f"   (per-request leaks grow by ~{n})" if n else ""))
        grown = 0
        for d, size, b, a in rows[:25]:
            flag = ""
            if n and abs(d - n) <= max(2, n * 0.1):
                flag = "   <== once per request"
                grown += size * d
            print(f"  {size:6d} {d:+7d}   {b:6d} -> {a:6d}{flag}")
        if n and grown:
            print(f"\n  per-request bytes in flagged sizes: {grown / n:.0f} B/request")


if __name__ == "__main__":
    main()
