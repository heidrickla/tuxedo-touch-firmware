#!/usr/bin/env python3
"""Attribute each leak: vendor-inherited, or introduced by our own patches?

Two independent tests per leak site:

  1. Are the bytes around the leaking instruction IDENTICAL in the untouched
     vendor image and in our v13 build? If yes, the defect predates every patch
     of ours and is the vendor's.
  2. Does the site fall inside any byte range that patches.tsv modifies? If it
     did, ours could have created or moved it.

Also checks that the code caves the leak fixes occupy do not collide with any
existing patch site - a silent overlap would corrupt an unrelated fix.

patches.tsv offsets are FILE offsets; .text VA = file offset + 0x8000.
"""

import argparse
import sys

TEXT_BIAS = 0x8000

# (VA, what leaks)
LEAK_SITES = [
    (0x29088, "parameter tree abandoned by r7 overwrite"),
    (0x1EFA0, "Base64Decode output buffer"),
    (0x47CC8, "tuxedoapi.html parsed document"),
    (0x1CC84, "getPartitionStatus tree B + Base64Encode buffer"),
    (0x1CC08, "getPartitionStatus json_write str1"),
    (0x1CC2C, "getPartitionStatus json_write str2 (stash)"),
    (0x1CC44, "getPartitionStatus json_write str2 (free)"),
    (0x2954C, "handler out-param string"),
    (0x29D7C, "authtoken HMAC digest buffer"),
    (0x29DC4, "authtoken base64 buffer"),
    (0x29BE8, "json_as_string -> strcpy (device field)"),
    (0x29C14, "json_as_string -> strcpy (session key)"),
    (0x29E20, "json_as_string -> strcpy (device field 2)"),
    (0x1F0F0, "json_as_string -> strncmp (operation)"),
    (0x29BBC, "json_as_string -> strcmp (device match)"),
    (0x29E84, "json_as_string -> strcmp (second lookup)"),
    (0x47C44, "json_as_string -> strcmp (tuxedoapi entry)"),
    (0x47C94, "json_as_string x2 -> printf (tuxedoapi entry)"),
]

# VA ranges our leak-fix stubs occupy
CAVES = [
    (0x64E10, 0x64E50, "AuthUserListEnumerator_nextElement"),
    (0x64E50, 0x64E94, "AuthenticatedUser_getType"),
    (0x64E9C, 0x64ED4, "LoginTracker_getFirstNode/getNextNode"),
    (0x65850, 0x658D0, "AuthenticatedUser_getAnonymous"),
    (0x693DC, 0x69444, "HttpServer_getStatusCode"),
]

CONTEXT = 64   # bytes either side to compare


def load_patches(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < 5:
                continue
            name, binary, off, stock, patched = p[:5]
            if "Barracuda" not in binary:
                continue
            rows.append((name, int(off, 16), len(bytes.fromhex(patched))))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stock", required=True)
    ap.add_argument("--ours", required=True)
    ap.add_argument("--patches", required=True)
    args = ap.parse_args()

    stock = open(args.stock, "rb").read()
    ours = open(args.ours, "rb").read()
    patches = load_patches(args.patches)

    print(f"  stock : {args.stock}  ({len(stock)} bytes)")
    print(f"  ours  : {args.ours}  ({len(ours)} bytes)")
    print(f"  patches.tsv Barracuda rows: {len(patches)}")

    # Overall difference between the two images
    diffs = [i for i in range(min(len(stock), len(ours))) if stock[i] != ours[i]]
    if diffs:
        print(f"  images differ in {len(diffs)} bytes, "
              f"file 0x{min(diffs):x}..0x{max(diffs):x} "
              f"(VA 0x{min(diffs)+TEXT_BIAS:x}..0x{max(diffs)+TEXT_BIAS:x})")

    print("\n  LEAK ATTRIBUTION")
    vendor = ours_count = 0
    for va, what in LEAK_SITES:
        off = va - TEXT_BIAS
        a = stock[off - CONTEXT:off + CONTEXT]
        b = ours[off - CONTEXT:off + CONTEXT]
        same = a == b
        in_patch = [n for n, po, plen in patches
                    if po - CONTEXT < off < po + plen + CONTEXT]
        if same and not in_patch:
            verdict = "VENDOR"
            vendor += 1
        else:
            verdict = "OURS?"
            ours_count += 1
        note = f"  <- overlaps {in_patch}" if in_patch else ""
        print(f"    0x{va:06x}  {verdict:7s} {what}{note}")

    print(f"\n  vendor-inherited: {vendor}    possibly ours: {ours_count}")

    print("\n  CAVE COLLISION CHECK (our stubs vs existing patches)")
    bad = 0
    for lo, hi, name in CAVES:
        hits = [n for n, po, plen in patches
                if lo - TEXT_BIAS <= po < hi - TEXT_BIAS
                or lo - TEXT_BIAS < po + plen <= hi - TEXT_BIAS]
        if hits:
            print(f"    0x{lo:06x}-0x{hi:06x} {name}: COLLIDES with {hits}")
            bad += 1
        else:
            nearest = min((abs((po + TEXT_BIAS) - lo), n, po + TEXT_BIAS)
                          for n, po, plen in patches)
            print(f"    0x{lo:06x}-0x{hi:06x} {name}: clear "
                  f"(nearest patch {nearest[1]} at VA 0x{nearest[2]:x})")
    print(f"  collisions: {bad}")


if __name__ == "__main__":
    sys.exit(main())
