#!/usr/bin/env python3
"""A/B the 0x2903c fix: WnmpDir_serviceField frees the reply string with free().

The reply string from json_write is registered in libjson's string registry by
toCString. free() releases the bytes and leaves the registry entry, so the entry
is stranded. json_free erases the entry AND frees the bytes.

Predicted effect if that is what the third registry string is: every arm that
reaches this line loses exactly 1.0000 strings per call, and nodes do not move.
If the family stays at +3 strings the mechanism is wrong, whatever the reasoning
said.

    bl free       at VA 0x2903c   ->   bl json_free

Writes a patched copy; never touches the input. Verifies the bytes it wrote and
refuses to proceed if the site does not hold the expected instruction, because a
patcher that does not check its own site is how a wrong offset becomes a silent
no-op that then "measures zero effect".
"""
import shutil
import struct
import sys

SITE_VA = 0x2903C
TEXT_BIAS = 0x8000
FREE_PLT = 0xC150
JSON_FREE_PLT = 0xBCA0


def bl(at_va, target_va):
    off = (target_va - (at_va + 8)) >> 2
    return 0xEB000000 | (off & 0x00FFFFFF)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    shutil.copyfile(src, dst)
    off = SITE_VA - TEXT_BIAS

    with open(dst, "r+b") as fh:
        fh.seek(off)
        cur = struct.unpack("<I", fh.read(4))[0]
        want = bl(SITE_VA, FREE_PLT)
        if cur != want:
            raise SystemExit("site 0x%x holds %08x, expected bl free %08x -- refusing"
                             % (SITE_VA, cur, want))
        new = bl(SITE_VA, JSON_FREE_PLT)
        fh.seek(off)
        fh.write(struct.pack("<I", new))
        fh.seek(off)
        back = struct.unpack("<I", fh.read(4))[0]
        if back != new:
            raise SystemExit("readback mismatch: wrote %08x, read %08x" % (new, back))

    print("patched %s" % dst)
    print("  VA 0x%x (file 0x%x): %08x -> %08x  (bl free -> bl json_free)"
          % (SITE_VA, off, cur, new))


if __name__ == "__main__":
    main()
