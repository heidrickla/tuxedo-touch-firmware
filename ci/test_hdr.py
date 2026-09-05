#!/usr/bin/env python3
"""Regression test for the ProgCV header checksum in tuxedo_hdr.py.

The algorithm was wrong once: a 16-bit accumulator with end-around carry on
every addition matches short inputs and diverges on long ones, which
reproduced two of five vendor files and cost a flash attempt. The long-input
case below is what catches that.
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tuxedo_hdr import checksum, HDR_SIZE  # noqa: E402

FAILED = 0


def check(name, got, want):
    global FAILED
    if got == want:
        print(f"ok   {name}: 0x{got:04x}")
    else:
        FAILED = 1
        print(f"FAIL {name}: got 0x{got:04x}, want 0x{want:04x}")


def csum(data):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\0" * HDR_SIZE + data)
        p = f.name
    try:
        return checksum(p, HDR_SIZE, len(data))
    finally:
        os.unlink(p)


# Hand-computed. BE words 0x0001 + 0x0203 = 0x0204; fold twice is a no-op;
# complement and truncate gives 0xfdfb.
check("4-byte fixture", csum(b"\x00\x01\x02\x03"), 0xFDFB)

# Empty payload: accumulator 0, complement 0xffff.
check("empty payload", csum(b""), 0xFFFF)

# Odd length: the trailing byte is added shifted left 8.
# BE word 0x0102 = 0x0102, plus 0x03 << 8 = 0x0300, total 0x0402 -> 0xfbfd.
check("odd length", csum(b"\x01\x02\x03"), 0xFBFD)

# Long input, where a 16-bit end-around-carry accumulator diverges from the
# 32-bit deferred fold the firmware actually uses. 100000 words of 0xffff:
# 32-bit sum = 0xffff * 100000 = 0x1867FE7961; mod 2^32 = 0x867FE7961 & 0xffffffff
# The value below is what the correct implementation produces; an end-around
# carry implementation gives a different one.
long_payload = b"\xff\xff" * 100000
acc = 0xFFFF * 100000
acc %= 1 << 32
acc = (acc >> 16) + (acc & 0xFFFF)
acc = acc + (acc >> 16)
check("long input (32-bit accumulator)", csum(long_payload), (~acc) & 0xFFFF)

# Vendor images, when present. Not committed; skipped in CI.
FW = os.environ.get("TUXEDO_FW_DIR", "")
VENDOR = {
    "app1.hdr": 0x2FBD,
    "app2.hdr": 0x8AD5,
    "app3.hdr": 0xEBBA,
    "ProgCV.hdr": 0x8720,
    "seconboot.hdr": 0xBDA7,
}
if FW and os.path.isdir(FW):
    for name, want in VENDOR.items():
        p = os.path.join(FW, name)
        if not os.path.exists(p):
            print(f"skip {name} (absent)")
            continue
        size = struct.unpack_from("<I", open(p, "rb").read(HDR_SIZE), 8)[0]
        check(f"vendor {name}", checksum(p, HDR_SIZE, size), want)
else:
    print("skip vendor images (set TUXEDO_FW_DIR to enable)")

sys.exit(FAILED)
