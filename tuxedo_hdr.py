#!/usr/bin/env python3
"""
Read, verify and rebuild the 128-byte vendor header on Tuxedo Touch firmware
files (`app1.hdr`, `app2.hdr`, `app3.hdr`, `ProgCV.hdr`, `seconboot.hdr`).

THE CHECKSUM IS REAL AND IT IS ENFORCED.

An earlier version of this project concluded that the 16-bit field at offset
0x14 was not checked, because the per-component loader sets its "checksum OK"
flag unconditionally after a successful read. That conclusion was wrong, and
the panel rejected a rebuilt image with

    File app2.hdr Checksum Error: Please remove the SD card and Format SD
    card using PC. Copy image again, insert SD card to unit and reboot the
    system for reprogramming.

The verification lives in a separate routine at `0x80003864` in `ProgCV`,
called from the validator at `0x800074c0` over the payload in chunks:

    80003884  ldrb  r6, [ip]        ; high byte
    80003888  lsls  r6, r6, #8
    80003894  ldrb  r6, [ip]        ; low byte  -> big-endian 16-bit word
    80003898  orrs  lr, r6, lr
    800038a0  uxtah r0, r0, lr      ; 32-bit accumulator, no carry folding yet
    ...
    800038d0  lsrs  r6, r0, #0x10   ; finalisation, last chunk only:
    800038d4  uxtah r0, r6, r0      ;   acc = (acc >> 16) + (acc & 0xffff)
    800038d8  adds  r0, r0, r0, lsr #16
    800038dc  mvns  r0, r0          ;   complement
    800038e0  uxth  r0, r0

So: sum big-endian 16-bit words into a **32-bit** accumulator, fold twice at
the very end, complement, truncate to 16 bits. It is the internet checksum
with a deferred fold. Accumulating in 16 bits with end-around carry on every
addition gives a DIFFERENT answer for large inputs, which is what made an
earlier attempt match two of the five vendor files and miss the other three.

Verified: this reproduces the shipped checksum of all five vendor files
exactly.

    python tuxedo_hdr.py show app2.hdr
    python tuxedo_hdr.py verify *.hdr
    python tuxedo_hdr.py build app2.jffs2 app2.hdr --template stock/app2.hdr
"""

import argparse
import os
import struct
import sys

try:
    import numpy as np
except ImportError:
    np = None

HDR_SIZE = 128
CHUNK = 1 << 24

FIELDS = [
    ("magic",     0x00, 8,  "str"),
    ("size",      0x08, 4,  "u32"),
    ("flashaddr", 0x0c, 4,  "u32"),
    ("loadaddr",  0x10, 4,  "u32"),
    ("checksum",  0x14, 2,  "u16"),
    ("date",      0x16, 26, "str"),
    ("filename",  0x30, 13, "str"),
    ("version",   0x3d, 17, "str"),
    ("type",      0x4e, 4,  "str"),
    ("platform",  0x52, 14, "str"),
]


def checksum(path, start=HDR_SIZE, length=None):
    """The ProgCV 0x80003864 checksum over `length` bytes starting at `start`."""
    if length is None:
        length = os.path.getsize(path) - start
    acc = 0
    with open(path, "rb") as f:
        f.seek(start)
        remaining = length
        while remaining > 0:
            buf = f.read(min(remaining, CHUNK))
            if not buf:
                break
            even = buf[: len(buf) & ~1]
            if np is not None:
                acc += int(np.frombuffer(even, dtype=">u2").sum(dtype=np.uint64))
            else:
                acc += sum(struct.unpack(f">{len(even)//2}H", even))
            remaining -= len(buf)
    acc %= 1 << 32                      # the ARM accumulator is 32 bits
    acc = (acc >> 16) + (acc & 0xFFFF)  # fold
    acc = acc + (acc >> 16)             # fold again
    return (~acc) & 0xFFFF


def parse(hdr):
    out = {}
    for name, off, size, kind in FIELDS:
        raw = hdr[off:off + size]
        if kind == "str":
            out[name] = raw.split(b"\0")[0].decode("latin-1")
        elif kind == "u32":
            out[name] = struct.unpack_from("<I", hdr, off)[0]
        else:
            out[name] = struct.unpack_from("<H", hdr, off)[0]
    return out


def show(path):
    hdr = open(path, "rb").read(HDR_SIZE)
    h = parse(hdr)
    print(f"{path}  ({os.path.getsize(path)} bytes)")
    for name, off, _, kind in FIELDS:
        v = h[name]
        v = f"0x{v:08x}" if kind == "u32" else (f"0x{v:04x}" if kind == "u16" else repr(v))
        print(f"  0x{off:02x}  {name:<10} {v}")


def verify(path):
    hdr = open(path, "rb").read(HDR_SIZE)
    h = parse(hdr)
    actual = os.path.getsize(path)
    size_ok = actual == HDR_SIZE + h["size"]
    got = checksum(path, HDR_SIZE, h["size"])
    ck_ok = got == h["checksum"]
    print(f"  {os.path.basename(path):16} size={h['size']:>10} "
          f"hdr=0x{h['checksum']:04x} computed=0x{got:04x} "
          f"len_ok={size_ok}  {'PASS' if (ck_ok and size_ok) else 'FAIL'}")
    return ck_ok and size_ok


def build(payload, out, template):
    hdr = bytearray(open(template, "rb").read(HDR_SIZE))
    size = os.path.getsize(payload)
    struct.pack_into("<I", hdr, 0x08, size)
    with open(out, "wb") as f:
        f.write(bytes(hdr))
        with open(payload, "rb") as g:
            while True:
                b = g.read(CHUNK)
                if not b:
                    break
                f.write(b)
    ck = checksum(out, HDR_SIZE, size)
    with open(out, "r+b") as f:
        f.seek(0x14)
        f.write(struct.pack("<H", ck))
    print(f"wrote {out}: size={size} checksum=0x{ck:04x}")
    return verify(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("show"); p.add_argument("files", nargs="+")
    p = sub.add_parser("verify"); p.add_argument("files", nargs="+")
    p = sub.add_parser("build")
    p.add_argument("payload"); p.add_argument("out")
    p.add_argument("--template", required=True,
                   help="a stock .hdr of the same component, for the fields "
                        "that must not change (flashaddr, loadaddr, filename, "
                        "version, type, platform)")
    a = ap.parse_args()
    if a.cmd == "show":
        for f in a.files:
            show(f)
        return 0
    if a.cmd == "verify":
        print("verifying as ProgCV does:")
        return 0 if all([verify(f) for f in a.files]) else 1
    return 0 if build(a.payload, a.out, a.template) else 1


if __name__ == "__main__":
    sys.exit(main())
