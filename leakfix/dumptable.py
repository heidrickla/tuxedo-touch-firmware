#!/usr/bin/env python3
"""Dump words from the Barracuda image and annotate them.

A word is annotated as a symbol when it matches one from nm, and as a string
when it points at printable bytes in the image. That turns a table of raw
words into a readable structure.
"""

import argparse
import struct
import subprocess

BIN = "/work/emu/stock/opt/webserver/Barracuda"


def symbols():
    out = subprocess.run(
        ["nm", "-C", BIN], capture_output=True, text=True, check=False
    ).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[0].strip():
            try:
                syms[int(parts[0], 16)] = parts[2].strip()
            except ValueError:
                pass
    return syms


def as_string(data, va):
    """Interpret va as a pointer into the image and return the string there."""
    for bias in (0x8000, 0x10000):
        off = va - bias
        if 0 <= off < len(data) - 1:
            end = data.find(b"\x00", off, off + 96)
            if end > off:
                raw = data[off:end]
                if raw and all(32 <= c < 127 for c in raw):
                    return raw.decode("ascii")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--off", required=True, help="file offset, hex")
    ap.add_argument("--n", default="0x80", help="bytes to dump, hex")
    args = ap.parse_args()

    data = open(BIN, "rb").read()
    syms = symbols()
    start = int(args.off, 16)
    count = int(args.n, 16)

    for i in range(start, start + count, 4):
        (word,) = struct.unpack_from("<I", data, i)
        note = ""
        if word in syms:
            note = f"   SYMBOL {syms[word]}"
        else:
            s = as_string(data, word)
            if s:
                note = f'   "{s}"'
        print(f"  file 0x{i:06x}  word 0x{word:08x}{note}")


if __name__ == "__main__":
    main()
