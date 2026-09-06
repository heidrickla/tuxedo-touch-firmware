#!/usr/bin/env python3
"""Rebuild /opt/tuxedo/configuration from the length-prefixed stream.

The panel has no tar, gzip or cpio, so the transfer is a single ssh session
emitting "===F <size> <path>\n" followed by exactly <size> raw bytes. Length
prefixing is what makes it binary-safe: several of these files are not text.
"""
import os, sys

stream, root = sys.argv[1], sys.argv[2]
d = open(stream, "rb").read()
i, n = 0, 0
while True:
    j = d.find(b"===F ", i)
    if j < 0:
        break
    eol = d.index(b"\n", j)
    size, path = d[j + 5:eol].split(b" ", 1)
    size = int(size)
    path = path.decode("utf-8", "replace")
    body = d[eol + 1:eol + 1 + size]
    rel = path.replace("/opt/tuxedo/configuration", "").lstrip("/")
    dst = os.path.join(root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(body)
    if len(body) != size:
        print(f"  SHORT {rel}: got {len(body)} of {size}")
    i = eol + 1 + size
    n += 1
print(f"restored {n} files into {root}")
