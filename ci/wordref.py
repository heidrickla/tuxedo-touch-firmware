#!/usr/bin/env python3
"""Byte-search a binary's LOADED ranges for a little-endian address word.

TRAPS section 2: objdump -d covers only executable sections here, so grepping a
disassembly cannot prove a data reference does not exist -- .rodata and .data are
absent from the dump entirely. This searches the file itself and maps every hit to
a section, ignoring hits in .symtab (which are st_value fields, not data).

Usage: wordref.py <binary> 0x693dc [0x...]
"""
import subprocess
import sys


def sections(path):
    out = subprocess.run(["arm-linux-gnueabi-readelf", "-SW", path],
                         capture_output=True, text=True).stdout
    secs = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            rest = line.split("]", 1)[1].split()
            name, _typ, addr, off, size = rest[0], rest[1], rest[2], rest[3], rest[4]
            secs.append((name, int(addr, 16), int(off, 16), int(size, 16)))
        except (IndexError, ValueError):
            continue
    return secs


def which(secs, off):
    for name, _addr, so, size in secs:
        if so <= off < so + size:
            return name
    return "?"


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    secs = sections(path)
    for arg in sys.argv[2:]:
        target = int(arg, 16)
        needle = target.to_bytes(4, "little")
        hits, pos = [], 0
        while True:
            pos = data.find(needle, pos)
            if pos < 0:
                break
            hits.append(pos)
            pos += 1
        print("0x%x: %d raw hit(s)" % (target, len(hits)))
        for h in hits:
            sec = which(secs, h)
            flag = "  <- IGNORE (symbol table)" if sec in (".symtab", ".strtab",
                                                           ".debug_info") else ""
            print("    file 0x%-8x  section %-14s%s" % (h, sec, flag))
        real = [h for h in hits if which(secs, h) not in
                (".symtab", ".strtab", ".debug_info")]
        print("    => %d hit(s) in loaded/real sections" % len(real))


if __name__ == "__main__":
    main()
