"""Find the table that reaches `set`, and read the argument blocks out of it.

`set` has zero static callers, so it is reached through a function pointer.
That means a data word somewhere equals its address, and whatever surrounds
that word is the dispatch table: for a REST tier, typically the endpoint name
and the per-endpoint argument block. The command codes the last four senders
take as an argument come out of that block -- `set` does
`ldm r4, {r0,r1,r2,r3}` with r4 being its own third argument.

Prints the neighbourhood of every hit as both words and strings so the shape
can be read rather than assumed.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxelf import Elf


def main(path, symbol):
    elf = Elf(path)
    d = elf.d
    target = elf.addr(symbol)
    print("== looking for data words equal to %s = 0x%x ==" % (symbol, target))

    def sec(va):
        for n, a, o, s in elf.secs:
            if s and a <= va < a + s and n != ".bss":
                return n
        return None

    def cstr(va):
        o = elf.v2o(va)
        if o is None:
            return None
        s = d[o:o + 48].split(b"\x00")[0]
        if s and s.isascii() and all(32 <= c < 127 for c in s):
            return s.decode("latin-1")
        return None

    pat = struct.pack("<I", target)
    hits = []
    i = d.find(pat)
    while i != -1:
        va = elf.o2v(i)
        if va is not None and sec(va) in (".rodata", ".data"):
            hits.append((i, va))
        i = d.find(pat, i + 1)

    print("%d hit(s) in .rodata/.data" % len(hits))
    for off, va in hits[:6]:
        print("\n  table word at va 0x%x (%s)" % (va, sec(va)))
        # show the surrounding words, annotating anything that resolves
        base = off - 8 * 4
        for k in range(20):
            o = base + k * 4
            if o < 0 or o + 4 > len(d):
                continue
            w = struct.unpack_from("<I", d, o)[0]
            wva = elf.o2v(o)
            mark = " <<<" if o == off else "    "
            note = ""
            s = cstr(w) if w else None
            if s:
                note = "  %r" % s
            elif w and elf.v2o(w) is not None and sec(w) == ".text":
                note = "  -> %s" % elf.name(w)
            print("   %s 0x%x: %08x%s" % (mark, wva if wva else 0, w, note))


main("/work/extracted/root_stock/opt/webserver/Barracuda", "set")
