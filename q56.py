"""5.6: does /tuxedo read webuseraccountsenc.json?

The question is not whether the string is present -- a symtab or debug hit
proves nothing. It is whether an instruction materialises the string's address.

The trap, hit on the first attempt: the needle matches in the MIDDLE of the
stored string. The literal pool holds the address of the start of the
NUL-terminated string, "/opt/tuxedo/configuration/webuseraccountsenc.json",
not of the substring. Searching for the substring's address found nothing --
in Barracuda too, which definitely does read this file, and that impossible
result is the only reason the method got a second look. Walk back to the
preceding NUL first.

Barracuda is the control: it must come out referenced. If it does not, the
method is broken and any answer about /tuxedo is worthless.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxelf import Elf

NEEDLE = b"webuseraccounts"


def section_of(elf, va):
    for n, a, o, s in elf.secs:
        if s and a <= va < a + s and n != ".bss":
            return n
    return "?"


def string_start(d, off):
    """Back up to the byte after the preceding NUL."""
    s = off
    while s > 0 and d[s - 1] != 0:
        s -= 1
    return s


def main(path):
    elf = Elf(path)
    d = elf.d
    print("== %s ==" % os.path.basename(path))

    seen = {}
    i = d.find(NEEDLE)
    while i != -1:
        s = string_start(d, i)
        if s not in seen:
            end = d.index(b"\x00", s)
            seen[s] = d[s:end].decode("latin-1")
        i = d.find(NEEDLE, i + 1)

    for off in sorted(seen):
        text = seen[off]
        va = elf.o2v(off)
        if va is None:
            print("  %-52s (file 0x%x, not in a loaded section)" % (text, off))
            continue
        refs = []
        pat = va.to_bytes(4, "little")
        j = d.find(pat)
        while j != -1 and len(refs) < 8:
            rva = elf.o2v(j)
            if rva is not None:
                refs.append((j, rva, section_of(elf, rva)))
            j = d.find(pat, j + 1)
        print("  %-52s va 0x%x" % (text, va))
        if refs:
            for j, rva, rsec in refs:
                print("     referenced: literal at 0x%x (%s), in %s"
                      % (rva, rsec, elf.name(rva)))
        else:
            print("     NOT referenced: no word in the file holds this address")
    print()


for p in sys.argv[1:]:
    main(p)
