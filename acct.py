"""What does /tuxedo actually DO with the web account store?

5.6 established that it reads and writes the file. That alone does not say
whether abandoning the store costs anything: a reader that only serves the
vendor's own account editor dies with the vendor UI, while a reader that
validates something at runtime does not.

So: who calls the five account functions, and what do those callers look like.
Tail calls are counted -- a `b` into a function is a call, and ignoring that
once put a false "dead code" claim into three documents here.
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import ARM_OP_IMM

from tuxelf import Elf

WANTED = (
    "readWebUserAccSetupJSONFile",
    "createWebUserAccSetupJSONFile",
    "encodewebUseraccJsonFile",
    "isWebUserAccSetupJSONFileEncPresent",
    "isInitWebUserAccSetupJSONFileEncPresent",
    "isWebUserAccSetupJSONFilePresent",
    "isInitWebUserAccSetupJSONFilePresent",
)


def main(path):
    elf = Elf(path)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True

    targets = {}
    for a, n in elf.syms:
        d = elf.dem(n)
        base = d.split("(")[0]
        if base in WANTED:
            targets.setdefault(a, base)

    print("targets:")
    for a, n in sorted(targets.items()):
        print("  0x%08x  %s" % (a, n))

    def name(va):
        i = bisect.bisect_right(elf.addrs, va) - 1
        if i < 0:
            return hex(va)
        return elf.dem(elf.syms[i][1])

    text = elf.d[elf.to:elf.to + elf.ts]
    callers = {}
    for i in range(0, len(text) - 3, 4):
        va = elf.ta + i
        ins = next(md.disasm(text[i:i + 4], va), None)
        if ins is None or not ins.operands:
            continue
        # bl AND b: a tail call is a call
        if ins.mnemonic not in ("bl", "blx", "b"):
            continue
        if ins.operands[0].type != ARM_OP_IMM:
            continue
        t = ins.operands[0].imm
        if t in targets:
            c = name(va)
            if c != targets[t]:
                callers.setdefault(targets[t], set()).add(c)

    print("\ncallers:")
    for fn in sorted(set(targets.values())):
        cs = sorted(callers.get(fn, ()))
        print("\n  %s" % fn)
        if not cs:
            print("     (none -- reached indirectly, or unused)")
        for c in cs:
            print("     <- %s" % c)


main("/work/extracted/root_stock/tuxedo")
