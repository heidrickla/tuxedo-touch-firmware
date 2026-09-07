"""Recover the webuseraccountsenc.json schema from the code that writes it.

Decision (a) means tuxweb has to produce a file /tuxedo will read back, so the
field names and their order have to come from the writer itself rather than
from a sample -- a sample shows what happened to be set, not what is expected.

Walks createWebUserAccSetupJSONFile and readWebUserAccSetupJSONFile printing
every json_* call with whatever string constant is in flight, so the document
shape can be read off in order.
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_REG

from tuxelf import Elf

ELF = "/work/extracted/root_stock/tuxedo"


def main(fns):
    e = Elf(ELF)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True

    def nm(va):
        exact = [n for a, n in e.syms if a == va]
        if exact:
            return e.dem(exact[0])
        i = bisect.bisect_right(e.addrs, va) - 1
        return "%s+0x%x" % (e.name(va), va - e.addrs[i]) if i >= 0 else hex(va)

    def cstr(va):
        o = e.v2o(va)
        if o is None:
            return None
        s = e.d[o:o + 80].split(b"\x00")[0]
        if s and s.isascii() and all(32 <= c < 127 for c in s):
            return s.decode("latin-1")
        return None

    for fn in fns:
        start = e.addr(fn)
        end = min(e.end(start), start + 0x900)
        print("=== %s 0x%x ===" % (fn, start))
        regs = {}
        for i in range((end - start) // 4):
            va = start + i * 4
            o = e.v2o(va)
            ins = next(md.disasm(e.d[o:o + 4], va), None)
            if ins is None:
                continue
            m, ops = ins.mnemonic, ins.operands

            if m.startswith("ldr") and "[pc," in ins.op_str and ops:
                try:
                    imm = int(ins.op_str.split("#")[1].rstrip("]"), 0)
                    po = e.v2o(va + 8 + imm)
                    val = int.from_bytes(e.d[po:po + 4], "little")
                except Exception:
                    continue
                s = cstr(val)
                regs[ops[0].reg] = ("str", s) if s else ("val", val)
                continue
            if m in ("mov", "movw") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                regs[ops[0].reg] = ("imm", ops[1].imm)
                continue
            if m in ("bl", "blx") and ops and ops[0].type == ARM_OP_IMM:
                callee = nm(ops[0].imm)
                short = callee.split("(")[0]
                if short.startswith("json") or short in (
                        "aes_init", "AES_ofb", "fopen", "fwrite", "fread",
                        "strcpy", "strncpy", "memcpy", "sprintf", "snprintf"):
                    a = []
                    for r in ("r0", "r1", "r2", "r3"):
                        for reg, v in regs.items():
                            if md.reg_name(reg) == r:
                                a.append("%s=%r" % (r, v[1]))
                                break
                    print("  %08x  %-22s %s" % (va, short, "  ".join(a)))
                regs.clear()           # a call clobbers r0-r3
                continue
            if ops and ops[0].type == ARM_OP_REG and not m.startswith(
                    ("str", "cmp", "cmn", "tst", "teq", "b", "push")):
                regs.pop(ops[0].reg, None)
        print()


main(sys.argv[1:] or ["createWebUserAccSetupJSONFile"])
