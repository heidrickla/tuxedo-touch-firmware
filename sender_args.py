#!/usr/bin/env python3
"""Which command codes does Barracuda actually send, when the code is an
argument rather than a constant?

sender_scan.py found only seven, because in most senders the code field is
written from an incoming parameter: `setarmwithcode` does
`ldr ip,[fp,#8] / str ip,[buf,#4]`, so the code is its second argument and the
value lives in the callers.

This resolves that one level up:
  1. in each function that reaches mq_send, find the store into buf+4 and
     backtrack it to the stack slot it came from;
  2. map that slot to an argument register through the `stm ip,{r0,r1,r2,r3}`
     spill every one of these functions does in its prologue;
  3. at every call site, backtrack that register to the immediate it was
     given.

Anything it cannot resolve to an immediate is printed as such rather than
dropped, because a silently short list is the failure mode this whole exercise
exists to avoid.

Usage: sender_args.py <barracuda-elf> <buffer-va>
"""
import os
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_REG

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxelf import Elf

BACK = 24


class Scan:
    def __init__(self, path, buf):
        self.elf = Elf(path)
        self.buf = buf
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True
        self.cache = {}

    def ins(self, va):
        if va not in self.cache:
            off = self.elf.v2o(va)
            self.cache[va] = None if off is None else next(
                self.md.disasm(self.elf.d[off:off + 4], va), None)
        return self.cache[va]

    def pool(self, va, ins):
        if "[pc," not in ins.op_str:
            return None
        try:
            imm = int(ins.op_str.split("#")[1].rstrip("]"), 0)
        except (IndexError, ValueError):
            return None
        off = self.elf.v2o(va + 8 + imm)
        return None if off is None else int.from_bytes(
            self.elf.d[off:off + 4], "little")

    def walk(self, start, end):
        va = start
        while va < end:
            i = self.ins(va)
            if i is not None:
                yield va, i
            va += 4

    def code_slot(self, fn):
        """Return ('imm', k) or ('slot', fp_offset) for the value stored at
        buf+4 in this function."""
        a = self.elf.addr(fn)
        end = min(self.elf.end(a), a + 0x400)
        base = None
        consts = {}
        src = {}
        out = []
        for va, i in self.walk(a, end):
            m, ops = i.mnemonic, i.operands
            if m.startswith("ldr") and self.pool(va, i) == self.buf and ops:
                base = ops[0].reg
                continue
            if m in ("mov", "movw") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                consts[ops[0].reg] = ops[1].imm & 0xFFFFFFFF
                src.pop(ops[0].reg, None)
                continue
            # gcc builds a code out of a running constant: mov ip,#0 / add ip,ip,#0x75
            if m in ("add", "sub", "orr") and len(ops) == 3                     and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM                     and ops[1].reg in consts:
                base_v = consts[ops[1].reg]
                k = ops[2].imm & 0xFFFFFFFF
                consts[ops[0].reg] = {"add": base_v + k, "sub": base_v - k,
                                      "orr": base_v | k}[m] & 0xFFFFFFFF
                src.pop(ops[0].reg, None)
                continue
            if m.startswith("ldr") and len(ops) == 2 and ops[1].type not in (
                    ARM_OP_IMM, ARM_OP_REG) and ops[1].mem.base \
                    and self.md.reg_name(ops[1].mem.base) == "fp":
                src[ops[0].reg] = ops[1].mem.disp
                consts.pop(ops[0].reg, None)
                continue
            if m == "str" and base is not None and len(ops) == 2 \
                    and ops[1].type not in (ARM_OP_IMM, ARM_OP_REG) \
                    and ops[1].mem.base == base and ops[1].mem.disp == 4:
                r = ops[0].reg
                if r in consts:
                    out.append(("imm", consts[r]))
                elif r in src:
                    out.append(("slot", src[r]))
                else:
                    out.append(("?", self.md.reg_name(r)))
                continue
            if ops and ops[0].type == ARM_OP_REG and not m.startswith(
                    ("str", "cmp", "cmn", "tst", "teq", "b", "push")):
                consts.pop(ops[0].reg, None)
                src.pop(ops[0].reg, None)
        return out

    def callers(self, fn):
        target = self.elf.addr(fn)
        out = []
        for va, i in self.walk(self.elf.ta, self.elf.ta + self.elf.ts):
            if i.mnemonic in ("bl", "blx") and i.operands \
                    and i.operands[0].type == ARM_OP_IMM \
                    and i.operands[0].imm == target:
                out.append(va)
        return out

    def arg_at(self, call_va, argno):
        """The immediate in r<argno> at a call site, if it is one."""
        want = argno
        for k in range(1, BACK + 1):
            i = self.ins(call_va - 4 * k)
            if i is None:
                continue
            ops = i.operands
            if not ops or ops[0].type != ARM_OP_REG:
                continue
            if self.md.reg_name(ops[0].reg) != "r%d" % want:
                continue
            if i.mnemonic in ("mov", "movw") and len(ops) == 2 \
                    and ops[1].type == ARM_OP_IMM:
                return ops[1].imm & 0xFFFFFFFF
            if i.mnemonic == "movt":
                continue
            if i.mnemonic.startswith(("str", "cmp", "b", "push")):
                continue
            return None
        return None


def main():
    s = Scan(sys.argv[1], int(sys.argv[2], 0))
    mq = [a for a, n in s.elf.syms if n.startswith("mq_send")]
    senders = []
    for va, i in s.walk(s.elf.ta, s.elf.ta + s.elf.ts):
        if i.mnemonic in ("bl", "blx") and i.operands \
                and i.operands[0].type == ARM_OP_IMM and i.operands[0].imm in mq:
            n = s.elf.name(va)
            if n not in senders:
                senders.append(n)

    print("# %d functions reach mq_send" % len(senders))
    print("sender\tcode_source\tcodes_seen\tcallers")
    codes = {}
    for fn in senders:
        try:
            wheres = s.code_slot(fn)
        except KeyError:
            continue
        if not wheres:
            print("%s\t-\t-\tno store into buf+4" % fn)
            continue
        for kind, v in wheres:
            if kind == "imm":
                print("%s\tconstant\t%d\t-" % (fn, v))
                codes.setdefault(v, set()).add(fn)
                continue
            if kind != "slot":
                print("%s\tregister %s\t-\tunresolved" % (fn, v))
                continue
            argno = (v - 4) // 4
            if not 0 <= argno <= 3:
                print("%s\tstack slot fp+0x%x\t-\tbeyond r0-r3" % (fn, v))
                continue
            seen, unres = set(), []
            cs = s.callers(fn)
            for c in cs:
                k = s.arg_at(c, argno)
                if k is None:
                    unres.append(s.elf.name(c))
                else:
                    seen.add(k)
                    codes.setdefault(k, set()).add(fn)
            print("%s\targ r%d (fp+0x%x)\t%s\t%d call sites%s"
                  % (fn, argno, v, ",".join(str(x) for x in sorted(seen)) or "-",
                     len(cs),
                     "; unresolved in " + ", ".join(sorted(set(unres)))
                     if unres else ""))

    print("# codes Barracuda is able to send:")
    print("code\tsenders")
    for k in sorted(codes):
        print("%d\t%s" % (k, ", ".join(sorted(codes[k]))))


main()
