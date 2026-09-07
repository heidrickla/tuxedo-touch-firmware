#!/usr/bin/env python3
"""Decode the 556-byte reply union by reading every builder.

§5.10 wants the payloads of the msgTypes nobody has decoded past `+0x0E`, and
the stage-6 window was going to be how we got them. It does not have to be:
the builders are all named functions in `/tuxedo` that pass `0x22c` to
`osal_MqSend`, so the layouts can be read out of the binary now, and the
window's capture becomes confirmation rather than discovery.

The reply is a UNION. `session` at +0x00 and `msg_type` at +0x04 hold for every
message; everything after depends on the type. `registerclient` puts a
partition description at +0x91 and single bytes at +0xaf..+0xb8, and nothing at
+0x0E at all. So "the reply layout" is not one thing, and this prints one map
per builder.

Method, per builder: find the `osal_MqSend(fd, buf, 0x22c)` call, recover the
register AND base offset that formed `buf`, then record every store through it.

Three things it deliberately will not do, because each would turn a guess into
something that reads like a finding:

* attribute a stored value to a function unless the value is `r0` and that call
  is the most recent thing to have set `r0`;
* report a store outside `[0, 0x22c)` as a field -- those are the prologue
  writing through `sp` before the frame exists;
* report an offset without subtracting the buffer's base, since `add r1,sp,#N`
  is common and ignoring N yields a complete, plausible, wrong layout.

    python reply-layouts.py <tuxedo-elf>
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_REG

from tuxelf import Elf

REPLY_LEN = 0x22C
WIDTH = {"str": 4, "strb": 1, "strh": 2}


class Layouts:
    def __init__(self, path):
        self.elf = Elf(path)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True
        self.sends = {
            a for a, n in self.elf.syms
            if self.elf.dem(n).startswith("osal_MqSend")
        }

    def name(self, va):
        i = bisect.bisect_right(self.elf.addrs, va) - 1
        return self.elf.dem(self.elf.syms[i][1]) if i >= 0 else hex(va)

    def ins(self, va):
        o = self.elf.v2o(va)
        if o is None:
            return None
        return next(self.md.disasm(self.elf.d[o:o + 4], va), None)

    def builders(self):
        out = {}
        text = self.elf.d[self.elf.to:self.elf.to + self.elf.ts]
        for i in range(0, len(text) - 3, 4):
            va = self.elf.ta + i
            ins = next(self.md.disasm(text[i:i + 4], va), None)
            if ins is None or ins.mnemonic not in ("bl", "blx") or not ins.operands:
                continue
            if ins.operands[0].type != ARM_OP_IMM or ins.operands[0].imm not in self.sends:
                continue
            for k in range(1, 10):
                p = self.ins(va - 4 * k)
                if p is None or not p.op_str.startswith("r2,"):
                    continue
                if p.mnemonic in ("mov", "movw") and len(p.operands) == 2 \
                        and p.operands[1].type == ARM_OP_IMM \
                        and p.operands[1].imm == REPLY_LEN:
                    out.setdefault(self.name(va), []).append(va)
                break
        return out

    def buffer_reg(self, send_va):
        """The register holding the buffer at the send, and its base offset."""
        for k in range(1, 12):
            p = self.ins(send_va - 4 * k)
            if p is None or not p.operands or p.operands[0].type != ARM_OP_REG:
                continue
            if self.md.reg_name(p.operands[0].reg) != "r1":
                continue
            if p.mnemonic == "mov" and len(p.operands) == 2 \
                    and p.operands[1].type == ARM_OP_REG:
                return self.md.reg_name(p.operands[1].reg), 0
            if p.mnemonic == "add" and len(p.operands) == 3 \
                    and p.operands[2].type == ARM_OP_IMM:
                return self.md.reg_name(p.operands[1].reg), p.operands[2].imm
            return None, 0
        return None, 0

    def layout(self, fn, send_va):
        start = self.elf.addr(fn)
        end = min(self.elf.end(start), start + 0x1200)
        reg, base = self.buffer_reg(send_va)
        if reg is None:
            return None, []

        rows = []
        r0_from = ""
        consts = {}
        va = start
        while va < end:
            i = self.ins(va)
            va += 4
            if i is None:
                continue
            if i.mnemonic in ("bl", "blx"):
                r0_from = (self.name(i.operands[0].imm)
                           if i.operands and i.operands[0].type == ARM_OP_IMM else "")
                consts.clear()
                continue
            if i.mnemonic in ("mov", "movw") and len(i.operands) == 2 \
                    and i.operands[1].type == ARM_OP_IMM:
                r = self.md.reg_name(i.operands[0].reg)
                consts[r] = i.operands[1].imm
                if r == "r0":
                    r0_from = ""
                continue
            if not i.mnemonic.startswith("str") or len(i.operands) < 2:
                continue
            m = i.operands[1]
            if m.type in (ARM_OP_IMM, ARM_OP_REG) or not m.mem.base:
                continue
            if self.md.reg_name(m.mem.base) != reg:
                continue
            # strbne / strbeq / strheq: capstone appends the condition to the
            # mnemonic, so a plain dict lookup silently drops every predicated
            # store. registerclient's +0xb0 and +0xb8 are exactly that, and
            # missing them produced a map that looked complete.
            w = WIDTH.get(i.mnemonic)
            if w is None:
                for base_m, bw in WIDTH.items():
                    if i.mnemonic.startswith(base_m) and len(i.mnemonic) == len(base_m) + 2:
                        w = bw
                        break
            if w is None:
                continue
            off = m.mem.disp - base
            if off < 0 or off >= REPLY_LEN:
                continue
            src = self.md.reg_name(i.operands[0].reg)
            rows.append((off, w, src, consts.get(src),
                         r0_from if src == "r0" else ""))
        return reg, rows


def main(path):
    L = Layouts(path)
    bs = L.builders()
    print("# %d builders send a %d-byte reply" % (len(bs), REPLY_LEN))
    print("# session is +0x00 and msgType +0x04 in all of them; the rest is")
    print("# per-type, which is why this is a union and not a struct.\n")
    unresolved = []
    for fn in sorted(bs):
        send_va = bs[fn][0]
        reg, rows = L.layout(fn, send_va)
        if not rows:
            unresolved.append(fn)
            continue
        mt = [r for r in rows if r[0] == 4 and r[3] is not None]
        print("== %s" % fn)
        print("   send 0x%x, buffer in %s, %s" % (
            send_va, reg,
            "msgType = %d" % mt[0][3] if mt else "msgType not a literal here"))
        seen = set()
        # None sorts against int and raises, which truncated the whole
        # report mid-run and left a count that looked like a result.
        for off, w, src, k, call in sorted(
                rows, key=lambda r: (r[0], r[1], r[2], r[3] is None, r[3] or 0)):
            key = (off, w, src, k)
            if key in seen:
                continue
            seen.add(key)
            sz = {1: "u8 ", 2: "u16", 4: "u32"}[w]
            what = ("= %d" % k) if k is not None else (
                "<- %s()" % call if call else "<- %s" % src)
            print("     +0x%03x %s  %s" % (off, sz, what))
        print()
    if unresolved:
        print("# %d builder(s) whose buffer could not be resolved, listed rather"
              % len(unresolved))
        print("# than dropped -- a short map that looks complete is the failure:")
        for fn in unresolved:
            print("#   %s" % fn)


main(sys.argv[1] if len(sys.argv) > 1 else "/work/extracted/root_stock/tuxedo")
