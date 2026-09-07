#!/usr/bin/env python3
"""The /Q_ServCmdRcver dispatch table, derived from what the comparisons prove
rather than from the shape of any one instruction pair.

Three methods have now been tried on this function and the first two both missed
cases:

  1. a linear scan for `cmp` + `beq` -- missed every `cmp/bne skip` form, and
     read a `bhs` search pivot as command 300;
  2. a CFG walk that carried the comparison result -- recovered 112, whose
     `beq` sits five words after its `cmp`, but still missed 126 and 128,
     which have no comparison of their own at all. gcc knows the value is
     already pinned: after `cmp #127 / beq / bhi` and `cmp #125 / beq / bls`,
     the only value left that can fall through is 126, so it just emits the
     handler.

So do not look for a shape. Carry the constraint. Each path holds an interval
and a set of excluded values for the received code; every conditional branch
narrows it on both edges. When a path leaves the comparison skeleton and starts
doing work, whatever code it is handling is whatever the constraint still
permits -- one value, or a range.

This subsumes all three forms and needs no rule per form.

VALIDATED FOR `CReceiverThread::run` ONLY. Its 84 codes were confirmed in
2026-09 by a different method -- every `cmp` whose operand IS the received
code, located by `reply-layouts.py`'s abstract interpretation. All 69 compared
constants are either in the table or a provable exclusive bound (`cmp #0x130`
gates 300-303; `cmp #0x1f8` sends everything above it to the default).

**It does NOT transfer to an arbitrary dispatcher.** Pointed at Barracuda's
`gettuxedoIPCCommFunc` with the msgType slot at `sp+0x278` it prints
overlapping intervals -- `28-50 accepted and dropped` alongside `29 bprintf`,
which cannot both hold -- and claims a handler for msgType 20, contradicting
the console-mode finding. That function has no jump table, so the cause is not
undecodable data; the walk does not fit its shape. If you need another
dispatcher's table, use the cmp-operand method instead, and check for
overlapping ranges before believing any output from this.

Usage: dispatch_tree.py <tuxedo-elf> [function] [sp-offset]
"""
import bisect
import os
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import (ARM_CC_EQ, ARM_CC_GE, ARM_CC_GT, ARM_CC_HI,
                          ARM_CC_HS, ARM_CC_LE, ARM_CC_LO, ARM_CC_LS,
                          ARM_CC_LT, ARM_CC_NE, ARM_OP_IMM, ARM_OP_REG)

TOP = 0x10000            # codes are small; a wider interval means "unpinned"
SKELETON_STR = ("str", "strb", "strh", "stm")


class Tree:
    def __init__(self, path, fname, spoff):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from tuxelf import Elf
        self.elf = Elf(path)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True
        self.start = self.elf.addr(fname)
        self.end = self.elf.end(self.start)
        self.spoff = spoff
        self.code = {}
        off = self.elf.v2o(self.start)
        self.bad = 0
        for i in range((self.end - self.start) // 4):
            va = self.start + i * 4
            ins = next(self.md.disasm(self.elf.d[off + i * 4:off + i * 4 + 4], va),
                       None)
            self.bad += ins is None
            self.code[va] = ins
        self.head = self.loop_head()

    def loop_head(self):
        tally = {}
        for ins in self.code.values():
            if ins is not None and ins.mnemonic == "b" and ins.cc in (0, 15) \
                    and ins.operands and ins.operands[0].type == ARM_OP_IMM:
                t = ins.operands[0].imm
                tally[t] = tally.get(t, 0) + 1
        return max(tally, key=tally.get) if tally else None

    def sym(self, va):
        exact = [n for a, n in self.elf.syms if a == va]
        if exact:
            return self.elf.dem(exact[0])
        i = bisect.bisect_right(self.elf.addrs, va) - 1
        base = self.elf.addrs[i] if i >= 0 else va
        return "%s+0x%x" % (self.elf.name(va), va - base)

    @staticmethod
    def sets_flags(ins):
        m = ins.mnemonic
        if m.startswith(("cmp", "cmn", "tst", "teq")):
            return True
        if m.startswith(("b", "str", "ldr", "push", "pop", "stm", "ldm")):
            return False
        return len(m) > 2 and m.endswith("s")

    def skeleton(self, ins):
        """Is this instruction still part of choosing a case, or is it the
        handler starting work? Register-to-register moves and calls are work;
        constant material and stores are not."""
        m, ops = ins.mnemonic, ins.operands
        if m.startswith(SKELETON_STR) or m.startswith(("cmp", "cmn", "tst", "teq")):
            return True
        if m.startswith("b") and m not in ("bl", "blx"):
            return True   # blo/bls/blt/ble are branches, not calls
        if m in ("mov", "movw", "movt") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
            return True
        if m in ("add", "sub", "orr") and len(ops) == 3 and ops[2].type == ARM_OP_IMM:
            return True
        if m.startswith("ldr") and len(ops) == 2 and ops[1].type not in (
                ARM_OP_IMM, ARM_OP_REG) and ops[1].mem.base:
            b = self.md.reg_name(ops[1].mem.base)
            return b in ("pc", "sp")
        return False

    @staticmethod
    def refine(lo, hi, ex, cc, k, taken):
        """Narrow the interval along one edge of a conditional branch."""
        ex = set(ex)
        if cc == ARM_CC_EQ:
            return (k, k, frozenset()) if taken else (lo, hi, frozenset(ex | {k}))
        if cc == ARM_CC_NE:
            return (lo, hi, frozenset(ex | {k})) if taken else (k, k, frozenset())
        if cc in (ARM_CC_HI, ARM_CC_GT):
            return (max(lo, k + 1), hi, frozenset(ex)) if taken \
                else (lo, min(hi, k), frozenset(ex))
        if cc in (ARM_CC_HS, ARM_CC_GE):
            return (max(lo, k), hi, frozenset(ex)) if taken \
                else (lo, min(hi, k - 1), frozenset(ex))
        if cc in (ARM_CC_LO, ARM_CC_LT):
            return (lo, min(hi, k - 1), frozenset(ex)) if taken \
                else (max(lo, k), hi, frozenset(ex))
        if cc in (ARM_CC_LS, ARM_CC_LE):
            return (lo, min(hi, k), frozenset(ex)) if taken \
                else (max(lo, k + 1), hi, frozenset(ex))
        return lo, hi, frozenset(ex)

    @staticmethod
    def pinned(lo, hi, ex):
        """The single value the constraint still permits, or None."""
        if hi < lo:
            return None
        if hi - lo > 64:
            return None
        left = [v for v in range(lo, hi + 1) if v not in ex]
        return left[0] if len(left) == 1 else None

    def run(self):
        cases, wide = {}, []
        start_state = (self.start, 0, TOP, frozenset(), (), (), None, self.start)
        stack = [start_state]
        seen = set()
        steps = 0
        while stack:
            steps += 1
            if steps > 4000000:
                raise RuntimeError("walk did not converge")
            va, lo, hi, ex, consts, disp, flag, entry = stack.pop()
            if not self.start <= va < self.end or hi < lo:
                continue
            key = (va, lo, hi, ex, consts, disp, flag)
            if key in seen:
                continue
            seen.add(key)
            ins = self.code.get(va)
            if ins is None:
                continue
            m, ops = ins.mnemonic, ins.operands

            armed = bool(disp) or flag is not None

            if armed and va == self.head:
                # a case whose whole body is "go back and receive" is still a
                # case: the panel accepts the command and does nothing. 123 and
                # 124 arrive here as a pair, so pinning is not required.
                v = self.pinned(lo, hi, ex)
                if v is not None:
                    cases.setdefault(v, (entry, "accepted and dropped", None))
                elif hi - lo <= 64:
                    left = tuple(x for x in range(lo, hi + 1) if x not in ex)
                    if left:
                        wide.append((left, entry))
                continue

            if armed and not self.skeleton(ins):
                v = self.pinned(lo, hi, ex)
                if v is not None:
                    cases.setdefault(v, (entry,) + self.body(entry))
                else:
                    left = tuple(v for v in range(lo, min(hi, lo + 64) + 1)
                                 if v not in ex)
                    # a bounded run of codes sharing one handler is a case too:
                    # 300..303 all reach sltSceneExecute through a range test,
                    # which is why publishing 300 from its `bhs` and then
                    # withdrawing it were both wrong
                    if left and hi - lo <= 64:
                        wide.append((left, entry))
                continue

            c, d = dict(consts), set(disp)
            if m.startswith("ldr") and len(ops) == 2 and ops[1].type not in (
                    ARM_OP_IMM, ARM_OP_REG) and ops[1].mem.base \
                    and self.md.reg_name(ops[1].mem.base) in ("sp", "pc"):
                c.pop(ops[0].reg, None)
                d.discard(ops[0].reg)
                if self.md.reg_name(ops[1].mem.base) == "pc":
                    # the codes too large for an ARM immediate live in the
                    # literal pool and are compared register to register
                    v = self.poolval(va, ins)
                    if v is not None:
                        c[ops[0].reg] = v
                elif ops[1].mem.disp == self.spoff:
                    d.add(ops[0].reg)
            elif m in ("mov", "movw") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                c[ops[0].reg] = ops[1].imm & 0xFFFFFFFF
                d.discard(ops[0].reg)
            elif m == "movt" and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                c[ops[0].reg] = (c.get(ops[0].reg, 0) & 0xFFFF) \
                    | ((ops[1].imm & 0xFFFF) << 16)
                d.discard(ops[0].reg)
            elif m in ("add", "sub", "orr") and len(ops) == 3 \
                    and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                if ops[1].reg in c:
                    b, k = c[ops[1].reg], ops[2].imm & 0xFFFFFFFF
                    c[ops[0].reg] = {"add": b + k, "sub": b - k,
                                     "orr": b | k}[m] & 0xFFFFFFFF
                else:
                    c.pop(ops[0].reg, None)
                d.discard(ops[0].reg)
            elif m.startswith("ldr") and ops and ops[0].type == ARM_OP_REG:
                c.pop(ops[0].reg, None)
                d.discard(ops[0].reg)

            if self.sets_flags(ins):
                flag = None
                if m == "cmp" and ops and ops[0].type == ARM_OP_REG \
                        and ops[0].reg in d:
                    if ops[1].type == ARM_OP_IMM:
                        flag = ops[1].imm & 0xFFFFFFFF
                    elif ops[1].type == ARM_OP_REG and ops[1].reg in c:
                        flag = c[ops[1].reg]

            ct, dt = tuple(sorted(c.items())), tuple(sorted(d))
            if m.startswith("b") and m not in ("bl", "blx") and ops \
                    and ops[0].type == ARM_OP_IMM:
                tgt = ops[0].imm
                if ins.cc in (0, 15):
                    stack.append((tgt, lo, hi, ex, ct, dt, flag, entry))
                    continue
                if flag is None:
                    stack.append((tgt, lo, hi, ex, ct, dt, flag, tgt))
                    stack.append((va + 4, lo, hi, ex, ct, dt, flag, va + 4))
                    continue
                for taken, nxt in ((True, tgt), (False, va + 4)):
                    l2, h2, e2 = self.refine(lo, hi, ex, ins.cc, flag, taken)
                    stack.append((nxt, l2, h2, e2, ct, dt, flag, nxt))
                continue
            if m == "bx" or (m == "pop" and "pc" in ins.op_str):
                continue
            stack.append((va + 4, lo, hi, ex, ct, dt, flag, entry))
        return cases, wide

    def body(self, va, limit=48):
        hops = 0
        pending = None
        for _ in range(limit):
            ins = self.code.get(va)
            if ins is None:
                return "undecodable word", None
            m = ins.mnemonic
            if m.startswith("ldr") and ins.op_str.startswith("r0, [pc,"):
                pending = self.literal(va, ins) or pending
            if m in ("bl", "blx") and ins.operands \
                    and ins.operands[0].type == ARM_OP_IMM:
                s = self.sym(ins.operands[0].imm)
                if s == "puts" and pending:
                    return 'prints "%s" and returns' % pending, s
                return s, s
            if m == "b" and ins.operands and ins.operands[0].type == ARM_OP_IMM:
                t = ins.operands[0].imm
                hops += 1
                if hops > 6 or not self.start <= t < self.end:
                    return "branches to 0x%x" % t, None
                va = t
                continue
            if m == "bx" or (m == "pop" and "pc" in ins.op_str):
                return "returns without calling", None
            va += 4
        return "no call within %d instructions" % limit, None

    def poolval(self, va, ins):
        try:
            imm = int(ins.op_str.split("#")[1].rstrip("]"), 0)
        except (IndexError, ValueError):
            return None
        off = self.elf.v2o(va + 8 + imm)
        return None if off is None else int.from_bytes(
            self.elf.d[off:off + 4], "little")

    def literal(self, va, ins):
        try:
            imm = int(ins.op_str.split("#")[1].rstrip("]"), 0)
            ptr = int.from_bytes(self.elf.d[self.elf.v2o(va + 8 + imm):][:4], "little")
            s = self.elf.d[self.elf.v2o(ptr):][:120].split(b"\x00")[0]
            return s.decode("latin-1") if s.isascii() and len(s) > 2 else None
        except Exception:
            return None


def main():
    t = Tree(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else
             "CReceiverThread::run",
             int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x2F8)
    cases, wide = t.run()

    # the arm that prints "Wrong Command from Web" is the default, not a case
    default = {v[0] for v in cases.values() if "Wrong Command" in v[1]}
    rows = {}
    for k, (entry, what, _) in cases.items():
        if entry in default:
            continue
        rows[(k, k)] = (entry, what)
    for left, entry in set(wide):
        if entry in default or not left:
            continue
        what = ("accepted and dropped" if entry == t.head
                else t.body(entry)[0])
        rows.setdefault((left[0], left[-1]), (entry, what))

    print("# 0x%x..0x%x, %d words, %d undecodable, receive loop at 0x%x"
          % (t.start, t.end, (t.end - t.start) // 4, t.bad, t.head))
    print("# default arm at %s prints \"Web:ERR:Wrong Command from Web\""
          % ", ".join(hex(a) for a in sorted(default)))
    print("# %d handled codes in %d blocks"
          % (sum(b - a + 1 for a, b in rows), len(rows)))
    print("code\tblock\thandler")
    for (a, b) in sorted(rows):
        entry, what = rows[(a, b)]
        print("%s\t0x%x\t%s" % (a if a == b else "%d-%d" % (a, b), entry, what))


main()
