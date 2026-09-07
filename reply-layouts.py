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

METHOD. Interpret the function forwards, giving every register a symbolic
pointer `(root, offset)` -- `sp`, an incoming argument, a literal-pool
constant, the result of a load, the return value of a call. Two registers point
at the same object when their roots match, and a field offset is the difference
of their offsets. The buffer is then whatever `r1` holds at the send, and a
field is any store, or any strcpy/memcpy/sprintf, whose destination shares that
root.

The first version walked backwards from the send looking for the instruction
that set `r1`, and left 33 of 78 builders unresolved. Each failure was a shape
that walk could not see, and each looked like a tidy short list rather than an
error:

* `CReceiverThread::run()` sets `r1` **12 instructions** before the send and
  the window stopped at 11 -- the fixed-distance bound TRAPS §1 warns about;
* `slthandleOKpress` builds the pointer in two steps, `add r1,sp,#0x19c0` then
  `add r1,r1,#0x3c`, and stores through other registers holding `sp+0x1000`;
* the Zwave and thermostat callbacks keep the buffer in a heap pointer and
  reload it per use, so the send reads `ldr r1,[r6]` while the stores go
  through `r3` from the same slot -- same object, different register;
* `getAllZoneListFunc` loads it with a predicated `ldrne r1,[r6,#0x244]`,
  which the walk treated as unresolvable;
* `sltTotalNoOfEventsReceived` has two sends and only the first was read.

Text fields are the other half. `strcpy`, `memcpy` and `sprintf` write through
a pointer, not a store instruction, so a store-only map shows nothing at
+0x91 for a builder that demonstrably puts a partition description there. The
pass records those calls, and remembers which function most recently received
a pointer as an out-parameter, so the source can be named: registerclient's
+0x91 comes back as `strcpy(GetPartitionDescription(out))`.

Widths come from capstone's instruction *id*, never the mnemonic text, because
`strbne`/`strheq` are the same instructions with a condition appended and a
mnemonic-keyed table silently drops every predicated store. That bug hid
registerclient's +0xb0 and +0xb8 behind a map that looked finished.

Three things it deliberately will not do, because each turns a guess into
something that reads like a finding:

* attribute a value to a function unless that call is the most recent thing to
  have set the register;
* report a store outside `[0, 0x22c)` as a field;
* report an offset without subtracting the buffer's own offset.

`registerclient` is the built-in positive control: its five fields were read by
hand before the tool existed, so a run that does not reproduce them is wrong
however complete the rest looks. `--check` reports it and exits non-zero.

    python reply-layouts.py <tuxedo-elf> [--check]
"""
import bisect
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import (ARM_CC_AL, ARM_INS_ADD, ARM_INS_AND, ARM_INS_ASR,
                          ARM_INS_BIC, ARM_INS_BL, ARM_INS_BLX, ARM_INS_EOR,
                          ARM_INS_LDM, ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRD,
                          ARM_INS_LDRH, ARM_INS_LDRSB, ARM_INS_LDRSH,
                          ARM_INS_B, ARM_INS_BX, ARM_INS_CMN, ARM_INS_CMP,
                          ARM_INS_LSL, ARM_INS_LSR, ARM_INS_MOV, ARM_INS_MOVT,
                          ARM_INS_MOVW, ARM_INS_MVN, ARM_INS_NOP, ARM_INS_ORR,
                          ARM_INS_POP, ARM_INS_PUSH, ARM_INS_STM, ARM_INS_STMDB,
                          ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRD,
                          ARM_INS_STRH, ARM_INS_SUB, ARM_INS_TEQ, ARM_INS_TST,
                          ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG)

from tuxelf import Elf

REPLY_LEN = 0x22C

STORES = {ARM_INS_STR: 4, ARM_INS_STRB: 1, ARM_INS_STRH: 2, ARM_INS_STRD: 8}
LOADS = (ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRH, ARM_INS_LDRD,
         ARM_INS_LDRSB, ARM_INS_LDRSH)
CLOBBERED = ("r0", "r1", "r2", "r3", "r12")
ARGS = ("r0", "r1", "r2", "r3")
REGS = ["r%d" % i for i in range(13)] + ["sp", "lr", "pc"]

# Arithmetic worth carrying: `GetArmingModes() & 8` is the field, and dropping
# the operation reports the raw register instead of what it means.
DERIVE = {ARM_INS_AND: "&", ARM_INS_ORR: "|", ARM_INS_EOR: "^",
          ARM_INS_BIC: "& ~", ARM_INS_LSL: "<<", ARM_INS_LSR: ">>",
          ARM_INS_ASR: ">>"}
NAMEABLE = ("ret", "load", "in", "derived")

# Their first operand is a register they only READ. Treating it as written
# destroyed the tested value one instruction before the predicated store that
# consumes it, which is exactly the `cmp r0,#0` / `strbeq r0,[sp,#0xb8]` pair
# that made registerclient's isRisSupported field read as a bare register.
NOWRITE = (ARM_INS_CMP, ARM_INS_CMN, ARM_INS_TST, ARM_INS_TEQ, ARM_INS_PUSH,
           ARM_INS_B, ARM_INS_BX, ARM_INS_NOP)

# Library functions that never write through a pointer argument, so being
# called with one says nothing about who produced its contents. Without this,
# `strlen(s)` immediately before `strcpy(dst, s)` is reported as the source of
# dst. Extend it when a wrong attribution shows up; it cannot be derived,
# because a C symbol carries no signature to read an out-parameter from.
READONLY = {"strlen", "strnlen", "strcmp", "strncmp", "strcasecmp",
            "strncasecmp", "strstr", "strchr", "strrchr", "atoi", "atol",
            "atof", "puts", "printf", "fprintf", "perror", "free", "strdup",
            "osal_Free"}

# Copies whose destination is r0. The value names the register holding the
# length where that is meaningful; strcpy's length is not knowable here.
COPIES = {"strcpy": None, "strncpy": "r2", "strcat": None, "strncat": "r2",
          "memcpy": "r2", "memmove": "r2", "sprintf": None, "snprintf": None,
          "stpcpy": None, "strlcpy": "r2"}

# What registerclient must produce; read by hand from the disassembly before
# this tool existed. See WEBSERVER-REPLACEMENT.md §5.10.
CONTROL_FN = "CReceiverThread::registerclient()"
CONTROL = {0x90: "GetCurrentPartition", 0x91: "GetPartitionDescription",
           0xB0: "GetArmingModes", 0xB2: "GetTotalPartitions",
           0xB8: "isRisSupported"}


def ptr(root, off=0):
    return (root, off)


def fresh(va, tag=""):
    return ptr(("?", va, tag))


def plain(name):
    """`strcpy@@GLIBC_2.4` -> `strcpy`, and drop a demangled parameter list so
    a field reads `GetTotalPartitions(out)` rather than
    `GetTotalPartitions(int*)(out)`. Arity is taken before this is applied."""
    name = name.split("@")[0]
    return name[:name.index("(")] if name.endswith(")") and "(" in name \
        else name


def arity(name):
    """Parameter count from the demangled signature, or None for a C symbol.

    This is what stops a stale register being read as an out-parameter.
    `GetCurrentPartition()` takes none, so `r3` still holding a pointer across
    that call is not an argument to it -- believing otherwise attributed
    registerclient's +0xb2 to the wrong function.
    """
    if not name.endswith(")"):
        return None
    depth, start = 0, None
    for i in range(len(name) - 1, -1, -1):
        c = name[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                start = i
                break
    if start is None:
        return None
    inner = name[start + 1:-1].strip()
    if not inner or inner == "void":
        return 0
    depth, n = 0, 1
    for c in inner:
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            depth -= 1
        elif c == "," and depth == 0:
            n += 1
    return n


class Layouts:
    def __init__(self, path):
        self.elf = Elf(path)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True
        self.sends, self.memsets, self.copies = set(), set(), {}
        for a, n in self.elf.syms:
            d = self.elf.dem(n)
            bare = d.split("@")[0]
            if d.startswith("osal_MqSend"):
                self.sends.add(a)
            elif bare == "memset":
                self.memsets.add(a)
            elif bare in COPIES:
                self.copies[a] = bare

    # -- helpers ----------------------------------------------------------

    def name(self, va):
        i = bisect.bisect_right(self.elf.addrs, va) - 1
        return self.elf.dem(self.elf.syms[i][1]) if i >= 0 else hex(va)

    def word(self, va):
        o = self.elf.v2o(va)
        if o is None or o + 4 > len(self.elf.d):
            return None
        return struct.unpack_from("<I", self.elf.d, o)[0]

    def cstr(self, va, limit=72):
        o = self.elf.v2o(va)
        if o is None:
            return None
        end = self.elf.d.find(b"\x00", o, o + limit)
        if end < 0:
            return None
        s = self.elf.d[o:end]
        if not s or any(c < 0x20 or c > 0x7E for c in s):
            return None
        return s.decode("ascii")

    def code(self, lo, hi):
        """Decode [lo, hi), stepping over words capstone cannot decode.

        TRAPS §1: `disasm()` STOPS at the first undecodable word, it does not
        skip it. A jump table's own entries sit in the middle of the function,
        so one bulk call returned 31 instructions of a 100-instruction
        function and everything past the table was invisible -- including a
        send site, which then showed up as unreachable.
        """
        out, va = [], lo
        while va < hi:
            o = self.elf.v2o(va)
            if o is None:
                break
            got = list(self.md.disasm(self.elf.d[o:o + (hi - va)], va))
            if not got:
                va += 4                 # data word; step over it
                continue
            out.extend(got)
            va = got[-1].address + got[-1].size + 4
        return out

    def reg(self, r):
        return self.md.reg_name(r)

    # -- finding the builders ---------------------------------------------

    def builders(self):
        """Every `osal_MqSend(fd, buf, 0x22c)`, grouped by containing function.

        All send sites are kept. sltTotalNoOfEventsReceived has two and reading
        only the first lost its second layout entirely.
        """
        out = {}
        text = self.elf.d[self.elf.to:self.elf.to + self.elf.ts]
        for i in range(0, len(text) - 3, 4):
            va = self.elf.ta + i
            ins = next(self.md.disasm(text[i:i + 4], va), None)
            if ins is None or ins.id not in (ARM_INS_BL, ARM_INS_BLX):
                continue
            if not ins.operands or ins.operands[0].type != ARM_OP_IMM:
                continue
            if ins.operands[0].imm not in self.sends:
                continue
            for k in range(1, 10):
                o = self.elf.v2o(va - 4 * k)
                p = None if o is None else next(
                    self.md.disasm(self.elf.d[o:o + 4], va - 4 * k), None)
                if p is None or not p.op_str.startswith("r2,"):
                    continue
                if p.id in (ARM_INS_MOV, ARM_INS_MOVW) and len(p.operands) == 2 \
                        and p.operands[1].type == ARM_OP_IMM \
                        and p.operands[1].imm == REPLY_LEN:
                    out.setdefault(self.name(va), []).append(va)
                break
        return out

    # -- abstract interpretation ------------------------------------------

    def memkey(self, regs, op, va):
        """Absolute symbolic pointer for a `[reg, #imm]` operand, else None."""
        if op.mem.index:
            return None
        b = self.reg(op.mem.base)
        if b == "pc":
            v = self.word((va & ~3) + 8 + op.mem.disp)
            return None if v is None else ptr(("abs",), v)
        root, off = regs.get(b, fresh(va))
        return ptr(root, off + op.mem.disp)

    def step(self, regs, ins):
        """Register transfer for one instruction. Stores change no register.

        Returns the register written, so the caller can tell an argument from a
        stale value left in r0-r3 by earlier code.
        """
        ops = ins.operands
        dst = self.reg(ops[0].reg) \
            if ops and ops[0].type == ARM_OP_REG else None

        if ins.id in (ARM_INS_BL, ARM_INS_BLX):
            tgt = ops[0].imm if ops and ops[0].type == ARM_OP_IMM else None
            for a in CLOBBERED:
                regs[a] = fresh(ins.address, a)
            regs["r0"] = ptr(("ret", plain(self.name(tgt)) if tgt else "?",
                              ins.address))
            return "r0"
        if ins.id in STORES or ins.id in (ARM_INS_STM, ARM_INS_STMDB) \
                or ins.id in NOWRITE:
            return None
        if dst == "sp":
            # Frame adjustments are prologue and epilogue only, and an early
            # return's `add sp,sp,#N` would shift every later [sp,#N] onto a
            # phantom frame. Hold sp fixed so one frame is described.
            return None
        if ins.id in LOADS and len(ops) >= 2 and ops[-1].type == ARM_OP_MEM:
            if not dst:
                return None
            k = self.memkey(regs, ops[-1], ins.address)
            if k is None:
                regs[dst] = fresh(ins.address)
            elif self.reg(ops[-1].mem.base) == "pc":
                regs[dst] = k                       # the literal's own value
            else:
                regs[dst] = ptr(("load", k[0], k[1]))
            if ins.id == ARM_INS_LDRD and len(ops) >= 3:
                regs[self.reg(ops[1].reg)] = fresh(ins.address)
            if ins.writeback:
                regs[self.reg(ops[-1].mem.base)] = fresh(ins.address)
            return dst
        if ins.id in (ARM_INS_LDM, ARM_INS_POP) and ops:
            # A `pop {r4,r5,pc}` is a return, and `pop {r4,r5,lr}` before a
            # tail-call `b` is the same epilogue: the writes belong to the
            # caller, not to the address after it. Letting one clobber
            # registers wiped buffer pointers held in callee-saved registers
            # before the send path that follows, and five builders the
            # previous tool resolved came back UNRESOLVED.
            first = 0 if ins.id == ARM_INS_POP else 1
            if any(op.type == ARM_OP_REG and self.reg(op.reg) in ("pc", "lr")
                   for op in ops[first:]):
                return None
            for op in ops[first:]:
                if op.type == ARM_OP_REG:
                    regs[self.reg(op.reg)] = fresh(ins.address)
            return None
        if not dst:
            return None
        if ins.id in DERIVE and len(ops) == 3 and ops[1].type == ARM_OP_REG \
                and ops[2].type == ARM_OP_IMM:
            inner = regs.get(self.reg(ops[1].reg), fresh(ins.address))
            regs[dst] = ptr(("derived", DERIVE[ins.id], inner, ops[2].imm)) \
                if inner[0][0] in NAMEABLE else fresh(ins.address)
        elif ins.id in (ARM_INS_MOV, ARM_INS_MOVW) and len(ops) == 2:
            if ops[1].type == ARM_OP_REG:
                regs[dst] = regs.get(self.reg(ops[1].reg), fresh(ins.address))
            elif ops[1].type == ARM_OP_IMM:
                regs[dst] = ptr(("imm",), ops[1].imm)
            else:
                regs[dst] = fresh(ins.address)
        elif ins.id == ARM_INS_MOVT and len(ops) == 2 \
                and ops[1].type == ARM_OP_IMM and regs[dst][0] == ("imm",):
            regs[dst] = ptr(("imm",), regs[dst][1] | (ops[1].imm << 16))
        elif ins.id in (ARM_INS_ADD, ARM_INS_SUB) and len(ops) == 3 \
                and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
            root, off = regs.get(self.reg(ops[1].reg), fresh(ins.address))
            regs[dst] = ptr(root, off + (ops[2].imm if ins.id == ARM_INS_ADD
                                         else -ops[2].imm))
        elif ins.id == ARM_INS_MVN and len(ops) == 2 \
                and ops[1].type == ARM_OP_IMM:
            regs[dst] = ptr(("imm",), (~ops[1].imm) & 0xFFFFFFFF)
        else:
            regs[dst] = fresh(ins.address)
        return dst

    def returns(self, ins):
        """A return: `pop {..,pc}`, `ldm sp!,{..,pc}`, `bx lr`, `mov pc,lr`."""
        ops = ins.operands
        if ins.id in (ARM_INS_POP, ARM_INS_LDM):
            first = 0 if ins.id == ARM_INS_POP else 1
            return any(o.type == ARM_OP_REG and self.reg(o.reg) == "pc"
                       for o in ops[first:])
        if ins.id == ARM_INS_BX:
            return True
        return ins.id != ARM_INS_B and bool(ops) \
            and ops[0].type == ARM_OP_REG and self.reg(ops[0].reg) == "pc"

    def table(self, ins, code, start, end):
        """Targets of a `ldrls pc,[pc,rN,lsl #2]` switch, or None.

        gcc dispatches a dense switch through a table sitting immediately
        after the instruction, and reading `ldr pc,...` as a return cut every
        case off: refreshUploadZoneList reached 178 of its 768 instructions
        and two of its sends disappeared from the map without comment. TRAPS
        §2 already says not every case has a comparison; this is that in its
        table form.
        """
        ops = ins.operands
        if ins.id not in LOADS or len(ops) < 2 or ops[0].type != ARM_OP_REG \
                or self.reg(ops[0].reg) != "pc":
            return None
        m = ops[-1]
        if m.type != ARM_OP_MEM or not m.mem.index \
                or self.reg(m.mem.base) != "pc":
            return None
        idx, n = self.reg(m.mem.index), None
        for k in range(1, 8):               # the bound comes from the cmp
            p = code.get(ins.address - 4 * k)
            if p is None:
                break
            if p.id == ARM_INS_CMP and len(p.operands) == 2 \
                    and p.operands[0].type == ARM_OP_REG \
                    and self.reg(p.operands[0].reg) == idx \
                    and p.operands[1].type == ARM_OP_IMM:
                n = p.operands[1].imm + 1
                break
        out, tbl = [], ins.address + 8
        for i in range(n if n is not None else 256):
            t = self.word(tbl + 4 * i)
            if t is None or not start <= t < end or t not in code:
                if n is None:
                    break               # no bound found; stop at the first
                continue                # word that is not a target in range
            out.append(t)
        return out

    def succs(self, ins, code, start, end):
        """Where control can actually go. `bl` falls through; `b` does not."""
        nxt = ins.address + 4
        tbl = self.table(ins, code, start, end)
        if tbl is not None:
            return tbl + ([nxt] if ins.cc != ARM_CC_AL and nxt in code else [])
        if ins.id == ARM_INS_B and ins.operands \
                and ins.operands[0].type == ARM_OP_IMM:
            out = []
            t = ins.operands[0].imm
            if start <= t < end:
                out.append(t)               # in range; otherwise a tail call
            if ins.cc != ARM_CC_AL:
                out.append(nxt)
            return [a for a in out if a in code]
        if self.returns(ins):
            return []
        return [nxt] if nxt in code else []

    def states(self, start, end):
        """Register state on entry to every REACHABLE instruction.

        A worklist to fixpoint, joining predecessors and dropping a register to
        unknown where they disagree. Reading the function linearly instead --
        which both earlier versions did -- is wrong twice over. It falls
        through an unconditional `b` into a block only a branch can reach,
        which is how two builders came back with their buffer pointer reported
        as `osal_Free()` and `CTimer2::start()`. And it decodes the literal
        pools sitting between blocks as instructions, so pool words silently
        rewrite registers. Following the edges visits neither.
        """
        code = {i.address: i for i in self.code(start, end)}
        init = {r: ptr(("in", r)) for r in REGS}
        init["sp"] = ptr(("sp",))
        entry = {start: init}
        work, budget = [start], 64 * (len(code) + 1)
        while work and budget > 0:
            budget -= 1
            a = work.pop()
            ins = code.get(a)
            if ins is None:
                continue
            out = dict(entry[a])
            self.step(out, ins)
            for b in self.succs(ins, code, start, end):
                cur = entry.get(b)
                if cur is None:
                    entry[b] = dict(out)
                    work.append(b)
                    continue
                changed = False
                for r in REGS:
                    top = ptr(("?", b, r))
                    if cur[r] != out[r] and cur[r] != top:
                        cur[r] = top        # disagreement is unknown, and the
                        changed = True      # token is stable, so this settles
                if changed:
                    work.append(b)
        return code, entry

    def trace(self, fn):
        """r1 at each send, plus every store and copy, over reachable code.

        Predication is applied unconditionally within a block, which is what
        makes a `strbne`/`strbeq` pair show up as both arms rather than one. A
        large multi-case function still pools stores from every case, so each
        field carries its store address and oversized functions are flagged.
        """
        start = self.elf.addr(fn)
        end = self.elf.end(start)
        code, entry = self.states(start, end)
        at_send, stores, copies, cleared, outp = {}, [], [], [], {}
        live = set()            # of r0-r3, those written since the last call

        for addr in sorted(entry):
            ins = code.get(addr)
            if ins is None:
                continue
            regs, ops = entry[addr], ins.operands
            if ins.id in (ARM_INS_BL, ARM_INS_BLX) and ops \
                    and ops[0].type == ARM_OP_IMM:
                tgt = ops[0].imm
                if tgt in self.sends:
                    # Only a 556-byte send is a reply. The same function sends
                    # a 0x244-byte message four instructions earlier, and
                    # recording every osal_MqSend published its fields as a
                    # layout of the reply union. r2 is checked from the
                    # dataflow, so this and the linear scan in builders() have
                    # to agree or the tripwire fires.
                    if regs["r2"] == ptr(("imm",), REPLY_LEN):
                        at_send[ins.address] = regs["r1"]
                elif tgt in self.copies:
                    copies.append((ins.address, regs["r0"], self.copies[tgt],
                                   regs["r1"], regs["r2"], ins.cc))
                elif tgt in self.memsets:
                    cleared.append((regs["r0"], regs["r2"]))
                else:
                    # Out-parameters, bounded two ways: by the demangled
                    # arity where there is one, and by whether the register
                    # was set since the previous call. Without both, a value
                    # merely still sitting in r3 is read as an argument to a
                    # function that takes none, and the field it later
                    # populates gets attributed to the wrong producer.
                    full = self.name(tgt)
                    callee, n = plain(full), arity(full)
                    for i, a in enumerate(ARGS):
                        if n is not None and i >= n:
                            break
                        if a not in live:
                            continue
                        if callee in READONLY:
                            continue
                        if regs[a][0][0] == "sp" or (
                                n is not None and regs[a][0][0] == "load"):
                            # First binding wins. A scratch buffer is filled
                            # once and then read repeatedly, so a later reader
                            # is not its producer -- overwriting reported the
                            # console payload's source as `strlen`.
                            outp.setdefault(regs[a], callee)
                live.clear()
            elif ins.id in STORES and len(ops) >= 2 \
                    and ops[-1].type == ARM_OP_MEM:
                k = self.memkey(regs, ops[-1], ins.address)
                if k is not None and ops[0].type == ARM_OP_REG:
                    stores.append((ins.address, k, STORES[ins.id],
                                   regs.get(self.reg(ops[0].reg), fresh(0)),
                                   self.reg(ops[0].reg), ins.cc))
            elif ins.id in (ARM_INS_STM, ARM_INS_STMDB) and ops \
                    and ops[0].type == ARM_OP_REG:
                root, off = regs.get(self.reg(ops[0].reg), fresh(ins.address))
                n = len(ops) - 1
                if ins.id == ARM_INS_STMDB:
                    off -= 4 * n
                for j, op in enumerate(ops[1:]):
                    if op.type != ARM_OP_REG:
                        continue
                    stores.append((ins.address, ptr(root, off + 4 * j), 4,
                                   regs.get(self.reg(op.reg), fresh(0)),
                                   self.reg(op.reg), ins.cc))
            # entry[] is the authoritative state; step a copy purely to learn
            # which register this instruction writes.
            w = self.step(dict(regs), ins)
            if w in ARGS:
                live.add(w)

        return at_send, stores, copies, cleared, outp, end - start

    # -- rendering --------------------------------------------------------

    def describe(self, p):
        root, off = p
        if root == ("sp",):
            return "sp+0x%x" % off
        if root[0] == "in":
            return "arg %s%s" % (root[1], "+0x%x" % off if off else "")
        if root[0] == "abs":
            return "*0x%x" % off
        if root[0] == "load":
            return "[%s]%s" % (self.describe((root[1], root[2])),
                               "+0x%x" % off if off else "")
        if root[0] == "ret":
            return self.call(root[1])
        if root[0] == "derived":
            return "%s %s %d" % (self.describe(root[2]), root[1], root[3])
        if root == ("imm",):
            return "#0x%x" % off
        return "?"

    @staticmethod
    def call(name):
        return name if name.endswith(")") else name + "()"

    def source(self, v, outp):
        """What a stored or copied value is, when that is knowable."""
        root, off = v
        if root == ("imm",):
            return "%d" % off
        if root[0] == "ret":
            return self.call(root[1])
        if v in outp:
            return "%s(out)" % outp[v]
        if root[0] == "load":
            # A value read back out of a buffer some function filled in is
            # that function's output; registerclient's +0xb2 is
            # GetTotalPartitions writing sp+0x24c and the byte being reloaded.
            inner = (root[1], root[2])
            if inner in outp and off == 0:
                return "%s(out)" % outp[inner]
            return self.describe(v)
        if root[0] == "abs":
            s = self.cstr(off)
            return '"%s"' % s if s else "*0x%x" % off
        if root[0] in ("in", "derived"):
            return self.describe(v)
        return None

    def layout(self, fn, expect=()):
        """(send_va, buffer, memset_confirmed, fields|None, size) per send.

        `expect` is what the linear scan found. A send the walk does not reach
        is reported, never dropped: the jump-table bug removed three of them
        and the totals still read as a complete map.
        """
        at_send, stores, copies, cleared, outp, size = self.trace(fn)
        for va in expect:
            if va not in at_send:
                at_send[va] = ptr(("unreached",))
        out = []
        for send_va, buf in sorted(at_send.items()):
            if buf[0][0] in ("?", "unreached"):
                out.append((send_va, buf, False, None, size))
                continue
            root, boff = buf
            confirmed = any(c[0] == buf and c[1] == ptr(("imm",), REPLY_LEN)
                            for c in cleared)
            fields = {}
            for addr, k, w, v, sreg, cc in stores:
                if k[0] != root or not 0 <= k[1] - boff < REPLY_LEN:
                    continue
                s = self.source(v, outp)
                what = ("= " + s) if v[0] == ("imm",) else \
                    ("<- " + (s or sreg))
                fields.setdefault((k[1] - boff, w, what), []).append((addr, cc))
            for addr, dst, cname, src, np, cc in copies:
                if dst[0] != root or not 0 <= dst[1] - boff < REPLY_LEN:
                    continue
                n = np[1] if COPIES[cname] and np[0] == ("imm",) else 0
                what = "<- %s(%s)" % (
                    cname, self.source(src, outp) or self.describe(src))
                fields.setdefault((dst[1] - boff, n, what), []).append((addr, cc))
            out.append((send_va, buf, confirmed, fields, size))
        return out


def render(L, fn, entries, sink):
    for send_va, buf, confirmed, fields, size in entries:
        sink("== %s" % fn)
        if fields is None:
            sink("   send 0x%x, %s" % (send_va, "NOT REACHED from the function"
                 " entry" if buf[0][0] == "unreached" else "buffer UNRESOLVED"))
            sink("")
            continue
        mt = [k for k in fields if k[0] == 4 and k[2].startswith("= ")]
        sink("   send 0x%x, buffer %s%s, %s" % (
            send_va, L.describe(buf),
            ", memset 0x22c confirms" if confirmed else "",
            "msgType %s" % mt[0][2][2:] if mt else "msgType not a literal here"))
        if size > 0x400:
            sink("   NOTE function is 0x%x bytes over several cases; they share"
                 % size)
            sink("        this frame, so check a field's address before using it.")
        for (off, w, what), sites in sorted(fields.items()):
            sz = {0: "str", 1: "u8 ", 2: "u16", 4: "u32", 8: "u64"}.get(
                w, "%-3d" % w)
            where = " ".join("0x%x%s" % (a, "?" if cc != ARM_CC_AL else "")
                             for a, cc in sites[:3])
            sink("     +0x%03x %s  %-38s @%s" % (off, sz, what, where))
        sink("")


def main(path, check):
    L = Layouts(path)
    bs = L.builders()
    lines, resolved, unresolved, sites, control = [], 0, 0, 0, {}
    for fn in sorted(bs):
        entries = L.layout(fn, bs[fn])
        sites += len(entries)
        for e in entries:
            if e[3] is None:
                unresolved += 1
            else:
                resolved += 1
        if fn == CONTROL_FN and entries and entries[0][3] is not None:
            # Join every row at an offset. A dict comprehension keeps only the
            # last, so a predicated pair reported one arm and the control
            # failed on a field the tool had in fact recovered.
            for k in entries[0][3]:
                control.setdefault(k[0], []).append(k[2])
        render(L, fn, entries, lines.append)

    head = [
        "# The 556-byte reply union, one layout per send site.",
        "#",
        "# Generated by reply-layouts.py; do not edit. Regenerate with:",
        "#     python reply-layouts.py <rootfs>/tuxedo --check > reply-layouts.txt",
        "#",
        "# %d builders send a %d-byte reply at %d send sites; %d layouts"
        % (len(bs), REPLY_LEN, sites, resolved),
        "# resolved, %d whose buffer could not be resolved." % unresolved,
        "#",
        "# The reply is a UNION. session at +0x00 and msgType at +0x04 hold for",
        "# every message; everything after them is per-type. registerclient puts",
        "# a partition description at +0x91 and single bytes at +0xaf..+0xb8 and",
        "# writes nothing at +0x0E, so ipc.rs's Reply::parse -- which reads text",
        "# at +0x0E -- is right for the status path it came from and wrong for a",
        "# 504.",
        "#",
        "# HOW TO READ AN ENTRY",
        "#   A field's store address follows it. `?` on an address means the",
        "#   store is predicated, so the field is written on only one path; two",
        "#   addresses against one offset are the two arms of such a pair.",
        "#   A size of `str` is a strcpy/strcat, whose length is not knowable",
        "#   statically; a number is a memcpy of that many bytes.",
        "#   `<- f(out)` means the value was produced by f writing through a",
        "#   pointer. That attribution is the first non-library call to receive",
        "#   the pointer, which is a heuristic: it is right for a scratch buffer",
        "#   filled once and read after, and can mislead for one reused twice.",
        "#   `<- rN` means the producer could not be determined -- the field is",
        "#   real, its source is not claimed.",
        "#   `msgType not a literal here` means +0x04 is not written with a",
        "#   constant in this function. The message still has a type; it arrives",
        "#   from a caller or inside a copy.",
        "#",
        "# WHAT THIS DOES NOT SHOW",
        "#   A function with several cases shares one frame across all of them,",
        "#   and stores are pooled per function, so an entry marked NOTE may",
        "#   list a field belonging to a different case. Check the address.",
        "#   Only reachable code is read, so a send with no path from the entry",
        "#   is reported as NOT REACHED rather than dropped.",
        "",
    ]
    ok = True
    if check:
        miss = [(o, w) for o, w in CONTROL.items()
                if not any(w in r for r in control.get(o, []))]
        sys.stderr.write("control %s: %d/%d fields\n" % (
            CONTROL_FN, len(CONTROL) - len(miss), len(CONTROL)))
        for o, w in sorted(miss):
            sys.stderr.write("  MISS +0x%02x expected %s, got %r\n"
                             % (o, w, control.get(o)))
        ok = not miss
    sys.stdout.write("\n".join(head + lines))
    return 0 if ok else 1


if __name__ == "__main__":
    a = [x for x in sys.argv[1:] if not x.startswith("--")]
    sys.exit(main(a[0] if a else "/work/extracted/root_stock/tuxedo",
                  "--check" in sys.argv))
