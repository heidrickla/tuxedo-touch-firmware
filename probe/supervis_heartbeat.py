#!/usr/bin/env python3
"""Re-derive: can `supervis` detect a process that goes quiet?

WEBSERVER-REPLACEMENT.md §5.11 answers no, and that answer decides whether a
stage-6 cutover binary must heartbeat on `/g_mqSupervisionThreadIn`. It was
recorded as NOT INDEPENDENTLY RE-DERIVED, correctly, because the vendor
binaries are deliberately absent from this repo (`ci/checks.sh` enforces that)
so the reviewer had nothing to check it against.

A claim that cannot be executed is a claim carried on trust, and a booked flash
window is the wrong place to find that out. This makes it runnable against a
binary the operator supplies, the way `ci/test_hdr.py` takes `TUXEDO_FW_DIR`.

    python probe/supervis_heartbeat.py <rootfs>/supervis

Exits 0 only if every assertion holds. Any failure, and any assertion that
cannot be evaluated, exits non-zero -- "could not check" must never render as
"checked and fine", which is the failure this whole section exists to document.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_LDR,
                          ARM_OP_IMM, ARM_OP_REG)

from tuxelf import Elf

#: `time()` may be reached only from these. Three IPC deadlines and one log
#: timestamp; none of them is a per-app last-seen, which is what silence would
#: have to be measured against.
TIME_CALLERS = {
    "osal_SemTimedWait(sem_t*, int)",
    "osal_MqRecv(int, char*, int, int, unsigned char)",
    "osal_MqSend(int, char*, int, int)",
    "log_SupervisionText(char*)",
}
#: The 600 s housekeeping decides on these and must not read the queue.
TIMEOUT_MUST_NOT_CALL = ("MqRecv", "mq_receive", "mq_timedreceive")

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    results.append((ok, "%s%s" % (label, (" -- " + detail) if detail else "")))


def main(path: str) -> int:
    if not os.path.isfile(path):
        print("supervis_heartbeat: %s not found" % path)
        print("  Supply the vendor binary; it is deliberately not in this repo.")
        return 2
    try:
        e = Elf(path)
    except (ValueError, KeyError, struct.error) as ex:
        print("supervis_heartbeat: %s is not a readable ARM ELF (%s)" % (path, ex))
        return 2
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True

    # ⛔ WRONG BINARY IS NOT A FAILED CLAIM, and the distinction is the whole
    # point of this script. Handed some other ELF, the first version raised out
    # of tuxelf and exited 1 -- which reads as "the assertions failed", i.e.
    # "supervis CAN detect silence". It cannot mean that: nothing was examined.
    # rc=2 is "could not evaluate", rc=1 is "evaluated and the claim is false".
    # Collapsing them is the same conflation this whole section documents,
    # pointing the other way.
    for required in ("main", "SupervisTimeout(sigval)"):
        try:
            e.addr(required)
        except KeyError:
            print("supervis_heartbeat: %s has no %r -- this is not supervis."
                  % (path, required))
            print("  Nothing was checked. This is NOT evidence about the claim.")
            return 2

    # 1. The queue has exactly one reader, and it is main.
    try:
        readers = e.callers("osal_MqRecv(int, char*, int)")
        check(readers == ["main"], "queue read only by main", str(readers))
    except KeyError as ex:
        check(False, "queue reader symbol resolvable", str(ex))

    # 2. The 600 s housekeeping never reads the queue.
    try:
        calls = e.calls("SupervisTimeout(sigval)")
        leak = [c for c in calls if any(p in c for p in TIMEOUT_MUST_NOT_CALL)]
        check(not leak, "SupervisTimeout never reads the queue", str(leak))
        check(any("getProcessPid" in c for c in calls),
              "SupervisTimeout decides on process PRESENCE")
    except KeyError as ex:
        check(False, "SupervisTimeout resolvable", str(ex))

    # 3. No per-app last-seen timestamp: time() is reachable only from the four.
    try:
        tc = set(e.callers("time"))
        check(tc == TIME_CALLERS, "time() confined to IPC deadlines and logging",
              "unexpected: %s" % sorted(tc - TIME_CALLERS) if tc - TIME_CALLERS
              else "missing: %s" % sorted(TIME_CALLERS - tc))
    except KeyError as ex:
        check(False, "time() resolvable", str(ex))

    # 3b. NO INDIRECT TRANSFER INSIDE SupervisTimeout.
    #
    # EVERY assertion above rests on e.calls()/e.callers(), which walk B and BL
    # only. A jump table (`ldrls pc,[pc,rN,lsl #2]`) or a `blx reg` leaves no B
    # or BL, so those queries return a clean, confident, INCOMPLETE answer --
    # the same blindness that cut reply-layouts.py to 178 of 768 instructions
    # and that made a branch scan call main's 0xc684 unreachable when three
    # jump-table slots point straight at it.
    #
    # This binary happens to be safe: every indirect transfer in it sits in
    # std::vector internals, log_SupervisionText, log_SupervisionEvent's own
    # table, main's dispatch and __libc_csu_init, and none is in the
    # supervision decision path. "Happens to be" is not a property a checker
    # may inherit, so it is asserted. If a future supervis dispatches inside
    # SupervisTimeout, the queries above stop being trustworthy and this says
    # so instead of passing quietly.
    #
    # It is a GUARD, not a detector: it adds no negative control of its own,
    # and stays green on supervis.control because redirecting a bl introduces
    # no indirect transfer. The MqRecv redirect is still the only thing
    # proving this script can fail.
    try:
        tlo = e.addr("SupervisTimeout(sigval)")
        thi = e.end(tlo)
        toff = e.v2o(tlo)
        indirect = []
        for va in range(tlo, thi, 4):
            raw = e.d[toff + (va - tlo):toff + (va - tlo) + 4]
            ins = next(md.disasm(raw, va), None)
            if ins is None or not ins.operands:
                continue
            op0 = ins.operands[0]
            is_pc = (op0.type == ARM_OP_REG
                     and md.reg_name(op0.reg) == "pc"
                     and ins.id != ARM_INS_B)
            is_blx_reg = (ins.id == ARM_INS_BLX and op0.type == ARM_OP_REG)
            if is_pc or is_blx_reg:
                indirect.append("%x:%s" % (va, ins.mnemonic))
        check(not indirect,
              "SupervisTimeout has no indirect transfer (so the call scan is complete)",
              str(indirect))
    except (KeyError, TypeError) as ex:
        check(False, "SupervisTimeout disassemblable for the indirect check", str(ex))

    # 4. The one thread supervis creates is the camera listener, and it touches
    #    nothing supervisory. Concluding "no monitor" from a call list alone is
    #    the absence-from-a-scan trap; this bounds it.
    pc = {a for a, n in e.syms if e.dem(n).startswith("pthread_create")}
    lo = e.addr("main")
    hi = e.end(lo)
    off = e.v2o(lo)
    code = list(md.disasm(e.d[off:off + (hi - lo)], lo))
    sites, entries = 0, []
    for i, ins in enumerate(code):
        if ins.id not in (ARM_INS_BL, ARM_INS_BLX) or not ins.operands:
            continue
        if ins.operands[0].type != ARM_OP_IMM or ins.operands[0].imm not in pc:
            continue
        sites += 1
        for p in code[max(0, i - 9):i]:
            if p.id == ARM_INS_LDR and "pc" in p.op_str and p.operands[-1].mem.base:
                va = (p.address & ~3) + 8 + p.operands[-1].mem.disp
                o = e.v2o(va)
                if o is None:
                    continue
                w = struct.unpack_from("<I", e.d, o)[0]
                if e.ta <= w < e.ta + e.ts:
                    entries.append((e.name(w), ins.address))
    # ⚠ NOT "exactly one". The first version asserted sites == 1 and FAILED on
    # the live v13 binary, where P9 replaces `bl pthread_create` with
    # `mov r0,#1` at 0xc5e8 and there are ZERO sites. Zero satisfies the
    # finding MORE strongly than one, so a checker demanding one would have
    # told a future reader that the panel in service violates §5.11. The
    # property is "no thread that could monitor", not "one benign thread".
    check(sites <= 1, "main creates at most one thread", "%d site(s)" % sites)
    if sites == 0:
        check(True, "no thread at all (P9 removes the camera listener)")
    else:
        check(any("serverThreadForCamera" in n for n, _ in entries),
              "the one thread is the camera listener", str(entries))
    for name, _ in entries:
        try:
            tc = e.calls(name)
            bad = [c for c in tc if any(k in c for k in
                                        ("MqRecv", "kill", "relaunch", "time"))]
            check(not bad, "thread touches no queue/kill/relaunch/clock", str(bad))
        except KeyError:
            pass

    width = max(len(t) for _, t in results)
    for ok, text in results:
        print("  %-4s %s" % ("ok" if ok else "FAIL", text[:width]))
    failed = [t for ok, t in results if not ok]
    print()
    if failed:
        print("%d assertion(s) FAILED. §5.11's answer does not hold for this "
              "binary; a cutover binary may need a heartbeat." % len(failed))
        return 1
    print("All assertions hold: supervis has no mechanism to notice silence.")
    print("A stage-6 cutover binary does not need to heartbeat.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-4].strip())
    sys.exit(main(sys.argv[1]))
