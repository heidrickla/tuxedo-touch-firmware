#!/usr/bin/env python3
"""Resolve the E_SUPVTRD_* event enum, and which events bypass the relaunch counter.

This is load-bearing for a flash window, so it is executable rather than a
number written down once. TRAPS section 6 records that exceeding 24 relaunches
makes `supervis` stop kicking the watchdog and the panel reset in hardware --
and that four cases in `main`'s dispatch reach that disarm path DIRECTLY,
spending no budget at all. Which four they are decides whether a stage-6
cutover binary is anywhere near them.

    python probe/supervis_events.py <rootfs>/supervis

Exits 0 only if the mapping resolves. Anything it cannot evaluate exits 2:
"could not check" must not read as "checked and fine".

TWO INDEXING CONVENTIONS, AND MIXING THEM INVERTS THE ANSWER
------------------------------------------------------------
`main` does `sub r3, r1, #1` before its dispatch, so main case k is enum value
k+1. `log_SupervisionEvent` dispatches on r0 with no subtraction, so its case k
IS enum value k. Both are checked below rather than assumed, because an
off-by-one here relabels every event.

DO NOT READ THE MAPPING OFF THE LITERAL POOL
--------------------------------------------
There is a run of 17 E_SUPVTRD_* string pointers at 0xbc90 that looks exactly
like an ordered lookup table. It is a literal pool inside
`log_SupervisionEvent`, laid out in order of first use, and it SKIPS every case
that shares the default handler. Indexing it by enum value produces a mapping
that is right for the first two entries and wrong from there on -- which is the
worst kind of wrong, because it looks correct where you check it. The mapping
below comes from control flow: each case's table entry, followed to its handler,
followed to the string that handler loads.
"""
from __future__ import annotations

import struct
import sys

#: Exit 2, never 1, for everything this cannot evaluate. `sys.exit("text")`
#: exits 1, which is the code for "evaluated, and the answer is no" -- the exact
#: conflation probe/supervis_heartbeat.py was rewritten to remove, and it was
#: reintroduced here in the first draft of this file. There is no rc=1 outcome
#: in this script: the mapping either resolves or it does not.
def cannot(msg: str) -> "None":
    print("supervis_events: %s" % msg)
    print("  Nothing was concluded. This is NOT a statement about the events.")
    raise SystemExit(2)


try:
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
except ImportError:
    cannot("needs capstone (pip install capstone)")

#: log_SupervisionEvent's dispatch: bound, table base, case count.
LOG_BOUND, LOG_TABLE, LOG_CASES = 0xBB78, 0xBB84, 27
#: main's dispatch, and the two targets that matter.
MAIN_BOUND, MAIN_TABLE, MAIN_CASES = 0xC528, 0xC534, 30
COUNTER_BLOCK, DISARM_DIRECT = 0xC684, 0xC910


def load(path):
    try:
        data = open(path, "rb").read()
    except OSError as err:
        cannot("%s: %s" % (path, err))
    if data[:4] != b"\x7fELF":
        cannot("%s is not an ELF" % path)
    return data


def sections(data):
    sho = struct.unpack_from("<I", data, 0x20)[0]
    es = struct.unpack_from("<H", data, 0x2E)[0]
    n = struct.unpack_from("<H", data, 0x30)[0]
    sx = struct.unpack_from("<H", data, 0x32)[0]
    sh = lambda i: struct.unpack_from("<10I", data, sho + i * es)
    st = sh(sx)[4]
    out = {}
    for i in range(n):
        s = sh(i)
        nm = data[st + s[0]: data.index(b"\0", st + s[0])].decode()
        out[nm] = (s[3], s[4], s[5], s[1])
    return out


def main(path):
    data = load(path)
    secs = sections(data)
    if ".text" not in secs:
        cannot("no .text section")

    def off(v):
        for a, o, sz, ty in secs.values():
            if ty != 8 and a <= v < a + sz:
                return o + (v - a)
        return None

    def word(v):
        o = off(v)
        return None if o is None else struct.unpack_from("<I", data, o)[0]

    def evstr(v):
        o = off(v)
        if o is None:
            return None
        try:
            s = data[o:data.index(b"\0", o)].decode()
        except (UnicodeDecodeError, ValueError):
            return None
        return s if s.startswith("E_SUPVTRD") else None

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def ins(a):
        o = off(a)
        if o is None:
            return None
        g = list(md.disasm(data[o:o + 4], a))
        return g[0] if g else None

    # Convention check, both dispatches, before anything is labelled.
    log_disp = ins(LOG_BOUND + 4)
    main_sub = ins(MAIN_BOUND - 4)
    if not log_disp or "pc" not in log_disp.op_str:
        cannot("no dispatch at 0x%05x; not this build" % (LOG_BOUND + 4))
    if not main_sub or main_sub.mnemonic != "sub":
        cannot("main does not subtract before its dispatch here, so the +1 "
               "convention is not established")
    print("conventions, checked not assumed:")
    print("  main   0x%05x  %-6s %s   -> main case k == enum value k+1"
          % (MAIN_BOUND - 4, main_sub.mnemonic, main_sub.op_str))
    print("  logger 0x%05x  %-6s %s   -> logger case k == enum value k"
          % (LOG_BOUND + 4, log_disp.mnemonic, log_disp.op_str))
    print()

    names = {}
    for k in range(LOG_CASES):
        tgt = word(LOG_TABLE + k * 4)
        if tgt is None:
            continue
        for a in range(tgt, tgt + 0x40, 4):
            i = ins(a)
            if not i:
                break
            if i.mnemonic.startswith("ldr") and "[pc" in i.op_str:
                try:
                    disp = int(i.op_str.split("#")[-1].rstrip("]"), 0)
                    s = evstr(word(a + 8 + disp))
                except (ValueError, TypeError):
                    s = None
                if s:
                    names[k] = s
                    break
            if i.mnemonic in ("b", "bx", "pop"):
                break

    print("event enum, resolved through each handler:")
    for k in sorted(names):
        print("  %-2d  %s" % (k, names[k]))
    print("  (cases with no string share the default handler and are not events)")
    print()

    counter, direct = [], []
    for k in range(MAIN_CASES):
        t = word(MAIN_TABLE + k * 4)
        if t == COUNTER_BLOCK:
            counter.append(k)
        elif t == DISARM_DIRECT:
            direct.append(k)

    print("main cases reaching the RELAUNCH COUNTER at 0x%05x: %s" % (COUNTER_BLOCK, counter))
    for k in counter:
        print("     case %-2d = value %-2d  %s" % (k, k + 1, names.get(k + 1, "<no label>")))
    print()
    print("main cases reaching the DISARM DIRECTLY at 0x%05x, spending no budget: %s"
          % (DISARM_DIRECT, direct))
    for k in direct:
        print("     case %-2d = value %-2d  %s" % (k, k + 1, names.get(k + 1, "<no label>")))
    print()

    if not counter or not direct:
        cannot("main's dispatch does not reach both the counter and the disarm "
               "in this build")
    print("A panel reset does NOT require the 24-relaunch budget to be spent.")
    print("The direct cases disarm the watchdog timer without touching the counter.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        cannot("usage: supervis_events.py <rootfs>/supervis")
    sys.exit(main(sys.argv[1]))
