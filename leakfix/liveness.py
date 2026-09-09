#!/usr/bin/env python3
"""THIS TOOL GAVE A WRONG ANSWER. Kept as a record, not as an instrument.

It reported that r7 is never reassigned on the executed path between 0x1ef0c and
0x2955c. A measurement contradicted that: with a json_delete of r7 spliced in at the
exit, libjson's node registry rose by one per request instead of staying flat, which
only happens if the erase never fired, which means the pointer was not the registered
tree. See leakfix/mkapifix.py LEAK 30, item 2.

The likely defect is block-extent reconstruction. It walks from each executed block
start to the first branch, so it cannot see instructions reached by falling into a
block whose start qemu never logged, and it treats every callee as register-preserving
because it never follows one. Either would hide a write.

Do not trust a NEGATIVE result from this ("the register is untouched") without a
measured cross-check. A POSITIVE result -- it found a write -- is still usable, since
that direction cannot be manufactured by missing coverage.

Original description follows.

Is r7 still the tree from 0x1ef04 when execution reaches 0x2955c?

WnmpDir_serviceField reassigns r7 126 times across its ~350 arms, so "r7 holds the
tree" is only true on some paths. The LEAK 30 stub deleted r7 at 0x2955c and WEDGED
the request, which is what deleting a live unrelated object looks like.

Only writes on the EXECUTED path matter. qemu's trace gives executed translation
block START addresses; a block runs until its first branch. So reconstruct each
executed block's extent from the disassembly, then look for r7 writes inside them
between the tree's creation and the exit.

Usage: liveness.py <objdump.txt> <blocks.txt>
"""
import re
import sys

TREE_SET = 0x1EF0C      # mov r7, r0  -- r7 becomes the json_new tree
EXIT = 0x2955C          # b 29874 -- the exit that skips cleanup

BRANCH = re.compile(r"\b(b|bl|bx|blx|beq|bne|bcc|bcs|blt|bgt|ble|bge|bhi|bls|"
                    r"bmi|bpl|bvs|bvc|pop|ldm)\b")
WRITES_R7 = re.compile(r"\b(mov|movw|movt|ldr|add|sub|and|orr|eor|rsb|mvn|lsl|"
                       r"lsr|asr|mul)\w*\s+r7\s*,")
LINE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(.*)$")


def main():
    dis, blocks_path = sys.argv[1], sys.argv[2]

    insns = {}
    order = []
    in_fn = False
    for line in open(dis, errors="replace"):
        if line.startswith(("0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                            "a", "b", "c", "d", "e", "f")) and "<" in line and line.rstrip().endswith(">:"):
            in_fn = "<WnmpDir_serviceField>:" in line
            continue
        if not in_fn:
            continue
        m = LINE.match(line)
        if m:
            a = int(m.group(1), 16)
            insns[a] = m.group(2)
            order.append(a)
    order.sort()
    print("serviceField instructions: %d" % len(order))

    executed = set()
    for line in open(blocks_path):
        line = line.strip()
        if line:
            try:
                executed.add(int(line, 16))
            except ValueError:
                pass
    print("executed block starts: %d" % len(executed))

    # Walk each executed block from its start to its first branch, collecting
    # the instructions that actually ran.
    ran = set()
    for start in sorted(executed):
        i = order.index(start) if start in insns else -1
        if i < 0:
            continue
        for a in order[i:]:
            ran.add(a)
            if BRANCH.search(insns[a]):
                break

    print("instructions on the executed path: %d" % len(ran))

    hits = [a for a in sorted(ran)
            if TREE_SET < a < EXIT and WRITES_R7.search(insns[a])]
    print()
    if hits:
        print("r7 IS REASSIGNED on the executed path between 0x%x and 0x%x:"
              % (TREE_SET, EXIT))
        for a in hits:
            print("  %05x  %s" % (a, insns[a]))
        print()
        print("=> r7 at the exit is NOT the tree. Deleting it is why the request wedged.")
    else:
        print("r7 is NOT reassigned on the executed path between 0x%x and 0x%x"
              % (TREE_SET, EXIT))
        print("=> r7 should still be the tree; the wedge has another cause.")


if __name__ == "__main__":
    main()
