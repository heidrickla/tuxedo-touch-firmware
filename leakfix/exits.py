#!/usr/bin/env python3
"""Find serviceField exits that skip the two json_delete calls.

WnmpDir_serviceField's normal epilogue is

    29860  mov r0, r6 ; bl json_delete      <- the reply tree
    29868  mov r0, r7 ; bl json_delete      <- the request tree
    29870  mov sp, r8
    29874  sub sp, fp, #40 ; ldm sp, {...pc}

Every other exit branches to 29874, which is AFTER both deletes. Most of those
branches delete first and jump only to reach the stack teardown -- that is correct
and not a leak. The ones that do NOT are where the trees go.

Measured per call (leakfix/README.md): 0 trees for /GetSecurityStatus, 1 for
/GetSceneList, 3 for the arm handlers. So the leaking exits are reachable from some
paths and not others, and counting them by hand across 43 KB of one function is how
the earlier reading missed it.

Usage: exits.py <objdump-of-serviceField>
"""
import re
import sys

LINE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+(.*)$")
TARGET = "29874"
WINDOW = 14          # instructions to look back for the deletes


def main():
    rows = []
    for raw in open(sys.argv[1], encoding="utf-8", errors="replace"):
        m = LINE.match(raw)
        if m:
            rows.append((m.group(1), m.group(2).strip()))

    index = {addr: i for i, (addr, _) in enumerate(rows)}
    clean = dirty = 0
    print("exits that branch to 0x%s:" % TARGET)
    for i, (addr, text) in enumerate(rows):
        if not re.match(r"^b\s+%s\b" % TARGET, text):
            continue
        back = rows[max(0, i - WINDOW):i]
        deletes = sum(1 for _, t in back if "json_delete" in t)
        if deletes >= 2:
            clean += 1
        else:
            dirty += 1
            print("  0x%s  LEAKS -- only %d json_delete in the %d instructions before"
                  % (addr, deletes, WINDOW))
            for a, t in back[-6:]:
                print("        %s  %s" % (a, t))
    print()
    print("  %d exit(s) delete both trees first" % clean)
    print("  %d exit(s) do NOT" % dirty)


if __name__ == "__main__":
    main()
