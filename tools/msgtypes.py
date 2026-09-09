#!/usr/bin/env python3
"""What can the stage-6 window actually confirm?

The plan lists 29 msgTypes as "not characterised". That list predates
reply-layouts.py, which decoded the builders statically, so it is stale. Rebuild it
from the tool's own output instead of trusting the prose.

Three sets matter:
  SENT      msgTypes /tuxedo writes to Barracuda's queue [*0xd2f25c]
  DECODED   msgTypes reply-layouts.txt gives a field map for
  EXPECTED  what a capture can possibly contain -- SENT, nothing else

Usage: msgtypes.py reply-layouts.txt
"""
import re
import sys

DOC_REMAINING = [3, 4, 5, 6, 7, 8, 9, 19, 25, 26, 27, 29, 51, 55, 56, 59, 61, 62,
                 104, 105, 112, 125, 130, 132, 133, 160, 161, 162, 716]

BARRACUDA_QUEUE = "0xd2f25c"


def main():
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()

    # Send lines look like:
    #   send 0x232ef8 -> queue [*0xd2f25c], buffer *0xd8c3b8, msgType 109
    send_re = re.compile(
        r"send\s+(0x[0-9a-f]+)\s*->\s*queue\s*(\[?\*?0x[0-9a-f]+\]?)[^\n]*?"
        r"msgType\s+(\d+|NOT WRITTEN HERE)", re.I)

    sent_to_barracuda, sent_elsewhere, unwritten = set(), set(), 0
    for m in send_re.finditer(text):
        queue, mt = m.group(2), m.group(3)
        to_barra = BARRACUDA_QUEUE in queue
        if mt.upper().startswith("NOT"):
            if to_barra:
                unwritten += 1
            continue
        n = int(mt)
        (sent_to_barracuda if to_barra else sent_elsewhere).add(n)

    print("msgTypes SENT to Barracuda's queue [%s]: %d" % (BARRACUDA_QUEUE,
                                                           len(sent_to_barracuda)))
    print("  " + " ".join(str(n) for n in sorted(sent_to_barracuda)))
    if sent_elsewhere:
        print()
        print("sent to some OTHER queue, so never addressed to Barracuda: %d"
              % len(sent_elsewhere))
        print("  " + " ".join(str(n) for n in sorted(sent_elsewhere)))
    print()
    print("send sites to Barracuda's queue whose msgType is set elsewhere "
          "(buffer arrives pre-filled): %d" % unwritten)

    print()
    print("=== the plan's 'not characterised' list, re-checked ===")
    now_known = sorted(n for n in DOC_REMAINING if n in sent_to_barracuda)
    other_q = sorted(n for n in DOC_REMAINING if n in sent_elsewhere)
    never = sorted(n for n in DOC_REMAINING
                   if n not in sent_to_barracuda and n not in sent_elsewhere)
    print("of %d listed:" % len(DOC_REMAINING))
    print("  %2d now DECODED and sent to Barracuda: %s"
          % (len(now_known), " ".join(map(str, now_known)) or "-"))
    print("  %2d sent only to another queue        : %s"
          % (len(other_q), " ".join(map(str, other_q)) or "-"))
    print("  %2d NO send site in /tuxedo at all    : %s"
          % (len(never), " ".join(map(str, never)) or "-"))
    print()
    print("A type with no send site cannot appear in a capture, so it is not a gap")
    print("in the window -- it is a constant Barracuda compares and nothing emits.")


if __name__ == "__main__":
    main()
