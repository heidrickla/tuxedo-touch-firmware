#!/usr/bin/env python3
"""Print one famcount2 row. Kept out of the shell script because the arithmetic
needs the two registry readings parsed, and inlining that as a heredoc inside a
function that already runs under sudo was where the last version broke."""
import os
import re
import sys


def parse(s):
    n = [int(x) for x in re.findall(r"\d+", s.replace(",", ""))]
    if len(n) < 2:
        raise SystemExit("could not parse registry line: %r" % s)
    return n[0], n[1]


def main():
    b_s, b_n = parse(os.environ["BEFORE"])
    a_s, a_n = parse(os.environ["AFTER"])
    n = int(os.environ["N"])
    label = os.environ["LABEL"]
    ep = os.environ["EP"]
    st = os.environ.get("ST", "")
    ok = "200: %d" % n in st
    print("%-14s %-46s %+10.4f %+10.4f%s"
          % (label, ep, (a_s - b_s) / n, (a_n - b_n) / n,
             "" if ok else "   <- NOT all 200s: %s" % st))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
