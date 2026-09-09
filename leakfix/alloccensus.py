#!/usr/bin/env python3
"""Every function whose allocations outnumber its frees, ranked.

LEAK 31 was found by asking one function what it allocates and what it releases.
Thirty earlier sites were found the other way, by hammering an endpoint and watching
RSS, and that method has a blind spot exactly the shape of LEAK 31: arming cannot be
hammered, so it never produced a slope, and a function no instrument pointed at was
never read for frees. This asks the question of every function at once.

It is a CANDIDATE LIST, not a verdict. A function that allocates and does not free is
not necessarily leaking:

  - it may RETURN the allocation, like getRegisteredDevNodes, whose caller owns it
  - it may store it in a structure that outlives the call
  - it may hand it to something that takes ownership, like json_push_back

So the output is ranked for reading, and every entry needs the same triage the
shipped fixes got. Two of the three arm handlers in LEAK 31 were confirmed by
reading; the counts only said where to look.

    python leakfix/alloccensus.py <objdump-output>
    arm-linux-gnueabi-objdump -d Barracuda > /tmp/bd.txt

Cross-references patches.tsv when it is beside this file, so sites already fixed are
marked rather than re-reported.
"""
import collections
import os
import re
import sys

# Calls that hand back something the caller must release.
ALLOC = {
    "json_new", "json_new_a", "json_new_b", "json_new_f", "json_new_i",
    "json_parse", "json_parse_unformatted", "json_copy", "json_duplicate",
    "json_write", "json_write_formatted", "json_as_string", "json_name",
    "json_strip_white_space",
    "malloc", "calloc", "realloc", "strdup", "Base64Encode", "Base64Decode",
}
# Calls that release one.
FREE = {"json_free", "json_delete", "json_delete_all", "json_free_all", "free"}
# Calls that TAKE ownership of something already allocated, so they cancel an
# allocation without being a free.
ABSORB = {"json_push_back", "json_insert", "json_set_a", "json_set_name"}

FUNC = re.compile(r"^([0-9a-f]+) <([^>]+)>:")
CALL = re.compile(r"\bbl\s+[0-9a-f]+ <([^>@]+)(?:@plt)?>")


def patched_functions(here):
    """Function names already touched by a shipped fix, by file offset."""
    path = os.path.join(here, "..", "patches.tsv")
    offsets = set()
    if not os.path.exists(path):
        return offsets
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or "\t" not in line:
                continue
            parts = line.split("\t")
            if len(parts) > 2 and parts[2].startswith("0x"):
                try:
                    offsets.add(int(parts[2], 16) + 0x8000)   # file -> VA
                except ValueError:
                    pass
    return offsets


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    patched = patched_functions(here)

    cur, start = None, 0
    counts = collections.defaultdict(collections.Counter)
    extent = {}
    for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
        m = FUNC.match(line)
        if m:
            cur = m.group(2)
            start = int(m.group(1), 16)
            extent[cur] = [start, start]
            continue
        if cur is None:
            continue
        if line and line[0].isspace() and ":" in line[:12]:
            try:
                extent[cur][1] = int(line.split(":")[0].strip(), 16)
            except ValueError:
                pass
        c = CALL.search(line)
        if c:
            counts[cur][c.group(1)] += 1

    rows = []
    for fn, c in counts.items():
        a = sum(n for k, n in c.items() if k in ALLOC)
        f = sum(n for k, n in c.items() if k in FREE)
        ab = sum(n for k, n in c.items() if k in ABSORB)
        if a == 0 or a - ab <= f:
            continue
        lo, hi = extent.get(fn, (0, 0))
        touched = any(lo <= p <= hi for p in patched)
        rows.append((a - ab - f, a, ab, f, fn, lo, touched,
                     {k: n for k, n in c.items()
                      if k in ALLOC or k in FREE or k in ABSORB}))

    rows.sort(key=lambda r: (-r[0], r[4]))
    print("functions where allocations exceed frees: %d" % len(rows))
    print("%-5s %-5s %-5s %-5s %-9s %s" % ("net", "alloc", "absrb", "free",
                                           "addr", "function"))
    # Print ALL of them. An earlier version stopped at 40, and a second tool then
    # read that output as the complete list -- which silently dropped
    # setarmwithcode, the very function this census was written to generalise. A
    # truncated report that does not look truncated is the failure this repo keeps
    # paying for; pipe to head if the terminal is the problem.
    for net, a, ab, f, fn, lo, touched, detail in rows:
        mark = "  [has a shipped fix]" if touched else ""
        print("%-5d %-5d %-5d %-5d %08x  %s%s" % (net, a, ab, f, lo, fn[:58], mark))
        parts = ", ".join("%s x%d" % (k, v) for k, v in sorted(detail.items()))
        print("        %s" % parts[:150])
    print()
    print("Not a verdict. A function may RETURN its allocation, store it somewhere")
    print("that outlives the call, or hand it to something that takes ownership.")
    print("Read each one before calling it a leak.")


if __name__ == "__main__":
    main()
