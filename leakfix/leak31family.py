#!/usr/bin/env python3
"""Pick the LEAK 31 family out of the allocation census.

The family is: a REST handler that serialises with json_write and frees nothing.
setarmwithcode, setdisarmwithcode and setPartitionArmed were confirmed by reading;
this finds every sibling with the same signature so they are triaged together
rather than one measurement at a time.
"""
import re
import sys

lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().split("\n")
ROW = re.compile(r"^(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-f]{8})\s+(\S+)(.*)$")

family, other = [], []
for i, line in enumerate(lines):
    m = ROW.match(line)
    if not m:
        continue
    net, alloc, absorb, free, addr, fn, rest = m.groups()
    detail = lines[i + 1] if i + 1 < len(lines) else ""
    if "shipped fix" in rest:
        continue
    row = (int(net), addr, fn, detail.strip())
    if "json_write" in detail and int(free) == 0:
        family.append(row)
    else:
        other.append(row)

print("=== LEAK 31 family: json_write present, ZERO frees, no shipped fix ===")
for net, addr, fn, _ in sorted(family, key=lambda r: -r[0]):
    print("  net %-3d  %s  %s" % (net, addr, fn[:58]))
print("  %d functions" % len(family))

print()
print("=== other unpatched candidates, top 12 by net ===")
for net, addr, fn, detail in sorted(other, key=lambda r: -r[0])[:12]:
    print("  net %-3d  %s  %s" % (net, addr, fn[:58]))
    print("           %s" % detail[:120])
