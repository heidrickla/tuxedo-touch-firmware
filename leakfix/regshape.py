"""Structural view of the registered-device file. Keys and shape only, never a
value -- the file holds per-device private keys."""
import json
import re
import sys

raw = open(sys.argv[1], 'rb').read()
print("  bytes: %d" % len(raw))
print("  first 12 bytes: %r" % raw[:12])
print("  last  12 bytes: %r" % raw[-12:])
print("  brace/bracket counts: {=%d }=%d [=%d ]=%d" %
      (raw.count(b'{'), raw.count(b'}'), raw.count(b'['), raw.count(b']')))
nonascii = sum(1 for b in raw if b < 0x20 or b > 0x7e)
print("  non-printable bytes: %d" % nonascii)

# key names only
keys = re.findall(rb'"([A-Za-z0-9_]+)"\s*:', raw)
from collections import Counter
print("  key names and how often each appears:")
for k, n in Counter(k.decode() for k in keys).most_common():
    print("    %-22s %d" % (k, n))

# lenient decode: take the longest prefix that parses
dec = json.JSONDecoder()
try:
    doc, end = dec.raw_decode(raw.decode('utf-8', 'replace'))
    print("  parsed %d of %d bytes; trailing %r" % (end, len(raw), raw[end:end + 20]))
except Exception as e:
    print("  even a prefix parse failed: %s" % e)
    sys.exit(0)

def shape(d, depth=0):
    pad = "    " + "  " * depth
    if isinstance(d, dict):
        print("%s{} %d fields: %s" % (pad, len(d), sorted(d.keys())))
        for v in d.values():
            if isinstance(v, (dict, list)):
                shape(v, depth + 1)
    elif isinstance(d, list):
        print("%s[] %d entries" % (pad, len(d)))
        for e in d:
            shape(e, depth + 1)

shape(doc)
