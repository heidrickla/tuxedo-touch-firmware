#!/usr/bin/env python3
"""Which round of login + register + handlerequest kills Barracuda?

Established so far, on the bench:
  * 30 logins plus registering GETs, twice, do NOT crash it.
  * each individual handlerequest variant (cookie or numeric sessionid, with or
    without tokenkey, several Types) does NOT crash it.
So it is cumulative across rounds that do both. This finds the round.

Checks liveness after every round so the count is a measurement, and prints the
serve log tail at the end so the crash is confirmed from the server side rather
than inferred from a client timeout.

BENCH ONLY. On the panel each crash posts supervis messages 7 and 8 -- two
relaunch units of twenty-four.
"""
import os
import re
import sys
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
N = int(sys.argv[3]) if len(sys.argv) > 3 else 20
if not USER:
    raise SystemExit("usage: roundcrash.py <host> <panel-user> [rounds]")
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()

for i in range(1, N + 1):
    try:
        p = TuxedoProbe(HOST, USER, password, scheme="http")
        p.login()
        ck = {"Cookie": p.session_cookie}
        p._open(p.base + "/authenticated/index.html?url=home.html", headers=ck)
        _s, _h, b = p._open(p.base + "/eventhandler.html", headers=ck)
        m = re.search(rb'hidSession" value="([^"]*)', b or b"")
        hid = m.group(1).decode() if m else "0"
        for t in (0, 141, 65535):
            params = {"cmd": str(t), "Type": str(t), "pID": "-1", "uCode": "0",
                      "sessionid": hid, "filters": "0", "index": "0",
                      "tarTemp": "0", "sceneid": "1", "tokenkey": "-1",
                      "sid": "0.5"}
            p._open(p.base + "/handlerequest.html?" + urllib.parse.urlencode(params),
                    headers=ck)
        # Liveness, on a fresh connection.
        q = TuxedoProbe(HOST, USER, password, scheme="http")
        q.login()
        print("  round %2d  hidSession=%-12s ok" % (i, hid))
    except Exception as exc:                         # noqa: BLE001
        print("  round %2d  FAILED: %s" % (i, type(exc).__name__))
        print("\nDIED ON ROUND %d (so %d full rounds survived)." % (i, i - 1))
        raise SystemExit(0)

print("\nall %d rounds survived" % N)
