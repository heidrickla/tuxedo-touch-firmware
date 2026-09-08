#!/usr/bin/env python3
"""Drive a /handlerequest.html command N times on ONE session, and report.

This is the driver the six latent scene leaks were waiting for. Everything
earlier failed for a reason that had nothing to do with the leaks:

  * the request needs `tokenkey` and the NUMERIC `hidSession` from
    /eventhandler.html, not the cookie's hex (httpRequest.js sendCommand);
  * authPage_service only registers the session when the GET carries `?url=`;
  * and `No_Of_Users` is 10 concurrent sessions, reaped only when the
    HttpSession dies, so A DRIVER MUST LOG IN ONCE. Re-logging exhausts the
    table and every later request answers 200 with an empty body -- see
    docs/TUXEDO-AUDIT-BUGS.md 2.4 and 2.6, where `hiddenKey == "-1"` is
    documented as "session has no slot".

So: one login, one registering GET, scrape the two values, then loop. Refuses to
run if the session did not get a slot, because a run without one measures the
bail-out and looks exactly like "no leak".

    python3 scenedrive.py <host> <panel-user> <cmd> <n> [extra=params]

Reports the status/size distribution, which is what distinguishes a real
measurement from N identical empty replies.
"""
import collections
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
CMD = sys.argv[3] if len(sys.argv) > 3 else "141"
N = int(sys.argv[4]) if len(sys.argv) > 4 else 200
EXTRA = sys.argv[5] if len(sys.argv) > 5 else "sceneid=1"
if not USER:
    raise SystemExit("usage: scenedrive.py <host> <panel-user> <cmd> <n> [extra]")
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()

probe = TuxedoProbe(HOST, USER, password, scheme="http")
probe.login()
ck = {"Cookie": probe.session_cookie}
probe._open(probe.base + "/authenticated/index.html?url=home.html", headers=ck)
_s, _h, body = probe._open(probe.base + "/eventhandler.html", headers=ck)
body = body or b""
hid = re.search(rb'hidSession" value="([^"]*)', body)
key = re.search(rb'hiddenKey" value="([^"]*)', body)
hid = hid.group(1).decode() if hid else ""
key = key.group(1).decode() if key else ""

print("  hidSession=%s  hiddenKey=%s" % (hid, key[:12] + "..." if key else "(none)"))
if not re.fullmatch(r"[0-9a-f]{31}", key or ""):
    raise SystemExit(
        "ABORT: hiddenKey is %r, so this session has no slot. Ten slots exist and "
        "they are reaped only when the HttpSession dies (10 min idle). Wait for "
        "them to expire or restart the server; do NOT just retry, because every "
        "request would answer 200 with an empty body and read as no leak." % key)

base = {"pID": "-1", "uCode": "0", "sessionid": hid, "filters": "0",
        "index": "0", "tarTemp": "0", "tokenkey": key}
for k, v in urllib.parse.parse_qsl(EXTRA, keep_blank_values=True):
    base[k] = v

statuses = collections.Counter()
sizes = collections.Counter()
t0 = time.monotonic()
for i in range(N):
    params = dict(base, cmd=str(CMD), Type=str(CMD), sid="0.%d" % i)
    st, _hh, b = probe._open(
        probe.base + "/handlerequest.html?" + urllib.parse.urlencode(params),
        headers=ck)
    statuses[st] += 1
    sizes[len(b or b"")] += 1

dt = time.monotonic() - t0
print("  drove %d x cmd=%s (%s) in %.1fs" % (N, CMD, EXTRA, dt))
print("  statuses: %s" % dict(statuses))
print("  body sizes: %s" % dict(sizes))
if len(sizes) == 1 and 0 in sizes:
    print("  WARNING: every reply was empty -- that is the bail-out, not a result.")
