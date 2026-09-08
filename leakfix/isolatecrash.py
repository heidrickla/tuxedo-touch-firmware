#!/usr/bin/env python3
"""Isolate which request crashed Barracuda during the fillslots run.

30 logins plus registering GETs, twice, did NOT crash it -- so the login path is
not the cause and my first inference was wrong. What fillslots did in addition
was issue /handlerequest.html with the NUMERIC hidSession as sessionid and
tokenkey=-1, for Type 0, 141 and 65535.

Tries each variable one at a time against a fresh server, checking liveness after
every request, so the answer names a specific request rather than a run.

BENCH ONLY: on the panel a crash posts supervis messages 7 and 8, i.e. two
relaunch units, and 24 of those resets the unit.
"""
import os
import re
import sys
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
if not USER:
    raise SystemExit("usage: isolatecrash.py <host> <panel-user>")
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()


def fresh():
    p = TuxedoProbe(HOST, USER, password, scheme="http")
    p.login()
    ck = {"Cookie": p.session_cookie}
    p._open(p.base + "/authenticated/index.html?url=home.html", headers=ck)
    _s, _h, b = p._open(p.base + "/eventhandler.html", headers=ck)
    m = re.search(rb'hidSession" value="([^"]*)', b or b"")
    return p, ck, (m.group(1).decode() if m else "0")


def alive(p, ck):
    try:
        s, _h, _b = p._open(p.base + "/eventhandler.html", headers=ck)
        return s == 200
    except Exception:                                # noqa: BLE001
        return False


CASES = [
    ("cookie sid, no tokenkey", "cookie", None, 141),
    ("numeric hidSession, no tokenkey", "hid", None, 141),
    ("cookie sid + tokenkey=-1", "cookie", "-1", 141),
    ("numeric hidSession + tokenkey=-1", "hid", "-1", 141),
    ("numeric hidSession + tokenkey=-1, Type=65535", "hid", "-1", 65535),
    ("numeric hidSession + tokenkey=-1, Type=0", "hid", "-1", 0),
]

for label, which, tok, typ in CASES:
    try:
        p, ck, hid = fresh()
    except Exception as exc:                         # noqa: BLE001
        print("  %-46s SERVER ALREADY DOWN (%s)" % (label, type(exc).__name__))
        break
    sid = hid if which == "hid" else p.session_cookie.split("=", 1)[-1]
    params = {"cmd": str(typ), "Type": str(typ), "pID": "-1", "uCode": "0",
              "sessionid": sid, "filters": "0", "index": "0", "tarTemp": "0",
              "sceneid": "1", "sid": "0.5"}
    if tok is not None:
        params["tokenkey"] = tok
    u = p.base + "/handlerequest.html?" + urllib.parse.urlencode(params)
    try:
        st, _h, b = p._open(u, headers=ck)
        got = "%s %dB" % (st, len(b or b""))
    except Exception as exc:                         # noqa: BLE001
        got = "request raised %s" % type(exc).__name__
    ok = alive(p, ck)
    print("  %-46s -> %-16s server %s" % (label, got, "alive" if ok else "DEAD"))
    if not ok:
        print("\nCRASHED ON: %s" % label)
        break
