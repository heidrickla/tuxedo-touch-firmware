#!/usr/bin/env python3
"""The §2.6 smoke test from docs/TUXEDO-AUDIT-BUGS.md, run as written.

    REST login -> GET /eventhandler.html
      (a) hiddenKey is 31 hex and NOT -1
      (b) hidSession == int(cookie[0:8], 16)
    then a Type that dispatches.

§2.4 says No_Of_Users = 10 concurrent sessions, reaped only when the HttpSession
dies (Session_Timer = 10 min), and warns: do not re-login per poll, a client that
re-logs will exhaust the table. hiddenKey == "-1" is documented at §2.6 as
"session has no slot, re-login".

That is what every earlier attempt today was hitting: dozens of logins against a
ten-slot table. So this does ONE login and nothing else.
"""
import hashlib
import os
import re
import sys
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
if not USER:
    raise SystemExit("usage: smoke26.py <host> <panel-user>")
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()

probe = TuxedoProbe(HOST, USER, password, scheme="http")
probe.login()
ck = {"Cookie": probe.session_cookie}
name, value = probe.session_cookie.split("=", 1)
print("cookie %s = %s" % (name, value[:16]))

# The registering GET: authPage_service needs the url parameter.
probe._open(probe.base + "/authenticated/index.html?url=home.html", headers=ck)

_s, _h, body = probe._open(probe.base + "/eventhandler.html", headers=ck)
body = body or b""
hid = re.search(rb'hidSession" value="([^"]*)', body)
key = re.search(rb'hiddenKey" value="([^"]*)', body)
hid = hid.group(1).decode() if hid else "?"
key = key.group(1).decode() if key else "?"

print("  hidSession = %s" % hid)
print("  hiddenKey  = %s" % key)

expect = int(value[:8], 16)
signed = expect - (1 << 32) if expect >= (1 << 31) else expect
print("  (a) hiddenKey is 31 hex, not -1 : %s"
      % ("PASS" if re.fullmatch(r"[0-9a-f]{31}", key) else "FAIL (%s)" % key))
print("  (b) hidSession == int(cookie[0:8],16) : %s   (%d or %d)"
      % ("PASS" if hid in (str(expect), str(signed)) else "FAIL", expect, signed))

digests, lengths = set(), set()
for t in (0, 141, 65535):
    params = {"cmd": str(t), "Type": str(t), "pID": "-1", "uCode": "0",
              "sessionid": hid, "filters": "0", "index": "0", "tarTemp": "0",
              "sceneid": "1", "tokenkey": key, "sid": "0.5"}
    _st, _hh, b = probe._open(
        probe.base + "/handlerequest.html?" + urllib.parse.urlencode(params),
        headers=ck)
    b = b or b""
    digests.add(hashlib.sha1(b).hexdigest()[:8])
    lengths.add(len(b))
print("  dispatch: sizes=%s  %s"
      % (sorted(lengths), "DISPATCHES" if len(digests) > 1 else "bails"))
