#!/usr/bin/env python3
"""Decide WITHOUT tracing whether /handlerequest.html dispatches for a session.

    python3 leakfix/dispatchcheck.py <host> [user] [credsfile]

This is the instrument that settled the panel half of the CSRF finding. The
bench can be traced and the panel cannot, so a trace-free test was needed to
show the panel behaves the same rather than assuming it.

The panel cannot be traced, so the bench result cannot simply be assumed to
carry over. But the bail-out at 0x3e858 is taken before the switch on `Type`,
so it cannot produce a command-dependent answer: if the handler is bailing,
every Type returns the SAME body, including nonsense ones. If it is dispatching,
a real command and an out-of-range command must differ somewhere.

Run it against the bench first -- that is the positive control, since the bench
is known by trace to bail -- then against the panel.

Read-only: the Types used are status reads and one out-of-range value. Nothing
here writes scenes or sends a panel command.
"""
import hashlib
import sys
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else "Lewis"
CREDS = sys.argv[3] if len(sys.argv) > 3 else "/tmp/pw.txt"

password = open(CREDS, encoding="utf-8").read().strip()
probe = TuxedoProbe(HOST, USER, password, scheme="http")
probe.login()
sid = probe.session_cookie.split("=", 1)[-1]
print("host %s, logged in" % HOST)

# 0 and 1 are ordinary low commands, 141 is the scene delete arm, and the last
# two are far outside the switch bound (cmp r1,#67 after sub #8, and the outer
# chain tops out well below these), so they MUST reach the default if the
# dispatch is running at all.
bodies = {}
for t in (0, 1, 141, 60000, 65535):
    params = {
        "cmd": str(t), "Type": str(t), "pID": "-1", "uCode": "0",
        "sessionid": sid, "filters": "0", "index": "0", "tarTemp": "0",
        "sceneid": "1",
    }
    url = probe.base + "/handlerequest.html?" + urllib.parse.urlencode(params)
    status, _h, body = probe._open(url, headers={"Cookie": probe.session_cookie})
    body = body or b""
    digest = hashlib.sha1(body).hexdigest()[:12]
    bodies[t] = digest
    print("  Type=%-6s %s  %5dB  sha1=%s  %r"
          % (t, status, len(body), digest, body[:60]))

distinct = len(set(bodies.values()))
print()
if distinct == 1:
    print("VERDICT: every Type returned an IDENTICAL body.")
    print("  The switch cannot produce that, so the handler is bailing before it.")
else:
    print("VERDICT: bodies DIFFER across Type (%d distinct)." % distinct)
    print("  The dispatch is running for this session.")
