#!/usr/bin/env python3
"""Log in repeatedly and report which attempt the server stops answering on.

Each iteration is a separate login plus the registering GET, which is what makes
addSessionItem run. Reports the last attempt that succeeded, so the count is a
measurement rather than "it broke at some point".

The password is always the correct one. Three WRONG submissions permanently
disable every web account on this hardware; nothing here ever varies it.
"""
import os
import sys

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
N = int(sys.argv[3]) if len(sys.argv) > 3 else 30
if not USER:
    raise SystemExit("usage: logincount.py <host> <panel-user> [rounds]")
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()

last_ok = 0
for i in range(1, N + 1):
    try:
        probe = TuxedoProbe(HOST, USER, password, scheme="http")
        probe.login()
        probe._open(probe.base + "/authenticated/index.html?url=home.html",
                    headers={"Cookie": probe.session_cookie})
        last_ok = i
    except Exception as exc:                        # noqa: BLE001
        print("attempt %d FAILED: %s" % (i, type(exc).__name__))
        print("last successful login+register: %d" % last_ok)
        raise SystemExit(0)

print("all %d logins succeeded, no crash" % N)
