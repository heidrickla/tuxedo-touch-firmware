#!/usr/bin/env python3
"""Print one API response body, to prove which handler answered.

famcount.sh measured +1.0000 strings per ViewIPURL call over the /GetSceneList
control. That figure only means "the ViewIPURL handler leaks one string" if the
handler actually RAN. A request rejected at parameter validation, or routed to a
generic error page, would also produce a stable per-call delta and would look
identical in the counts.

So: issue one call and show what came back. Reuses leakprobe's own TuxedoProbe so
the auth, the HMAC path binding and the payload encryption are identical to the
measured runs rather than a second implementation that might differ.

Usage: showbody.py <endpoint> <plain-params>
"""
import sys

sys.path.insert(0, "/work/fwcheck")

import os
import hashlib
import time
import urllib.parse

from tuxedo_status_probe import API_BASE_PATH, TuxedoProbe, hmac_hex


def main():
    endpoint, plain = sys.argv[1], sys.argv[2]
    password = open("/tmp/pw.txt", encoding="utf-8").read().strip()

    probe = TuxedoProbe("127.0.0.1", os.environ.get("PANEL_USER", "admin"), password, scheme="https")
    probe.login()
    if not probe.session_cookie:
        raise SystemExit("login produced no session cookie")
    probe._fetch_keys()

    url = f"{probe.base}{API_BASE_PATH}{endpoint}"
    token = hmac_hex(probe.key_hex,
                     f"MACID:Browser,Path:API_REV01{endpoint}", hashlib.sha1)
    enc = probe._encrypt(plain)
    payload = urllib.parse.urlencode({
        "param": enc,
        "len": str(len(enc)),
        "tstamp": str(int(time.time() * 1000)),
    }).encode("ascii")
    status, _headers, body = probe._open(url, data=payload, headers={
        "authtoken": token,
        "identity": probe.iv_hex,
        "Cookie": probe.session_cookie,
        "Content-Type": "application/x-www-form-urlencoded",
    })
    print("status   : %s" % status)

    print("endpoint : %s" % endpoint)
    print("params   : %s" % plain)
    print("raw body : %r" % body[:400])
    try:
        print("decrypted: %r" % probe._decrypt(body.decode().strip())[:400])
    except Exception as exc:                      # noqa: BLE001
        print("decrypted: (not decryptable as a param blob: %s)" % exc)


if __name__ == "__main__":
    main()
