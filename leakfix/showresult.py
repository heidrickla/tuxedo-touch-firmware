#!/usr/bin/env python3
"""Decrypt an API reply body, so an error says what it wants.

The reply is {"Result":"<base64 of AES-OFB ciphertext>"} using the same key the
request uses. Reading it turns "the set path bails" into the server's own sentence
about which parameter is missing.

Usage: showresult.py <endpoint> <plain-params>
"""
import json
import sys

sys.path.insert(0, "/work/fwcheck")

import base64
import hashlib
import os
import time
import urllib.parse

from tuxedo_status_probe import API_BASE_PATH, TuxedoProbe, hmac_hex


def main():
    endpoint, plain = sys.argv[1], sys.argv[2]
    password = open("/tmp/pw.txt", encoding="utf-8").read().strip()

    probe = TuxedoProbe("127.0.0.1", os.environ.get("PANEL_USER", "admin"),
                        password, scheme="https")
    probe.login()
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
    status, _h, body = probe._open(url, data=payload, headers={
        "authtoken": token,
        "identity": probe.iv_hex,
        "Cookie": probe.session_cookie,
        "Content-Type": "application/x-www-form-urlencoded",
    })

    print("status  : %s" % status)
    try:
        result = json.loads(body)["Result"]
    except Exception as exc:                       # noqa: BLE001
        print("body    : %r" % body[:200])
        raise SystemExit("no Result field: %s" % exc)

    for name in ("_decrypt", "decrypt"):
        fn = getattr(probe, name, None)
        if fn is None:
            continue
        try:
            print("decoded : %r" % fn(result)[:400])
            return
        except Exception as exc:                   # noqa: BLE001
            print("(%s failed: %s)" % (name, exc))
    print("raw b64 : %s" % result[:120])
    print("rawbytes: %r" % base64.b64decode(result)[:120])


if __name__ == "__main__":
    main()
