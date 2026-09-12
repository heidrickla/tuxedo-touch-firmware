#!/usr/bin/env python3
"""Verify a cut-over panel from the workstation (stage 8d).

Standalone -- sockets and ssl only, no librt -- so it runs on Windows, unlike
push_capture_check.py. Every TLS connection VERIFIES the panel's certificate
against the owner root and checks the IP SAN, so a pass proves the served
certificate, not just that bytes flowed.

    python emu/stage8-verify.py --panel 10.10.52.5 --token <64 hex> \
        --ca ~/.tuxedo-ca/ca.crt [--arm-cycle <user code>]

Default checks (read-only): capabilities 200 without a token, status with the
token, push denied without / subscribed with the token, 80 -> 301. The arm
cycle is opt-in: ArmWithCode (stay) then DisarmWithCode, each expected to
answer Sucess only after the panel confirmed, with the status checked between.
It leaves the panel DISARMED and stops at the first failure.
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time

API = "/system_http_api/API_REV01"
OPEN, CLOSE, PART_HEAD = b"--EH912ZZ\r\n", b"--EH912ZZ--\r\n", b"Content-type: text/plain\r\n\r\n"
SP = b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\""

fails = 0


def ok(msg):
    print("  PASS " + msg)


def bad(msg):
    global fails
    fails += 1
    print("  FAIL " + msg)


def connect(host, port, ca, tls):
    sk = socket.create_connection((host, port), timeout=8)
    if not tls:
        return sk
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx.wrap_socket(sk, server_hostname=host)


def http(host, port, ca, tls, method, path, body=None, token=None, token_cookie=False, read_secs=6):
    hdr = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (method, path, host)
    if token and token_cookie:
        hdr += "Cookie: tuxweb_token=%s\r\n" % token
    elif token:
        hdr += "Authorization: Bearer %s\r\n" % token
    data = b""
    if body is not None:
        data = body.encode()
        hdr += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(data)
    hdr += "\r\n"
    sk = connect(host, port, ca, tls)
    sk.sendall(hdr.encode() + data)
    sk.settimeout(read_secs)
    got = bytearray()
    end = time.time() + read_secs
    try:
        while time.time() < end:
            b = sk.recv(4096)
            if not b:
                break
            got += b
    except (socket.timeout, ssl.SSLError):
        pass
    finally:
        sk.close()
    head, _, rest = bytes(got).partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin-1", "replace") if head else "(no response)"
    return status, head.decode("latin-1", "replace"), rest


def status_texts(body):
    out, i = [], 0
    while True:
        s = body.find(OPEN, i)
        if s < 0:
            break
        h = s + len(OPEN)
        if not body[h:].startswith(PART_HEAD):
            break
        ps = h + len(PART_HEAD)
        e = body.find(CLOSE, ps)
        if e < 0:
            break
        p = body[ps:e - 2]
        out.append(p[len(SP):-3] if p.startswith(SP) else p)
        i = e + len(CLOSE)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--ca", default=os.path.expanduser("~/.tuxedo-ca/ca.crt"))
    ap.add_argument("--arm-cycle", metavar="UCODE", help="opt-in: arm STAY then disarm via the API")
    a = ap.parse_args()
    H, T, CA = a.panel, a.token, os.path.expanduser(a.ca)
    if not os.path.exists(CA):
        sys.exit("no CA at %s" % CA)

    print("=== 1. GetCapabilities, no token, TLS verified against %s ===" % CA)
    try:
        st, _, body = http(H, 443, CA, True, "GET", API + "/GetCapabilities")
    except ssl.SSLError as e:
        bad("TLS: %s" % e)
        return finish()
    print("  %s  %s" % (st, body[:160].decode("latin-1", "replace")))
    try:
        caps = json.loads(body)
        ok("200 + JSON contract=%s caps=%s" % (caps.get("contract"), caps.get("capabilities"))) \
            if st.startswith("HTTP/1.1 200") and caps.get("contract") == 1 else bad("unexpected")
    except Exception as e:
        bad("not JSON: %s" % e)

    print("=== 2. GetSecurityStatus with the token ===")
    st, _, body = http(H, 443, CA, True, "GET", API + "/GetSecurityStatus", token=T)
    print("  %s  %s" % (st, body[:160].decode("latin-1", "replace")))
    try:
        j = json.loads(body)
        ok("armed=%s state=%r" % (j["armed"], j["state"])) if st.startswith("HTTP/1.1 200") else bad("status")
    except Exception as e:
        bad("status body: %s" % e)

    print("=== 3. push stream: denied without a token, subscribed with it ===")
    st, _, _ = http(H, 443, CA, True, "GET", "/SimpleDebugger.interface/G.", read_secs=3)
    ok("no token -> %s" % st) if st.startswith("HTTP/1.1 401") else bad("no token -> %s (expected 401)" % st)
    st, head, body = http(H, 443, CA, True, "GET", "/SimpleDebugger.interface/G.", token=T, token_cookie=True, read_secs=6)
    texts = status_texts(body)
    if st.startswith("HTTP/1.1 200") and "multipart/x-mixed-replace" in head and texts:
        ok("subscribed: %d parts in 6s; first: %s" % (len(texts), [t.decode("latin-1", "replace")[:40] for t in texts[:5]]))
    else:
        bad("subscribe -> %s, %d parts" % (st, len(texts)))

    print("=== 4. plain :80 -> 301 https, path preserved ===")
    st, head, _ = http(H, 80, CA, False, "GET", "/authenticated/tuxedoapi.html?url=x", read_secs=4)
    loc = next((l for l in head.split("\r\n") if l.lower().startswith("location:")), "")
    print("  %s  %s" % (st, loc))
    ok("301 to https") if st.startswith("HTTP/1.1 301") and loc.lower().startswith("location: https://") and "tuxedoapi.html?url=x" in loc else bad("redirect")

    if a.arm_cycle:
        print("=== 5. ARM STAY via the API (opt-in), confirmed by the panel ===")
        st, _, body = http(H, 443, CA, True, "POST", API + "/AdvancedSecurity/ArmWithCode",
                           body="arming=stay&pID=1&ucode=%s&operation=set" % a.arm_cycle, token=T, read_secs=12)
        print("  %s  %s" % (st, body[:160].decode("latin-1", "replace")))
        if st.startswith("HTTP/1.1 200") and b'"Sucess"' in body:
            ok("arm confirmed")
        else:
            bad("arm not confirmed -- NOT disarming automatically; check the panel")
            return finish()
        st, _, body = http(H, 443, CA, True, "GET", API + "/GetSecurityStatus", token=T)
        print("  status: %s" % body[:120].decode("latin-1", "replace"))
        ok("armed:true") if b'"armed":true' in body else bad("status did not show armed")
        time.sleep(2)
        print("=== 6. DISARM via the API, confirmed by the panel ===")
        st, _, body = http(H, 443, CA, True, "POST", API + "/AdvancedSecurity/DisarmWithCode",
                           body="pID=1&ucode=%s&operation=set" % a.arm_cycle, token=T, read_secs=12)
        print("  %s  %s" % (st, body[:160].decode("latin-1", "replace")))
        ok("disarm confirmed") if st.startswith("HTTP/1.1 200") and b'"Result":{"Result"' in body else bad("disarm not confirmed -- CHECK THE PANEL, it may be armed")
        st, _, body = http(H, 443, CA, True, "GET", API + "/GetSecurityStatus", token=T)
        print("  status: %s" % body[:120].decode("latin-1", "replace"))
        ok("armed:false -- panel left disarmed") if b'"armed":false' in body else bad("PANEL NOT DISARMED")
    return finish()


def finish():
    print()
    print("OK stage8-verify" if fails == 0 else "FAIL stage8-verify (%d)" % fails)
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
