#!/usr/bin/env python3
"""Before/after test for authenticating the push stream.

    python test-stream-auth.py --host 203.0.113.5            # anonymous checks only
    python test-stream-auth.py --host 203.0.113.5 --creds D:/temp/tuxpw.txt

All FOUR listeners are exercised -- 80 and 6280 plaintext, 443 and 9443 TLS.
They share one HttpServer and one EhDir, so a gate installed at the directory
must move all four together; a split result means the model is wrong, and that
is worth catching on the first run rather than in production.

Run it BEFORE a patch to capture the baseline and AFTER to show what changed.
Without a baseline, "the stream is denied now" is indistinguishable from "the
web server is broken now", which is the failure this is meant to catch.

SAFETY, and these are constraints rather than preferences:

* It NEVER submits a wrong password. Three failed web logins disable every web
  account on stock firmware and the count survives a reflash, so the bad-password
  path is excluded by construction, not by remembering not to run it.
* It never arms or disarms.
* It only reads.

Exit status is the number of checks whose result changed in a way that looks
like breakage. A denied anonymous stream is the GOAL, not a failure, so it is
reported as such.
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time

PUSH = "/SimpleDebugger.interface/G."


# The stream is served by FOUR listeners, not two: 80 and 6280 plaintext, 443
# and 9443 TLS. They share ONE HttpServer and ONE EhDir (0x55b59c), so a gate at
# the directory covers all four -- and a result that differed between them would
# mean the model is wrong. Testing only the plaintext pair would have hidden that.
PORTS = ((80, False), (6280, False), (443, True), (9443, True))


def _ctx():
    """The panel's TLS is OpenSSL 1.0.1h. A default modern client cannot reach
    it: legacy renegotiation is refused and its ciphers sit below SECLEVEL 1."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def _stream(host, port, tls, cookie=None, seconds=12):
    """Open the push stream, with or without a session cookie.

    Returns (outcome, detail). The two directions are judged differently on
    purpose: for an anonymous client OPEN is the exposure, for an authenticated
    one anything but frames is the regression.
    """
    try:
        sk = socket.create_connection((host, port), timeout=15)
        if tls:
            sk = _ctx().wrap_socket(sk, server_hostname=host)
    except Exception as e:
        return "unreachable", f"{type(e).__name__}: {e}"
    try:
        req = f"GET {PUSH} HTTP/1.1\r\nHost: {host}\r\n"
        if cookie:
            req += f"Cookie: {cookie}\r\n"
        req += "Connection: keep-alive\r\n\r\n"
        sk.sendall(req.encode())
        sk.settimeout(2.0)
        buf = b""
        t0 = time.time()
        while time.time() - t0 < seconds and len(buf) < 8192:
            try:
                d = sk.recv(4096)
            except socket.timeout:
                continue
            except ssl.SSLError:
                break
            if not d:
                break
            buf += d
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        status = head.splitlines()[0] if head else "?"
        frames = re.findall(rb"statusMessageText',\[\"(.*?)\"\]", buf)

        if cookie:
            if frames:
                return "OK", f"{len(frames)} frames"
            if not buf:
                return "BROKEN", "authenticated client got nothing -- the regression to fear"
            return "BROKEN", status or "no frames"

        alarm = [f for f in frames
                 if b"\xfe" in f or b"\xff" in f or b"Ready" in f or b"Secs" in f]
        if not buf:
            return "closed-no-data", "accepted then closed with no body"
        if alarm:
            return "OPEN", f"{status} -- {len(frames)} frames, {len(alarm)} carrying alarm state"
        if frames:
            return "open-no-alarm-state", f"{status} -- {len(frames)} frames, none with state"
        if any(c in status for c in ("401", "403", "302")):
            return "denied", status
        return "no-frames", status
    finally:
        try:
            sk.close()
        except Exception:
            pass


def anon_stream(host, port, tls=False, seconds=12):
    return _stream(host, port, tls, None, seconds)


def authed_stream(host, cookie, port, tls=False, seconds=12):
    return _stream(host, port, tls, cookie, seconds)


def web_ui(host):
    """The panel's own web interface must still answer."""
    import http.client
    try:
        c = http.client.HTTPConnection(host, 80, timeout=15)
        c.request("GET", "/")
        r = c.getresponse()
        r.read(256)
        c.close()
        return "OK", f"HTTP {r.status}"
    except Exception as e:
        return "BROKEN", f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="203.0.113.5")
    ap.add_argument("--seconds", type=int, default=12,
                    help="how long to hold each stream open")
    ap.add_argument("--creds", help="file holding the panel password (never a wrong one)")
    ap.add_argument("--save", help="write results as JSON, for before/after comparison")
    ap.add_argument("--compare", help="a previous --save file to diff against")
    args = ap.parse_args()

    results = {}
    print(f"push-stream auth test: {args.host}\n")

    print("anonymous access (no credential) -- OPEN means the exposure is present")
    for port, tls in PORTS:
        outcome, detail = anon_stream(args.host, port, tls, args.seconds)
        results[f"anon:{port}"] = outcome
        flag = {"OPEN": "EXPOSED", "denied": "denied (good)",
                "closed-no-data": "closed (good)"}.get(outcome, outcome)
        print(f"  port {port:<5}{'tls ' if tls else '    '} {flag:<18} {detail}")

    print("\nauthenticated access -- must keep working")
    if args.creds and os.path.exists(args.creds):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from tuxedo_status_probe import TuxedoProbe
        raw = open(args.creds, encoding="utf-8").read().strip().splitlines()[0]
        user, pw = raw.split(":", 1) if ":" in raw else ("Lewis", raw)
        try:
            p = TuxedoProbe(args.host, user, pw, scheme="https")
            p.login()   # one SUCCESSFUL login; a wrong one is never attempted
            for port, tls in PORTS:
                outcome, detail = authed_stream(args.host, p.session_cookie,
                                                port, tls, args.seconds)
                results[f"authed:{port}"] = outcome
                print(f"  port {port:<5}{'tls ' if tls else '    '} {outcome:<18} {detail}")
        except Exception as e:
            for port, _ in PORTS:
                results[f"authed:{port}"] = "login-failed"
            print(f"  login-failed  {type(e).__name__}: {e}")
    else:
        for port, _ in PORTS:
            results[f"authed:{port}"] = "skipped"
        print("  skipped (no --creds); this is the check that catches a broken patch")

    print("\nthe panel's own web UI")
    outcome, detail = web_ui(args.host)
    results["webui"] = outcome
    print(f"  port 80    {outcome:<18} {detail}")

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nsaved to {args.save}")

    bad = 0
    if args.compare and os.path.exists(args.compare):
        before = json.load(open(args.compare, encoding="utf-8"))
        print("\nchange vs baseline")
        for k in sorted(set(before) | set(results)):
            b, a = before.get(k, "-"), results.get(k, "-")
            if b == "-":
                # the baseline predates the 443/9443 rows. New coverage is not
                # a regression; counting it as one would cry wolf on every run
                # until someone re-baselines.
                print(f"  {k:<14} {a}  (new coverage, no baseline)")
                continue
            if b == a:
                print(f"  {k:<14} {a}  (unchanged)")
                continue
            good = k.startswith("anon:") and b == "OPEN" and a in ("denied", "closed-no-data")
            mark = "FIXED" if good else "REGRESSION"
            if not good:
                bad += 1
            print(f"  {k:<14} {b} -> {a}   <<< {mark}")
    return bad


if __name__ == "__main__":
    sys.exit(main())
