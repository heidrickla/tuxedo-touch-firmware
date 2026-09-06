#!/usr/bin/env python3
"""Before/after test for authenticating the push stream.

    python test-stream-auth.py --host 203.0.113.5            # anonymous checks only
    python test-stream-auth.py --host 203.0.113.5 --creds D:/temp/tuxpw.txt

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


def anon_stream(host, port, seconds=12):
    """Open the push stream with NO credential. Returns (outcome, detail)."""
    try:
        s = socket.create_connection((host, port), timeout=15)
    except Exception as e:
        return "unreachable", f"{type(e).__name__}: {e}"
    try:
        s.sendall(f"GET {PUSH} HTTP/1.1\r\nHost: {host}\r\n"
                  f"Connection: keep-alive\r\n\r\n".encode())
        s.settimeout(2.0)
        buf = b""
        t0 = time.time()
        while time.time() - t0 < seconds and len(buf) < 8192:
            try:
                d = s.recv(4096)
            except socket.timeout:
                continue
            if not d:
                break
            buf += d
        if not buf:
            return "closed-no-data", "connection accepted then closed with no body"
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        status = head.splitlines()[0] if head else "?"
        frames = re.findall(rb"statusMessageText',\[\"(.*?)\"\]", buf)
        alarm = [f for f in frames
                 if b"\xfe" in f or b"\xff" in f or b"Ready" in f or b"Secs" in f]
        if alarm:
            return "OPEN", f"{status} -- {len(frames)} frames, {len(alarm)} carrying alarm state"
        if frames:
            return "open-no-alarm-state", f"{status} -- {len(frames)} frames, none with state"
        if "401" in status or "403" in status or "302" in status:
            return "denied", status
        return "no-frames", status
    finally:
        s.close()


def authed_stream(host, cookie, port, seconds=12):
    """Same, but presenting a session cookie."""
    try:
        s = socket.create_connection((host, port), timeout=15)
    except Exception as e:
        return "unreachable", f"{type(e).__name__}: {e}"
    try:
        s.sendall(f"GET {PUSH} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
                  f"Connection: keep-alive\r\n\r\n".encode())
        s.settimeout(2.0)
        buf = b""
        t0 = time.time()
        while time.time() - t0 < seconds and len(buf) < 8192:
            try:
                d = s.recv(4096)
            except socket.timeout:
                continue
            if not d:
                break
            buf += d
        frames = re.findall(rb"statusMessageText',\[\"(.*?)\"\]", buf)
        if frames:
            return "OK", f"{len(frames)} frames"
        if not buf:
            return "BROKEN", "authenticated client got nothing -- this is the regression to fear"
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        return "BROKEN", head.splitlines()[0] if head else "no frames"
    finally:
        s.close()


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
    ap.add_argument("--creds", help="file holding the panel password (never a wrong one)")
    ap.add_argument("--save", help="write results as JSON, for before/after comparison")
    ap.add_argument("--compare", help="a previous --save file to diff against")
    args = ap.parse_args()

    results = {}
    print(f"push-stream auth test: {args.host}\n")

    print("anonymous access (no credential) -- OPEN means the exposure is present")
    for port in (80, 6280):
        outcome, detail = anon_stream(args.host, port)
        results[f"anon:{port}"] = outcome
        flag = {"OPEN": "EXPOSED", "denied": "denied (good)",
                "closed-no-data": "closed (good)"}.get(outcome, outcome)
        print(f"  port {port:<5} {flag:<18} {detail}")

    print("\nauthenticated access -- must keep working")
    if args.creds and os.path.exists(args.creds):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from tuxedo_status_probe import TuxedoProbe
        raw = open(args.creds, encoding="utf-8").read().strip().splitlines()[0]
        user, pw = raw.split(":", 1) if ":" in raw else ("Lewis", raw)
        try:
            p = TuxedoProbe(args.host, user, pw, scheme="https")
            p.login()   # one SUCCESSFUL login; a wrong one is never attempted
            outcome, detail = authed_stream(args.host, p.session_cookie, 80)
        except Exception as e:
            outcome, detail = "login-failed", f"{type(e).__name__}: {e}"
        results["authed:80"] = outcome
        print(f"  port 80    {outcome:<18} {detail}")
    else:
        results["authed:80"] = "skipped"
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
