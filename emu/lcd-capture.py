#!/usr/bin/env python3
"""Capture the keypad LCD (msgType 20) across an arm STAY -> disarm cycle.

Evidence for ha-tuxedo-touch's `changed_by` (feature spec item 3): does the
panel's display name the user on an arm or disarm, and in what exact text? The
spec says do not write a parser until real frames are pinned; this produces them.

Subscribes to the push stream with the token, records every id-20 record with a
timestamp, arms STAY through the API, waits, disarms, waits, and prints the
distinct LCD lines in order. Leaves the panel DISARMED (stops before disarming
only if the arm was not confirmed, and says so loudly). TLS verified against the
owner root; the user code is read from a file and never printed.

    python emu/lcd-capture.py --panel 10.10.52.5 --token <t> --code-file D:/temp/tuxpw.txt
"""
import argparse
import os
import socket
import ssl
import threading
import time

API = "/system_http_api/API_REV01"
OPEN, CLOSE, PART_HEAD = b"--EH912ZZ\r\n", b"--EH912ZZ--\r\n", b"Content-type: text/plain\r\n\r\n"
SP = b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\""


def connect(host, port, ca):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx.wrap_socket(socket.create_connection((host, port), timeout=8), server_hostname=host)


def http(host, ca, method, path, body=None, token=None, read_secs=12):
    hdr = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (method, path, host)
    if token:
        hdr += "Authorization: Bearer %s\r\n" % token
    data = b""
    if body is not None:
        data = body.encode()
        hdr += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(data)
    hdr += "\r\n"
    s = connect(host, 443, ca)
    s.sendall(hdr.encode() + data)
    s.settimeout(read_secs)
    got = bytearray()
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            got += b
    except (socket.timeout, ssl.SSLError):
        pass
    finally:
        s.close()
    head, _, rest = bytes(got).partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode("latin-1", "replace"), rest


def stream(host, ca, token, seconds, out, t0):
    """Subscribe and append (t, text) for every statusMessageText part."""
    s = connect(host, 443, ca)
    s.sendall(("GET /SimpleDebugger.interface/G. HTTP/1.1\r\nHost: %s\r\n"
               "Cookie: tuxweb_token=%s\r\n\r\n" % (host, token)).encode())
    s.settimeout(2)
    buf = bytearray()
    end = time.time() + seconds
    head_done = False
    while time.time() < end:
        try:
            b = s.recv(4096)
            if not b:
                break
            buf += b
        except (socket.timeout, ssl.SSLError):
            continue
        if not head_done:
            i = buf.find(b"\r\n\r\n")
            if i < 0:
                continue
            del buf[:i + 4]
            head_done = True
        while True:
            st = buf.find(OPEN)
            if st < 0:
                break
            h = st + len(OPEN)
            if not buf[h:].startswith(PART_HEAD):
                if len(buf) > h + len(PART_HEAD):
                    del buf[:h]
                break
            ps = h + len(PART_HEAD)
            e = buf.find(CLOSE, ps)
            if e < 0:
                break
            p = bytes(buf[ps:e - 2])
            del buf[:e + len(CLOSE)]
            if p.startswith(SP) and p.endswith(b'"]]'):
                out.append((time.time() - t0, p[len(SP):-3]))
    s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--ca", default=os.path.expanduser("~/.tuxedo-ca/ca.crt"))
    ap.add_argument("--code-file", required=True, help="file holding the user code; never printed")
    ap.add_argument("--settle", type=float, default=6.0, help="seconds to watch before arming")
    ap.add_argument("--armed-for", type=float, default=12.0, help="seconds to stay armed (exit delay text)")
    ap.add_argument("--after", type=float, default=20.0, help="seconds to watch after the disarm")
    a = ap.parse_args()
    ca = os.path.expanduser(a.ca)
    code = open(a.code_file).read().strip()
    if not code.isdigit():
        raise SystemExit("code file does not hold a numeric code")

    records = []
    t0 = time.time()
    total = a.settle + a.armed_for + a.after + 20
    th = threading.Thread(target=stream, args=(a.panel, ca, a.token, total, records, t0), daemon=True)
    th.start()
    time.sleep(a.settle)

    print("[%5.1fs] ARM STAY" % (time.time() - t0))
    st, body = http(a.panel, ca, "POST", API + "/AdvancedSecurity/ArmWithCode",
                    "arming=stay&pID=1&ucode=%s&operation=set" % code, a.token)
    print("         -> %s %s" % (st, body[:80].decode("latin-1", "replace")))
    if not (st.startswith("HTTP/1.1 200") and b"Sucess" in body):
        print("ARM NOT CONFIRMED -- not disarming automatically; CHECK THE PANEL")
        th.join(timeout=5)
        return dump(records, code)
    time.sleep(a.armed_for)

    print("[%5.1fs] DISARM" % (time.time() - t0))
    st, body = http(a.panel, ca, "POST", API + "/AdvancedSecurity/DisarmWithCode",
                    "pID=1&ucode=%s&operation=set" % code, a.token)
    print("         -> %s %s" % (st, body[:80].decode("latin-1", "replace")))
    if not (st.startswith("HTTP/1.1 200") and b"Sucess" in body):
        print("DISARM NOT CONFIRMED -- CHECK THE PANEL, it may be armed")
    time.sleep(a.after)
    th.join(timeout=total)
    dump(records, code)


def dump(records, code):
    print()
    print("=== id-20 LCD records, distinct consecutive lines, with time since start ===")
    last = None
    n20 = 0
    for t, text in records:
        if not text.startswith(b"0:20:2"):
            continue
        n20 += 1
        line = text[6:].decode("latin-1", "replace")
        if line == last:
            continue
        last = line
        shown = line.replace(code, "<code>")
        print("[%5.1fs] %r" % (t, shown))
    print("(%d id-20 records total, %d status texts of all kinds)" % (n20, len(records)))
    print("=== status (21) transitions ===")
    last = None
    for t, text in records:
        if text.startswith(b"0:21:"):
            f = text.split(b":")
            key = (f[3], f[4][1:]) if len(f) >= 5 else (text,)
            if key != last:
                last = key
                print("[%5.1fs] state=%s %r" % (t, f[3].decode(), f[4][1:].decode("latin-1", "replace")))


if __name__ == "__main__":
    main()
