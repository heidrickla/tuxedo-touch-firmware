#!/usr/bin/env python3
"""Wire-conformance checker for the Tuxedo Touch web surface.

Validates a server against `docs/wire-contract.json` from ha-tuxedo-touch --
the contract the public Home Assistant integration is written to. Run it
against the vendor firmware to confirm the contract is accurate, and against a
replacement to prove the replacement is compatible.

    python conformance.py --host 203.0.113.5 --contract ../ha-tuxedo-touch/docs/wire-contract.json

Every check here is READ-ONLY. Nothing arms, disarms, or changes panel state,
and no check submits credentials -- three failed web logins disable every web
account on stock firmware and the counter survives a reflash, so the suite must
not be able to spend that budget even by accident.

Exit status is the number of failed checks.
"""

import argparse
import http.client
import json
import os
import re
import socket
import sys

TIMEOUT = 20


class Result:
    def __init__(self):
        self.rows = []

    def add(self, ok, name, detail="", skipped=False):
        self.rows.append((ok, name, detail, skipped))
        mark = "skip" if skipped else ("ok  " if ok else "FAIL")
        print(f"  {mark}  {name}")
        if detail and (not ok or skipped):
            print(f"        {detail}")

    def failures(self):
        return sum(1 for ok, _, _, sk in self.rows if not ok and not sk)


def http_get(host, path, port=80, headers=None, body_limit=4096, read_secs=None):
    """Plain HTTP GET returning (status, headers dict, body bytes)."""
    conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read(body_limit)
    finally:
        conn.close()


def https_get(host, path, port=443, headers=None, body_limit=4096):
    """HTTPS GET over the panel's legacy TLS. The REST namespace requires TLS."""
    sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    from tuxedo_status_probe import legacy_ssl_context
    conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT,
                                       context=legacy_ssl_context())
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read(body_limit)
    finally:
        conn.close()


def read_stream(host, path, seconds=12, limit=8192, cookie=None):
    """Hold the multipart stream on a raw socket and return the bytes seen.

    `cookie` is required against firmware carrying P13, which gates this path on
    a logged-in session. Without it the framing checks see a 401 body instead of
    a stream, and fail in a way that looks like broken framing.
    """
    import time
    s = socket.create_connection((host, 80), timeout=TIMEOUT)
    try:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        if cookie:
            req += f"Cookie: {cookie}\r\n"
        req += "Connection: keep-alive\r\n\r\n"
        s.sendall(req.encode())
        s.settimeout(2.0)
        buf = b""
        t0 = time.time()
        while len(buf) < limit and time.time() - t0 < seconds:
            try:
                d = s.recv(4096)
            except socket.timeout:
                continue
            if not d:
                break
            buf += d
        return buf
    finally:
        s.close()


def check_push_transport(host, contract, r, cookie=None):
    ps = contract["transport"]["push_stream"]
    path = ps["path"]

    raw = read_stream(host, path, cookie=cookie)
    head, _, body = raw.partition(b"\r\n\r\n")
    head_s = head.decode("latin-1")

    r.add(raw.startswith(b"HTTP/1.1 200"), "push stream returns 200",
          head_s.splitlines()[0] if head_s else "no response")

    ct = ps["content_type"]
    r.add(ct in head_s, f"content_type is {ct}", head_s)

    boundary = ps["boundary"]
    r.add(f'boundary="{boundary}"' in head_s, f'boundary is "{boundary}"', head_s)

    # quirk: Server header present with an EMPTY value, not absent
    m = re.search(r"^Server:(.*)$", head_s, re.M)
    r.add(m is not None and m.group(1).strip() == "",
          "quirk: 'Server:' present with empty value",
          f"got {m.group(0)!r}" if m else "header absent entirely")

    # quirk: Connection: Close on a stream then held open
    r.add(re.search(r"^Connection:\s*Close", head_s, re.M | re.I) is not None,
          "quirk: 'Connection: Close' on a held-open stream", head_s)

    # quirk: the CLOSE delimiter appears after EVERY part, not once at the end
    opens = body.count(b"--" + boundary.encode() + b"\r\n")
    closes = body.count(b"--" + boundary.encode() + b"--")
    r.add(opens > 1 and opens == closes,
          "quirk: close delimiter after EVERY part (invalid RFC 2046)",
          f"{opens} opening boundaries, {closes} close delimiters")

    return body


def check_push_auth(host, contract, r, cookie=None):
    """Whether the stream is gated, reported for what it is.

    The contract records VENDOR behaviour, where this path needs no credential.
    Firmware carrying P13 deliberately diverges: anonymous gets 401. Both are
    legitimate states, so this reports which one is in front of it rather than
    failing on the divergence -- but it is never silent about an open one.

    The check this replaces was `len(body) > 0`, which passed on a 401 as
    happily as on a stream, because an error response also has a body. It
    reported a gated panel as "delivers frames with no credential".
    """
    path = contract["transport"]["push_stream"]["path"]
    raw = read_stream(host, path, seconds=8)
    head, _, body = raw.partition(b"\r\n\r\n")
    status = head.decode("latin-1").splitlines()[0] if head else "(no response)"
    boundary = contract["transport"]["push_stream"]["boundary"].encode()

    if body.count(b"--" + boundary) > 0:
        r.add(True, "anonymous access: STOCK behaviour, stream is OPEN",
              f"{status} -- {len(body)} body bytes with no credential. This is "
              f"the exposure in tls/THREAT-MODEL.md section 3.")
    else:
        r.add(status.startswith("HTTP/1.1 401"),
              "anonymous access: gated by P13, 401 and no frames", status)

    if cookie:
        _, _, body2 = read_stream(host, path, seconds=8,
                                  cookie=cookie).partition(b"\r\n\r\n")
        r.add(body2.count(b"--" + boundary) > 0,
              "authenticated access still streams (what Home Assistant needs)",
              f"{len(body2)} body bytes")
    else:
        r.add(True, "authenticated access still streams",
              detail="no --creds given", skipped=True)


def check_push_path_quirk(host, contract, r):
    """The SLASH before 'G.' is required; without it the server answers 404."""
    path = contract["transport"]["push_stream"]["path"]
    bad = path.replace("/G.", "G.")   # /SimpleDebugger.interfaceG.
    try:
        st, _, _ = http_get(host, bad, body_limit=256)
        r.add(st == 404, "quirk: push path without the slash before 'G.' 404s",
              f"{bad} -> HTTP {st}")
    except Exception as e:
        r.add(False, "quirk: push path without the slash before 'G.' 404s", repr(e))


def check_frame_cases(contract, body, r):
    """Every contract frame case must be decodable by the documented rules."""
    cases = contract["push_frames"]["cases"]
    seen = re.findall(rb"statusMessageText',\[\"(.*?)\"\]\]", body)
    live = [x.decode("latin-1") for x in seen]

    for c in cases:
        payload = bytes.fromhex(c["payload_latin1_hex"]).decode("latin-1")
        fields = payload.split(":")
        ok = True
        detail = []

        if c.get("decodes"):
            # the raw 0xFE/0xFF state byte is the discriminator
            raw_flag = None
            for f in fields[2:]:
                if f and f[0] in ("\xfe", "\xff"):
                    raw_flag = f[0]
                    break
            expect_armed = c.get("armed")
            if expect_armed is not None:
                got = (raw_flag == "\xff")
                if got != expect_armed:
                    ok = False
                    detail.append(f"armed: expected {expect_armed}, decoded {got}")
            if c.get("cmd") is not None and len(fields) > 1:
                try:
                    if int(fields[1]) != c["cmd"]:
                        ok = False
                        detail.append(f"cmd: expected {c['cmd']}, got {fields[1]}")
                except ValueError:
                    ok = False
                    detail.append(f"cmd field not an int: {fields[1]!r}")
        else:
            # documented as carrying no status
            if any(f and f[0] in ("\xfe", "\xff") for f in fields[2:]):
                ok = False
                detail.append("expected no status, but a raw state byte is present")

        r.add(ok, f"frame case: {c['label'][:64]}", "; ".join(detail))

    r.add(len(live) > 0, "live frames observed to compare against",
          f"{len(live)} frames captured")


def check_capability_detection(host, contract, r):
    cap = contract.get("capability_detection")
    if not cap:
        r.add(True, "capability_detection block present", "absent from contract", skipped=True)
        return
    path = cap["path"]
    stock = cap.get("stock_behaviour", {})
    want_status = stock.get("status", 404)

    # Must go over TLS: the whole /system_http_api/ namespace 302s to https on
    # port 80, so probing it over plain HTTP measures the redirect, not the
    # endpoint. NO session is sent -- that is the point of the check.
    try:
        st, _, body = https_get(host, path, body_limit=256)
        txt = body.decode("latin-1", "replace")
        r.add(st == want_status,
              f"capability probe unauthenticated -> HTTP {want_status}",
              f"got HTTP {st}: {txt[:60]!r}")
        r.add(st not in (401, 403),
              "capability probe never 401/403 (cannot spend a login attempt)",
              f"got HTTP {st}")
    except Exception as e:
        r.add(False, "capability probe reachable", repr(e))


def check_rest_requires_tls(host, contract, r):
    """Plain HTTP on the REST namespace must redirect to TLS."""
    st, hdrs, _ = http_get(host, "/system_http_api/API_REV01/GetSecurityStatus",
                           body_limit=256)
    loc = hdrs.get("Location", "")
    r.add(st in (301, 302) and loc.startswith("https://"),
          "REST namespace redirects to TLS over plain HTTP",
          f"HTTP {st} Location={loc!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="203.0.113.5")
    ap.add_argument("--contract", required=True)
    ap.add_argument("--creds", help="file holding the panel password. Needed "
                                    "against P13 firmware, which gates the push "
                                    "stream on a session. A wrong password is "
                                    "never submitted.")
    args = ap.parse_args()

    cookie = None
    if args.creds and os.path.exists(args.creds):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from tuxedo_status_probe import TuxedoProbe
        line = open(args.creds, encoding="utf-8").read().strip().splitlines()[0]
        # user:password, or a bare password with the account name supplied by
        # the environment. The panel account name is deliberately kept out of
        # this repo -- aff1f99 removed it from leakprobe.py for the same reason.
        if ":" in line:
            user, pw = line.split(":", 1)
        else:
            user, pw = os.environ.get("TUXEDO_USER", ""), line
            if not user:
                sys.exit("creds file holds a bare password; set TUXEDO_USER "
                         "or use user:password")
        probe = TuxedoProbe(args.host, user, pw, scheme="https")
        probe.login()
        cookie = probe.session_cookie

    with open(args.contract, encoding="utf-8") as fh:
        contract = json.load(fh)

    print(f"wire conformance: {args.host}")
    print(f"contract v{contract.get('version')} "
          f"observed on {contract.get('firmware_observed')}")
    print()

    r = Result()
    print("transport / framing")
    body = check_push_transport(args.host, contract, r, cookie)
    check_push_path_quirk(args.host, contract, r)
    check_push_auth(args.host, contract, r, cookie)
    print("\nframe decoding")
    check_frame_cases(contract, body, r)
    print("\nendpoints")
    check_capability_detection(args.host, contract, r)
    check_rest_requires_tls(args.host, contract, r)

    n = r.failures()
    print()
    print(f"{len(r.rows)} checks, {n} failed")
    return n


if __name__ == "__main__":
    sys.exit(main())
