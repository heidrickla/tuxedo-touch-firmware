#!/usr/bin/env python3
"""Check the push-stream auth gate on the TLS listeners.

curl on a modern host cannot negotiate with this server's SharkSSL build: it fails in
~10 ms with an immediate cipher rejection, which looks identical to a dead listener.
The same curl fails against the healthy live panel, so the failure is curl's.

Python's ssl module with SECLEVEL lowered completes the handshake, so it can tell
"denied" from "unreachable". A 401 is the correct answer; a 200 means P13 has regressed
and live alarm state is readable without a session.
"""
import http.client
import ssl
import sys

PATH = "/SimpleDebugger.interface/G."


def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1
    try:
        c.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        c.set_ciphers("ALL")
    # OpenSSL 3 refuses this server with UNSAFE_LEGACY_RENEGOTIATION_DISABLED, another
    # failure that looks like a dead listener. SharkSSL of this vintage does not
    # implement RFC 5746, so the option is required to reach it at all.
    for name in ("OP_LEGACY_SERVER_CONNECT", "OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION"):
        opt = getattr(ssl, name, None)
        if opt is not None:
            c.options |= opt
    return c


def probe(host, port, tls):
    try:
        if tls:
            conn = http.client.HTTPSConnection(host, port, timeout=45, context=ctx())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=45)
        conn.request("GET", PATH)
        r = conn.getresponse()
        body = r.read(120)
        conn.close()
        return r.status, body
    except Exception as exc:
        return None, repr(exc)[:90]


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    targets = [(80, False), (443, True), (6280, True), (9443, True)]
    bad = 0
    for port, tls in targets:
        status, extra = probe(host, port, tls)
        scheme = "https" if tls else "http "
        if status == 401:
            verdict = "401 DENIED (correct)"
        elif status is None:
            verdict = "UNREACHABLE: %s" % extra
            bad += 1
        else:
            verdict = "%s <-- P13 REGRESSION, anonymous read" % status
            bad += 1
        print("  %s://%s:%-5d %s" % (scheme, host, port, verdict))
    print()
    print("all four listeners deny anonymous push access" if not bad
          else "%d listener(s) did not answer 401" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
