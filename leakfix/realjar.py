#!/usr/bin/env python3
"""Drive the whole flow through a REAL cookie jar, the way a browser does.

The suspect is the framework session: both authPage_service and the
handlerequest handler key on HttpRequest_getSession(req, ...)->[r7,#8], and
0x142b0 calls it with the CREATE flag. A client that does not carry whatever
identifies that session mints a new one per request, so the id registered by the
GET is not the id looked up by the command -- both halves correct, no match.

The earlier attempt hand-parsed Set-Cookie with a regex that swallows attributes
and produced a cookie named "path", so it proved nothing. This uses
http.cookiejar, which handles attributes, domains and paths properly, and keeps
one jar across login, the registering GET and the commands.

Verdict is command-independence, not hiddenKey: the bail precedes the switch.
"""
import os
import hashlib
import http.cookiejar
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, "/work/fwcheck")
from tuxedo_status_probe import hmac_hex  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
# The panel account name is deliberately kept OUT of this repo -- aff1f99
# removed it from leakprobe.py and gave pubscan a detector for it. Pass it in.
USER = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TUXEDO_USER", "")
if not USER:
    raise SystemExit("usage: %s <host> <panel-user> [creds]  (or set TUXEDO_USER)"
                     % sys.argv[0])
password = open("/tmp/pw.txt", encoding="utf-8").read().strip()
import ssl
SCHEME = sys.argv[3] if len(sys.argv) > 3 else "http"
BASE = SCHEME + "://" + HOST
_ctx = ssl._create_unverified_context()
_ctx.set_ciphers("DEFAULT@SECLEVEL=0")
# OpenSSL 3 refuses the panel's TLS without this; it is why curl reports HTTP 000
# against a server that is perfectly alive.
_ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x00000004)
try:
    _ctx.options &= ~ssl.OP_NO_RENEGOTIATION
except AttributeError:
    pass

jar = http.cookiejar.CookieJar()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep redirects visible instead of following them silently."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar), NoRedirect,
    urllib.request.HTTPSHandler(context=_ctx))
opener.addheaders = [("User-Agent", "Mozilla/5.0")]


def fetch(path, data=None):
    req = urllib.request.Request(BASE + path, data=data)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = opener.open(req, timeout=30)
        return r.getcode(), dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


LOGIN = "/authenticated/index.html?url=home.html"
status, headers, _b = fetch(LOGIN)
challenge, random_id = headers.get("Random"), headers.get("RandomID")
print("challenge page %s, cookies now: %s"
      % (status, [c.name for c in jar]))

body = urllib.parse.urlencode({
    "log": hmac_hex(challenge, USER.lower(), hashlib.sha512),
    "log1": hmac_hex(challenge, USER.lower() + password, hashlib.sha512),
    "identity": random_id,
}).encode("ascii")
status, headers, _b = fetch(LOGIN, data=body)
print("login POST %s, cookies now: %s" % (status, [c.name for c in jar]))

sid = None
for c in jar:
    if not c.name.startswith("_zFL"):
        sid = c.value
print("vendor sessionid=%s" % sid)


def dispatches(label):
    digests, lengths = set(), set()
    for t in (0, 141, 65535):
        q = urllib.parse.urlencode({
            "cmd": str(t), "Type": str(t), "pID": "-1", "uCode": "0",
            "sessionid": sid or "", "filters": "0", "index": "0",
            "tarTemp": "0", "sceneid": "1"})
        _s, _h, b = fetch("/handlerequest.html?" + q)
        b = b or b""
        digests.add(hashlib.sha1(b).hexdigest()[:8])
        lengths.add(len(b))
    ok = len(digests) > 1
    print("  %-28s sizes=%-12s %s" % (label, sorted(lengths),
                                      "DISPATCHES" if ok else "bails"))
    return ok


dispatches("straight after login")
for n in (1, 2, 3):
    st, _h, _b = fetch(LOGIN)
    if dispatches("after registering GET #%d" % n):
        print("\nUNBLOCKED with a real cookie jar.")
        break
