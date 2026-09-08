"""Find a request shape for commandID=5002 that the mobile handler accepts.

/console.html polls it every 5 s -- 720 requests an hour, heavier than anything
the leak work has driven, on an endpoint with a different parameter scheme. My
first attempt returned Session_Expired using the page's own hiddenKey, so try
several shapes and report which answers.

Read-only: 5002 is the display poll the page itself issues. No keystroke is sent.
"""
import re
import sys
import urllib.parse

sys.path.insert(0, "/work/fwcheck")
from leakprobe import TuxedoProbe

pw = open("/tmp/pw").read().strip()
p = TuxedoProbe("127.0.0.1", "Lewis", pw, scheme="http")
p.login()
ck = {"Cookie": p.session_cookie}

_s, _h, body = p._open(p.base + "/console.html", headers=ck)
page = body.decode("utf-8", "replace")


def hidden(name):
    for pat in (r'id\s*=\s*["\']%s["\'][^>]*value\s*=\s*["\']([^"\']*)',
                r'value\s*=\s*["\']([^"\']*)["\'][^>]*id\s*=\s*["\']%s["\']',
                r'name\s*=\s*["\']%s["\'][^>]*value\s*=\s*["\']([^"\']*)'):
        m = re.search(pat % name, page, re.I)
        if m:
            return m.group(1)
    return ""


tok = hidden("hiddenKey")
sess = hidden("hidSession")
cookie_sid = p.session_cookie.split("=", 1)[-1]
print("  hiddenKey=%r  hidSession=%r  cookie sid=%r" % (tok[:24], sess[:24], cookie_sid[:24]))
print("  hidden ids on the page: %s" % sorted(set(re.findall(r'id\s*=\s*["\'](hid[A-Za-z]*)', page)))[:12])

SHAPES = {
    "page token + page session": {"commandID": "5002", "param2": "0", "param3": sess,
                                  "param4": "0", "param5": "0", "tokenkey": tok, "sid": "0.5"},
    "page token + cookie sid":   {"commandID": "5002", "param2": "0", "param3": cookie_sid,
                                  "param4": "0", "param5": "0", "tokenkey": tok, "sid": "0.5"},
    "no tokenkey":               {"commandID": "5002", "param2": "0", "param3": sess,
                                  "param4": "0", "param5": "0", "sid": "0.5"},
    "minimal":                   {"commandID": "5002"},
    "cookie sid, no token":      {"commandID": "5002", "param3": cookie_sid},
}
for label, params in SHAPES.items():
    st, _h2, rb = p._open(p.base + "/handlerequest_mobile.html?" + urllib.parse.urlencode(params),
                          headers=ck)
    txt = rb.decode("utf-8", "replace")
    short = " ".join(txt.split())[:90]
    print("  %-26s HTTP %-4s %4d B  %s" % (label, st, len(txt), short))
