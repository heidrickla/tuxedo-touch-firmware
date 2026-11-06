"""Bench harness for tuxweb's browser pages, driven by emu/ui-serve-test.sh.

Runs against `tuxweb --serve` on real kernel queues with push_capture_check's
reactive fake /tuxedo. Nothing here talks to a panel. Subcommands:

    mkaccounts <dir>                a throwaway account store and a fake
                                    /tuxedo ELF holding its key: <dir>/tuxedo,
                                    <dir>/accounts.enc (user "bench", code 1234)
    flow <host:port> <token> <secs> the whole browser flow plus the API's
                                    code-free arm; see flow() for the order
    verify_ui_cmds <cmdlog>         the fake tuxedo saw the commands the flow
                                    sent, and nothing with a zero code
"""
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from push_capture_check import _http, die  # noqa: E402

KEY_VA = 0xD09654  # accounts.rs KEY_VA; the IV follows at +16
USER, CODE = "bench", "1234"
CSP = ("default-src 'self'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'; object-src 'none'")


def mkaccounts(d):
    """A 32-bit ELF with one PT_LOAD mapping KEY_VA to a random key and IV, and
    a five-slot store sealed and encrypted the vendor's way (AES-128-OFB,
    EncNamePass = md5(lower(name) + code)) with that key."""
    key, iv = secrets.token_bytes(16), secrets.token_bytes(16)
    elf = bytearray(0x120)
    elf[0:4] = b"\x7fELF"
    elf[4] = 1
    elf[0x1C:0x20] = (52).to_bytes(4, "little")
    elf[0x2A:0x2C] = (32).to_bytes(2, "little")
    elf[0x2C:0x2E] = (1).to_bytes(2, "little")
    elf[52:56] = (1).to_bytes(4, "little")
    elf[56:60] = (0x100).to_bytes(4, "little")
    elf[60:64] = KEY_VA.to_bytes(4, "little")
    elf[68:72] = (32).to_bytes(4, "little")
    elf[0x100:0x110] = key
    elf[0x110:0x120] = iv
    with open(os.path.join(d, "tuxedo"), "wb") as f:
        f.write(elf)

    def entry(i, name, code):
        return {"u8UserId": i, "userName": name, "passWord": code,
                "EncNamePass": hashlib.md5((name.lower() + code).encode()).hexdigest(),
                "status": 1, "accountLocked": 0, "accLockedTime": 0,
                "userCreatedDate": 1700000000, "userUpdatedDate": 1700000000,
                "accLockedCount": 0}
    users = [entry(1, USER, CODE)] + [entry(i, "slot%d" % i, "9999") for i in range(2, 6)]
    plain = json.dumps({"WEBUSERS": users}, separators=(",", ":")).encode()
    enc = subprocess.run(
        ["openssl", "enc", "-aes-128-ofb", "-K", key.hex(), "-iv", iv.hex(), "-nosalt"],
        input=plain, capture_output=True, check=True).stdout
    if len(enc) != len(plain):
        die("FAIL: openssl OFB output is %d bytes for %d in" % (len(enc), len(plain)))
    with open(os.path.join(d, "accounts.enc"), "wb") as f:
        f.write(enc)
    print("  fake /tuxedo and a %d-byte store: user %r, 5 slots" % (len(enc), USER))


# -- one HTTP exchange ----------------------------------------------------------

class Resp:
    def __init__(self, raw):
        head, _, self.body = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        self.status = lines[0] if lines and lines[0] else "(no response)"
        self.headers = [tuple(x.strip() for x in ln.split(":", 1)) for ln in lines[1:] if ":" in ln]

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def code(self):
        parts = self.status.split()
        return parts[1] if len(parts) > 1 else "-"


def request(hp, method, path, body=None, headers=(), secs=12):
    h = "%s %s HTTP/1.1\r\nHost: panel.test\r\nConnection: close\r\n" % (method, path)
    for x in headers:
        h += x + "\r\n"
    b = b""
    if body is not None:
        b = body.encode()
        h += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(b)
    return Resp(_http(hp, (h + "\r\n").encode() + b, secs))


failures = []


def check(what, ok, detail=""):
    print("  %s %s%s" % ("PASS" if ok else "FAIL", what, (": " + detail) if (detail and not ok) else ""))
    if not ok:
        failures.append(what)


def expect(what, r, code, csp=True):
    ok = r.code() == code and (not csp or r.header("Content-Security-Policy") == CSP)
    check("%s -> %s" % (what, code), ok, "got %s, CSP %r" % (r.status, r.header("Content-Security-Policy")))
    return ok


# -- the event stream, recorded in the background --------------------------------

def record_stream(hp, cookie, secs, out):
    """Hold /ui/events open for `secs` and keep every state event's JSON."""
    raw = _http(hp, ("GET /ui/events HTTP/1.1\r\nHost: panel.test\r\nCookie: %s\r\n\r\n"
                     % cookie).encode(), secs)
    head, _, body = raw.partition(b"\r\n\r\n")
    out["head"] = head.decode("latin-1")
    out["events"] = [json.loads(m) for m in
                     re.findall(r"^event: state\ndata: (.*)$", body.decode("latin-1"), re.M)]
    out["keepalive"] = b": keep-alive" in body


def flow(hp, token, secs):
    """Signed out -> pages and assets -> sign-in backoff -> sign-in -> status
    page -> live stream -> arm away from the page (no code; CSRF and origin
    refusals first) -> disarm from the pad (0000 refused first) -> the API's
    code-free arm and its disarm refusal -> sign-out."""
    api = "/system_http_api/API_REV01"
    bearer = "Authorization: Bearer %s" % token

    r = request(hp, "GET", "/")
    expect("GET / signed out", r, "303")
    check("  ...to /login", r.header("Location") == "/login")
    r = request(hp, "GET", "/login")
    expect("GET /login", r, "200")
    check("  ...is the sign-in form", b'action="/login"' in r.body and b"{{" not in r.body)
    for name, ctype in (("app.js", "text/javascript"), ("app.css", "text/css"), ("icon.svg", "image/svg+xml")):
        r = request(hp, "GET", "/ui/assets/" + name)
        expect("GET /ui/assets/" + name, r, "200")
        check("  ...as " + ctype, (r.header("Content-Type") or "").startswith(ctype))
    expect("GET /nope", request(hp, "GET", "/nope"), "404")
    expect("GET /authenticated/tuxedoapi.html (vendor path)", request(hp, "GET", "/authenticated/tuxedoapi.html"), "404")

    # three wrong codes are free; then even the right one waits and is not checked
    for i in range(3):
        r = request(hp, "POST", "/login", "username=%s&password=0000" % USER)
        expect("sign-in with a wrong password #%d" % (i + 1), r, "401")
    r = request(hp, "POST", "/login", "username=%s&password=%s" % (USER, CODE))
    expect("the right password inside the backoff", r, "429")
    check("  ...with Retry-After", r.header("Retry-After") == "1" and r.header("Set-Cookie") is None)
    time.sleep(1.2)
    r = request(hp, "POST", "/login", "username=%s&password=%s" % (USER, CODE),
                headers=("Origin: https://evil.test",))
    expect("cross-origin sign-in", r, "403")
    r = request(hp, "POST", "/login", "username=%s&password=%s" % (USER.upper(), CODE))
    expect("sign-in after the wait (name case-folded)", r, "303")
    sc = r.header("Set-Cookie") or ""
    attrs = [a.strip() for a in sc.split(";")]
    check("  ...cookie HttpOnly, Secure, SameSite=Strict, Path=/",
          all(a in attrs for a in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/")), sc)
    m = re.match(r"tuxweb_session=([0-9a-f]{64})$", attrs[0] if attrs else "")
    check("  ...a 64-hex session id", bool(m))
    if not m:
        return
    cookie = "tuxweb_session=" + m.group(1)

    r = request(hp, "GET", "/", headers=("Cookie: " + cookie,))
    expect("GET / signed in", r, "200")
    m = re.search(rb'name="csrf-token" content="([0-9a-f]{64})"', r.body)
    check("  ...carries a CSRF token, the build and the certificate line",
          bool(m) and b"tuxweb/" in r.body and (b"Certificate expires" in r.body or b"No certificate" in r.body))
    if not m:
        return
    tok = "X-CSRF-Token: " + m.group(1).decode()
    check("API token is not a browser session",
          request(hp, "GET", "/", headers=("Cookie: tuxweb_token=" + token,)).code() == "303")
    check("browser session is not an API token",
          request(hp, "GET", api + "/GetSecurityStatus", headers=("Cookie: " + cookie,)).code() == "401")

    stream = {}
    t = threading.Thread(target=record_stream, args=(hp, cookie, float(secs), stream))
    t.start()
    time.sleep(1)

    r = request(hp, "POST", "/ui/arm", "mode=away", headers=("Cookie: " + cookie,))
    expect("arm without the CSRF token", r, "403")
    r = request(hp, "POST", "/ui/arm", "mode=away",
                headers=("Cookie: " + cookie, tok, "Origin: https://evil.test"))
    expect("arm from another origin", r, "403")
    r = request(hp, "POST", "/ui/arm", "mode=away", headers=("Cookie: " + cookie, tok))
    expect("arm away from the page, no code", r, "200")
    check("  ...ok once the panel confirms", b'"ok":true' in r.body, r.body.decode("latin-1"))
    r = request(hp, "GET", api + "/GetSecurityStatus", headers=(bearer,))
    check("API status reads armed", b'"armed":true' in r.body, r.body.decode("latin-1"))
    r = request(hp, "POST", "/ui/arm", "mode=stay", headers=("Cookie: " + cookie, tok))
    expect("arm while armed", r, "409")

    r = request(hp, "POST", "/ui/disarm", "code=0000", headers=("Cookie: " + cookie, tok))
    expect("disarm with 0000", r, "400")
    r = request(hp, "POST", "/ui/disarm", "code=", headers=("Cookie: " + cookie, tok))
    expect("disarm with no code", r, "400")
    r = request(hp, "POST", "/ui/disarm", "code=" + CODE, headers=("Cookie: " + cookie, tok))
    expect("disarm from the pad", r, "200")
    check("  ...ok once the panel confirms", b'"ok":true' in r.body, r.body.decode("latin-1"))

    # the API: an arm with no ucode now arms (p2 0xFFFF); a disarm without one is refused
    time.sleep(1.5)
    r = request(hp, "POST", api + "/AdvancedSecurity/ArmWithCode",
                "arming=stay&pID=1&operation=set", headers=(bearer,))
    expect("API ArmWithCode with no ucode", r, "200", csp=False)
    check("  ...vendor shape", b'"Response":"Command sent sucessfully"' in r.body, r.body.decode("latin-1"))
    r = request(hp, "POST", api + "/AdvancedSecurity/DisarmWithCode",
                "pID=1&operation=set", headers=(bearer,))
    expect("API DisarmWithCode with no ucode", r, "400", csp=False)
    r = request(hp, "POST", api + "/AdvancedSecurity/DisarmWithCode",
                "pID=1&ucode=%s&operation=set" % CODE, headers=(bearer,))
    expect("API DisarmWithCode", r, "200", csp=False)

    r = request(hp, "POST", "/logout", "", headers=("Cookie: " + cookie, tok))
    expect("sign-out", r, "200")
    check("  ...clears the cookie", "Max-Age=0" in (r.header("Set-Cookie") or ""))
    expect("GET / after sign-out", request(hp, "GET", "/", headers=("Cookie: " + cookie,)), "303")

    t.join()
    head = stream.get("head", "")
    check("event stream opened with CSP", head.startswith("HTTP/1.1 200")
          and "Content-Type: text/event-stream" in head and ("Content-Security-Policy: " + CSP) in head, head)
    ev = stream.get("events", [])
    phases = []
    for e in ev:
        if not phases or phases[-1] != e["phase"]:
            phases.append(e["phase"])
    print("  stream: %d state events, phases %s, links %s" %
          (len(ev), phases, sorted({e["link"] for e in ev})))
    for e in ev:
        print("        " + json.dumps(e))
    check("stream showed disarmed, then armed, then disarmed",
          phases[:3] == ["disarmed", "armed", "disarmed"], str(phases))
    check("stream carried the keypad LCD", any(e["lcd"] and "DISARMED" in e["lcd"][0] for e in ev))
    check("stream showed the link lost during the fake's offline episode",
          any(e["link"] == "lost" for e in ev))
    check("no event repeated the one before it",
          all(a != b for a, b in zip(ev, ev[1:])))
    if failures:
        die("FAIL: %d check(s): %s" % (len(failures), "; ".join(failures)))
    print("  PASS: the browser flow")


def verify_ui_cmds(cmdlog):
    with open(cmdlog) as f:
        rows = [tuple(int(x) for x in ln.split("\t")) for ln in f if ln.strip()]
    print("  fake tuxedo saw commands: %s" % rows)
    sec = [r for r in rows if r[0] in (1, 2, 3, 4)]
    want = [(1, 0xFFFF), (3, int(CODE)), (2, 0xFFFF), (3, int(CODE))]
    if sec != want:
        die("FAIL: arm/disarm commands %r, expected %r (page arm away with 0xFFFF, "
            "pad disarm, API arm with 0xFFFF, API disarm)" % (sec, want))
    if any(c in (1, 2, 3, 4) and p == 0 for c, p in rows):
        die("FAIL: a command with code 0 reached the queue")
    print("  PASS: arm away 0xFFFF, disarm 1234, arm stay 0xFFFF, disarm 1234; "
          "no refused request reached the queue")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        die(__doc__)
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd == "mkaccounts":
        mkaccounts(a[0])
    elif cmd == "flow":
        flow(a[0], a[1], a[2])
    elif cmd == "verify_ui_cmds":
        verify_ui_cmds(a[0])
    else:
        die("unknown subcommand %r" % cmd)
