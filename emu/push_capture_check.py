"""Bench harness for stage 8's push generator and serve mode.

Proves the whole IPC -> PanelState -> legacy-frame path, and the token-gated
API on top of it, on REAL kernel message queues without Barracuda and without a
panel: a fake `/tuxedo` answers the 500 with a registration and reacts to
arm/disarm commands with the status replies a real panel would send, tuxweb
serves the stream and the API, and the verifiers assert byte-for-byte.

Runs on the build VM as root (POSIX mqueues are in the kernel; the chroot does
not change the IPC namespace -- see emu/pushdriver.py). Subcommands:

    mkqueues                        (re)create both queues at panel geometry
    serve <deadline>                capture-test fake tuxedo: 504 + 3 statuses
    serve_tux <deadline> <cmdlog>   serve-test fake tuxedo: reactive to arm/disarm
    client <host:port> <secs> <out> [token]   subscribe (Cookie form) and record
    pushdeny <host:port>            subscribe WITHOUT a token: expect 401
    apicall <method> <host:port> <path> <body|-> <token|-> <status> <needle|->
    verify <file>                   capture-test oracle
    verify_serve <file>             serve-test oracle (snapshot + live arm/disarm)
    verify_cmds <cmdlog>            the fake tuxedo saw the right commands
    unlink                          remove both queues
"""
import ctypes
import ctypes.util
import os
import sys
import time

QR = b"/Q_ServCmdTrsmtr"   # replies,  tuxedo -> us,   556
QC = b"/Q_ServCmdRcver"    # commands, us -> tuxedo,   404
REPLY, COMMAND = 556, 404

rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)


class Attr(ctypes.Structure):
    _fields_ = [("mq_flags", ctypes.c_long), ("mq_maxmsg", ctypes.c_long),
                ("mq_msgsize", ctypes.c_long), ("mq_curmsgs", ctypes.c_long),
                ("pad", ctypes.c_long * 4)]


rt.mq_open.restype = ctypes.c_int
rt.mq_send.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint]
rt.mq_timedreceive.argtypes = None
O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_NONBLOCK = 0, 1, 2, 0o100, 0o200, 0o4000
FE, FF = 0xFE, 0xFF


def die(msg):
    print("  " + msg)
    sys.exit(1)


def mkqueues():
    for name, size in ((QR, REPLY), (QC, COMMAND)):
        rt.mq_unlink(name)
        a = Attr(0, 32, size, 0, (ctypes.c_long * 4)())
        fd = rt.mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0o666, ctypes.byref(a))
        if fd < 0:
            die("mq_open %s: %s" % (name.decode(), os.strerror(ctypes.get_errno())))
        print("  %-18s msgsize=%d ok" % (name.decode(), size))


# -- reply builders, laid out as Reply::parse / parse_504 read them ---------

def reply_status(msg_type, arg, flag, text):
    """556-byte status reply: session +0x00 (0), msgType +0x04, arg +0x08, and
    the text at +0x0E with the 0xFE/0xFF state byte as its FIRST byte."""
    b = bytearray(REPLY)
    b[0x04:0x08] = msg_type.to_bytes(4, "little")
    b[0x08:0x0C] = (arg & 0xFFFFFFFF).to_bytes(4, "little")
    b[0x0E] = flag
    t = text.encode("latin-1")
    b[0x0F:0x0F + len(t)] = t
    return bytes(b)


def reply_typed(msg_type, arg, text):
    """556-byte typed reply (18): text begins AT +0x0E, no state byte."""
    b = bytearray(REPLY)
    b[0x04:0x08] = msg_type.to_bytes(4, "little")
    b[0x08:0x0C] = (arg & 0xFFFFFFFF).to_bytes(4, "little")
    t = text.encode("latin-1")
    b[0x0E:0x0E + len(t)] = t
    return bytes(b)


def reply_504(part, desc, extra):
    """556-byte registration reply at the 504 offsets (reply-layouts.txt / §5.12)."""
    b = bytearray(REPLY)
    b[0x04:0x08] = (504).to_bytes(4, "little")
    b[0x90] = part
    d = desc.encode("latin-1")
    b[0x91:0x91 + len(d)] = d
    b[0xAF] = extra[0]
    b[0xB1] = extra[1]
    b[0xB2] = extra[2]
    b[0xB4:0xB8] = extra[3].to_bytes(4, "little")
    return bytes(b)


REG = reply_504(1, "P1  H", (1, 0, 3, 3))
READY = reply_status(21, 1, FE, "1Ready To Arm")
ARMED = reply_status(21, 1, FF, "2Armed Stay")
HOME = reply_typed(18, 2, "1 P1  H")
# the keypad LCD (msgType 20): text at +0x0E, no state byte. The disarmed line is
# what the 2026-09-11 stage-7c window received from the real panel; the armed
# one carries a ':' so the vendor's first-colon-to-'-' rule is exercised.
LCD_DISARMED = reply_typed(20, 0, "****DISARMED****|  Ready to Arm  ")
LCD_ARMED = reply_typed(20, 0, "ARMED ***STAY***|Exit: 59 secs")


def s(*parts):
    out = bytearray()
    for p in parts:
        out += p if isinstance(p, bytes) else p.encode("latin-1")
    return bytes(out)


# the frame texts tuxweb must produce for those replies (proven vs fixtures)
T_REG = b"0:504:1:P1  H:1:0:3:3"
T_REGF = b"0:-1:1:P1  H:1:0:3:3"
T_READY = s("0:21:1:fe:", bytes([FE]), "1Ready To Arm:2")
T_READYF = s("0:-1:", bytes([FE]), "1Ready To Arm")
T_ARMED = s("0:21:1:ff:", bytes([FF]), "2Armed Stay:2")
T_ARMEDF = s("0:-1:", bytes([FF]), "2Armed Stay")
T_HOME = b"0:18:1 P1  H:2"
# console frames: id 20 with the constant ":2" and the first ':' -> '-'; then
# three -1 copies of the RAW text (vendor handler 0xdb8c, decompiled)
T_LCD_DIS = b"0:20:2****DISARMED****|  Ready to Arm  "
T_LCD_DISU = b"0:-1:2****DISARMED****|  Ready to Arm  "
T_LCD_ARM = b"0:20:2ARMED ***STAY***|Exit- 59 secs"
T_LCD_ARMU = b"0:-1:2ARMED ***STAY***|Exit: 59 secs"


def _open_tux():
    cmdq = rt.mq_open(QC, O_RDWR | O_NONBLOCK)
    repq = rt.mq_open(QR, O_RDWR)
    if cmdq < 0 or repq < 0:
        die("fake tuxedo mq_open failed: %s" % os.strerror(ctypes.get_errno()))
    return cmdq, repq


def _recv_cmd(cmdq, buf):
    prio = ctypes.c_uint(0)
    n = rt.mq_timedreceive(cmdq, buf, COMMAND, ctypes.byref(prio), ctypes.c_char_p(None))
    if n < 0:
        return None
    return (int.from_bytes(buf.raw[4:8], "little"),   # code   +0x04
            int.from_bytes(buf.raw[12:16], "little"))  # p2     +0x0C (user code)


def serve(deadline_s):
    """Capture-test fake /tuxedo: on the 500, emit a 504 + three statuses."""
    cmdq, repq = _open_tux()
    buf = ctypes.create_string_buffer(COMMAND)
    deadline = time.time() + float(deadline_s)
    registered = False
    print("  fake tuxedo: waiting for the 500")
    while time.time() < deadline:
        got = _recv_cmd(cmdq, buf)
        if got is None:
            time.sleep(0.1)
            continue
        code, _ = got
        if code == 500 and not registered:
            registered = True
            print("  fake tuxedo: got 500, sending 504 + 3 status replies")
            for msg in (REG, READY, HOME, ARMED):
                rt.mq_send(repq, msg, REPLY, 0)
                time.sleep(0.25)
        elif code == 501:
            print("  fake tuxedo: got 501, done")
            return
    print("  fake tuxedo: deadline reached")


def serve_tux(deadline_s, cmdlog):
    """Serve-test fake /tuxedo: register the panel as Ready on the 500, then
    REACT to commands the way a panel does -- an arm (1/2/4) produces an armed
    status, a disarm (3) a ready status -- and log every command it received so
    the test can assert the code and the user code reached the queue."""
    cmdq, repq = _open_tux()
    buf = ctypes.create_string_buffer(COMMAND)
    deadline = time.time() + float(deadline_s)
    console = False
    print("  fake tuxedo (serve): waiting for the 500")

    def send(*msgs):
        for m in msgs:
            rt.mq_send(repq, m, REPLY, 0)
            time.sleep(0.2)

    with open(cmdlog, "w") as log:
        while time.time() < deadline:
            got = _recv_cmd(cmdq, buf)
            if got is None:
                time.sleep(0.05)
                continue
            code, ucode = got
            log.write("%d\t%d\n" % (code, ucode))
            log.flush()
            if code == 500:
                # EVERY 500 registers again (registerclient flushes, then answers
                # with a fresh 504): that is how a silence re-register shows up.
                print("  fake tuxedo (serve): got 500, registering panel as Ready")
                send(REG, READY)
            elif code == 19:
                # console mode on: the panel starts streaming its LCD
                console = True
                print("  fake tuxedo (serve): got 19, console mode ON -> LCD line")
                send(LCD_DISARMED)
            elif code in (1, 2, 4):
                print("  fake tuxedo (serve): got ARM code %d ucode %d -> Armed" % (code, ucode))
                time.sleep(0.3)
                send(ARMED)
                if console:
                    send(LCD_ARMED)
            elif code == 3:
                print("  fake tuxedo (serve): got DISARM ucode %d -> Ready" % ucode)
                time.sleep(0.3)
                send(READY)
                if console:
                    send(LCD_DISARMED)
            elif code == 501:
                print("  fake tuxedo (serve): got 501, done")
                return
    print("  fake tuxedo (serve): deadline reached")


# -- HTTP helpers ------------------------------------------------------------

def _http(hostport, request, secs, plain=False):
    """One HTTP exchange. If TLS_CA is set in the environment (and `plain` is
    not asked for), the connection is TLS with the certificate chain VERIFIED
    against that CA and the hostname/IP checked -- so a TLS run proves the
    listener serves our certificate, not merely that bytes flowed."""
    import socket
    host, port = hostport.rsplit(":", 1)
    sk = socket.create_connection((host, int(port)), timeout=5)
    ca = os.environ.get("TLS_CA")
    if ca and not plain:
        import ssl
        ctx = ssl.create_default_context(cafile=ca)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        sk = ctx.wrap_socket(sk, server_hostname=host)
    sk.sendall(request)
    sk.settimeout(float(secs))
    got = bytearray()
    end = time.time() + float(secs)
    try:
        while time.time() < end:
            b = sk.recv(4096)
            if not b:
                break
            got += b
    except socket.timeout:
        pass
    finally:
        sk.close()
    return bytes(got)


def client(hostport, seconds, outfile, token=None):
    """Subscribe to the push stream (Cookie form of the token) and record all."""
    req = b"GET /SimpleDebugger.interface/G. HTTP/1.1\r\nHost: x\r\n"
    if token:
        req += ("Cookie: tuxweb_token=%s\r\n" % token).encode()
    req += b"\r\n"
    got = _http(hostport, req, seconds)
    with open(outfile, "wb") as f:
        f.write(got)
    print("  client received %d bytes" % len(got))


def pushdeny(hostport):
    got = _http(hostport, b"GET /SimpleDebugger.interface/G. HTTP/1.1\r\nHost: x\r\n\r\n", 3)
    status = got.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print("  push without token -> %s" % status)
    if not status.startswith("HTTP/1.1 401"):
        die("FAIL: expected 401 for a tokenless subscribe")
    print("  PASS: push denied without a token")


def apicall(method, hostport, path, body, token, expect, needle):
    body_b = b"" if body == "-" else body.encode()
    hdr = "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" % (method, path)
    if token != "-":
        hdr += "Authorization: Bearer %s\r\n" % token
    if body_b:
        hdr += ("Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\n" % len(body_b))
    hdr += "\r\n"
    # an arm/disarm may block up to the 8 s confirm ceiling
    got = _http(hostport, hdr.encode() + body_b, 12)
    head, _, rbody = got.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin-1", "replace") if head else "(no response)"
    print("  %s %s -> %s" % (method, path, status))
    print("  body: %s" % rbody.decode("latin-1", "replace")[:200])
    ok = status.startswith("HTTP/1.1 " + expect) and (needle == "-" or needle.encode() in rbody)
    if not ok:
        die("FAIL: expected %s with %r" % (expect, needle))
    print("  PASS")


def redirectget(hostport, path):
    # the 80 leg is plaintext by definition, whatever the main listener does
    got = _http(hostport, ("GET %s HTTP/1.1\r\nHost: panel.test\r\nConnection: close\r\n\r\n"
                           % path).encode(), 5, plain=True)
    head = got.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    status = head.split("\r\n")[0]
    want_loc = "Location: https://panel.test%s" % path
    print("  GET %s -> %s" % (path, status))
    if not (status.startswith("HTTP/1.1 301") and want_loc in head):
        die("FAIL: expected 301 with %r" % want_loc)
    print("  PASS: 80 answered 301 to https preserving the path")


# -- multipart parse, mirroring frame.rs, for the verifiers -----------------
OPEN = b"--EH912ZZ\r\n"
CLOSE = b"--EH912ZZ--\r\n"
PART_HEAD = b"Content-type: text/plain\r\n\r\n"
SP = b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\""
NCP = b"['ud','SimpleDbgServer2ClientIntf','noOfClient',["
SCP = b"['setCid',"


def parse_parts(body):
    parts, i = [], 0
    while True:
        st = body.find(OPEN, i)
        if st < 0:
            break
        head = st + len(OPEN)
        if not body[head:].startswith(PART_HEAD):
            break
        ps = head + len(PART_HEAD)
        end = body.find(CLOSE, ps)
        if end < 0:
            break
        parts.append(body[ps:end - 2])
        i = end + len(CLOSE)
    return parts


def label_of(payload):
    if payload.startswith(SCP) and payload.endswith(b"]"):
        return ("setCid", payload[len(SCP):-1])
    if payload.startswith(NCP) and payload.endswith(b"]]"):
        return ("noOfClient", payload[len(NCP):-2])
    if payload.startswith(SP) and payload.endswith(b'"]]'):
        return ("status", payload[len(SP):-3])
    return ("other", payload)


def _status_texts(body):
    return [t for (k, t) in (label_of(p) for p in parse_parts(body)) if k == "status"]


def _report(got, want, what):
    if got == want:
        print("  PASS: %s (%d frames)" % (what, len(got)))
        for t in got:
            print("        " + t.decode("latin-1"))
        return
    print("  FAIL: %s" % what)
    print("  got  (%d):" % len(got))
    for t in got:
        print("        " + repr(t))
    print("  want (%d):" % len(want))
    for t in want:
        print("        " + repr(t))
    sys.exit(1)


def verify(path):
    with open(path, "rb") as f:
        body = f.read()
    want = ([T_REG] + [T_REGF] * 3 + [T_READY] + [T_READYF] * 3 + [T_HOME]
            + [T_ARMED] + [T_ARMEDF] * 3)
    _report(_status_texts(body), want, "generated stream matches the expected sequence")


def verify_serve(path):
    with open(path, "rb") as f:
        raw = f.read()
    head_end = raw.find(b"\r\n\r\n")
    if head_end < 0 or b"multipart/x-mixed-replace" not in raw[:head_end]:
        die("FAIL: no multipart subscribe head; got:\n    %r" % raw[:120])
    labels = [label_of(p) for p in parse_parts(raw[head_end + 4:])]
    if len(labels) < 3 or labels[0][0] != "setCid":
        die("FAIL: part 0 should be setCid, got %r" % labels[:1])
    if labels[1] != ("status", b"Client Connected"):
        die("FAIL: part 1 should be 'Client Connected', got %r" % (labels[1],))
    if labels[2][0] != "noOfClient":
        die("FAIL: part 2 should be noOfClient, got %r" % (labels[2],))
    got = [t for (k, t) in labels[3:] if k == "status"]
    # snapshot (504 + Ready + the current LCD line), then LIVE: armed + its LCD
    # line (from the arm API call), then ready + its LCD line (from the disarm).
    # Console frames are 1 x id 20 + 3 x id -1 copies each.
    want = ([T_REG] + [T_REGF] * 3 + [T_READY] + [T_READYF] * 3
            + [T_LCD_DIS] + [T_LCD_DISU] * 3
            + [T_ARMED] + [T_ARMEDF] * 3 + [T_LCD_ARM] + [T_LCD_ARMU] * 3
            + [T_READY] + [T_READYF] * 3 + [T_LCD_DIS] + [T_LCD_DISU] * 3)
    # Required PREFIX: a silence re-register late in the capture window would
    # legitimately append another 504 + Ready + LCD set, so trailing frames are
    # reported, not failed.
    if got[:len(want)] == want:
        extra = len(got) - len(want)
        print("  PASS: snapshot then live arm/disarm with LCD lines, in order (%d frames%s)"
              % (len(want), ", +%d after (re-register)" % extra if extra else ""))
        for t in got[:len(want)]:
            print("        " + t.decode("latin-1"))
        return
    _report(got, want, "served stream")


def verify_cmds(cmdlog, permanent=False):
    """`permanent`: the server was killed rather than reaching a window's end, so
    no 501 is expected -- a permanent server never unregisters; its relaunch
    re-registers with a fresh 500 instead."""
    with open(cmdlog) as f:
        rows = [tuple(int(x) for x in ln.split("\t")) for ln in f if ln.strip()]
    print("  fake tuxedo saw commands: %s" % rows)
    codes = [c for c, _ in rows]
    if codes[:2] != [500, 19]:
        die("FAIL: must open with 500 REGISTER then 19 CONSOLE_MODE (got %r)" % codes[:2])
    if (2, 1234) not in rows:
        die("FAIL: no ARM_STAY (2) with user code 1234 at +0x0C reached the queue")
    if (3, 1234) not in rows:
        die("FAIL: no DISARM (3) with user code 1234 at +0x0C reached the queue")
    if rows.index((3, 1234)) < rows.index((2, 1234)):
        die("FAIL: disarm arrived before arm")
    # the silence watchdog: after the disarm the fake panel goes quiet, and
    # tuxweb must register again -- 500 then 19 -- exactly once per silence
    regs = [i for i, c in enumerate(codes) if c == 500]
    if len(regs) < 2:
        die("FAIL: no silence re-register (only %d x 500); the Home/Back gap is open" % len(regs))
    for i in regs:
        if codes[i + 1:i + 2] != [19]:
            die("FAIL: a 500 at index %d was not followed by 19 (console mode)" % i)
    if regs[1] < codes.index(3):
        die("FAIL: the re-register came before the disarm, i.e. during traffic, not silence")
    if permanent:
        if 501 in codes:
            die("FAIL: a permanent server must never send 501 (it would switch the firehose off)")
        print("  PASS: 500+19, arm(2,1234), disarm(3,1234), silence re-register 500+19, NO 501")
    else:
        if codes[-1:] != [501]:
            die("FAIL: the last command must be the 501 UNREGISTER (got %r)" % codes[-1:])
        print("  PASS: 500+19, arm(2,1234), disarm(3,1234), silence re-register 500+19, then 501")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        die(__doc__)
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd == "mkqueues":
        mkqueues()
    elif cmd == "serve":
        serve(a[0] if a else "12")
    elif cmd == "serve_tux":
        serve_tux(a[0], a[1])
    elif cmd == "client":
        client(a[0], a[1], a[2], a[3] if len(a) > 3 else None)
    elif cmd == "pushdeny":
        pushdeny(a[0])
    elif cmd == "apicall":
        apicall(*a[:7])
    elif cmd == "redirectget":
        redirectget(a[0], a[1])
    elif cmd == "verify":
        verify(a[0])
    elif cmd == "verify_serve":
        verify_serve(a[0])
    elif cmd == "verify_cmds":
        verify_cmds(a[0], permanent=(len(a) > 1 and a[1] == "permanent"))
    elif cmd == "unlink":
        for name in (QR, QC):
            rt.mq_unlink(name)
        print("  unlinked both queues")
    else:
        die("unknown subcommand %r" % cmd)
