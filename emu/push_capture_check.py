"""Bench harness for stage 8a's push generator (`tuxweb --push-capture`).

Proves the whole IPC -> PanelState -> legacy-frame path on REAL kernel message
queues, without Barracuda and without a panel: a fake `/tuxedo` writes 556-byte
replies, tuxweb receives them and writes the generated multipart stream to a
file, and `verify` asserts that stream frame-for-frame against what the two
capture fixtures proved the vendor emits.

Runs on the build VM as root (POSIX mqueues are in the kernel; the chroot does
not change the IPC namespace, which is why an x86 driver can feed an ARM guest
-- see emu/pushdriver.py). Subcommands:

    mkqueues            (re)create /Q_ServCmdTrsmtr (556) and /Q_ServCmdRcver (404)
    serve <deadline>    act as /tuxedo: on the 500, emit a 504 + status replies
    verify <file>       assert the generated stream matches the expected frames

The expected frames here are the SAME shapes `push::tests` reproduces from the
fixtures; if this passes on real queues and those pass on the captures, the
generator is exercised end to end.
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


def reply_status(msg_type, arg, flag, text):
    """A 556-byte status/typed reply, laid out as Reply::parse reads it:
    session +0x00 (0, as registerclient writes), msgType +0x04, arg +0x08,
    then the text at +0x0E with the state byte as its first byte."""
    b = bytearray(REPLY)
    b[0x00:0x04] = (0).to_bytes(4, "little")
    b[0x04:0x08] = msg_type.to_bytes(4, "little")
    b[0x08:0x0C] = (arg & 0xFFFFFFFF).to_bytes(4, "little")
    b[0x0E] = flag
    t = text.encode("latin-1")
    b[0x0F:0x0F + len(t)] = t
    return bytes(b)


def reply_typed(msg_type, arg, text):
    """A 556-byte typed reply (msgType 18) whose text begins AT +0x0E.

    Unlike a 21, an 18 has no 0xFE/0xFF state byte -- its text starts at +0x0E
    directly (the captured frame is `0:18:1 P1  H:2`, so `text[0]` is '1'). This
    is the layout `frame_typed` reads; using the status helper here would put a
    byte where the panel puts the first text character."""
    b = bytearray(REPLY)
    b[0x04:0x08] = msg_type.to_bytes(4, "little")
    b[0x08:0x0C] = (arg & 0xFFFFFFFF).to_bytes(4, "little")
    t = text.encode("latin-1")
    b[0x0E:0x0E + len(t)] = t
    return bytes(b)


def reply_504(part, desc, extra):
    """A 556-byte registration reply at the 504 offsets (reply-layouts.txt / §5.12)."""
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


# The replies the fake /tuxedo emits after the 500, and the exact status texts
# tuxweb must produce for them (frame + its measured fillers). Kept together so
# the responder and the oracle cannot drift apart.
FE, FF = 0xFE, 0xFF
REPLIES_TO_SEND = [
    reply_504(1, "P1  H", (1, 0, 3, 3)),
    reply_status(21, 1, FE, "1Ready To Arm"),
    reply_typed(18, 2, "1 P1  H"),                  # text begins at +0x0E, no state byte
    reply_status(21, 1, FF, "2Armed Stay"),
]


def expected_texts():
    def s(*parts):
        out = bytearray()
        for p in parts:
            out += p if isinstance(p, bytes) else p.encode("latin-1")
        return bytes(out)
    reg = b"0:504:1:P1  H:1:0:3:3"
    regf = b"0:-1:1:P1  H:1:0:3:3"
    ready = s("0:21:1:fe:", bytes([FE]), "1Ready To Arm:2")
    readyf = s("0:-1:", bytes([FE]), "1Ready To Arm")
    home = b"0:18:1 P1  H:2"
    armed = s("0:21:1:ff:", bytes([FF]), "2Armed Stay:2")
    armedf = s("0:-1:", bytes([FF]), "2Armed Stay")
    return [reg] + [regf] * 3 + [ready] + [readyf] * 3 + [home] + [armed] + [armedf] * 3


def serve(deadline_s):
    """Read commands; on the 500, emit the reply sequence; exit on 501/deadline."""
    cmdq = rt.mq_open(QC, O_RDWR | O_NONBLOCK)
    repq = rt.mq_open(QR, O_RDWR)
    if cmdq < 0 or repq < 0:
        die("serve mq_open failed: %s" % os.strerror(ctypes.get_errno()))
    buf = ctypes.create_string_buffer(COMMAND)
    prio = ctypes.c_uint(0)
    ts = ctypes.c_char_p(None)
    deadline = time.time() + float(deadline_s)
    registered = False
    print("  fake tuxedo: waiting for the 500")
    while time.time() < deadline:
        n = rt.mq_timedreceive(cmdq, buf, COMMAND, ctypes.byref(prio), ts)
        if n < 0:
            time.sleep(0.1)
            continue
        code = int.from_bytes(buf.raw[4:8], "little")
        if code == 500 and not registered:
            registered = True
            print("  fake tuxedo: got 500, sending 504 + %d status replies"
                  % (len(REPLIES_TO_SEND) - 1))
            for msg in REPLIES_TO_SEND:
                if rt.mq_send(repq, msg, REPLY, 0) < 0:
                    die("mq_send reply: %s" % os.strerror(ctypes.get_errno()))
                time.sleep(0.25)
        elif code == 501:
            print("  fake tuxedo: got 501, done")
            return
    print("  fake tuxedo: deadline reached")


# -- multipart parse, mirroring frame.rs, for the verifier ------------------
OPEN = b"--EH912ZZ\r\n"
CLOSE = b"--EH912ZZ--\r\n"
PART_HEAD = b"Content-type: text/plain\r\n\r\n"
SP = b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\""
NCP = b"['ud','SimpleDbgServer2ClientIntf','noOfClient',["
SCP = b"['setCid',"


def parse_parts(body):
    """Every part payload, in order (not just statusMessageText)."""
    parts, i = [], 0
    while True:
        s = body.find(OPEN, i)
        if s < 0:
            break
        head = s + len(OPEN)
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


def parse_status_texts(body):
    texts, i = [], 0
    while True:
        s = body.find(OPEN, i)
        if s < 0:
            break
        head = s + len(OPEN)
        if not body[head:].startswith(PART_HEAD):
            break
        ps = head + len(PART_HEAD)
        end = body.find(CLOSE, ps)
        if end < 0:
            break
        payload = body[ps:end - 2]
        if payload.startswith(SP) and payload.endswith(b'"]]'):
            texts.append(payload[len(SP):-3])
        i = end + len(CLOSE)
    return texts


def verify(path):
    with open(path, "rb") as f:
        body = f.read()
    got = parse_status_texts(body)
    want = expected_texts()
    if got == want:
        print("  PASS: %d generated frames match the expected sequence" % len(got))
        for t in got:
            print("        " + t.decode("latin-1"))
        return
    print("  FAIL: generated stream does not match")
    print("  got  (%d):" % len(got))
    for t in got:
        print("        " + repr(t))
    print("  want (%d):" % len(want))
    for t in want:
        print("        " + repr(t))
    sys.exit(1)


def serve_tux(deadline_s):
    """Two-phase fake /tuxedo for the --serve test: on the 500, register the
    panel as Ready; a beat later (after the client has connected) push a live
    Armed frame. That is what proves the client gets the snapshot AND a live
    update, not just one or the other."""
    cmdq = rt.mq_open(QC, O_RDWR | O_NONBLOCK)
    repq = rt.mq_open(QR, O_RDWR)
    if cmdq < 0 or repq < 0:
        die("serve_tux mq_open failed: %s" % os.strerror(ctypes.get_errno()))
    buf = ctypes.create_string_buffer(COMMAND)
    prio = ctypes.c_uint(0)
    ts = ctypes.c_char_p(None)
    deadline = time.time() + float(deadline_s)
    registered = False
    sent_live = False
    print("  fake tuxedo (serve): waiting for the 500")
    while time.time() < deadline:
        n = rt.mq_timedreceive(cmdq, buf, COMMAND, ctypes.byref(prio), ts)
        if n >= 0:
            code = int.from_bytes(buf.raw[4:8], "little")
            if code == 500 and not registered:
                registered = True
                print("  fake tuxedo (serve): got 500, registering panel as Ready")
                for msg in (reply_504(1, "P1  H", (1, 0, 3, 3)),
                            reply_status(21, 1, FE, "1Ready To Arm")):
                    rt.mq_send(repq, msg, REPLY, 0)
                    time.sleep(0.2)
                register_t = time.time()
            elif code == 501:
                print("  fake tuxedo (serve): got 501, done")
                return
        else:
            time.sleep(0.1)
        # ~2.5s after registering, push a LIVE armed frame (the client has
        # connected by now), then keep draining for the 501.
        if registered and not sent_live and time.time() - register_t > 2.5:
            print("  fake tuxedo (serve): pushing a LIVE Armed frame")
            rt.mq_send(repq, reply_status(21, 1, FF, "2Armed Stay"), REPLY, 0)
            sent_live = True
    print("  fake tuxedo (serve): deadline reached")


def client(hostport, seconds, outfile):
    """Subscribe to the push stream and record everything received."""
    import socket
    host, port = hostport.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(b"GET /SimpleDebugger.interface/G. HTTP/1.1\r\nHost: x\r\n\r\n")
    s.settimeout(float(seconds))
    got = bytearray()
    end = time.time() + float(seconds)
    try:
        while time.time() < end:
            b = s.recv(4096)
            if not b:
                break
            got += b
    except socket.timeout:
        pass
    finally:
        s.close()
    with open(outfile, "wb") as f:
        f.write(got)
    print("  client received %d bytes" % len(got))


def apiget(hostport, path, needle):
    """GET an API path on a separate connection; assert 200 and a body needle."""
    import socket
    host, port = hostport.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path).encode())
    s.settimeout(5)
    data = bytearray()
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            data += b
    except socket.timeout:
        pass
    s.close()
    head, _, body = bytes(data).partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin-1", "replace") if head else "(no response)"
    print("  GET %s -> %s" % (path, status))
    print("  body: %s" % body.decode("latin-1", "replace")[:200])
    if not (status.startswith("HTTP/1.1 200") and needle.encode() in body):
        print("  FAIL: expected 200 and %r in the body" % needle)
        sys.exit(1)
    print("  PASS: capability endpoint answered 200 with %r" % needle)


def redirectget(hostport, path):
    """GET a path on the plaintext redirect port; assert 301 to https + path."""
    import socket
    host, port = hostport.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(("GET %s HTTP/1.1\r\nHost: panel.test\r\nConnection: close\r\n\r\n" % path).encode())
    s.settimeout(5)
    data = bytearray()
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            data += b
    except socket.timeout:
        pass
    s.close()
    head = bytes(data).split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    status = head.split("\r\n")[0]
    want_loc = "Location: https://panel.test%s" % path
    print("  GET %s -> %s" % (path, status))
    print("  %s" % next((l for l in head.split("\r\n") if l.lower().startswith("location:")), "(no Location)"))
    if not (status.startswith("HTTP/1.1 301") and want_loc in head):
        print("  FAIL: expected 301 with %r" % want_loc)
        sys.exit(1)
    print("  PASS: 80 answered 301 to https preserving the path")


def verify_serve(path):
    with open(path, "rb") as f:
        raw = f.read()
    # the subscribe head must be the multipart one, then the body
    head_end = raw.find(b"\r\n\r\n")
    if head_end < 0 or b"multipart/x-mixed-replace" not in raw[:head_end]:
        die("FAIL: no multipart subscribe head; got:\n    %r" % raw[:120])
    parts = parse_parts(raw[head_end + 4:])
    labels = [label_of(p) for p in parts]

    # preamble: setCid, Client Connected, noOfClient (setCid value is minted, so
    # only its shape is checked)
    def want_kind(i, kind, note):
        if i >= len(labels) or labels[i][0] != kind:
            die("FAIL: part %d expected %s (%s), got %r" % (i, kind, note, labels[i:i + 1]))
    want_kind(0, "setCid", "per-connection id")
    if labels[1] != ("status", b"Client Connected"):
        die("FAIL: part 1 expected 'Client Connected', got %r" % (labels[1],))
    want_kind(2, "noOfClient", "subscriber count")

    got_status = [t for (k, t) in labels[3:] if k == "status"]

    def s(*p):
        out = bytearray()
        for x in p:
            out += x if isinstance(x, bytes) else x.encode("latin-1")
        return bytes(out)
    want = (
        [b"0:504:1:P1  H:1:0:3:3"] + [b"0:-1:1:P1  H:1:0:3:3"] * 3
        + [s("0:21:1:fe:", bytes([FE]), "1Ready To Arm:2")] + [s("0:-1:", bytes([FE]), "1Ready To Arm")] * 3
        + [s("0:21:1:ff:", bytes([FF]), "2Armed Stay:2")] + [s("0:-1:", bytes([FF]), "2Armed Stay")] * 3
    )
    if got_status == want:
        print("  PASS: snapshot + live update delivered in order (%d status frames)" % len(got_status))
        for t in got_status:
            print("        " + t.decode("latin-1"))
        return
    print("  FAIL: served stream does not match")
    print("  got  (%d):" % len(got_status))
    for t in got_status:
        print("        " + repr(t))
    print("  want (%d):" % len(want))
    for t in want:
        print("        " + repr(t))
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        die("usage: push_capture_check.py mkqueues|serve <deadline>|serve_tux <deadline>"
            "|client <host:port> <secs> <out>|verify <file>|verify_serve <file>|unlink")
    cmd = sys.argv[1]
    if cmd == "mkqueues":
        mkqueues()
    elif cmd == "serve":
        serve(sys.argv[2] if len(sys.argv) > 2 else "12")
    elif cmd == "serve_tux":
        serve_tux(sys.argv[2] if len(sys.argv) > 2 else "15")
    elif cmd == "client":
        client(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "apiget":
        apiget(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "redirectget":
        redirectget(sys.argv[2], sys.argv[3])
    elif cmd == "verify":
        verify(sys.argv[2])
    elif cmd == "verify_serve":
        verify_serve(sys.argv[2])
    elif cmd == "unlink":
        for name in (QR, QC):
            rt.mq_unlink(name)
        print("  unlinked both queues")
    else:
        die("unknown subcommand %r" % cmd)
