#!/usr/bin/env python3
"""
Read a Honeywell Tuxedo Touch's EventHandler PUSH STREAM, and issue commands
whose replies arrive on it.

WHY THIS MATTERS

The panel's REST endpoint `GetSecurityStatus` reads a cache that the firmware
can only fill from an ECP message, and returns the literal `"Not available"`
when that cache is empty. That is the long-standing "status goes unknown" bug.

**The push stream does not use that cache.** Partition status arrives on it
directly. A client on this stream gets the alarm state pushed, and never sees
`"Not available"` at all.

THE URL, which is the whole trick

    GET /SimpleDebugger.interface/G.        <- works
    GET /SimpleDebugger.interfaceG.         <- 404

The slash before "G." is required. Only the session cookie is needed: no CSRF
token, no query string. (The vendor's own client appends "G." to a base URL that
already ends in a slash, which is why this is easy to get wrong.)

WIRE FORMAT  [CONFIRMED against a live panel]

    Content-type: multipart/x-mixed-replace; boundary="EH912ZZ"

each part being one of

    ['setCid', <connection id>]
    ['ud','SimpleDbgServer2ClientIntf','noOfClient',[<n>]]
    ['ud','SimpleDbgServer2ClientIntf','statusMessageText',["<payload>"]]

Payloads are colon-delimited and **field 2 is the originating command id**:

    0:504:1:P1  H:1:0:3:3        504 = registration / initial data
    0:21:1:fe:<part>Ready To Arm:2   21 = PARTITION STATUS  <- the useful one
    0:18:1 P1  H:2               18 = home partition
    0:-1:<part>Ready To Arm      -1 = unsolicited status update

    python tuxedo_push.py 203.0.113.5 -u Lewis                 # watch the stream
    python tuxedo_push.py 203.0.113.5 -u Lewis --cmd 12 17     # send, then watch

READ-ONLY BY DEFAULT. --cmd accepts only commands from a read-only allowlist.
Arming, disarming and bypass are deliberately NOT reachable from this tool.
"""

import argparse
import getpass
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxedo_status_probe import TuxedoProbe, legacy_ssl_context  # noqa: E402

PUSH_PATH = "/SimpleDebugger.interface/G."

# Commands that only READ. Anything that arms, disarms, bypasses or programs is
# excluded on purpose — this is a diagnostic tool, not a control surface.
READ_ONLY_CMDS = {
    12: "all zone current status",
    17: "event log upload",
    18: "get home partition",
    21: "partition status broadcast",
    22: "panel offline broadcast",
    51: "IP camera status",
    134: "get scene list",
    138: "get system time",
    155: "get camera list",
    500: "client register",
}

# ---------------------------------------------------------------------------
# Frame decoding  [CONFIRMED byte-exact against a live panel, arm/disarm cycle]
#
#   0:21:1:fe:þ1Ready To Arm:2
#   0:21:1:ff:ÿ259  Secs Remaining:2
#   |  |  | |   |  ||
#   |  |  | |   |  |+- display text
#   |  |  | |   |  +-- COLOUR code: 1 = green, 2 = red (matches the REST API)
#   |  |  | |   +----- the same flag again, as a RAW BYTE
#   |  |  | +--------- state flag as hex TEXT: fe = ready/disarmed,
#   |  |  |            ff = arming/armed
#   |  |  +----------- partition number
#   |  +-------------- command id (21 partition status, 18 home partition,
#   |                  504 initial data, -1 unsolicited update)
#   +----------------- always 0 in everything observed
#
# The raw byte is why the stream MUST be decoded latin-1: utf-8 turns 0xfe/0xff
# into U+FFFD and the state flag is lost.
# ---------------------------------------------------------------------------

STATE_FLAG = {0xFE: "ready/disarmed", 0xFF: "arming/armed"}
COLOUR = {"1": "green", "2": "red", "3": "yellow"}


def decode_status_frame(payload):
    """
    Parse a statusMessageText payload into a dict, or None if it is not a
    status frame. `payload` must be a latin-1 string so raw bytes survive.
    """
    f = payload.split(":")
    if len(f) < 3:
        return None
    try:
        cmd = int(f[1])
    except ValueError:
        return None
    out = {"cmd": cmd, "raw": payload}
    # Locate the field carrying the raw flag byte.
    for part in f[2:]:
        if part and ord(part[0]) in STATE_FLAG:
            flag = ord(part[0])
            out["state_flag"] = STATE_FLAG[flag]
            out["armed"] = (flag == 0xFF)
            body = part[1:]
            if body and body[0] in COLOUR:
                out["colour"] = COLOUR[body[0]]
                body = body[1:]
            out["text"] = body
            break
    if "text" not in out:
        out["text"] = ":".join(f[2:])
    if len(f) > 2 and f[2].isdigit():
        out["partition"] = int(f[2])
    return out


FRAME_RE = re.compile(r"\[.*?\]\]|\['setCid',\s*\d+\]")


def parse_payload(payload):
    """
    Split a colon-delimited payload. Field 2 is the command id when present.
    Returns (cmd_id or None, fields).
    """
    fields = payload.split(":")
    cmd = None
    if len(fields) > 1:
        try:
            cmd = int(fields[1])
        except ValueError:
            pass
    return cmd, fields


def describe(payload):
    d = decode_status_frame(payload)
    if d and "state_flag" in d:
        return (f"  cmd {d['cmd']:<5} part {d.get('partition','?')}  "
                f"{d['state_flag']:<15} {d.get('colour','?'):<6} {d['text']}")
    cmd, fields = parse_payload(payload)
    if cmd is None:
        return f"          {payload}"
    name = READ_ONLY_CMDS.get(cmd, "")
    if cmd == -1:
        name = "unsolicited status update"
    tag = f"cmd {cmd}" + (f" ({name})" if name else "")
    return f"  {tag:<38} {':'.join(fields[2:]) or payload}"


class PushStream:
    """Long-lived multipart reader. Runs on its own socket, not urllib."""

    def __init__(self, host, cookie, port=443, on_frame=None):
        self.host, self.port, self.cookie = host, port, cookie
        self.on_frame = on_frame or (lambda raw: None)
        self._stop = threading.Event()
        self.cid = None
        self.clients = None

    def stop(self):
        self._stop.set()

    def run(self, seconds=None):
        ctx = legacy_ssl_context()
        raw = socket.create_connection((self.host, self.port), timeout=15)
        sock = ctx.wrap_socket(raw, server_hostname=self.host)
        req = (
            f"GET {PUSH_PATH} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Cookie: {self.cookie}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        sock.sendall(req.encode())
        sock.settimeout(2.0)

        deadline = (time.monotonic() + seconds) if seconds else None
        buf = ""
        seen = 0
        try:
            while not self._stop.is_set():
                if deadline and time.monotonic() > deadline:
                    break
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                # latin-1, NOT utf-8: payloads embed the partition number as a RAW BYTE.
                # Decoding as utf-8 turns it into U+FFFD and destroys the value.
                buf += chunk.decode("latin-1")
                # Emit complete frames, keep the tail for the next read.
                for m in FRAME_RE.finditer(buf):
                    self._handle(m.group())
                    seen = m.end()
                if seen:
                    buf = buf[seen:]
                    seen = 0
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _handle(self, frame):
        if frame.startswith("['setCid'"):
            m = re.search(r"(\d+)", frame)
            if m:
                self.cid = int(m.group(1))
            self.on_frame(frame)
            return
        m = re.search(r"'(\w+)',\[(.*)\]\]$", frame)
        if m and m.group(1) == "noOfClient":
            try:
                self.clients = int(m.group(2))
            except ValueError:
                pass
        self.on_frame(frame)


def main():
    ap = argparse.ArgumentParser(
        description="Read the Tuxedo Touch push stream. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Read-only commands: "
               + ", ".join(f"{k}={v}" for k, v in sorted(READ_ONLY_CMDS.items())),
    )
    ap.add_argument("host")
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("--password", default=os.environ.get("TUXEDO_PASSWORD"))
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--cmd", type=int, nargs="*", default=[],
                    help="read-only command ids to issue while listening")
    ap.add_argument("--raw", action="store_true", help="print frames verbatim")
    ap.add_argument("--jsonl", help="append parsed frames here")
    args = ap.parse_args()

    bad = [c for c in args.cmd if c not in READ_ONLY_CMDS]
    if bad:
        ap.error(f"not on the read-only allowlist: {bad}. This tool cannot arm, "
                 f"disarm or bypass by design.")

    pw = args.password or getpass.getpass("Tuxedo password: ")
    probe = TuxedoProbe(args.host, args.username, pw, scheme="https")
    print(f"Logging in to {probe.base} as {args.username} ...")
    probe.login()
    print("Login OK.\n")

    sink = open(args.jsonl, "a", encoding="utf-8") if args.jsonl else None
    count = {"n": 0}

    def on_frame(raw):
        count["n"] += 1
        if args.raw:
            print("  " + raw[:200])
        else:
            m = re.search(r"'statusMessageText',\[\"(.*?)\"\]\]", raw)
            if m:
                print(describe(m.group(1)))
            elif raw.startswith("['setCid'"):
                print(f"  connected, cid={re.search(r'(\d+)', raw).group(1)}")
            elif "noOfClient" in raw:
                print(f"  clients now {re.search(r'\[(\d+)\]', raw).group(1)}")
        if sink:
            m = re.search(r"'statusMessageText',\[\"(.*?)\"\]\]", raw)
            if m:
                cmd, fields = parse_payload(m.group(1))
                sink.write(json.dumps({"cmd": cmd, "fields": fields,
                                       "raw": m.group(1)}) + "\n")
                sink.flush()

    stream = PushStream(args.host, probe.session_cookie, on_frame=on_frame)
    t = threading.Thread(target=stream.run, kwargs={"seconds": args.seconds},
                         daemon=True)
    t.start()
    time.sleep(2.0)

    if args.cmd:
        st, h, b = probe._open(f"{probe.base}/eventhandler.html",
                               headers={"Cookie": probe.session_cookie})
        m = re.search(r'id="hidSession"[^>]*value="([^"]*)"',
                      b.decode("utf-8", "replace"))
        sid = m.group(1) if m else ""
        for c in args.cmd:
            q = {"cmd": str(c), "Type": str(c), "pID": "-1", "uCode": "0",
                 "sessionid": sid, "filters": "0", "index": "0",
                 "tarTemp": "0", "tokenkey": "", "sid": "1"}
            probe._open(f"{probe.base}/handlerequest.html?"
                        + urllib.parse.urlencode(q),
                        headers={"Cookie": probe.session_cookie})
            print(f"  >> sent cmd {c} ({READ_ONLY_CMDS[c]})")
            time.sleep(2.5)

    t.join(timeout=args.seconds + 5)
    stream.stop()
    if sink:
        sink.close()
    print(f"\n{count['n']} frames; cid={stream.cid} clients={stream.clients}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
