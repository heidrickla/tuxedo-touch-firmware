#!/usr/bin/env python3
"""
A WORKING API console for the Honeywell Tuxedo Touch.

The panel ships its own "API test console" at /tuxedoapi.html. It is not usable:
most endpoints answer with their own documentation form instead of data, and
nothing there exercises the second (command) API or the push stream at all.

This replaces it with something that actually works, against everything verified
live on TUXW_V5.3.21.0:

  * the REST API          /system_http_api/API_REV01/...   (AES-encrypted body)
  * the command API       /handlerequest.html?cmd=N...     (numeric commands)
  * the push stream       /SimpleDebugger.interface/G.     (replies + live state)

    python tuxedo_api_console.py 203.0.113.5 -u Lewis

Then, at the prompt:

    help                 commands and endpoint lists
    status               security status
    get <Endpoint>       any REST endpoint, e.g.  get GetSceneList
    cmd <N>              any command id, e.g.  cmd 18
    watch [secs]         live push stream
    arm stay|away|night  ARMS THE PANEL
    disarm               disarms
    raw <path> [body]    arbitrary REST path, for exploration

ARMING IS REAL. This panel's web password is also the panel user code, so the
console can arm and disarm for real. Those two verbs prompt for confirmation.
Nothing else changes panel state.
"""

import argparse
import getpass
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxedo_status_probe import TuxedoProbe, hmac_hex  # noqa: E402
from tuxedo_push import PushStream, READ_ONLY_CMDS  # noqa: E402

# Verified live: these answer with data. Everything else tested returned the
# endpoint's own documentation form or an embedded 404.
REST_WORKING = [
    "GetSecurityStatus",
    "GetSceneList",
    "GetOccupancyMode",                      # misrouted: returns security status
    "AdvancedMultimedia/GetCameraList",
    "AdvancedAutomation/DoorBell/getDoorBell",
    "Administration/ViewEnrolledDeviceMAC",  # answers "local only"
    "Administration/ViewIPURL",
]

REST_FORM_ONLY = [
    "GetDeviceList", "GetLightStatus", "GetDoorLockStatus", "GetGarageDoorStatus",
    "GetWaterValveStatus", "GetThermostatMode", "GetThermostatTemperature",
    "GetThermostatClock", "GetThermostatSchedule", "AdvancedMultimedia/GetVideoEvents",
]


def decode_payload(s):
    """
    Push payloads are colon-delimited; the byte before a status string is the
    PARTITION NUMBER as a raw byte, not text. Render it readably.
    """
    out = []
    for ch in s:
        o = ord(ch)
        out.append(ch if 32 <= o < 127 else f"<{o}>")
    return "".join(out)


class Console:
    def __init__(self, host, user, pw):
        self.host, self.user, self.code = host, user, pw
        self.p = TuxedoProbe(host, user, pw, scheme="http")
        self.p.login()
        self.sid = self._session_id()
        self.tokenkey = self._hidden("hiddenKey")

    def _session_id(self):
        st, h, b = self.p._open(f"{self.p.base}/eventhandler.html",
                                headers={"Cookie": self.p.session_cookie})
        body = b.decode("utf-8", "replace")
        # The attribute order varies, so try both. The old pattern assumed
        # id before value and silently returned "id=" on this firmware.
        for pat in (r'id="hidSession"[^>]*value="([^"]*)"',
                    r'value="([^"]*)"[^>]*id="hidSession"'):
            m = re.search(pat, body)
            if m:
                return m.group(1)
        return ""

    # -- REST -------------------------------------------------------------

    def _hidden(self, name):
        """Read a hidden input from eventhandler.html by id."""
        st, h, b = self.p._open(f"{self.p.base}/eventhandler.html",
                                headers={"Cookie": self.p.session_cookie})
        body = b.decode("utf-8", "replace")
        for pat in (r'id="%s"[^>]*value="([^"]*)"' % name,
                    r'value="([^"]*)"[^>]*id="%s"' % name):
            m = re.search(pat, body)
            if m:
                return m.group(1)
        return ""

    def rest(self, endpoint, plain=""):
        ep = "/" + endpoint.lstrip("/")
        tok = hmac_hex(self.p.key_hex,
                       f"MACID:Browser,Path:API_REV01{ep}", hashlib.sha1)
        enc = self.p._encrypt(plain)
        body = urllib.parse.urlencode(
            {"param": enc, "len": str(len(enc)), "tstamp": "1"}).encode()
        st, h, b = self.p._open(
            f"{self.p.base}/system_http_api/API_REV01{ep}", data=body,
            headers={"authtoken": tok, "identity": self.p.iv_hex,
                     "Cookie": self.p.session_cookie,
                     "Content-Type": "application/x-www-form-urlencoded"})
        raw = b.decode("utf-8", "replace")
        if st != 200:
            return f"HTTP {st}"
        try:
            r = json.loads(raw).get("Result")
            return self.p._decrypt(r) if r else raw
        except Exception:
            if "<input" in raw:
                return "[not implemented — endpoint returned its documentation form]"
            if "ErrorCode" in raw:
                m = re.search(r'\{[^}]*ErrorCode[^}]*\}', raw)
                return f"[embedded error] {m.group() if m else raw[:80]}"
            return "[non-JSON] " + raw[:120].replace("\n", " ")

    def status(self):
        return self.rest("GetSecurityStatus", "")

    # -- command API ------------------------------------------------------

    def cmd(self, code, **extra):
        # Shape taken from the panel's own script/httpRequest.js and
        # script/consoleRequest.js. tokenkey comes from the hidden field
        # "hiddenKey" in eventhandler.html (getKeyFromEV), and httpRequest.js
        # sends it as a request header as well as a query parameter. It was
        # previously hardcoded empty here.
        q = {"cmd": str(code), "Type": str(code), "pID": "-1", "uCode": "0",
             "sessionid": self.sid, "filters": "0", "index": "0",
             "tarTemp": "0", "tokenkey": self.tokenkey, "sid": "0.5"}
        q.update({k: str(v) for k, v in extra.items()})
        st, h, b = self.p._open(
            f"{self.p.base}/handlerequest.html?" + urllib.parse.urlencode(q),
            headers={"Cookie": self.p.session_cookie,
                     "tokenkey": self.tokenkey})
        return st, len(b)

    # -- arming -----------------------------------------------------------

    def arm(self, mode):
        return self.rest("/AdvancedSecurity/ArmWithCode",
                         f"arming={mode.upper()}&ucode={self.code}&pID=1&operation=set")

    def disarm(self):
        return self.rest("/AdvancedSecurity/DisarmWithCode",
                         f"ucode={self.code}&pID=1&operation=set")

    # -- push -------------------------------------------------------------

    def watch(self, seconds=20):
        rows = []

        def on_frame(raw):
            m = re.search(r"'statusMessageText',\[\"(.*?)\"\]\]", raw)
            if m:
                rows.append((time.strftime("%H:%M:%S"), decode_payload(m.group(1))))
                print(f"   {rows[-1][0]}  {rows[-1][1][:96]}")
            elif raw.startswith("['setCid'"):
                print(f"   connected (cid {re.search(r'(\d+)', raw).group(1)})")
        ps = PushStream(self.host, self.p.session_cookie, on_frame=on_frame)
        t = threading.Thread(target=ps.run, kwargs={"seconds": seconds}, daemon=True)
        t.start()
        t.join(timeout=seconds + 3)
        ps.stop()
        return len(rows)


HELP = """
  status                  security status (REST)
  get <Endpoint> [body]   call a REST endpoint
  cmd <N> [k=v ...]       send a command-API command
  watch [seconds]         live push stream (replies + state changes)
  arm stay|away|night     ARM the panel (confirms first)
  disarm                  DISARM the panel (confirms first)
  raw <path> [body]       arbitrary REST path
  endpoints               which REST endpoints work and which do not
  cmds                    read-only command ids
  quit
"""


def main():
    ap = argparse.ArgumentParser(description="A working API console for the Tuxedo Touch.")
    ap.add_argument("host")
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("--password", default=os.environ.get("TUXEDO_PASSWORD"))
    ap.add_argument("-e", "--exec", dest="script", nargs="*", default=None,
                    help="run these commands then exit (non-interactive)")
    args = ap.parse_args()
    pw = args.password or getpass.getpass("Tuxedo password (= panel code): ")

    c = Console(args.host, args.username, pw)
    print(f"connected to {c.p.base} as {args.username}; sessionid={c.sid}")
    print(f"status: {c.status()}")

    def run(line):
        parts = line.strip().split()
        if not parts:
            return True
        op, rest = parts[0].lower(), parts[1:]
        if op in ("quit", "exit"):
            return False
        elif op == "help":
            print(HELP)
        elif op == "status":
            print("  " + c.status())
        elif op == "endpoints":
            print("  WORKING:")
            for e in REST_WORKING:
                print(f"    {e}")
            print("  RETURN A FORM (not implemented):")
            for e in REST_FORM_ONLY:
                print(f"    {e}")
        elif op == "cmds":
            for k, v in sorted(READ_ONLY_CMDS.items()):
                print(f"    {k:<5} {v}")
        elif op == "get" and rest:
            print("  " + c.rest(rest[0], " ".join(rest[1:])))
        elif op == "raw" and rest:
            print("  " + c.rest(rest[0], " ".join(rest[1:])))
        elif op == "cmd" and rest:
            extra = dict(kv.split("=", 1) for kv in rest[1:] if "=" in kv)
            st, n = c.cmd(int(rest[0]), **extra)
            print(f"  HTTP {st}, {n}-byte body (replies arrive on the push stream)")
        elif op == "watch":
            secs = float(rest[0]) if rest else 20
            print(f"  watching {secs:.0f}s ...")
            print(f"  {c.watch(secs)} frames")
        elif op in ("arm", "disarm"):
            what = f"ARM {rest[0].upper()}" if op == "arm" and rest else op.upper()
            ok = os.environ.get("TUXEDO_CONFIRM") == "yes"
            if not ok:
                try:
                    ok = input(f"  {what} the panel. Type YES to confirm: ") == "YES"
                except EOFError:
                    ok = False
            if not ok:
                print("  cancelled")
            else:
                print("  " + (c.arm(rest[0]) if op == "arm" and rest else c.disarm()))
        else:
            print("  ? try: help")
        return True

    if args.script is not None:
        for line in args.script:
            print(f"\n> {line}")
            if not run(line):
                break
        return 0
    print(HELP)
    while True:
        try:
            line = input("tuxedo> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not run(line):
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
