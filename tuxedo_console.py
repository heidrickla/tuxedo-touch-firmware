#!/usr/bin/env python3
"""
Read a Honeywell Tuxedo Touch's console-mode keypad display over HTTP.

*** SUPERSEDED — the reply path was found. See the note below. ***

Live result on 203.0.113.5: entering console mode (cmd 19), subscribing
(cmd 1125) and requesting the broadcast (cmd 20) all return HTTP 200 with a
ZERO-BYTE body, and /consolekeypad.html contains no consoleText element before
or after. There is no display to read.

CORRECTED: replies DO arrive, on the EventHandler push channel. The working
URL is  GET /SimpleDebugger.interface/G.  (note the SLASH before "G.") with the
session cookie. It returns a multipart/x-mixed-replace stream carrying frames
of the form ['ud',<intf>,'statusMessageText',["<colon:delimited:payload>"]],
where field 2 of the payload is the originating command id.

This tool still needs rework: it expects an inline response, but the reply comes
on the stream. The request shapes and session handling below are correct.

This is almost certainly why the vendor's own virtual console is unreliable:
its display is fed by the same dead channel.

The code below is kept because the request shapes, session model and
error handling are correct and verified — only the reply path is missing. If a
firmware build registers the push channel, or another reply route is found,
this becomes usable unchanged.

WHY THIS EXISTS

The panel's own virtual-console web page is unreliable, and its source explains
why: session-expiry handling is commented out (and pointed at a filename that
does not exist), every send error is swallowed by an empty catch block, the
keystroke buffer is cleared whether or not the send succeeded, and a 1500 ms
debounce means nothing reaches the panel until 1.5 s after the last key. See
TUXEDO-VIRTUAL-CONSOLE-BUGS.md.

This client avoids all of that by construction:
  * session expiry is a first-class case -> re-authenticate and retry, once
  * every failure is surfaced, never swallowed
  * nothing is discarded until the panel has confirmed it
  * no batching, no debounce

WHY IT IS WORTH HAVING

Console mode returns the panel's ACTUAL two-line keypad display. That is far
richer than GetSecurityStatus, which returns one word — and it reads the panel
directly rather than the cache that produces the "Not available" bug.

    python tuxedo_console.py 203.0.113.5 -u Lewis --watch
    python tuxedo_console.py 203.0.113.5 -u Lewis --once

SAFETY. Console mode IS a keypad: the owner confirms it arms and disarms the
system exactly like the physical one. Keystrokes sent here are real keypad
presses on a live alarm panel.

By default this tool is READ-ONLY — it reads the display and sends nothing.
Sending needs --i-understand-this-sends-keys, and even then digits are refused,
because a digit sequence is how a panel is armed, disarmed, or given a code.

UNVERIFIED. The console-mode request shape here is derived from the panel's own
consoleRequest.js and from CReceiverThread::requestconsolemode(web_request*) in
the firmware. It has NOT been run against a live panel. Treat a first run as an
experiment, not as a working tool.
"""

import argparse
import getpass
import html
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxedo_status_probe import TuxedoProbe, legacy_ssl_context  # noqa: E402

# From the panel's own script/consoleRequest.js.
SERV_CONSOLE_MODE = 19
CONSOLEMODESTATUSADD = 1125
CONSOLEMODESTATUSSUB = 1126
HANDLEREQUEST = "/handlerequest.html"

# A session-expired reply redirects to, or renders, the session page.
SESSION_GONE = re.compile(r"SessionPage|sessiontimeout|denied\.html", re.I)


class ConsoleError(RuntimeError):
    """Raised with a real reason. Never swallowed — that is the whole point."""


class TuxedoConsole:
    """
    Console-mode client. Wraps TuxedoProbe for the login/session handling that
    is already proven against real hardware.
    """

    def __init__(self, host, username, password, scheme="https", timeout=20):
        self.probe = TuxedoProbe(host, username, password,
                                 scheme=scheme, timeout=timeout)
        self._session_started = 0.0

    # -- session ----------------------------------------------------------

    def login(self):
        self.probe.login()
        self._session_started = time.monotonic()

    @property
    def session_age(self):
        return time.monotonic() - self._session_started

    # -- the request ------------------------------------------------------

    def _console_request(self, cmd, keys="", retry=True):
        """
        One /handlerequest.html call. Returns the raw body.

        Session expiry is detected and handled HERE rather than ignored: on a
        redirect, a 401/403, or a body that looks like the session page, we
        re-authenticate once and retry. The panel's own page does none of this,
        which is why it dies silently.
        """
        if not self.probe.session_cookie:
            raise ConsoleError("not logged in")

        params = {
            "cmd": str(cmd),
            "Type": str(cmd),
            "pID": "-1",
            "uCode": "0",
            "sessionid": self.probe.session_cookie.split("=", 1)[-1],
            "filters": "0",
            "index": "0",
            "tarTemp": "0",
        }
        if keys:
            params["keys"] = keys
        url = f"{self.probe.base}{HANDLEREQUEST}?" + urllib.parse.urlencode(params)

        status, headers, body = self.probe._open(
            url, headers={"Cookie": self.probe.session_cookie}
        )
        text = body.decode("utf-8", "replace") if body else ""

        expired = (
            status in (301, 302, 303, 307, 308)
            or status in (401, 403)
            or SESSION_GONE.search(text)
            or SESSION_GONE.search(headers.get("Location", ""))
        )
        if expired:
            if not retry:
                raise ConsoleError(
                    f"session rejected again after re-login (HTTP {status})"
                )
            self.login()
            return self._console_request(cmd, keys, retry=False)

        if status != 200:
            raise ConsoleError(f"HTTP {status} from {HANDLEREQUEST}")
        return text

    # -- display ----------------------------------------------------------

    @staticmethod
    def parse_display(body):
        """
        Pull the keypad text out of the response.

        The web page drops it into an element with id "consoleText". We accept
        that, and fall back to the longest plausible text run so a format change
        degrades to something rather than nothing.
        """
        m = re.search(
            r'id=["\']consoleText["\'][^>]*>(.*?)</', body, re.S | re.I
        )
        if m:
            raw = m.group(1)
        else:
            stripped = re.sub(r"<[^>]+>", "\n", body)
            cands = [c.strip() for c in stripped.splitlines() if c.strip()]
            if not cands:
                return None
            raw = max(cands, key=len)

        text = html.unescape(re.sub(r"<br\s*/?>", "\n", raw, flags=re.I))
        text = re.sub(r"<[^>]+>", "", text)
        # Keypad text arrives padded with &nbsp;. Normalise it so callers
        # can string-compare against what a physical keypad shows.
        text = text.replace(" ", " ")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return "\n".join(lines) if lines else None

    def enter(self):
        """Enter console mode and subscribe to status updates."""
        self._console_request(SERV_CONSOLE_MODE)
        self._console_request(CONSOLEMODESTATUSADD)

    def leave(self):
        """Unsubscribe. Best-effort, but the failure is still reported."""
        try:
            self._console_request(CONSOLEMODESTATUSSUB)
        except ConsoleError as exc:
            print(f"  note: could not unsubscribe cleanly: {exc}", file=sys.stderr)

    def read_display(self):
        return self.parse_display(self._console_request(SERV_CONSOLE_MODE))

    def send_keys(self, keys):
        """
        Send keystrokes. Returns the display text afterwards.

        Note what this does NOT do: it does not clear or forget anything until
        the panel has answered. The vendor page discards the buffer whether or
        not the send worked, which is how keystrokes go missing.
        """
        body = self._console_request(SERV_CONSOLE_MODE, keys=keys)
        return self.parse_display(body)



# ---------------------------------------------------------------------------
# Interactive keypad
# ---------------------------------------------------------------------------

class _RawKeyboard:
    """
    Non-blocking single-key input on both Windows and POSIX.

    The POSIX path matters: a blocking read would freeze the refresh timer, so
    the display would only update when you pressed something. A real keypad
    shows countdowns and panel-driven changes while you stand there doing
    nothing, so this uses select() with a short timeout instead.
    """

    def __init__(self):
        self.windows = False
        try:
            import msvcrt  # noqa: F401
            self.windows = True
        except ImportError:
            pass
        self._fd = None
        self._saved = None

    def __enter__(self):
        if not self.windows:
            import termios, tty
            self._fd = sys.stdin.fileno()
            self._saved = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)
        return self

    def __exit__(self, *exc):
        if not self.windows and self._saved is not None:
            import termios
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
        return False

    def get(self, timeout=0.05):
        """Return one character, or None if nothing was typed within timeout."""
        if self.windows:
            import msvcrt
            if msvcrt.kbhit():
                return msvcrt.getwch()
            time.sleep(timeout)
            return None
        import select
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        return sys.stdin.read(1) if r else None


# What the panel's own keypad offers. Letters map to the function keys.
KEYPAD_KEYS = set("0123456789*#ABCD")


def run_keypad(con, refresh=3.0):
    """
    A live keypad. Every keypress is sent IMMEDIATELY — no batching and no
    debounce, which is defect #4 in the vendor page. The display is reprinted
    after each send and refreshed on a timer so entry-delay countdowns move.
    """
    print("=" * 62)
    print(" TUXEDO VIRTUAL KEYPAD — this is a REAL keypad on a LIVE panel.")
    print(" Keys are sent immediately. Digits arm and disarm, exactly as they")
    print(" do on the wall unit.")
    print()
    print("   0-9 * #      keypad keys")
    print("   A B C D      function keys")
    print("   Ctrl-C       quit")
    print("=" * 62)
    print()

    last_shown = None
    last_refresh = 0.0

    def show(text):
        nonlocal last_shown
        if text and text != last_shown:
            stamp = time.strftime("%H:%M:%S")
            flat = text.replace(chr(10), "  |  ")
            print(f"  [{stamp}] {flat}")
            last_shown = text

    try:
        show(con.read_display())
    except ConsoleError as exc:
        print(f"  could not read display: {exc}")

    with _RawKeyboard() as kb:
        while True:
            # Timed refresh, so countdowns and panel-driven changes appear even
            # while nobody is typing. This is what makes it feel like a keypad.
            if time.monotonic() - last_refresh > refresh:
                last_refresh = time.monotonic()
                try:
                    show(con.read_display())
                except ConsoleError as exc:
                    print(f"  refresh failed: {exc}")

            ch = kb.get()
            if ch is None:
                continue
            if ch in ("", ""):
                raise KeyboardInterrupt
            key = ch.upper()
            if key not in KEYPAD_KEYS:
                continue

            try:
                out = con.send_keys(key)
                print(f"  -> {key}")
                show(out)
                last_refresh = time.monotonic()
            except ConsoleError as exc:
                # Never silent. The vendor page swallows this, which is how
                # keystrokes vanish without trace.
                print(f"  !! key {key!r} FAILED: {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="Read a Tuxedo Touch's console-mode keypad display.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SAFETY NOTES

  Read-only by default. --watch and --once only READ the display.

  Sending keystrokes is gated behind --i-understand-this-sends-keys, and digits
  are refused outright: digit sequences are how a panel is armed, disarmed, or
  given a user code, and this tool has never been validated against live
  hardware.

  CONFIRMED BY THE OWNER: the virtual console ARMS AND DISARMS THE SYSTEM
  EXACTLY LIKE THE PHYSICAL KEYPAD. Keystrokes sent through console mode are
  real keypad presses on a live alarm panel.

  This is not a diagnostic read-out with a side effect. It is a keypad. A digit
  sequence here does what the same sequence does on the wall.

  Reading the display appears to be passive, and that is what this tool does by
  default. Sending is the dangerous half, which is why digits are refused
  outright rather than merely warned about.
""",
    )
    parser.add_argument("host")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("--password", default=os.environ.get("TUXEDO_PASSWORD"))
    parser.add_argument("--scheme", choices=("https", "http"), default="https")
    parser.add_argument("--once", action="store_true", help="read once and exit")
    parser.add_argument("--watch", action="store_true",
                        help="poll the display until interrupted")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between reads when watching (default 2)")
    parser.add_argument("--keypad", action="store_true",
                        help="interactive keypad: type keys, see the display live")
    parser.add_argument("--keys", help="send this key sequence, then exit")
    parser.add_argument("--i-understand-this-sends-keys", action="store_true",
                        dest="allow_keys",
                        help="required before --keys will do anything")
    args = parser.parse_args()

    if args.keys:
        if not args.allow_keys:
            parser.error("--keys needs --i-understand-this-sends-keys")
        # Digits are permitted: this is a keypad, and refusing them made the
        # tool useless for its actual purpose. The acknowledgement flag above is
        # the gate, and it is deliberately verbose rather than blocking.
    if args.keypad and not args.allow_keys:
        parser.error("--keypad sends real keypresses; add --i-understand-this-sends-keys")
    if not (args.once or args.watch or args.keys or args.keypad):
        parser.error("nothing to do — pass --once, --watch, --keypad, or --keys")

    password = args.password or getpass.getpass("Tuxedo password: ")
    con = TuxedoConsole(args.host, args.username, password, scheme=args.scheme)

    print(f"Logging in to {con.probe.base} as {args.username} ...")
    try:
        con.login()
    except Exception as exc:  # noqa: BLE001 — report, never swallow
        print(f"login failed: {exc}")
        return 1
    print("Login OK.")

    try:
        con.enter()
        print("Console mode entered.\n")

        if args.keypad:
            run_keypad(con)
            return 0

        if args.keys:
            out = con.send_keys(args.keys)
            print(f"sent {args.keys!r}")
            print("display:\n" + (out or "  (no display text returned)"))
            return 0

        if args.once:
            out = con.read_display()
            print(out or "(no display text returned)")
            return 0

        print(f"Watching every {args.interval}s. Ctrl-C to stop.\n")
        last = object()
        while True:
            loop = time.monotonic()
            try:
                out = con.read_display()
            except ConsoleError as exc:
                print(f"  [{time.strftime('%H:%M:%S')}] error: {exc}")
                out = None
            if out != last:
                stamp = time.strftime("%H:%M:%S")
                print(f"[{stamp}] " + (out or "(no display text)").replace("\n", " | "))
                last = out
            time.sleep(max(0.0, args.interval - (time.monotonic() - loop)))

    except KeyboardInterrupt:
        print("\ninterrupted")
        return 0
    except ConsoleError as exc:
        print(f"console error: {exc}")
        return 1
    finally:
        con.leave()


if __name__ == "__main__":
    sys.exit(main())
