#!/usr/bin/env python3
"""
Work out *why* a Tuxedo Touch's security status goes stale, by measuring the
panel directly over a long window and running a control at the moment it fails.

THE PROBLEM THIS SOLVES

`GetSecurityStatus` on a Tuxedo Touch stops reporting the real state after a
few minutes of quiet, and recovers when something changes. Several unrelated
causes produce that same visible symptom, and they need opposite fixes:

  H1  session expiry     the login goes stale on a timer; a fresh login fixes
                         it instantly.
  H2  idle timeout       the panel drops the session after N seconds with no
                         traffic; polling more often prevents it.
  H3  ECP / AUI fault    the Tuxedo module has lost its status feed from the
                         VISTA panel. A fresh login changes NOTHING. Commonly
                         an AUI device-address collision (the Tuxedo and Total
                         Connect sharing an address, or an address not enabled
                         in panel field *189). Fixed in PANEL PROGRAMMING, not
                         in software.
  H4  contention         something else holds the panel's single connection
                         slot; polls hang rather than answering.

Guessing between these wastes days. So this tool does not guess: when it sees
the first bad status it immediately re-logs-in and re-polls. That one
controlled comparison splits the field in half:

    fresh session returns a REAL status   -> H1/H2, a software-side fix
    fresh session still returns bad        -> H3, stop writing code and go
                                              look at the panel programming

READ THIS BEFORE RUNNING

The unit serves ONE connection at a time, and contention presents as a hang,
not a refusal - so a second client makes a healthy panel look dead and can
poison the measurement (that is H4 masquerading as everything else). Stop or
disable the Home Assistant integration, and close any browser tab open on the
panel's web UI, before starting a run. The tool refuses to start until you
acknowledge this with --exclusive.

This probe is READ-ONLY. It calls GetSecurityStatus and nothing else. It
cannot arm, disarm, or change any setting on the panel.

    python tuxedo_status_probe.py 192.168.1.50 -u admin --exclusive
    python tuxedo_status_probe.py 192.168.1.50 -u admin --exclusive \
        --interval 30 --duration 3600 --jsonl run.jsonl

Credentials: pass --password, or set TUXEDO_PASSWORD, or be prompted.
"""

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from cryptography.hazmat.primitives import padding as _padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit(
        "This tool needs the 'cryptography' package for AES-256-CBC.\n"
        "    pip install cryptography"
    )

LOGIN_PATH = "/authenticated/index.html"
KEYS_PATH = "/tuxedoapi.html"
API_BASE_PATH = "/system_http_api/API_REV01"
STATUS_ENDPOINT = "/GetSecurityStatus"

STATUS_NOT_AVAILABLE = "Not available"

# The key blob is handed out in a hidden input on tuxedoapi.html.
READIT_RE = re.compile(
    r'id=["\']readit["\'][^>]*value=["\']([0-9a-fA-F]+)["\']', re.IGNORECASE
)

# Classification of each poll result.
GOOD = "good"
NOT_AVAILABLE = "not-available"
TIMEOUT = "timeout"
ERROR = "error"
# A response saying THIS CLIENT is malformed, not that the device is unwell.
# Kept separate because conflating the two is how you manufacture a verdict:
# an early version of this tool sent GET where the API wants POST, collected
# a run of HTTP 405s, classified them as generic errors, and confidently
# announced a panel-side fault that did not exist. Any of these means STOP
# AND FIX THE TOOL - the run says nothing about the device.
BAD_REQUEST = "bad-request"
CLIENT_FAULT_CODES = {400, 405, 411, 414, 415, 501}


def legacy_ssl_context():
    """
    The panel serves a self-signed 1024-bit MD5 certificate from ~2009 and
    requires unsafe legacy TLS renegotiation. Modern stacks refuse both. This
    is safe here only because the tool never sends anything but a status read
    to a device on your own LAN - do not copy this context into anything that
    carries secrets across a network you do not control.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def hmac_hex(key_text, message, digestmod):
    """
    NOTE the quirk: the HMAC key is the literal hex TEXT the device handed us,
    used as ASCII bytes - NOT the hex-decoded value. Decoding it first is the
    single most common reason a reimplementation authenticates fine and then
    fails every API call.
    """
    return hmac.new(
        key_text.encode("ascii"), message.encode("utf-8"), digestmod
    ).hexdigest()


class TuxedoProbe:
    """Minimal read-only client: login, fetch keys, read status."""

    def __init__(self, host, username, password, scheme="https", timeout=20):
        self.base = f"{scheme}://{host}"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ctx = legacy_ssl_context() if scheme == "https" else None

        self.session_cookie = None
        self.key_hex = None
        self.iv_hex = None
        self.login_monotonic = None

    # -- plumbing ---------------------------------------------------------

    def _open(self, url, data=None, headers=None, allow_redirects=False):
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
        for key, value in (headers or {}).items():
            req.add_header(key, value)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None

        handlers = [urllib.request.HTTPSHandler(context=self.ctx)] if self.ctx else []
        if not allow_redirects:
            handlers.append(NoRedirect)
        opener = urllib.request.build_opener(*handlers)
        try:
            resp = opener.open(req, timeout=self.timeout)
            return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    # -- login ------------------------------------------------------------

    def login(self):
        """GET the challenge, POST the HMACs, keep the session cookie."""
        url = f"{self.base}{LOGIN_PATH}?url=tuxedoapi.html"
        status, headers, _body = self._open(url)
        if status not in (200, 302):
            raise RuntimeError(f"login page returned HTTP {status}")

        challenge = headers.get("Random")
        random_id = headers.get("RandomID")
        if not challenge or not random_id:
            raise RuntimeError(
                "login page did not return Random/RandomID headers - "
                "unexpected firmware or not a Tuxedo Touch"
            )

        zfl = None
        raw_cookie = headers.get("Set-Cookie", "")
        match = re.search(r"(_zFL[^=]*=[^;]+)", raw_cookie)
        if match:
            zfl = match.group(1)

        user = self.username.lower()
        body = urllib.parse.urlencode(
            {
                "log": hmac_hex(challenge, user, hashlib.sha512),
                "log1": hmac_hex(challenge, user + self.password, hashlib.sha512),
                "identity": random_id,
            }
        ).encode("ascii")

        headers_out = {"Content-Type": "application/x-www-form-urlencoded"}
        if zfl:
            headers_out["Cookie"] = zfl

        status, headers, _body = self._open(url, data=body, headers=headers_out)
        if status not in (200, 302):
            raise RuntimeError(f"login POST returned HTTP {status}")

        session = None
        for cookie in re.findall(r"([^,;\s]+=[^,;\s]+)", headers.get("Set-Cookie", "")):
            name = cookie.split("=", 1)[0]
            if name.startswith("_zFL"):
                continue
            session = cookie
            break
        if not session:
            raise RuntimeError(
                "no session cookie returned - check username/password"
            )

        self.session_cookie = session
        self.login_monotonic = time.monotonic()
        self._fetch_keys()

    def _fetch_keys(self):
        url = f"{self.base}{KEYS_PATH}"
        status, _headers, body = self._open(
            url, headers={"Cookie": self.session_cookie}
        )
        if status != 200:
            raise RuntimeError(f"key fetch returned HTTP {status}")
        match = READIT_RE.search(body.decode("utf-8", "replace"))
        if not match:
            raise RuntimeError(
                "no #readit key blob on tuxedoapi.html - session not "
                "actually authenticated"
            )
        blob = match.group(1)
        if len(blob) < 96:
            raise RuntimeError(f"key blob too short ({len(blob)} chars)")
        self.key_hex, self.iv_hex = blob[0:64], blob[64:96]

    # -- status read ------------------------------------------------------

    def _encrypt(self, plaintext):
        key = bytes.fromhex(self.key_hex)
        iv = bytes.fromhex(self.iv_hex)
        padder = _padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return base64.b64encode(
            encryptor.update(padded) + encryptor.finalize()
        ).decode("ascii")

    def _decrypt(self, ciphertext_b64):
        key = bytes.fromhex(self.key_hex)
        iv = bytes.fromhex(self.iv_hex)
        raw = base64.b64decode(ciphertext_b64)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plain = decryptor.update(raw) + decryptor.finalize()
        # Strip PKCS#7 padding if it looks sane, else trailing NULs.
        if plain and 1 <= plain[-1] <= 16:
            plain = plain[: -plain[-1]]
        return plain.rstrip(b"\x00").decode("utf-8", "replace")

    def get_status(self):
        """
        Returns (classification, status_text, latency_seconds, detail).
        Never raises for an expected failure - the failure IS the measurement.
        """
        url = f"{self.base}{API_BASE_PATH}{STATUS_ENDPOINT}"
        token = hmac_hex(
            self.key_hex,
            f"MACID:Browser,Path:API_REV01{STATUS_ENDPOINT}",
            hashlib.sha1,
        )
        headers = {
            "authtoken": token,
            "identity": self.iv_hex,
            "Cookie": self.session_cookie,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # This endpoint is a POST, not a GET - a GET returns HTTP 405 and
        # every reading in the run becomes an artifact of the wrong method.
        # The body is the AES-encrypted plaintext "operation=get", with `len`
        # measuring the RAW ciphertext before url-encoding.
        enc = self._encrypt("operation=get")
        payload = urllib.parse.urlencode(
            {"param": enc, "len": str(len(enc)), "tstamp": str(int(time.time() * 1000))}
        ).encode("ascii")

        started = time.monotonic()
        try:
            status, resp_headers, body = self._open(url, data=payload, headers=headers)
        except TimeoutError:
            return TIMEOUT, None, time.monotonic() - started, "socket timeout"
        except OSError as exc:
            return ERROR, None, time.monotonic() - started, f"{type(exc).__name__}: {exc}"
        latency = time.monotonic() - started

        if status in (301, 302, 303, 307, 308):
            where = resp_headers.get("Location", "?")
            return ERROR, None, latency, f"HTTP {status} redirect -> {where}"
        if status == 401:
            return ERROR, None, latency, "HTTP 401 - session rejected"
        if status in CLIENT_FAULT_CODES:
            return (
                BAD_REQUEST, None, latency,
                f"HTTP {status} - the REQUEST is wrong, not the panel",
            )
        if status != 200:
            return ERROR, None, latency, f"HTTP {status}"

        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return ERROR, None, latency, "response was not JSON (session lost?)"

        blob = payload.get("Result")
        if not blob:
            return ERROR, None, latency, f"no Result field: {payload!r}"

        try:
            decrypted = json.loads(self._decrypt(blob))
        except Exception as exc:  # noqa: BLE001 - any decrypt failure is data
            return ERROR, None, latency, f"decrypt failed: {exc}"

        text = decrypted.get("Status", "?")
        if text == STATUS_NOT_AVAILABLE:
            return NOT_AVAILABLE, text, latency, ""
        return GOOD, text, latency, ""


def run(probe, interval, duration, jsonl_path):
    """Poll on an interval; on the first bad read, run the control."""
    started = time.monotonic()
    deadline = started + duration
    records = []
    sink = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None

    control_done = False
    control_result = None
    last_good_monotonic = None
    counts = {GOOD: 0, NOT_AVAILABLE: 0, TIMEOUT: 0, ERROR: 0, BAD_REQUEST: 0}

    print(f"\nPolling every {interval}s for {duration}s. Ctrl-C to stop early.\n")
    print(f"{'elapsed':>8}  {'since login':>11}  {'lat':>6}  {'class':<14} status")
    print("-" * 72)

    try:
        while time.monotonic() < deadline:
            kind, text, latency, detail = probe.get_status()
            now = time.monotonic()
            elapsed = now - started
            since_login = now - probe.login_monotonic if probe.login_monotonic else 0.0
            counts[kind] += 1
            if kind == GOOD:
                last_good_monotonic = now

            record = {
                "wall": dt.datetime.now().isoformat(timespec="seconds"),
                "elapsed_s": round(elapsed, 1),
                "since_login_s": round(since_login, 1),
                "latency_s": round(latency, 3),
                "class": kind,
                "status": text,
                "detail": detail,
            }
            records.append(record)
            if sink:
                sink.write(json.dumps(record) + "\n")
                sink.flush()

            shown = text if text else detail
            print(
                f"{elapsed:>8.0f}  {since_login:>11.0f}  {latency:>6.2f}  "
                f"{kind:<14} {shown}"
            )

            # --- the control ---------------------------------------------
            # First bad read: re-login and immediately re-poll. A fresh
            # session either fixes it (session-side cause) or does not
            # (panel-side cause). Nothing else separates those two.
            if kind in (NOT_AVAILABLE, ERROR) and not control_done:
                control_done = True
                print("\n  >> CONTROL: first bad read. Re-logging in and "
                      "re-polling immediately.")
                try:
                    probe.login()
                except Exception as exc:  # noqa: BLE001
                    print(f"  >> re-login FAILED: {exc}")
                    control_result = ("relogin-failed", str(exc))
                else:
                    kind2, text2, lat2, detail2 = probe.get_status()
                    print(f"  >> fresh session says: {kind2} "
                          f"{text2 or detail2} ({lat2:.2f}s)")
                    control_result = (kind2, text2 or detail2)
                    counts[kind2] += 1
                    if kind2 == GOOD:
                        last_good_monotonic = time.monotonic()
                print()

            time.sleep(max(0.0, interval - (time.monotonic() - now)))
    except KeyboardInterrupt:
        print("\n  interrupted\n")
    finally:
        if sink:
            sink.close()

    return records, counts, control_result, last_good_monotonic


def interpret(records, counts, control_result):
    """Say what the numbers mean, including when they mean 'inconclusive'."""
    print("\n" + "=" * 72)
    print("RESULT")
    print("=" * 72)

    total = sum(counts.values())
    if not total:
        print("  No polls completed.")
        return 1

    for kind in (GOOD, NOT_AVAILABLE, TIMEOUT, ERROR, BAD_REQUEST):
        if counts[kind]:
            pct = 100.0 * counts[kind] / total
            print(f"  {kind:<14} {counts[kind]:>4}  ({pct:.0f}%)")

    # Time-to-first-failure is the H1/H2 signal.
    first_bad = next(
        (r for r in records if r["class"] != GOOD), None
    )
    if first_bad:
        print(f"\n  First bad read at {first_bad['elapsed_s']:.0f}s "
              f"({first_bad['since_login_s']:.0f}s after login).")

    print()
    if counts[BAD_REQUEST]:
        print("  NO VERDICT. This run is INVALID.")
        print()
        print(f"  {counts[BAD_REQUEST]} poll(s) returned a status code meaning")
        print("  the request itself was malformed - wrong method, wrong")
        print("  content type, wrong body shape. That says nothing whatever")
        print("  about the panel's health.")
        print()
        print("  Fix the request and re-run. Do NOT read a device fault into")
        print("  these numbers: a broken client and a broken panel produce")
        print("  the same shaped failure, and only one of them is real.")
        return 1

    if counts[TIMEOUT] > total * 0.2:
        print("  H4 CONTENTION is likely: a large share of polls timed out.")
        print("  Something else is holding the panel's single connection")
        print("  slot. Re-run with everything else disconnected before")
        print("  drawing any other conclusion - contention imitates every")
        print("  other cause.")
        return 0

    if counts[GOOD] == total:
        print("  No failure reproduced in this window. Either the run was")
        print("  too short, or the fault needs a quiet period this run did")
        print("  not contain. Re-run for longer with --duration.")
        return 0

    if control_result is None:
        # The control deliberately does not fire on a timeout: re-logging in
        # to a panel whose connection slot is already contended just adds
        # another client to the pile-up and makes the measurement worse.
        if counts[TIMEOUT]:
            print("  INCONCLUSIVE. Every failure this run was a timeout, and")
            print("  the control does not run on those - re-authenticating")
            print("  into a contended panel only adds another client.")
            print()
            print("  Timeouts below the contention threshold usually still")
            print("  mean something intermittently takes the connection")
            print("  slot. Find and stop it, then re-run: until the run is")
            print("  clean of timeouts, no other verdict is trustworthy.")
        else:
            print("  Failures seen but the control never ran. That is a bug")
            print("  in this tool - please report the run above.")
        return 1

    kind2, detail2 = control_result
    if kind2 == GOOD:
        print("  H1/H2 SESSION-SIDE. A fresh login immediately restored a")
        print("  real status, so the panel's feed from the VISTA panel is")
        print("  fine - the session is going stale.")
        print()
        print("  Fix in software: re-authenticate on the failure rather")
        print("  than treating it as no-new-information, and consider a")
        print("  shorter poll interval to stay inside the idle window.")
    elif kind2 == "relogin-failed":
        print("  INCONCLUSIVE. The re-login itself failed:")
        print(f"    {detail2}")
        print("  That points at the transport or credentials, not at the")
        print("  status feed. Fix the login first, then re-run.")
        return 1
    else:
        print("  H3 PANEL-SIDE. A brand-new session got the same bad answer,")
        print("  so this is NOT session expiry and no amount of client-side")
        print("  retry logic will fix it. The Tuxedo module has lost its")
        print("  status feed from the VISTA panel.")
        print()
        print("  FIRST, run the cross-check. It costs nothing and it decides")
        print("  whether the fault is the Tuxedo module or the panel itself:")
        print("    Look at a SECOND, independent reader of the same panel -")
        print("    an Envisalink or other ECP-bus integration. If it shows a")
        print("    correct armed/disarmed state right now, the panel is fine")
        print("    and only the Tuxedo's status feed is broken. If it is also")
        print("    wrong, the problem is the panel, not the Tuxedo.")
        print()
        print("  THEN look for an AUI ADDRESS COLLISION, in this order:")
        print("    1. The Tuxedo's own ECP/AUI address (Tuxedo setup screen).")
        print("    2. Whether ANYTHING ELSE claims that address. Total")
        print("       Connect emulates a touchscreen and takes an address of")
        print("       its own, DEFAULTING TO ADDRESS 2 - the likeliest")
        print("       collision. Other touchscreens count too.")
        print("    3. Only then, that the address is enabled in field *189.")
        print()
        print("       AUI addresses are 1, 2, 5 and 6, enabled in *189 as")
        print("       AUI 1-4 respectively. A VISTA-21iP supports four; a")
        print("       VISTA-20P below revision 5.0 supports only two.")
        print()
        print("  Note the ORDER, and why *189 is checked last. A device whose")
        print("  address is not enabled at all usually reports ECP Error and")
        print("  does not work; if commands still succeed, the address IS")
        print("  live, so a collision fits the evidence better than a")
        print("  missing enable. Two devices sharing one address both partly")
        print("  work, and status requests are what breaks - which is")
        print("  exactly the split seen here.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Diagnose why a Tuxedo Touch's security status goes "
                    "stale. Read-only.",
    )
    parser.add_argument("host", help="panel IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("--password", default=os.environ.get("TUXEDO_PASSWORD"))
    parser.add_argument("--scheme", choices=("https", "http"), default="https")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="seconds between polls (default 30, matching the "
                             "integration)")
    parser.add_argument("--duration", type=float, default=1800.0,
                        help="total run time in seconds (default 1800)")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="per-request timeout (default 20)")
    parser.add_argument("--jsonl", help="append each poll to this file")
    parser.add_argument("--exclusive", action="store_true",
                        help="confirm nothing else is talking to the panel")
    args = parser.parse_args()

    if not args.exclusive:
        parser.error(
            "\n\nThe panel serves ONE connection at a time, and contention "
            "presents as a\nhang rather than a refusal - a second client "
            "makes a healthy panel look\ndead and will corrupt this "
            "measurement.\n\n"
            "Stop the Home Assistant integration and close any browser tab "
            "on the\npanel, then re-run with --exclusive.\n"
        )

    password = args.password or getpass.getpass("Tuxedo password: ")

    probe = TuxedoProbe(
        args.host, args.username, password,
        scheme=args.scheme, timeout=args.timeout,
    )

    print(f"Logging in to {probe.base} as {args.username} ...")
    try:
        probe.login()
    except Exception as exc:  # noqa: BLE001
        print(f"\nLogin failed: {exc}")
        print("\nIf this is a timeout, something else probably holds the "
              "panel's\nsingle connection slot. Check for an open browser tab "
              "or a running\nintegration.")
        return 1
    print("Login OK, key material fetched.")

    records, counts, control, _last_good = run(
        probe, args.interval, args.duration, args.jsonl
    )
    return interpret(records, counts, control)


if __name__ == "__main__":
    sys.exit(main())
