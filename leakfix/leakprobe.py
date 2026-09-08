#!/usr/bin/env python3
"""Measure per-request heap growth of an emulated Barracuda.

Drives authenticated /handlerequest.html calls and fits RSS against request
count. The slope is bytes leaked per request.

Two things this reports that a before/after difference does not:

  * the HTTP status distribution. 2000 requests that all 302 to the login page
    exercise nothing, and the RSS would sit flat and read as "no leak".
  * a fitted slope over many samples rather than two endpoints, because a
    working-set ramp makes the two-point difference say whatever the ramp says.

Never submits a wrong password: one login, and a failure aborts.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
from collections import Counter

# The probe lives in the repo root, one level up from here.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tuxedo_status_probe import API_BASE_PATH, TuxedoProbe, hmac_hex  # noqa: E402

HANDLEREQUEST = "/handlerequest.html"


def qemu_pid(binary="/opt/webserver/Barracuda"):
    """The emulated Barracuda, found by argv rather than by process name.

    ps shows 'qemu-arm-static'; the guest binary only appears in cmdline.
    """
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                cmd = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        if binary in cmd and "qemu-arm" in cmd:
            return int(entry)
    return None


def rss_kb(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("no VmRSS")


def request_url(probe, cmd):
    params = {
        "cmd": str(cmd),
        "Type": str(cmd),
        "pID": "-1",
        "uCode": "0",
        "sessionid": probe.session_cookie.split("=", 1)[-1],
        "filters": "0",
        "index": "0",
        "tarTemp": "0",
    }
    return f"{probe.base}{HANDLEREQUEST}?" + urllib.parse.urlencode(params)


def fit(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0
    sx = sum(xs)
    sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return 0.0
    return (n * sxy - sx * sy) / denom


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--mode", choices=("console", "api"), default="api",
                    help="console = /handlerequest.html; api = GetSecurityStatus, "
                         "which is what Home Assistant actually polls")
    ap.add_argument("--scheme", default="")
    # No default account name. A real one is an author identifier and this file
    # is published; it also logs in for real, so a wrong default SPENDS a login
    # attempt -- and three failures disable every web account on stock firmware.
    # Same reasoning panelleak.py already applies to --creds.
    ap.add_argument("--user", required=True,
                    help="panel web account to log in as")
    ap.add_argument("--creds", required=True,
                    help="file holding the panel password. Required rather than "
                         "defaulted, for the reason above.")
    ap.add_argument("--cmd", default="0")
    ap.add_argument("--path", default="", help="console mode: GET this path instead of handlerequest")
    ap.add_argument("--endpoint", default="/GetSecurityStatus",
                    help="api mode: which /system_http_api/API_REV01 endpoint")
    ap.add_argument("--plain", default="operation=get",
                    help="api mode: plaintext params, encrypted into `param`")
    ap.add_argument("--warmup", type=int, default=300)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--every", type=int, default=100)
    ap.add_argument("--pause-after-login", type=float, default=0.0,
                    help="sleep this long after login and key fetch, before any "
                         "measured request. Lets an external tracer mark the log "
                         "offset so the capture holds ONLY the request path - "
                         "the login is far larger and buries it.")
    ap.add_argument("--label", default="run")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    pid = qemu_pid()
    if pid is None:
        sys.exit("no emulated Barracuda running")
    print(f"emulated Barracuda: qemu pid {pid}")

    password = open(args.creds, encoding="utf-8").read().strip()
    # The API path REQUIRES TLS: over plain HTTP every /system_http_api/
    # request answers 302 to tuxedoapi.html, so an http run would measure
    # 2000 redirects and call it "no leak".
    scheme = args.scheme or ("https" if args.mode == "api" else "http")
    probe = TuxedoProbe(args.host, args.user, password, scheme=scheme)
    probe.login()
    if not probe.session_cookie:
        sys.exit("login produced no session cookie")
    print(f"mode {args.mode} over {scheme}; "
          f"cookie {probe.session_cookie.split('=', 1)[0]}=...")

    statuses = Counter()
    sizes = {}

    if args.mode == "api":
        # Generic API call so a DIFFERENT endpoint can be driven: that is what
        # separates "shared API plumbing leaks" from "this one handler leaks".
        probe._fetch_keys()
        api_url = f"{probe.base}{API_BASE_PATH}{args.endpoint}"
        token = hmac_hex(
            probe.key_hex,
            f"MACID:Browser,Path:API_REV01{args.endpoint}",
            hashlib.sha1,
        )
        api_headers = {
            "authtoken": token,
            "identity": probe.iv_hex,
            "Cookie": probe.session_cookie,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        def one():
            # POST, not GET: a GET answers 405 and every reading becomes an
            # artifact of the wrong method.
            enc = probe._encrypt(args.plain)
            payload = urllib.parse.urlencode({
                "param": enc,
                "len": str(len(enc)),
                "tstamp": str(int(time.time() * 1000)),
            }).encode("ascii")
            status, _headers, body = probe._open(
                api_url, data=payload, headers=api_headers
            )
            statuses[status] += 1
            sizes["req_body"] = len(payload)
            sizes["resp_body"] = len(body) if body else 0
    else:
        url = (f"{probe.base}{args.path}" if args.path
               else request_url(probe, args.cmd))
        print(f"  GET {url}")

        def one():
            status, _headers, _body = probe._open(
                url, headers={"Cookie": probe.session_cookie}
            )
            statuses[status] += 1

    if args.pause_after_login:
        print(f"  paused {args.pause_after_login}s after login "
              f"(mark the trace offset now)", flush=True)
        time.sleep(args.pause_after_login)

    for _ in range(args.warmup):
        one()
    warm = dict(statuses)
    statuses.clear()

    xs, ys = [], []
    base = rss_kb(pid)
    xs.append(0)
    ys.append(base)
    t0 = time.monotonic()

    for i in range(1, args.n + 1):
        one()
        if i % args.every == 0:
            xs.append(i)
            ys.append(rss_kb(pid))

    elapsed = time.monotonic() - t0
    slope_kb_per_req = fit(xs, ys)
    per_req_bytes = slope_kb_per_req * 1024
    total = ys[-1] - ys[0]

    print(f"warmup statuses : {warm}")
    print(f"measured statuses: {dict(statuses)}")
    print(f"requests        : {args.n} in {elapsed:.1f}s "
          f"({args.n / elapsed:.1f}/s)")
    print(f"rss             : {ys[0]} -> {ys[-1]} kB   (delta {total} kB)")
    print(f"slope           : {per_req_bytes:.1f} bytes/request")
    print(f"samples         : {len(xs)}")
    if sizes:
        print(f"sizes           : request body {sizes.get('req_body')} B, "
              f"response body {sizes.get('resp_body')} B")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({
                "label": args.label,
                "pid": pid,
                "warmup_statuses": warm,
                "statuses": dict(statuses),
                "n": args.n,
                "elapsed_s": elapsed,
                "rss_series": list(zip(xs, ys)),
                "bytes_per_request": per_req_bytes,
                "delta_kb": total,
            }, fh, indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
