#!/usr/bin/env python3
"""Measure Barracuda's per-request growth on the LIVE panel.

Drives the same authenticated GetSecurityStatus call Home Assistant polls, and
reads the panel's VmRSS over ssh between batches. Reports a fitted slope rather
than a two-point difference, and prints the sample series so a startup ramp is
visible rather than silently folded into the answer.

Read-only with respect to panel state: GetSecurityStatus only reads.
"""

import argparse
import os
import subprocess
import sys
import time

# The probe lives in the repo root, one level up from here.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tuxedo_status_probe import TuxedoProbe  # noqa: E402

DEFAULT_KEY = os.path.join(os.path.expanduser("~"), ".ssh", "tuxedo_ed25519")


def ssh_cmd(key):
    return ["ssh", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes", "-i", key]


def panel_rss(host, key):
    """Total VmRSS, and the [heap] mapping's own Rss.

    The distinction is the whole point: a heap that grows is a leak, whereas
    RSS growing while [heap] holds steady is the working set being paged in
    after a restart. Totals alone cannot tell those apart.
    """
    cmd = ssh_cmd(key) + [f"root@{host}",
                 "P=$(netstat -ltnp 2>/dev/null | grep ':443 ' | "
                 "grep -oE '[0-9]+/Barracuda' | cut -d/ -f1 | head -1); "
                 "grep ^VmRSS /proc/$P/status | tr -dc '0-9'; echo ' '; "
                 r"grep -A3 '\[heap\]' /proc/$P/smaps | grep '^Rss' | tr -dc '0-9'"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
    parts = out.split()
    tot = int(parts[0]) if parts else 0
    heap = int(parts[1]) if len(parts) > 1 else 0
    return tot, heap


def fit(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    d = n * sxx - sx * sx
    return 0.0 if d == 0 else (n * sxy - sy * sx) / d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="203.0.113.5",
                    help="panel address; the default is a documentation address")
    ap.add_argument("--creds", required=True,
                    help="file holding the panel password, optionally user:pass. "
                         "Required rather than defaulted: this logs in for real, "
                         "and three failed web logins disable every web account "
                         "on stock firmware.")
    ap.add_argument("--key", default=DEFAULT_KEY, help="ssh key for the panel")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--warmup", type=int, default=100)
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--every", type=int, default=50)
    args = ap.parse_args()

    raw = open(args.creds, encoding="utf-8").read().strip().splitlines()[0]
    user, pw = raw.split(":", 1) if ":" in raw else (args.user, raw)

    probe = TuxedoProbe(args.host, user, pw, scheme="https")
    probe.login()
    print(f"  logged in as {user}")

    ok = err = 0

    def one():
        nonlocal ok, err
        try:
            probe.get_status()
            ok += 1
        except Exception:                                   # noqa: BLE001
            err += 1

    for _ in range(args.warmup):
        one()
    print(f"  warmup done ({ok} ok, {err} failed)")
    ok = err = 0

    t, h = panel_rss(args.host, args.key)
    xs, ys, hs = [0], [t], [h]
    t0 = time.monotonic()
    for i in range(1, args.n + 1):
        one()
        if i % args.every == 0:
            xs.append(i)
            t, h = panel_rss(args.host, args.key)
            ys.append(t); hs.append(h)
    el = time.monotonic() - t0

    print(f"  requests : {args.n} in {el:.1f}s ({args.n/el:.1f}/s), "
          f"{ok} ok, {err} failed")
    print(f"  rss      : {ys[0]} -> {ys[-1]} kB  (delta {ys[-1]-ys[0]} kB)")
    print(f"  rss series : {ys}")
    print(f"  HEAP     : {hs[0]} -> {hs[-1]} kB  (delta {hs[-1]-hs[0]} kB)")
    print(f"  heap series: {hs}")
    print(f"  rss  slope : {fit(xs, ys)*1024:.1f} bytes/request")
    print(f"  HEAP slope : {fit(xs, hs)*1024:.1f} bytes/request   <- the leak figure")


if __name__ == "__main__":
    main()
