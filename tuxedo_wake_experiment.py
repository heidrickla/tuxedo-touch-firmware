#!/usr/bin/env python3
"""
Test, REPEATEDLY, whether polling is what keeps a Tuxedo Touch's status feed
alive - by cycling quiet and active periods and counting outcomes.

WHY THIS EXISTS

`tuxedo_status_probe.py` answers "is the feed dark, and can a fresh login clear
it". It cannot answer "what makes it go dark", because a single observation of
"went dark after polling stopped" is a coincidence with a story attached. Two
such observations are two coincidences.

So this script does the boring thing: it runs the same cycle N times and
reports the counts. The hypothesis under test is

    H: the feed stays alive while something polls it, and goes dark when
       nothing does.

which predicts, per cycle:

    after a quiet period  -> the first poll reads BAD
    during an active period -> polls read GOOD and stay GOOD

Both halves have to hold, repeatedly, or H is wrong. The script prints the
per-cycle outcomes and a tally, and it explicitly reports DISAGREEMENT rather
than averaging it away - a hypothesis that holds 3 times out of 5 is not
"mostly true", it is false, and the exceptions are where the real mechanism is.

    python tuxedo_wake_experiment.py 203.0.113.5 -u <panel-user> --exclusive \
        --cycles 4 --quiet 600 --active 300

Time cost is cycles * (quiet + active). The defaults run about an hour.

READ THIS FIRST: the panel serves one connection at a time, and a quiet period
means QUIET - if anything else touches the panel (an enabled Home Assistant
integration, a browser tab, another ECP-bus client doing something on the same
physical panel) the quiet periods are not quiet and the experiment measures
nothing. Stop everything else first.

This script is READ-ONLY. It calls GetSecurityStatus and nothing else.
"""

import argparse
import datetime as dt
import getpass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxedo_status_probe import (  # noqa: E402
    GOOD,
    TuxedoProbe,
)


def stamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%SZ")


def countdown(seconds, label):
    """Sleep, reporting progress, so a long quiet period is not a black box."""
    end = time.monotonic() + seconds
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return
        print(f"    {label}: {left/60:.1f} min remaining", end="\r", flush=True)
        time.sleep(min(30.0, left))


def run_cycle(probe, index, quiet_s, active_s, interval, sink):
    """One quiet-then-active cycle. Returns a dict of what happened."""
    print(f"\n--- cycle {index} ---")

    # PHASE 1: quiet. Nothing touches the panel.
    print(f"  [{stamp()}] quiet for {quiet_s/60:.1f} min (no traffic at all)")
    countdown(quiet_s, "quiet")
    print(" " * 60, end="\r")

    # PHASE 2: the measurement that matters - the FIRST poll after quiet.
    #
    # LOAD-BEARING ASSUMPTION: logging in does not itself wake a dark feed.
    # If it did, this login would destroy the very thing being measured and
    # every cycle would read "alive" for the wrong reason. The assumption is
    # not free - it rests on repeated observation that a fresh login followed
    # immediately by a poll returns the same bad status, in 0.22s, on a dark
    # feed. That is exactly what `tuxedo_status_probe.py`'s control does, and
    # it has never once cleared a dark feed. If a future firmware changes
    # that, this experiment silently starts lying: re-verify the control
    # before trusting these results again.
    probe.login()
    kind, text, latency, detail = probe.get_status()
    dark_after_quiet = kind != GOOD
    print(f"  [{stamp()}] first poll after quiet: {kind} "
          f"{text or detail} ({latency:.2f}s)"
          f"  -> {'DARK' if dark_after_quiet else 'ALIVE'}")

    # PHASE 3: active. Poll continuously and see whether it holds.
    print(f"  [{stamp()}] polling every {interval}s for {active_s/60:.1f} min")
    started = time.monotonic()
    active = []
    while time.monotonic() - started < active_s:
        loop = time.monotonic()
        k, t, lat, d = probe.get_status()
        active.append(k)
        if sink:
            sink.write(json.dumps({
                "cycle": index, "phase": "active",
                "wall": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "class": k, "status": t, "detail": d, "latency_s": round(lat, 3),
            }) + "\n")
            sink.flush()
        time.sleep(max(0.0, interval - (time.monotonic() - loop)))

    good = sum(1 for k in active if k == GOOD)
    held = bool(active) and good == len(active)
    recovered = bool(active) and active[0] != GOOD and active[-1] == GOOD
    print(f"  [{stamp()}] active: {good}/{len(active)} good"
          f"  -> {'HELD' if held else 'did NOT hold'}"
          + ("  (recovered mid-phase)" if recovered else ""))

    return {
        "cycle": index,
        "dark_after_quiet": dark_after_quiet,
        "active_good": good,
        "active_total": len(active),
        "held": held,
        "recovered_during_active": recovered,
    }


def report(results, quiet_s):
    print("\n" + "=" * 72)
    print("REPLICATION RESULT")
    print("=" * 72)

    n = len(results)
    if not n:
        print("  no cycles completed")
        return 1

    dark = sum(1 for r in results if r["dark_after_quiet"])
    held = sum(1 for r in results if r["held"])

    print(f"  cycles run: {n}   quiet period: {quiet_s/60:.1f} min each\n")
    print(f"  {'cycle':>5}  {'after quiet':>12}  {'during active':>14}")
    for r in results:
        print(f"  {r['cycle']:>5}  {'DARK' if r['dark_after_quiet'] else 'alive':>12}"
              f"  {r['active_good']}/{r['active_total']} good"
              f"{'  (held)' if r['held'] else '  (BROKE)'}")

    print(f"\n  went dark after quiet:  {dark}/{n}")
    print(f"  held alive while polled: {held}/{n}")

    print()
    if dark == n and held == n:
        print(f"  HYPOTHESIS HELD in all {n} cycles.")
        print("  Polling keeps the feed alive; stopping lets it go dark.")
        print()
        print("  Practical consequence: keep something polling the panel.")
        print("  Leaving the integration enabled is the fix, and disabling")
        print("  it is what causes the symptom.")
        print()
        print(f"  Caveat worth stating: {n} cycles at one quiet length is")
        print("  evidence, not proof. It does not establish the threshold -")
        print("  re-run with a shorter --quiet to find where it flips.")
        return 0

    if dark == 0:
        print(f"  HYPOTHESIS FAILED. The feed never went dark after quiet,")
        print(f"  across {n} cycles. Whatever darkens it, it is not simply")
        print("  the absence of polling - a longer --quiet may be needed, or")
        print("  something else on the ECP bus is keeping it awake.")
        return 1

    print(f"  MIXED, AND THAT IS THE INTERESTING RESULT: dark {dark}/{n},")
    print(f"  held {held}/{n}. A hypothesis that holds sometimes is not")
    print("  'mostly right' - the disagreeing cycles are where the real")
    print("  mechanism is. Look at what differed in those, and do NOT")
    print("  average this into a conclusion.")
    return 1


def main():
    p = argparse.ArgumentParser(
        description="Repeatedly test whether polling keeps the Tuxedo status "
                    "feed alive. Read-only.")
    p.add_argument("host")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("--password", default=os.environ.get("TUXEDO_PASSWORD"))
    p.add_argument("--cycles", type=int, default=4)
    p.add_argument("--quiet", type=float, default=600.0,
                   help="seconds of no traffic per cycle (default 600)")
    p.add_argument("--active", type=float, default=300.0,
                   help="seconds of polling per cycle (default 300)")
    p.add_argument("--interval", type=float, default=30.0)
    p.add_argument("--scheme", choices=("https", "http"), default="https")
    p.add_argument("--jsonl")
    p.add_argument("--exclusive", action="store_true")
    args = p.parse_args()

    if not args.exclusive:
        p.error("\n\nQuiet periods must be genuinely quiet: stop the Home "
                "Assistant\nintegration and anything else touching the panel, "
                "then pass --exclusive.\n")

    password = args.password or getpass.getpass("Tuxedo password: ")
    probe = TuxedoProbe(args.host, args.username, password, scheme=args.scheme)

    total = args.cycles * (args.quiet + args.active)
    print(f"{args.cycles} cycles, {args.quiet/60:.1f} min quiet + "
          f"{args.active/60:.1f} min active each.")
    print(f"Total run time about {total/60:.0f} minutes.")

    sink = open(args.jsonl, "a", encoding="utf-8") if args.jsonl else None
    results = []
    try:
        for i in range(1, args.cycles + 1):
            results.append(run_cycle(probe, i, args.quiet, args.active,
                                     args.interval, sink))
    except KeyboardInterrupt:
        print("\n  interrupted - reporting what completed\n")
    except Exception as exc:  # noqa: BLE001
        print(f"\n  cycle aborted: {type(exc).__name__}: {exc}")
    finally:
        if sink:
            sink.close()

    return report(results, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
