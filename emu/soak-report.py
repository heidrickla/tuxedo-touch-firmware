#!/usr/bin/env python3
"""Read /tmp/soak.tsv from the panel and say whether the week passed.

The soak exists to answer two questions a 50-second test cannot: does the
shim's memory climb, and does its fd count drift. Raw TSV does not answer
either at a glance, and a week from now the answer wants to be one line rather
than a scrolling table.

    ssh root@panel 'cat /tmp/soak.tsv' | python3 emu/soak-report.py

Reports a least-squares slope rather than first-versus-last: a process that
allocates buffers early and then holds steady is healthy, and comparing the
endpoints alone would call that a leak. It also flags restarts and sampling
gaps, because a soak that quietly stopped is the failure this is guarding
against and it looks identical to a soak that went well.
"""
import sys


def col(rows, name, cast=float):
    i = HEAD.index(name)
    out = []
    for r in rows:
        v = r[i]
        if v == "-":
            out.append(None)
        else:
            try:
                out.append(cast(v))
            except ValueError:
                out.append(None)
    return out


def slope(xs, ys):
    """Least squares gradient, per hour. None if there is nothing to fit."""
    pts = [(x, y) for x, y in zip(xs, ys) if y is not None]
    if len(pts) < 3:
        return None
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    denom = sum((p[0] - mx) ** 2 for p in pts)
    if denom == 0:
        return None
    return sum((p[0] - mx) * (p[1] - my) for p in pts) / denom * 3600.0


text = sys.stdin.read().strip().splitlines()
if not text:
    print("no data")
    sys.exit(1)
HEAD = text[0].split("\t")
rows = [ln.split("\t") for ln in text[1:] if ln.strip()]
if not rows:
    print("header only -- the sampler wrote nothing, so it is not running")
    sys.exit(1)

t = col(rows, "unix")
rss = col(rows, "rss_kb")
fds = col(rows, "fds")
pids = col(rows, "pid", str)
listen = col(rows, "listen8443")
free = col(rows, "memfree_kb")

span = (t[-1] - t[0]) / 3600.0
alive = [p for p in pids if p not in (None, "-")]
print("samples      %d over %.1f h" % (len(rows), span))

# restarts: a changed pid means the shim died and something restarted it, or
# it was restarted by hand. Either way the soak's clock resets.
uniq = []
for p in pids:
    if p not in (None, "-") and (not uniq or uniq[-1] != p):
        uniq.append(p)
print("shim pids    %s%s" % (", ".join(uniq[:6]), " ..." if len(uniq) > 6 else ""))
if len(uniq) > 1:
    print("             RESTARTED %d time(s) -- the soak clock resets at each" % (len(uniq) - 1))

# gaps: the sampler sleeps a fixed interval, so a much longer gap means it or
# the panel stalled
if len(t) > 2:
    deltas = [b - a for a, b in zip(t, t[1:])]
    typical = sorted(deltas)[len(deltas) // 2]
    gaps = [d for d in deltas if d > typical * 3]
    print("interval     ~%ds typical, %d gap(s) over 3x" % (typical, len(gaps)))
    if gaps:
        print("             longest gap %ds -- something stalled" % max(gaps))

down = sum(1 for l in listen if l == 0)
print("listener     up in %d of %d samples%s"
      % (len(listen) - down, len(listen), "" if down == 0 else "  <-- DOWN at times"))

vals = [v for v in rss if v is not None]
if vals:
    s = slope(t, rss)
    print("shim rss     %d -> %d kB (min %d, max %d)"
          % (vals[0], vals[-1], min(vals), max(vals)))
    if s is not None:
        print("             trend %+.1f kB/h" % s)
        # 31 MB ceiling from 5.2; anything that would reach it inside a year
        # is worth a second look even if it looks small per hour
        if s > 0:
            hours = (31000 - max(vals)) / s
            print("             at that rate the ~31 MB ceiling is %.0f days away"
                  % (hours / 24))
        if abs(s) < 1:
            # NOT "no leak": a synthetic 0.24 kB/h leak measures at +0.2 and
            # would be called flat here. The claim is about consequence, not
            # about absence, and saying otherwise would be the more comfortable
            # wording rather than the true one.
            print("             under 1 kB/h: negligible against this ceiling,"
                  " which is not the same as zero")

fv = [v for v in fds if v is not None]
if fv:
    print("shim fds     %d -> %d (min %d, max %d)%s"
          % (fv[0], fv[-1], min(fv), max(fv),
             "" if max(fv) == min(fv) else "  <-- drifts, check for leaked sockets"))

frv = [v for v in free if v is not None]
if frv:
    print("system free  %d -> %d kB" % (frv[0], frv[-1]))

ok = down == 0 and len(uniq) <= 1 and (not fv or max(fv) - min(fv) <= 2)
print()
print("verdict      %s" % ("looks healthy so far" if ok else "SOMETHING TO LOOK AT above"))
print("             a week is the bar; %.1f h so far" % span)
