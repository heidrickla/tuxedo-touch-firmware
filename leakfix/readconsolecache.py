"""Read setConsoleMessage's buffer, listing EVERY mapping that contains it.

The first attempt matched the first mapping covering guest VA 0x55b7e4 and got a
read-only one full of S-box data. Overlapping mappings are the likely cause, so
this lists them all and reads from each writable one. It also searches for the
marker directly, which is the fact that matters: if the cache holds
"20<sep>MARKER..." then commandID 5002 would serve exactly that.
"""
import re
import subprocess
import sys

BUF = 0x55B7E4
MARKER = b"CONSOLEMARK42"


def guest_pid():
    out = subprocess.run(["ss", "-lntp"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        if ":80 " in ln:
            m = re.search(r"pid=(\d+)", ln)
            if m:
                return int(m.group(1))
    return None


pid = guest_pid()
if pid is None:
    sys.exit("ABORT: nothing on :80")
print("  guest pid %d" % pid)

regions = []
with open("/proc/%d/maps" % pid) as fh:
    for ln in fh:
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)$", ln.rstrip())
        if m:
            lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
            regions.append((lo, hi, perms, name))

print("  mappings containing %#x:" % BUF)
for lo, hi, perms, name in regions:
    if lo <= BUF < hi:
        print("    %#x-%#x %s %s" % (lo, hi, perms, name or "(anon)"))

with open("/proc/%d/mem" % pid, "rb", 0) as mem:
    for lo, hi, perms, name in regions:
        if lo <= BUF < hi and "r" in perms:
            try:
                mem.seek(BUF)
                raw = mem.read(120)
            except Exception as e:
                print("    read failed: %s" % e)
                continue
            s = raw.split(b"\0")[0]
            print("    from %#x-%#x %s -> %r" % (lo, hi, perms, s[:70]))
            if MARKER in raw:
                print("    *** MARKER PRESENT: setConsoleMessage populated this buffer ***")

    # And find where the marker actually lives, with the bytes around it
    print("  marker sites and surrounding bytes:")
    for lo, hi, perms, name in regions:
        if "r" not in perms or "w" not in perms or hi - lo > (64 << 20):
            continue
        try:
            mem.seek(lo)
            buf = mem.read(hi - lo)
        except Exception:
            continue
        start = 0
        while True:
            i = buf.find(MARKER, start)
            if i < 0:
                break
            ctx = buf[max(0, i - 12):i + 40]
            print("    %#x  %r" % (lo + i, ctx))
            start = i + 1
