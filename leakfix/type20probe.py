"""Prove whether Barracuda handles IPC reply type 20 (console display text).

The repo records that gettuxedoIPCCommFunc "discards type 20 entirely", derived
from enumerating the dispatch chain's EQUALITY comparisons. But type 20 is routed
by a RANGE branch that such an enumeration cannot see:

    d6b0  cmp r8, #21
    d6b4  beq da80        <- 21, partition status
    d6b8  bcc db8c        <- r8 < 21, THE CONSOLE HANDLER

and 0xdb8c broadcasts the text on the stream (as id 20, then again as -1) and
calls setConsoleMessage(20, text), which is the cache commandID 5002 returns.

The test: inject a type-20 message carrying a unique marker, then look for that
marker in the guest's memory. setConsoleMessage's buffer is at guest VA
0x55b7e4, so if the marker appears, the handler ran and the display path is
complete -- meaning console mode needs no Barracuda change at all.

The console handler reads its text at message + 14 (0x0E), NOT +0x0F where the
type-21 layout puts it. Getting that wrong sends an empty string and the test
would fail for the wrong reason.
"""
import ctypes
import ctypes.util
import re
import subprocess
import sys
import time

MSG_SIZE = 556
QUEUE = b"/Q_ServCmdTrsmtr"
MARKER = "CONSOLEMARK42"

rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
rt.mq_open.argtypes = [ctypes.c_char_p, ctypes.c_int]
rt.mq_open.restype = ctypes.c_int
rt.mq_send.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint]


def guest_pid():
    out = subprocess.run(["ss", "-lntp"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        if ":80 " in ln:
            m = re.search(r"pid=(\d+)", ln)
            if m:
                return int(m.group(1))
    return None


def drain_check():
    out = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        if "mqdrain" in ln and QUEUE.decode() in ln:
            return True
    return False


pid = guest_pid()
if pid is None:
    sys.exit("ABORT: nothing on :80")
print("  guest pid %d" % pid)
if drain_check():
    sys.exit("ABORT: mqdrain is on the INBOUND queue; it would eat this message")

# type 20, text at +0x0E as the console handler reads it
b = bytearray(MSG_SIZE)
b[0:4] = (0).to_bytes(4, "little")
b[4:8] = (20).to_bytes(4, "little")
b[8:12] = (7).to_bytes(4, "little")
t = ("%s|LINE2TEXT" % MARKER).encode("latin-1")
b[0x0E:0x0E + len(t)] = t

mq = rt.mq_open(QUEUE, 1)  # O_WRONLY
if mq < 0:
    sys.exit("ABORT: mq_open failed errno %d" % ctypes.get_errno())
for _ in range(3):
    if rt.mq_send(mq, bytes(b), MSG_SIZE, 0) != 0:
        sys.exit("ABORT: mq_send failed errno %d" % ctypes.get_errno())
print("  sent 3 messages of msgType 20, text at +0x0E, marker %r" % MARKER)
time.sleep(6)

# Look for the marker anywhere in the guest's memory.
need = MARKER.encode()
found = 0
with open("/proc/%d/maps" % pid) as fh:
    regions = []
    for ln in fh:
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})", ln)
        if m and "r" in m.group(3) and "w" in m.group(3):
            regions.append((int(m.group(1), 16), int(m.group(2), 16)))
with open("/proc/%d/mem" % pid, "rb", 0) as mem:
    for lo, hi in regions:
        if hi - lo > 64 << 20:
            continue
        try:
            mem.seek(lo)
            buf = mem.read(hi - lo)
        except Exception:
            continue
        n = buf.count(need)
        if n:
            off = buf.find(need)
            print("    marker x%d in %#x-%#x, first at %#x" % (n, lo, hi, lo + off))
            found += n
print("  marker occurrences in guest memory: %d" % found)
print("  VERDICT: %s" % ("type 20 IS handled - setConsoleMessage ran"
                         if found else "no trace - type 20 may indeed be dropped"))
