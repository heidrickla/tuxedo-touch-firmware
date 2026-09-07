"""Force status pushes into the emulated Barracuda and count the stacks it leaks.

The three attr=NULL pthread_create sites fire on IPC, not on HTTP, so no
credentials and no web request are involved. gettuxedoIPCCommFunc reads
/Q_ServCmdTrsmtr and dispatches on msgType; 21 and 22 both reach a
pthread_create whose thread entry is pushSecurityStatus. One message in, one
8188 kB stack leaked.

THE POSITIVE CONTROL IS THE POINT. Against an UNPATCHED binary the stack count
must RISE by roughly the number of messages sent. If it does not, the driver is
not reaching the dispatcher and every subsequent result is void -- a driver that
silently fails to trigger produces a flat count, which is exactly what a working
fix looks like. So this refuses to report success on a patched binary unless a
control run has been seen to rise first.

TRAP, and it is in serve.sh: mqdrain.py is started on EVERY queue found under
the tree's dev/mq, including the inbound /Q_ServCmdTrsmtr. It would consume
these messages before Barracuda ever reads them, and the symptom is a flat
count -- indistinguishable from a fix, again. Checked for explicitly below.

Runs on the host as root. POSIX mqueues live in the kernel and the chroot does
not change the IPC namespace, so this x86 process and the ARM guest address the
same queues by name -- the same reason mqdrain works.
"""

import argparse
import ctypes
import ctypes.util
import os
import re
import subprocess
import sys
import time

QUEUE = "/Q_ServCmdTrsmtr"
MSG_SIZE = 556
STACK_KB = 8188

rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)


class Attr(ctypes.Structure):
    _fields_ = [("mq_flags", ctypes.c_long), ("mq_maxmsg", ctypes.c_long),
                ("mq_msgsize", ctypes.c_long), ("mq_curmsgs", ctypes.c_long),
                ("pad", ctypes.c_long * 4)]


rt.mq_open.argtypes = [ctypes.c_char_p, ctypes.c_int]
rt.mq_open.restype = ctypes.c_int
rt.mq_getattr.argtypes = [ctypes.c_int, ctypes.POINTER(Attr)]
rt.mq_send.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t,
                       ctypes.c_uint]
rt.mq_send.restype = ctypes.c_int

O_WRONLY, O_NONBLOCK = 1, 0o4000


def qemu_pid():
    """The guest process, found by who holds :80 -- not by name.

    pgrep on the binary name matches this script's own command line and any
    ssh command carrying the string, which has already cost two sessions today.
    """
    out = subprocess.run(["ss", "-lntp"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        if ":80 " in ln:
            m = re.search(r"pid=(\d+)", ln)
            if m:
                return int(m.group(1))
    return None


def stacks(pid, kb=STACK_KB):
    n = 0
    with open("/proc/%d/maps" % pid) as f:
        for ln in f:
            a, _, b = ln.partition(" ")[0].partition("-")
            if a and b and (int(b, 16) - int(a, 16)) // 1024 == kb:
                n += 1
    return n


def drainer_on_inbound():
    """Is mqdrain eating the queue we are about to write to?"""
    out = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                         text=True).stdout
    for ln in out.splitlines():
        if "mqdrain" in ln and QUEUE in ln:
            return ln.strip()
    return None


def message(msg_type, partition=0, value=7, flag=0xFE, text="Ready To Arm"):
    """One IPC status message, laid out per reply-layouts.txt.

        +0x000 u32  partition
        +0x004 u32  msgType          21 or 22
        +0x008 u32  value
        +0x00e u8   flag             0xfe ready/disarmed, 0xff arming/armed
        +0x00f str  status text, NUL terminated
    """
    b = bytearray(MSG_SIZE)
    b[0:4] = partition.to_bytes(4, "little")
    b[4:8] = msg_type.to_bytes(4, "little")
    b[8:12] = (value & 0xFFFFFFFF).to_bytes(4, "little")
    b[0x0E] = flag
    t = text.encode("latin-1")[:MSG_SIZE - 0x10]
    b[0x0F:0x0F + len(t)] = t
    return bytes(b)


ap = argparse.ArgumentParser()
ap.add_argument("--count", type=int, default=5)
ap.add_argument("--msgtype", type=int, default=21, choices=(21, 22))
ap.add_argument("--settle", type=float, default=8.0)
ap.add_argument("--control", action="store_true",
                help="unpatched binary: REQUIRE the count to rise")
args = ap.parse_args()

pid = qemu_pid()
if not pid:
    sys.exit("nothing serving on :80 -- start the rig first")
print("  guest pid %d, root %s" % (pid, os.readlink("/proc/%d/root" % pid)))

bad = drainer_on_inbound()
if bad:
    print("  ABORT: mqdrain is draining %s, it would eat these messages" % QUEUE)
    print("         %s" % bad)
    print("         Restart it on the OUTBOUND queue only (/Q_ServCmdRcver).")
    sys.exit(2)

fd = rt.mq_open(QUEUE.encode(), O_WRONLY | O_NONBLOCK)
if fd < 0:
    sys.exit("mq_open %s: %s" % (QUEUE, os.strerror(ctypes.get_errno())))
a = Attr()
rt.mq_getattr(fd, ctypes.byref(a))
print("  %s: maxmsg=%d msgsize=%d cur=%d"
      % (QUEUE, a.mq_maxmsg, a.mq_msgsize, a.mq_curmsgs))
if a.mq_msgsize < MSG_SIZE:
    sys.exit("queue msgsize %d < %d; layout assumption is wrong"
             % (a.mq_msgsize, MSG_SIZE))

before = stacks(pid)
print("  %d kB stacks before: %d" % (STACK_KB, before))

sent = 0
for i in range(args.count):
    msg = message(args.msgtype, partition=0, value=7,
                  flag=0xFE if i % 2 == 0 else 0xFF,
                  text="Ready To Arm" if i % 2 == 0 else "Armed Stay")
    if rt.mq_send(fd, msg, MSG_SIZE, 0) < 0:
        print("  mq_send %d: %s" % (i, os.strerror(ctypes.get_errno())))
        break
    sent += 1
    time.sleep(0.3)
print("  sent %d message(s) of msgType %d" % (sent, args.msgtype))

deadline = time.time() + args.settle
after = before
while time.time() < deadline:
    time.sleep(0.5)
    try:
        after = stacks(pid)
    except FileNotFoundError:
        sys.exit("  guest died during the run -- result void")
    if after >= before + sent:
        break
print("  %d kB stacks after:  %d   delta %+d  (sent %d)"
      % (STACK_KB, after, after - before, sent))
print()

rose = after > before
if args.control:
    if rose:
        print("  CONTROL PASSED: the driver reaches the dispatcher and each")
        print("  message costs a stack. A flat count in a patched run now means")
        print("  something.")
    else:
        print("  CONTROL FAILED: no stack appeared on an UNPATCHED binary.")
        print("  The driver is not triggering the path. Do NOT interpret any")
        print("  patched-binary result until this rises -- a flat count here and")
        print("  a working fix are the same observation.")
        sys.exit(1)
else:
    print("  Flat is only meaningful if a control run on this same rig has been")
    print("  seen to rise. Run with --control against the unpatched binary first.")
