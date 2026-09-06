#!/usr/bin/env python3
"""Drain Barracuda's outbound POSIX queues so the emulated server can run.

Under emulation there is no /tuxedo to read /Q_ServCmdRcver, so Barracuda's
main thread blocks in mq_timedsend once the queue fills -- the host's
/proc/sys/fs/mqueue/msg_max is 10, against the panel's 32 -- and the socket
dispatcher never gets to accept(). Draining is enough to unblock it. This does
NOT reply, so no alarm-state frames are produced; that is fine, because the
P13 gate answers 401 in EhDir_service before any IPC happens.

POSIX mqueues live in the kernel, so this x86 helper and the ARM binary inside
the chroot address the same queues by name.
"""
import ctypes, ctypes.util, os, sys, time

rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)

class Attr(ctypes.Structure):
    _fields_ = [("mq_flags", ctypes.c_long), ("mq_maxmsg", ctypes.c_long),
                ("mq_msgsize", ctypes.c_long), ("mq_curmsgs", ctypes.c_long),
                ("pad", ctypes.c_long * 4)]

rt.mq_open.argtypes = [ctypes.c_char_p, ctypes.c_int]
rt.mq_open.restype = ctypes.c_int
rt.mq_getattr.argtypes = [ctypes.c_int, ctypes.POINTER(Attr)]
rt.mq_receive.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.POINTER(ctypes.c_uint)]
rt.mq_receive.restype = ctypes.c_ssize_t

O_RDONLY, O_NONBLOCK = 0, 0o4000
names = sys.argv[1:] or ["/Q_ServCmdRcver"]
qs = []
for n in names:
    fd = rt.mq_open(n.encode(), O_RDONLY | O_NONBLOCK)
    if fd < 0:
        print(f"  mq_open {n}: {os.strerror(ctypes.get_errno())}", flush=True)
        continue
    a = Attr()
    rt.mq_getattr(fd, ctypes.byref(a))
    print(f"  draining {n}: maxmsg={a.mq_maxmsg} msgsize={a.mq_msgsize} cur={a.mq_curmsgs}", flush=True)
    qs.append((n, fd, a.mq_msgsize))
if not qs:
    sys.exit(1)

buf_cache = {sz: ctypes.create_string_buffer(sz) for _, _, sz in qs}
total = 0
t0 = time.time()
while time.time() - t0 < 240:
    moved = False
    for n, fd, sz in qs:
        while True:
            got = rt.mq_receive(fd, buf_cache[sz], sz, None)
            if got < 0:
                break
            total += 1
            moved = True
    if not moved:
        time.sleep(0.02)
print(f"  drained {total} messages", flush=True)
