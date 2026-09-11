#!/bin/bash
# Prove stage 7a on the bench before it is ever pointed at the alarm bus.
#
# Stage 7a is the first stage that WRITES. Stage 6 could be argued safe because it
# opened the reply queue read-only and sent nothing; this one sends 500 and 501, and
# 501 switches the broadcast firehose off for every consumer, not just for us. So the
# send path gets proven here, against a fake /tuxedo that checks what it receives,
# rather than on a panel where a malformed command is someone's alarm.
#
# What a stand-in CAN prove: that the command is 404 bytes with the session at +0x00
# and the code at +0x04, that 500 is sent first and 501 last, and that a 504 reply is
# received and recognised. What it CANNOT prove is how /tuxedo actually reacts -- that
# is the window, and it is why this stops short of claiming 7a passes on hardware.
#
#   sudo bash emu/stage7a-test.sh
set -u
BIN=${BIN:-/build/tuxweb-src/tuxweb/target/release/tuxweb}
QR=/Q_ServCmdTrsmtr     # replies,  tuxedo -> us,  556
QC=/Q_ServCmdRcver      # commands, us -> tuxedo,  404
SESSION=4242
OUT=/tmp/stage7a-test.out
SEEN=/tmp/stage7a-seen.bin
fail=0

say() { echo; echo "=== $* ==="; }
[ -x "$BIN" ] || { echo "ABORT: no binary at $BIN"; exit 1; }

say "0. both queues, created by something ELSE, with the panel's geometries"
python3 - "$QR" "$QC" <<'PY'
import ctypes, ctypes.util, sys
rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
class Attr(ctypes.Structure):
    _fields_ = [("mq_flags", ctypes.c_long), ("mq_maxmsg", ctypes.c_long),
                ("mq_msgsize", ctypes.c_long), ("mq_curmsgs", ctypes.c_long),
                ("pad", ctypes.c_long * 4)]
rt.mq_open.restype = ctypes.c_int
for name, size in ((sys.argv[1], 556), (sys.argv[2], 404)):
    b = name.encode()
    rt.mq_unlink(b)
    a = Attr(0, 32, size, 0, (ctypes.c_long * 4)())
    fd = rt.mq_open(b, 0o100 | 0o2, 0o666, ctypes.byref(a))
    print("  %-18s msgsize=%d %s" % (name, size, "ok" if fd >= 0 else "FAILED"))
PY

say "1. a fake /tuxedo: read the command, check it, answer with a 504"
# Backgrounded BEFORE tuxweb starts, because registerclient's real counterpart
# answers immediately and a responder started afterwards would miss the 500.
python3 - "$QC" "$QR" "$SEEN" <<'PY' &
import ctypes, ctypes.util, os, struct, sys, time
rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
rt.mq_open.restype = ctypes.c_int
# O_RDWR | O_NONBLOCK, so the deadline below is real: a blocking mq_receive would
# sit here forever if the send path is broken, which is exactly the case this test
# exists to catch.
cmdq = rt.mq_open(sys.argv[1].encode(), 0o2 | os.O_NONBLOCK)
repq = rt.mq_open(sys.argv[2].encode(), 0o2)
buf = ctypes.create_string_buffer(404)
prio = ctypes.c_uint(0)
seen = []
deadline = time.time() + 25
while time.time() < deadline:
    n = rt.mq_receive(cmdq, buf, 404, ctypes.byref(prio))
    if n < 0:
        time.sleep(0.05)
        continue
    raw = buf.raw[:n]
    session, code = struct.unpack("<II", raw[:8])
    seen.append((n, session, code))
    print("    fake tuxedo: got %d bytes session=%d code=%d" % (n, session, code))
    if code == 500:
        rep = bytearray(556)
        rep[0x00:0x04] = struct.pack("<I", session)
        rep[0x04:0x08] = struct.pack("<I", 504)
        rep[0x08:0x0C] = struct.pack("<I", 0)
        rep[0x0E:0x14] = b"P1  H\x00"
        rt.mq_send(repq, bytes(rep), 556, 1)
        print("    fake tuxedo: answered 504")
    if code == 501:
        break
open(sys.argv[3], "w").write("\n".join("%d %d %d" % s for s in seen))
PY
RESPONDER=$!
sleep 1

say "2. run stage 7a"
timeout 60 "$BIN" --stage7a "$SESSION" 8 > "$OUT" 2>&1
rc=$?
sed 's/^/    /' "$OUT"
wait $RESPONDER 2>/dev/null

say "3. what the fake tuxedo actually received"
if [ -s "$SEEN" ]; then
    sed 's/^/    len session code: /' "$SEEN"
else
    echo "    NOTHING -- the send path did not work"; fail=1
fi

say "4. checks"
grep -q "len session code: 404 $SESSION 500" <(sed 's/^/len session code: /' "$SEEN" 2>/dev/null) \
    && echo "    500 sent, 404 bytes, session at +0x00" \
    || { echo "    500 NOT seen as 404 bytes with the session"; fail=1; }
grep -q "len session code: 404 $SESSION 501" <(sed 's/^/len session code: /' "$SEEN" 2>/dev/null) \
    && echo "    501 sent -- the panel is left as it was found" \
    || { echo "    501 NOT sent; the firehose would have been left ON"; fail=1; }
grep -q "saw504=true" "$OUT" && echo "    504 reply received and recognised" \
    || { echo "    504 not recognised"; fail=1; }
[ "$rc" = "0" ] && echo "    exit 0 (unregister confirmed)" \
    || { echo "    exit $rc -- a run that cannot unregister is a failure"; fail=1; }

say "5. a zero session is refused before anything is opened"
if "$BIN" --stage7a 0 1 >/tmp/s7a-zero.out 2>&1; then
    echo "    ACCEPTED a zero session -- it would look like a silent panel"; fail=1
else
    grep -q "non-zero" /tmp/s7a-zero.out && echo "    refused, and said why" \
        || { echo "    refused, but not for the stated reason"; fail=1; }
fi

say "verdict"
[ "$fail" = "0" ] && echo "  STAGE 7A SEND PATH PASSES (against a stand-in, not the panel)" \
    || echo "  FAILURES ABOVE"
exit "$fail"
