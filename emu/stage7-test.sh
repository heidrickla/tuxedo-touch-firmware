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
# Plain greps on the file, NOT `grep <(...)`. ci/checks.sh validates every script
# with `sh -n` because the panel runs busybox sh, and process substitution is a
# bashism dash rejects. Git Bash's `sh` accepts it, so the version with <() passed
# locally and failed in CI -- the check was right and the local pass was the wrong
# answer.
grep -q "^404 $SESSION 500$" "$SEEN" \
    && echo "    500 sent, 404 bytes, session at +0x00" \
    || { echo "    500 NOT seen as 404 bytes with the session"; fail=1; }
grep -q "^404 $SESSION 501$" "$SEEN" \
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

say "6. stage 7b: the four read-only queries, with 17 answered as PAGED"
SEEN7B=/tmp/stage7b-seen.bin
OUT7B=/tmp/stage7b-test.out
python3 - "$QC" "$QR" "$SEEN7B" <<'PY' &
import ctypes, ctypes.util, os, struct, sys, time
rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
rt.mq_open.restype = ctypes.c_int
cmdq = rt.mq_open(sys.argv[1].encode(), 0o2 | os.O_NONBLOCK)
repq = rt.mq_open(sys.argv[2].encode(), 0o2)
buf = ctypes.create_string_buffer(404)
prio = ctypes.c_uint(0)
seen = []


def reply(session, mtype, arg=0, text=b"x"):
    r = bytearray(556)
    r[0x00:0x04] = struct.pack("<I", session)
    r[0x04:0x08] = struct.pack("<I", mtype)
    r[0x08:0x0C] = struct.pack("<I", arg)
    r[0x0E:0x0E + len(text)] = text
    rt.mq_send(repq, bytes(r), 556, 1)


deadline = time.time() + 30
while time.time() < deadline:
    n = rt.mq_receive(cmdq, buf, 404, ctypes.byref(prio))
    if n < 0:
        time.sleep(0.05)
        continue
    session, code = struct.unpack("<II", buf.raw[:8])
    seen.append((n, session, code))
    if code == 500:
        reply(session, 504, text=b"P1  H")
    elif code == 5:
        reply(session, 21, text=b"Ready To Arm")
    elif code == 12:
        reply(session, 22, text=b"zones")
    elif code == 18:
        reply(session, 18, text=b"home")
    elif code == 17:
        # PAGED: the event log comes back as more than one message. A checker
        # that expects one reply per query would call this a failure.
        for page in range(3):
            reply(session, 23, arg=page, text=b"page%d" % page)
    elif code == 501:
        break
open(sys.argv[3], "w").write("\n".join("%d %d %d" % s for s in seen))
PY
R7B=$!
sleep 1
timeout 60 "$BIN" --stage7b "$SESSION" 8 > "$OUT7B" 2>&1
rc7b=$?
sed 's/^/    /' "$OUT7B"
wait $R7B 2>/dev/null

say "7. checks for 7b"
codes=$(awk '{print $3}' "$SEEN7B" 2>/dev/null | tr '\n' ' ')
echo "    codes the fake tuxedo saw: $codes"
[ "$codes" = "500 5 12 18 17 501 " ] \
    && echo "    500 first, the four queries in order, 501 last" \
    || { echo "    WRONG ORDER or missing codes"; fail=1; }
awk '{ if ($1 != 404) bad=1 } END { if (bad) exit 1 }' "$SEEN7B" \
    && echo "    every command was 404 bytes" \
    || { echo "    a command was not 404 bytes"; fail=1; }
grep -q "queries=4" "$OUT7B" && echo "    all four queries sent" \
    || { echo "    not all queries sent"; fail=1; }
# 17 is paged, so replies EXCEED queries; this is the check that would break if
# someone "fixed" the tally to one-reply-per-query.
grep -qE "received=([7-9]|[1-9][0-9])" "$OUT7B" \
    && echo "    replies exceed queries -- the paged 17 was not miscounted" \
    || { echo "    reply count looks like one-per-query; 17's pages were lost"; fail=1; }
grep -q "msgTypes .*23x3" "$OUT7B" && echo "    the three pages of 17 all arrived" \
    || { echo "    17's pages did not all arrive"; fail=1; }
[ "$rc7b" = "0" ] && echo "    exit 0 (unregister confirmed)" \
    || { echo "    exit $rc7b"; fail=1; }

say "8. stage 7c: console mode DURING the watch, BACK strictly AFTER it"
# The ordering is the whole point. 502/503 reach home_back_press(), which zeroes
# F7_Mesgs_enabled, so a BACK sent among the queries would switch off the broadcast
# the run is trying to observe -- the same way the first stage-6 window logged zero.
SEEN7C=/tmp/stage7c-seen.bin
OUT7C=/tmp/stage7c-test.out
python3 - "$QC" "$QR" "$SEEN7C" <<'PY' &
import ctypes, ctypes.util, os, struct, sys, time
rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
rt.mq_open.restype = ctypes.c_int
cmdq = rt.mq_open(sys.argv[1].encode(), 0o2 | os.O_NONBLOCK)
repq = rt.mq_open(sys.argv[2].encode(), 0o2)
buf = ctypes.create_string_buffer(404)
prio = ctypes.c_uint(0)
seen = []
deadline = time.time() + 30
while time.time() < deadline:
    n = rt.mq_receive(cmdq, buf, 404, ctypes.byref(prio))
    if n < 0:
        time.sleep(0.05)
        continue
    session, code = struct.unpack("<II", buf.raw[:8])
    seen.append(code)
    if code == 500:
        r = bytearray(556)
        r[0x00:0x04] = struct.pack("<I", session)
        r[0x04:0x08] = struct.pack("<I", 504)
        rt.mq_send(repq, bytes(r), 556, 1)
    if code == 501:
        break
open(sys.argv[3], "w").write(" ".join(str(c) for c in seen))
PY
R7C=$!
sleep 1
timeout 60 "$BIN" --stage7c "$SESSION" 5 > "$OUT7C" 2>&1
rc7c=$?
sed 's/^/    /' "$OUT7C"
wait $R7C 2>/dev/null
order=$(cat "$SEEN7C" 2>/dev/null)
echo "    codes in order: $order"
[ "$order" = "500 19 502 501" ] \
    && echo "    500, console 19, then BACK 502, then 501 -- BACK is after the watch" \
    || { echo "    WRONG ORDER: expected '500 19 502 501'"; fail=1; }
grep -q "ends the broadcast" "$OUT7C" \
    && echo "    the run said out loud that 502 ends the broadcast" \
    || { echo "    502 was sent without noting it ends the broadcast"; fail=1; }
[ "$rc7c" = "0" ] || { echo "    exit $rc7c"; fail=1; }

say "9. 7d refuses anything that is not one of the four arming commands"
# The stage plan is one command per attempt. 19 is console mode -- a plausible
# typo for an arming code and one that would put the panel in console mode
# instead of arming it.
"$BIN" --stage7d "$SESSION" 1 19 >/tmp/7d-bad.out 2>&1
[ "$?" = "2" ] && grep -q "ONE arming command" /tmp/7d-bad.out \
    && echo "    a non-arming code is refused, exit 2, and the message lists the four" \
    || { echo "    7d accepted a non-arming code"; fail=1; }
"$BIN" --stage7d "$SESSION" 1 >/tmp/7d-none.out 2>&1
[ "$?" = "2" ] && echo "    a missing code is refused too" \
    || { echo "    7d accepted a missing code"; fail=1; }

say "verdict"
[ "$fail" = "0" ] && echo "  STAGE 7A, 7B AND 7C SEND PATHS PASS (against a stand-in, not the panel)" \
    || echo "  FAILURES ABOVE"
exit "$fail"
