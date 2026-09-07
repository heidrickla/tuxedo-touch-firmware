#!/bin/bash
# Prove the stage-6 safety scaffolding before anyone books a panel window.
#
# Everything stage 6 lists as mandatory is exercised here, on the build VM,
# where a queue can be created and destroyed freely and a failed handover costs
# nothing. What cannot be tested here is the only thing the panel window is
# for: whether /tuxedo's replies actually reach a process other than Barracuda.
# Separating those two is the point -- when the window fails, it should fail
# for that reason and not because the deadman was untested.
#
# Run as root: the queues left behind by the emulation rig are root-owned,
# and this needs to unlink them before creating its own.
#
#   sudo bash /work/cutover-test.sh
set -u
BIN=/build/tuxweb-src/tuxweb/target/release/tuxweb
Q=/Q_ServCmdTrsmtr
LOG=/tmp/cutover-test.tsv
VENDOR=/tmp/fake-vendor
fail=0

say() { echo; echo "=== $* ==="; }

# A stand-in for the vendor binary. The handover is an execve, so this has to
# be a real executable; what it prints is how we know the exec happened.
# Written fresh every run, and the run ABORTS if it cannot be. An earlier run
# of this script left a stub behind, the next run failed to overwrite it with
# "Permission denied", and every later step then validated against a file this
# run did not write. It happened to be identical. That is the stale-artifact
# failure this project has already paid for once, so it is an abort now.
rm -f "$VENDOR"
cat > "$VENDOR" <<'EOF'
#!/bin/sh
echo "FAKE VENDOR RUNNING (argv0=$0)"
EOF
if [ ! -s "$VENDOR" ]; then
    echo "ABORT: cannot write $VENDOR -- every later step would test a stale file"
    exit 1
fi
chmod 755 "$VENDOR"
grep -q "FAKE VENDOR RUNNING" "$VENDOR" || { echo "ABORT: $VENDOR is not ours"; exit 1; }

say "0. a queue with the panel's geometry, created by something ELSE"
python3 - "$Q" <<'PY'
import ctypes, ctypes.util, sys, os
rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
class Attr(ctypes.Structure):
    _fields_ = [("mq_flags", ctypes.c_long), ("mq_maxmsg", ctypes.c_long),
                ("mq_msgsize", ctypes.c_long), ("mq_curmsgs", ctypes.c_long),
                ("pad", ctypes.c_long * 4)]
name = sys.argv[1].encode()
# The emulation rig leaves these behind -- they are kernel objects that outlive
# the process that made them, and run.sh recreates them on demand, so removing
# a stale one costs nothing and colliding with it costs the whole test.
if rt.mq_unlink(name) == 0:
    print("  unlinked a stale %s left by an earlier emulation run" % sys.argv[1])
a = Attr(0, 32, 556, 0)
rt.mq_open.restype = ctypes.c_int
fd = rt.mq_open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600, ctypes.byref(a))
if fd == -1:
    print("  could not create the queue:", os.strerror(ctypes.get_errno())); sys.exit(1)
print("  created %s maxmsg=32 msgsize=556" % sys.argv[1])
PY
[ $? = 0 ] || { echo "ABORT: no queue"; exit 1; }

say "1. start the cutover with a 20 s deadman"
rm -f "$LOG"
setsid "$BIN" --cutover "$VENDOR" 20 "$LOG" > /tmp/cutover-test.out 2>&1 &
sleep 3
head -6 /tmp/cutover-test.out | sed 's/^/  /'
grep -q "SOLE READER" /tmp/cutover-test.out || { echo "  did not take the queue"; fail=1; }
grep -q "read-only" /tmp/cutover-test.out || { echo "  not opened read-only"; fail=1; }

say "2. send replies as /tuxedo would, and see them logged"
python3 - "$Q" <<'PY'
import ctypes, ctypes.util, os, struct, sys, time
rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
rt.mq_open.restype = ctypes.c_int
fd = rt.mq_open(sys.argv[1].encode(), os.O_WRONLY)
if fd == -1:
    print("  cannot open for write:", os.strerror(ctypes.get_errno())); sys.exit(1)
for i, (mt, text) in enumerate([(21, b"\xfe1Ready To Arm:2"), (20, b"\xff\x80raw"),
                                (19, b"\xfeconsole"), (504, b"\xfeP1  H:1:0:3:3")]):
    buf = bytearray(556)
    buf[0:4] = struct.pack("<I", 7)
    buf[4:8] = struct.pack("<I", mt)
    buf[8:12] = struct.pack("<I", i)
    buf[14:14+len(text)] = text
    rt.mq_send(fd, bytes(buf), 556, 1)
    time.sleep(0.2)
print("  sent 4 replies")
PY
sleep 2
if [ -s "$LOG" ]; then
    echo "  log has $(wc -l < "$LOG") lines:"
    cut -c1-118 "$LOG" | sed 's/^/    /'
else
    echo "  LOG IS EMPTY -- nothing was received"; fail=1
fi
grep -q "msgType=21" "$LOG" 2>/dev/null || { echo "  msgType 21 missing"; fail=1; }
grep -q "msgType=504" "$LOG" 2>/dev/null || { echo "  msgType 504 missing"; fail=1; }
grep -q "state=0xfe" "$LOG" 2>/dev/null || { echo "  state byte not decoded"; fail=1; }

say "3. the raw bytes are kept, not just the decoded fields"
# 556 bytes = 1112 hex characters, on every line
awk -F'\t' '{ n=length($NF); if (n != 1112) { print "    line " NR " raw is " n " chars, want 1112"; bad=1 } }
            END { if (!bad) print "    every line carries all 556 bytes as hex" }' "$LOG"

say "4. the deadman fires and hands the panel back"
for i in $(seq 1 40); do
    grep -q "FAKE VENDOR RUNNING" /tmp/cutover-test.out && break
    sleep 1
done
if grep -q "DEADMAN" /tmp/cutover-test.out && grep -q "FAKE VENDOR RUNNING" /tmp/cutover-test.out; then
    echo "  handed back by itself:"
    grep -E "DEADMAN|FAKE VENDOR" /tmp/cutover-test.out | sed 's/^/    /'
else
    echo "  DID NOT HAND BACK -- this is the failure that reboots a panel"; fail=1
    tail -4 /tmp/cutover-test.out | sed 's/^/    /'
fi

say "5. it refuses to start when the vendor fallback is missing"
"$BIN" --cutover /tmp/definitely-not-here 20 /tmp/x.tsv > /tmp/cutover-missing.out 2>&1
rc=$?
echo "  exit $rc: $(head -1 /tmp/cutover-missing.out)"
[ "$rc" = 2 ] || { echo "  expected exit 2"; fail=1; }
# and it must refuse BEFORE arming anything: a deadman whose action is to exec
# a binary that is not there is worse than no deadman, and the banner claiming
# one was armed is what someone reads when it matters
grep -q "deadman armed" /tmp/cutover-missing.out     && { echo "  ARMED A DEADMAN it could never honour"; fail=1; }     || echo "  refused before arming anything"
grep -q "nothing was armed" /tmp/cutover-missing.out || { echo "  did not say so"; fail=1; }

say "6. a missing queue hands back rather than creating one"
python3 -c "
import ctypes,ctypes.util,sys
rt=ctypes.CDLL(ctypes.util.find_library('rt') or 'librt.so.1'); rt.mq_unlink(b'$Q')"
"$BIN" --cutover "$VENDOR" 20 /tmp/y.tsv > /tmp/cutover-noq.out 2>&1
grep -q "does not exist" /tmp/cutover-noq.out && echo "  explained the absence" \
    || { echo "  did not explain"; fail=1; }
grep -q "FAKE VENDOR RUNNING" /tmp/cutover-noq.out && echo "  handed back" \
    || { echo "  did not hand back"; fail=1; }
ls /dev/mqueue$Q >/dev/null 2>&1 && { echo "  IT CREATED THE QUEUE -- B4 violated"; fail=1; } \
    || echo "  and did not create the queue"

say "verdict"
[ "$fail" = 0 ] && echo "  SCAFFOLDING PASSES" || echo "  FAILURES ABOVE"
rm -f "$VENDOR"
exit "$fail"
