#!/bin/bash
# Measure LEAK 31 on the panel, where the arm handlers actually complete.
#
# The bench cannot do this: setarmwithcode mq_sends to the alarm bus and waits for
# /tuxedo's reply, which does not exist under emulation, so the request never
# returns and the handler's allocations cannot be attributed to a completed call.
# The panel is the only place the path runs end to end.
#
# jsoncount cannot be used here either -- 2.6.31 refuses /proc/PID/mem with ESRCH --
# so this measures VmRSS, which is page-quantised at 4 kB. Hence the paired control:
# an idle stretch, so per-request growth is separated from the post-restart heap ramp
# that this panel is known to show.
#
# SUPERSEDED BY armrss2.sh. KEPT AS THE RECORD OF A RUN THAT DOES NOT PAIR.
#
# The control below is a fixed 200s, but 12 arm/disarm cycles take ~633s, because each
# round-trip spends ~26s polling status. So the control covered under a third of the
# test's duration and the two arms are not comparable. This run reported 392 kB over
# 24 calls against a 0 kB control, implying ~16 kB per call; armrss2.sh, which derives
# the control duration from the measured test duration, got 3.3 kB per call for
# identical work. The difference is mostly this panel's post-restart heap ramp, which
# run 1 started inside of. Do not quote this script's number.
#
# Every arm and disarm uses the real code. No wrong code is ever sent: three
# failures permanently disable every web account (TRAPS §6).
set -u
CYCLES="${1:-12}"
PANEL="${PANEL:-203.0.113.5}"   # the real address is not in this repo
ARMDIR="${ARMDIR:-/d/temp}"      # holds tux-arm.py and tux-disarm.py
KEY=$HOME/.ssh/tuxedo_ed25519
PSSH="ssh -n -o ConnectTimeout=25 -o BatchMode=yes -i $KEY root@$PANEL"

rss() {
    $PSSH 'export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
      for p in /proc/[0-9]*; do
        c=$(sed -n "s/^\([0-9]*\) (\([^)]*\)).*/\2/p" $p/stat 2>/dev/null)
        [ "$c" = "Barracuda" ] && grep VmRSS /proc/${p#/proc/}/status | tr -s " " | cut -d" " -f2
      done | head -1'
}
pid() {
    $PSSH 'for p in /proc/[0-9]*; do
        c=$(sed -n "s/^\([0-9]*\) (\([^)]*\)).*/\2/p" $p/stat 2>/dev/null)
        [ "$c" = "Barracuda" ] && echo ${p#/proc/}
      done | head -1'
}

P0=$(pid)
A=$(rss)
echo "pid $P0, VmRSS $A kB"

echo
echo "=== CONTROL: idle, same duration as the test ==="
# An until-loop on elapsed time, not a long foreground sleep: the harness blocks
# those, which killed the first run of this script and produced no output at all.
START=$(date +%s)
until [ $(( $(date +%s) - START )) -ge 200 ]; do sleep 5; done
B=$(rss)
IDLE=$(( $(date +%s) - START ))
echo "  ${IDLE}s idle: $A -> $B kB  (delta $((B - A)) kB)"

echo
echo "=== TEST: $CYCLES arm/disarm cycles = $((CYCLES * 2)) handler calls ==="
START=$(date +%s)
ok=0
for i in $(seq 1 "$CYCLES"); do
    python $ARMDIR/tux-arm.py stay   >/dev/null 2>&1 && ok=$((ok + 1))
    python $ARMDIR/tux-disarm.py     >/dev/null 2>&1 && ok=$((ok + 1))
    printf "  cycle %2d/%d\r" "$i" "$CYCLES"
done
echo
BUSY=$(( $(date +%s) - START ))
C=$(rss)
P1=$(pid)
echo "  ${BUSY}s busy, $ok/$((CYCLES * 2)) calls returned ok"
echo "  $B -> $C kB  (delta $((C - B)) kB)"

echo
echo "=== result ==="
echo "  idle  ${IDLE}s -> $((B - A)) kB"
echo "  busy  ${BUSY}s -> $((C - B)) kB over $((CYCLES * 2)) handler calls"
if [ "$P0" != "$P1" ]; then
    echo "  BARRACUDA RESTARTED mid-test (pid $P0 -> $P1); the numbers are void"
fi
echo
echo "  leave the panel DISARMED, and confirm it:"
python $ARMDIR/tux-disarm.py 2>&1 | tail -2 | sed 's/^/    /'
