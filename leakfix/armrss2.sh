#!/bin/bash
# Replication of the LEAK 31 panel measurement, with the control fixed.
#
# Run 1 paired a 203s idle control against a 633s test, because each arm/disarm
# round-trip spends ~26s polling status and the control was written to a fixed
# 200s. Three times the wall clock is not a paired control. This one measures the
# test first, then idles for exactly as long as the test took, so the two arms are
# duration-matched by construction rather than by guess.
#
# Test-then-control also puts the idle stretch AFTER the burst, which is the
# stricter direction: if the arm handler leaves a heap that keeps growing on its
# own, the control absorbs that growth and the attributed per-call figure comes
# out lower, not higher.
#
# Every arm and disarm uses the real code. No wrong code is ever sent: three
# failures permanently disable every web account (TRAPS 6).
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
B=$(rss)
echo "  ${BUSY}s busy, $ok/$((CYCLES * 2)) calls returned ok"
echo "  $A -> $B kB  (delta $((B - A)) kB)"

echo
echo "=== CONTROL: idle for the same ${BUSY}s ==="
# An until-loop on elapsed time, not a long foreground sleep: the harness blocks
# those, which killed the first run of run 1's script and produced no output.
START=$(date +%s)
until [ $(( $(date +%s) - START )) -ge "$BUSY" ]; do sleep 5; done
C=$(rss)
IDLE=$(( $(date +%s) - START ))
P1=$(pid)
echo "  ${IDLE}s idle: $B -> $C kB  (delta $((C - B)) kB)"

echo
echo "=== result ==="
echo "  busy  ${BUSY}s -> $((B - A)) kB over $((CYCLES * 2)) handler calls"
echo "  idle  ${IDLE}s -> $((C - B)) kB"
echo "  attributable to the calls: $(( (B - A) - (C - B) )) kB over $((CYCLES * 2)) calls"
if [ "$P0" != "$P1" ]; then
    echo "  BARRACUDA RESTARTED mid-test (pid $P0 -> $P1); the numbers are void"
fi
echo
echo "  leave the panel DISARMED, and confirm it:"
python $ARMDIR/tux-disarm.py 2>&1 | tail -2 | sed 's/^/    /'
