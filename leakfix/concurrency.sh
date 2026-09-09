#!/bin/bash
# Can two request handlers run AT THE SAME TIME?
#
# This is the load-bearing safety fact for any request-scoped bulk free. libjson's
# allocation registries are process-global and unlocked, so a free-everything at the
# end of request A would release strings that an in-flight request B still holds --
# but only if A and B can overlap.
#
# Already measured: 25 SEQUENTIAL requests were served across 20 different qemu CPUs
# (one CPU per guest thread), so handlers migrate across the whole worker pool. That
# is not the same as overlapping.
#
# Method: trace the handler's ENTRY block only, drive two clients in parallel, and
# look for two DIFFERENT threads entering within the same window. With a sequential
# driver every entry is separated by a full response; with parallel drivers, an
# interleave proves genuine concurrency.
set -u
N="${1:-40}"
: "${PANEL_USER:?set PANEL_USER}"
VMSSH="ssh -o ConnectTimeout=25 -i $HOME/.ssh/fwbuild_ed25519 -o IdentitiesOnly=yes claude@${VMHOST:-203.0.113.40}"

$VMSSH "sudo bash /work/fwcheck/serve-traced.sh /work/emu/scenes 0x3a2a0..0x3a2b0 /trace.log > /tmp/cc.serve 2>&1; tail -1 /tmp/cc.serve"
$VMSSH "sudo truncate -s 0 /work/emu/scenes/trace.log"

# Two drivers, started together, each with its own login.
$VMSSH "cd /work/fwcheck && (sudo TUXEDO_USER=$PANEL_USER python3 /tmp/scenedrive.py 127.0.0.1 $PANEL_USER 141 $N sceneid=1 > /tmp/cc.a 2>&1 &) ; (sudo TUXEDO_USER=$PANEL_USER python3 /tmp/scenedrive.py 127.0.0.1 $PANEL_USER 141 $N sceneid=2 > /tmp/cc.b 2>&1 &) ; sleep 45; grep -h 'body sizes' /tmp/cc.a /tmp/cc.b | sed 's/^/    /'"

echo "  === distinct threads entering the handler ==="
$VMSSH "sudo grep -a -oE '^Trace [0-9]+' /work/emu/scenes/trace.log | sort -u | wc -l | sed 's/^/    distinct: /'"
echo "  === the entry sequence, to spot interleaving ==="
$VMSSH "sudo grep -a -oE '^Trace [0-9]+' /work/emu/scenes/trace.log | head -40 | tr '\n' ' '"
echo
echo "  (a run of alternating DIFFERENT thread numbers is what concurrency looks like;"
echo "   long runs of the same number would mean the pool serialises)"
