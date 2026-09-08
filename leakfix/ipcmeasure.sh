#!/bin/bash
# Measure the IPC leak on the emulated panel, separating the three quantities
# that have been conflated so far:
#
#   qemu RSS        includes qemu's OWN per-guest-thread cost, which the panel
#                   does not pay. This is the number that read ~38.5 kB/message.
#   guest heap size the brk region inside the guest, found by address not name.
#   in-use chunks   what the guest has actually allocated and not freed.
#
# Usage: ipcmeasure.sh <tree> <label> <warmup> <count>
set -u
TREE="${1:-/work/emu/p15}"
LABEL="${2:-p15}"
WARM="${3:-100}"
N="${4:-100}"
cd /work/fwcheck

echo "=== killing any emulator, by exe so the pattern cannot match this script ==="
for p in /proc/[0-9]*; do
    e=$(sudo readlink "$p/exe" 2>/dev/null)
    case "$e" in *qemu-arm-static) echo "  killing ${p#/proc/}"; sudo kill -9 "${p#/proc/}" 2>/dev/null ;;
    esac
done
for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in "python3 /tmp/mqdrain.py"*) sudo kill "${p#/proc/}" 2>/dev/null ;; esac
done
sleep 3

echo "=== starting $TREE untraced ==="
sudo bash emu/serve.sh "$TREE" "$LABEL" 2>&1 | sed 's/^/  /'

echo "=== re-arming mqdrain on the OUTBOUND queue only ==="
# serve.sh drains EVERY queue including the inbound one, which would eat the
# injected messages and give a flat count indistinguishable from a fix.
for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in "python3 /tmp/mqdrain.py"*) sudo kill "${p#/proc/}" 2>/dev/null ;; esac
done
sleep 2
# The redirect must happen INSIDE sudo: done outside, the shell creates the file
# as the calling user and a root-owned leftover from an earlier run makes it
# fail with "Permission denied" -- and the drain then silently does not start.
sudo sh -c "setsid python3 /tmp/mqdrain.py /Q_ServCmdRcver >/tmp/drain.$LABEL.log 2>&1 &"
sleep 3
nout=0; nin=0
for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in
        "python3 /tmp/mqdrain.py"*Trsmtr*) echo "  INBOUND drain still up: $c"; nin=1 ;;
        "python3 /tmp/mqdrain.py"*)        echo "  draining: $c"; nout=1 ;;
    esac
done
[ "$nin" -eq 1 ] && { echo "ABORT: something is draining the inbound queue"; exit 1; }
[ "$nout" -eq 0 ] && { echo "ABORT: outbound drain did not start"; exit 1; }

# sudo is REQUIRED: without it ss omits the process info for sockets this user
# does not own, and the lookup silently returns nothing.
PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
R=$(sudo readlink /proc/$PID/root)
[ "$R" = "$TREE" ] || { echo "ABORT: :80 served from '$R', not '$TREE'"; exit 1; }
echo "  guest pid $PID  root $R"
echo -n "  binary: "; sudo md5sum "$TREE/opt/webserver/Barracuda" | cut -c1-8

snap() {
    local tag="$1"
    local rss heap
    rss=$(sudo awk '/^VmRSS/{print $2}' /proc/$PID/status)
    # the guest brk heap: the large anonymous rw mapping at low guest addresses
    heap=$(sudo awk '$1 ~ /^0[0-9a-f]*-/ && $2 ~ /rw/ && NF==5 {
              split($1,a,"-"); s=strtonum("0x" a[1]); e=strtonum("0x" a[2]);
              if (s < 0x01000000 && (e-s) > 0x10000) t += (e-s) } END {print t+0}' /proc/$PID/maps)
    echo "  $tag qemu_rss_kb=$rss guest_heap_bytes=$heap"
}

echo "=== warmup: $WARM messages ==="
sudo timeout 900 python3 emu/pushdriver.py --count "$WARM" --msgtype 21 --settle 15 2>&1 | sed 's/^/  /'

echo "=== baseline after warmup ==="
snap BEFORE
sudo python3 heapwalk.py --pid $PID --save /tmp/hw.$LABEL.before.json 2>&1 | tail -5 | sed 's/^/  /'

echo "=== measured run: $N messages ==="
sudo timeout 900 python3 emu/pushdriver.py --count "$N" --msgtype 21 --settle 20 2>&1 | sed 's/^/  /'

echo "=== after ==="
snap AFTER
sudo python3 heapwalk.py --pid $PID --compare /tmp/hw.$LABEL.before.json --expect "$N" 2>&1 | tail -25 | sed 's/^/  /'
