#!/bin/bash
# Identify WHICH allocations a leaking page retains, by chunk size.
#
# Same technique that named the IPC leaks: histogram the guest's in-use chunks,
# drive N requests, histogram again. Any size growing by ~N is allocated once
# per request and never freed, which points at a call site.
#
# Usage: pageleak.sh <path> <n>
set -u
P="${1:-/scene_configuration.html}"
N="${2:-300}"
cd /work/fwcheck

PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  guest pid $PID  root $(sudo readlink /proc/$PID/root)"
echo -n "  binary: "; sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8

# Warm first, so the startup working-set ramp is not counted as the leak.
echo "=== warming ==="
sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode console --path "$P" \
    --warmup 300 --n 10 --every 10 2>&1 | grep -E "statuses" | sed 's/^/  /'

echo "=== snapshot before ==="
sudo python3 heapwalk.py --pid "$PID" --save /tmp/pl.before.json 2>&1 | tail -3 | sed 's/^/  /'

echo "=== driving $N requests to $P ==="
sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode console --path "$P" \
    --warmup 0 --n "$N" --every 100 2>&1 | grep -E "statuses|requests|rss|slope" | sed 's/^/  /'

echo "=== snapshot after ==="
sudo python3 heapwalk.py --pid "$PID" --compare /tmp/pl.before.json --expect "$N" 2>&1 | tail -22 | sed 's/^/  /'
