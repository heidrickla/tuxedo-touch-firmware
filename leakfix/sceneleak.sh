#!/bin/bash
# Identify WHICH allocations /GetSceneList retains, by chunk size and contents.
#
# /GetSceneList answers 200 and leaks ~780 B/request, so the scene helper
# functions that abandon their parsed tree are finally drivable. Same technique
# that named the IPC leaks: histogram in-use chunks, drive N, histogram again,
# then dump the contents of the sizes that grew.
set -u
N="${1:-300}"
cd /work/fwcheck
PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  guest pid $PID"
echo -n "  binary: "; sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8

echo "=== warm, so the startup ramp is not counted as the leak ==="
sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode api \
    --endpoint /GetSceneList --plain "operation=get" --warmup 300 --n 10 --every 10 2>&1 \
    | grep -E "measured statuses" | sed 's/^/  /'

echo "=== snapshot before ==="
sudo python3 heapwalk.py --pid "$PID" --save /tmp/sc.before.json 2>&1 | tail -2 | sed 's/^/  /'

echo "=== driving $N requests ==="
sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode api \
    --endpoint /GetSceneList --plain "operation=get" --warmup 0 --n "$N" --every 100 2>&1 \
    | grep -E "statuses|rss|slope" | sed 's/^/  /'

echo "=== snapshot after ==="
sudo python3 heapwalk.py --pid "$PID" --compare /tmp/sc.before.json --expect "$N" 2>&1 | tail -20 | sed 's/^/  /'
echo DONE-SCENELEAK
