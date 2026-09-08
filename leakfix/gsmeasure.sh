#!/bin/bash
# Re-measure /GetSceneList's documented ~491 B/request residual on the current
# build, now that LEAKS 24, 26, 27 and 28 are in.
#
# This uses the API surface, whose auth is the authtoken/HMAC scheme rather than
# the session table, so the ten-slot limit does not apply and leakprobe can drive
# it directly.
set -u
N="${1:-300}"
: "${PANEL_USER:?set PANEL_USER}"

sudo pkill -9 -f qemu-arm-static 2>/dev/null
sudo pkill -9 -f mqdrain.py 2>/dev/null
sleep 5
sudo bash /work/fwcheck/emu/serve.sh /work/emu/scenes scenes >/dev/null 2>&1

PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  pid $PID  binary $(sudo md5sum /work/emu/scenes/opt/webserver/Barracuda | cut -c1-8)"

cd /work/fwcheck
echo "=== warm 200 ==="
sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode api \
    --endpoint /GetSceneList --plain "operation=get" \
    --user "$PANEL_USER" --creds /tmp/pw.txt \
    --warmup 200 --n 10 --every 10 2>&1 | grep -E "measured statuses" | sed 's/^/    /'

sudo python3 heapwalk.py --pid "$PID" --save /tmp/gs.json >/dev/null 2>&1

echo "=== drive $N ==="
sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode api \
    --endpoint /GetSceneList --plain "operation=get" \
    --user "$PANEL_USER" --creds /tmp/pw.txt \
    --warmup 0 --n "$N" --every 100 2>&1 \
    | grep -E "measured statuses|slope" | sed 's/^/    /'

echo "=== growth ==="
sudo python3 heapwalk.py --pid "$PID" --compare /tmp/gs.json --expect "$N" 2>&1 \
    | grep -E "^ +[0-9]+ +[+-]|per-request" | head -8 | sed 's/^/    /'
