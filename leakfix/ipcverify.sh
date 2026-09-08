#!/bin/bash
# Prove the IPC-patched binary still WORKS, not merely that it leaks less.
#
# A wrong free does not usually announce itself: it corrupts the heap and the
# damage surfaces somewhere else entirely. So this drives the patched paths
# hard, then checks the server is still serving and still answering correctly.
#
# Usage: ipcverify.sh <tree> <label>
set -u
TREE="${1:-/work/emu/p15ipc3}"
LABEL="${2:-verify}"
cd /work/fwcheck

PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
R=$(sudo readlink /proc/$PID/root)
[ "$R" = "$TREE" ] || { echo "ABORT: :80 served from '$R', not '$TREE'"; exit 1; }
echo -n "  binary under test: "; sudo md5sum "$TREE/opt/webserver/Barracuda" | cut -c1-8
echo "  guest pid $PID"

echo
echo "=== 1. all four listeners still bound ==="
sudo ss -lnt 2>/dev/null | grep -E ":(80|443|6280|9443)\b" | sed 's/^/  /'
n=$(sudo ss -lnt 2>/dev/null | grep -cE ":(80|443|6280|9443)\b")
echo "  listeners: $n/4"
[ "$n" -eq 4 ] || echo "  *** FAIL: not all four listeners are up ***"

echo
echo "=== 2. the web server still answers (PLAINTEXT ports only) ==="
# ⚠ curl CANNOT be used against this panel's TLS ports. The target links
# OpenSSL 1.0.0 and a modern curl on OpenSSL 3 refuses with
#   error:0A000152:SSL routines::unsafe legacy renegotiation disabled
# reporting HTTP 000, which reads exactly like "the server is dead". The TLS
# listeners are covered by step 3 instead, which uses Python and does reach
# them. Do not "fix" this by adding a TLS check here with curl.
for u in "http://127.0.0.1/" "http://127.0.0.1:6280/"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 20 "$u")
    echo "  $u -> $code"
    [ "$code" = "000" ] && echo "  *** FAIL: no response from $u ***"
done

echo
echo "=== 3. the push stream is still gated (P13 must survive) ==="
sudo timeout 200 python3 test-stream-auth.py --host 127.0.0.1 --seconds 6 2>&1 | tail -20 | sed 's/^/  /'

echo
echo "=== 4. drive the patched IPC path hard, then re-check ==="
sudo timeout 900 python3 emu/pushdriver.py --count 300 --msgtype 21 --settle 15 2>&1 | sed 's/^/  /'
sudo timeout 900 python3 emu/pushdriver.py --count 100 --msgtype 22 --settle 15 2>&1 | sed 's/^/  /'

echo
echo "=== 5. still alive and serving after 400 messages ==="
if [ -d /proc/$PID ]; then echo "  guest pid $PID still present"; else echo "  *** FAIL: guest died ***"; fi
n=$(sudo ss -lnt 2>/dev/null | grep -cE ":(80|443|6280|9443)\b")
echo "  listeners: $n/4"
code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 20 http://127.0.0.1/)
echo "  http://127.0.0.1/ -> $code"
echo -n "  guest heap now: "
sudo awk '$1 ~ /^0[0-9a-f]*-/ && $2 ~ /rw/ && NF==5 {
    split($1,a,"-"); s=strtonum("0x" a[1]); e=strtonum("0x" a[2]);
    if (s < 0x01000000 && (e-s) > 0x10000) t += (e-s) } END {print t+0 " bytes"}' /proc/$PID/maps

echo
echo "=== 6. heap integrity: the walker must still traverse cleanly ==="
# A corrupted chunk header makes heapwalk resync or stop early; the control run
# needed exactly 4 resyncs, so anything much higher is a red flag.
sudo python3 heapwalk.py --pid $PID 2>&1 | grep -E "region|chunks walked" | sed 's/^/  /'

echo
echo "=== 7. guest log tail (crashes, asserts, libjson complaints) ==="
sudo tail -20 /tmp/barra.$LABEL.log 2>/dev/null | sed 's/^/  /' || echo "  (no log)"
