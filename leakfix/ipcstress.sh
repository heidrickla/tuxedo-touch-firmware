#!/bin/bash
# Drive 400 IPC messages at the running emulator and check nothing accumulates.
# Assumes mqdrain is already on the OUTBOUND queue only; pushdriver aborts if not.
set -u
cd /work/fwcheck
PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "guest pid $PID  root $(sudo readlink /proc/$PID/root)"
sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8 | sed 's/^/binary: /'

sudo python3 heapwalk.py --pid "$PID" --save /tmp/st.before.json 2>&1 | tail -2
sudo timeout 900 python3 emu/pushdriver.py --count 300 --msgtype 21 --settle 15 2>&1
sudo timeout 900 python3 emu/pushdriver.py --count 100 --msgtype 22 --settle 15 2>&1
sudo python3 heapwalk.py --pid "$PID" --compare /tmp/st.before.json --expect 400 2>&1 | tail -14

echo "alive: $([ -d /proc/$PID ] && echo yes || echo NO)"
echo "listeners: $(sudo ss -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443)\b')"
curl -s -o /dev/null -w 'GET / -> %{http_code}\n' --max-time 15 http://127.0.0.1/
echo DONE-IPCSTRESS
