#!/bin/bash
# Name the allocation behind /GetSceneList's remaining ~491 B/request.
#
# Freeing both json_write strings changed nothing, and the histogram says the
# residual is a dozen small chunks per request - 40, 32, 16, 64, 56 bytes - which
# is a JSON tree, not serialised strings. chunkdiff dumps the CONTENTS of chunks
# that appeared between two snapshots, and their contents name the allocation.
# That is what identified the IPC registry buffers and the voice vocabulary when
# tracing could not.
set -u
cd /work/fwcheck
PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  guest pid $PID"
echo -n "  binary: "; sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8

echo "=== warm ==="
sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode api \
    --endpoint /GetSceneList --plain "operation=get" --warmup 300 --n 5 --every 5 2>&1 \
    | grep -E "measured statuses" | sed 's/^/  /'

for size in 40 64 56; do
    echo "=== $size-byte chunks: snapshot, drive 20, dump what is new ==="
    sudo python3 chunkdiff.py --pid "$PID" --sizes "$size" --save /tmp/cd.$size.json 2>&1 | tail -1 | sed 's/^/  /'
    sudo timeout 300 python3 leakprobe.py --host 127.0.0.1 --mode api \
        --endpoint /GetSceneList --plain "operation=get" --warmup 0 --n 20 --every 20 2>&1 \
        | grep -E "measured statuses" | sed 's/^/  /'
    sudo python3 chunkdiff.py --pid "$PID" --sizes "$size" --compare /tmp/cd.$size.json --dump 5 2>&1 \
        | tail -28 | sed 's/^/  /'
done
echo DONE-SCENEDUMP
