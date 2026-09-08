#!/bin/bash
# Name the allocation behind cmd=141's ~107 B/request, by its CONTENTS.
#
# LEAK 23 proved the leak is NOT checkIfSceneExists's tree: that tree is always
# NULL because hascenedb.json is empty, and the fix changed nothing. The growing
# sizes are 40 and 32 bytes at about 1.2 each per request, which is a JSON tree
# rather than a serialised string. chunkdiff dumps the CONTENTS of chunks that
# appeared between two snapshots, and the contents name the allocation -- that is
# how the IPC registry buffers and the voice vocabulary were identified when
# tracing could not.
#
# ⚠ ONE login for the whole run, enforced by scenedrive.py: ten session slots
# exist and re-logging exhausts them, after which every reply is an empty 200 that
# reads as no leak.
set -u
N="${1:-200}"
CMD="${2:-141}"
EXTRA="${3:-sceneid=1}"
: "${PANEL_USER:?set PANEL_USER to the panel web account}"
cd /work/fwcheck

PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  guest pid $PID  binary $(sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8)"

echo "=== warm ==="
sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
    "$CMD" "$N" "$EXTRA" 2>&1 | grep -E "statuses|body sizes" | sed 's/^/    /'

for size in 40 32 24; do
    echo "=== ${size}-byte chunks: snapshot, drive $N, dump what is new ==="
    sudo python3 chunkdiff.py --pid "$PID" --sizes "$size" --save /tmp/cd141.$size.json 2>&1 \
        | tail -1 | sed 's/^/    /'
    sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
        "$CMD" "$N" "$EXTRA" 2>&1 | grep -E "body sizes" | sed 's/^/    /'
    sudo python3 chunkdiff.py --pid "$PID" --sizes "$size" \
        --compare /tmp/cd141.$size.json --dump 6 2>&1 | tail -24 | sed 's/^/    /'
done
echo DONE-SCENEOPDUMP
