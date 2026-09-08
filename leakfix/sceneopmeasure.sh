#!/bin/bash
# Measure the scene-helper leak now that the endpoint actually dispatches.
#
# cmd=141 -> deleteExistngScene(atoi(sceneid)), which opens with
# checkIfSceneExists -> scene_getRootNodeOfObjects and returns an int, dropping
# the parsed tree. That happens on EVERY call, whether or not the scene exists,
# so a database of placeholder scenes still exercises it -- and deleteExistngScene
# returns at 0x34c70 before writeSceneNode, so nothing is written.
#
# The verdict comes from the chunk histogram, not the RSS slope: RSS is
# page-quantised at 4 kB and cannot resolve a few hundred bytes per request.
#
# ⚠ ONE login for the whole run. scenedrive.py enforces that and aborts if the
# session has no slot, because ten slots exist and a driver that re-logs
# exhausts them, after which every reply is an empty 200 that reads as no leak.
set -u
CMD="${1:-141}"
N="${2:-300}"
EXTRA="${3:-sceneid=1}"
: "${PANEL_USER:?set PANEL_USER to the panel web account}"
cd /work/fwcheck

PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  guest pid $PID"
echo -n "  binary: "; sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8

echo "=== warm $N, so the startup ramp is not counted as the leak ==="
sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
    "$CMD" "$N" "$EXTRA" 2>&1 | tee /tmp/sd.last | sed 's/^/    /'
# A run that drove nothing produces an EMPTY delta table, which reads exactly like
# a fixed leak. scenedrive aborts when the session has no slot; surface that
# rather than letting the wrapper's greps swallow it.
grep -q "body sizes" /tmp/sd.last || {
    echo "ABORT: the driver did not run -- see above. Ten session slots exist and"
    echo "they are reaped only when the HttpSession dies, so restart the server"
    echo "before re-measuring. An empty delta table is NOT a clean result."
    exit 1
}

echo "=== snapshot before ==="
sudo python3 heapwalk.py --pid "$PID" --save /tmp/som.before.json 2>&1 | tail -2 | sed 's/^/    /'

echo "=== driving $N under measurement ==="
sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
    "$CMD" "$N" "$EXTRA" 2>&1 | tee /tmp/sd.last | sed 's/^/    /'
# A run that drove nothing produces an EMPTY delta table, which reads exactly like
# a fixed leak. scenedrive aborts when the session has no slot; surface that
# rather than letting the wrapper's greps swallow it.
grep -q "body sizes" /tmp/sd.last || {
    echo "ABORT: the driver did not run -- see above. Ten session slots exist and"
    echo "they are reaped only when the HttpSession dies, so restart the server"
    echo "before re-measuring. An empty delta table is NOT a clean result."
    exit 1
}

echo "=== snapshot after ==="
sudo python3 heapwalk.py --pid "$PID" --compare /tmp/som.before.json --expect "$N" 2>&1 \
    | tail -18 | sed 's/^/    /'
echo DONE-SCENEOPMEASURE
