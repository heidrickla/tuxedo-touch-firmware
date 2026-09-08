#!/bin/bash
# Measure the scene-helper leaks that /GetSceneList never reaches.
#
# The README recorded the six latent sites as NOT drivable: "no scene endpoint
# is wired into leakprobe.py, so a fix could not be verified". That is no longer
# true. `handlerequest_html076EF7::service` dispatches on r5 and two of its arms
# land straight on them:
#
#     cmd 140  -> editSceneDetails(getParameter("scenedata"))
#     cmd 141  -> deleteExistngScene(atoi(getParameter("sceneid")))
#
# and BOTH open with checkIfSceneExists, which calls scene_getRootNodeOfObjects
# and returns an int without ever freeing the tree. So the leak is reachable on
# a database of placeholder scenes even though the delete itself does nothing:
#
#     34c00  bl scene_getRootNodeOfObjects  -> r6 = parsed tree
#     34c04  subs r6, r0, #0 ; beq 34c50    -> NULL tree, nothing to free
#     ...    loop comparing the id field
#     34c50  mov r0, r5                     <- r5 is an int; the TREE IS DROPPED
#
# ⚠ This is non-destructive on a placeholder database and that is not luck:
# deleteExistngScene returns at 0x34c70 when checkIfSceneExists says no, so
# writeSceneNode is never reached. Check that still holds before running it
# against a panel with real scenes configured.
#
# RSS is page-quantised at 4 kB and cannot resolve a few hundred bytes per
# request, so the verdict comes from the chunk histogram, not from the slope.
set -u
CMD="${1:-141}"
EXTRA="${2:-sceneid=1}"
N="${3:-300}"
# The panel account name is deliberately not in this repo; pass it in.
PANEL_USER="${PANEL_USER:-${TUXEDO_USER:-}}"
CREDS="${CREDS:-/tmp/pw.txt}"
[ -z "$PANEL_USER" ] && { echo "ABORT: set PANEL_USER (the panel web account)"; exit 1; }
cd /work/fwcheck

PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
echo "  guest pid $PID"
echo -n "  binary: "; sudo md5sum "$(sudo readlink /proc/$PID/root)/opt/webserver/Barracuda" | cut -c1-8

echo "=== warm $N, so the startup ramp is not counted as the leak ==="
sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode console \
    --cmd "$CMD" --extra "$EXTRA" --user "$PANEL_USER" --creds "$CREDS" \
    --warmup "$N" --n 10 --every 10 2>&1 \
    | grep -E "measured statuses|GET " | sed 's/^/  /'

echo "=== snapshot before ==="
sudo python3 heapwalk.py --pid "$PID" --save /tmp/so.before.json 2>&1 | tail -2 | sed 's/^/  /'

echo "=== driving $N ==="
sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode console \
    --cmd "$CMD" --extra "$EXTRA" --user "$PANEL_USER" --creds "$CREDS" \
    --warmup 0 --n "$N" --every 100 2>&1 \
    | grep -E "measured statuses|slope|rss" | sed 's/^/  /'

echo "=== snapshot after ==="
sudo python3 heapwalk.py --pid "$PID" --compare /tmp/so.before.json --expect "$N" 2>&1 \
    | tail -20 | sed 's/^/  /'
echo DONE-SCENEOPLEAK
