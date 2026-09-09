#!/bin/bash
# Which handlerequest command arms leak? Measure, do not guess.
#
# The dispatch chain at 0x3a6c8.. routes these values; 140 and 141 are already
# fixed. This drives each in turn and reports the chunk growth, so the next fix is
# chosen by size rather than by which function looked suspicious.
#
# Ten session slots, reaped only when the HttpSession dies, and every scenedrive
# invocation logs in once. So this restarts the server between commands -- without
# that, later commands measure an exhausted table and report a clean zero.
#
# Growth here is NOT yet a per-request rate: each measured phase includes one
# login, which allocates. Anything that looks interesting must then be re-measured
# at two request counts, because a per-login constant divided by N looks exactly
# like a small leak.
set -u
N="${1:-200}"
shift || true
CMDS="${*:-129 134 136 137 139 145 146}"
: "${PANEL_USER:?set PANEL_USER}"
TREE=/work/emu/scenes

for c in $CMDS; do
    sudo pkill -9 -f qemu-arm-static 2>/dev/null
    sudo pkill -9 -f mqdrain.py 2>/dev/null
    sleep 5
    sudo bash /work/fwcheck/emu/serve.sh "$TREE" scenes >/dev/null 2>&1
    PID=$(sudo ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    [ -z "${PID:-}" ] && { echo "  cmd=$c  ABORT: nothing on :80"; continue; }

    cd /work/fwcheck
    sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
        "$c" "$N" "sceneid=1" > /tmp/sw.$c.warm 2>&1
    if ! grep -q "body sizes" /tmp/sw.$c.warm; then
        echo "  cmd=$c  driver did not run (see /tmp/sw.$c.warm)"
        continue
    fi
    sizes=$(grep -o "body sizes: .*" /tmp/sw.$c.warm)

    sudo python3 heapwalk.py --pid "$PID" --save /tmp/sw.$c.json >/dev/null 2>&1
    sudo TUXEDO_USER="$PANEL_USER" python3 /tmp/scenedrive.py 127.0.0.1 "$PANEL_USER" \
        "$c" "$N" "sceneid=1" > /tmp/sw.$c.run 2>&1
    top=$(sudo python3 heapwalk.py --pid "$PID" --compare /tmp/sw.$c.json --expect "$N" 2>&1 \
          | grep -E "^ +[0-9]+ +[+-]" | head -3 | tr -s ' ' | tr '\n' ' ')
    printf "  cmd=%-4s %-24s growth: %s\n" "$c" "$sizes" "${top:-none}"
done
