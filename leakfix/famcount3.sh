#!/bin/bash
# Per-call registry cost of several endpoints, measured serially on one rig.
#
# Extends famcount.sh with the control it was missing. A single family member
# measured against /GetSceneList shows a difference, but not whether the
# difference is the FAMILY or just this pair of endpoints. So two non-family
# endpoints run first: if they agree with each other and the family members sit
# above both, the delta is attributable to the handler shape rather than to
# /GetSceneList being unusual.
#
# Mutating handlers run LAST. AddIPURL and UpdateIPURL write the registered-device
# list, which is what getRegisteredDevNodes walks, so running them earlier would
# change the input to every later arm. They are safe here only because emu/serve.sh
# re-seeds /opt/tuxedo/configuration from /work/panel-config on every start -- this
# is a copy, never the panel.
#
# Arms are serial by necessity: one process, one global registry. Driving two
# endpoints concurrently would attribute each one's allocations to the other.
set -u
: "${PANEL_USER:?set PANEL_USER}"
N="${1:-200}"
PID=$(pgrep -x qemu-arm-static | head -1)
[ -n "$PID" ] || { echo "no emulator running -- start it with emu/serve.sh"; exit 1; }
echo "emulator pid $PID"
printf "\n%-14s %-46s %10s %10s\n" ARM ENDPOINT STRINGS NODES

count() { sudo python3 /tmp/jsoncount.py --pid "$PID" | grep -E "^outstanding:"; }

arm() {
    local label="$1" ep="$2" params="$3"
    cd /work/fwcheck || exit 1
    # warm 200 first: the post-restart heap ramp is large enough to swamp the delta
    sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode api \
        --endpoint "$ep" --plain "$params" --user "$PANEL_USER" --creds /tmp/pw.txt \
        --warmup 200 --n 1 --every 1000 >/dev/null 2>&1
    local before after st
    before=$(count)
    st=$(sudo timeout 900 python3 leakprobe.py --host 127.0.0.1 --mode api \
        --endpoint "$ep" --plain "$params" --user "$PANEL_USER" --creds /tmp/pw.txt \
        --warmup 0 --n "$N" --every 1000 2>&1 | grep -oE "measured statuses: .*")
    after=$(count)
    BEFORE="$before" AFTER="$after" N="$N" LABEL="$label" EP="$ep" ST="$st" \
        python3 /tmp/famrow.py
}

arm CONTROL-A /GetSceneList "operation=get"
arm CONTROL-B /GetSecurityStatus "operation=get"
arm SetSecurityArm /SetSecurityArm "operation=set&arming=STAY&pID=1"
arm ArmWithCode /AdvancedSecurity/ArmWithCode "operation=set&arming=STAY&pID=1&ucode=1234"

echo "Read the two CONTROL rows first. If they disagree, the baseline is not stable"
arm SetDoorLock /SetDoorLock "operation=set&nodeID=1&cntrl=1"

echo
echo "Controls first: if they disagree the baseline moved and no family row is readable."
