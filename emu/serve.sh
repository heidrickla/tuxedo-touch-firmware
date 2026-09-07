#!/bin/bash
# Start one tree and LEAVE IT RUNNING, so an external client can drive it.
set -u
T="$1"; LABEL="$2"; FORCE="${3:-}"

# REFUSE to start when another instance is live. Do not kill it.
#
# This used to open with an unscoped `pkill -f qemu-arm-static`. On a VM two
# sessions share, that silently kills whatever the other one is running, and the
# damage is invisible: both of us started a rig, each killed the other's, and
# then read the dead instance's log as evidence about our own. Hours of
# "deterministic startup segfault" came out of it. The ABORT below could never
# catch the collision either, because the pkill had already freed the ports it
# checks.
#
# The pattern is split because `pkill -f` also matches the CALLER's own command
# line -- running this over ssh with the literal in the command kills the ssh
# session. That cost a session too.
PAT="qemu-arm-sta""tic /opt/webserver/Barracuda"
LIVE=$(pgrep -f "$PAT" | head -1)
if [ -n "${LIVE:-}" ] && [ "$FORCE" != "--force" ]; then
    echo "ABORT: an emulated Barracuda is already running."
    echo "       pid $LIVE, root $(readlink "/proc/$LIVE/root" 2>/dev/null || echo '?')"
    echo "       Someone may be mid-soak. Stop it deliberately, or pass --force."
    exit 1
fi
[ -n "${LIVE:-}" ] && echo "--force given: stopping pid $LIVE"
pkill -f "$PAT" 2>/dev/null; pkill -f "mqdra""in.py" 2>/dev/null; sleep 2
ss -lnt 2>/dev/null | grep -qE ":(80|443|6280|9443)\b" && { echo "ABORT: ports held"; exit 1; }
for m in dev/mq proc dev/pts; do mountpoint -q "$T/$m" && umount -l "$T/$m"; done
mkdir -p "$T/dev/mq" "$T/dev/pts" "$T/proc" "$T/usr/bin"
# Re-seed the panel configuration on EVERY start, not just when it is missing.
#
# Barracuda REWRITES its configuration as it runs -- CRCdata.json goes from
# 1198 B of real CRCs to 961 B of mostly zeros. The old condition only seeded
# when the directory was EMPTY, so it fired once and never again: run 2 inherited
# run 1's mutated config, run 3 inherited run 2's, and no two runs ever started
# from the same state. Survival times of 30 s, 60 s and 140 s may be three
# different starting configurations rather than three samples of one behaviour.
# Repeatability is the precondition for characterising the crash at all.
#
# Delete-then-copy rather than cp -a over the top, because cp -a MERGES: a run
# that creates a file leaves it there forever, and overwriting only what the
# seed already has leaves that drift in place.
SEED=/work/panel-config
CFG="$T/opt/tuxedo/configuration"
if [ "${KEEP_CONFIG:-}" = "1" ]; then
    echo "config: KEEP_CONFIG=1, leaving the tree's own configuration alone"
elif [ ! -d "$SEED" ] || [ -z "$(ls -A "$SEED" 2>/dev/null)" ]; then
    # Never delete the tree's config when there is nothing to restore from.
    echo "ABORT: seed $SEED is missing or empty; refusing to clear $CFG"
    exit 1
elif [ ! -x "$T/opt/webserver/Barracuda" ]; then
    # Guard the rm below: only ever act on something shaped like an emu tree.
    echo "ABORT: $T does not look like an emu tree (no opt/webserver/Barracuda)"
    exit 1
else
    rm -rf "$CFG"
    mkdir -p "$CFG"
    cp -a "$SEED/." "$CFG/"
    echo "config: re-seeded from $SEED ($(ls -A "$CFG" | wc -l) entries)"
fi
cp /usr/bin/qemu-arm-static "$T/usr/bin/"
mount -t proc proc "$T/proc"; mount -t devpts devpts "$T/dev/pts" 2>/dev/null
mount -t mqueue none "$T/dev/mq"
for n in "ptmx c 5 2" "urandom c 1 9" "random c 1 8" "null c 1 3" "zero c 1 5"; do
    set -- $n; [ -e "$T/dev/$1" ] || mknod "$T/dev/$1" "$2" "$3" "$4"
done
chmod 666 "$T"/dev/{ptmx,urandom,random,null,zero} 2>/dev/null
echo "binary: $(md5sum "$T/opt/webserver/Barracuda" | cut -d' ' -f1)"
# Fingerprint the config we are actually starting from. Barracuda mutates it
# during the run, so this is the only moment it can be recorded, and comparing
# it across runs is what shows whether two survival times are comparable.
echo "config: CRCdata $(md5sum "$CFG/CRCdata.json" 2>/dev/null | cut -d' ' -f1 || echo missing)"
setsid chroot "$T" /usr/bin/qemu-arm-static /opt/webserver/Barracuda </dev/null >/tmp/barra.$LABEL.log 2>&1 &
sleep 6
Q=$(ls "$T/dev/mq" 2>/dev/null | sed 's|^|/|' | tr '\n' ' ')
setsid python3 /tmp/mqdrain.py $Q </dev/null >/tmp/drain.$LABEL.log 2>&1 &
for i in $(seq 1 40); do ss -lnt 2>/dev/null | grep -q ":80\b" && break; sleep 1; done
PID=$(ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -z "${PID:-}" ] && { echo "ABORT: nothing on :80"; exit 1; }
R=$(readlink /proc/$PID/root)
[ "$R" = "$T" ] || { echo "ABORT: :80 served from '$R', not '$T'"; exit 1; }
echo "RUNNING pid=$PID root=$R  listeners=$(ss -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443)\b')/4"
