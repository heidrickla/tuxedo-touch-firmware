#!/bin/bash
# Start one tree and LEAVE IT RUNNING, so an external client can drive it.
set -u
T="$1"; LABEL="$2"
pkill -f "qemu-arm-static" 2>/dev/null; pkill -f mqdrain.py 2>/dev/null; sleep 2
ss -lnt 2>/dev/null | grep -qE ":(80|443|6280|9443)\b" && { echo "ABORT: ports held"; exit 1; }
for m in dev/mq proc dev/pts; do mountpoint -q "$T/$m" && umount -l "$T/$m"; done
mkdir -p "$T/dev/mq" "$T/dev/pts" "$T/proc" "$T/usr/bin"
# Seed the panel configuration if this tree has none. Without it Barracuda
# starts but its init fails and it serves nothing. /work/panel-config is the
# canonical copy; emu/fetch-config.sh refreshes it from the panel.
if [ -d /work/panel-config ] && [ -z "$(ls -A "$T/opt/tuxedo/configuration" 2>/dev/null)" ]; then
    mkdir -p "$T/opt/tuxedo"
    cp -a /work/panel-config/. "$T/opt/tuxedo/configuration/"
fi
cp /usr/bin/qemu-arm-static "$T/usr/bin/"
mount -t proc proc "$T/proc"; mount -t devpts devpts "$T/dev/pts" 2>/dev/null
mount -t mqueue none "$T/dev/mq"
for n in "ptmx c 5 2" "urandom c 1 9" "random c 1 8" "null c 1 3" "zero c 1 5"; do
    set -- $n; [ -e "$T/dev/$1" ] || mknod "$T/dev/$1" "$2" "$3" "$4"
done
chmod 666 "$T"/dev/{ptmx,urandom,random,null,zero} 2>/dev/null
echo "binary: $(md5sum "$T/opt/webserver/Barracuda" | cut -d' ' -f1)"
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
