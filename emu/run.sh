#!/bin/bash
# Run ONE tree under emulation and prove the answering process is the one we
# started. An earlier version of this script silently measured a stale process:
# its pkill pattern was "qemu-arm-static /opt/webserver/Barracuda", which does
# not match "qemu-arm-static -strace /opt/webserver/Barracuda", so a diagnostic
# run kept the ports and answered every probe. Three results were wrong and
# looked plausible. Hence the assertions below -- they are the point of the
# script, not decoration.
set -u
T="$1"; LABEL="$2"

pkill -f "qemu-arm-static" 2>/dev/null
sleep 2
if ss -lnt 2>/dev/null | grep -qE ":(80|443|6280|9443)\b"; then
    echo "ABORT: ports still held before start:"
    ss -lntp 2>/dev/null | grep -E ":(80|443|6280|9443)\b" | sed 's/^/  /'
    exit 1
fi

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
[ -x "$T/usr/bin/qemu-arm-static" ] || { echo "ABORT: no qemu in $T"; exit 1; }
mount -t proc proc "$T/proc"
mount -t devpts devpts "$T/dev/pts" 2>/dev/null
mount -t mqueue none "$T/dev/mq"
for n in "ptmx c 5 2" "urandom c 1 9" "random c 1 8" "null c 1 3" "zero c 1 5"; do
    set -- $n; [ -e "$T/dev/$1" ] || mknod "$T/dev/$1" "$2" "$3" "$4"
done
chmod 666 "$T"/dev/{ptmx,urandom,random,null,zero} 2>/dev/null

echo "=== [$LABEL] binary: $(md5sum "$T/opt/webserver/Barracuda" | cut -d' ' -f1) ==="
setsid chroot "$T" /usr/bin/qemu-arm-static /opt/webserver/Barracuda </dev/null >/tmp/barra.$LABEL.log 2>&1 &
sleep 6
Q=$(ls "$T/dev/mq" 2>/dev/null | sed 's|^|/|' | tr '\n' ' ')
setsid python3 /tmp/mqdrain.py $Q </dev/null >/tmp/drain.$LABEL.log 2>&1 &
for i in $(seq 1 40); do ss -lnt 2>/dev/null | grep -q ":80\b" && break; sleep 1; done

PID=$(ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
if [ -z "${PID:-}" ]; then echo "ABORT: nothing listening on :80"; strings /tmp/barra.$LABEL.log|tail -6|sed 's/^/  /'; exit 1; fi
ROOT=$(readlink /proc/$PID/root 2>/dev/null)
echo "  serving pid=$PID  root=$ROOT"
if [ "$ROOT" != "$T" ]; then
    echo "  ABORT: the process on :80 is rooted at '$ROOT', not '$T' -- STALE PROCESS"
    exit 1
fi
echo "  VERIFIED: the process answering is the one started from $T"

python3 - "$LABEL" <<'PY'
import socket, sys
lbl = sys.argv[1]
for port, path in ((80, "/"), (80, "/SimpleDebugger.interface/G."),
                   (6280, "/SimpleDebugger.interface/G."), (80, "/home.html")):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10); s.settimeout(15)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        try:
            while len(buf) < 600:
                d = s.recv(600)
                if not d: break
                buf += d
        except socket.timeout: pass
        s.close()
        first = buf.split(b"\r\n")[0].decode("latin-1","replace") if buf else "(nothing)"
        print(f"  [{lbl}] :{port:<5}{path:32} -> {len(buf):>4} B  {first}")
    except Exception as e:
        print(f"  [{lbl}] :{port:<5}{path:32} -> ERROR {type(e).__name__}: {e}")
PY
kill -0 $PID 2>/dev/null && echo "  process: ALIVE after all requests" || echo "  process: DIED during the requests"
pkill -f "qemu-arm-static" 2>/dev/null
pkill -f mqdrain.py 2>/dev/null
sleep 2
