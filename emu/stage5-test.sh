#!/bin/bash
# Stage 5 rehearsal: does anything break when tuxweb stands where Barracuda
# stands and does nothing but exec it?
#
# The stage exists to isolate the riskiest unknown -- whether supervis accepts
# a different binary at /opt/webserver/Barracuda -- from every other one. This
# script answers the half that does not need supervis: that the exec chain
# works, keeps the pid, keeps the basename, and serves exactly as before. Only
# after this is clean is it worth doing on the panel, where supervis is the
# remaining variable.
#
# Run as root on the build VM.  bash /work/stage5-test.sh
set -u
T=/work/emu/stage5
SRC=/work/emu/p13

say() { echo; echo "=== $* ==="; }

say "0. build a tree from the P13 one, with nothing mounted under it"
for m in $(mount | grep -o "/work/emu/[^ ]*" | sort -r); do umount -l "$m" 2>/dev/null; done
rm -rf "$T"
cp -a "$SRC" "$T" || exit 1
[ -f "$T/opt/webserver/Barracuda" ] || { echo "no vendor binary in the copy"; exit 1; }

say "1. move the vendor aside and put tuxweb in its place"
mkdir -p "$T/opt/webserver/vendor"
mv "$T/opt/webserver/Barracuda" "$T/opt/webserver/vendor/Barracuda"
cp /tmp/tuxweb-arm "$T/opt/webserver/Barracuda"
chmod 755 "$T/opt/webserver/Barracuda"
echo "  at the vendor's path: $(md5sum "$T/opt/webserver/Barracuda" | cut -d' ' -f1)  (tuxweb)"
echo "  moved aside:          $(md5sum "$T/opt/webserver/vendor/Barracuda" | cut -d' ' -f1)  (vendor)"

say "2. start it through the same path serve.sh uses"
bash /work/emu-serve.sh "$T" stage5 || {
    echo "  FAILED to come up -- stage 5 would not be safe on the panel"; exit 1; }

say "3. what is actually running?"
PID=$(ss -lntp 2>/dev/null | grep ":80 " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
echo "  pid on :80        $PID"
echo "  comm              $(cut -d' ' -f2 /proc/$PID/stat | tr -d '()')"
echo "  cmdline           $(tr '\0' ' ' < /proc/$PID/cmdline)"
echo "  exe               $(readlink /proc/$PID/exe)"
echo "  root              $(readlink /proc/$PID/root)"
echo "  open fds          $(ls /proc/$PID/fd 2>/dev/null | wc -l)"
echo "  listeners         $(ss -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443)\b')/4"

say "4. does it still serve what the vendor served?"
python3 - <<'PY'
import socket
for port, path in ((80, "/"), (80, "/SimpleDebugger.interface/G."), (6280, "/")):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10); s.settimeout(12)
        s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                   % path).encode())
        buf = b""
        try:
            while len(buf) < 400:
                d = s.recv(400)
                if not d: break
                buf += d
        except socket.timeout:
            pass
        s.close()
        first = buf.split(b"\r\n")[0].decode("latin-1", "replace") if buf else "(nothing)"
        print("  :%-5d %-30s -> %4d B  %s" % (port, path, len(buf), first))
    except Exception as e:
        print("  :%-5d %-30s -> ERROR %s" % (port, path, e))
PY

say "5. the failure case: vendor missing must be loud, not a silent loop"
# No `|| true` here. It would be harmless on this line and fatal on the next,
# where $? has to be the exit status of the command itself -- which is the
# check ci/checks.sh flagged this script for, correctly.
"$T/opt/webserver/Barracuda" 2>&1 | head -2
TUXWEB_EXEC=/nonexistent "$T/opt/webserver/Barracuda" >/dev/null 2>/tmp/s5err
rc=$?
echo "  exit $rc: $(head -1 /tmp/s5err)"
[ "$rc" = 2 ] && echo "  refuses rather than exec'ing something wrong" \
              || echo "  WRONG exit code -- expected 2"

say "cleanup"
pkill -f qemu-arm-static 2>/dev/null; pkill -f mqdrain.py 2>/dev/null; sleep 2
for m in $(mount | grep -o "/work/emu/stage5[^ ]*" | sort -r); do umount -l "$m"; done
ss -lnt 2>/dev/null | grep -qE ":(80|443|6280|9443)\b" \
    && echo "  ports STILL held" || echo "  all ports closed"
