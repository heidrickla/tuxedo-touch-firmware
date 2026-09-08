#!/bin/bash
# Start the emulated Barracuda with qemu execution tracing restricted to one
# address range.
#
# Mirrors emu/serve.sh but adds -d exec,nochain. `nochain` is REQUIRED: without
# it chained translation blocks emit no Trace line, so the log silently shows
# only a fraction of the path and "that code never ran" is an artifact.
#
# Kills EVERY existing instance, not the first one found. A previous attempt
# used `head -1`, left a second instance holding :443, and the request under
# measurement went to the untraced one -- the exact collision emu/serve.sh
# documents.
set -u
TREE="${1:-/work/emu/stock}"
RANGE="${2:-0x1eedc..0x29978}"
LOG="${3:-/trace.log}"

for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in
        */qemu-arm-static*Barracuda*) echo "  killing ${p#/proc/}"; kill -9 "${p#/proc/}" 2>/dev/null ;;
    esac
done
sleep 3

if ss -lnt 2>/dev/null | grep -qE ':(80|443|6280|9443)\b'; then
    echo "ABORT: ports still held after kill"
    ss -lnt | grep -E ':(80|443|6280|9443)\b'
    exit 1
fi

for m in dev/mq proc dev/pts; do
    mountpoint -q "$TREE/$m" || echo "  WARNING: $TREE/$m not mounted"
done

rm -f "$TREE$LOG"
setsid chroot "$TREE" /usr/bin/qemu-arm-static \
    -d exec,nochain -dfilter "$RANGE" -D "$LOG" \
    /opt/webserver/Barracuda </dev/null >/tmp/barra.traced.log 2>&1 &

for _ in $(seq 1 40); do
    sleep 2
    ss -lnt 2>/dev/null | grep -q ':443 ' && break
done

n=$(ss -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443)\b')
inst=$(for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in */qemu-arm-static*Barracuda*) echo x ;; esac
done | wc -l)

echo "  listeners: $n   instances: $inst   trace: $TREE$LOG"
[ "$n" -eq 4 ] || { echo "  FAILED to come up"; tail -5 /tmp/barra.traced.log; exit 1; }
[ "$inst" -eq 1 ] || { echo "  WRONG INSTANCE COUNT -- measurements would be ambiguous"; exit 1; }
echo "  ready"
