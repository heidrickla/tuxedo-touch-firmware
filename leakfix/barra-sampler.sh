#!/bin/sh
# Sample Barracuda's memory on the live panel under its NORMAL load
# (Home Assistant polling every ~30 s), so the leak fix is judged in production
# rather than only under emulation.
#
# Emulation measured exactly 0 bytes/request. The panel measured ~61 B/request
# shortly after a restart, which is either the startup working-set ramp or a
# path emulation does not exercise (real IPC, the real device registry, HA
# polling concurrently). Those two are told apart by TIME: a ramp decays, a leak
# stays linear. Hence a long run, not another burst.
#
# Identify the process by who holds :443, never by name: busybox `ps` here
# prints only the applet name, and `pidof` can pick a different instance.
#
# Start with:  setsid sh /tmp/barra-sampler.sh >/dev/null 2>&1 &
LOG=/tmp/barra-leakfix.tsv
INTERVAL=300

[ -f "$LOG" ] || printf 'unix\tuptime_s\tpid\trss_kb\tvmsize_kb\tmaps\tmemfree_kb\tcached_kb\n' > "$LOG"

while :; do
    PID=$(netstat -ltnp 2>/dev/null | grep ':443 ' | grep -oE '[0-9]+/Barracuda' | cut -d/ -f1 | head -1)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        RSS=$(grep '^VmRSS' "/proc/$PID/status" 2>/dev/null | tr -dc '0-9')
        VSZ=$(grep '^VmSize' "/proc/$PID/status" 2>/dev/null | tr -dc '0-9')
        MAPS=$(wc -l < "/proc/$PID/maps" 2>/dev/null | tr -dc '0-9')
    else
        PID=0; RSS=; VSZ=; MAPS=
    fi
    FREE=$(grep '^MemFree' /proc/meminfo | tr -dc '0-9')
    CACHED=$(grep '^Cached' /proc/meminfo | head -1 | tr -dc '0-9')
    UP=$(cut -d. -f1 /proc/uptime)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date +%s)" "$UP" "$PID" "${RSS:--}" "${VSZ:--}" "${MAPS:--}" \
        "$FREE" "$CACHED" >> "$LOG"
    sleep "$INTERVAL"
done
