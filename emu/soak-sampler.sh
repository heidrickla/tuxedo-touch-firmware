#!/bin/sh
# Sample the stage-3 shim's footprint on the panel, for the soak §5.11 asks for.
#
# "The longest any test binary has run on this panel is ~50 seconds. No soak, no
# memory-growth-over-hours measurement... Stage 3 should run for a week before
# stage 6 is booked." This is that measurement. It is started early on purpose:
# it costs a week of wall-clock and nothing else, and starting it late would be
# the thing that delays stage 6.
#
# Appends one line per interval. Deliberately dumb and append-only so a crash of
# the thing being watched cannot lose the history that led up to it.
#
#   setsid sh /tmp/soak-sampler.sh > /dev/null 2>&1 &
PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
LOG=/tmp/soak.tsv
INTERVAL=${SOAK_INTERVAL:-300}

comm_of() { sed -n 's/^[0-9]* (\([^)]*\)).*/\1/p' /proc/$1/stat 2>/dev/null; }

# Find the shim by its exe, not by cmdline: the cmdline holds the token-bearing
# argv and matching on it is how a pkill once killed its own ssh session.
shim_pid() {
    for p in /proc/[0-9]*; do
        [ "$(readlink $p/exe 2>/dev/null)" = /tmp/tuxweb ] && { echo "${p#/proc/}"; return; }
    done
}

[ -f "$LOG" ] || printf 'unix\tuptime_s\tpid\trss_kb\tfds\tthreads\tlisten8443\tbarracuda_rss_kb\tmemfree_kb\n' > "$LOG"

while :; do
    P=$(shim_pid)
    if [ -n "$P" ]; then
        RSS=$(sed -n 's/^VmRSS:[ \t]*\([0-9]*\).*/\1/p' /proc/$P/status)
        FDS=$(ls /proc/$P/fd 2>/dev/null | wc -l)
        THR=$(sed -n 's/^Threads:[ \t]*\([0-9]*\)/\1/p' /proc/$P/status)
    else
        P=-; RSS=-; FDS=-; THR=-
    fi
    L=$(netstat -lnt 2>/dev/null | grep -c ":8443 ")
    B=-
    for p in /proc/[0-9]*; do
        [ "$(comm_of ${p#/proc/})" = Barracuda ] && {
            B=$(sed -n 's/^VmRSS:[ \t]*\([0-9]*\).*/\1/p' $p/status); break; }
    done
    MF=$(sed -n 's/^MemFree:[ \t]*\([0-9]*\).*/\1/p' /proc/meminfo)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date +%s)" "$(cut -d. -f1 /proc/uptime)" "$P" "$RSS" "$FDS" "$THR" "$L" "$B" "$MF" \
        >> "$LOG"
    sleep "$INTERVAL"
done
