#!/bin/sh
# Stage 6 on the live panel, in four phases, so the booked window contains only
# the part that actually needs Lewis standing at the touchscreen.
#
# §5.1 is the claim the whole project rests on: that a process other than
# Barracuda, holding /Q_ServCmdTrsmtr as sole reader, receives tuxedo's
# replies. Nothing else can answer it -- the single-reader rule (B4/B5) means
# it cannot be tested alongside a running Barracuda.
#
# HOW THE WINDOW IS TAKEN, because it is not obvious from the outside:
# tuxweb lives at /opt/webserver/Barracuda and the vendor moves to
# /opt/webserver/vendor/Barracuda. Launched by supervis under the vendor's
# name, tuxweb normally just execs the vendor -- passthrough, panel unchanged.
# Writing the marker at /opt/tuxedo/configuration/tuxweb-cutover.arm turns
# EXACTLY ONE relaunch into the cutover: main() consumes the marker before
# anything else, so a crash mid-window is relaunched as a passthrough rather
# than as a second window. That is what stands between a failed cutover and the
# 24-relaunch watchdog reset (§1.2).
#
#   phase0  read-only pre-flight. Changes nothing. Run it days early.
#   phase1  install tuxweb as a passthrough. Reversible, panel keeps working.
#           This is stage 5 again, and it is where a bad binary is caught.
#   phase2  THE WINDOW. Needs Lewis at the panel. Arms the marker, kills
#           Barracuda, and the deadman hands the panel back by itself.
#   revert  always available, and phase1/phase2 trap onto it.
#
# THE SOAK: phases 1-3 kill Barracuda, and the stage-3 shim proxies to
# 127.0.0.1:80, so they end the soak. phase0 does not touch it.
#
#   ssh root@panel 'sh /tmp/stage6-panel.sh phase0'
#   setsid sh /tmp/stage6-panel.sh phase2 > /tmp/stage6.log 2>&1 &
PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
W=/opt/webserver
MARKER=/opt/tuxedo/configuration/tuxweb-cutover.arm
STAGED=/tmp/tuxweb-stage6
LOG=/tmp/cutover.tsv
BB=/bin/busybox
VENDORMD5=/tmp/stage6-vendor.md5
KEYPRESS_SECS=${KEYPRESS_SECS:-120}

say() { echo; echo "=== $* ==="; }
fail() { echo "FAIL: $*"; exit 1; }

# comm, not exe: once the binary at that path is replaced, /proc/N/exe reads
# "(deleted)" and a path match finds nothing (TRAPS §4). Never match cmdline --
# that kills the ssh session running this script.
pids_named() {
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "$p" = "$$" ] && continue
        n=$(sed -n 's/^[0-9]* (\([^)]*\)).*/\1/p' "$d/stat" 2>/dev/null)
        [ "$n" = "$1" ] && echo "$p"
    done
}

# The four Barracuda ports are 80, 443, 6280 and 9443. NOT 8080 -- a pattern
# with 8080 in it counts 3 on a perfectly healthy panel, which reads as a
# missing listener. stage5-panel.sh already had this right.
listeners() { netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) '; }

wait_new_pid() {
    # A port opening proves nothing: the predecessor holds all four until it
    # dies, so the wait returns instantly. Wait for a DIFFERENT pid.
    old="$1"; i=0
    while [ $i -lt 30 ]; do
        now=$(pids_named Barracuda | tr '\n' ' ')
        for p in $now; do
            case " $old " in *" $p "*) ;; *) echo "$p"; return 0 ;; esac
        done
        i=$((i + 1))
        usleep 500000 2>/dev/null || sleep 1
    done
    return 1
}

revert() {
    say "REVERT (always runs)"
    rm -f "$MARKER" && echo "  marker cleared"
    if [ -f "$W/vendor/Barracuda" ]; then
        mv -f "$W/vendor/Barracuda" "$W/Barracuda"
        rmdir "$W/vendor" 2>/dev/null
        echo "  vendor restored at $W/Barracuda"
    else
        echo "  vendor already in place"
    fi
    now=$($BB md5sum $W/Barracuda | cut -d' ' -f1)
    echo "  md5 now: $now"
    if [ -f "$VENDORMD5" ]; then
        if [ "$now" = "$(cat $VENDORMD5)" ]; then
            echo "  md5 MATCHES the binary phase 1 moved aside"
        else
            echo "  WARNING md5 differs from what phase 1 recorded -- CHECK THE PANEL"
        fi
    fi
    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill "$p" 2>/dev/null; done
    new=$(wait_new_pid "$old") \
        && echo "  supervis relaunched the vendor as pid $new" \
        || echo "  WARNING no new pid within 15s -- CHECK THE PANEL"
    i=0
    while [ $i -lt 30 ]; do
        n=$(listeners); [ "$n" -ge 4 ] && break
        i=$((i + 1)); sleep 1
    done
    echo "  listeners: $(listeners)/4"
}

phase0() {
    say "PHASE 0 -- pre-flight, read-only"
    rc=0

    [ -x "$BB" ] || { echo "  busybox MISSING at $BB"; rc=1; }
    [ -f "$STAGED" ] || { echo "  staged binary MISSING at $STAGED"; rc=1; }
    [ -f "$STAGED" ] && echo "  staged  md5 $($BB md5sum $STAGED | cut -d' ' -f1) $($BB stat -c %s $STAGED 2>/dev/null) bytes"

    # Do NOT compare against the stock md5: this panel runs patched v13, so
    # "not stock" is the correct state and flagging it trains you to ignore the
    # check. What matters is that the binary moved aside is the one that comes
    # back, so record it here and verify it in revert.
    v=$($BB md5sum $W/Barracuda 2>/dev/null | cut -d' ' -f1)
    echo "  vendor  md5 $v  (recorded for the revert check)" 
    [ -e "$W/vendor/Barracuda" ] && { echo "  $W/vendor/Barracuda ALREADY EXISTS -- a previous run did not revert"; rc=1; }

    [ -e "$MARKER" ] && { echo "  MARKER ALREADY PRESENT at $MARKER -- the next relaunch would take a window"; rc=1; }

    # /opt/tuxedo/configuration is mtdblock17 and survives a reflash, so a
    # marker left behind is not cleaned up by reimaging. It matters that it is
    # absent now and written only seconds before the kill.
    echo "  marker absent, and its directory is $(mount | grep -c 'on /opt/tuxedo/configuration') mount(s) deep"

    say "queue"
    ls -l /dev/mq/Q_ServCmdTrsmtr 2>/dev/null || echo "  /dev/mq/Q_ServCmdTrsmtr NOT VISIBLE (queues mount at /dev/mq, not /dev/mqueue)"

    say "supervis relaunch budget"
    # 24 relaunches then a HARDWARE RESET, and the counter is never zeroed.
    # It lives in supervis's own memory, not in /proc, so it CANNOT be read
    # here and has to be tracked by hand across sessions. Saying that plainly
    # is better than printing a number that looks like the budget and is not.
    s=$(pids_named supervis | head -1)
    if [ -n "$s" ]; then
        echo "  supervis pid $s, system uptime $($BB awk '{print int($1)}' /proc/uptime)s"
    else
        echo "  supervis NOT RUNNING"
    fi
    echo "  budget is NOT readable from /proc -- track it by hand"
    echo "  a full phase1 + phase2 + revert spends THREE of the 24"

    say "current state"
    echo "  Barracuda pids: $(pids_named Barracuda | tr '\n' ' ')"
    echo "  listeners: $(listeners)/4"
    # A logged 556-byte reply is ~1.2 kB of hex, so free/1200 is the cap on
    # messages the window can record before /tmp fills.
    free=$(df /tmp 2>/dev/null | tail -1 | $BB awk '{print $4}')
    echo "  free /tmp: ${free} kB -- room for about $((free * 1024 / 1200)) logged messages"
    echo "  MemFree: $(grep MemFree /proc/meminfo)"

    say "phase 0 result"
    [ $rc -eq 0 ] && echo "  READY -- nothing was changed" || echo "  NOT READY (see above); nothing was changed"
    return $rc
}

phase1() {
    say "PHASE 1 -- install tuxweb as a passthrough (reversible)"
    trap revert EXIT INT TERM
    phase0 || fail "pre-flight said not ready"

    mkdir -p "$W/vendor" || fail "cannot create $W/vendor"
    # Copy, then rename. Writing a running executable gives ETXTBSY.
    $BB md5sum "$W/Barracuda" | cut -d' ' -f1 > "$VENDORMD5"
    cp "$W/Barracuda" "$W/vendor/Barracuda" || fail "cannot stage the vendor"
    cp "$STAGED" "$W/Barracuda.new" || fail "cannot stage tuxweb"
    chmod 755 "$W/Barracuda.new" "$W/vendor/Barracuda"
    mv -f "$W/Barracuda.new" "$W/Barracuda" || fail "cannot install tuxweb"
    echo "  installed; md5 now $($BB md5sum $W/Barracuda | cut -d' ' -f1)"

    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill "$p" 2>/dev/null; done
    new=$(wait_new_pid "$old") || fail "supervis did not relaunch within 15s"
    echo "  relaunched as pid $new"
    i=0
    while [ $i -lt 30 ]; do n=$(listeners); [ "$n" -ge 4 ] && break; i=$((i+1)); sleep 1; done
    [ "$(listeners)" -ge 4 ] || fail "only $(listeners)/4 listeners after passthrough"
    echo "  PASSTHROUGH WORKS: $(listeners)/4 listeners, vendor serving behind tuxweb"
    trap - EXIT INT TERM
    echo "  phase 1 left INSTALLED on purpose. Run 'revert' to undo."
}

phase2() {
    say "PHASE 2 -- THE WINDOW (§5.1)"
    trap revert EXIT INT TERM
    [ -f "$W/vendor/Barracuda" ] || fail "phase 1 has not run: no $W/vendor/Barracuda"
    [ -e "$MARKER" ] && fail "marker already present"
    rm -f "$LOG"

    say "arming"
    : > "$MARKER" || fail "cannot write $MARKER"
    echo "  marker written -- the NEXT relaunch is the window, and only the next"

    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill "$p" 2>/dev/null; done
    new=$(wait_new_pid "$old") || fail "supervis did not relaunch within 15s"
    echo "  cutover pid $new"
    [ -e "$MARKER" ] && echo "  WARNING marker still present -- it was NOT consumed, so this is a passthrough"

    say "PRESS KEYS ON THE TOUCHSCREEN NOW -- ${KEYPRESS_SECS}s"
    i=0
    while [ $i -lt "$KEYPRESS_SECS" ]; do
        sleep 10; i=$((i + 10))
        echo "  ${i}s  log lines: $( [ -f $LOG ] && wc -l < $LOG || echo 0 )"
    done

    say "result"
    if [ -s "$LOG" ]; then
        echo "  $(wc -l < $LOG) messages received as SOLE READER -- §5.1 ANSWERED YES"
        # Column 3 is OK/SHORT; the type is column 5 as msgType=N. Cutting the
        # wrong column prints "OK" once and reads like a result.
        echo "  msgTypes seen: $(cut -f5 "$LOG" 2>/dev/null | sed -n 's/^msgType=//p' | sort -un | tr '\n' ' ')"
        echo "  short/unparsed: $(cut -f3 "$LOG" 2>/dev/null | grep -c SHORT)"
    else
        echo "  NO MESSAGES. §5.1 answered NO, or the cutover never started."
        echo "  Check /tmp/stage6.log for 'deadman armed' and 'SOLE READER'."
    fi
    # The deadman hands the panel back by itself; revert makes it deterministic.
}

case "${1:-phase0}" in
    phase0) phase0 ;;
    phase1) phase1 ;;
    phase2) phase2 ;;
    revert) revert ;;
    *) echo "usage: $0 [phase0|phase1|phase2|revert]"; exit 2 ;;
esac
