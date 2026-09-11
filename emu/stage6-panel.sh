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
STAGED_MD5=dbe64a01715d52de2a9d4f4f4cf7f2b4
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
    #
    # Second argument is the number of half-second ticks to wait, because the two
    # kills respawn at very different speeds: SIGTERM takes supervis's reported
    # path and relaunches in ~5 s, SIGKILL posts no message and took ~90 s when it
    # was measured on this panel. A 15 s wait is right for the first and guarantees
    # a spurious "did not relaunch" for the second.
    old="$1"; ticks="${2:-30}"; i=0
    while [ $i -lt "$ticks" ]; do
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
    # LEFT THE PANEL WITH NO WEB SERVER TWICE (2026-09-11) before this was fixed.
    #
    # The process being killed here is usually TUXWEB, not the vendor, and tuxweb
    # does not register Barracuda's sigHandler -- so its death posts no message to
    # supervis and is only noticed by the periodic getProcessPid("Barracuda") check,
    # measured at ~90 s. Waiting 15 s and printing "CHECK THE PANEL" therefore
    # guaranteed a false alarm AND a panel sitting with 0/4 listeners until someone
    # restarted it by hand. A revert that needs manual rescue is not a revert.
    #
    # So: wait long enough for the unreported path, and if supervis still has not
    # acted, start the vendor the same way supervis does rather than reporting
    # failure and stopping. launchBarracuda is system("/opt/webserver/Barracuda &").
    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill "$p" 2>/dev/null; done
    if new=$(wait_new_pid "$old" 300); then
        echo "  supervis relaunched the vendor as pid $new"
    else
        echo "  supervis did not relaunch within 150s -- starting the vendor here"
        setsid "$W/Barracuda" </dev/null >/tmp/revert-launch.log 2>&1 &
        new=$(wait_new_pid "$old" 60) \
            && echo "  started the vendor as pid $new" \
            || echo "  STILL NO BARRACUDA -- CHECK THE PANEL"
    fi
    i=0
    while [ $i -lt 60 ]; do
        n=$(listeners); [ "$n" -ge 4 ] && break
        i=$((i + 1)); sleep 1
    done
    echo "  listeners: $(listeners)/4"
    [ "$(listeners)" -ge 4 ] || echo "  WARNING fewer than 4 listeners -- CHECK THE PANEL"
}

phase0() {
    say "PHASE 0 -- pre-flight, read-only"
    rc=0

    [ -x "$BB" ] || { echo "  busybox MISSING at $BB"; rc=1; }
    [ -f "$STAGED" ] || { echo "  staged binary MISSING at $STAGED"; rc=1; }
    if [ -f "$STAGED" ]; then
        sm=$($BB md5sum $STAGED | cut -d' ' -f1)
        echo "  staged  md5 $sm ($($BB stat -c %s $STAGED 2>/dev/null) bytes)"
        if [ "$sm" != "$STAGED_MD5" ]; then
            echo "  STAGED BINARY IS NOT THE EXPECTED BUILD ($STAGED_MD5)"
            rc=1
        fi
    fi

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
    # 24 relaunches then a HARDWARE RESET. The live counter lives in supervis's
    # own .bss and cannot be read from /proc -- but supervis WRITES each relaunch
    # to a log on mtdblock17, so the count IS readable without touching the
    # process. This block used to say "track it by hand", which sent you into a
    # window that spends three relaunches without knowing how many were left.
    # Do not ptrace supervis to read the counter: it holds /dev/watchdog and
    # kicks it at 1 Hz, so stopping it resets the panel in hardware (TRAPS §6).
    s=$(pids_named supervis | head -1)
    if [ -n "$s" ]; then
        echo "  supervis pid $s, system uptime $($BB awk '{print int($1)}' /proc/uptime)s"
    else
        echo "  supervis NOT RUNNING"
    fi
    SLOG=/opt/tuxedo/configuration/SupervisionLog.txt
    if [ -f "$SLOG" ]; then
        # SCOPE TO THE CURRENT BOOT. The log is on mtdblock17 and survives both
        # reboots and reflashes, so its LAST BARRACUDA_RESTART-N is whatever
        # supervis wrote most recently -- possibly several boots ago. Reading that
        # as the live count reported 6 of 24 on a panel that had rebooted 20
        # minutes earlier and had spent none. Over-reporting is the safe
        # direction, but it is still wrong, and it would talk you out of a window
        # you could afford.
        #
        # supervis writes "######## SYSTEM START ########" at each boot, so reset
        # the count at every such line and keep the last value after it.
        # OFF BY ONE, FIXED 2026-09-11 -- this read ZERO on a panel that had spent
        # four, and printed "0 of 24, 24 left" in the pre-flight immediately
        # before a window. "BARRACUDA_RESTART-" is EIGHTEEN characters, not
        # nineteen: RSTART+19 starts one past a single-digit count and
        # substr(pos, RLENGTH-19) then asks for zero characters, so every
        # one-digit count reported as 0 and "RESTART-12" would have reported 2.
        # Under-reporting is the UNSAFE direction on the counter that guards the
        # 24-relaunch hardware reset. Count the characters before trusting substr.
        used=$($BB awk '
            /SYSTEM START/ { n = 0; next }
            /BARRACUDA_RESTART-/ {
                if (match($0, /BARRACUDA_RESTART-[0-9]+/))
                    n = substr($0, RSTART + 18, RLENGTH - 18) + 0
            }
            END { print n + 0 }' "$SLOG" 2>/dev/null)
        [ -n "$used" ] || used=0
        echo "  relaunches used THIS BOOT: $used of 24, $((24 - used)) left"
        if [ "$used" -gt 20 ]; then
            echo "  TOO FEW LEFT for a window -- reboot first to clear it"
            rc=1
        fi
    else
        echo "  $SLOG MISSING -- cannot read the budget, track it by hand"
    fi
    # Was "THREE", counting one per kill. A SIGTERM restart is charged TWO: the
    # signal posts message 7, and sigHandler's long cleanup frequently faults
    # partway and posts message 8, each advancing the counter (the live log steps
    # RESTART-17 -> RESTART-19 with no 18, and this runbook's own window stepped
    # RESTART-5 -> RESTART-7). Only phase2's SIGKILL costs one. Under-estimating
    # the budget is how a window starts that cannot afford to finish.
    echo "  budget cost: phase1 SIGTERM 2 + phase2 SIGKILL 1 + revert SIGTERM 2 = FIVE"
    echo "  the count is per BOOT and a reboot clears it"

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

    # The deadman is a HARD 900s and cannot be extended: Deadman::reset exists
    # but the cutover never calls it, and TUXWEB_CUTOVER_SECS is read from the
    # environment supervis passes, which a shell cannot set. The clock is
    # absolute from the moment the cutover starts, so leave headroom for the
    # revert rather than pressing keys until it fires.
    if [ "$KEYPRESS_SECS" -gt 600 ]; then
        fail "KEYPRESS_SECS=$KEYPRESS_SECS leaves no headroom in a hard 900s window"
    fi
    echo "  window is a hard 900s; pressing keys for ${KEYPRESS_SECS}s of it"

    say "arming"
    : > "$MARKER" || fail "cannot write $MARKER"
    echo "  marker written -- the NEXT relaunch is the window, and only the next"

    # SIGKILL, NOT SIGTERM -- this is what made the 2026-09-11 window log zero.
    #
    # SIGTERM runs Barracuda's sigHandler, whose cleanup list includes
    # sendUnregisterCommand. That reaches /tuxedo's unregisterclient(), which
    # unconditionally zeroes F7_Mesgs_enabled (0xd2f269) -- and that byte gates the
    # very top of wsltHandleRawDataFromPanel, which returns immediately when it is
    # 0. So a polite kill switches the broadcast firehose OFF a few seconds before
    # the cutover opens the queue, and the window then holds a queue that /tuxedo
    # will never write to. Nothing about sole-reader semantics is being tested at
    # that point.
    #
    # SIGKILL cannot run sigHandler, so no unregister is sent and the flag survives
    # whatever the dying vendor had set. It is also CHEAPER on the budget: a SIGTERM
    # restart is charged 2 (the signal, then the frequent fault partway through that
    # long cleanup -- which is exactly the RESTART-5 -> RESTART-7 step this window
    # left in the log), against 1 for SIGKILL.
    #
    # The cost is latency: ~90 s to respawn, measured, against ~5 s for SIGTERM.
    # Hence the longer wait. See PUSH-STREAM-AUTH.md.
    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill -9 "$p" 2>/dev/null; done
    echo "  SIGKILL sent; supervis respawns on the unreported path, ~90s"
    new=$(wait_new_pid "$old" 300) || fail "supervis did not relaunch within 150s"
    echo "  cutover pid $new"
    [ -e "$MARKER" ] && echo "  WARNING marker still present -- it was NOT consumed, so this is a passthrough"

    # DO NOT ask for Home or Back. home_back_press() zeroes F7_Mesgs_enabled
    # (0xd2f269), and that byte gates the very top of wsltHandleRawDataFromPanel,
    # which returns immediately when it is 0 -- so a Home/Back press switches OFF
    # the firehose this window exists to observe. The 2026-09-11 run asked for
    # "keys" with no such restriction and logged nothing.
    #
    # Keypresses were never the stimulus anyway: /tuxedo posts on panel events, and
    # whether it posts AT ALL depends on F7_Mesgs_enabled, which is set by
    # SERV_CLIENT_REGISTER (500) and NOT by this read-only cutover. Receiving
    # anything depends on the dying vendor having left the flag set -- which is
    # exactly why the kill above is SIGKILL. See WEBSERVER-REPLACEMENT.md, stage 6.
    #
    # MEASURED 2026-09-11: arming and disarming from the touchscreen produced 29
    # replies in 120s (msgType 21 partition status, 18 home partition details). That
    # is the stimulus to use. Home and Back are the two to avoid: home_back_press()
    # zeroes F7_Mesgs_enabled and switches the firehose off mid-window.
    say "WAITING ${KEYPRESS_SECS}s -- arm/disarm is a good stimulus; NOT Home or Back"
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
