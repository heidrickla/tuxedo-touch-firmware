#!/bin/sh
# Stage 8d on the live panel: retire the vendor web server for good.
#
# Built on stage6-panel.sh's proven pieces (pids by comm, the per-boot budget
# readout, the two-kill revert). What is different about stage 8:
#
#  * It is PERMANENT, not a window. There is no marker and no deadman. The
#    switch is a conf file on mtd17 (conf.rs): while
#    /opt/tuxedo/configuration/tuxweb-serve.conf exists, every relaunch of
#    /opt/webserver/Barracuda (which is tuxweb) serves; remove it and the next
#    relaunch passes through to the vendor at vendor/Barracuda. tuxweb also
#    bounds a crash loop itself -- past 6 serve launches in one boot it passes
#    through -- so a bad build cannot walk the panel into the 24-relaunch reset.
#  * Serve mode binds 80 (301 only) and 443 (TLS). It does NOT bind 6280 or 9443.
#    So the healthy count is TWO listeners, not four, and 6280/9443 must be GONE.
#  * The push stream and the write API need a token. `token` issues one for HA
#    with the STAGED copy of the binary (the installed one is named Barracuda
#    and would pass its arguments through to the vendor).
#
#   phase0    read-only pre-flight. Changes nothing. Run it days early.
#   phase1    install tuxweb as a passthrough (stage 5 again). Reversible.
#   token     issue the HA token (prints it ONCE). Needs phase1's staged binary.
#   cutover   THE CHANGE. Writes the serve conf, kill -9 the vendor, tuxweb
#             relaunches as the permanent server. Verify from the workstation.
#   revert    remove the conf and put the vendor back. Always available.
#
# Budget: phase1 SIGTERM 2 + cutover SIGKILL 1 + revert SIGTERM 2 = FIVE.
#
#   ssh -i ~/.ssh/tuxedo_ed25519 root@<panel> 'cat > /tmp/tuxweb-stage8' < tuxweb-arm
#   ssh ... 'cat > /tmp/stage8-panel.sh' < emu/stage8-panel.sh
#   ssh ... 'sh /tmp/stage8-panel.sh phase0'
PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
W=/opt/webserver
CFG=/opt/tuxedo/configuration
CONF=$CFG/tuxweb-serve.conf
COUNTER=/tmp/tuxweb-serve-launches
STAGED=/tmp/tuxweb-stage8
STAGED_MD5=8ed6abee71473f8b1d67ba1503805f62
CHAIN=$CFG/tls/chain.pem
KEY=$CFG/tls/server.key
TOKENS=$CFG/tuxweb-tokens.json
BB=/bin/busybox
VENDORMD5=/tmp/stage8-vendor.md5

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

vendor_listeners() { netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) '; }
serve_listeners()  { netstat -lnt 2>/dev/null | grep -cE ':(80|443) '; }
legacy_listeners() { netstat -lnt 2>/dev/null | grep -cE ':(6280|9443) '; }

wait_new_pid() {
    # A port opening proves nothing: the predecessor holds its ports until it
    # dies. Wait for a DIFFERENT pid. Ticks are half-seconds; SIGKILL's respawn
    # has taken 90 s and once SEVEN MINUTES on this panel (stage 7), so callers
    # pass a long count.
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

budget() {
    # 24 relaunches then a HARDWARE RESET. Readable without touching supervis
    # from the log it writes on mtd17; scoped to THIS boot by the SYSTEM START
    # line; "BARRACUDA_RESTART-" is EIGHTEEN characters (stage6-panel.sh).
    SLOG=$CFG/SupervisionLog.txt
    [ -f "$SLOG" ] || { echo "  $SLOG MISSING -- cannot read the budget"; return 1; }
    used=$($BB awk '
        /SYSTEM START/ { n = 0; next }
        /BARRACUDA_RESTART-/ {
            if (match($0, /BARRACUDA_RESTART-[0-9]+/))
                n = substr($0, RSTART + 18, RLENGTH - 18) + 0
        }
        END { print n + 0 }' "$SLOG" 2>/dev/null)
    [ -n "$used" ] || used=0
    echo "  relaunches used THIS BOOT: $used of 24, $((24 - used)) left"
    [ "$used" -gt 19 ] && { echo "  TOO FEW LEFT (need 5) -- reboot first to clear it"; return 1; }
    return 0
}

revert() {
    say "REVERT (always runs)"
    rm -f "$CONF" && echo "  serve conf removed -- the next relaunch passes through"
    rm -f "$COUNTER"
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
        [ "$now" = "$(cat $VENDORMD5)" ] && echo "  md5 MATCHES the binary phase 1 moved aside" \
            || echo "  WARNING md5 differs from what phase 1 recorded -- CHECK THE PANEL"
    fi
    # The process being killed is usually tuxweb, which posts nothing to
    # supervis; its death is noticed only by the periodic pid check (~90 s, once
    # seven minutes). Wait long enough, and if supervis still has not acted,
    # start the vendor the way supervis does (stage6-panel.sh, the lesson that
    # left the panel with no web server twice).
    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill "$p" 2>/dev/null; done
    if new=$(wait_new_pid "$old" 900); then
        echo "  supervis relaunched the vendor as pid $new"
    else
        echo "  supervis did not relaunch within 450s -- starting the vendor here"
        setsid "$W/Barracuda" </dev/null >/tmp/revert-launch.log 2>&1 &
        new=$(wait_new_pid "$old" 60) \
            && echo "  started the vendor as pid $new" \
            || echo "  STILL NO BARRACUDA -- CHECK THE PANEL"
    fi
    i=0
    while [ $i -lt 60 ]; do
        n=$(vendor_listeners); [ "$n" -ge 4 ] && break
        i=$((i + 1)); sleep 1
    done
    echo "  vendor listeners: $(vendor_listeners)/4"
    [ "$(vendor_listeners)" -ge 4 ] || echo "  WARNING fewer than 4 listeners -- CHECK THE PANEL"
}

phase0() {
    say "PHASE 0 -- pre-flight, read-only"
    rc=0
    [ -x "$BB" ] || { echo "  busybox MISSING at $BB"; rc=1; }
    if [ -f "$STAGED" ]; then
        sm=$($BB md5sum $STAGED | cut -d' ' -f1)
        echo "  staged  md5 $sm ($($BB stat -c %s $STAGED 2>/dev/null) bytes)"
        [ "$sm" = "$STAGED_MD5" ] || { echo "  STAGED BINARY IS NOT THE EXPECTED BUILD ($STAGED_MD5)"; rc=1; }
    else
        echo "  staged binary MISSING at $STAGED (tmpfs: a reboot wipes it)"; rc=1
    fi
    v=$($BB md5sum $W/Barracuda 2>/dev/null | cut -d' ' -f1)
    echo "  vendor  md5 $v  (recorded for the revert check)"
    [ -e "$W/vendor/Barracuda" ] && echo "  NOTE $W/vendor/Barracuda exists -- phase1 is installed (fine before cutover)"
    [ -e "$CONF" ] && { echo "  SERVE CONF ALREADY PRESENT at $CONF -- the panel is already cut over, or a run did not revert"; rc=1; }

    say "what serve mode needs"
    [ -f "$CHAIN" ] && [ -f "$KEY" ] && echo "  cert pair present: $CHAIN, $KEY" \
        || { echo "  CERT PAIR MISSING under $CFG/tls/ -- stage 4 must have run"; rc=1; }
    [ -f "$CFG/quickarmstate" ] && echo "  quickarmstate: $(cat $CFG/quickarmstate)" \
        || echo "  quickarmstate MISSING -- status frames would carry quick_arm 0"
    if [ -f "$TOKENS" ]; then
        echo "  token store present ($($BB stat -c %s $TOKENS) bytes)"
    else
        echo "  no token store yet -- run 'token' after phase1 (HA cannot connect without one)"
    fi
    ls -l /dev/mq/Q_ServCmdTrsmtr 2>/dev/null || echo "  /dev/mq/Q_ServCmdTrsmtr NOT VISIBLE"

    say "supervis relaunch budget"
    budget || rc=1
    echo "  budget cost: phase1 SIGTERM 2 + cutover SIGKILL 1 + revert SIGTERM 2 = FIVE"

    say "current state"
    echo "  Barracuda pids: $(pids_named Barracuda | tr '\n' ' ')"
    echo "  listeners: vendor $(vendor_listeners)/4, serve-set $(serve_listeners)/2, legacy $(legacy_listeners)/2"
    echo "  MemFree: $(grep MemFree /proc/meminfo)"

    say "phase 0 result"
    [ $rc -eq 0 ] && echo "  READY -- nothing was changed" || echo "  NOT READY (see above); nothing was changed"
    return $rc
}

phase1() {
    say "PHASE 1 -- install tuxweb as a passthrough (reversible)"
    trap revert EXIT INT TERM
    phase0 || fail "pre-flight said not ready"
    [ -e "$W/vendor/Barracuda" ] && fail "vendor/ already exists; revert first"

    mkdir -p "$W/vendor" || fail "cannot create $W/vendor"
    $BB md5sum "$W/Barracuda" | cut -d' ' -f1 > "$VENDORMD5"
    cp "$W/Barracuda" "$W/vendor/Barracuda" || fail "cannot stage the vendor"
    cp "$STAGED" "$W/Barracuda.new" || fail "cannot stage tuxweb"
    chmod 755 "$W/Barracuda.new" "$W/vendor/Barracuda"
    mv -f "$W/Barracuda.new" "$W/Barracuda" || fail "cannot install tuxweb"
    echo "  installed; md5 now $($BB md5sum $W/Barracuda | cut -d' ' -f1)"

    old=$(pids_named Barracuda | tr '\n' ' ')
    for p in $old; do kill "$p" 2>/dev/null; done
    new=$(wait_new_pid "$old" 60) || fail "supervis did not relaunch within 30s"
    echo "  relaunched as pid $new"
    i=0
    while [ $i -lt 30 ]; do n=$(vendor_listeners); [ "$n" -ge 4 ] && break; i=$((i+1)); sleep 1; done
    [ "$(vendor_listeners)" -ge 4 ] || fail "only $(vendor_listeners)/4 listeners after passthrough"
    echo "  PASSTHROUGH WORKS: $(vendor_listeners)/4 listeners, vendor serving behind tuxweb"
    trap - EXIT INT TERM
    echo "  phase 1 left INSTALLED on purpose. Next: 'token', then 'cutover'."
}

token() {
    say "TOKEN -- issue the Home Assistant token"
    [ -x "$STAGED" ] || fail "no staged binary at $STAGED (it is tmpfs; re-stage it)"
    # The staged copy, not the installed one: installed it is named Barracuda
    # and hands its arguments to the vendor.
    "$STAGED" --issue-token "${1:-home-assistant}" "$TOKENS" || fail "issue failed"
    echo "  configure HA with the token above; it is stored only as a hash in $TOKENS"
}

cutover() {
    say "CUTOVER -- tuxweb becomes the permanent web server"
    trap revert EXIT INT TERM
    [ -f "$W/vendor/Barracuda" ] || fail "phase1 not installed (no $W/vendor/Barracuda)"
    [ -f "$CHAIN" ] && [ -f "$KEY" ] || fail "cert pair missing under $CFG/tls/"
    [ -f "$TOKENS" ] || fail "no token store at $TOKENS -- run 'token' first or HA cannot connect"
    budget || fail "budget"
    # This script cannot see Home Assistant. The ORDER matters. The tuxweb-aware
    # integration (ha-tuxedo-touch 'tuxweb-api') probes GetCapabilities ONCE, at
    # entry setup: against the vendor that is a 404, so it is in stock mode now
    # and stays there until reloaded. Have it installed with the token in the
    # entry BEFORE the kill; AFTER the kill, reload the entry so it re-probes
    # (200) and switches to the token + plain-form contract. Until that reload
    # its stock-mode stream gets a 401 here and it will fail its poll -- that is
    # expected and harmless (tuxweb serves no login page, so no login is spent).
    echo "  ORDER CHECK: HA must already run the tuxweb-aware integration with the"
    echo "  token in the entry. If not, revert now (ctrl-c). After the cutover,"
    echo "  RELOAD the Tuxedo Touch entry in HA so it re-probes into tuxweb mode."
    sleep 5

    # The switch. Written last, seconds before the kill; the launch counter is
    # cleared so this boot's serve launches start from zero.
    {
        printf '%s\n' "# stage 8: tuxweb is the permanent web server. Remove this file and"
        printf '%s\n' "# kill -9 the Barracuda process to fall back to the vendor at $W/vendor/."
        printf '%s\n' "bind=0.0.0.0:443"
        printf '%s\n' "redirect_bind=0.0.0.0:80"
        printf '%s\n' "chain=$CHAIN"
        printf '%s\n' "key=$KEY"
        printf '%s\n' "token_store=$TOKENS"
        printf '%s\n' "quickarm=$CFG/quickarmstate"
        printf '%s\n' "session=4242"
    } > "$CONF" || fail "cannot write $CONF"
    rm -f "$COUNTER"
    echo "  serve conf written:"; sed 's/^/     /' "$CONF"

    # SIGKILL: costs one relaunch, and unlike SIGTERM it does not run the
    # vendor's sigHandler. tuxweb registers itself with a 500 on start, so the
    # broadcast flag's state at this moment does not matter.
    old=$(pids_named Barracuda | tr '\n' ' ')
    echo "  kill -9 $old"
    for p in $old; do kill -9 "$p" 2>/dev/null; done
    new=$(wait_new_pid "$old" 900) || fail "supervis did not relaunch within 450s"
    echo "  relaunched as pid $new (this should be tuxweb in serve mode)"
    i=0
    while [ $i -lt 60 ]; do n=$(serve_listeners); [ "$n" -ge 2 ] && break; i=$((i+1)); sleep 1; done
    echo "  listeners: serve-set $(serve_listeners)/2, legacy $(legacy_listeners) (must be 0)"
    [ "$(serve_listeners)" -ge 2 ] || fail "serve mode did not bind 80 and 443"
    [ "$(legacy_listeners)" -eq 0 ] || fail "6280/9443 are bound -- that is the vendor, not tuxweb"
    echo "  launch counter: $(cat $COUNTER 2>/dev/null) of 6 this boot"
    trap - EXIT INT TERM
    say "CUT OVER. Reload the HA entry, verify from the workstation, leave the panel DISARMED:"
    echo "  HA:  Settings > Devices & services > Tuxedo Touch > Reload  (re-probes -> tuxweb mode)"
    echo "  GET  https://<panel>/system_http_api/API_REV01/GetCapabilities   -> 200 JSON"
    echo "  push https://<panel>/SimpleDebugger.interface/G. with the token    -> frames"
    echo "  arm STAY then DISARM through HA (or the API with ucode)            -> Sucess, state flips"
    echo "  http://<panel>/anything                                            -> 301 https"
    echo "  Revert at any time: sh /tmp/stage8-panel.sh revert"
}

case "${1:-phase0}" in
    phase0)  phase0 ;;
    phase1)  phase1 ;;
    token)   token "${2:-}" ;;
    cutover) cutover ;;
    revert)  revert ;;
    *) echo "usage: $0 phase0|phase1|token [label]|cutover|revert"; exit 2 ;;
esac
