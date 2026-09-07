#!/bin/sh
# Stage 5 on the live panel: does supervis accept a different binary at
# /opt/webserver/Barracuda?
#
# Everything else about stage 5 was settled off the panel first. The exec chain,
# the pid, comm, the listeners and the loud-failure case were all rehearsed
# under emulation, and supervis's matching was read out of the binary:
# processdir() reads /proc/<pid>/stat, takes the text between the parentheses --
# comm -- and strcmp's it against "Barracuda". comm follows the exec'd basename,
# and the vendor keeps that basename at vendor/Barracuda, so the match holds.
#
# supervis acceptance is the one thing emulation cannot answer, which is why
# this runs here and does nothing else.
#
# IT ALWAYS PUTS THE VENDOR BACK. The revert is in a trap and runs on every
# exit path including a dropped connection, because leaving tuxweb in the boot
# path of an alarm panel is not an acceptable state to fail into. Run under
# setsid so a dead ssh session cannot interrupt it.
#
#   setsid sh /tmp/stage5-panel.sh > /tmp/stage5.log 2>&1 &
PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
W=/opt/webserver
OUT=/tmp/stage5.result

say() { echo; echo "=== $* ==="; }

revert() {
    say "REVERT (always runs)"
    if [ -f "$W/vendor/Barracuda" ]; then
        mv -f "$W/vendor/Barracuda" "$W/Barracuda"
        rmdir "$W/vendor" 2>/dev/null
        echo "  vendor restored at $W/Barracuda"
    else
        echo "  vendor already in place"
    fi
    echo "  md5 now: $(md5sum $W/Barracuda | cut -d' ' -f1)"
    # Make sure something is serving again before walking away, and wait for
    # ALL FOUR listeners rather than the first one. They do not bind at the
    # same instant: a run that waited for :443 and then counted reported
    # "1/4" on a panel that reached 4/4 a moment later, which reads as a
    # failed revert when nothing was wrong.
    kill_barracuda
    i=0
    while [ $i -lt 60 ]; do
        [ "$(netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) ')" = 4 ] && break
        sleep 2; i=$((i+1))
    done
    echo "  listeners after revert: $(netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) ')/4 after $((i*2))s"
    echo "  comm now: $(comm_of $(pid_on_80))"
}
trap revert EXIT INT TERM HUP

# Find it by comm, NOT by the exe symlink.
#
# The first version of this matched `readlink /proc/<pid>/exe` against
# */Barracuda. The moment the file at that path is replaced, the running
# process's exe reads "/opt/webserver/Barracuda (deleted)", the pattern stops
# matching, and the function returns nothing. The whole test then reported
# "supervis did not accept it" while the original vendor process was still
# running happily and had never even been signalled. A null result dressed as
# a finding.
#
# comm is also exactly the predicate supervis uses -- processdir() reads
# /proc/<pid>/stat and strcmp's the text between the parentheses -- so matching
# on it means the test asks the same question supervis does.
comm_of() { [ -n "$1" ] && sed -n 's/^[0-9]* (\([^)]*\)).*/\1/p' /proc/$1/stat 2>/dev/null; }

pid_on_80() {
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        [ "$(comm_of $pid)" = "Barracuda" ] && { echo "$pid"; return; }
    done
}

kill_barracuda() {
    p=$(pid_on_80)
    [ -n "$p" ] && kill "$p" 2>/dev/null
    sleep 3
}

VENDOR_MD5=$(md5sum $W/Barracuda | cut -d' ' -f1)
say "before"
P=$(pid_on_80)
echo "  vendor md5   $VENDOR_MD5"
echo "  pid          $P"
echo "  comm         $(comm_of $P)"
echo "  cmdline      $(tr '\0' ' ' < /proc/$P/cmdline)"
echo "  listeners    $(netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) ')/4"

say "install: vendor aside, tuxweb in its place"
mkdir -p $W/vendor
cp -p $W/Barracuda $W/vendor/Barracuda || exit 1
[ "$(md5sum $W/vendor/Barracuda | cut -d' ' -f1)" = "$VENDOR_MD5" ] || {
    echo "  copy does not match; ABORT before touching the live path"; exit 1; }
cp /tmp/tuxweb-arm $W/Barracuda.new || exit 1
chmod 755 $W/Barracuda.new
mv -f $W/Barracuda.new $W/Barracuda        # rename: never a partial file at that path
echo "  at the vendor path now: $(md5sum $W/Barracuda | cut -d' ' -f1)"

say "make supervis relaunch it"
OLDPID=$(pid_on_80)
echo "  killing pid $OLDPID"
kill_barracuda
# Wait for a DIFFERENT pid to appear, not merely for a port to be open. The
# old process holds all four ports until it dies, so waiting on :443 returns
# instantly and measures nothing -- which is how the first run of this script
# reported "waited 0s" and then read the state of a process that had never
# been replaced.
i=0
while [ $i -lt 60 ]; do
    NEW=$(pid_on_80)
    [ -n "$NEW" ] && [ "$NEW" != "$OLDPID" ] && break
    sleep 2; i=$((i+1))
done
echo "  waited $((i*2))s; pid $OLDPID -> ${NEW:-none}"

say "after: what is supervis looking at?"
P=$(pid_on_80)
if [ -z "$P" ]; then
    echo "  NOTHING is serving -- supervis did not accept it" | tee $OUT
else
    {
    echo "  pid          $P"
    echo "  comm         $(comm_of $P)   <- what supervis strcmp's"
    echo "  cmdline      $(tr '\0' ' ' < /proc/$P/cmdline)"
    echo "  exe          $(readlink /proc/$P/exe)"
    echo "  open fds     $(ls /proc/$P/fd 2>/dev/null | wc -l)"
    echo "  listeners    $(netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) ')/4"
    } | tee $OUT
fi

say "does it still serve?"
for i in 1 2 3; do
    sleep 5
    echo "  t+$((i*5))s pid=$(pid_on_80) listeners=$(netstat -lnt 2>/dev/null | grep -cE ':(80|443|6280|9443) ')/4"
done

say "relaunch count: did supervis fight it?"
echo "  (a stable pid across the samples above means it did not)"
