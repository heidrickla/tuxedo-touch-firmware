#!/bin/bash
# Does the shim actually renew an expired panel session?
#
# The renewal path in shim.rs has never been exercised. It fires only when the
# upstream GET answers 401, and on the live panel there was no way to make that
# happen without waiting out a session or restarting Barracuda. Under emulation
# restarting Barracuda is free, and P13's 401 gate runs in EhDir_service before
# any IPC, so the emulated server rejects a stale cookie exactly as the panel
# does. That is the whole behaviour under test.
#
# Run as root on the build VM.  bash /work/renewal-test.sh
set -u
T=/work/emu/p13
LOG=/tmp/renewal-shim.log
TOK=renewal-test-token

say() { echo; echo "=== $* ==="; }

kill_shim() {
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        [ "$(readlink "$p/exe" 2>/dev/null)" = /tmp/tuxweb-host ] && kill "$pid" 2>/dev/null
    done
    sleep 1
}

say "1. start the emulated P13 panel"
bash /work/emu-serve.sh "$T" p13 || exit 1

say "2. start the shim against it"
kill_shim
rm -f "$LOG"
TUXWEB_TOKEN="$TOK" setsid /tmp/tuxweb-host --shim-login 127.0.0.1:80 lewis /tmp/pw \
    0.0.0.0:8081 </dev/null >"$LOG" 2>&1 &
sleep 10
sed 's/^/  /' "$LOG"
grep -q "session acquired" "$LOG" || { echo "  ABORT: the shim never logged in"; exit 1; }
COOKIE_BEFORE=$(grep -c "logging in again" "$LOG")

say "3. a client is served before anything is broken"
python3 /tmp/probe.py "$TOK"

say "4. restart Barracuda, which drops every session it issued"
pkill -f qemu-arm-static; pkill -f mqdrain.py; sleep 3
echo "  barracuda down; the shim's cookie is now worthless"
bash /work/emu-serve.sh "$T" p13b || exit 1

say "5. wait for the shim to notice, reconnect and renew"
for i in $(seq 1 15); do
    grep -q "logging in again" "$LOG" && break
    sleep 5
done
grep -E "shim:|tuxweb:" "$LOG" | sed 's/^/  /'

say "6. is a client served again, on the renewed session?"
python3 /tmp/probe.py "$TOK" 8

say "verdict"
COOKIE_AFTER=$(grep -c "logging in again" "$LOG")
if [ "$COOKIE_AFTER" -gt "$COOKIE_BEFORE" ]; then
    echo "  RENEWAL FIRED ($COOKIE_AFTER time(s))"
else
    echo "  renewal did NOT fire -- read $LOG"
fi
echo "  re-login failures: $(grep -c 're-login failed' "$LOG")"

say "cleanup"
kill_shim
pkill -f qemu-arm-static 2>/dev/null
pkill -f mqdrain.py 2>/dev/null
sleep 2
if ss -lnt 2>/dev/null | grep -qE ":(80|443|6280|9443|8081)\b"; then
    ss -lnt | grep -E ":(80|443|6280|9443|8081)\b" | sed 's/^/  STILL OPEN: /'
else
    echo "  all test ports closed"
fi
