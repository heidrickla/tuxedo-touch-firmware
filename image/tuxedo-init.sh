# Runs as root at boot from rc.local when TUXEDO-DEV is also on the card.
# Output lands in /mnt/sd/tuxedo-init.log. v9 checks.
echo "--- build ---";   cat /etc/tuxedo-build 2>&1
echo "--- clock ---"
echo "date:  $(date 2>&1)"
echo "rtc0:  $(/sbin/hwclock -r -f /dev/rtc0 2>&1)"
echo "ntp:   NTP_SERVER=$(grep NTP_SERVER /etc/rc.d/rc.conf 2>&1)"
echo "ntpclient: $(ls -l /bin/ntpclient 2>&1)"
echo "--- hosts, entries only (must be 7, none mangled) ---"
grep -vE '^[[:space:]]*#' /etc/hosts 2>&1 | grep -vE '^[[:space:]]*$'
echo "--- hosts.ota-notes present? ---"; ls -l /etc/hosts.ota-notes 2>&1
echo "--- ssh binaries ---"; ls -l /usr/sbin/dropbear /usr/sbin/dropbear.musl 2>&1
echo "--- musl build runs? ---"; /usr/sbin/dropbear.musl -h 2>&1 | head -2
echo "--- listening ---"; netstat -ltn 2>&1 | head -12
echo "--- time log from rc.local ---"; cat /mnt/sd/tuxedo-time.log 2>&1 | tail -12
