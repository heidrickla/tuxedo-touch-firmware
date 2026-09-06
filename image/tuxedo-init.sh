# Runs as root at boot from rc.local when TUXEDO-DEV is on the card.
# Output lands in /mnt/sd/tuxedo-init.log. v10 checks.
echo "--- build ---";  cat /etc/tuxedo-build 2>&1
echo "--- clock ---";  echo "date: $(date 2>&1)"
echo "--- syslog: did the vendor service start our binaries? ---"
ls -l /sbin/syslogd /sbin/klogd 2>&1
ps 2>&1 | grep -E "[s]yslogd|[k]logd"
echo "messages file: $(ls -l /var/log/messages 2>&1)"
echo "--- first kernel lines captured ---"
head -5 /var/log/messages 2>&1
echo "--- does dropbear log to syslog now (no -E needed)? ---"
grep -i dropbear /var/log/messages 2>&1 | head -3
echo "--- busybox tools ---"
ls -l /bin/busybox 2>&1
echo "usr/local/bin: $(ls /usr/local/bin 2>/dev/null | tr '\n' ' ')"
echo "awk works: $(echo 'a b c' | /usr/local/bin/awk '{print $2}' 2>&1)"
echo "--- NAND bad blocks (baseline was 9) ---"
grep -c "Bad block at" /var/log/messages 2>&1
echo "--- listening ---"; netstat -ltn 2>&1 | grep LISTEN
echo "--- hosts entries (must be 7, none mangled) ---"
grep -vE '^[[:space:]]*#' /etc/hosts 2>&1 | grep -vE '^[[:space:]]*$'
