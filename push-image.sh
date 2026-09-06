#!/usr/bin/env bash
# Put a firmware image on the panel's SD card over the network, so the card
# never has to move between the PC and the panel again.
#
# The vendor's own OTA works this way: RemoteUpgradeHelper downloads to
# /mnt/sd/<file>, verifies a checksum, and reboots into ProgCV, which flashes
# from the card. We have root and the card is mounted rw, so we can put the
# image there directly and skip the XML/redirector machinery entirely.
#
#   ./push-image.sh <image.hdr>              copy and verify
#   ./push-image.sh <image.hdr> --reboot     copy, verify, then reboot to flash
#
# The image is verified BY MD5 ON THE PANEL after transfer. A corrupt copy is
# never left in place for the flasher to find.
set -uo pipefail

IMG="${1:-}"
HOST="${HOST:-203.0.113.5}"
KEY="${KEY:-$HOME/.ssh/tuxedo_ed25519}"
REBOOT=0
for a in "$@"; do [ "$a" = "--reboot" ] && REBOOT=1; done

[ -f "$IMG" ] || { echo "usage: $0 <image.hdr> [--reboot]"; exit 2; }

Q="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR"
SSH="ssh -n -i $KEY $Q root@$HOST"
SSHW="ssh -i $KEY $Q root@$HOST"

SIZE=$(stat -c%s "$IMG")
echo "image   $IMG"
echo "size    $SIZE bytes"
echo -n "local md5   "
LMD5=$(md5sum "$IMG" | cut -d' ' -f1); echo "$LMD5"

$SSH 'grep -q " /mnt/sd " /proc/mounts' || { echo "SD card is not mounted on the panel"; exit 1; }
FREE=$($SSH "df /mnt/sd | tail -1 | sed 's/  */ /g' | cut -d' ' -f4")
echo "card    $((FREE/1024)) MB free"
[ "$FREE" -lt $((SIZE/1024)) ] && { echo "not enough space on the card"; exit 1; }

echo
echo "transferring..."
START=$(date +%s)
# Write to a temporary name first: a half-copied app2.hdr is exactly what the
# flasher must never see.
cat "$IMG" | $SSHW "cat > /mnt/sd/.app2.new" || { echo "transfer failed"; exit 1; }
END=$(date +%s)
SECS=$((END-START)); [ "$SECS" -lt 1 ] && SECS=1
printf '  %d bytes in %ds, %.1f MB/s\n' "$SIZE" "$SECS" "$(echo "$SIZE $SECS" | awk '{printf "%.1f", $1/$2/1048576}' 2>/dev/null || echo 0)"

echo
echo -n "panel md5   "
RMD5=$($SSH "md5sum /mnt/sd/.app2.new | cut -d' ' -f1")
echo "$RMD5"
if [ "$LMD5" != "$RMD5" ]; then
    echo "MISMATCH. Leaving the existing image untouched and removing the bad copy."
    $SSH "rm -f /mnt/sd/.app2.new"
    exit 1
fi
echo "  match"

$SSH "mv /mnt/sd/.app2.new /mnt/sd/app2.hdr && sync" && echo "  installed as /mnt/sd/app2.hdr"
$SSH "ls -l /mnt/sd/app2.hdr /mnt/sd/ProgCV.hdr 2>&1" | sed 's/^/  /'

if [ "$REBOOT" = "1" ]; then
    echo
    echo "rebooting into the flasher..."
    $SSH "sync; reboot" 2>/dev/null || true
    echo "  panel is rebooting; it will flash from the card and come back."
else
    echo
    echo "not rebooting. The panel will flash this on its next boot."
fi
