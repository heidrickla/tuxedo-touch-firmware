#!/bin/sh
#
# Firmware upload handler for the Tuxedo Touch, run from inetd.
#
# inetd does the listen, accept and fork, and hands the connected socket to
# this script as stdin and stdout. The script speaks just enough HTTP to accept
# a PUT and write the body to the panel's SD card.
#
# INSTALL
#   /usr/sbin/inetd              static armel binary (see TUXEDO-BUILD.md)
#   /usr/sbin/tuxedo-upload.sh   this file, chmod 755
#   /etc/inetd.conf              add the line in inetd.conf.example
#
# USE
#   curl -u tuxedo:<secret> -T app2.hdr http://<panel>:8081/app2.hdr
#
# THIS PUTS A WRITABLE NETWORK SERVICE ON AN ALARM PANEL. Read the security
# notes at the bottom before installing it. The panel's existing web stack
# already carries nine findings in TUXEDO-AUDIT-BUGS.md section (b); this adds
# a tenth surface, deliberately.

SD=/mnt/sd
LOG=/opt/tuxedo/configuration/upload.log

# Shared secret. REPLACE THIS. It is compared in full, not hashed, because
# there is no hashing tool in this userland; it is only as private as the
# filesystem it sits in and the network it travels over.
SECRET="CHANGE-ME"

# Only these names are accepted. A firmware upload has a fixed vocabulary, so
# an allowlist removes path traversal as a category rather than filtering it.
ALLOWED="app1.hdr app2.hdr app3.hdr ProgCV.hdr seconboot.hdr MCU.hex"

say() { printf '%s\r\n' "$*"; }

reply() {
    say "HTTP/1.1 $1"
    say "Content-Type: text/plain"
    say "Connection: close"
    say ""
    say "$2"
    echo "$(date) $1 $2" >> "$LOG" 2>/dev/null
    exit 0
}

# ---- request line -----------------------------------------------------------

read -r METHOD TARGET PROTO || exit 0
NAME=$(echo "$TARGET" | sed 's|^.*/||; s|[?#].*$||')

# ---- headers ----------------------------------------------------------------

LEN=0
AUTH=""
while read -r line; do
    line=$(echo "$line" | tr -d '\r')
    [ -z "$line" ] && break
    case "$line" in
        [Cc]ontent-[Ll]ength:*) LEN=$(echo "$line" | sed 's/^[^:]*: *//') ;;
        [Xx]-[Uu]pload-[Kk]ey:*) AUTH=$(echo "$line" | sed 's/^[^:]*: *//') ;;
    esac
done

# ---- checks, cheapest and least revealing first ------------------------------

[ "$AUTH" = "$SECRET" ] || reply "403 Forbidden" "no"

case "$METHOD" in
    PUT|POST) ;;
    *) reply "405 Method Not Allowed" "PUT only" ;;
esac

ok=0
for a in $ALLOWED; do [ "$NAME" = "$a" ] && ok=1; done
[ "$ok" = "1" ] || reply "400 Bad Request" "name not allowed"

case "$LEN" in
    ''|*[!0-9]*) reply "411 Length Required" "need Content-Length" ;;
esac
[ "$LEN" -gt 0 ] || reply "400 Bad Request" "empty"

mountpoint_ok=$(grep -c " $SD " /proc/mounts 2>/dev/null)
[ "$mountpoint_ok" = "0" ] && reply "503 Service Unavailable" "no SD card"

# Refuse rather than half-fill the card. df reports 1K blocks.
FREE=$(df "$SD" 2>/dev/null | awk 'NR==2 {print $4}')
NEED=$(( LEN / 1024 + 1024 ))
[ -n "$FREE" ] && [ "$FREE" -lt "$NEED" ] && \
    reply "507 Insufficient Storage" "need ${NEED}K, have ${FREE}K"

# ---- write ------------------------------------------------------------------
#
# To a temporary name first, then rename. A connection that dies mid-transfer
# must not leave a truncated file where the flasher will find it: a truncated
# component is the one failure mode the header checksum cannot save you from,
# because the panel would flash whatever is there if the length happened to
# agree.

TMP="$SD/.$NAME.part"
rm -f "$TMP"

dd of="$TMP" bs=1024 count=$(( (LEN + 1023) / 1024 )) 2>/dev/null
GOT=$(wc -c < "$TMP" 2>/dev/null)

# dd rounds up to the block size; trim to the declared length.
if [ "$GOT" -gt "$LEN" ]; then
    dd if="$TMP" of="$TMP.trim" bs=1 count="$LEN" 2>/dev/null
    mv "$TMP.trim" "$TMP"
    GOT=$(wc -c < "$TMP" 2>/dev/null)
fi

if [ "$GOT" != "$LEN" ]; then
    rm -f "$TMP"
    reply "400 Bad Request" "short: got $GOT of $LEN"
fi

mv "$TMP" "$SD/$NAME" || reply "500 Internal Server Error" "rename failed"
sync

reply "200 OK" "wrote $NAME ($GOT bytes)"

# ---- security notes ---------------------------------------------------------
#
# WHAT THIS DOES NOT DO, deliberately, and what you must do around it:
#
# * No TLS. The secret and the firmware both cross the network in clear. Bind
#   it to the LAN only and treat the secret as a speed bump, not a control.
# * The secret is compared as plain text and lives in this file on the panel.
#   Anyone who can read the filesystem can read it.
# * It writes to the SD card only, never to flash. It cannot reprogram the
#   panel by itself; the panel still has to be rebooted with the card present.
#   That is a feature. Keep it that way.
# * The panel wants a BLANK card for its own OTA path. If you use this to stage
#   files, you are using the manual flash route, not the OTA one.
# * There is no rate limit and no lockout. inetd's own `nowait` concurrency
#   limit is the only bound. Set it low.
