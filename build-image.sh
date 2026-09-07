#!/usr/bin/env bash
# Build a firmware image from a base payload plus patches.tsv.
#
#   ./build-image.sh <base.jffs2> <version> [--host user@buildvm]
#
#   ./build-image.sh app2.v11.jffs2 v12 --host claude@203.0.113.40
#
# This is what produced v12. It exists because v12 was first built by hand, and
# a recipe that lives only in a transcript is not a recipe.
#
# The build needs mkfs.jffs2, sumtool and root, so it runs on the build VM
# rather than locally. WSL also works but has more traps (MSYS path rewriting,
# /tmp meaning two different things, and a mount that cannot hold modes,
# symlinks or device nodes) -- see docs/TUXEDO-BUILD.md.
#
# Every stage is verified and the script stops on the first failure. The
# round-trip check in particular is not optional: it is what distinguishes a
# broken toolchain from a broken patch.
set -euo pipefail

BASE="${1:-}"
VER="${2:-}"
HOSTSPEC=""
for i in "$@"; do
    [ "$i" = "--host" ] && HOSTSPEC="next"
    [ "$HOSTSPEC" = "next" ] && [ "$i" != "--host" ] && { HOSTSPEC="$i"; break; }
done
[ -n "$BASE" ] && [ -n "$VER" ] || { echo "usage: $0 <base.jffs2> <version> [--host user@vm]"; exit 2; }
[ -f "$BASE" ] || { echo "base payload not found: $BASE"; exit 2; }
[ -n "$HOSTSPEC" ] && [ "$HOSTSPEC" != "next" ] || { echo "--host is required (the build needs mkfs.jffs2 and root)"; exit 2; }

KEY="${KEY:-$HOME/.ssh/fwbuild_ed25519}"
Q="-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o LogLevel=ERROR"
SSH="ssh -n -i $KEY $Q $HOSTSPEC"
SSHW="ssh -i $KEY $Q $HOSTSPEC"
D="/work/$VER"
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\n=== %s ===\n' "$1"; }

say "stage the base payload"
LMD5=$(md5sum "$BASE" | cut -d' ' -f1)
echo "  local  $BASE  $(stat -c%s "$BASE") bytes  md5 $LMD5"
$SSH "mkdir -p $D"
cat "$BASE" | $SSHW "cat > $D/base.jffs2"
RMD5=$($SSH "md5sum $D/base.jffs2 | cut -d' ' -f1")
[ "$LMD5" = "$RMD5" ] || { echo "  transfer md5 mismatch: $RMD5"; exit 1; }
echo "  remote md5 $RMD5  match"

say "ship the patch table and tooling"
cat "$HERE/apply-patches.py" | $SSHW "cat > $D/apply-patches.py"
cat "$HERE/patches.tsv"      | $SSHW "cat > $D/patches.tsv"
cat "$HERE/tuxedo_hdr.py"    | $SSHW "cat > $D/tuxedo_hdr.py"

say "extract"
$SSH "sudo sh -c 'cd $D && rm -rf root && python3 /build/tuxedo_jffs2_extract.py base.jffs2 root'" | tail -2
# mkfs.jffs2 records uid/gid, so a stray non-root file ships an image nobody can
# boot. This has happened; do not remove the check.
NONROOT=$($SSH "sudo find $D/root ! -user root -o ! -group root | wc -l")
[ "$NONROOT" = "0" ] || { echo "  $NONROOT non-root-owned paths; refusing to build"; exit 1; }
echo "  all paths root:root"

say "apply patches"
$SSH "sudo sh -c 'cd $D && python3 apply-patches.py --apply --root root --table patches.tsv'" | tail -12

say "stamp the build marker"
# DROPBEAR_LINK and CHANGES are carried forward from the base image's marker,
# not regenerated: they describe things this script does not know about (how
# dropbear was linked, and the human-readable change list). Dropping them was a
# real regression the first time this was scripted -- verify-panel.sh prints
# CHANGES, so losing it makes the panel look less patched than it is.
# Append to CHANGES with:  CHANGES_ADD=console-gate,back-home-fix ./build-image.sh ...
CHANGES_ADD="${CHANGES_ADD:-}"
$SSH "sudo sh -c 'cd $D && {
  OLD=root/etc/tuxedo-build
  LINK=\$(sed -n s/^DROPBEAR_LINK=//p \$OLD 2>/dev/null)
  CH=\$(sed -n s/^CHANGES=//p \$OLD 2>/dev/null)
  [ -n \"$CHANGES_ADD\" ] && CH=\"\$CH,$CHANGES_ADD\"
  {
  echo BUILD=$VER
  echo BUILT=\$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo BASE=TUXW_V5.3.21.0_VA
  echo TUXEDO_MD5=\$(md5sum root/tuxedo | cut -d\" \" -f1)
  echo BARRACUDA_MD5=\$(md5sum root/opt/webserver/Barracuda | cut -d\" \" -f1)
  echo SUPERVIS_MD5=\$(md5sum root/supervis | cut -d\" \" -f1)
  echo DROPBEAR_MD5=\$(md5sum root/usr/sbin/dropbear 2>/dev/null | cut -d\" \" -f1)
  echo BUSYBOX_MD5=\$(md5sum root/bin/busybox 2>/dev/null | cut -d\" \" -f1)
  [ -n \"\$LINK\" ] && echo DROPBEAR_LINK=\$LINK
  [ -n \"\$CH\" ] && echo CHANGES=\$CH
  } > /tmp/marker.\$\$ && mv /tmp/marker.\$\$ root/etc/tuxedo-build
} && chmod 644 root/etc/tuxedo-build && chown root:root root/etc/tuxedo-build && cat root/etc/tuxedo-build'" | sed 's/^/  /'

say "mkfs.jffs2 and sumtool"
# Geometry is not negotiable: -e 0x20000 -l -n, no -p, same flags to sumtool.
$SSH "sudo sh -c 'cd $D && mkfs.jffs2 -r root -o $VER.raw -e 0x20000 -l -n && sumtool -i $VER.raw -o $VER.jffs2 -e 0x20000 -l -n && ls -l $VER.jffs2'" | sed 's/^/  /'

say "round trip: rebuild, re-extract, diff"
$SSH "sudo sh -c 'cd $D && rm -rf root_verify && python3 /build/tuxedo_jffs2_extract.py $VER.jffs2 root_verify'" | tail -1
# LC_ALL=C or locale collation invents ~900 phantom differences.
# Lines diff cannot help with are excluded explicitly, not by count:
#   - special files (device nodes, fifos) it cannot compare
#   - dangling symlinks, which are identical in both trees
REAL=$($SSH "sudo sh -c 'cd $D && LC_ALL=C diff -r root root_verify 2>&1 | grep -vE \"is a character special file while|is a fifo while|^diff: .*No such file or directory\" | wc -l'")
[ "$REAL" = "0" ] || {
    echo "  $REAL REAL differences after round trip; refusing to ship"
    $SSH "sudo sh -c 'cd $D && LC_ALL=C diff -r root root_verify 2>&1 | grep -vE \"is a character special file while|is a fifo while|^diff: .*No such file or directory\" | head -20'"
    exit 1
}
echo "  zero real differences"
$SSH "sudo sh -c 'cd $D && python3 apply-patches.py --check --root root_verify --table patches.tsv'" | tail -1

say "wrap in the vendor header"
$SSH "sudo sh -c 'cd $D && python3 tuxedo_hdr.py build $VER.jffs2 app2.hdr --template /work/stock/app2.hdr'" | sed 's/^/  /'
$SSH "sudo sh -c 'cd $D && python3 tuxedo_hdr.py verify app2.hdr'" | sed 's/^/  /'

say "collect"
OUT="${OUT:-$HERE/build/$VER}"
mkdir -p "$OUT"
$SSH "sudo cat $D/app2.hdr" > "$OUT/app2.hdr"
HMD5=$($SSH "sudo md5sum $D/app2.hdr | cut -d' ' -f1")
LMD5=$(md5sum "$OUT/app2.hdr" | cut -d' ' -f1)
[ "$HMD5" = "$LMD5" ] || { echo "  collect md5 mismatch"; exit 1; }
echo "  $OUT/app2.hdr  $(stat -c%s "$OUT/app2.hdr") bytes  md5 $LMD5"

# Point /work/current at this build. deploy.py defaults TREE to it, so the
# default cannot go stale at the next version -- the previous default was a
# path that no longer existed, and the nearest surviving tree held a v9-era
# Barracuda, which would have pushed nine-version-old binaries to the panel.
$SSH "sudo ln -sfn $D/root /work/current"
echo "  /work/current -> $($SSH 'readlink /work/current')"
echo
echo "built $VER. Stage it with:  ./push-image.sh $OUT/app2.hdr"
