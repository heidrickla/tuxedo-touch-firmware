#!/usr/bin/env python3
"""Compare two staged rootfs trees exactly: content, type, mode, owner, links, devs.

`diff -r` is not enough for this job. It cannot compare character devices or fifos
and prints them as differences on both sides, it reports dangling symlinks as
missing files even when both sides dangle identically, and piping it into `head`
throws away its exit status -- so "exit=0" can mean nothing at all.

This walks both trees with os.lstat and compares every attribute that JFFS2 stores,
then reports only genuine mismatches.

Usage: treecmp.py <tree_a> <tree_b>
"""
import hashlib
import os
import stat
import sys


def walk(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            try:
                st = os.lstat(full)
            except OSError as exc:
                out[rel] = ("STAT_FAILED", str(exc))
                continue
            m = st.st_mode
            kind = ("dir" if stat.S_ISDIR(m) else "link" if stat.S_ISLNK(m)
                    else "chr" if stat.S_ISCHR(m) else "blk" if stat.S_ISBLK(m)
                    else "fifo" if stat.S_ISFIFO(m) else "sock" if stat.S_ISSOCK(m)
                    else "file")
            rec = [kind, stat.S_IMODE(m), st.st_uid, st.st_gid]
            if kind == "link":
                rec.append(os.readlink(full))
            elif kind in ("chr", "blk"):
                rec.append((os.major(st.st_rdev), os.minor(st.st_rdev)))
            elif kind == "file":
                h = hashlib.md5()
                with open(full, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                rec.extend([st.st_size, h.hexdigest()])
            out[rel] = tuple(rec)
    return out


def main():
    a_root, b_root = sys.argv[1], sys.argv[2]
    a, b = walk(a_root), walk(b_root)
    print("entries: %d in A, %d in B" % (len(a), len(b)))

    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    diff = sorted(p for p in set(a) & set(b) if a[p] != b[p])

    def show(title, items, fmt):
        print()
        print("%s: %d" % (title, len(items)))
        for p in items[:20]:
            print("    %s" % fmt(p))
        if len(items) > 20:
            print("    ... and %d more" % (len(items) - 20))

    if only_a:
        show("ONLY IN A", only_a, lambda p: "%s  %s" % (p, a[p][0]))
    if only_b:
        show("ONLY IN B", only_b, lambda p: "%s  %s" % (p, b[p][0]))
    if diff:
        show("DIFFERENT", diff,
             lambda p: "%s\n        A=%s\n        B=%s" % (p, a[p], b[p]))

    print()
    if not (only_a or only_b or diff):
        # Say what was actually compared, so a clean result cannot be mistaken
        # for a scan that checked nothing.
        kinds = {}
        for rec in a.values():
            kinds[rec[0]] = kinds.get(rec[0], 0) + 1
        print("IDENTICAL: %s" % ", ".join(
            "%d %s" % (n, k) for k, n in sorted(kinds.items())))
        print("compared content hash, mode, uid, gid, symlink target and device "
              "major/minor for every entry.")
        return 0
    print("MISMATCH: %d only-in-A, %d only-in-B, %d differing"
          % (len(only_a), len(only_b), len(diff)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
