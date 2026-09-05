#!/usr/bin/env python3
"""Extract a JFFS2 image to a real Linux tree, preserving mode/uid/gid,
symlinks, device nodes and hard links. Must run as root on a Unix filesystem."""
import os, sys, stat, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tuxedo_jffs2 import scan, build_tree, file_bytes

def main(img_path, dest):
    img = open(img_path, "rb").read()
    dirents, inodes, stats = scan(img)
    print("node stats:", {k: v for k, v in stats.items() if v})
    children = build_tree(dirents, inodes)

    # winning metadata per inode = highest-version node
    meta = {ino: max(f, key=lambda x: x["ver"]) for ino, f in inodes.items()}
    made = {}                      # ino -> first path, for hard links
    counts = dict(dir=0, file=0, link=0, dev=0, fifo=0, hardlink=0, bytes=0)
    deferred = []                  # (path, mode, uid, gid) applied after children

    def walk(ino, path):
        for name, cino, dtype in sorted(children.get(ino, [])):
            p = os.path.join(path, name)
            m = meta.get(cino)
            if m is None:
                print("  !! no inode node for", p); continue
            mode, uid, gid = m["mode"], m["uid"], m["gid"]
            if cino in made and not stat.S_ISDIR(mode):
                os.link(made[cino], p); counts["hardlink"] += 1; continue
            if stat.S_ISDIR(mode):
                os.makedirs(p, exist_ok=True); counts["dir"] += 1
                deferred.append((p, mode, uid, gid))
                walk(cino, p)
            elif stat.S_ISLNK(mode):
                os.symlink(file_bytes(inodes[cino]).decode("latin-1"), p)
                os.lchown(p, uid, gid); counts["link"] += 1
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                # Device nodes carry rdev in the data node while isize == 0,
                # so file_bytes() (which truncates to isize) returns nothing.
                from tuxedo_jffs2 import decompress
                fr = max(inodes[cino], key=lambda f: f["ver"])
                d = decompress(fr["ctype"], fr["data"], fr["dsize"])
                if len(d) == 2:
                    v = struct.unpack("<H", d)[0]; major, minor = v >> 8, v & 0xFF
                elif len(d) >= 4:
                    v = struct.unpack("<I", d[:4])[0]
                    major, minor = (v >> 8) & 0xFFF, (v & 0xFF) | ((v >> 12) & 0xFFF00)
                else:
                    major = minor = 0
                os.mknod(p, mode, os.makedev(major, minor))
                os.chown(p, uid, gid); os.chmod(p, stat.S_IMODE(mode))
                counts["dev"] += 1
            elif stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                os.mknod(p, mode); os.chown(p, uid, gid); counts["fifo"] += 1
            else:
                b = file_bytes(inodes[cino])
                with open(p, "wb") as fh: fh.write(b)
                os.chown(p, uid, gid); os.chmod(p, stat.S_IMODE(mode))
                counts["file"] += 1; counts["bytes"] += len(b)
                made[cino] = p
            if not stat.S_ISDIR(mode): made.setdefault(cino, p)

    os.makedirs(dest, exist_ok=True)
    walk(1, dest)
    for p, mode, uid, gid in reversed(deferred):
        os.chown(p, uid, gid); os.chmod(p, stat.S_IMODE(mode))
    rm = meta.get(1)
    if rm: os.chown(dest, rm["uid"], rm["gid"]); os.chmod(dest, stat.S_IMODE(rm["mode"]))
    print("extracted:", counts)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
