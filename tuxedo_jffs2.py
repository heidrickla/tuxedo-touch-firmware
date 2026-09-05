"""Minimal JFFS2 reader/verifier: parse nodes, replay the log, extract the tree."""
import struct, zlib, os, sys, stat

MAGIC = 0x1985
DIRENT, INODE, CLEANMARKER, PADDING, SUMMARY, XATTR, XREF = (
    0xe001, 0xe002, 0x2003, 0x2004, 0x2006, 0xe008, 0xe009)
NAMES = {DIRENT:"DIRENT", INODE:"INODE", CLEANMARKER:"CLEANMARKER",
         PADDING:"PADDING", SUMMARY:"SUMMARY", XATTR:"XATTR", XREF:"XREF"}
COMPR = {0:"none",1:"zero",2:"rtime",3:"rubinmips",4:"copy",5:"dynrubin",
         6:"zlib",7:"lzo"}

_TBL = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _TBL.append(_c)

def crc(b, seed=0):
    """JFFS2 uses Linux crc32_le with seed 0 and NO final inversion.

    This is NOT zlib.crc32 / the standard CRC-32: zlib pre-inverts and
    post-inverts. Getting this wrong makes every node in a valid image
    look corrupt, which is exactly what happened on the first attempt.
    """
    c = seed
    for ch in b:
        c = _TBL[(c ^ ch) & 0xFF] ^ (c >> 8)
    return c & 0xFFFFFFFF

def unpack_unknown(data, out_len):
    """JFFS2 'rtime' decompressor (the only non-zlib one the vendor image uses)."""
    positions = [0]*256
    out = bytearray(); ip = 0
    while len(out) < out_len:
        value = data[ip]; ip += 1
        out.append(value)
        repeat = data[ip]; ip += 1
        backoffs = positions[value]
        positions[value] = len(out)
        if repeat:
            if backoffs + repeat >= len(out):
                while repeat:
                    out.append(out[backoffs]); backoffs += 1; repeat -= 1
            else:
                out.extend(out[backoffs:backoffs+repeat])
    return bytes(out[:out_len])

def decompress(ctype, data, dlen):
    if ctype == 0: return data[:dlen]
    if ctype == 1: return b"\0"*dlen
    if ctype == 6: return zlib.decompress(data)[:dlen]
    if ctype == 2: return unpack_unknown(data, dlen)
    raise ValueError(f"unsupported compression {ctype} ({COMPR.get(ctype,'?')})")

class Node: __slots__=("off","ntype","totlen","hdr_ok","body")

def scan(img, verbose=False):
    """Walk the image, returning (nodes, stats). Tolerates 0xFF padding."""
    n = len(img); off = 0
    dirents = []; inodes = {}
    stats = {k:0 for k in list(NAMES.values())+["bad_hdr_crc","bad_node_crc","skipped"]}
    while off + 12 <= n:
        magic, ntype, totlen, hcrc = struct.unpack_from("<HHII", img, off)
        if magic != MAGIC:
            off += 4          # erase-block padding / erased space
            stats["skipped"] += 4
            continue
        if crc(img[off:off+8]) != hcrc:
            stats["bad_hdr_crc"] += 1; off += 4; continue
        if totlen < 12 or off + totlen > n:
            stats["bad_hdr_crc"] += 1; off += 4; continue
        stats[NAMES.get(ntype, "skipped")] = stats.get(NAMES.get(ntype,"skipped"),0)+1
        if ntype == DIRENT:
            (pino, ver, ino, mctime, nsize, dtype, _u, node_crc, name_crc) = \
                struct.unpack_from("<IIIIBBHII", img, off+12)
            name = img[off+40:off+40+nsize]
            if crc(name) != name_crc: stats["bad_node_crc"] += 1
            else: dirents.append((pino, ver, ino, dtype, name.decode("latin-1"), mctime))
        elif ntype == INODE:
            (ino, ver, mode, uid, gid, isize, atime, mtime, ctime, offs,
             csize, dsize, ctype, cflags, _u, data_crc, node_crc) = \
                struct.unpack_from("<IIIHHIIIIIIIBBHII", img, off+12)
            payload = img[off+68:off+68+csize]
            if csize and crc(payload) != data_crc:
                stats["bad_node_crc"] += 1
            else:
                inodes.setdefault(ino, []).append(
                    dict(ver=ver, mode=mode, uid=uid, gid=gid, isize=isize,
                         off=offs, csize=csize, dsize=dsize, ctype=ctype,
                         data=payload, mtime=mtime))
        off += (totlen + 3) & ~3
    return dirents, inodes, stats

def build_tree(dirents, inodes):
    """Replay: highest version wins per (pino, name); ino 0 = deletion."""
    latest = {}
    for pino, ver, ino, dtype, name, mctime in dirents:
        k = (pino, name)
        if k not in latest or ver > latest[k][0]:
            latest[k] = (ver, ino, dtype)
    children = {}
    for (pino, name), (ver, ino, dtype) in latest.items():
        if ino == 0: continue          # unlink
        children.setdefault(pino, []).append((name, ino, dtype))
    return children

def file_bytes(frags):
    """Assemble one inode's data from its fragments, highest version wins."""
    frags = sorted(frags, key=lambda f: f["ver"])
    size = 0; buf = bytearray()
    for f in frags:
        size = f["isize"]
        if f["dsize"] == 0: continue
        raw = decompress(f["ctype"], f["data"], f["dsize"])
        end = f["off"] + len(raw)
        if end > len(buf): buf.extend(b"\0"*(end-len(buf)))
        buf[f["off"]:end] = raw
    if len(buf) < size: buf.extend(b"\0"*(size-len(buf)))
    return bytes(buf[:size])

def extract(img, dest, root_ino=1):
    dirents, inodes, stats = scan(img)
    children = build_tree(dirents, inodes)
    written = {"files":0,"dirs":0,"links":0,"bytes":0}
    def walk(ino, path):
        for name, cino, dtype in sorted(children.get(ino, [])):
            p = os.path.join(path, name)
            frags = inodes.get(cino)
            if frags is None: continue
            mode = max(frags, key=lambda f: f["ver"])["mode"]
            if stat.S_ISDIR(mode) or dtype == 4:
                os.makedirs(p, exist_ok=True); written["dirs"] += 1; walk(cino, p)
            elif stat.S_ISLNK(mode) or dtype == 10:
                tgt = file_bytes(frags)
                with open(p + ".symlink", "wb") as fh: fh.write(tgt)
                written["links"] += 1
            else:
                b = file_bytes(frags)
                with open(p, "wb") as fh: fh.write(b)
                written["files"] += 1; written["bytes"] += len(b)
    os.makedirs(dest, exist_ok=True)
    walk(root_ino, dest)
    return stats, written

if __name__ == "__main__":
    img = open(sys.argv[1], "rb").read()
    if len(sys.argv) > 2:
        st, w = extract(img, sys.argv[2])
        print("stats:", {k:v for k,v in st.items() if v})
        print("written:", w)
    else:
        d, i, st = scan(img)
        print("stats:", {k:v for k,v in st.items() if v})
        print(f"dirents={len(d)} inodes={len(i)}")
