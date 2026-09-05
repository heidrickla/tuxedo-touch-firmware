#!/usr/bin/env python3
"""
Carve embedded filesystems out of header-wrapped firmware images, and work out
what the wrapper header is protecting.

Written against Honeywell Tuxedo Touch update images (`app1.hdr`, `app2.hdr`,
`app3.hdr`, `ProgCV.hdr`, `seconboot.hdr` -- each a JFFS2 filesystem behind a
short binary header), but nothing here is Tuxedo-specific: it scans for the
magic rather than trusting a hardcoded offset.

Two jobs, and the second is the one that matters if you intend to *modify*
anything:

  1. Find the payload and carve it out.           --> you can read the firmware
  2. Identify which header fields are integrity   --> you can repack it
     checks over that payload.

Job 2 is the gate. Any field that turns out to be a CRC or a length has to be
recomputed after an edit, or the bootloader rejects the image. This tool brute
-forces every 4-byte slot in the header against a battery of candidate
functions of the payload and tells you which ones matched. A field it cannot
explain is a field you do not yet understand -- treat that as a stop sign, not
a rounding error.

Pure stdlib. Extraction of the carved JFFS2 needs an external tool; this script
will use `jefferson` if it is on PATH, and otherwise just tells you what to run.

    python fw_extract.py firmware/                 # scan a directory
    python fw_extract.py app1.hdr --carve out/     # carve payload to out/
    python fw_extract.py app1.hdr --analyse-header # checksum hunt only

NOTE ON SCOPE: this reads files you already have. It does not download
firmware, and it does not write to any device. Flashing a modified image to a
wall-mounted alarm panel is a separate, riskier decision -- see README.
"""

import argparse
import binascii
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import zlib

# ---------------------------------------------------------------------------
# Filesystem / payload signatures.
#
# (name, magic bytes, note). Order matters only for reporting.
# ---------------------------------------------------------------------------

SIGNATURES = [
    ("JFFS2 (little-endian)", b"\x85\x19", "node magic 0x1985, LE"),
    ("JFFS2 (big-endian)", b"\x19\x85", "node magic 0x1985, BE"),
    ("SquashFS (little-endian)", b"hsqs", "squashfs 4.x LE"),
    ("SquashFS (big-endian)", b"sqsh", "squashfs 4.x BE"),
    ("CramFS", b"\x45\x3d\xcd\x28", "cramfs superblock"),
    ("UBI", b"UBI#", "UBI erase-counter header"),
    ("UBIFS", b"\x31\x18\x10\x06", "UBIFS node magic"),
    ("gzip", b"\x1f\x8b\x08", "gzip stream"),
    ("LZMA (alone)", b"\x5d\x00\x00", "lzma_alone header"),
    ("XZ", b"\xfd7zXZ\x00", "xz stream"),
    ("U-Boot legacy image", b"\x27\x05\x19\x56", "uImage header"),
    ("ARM Linux zImage", b"\x18\x28\x6f\x01", "zImage magic"),
    ("ELF", b"\x7fELF", "raw executable, not a filesystem"),
]

# JFFS2 node types, used to sanity-check that a 0x1985 hit is a real node
# header and not two coincidental bytes.
JFFS2_NODETYPES = {
    0xE001: "DIRENT",
    0xE002: "INODE",
    0x2003: "CLEANMARKER",
    0x2004: "PADDING",
    0xE006: "XATTR",
    0xE007: "XREF",
}

# A header this long is almost certainly not a header. Guards against a file
# whose payload magic appears only deep inside compressed data.
MAX_PLAUSIBLE_HEADER = 4096


def find_signatures(data, limit=MAX_PLAUSIBLE_HEADER):
    """Every signature hit within the first `limit` bytes, offset-sorted."""
    hits = []
    window = data[: limit + 8]
    for name, magic, note in SIGNATURES:
        start = 0
        while True:
            idx = window.find(magic, start)
            if idx == -1:
                break
            hits.append((idx, name, magic, note))
            start = idx + 1
    hits.sort(key=lambda h: (h[0], h[1]))
    return hits


def jffs2_plausible(data, offset, endian):
    """
    Does `offset` look like a genuine JFFS2 node header rather than a chance
    0x1985? Checks the node type against known values and the total length
    against the remaining file size.
    """
    fmt = "<HHI" if endian == "little" else ">HHI"
    if offset + 8 > len(data):
        return False, "truncated"
    _magic, nodetype, totlen = struct.unpack_from(fmt, data, offset)
    if nodetype not in JFFS2_NODETYPES:
        return False, f"unknown nodetype 0x{nodetype:04x}"
    remaining = len(data) - offset
    if totlen == 0 or totlen > remaining:
        return False, f"totlen {totlen} exceeds remaining {remaining}"
    return True, f"{JFFS2_NODETYPES[nodetype]}, totlen={totlen}"


# ---------------------------------------------------------------------------
# Header analysis: which 4-byte slots are functions of the payload?
# ---------------------------------------------------------------------------


def crc32_jffs2(payload):
    """
    The CRC variant mkfs.jffs2 uses: zlib crc32 seeded with 0, not 0xffffffff.
    Differs from the plain zlib default and catches images the standard CRC
    misses.
    """
    return (zlib.crc32(payload, 0) ^ 0) & 0xFFFFFFFF


def candidate_values(payload):
    """
    Functions a firmware header plausibly stores about its payload. Each is a
    32-bit value we can look for verbatim in the header.
    """
    byte_sum = sum(payload) & 0xFFFFFFFF
    word_sum = 0
    # 32-bit word sum, LE, over the payload truncated to a word boundary.
    for i in range(0, len(payload) - 3, 4):
        word_sum = (word_sum + struct.unpack_from("<I", payload, i)[0]) & 0xFFFFFFFF

    md5 = hashlib.md5(payload).digest()
    sha1 = hashlib.sha1(payload).digest()

    return {
        "payload length": len(payload) & 0xFFFFFFFF,
        "zlib crc32 (init 0xffffffff)": binascii.crc32(payload) & 0xFFFFFFFF,
        "crc32 (init 0, jffs2 style)": crc32_jffs2(payload),
        "crc32 inverted": (~binascii.crc32(payload)) & 0xFFFFFFFF,
        "sum of bytes": byte_sum,
        "sum of bytes (16-bit)": byte_sum & 0xFFFF,
        "sum of 32-bit words": word_sum,
        "two's complement of byte sum": (-byte_sum) & 0xFFFFFFFF,
        "md5[0:4] LE": struct.unpack("<I", md5[:4])[0],
        "md5[0:4] BE": struct.unpack(">I", md5[:4])[0],
        "sha1[0:4] LE": struct.unpack("<I", sha1[:4])[0],
        "sha1[0:4] BE": struct.unpack(">I", sha1[:4])[0],
    }


def analyse_header(header, payload):
    """
    Try to explain every 4-byte slot in `header` as a function of `payload`.
    Returns (explained, unexplained) where explained maps offset -> list of
    descriptions.
    """
    wanted = candidate_values(payload)
    explained = {}

    for off in range(0, len(header) - 3):
        le = struct.unpack_from("<I", header, off)[0]
        be = struct.unpack_from(">I", header, off)[0]
        for label, value in wanted.items():
            if value == 0:
                continue  # zero matches too much padding to be informative
            if le == value:
                explained.setdefault(off, []).append(f"{label} (LE)")
            if be == value and be != le:
                explained.setdefault(off, []).append(f"{label} (BE)")

    # Report only word-aligned slots as "unexplained"; unaligned matches above
    # are kept because they occasionally reveal a packed struct.
    unexplained = [
        off
        for off in range(0, len(header) - 3, 4)
        if off not in explained
        and header[off : off + 4] not in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff")
    ]
    return explained, unexplained


def hexdump(data, base=0, width=16, limit=None):
    out = []
    view = data if limit is None else data[:limit]
    for off in range(0, len(view), width):
        chunk = view[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {base + off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(out)


def printable_strings(data, minlen=4):
    """ASCII runs, for spotting version stamps and build tags in a header."""
    found, current = [], bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= minlen:
                found.append(current.decode("ascii"))
            current = bytearray()
    if len(current) >= minlen:
        found.append(current.decode("ascii"))
    return found


# ---------------------------------------------------------------------------
# Per-file driver
# ---------------------------------------------------------------------------


def examine(path, carve_dir=None, header_analysis=True, verbose=False):
    with open(path, "rb") as handle:
        data = handle.read()

    print(f"\n{'=' * 72}")
    print(f"{path}  ({len(data):,} bytes)")
    print("=" * 72)

    if not data:
        print("  empty file, skipping")
        return None

    hits = find_signatures(data)
    if not hits:
        print("  No known filesystem signature in the first "
              f"{MAX_PLAUSIBLE_HEADER} bytes.")
        print("  Leading bytes:")
        print(hexdump(data, limit=64))
        return None

    # Prefer the first hit that survives a structural sanity check.
    chosen = None
    for offset, name, magic, note in hits:
        if name.startswith("JFFS2"):
            endian = "little" if "little" in name else "big"
            ok, detail = jffs2_plausible(data, offset, endian)
            status = "plausible" if ok else f"rejected: {detail}"
            if verbose or ok:
                print(f"  0x{offset:04x}  {name:<26} {status}"
                      + (f" -- {detail}" if ok else ""))
            if ok and chosen is None:
                chosen = (offset, name, endian)
        else:
            print(f"  0x{offset:04x}  {name:<26} {note}")
            if chosen is None and offset <= MAX_PLAUSIBLE_HEADER:
                chosen = (offset, name, None)

    if chosen is None:
        print("  Signatures found but none passed a structural check.")
        print("  This usually means the payload is compressed or encrypted.")
        return None

    offset, name, _endian = chosen
    header, payload = data[:offset], data[offset:]

    print(f"\n  Payload: {name} at offset {offset} "
          f"({len(payload):,} bytes)")
    print(f"  Header:  {offset} bytes")

    if offset == 0:
        print("  No wrapper header -- the file is the filesystem.")
    elif header_analysis:
        print(f"\n  --- header bytes ---")
        print(hexdump(header))

        strings = printable_strings(header)
        if strings:
            print(f"\n  --- ASCII in header ---")
            for s in strings:
                print(f"    {s!r}")

        explained, unexplained = analyse_header(header, payload)
        print(f"\n  --- header fields explained by the payload ---")
        if explained:
            for off in sorted(explained):
                le = struct.unpack_from("<I", header, off)[0]
                print(f"    +0x{off:03x}  0x{le:08x}  "
                      + ", ".join(explained[off]))
        else:
            print("    none matched")

        print(f"\n  --- unexplained word-aligned, non-padding slots ---")
        if unexplained:
            for off in unexplained:
                le = struct.unpack_from("<I", header, off)[0]
                print(f"    +0x{off:03x}  0x{le:08x}")
            print("\n    Any of these could be a checksum you have not "
                  "identified,")
            print("    a version/model gate, or a signature. Repacking "
                  "without")
            print("    understanding them will produce an image the device "
                  "rejects.")
        else:
            print("    none -- every non-padding slot is accounted for")

    if carve_dir:
        os.makedirs(carve_dir, exist_ok=True)
        base = os.path.basename(path)
        stem = base[:-4] if base.lower().endswith(".hdr") else base
        out_path = os.path.join(carve_dir, stem + ".payload.bin")
        with open(out_path, "wb") as handle:
            handle.write(payload)
        print(f"\n  Carved payload -> {out_path}")

        if offset:
            hdr_path = os.path.join(carve_dir, stem + ".header.bin")
            with open(hdr_path, "wb") as handle:
                handle.write(header)
            print(f"  Carved header  -> {hdr_path}")

        if name.startswith("JFFS2"):
            suggest_extraction(out_path)

    return {"path": path, "offset": offset, "payload_type": name,
            "payload_size": len(payload)}


def suggest_extraction(payload_path):
    """Run jefferson if available; otherwise print what to run."""
    jefferson = shutil.which("jefferson")
    if jefferson:
        dest = payload_path + ".extracted"
        print(f"  jefferson found, extracting -> {dest}")
        try:
            result = subprocess.run(
                [jefferson, payload_path, "-d", dest],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                print("  extraction OK")
            else:
                print(f"  jefferson exited {result.returncode}")
                if result.stderr.strip():
                    print(f"    {result.stderr.strip().splitlines()[-1]}")
        except subprocess.TimeoutExpired:
            print("  jefferson timed out after 300s")
        except OSError as exc:
            print(f"  could not run jefferson: {exc}")
    else:
        print("  To extract the JFFS2 contents:")
        print("    pip install jefferson")
        print(f"    jefferson {os.path.basename(payload_path)} -d extracted/")
        print("  On Linux you can also mount it directly:")
        print("    sudo modprobe mtdram total_size=32768 && sudo modprobe "
              "mtdblock")
        print(f"    sudo dd if={os.path.basename(payload_path)} of=/dev/mtdblock0")
        print("    sudo mount -t jffs2 /dev/mtdblock0 /mnt")


def main():
    parser = argparse.ArgumentParser(
        description="Carve embedded filesystems out of firmware images and "
                    "identify the wrapper header's integrity fields.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("NOTE ON SCOPE")[0].strip().split("\n\n")[-1],
    )
    parser.add_argument("target", help="firmware file, or a directory of them")
    parser.add_argument("--carve", metavar="DIR",
                        help="write carved headers and payloads to DIR")
    parser.add_argument("--analyse-header", action="store_true",
                        help="header checksum hunt only, no carving")
    parser.add_argument("--no-header-analysis", action="store_true",
                        help="skip the checksum hunt (faster on big images)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show rejected signature hits too")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        parser.error(f"no such file or directory: {args.target}")

    if os.path.isdir(args.target):
        names = sorted(os.listdir(args.target))
        targets = [
            os.path.join(args.target, n)
            for n in names
            if os.path.isfile(os.path.join(args.target, n))
        ]
        if not targets:
            parser.error(f"no files in {args.target}")
    else:
        targets = [args.target]

    results = []
    for path in targets:
        try:
            found = examine(
                path,
                carve_dir=args.carve,
                header_analysis=not args.no_header_analysis,
                verbose=args.verbose,
            )
        except (OSError, struct.error) as exc:
            print(f"\n{path}: could not read -- {exc}")
            continue
        if found:
            results.append(found)

    print(f"\n{'=' * 72}")
    print(f"Summary: {len(results)} of {len(targets)} file(s) had a "
          f"recognisable payload")
    print("=" * 72)
    for found in results:
        print(f"  {os.path.basename(found['path']):<24} "
              f"{found['payload_type']:<26} "
              f"header={found['offset']:>4}B  "
              f"payload={found['payload_size']:,}B")

    if not results:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
