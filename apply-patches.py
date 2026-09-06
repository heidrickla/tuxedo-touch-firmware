#!/usr/bin/env python3
"""Apply or check the firmware patch set defined in patches.tsv.

    python apply-patches.py --check --root /work/root_patched
    python apply-patches.py --apply --root /work/root_patched

`patches.tsv` is the single source of truth; `verify-panel.sh` reads the same
file to check the running panel, so a patch cannot be applied in one place and
forgotten in the other.

Every write is guarded: a site whose current bytes are neither the expected
stock nor the expected patched value is refused, never overwritten. Applying to
an already-patched tree is a no-op rather than an error, so this is safe to
re-run.

Exit status is the number of sites in an unexpected state.
"""

import argparse
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                raise SystemExit(f"{path}:{n}: expected 5+ tab-separated fields, got {len(parts)}")
            name, binary, off, stock, patched = parts[:5]
            desc = parts[5] if len(parts) > 5 else ""
            rows.append({
                "name": name,
                "binary": binary,
                "off": int(off, 16),
                "stock": bytes.fromhex(stock),
                "patched": bytes.fromhex(patched),
                "desc": desc,
            })
    return rows


def target(root, binary):
    return os.path.join(root, binary.lstrip("/").replace("/", os.sep))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="staged rootfs to patch")
    ap.add_argument("--table", default=os.path.join(HERE, "patches.tsv"))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="report only, write nothing")
    g.add_argument("--apply", action="store_true", help="apply any site still stock")
    args = ap.parse_args()

    rows = load(args.table)
    bad = 0
    applied = 0
    already = 0

    for r in rows:
        path = target(args.root, r["binary"])
        if not os.path.isfile(path):
            print(f"  MISS  {r['name']:18} {r['binary']} not found under --root")
            bad += 1
            continue
        n = len(r["stock"])
        with open(path, "rb") as fh:
            fh.seek(r["off"])
            cur = fh.read(n)

        if cur == r["patched"]:
            print(f"  ok    {r['name']:18} already patched")
            already += 1
        elif cur == r["stock"]:
            if args.apply:
                with open(path, "r+b") as fh:
                    fh.seek(r["off"])
                    fh.write(r["patched"])
                print(f"  APPLY {r['name']:18} {cur.hex(' ')} -> {r['patched'].hex(' ')}")
                applied += 1
            else:
                print(f"  STOCK {r['name']:18} not yet patched")
                bad += 1
        else:
            # Never overwrite something we do not recognise.
            print(f"  BAD   {r['name']:18} unexpected bytes [{cur.hex(' ')}]")
            print(f"        expected stock [{r['stock'].hex(' ')}] "
                  f"or patched [{r['patched'].hex(' ')}] at {r['binary']}+{r['off']:#x}")
            bad += 1

    print()
    print(f"{len(rows)} sites: {already} already patched, "
          f"{applied} applied, {bad} needing attention")
    return bad


if __name__ == "__main__":
    sys.exit(main())
