#!/usr/bin/env python3
"""Create a minimal /dev/zwavestatusdb so device-gated handlers can be measured.

getDeviceTypeFromFile @0x1128c reads this file in 120-byte records with
fread(buf, 0x78, 1, f) and returns record[5] for the record whose record[0] equals
the requested node id. Nothing else in the record is consulted on that path, so a
single record is enough to get past the device-type gate.

Bench only. The real panel has its own, written by the Z-Wave stack; this exists so
SetDoorLock, SetLight and the thermostat handlers stop bailing at validation on an
emulator whose zwavedevdb.json is empty.

    type 0x40 = door lock   (setDoorLock compares getDeviceTypeFromFile(node) to 0x40)

Usage: mkzwdb.py <path> [node:type ...]
"""
import sys

RECORD = 0x78
TYPE_OFF = 5


def main():
    path = sys.argv[1]
    specs = sys.argv[2:] or ["1:0x40"]
    out = bytearray()
    for spec in specs:
        node_s, type_s = spec.split(":")
        node, dtype = int(node_s, 0), int(type_s, 0)
        if not 0 < node < 256 or not 0 <= dtype < 256:
            raise SystemExit("node and type must fit in a byte: %s" % spec)
        rec = bytearray(RECORD)
        rec[0] = node
        rec[TYPE_OFF] = dtype
        out += rec
        print("  node %d type 0x%02x" % (node, dtype))
    with open(path, "wb") as fh:
        fh.write(out)
    print("wrote %s, %d byte(s), %d record(s)" % (path, len(out), len(out) // RECORD))


if __name__ == "__main__":
    main()
