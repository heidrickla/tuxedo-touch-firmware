#!/usr/bin/env python3
"""Recover the REST parameter contract statically, from serviceField's own json_gets.

The contract does not need probing. serviceField dispatches on the field name with
strncmp against a string literal, and each endpoint's block then calls
json_get(tree, "<param>") once per parameter it requires. Both operands are literal
pool entries, so endpoint and parameter names are both recoverable from the
disassembly:

    ldr r1, [pc, #N]   @ LITADDR        LITADDR holds a .rodata VA
    bl  <strncmp@plt>                   -> this block handles endpoint <name>
    ...
    ldr r1, [pc, #M]   @ LITADDR2
    bl  <json_get@plt>                  -> that endpoint reads parameter <name>

Each json_get is attributed to the nearest preceding strncmp, which is how the
generated dispatcher is laid out. Verified by hand against four endpoints already
established by live probing: Unregister/token+DeviceMAC, SetDoorLock/nodeID+cntrl.

Beats probing on every axis that matters here: it covers endpoints whose validation
a prober could never satisfy (no registered MAC, no Z-Wave device), it sends no
writes at a live alarm, and it reads the requirement rather than inferring it from a
refusal message.

Usage: apicontract.py <objdump-of-serviceField> <binary>
"""
import io
import re
import struct
import sys

TEXT_BIAS = 0x8000
LINE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+(.*)$")
LDR_LIT = re.compile(r"ldr\s+(r\d+),\s*\[pc,\s*#-?\d+\]\s*@\s*([0-9a-f]+)")
CALL = re.compile(r"bl\s+[0-9a-f]+\s+<([^>@]+)@?[^>]*>")
MOV_REG = re.compile(r"mov\s+(r\d+),\s*(r\d+)\s*$")
TREE_REG = "r7"


def cstr(buf, va, limit=96):
    off = va - TEXT_BIAS
    if off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\0", off, off + limit)
    if end < 0:
        return None
    try:
        s = buf[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def literal(buf, lit_va):
    off = lit_va - TEXT_BIAS
    if off < 0 or off + 4 > len(buf):
        return None
    return struct.unpack("<I", buf[off:off + 4])[0]


def main():
    dis_path, bin_path = sys.argv[1], sys.argv[2]
    buf = open(bin_path, "rb").read()

    pending = {}          # register -> resolved string
    r0src = {}            # register -> register it was last copied from
    current = None
    out = {}              # endpoint -> [params in order]
    order = []

    for raw in io.open(dis_path, encoding="utf-8", errors="replace"):
        m = LINE.match(raw)
        if not m:
            continue
        text = m.group(2)

        lm = LDR_LIT.search(text)
        if lm:
            reg, lit = lm.group(1), int(lm.group(2), 16)
            va = literal(buf, lit)
            pending[reg] = cstr(buf, va) if va else None
            continue

        mv = MOV_REG.search(text)
        if mv:
            r0src[mv.group(1)] = mv.group(2)
            continue

        cm = CALL.search(text)
        if not cm:
            continue
        fn = cm.group(1)
        arg1 = pending.get("r1")

        if fn == "strncmp" and arg1:
            current = arg1
            if current not in out:
                out[current] = []
                order.append(current)
        elif fn == "json_get" and arg1 and current:
            # Only count a json_get whose OBJECT is the request tree. In
            # serviceField that is r7 (set by `mov r7, r0` right after the
            # json_new at 0x1ef04). WnmpDir_service also calls json_get, but on
            # the registered-device records from getRegisteredDevNodes -- those
            # are PublicKey/PrivateKey/DeviceMAC field reads, not request
            # parameters, and counting them would publish device-record fields as
            # an API contract.
            if r0src.get("r0") == TREE_REG and arg1 not in out[current]:
                out[current].append(arg1)
        pending.pop("r1", None)
        r0src.pop("r0", None)

    withp = [n for n in order if out[n]]
    without = [n for n in order if not out[n]]
    for name in withp:
        print("%-34s %s" % (name, ", ".join(out[name])))
    print()
    print("# %d endpoint blocks read a parameter; %d read none."
          % (len(withp), len(without)))
    print("# no-parameter blocks (a bare operation= call, or not a REST endpoint):")
    for i in range(0, len(without), 4):
        print("#   " + "  ".join("%-22s" % n for n in without[i:i + 4]).rstrip())


if __name__ == "__main__":
    main()
