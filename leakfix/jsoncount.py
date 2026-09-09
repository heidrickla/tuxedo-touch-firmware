#!/usr/bin/env python3
"""Count OUTSTANDING libjson allocations in a running Barracuda, read-only.

libjson is built with JSON_MEMORY_MANAGE: it keeps a std::map of every pointer its
C API hands out, and json_free erases from that map. So its node count is the
number of libjson allocations outstanding: exact, with no patch and nothing on
the request path.

chunkdiff's histogram names allocations by content and has to guess ownership.
This counts what libjson itself still owes, and separates strings from nodes.

Layout, derived in docs/ALLOCATOR-REWORK.md (do not re-derive):

    strings registry   libjson + 0x35cd4   (std::map, st_size 24)
    nodes   registry   libjson + 0x35c9c
    node count         registry + 20       (_M_node_count)
    init guard         + 0x35a90 strings, + 0x35a94 nodes

These hold for BOTH copies of the library. The panel maps /vidrec/lib/libjson.so.7
(md5 610d5009), not /usr/lib/libjson.so.7.6.1 (md5 6aa09429), because
/etc/rc.d/init.d/startup puts /vidrec/lib on LD_LIBRARY_PATH. The two have
identical section tables and a byte-identical json_free and differ only by 499
bytes of non-loaded content, so neither needs its own address set.

Offset 20 is confirmed two ways: json_free computes end() as map+4 before
_Rb_tree_rebalance_for_erase, and both singletons have st_size exactly 24, which
only fits 4 pad + 16 _Rb_tree_node_base + 4 count.

READ-ONLY by construction: opens /proc/PID/mem 'rb' and never ptrace-attaches.
TRAPS.md section 6: attaching to a process that holds /dev/watchdog resets the
panel.

Does not work on the panel, for kernel reasons. On 2.6.31 /proc/PID/mem refuses
every read from another process with ESRCH ("No such process") -- measured on the
panel against a live Barracuda, at offset 0 and at a mapped address. Pre-2.6.39
mem_read requires the target ptrace-attached AND stopped by the reader, and
stopping Barracuda makes supervis relaunch it, spending relaunch budget, so there
is no read-only path to this counter on the unit. The panel also has no python at
all (checked: no python, python2, python3 or perl -- only dd, od, hexdump), so a
shell port would not help.

A BENCH instrument, then: run it on the build VM against the qemu-user process,
whose /proc/PID/mem the VM's own kernel does allow. The guest's libjson mapping
appears in the qemu process's maps under its real path.

Usage, on the build VM:
    jsoncount.py                      # one reading
    jsoncount.py --watch 5            # every 5 s until interrupted
    jsoncount.py --pid 1234
"""
import argparse
import re
import struct
import sys
import time

STRINGS_REG = 0x35CD4
NODES_REG = 0x35C9C
COUNT_OFF = 20
GUARD_STRINGS = 0x35A90
GUARD_NODES = 0x35A94

LIBJSON_RE = re.compile(r"libjson\.so")


def find_pid(explicit=None):
    """Locate Barracuda. /proc/PID/comm does not exist on 2.6.31, and after an
    atomic mv the exe link reads '<path> (deleted)', so tolerate that suffix."""
    if explicit:
        return explicit
    import os
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            exe = os.readlink("/proc/%s/exe" % entry)
        except OSError:
            continue
        if "Barracuda" in exe:
            return int(entry)
    sys.exit("no Barracuda process found")


def libjson_base(pid):
    """First mapping of libjson, which is the load base for our offsets."""
    best = None
    with open("/proc/%d/maps" % pid) as fh:
        for line in fh:
            if not LIBJSON_RE.search(line):
                continue
            start = int(line.split("-", 1)[0], 16)
            # the r-xp text mapping at the lowest address is the base
            if best is None or start < best:
                best = start
    if best is None:
        sys.exit("libjson is not mapped in pid %d" % pid)
    return best


def read_word(mem, addr):
    mem.seek(addr)
    raw = mem.read(4)
    if len(raw) != 4:
        raise IOError("short read at 0x%x" % addr)
    return struct.unpack("<I", raw)[0]


def sample(mem, base):
    out = {}
    for label, reg, guard in (
        ("strings", STRINGS_REG, GUARD_STRINGS),
        ("nodes", NODES_REG, GUARD_NODES),
    ):
        g = read_word(mem, base + guard)
        # guard zero => the function-local static is not constructed yet, so the
        # map is still all zeros; report 0 rather than a garbage read.
        out[label] = read_word(mem, base + reg + COUNT_OFF) if g else 0
        out[label + "_init"] = bool(g)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pid", type=int, help="Barracuda pid (default: find it)")
    ap.add_argument("--watch", type=float, metavar="SECS",
                    help="re-read every SECS and show the delta")
    args = ap.parse_args()

    pid = find_pid(args.pid)
    base = libjson_base(pid)
    print("pid %d, libjson mapped at 0x%08x" % (pid, base))
    print("  strings registry 0x%08x  nodes registry 0x%08x"
          % (base + STRINGS_REG, base + NODES_REG))

    try:
        mem = open("/proc/%d/mem" % pid, "rb")
    except IOError as exc:
        sys.exit("cannot read /proc/%d/mem (%s) -- run as root" % (pid, exc))

    first = prev = None
    try:
        while True:
            s = sample(mem, base)
            if not (s["strings_init"] and s["nodes_init"]):
                print("  note: registry not constructed yet (%s) -- "
                      "issue one API request first"
                      % ("strings" if not s["strings_init"] else "nodes"))
            if prev is None:
                first = s
                print("outstanding: %d strings, %d nodes"
                      % (s["strings"], s["nodes"]))
            else:
                print("outstanding: %d strings (%+d, %+d total)   "
                      "%d nodes (%+d, %+d total)"
                      % (s["strings"], s["strings"] - prev["strings"],
                         s["strings"] - first["strings"],
                         s["nodes"], s["nodes"] - prev["nodes"],
                         s["nodes"] - first["nodes"]))
            prev = s
            if not args.watch:
                break
            time.sleep(args.watch)
    except KeyboardInterrupt:
        pass
    finally:
        mem.close()


if __name__ == "__main__":
    main()
