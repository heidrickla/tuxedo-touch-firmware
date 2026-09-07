"""Interactive ARM ELF analysis for the Tuxedo binaries.

/tuxedo ships an unstripped .symtab with 12,592 named functions, which turns
most questions about the panel application into lookups rather than reverse
engineering. This wraps the parts that were retyped over and over.

    python tuxelf.py <binary>          # then use it interactively
    >>> callers("PanelIsTalking")
    >>> calls("handleApplyPress")
    >>> dis("HandleGetCurrentTimeResponse")
    >>> refs(0x599ff8)
    >>> grep("InternetTime")

Sections and symbols are parsed here rather than shelled out to binutils, so it
runs anywhere python3 does. That also sidesteps readelf truncating symbol names
to __[...] without -W, which once turned a sweep of 680 executables into a
confident false negative and hid the panel's clock source for an hour.
"""
import bisect
import re
import struct
import subprocess
import sys


class Elf:
    def __init__(self, path):
        self.path = path
        self.d = d = open(path, "rb").read()
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF")
        shoff = struct.unpack_from("<I", d, 0x20)[0]
        shentsize = struct.unpack_from("<H", d, 0x2E)[0]
        shnum = struct.unpack_from("<H", d, 0x30)[0]
        shstrndx = struct.unpack_from("<H", d, 0x32)[0]

        raw = []
        for i in range(shnum):
            o = shoff + i * shentsize
            raw.append(struct.unpack_from("<10I", d, o))
        shstr = raw[shstrndx][4]

        def cstr(base, off):
            end = d.index(b"\x00", base + off)
            return d[base + off:end].decode("latin-1")

        self.secs = []
        symtabs = []
        for nameoff, typ, flags, addr, off, size, link, info, align, entsz in raw:
            self.secs.append((cstr(shstr, nameoff), addr, off, size))
            if typ in (2, 11) and entsz:                 # SYMTAB, DYNSYM
                symtabs.append((off, size, entsz, raw[link][4]))

        self.syms = []
        seen = set()
        for off, size, entsz, stroff in symtabs:
            for i in range(size // entsz):
                o = off + i * entsz
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from("<IIIBBH", d, o)
                if (st_info & 0xF) != 2 or not st_value:  # STT_FUNC with an address
                    continue
                nm = cstr(stroff, st_name)
                key = (st_value, nm)
                if not nm or key in seen:
                    continue
                seen.add(key)
                self.syms.append((st_value & ~1, nm))
        self.syms.sort()
        self.addrs = [s[0] for s in self.syms]
        t = [s for s in self.secs if s[0] == ".text"]
        self.ta, self.to, self.ts = (t[0][1], t[0][2], t[0][3]) if t else (0, 0, 0)
        self._dem = {}
        self._cxxfilt = None

    # -- names ------------------------------------------------------------

    @staticmethod
    def _qualified(n):
        """Pull the qualified name out of an Itanium mangling, ignoring the
        signature. _ZN14CReceiverThread30sltSendChangedPartitionStatusEi ->
        CReceiverThread::sltSendChangedPartitionStatus. Enough to search and
        display by; c++filt is used instead when it is available."""
        if not n.startswith("_Z"):
            return n
        i = 2
        nested = False
        if i < len(n) and n[i] == "N":
            nested = True
            i += 1
            while i < len(n) and n[i] in "KVr":      # cv-qualifiers
                i += 1
        parts = []
        while i < len(n) and n[i].isdigit():
            j = i
            while j < len(n) and n[j].isdigit():
                j += 1
            ln = int(n[i:j])
            if j + ln > len(n):
                break
            parts.append(n[j:j + ln])
            i = j + ln
            if not nested:
                break
        if not parts:
            return n
        return "::".join(parts)

    def dem(self, n):
        """C++ names are stored mangled. Use c++filt when present, otherwise
        recover the qualified name well enough to search and display."""
        if not n.startswith("_Z"):
            return n
        if n not in self._dem:
            out = ""
            if self._cxxfilt is not False:
                try:
                    out = subprocess.run(["c++filt", n], capture_output=True,
                                         text=True, timeout=5).stdout.strip()
                    self._cxxfilt = True
                except Exception:
                    self._cxxfilt = False
            self._dem[n] = out if out and out != n else self._qualified(n)
        return self._dem[n]

    def name(self, va):
        i = bisect.bisect_right(self.addrs, va) - 1
        return self.dem(self.syms[i][1]) if i >= 0 else "?"

    def addr(self, what):
        if isinstance(what, int):
            return what
        hits = [a for a, n in self.syms if n == what or self.dem(n) == what]
        if hits:
            return hits[0]
        loose = [(a, self.dem(n)) for a, n in self.syms
                 if what in n or what in self.dem(n)]
        if len(loose) == 1:
            return loose[0][0]
        if not loose:
            raise KeyError(what)
        raise KeyError(f"{what!r} is ambiguous: {[n for _, n in loose[:6]]}")

    def end(self, va):
        later = [a for a in self.addrs if a > va]
        return min(later) if later else va + 0x400

    def grep(self, pattern):
        r = re.compile(pattern, re.I)
        return [(a, self.dem(n)) for a, n in self.syms if r.search(self.dem(n))]

    # -- address mapping --------------------------------------------------

    def v2o(self, va):
        """Virtual address -> file offset, or None if the address is not mapped.

        Skips sections with sh_addr == 0 for the same reason o2v does: they are
        not loaded, so an address "inside" one is arithmetic, not data. Without
        this, the small integer 801 -- a literal-pool constant that is a
        message type, not a pointer -- landed in .comment and read back as the
        string "U) 4.1.2", a fragment of the GCC version banner, which was then
        published as the value of a reply's msgType field. o2v carried this
        guard and v2o did not, so the same trap caught this file twice.
        """
        for n, a, o, s in self.secs:
            if a == 0:
                continue          # not loaded; an address here is not data
            if s and a <= va < a + s and n != ".bss":
                return o + (va - a)
        return None

    def o2v(self, off):
        """File offset -> virtual address, or None if the offset is not mapped.

        Sections with sh_addr == 0 are NOT loaded at runtime -- .symtab,
        .strtab, .comment, .shstrtab, .ARM.attributes. Translating an offset
        inside one of those produced a virtual address in low text space and
        made every function symbol look like it had a data reference to
        itself: LoginTracker_getFirstNode's `st_value` word inside .symtab
        was reported as a pointer at VA 0xd0b4, "in createServer".

        That is the same shape as the BL-only caller bug -- a scan returning a
        confident wrong answer rather than nothing -- and it was used to rank
        code-cave risk, which is exactly where a phantom reference is most
        expensive. Skip unmapped sections.
        """
        for n, a, o, s in self.secs:
            if a == 0:
                continue          # not loaded; an offset here has no VA
            if s and o <= off < o + s:
                return a + (off - o)
        return None

    # -- code -------------------------------------------------------------

    def _branches(self, lo, hi):
        """Yield (site, target, is_link) for every B and BL, any condition.

        Tail calls matter here. Qt's moc dispatch reaches a slot with a plain
        `b` after popping the frame, so a BL-only scan reports a live slot as
        having no callers -- that made all 20 reachable CKeyPadWin slots look
        dead. Conditional forms count too; gcc emits `bleq` freely.
        """
        base = self.to + (lo - self.ta)
        for i in range((hi - lo) // 4):
            w = struct.unpack_from("<I", self.d, base + i * 4)[0]
            if (w >> 25) & 0x07 != 0x05 or (w >> 28) == 0xF:
                continue                    # cond 0xF is BLX(imm), other form
            imm = w & 0xFFFFFF
            if imm & 0x800000:
                imm -= 0x1000000
            yield lo + i * 4, lo + i * 4 + 8 + imm * 4, bool((w >> 24) & 1)

    def _bl_targets(self, lo, hi):
        for site, tgt, link in self._branches(lo, hi):
            if link:
                yield site, tgt

    def callers(self, what, tails=True):
        """Functions that call `what`, counting tail-call branches by default.

        A `b` is a call only when it leaves the function it sits in; inside one
        it is ordinary control flow. `what` is a function start, so a branch to
        it from a different function is a tail call into it.
        """
        t = self.addr(what)
        tn = self.name(t)
        out = []
        for site, tgt, link in self._branches(self.ta, self.ta + self.ts):
            if tgt != t:
                continue
            n = self.name(site)
            if not link and (not tails or n == tn):
                continue
            if n not in out:
                out.append(n)
        return out

    def calls(self, what, tails=True):
        lo = self.addr(what)
        hi = self.end(lo)
        out = []
        for site, tgt, link in self._branches(lo, hi):
            if not link and (not tails or lo <= tgt < hi):
                continue                    # internal branch, not a call
            n = self.name(tgt)
            if n not in out:
                out.append(n)
        return out

    def refs(self, va):
        """Where an address appears as a 4-byte value: vtables, timer callbacks."""
        pat = struct.pack("<I", va)
        out, i = [], self.d.find(pat)
        while i != -1:
            v = self.o2v(i)
            if v is not None:
                out.append((v, self.name(v)))
            i = self.d.find(pat, i + 1)
        return out

    def dis(self, what, count=40):
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
        lo = self.addr(what)
        hi = min(self.end(lo), lo + count * 4)
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        o = self.v2o(lo)
        for ins in md.disasm(self.d[o:o + (hi - lo)], lo):
            tail = ""
            if ins.mnemonic == "bl":
                try:
                    tail = "   -> " + self.name(int(ins.op_str.strip("#"), 0))
                except ValueError:
                    pass
            print(f"{ins.address:#010x}  {ins.mnemonic:8} {ins.op_str}{tail}")


if __name__ == "__main__":
    e = Elf(sys.argv[1] if len(sys.argv) > 1 else "tuxedo")
    callers, calls, dis, refs, grep, name = (
        e.callers, e.calls, e.dis, e.refs, e.grep, e.name)
    print(f"{e.path}: {len(e.syms)} functions, .text {e.ta:#x}+{e.ts:#x}")
