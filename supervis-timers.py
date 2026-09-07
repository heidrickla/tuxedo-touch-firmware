import sys, bisect
sys.path.insert(0,"/work")
from tuxelf import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM
e = Elf("/work/extracted/root_stock/supervis")
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail=True
def nm(va):
    i=bisect.bisect_right(e.addrs,va)-1
    return e.dem(e.syms[i][1]) if i>=0 else hex(va)
targets = {}
for a,n in e.syms:
    d = e.dem(n)
    if d.startswith(("ArmSWTimer","CreateSWTimer","DisArmSWTimer")) or \
       d in ("signal","sigaction","waitpid","wait","sleep","usleep","alarm","system"):
        targets[a] = d
text = e.d[e.to:e.to+e.ts]
print("call sites of the timer/signal/wait primitives:")
for i in range(0, len(text)-3, 4):
    va = e.ta+i
    ins = next(md.disasm(text[i:i+4], va), None)
    if ins is None or ins.mnemonic not in ("bl","blx") or not ins.operands: continue
    if ins.operands[0].type != ARM_OP_IMM: continue
    t = ins.operands[0].imm
    if t not in targets: continue
    r1 = ""
    for k in range(1, 12):
        o = e.v2o(va-4*k)
        if o is None: continue
        p = next(md.disasm(e.d[o:o+4], va-4*k), None)
        if p is None: continue
        if p.mnemonic in ("mov","movw") and p.op_str.startswith("r1,"):
            r1 = "  r1=" + p.op_str.split(",",1)[1].strip(); break
        if p.mnemonic in ("mov","movw") and p.op_str.startswith("r0,") and targets[t] in ("sleep","usleep","alarm"):
            r1 = "  r0=" + p.op_str.split(",",1)[1].strip(); break
    print("  0x%-8x %-34s <- %s%s" % (va, targets[t], nm(va), r1))
