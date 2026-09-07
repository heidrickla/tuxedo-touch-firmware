"""Build a NEGATIVE CONTROL for supervis_heartbeat.py.

Tightening the wrong-binary case to rc=2 was right and it cost me the only
demonstration that the assertions can fail at all: Barracuda used to trip three
of them, and now it correctly reports "not supervis, nothing checked". Passing
on two real binaries proves the checker runs; only a failure proves it can
discriminate.

So make a supervis that genuinely violates the claim: redirect one `bl` inside
SupervisTimeout to osal_MqRecv, so the 600 s housekeeping DOES read the
supervision queue. If the checker still says the claim holds, it is not
checking.

Writes a copy. Never touches the original.
"""
import shutil
import struct
import sys

sys.path.insert(0, "/work")
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import ARM_INS_BL, ARM_OP_IMM

from tuxelf import Elf

SRC = "/work/extracted/root_stock/supervis"
DST = "/work/supervis.control"

e = Elf(SRC)
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

recv = e.addr("osal_MqRecv(int, char*, int)")
lo = e.addr("SupervisTimeout(sigval)")
hi = e.end(lo)
off = e.v2o(lo)

site = None
for ins in md.disasm(e.d[off:off + (hi - lo)], lo):
    if ins.id == ARM_INS_BL and ins.operands and ins.operands[0].type == ARM_OP_IMM:
        site = ins.address
        break
if site is None:
    sys.exit("no bl found in SupervisTimeout")

# Rewrite that bl to target osal_MqRecv. ARM BL: cond=1110, 101L, imm24 signed,
# target = site + 8 + imm*4.
imm = (recv - site - 8) // 4
word = 0xEB000000 | (imm & 0xFFFFFF)
shutil.copy(SRC, DST)
with open(DST, "r+b") as fh:
    fh.seek(e.v2o(site))
    fh.write(struct.pack("<I", word))

print("control written: %s" % DST)
print("  redirected the bl at 0x%x inside SupervisTimeout to osal_MqRecv 0x%x"
      % (site, recv))
print("  this binary DOES read the queue from the 600s housekeeping,")
print("  so the checker must report the claim FALSE (rc=1) for it.")
