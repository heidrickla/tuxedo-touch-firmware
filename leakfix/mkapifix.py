#!/usr/bin/env python3
"""Patch the /system_http_api parameter-tree leak in Barracuda.

THE DEFECT
    WnmpDir_serviceField builds a JSON object from the request parameters:

        1ef04  bl json_new          -> root
        1ef0c  mov r7, r0           -> r7 holds the root for the whole function
        1f008  json_new_a(name,val) -> a COPY of every parameter value
        1f014  json_push_back(r7, node)

    and then at 0x29088 overwrites r7 with an unrelated pointer:

        2907c  ldr r3, [fp, #-876]
        29088  ldr r7, [r3, #8]     <-- root pointer destroyed here

    `str r7` appears ZERO times in the function, so the root lives only in that
    register. Once it is overwritten the tree is unreachable to all code and can
    never be freed - the epilogue's json_delete(r7) frees the replacement value
    instead. One abandoned tree per request.

WHY FREEING HERE IS SAFE
    Unreachable means unusable. After 0x29088 no code can reach the tree: it is
    in no register, no memory location, and was never passed to the handler,
    which is exactly why it leaks. Freeing it immediately before the pointer is
    destroyed cannot break a consumer, because no consumer can exist.

THE PATCH
    0x29088 is replaced by a branch into a dead 56-byte cave
    (LoginTracker_getFirstNode/getNextNode, 0 direct callers, and its only two
    image references are ELF symtab entries). The cave frees the tree, restores
    the registers the following code needs, performs the displaced load, and
    branches back.

    json_delete clobbers r0-r3 and r12 per AAPCS; r1, r2 and r3 are all live
    across this point (r3 is the base of the displaced load itself), so they are
    saved. Four registers keeps sp 8-byte aligned. r7 is callee-saved, so
    json_delete preserves it; the displaced load then sets it as the original
    code did.
"""

import argparse
import struct
import sys

TEXT_BIAS = 0x8000

PATCH_SITE = 0x29088          # ldr r7, [r3, #8]  -- destroys the root
RETURN_TO = 0x2908C
CAVE = 0x64E9C                # LoginTracker_getFirstNode/getNextNode, dead
CAVE_END = 0x64ED4
JSON_DELETE_PLT = 0xBA18

ORIG_AT_SITE = 0xE5937008     # ldr r7, [r3, #8]

# LEAK 2: the Base64Decode output buffer.
#
#   1ef78  bl Base64Decode      -- mallocs its output, pointer stored at fp-52
#   1ef8c  ldr r0, [fp, #-52]   -- the ONLY load of it, passed to decrypt
#   1ef90  bl decrypt
#
# Base64Decode calls calcDecodeLength31 then malloc, so the caller owns the
# buffer. It is never freed: fp-52 is referenced exactly once in the whole
# 43 KB function. Freed here, immediately after its last use.
#
# 0x1efa0 is reachable ONLY by falling through from the decode (nothing branches
# to it or to 0x1efa4), so the pointer is always initialised when this runs -
# on the empty-param path the code jumps away long before here.
PATCH2_SITE = 0x1EFA0         # mov r0, r6
RETURN2_TO = 0x1EFA4
CAVE2 = 0x64EB4
FREE_PLT = 0xC150

ORIG2_AT_SITE = 0xE1A00006    # mov r0, r6

# LEAK 3: tuxedoapi_html076EF::service leaks its whole parsed JSON document.
#
#   47c10  bl json_parse_unformatted
#   47c14  mov r4, r0            -- the document, live to the end
#   ...    json_size/json_at/json_get/json_as_string over r4
#   47cc8  b 47ce4               -- straight to the epilogue
#
# The full 616-byte function contains ZERO json_delete, json_free, free or
# malloc. Measured at 7537 bytes/request on a plain authenticated GET, which is
# five times the API path.
#
# Patched at 0x47cc8: nothing branches there, and its only predecessor chain
# (47ca4 -> 47cb0 -> 47cc4) runs after the parse, so r4 always holds the
# document. The epilogue restores pc from the stack rather than lr, so the stub
# does not need to preserve lr. r0-r3 are dead across it.
#
# NULL-guarded: json_parse_unformatted returns NULL on a malformed document, and
# this stub must not hand that to json_delete.
PATCH3_SITE = 0x47CC8         # b 47ce4
RETURN3_TO = 0x47CE4
CAVE3 = 0x64E50               # AuthenticatedUser_getType, 68 B, 0 callers

ORIG3_AT_SITE = 0xEA000005    # b 47ce4

# LEAK 4: getPartitionStatus (0x1cad8) - the RESPONSE side, and the biggest
# remaining term on the path Home Assistant actually polls.
#
#   1caf8  json_new  -> r7    tree A, the status object
#   1cbf4  json_new  -> r6    tree B, the response wrapper
#   1cc50  Base64Encode(...)  -> malloc'd buffer, pointer at fp-52
#   1cc80  json_delete(r7)    tree A IS freed
#   1cc84  mov r0, #0 ; ret   <-- r6 and fp-52 are NOT
#
# Two of the four leaks here are fixable at the return, where both pointers are
# still live: tree B in the callee-saved r6, and the Base64Encode buffer in the
# stack slot fp-52. Both NULL-guarded.
#
# The other two are NOT fixed here and need their own capture sites, because
# each pointer is destroyed at birth:
#   1cc04  json_write(r7) -> str1, immediately consumed by strlen whose RESULT
#          overwrites r0. Used only to measure a length; the string is abandoned.
#   1cc2c  json_write(r7) -> str2, passed to encrypt; r0 is then encrypt's
#          return. Same shape.
# json_write mallocs its result in this library, so both are per-request leaks.
PATCH4_SITE = 0x1CC84         # mov r0, #0
RETURN4_TO = 0x1CC88
CAVE4 = 0x64E60               # continues the AuthenticatedUser_getType cave

ORIG4_AT_SITE = 0xE3A00000    # mov r0, #0

# LEAKS 5 and 6: the two json_write results in getPartitionStatus.
#
# RELEASE CONTRACT: libjson's json_write() result is released with
# **json_free**, NOT free. Verified in this binary: json_free@plt exists at
# 0xbca0 and the vendor's own correct sites use `mov r0, rX ; bl json_free`
# (e.g. 0x1887c, 0x30100, 0x30108). The omission is systematic - the image makes
# 521 json_write calls against 28 json_free.
#
#   1cc04  json_write(r7) -> str1, then 1cc08 strlen(str1) whose RESULT
#          overwrites r0. Freed at the strlen site, using r4 as scratch: r4 is
#          dead between 0x1cb90 and 0x1cc24.
#   1cc2c  json_write(r7) -> str2, passed to encrypt at 0x1cc40 which then
#          overwrites r0 with its own return.
#
# str2 cannot be saved with `push`: encrypt takes a stack argument stored by
# `str r5,[sp]` at 0x1cc34, so moving sp would misplace it. The alloca at
# 0x1cc0c-0x1cc1c reserves EIGHT bytes at sp (`add r3,r3,#8`) but uses only
# sp+0 for that argument, with the output buffer at sp+8 - so **[sp,#4] is a
# spare word inside the frame**. str2 is stashed there and freed after encrypt
# returns (where it appears at [sp,#12], sp having moved by the stub's push).
PATCH5_SITE = 0x1CC08         # bl strlen
RETURN5_TO = 0x1CC0C
CAVE5 = 0x64E10               # AuthUserListEnumerator_nextElement, 64 B, dead
ORIG5_AT_SITE = 0xEBFFBC2D    # bl strlen

PATCH6_SITE = 0x1CC2C         # bl json_write
RETURN6_TO = 0x1CC30
CAVE6 = 0x64E2C
ORIG6_AT_SITE = 0xEBFFBD29    # bl json_write

PATCH7_SITE = 0x1CC44         # sub r2, fp, #52
RETURN7_TO = 0x1CC48
CAVE7 = 0x64E38
CAVE7_END = 0x64E50
ORIG7_AT_SITE = 0xE24B2034    # sub r2, fp, #52

JSON_FREE_PLT = 0xBCA0
STRLEN_PLT = 0xBCC4
JSON_WRITE_PLT = 0xC0D8

# LEAK 7: the handler's out-parameter string, abandoned by the caller.
#
# getPartitionStatus finishes with `json_write(r6)` (0x1cc70) and stores the
# result through its out-parameter at 0x1cc78. In WnmpDir_serviceField that slot
# is [fp,#-868]. On the branch a GetSecurityStatus request actually takes
# (0x290b4 -> 0x290d8 -> 0x290e0, since the handler returns 0 and r6 is 0) the
# slot is NEVER READ and never freed. The other branch (0x294a0) does read it -
# printf'ing it at 0x294d8 - and does not free it either.
#
# Freed at 0x2954c, on the exit every branch converges to, so it is released
# after any use rather than before. The slot is zero-initialised at 0x2908c
# (`str r1,[fp,#-868]` with r1 = 0), so the NULL guard also covers the case
# where the handler never ran.
#
# 0x29548 would be the tidier site but its instruction is `ldr r2,[pc,#836]` -
# pc-relative, so relocating it into a cave would change what it loads. 0x2954c
# is a plain `ldr r3,[r2]`. r2 is live across it (used again at 0x29558) and
# json_free clobbers r0-r3, so r2 is saved.
PATCH8_SITE = 0x2954C         # ldr r3, [r2]
RETURN8_TO = 0x29550
CAVE8 = 0x65850               # AuthenticatedUser_getAnonymous, 128 B, dead
CAVE8_END = 0x658D0
ORIG8_AT_SITE = 0xE5923000    # ldr r3, [r2]

# LEAK 8: the authtoken HMAC output buffer in WnmpDir_service.
#
#   29cdc  malloc(20)          -> [fp,#-1632]   (20 B = a SHA-1 digest)
#   29d3c  HMAC_Final(ctx, [fp,#-1632], &len)
#   29d54  ldr r3,[fp,#-1632]  -- read in the hex-encoding loop 29d54..29d78
#   29d7c  loop exits          <-- buffer dead here, and never freed
#
# WnmpDir_service makes two mallocs and has ONE free (0x2a14c), which releases
# the other one on the redirect path. HMAC_CTX_init/cleanup are balanced; only
# this buffer leaks. 20 bytes lands in a 24-byte chunk, matching the 24 B x1
# per request left in the histogram.
#
# Freed at 0x29d7c: nothing branches there, and the only live register across it
# is r6, which is callee-saved and so survives the call.
PATCH9_SITE = 0x29D7C         # sub r0, fp, #44
RETURN9_TO = 0x29D80
CAVE9 = 0x6586C               # continues the AuthenticatedUser_getAnonymous cave
ORIG9_AT_SITE = 0xE24B002C    # sub r0, fp, #44

# LEAK 9: the authtoken's base64 buffer in WnmpDir_service.
#
# Base64Encode is called TWICE per request. getPartitionStatus's call (0x1cc44)
# is released by LEAK 4's stub. WnmpDir_service calls it again at 0x29dbc with
# `r2 = &[fp,#-52]`, and on the path a real request takes that output is
# **written, never read, and never freed** - the slot's only reader (0x2a050)
# sits after a DIFFERENT Base64Encode (0x2a04c) on a branch this request does
# not take. Base64 of the 40-char HMAC hex is 57 bytes: a 64-byte chunk,
# matching the 64 B x1 per request the histogram still showed.
#
# Freed immediately after the call rather than at the epilogue. The epilogue
# would be WRONG: [fp,#-52] is written only by Base64Encode, so a path that
# returns earlier would hand uninitialised stack to free(). 0x29dc4 is reached
# only by falling through from the call, so the pointer is always valid there.
#
# The slot is then set to NULL, so if the 0x2a04c path later reads it before
# overwriting it, it sees NULL rather than a dangling pointer. r1 is live across
# the site (loaded 0x29dc0, consumed by the call at 0x29dc8) and free clobbers
# r0-r3, so r1 is saved.
PATCH10_SITE = 0x29DC4        # mov r0, sl
RETURN10_TO = 0x29DC8
CAVE10 = 0x65888
CAVE10_END = 0x658D0
ORIG10_AT_SITE = 0xE1A0000A   # mov r0, sl

# LEAK 10: json_as_string results are never released.
#
# libjson's json_as_string() returns a caller-owned string that must be given to
# json_free. The vendor knows this - 0x470e8 does `bl json_as_string` followed
# immediately by `bl json_free` at 0x470ec - but applies it almost nowhere:
# **391 json_as_string call sites against 28 json_free**. Six run per API
# request and NONE is freed (measured on a traced request: 6 x 0xbc34, 0 x
# 0xbca0).
#
# Three of those six hand the string straight to strcpy with it still in r1:
#
#   29bdc/29be8   the matched device's field   -> [fp,#-186]
#   29c04/29c14   the 64-hex SESSION KEY       -> [fp,#-82]
#   29e14/29e20   a device field               -> [fp,#-250]
#
# The session key one is the 72-byte chunk whose contents chunkdiff dumped, and
# which was measured accumulating 2 copies per request.
#
# ONE shared stub serves all three. It replaces `bl strcpy` with `bl stub` and
# RETURNS VIA lr, so the same 28 bytes work from any call site - no per-site
# cave, no return-address baked in. It preserves strcpy's return value (the
# destination), which some callers use.
#
# Only these three strcpy calls are redirected. Every other strcpy in the image
# is untouched, because elsewhere r1 is not a json_as_string result and freeing
# it would be catastrophic.
STRCPY_PLT = 0xBE38
FREESTR_STUB = 0x658AC        # tail of the AuthenticatedUser_getAnonymous cave
STRCPY_SITES = (
    (0x29BE8, 0xEBFF8892),
    (0x29C14, 0xEBFF8887),
    (0x29E20, 0xEBFF8804),
)

# The other three json_as_string results feed a COMPARISON rather than a copy,
# with the string in r0. Same trick, two more shared stubs - one per comparison
# function - each returning via lr and preserving the comparison's result.
#
#   1f0e4/1f0f0  strncmp(str, "set", 4)   in WnmpDir_serviceField
#   29ba0/29bbc  strcmp(str, header)      device-match loop, iteration compare
#   29e68/29e84  strcmp(str, header)      second lookup's compare
#
# r4 carries the string into each strcmp and is reassigned on the next loop
# iteration (0x29ba8 / 0x29e70), so it is dead immediately after the compare.
STRNCMP_PLT = 0xB994
STRCMP_PLT = 0xBC40
CMPFREE_CAVE = 0x693DC        # HttpServer_getStatusCode, 896 B, verified dead
CMPFREE_CAVE_END = 0x6975C
FREE_STRNCMP_STUB = 0x693DC
FREE_STRCMP_STUB = 0x693FC
STRNCMP_SITES = ((0x1F0F0, 0xEBFFB227),)
STRCMP_SITES = (
    (0x29BBC, 0xEBFF881F),
    (0x29E84, 0xEBFF876D),
    (0x47C44, 0xEBFF0FFD),    # tuxedoapi.html's per-entry name compare
)

# LEAK 12: tuxedoapi.html leaks TWO json_as_string results per list entry.
#
#   47c64  json_as_string -> r6   \ both consumed as varargs by
#   47c80  json_as_string -> r3   / HttpResponse_printf at 0x47c94
#
# and the loop runs once per entry in the parsed document, so this scales with
# the file. Freed by a stub that wraps the printf and releases r2 and r3
# afterwards; printf's return value is unused (0x47c98 is `add r5, r5, #1`).
# NULL-guarded, because a missing key makes json_as_string return NULL.
HTTPRESP_PRINTF = 0x6B678
PRINTF2_STUB = 0x6941C
PRINTF2_SITES = ((0x47C94, 0xEB008E77),)

# LEAK 13 - THE IPC PATH, and it dwarfs every HTTP leak here.
#
# gettuxedoIPCCommFunc -> pushSecurityStatus -> pushEventsToClientsDevAdded ->
# registeredClients -> scene_getRootNodeOfObjects. Measured ~38.5 kB PER IPC
# STATUS MESSAGE under emulation via emu/pushdriver.py, strictly linear across
# three batches of 200 and never returned. The panel drives this constantly;
# HTTP-only testing never touches it.
#
# scene_getRootNodeOfObjects (0x347f8) reads the registered-device file:
#
#   348f8  operator new[](len+1) -> r7    the raw file buffer
#   34924  fread into r7
#   3495c  mov r0, r7
#   34960  bl json_strip_white_space      returns a NEW string
#   34964  bl json_parse_unformatted      parses it; r0 becomes the tree
#   3496c  mov r0, r4 ; pop               returns the tree
#
# The tree is returned and the caller does free it. The `new[]` buffer is not:
# zero delete[], zero json_free, zero json_delete in the whole function. It
# holds the entire registry file, which is exactly what the leaked chunks
# contained.
#
# PATCHED AT 0x34964, NOT AT THE EPILOGUE. 0x3496c and 0x34968 are both branch
# targets from error paths (0x348c8 and 0x34840) taken BEFORE `new[]` runs, so
# freeing r7 there would hand uninitialised stack to delete[]. Nothing branches
# to 0x34964 and r7 is written exactly once, at 0x34900, so the pointer is
# always the live buffer here.
#
# `operator new[]` pairs with `operator delete[]` (_ZdaPv, 0xc168) - not free,
# not json_free. Three different release functions are in play on this path and
# using the wrong one corrupts the heap rather than leaking.
#
# The json_strip_white_space result is ALSO leaked and is deliberately left for
# now: its pointer is consumed by the parse whose return overwrites r0, and
# freeing it depends on whether libjson's parser copies its input. Unverified,
# so untouched.
DELETE_ARRAY_PLT = 0xC168
JSON_PARSE_PLT = 0xBF58
IPC_BUF_STUB = 0x69444
IPC_BUF_SITES = ((0x34964, 0xEBFF5D7B),)


def b_encode(at, target, link=False):
    """ARM B/BL: offset counts from pc+8, in words, 24-bit signed."""
    off = (target - (at + 8)) >> 2
    if not -(1 << 23) <= off < (1 << 23):
        raise SystemExit(f"branch out of range: 0x{at:x} -> 0x{target:x}")
    op = 0xEB000000 if link else 0xEA000000
    return op | (off & 0xFFFFFF)


def build_cave():
    return [
        (CAVE + 0x00, 0xE92D400E, "push {r1, r2, r3, lr}"),
        (CAVE + 0x04, 0xE1A00007, "mov  r0, r7            @ the abandoned root"),
        (CAVE + 0x08, b_encode(CAVE + 0x08, JSON_DELETE_PLT, link=True),
         "bl   json_delete"),
        (CAVE + 0x0C, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (CAVE + 0x10, ORIG_AT_SITE, "ldr  r7, [r3, #8]      @ displaced original"),
        (CAVE + 0x14, b_encode(CAVE + 0x14, RETURN_TO), "b    0x2908c"),
    ]


def build_cave2():
    # r1 was loaded at 0x1ef9c and is consumed by the strtok at 0x1efa4;
    # free() clobbers r0-r3, so r1 is saved. Two registers keeps sp aligned.
    return [
        (CAVE2 + 0x00, 0xE92D4002, "push {r1, lr}"),
        (CAVE2 + 0x04, 0xE51B0034, "ldr  r0, [fp, #-52]    @ Base64Decode buffer"),
        (CAVE2 + 0x08, b_encode(CAVE2 + 0x08, FREE_PLT, link=True), "bl   free"),
        (CAVE2 + 0x0C, 0xE8BD4002, "pop  {r1, lr}"),
        (CAVE2 + 0x10, ORIG2_AT_SITE, "mov  r0, r6            @ displaced original"),
        (CAVE2 + 0x14, b_encode(CAVE2 + 0x14, RETURN2_TO), "b    0x1efa4"),
    ]


def build_cave3():
    # blne, not bl: a malformed document parses to NULL and must not be freed.
    blne = (b_encode(CAVE3 + 0x08, JSON_DELETE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (CAVE3 + 0x00, 0xE1A00004, "mov  r0, r4            @ the parsed document"),
        (CAVE3 + 0x04, 0xE3500000, "cmp  r0, #0"),
        (CAVE3 + 0x08, blne, "blne json_delete       @ NULL-guarded"),
        (CAVE3 + 0x0C, b_encode(CAVE3 + 0x0C, RETURN3_TO), "b    0x47ce4"),
    ]


def build_cave4():
    # At 0x1cc84 the function is about to return: r0-r3 and lr are all dead
    # (the epilogue restores pc from the stack), so nothing needs saving. fp is
    # callee-saved and still addresses the frame, and r6 still holds tree B.
    blne_del = (b_encode(CAVE4 + 0x08, JSON_DELETE_PLT, link=True)
                & 0x0FFFFFFF) | 0x10000000
    blne_free = (b_encode(CAVE4 + 0x14, FREE_PLT, link=True)
                 & 0x0FFFFFFF) | 0x10000000
    return [
        (CAVE4 + 0x00, 0xE1A00006, "mov  r0, r6            @ tree B, never freed"),
        (CAVE4 + 0x04, 0xE3500000, "cmp  r0, #0"),
        (CAVE4 + 0x08, blne_del, "blne json_delete"),
        (CAVE4 + 0x0C, 0xE51B0034, "ldr  r0, [fp, #-52]    @ Base64Encode buffer"),
        (CAVE4 + 0x10, 0xE3500000, "cmp  r0, #0"),
        (CAVE4 + 0x14, blne_free, "blne free"),
        (CAVE4 + 0x18, ORIG4_AT_SITE, "mov  r0, #0            @ displaced original"),
        (CAVE4 + 0x1C, b_encode(CAVE4 + 0x1C, RETURN4_TO), "b    0x1cc88"),
    ]


def build_cave5():
    # r4 is dead here (reassigned at 0x1cc24), so it carries str1 across strlen.
    return [
        (CAVE5 + 0x00, 0xE1A04000, "mov  r4, r0            @ str1 (r4 is dead here)"),
        (CAVE5 + 0x04, b_encode(CAVE5 + 0x04, STRLEN_PLT, link=True), "bl   strlen"),
        (CAVE5 + 0x08, 0xE92D4001, "push {r0, lr}          @ keep the length"),
        (CAVE5 + 0x0C, 0xE1A00004, "mov  r0, r4"),
        (CAVE5 + 0x10, b_encode(CAVE5 + 0x10, JSON_FREE_PLT, link=True),
         "bl   json_free         @ release str1"),
        (CAVE5 + 0x14, 0xE8BD4001, "pop  {r0, lr}          @ length back in r0"),
        (CAVE5 + 0x18, b_encode(CAVE5 + 0x18, RETURN5_TO), "b    0x1cc0c"),
    ]


def build_cave6():
    # Stash str2 in the spare word the alloca already reserves at [sp,#4].
    return [
        (CAVE6 + 0x00, b_encode(CAVE6 + 0x00, JSON_WRITE_PLT, link=True),
         "bl   json_write        @ displaced original"),
        (CAVE6 + 0x04, 0xE58D0004, "str  r0, [sp, #4]      @ stash str2"),
        (CAVE6 + 0x08, b_encode(CAVE6 + 0x08, RETURN6_TO), "b    0x1cc30"),
    ]


def build_cave7():
    # encrypt has returned; str2 is at [sp,#4], which the push shifts to
    # [sp,#12]. r0 holds encrypt's return and must survive.
    return [
        (CAVE7 + 0x00, 0xE92D4001, "push {r0, lr}          @ keep encrypt's result"),
        (CAVE7 + 0x04, 0xE59D000C, "ldr  r0, [sp, #12]     @ str2"),
        (CAVE7 + 0x08, b_encode(CAVE7 + 0x08, JSON_FREE_PLT, link=True),
         "bl   json_free         @ release str2"),
        (CAVE7 + 0x0C, 0xE8BD4001, "pop  {r0, lr}"),
        (CAVE7 + 0x10, ORIG7_AT_SITE, "sub  r2, fp, #52       @ displaced original"),
        (CAVE7 + 0x14, b_encode(CAVE7 + 0x14, RETURN7_TO), "b    0x1cc48"),
    ]


def build_cave8():
    blne = (b_encode(CAVE8 + 0x0C, JSON_FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (CAVE8 + 0x00, 0xE92D4004, "push {r2, lr}          @ r2 live at 0x29558"),
        (CAVE8 + 0x04, 0xE51B0364, "ldr  r0, [fp, #-868]   @ handler out-param"),
        (CAVE8 + 0x08, 0xE3500000, "cmp  r0, #0"),
        (CAVE8 + 0x0C, blne, "blne json_free         @ NULL-guarded"),
        (CAVE8 + 0x10, 0xE8BD4004, "pop  {r2, lr}"),
        (CAVE8 + 0x14, ORIG8_AT_SITE, "ldr  r3, [r2]          @ displaced original"),
        (CAVE8 + 0x18, b_encode(CAVE8 + 0x18, RETURN8_TO), "b    0x29550"),
    ]


def build_cave9():
    blne = (b_encode(CAVE9 + 0x0C, FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (CAVE9 + 0x00, 0xE92D4001, "push {r0, lr}"),
        (CAVE9 + 0x04, 0xE51B0660, "ldr  r0, [fp, #-1632]  @ HMAC digest buffer"),
        (CAVE9 + 0x08, 0xE3500000, "cmp  r0, #0"),
        (CAVE9 + 0x0C, blne, "blne free              @ NULL-guarded"),
        (CAVE9 + 0x10, 0xE8BD4001, "pop  {r0, lr}"),
        (CAVE9 + 0x14, ORIG9_AT_SITE, "sub  r0, fp, #44       @ displaced original"),
        (CAVE9 + 0x18, b_encode(CAVE9 + 0x18, RETURN9_TO), "b    0x29d80"),
    ]


def build_cave10():
    blne = (b_encode(CAVE10 + 0x0C, FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (CAVE10 + 0x00, 0xE92D4002, "push {r1, lr}          @ r1 consumed at 0x29dc8"),
        (CAVE10 + 0x04, 0xE51B0034, "ldr  r0, [fp, #-52]    @ authtoken base64 buffer"),
        (CAVE10 + 0x08, 0xE3500000, "cmp  r0, #0"),
        (CAVE10 + 0x0C, blne, "blne free"),
        (CAVE10 + 0x10, 0xE3A00000, "mov  r0, #0"),
        (CAVE10 + 0x14, 0xE50B0034, "str  r0, [fp, #-52]    @ poison the slot"),
        (CAVE10 + 0x18, 0xE8BD4002, "pop  {r1, lr}"),
        (CAVE10 + 0x1C, ORIG10_AT_SITE, "mov  r0, sl            @ displaced original"),
        (CAVE10 + 0x20, b_encode(CAVE10 + 0x20, RETURN10_TO), "b    0x29dc8"),
    ]


def build_freestr_stub():
    """strcpy(dest, src) then json_free(src), returning strcpy's result.

    Called with `bl`, returns via lr, so one copy serves every site. Four
    registers are pushed to keep sp 8-byte aligned; r1/r2 are caller-saved so
    restoring them into scratch on the way out is harmless.
    """
    s = FREESTR_STUB
    return [
        (s + 0x00, 0xE92D4007, "push {r0, r1, r2, lr}  @ dest, src, pad, lr"),
        (s + 0x04, b_encode(s + 0x04, STRCPY_PLT, link=True), "bl   strcpy"),
        (s + 0x08, 0xE59D0004, "ldr  r0, [sp, #4]      @ src = the json string"),
        (s + 0x0C, b_encode(s + 0x0C, JSON_FREE_PLT, link=True), "bl   json_free"),
        (s + 0x10, 0xE59D0000, "ldr  r0, [sp]          @ strcpy's return value"),
        (s + 0x14, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (s + 0x18, 0xE12FFF1E, "bx   lr"),
    ]


def build_cmpfree_stub(at, plt, label):
    """cmp(str, ...) then json_free(str), preserving the comparison result.

    The string arrives in r0 and is dead after the comparison at every site
    this serves. The result is stashed in the saved-r1 slot across json_free,
    which clobbers r0-r3.
    """
    return [
        (at + 0x00, 0xE92D4007, f"push {{r0, r1, r2, lr}}  @ {label}"),
        (at + 0x04, b_encode(at + 0x04, plt, link=True), f"bl   {label}"),
        (at + 0x08, 0xE58D0004, "str  r0, [sp, #4]      @ stash the result"),
        (at + 0x0C, 0xE59D0000, "ldr  r0, [sp]          @ the json string"),
        (at + 0x10, b_encode(at + 0x10, JSON_FREE_PLT, link=True), "bl   json_free"),
        (at + 0x14, 0xE59D0004, "ldr  r0, [sp, #4]      @ result back"),
        (at + 0x18, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (at + 0x1C, 0xE12FFF1E, "bx   lr"),
    ]


def build_ipc_buf_stub():
    """json_parse_unformatted(strip_result), then delete[] the new[] file buffer.

    Called with `bl` and returns via `lr`. r7 still holds the buffer here and is
    saved so the stub can read it after the parse clobbers r0-r3; the parse
    result is stashed on the stack across the delete[] for the same reason.
    Four registers keeps sp 8-byte aligned.
    """
    s = IPC_BUF_STUB
    blne = (b_encode(s + 0x14, DELETE_ARRAY_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (s + 0x00, 0xE92D4083, "push {r0, r1, r7, lr}  @ strip result, pad, buffer, lr"),
        (s + 0x04, b_encode(s + 0x04, JSON_PARSE_PLT, link=True),
         "bl   json_parse_unformatted"),
        (s + 0x08, 0xE58D0000, "str  r0, [sp]          @ stash the parsed tree"),
        (s + 0x0C, 0xE59D0008, "ldr  r0, [sp, #8]      @ the new[] file buffer"),
        (s + 0x10, 0xE3500000, "cmp  r0, #0"),
        (s + 0x14, blne, "blne operator delete[]"),
        (s + 0x18, 0xE59D0000, "ldr  r0, [sp]          @ tree back"),
        (s + 0x1C, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (s + 0x20, 0xE12FFF1E, "bx   lr"),
    ]


def build_printf2_stub():
    """HttpResponse_printf(resp, fmt, s1, s2) then json_free(s1), json_free(s2).

    r1 is the format string - a static literal - and is saved only to keep sp
    8-byte aligned; it is never freed.
    """
    s = PRINTF2_STUB
    blne1 = (b_encode(s + 0x10, JSON_FREE_PLT, link=True) & 0x0FFFFFFF) | 0x10000000
    blne2 = (b_encode(s + 0x1C, JSON_FREE_PLT, link=True) & 0x0FFFFFFF) | 0x10000000
    return [
        (s + 0x00, 0xE92D400E, "push {r1, r2, r3, lr}  @ fmt, s1, s2, lr"),
        (s + 0x04, b_encode(s + 0x04, HTTPRESP_PRINTF, link=True),
         "bl   HttpResponse_printf"),
        (s + 0x08, 0xE59D0004, "ldr  r0, [sp, #4]      @ s1"),
        (s + 0x0C, 0xE3500000, "cmp  r0, #0"),
        (s + 0x10, blne1, "blne json_free"),
        (s + 0x14, 0xE59D0008, "ldr  r0, [sp, #8]      @ s2"),
        (s + 0x18, 0xE3500000, "cmp  r0, #0"),
        (s + 0x1C, blne2, "blne json_free"),
        (s + 0x20, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (s + 0x24, 0xE12FFF1E, "bx   lr"),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--out", required=True)
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--tsv", action="store_true",
                    help="emit patches.tsv rows instead of writing a binary, so "
                         "a reflash keeps these fixes. Offsets are FILE offsets "
                         "(VA - 0x8000), matching the rest of the table.")
    args = ap.parse_args()

    data = bytearray(open(args.binary, "rb").read())

    def rd(va):
        return struct.unpack_from("<I", data, va - TEXT_BIAS)[0]

    def wr(va, word):
        struct.pack_into("<I", data, va - TEXT_BIAS, word)

    # Guard: refuse unless the site still holds the exact instruction we mean
    # to displace. A different build, or an already-patched one, must not be
    # silently rewritten.
    at_site = rd(PATCH_SITE)
    if at_site != ORIG_AT_SITE:
        sys.exit(f"REFUSING: 0x{PATCH_SITE:x} holds 0x{at_site:08x}, "
                 f"expected 0x{ORIG_AT_SITE:08x} (ldr r7,[r3,#8])")

    # Guard: the cave must still be the stock dead code, not something else's
    # patch. P13 uses HttpServer_destructor at 0x6c8c0; this is a different one.
    cave_words = [rd(CAVE + i) for i in range(0, CAVE_END - CAVE, 4)]
    if all(w == 0 for w in cave_words):
        sys.exit("REFUSING: cave is all zeroes -- unexpected, verify the image")

    at_site2 = rd(PATCH2_SITE)
    if at_site2 != ORIG2_AT_SITE:
        sys.exit(f"REFUSING: 0x{PATCH2_SITE:x} holds 0x{at_site2:08x}, "
                 f"expected 0x{ORIG2_AT_SITE:08x} (mov r0,r6)")

    at_site3 = rd(PATCH3_SITE)
    if at_site3 != ORIG3_AT_SITE:
        sys.exit(f"REFUSING: 0x{PATCH3_SITE:x} holds 0x{at_site3:08x}, "
                 f"expected 0x{ORIG3_AT_SITE:08x} (b 0x47ce4)")

    at_site4 = rd(PATCH4_SITE)
    if at_site4 != ORIG4_AT_SITE:
        sys.exit(f"REFUSING: 0x{PATCH4_SITE:x} holds 0x{at_site4:08x}, "
                 f"expected 0x{ORIG4_AT_SITE:08x} (mov r0,#0)")

    cave = build_cave()
    cave2 = build_cave2()
    cave3 = build_cave3()
    cave4 = build_cave4()
    for site, want, name in ((PATCH5_SITE, ORIG5_AT_SITE, "bl strlen"),
                             (PATCH6_SITE, ORIG6_AT_SITE, "bl json_write"),
                             (PATCH7_SITE, ORIG7_AT_SITE, "sub r2,fp,#52"),
                             (PATCH8_SITE, ORIG8_AT_SITE, "ldr r3,[r2]"),
                             (PATCH9_SITE, ORIG9_AT_SITE, "sub r0,fp,#44"),
                             (PATCH10_SITE, ORIG10_AT_SITE, "mov r0,sl")):
        got = rd(site)
        if got != want:
            sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, "
                     f"expected 0x{want:08x} ({name})")
    cave5 = build_cave5()
    cave6 = build_cave6()
    cave7 = build_cave7()
    if cave4[-1][0] + 4 > CAVE:
        sys.exit("REFUSING: cave4 runs into the cave1/2 region")
    if cave3[-1][0] + 4 > CAVE4:
        sys.exit("REFUSING: cave3 and cave4 overlap")
    if cave5[-1][0] + 4 > CAVE6:
        sys.exit("REFUSING: cave5 and cave6 overlap")
    if cave6[-1][0] + 4 > CAVE7:
        sys.exit("REFUSING: cave6 and cave7 overlap")
    if cave7[-1][0] + 4 > CAVE7_END:
        sys.exit("REFUSING: cave7 overruns its dead region")
    cave8 = build_cave8()
    cave9 = build_cave9()
    if cave8[-1][0] + 4 > CAVE9:
        sys.exit("REFUSING: cave8 and cave9 overlap")
    cave10 = build_cave10()
    for site, want in STRCPY_SITES:
        got = rd(site)
        if got != want:
            sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, expected "
                     f"0x{want:08x} (bl strcpy after json_as_string)")
    freestr = build_freestr_stub()
    for site, want in STRNCMP_SITES + STRCMP_SITES + PRINTF2_SITES + IPC_BUF_SITES:
        got = rd(site)
        if got != want:
            sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, expected "
                     f"0x{want:08x} (cmp after json_as_string)")
    ncmp = build_cmpfree_stub(FREE_STRNCMP_STUB, STRNCMP_PLT, "strncmp")
    scmp = build_cmpfree_stub(FREE_STRCMP_STUB, STRCMP_PLT, "strcmp")
    if ncmp[-1][0] + 4 > FREE_STRCMP_STUB:
        sys.exit("REFUSING: the two cmp stubs overlap")
    printf2 = build_printf2_stub()
    ipcbuf = build_ipc_buf_stub()
    if printf2[-1][0] + 4 > IPC_BUF_STUB:
        sys.exit("REFUSING: printf2 and ipc stubs overlap")
    if ipcbuf[-1][0] + 4 > CMPFREE_CAVE_END:
        sys.exit("REFUSING: ipc stub overruns its dead region")
    if scmp[-1][0] + 4 > PRINTF2_STUB:
        sys.exit("REFUSING: cmp stubs and printf2 stub overlap")
    if printf2[-1][0] + 4 > CMPFREE_CAVE_END:
        sys.exit("REFUSING: stubs overrun their dead region")
    if cave10[-1][0] + 4 > FREESTR_STUB:
        sys.exit("REFUSING: cave10 and the freestr stub overlap")
    if freestr[-1][0] + 4 > CAVE10_END:
        sys.exit("REFUSING: freestr stub overruns its dead region")
    if cave9[-1][0] + 4 > CAVE10:
        sys.exit("REFUSING: cave9 and cave10 overlap")
    if cave10[-1][0] + 4 > CAVE10_END:
        sys.exit("REFUSING: cave10 overruns its dead region")
    if cave2[-1][0] + 4 > CAVE_END:
        sys.exit("REFUSING: cave code overruns the dead region")
    if cave[-1][0] + 4 > CAVE2:
        sys.exit("REFUSING: the two cave stubs overlap")
    if cave3[-1][0] + 4 > CAVE:
        sys.exit("REFUSING: cave3 runs into the cave1/2 region")

    print(f"binary        : {args.binary}")
    print(f"cave region   : 0x{CAVE:08x}..0x{CAVE_END:08x} "
          f"({CAVE_END - CAVE} bytes, using {(len(cave) + len(cave2)) * 4})")
    print()
    print("LEAK 1 - abandoned parameter tree")
    print(f"  site 0x{PATCH_SITE:08x}  0x{at_site:08x} -> "
          f"0x{b_encode(PATCH_SITE, CAVE):08x}  (b 0x{CAVE:x})")
    for va, word, note in cave:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAK 2 - Base64Decode output buffer")
    print(f"  site 0x{PATCH2_SITE:08x}  0x{at_site2:08x} -> "
          f"0x{b_encode(PATCH2_SITE, CAVE2):08x}  (b 0x{CAVE2:x})")
    for va, word, note in cave2:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAK 3 - tuxedoapi.html parsed document")
    print(f"  site 0x{PATCH3_SITE:08x}  0x{at_site3:08x} -> "
          f"0x{b_encode(PATCH3_SITE, CAVE3):08x}  (b 0x{CAVE3:x})")
    for va, word, note in cave3:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAK 4 - getPartitionStatus response wrapper + Base64Encode buffer")
    print(f"  site 0x{PATCH4_SITE:08x}  0x{at_site4:08x} -> "
          f"0x{b_encode(PATCH4_SITE, CAVE4):08x}  (b 0x{CAVE4:x})")
    for va, word, note in cave4:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAKS 5 and 6 - the two json_write results in getPartitionStatus")
    for site, c, cv in ((PATCH5_SITE, CAVE5, cave5),
                        (PATCH6_SITE, CAVE6, cave6),
                        (PATCH7_SITE, CAVE7, cave7)):
        print(f"  site 0x{site:08x}  0x{rd(site):08x} -> "
              f"0x{b_encode(site, c):08x}  (b 0x{c:x})")
        for va, word, note in cv:
            print(f"    0x{va:08x}  {word:08x}   {note}")

    print()
    print("LEAK 7 - handler out-param string abandoned by the caller")
    print(f"  site 0x{PATCH8_SITE:08x}  0x{rd(PATCH8_SITE):08x} -> "
          f"0x{b_encode(PATCH8_SITE, CAVE8):08x}  (b 0x{CAVE8:x})")
    for va, word, note in cave8:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAK 8 - authtoken HMAC digest buffer in WnmpDir_service")
    print(f"  site 0x{PATCH9_SITE:08x}  0x{rd(PATCH9_SITE):08x} -> "
          f"0x{b_encode(PATCH9_SITE, CAVE9):08x}  (b 0x{CAVE9:x})")
    for va, word, note in cave9:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAK 9 - authtoken base64 buffer in WnmpDir_service")
    print(f"  site 0x{PATCH10_SITE:08x}  0x{rd(PATCH10_SITE):08x} -> "
          f"0x{b_encode(PATCH10_SITE, CAVE10):08x}  (b 0x{CAVE10:x})")
    for va, word, note in cave10:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    print()
    print("LEAK 10 - json_as_string results never freed (3 strcpy sites, 1 stub)")
    for va, word, note in freestr:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    for site, _w in STRCPY_SITES:
        print(f"  site 0x{site:08x}  0x{rd(site):08x} -> "
              f"0x{b_encode(site, FREESTR_STUB, link=True):08x}  (bl stub)")
    print()
    print("LEAK 11 - json_as_string feeding comparisons (3 sites, 2 stubs)")
    for va, word, note in ncmp + scmp:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    for site, _w in STRNCMP_SITES:
        print(f"  site 0x{site:08x} -> 0x{b_encode(site, FREE_STRNCMP_STUB, link=True):08x}")
    for site, _w in STRCMP_SITES:
        print(f"  site 0x{site:08x} -> 0x{b_encode(site, FREE_STRCMP_STUB, link=True):08x}")
    print()
    print("LEAK 12 - tuxedoapi.html: two strings per list entry")
    for va, word, note in printf2:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    for site, _w in PRINTF2_SITES:
        print(f"  site 0x{site:08x} -> 0x{b_encode(site, PRINTF2_STUB, link=True):08x}")
    print()
    print("LEAK 13 - IPC path: the registry file buffer (~38.5 kB per message)")
    for va, word, note in ipcbuf:
        print(f"    0x{va:08x}  {word:08x}   {note}")
    for site, _w in IPC_BUF_SITES:
        print(f"  site 0x{site:08x} -> 0x{b_encode(site, IPC_BUF_STUB, link=True):08x}")

    if args.tsv:
        rows = []
        for va, word, note in (cave + cave2 + cave3 + cave4 + cave5 + cave6
                               + cave7 + cave8 + cave9 + cave10 + freestr
                               + ncmp + scmp + printf2 + ipcbuf):
            rows.append((f"P15-leakfix-cave-{va:x}", va, rd(va), word,
                         note.split("@")[0].strip()))
        sites = [(PATCH_SITE, CAVE), (PATCH2_SITE, CAVE2), (PATCH3_SITE, CAVE3),
                 (PATCH4_SITE, CAVE4), (PATCH5_SITE, CAVE5), (PATCH6_SITE, CAVE6),
                 (PATCH7_SITE, CAVE7), (PATCH8_SITE, CAVE8), (PATCH9_SITE, CAVE9),
                 (PATCH10_SITE, CAVE10)]
        for site, cv in sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, cv), "redirect into leak-fix stub"))
        for site, _w in STRCPY_SITES:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, FREESTR_STUB, link=True),
                         "strcpy + json_free stub"))
        for site, _w in STRNCMP_SITES:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, FREE_STRNCMP_STUB, link=True),
                         "strncmp + json_free stub"))
        for site, _w in STRCMP_SITES:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, FREE_STRCMP_STUB, link=True),
                         "strcmp + json_free stub"))
        for site, _w in PRINTF2_SITES:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, PRINTF2_STUB, link=True),
                         "printf + json_free x2 stub"))
        for site, _w in IPC_BUF_SITES:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, IPC_BUF_STUB, link=True),
                         "IPC: parse then delete[] the registry file buffer"))
        def le(w):
            return struct.pack("<I", w).hex()
        for name, va, old, new, desc in rows:
            print("%s	/opt/webserver/Barracuda	0x%x	%s	%s	%s"
                  % (name, va - TEXT_BIAS, le(old), le(new), desc))
        return

    if args.check_only:
        print("check-only: nothing written")
        return

    all_stubs = (cave + cave2 + cave3 + cave4 + cave5 + cave6 + cave7
                 + cave8 + cave9 + cave10 + freestr + ncmp + scmp + printf2
                 + ipcbuf)
    # ONE list drives both the writes and the self-check below. They cannot
    # diverge, which is the failure this structure exists to prevent: the write
    # list was once edited on one line while it spanned two, silently dropping a
    # whole stub while the site that branches into it was still redirected.
    site_writes = [
        (PATCH_SITE, CAVE, False), (PATCH2_SITE, CAVE2, False),
        (PATCH3_SITE, CAVE3, False), (PATCH4_SITE, CAVE4, False),
        (PATCH5_SITE, CAVE5, False), (PATCH6_SITE, CAVE6, False),
        (PATCH7_SITE, CAVE7, False), (PATCH8_SITE, CAVE8, False),
        (PATCH9_SITE, CAVE9, False), (PATCH10_SITE, CAVE10, False),
    ]
    site_writes += [(s, FREESTR_STUB, True) for s, _ in STRCPY_SITES]
    site_writes += [(s, FREE_STRNCMP_STUB, True) for s, _ in STRNCMP_SITES]
    site_writes += [(s, FREE_STRCMP_STUB, True) for s, _ in STRCMP_SITES]
    site_writes += [(s, PRINTF2_STUB, True) for s, _ in PRINTF2_SITES]
    site_writes += [(s, IPC_BUF_STUB, True) for s, _ in IPC_BUF_SITES]

    intended = {va: word for va, word, _ in all_stubs}
    for site, target, linked in site_writes:
        intended[site] = b_encode(site, target, link=linked)
    for va, word in intended.items():
        wr(va, word)

    # SELF-CHECK, and it exists because the tool once silently emitted a binary
    # with the call sites redirected but the STUBS MISSING. A two-line write
    # list lost a term to a one-line edit, the build succeeded, the dry-run
    # printed the stub it had not written, and the result was a `bl` into the
    # middle of an unrelated live function. It reached the panel.
    #
    # Every word this run intends to change is read back from the produced
    # image and compared. A mismatch is fatal, not a warning.
    orig = open(args.binary, "rb").read()
    bad = []
    for va, want in intended.items():
        got = struct.unpack_from("<I", data, va - TEXT_BIAS)[0]
        if got != want:
            bad.append(f"0x{va:x}: wrote 0x{got:08x}, intended 0x{want:08x}")
    if bad:
        sys.exit("REFUSING: produced image does not match intent:\n  "
                 + "\n  ".join(bad))
    changed = sum(1 for i in range(0, len(data), 4)
                  if data[i:i + 4] != orig[i:i + 4])
    if changed != len(intended):
        sys.exit(f"REFUSING: {changed} words differ from the input but "
                 f"{len(intended)} were intended - the image has changes this "
                 f"run did not make, or is missing some it did")
    print(f"  self-check: {len(intended)} words, all present and correct")

    with open(args.out, "wb") as fh:
        fh.write(data)
    print(f"wrote {args.out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
