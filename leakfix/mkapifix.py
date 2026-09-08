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
# The json_strip_white_space result is ALSO leaked, and is now freed too.
#
# ✅ OWNERSHIP VERIFIED IN libjson.so.7.6.1 RATHER THAN ASSUMED - this was the
# open question that kept it untouched, and freeing wrongly here corrupts the
# heap instead of leaking:
#
#   json_strip_white_space -> JSONWorker::RemoveWhiteSpaceAndCommentsC(
#                                 std::string const&, bool)
#       takes its input BY std::string, so the result is a fresh buffer.
#   json_parse_unformatted -> JSONWorker::parse_unformatted(std::string const&)
#       ALSO takes std::string, so the tree holds copies and retains NO pointer
#       into the buffer it parsed. Freeing the strip result the moment the parse
#       returns is therefore safe.
#   json_free itself contains a `free@plt`, so it is the right deallocator for
#   a libjson-allocated string.
DELETE_ARRAY_PLT = 0xC168
JSON_PARSE_PLT = 0xBF58
JSON_STRIP_PLT = 0xC2AC
IPC_BUF_STUB = 0x69444
IPC_BUF_SITES = ((0x34964, 0xEBFF5D7B),)

# LEAK 14 and 15 - registeredClients (0x34980), the BULK of the IPC leak.
#
#   r8 = scene_getRootNodeOfObjects(file)   the parsed registry tree
#   r7 = json_size(r8);  r6 = 0
#   while r6 < r7:
#       r5 = json_new()                     one object per entry
#       r4 = json_at(r8, r6++)              a node INSIDE r8
#       if json_size(r4) <= 4: continue
#       4 x { json_get(r4,key); json_as_string(); json_new_a(name,str);
#             json_push_back(r5, node) }
#       json_push_back(sl, r5)              into the CALLER's array
#   return 5                                a CONSTANT, never the tree
#
# LEAK 14: the four json_as_string results leak once PER ENTRY - eight per
# message with the registry's two entries. Measured as 57x16 B + 56x40 B +
# 40x32 B and friends, ~4.4 kB per message, the largest single item on the path.
#
# LEAK 15: r8 is never freed. No json_delete appears anywhere in the function,
# and the tree is not returned, so on return it is unreachable.
#
# 🔑 BOTH FREES ARE SAFE FOR THE SAME VERIFIED REASON: json_new_a reaches
# JSONNode::JSONNode(std::string const&, std::string const&), so it COPIES the
# value. Only copies are pushed into the caller's array, and json_at returns a
# node inside r8 that is used solely within its own loop iteration. Nothing
# outside the function points into r8 or at the strings.
#
# The tree stub must restore r0 = 5: `mov r0,#5` is set at 0x34a84 inside the
# loop-condition block and json_delete clobbers r0. 0x34a8c is reached ONLY by
# falling through from 0x34a88 (the `bls` at 0x349d8 targets 0x34a80), so
# nothing branches into the displaced instruction.
JSON_NEW_A_PLT = 0xBFE8
IPC_NEWA_STUB = 0x69474
IPC_TREE_STUB = 0x69498
IPC_NEWA_SITES = (
    (0x349EC, 0xEBFF5D7D),
    (0x34A14, 0xEBFF5D73),
    (0x34A3C, 0xEBFF5D69),
    (0x34A64, 0xEBFF5D5F),
)
IPC_TREE_SITE = 0x34A8C
IPC_TREE_ORIG = 0xE28DD004    # add sp, sp, #4
IPC_TREE_RETURN = 0x34A90

# LEAK 16 - registeredClients abandons an EMPTY object per SKIPPED entry.
#
#   349ac  r5 = json_new()          <-- allocated BEFORE the entry is vetted
#   349bc  r4 = json_at(r8, r6++)
#   349c4  json_size(r4)
#   349d8  bls 34a80                <-- skip: r5 is never pushed and never freed
#
# The object is created before the `json_size(r4) > 4` test that decides whether
# it will be used, so every skipped entry leaks one. MEASURED: the registry
# parses to SIX entries and the trace takes this branch for ALL SIX, so this
# fires 6 times per message and 0 entries ever reach the four json_as_string
# calls below it.
#
# Freed on the skip branch itself. json_delete preserves r4-r8 and sl (callee
# -saved), which is everything 0x34a80 needs, and r0 is reloaded with #5 at
# 0x34a84 immediately after the join. r5 is always initialised here: it is set
# at 0x349b4, before this branch.
IPC_SKIP_STUB = 0x694B0
IPC_SKIP_SITE = 0x349D8
IPC_SKIP_ORIG = 0x9A000028    # bls 0x34a80
IPC_SKIP_RETURN = 0x34A80

# LEAK 17 - pushEventsToClientsDevAdded never frees TREE A.
#
#   13260  r7 = json_new()      the event payload, built up over 4 nodes
#   13394  json_delete(r5)      only the registeredClients ARRAY is freed
#   13398  add sp, sp, #260     r7 abandoned
#
# r7 is not returned and nothing outside holds it: json_write(r7) appears only
# inside the per-client loop, which is empty here. Freed at the epilogue.
# 0x13398 is reached only by falling through from 0x13394 (0x13390 is the
# branch target), and the existing code already lets json_delete clobber r0,
# so no return value is disturbed.
#
# ⚠ NOT PATCHED, DELIBERATELY: the three per-client leaks inside that loop -
# json_as_string 0x13314, json_write 0x13350, curl_easy_escape 0x13360. The
# loop body executes ZERO times (measured: 0x132fc runs 0 times over 3
# messages) because registeredClients pushes nothing, so patching them would
# ship code no test on this rig can exercise. That is exactly the mistake this
# file already records once. They are real defects; leave them until a registry
# with a >4-field entry exists to drive them.
# ⚠ Same caveat applies to LEAK 14 above, which is already built: correct by
# construction but never executed on this bench.
IPC_TREEA_STUB = 0x694C0
IPC_TREEA_SITE = 0x13398
IPC_TREEA_ORIG = 0xE28DDF41   # add sp, sp, #260
IPC_TREEA_RETURN = 0x1339C

# LEAK 18 - scene_getRootNodeOfObjects discards a getErrorNode result.
#
#   34954  movne r0, sl          sl = 0
#   34958  bl getErrorNode       builds a node and returns it
#   3495c  mov r0, r7            <-- the node pointer is overwritten HERE
#   34960  bl json_strip_white_space
#
# On the SUCCESS path the vendor calls getErrorNode(0) and throws the result
# away on the very next instruction. getErrorNode does json_new + json_new_a +
# json_push_back, so that is one abandoned node per message.
#
# This is the safest free on the whole path: the value is provably dead one
# instruction later, in the original code, on every path that reaches it.
# Nothing branches to 0x34958 - it is fall-through only from 0x34950/0x34954 -
# and the OTHER two getErrorNode calls (0x3483c, 0x348b8) keep their results,
# so only this site is redirected.
GET_ERROR_NODE = 0x338E8
IPC_ERRNODE_STUB = 0x694D4
IPC_ERRNODE_SITES = ((0x34958, 0xEBFFFBE2),)

# LEAK 19 - EVERY json_strip_white_space RESULT IN THE IMAGE IS LEAKED.
#
# The image makes 44 json_strip_white_space calls and ALL 44 are immediately
# followed by `bl json_parse_unformatted` - adjacent, no exceptions:
#
#   3fdec  bl json_strip_white_space   -> r0 = a fresh stripped copy
#   3fdf0  bl json_parse_unformatted   -> r0 OVERWRITTEN by the tree
#
# so the only pointer to the copy is destroyed by the very call that consumes
# it. Same shape as the parameter tree at 0x29088 and the two json_write
# results in getPartitionStatus: destroyed at birth.
#
# FOUND BY MEASUREMENT, NOT BY READING: /scene_configuration.html leaked 727.9
# then 726.7 B/request (two runs agreeing, with /tuxedoapi.html reading 0.0 in
# the same session as a negative control). heapwalk pinned it to ONE 648-byte
# chunk per request, and chunkdiff dumped the contents - the voice-command
# vocabulary. voicecommandglobal.json is exactly 640 bytes, and 640 + 8 = 648.
#
# WHY ONE SHARED STUB IS SAFE AT ALL 43 SITES, with no per-site analysis:
#   * the two calls are ADJACENT at every site, so r0 on entry to the parse is
#     always the strip result - there is no site where it is something else;
#   * json_parse_unformatted reaches JSONWorker::parse_unformatted(std::string
#     const&), so the tree holds copies and retains no pointer into the input
#     (verified in libjson.so.7.6.1, see LEAK 13);
#   * the original code already lets the parse's return value destroy the
#     pointer, so nothing downstream can be using it;
#   * json_free is libjson's deallocator (it contains a free@plt), which is the
#     right one for a libjson-allocated string - NOT plain free.
# The stub returns via lr, so one 36-byte stub serves every site regardless of
# location, exactly like the strcpy/strcmp free stubs above.
#
# 0x34964 is EXCLUDED: it is already redirected to IPC_BUF_STUB, which frees
# this same string AND the operator new[] buffer that only that site has.
# LEAK 20 - getEScenes (0x16520), the /GetSceneList handler: ~780 B per request.
#
# ATTRIBUTION, and a bl-search would never have found it. /GetSceneList is
# dispatched by ID, not by name->function pointer:
#
#   Test1Module_constructor (0x15740) registers the endpoint table
#     base 0x8ab14, 74 entries of {name1_ptr, name2_ptr, id}
#   with the handler at 0x15778, which decodes the id:
#     ldrh r1,[r0] -> 0x8039 ; bic #0xf000 -> 0x39 ; sub #8 -> 49
#     ldr pc,[pc,r1,lsl #2]  -> jump table at 0x15798, entry 49 = 0x1585c
#   0x159a0 is a TAIL BRANCH thunk: mov r1,r3 ; b getEScenes
#
# THE FUNCTION IS STRAIGHT-LINE - no conditional branches at all - so every
# pointer below is always initialised and nothing can skip the epilogue:
#
#   16540  r6 = json_new()               TREE A, the payload
#   1656c  json_write(r6) -> r0          STRING 1
#   16570  strlen(r0) -> r4              <- r0 destroyed at birth, STRING 1 leaks
#   1657c  r7 = json_new()               TREE B, the wrapper
#   165a4  json_write(r6) -> r0          STRING 2
#   165b8  encrypt(...)                  <- r0 clobbered, STRING 2 leaks
#   165c8  Base64Encode -> [fp-48]       malloc'd, copied by json_new_a, leaks
#   165e8  json_write_formatted(r7)      returned via the out-param, caller owns
#   165f8  json_delete(r6)               TREE A freed; TREE B and [fp-48] are NOT
#
# Structurally identical to getPartitionStatus (LEAKS 4-7) - the same four leaks
# in the same order in a sibling function.
#
# THIS PATCH takes the two the epilogue can reach safely: TREE B and the Base64
# buffer. 0x165f8 is redirected to a stub that performs the displaced
# json_delete(r6), then frees r7 and [fp-48]. r7 is callee-saved so json_delete
# preserves it; fp is live; 0x165fc sets r0 = 0 so the stub's r0 is irrelevant.
# STRING 1 and STRING 2 are left for a later increment - freeing them needs the
# strlen-result and stack-argument care that LEAKS 5 and 6 documented, and this
# increment is measured on its own first.
GETESCENES_STUB = 0x69510
GETESCENES_SITES = ((0x165F8, 0xEBFFD506),)

# LEAK 21 - getEScenes STRING 1: json_write(r6) destroyed by strlen's return.
#
#   1656c  bl json_write   -> r0 = the serialised tree
#   16570  bl strlen       -> r0 becomes the LENGTH; the string pointer is gone
#
# Identical to LEAK 5 in getPartitionStatus. Freed by wrapping the strlen call:
# stash the string, take the length, release the string, hand the length back.
# The pointer is provably the json_write result because the two calls are
# adjacent and nothing writes r0 between them.
#
# ⚠ STRING 2 at 0x165a4 is NOT patched here and needs more care: it is consumed
# by `encrypt` at 0x165b8, which takes a STACK argument (`str r5,[sp]` at
# 0x165ac), so a stub must not push. The registers dead after that call in this
# straight-line function are r4, r8 and r9, so the shape would be
# `mov r4,r0 ; mov r9,lr ; bl encrypt ; mov r8,r0 ; json_free(r4) ; mov r0,r8 ;
# bx r9` - three stashes and a custom return, the most delicate stub in this
# file. Measured on its own increment before being written.
# 🚨 BUILT, MEASURED, AND DELIBERATELY NOT SHIPPED. Redirecting 0x16570 changed
# the leak by NOTHING: /GetSceneList read 491.5 B/request with and without it, on
# two runs each, and the chunk histogram showed no row disappearing either. So
# either the string is already released somewhere, or its effect is below both
# instruments.
#
# An unverifiable free is not worth shipping: if that json_write result is not
# actually caller-owned at 0x16570, freeing it is a double-free, and the upside is
# measurably zero. Same reasoning that left the unreachable per-client leaks
# alone. The stub and its site are kept here, disabled, so the next attempt knows
# this was tried and what it produced rather than re-deriving it.
#
# To re-enable for another look: restore the site tuple below and re-measure with
# leakfix/sceneleak.sh, which is the sensitive instrument - the RSS slope is
# page-quantised at 4 kB, so 144 kB over 300 requests cannot resolve a change
# smaller than about 14 B/request.
STRLEN_PLT = 0xBCC4
ESCENES_STR1_STUB = 0x69538
ESCENES_STR1_SITES = ()          # was ((0x16570, 0xEBFFD5D3),)

# LEAK 22 - getEScenes STRING 2: json_write destroyed by encrypt's return.
#
#   165a4  bl json_write   -> r0 = the serialised tree
#   165ac  str r5, [sp]     <- encrypt takes a STACK ARGUMENT
#   165b8  bl encrypt      -> r0 becomes the ciphertext; the string is gone
#
# ⚠ A STUB HERE MUST NOT PUSH. [sp] holds encrypt's fifth argument, so moving sp
# by even one word hands it the wrong value. That rules out the stack-stash shape
# every other stub in this file uses.
#
# Instead it stashes in registers that are provably dead. getEScenes is
# straight-line, and r4, r8 and r9 are each consumed into an argument register
# BEFORE the call and never read again:
#
#   165a8  mov r3, r8      <- r8 consumed
#   165b0  mov r2, r9      <- r9 consumed
#   165b4  mov r1, r4      <- r4 consumed
#   165b8  bl encrypt      <- nothing after this reads r4, r8 or r9
#
# and all three are callee-saved, so encrypt and json_free preserve them and the
# function's own epilogue at 0x16608 restores the caller's values from the stack.
# lr is saved in r9 because `bl json_free` would otherwise destroy the return
# address; the stub returns with `bx r9`.
# 🚨 ALSO BUILT, MEASURED, AND NOT SHIPPED - same verdict as LEAK 21, and the two
# together are the informative result. /GetSceneList read 491.5 B/request with
# STRING 1 freed, with STRING 2 freed, and with neither: identical, two runs each.
# The stub itself is sound (the server answered 302 with all four listeners up
# afterwards), it just releases nothing that was accumulating.
#
# 🔑 WHAT THE TWO NULL RESULTS TOGETHER SAY: the residual is NOT the json_write
# strings. The chunk histogram after LEAK 20 shows, per request, roughly
# 5x40 B, 3x32 B, 2.7x16 B, 1x64 B and 1x56 B - a dozen small chunks, which is
# the shape of a JSON TREE, not of two large serialised strings. Freeing strings
# was the wrong target and the measurements said so twice before any of it
# shipped.
#
# Next step for whoever picks this up: find which tree. getEScenes' own two trees
# are now both freed, so look OUTSIDE it - the likeliest candidate is STRING 3,
# `json_write_formatted(r7)` at 0x165e8, handed to the caller through the
# out-param at [fp-56] and possibly never released there (the shape of LEAK 7),
# or an allocation inside encrypt/Base64Encode. Drive it with
# leakfix/sceneleak.sh and dump the growing sizes with chunkdiff.py, which is
# what named the IPC leaks.
ENCRYPT_FN = 0x1CDF8
ESCENES_STR2_STUB = 0x6955C
ESCENES_STR2_SITES = ()          # was ((0x165B8, 0xEB001A0E),)

# LEAK 23 - checkIfSceneExists abandons its parsed tree on EVERY call.
#
#   34c00  bl   scene_getRootNodeOfObjects  -> r6 = the parsed tree
#   34c04  subs r6, r0, #0 ; beq 34c50      -> r6 NULL only if the parse failed
#   34c24  loop: json_at / json_get / json_as_int, r5 = 1 on an id match
#   34c50  mov  r0, r5                      <- returns an INT; THE TREE IS DROPPED
#   34c54  pop  {r4,r5,r6,r7,r8,pc}
#
# Nothing derived from the tree escapes: the loop reads ids with json_as_int,
# which returns a value, and the result r5 is a flag. Both exits converge on
# 0x34c50, and the NULL path is exactly the one that arrives with r6 = 0, so one
# NULL-guarded json_delete at the convergence covers both.
#
# MEASURED on a session that actually dispatches - 300 requests to cmd=141:
#   40 B +374, 32 B +361, 24 B +128, 16 B +75, about 107 B/request, one tree each.
# Every reply was 200 with a 43-byte body, not the empty bail-out.
#
# The stub does NOT push and does not need lr: checkIfSceneExists returns through
# `pop {...,pc}` off the frame built at 0x34bf0, so `bl json_delete` clobbering lr
# is harmless, and r5/r6 are callee-saved so json_delete preserves both.
#
# The site is a `b`, not a `bl` - the stub performs the displaced `mov r0, r5` and
# then executes the function's own epilogue. 0x34c50 is also a BRANCH TARGET
# (`beq 34c50` at 0x34c0c, and the loop exit), which a `b` into a stub handles
# because both arrivals fall into it - but it is why the displaced instruction has
# to be reproduced rather than dropped.
# 🚨 BUILT, MEASURED, AND NOT SHIPPED - the free is correct and frees NOTHING on
# this unit, because the tree is always NULL. Same verdict as LEAKS 21 and 22,
# reached the same way, and the evidence is specific rather than a null slope:
#
#   json_delete calls per 10 requests, traced at the PLT (0xba18):
#       62ee361c unpatched   29
#       + this stub          29      <- identical, so the blne is NEVER taken
#
# The stub itself definitely runs - 0x69580 and 0x6958c each execute exactly once
# per request - so this is not the "stub never written" failure. r6 is simply 0.
#
# 🔑 WHY, and it is not a mystery once the right string is read:
# checkIfSceneExists parses the file named by the pointer at 0x90e94, which is
# 0x8b080 = "/opt/tuxedo/configuration/hascenedb.json" - the ZWAVE scene database,
# which is **0 bytes** on this unit (and on the bench). Not hatcscenedb.json, the
# 3182-byte TC scene file the rest of the scene code uses. An empty file parses to
# NULL, so scene_getRootNodeOfObjects allocates nothing and there is nothing to
# free. The leak measured on this path (about 107 B/request) comes from somewhere
# else in the cmd=141 handler.
#
# Re-enable it if hascenedb.json ever becomes non-empty, i.e. once real Z-Wave
# scenes exist: then the tree is real, the leak is real, and this frees it.
CHECKSCENE_STUB = 0x69580
CHECKSCENE_SITES = ()            # was ((0x34C50, 0xE1A00005),)

# LEAK 24 - validatePageName drops the page-map tree on every call.
#
# The map is a literal at 0x86168: [{"1":"zwavedevicelist.html"},...29 entries].
# 0x13b70, its only reference in the image, is validatePageName's literal pool.
#
#   13b0c  bl json_strip_white_space   already freed - 0x13B10 is LEAK 19's first site
#   13b10  bl json_parse_unformatted   -> r6, THE TREE, never json_delete'd
#   13b14  subs r6, r0, #0 ; beq 13b64
#   13b38  json_as_string in the loop  -> a SECOND leak, per iteration, NOT fixed here
#   13b64  mov r0, #0                  no-match path, falls through
#   13b68  add sp, #4 ; pop {r4,r5,r6,r7,pc}
#
# Named by contents first: chunkdiff on the 40-byte size dumped
# `"10":"home.'/`html"}` and `"9":"mobile'/`view.htm`, which is this literal.
#
# 0x13b68 is the ONE exit - 0x13b64 falls into it - so a single stub covers the
# match and no-match paths. r6 is NULL exactly on the branch that skips the loop,
# so the guard covers it. lr is expendable because the function returns through
# `pop {...,pc}`, and r4 is restored by that same pop, so it can carry the return
# value (0 or 1) across the call. r6 is callee-saved, so json_delete preserves it.
#
# The per-iteration json_as_string leak is deliberately left alone until this one
# is measured: LEAK 23 was a correct free that moved nothing, and doing both at
# once would leave no way to tell which did the work.
VALIDPAGE_STUB = 0x69594
VALIDPAGE_SITES = ((0x13B68, 0xE28DD004),)

# LEAK 25 - validatePageName's SECOND leak: a json_as_string result per iteration.
#
# LEAK 24 freed the tree and took cmd=141 from ~107 to 39 B/request. The 32-byte
# row barely moved (+361 -> +349), and this is it:
#
#   13b34  bl json_at          -> the value node for this entry
#   13b38  bl json_as_string   -> r0 = CALLER-OWNED string, needs json_free
#   13b3c  mov r1, r7             the page name being looked for
#   13b40  bl strcmp           <- consumes r0 and DROPS it
#   13b44  cmp r0, #0 ; addeq r0,r0,#1 ; beq 13b68
#
# Once per loop iteration, up to 29 entries before a match, which is why this row
# is the larger share. json_free, not free: they are different functions and the
# wrong one corrupts the heap.
#
# Freed by wrapping the strcmp, which is the same shape as LEAK 12's printf stub.
# ⚠ THE RESULT CANNOT BE HELD IN A REGISTER ACROSS THE FREE. Every callee-saved
# register here is live -- r4 is the loop counter, r5 the entry count, r6 the tree,
# r7 the target name -- so the compare result goes on the stack instead, over the
# stashed r1. Registers dead after the compare are r1 (reassigned at 0x13b54), r2
# and r3, so popping into those is safe; lr must come back for the `bx lr`.
# 🚨 BUILT, MEASURED, NOT SHIPPED - it changes nothing, and the reasoning that
# predicted otherwise was wrong in a way worth writing down.
#
#   per-request bytes on cmd=141:  + LEAK 24        39 B
#                                  + LEAK 24 and 25 39 B
#   32-byte row:                   +349  ->  +337
#
# The stub RUNS - 0x695b0, 0x695b8 and 0x695c8 each execute exactly once per
# request - so this is not the never-reached failure.
#
# 🔑 "Once per request" is the finding. I predicted up to 29 frees per request,
# one per map entry, and the trace says the loop body runs ONCE. So the 32-byte
# row at ~1.16 per request was never the loop, and the arithmetic said so before
# the trace did: 349 growth over 300 requests is 1.16, not 10 or 29. **When a
# per-iteration theory predicts N per request and the measurement says ~1, the
# theory is already refuted; check that before building the stub.**
#
# What the 32-byte chunks actually hold is POINTERS, not text - a 0x21 header then
# pointer pairs, the shape of an internal node - so they belong to some other
# structure abandoned once per request, still unidentified.
VALIDSTR_STUB = 0x695B0
VALIDSTR_SITES = ()              # was ((0x13B40, 0xEBFFE03E),)

STRIP_PARSE_STUB = 0x694EC
STRIP_PARSE_SITES = (
    0x13B10, 0x16200, 0x166E8, 0x16954, 0x1712C, 0x19FCC, 0x1A010, 0x1A054,
    0x1A1D4, 0x1A544, 0x1A720, 0x1A8FC, 0x1B754, 0x1BE74, 0x1C050, 0x1C22C,
    0x1C6D8, 0x2FD78, 0x33A18, 0x34DD0, 0x35000, 0x35754, 0x357E4, 0x35AFC,
    0x35B9C, 0x363EC, 0x3647C, 0x36804, 0x36894, 0x36DA0, 0x36E34, 0x372CC,
    0x37358, 0x3C78C, 0x3DEC0, 0x3FDF0, 0x3FF28, 0x407D4, 0x40FEC, 0x42F3C,
    0x46D68, 0x46E1C, 0x490B8,
)


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
    blne_del = (b_encode(s + 0x14, DELETE_ARRAY_PLT, link=True)
                & 0x0FFFFFFF) | 0x10000000
    blne_free = (b_encode(s + 0x20, JSON_FREE_PLT, link=True)
                 & 0x0FFFFFFF) | 0x10000000
    return [
        (s + 0x00, 0xE92D4083, "push {r0, r1, r7, lr}  @ strip result, pad, buffer, lr"),
        (s + 0x04, b_encode(s + 0x04, JSON_PARSE_PLT, link=True),
         "bl   json_parse_unformatted"),
        # The tree goes in the PAD slot, not slot 0: slot 0 must keep holding
        # the strip result so it can be freed below.
        (s + 0x08, 0xE58D0004, "str  r0, [sp, #4]      @ stash the parsed tree"),
        (s + 0x0C, 0xE59D0008, "ldr  r0, [sp, #8]      @ the new[] file buffer"),
        (s + 0x10, 0xE3500000, "cmp  r0, #0"),
        (s + 0x14, blne_del, "blne operator delete[]"),
        (s + 0x18, 0xE59D0000, "ldr  r0, [sp]          @ the strip result"),
        (s + 0x1C, 0xE3500000, "cmp  r0, #0"),
        (s + 0x20, blne_free, "blne json_free         @ NOT free: libjson owns it"),
        (s + 0x24, 0xE59D0004, "ldr  r0, [sp, #4]      @ tree back"),
        (s + 0x28, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (s + 0x2C, 0xE12FFF1E, "bx   lr"),
    ]


def build_ipc_newa_stub():
    """json_new_a(name, str), then json_free the string it just copied.

    Shared by all four registeredClients sites: called with `bl` and returning
    via `lr`, so one stub serves every site with no per-site cave and no return
    address baked in. r1 holds the json_as_string result on entry and is dead
    the moment json_new_a returns, because the node holds a COPY.
    """
    t = IPC_NEWA_STUB
    blne = (b_encode(t + 0x14, JSON_FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (t + 0x00, 0xE92D400E, "push {r1, r2, r3, lr}  @ the string, pad, pad, lr"),
        (t + 0x04, b_encode(t + 0x04, JSON_NEW_A_PLT, link=True),
         "bl   json_new_a        @ copies the string into the node"),
        (t + 0x08, 0xE58D0004, "str  r0, [sp, #4]      @ stash the new node"),
        (t + 0x0C, 0xE59D0000, "ldr  r0, [sp]          @ the json_as_string result"),
        (t + 0x10, 0xE3500000, "cmp  r0, #0"),
        (t + 0x14, blne, "blne json_free"),
        (t + 0x18, 0xE59D0004, "ldr  r0, [sp, #4]      @ node back"),
        (t + 0x1C, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (t + 0x20, 0xE12FFF1E, "bx   lr"),
    ]


def build_getescenes_stub():
    """json_delete(tree A), then also free tree B and the Base64Encode buffer.

    Called with `bl` from 0x165f8 with r0 already holding tree A, and returns via
    lr. r7 (tree B) is callee-saved so json_delete preserves it across the first
    call; [fp-48] is written unconditionally by Base64Encode at 0x165c8 because
    the function is straight-line.
    """
    g = GETESCENES_STUB
    blne_del = (b_encode(g + 0x10, JSON_DELETE_PLT, link=True)
                & 0x0FFFFFFF) | 0x10000000
    blne_free = (b_encode(g + 0x1C, FREE_PLT, link=True)
                 & 0x0FFFFFFF) | 0x10000000
    return [
        (g + 0x00, 0xE92D400E, "push {r1, r2, r3, lr}"),
        (g + 0x04, b_encode(g + 0x04, JSON_DELETE_PLT, link=True),
         "bl   json_delete       @ tree A, the displaced call"),
        (g + 0x08, 0xE1A00007, "mov  r0, r7            @ tree B, never freed"),
        (g + 0x0C, 0xE3500000, "cmp  r0, #0"),
        (g + 0x10, blne_del, "blne json_delete"),
        (g + 0x14, 0xE51B0030, "ldr  r0, [fp, #-48]    @ the Base64Encode buffer"),
        (g + 0x18, 0xE3500000, "cmp  r0, #0"),
        (g + 0x1C, blne_free, "blne free              @ malloc'd, so plain free"),
        (g + 0x20, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (g + 0x24, 0xE12FFF1E, "bx   lr"),
    ]


def build_checkscene_stub():
    """json_delete the tree checkIfSceneExists drops, then run its own epilogue.

    Reached by `b` from the converged exit at 0x34c50, so it does not return to
    the site: it reproduces the displaced `mov r0, r5` and then performs the
    function's `pop {r4,r5,r6,r7,r8,pc}`. No push, and lr is expendable because
    the return address comes off the frame rather than out of lr. r5 (the flag it
    returns) and r6 (the tree) are callee-saved, so json_delete preserves both.
    """
    g = CHECKSCENE_STUB
    blne_del = (b_encode(g + 0x08, JSON_DELETE_PLT, link=True)
                & 0x0FFFFFFF) | 0x10000000
    return [
        (g + 0x00, 0xE1A00006, "mov  r0, r6            @ the parsed tree"),
        (g + 0x04, 0xE3500000, "cmp  r0, #0            @ NULL on the parse-failed path"),
        (g + 0x08, blne_del, "blne json_delete"),
        (g + 0x0C, 0xE1A00005, "mov  r0, r5            @ the displaced instruction"),
        (g + 0x10, 0xE8BD81F0, "pop  {r4,r5,r6,r7,r8,pc}  @ the function's epilogue"),
    ]


def build_validpage_stub():
    """json_delete the page-map tree validatePageName drops, at its one exit.

    Reached by `b` from 0x13b68, so it does not return: it frees, restores the
    return value, performs the displaced `add sp, sp, #4` and then the function's
    own pop. r4 carries r0 across the call because that pop restores r4 anyway,
    and r6 (the tree) is callee-saved so json_delete preserves it.
    """
    g = VALIDPAGE_STUB
    blne_del = (b_encode(g + 0x0C, JSON_DELETE_PLT, link=True)
                & 0x0FFFFFFF) | 0x10000000
    return [
        (g + 0x00, 0xE1A04000, "mov  r4, r0            @ the 0/1 return value"),
        (g + 0x04, 0xE1A00006, "mov  r0, r6            @ the parsed page map"),
        (g + 0x08, 0xE3500000, "cmp  r0, #0            @ NULL on the skip-loop path"),
        (g + 0x0C, blne_del, "blne json_delete"),
        (g + 0x10, 0xE1A00004, "mov  r0, r4            @ restore the return value"),
        (g + 0x14, 0xE28DD004, "add  sp, sp, #4        @ the displaced instruction"),
        (g + 0x18, 0xE8BD80F0, "pop  {r4,r5,r6,r7,pc}  @ the function's epilogue"),
    ]


def build_validstr_stub():
    """strcmp(...), then json_free the json_as_string result it consumed.

    Called with `bl` from 0x13b40 with r0 and r1 already set, and returns via lr.
    The compare result is stashed on the stack rather than in a register because
    every callee-saved register in validatePageName is live across the loop.
    """
    s = VALIDSTR_STUB
    blne_free = (b_encode(s + 0x14, JSON_FREE_PLT, link=True)
                 & 0x0FFFFFFF) | 0x10000000
    return [
        (s + 0x00, 0xE92D4007, "push {r0, r1, r2, lr}   @ [sp] = the string"),
        (s + 0x04, b_encode(s + 0x04, STRCMP_PLT, link=True),
         "bl   strcmp             @ the displaced call, args already in r0/r1"),
        (s + 0x08, 0xE58D0004, "str  r0, [sp, #4]       @ stash the compare result"),
        (s + 0x0C, 0xE59D0000, "ldr  r0, [sp]           @ the json_as_string result"),
        (s + 0x10, 0xE3500000, "cmp  r0, #0"),
        (s + 0x14, blne_free, "blne json_free          @ NOT free; different function"),
        (s + 0x18, 0xE59D0004, "ldr  r0, [sp, #4]       @ restore the compare result"),
        (s + 0x1C, 0xE8BD400E, "pop  {r1, r2, r3, lr}   @ r1-r3 are dead here"),
        (s + 0x20, 0xE12FFF1E, "bx   lr"),
    ]


def build_escenes_str2_stub():
    """encrypt(...), then json_free the json_write result it consumed.

    Touches NO stack: encrypt's fifth argument lives at [sp]. Stashes the string
    in r4, the return address in r9 and encrypt's result in r8 - all three dead
    after 0x165b8 and all three callee-saved, so encrypt and json_free preserve
    them. r0-r3 are untouched before the call, so encrypt sees its original
    arguments.
    """
    k = ESCENES_STR2_STUB
    blne = (b_encode(k + 0x18, JSON_FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (k + 0x00, 0xE1A04000, "mov  r4, r0            @ stash the json_write string"),
        (k + 0x04, 0xE1A0900E, "mov  r9, lr            @ save the return address"),
        (k + 0x08, b_encode(k + 0x08, ENCRYPT_FN, link=True),
         "bl   encrypt           @ r0-r3 and [sp] untouched"),
        (k + 0x0C, 0xE1A08000, "mov  r8, r0            @ stash the ciphertext"),
        (k + 0x10, 0xE1A00004, "mov  r0, r4"),
        (k + 0x14, 0xE3500000, "cmp  r0, #0"),
        (k + 0x18, blne, "blne json_free"),
        (k + 0x1C, 0xE1A00008, "mov  r0, r8            @ ciphertext back"),
        (k + 0x20, 0xE12FFF19, "bx   r9                @ NOT lr: json_free clobbered it"),
    ]


def build_escenes_str1_stub():
    """strlen(str), then json_free(str), returning the LENGTH in r0.

    Wraps the `bl strlen` at 0x16570. r0 on entry is the json_write result from
    the immediately preceding call, so the stub needs no per-site analysis. The
    length is stashed across the free because json_free clobbers r0.
    """
    h = ESCENES_STR1_STUB
    blne = (b_encode(h + 0x14, JSON_FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (h + 0x00, 0xE92D4007, "push {r0, r1, r2, lr}  @ the string, pad, pad, lr"),
        (h + 0x04, b_encode(h + 0x04, STRLEN_PLT, link=True), "bl   strlen"),
        (h + 0x08, 0xE58D0004, "str  r0, [sp, #4]      @ stash the length"),
        (h + 0x0C, 0xE59D0000, "ldr  r0, [sp]          @ the json_write string"),
        (h + 0x10, 0xE3500000, "cmp  r0, #0"),
        (h + 0x14, blne, "blne json_free"),
        (h + 0x18, 0xE59D0004, "ldr  r0, [sp, #4]      @ length back"),
        (h + 0x1C, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (h + 0x20, 0xE12FFF1E, "bx   lr"),
    ]


def build_strip_parse_stub():
    """json_parse_unformatted(strip_result), then json_free the strip result.

    Shared by all 43 sites: called with `bl` and returning via `lr`, so one stub
    serves every site with no per-site cave and no return address baked in. r0
    on entry is the strip result at every site because the two calls are
    adjacent everywhere in the image.
    """
    n = STRIP_PARSE_STUB
    blne = (b_encode(n + 0x14, JSON_FREE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (n + 0x00, 0xE92D4007, "push {r0, r1, r2, lr}  @ strip result, pad, pad, lr"),
        (n + 0x04, b_encode(n + 0x04, JSON_PARSE_PLT, link=True),
         "bl   json_parse_unformatted"),
        (n + 0x08, 0xE58D0004, "str  r0, [sp, #4]      @ stash the parsed tree"),
        (n + 0x0C, 0xE59D0000, "ldr  r0, [sp]          @ the strip result"),
        (n + 0x10, 0xE3500000, "cmp  r0, #0"),
        (n + 0x14, blne, "blne json_free         @ NOT free: libjson owns it"),
        (n + 0x18, 0xE59D0004, "ldr  r0, [sp, #4]      @ tree back"),
        (n + 0x1C, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (n + 0x20, 0xE12FFF1E, "bx   lr"),
    ]


def build_ipc_errnode_stub():
    """getErrorNode(...), then json_delete the node the caller throws away.

    Called with `bl` and returning via `lr`. r0's value on return is irrelevant:
    the instruction after the call site is `mov r0, r7`.
    """
    p = IPC_ERRNODE_STUB
    blne = (b_encode(p + 0x0C, JSON_DELETE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (p + 0x00, 0xE92D400E, "push {r1, r2, r3, lr}"),
        (p + 0x04, b_encode(p + 0x04, GET_ERROR_NODE, link=True),
         "bl   getErrorNode"),
        (p + 0x08, 0xE3500000, "cmp  r0, #0"),
        (p + 0x0C, blne, "blne json_delete       @ the caller discards it"),
        (p + 0x10, 0xE8BD400E, "pop  {r1, r2, r3, lr}"),
        (p + 0x14, 0xE12FFF1E, "bx   lr"),
    ]


def build_ipc_skip_stub():
    """json_delete the object registeredClients abandons on a skipped entry.

    Entered by the `bls` itself, so it runs ONLY on the skip path, and rejoins
    at 0x34a80. json_delete clobbers r0-r3 and r12; r4-r8 and sl survive, which
    is all the loop condition reads, and r0 is set to #5 at 0x34a84.
    """
    z = IPC_SKIP_STUB
    blne = (b_encode(z + 0x08, JSON_DELETE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (z + 0x00, 0xE1A00005, "mov  r0, r5            @ the abandoned object"),
        (z + 0x04, 0xE3500000, "cmp  r0, #0"),
        (z + 0x08, blne, "blne json_delete"),
        (z + 0x0C, b_encode(z + 0x0C, IPC_SKIP_RETURN), "b    0x34a80"),
    ]


def build_ipc_treea_stub():
    """json_delete tree A at pushEventsToClientsDevAdded's epilogue."""
    y = IPC_TREEA_STUB
    blne = (b_encode(y + 0x08, JSON_DELETE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (y + 0x00, 0xE1A00007, "mov  r0, r7            @ tree A, the event payload"),
        (y + 0x04, 0xE3500000, "cmp  r0, #0"),
        (y + 0x08, blne, "blne json_delete"),
        (y + 0x0C, IPC_TREEA_ORIG, "add  sp, sp, #260      @ the displaced instruction"),
        (y + 0x10, b_encode(y + 0x10, IPC_TREEA_RETURN), "b    0x1339c"),
    ]


def build_ipc_tree_stub():
    """json_delete the parsed registry tree at registeredClients' epilogue.

    Reached by `b` from 0x34a8c, performs the displaced `add sp,sp,#4` and
    branches back to the pop. r0 must be restored to 5, the function's constant
    return value, because json_delete clobbers it. lr is dead here: the epilogue
    restores pc from the stack.
    """
    u = IPC_TREE_STUB
    blne = (b_encode(u + 0x08, JSON_DELETE_PLT, link=True)
            & 0x0FFFFFFF) | 0x10000000
    return [
        (u + 0x00, 0xE1A00008, "mov  r0, r8            @ the parsed registry tree"),
        (u + 0x04, 0xE3500000, "cmp  r0, #0"),
        (u + 0x08, blne, "blne json_delete"),
        (u + 0x0C, 0xE3A00005, "mov  r0, #5            @ restore the return value"),
        (u + 0x10, IPC_TREE_ORIG, "add  sp, sp, #4        @ the displaced instruction"),
        (u + 0x14, b_encode(u + 0x14, IPC_TREE_RETURN), "b    0x34a90"),
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
    # NOT required: --tsv and --check-only write no binary, and demanding --out
    # for them made `mkapifix.py IMG --tsv` exit through argparse. With stderr
    # redirected that produced ZERO rows and no error, which reads as "there is
    # nothing to add to the patch table" -- the same silent-empty-result failure
    # this tool's self-check exists to prevent.
    ap.add_argument("--out")
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--without-ipc", action="store_true",
                    help="omit LEAK 13 (the IPC registry-file buffer). Produces "
                         "the binary that is LIVE on the panel, a84c220a, which "
                         "is the control the IPC candidate must be measured "
                         "against. LEAK 13 is the only patch here whose effect "
                         "has never been observed on a path the bench reaches.")
    ap.add_argument("--tsv", action="store_true",
                    help="emit patches.tsv rows instead of writing a binary, so "
                         "a reflash keeps these fixes. Offsets are FILE offsets "
                         "(VA - 0x8000), matching the rest of the table.")
    args = ap.parse_args()
    if not args.out and not (args.tsv or args.check_only):
        ap.error("--out is required unless --tsv or --check-only is given")

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
    ipc_sites = () if args.without_ipc else IPC_BUF_SITES
    ipc_newa_sites = () if args.without_ipc else IPC_NEWA_SITES
    ipc_errnode_sites = () if args.without_ipc else IPC_ERRNODE_SITES
    strip_sites = () if args.without_ipc else STRIP_PARSE_SITES
    escenes_sites = () if args.without_ipc else GETESCENES_SITES
    str1_sites = () if args.without_ipc else ESCENES_STR1_SITES
    str2_sites = () if args.without_ipc else ESCENES_STR2_SITES
    checkscene_sites = () if args.without_ipc else CHECKSCENE_SITES
    validpage_sites = () if args.without_ipc else VALIDPAGE_SITES
    validstr_sites = () if args.without_ipc else VALIDSTR_SITES
    for site, want, what in ([(s, w, "bl json_delete in getEScenes")
                              for s, w in escenes_sites]
                             + [(s, w, "bl strlen in getEScenes")
                                for s, w in str1_sites]
                             + [(s, w, "bl encrypt in getEScenes")
                                for s, w in str2_sites]
                             + [(s, w, "bl strcmp in validatePageName")
                                for s, w in validstr_sites]
                             + [(s, w, "add sp at validatePageName exit")
                                for s, w in validpage_sites]
                             + [(s, w, "mov r0, r5 at checkIfSceneExists exit")
                                for s, w in checkscene_sites]):
        got = rd(site)
        if got != want:
            sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, expected "
                     f"0x{want:08x} ({what})")
    # Each site must currently hold a `bl json_parse_unformatted`. Computing the
    # expected word rather than listing 43 of them keeps the check honest: it
    # still refuses on a different build or an already-patched image, and it
    # cannot drift out of step with the address list.
    for site in strip_sites:
        want = b_encode(site, JSON_PARSE_PLT, link=True)
        got = rd(site)
        if got != want:
            sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, expected "
                     f"0x{want:08x} (bl json_parse_unformatted)")
        # and the instruction BEFORE it must be the strip call, which is what
        # makes r0 the strip result and the shared stub safe here.
        pwant = b_encode(site - 4, JSON_STRIP_PLT, link=True)
        pgot = rd(site - 4)
        if pgot != pwant:
            sys.exit(f"REFUSING: 0x{site - 4:x} holds 0x{pgot:08x}, expected "
                     f"0x{pwant:08x} (bl json_strip_white_space)")
    if 0x34964 in strip_sites:
        sys.exit("REFUSING: 0x34964 is already redirected to IPC_BUF_STUB")
    if not args.without_ipc:
        for site, want, name in ((IPC_TREE_SITE, IPC_TREE_ORIG, "add sp,sp,#4"),
                                 (IPC_SKIP_SITE, IPC_SKIP_ORIG, "bls 0x34a80"),
                                 (IPC_TREEA_SITE, IPC_TREEA_ORIG,
                                  "add sp,sp,#260")):
            got = rd(site)
            if got != want:
                sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, "
                         f"expected 0x{want:08x} ({name})")
    for site, want in (STRNCMP_SITES + STRCMP_SITES + PRINTF2_SITES
                       + ipc_sites + ipc_newa_sites + ipc_errnode_sites):
        got = rd(site)
        if got != want:
            sys.exit(f"REFUSING: 0x{site:x} holds 0x{got:08x}, expected "
                     f"0x{want:08x} (cmp after json_as_string)")
    ncmp = build_cmpfree_stub(FREE_STRNCMP_STUB, STRNCMP_PLT, "strncmp")
    scmp = build_cmpfree_stub(FREE_STRCMP_STUB, STRCMP_PLT, "strcmp")
    if ncmp[-1][0] + 4 > FREE_STRCMP_STUB:
        sys.exit("REFUSING: the two cmp stubs overlap")
    printf2 = build_printf2_stub()
    ipcbuf = [] if args.without_ipc else build_ipc_buf_stub()
    ipcnewa = [] if args.without_ipc else build_ipc_newa_stub()
    ipctree = [] if args.without_ipc else build_ipc_tree_stub()
    ipcskip = [] if args.without_ipc else build_ipc_skip_stub()
    ipctreea = [] if args.without_ipc else build_ipc_treea_stub()
    ipcerrnode = [] if args.without_ipc else build_ipc_errnode_stub()
    stripparse = [] if args.without_ipc else build_strip_parse_stub()
    escenes = [] if args.without_ipc else build_getescenes_stub()
    # Only emit the str1 stub if its site is actually redirected. It is disabled
    # (see ESCENES_STR1_SITES) because it measured zero, and an orphan stub with
    # nothing branching into it is exactly the "wrote the stub, lost the site"
    # failure this tool's self-check exists to catch - in reverse.
    escstr1 = build_escenes_str1_stub() if str1_sites else []
    escstr2 = build_escenes_str2_stub() if str2_sites else []
    checkscene = build_checkscene_stub() if checkscene_sites else []
    validpage = build_validpage_stub() if validpage_sites else []
    validstr = build_validstr_stub() if validstr_sites else []
    if ipcbuf:
        if printf2[-1][0] + 4 > IPC_BUF_STUB:
            sys.exit("REFUSING: printf2 and ipc stubs overlap")
        if ipcbuf[-1][0] + 4 > IPC_NEWA_STUB:
            sys.exit("REFUSING: the ipc buffer and json_new_a stubs overlap")
        if ipcnewa[-1][0] + 4 > IPC_TREE_STUB:
            sys.exit("REFUSING: the ipc json_new_a and tree stubs overlap")
        if ipctree[-1][0] + 4 > IPC_SKIP_STUB:
            sys.exit("REFUSING: the ipc tree and skip stubs overlap")
        if ipcskip[-1][0] + 4 > IPC_TREEA_STUB:
            sys.exit("REFUSING: the ipc skip and tree-A stubs overlap")
        if ipctreea[-1][0] + 4 > IPC_ERRNODE_STUB:
            sys.exit("REFUSING: the ipc tree-A and errnode stubs overlap")
        if ipcerrnode[-1][0] + 4 > STRIP_PARSE_STUB:
            sys.exit("REFUSING: the errnode and strip-parse stubs overlap")
        if stripparse[-1][0] + 4 > GETESCENES_STUB:
            sys.exit("REFUSING: the strip-parse and getEScenes stubs overlap")
        if escstr1 and escenes[-1][0] + 4 > ESCENES_STR1_STUB:
            sys.exit("REFUSING: the getEScenes and str1 stubs overlap")
        if escstr2 and escstr2[-1][0] + 4 > CMPFREE_CAVE_END:
            sys.exit("REFUSING: the str2 stub overruns its dead region")
        if (escstr1 or escenes) and (escstr1 or escenes)[-1][0] + 4 > CMPFREE_CAVE_END:
            sys.exit("REFUSING: ipc stubs overrun their dead region")
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
    if args.without_ipc:
        print("LEAK 13 - IPC path: OMITTED (--without-ipc), this is the live "
              "a84c220a control")
    else:
        print("LEAK 13 - IPC path: the registry file buffer + the strip result")
        for va, word, note in ipcbuf:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        for site, _w in ipc_sites:
            print(f"  site 0x{site:08x} -> "
                  f"0x{b_encode(site, IPC_BUF_STUB, link=True):08x}")
        print()
        print("LEAK 14 - registeredClients: json_as_string x4 per registry ENTRY")
        for va, word, note in ipcnewa:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        for site, _w in ipc_newa_sites:
            print(f"  site 0x{site:08x} -> "
                  f"0x{b_encode(site, IPC_NEWA_STUB, link=True):08x}")
        print()
        print("LEAK 15 - registeredClients: the parsed registry tree is abandoned")
        for va, word, note in ipctree:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        print(f"  site 0x{IPC_TREE_SITE:08x}  0x{rd(IPC_TREE_SITE):08x} -> "
              f"0x{b_encode(IPC_TREE_SITE, IPC_TREE_STUB):08x}  "
              f"(b 0x{IPC_TREE_STUB:x})")
        print()
        print("LEAK 16 - registeredClients: an empty object per SKIPPED entry "
              "(6 per message)")
        for va, word, note in ipcskip:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        print(f"  site 0x{IPC_SKIP_SITE:08x}  0x{rd(IPC_SKIP_SITE):08x} -> "
              f"0x{((b_encode(IPC_SKIP_SITE, IPC_SKIP_STUB) & 0x0FFFFFFF) | 0x90000000):08x}"
              f"  (bls 0x{IPC_SKIP_STUB:x}, condition preserved)")
        print()
        print("LEAK 17 - pushEventsToClientsDevAdded: tree A never freed")
        for va, word, note in ipctreea:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        print(f"  site 0x{IPC_TREEA_SITE:08x}  0x{rd(IPC_TREEA_SITE):08x} -> "
              f"0x{b_encode(IPC_TREEA_SITE, IPC_TREEA_STUB):08x}  "
              f"(b 0x{IPC_TREEA_STUB:x})")
        print()
        print("LEAK 18 - a getErrorNode result the caller overwrites immediately")
        for va, word, note in ipcerrnode:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        for site, _w in ipc_errnode_sites:
            print(f"  site 0x{site:08x} -> "
                  f"0x{b_encode(site, IPC_ERRNODE_STUB, link=True):08x}")
        print()
        print(f"LEAK 19 - every json_strip_white_space result in the image "
              f"({len(strip_sites)} sites, 1 stub)")
        for va, word, note in stripparse:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        print("  sites: " + " ".join(f"0x{s:x}" for s in strip_sites))
        print()
        print("LEAK 20 - getEScenes: tree B and the Base64Encode buffer")
        for va, word, note in escenes:
            print(f"    0x{va:08x}  {word:08x}   {note}")
        for site, _w in escenes_sites:
            print(f"  site 0x{site:08x} -> "
                  f"0x{b_encode(site, GETESCENES_STUB, link=True):08x}")
        print()
        print()
        if not str2_sites:
            print("LEAK 22 - getEScenes STRING 2: DISABLED, measured zero effect "
                  "(see ESCENES_STR2_SITES)")
        else:
            print("LEAK 22 - getEScenes STRING 2: json_write destroyed by encrypt")
            for va, word, note in escstr2:
                print(f"    0x{va:08x}  {word:08x}   {note}")
            for site, _w in str2_sites:
                print(f"  site 0x{site:08x} -> "
                      f"0x{b_encode(site, ESCENES_STR2_STUB, link=True):08x}")
        print()
        if not str1_sites:
            print("LEAK 21 - getEScenes STRING 1: DISABLED, measured zero effect "
                  "(see ESCENES_STR1_SITES)")
        else:
            print("LEAK 21 - getEScenes STRING 1: json_write destroyed by strlen")
            for va, word, note in escstr1:
                print(f"    0x{va:08x}  {word:08x}   {note}")
            for site, _w in str1_sites:
                print(f"  site 0x{site:08x} -> "
                      f"0x{b_encode(site, ESCENES_STR1_STUB, link=True):08x}")

    if args.tsv:
        rows = []
        for va, word, note in (cave + cave2 + cave3 + cave4 + cave5 + cave6
                               + cave7 + cave8 + cave9 + cave10 + freestr
                               + ncmp + scmp + printf2 + ipcbuf
                               + ipcnewa + ipctree + ipcskip + ipctreea
                               + ipcerrnode + stripparse + escenes + escstr1 + escstr2
                               + checkscene + validpage + validstr):
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
        for site, _w in ipc_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, IPC_BUF_STUB, link=True),
                         "IPC: parse, delete[] the file buffer, free the strip"))
        for site, _w in ipc_newa_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, IPC_NEWA_STUB, link=True),
                         "IPC: json_new_a then json_free the copied string"))
        if ipctree:
            rows.append((f"P15-leakfix-site-{IPC_TREE_SITE:x}", IPC_TREE_SITE,
                         rd(IPC_TREE_SITE),
                         b_encode(IPC_TREE_SITE, IPC_TREE_STUB),
                         "IPC: json_delete the abandoned registry tree"))
            rows.append((f"P15-leakfix-site-{IPC_SKIP_SITE:x}", IPC_SKIP_SITE,
                         rd(IPC_SKIP_SITE),
                         (b_encode(IPC_SKIP_SITE, IPC_SKIP_STUB) & 0x0FFFFFFF)
                         | 0x90000000,
                         "IPC: free the object abandoned on a skipped entry"))
            rows.append((f"P15-leakfix-site-{IPC_TREEA_SITE:x}", IPC_TREEA_SITE,
                         rd(IPC_TREEA_SITE),
                         b_encode(IPC_TREEA_SITE, IPC_TREEA_STUB),
                         "IPC: json_delete tree A in pushEventsToClients"))
        for site, _w in ipc_errnode_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, IPC_ERRNODE_STUB, link=True),
                         "IPC: free the discarded getErrorNode result"))
        for site in strip_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, STRIP_PARSE_STUB, link=True),
                         "parse then json_free the strip_white_space result"))
        for site, _w in escenes_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, GETESCENES_STUB, link=True),
                         "getEScenes: free tree B and the Base64 buffer"))
        for site, _w in str1_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, ESCENES_STR1_STUB, link=True),
                         "getEScenes: strlen then json_free the json_write result"))
        for site, _w in str2_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, ESCENES_STR2_STUB, link=True),
                         "getEScenes: encrypt then json_free the json_write result"))
        for site, _w in checkscene_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, CHECKSCENE_STUB),
                         "checkIfSceneExists: json_delete the abandoned tree"))
        for site, _w in validpage_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, VALIDPAGE_STUB),
                         "validatePageName: json_delete the page-map tree"))
        for site, _w in validstr_sites:
            rows.append((f"P15-leakfix-site-{site:x}", site, rd(site),
                         b_encode(site, VALIDSTR_STUB, link=True),
                         "validatePageName: strcmp then json_free the as_string"))
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
                 + ipcbuf + ipcnewa + ipctree + ipcskip + ipctreea
                 + ipcerrnode + stripparse + escenes + escstr1 + escstr2
                 + checkscene + validpage + validstr)
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
    site_writes += [(s, IPC_BUF_STUB, True) for s, _ in ipc_sites]
    site_writes += [(s, IPC_NEWA_STUB, True) for s, _ in ipc_newa_sites]
    site_writes += [(s, IPC_ERRNODE_STUB, True) for s, _ in ipc_errnode_sites]
    site_writes += [(s, STRIP_PARSE_STUB, True) for s in strip_sites]
    site_writes += [(s, GETESCENES_STUB, True) for s, _ in escenes_sites]
    site_writes += [(s, ESCENES_STR1_STUB, True) for s, _ in str1_sites]
    site_writes += [(s, ESCENES_STR2_STUB, True) for s, _ in str2_sites]
    # `b`, not `bl`: the stub reproduces the displaced `mov r0, r5` and then runs
    # checkIfSceneExists's own `pop {...,pc}`, so it never returns to the site.
    site_writes += [(s, CHECKSCENE_STUB, False) for s, _ in checkscene_sites]
    site_writes += [(s, VALIDPAGE_STUB, False) for s, _ in validpage_sites]
    site_writes += [(s, VALIDSTR_STUB, True) for s, _ in validstr_sites]
    # `b`, not `bl`: the tree stub performs the displaced instruction and
    # branches back rather than returning through lr.
    if ipctree:
        site_writes += [(IPC_TREE_SITE, IPC_TREE_STUB, False)]

    intended = {va: word for va, word, _ in all_stubs}
    for site, target, linked in site_writes:
        intended[site] = b_encode(site, target, link=linked)
    if ipcskip:
        # The skip site keeps its ORIGINAL condition code: cond=LS (0x9), not
        # AL. The stub must run only when the entry is actually skipped, so
        # this is a `bls` into the stub, not a `b`.
        intended[IPC_SKIP_SITE] = ((b_encode(IPC_SKIP_SITE, IPC_SKIP_STUB)
                                    & 0x0FFFFFFF) | 0x90000000)
        intended[IPC_TREEA_SITE] = b_encode(IPC_TREEA_SITE, IPC_TREEA_STUB)
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
