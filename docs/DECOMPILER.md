# Decompiler

Ghidra 12.1.3, headless, on the build VM. Installed 2026-09-09.

Read this before writing another analysis script. It exists because two days went
into hand-rolled tooling that a decompiler answers directly, and the only thing that
stopped it was being asked why.

## Where it is

    /opt/ghidra                      symlink to /opt/ghidra_12.1.3_PUBLIC
    /opt/ghidra/support/analyzeHeadless
    /work/ghidra-proj                the project, holding the imported binaries
    /work/ghidra-scripts/Decomp.java the query script

Java 21 from Ubuntu's `openjdk-21-jdk-headless`. The release zip was checked against
the SHA-256 GitHub publishes for the asset before it was unpacked:
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`, 569,445,154
bytes. Do that again for any future upgrade.

## Importing and querying

    # one-off per binary, slow: minutes for Barracuda, longer for /tuxedo at 14.6 MB
    /opt/ghidra/support/analyzeHeadless /work/ghidra-proj tuxedo \
        -import /tmp/Barracuda.v14 -processor ARM:LE:32:v7 -cspec default

    # afterwards, cheap: reuse the analysed program
    /opt/ghidra/support/analyzeHeadless /work/ghidra-proj tuxedo \
        -process Barracuda.v14 -noanalysis \
        -scriptPath /work/ghidra-scripts -postScript Decomp.java \
        /work/out.txt 0x1afc8 setarmwithcode

`Decomp.java` takes an output file then any number of targets, each either `0x<addr>`
or a symbol name, and writes the decompiled C. Addresses that fall inside a function
resolve to it, so an address from a disassembly listing works.

## Why it is worth the setup here

**Both binaries carry full symbols.** `/tuxedo` has C++ mangled names, so functions
come out as `CReceiverThread::sltSendUserCodeAcceptedMsg` rather than
`FUN_0013c408`, and the class structure survives. That is unusual and it is most of
the value.

It found LEAK 31 within twenty minutes of being installed, in a function that had
already been read twice by hand the same day for a different question. The census
built on top of it, `leakfix/alloccensus.py`, then turned that single finding into a
family of nineteen.

## What it does not do

It answers *what this code does*, never *whether this path runs*. Every decisive
result in the leak work came from executing something and counting: 1.0000 leaked
trees per request, the NOP bisect that isolated a wedge to the free itself, phase 1's
`exe` link proving an `execve` happened. A decompiler produces none of those, and
`TRAPS.md` §1 is entirely about that gap.

Qt C++ on ARM also decompiles unevenly. Signal/slot dispatch, vtables and `QObject`
plumbing come out messy, and the register-level reading in `TRAPS.md` §2 is still
needed where the output is ambiguous.

## The rule that follows from this

When about to build the second bespoke tool answering the same *category* of
question, stop and ask whether that category has a name. "Recover struct layouts from
machine code" has a name. So does "which register holds this value here" — and the
hand-rolled answer to that one, `leakfix/liveness.py`, was wrong, and its wrongness
reached a commit.
