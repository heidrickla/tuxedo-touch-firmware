# Why these two captures are here

There is a standing question about whether captures belong in this repository
at all. `evidence/` and the two `tuxedo-*.jsonl` files are under review for
removal on exactly that basis.

**These two are different, and if you are sweeping for captures again this file
is the answer.** They are not evidence kept for the record. They are test
vectors that the code compiles against.

    push-idle-300s.bin    10737 bytes   300 s of the push stream from an idle panel
    push-armcycle.bin      9614 bytes   arm-stay -> exit delay -> Armed Stay -> disarm

## Removing them does not fail a test, it fails the build

`include_bytes!` pulls them in from three source files, five sites:

    tuxweb/src/frame.rs:118,122
    tuxweb/src/ipc.rs:400,401
    tuxweb/src/shim.rs:573

`include_bytes!` resolves at compile time, so a missing fixture is a compile
error and not a red test. The release binary stops building too, which is worth
knowing before someone deletes them expecting to see a failing assertion.

## They disclose nothing

Scanned independently rather than taken on trust, over both files in full:

    IPv4 addresses  0        Cookie / Set-Cookie   0
    MAC addresses   0        Host: headers         0
    session/token   0        Authorization         0
    Tux hostnames   0        password strings      0

What they contain is an HTTP response header and then protocol frames:

    HTTP/1.1 200 OK\r\nDate: Sun, 06 Sep 2026 ...

No address, no session, no hostname, no credential.

## DO NOT REPLACE THEM WITH GENERATED FIXTURES

This was proposed and rejected, and the reasoning is in the code at each site:

* `frame.rs` — the only capture holding `0xFF` and the countdown, so the state
  byte and the arming frames are *"covered by evidence rather than by
  reasoning"*.
* `ipc.rs` — `every_captured_frame_is_reproducible_from_its_fields`:
  *"Four vectors can be made to pass by accident. 150 cannot."*
* `shim.rs` — *"Feeding the shim's re-emitter a real capture must give back the
  same bytes the panel sent -- this is the whole promise of the stage."*

Synthesise these and all three become tests that cannot fail: frames generated
from the same model they are meant to be checking, passing by construction.
That is the defect `docs/TRAPS.md` section 1 opens with, and these captures are
what prevent it.

**They are also the arbiter when two sources disagree.** `docs/TRAPS.md`: when a
capture disagrees with the disassembly, the capture is right and the
disassembly is incomplete. Not hypothetical — the static reply map and the
capture disagreed about `frame_registration`'s third field, the capture was
right, and `Reply::parse` was reading `+0x08`, an offset `registerclient` never
writes.

## If they ever do have to go

Delete the three tests honestly rather than re-pointing them at generated data.
A suite that is smaller and truthful beats one that is the same size and cannot
fail.
