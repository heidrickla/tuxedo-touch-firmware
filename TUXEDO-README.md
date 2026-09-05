# Honeywell Tuxedo Touch — start here

Reverse-engineering a Tuxedo Touch WIFI on a VISTA-21iP. What began as "can we
update or patch the firmware to fix a buggy panel" ended somewhere better.

## The short version

**The status bug is solved, and not by patching anything.** The panel has a push
stream the integration was not using. It reports alarm state directly and
structurally cannot return `"Not available"`.

```
GET /SimpleDebugger.interface/G.      <- the slash before G. is the whole trick
```

Session cookie only. Verified live through arm and disarm.

## The documents

| File | What it answers |
|---|---|
| `TUXEDO-FINDINGS.md` | Why the status went unknown, measured then confirmed in the binaries |
| `TUXEDO-HA-ENRICHMENT.md` | What data is really reachable, and the live test results |
| `TUXEDO-FIRMWARE.md` | Firmware internals: image format, flasher, kernel, OTA, safe-write rule |
| `TUXEDO-VERIFIED.md` | Ten high-severity findings put to skeptics told to refute them |
| `TUXEDO-AUDIT-BUGS.md` | 40 findings from the subsystem audit |
| `TUXEDO-LOCKOUT-PATCH.md` | Byte-level patch for the 3-strike lockout, with review and recovery |
| `TUXEDO-VIRTUAL-CONSOLE-BUGS.md` | Why the virtual console is unreliable |
| `TUXEDO-ZONE-PROGRAMMING.md` | Zone types and the descriptor vocabulary |

## The tools

| File | Does |
|---|---|
| `tuxedo_push.py` | Reads the push stream; decodes status frames |
| `tuxedo_api_console.py` | Working API console — REST, commands and stream together |
| `tuxedo_status_probe.py` | Diagnoses *why* status goes stale, with a control |
| `tuxedo_wake_experiment.py` | Repeated quiet/active cycles for replication |
| `fw_extract.py` | Carves filesystems out of header-wrapped firmware |
| `tuxedo_zone_tables.json` | Zone types and descriptor words, machine-readable |

## Things I got wrong, and how

Kept visible in the documents rather than edited out, because each was corrected
by evidence rather than argument.

**Wrong about the device:**

1. **"The push channel is dead."** A missing slash in the URL. The most
   consequential error here — it nearly buried the actual fix.
2. **"~40 endpoints available."** Most are unimplemented and return their own
   documentation form.
3. **"Add thermostat/lock/light entities."** All Z-Wave, out of scope. Lewis
   caught it.
4. **"The installer code is never persisted."** It is. I traced one setter and
   generalised from it.
5. **"No zone command exists."** I searched the vendor's JavaScript and drew a
   conclusion about the server.
6. **"The stock library has a ban timer."** It does not; the patch designer
   checked the constructor.
7. **A probe that sent GET where the API wants POST**, then reported a device
   fault that was entirely my own bug.

**Wrong about the mechanism, four times in one night:**

8. **"Polling holds the feed alive."** Refuted by 25 minutes of true quiet.
9. **"The 405 burst caused it."** Refuted — 8 deliberate 405s changed nothing.
10. **"The latch-dedup is the surviving mechanism."** Withdrawn after reading it
    properly: three functions share that table and one actively clears the bits
    the story needed set.
11. **"Cold cache after restart."** Loose wording. The string is in read-only
    data, so it is a constant substituted for an *absent* value, not a stale
    buffer.

**Wrong about a person:**

12. **I recorded that Lewis's recollection was mistaken** about the integration
    polling. He had made no such claim — he was describing a billing error and I
    read a contradiction into it. The misattribution was mine.

**Wrong four more times on flash day, all in the same register:**

13. **"The flasher does not verify a payload checksum."** It does. I read the
    per-component loader, saw it set a flag literally named "checksum OK"
    unconditionally after a successful read, and concluded no verification
    existed. That flag means *the file was present and readable*; it is there
    so the error reporter can choose between "not found" and "checksum error".
    The real routine is elsewhere. **The panel refuted this**, cleanly,
    rejecting the image with nothing written. Cost: one wasted trip to the
    panel. The algorithm is now in `tuxedo_hdr.py` and reproduces all five
    vendor files.
14. **"Every login outcome is HTTP 200, so only the body differs."** Half true.
    An ordinary failure is a 200 forward, but a locked-out panel returns 302
    with a redirect. I had already resolved the symbol at `0x6e024` as
    `HttpResponse_sendRedirect` earlier in the same session and wrote "forward"
    anyway. Caught by verification agents before it reached anyone's code.
15. **"The flash cleared `/opt/tuxedo/configuration/datetime`."** It cannot.
    That directory is `mtdblock17` and survives a reflash — a fact I had
    established myself four hours earlier and failed to apply. The panel simply
    has no clock across a power cycle. Caught by me, unprompted, which is the
    only one of the four that was.
16. **"The console JavaScript is a text edit."** The web application is a
    776-entry ZIP embedded mid-ELF inside the `Barracuda` binary, so it cannot
    change size and every edit must recompress to its exact original byte
    count. Caught before promising the work, not after.

## The pattern

Reading the code and reading the device disagreed repeatedly, and **the device
won every time.** Where no device test was possible, I reached for a mechanism
before finishing the code that implements it — which is how items 10 and 11
happened within an hour of each other.

Items 13 to 15 are one failure mode with three faces, and a collaborator named
it better than I did: **reading a mechanism partly, then describing it in the
confident register the fully-resolved parts had earned.** Each time the
instructions I actually read were reported correctly. What was wrong was the
generalisation from them — who else writes that flag, what else that symbol
resolves to, which partition that path is on.

The rule that follows, and the standard now applied to the word CONFIRMED here:
**it is not enough to have read the instructions at the site. Every branch into
and out of the thing has to be traced.** Both flash-day misses would have
failed that test. Neither would have survived asking "what else writes this?"

A second rule, from item 13: **absence of an obvious access pattern is not
absence of a check.** I searched for `ldrh [rX, #0x14]` and found nothing,
because the header is `memcpy`'d to a scratch buffer first and read from there.
The search was sound and the conclusion drawn from its emptiness was not.

The one thing that consistently worked: name what would falsify a claim, then go
and try it.
