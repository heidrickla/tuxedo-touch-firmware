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

## The pattern

Reading the code and reading the device disagreed repeatedly, and **the device
won every time.** Where no device test was possible, I reached for a mechanism
before finishing the code that implements it — which is how items 10 and 11
happened within an hour of each other.

The one thing that consistently worked: name what would falsify a claim, then go
and try it.
