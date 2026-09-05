# Honeywell Tuxedo Touch WIFI

Firmware internals, the local API surface, and the reverse-engineering record
for a Tuxedo Touch WIFI (`TUXW_V5.3.21.0_VA`) sitting on a VISTA-21iP.

The work started as "the alarm status in Home Assistant keeps going unknown,
can we patch the panel to fix it" and ended somewhere better: the status bug
turned out to be fixable entirely on the client side, and the firmware work
became a separate, smaller question.

## Start here

**The status bug is solved, and not by patching anything.** The panel has a
push stream the integration was not using. It reports alarm state directly and
structurally cannot answer `"Not available"`.

```
GET /SimpleDebugger.interface/G.
```

The slash before `G.` is the whole trick. Session cookie only, no token, no
signed body. Verified live through arm and disarm.

## Scope and status

| | |
|---|---|
| Device | Honeywell Tuxedo Touch WIFI, firmware `TUXW_V5.3.21.0_VA` |
| Panel behind it | Honeywell VISTA-21iP |
| Owner | Lewis |
| Consumer of this work | [`ha-tuxedo-touch`](https://github.com/heidrickla/ha-tuxedo-touch), the Home Assistant integration |
| Licence | GPL-3.0 |

Most documents here are **static analysis**. Where something was measured
against the live panel, the document says so and gives the numbers. Where a
conclusion was later retracted, the retraction is left in place rather than
edited out.

## The documents

| File | What it answers |
|---|---|
| `TUXEDO-README.md` | The original start-here, kept for its "things I got wrong" record |
| `TUXEDO-FINDINGS.md` | Why the status went unknown, measured and then confirmed in the binaries |
| `TUXEDO-HA-ENRICHMENT.md` | What data is really reachable from the panel, with live test results |
| `TUXEDO-FIRMWARE.md` | Firmware internals: image format, flasher, kernel, OTA, the safe-write rule |
| `TUXEDO-BUILD.md` | Taking the stock image apart, changing the root filesystem, and proving the rebuild is correct |
| `TUXEDO-VERIFIED.md` | Ten high-severity findings put to skeptics told to refute them |
| `TUXEDO-AUDIT-BUGS.md` | 40 findings from the subsystem audit |
| `TUXEDO-LOCKOUT-PATCH.md` | Byte-level patch for the 3-strike web lockout, with review and recovery |
| `TUXEDO-FIX-STATUS.md` | Which bugs are actually fixed and where: mostly client-side, one in firmware |
| `TUXEDO-VIRTUAL-CONSOLE-BUGS.md` | Why the virtual console is unreliable |
| `TUXEDO-ZONE-PROGRAMMING.md` | Zone types and the descriptor vocabulary |

## The tools

| File | Does |
|---|---|
| `tuxedo_push.py` | Reads the push stream and decodes status frames |
| `tuxedo_api_console.py` | Working API console: REST, commands and the stream together |
| `tuxedo_console.py` | Virtual-console client |
| `tuxedo_status_probe.py` | Diagnoses why status goes stale, with a control |
| `tuxedo_wake_experiment.py` | Repeated quiet/active cycles, for replication |
| `fw_extract.py` | Carves filesystems out of header-wrapped firmware |
| `tuxedo_jffs2.py`, `tuxedo_jffs2_extract.py` | JFFS2 handling for the root filesystem |

Credentials are never hardcoded. Every tool takes `--password`, or reads
`TUXEDO_PASSWORD`, or prompts. Note that on this panel **the web password is
also the panel user code**, so a tool that can log in can arm and disarm.

### Data

`tuxedo_zone_tables.json` (zone types and descriptor words, machine-readable),
`tuxedo_audit_bugs.json`, `tuxedo_refutations.json`, and two measurement runs,
`tuxedo-decay.jsonl` and `tuxedo-probe-run2.jsonl`.

## The web login lockout

Worth stating plainly, because it governs how any client should behave:

- **Stock firmware disables every web account after three failed logins.** No
  timeout, no self-clear. Recovery is only at the touchscreen (account setup,
  Enable All, Apply).
- **Patched firmware** allows five attempts and arms a 300-second
  self-clearing lock on the sixth. The state is in memory, so a reboot clears
  it. The same patch fixes a 56-byte heap overflow.

There is **no version, model or firmware endpoint on the panel**, so a client
cannot detect which of the two it is talking to and must be safe on the
stricter one. In practice that means never retrying a rejected credential
automatically. `TUXEDO-LOCKOUT-PATCH.md` has the byte-level detail and the
recovery procedure.

## Relationship to the Home Assistant integration

`ha-tuxedo-touch` is the consumer, not part of this repo. Its own
`docs/tuxedo_touch_api_notes.md` is the integration-side API reference and is
maintained there deliberately, so it stays in step with the code that depends
on it. This repo is the firmware and protocol record underneath it.

## Handling

This repository is **private on the personal forge**. It documents unpatched
vulnerabilities in a commercial alarm product, including a heap overflow and a
lockout bypass, and it carries the panel's real address, MAC and account name
in usage examples.

None of that is a reason not to keep the work. It is a reason not to publish it
casually. Before any of this becomes public, two separate decisions are owed:
genericising the network detail, and whether the vendor should be contacted
first. Neither has been made.
