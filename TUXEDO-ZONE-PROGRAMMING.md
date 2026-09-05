# Zone types and zone data — for pre-populating a field programmer

Extracted from the `tuxedo` binary's symbol table and data sections. All
**[CONFIRMED]** by disassembling the lookup functions and reading the tables
they index.

Purpose: let an Envisalink-based field programmer pre-populate zone settings
instead of asking the user to type everything from scratch.

---

## The Tuxedo has a built-in panel programmer

`CQuickProgramming` is a full zone-programming UI inside the Tuxedo, operating
on two structures, `PANEL_INFO` and `ZONE_DATA`:

```
CQuickProgramming::Set_P5Attr_DefaultValue(unsigned char, PANEL_INFO*, ZONE_DATA*)
CQuickProgramming::sltHandleZoneTypeChanged(QString const&)
CQuickProgramming::sltHandleHwConfigChanged(int)      // hardwired vs RF
CQuickProgramming::sltHandleInputTypeChanged(int)
myQuickP::GetZoneData(unsigned char)   /   apl_QuickP_GetZoneData(unsigned char)
```

So the panel's zone configuration is **readable**, not just writable — the
Tuxedo reads it to populate its own editor. The read accessors:

```
GetZoneTypeByZoneNo(int, int*)            <- zone type for a zone number
GetZoneDescByZoneNo(int, char*)           <- zone description
GetZoneDeviceType(int, int, char*)        <- hardwire / RF / etc
GetZoneNumber(int, int, int*)
GetZoneTypeByZnIndex(int, int, char*)
myPanel::GetZoneInformationByZoneNo(char, int, int*, char*)
myPanel::GetZoneInformation(char, int, int, int*, char*)
myPartition::GetZoneInformation(char, int, int*, char*)
Apl_GetZoneList(AplMessage)   /   Apl_GetZoneDesc(AplMessage)
AskFromPanel(int, int, unsigned*, void*, void*, bool)     <- the generic query
```

`AskFromPanel` is the primitive worth studying: a generic "ask the panel for X"
call that the zone getters sit on top of.

---

## Zone type table — the numbering a programmer needs

Table at `0x0060557c`, 8 bytes per entry, code at `+1`, name pointer at `+4`.
Read by `Get_ZoneTypeIndex(unsigned char)` @`0x00453610` and
`Get_ZoneTypeDesp(PANEL_INFO*, ZONE_DATA*, unsigned char)` @`0x00453764`.

**Note the codes are not contiguous** — a UI that assumes 0..23 will be wrong.

| Code | Type |
|---:|---|
| 0 | Not Used |
| 1 | Entry/Exit 1 |
| 2 | Entry/Exit 2 |
| 3 | Perimeter |
| 4 | Interior Follower |
| 5 | Day/Night |
| 6 | 24-Hr Silent |
| 7 | 24-Hr Audible |
| 8 | 24-Hr Aux |
| 9 | Fire |
| 10 | Interior w/Delay |
| 12 | Monitor Zone |
| 14 | Carbon Monoxide |
| 15 | Medical |
| 16 | Fire w/Verify |
| 19 | 24hr Trouble |
| 20 | Arm-Stay |
| 21 | Arm-Away |
| 22 | Disarm |
| 23 | No Alarm Response |
| 24 | Silent Burglary |
| 31 | Chime Zone |
| 77 | Keyswitch |
| 81 | AAV Monitor Zone |

### Three types are panel-dependent — **[CONFIRMED]**

`Get_ZoneTypeDesp` gates three codes on feature flags in `PANEL_INFO` (a flag
byte at offset `+4`). If the flag is clear, the type is **not offered**:

| Code | Type | Gated on |
|---:|---|---|
| 15 | Medical | flag bit `0x80` (tested as a sign bit) |
| 19 | 24hr Trouble | flag bit `0x40` |
| 31 | Chime Zone | flag bit `0x20` |

A field programmer should read those feature flags before offering these three,
or it will present zone types the panel will reject.

Valid index range is 1–24; index 0 and anything above `0x18` return null.

---

## Zone descriptions are built from a fixed word library

Second table at `0x00604f4c`, same 8-byte stride, indices up to `0xc5` (197).
It is the **alpha descriptor vocabulary** — VISTA zone names are not free text;
they are sequences of indices into this fixed word list.

The first entries run alphabetically:

```
1 AIR        2 ALARM      3 ALLEY     4 AMBUSH    5 AREA
6 APARTMENT  7 ATTIC      8 AUDIO     9 BABY     10 BACK
11 BAR      12 BASEMENT  13 BATHROOM 14 BED      15 BEDROOM
...continuing alphabetically to index 197
```

**This is the key to rendering and composing zone descriptions.** To show a
human-readable zone name you resolve each index through this table; to *set*
one you must choose words that exist in it. A programmer UI can offer the list
as a picker rather than a free-text box that produces invalid descriptors.

The full 197-entry table is in the binary at that address and can be dumped with
the same 8-byte-stride walk used above; it is reproduced here only in part
because the structure, not the word list, is the reusable finding.

Note the audio vocabulary in `opt/tuxedo/audio/*.wav` mirrors this list
(`ATTIC.wav`, `BASEMENT.wav`, `BEDROOM.wav`…) — the same words the panel speaks
aloud, which is a useful cross-check that the table has been read correctly.

---

## What this does and does not give you

**Gives you [CONFIRMED]:** the zone type numbering with names, the panel-feature
gating on three of them, and the structure of the description vocabulary. That
is enough to build a correct picker UI and to interpret zone data you read by
any means.

**Does not give you [UNKNOWN]:** the wire format for *reading* zone
configuration from the panel. The Tuxedo does it over ECP via `AskFromPanel`,
but whether an Envisalink can issue the equivalent request over TPI is a
separate question — the TPI is a higher-level interface and may not expose the
raw ECP exchange.

**The pragmatic path** for the field programmer is probably unchanged: enter
programming mode and read fields back with `#` rather than `*` (view rather than
write). What the tables above add is that once the numbers come back, they can
now be **rendered correctly** — zone type 4 shown as "Interior Follower" rather
than as `4`, and a descriptor's word indices resolved to words.

That alone removes most of the guesswork from pre-populating.
