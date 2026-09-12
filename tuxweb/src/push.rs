//! Stage 8a: build the legacy push stream from IPC replies.
//!
//! Until stage 8 the stream came from Barracuda -- `shim.rs` opened
//! `GET /SimpleDebugger.interface/G.` over loopback and re-emitted the parts it
//! read. Blocker B1 (a POSIX mqueue delivers each message to exactly one reader)
//! means that source disappears the instant tuxweb holds `/Q_ServCmdTrsmtr`, so
//! the stream has to be GENERATED from the 556-byte replies instead. The frame
//! builders that do the reply->text formatting already live in `ipc.rs` and are
//! byte-verified against the captures; what this module adds is the layer above
//! them: which builder a reply's msgType selects, how many `-1` filler frames
//! trail it, and the fixed three-part connect preamble.
//!
//! **The emission pattern is measured, not invented.** Reproduced byte-for-byte
//! from the two capture fixtures (`tests/fixtures/*.bin`), and the counts were
//! cross-checked over both:
//!
//! | reply msgType | frame builder            | trailing `-1` fillers |
//! |---------------|--------------------------|-----------------------|
//! | 504 (register)| `frame_registration`     | 3 (`frame_registration_filler`) |
//! | 21  (status)  | `frame_status(quick_arm)`| 3 (`frame_filler`) |
//! | 18  (typed)   | `frame_typed(+0x08)`     | 0 |
//!
//! The filler count is per-msgType and 18 genuinely gets none -- the "three
//! after every status frame" note that used to sit on `ipc::frame_filler` was
//! too broad, and `every_reply_reproduces_its_captured_run` below is the
//! evidence.
//!
//! Connect preamble, identical in both fixtures and reproduced verbatim:
//! `['setCid',<n>]`, then the `Client Connected` status literal, then
//! `noOfClient`. After that comes the registration (504) and current status,
//! which for a client connecting mid-session come from [`PanelState`] rather
//! than from re-registering -- re-registering would flush the reply queue for
//! every other consumer (B7).

use std::collections::BTreeMap;

use crate::frame::{self, Part};
use crate::ipc::{self, Reply};

/// Trailing `-1` fillers per reply type. Named, with the evidence in the module
/// docs, so a change to one of these is a deliberate edit and not a silent drift.
const STATUS_FILLERS: usize = 3; // after a msgType 21
const REG_FILLERS: usize = 3; // after a msgType 504
const TYPED_FILLERS: usize = 0; // after a msgType 18

/// What a single reply turns into on the wire.
pub struct Emission {
    /// Legacy-shim parts to broadcast, in order: the frame, then its fillers.
    pub parts: Vec<Part>,
    /// A reply whose msgType this module does not yet format to a frame. §2.5:
    /// emit such a payload verbatim on a diagnostic channel rather than guess a
    /// shape a consumer would act on. Carries `(msg_type, raw)` so the caller
    /// can log it; `parts` is empty in that case, never a fabricated frame.
    pub undecoded: Option<(u32, Vec<u8>)>,
}

impl Emission {
    fn frames(parts: Vec<Part>) -> Emission {
        Emission { parts, undecoded: None }
    }
    fn unknown(msg_type: u32, raw: &[u8]) -> Emission {
        Emission { parts: Vec::new(), undecoded: Some((msg_type, raw.to_vec())) }
    }
}

/// Turn one raw 556-byte reply into the parts Barracuda would have emitted for
/// it. `quick_arm` is the trailing field of a status (21) frame -- from
/// `/opt/tuxedo/configuration/quickarmstate`, indexed by partition (§5.12); it
/// is ignored for every other type.
pub fn on_reply(raw: &[u8], quick_arm: u32) -> Emission {
    // parse() is the status-path view: session/msgType always, text at +0x0E.
    // Right for 21 and 18; deliberately NOT used to read a 504's payload.
    let Some(base) = Reply::parse(raw) else {
        // Too short even for the header. Nothing to emit and nothing to
        // diagnose usefully; the receive layer already logs SHORT messages.
        return Emission::frames(Vec::new());
    };

    match base.msg_type {
        504 => {
            // A 504 keeps nothing at +0x08 or +0x0E: read it at its own offsets.
            let (Some(r), Some(extra)) =
                (Reply::parse_504(raw), Reply::registration_extra(raw))
            else {
                return Emission::unknown(504, raw);
            };
            let mut parts = Vec::with_capacity(1 + REG_FILLERS);
            parts.push(frame::status_part(&ipc::frame_registration(&r, extra)));
            let filler = frame::status_part(&ipc::frame_registration_filler(&r, extra));
            for _ in 0..REG_FILLERS {
                parts.push(filler.clone());
            }
            Emission::frames(parts)
        }
        21 => {
            let mut parts = Vec::with_capacity(1 + STATUS_FILLERS);
            parts.push(frame::status_part(&ipc::frame_status(&base, quick_arm)));
            let filler = frame::status_part(&ipc::frame_filler(&base));
            for _ in 0..STATUS_FILLERS {
                parts.push(filler.clone());
            }
            Emission::frames(parts)
        }
        18 => {
            // frame_typed's trailing value is the reply's +0x08, which for an 18
            // is uninitialised stack the panel prints anyway (`ipc.rs`). Pass it
            // through verbatim -- never synthesise it -- so `r.arg` is exactly
            // right here. TYPED_FILLERS is 0.
            let mut parts = Vec::with_capacity(1 + TYPED_FILLERS);
            parts.push(frame::status_part(&ipc::frame_typed(&base, base.arg)));
            Emission::frames(parts)
        }
        // 22 shares frame_typed's shape with 18 but is the status-when-not-online
        // variant, and NEITHER fixture contains one -- so its filler count is
        // unproven. Route it to the diagnostic channel rather than guess; a
        // capture with a 22 in it promotes this to a real branch.
        other => Emission::unknown(other, raw),
    }
}

/// The three parts every connection opens with, in the fixtures' order.
///
/// `cid` is per-connection (the fixtures carry 1315689843 and 3461147938), so a
/// caller mints its own; byte-identity is a property of the shape. `n_clients`
/// is what the panel reported as `noOfClient` -- 2 in both captures.
pub fn connect_preamble(cid: u32, n_clients: u32) -> Vec<Part> {
    vec![
        frame::setcid_part(cid),
        frame::status_part(ipc::literal::CLIENT_CONNECTED),
        frame::noofclient_part(n_clients),
    ]
}

/// The current panel state, rebuilt from the reply stream (§2.4 "state: panel
/// model, rebuilt from reply msgTypes").
///
/// tuxweb registers ONCE and stays registered; a web client that connects later
/// must not trigger another 500, because `registerclient` flushes the reply
/// queue for everyone (B7). So the current registration and the latest status
/// per partition are cached here and replayed to a new subscriber instead.
///
/// **Scope of the evidence:** `on_reply` and `connect_preamble` are proven
/// byte-for-byte against the captures. The *replay* a late-joining client
/// receives is a design choice -- both captures are connect-from-start, so what
/// Barracuda sends a mid-session joiner is not in the corpus. This reproduces
/// current state (registration + latest status), which is what the consumer
/// needs; it is not claimed to be byte-identical to an unobserved vendor replay.
#[derive(Default)]
pub struct PanelState {
    /// Raw registration (504) reply.
    last_504: Option<Vec<u8>>,
    /// Latest raw reply per (msgType, arg); arg distinguishes partitions.
    latest: BTreeMap<(u32, u32), Vec<u8>>,
    /// The most recent status (21) reply, kept for arm-state queries and command
    /// confirmation. The state byte here is the same `0xFE`/`0xFF` an armed/
    /// disarmed transition flips, which is how a command is confirmed to have
    /// ACTED rather than merely been sent (§4.10.3).
    last_21: Option<Vec<u8>>,
}

/// Minimal JSON string escaping for a value taken from panel text.
fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

impl PanelState {
    pub fn new() -> PanelState {
        PanelState::default()
    }

    /// Record a reply and return what to broadcast for it now. The caller feeds
    /// every received reply through here; the state update and the live
    /// emission are one call so they cannot fall out of step.
    pub fn observe(&mut self, raw: &[u8], quick_arm: u32) -> Emission {
        if let Some(r) = Reply::parse(raw) {
            match r.msg_type {
                504 => self.last_504 = Some(raw.to_vec()),
                21 | 18 => {
                    self.latest.insert((r.msg_type, r.arg), raw.to_vec());
                    if r.msg_type == 21 {
                        self.last_21 = Some(raw.to_vec());
                    }
                }
                _ => {}
            }
        }
        on_reply(raw, quick_arm)
    }

    /// The current arm-state byte from the latest status: `0xFF` armed/arming,
    /// `0xFE` ready/disarmed (`enableDisarmOption()`, §2.5). `None` until a
    /// status has been seen.
    pub fn arm_state_byte(&self) -> Option<u8> {
        self.last_21.as_ref().and_then(|r| Reply::parse(r)).and_then(|r| r.state_byte())
    }

    /// Whether the panel is armed or arming right now (`0xFF`).
    pub fn is_armed(&self) -> Option<bool> {
        self.arm_state_byte().map(|b| b == 0xFF)
    }

    /// A JSON status object for the read-only status endpoint (`status_refresh`).
    /// Reports the current partition, whether armed, and the display text (the
    /// bytes after the state byte). Built from the model, so there is no cache to
    /// go stale (§4.10.3, the defect that started the project).
    pub fn status_json(&self) -> String {
        let partition = self.current_partition();
        let (armed, display) = match self.last_21.as_ref().and_then(|r| Reply::parse(r)) {
            Some(r) => {
                let armed = r.state_byte() == Some(0xFF);
                let disp = if r.text.len() > 1 { &r.text[1..] } else { &[][..] };
                (armed, String::from_utf8_lossy(disp).to_string())
            }
            None => (false, String::new()),
        };
        format!(
            "{{\"partition\":{partition},\"armed\":{armed},\"state\":\"{}\"}}",
            json_escape(&display)
        )
    }

    /// Parts to hand a newly connected client: the preamble, then current state.
    ///
    /// `quick_arm` for a replayed 21 is read from `quickarm_path` indexed by the
    /// current partition -- the SAME source and index the live path uses, so a
    /// snapshot frame and the live frame that supersedes it agree on that field.
    /// Passing a bare number here was the bug that made a snapshot's status carry
    /// `:0` while the live update carried `:2`.
    pub fn snapshot(&self, cid: u32, n_clients: u32, quickarm_path: &str) -> Vec<Part> {
        let mut parts = connect_preamble(cid, n_clients);
        let quick = read_quick_arm(quickarm_path, self.current_partition());
        if let Some(raw) = &self.last_504 {
            parts.extend(on_reply(raw, quick).parts); // a 504 ignores quick_arm
        }
        for raw in self.latest.values() {
            parts.extend(on_reply(raw, quick).parts); // a 21 uses it; an 18 ignores it
        }
        parts
    }

    pub fn has_registration(&self) -> bool {
        self.last_504.is_some()
    }

    /// The current partition, from the last registration's `+0x90`
    /// (`GetCurrentPartition`). 1 until a 504 has been seen -- a single-partition
    /// panel is partition 1, which is also what the captures show.
    pub fn current_partition(&self) -> u32 {
        self.last_504
            .as_ref()
            .and_then(|raw| raw.get(0x90).copied())
            .filter(|&p| p != 0)
            .map(u32::from)
            .unwrap_or(1)
    }
}

/// The `quick_arm` trailing field of a status (21) frame: `quickarmstate`,
/// eight ints, indexed by partition (§5.12).
///
/// `getQuickArmStatus` reads `byte[0x55ba18 + partition - 1]` after loading the
/// file, so this indexes the same way. A missing or short file yields 0 -- the
/// vendor tolerates a missing `quickarmstate_` sidecar and so must we, and 0 is
/// the safe default (no quick-arm) rather than a guess.
pub fn read_quick_arm(path: &str, partition: u32) -> u32 {
    let Ok(s) = std::fs::read_to_string(path) else {
        return 0;
    };
    let idx = partition.saturating_sub(1) as usize;
    s.split_whitespace()
        .nth(idx)
        .and_then(|t| t.parse::<u32>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw status/typed reply the way `parse` reads it.
    fn raw_reply(session: u32, msg_type: u32, arg: u32, text: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; ipc::REPLY_LEN];
        b[0x00..0x04].copy_from_slice(&session.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&msg_type.to_le_bytes());
        b[0x08..0x0C].copy_from_slice(&arg.to_le_bytes());
        b[0x0E..0x0E + text.len()].copy_from_slice(text);
        b
    }

    /// Build a raw 504 the way `parse_504`/`registration_extra` read it.
    fn raw_504(session: u32, part: u8, desc: &[u8], extra: [u32; 4]) -> Vec<u8> {
        let mut b = vec![0u8; ipc::REPLY_LEN];
        b[0x00..0x04].copy_from_slice(&session.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&504u32.to_le_bytes());
        b[0x90] = part;
        b[0x91..0x91 + desc.len()].copy_from_slice(desc);
        b[0xAF] = extra[0] as u8;
        b[0xB1] = extra[1] as u8;
        b[0xB2] = extra[2] as u8;
        b[0xB4..0xB8].copy_from_slice(&extra[3].to_le_bytes());
        b
    }

    /// The status texts inside an emission's parts, asserting each part really
    /// is a `statusMessageText` envelope (a 504 or 21 or 18 frame rides inside
    /// one, exactly like the fillers).
    fn emitted_texts(e: &Emission) -> Vec<Vec<u8>> {
        e.parts
            .iter()
            .map(|p| match crate::frame::classify(p) {
                crate::frame::Message::StatusText(t) => t,
                other => panic!("emitted part is not a statusMessageText: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn a_status_reply_becomes_a_frame_and_three_fillers() {
        let mut text = vec![0xFEu8];
        text.extend_from_slice(b"1Ready To Arm");
        let e = on_reply(&raw_reply(0, 21, 1, &text), 2);
        assert!(e.undecoded.is_none());
        assert_eq!(e.parts.len(), 1 + STATUS_FILLERS);
        // the head is the status frame, the tail three identical fillers
        let base = Reply { session: 0, msg_type: 21, arg: 1, text: text.clone() };
        assert_eq!(e.parts[0], frame::status_part(&ipc::frame_status(&base, 2)));
        let filler = frame::status_part(&ipc::frame_filler(&base));
        for p in &e.parts[1..] {
            assert_eq!(*p, filler);
        }
    }

    #[test]
    fn a_typed_reply_has_no_fillers() {
        let e = on_reply(&raw_reply(0, 18, 2, b"1 P1  H"), 0);
        assert!(e.undecoded.is_none());
        assert_eq!(e.parts.len(), 1, "msgType 18 gets zero fillers");
        let base = Reply { session: 0, msg_type: 18, arg: 2, text: b"1 P1  H".to_vec() };
        assert_eq!(e.parts[0], frame::status_part(&ipc::frame_typed(&base, 2)));
    }

    #[test]
    fn a_registration_reply_becomes_a_504_and_three_reg_fillers() {
        let e = on_reply(&raw_504(0, 1, b"P1  H", [1, 0, 3, 3]), 0);
        assert!(e.undecoded.is_none());
        assert_eq!(e.parts.len(), 1 + REG_FILLERS);
        assert_eq!(e.parts[0].0, b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\"0:504:1:P1  H:1:0:3:3\"]]");
        // the fillers differ from the head only in the type slot (-1)
        assert_eq!(e.parts[1].0, b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\"0:-1:1:P1  H:1:0:3:3\"]]");
    }

    #[test]
    fn an_unknown_type_is_diagnosed_not_guessed() {
        // msgType 22 has no fixture, so it must not be fabricated onto the
        // legacy stream. It goes to the diagnostic channel with its raw bytes.
        let raw = raw_reply(0, 22, 1, b"\xfe1Ready To Arm");
        let e = on_reply(&raw, 2);
        assert!(e.parts.is_empty(), "no fabricated frame for an unproven type");
        assert_eq!(e.undecoded.as_ref().map(|(t, _)| *t), Some(22));
        assert_eq!(e.undecoded.unwrap().1, raw, "the raw reply is preserved verbatim");
    }

    #[test]
    fn connect_preamble_is_the_three_parts_both_captures_open_with() {
        let p = connect_preamble(1315689843, 2);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0], frame::setcid_part(1315689843));
        assert_eq!(p[1], frame::status_part(b"Client Connected"));
        assert_eq!(p[2], frame::noofclient_part(2));
        // and each classifies back to the shape it is
        assert!(matches!(frame::classify(&p[0]), frame::Message::SetCid(_)));
        assert!(matches!(frame::classify(&p[1]), frame::Message::StatusText(_)));
        assert!(matches!(frame::classify(&p[2]), frame::Message::NoOfClient(_)));
    }

    #[test]
    fn panel_state_replays_registration_and_latest_status() {
        let mut st = PanelState::new();
        assert!(!st.has_registration());
        st.observe(&raw_504(0, 1, b"P1  H", [1, 0, 3, 3]), 0);
        assert!(st.has_registration());
        let mut text = vec![0xFEu8];
        text.extend_from_slice(b"1Ready To Arm");
        st.observe(&raw_reply(0, 21, 1, &text), 2);
        // a newer status for the same partition replaces the older
        let mut armed = vec![0xFFu8];
        armed.extend_from_slice(b"2Armed Stay");
        st.observe(&raw_reply(0, 21, 1, &armed), 2);

        // quick_arm comes from the file, indexed by the current partition (1 here)
        let qa = std::env::temp_dir().join(format!("qa-snap-{}", std::process::id()));
        std::fs::write(&qa, "7 0 0 0 0 0 0 0\n").unwrap();
        let snap = st.snapshot(42, 2, qa.to_str().unwrap());
        let _ = std::fs::remove_file(&qa);

        // the first part is the per-connection setCid
        assert!(matches!(frame::classify(&snap[0]), frame::Message::SetCid(_)));
        // registration present, and the LATEST status (armed), not the stale one,
        // and it must carry the quick_arm read from the file (:7), not a 0
        let text_of = |s: &[u8]| snap.iter().any(|p| {
            matches!(frame::classify(p), frame::Message::StatusText(t) if t.windows(s.len()).any(|w| w == s))
        });
        assert!(text_of(b"504:1:P1  H"), "registration must be replayed");
        assert!(text_of(b"2Armed Stay:7"), "latest status replayed WITH the file's quick_arm");
        assert!(!text_of(b"1Ready To Arm"), "the superseded status must not be");
    }

    #[test]
    fn arm_state_and_status_track_the_latest_21() {
        let mut st = PanelState::new();
        assert_eq!(st.arm_state_byte(), None, "no status seen yet");
        assert_eq!(st.is_armed(), None);
        st.observe(&raw_504(0, 1, b"P1  H", [1, 0, 3, 3]), 0);

        let mut ready = vec![0xFEu8];
        ready.extend_from_slice(b"1Ready To Arm");
        st.observe(&raw_reply(0, 21, 1, &ready), 2);
        assert_eq!(st.is_armed(), Some(false));
        assert!(st.status_json().contains("\"armed\":false"));
        assert!(st.status_json().contains("\"partition\":1"));
        assert!(st.status_json().contains("Ready To Arm"));

        let mut armed = vec![0xFFu8];
        armed.extend_from_slice(b"2Armed Stay");
        st.observe(&raw_reply(0, 21, 1, &armed), 2);
        assert_eq!(st.arm_state_byte(), Some(0xFF));
        assert_eq!(st.is_armed(), Some(true));
        assert!(st.status_json().contains("\"armed\":true"), "{}", st.status_json());
    }

    #[test]
    fn current_partition_comes_from_the_registration() {
        let mut st = PanelState::new();
        assert_eq!(st.current_partition(), 1, "default is partition 1 before any 504");
        st.observe(&raw_504(0, 2, b"P2  H", [1, 0, 3, 3]), 0);
        assert_eq!(st.current_partition(), 2);
    }

    #[test]
    fn quick_arm_indexes_the_state_file_by_partition() {
        let p = std::env::temp_dir().join(format!("qa-{}", std::process::id()));
        std::fs::write(&p, "2 5 0 0 0 0 0 0\n").unwrap();
        let path = p.to_str().unwrap();
        assert_eq!(read_quick_arm(path, 1), 2, "partition 1 -> first value, as §5.12 measured");
        assert_eq!(read_quick_arm(path, 2), 5);
        assert_eq!(read_quick_arm(path, 9), 0, "past the eight ints -> 0, not a panic");
        let _ = std::fs::remove_file(&p);
        // a missing file is tolerated (no quickarmstate_ sidecar either) -> 0
        assert_eq!(read_quick_arm(path, 1), 0);
    }

    /// The arbiter test: every real status frame in both captures, when its
    /// reply is reconstructed and run through `on_reply`, must reproduce that
    /// frame followed by EXACTLY the filler frames that trail it in the capture.
    ///
    /// This is where the dispatch (which builder per msgType) and the filler
    /// counts are checked against evidence rather than against this module's own
    /// idea of them -- and it can go red, which is the whole point.
    #[test]
    fn every_reply_reproduces_its_captured_run() {
        let idle = include_bytes!("../tests/fixtures/push-idle-300s.bin");
        let armed = include_bytes!("../tests/fixtures/push-armcycle.bin");

        let num = |b: &[u8]| std::str::from_utf8(b).ok()?.parse::<u32>().ok();
        let mut checked = 0usize;

        for cap in [&idle[..], &armed[..]] {
            // classify every part to (kind, text) once
            let parts = crate::frame::parse(cap).0;
            let msgs: Vec<crate::frame::Message> =
                parts.iter().map(crate::frame::classify).collect();
            // pull the StatusText payloads in order; the preamble/noOfClient/
            // setCid parts are checked by frame.rs's own test
            let texts: Vec<Vec<u8>> = msgs
                .iter()
                .filter_map(|m| match m {
                    crate::frame::Message::StatusText(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();

            let mut i = 0;
            while i < texts.len() {
                let t = &texts[i];
                let f: Vec<&[u8]> = t.split(|&b| b == b':').collect();
                // a real status frame has a numeric type in field 1 that is not -1
                let is_real = f.len() >= 2 && f[1] != b"-1" && num(f[0]).is_some() && num(f[1]).is_some();
                if !is_real {
                    i += 1;
                    continue;
                }
                // gather the run of trailing "-1" fillers
                let mut fillers: Vec<Vec<u8>> = Vec::new();
                let mut j = i + 1;
                while j < texts.len() {
                    let g: Vec<&[u8]> = texts[j].split(|&b| b == b':').collect();
                    if g.len() >= 2 && g[1] == b"-1" && num(g[0]).is_some() {
                        fillers.push(texts[j].clone());
                        j += 1;
                    } else {
                        break;
                    }
                }

                // reconstruct the reply and the quick_arm for this frame
                let ty = num(f[1]).unwrap();
                let (raw, quick) = match ty {
                    21 => {
                        // session:21:arg:hex:text:quick
                        assert_eq!(f.len(), 6, "unexpected 21 field count: {t:?}");
                        let (s, arg, q) = (num(f[0]).unwrap(), num(f[2]).unwrap(), num(f[5]).unwrap());
                        (raw_reply(s, 21, arg, f[4]), q)
                    }
                    18 => {
                        // session:18:text:trailing
                        assert_eq!(f.len(), 4, "unexpected 18 field count: {t:?}");
                        let (s, tr) = (num(f[0]).unwrap(), num(f[3]).unwrap());
                        (raw_reply(s, 18, tr, f[2]), 0)
                    }
                    504 => {
                        // session:504:arg:text:a:b:c:d
                        assert_eq!(f.len(), 8, "unexpected 504 field count: {t:?}");
                        let s = num(f[0]).unwrap();
                        let arg = num(f[2]).unwrap() as u8;
                        let e = [num(f[4]).unwrap(), num(f[5]).unwrap(), num(f[6]).unwrap(), num(f[7]).unwrap()];
                        // session goes at +0x00, but the captured frames all use 0
                        let mut b = raw_504(s, arg, f[3], e);
                        b[0x00..0x04].copy_from_slice(&s.to_le_bytes());
                        (b, 0)
                    }
                    other => panic!("capture holds an unexpected real msgType {other}: {t:?}"),
                };

                let got = on_reply(&raw, quick);
                assert!(got.undecoded.is_none(), "type {ty} routed to diagnostic");
                let want: Vec<Vec<u8>> = std::iter::once(t.clone()).chain(fillers.clone()).collect();
                assert_eq!(emitted_texts(&got), want, "run for msgType {ty} drifted");
                checked += 1;
                i = j;
            }
        }
        assert!(checked >= 30, "expected many runs reproduced, got {checked}");
        println!("reproduced {checked} reply->run emissions from the captures");
    }
}
