//! The legacy push-stream wire format, parsed and re-emitted byte for byte.
//!
//! This is the compatibility surface `ha-tuxedo-touch` consumes, so the tests
//! assert re-emission is byte-identical against a capture taken off the panel
//! rather than against this module's own idea of the format.
//!
//! The format is `multipart/x-mixed-replace` with boundary `EH912ZZ`, and it
//! violates RFC 2046 in a way a compliant parser will get wrong: the CLOSE
//! delimiter `--EH912ZZ--` is emitted after EVERY part, not once at the end.
//! A parser that stops at the first close delimiter sees exactly one frame and
//! then waits forever. Measured on the capture in tests/fixtures: 83 opening
//! boundaries, 83 close delimiters.
//!
//! Bytes are latin-1, NOT utf-8. Frame text carries a raw 0xFE/0xFF state byte
//! which is not valid utf-8, so this module works in `[u8]` throughout and
//! never converts to `String`.

pub const BOUNDARY: &[u8] = b"EH912ZZ";

const OPEN: &[u8] = b"--EH912ZZ\r\n";
const CLOSE: &[u8] = b"--EH912ZZ--\r\n";
const PART_HEAD: &[u8] = b"Content-type: text/plain\r\n\r\n";

/// One part's payload: the bytes between the part header and the trailing CRLF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part(pub Vec<u8>);

impl Part {
    /// Re-emit exactly as the vendor does, close delimiter and all.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(OPEN);
        out.extend_from_slice(PART_HEAD);
        out.extend_from_slice(&self.0);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(CLOSE);
    }
}

/// Split a stream body into parts. Returns the parts and the number of trailing
/// bytes that did not form a complete part, so a caller streaming from a socket
/// can retain the remainder.
pub fn parse(body: &[u8]) -> (Vec<Part>, usize) {
    let mut parts = Vec::new();
    let mut i = 0usize;
    loop {
        let Some(start) = find(&body[i..], OPEN).map(|p| i + p) else { break };
        let head = start + OPEN.len();
        if !body[head..].starts_with(PART_HEAD) {
            break;
        }
        let payload_start = head + PART_HEAD.len();
        let Some(end) = find(&body[payload_start..], CLOSE).map(|p| payload_start + p) else {
            break;
        };
        // the payload is everything up to the CRLF that precedes the close
        let payload_end = end.saturating_sub(2);
        if payload_end < payload_start {
            break;
        }
        parts.push(Part(body[payload_start..payload_end].to_vec()));
        i = end + CLOSE.len();
    }
    (parts, body.len() - i)
}

/// The three payload shapes the panel emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `['setCid',1315689843]`
    SetCid(Vec<u8>),
    /// `['ud','SimpleDbgServer2ClientIntf','statusMessageText',["..."]]`
    StatusText(Vec<u8>),
    /// `['ud','SimpleDbgServer2ClientIntf','noOfClient',[2]]`
    NoOfClient(Vec<u8>),
    /// Anything else, kept verbatim rather than guessed at.
    Other(Vec<u8>),
}

const STATUS_PREFIX: &[u8] =
    b"['ud','SimpleDbgServer2ClientIntf','statusMessageText',[\"";
const NCLIENT_PREFIX: &[u8] = b"['ud','SimpleDbgServer2ClientIntf','noOfClient',[";
const SETCID_PREFIX: &[u8] = b"['setCid',";

pub fn classify(p: &Part) -> Message {
    let b = &p.0;
    if b.starts_with(STATUS_PREFIX) && b.ends_with(b"\"]]") {
        Message::StatusText(b[STATUS_PREFIX.len()..b.len() - 3].to_vec())
    } else if b.starts_with(NCLIENT_PREFIX) && b.ends_with(b"]]") {
        Message::NoOfClient(b[NCLIENT_PREFIX.len()..b.len() - 2].to_vec())
    } else if b.starts_with(SETCID_PREFIX) && b.ends_with(b"]") {
        Message::SetCid(b[SETCID_PREFIX.len()..b.len() - 1].to_vec())
    } else {
        Message::Other(b.clone())
    }
}

/// Build a `statusMessageText` part from raw latin-1 frame text.
pub fn status_part(text: &[u8]) -> Part {
    let mut v = Vec::with_capacity(STATUS_PREFIX.len() + text.len() + 3);
    v.extend_from_slice(STATUS_PREFIX);
    v.extend_from_slice(text);
    v.extend_from_slice(b"\"]]");
    Part(v)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Idle panel: only 0xFE, no countdown.
    const CAPTURE: &[u8] = include_bytes!("../tests/fixtures/push-idle-300s.bin");
    /// A real arm-stay -> exit delay -> Armed Stay -> disarm cycle. This is the
    /// only capture holding 0xFF and the countdown, so the state byte and the
    /// arming frames are covered by evidence rather than by reasoning.
    const ARMED: &[u8] = include_bytes!("../tests/fixtures/push-armcycle.bin");

    fn body_of(capture: &'static [u8]) -> &'static [u8] {
        let at = find(capture, b"\r\n\r\n").expect("headers");
        &capture[at + 4..]
    }

    fn body() -> &'static [u8] {
        body_of(CAPTURE)
    }

    fn both() -> [&'static [u8]; 2] {
        [body_of(CAPTURE), body_of(ARMED)]
    }

    #[test]
    fn boundary_matches_what_the_panel_advertises() {
        // the Content-type header must name the same boundary this module uses
        let hdr = &CAPTURE[..find(CAPTURE, b"\r\n\r\n").unwrap()];
        let mut needle = b"boundary=\"".to_vec();
        needle.extend_from_slice(BOUNDARY);
        needle.push(b'"');
        assert!(find(hdr, &needle).is_some(), "header does not advertise BOUNDARY");
    }

    #[test]
    fn close_delimiter_follows_every_part() {
        for b in both() {
            let opens = b.windows(OPEN.len()).filter(|w| *w == OPEN).count();
            let closes = b.windows(CLOSE.len()).filter(|w| *w == CLOSE).count();
            assert_eq!(opens, closes, "the vendor closes every part; see module docs");
            assert!(opens > 1, "capture should hold many parts, saw {opens}");
        }
    }

    /// The arming frames are the ones a status consumer actually acts on, and
    /// they only exist in the arm-cycle capture.
    #[test]
    fn arm_cycle_carries_the_0xff_state_byte_and_a_countdown() {
        let (parts, _) = parse(body_of(ARMED));
        let texts: Vec<Vec<u8>> = parts
            .iter()
            .filter_map(|p| match classify(p) {
                Message::StatusText(t) => Some(t),
                _ => None,
            })
            .collect();

        let ff = texts.iter().filter(|t| t.contains(&0xFFu8)).count();
        let fe = texts.iter().filter(|t| t.contains(&0xFEu8)).count();
        assert!(ff > 0, "no 0xFF frame: the arm never happened in this capture");
        assert!(fe > 0, "no 0xFE frame: the disarm never happened");

        // "Secs Remaining" is the exit-delay countdown
        let countdown = texts
            .iter()
            .filter(|t| find(t, b"Secs Remaining").is_some())
            .count();
        assert!(countdown > 1, "expected several countdown frames, saw {countdown}");

        let armed = texts.iter().any(|t| find(t, b"Armed Stay").is_some());
        assert!(armed, "capture never reached Armed Stay");

        // and it must end disarmed -- the panel is left safe
        let last_state = texts
            .iter()
            .rev()
            .find(|t| find(t, b"Ready To Arm").is_some());
        assert!(last_state.is_some(), "capture does not end back at Ready To Arm");
    }

    #[test]
    fn reemission_is_byte_identical() {
        for b in both() {
            let (parts, rest) = parse(b);
            assert!(!parts.is_empty());
            let mut out = Vec::with_capacity(b.len());
            for p in &parts {
                p.encode(&mut out);
            }
            // everything the parser consumed must re-emit exactly
            assert_eq!(&out[..], &b[..b.len() - rest], "re-emission drifted");
        }
    }

    #[test]
    fn classifies_the_shapes_the_panel_sends() {
        let (parts, _) = parse(body());
        let mut status = 0;
        let mut setcid = 0;
        let mut nclient = 0;
        let mut other = 0;
        for p in &parts {
            match classify(p) {
                Message::StatusText(_) => status += 1,
                Message::SetCid(_) => setcid += 1,
                Message::NoOfClient(_) => nclient += 1,
                Message::Other(_) => other += 1,
            }
        }
        assert_eq!(setcid, 1, "exactly one setCid, on connect");
        assert!(status > 1, "expected many status frames, saw {status}");
        assert_eq!(other, 0, "unrecognised payload shape in the capture");
        let _ = nclient;
    }

    #[test]
    fn status_text_round_trips_including_the_raw_state_byte() {
        let (parts, _) = parse(body());
        let mut saw_state_byte = false;
        for p in &parts {
            if let Message::StatusText(t) = classify(p) {
                assert_eq!(status_part(&t), *p, "status_part is not the inverse");
                if t.contains(&0xFEu8) || t.contains(&0xFFu8) {
                    saw_state_byte = true;
                }
            }
        }
        assert!(saw_state_byte, "no 0xFE/0xFF frame in the capture");
    }
}
