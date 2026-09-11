//! Stage 6: hold the reply queue as sole reader, log what arrives, send nothing.
//!
//! This is the decisive test of the whole replacement plan (§5.1): whether a
//! process other than Barracuda actually receives `/tuxedo`'s replies. Every
//! other stage was arranged so that when this one fails, it fails for a reason
//! already eliminated.
//!
//! **It sends nothing.** The reply queue is opened `O_RDONLY`, so "we do not
//! command the panel during this window" is a property of the file descriptor
//! rather than a promise about the code. The touchscreen keeps full control
//! throughout, which is the point — the web UI going quiet for fifteen minutes
//! is the cost, and it is the whole cost.
//!
//! Failure handling is uniform and blunt: **anything that goes wrong before we
//! reach a steady state hands the panel back to the vendor.** Not a retry, not
//! a log-and-continue. The panel is an alarm system and the fallback is a
//! working vendor stack that is one `execve` away.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::deadman::{hand_back_to_vendor, Deadman};
use crate::ipc::Reply;
use crate::mq::Queue;

/// One window, armed deliberately, consumed on entry.
///
/// This exists because of how the stage actually has to be deployed, which is
/// not obvious until the revert paths are followed all the way through.
///
/// The cutover needs the reply queue, so the vendor must not be holding it. But
/// `supervis` relaunches whatever is at `/opt/webserver/Barracuda` within ~5 s
/// (§5.2), so the only way to be the process that holds the queue is to BE the
/// thing at that path — which is what stage 5 proved is possible. `tuxweb`
/// therefore has to decide, when `supervis` launches it with no arguments,
/// whether this is a cutover or a passthrough.
///
/// A marker file decides, and **entering deletes it**. That is the whole safety
/// property: one marker is exactly one window. Without the delete, a cutover
/// that crashed would be relaunched by `supervis` straight back into another
/// cutover, and again, and that is a loop that ends at the 24-relaunch watchdog
/// reset — the failure this stage is most anxious to avoid, reached by the
/// mechanism meant to prevent it.
///
/// After the marker is consumed, every later relaunch passes through to the
/// vendor. The panel converges on the vendor stack from any failure.
pub const ARM_MARKER: &str = "/opt/tuxedo/configuration/tuxweb-cutover.arm";

/// Consume the marker. `Some(body)` means this launch is the armed window.
///
/// Deleted before the window opens, not after it closes: "after" is a promise
/// that a crash breaks, and a crash is exactly when it matters.
///
/// The CONTENTS select what the window does. Empty -- the stage-6 form -- is the
/// read-only cutover. Anything else names a stage-7 run, because supervis launches
/// us as argv[0] = "Barracuda" with NO arguments, so a command-line flag cannot
/// reach a window. The marker is the only channel that exists.
///
/// Read BEFORE the delete, and the delete still decides whether the window opens:
/// one marker is one window, and a failed remove means not armed, so a crash cannot
/// be relaunched into a second window and onward into the 24-relaunch reset.
pub fn take_arm_marker(path: &str) -> Option<String> {
    // A marker we cannot read is still a marker; default to empty so an unreadable
    // one runs the read-only stage 6 rather than something more consequential.
    let body = std::fs::read_to_string(path).unwrap_or_default();
    match std::fs::remove_file(path) {
        Ok(()) => {
            let body = body.trim().to_string();
            if body.is_empty() {
                println!("tuxweb cutover: consumed {path} -- this is the one armed window");
            } else {
                println!(
                    "tuxweb cutover: consumed {path} -- one armed window, stage {body:?}"
                );
            }
            Some(body)
        }
        Err(_) => None,
    }
}

pub struct Config {
    /// Where the vendor went in stage 5. The deadman and every failure path
    /// exec this.
    pub vendor: String,
    /// Raw replies land here, one line each, so the window's evidence survives
    /// the process that collected it.
    pub log: String,
    pub window: Duration,
}

/// What the window measured. Printed at the end and, more importantly,
/// available to a caller that wants to assert on it.
#[derive(Debug, Default)]
pub struct Tally {
    pub received: u64,
    pub decoded: u64,
    pub undecodable: u64,
}

/// Format one reply as a log line: the raw bytes, then what we made of them.
///
/// Raw first and always, even when parsing succeeds. §5.10 wants the payloads
/// of the 36 msgTypes nobody has decoded past `+0x0E`, and a log that only
/// records the fields we already understand cannot answer a question we have
/// not thought of yet.
pub fn log_line(seq: u64, at: Duration, raw: &[u8]) -> String {
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    match Reply::parse(raw) {
        Some(r) => format!(
            "{seq}\t{:.3}\tOK\tsession={}\tmsgType={}\targ={}\tstate={}\ttext={}\t{hex}\n",
            at.as_secs_f64(),
            r.session,
            r.msg_type,
            r.arg,
            r.state_byte().map(|b| format!("0x{b:02x}")).unwrap_or_else(|| "-".into()),
            // latin-1: the text is not utf-8 and lossy-decoding it would
            // destroy the very bytes this log exists to preserve
            r.text.iter().map(|&b| format!("{b:02x}")).collect::<String>(),
            hex = hex,
        ),
        None => format!("{seq}\t{:.3}\tSHORT\t{hex}\n", at.as_secs_f64()),
    }
}

/// Run the window. Returns only by handing the panel back.
pub fn run(cfg: Config) -> ! {
    // The fallback has to exist before anything else happens, including before
    // the deadman is armed. Arming first looked harmless -- the process exits
    // either way -- but it meant arming a timer whose one job is to exec a
    // binary that is not there, and the startup banner then announced a
    // recovery that could not work. Order matters here even when the outcome
    // does not, because the log is what someone reads at 2am.
    if !std::path::Path::new(&cfg.vendor).is_file() {
        eprintln!("tuxweb cutover: {} is missing; REFUSING to start", cfg.vendor);
        eprintln!("tuxweb cutover: nothing was armed and no queue was opened");
        std::process::exit(2);
    }

    // Now arm, before anything that could block. If the queue open hangs on
    // some kernel path nobody predicted, the recovery is already on its own
    // thread and does not depend on this one making progress.
    let vendor = cfg.vendor.clone();
    let deadman = Deadman::arm(cfg.window, move || hand_back_to_vendor(&vendor));
    println!(
        "tuxweb cutover: deadman armed for {}s -- the panel returns to the vendor \
         by itself if nothing resets it",
        cfg.window.as_secs()
    );

    // Startup fallback. Every one of these is a reason to give the panel back
    // rather than to carry on degraded.
    let fail = |what: String| -> ! {
        eprintln!("tuxweb cutover: {what}");
        eprintln!("tuxweb cutover: handing back rather than continuing");
        hand_back_to_vendor(&cfg.vendor)
    };

    let q = match Queue::open(crate::mq::REPLIES, true) {
        Ok(q) => q,
        Err(e) => fail(format!("cannot open the reply queue: {e}")),
    };
    let attr = match q.attr() {
        Ok(a) => a,
        Err(e) => fail(format!("cannot read the queue geometry: {e}")),
    };
    println!(
        "tuxweb cutover: holding {} as SOLE READER, read-only \
         (maxmsg={} msgsize={} curmsgs={})",
        crate::mq::REPLIES,
        attr.maxmsg,
        attr.msgsize,
        attr.curmsgs
    );
    if attr.msgsize != crate::ipc::REPLY_LEN as i64 {
        // Not fatal: the measured geometry is 556 and a different number means
        // the panel is not what the documents describe, which is worth saying
        // out loud rather than quietly coping with.
        println!(
            "tuxweb cutover: NOTE msgsize is {} not the documented {}",
            attr.msgsize,
            crate::ipc::REPLY_LEN
        );
    }

    let mut buf = match q.buffer() {
        Ok(b) => b,
        Err(e) => fail(format!("cannot size the receive buffer: {e}")),
    };
    let mut log = match std::fs::File::create(&cfg.log) {
        Ok(f) => f,
        Err(e) => fail(format!("cannot open {}: {e}", cfg.log)),
    };

    let seq = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let mut tally = Tally::default();
    println!("tuxweb cutover: receiving. Press keys on the touchscreen.");

    loop {
        if deadman.has_fired() {
            // the deadman is mid-exec; stop touching the queue
            std::thread::sleep(Duration::from_secs(5));
        }
        match q.receive(&mut buf, Duration::from_millis(500)) {
            Ok(None) => {}
            Ok(Some(n)) => {
                let i = seq.fetch_add(1, Ordering::Relaxed);
                tally.received += 1;
                let line = log_line(i, started.elapsed(), &buf[..n]);
                if Reply::parse(&buf[..n]).is_some() {
                    tally.decoded += 1;
                } else {
                    tally.undecodable += 1;
                }
                if log.write_all(line.as_bytes()).is_err() || log.flush().is_err() {
                    fail("the log became unwritable; the window's evidence is the \
                          point of it, so there is no value in continuing".into());
                }
                if tally.received % 10 == 0 {
                    println!(
                        "tuxweb cutover: {} received ({} decoded, {} short), {}s left",
                        tally.received,
                        tally.decoded,
                        tally.undecodable,
                        deadman.remaining().as_secs()
                    );
                }
            }
            Err(e) => fail(format!("receive failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply_bytes(msg_type: u32, text: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; crate::ipc::REPLY_LEN];
        b[0..4].copy_from_slice(&7u32.to_le_bytes());
        b[4..8].copy_from_slice(&msg_type.to_le_bytes());
        b[8..12].copy_from_slice(&99u32.to_le_bytes());
        b[0x0E..0x0E + text.len()].copy_from_slice(text);
        b
    }

    #[test]
    fn the_arm_marker_is_consumed_exactly_once() {
        let p = std::env::temp_dir().join(format!("tuxweb-arm-{}", std::process::id()));
        let path = p.to_str().unwrap();

        // absent: this is a passthrough launch, not a window
        let _ = std::fs::remove_file(&p);
        assert!(take_arm_marker(path).is_none(), "no marker must mean no window");

        std::fs::write(&p, b"").unwrap();
        assert_eq!(
            take_arm_marker(path).as_deref(),
            Some(""),
            "an empty marker opens the window and asks for the read-only stage 6"
        );
        // and the SECOND launch must not get a window. This is the assertion
        // that stands between a crashed cutover and a relaunch loop ending at
        // the 24-relaunch watchdog reset.
        assert!(take_arm_marker(path).is_none(), "one marker is exactly one window");
        assert!(!p.exists(), "the marker must be gone, not merely ignored");

        // A marker carrying a stage returns it, trimmed -- that string is the only
        // channel a window has, because supervis passes no arguments.
        std::fs::write(&p, b"7d 2\n").unwrap();
        assert_eq!(take_arm_marker(path).as_deref(), Some("7d 2"));
        assert!(!p.exists(), "a stage marker is consumed like any other");
    }

    #[test]
    fn a_log_line_keeps_the_raw_bytes_even_when_it_parses() {
        // §5.10 wants payloads for msgTypes nobody has decoded. A log that
        // records only the understood fields cannot answer a later question.
        let raw = reply_bytes(21, b"\xfe1Ready To Arm:2");
        let line = log_line(3, Duration::from_millis(1500), &raw);
        assert!(line.starts_with("3\t1.500\tOK\t"), "{line}");
        assert!(line.contains("msgType=21"));
        assert!(line.contains("session=7"));
        assert!(line.contains("state=0xfe"));
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert!(line.contains(&hex), "the full raw message must be present");
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn the_text_is_hex_not_utf8() {
        // The text starts 0xFE/0xFF and is latin-1. Lossy-decoding it would
        // destroy exactly the bytes worth keeping.
        let raw = reply_bytes(20, b"\xff\xfe\x80hello");
        let line = log_line(0, Duration::ZERO, &raw);
        assert!(line.contains("text=fffe80"), "{line}");
        assert!(!line.contains('\u{fffd}'), "no replacement characters: {line}");
    }

    #[test]
    fn a_short_message_is_logged_rather_than_dropped() {
        // A message too short to parse is evidence too -- and dropping it is
        // how a corpus quietly acquires a hole.
        let line = log_line(9, Duration::from_secs(2), &[1, 2, 3]);
        assert!(line.starts_with("9\t2.000\tSHORT\t010203"), "{line}");
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn log_lines_are_single_lines_so_the_log_stays_parseable() {
        for text in [&b"\x00\x01\x02"[..], b"\xfe1Ready\tTo\nArm", b""] {
            let line = log_line(1, Duration::ZERO, &reply_bytes(19, text));
            assert_eq!(line.matches('\n').count(), 1, "exactly one newline: {line:?}");
            assert!(!line[..line.len() - 1].contains('\n'));
        }
    }
}
