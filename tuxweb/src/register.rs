//! Stage 7a: register, watch, unregister. The first stage that WRITES.
//!
//! Stage 6 proved a non-Barracuda process holding `/Q_ServCmdTrsmtr` as sole reader
//! receives `/tuxedo`'s replies -- 29 of them, on 2026-09-11 -- but it received them
//! only because the dying vendor left `F7_Mesgs_enabled` set. This stage stops
//! depending on that: it turns the firehose on itself with command 500, and off
//! again with 501.
//!
//! TWO THINGS THIS DOES TO THE PANEL, both deliberate and both stated up front:
//!
//! 1. `registerclient()`'s first act is `osal_MqFlush` -- registering DISCARDS every
//!    reply already queued for whoever was connected. Acceptable in a window that
//!    owns the panel; not acceptable while anything else is relied upon.
//! 2. `unregisterclient()` @`0x13c00c` unconditionally zeroes `clients_connected`
//!    AND `F7_Mesgs_enabled`. It is not a refcount: the 501 at the end switches the
//!    firehose off for EVERY consumer. That is the correct way to leave the panel as
//!    it was found, and the wrong thing to do if a real client is still watching.
//!
//! The session id must be non-zero: `setarmwithcode` hard-codes zero at `+0x00` and
//! the confirmation-frame senders return early on a zero session. Non-zero is
//! necessary but NOT sufficient -- a second field at `0x50d4` also gates the accepted
//! path -- so a quiet run here does not by itself refute the 7d prediction.

use crate::ipc::{cmd, Command, Reply, COMMAND_LEN};
use crate::mq::{Queue, COMMANDS, REPLIES};
use std::io::Write;
use std::time::{Duration, Instant};

pub struct Config {
    /// Non-zero. Zero is silently accepted by the queue and then ignored by the
    /// senders, which looks exactly like "the panel sent nothing".
    pub session: u32,
    /// How long to watch between the 500 and the 501.
    pub watch: Duration,
    pub log: String,
    /// What to call this run in its own output. A window's log is read back later
    /// by someone who was not watching it, and "stage7a" printed during a 7b run is
    /// a small lie that costs a re-read.
    pub label: String,
    /// Stage 7b: read-only query commands to send after registering, in order.
    /// Empty for 7a, which sends nothing but the register pair.
    ///
    /// They go through the SAME register/unregister path deliberately. The 501 is
    /// what leaves the panel as it was found, so there must not be a second code
    /// path that can send queries and skip it.
    pub queries: Vec<u32>,
}

#[derive(Debug)]
pub struct Outcome {
    pub sent_register: bool,
    pub queries_sent: usize,
    pub received: usize,
    pub decoded: usize,
    pub saw_504: bool,
    pub sent_unregister: bool,
    /// (msg_type, count), sorted. Reported rather than a bare total because
    /// command 17 is paged: its reply is several messages, so "replies == queries"
    /// is never the right check.
    pub types: Vec<(u32, usize)>,
}

/// Build the 404-byte register/unregister command.
///
/// Sized from `COMMAND_LEN`, never from the reply layout: the reply union is 556 and
/// this direction is 404. `mq_send` refuses anything larger than the queue's
/// `msgsize`, so getting this wrong is an EMSGSIZE rather than a silent truncation --
/// but it would still be a wasted window.
fn command(session: u32, code: u32) -> Vec<u8> {
    let v = Command { head: session, code, p1: 0, p2: 0 }.encode();
    debug_assert_eq!(v.len(), COMMAND_LEN);
    v
}

/// Commands that switch the broadcast firehose OFF for every consumer.
///
/// `unregisterclient()` and `home_back_press()` both zero `F7_Mesgs_enabled`, which
/// gates the top of `wsltHandleRawDataFromPanel`. A run that sends one of these and
/// then expects to keep receiving is wrong by construction -- that is exactly how
/// the first stage-6 window logged zero -- so `run` refuses to put one in the query
/// list rather than leaving the ordering to a runbook note.
pub fn kills_firehose(code: u32) -> bool {
    code == cmd::BACK || code == cmd::HOME || code == cmd::UNREGISTER
}

/// Send 500, watch, send 501. Returns what happened rather than exiting, so the
/// caller can still run the unregister on a failure path.
pub fn run(cfg: &Config) -> Result<Outcome, String> {
    if cfg.session == 0 {
        return Err("session id must be non-zero; zero is accepted and then ignored".into());
    }
    // Refuse a query set that would switch off the very broadcast the run exists to
    // observe. Checked before anything is opened, so a bad sequence costs nothing.
    if let Some(bad) = cfg.queries.iter().copied().find(|c| kills_firehose(*c)) {
        return Err(format!(
            "command {bad} zeroes F7_Mesgs_enabled and would switch the broadcast off \
             mid-run; send it after the watch, not in the query list"
        ));
    }

    // Reply queue read-only, command queue read-write. Opening the reply queue
    // read-only keeps "we only ever write to the command queue" structural.
    let replies = Queue::open(REPLIES, true)?;
    let commands = Queue::open(COMMANDS, false)?;

    let attr = replies.attr()?;
    println!(
        "{}: replies maxmsg={} msgsize={} curmsgs={}", cfg.label,
        attr.maxmsg, attr.msgsize, attr.curmsgs
    );
    if attr.curmsgs > 0 {
        println!(
            "{}: NOTE {} message(s) already queued -- the 500 below will FLUSH them", cfg.label,
            attr.curmsgs
        );
    }

    let mut out = Outcome {
        sent_register: false,
        queries_sent: 0,
        received: 0,
        decoded: 0,
        saw_504: false,
        sent_unregister: false,
        types: Vec::new(),
    };
    let mut tally: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();

    let mut log = std::fs::File::create(&cfg.log)
        .map_err(|e| format!("cannot open {}: {e}", cfg.log))?;

    println!("{}: sending 500 REGISTER, session {}", cfg.label, cfg.session);
    commands.send(&command(cfg.session, cmd::REGISTER))?;
    out.sent_register = true;

    // Queries go out after the register and before the watch, spaced so a reply can
    // be attributed to the command that caused it. 17 is paged -- its reply is more
    // than one message -- so the count below is messages, never "one per query".
    for (i, code) in cfg.queries.iter().enumerate() {
        println!("{}: sending query {} of {}: code {}", cfg.label, i + 1, cfg.queries.len(), code);
        if let Err(e) = commands.send(&command(cfg.session, *code)) {
            // Report and keep going to the unregister: a half-sent query set is
            // recoverable, a panel left registered is not.
            println!("{}: query {code} failed: {e}", cfg.label);
            break;
        }
        out.queries_sent += 1;
        std::thread::sleep(Duration::from_millis(400));
    }

    let mut buf = replies.buffer()?;
    let started = Instant::now();
    while started.elapsed() < cfg.watch {
        match replies.receive(&mut buf, Duration::from_millis(500)) {
            Ok(None) => {}
            Ok(Some(n)) => {
                out.received += 1;
                let raw = &buf[..n];
                let line = crate::cutover::log_line(out.received as u64, started.elapsed(), raw);
                let _ = log.write_all(line.as_bytes());
                let _ = log.flush();
                if let Some(r) = Reply::parse(raw) {
                    out.decoded += 1;
                    *tally.entry(r.msg_type).or_insert(0) += 1;
                    // 504 is the registration confirmation. Its text is NOT at
                    // +0x0E -- the 556-byte reply is a union, and for a 504 that
                    // offset holds nothing of interest -- so only the type is read
                    // here and the raw bytes go to the log for later work.
                    if r.msg_type == 504 {
                        out.saw_504 = true;
                    }
                }
            }
            // Report and still unregister: leaving the firehose on is worse than
            // losing the rest of the sample.
            Err(e) => {
                println!("{}: receive failed: {e}", cfg.label);
                break;
            }
        }
    }

    out.types = tally.into_iter().collect();

    println!("{}: sending 501 UNREGISTER", cfg.label);
    match commands.send(&command(cfg.session, cmd::UNREGISTER)) {
        Ok(()) => out.sent_unregister = true,
        Err(e) => println!("{}: UNREGISTER FAILED: {e} -- the firehose may still be on", cfg.label),
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_404_bytes_not_556() {
        let c = command(7, cmd::REGISTER);
        assert_eq!(c.len(), COMMAND_LEN, "the command direction is 0x194");
        assert_ne!(c.len(), crate::ipc::REPLY_LEN, "556 is the REPLY size");
    }

    #[test]
    fn session_is_at_offset_zero_and_code_at_four() {
        // setarmwithcode writes sessionId to +0x00 then msgType to +0x04; this
        // must match or /tuxedo reads the fields transposed.
        let c = command(0x1234, cmd::REGISTER);
        assert_eq!(&c[0x00..0x04], &0x1234u32.to_le_bytes());
        assert_eq!(&c[0x04..0x08], &500u32.to_le_bytes());
    }

    #[test]
    fn back_and_home_are_not_transposed() {
        // The stage plan said "502/503 (home/back)", which reads as 502=home. The
        // measured result in RELEASES.md is the other way round, and getting it
        // wrong presses the wrong button on a live alarm panel.
        assert_eq!(cmd::BACK, 502);
        assert_eq!(cmd::HOME, 503);
    }

    #[test]
    fn the_firehose_killers_are_known_and_listed() {
        // Anything that reaches home_back_press() zeroes F7_Mesgs_enabled, which is
        // the same byte 501 clears. A sequence that sends one of these and then
        // expects to keep receiving is wrong by construction.
        for code in [cmd::BACK, cmd::HOME, cmd::UNREGISTER] {
            assert!(
                kills_firehose(code),
                "{code} switches the broadcast off and must be sequenced last"
            );
        }
        for code in [cmd::PARTITION_STATUS, cmd::ALL_ZONE_STATUS, cmd::ARM_STAY] {
            assert!(!kills_firehose(code), "{code} does not");
        }
    }

    #[test]
    fn the_7b_query_codes_are_the_read_only_four() {
        // Guards against a transposed constant reaching a panel. 2, 3 and 1 are
        // ARM_STAY, DISARM and ARM_AWAY -- stage 7d, not 7b -- and must never
        // appear in this set.
        let q = [
            cmd::PARTITION_STATUS,
            cmd::ALL_ZONE_STATUS,
            cmd::HOME_PART_DETAILS,
            cmd::EVENT_LOG_UPLOAD,
        ];
        assert_eq!(q, [5, 12, 18, 17]);
        for code in q {
            assert!(
                code != cmd::ARM_AWAY
                    && code != cmd::ARM_STAY
                    && code != cmd::DISARM
                    && code != cmd::CONSOLE_MODE,
                "7b must not contain a state-changing command: {code}"
            );
        }
    }

    #[test]
    fn register_and_unregister_differ_only_in_the_code() {
        let r = command(9, cmd::REGISTER);
        let u = command(9, cmd::UNREGISTER);
        assert_eq!(&r[0x00..0x04], &u[0x00..0x04], "same session");
        assert_eq!(&r[0x08..], &u[0x08..], "same everything after the code");
        assert_ne!(&r[0x04..0x08], &u[0x04..0x08]);
        assert_eq!(&u[0x04..0x08], &501u32.to_le_bytes());
    }

    #[test]
    fn a_zero_session_is_refused_before_anything_is_opened() {
        let cfg = Config {
            session: 0,
            watch: Duration::from_millis(1),
            label: "test".into(),
            log: "/tmp/stage7a-should-not-exist".into(),
            queries: vec![cmd::PARTITION_STATUS],
        };
        let e = run(&cfg).unwrap_err();
        assert!(e.contains("non-zero"), "{e}");
        assert!(
            !std::path::Path::new("/tmp/stage7a-should-not-exist").exists(),
            "refused before creating the log, so nothing was opened either"
        );
    }
}
