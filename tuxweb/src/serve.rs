//! Stage 8c: the production serve mode -- tuxweb serves the push stream itself.
//!
//! This is where 8a's generator becomes a server. tuxweb registers ONCE and
//! stays registered; a dedicated reader thread does nothing but `mq_receive`
//! into a channel (blocker B5: a reader that also formats and writes can fall
//! behind under a burst and lose all 32 queued messages), and a worker drains
//! that channel, updates the [`PanelState`] model, and fans the generated frames
//! out to every subscriber. A client connecting later is handed the current
//! state from the model rather than triggering another 500 -- re-registering
//! flushes the reply queue for everyone (B7).
//!
//! **This first cut is the push path over plaintext, for the bench.** The
//! things that layer onto it, each already built or proven elsewhere and wired
//! in by the serve entrypoint, not here:
//!   * TLS on 443 (main.rs / shim.rs already terminate rustls on this hardware),
//!   * the `80 -> 301` leg (`redirect.rs`),
//!   * the typed API (`api.rs`) turning a request into a command + reply,
//!   * the auth gate on the push path (§4.10.1 -- required; `shim`'s token/
//!     session logic moves here). Left OPEN here with a loud warning, exactly as
//!     `shim` does for a deliberately-open test, so the bench can exercise the
//!     generation path without the auth plumbing.
//!
//! Unlike `shim`, which drops its upstream subscription when no client is
//! watching (a subscription is not free for the panel), this ALWAYS drains the
//! queue: tuxweb is the registered client now, so not draining means the queue
//! fills to 32 and flushes (B5) and the state model goes stale. Broadcasting to
//! zero subscribers is a no-op; draining is not optional.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ipc::{cmd, Command, Reply, COMMAND_LEN};
use crate::mq::{Queue, COMMANDS, REPLIES};
use crate::push::{self, PanelState};
use crate::shim::Sink;

/// The vendor push path. A GET here subscribes to the stream.
const PUSH_PATH: &str = "/SimpleDebugger.interface/";

/// The response head that opens a subscription -- byte-identical to the vendor's
/// (`shim` documents each quirk; `conformance.py` asserts them).
const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
Server: \r\n\
Connection: Close\r\n\
Cache-Control: no-store, no-cache, must-revalidate\r\n\
Pragma: no-cache\r\n\
Content-type: multipart/x-mixed-replace;boundary=\"EH912ZZ\"\r\n\r\n";

pub struct Config {
    /// Non-zero registration session id.
    pub session: u32,
    /// Where to accept push subscribers (plaintext, this cut).
    pub bind: String,
    /// `quickarmstate` path (§5.12).
    pub quickarm: String,
    /// Run this long then unregister and return. `None` runs until killed --
    /// the permanent server. A bench test passes `Some`.
    pub window: Option<Duration>,
    /// Where to answer plaintext `80` traffic with a `301` to https (§2.6).
    /// `None` binds no redirect listener. On the panel this is `0.0.0.0:80`; a
    /// bench test uses a high port. 6280 and 9443 are never bound (§1.5).
    pub redirect_bind: Option<String>,
    /// The token store path (`auth.rs`). The push stream and the write API are
    /// gated on a token from it (§4.10.1); an empty store authenticates nobody.
    pub token_store: String,
    /// TLS for the push + API listener (this is the `:443` leg on the panel).
    /// `None` serves plaintext -- only for the bench. rustls on this hardware
    /// has been proven since stage 3; `main::tls_from_env` builds this from
    /// `TUXWEB_CHAIN`/`TUXWEB_KEY` and exits rather than silently serving in the
    /// clear if they are set but unusable.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// How long the reply queue may stay silent before tuxweb assumes the
    /// broadcast has been switched off underneath it and registers again.
    ///
    /// `home_back_press()` in `/tuxedo` zeroes `F7_Mesgs_enabled` -- the same
    /// byte a 501 clears -- and a Home or Back press on the touchscreen reaches
    /// it. The vendor never noticed because every new push connection made it
    /// re-register; a permanent server that registers once would go silent until
    /// its next relaunch. An idle panel sends a status roughly every 30 s
    /// (`push-idle-300s.bin`: 19 in 300 s), so a silence several times that long
    /// means the flag is off. Re-registering flushes a queue that is empty
    /// anyway and yields a fresh 504, which the stream carries like any other.
    pub silence: Duration,
}

/// Default silence before a re-register: four idle status periods.
pub const DEFAULT_SILENCE: Duration = Duration::from_secs(120);

/// How long to wait for an arm/disarm to be confirmed by a state-byte flip on
/// the push stream. The consumer's own client waits ~1.5–1.8 s against an 8 s
/// ceiling (`ha-tuxedo-touch/api.py`); match the ceiling.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(8);

/// The plaintext `301` leg. Every connection is read once and answered with a
/// redirect to https (or a 400); no keep-alive, no state -- port 80 does exactly
/// one thing (§2.6). Failures are logged and dropped; a bad client here must not
/// affect the push stream on 443.
fn run_redirect_listener(bind: String) {
    let l = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("serve: redirect bind {bind}: {e}");
            return;
        }
    };
    println!("serve: 80->301 redirect on {bind}");
    for s in l.incoming() {
        let mut sock = match s {
            Ok(c) => c,
            Err(e) => {
                eprintln!("serve redirect: accept: {e}");
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
        match crate::proxy::read_head(&mut sock, 8 * 1024) {
            Ok((head, _)) => {
                let _ = sock.write_all(&crate::redirect::respond(&head));
                let _ = sock.flush();
            }
            Err(e) => eprintln!("serve redirect: {e}"),
        }
    }
}

fn command(session: u32, code: u32) -> Vec<u8> {
    let v = Command { head: session, code, p1: 0, p2: 0 }.encode();
    debug_assert_eq!(v.len(), COMMAND_LEN);
    v
}

/// Write the parts to a sink; true if it stayed writable.
fn write_parts(sink: &mut Sink, parts: &[crate::frame::Part]) -> bool {
    let mut out = Vec::new();
    for p in parts {
        p.encode(&mut out);
    }
    sink.write_all(&out).is_ok() && sink.flush().is_ok()
}

/// `401`, a real status with an empty body -- shaped so a stream client sees the
/// denial rather than reading a login page to EOF (the P13 failure mode).
fn unauthorized() -> Vec<u8> {
    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

fn json_response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// `Content-Length` of a request head, or 0 if absent/unparseable.
fn content_length(head: &str) -> usize {
    crate::proxy::header(head, "content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Read the full request body: the bytes already read with the head, plus enough
/// more from the socket to reach `want`. Bounded so a lying Content-Length cannot
/// make us read forever.
fn read_body(sink: &mut Sink, already: &[u8], want: usize) -> Vec<u8> {
    let want = want.min(64 * 1024);
    let mut body = already.to_vec();
    let mut buf = [0u8; 2048];
    while body.len() < want {
        match sink.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    body.truncate(want.max(body.len().min(want)));
    body
}

/// Get a value from an `application/x-www-form-urlencoded` body, url-decoded.
fn form_get(body: &str, key: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(url_decode(v));
            }
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Wait for the panel's arm-state byte to reach `target` (`0xFF` armed/arming,
/// `0xFE` disarmed), i.e. for the command to have ACTED rather than merely been
/// sent (§4.10.3). Returns whether it was seen within the ceiling.
fn confirm(state: &Arc<Mutex<PanelState>>, target: u8) -> bool {
    let deadline = Instant::now() + CONFIRM_TIMEOUT;
    loop {
        if state.lock().unwrap().arm_state_byte() == Some(target) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Serve an arm or disarm: send the command, then wait for the panel to confirm
/// it acted (a state-byte flip on the push stream). The pin comes from the
/// request body (`ucode`), as the consumer sends it. Response keeps the vendor
/// JSON shapes (§4.10.4): arm's inner key is `Response`, disarm's is `Result`.
fn handle_security(
    action: &crate::api::Action,
    form: &str,
    session: u32,
    commands: &Queue,
    state: &Arc<Mutex<PanelState>>,
) -> Vec<u8> {
    let ucode: u32 = form_get(form, "ucode").and_then(|v| v.parse().ok()).unwrap_or(0);
    // A command with code 0 is DECLINED, and the declined path changes panel
    // state before its own guard (register.rs) -- refuse before sending.
    if ucode == 0 {
        return json_response(
            "400 Bad Request",
            b"{\"Status\":\"Failure\",\"Result\":{\"Response\":\"a user code is required\"}}",
        );
    }
    let (code, target, disarm) = match action {
        crate::api::Action::Arm { .. } => {
            let level = form_get(form, "arming").unwrap_or_default();
            (crate::api::arm_code_for(&level), 0xFFu8, false)
        }
        crate::api::Action::Disarm => (cmd::DISARM, 0xFEu8, true),
        _ => return json_response("500 Internal Server Error", b"{\"Status\":\"Failure\"}"),
    };
    let msg = Command { head: session, code, p1: 0, p2: ucode }.encode();
    if let Err(e) = commands.send(&msg) {
        eprintln!("serve: command {code} send failed: {e}");
        return json_response(
            "502 Bad Gateway",
            b"{\"Status\":\"Failure\",\"Result\":{\"Response\":\"could not reach the panel\"}}",
        );
    }
    if !confirm(state, target) {
        // Sent, but not confirmed within the ceiling. Say so rather than the
        // vendor's unconditional Sucess -- the whole point of command_result.
        return json_response(
            "504 Gateway Timeout",
            b"{\"Status\":\"Failure\",\"Result\":{\"Response\":\"command sent but not confirmed\"}}",
        );
    }
    if disarm {
        crate::api::disarm_success("Disarmed")
    } else {
        crate::api::arm_success()
    }
}

/// Register, serve the push stream from IPC for the window, unregister.
pub fn run(cfg: Config) -> Result<(), String> {
    if cfg.session == 0 {
        return Err("session id must be non-zero; zero is accepted and then ignored".into());
    }

    let commands = Arc::new(Queue::open(COMMANDS, false)?);
    let replies = Queue::open(REPLIES, true)?;
    let attr = replies.attr()?;
    println!(
        "serve: replies maxmsg={} msgsize={} curmsgs={}",
        attr.maxmsg, attr.msgsize, attr.curmsgs
    );

    let store = Arc::new(crate::auth::TokenStore::load(&cfg.token_store)?);
    match store.tokens.len() {
        0 => println!(
            "serve: *** token store {} has NO tokens -- the push stream and the write \
             API will deny everyone until one is issued (tuxweb --issue-token) ***",
            cfg.token_store
        ),
        n => println!("serve: {n} token(s) loaded from {}", cfg.token_store),
    }

    let state = Arc::new(Mutex::new(PanelState::new()));
    let clients: Arc<Mutex<Vec<Sink>>> = Arc::new(Mutex::new(Vec::new()));
    let cid = Arc::new(AtomicU32::new(0x4242_0000));

    // Register, then switch console mode on so /tuxedo streams the keypad LCD
    // (msgType 20). Console mode is display-only -- the key-sending path is a
    // separate write this server never issues -- and it is a standing change
    // to the panel: whoever opens the touchscreen's console page will find it
    // already on. Both the broadcast and console mode are cleared by a Home/Back
    // press, which the silence watchdog below repairs by doing this again.
    let register = |why: &str| -> Result<(), String> {
        println!("serve: sending 500 REGISTER, session {} ({why})", cfg.session);
        commands.send(&command(cfg.session, cmd::REGISTER))?;
        std::thread::sleep(Duration::from_millis(200));
        println!("serve: sending 19 CONSOLE_MODE (keypad LCD on the stream)");
        commands.send(&command(cfg.session, cmd::CONSOLE_MODE))
    };
    register("startup")?;

    // Reader thread: nothing but receive -> channel. B5.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut buf = match replies.buffer() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("serve reader: {e}");
                return;
            }
        };
        loop {
            match replies.receive(&mut buf, Duration::from_millis(500)) {
                Ok(Some(n)) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return; // worker gone: shut down
                    }
                }
                Ok(None) => {
                    // idle; but if the worker has dropped the receiver, stop
                    if tx.send(Vec::new()).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("serve reader: receive failed: {e}");
                    return;
                }
            }
        }
    });

    // Accept thread: gate the push path, hand the new client current state, enrol.
    let listener = TcpListener::bind(&cfg.bind).map_err(|e| format!("bind {}: {e}", cfg.bind))?;
    println!("serve: push + API on {} (from IPC, no Barracuda)", cfg.bind);
    let acc_clients = Arc::clone(&clients);
    let acc_state = Arc::clone(&state);
    let acc_cid = Arc::clone(&cid);
    let acc_quickarm = cfg.quickarm.clone();
    let acc_store = Arc::clone(&store);
    let acc_commands = Arc::clone(&commands);
    let acc_session = cfg.session;
    let acc_tls = cfg.tls.clone();
    match &acc_tls {
        Some(_) => println!("serve: listener is TLS (rustls)"),
        None => println!("serve: *** listener is PLAINTEXT -- bench only ***"),
    }
    let accept = std::thread::spawn(move || {
        for s in listener.incoming() {
            let raw = match s {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("serve accept: {e}");
                    continue;
                }
            };
            let peer = raw.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            // Set both timeouts on the socket before wrapping so a client that
            // connects and says nothing cannot hold a slot, and a stuck write
            // cannot wedge the fan-out. TLS (if configured) wraps the same socket;
            // the handshake happens lazily on the first read.
            let _ = raw.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = raw.set_write_timeout(Some(Duration::from_secs(5)));
            let mut sink = match Sink::accept(raw, acc_tls.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("serve: {peer}: {e}");
                    continue;
                }
            };
            let (head, body0) = match crate::proxy::read_head(&mut sink, 16 * 1024) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("serve: {peer}: {e}");
                    continue;
                }
            };
            let target = crate::proxy::path(&head);
            let method = head.split_whitespace().next().unwrap_or("");
            // A valid token from the header (bearer or cookie). The push stream
            // and the write API require it (§4.10.1); GetCapabilities does not.
            let authed = crate::auth::token_from_head(&head)
                .map(|t| acc_store.is_valid(&t))
                .unwrap_or(false);

            // The push stream.
            if target.starts_with(PUSH_PATH) {
                if !authed {
                    let _ = sink.write_all(&unauthorized());
                    let _ = sink.flush();
                    eprintln!("serve: {peer}: push denied, no valid token");
                    continue;
                }
                if sink.write_all(HEAD).is_err() || sink.flush().is_err() {
                    continue;
                }
                // Current state before enrolling, so the client is never behind.
                let my_cid = acc_cid.fetch_add(1, Ordering::Relaxed);
                let n = acc_clients.lock().unwrap().len() as u32 + 1;
                let snapshot = acc_state.lock().unwrap().snapshot(my_cid, n, &acc_quickarm);
                if !write_parts(&mut sink, &snapshot) {
                    continue;
                }
                println!("serve: {peer} subscribed (cid {my_cid}, {n} client(s))");
                acc_clients.lock().unwrap().push(sink);
                continue;
            }

            // The typed API.
            let resp = if target.starts_with("/system_http_api/") {
                match crate::api::classify(method, target, 0) {
                    // Session-optional: 200 on custom is how a client tells us
                    // apart from stock (§4.10.6), so it must not require a token.
                    crate::api::Action::Capabilities => crate::api::capabilities_response(),
                    crate::api::Action::MethodNotAllowed => crate::api::method_not_allowed(),
                    crate::api::Action::NotFound => crate::api::not_found(),
                    // The rest require a token.
                    _ if !authed => unauthorized(),
                    crate::api::Action::Status => {
                        json_response("200 OK", acc_state.lock().unwrap().status_json().as_bytes())
                    }
                    action @ (crate::api::Action::Arm { .. } | crate::api::Action::Disarm) => {
                        let body = read_body(&mut sink, &body0, content_length(&head));
                        let form = String::from_utf8_lossy(&body);
                        handle_security(&action, &form, acc_session, &acc_commands, &acc_state)
                    }
                }
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            };
            let _ = sink.write_all(&resp);
            let _ = sink.flush();
        }
    });

    // The 80->301 leg, if configured. Detached: it ends with the process.
    if let Some(rb) = cfg.redirect_bind.clone() {
        std::thread::spawn(move || run_redirect_listener(rb));
    }

    // Worker: drain the channel, update the model, fan out. Always drains.
    let started = Instant::now();
    let mut last_reply = Instant::now();
    let mut reregisters = 0u32;
    // Reply types with no frame shape, each logged once. Before this the
    // diagnostic emission was dropped in silence, which is how a msgType 22
    // (the panel-offline status) went unrelayed from the cutover to v16.
    let mut undecoded_seen = std::collections::BTreeSet::new();
    loop {
        if let Some(w) = cfg.window {
            if started.elapsed() >= w {
                break;
            }
        }
        // The silence watchdog: no reply for `silence` means the broadcast was
        // switched off underneath us (a touchscreen Home/Back, or a /tuxedo
        // restart). Register again -- once per silence period, never in a loop.
        if last_reply.elapsed() >= cfg.silence {
            reregisters += 1;
            match register(&format!(
                "silence: no reply for {}s, re-register #{reregisters}",
                last_reply.elapsed().as_secs()
            )) {
                Ok(()) => {}
                Err(e) => eprintln!("serve: re-register failed: {e}"),
            }
            last_reply = Instant::now();
        }
        let raw = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(r) => r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if raw.is_empty() {
            continue; // reader's idle tick
        }
        last_reply = Instant::now();
        let quick = match Reply::parse(&raw).map(|r| r.msg_type) {
            Some(21) => {
                let part = state.lock().unwrap().current_partition();
                push::read_quick_arm(&cfg.quickarm, part)
            }
            _ => 0,
        };
        let em = state.lock().unwrap().observe(&raw, quick);
        if let Some((t, r)) = &em.undecoded {
            if undecoded_seen.insert(*t) {
                let head: Vec<String> = r.iter().take(16).map(|b| format!("{b:02x}")).collect();
                eprintln!(
                    "serve: reply msgType {t} has no frame shape; not relayed \
                     (first 16 bytes {}; said once per type)",
                    head.join(" ")
                );
            }
        }
        if em.parts.is_empty() {
            continue;
        }
        let mut cs = clients.lock().unwrap();
        let before = cs.len();
        cs.retain_mut(|c| write_parts(c, &em.parts));
        if cs.len() != before {
            println!("serve: {} subscriber(s) dropped", before - cs.len());
        }
    }

    println!("serve: sending 501 UNREGISTER");
    if let Err(e) = commands.send(&command(cfg.session, cmd::UNREGISTER)) {
        eprintln!("serve: UNREGISTER FAILED: {e} -- the firehose may still be on");
    }
    // The reader thread notices the dropped receiver on its next tick and exits;
    // the accept thread is detached and ends with the process.
    drop(rx);
    let _ = reader.join();
    drop(accept);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_session_is_refused() {
        let e = run(Config {
            session: 0,
            bind: "127.0.0.1:0".into(),
            quickarm: "/nonexistent".into(),
            window: Some(Duration::from_millis(1)),
            redirect_bind: None,
            token_store: "/nonexistent".into(),
            tls: None,
            silence: DEFAULT_SILENCE,
        })
        .unwrap_err();
        assert!(e.contains("non-zero"), "{e}");
    }

    #[test]
    fn the_subscribe_head_carries_the_vendor_quirks() {
        let h = String::from_utf8(HEAD.to_vec()).unwrap();
        assert!(h.contains("\r\nServer: \r\n"), "empty Server is a preserved quirk");
        assert!(h.contains("Connection: Close"));
        assert!(h.contains("multipart/x-mixed-replace;boundary=\"EH912ZZ\""));
    }
}
