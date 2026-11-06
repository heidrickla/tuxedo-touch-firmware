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

use crate::ipc::{cmd, Command, Reply, COMMAND_LEN, NO_CODE};
use crate::mq::{Queue, COMMANDS, REPLIES};
use crate::push::{self, PanelState};
use crate::shim::Sink;
use crate::ui::{self, Outcome};

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
    /// TLS for the push + API listener (this is the `:443` leg on the panel),
    /// with the chain and key paths it was loaded from so `InstallCertificate`
    /// can replace them. `None` serves plaintext -- only for the bench. rustls
    /// on this hardware has been proven since stage 3; `main` builds this from
    /// the serve conf's `chain=`/`key=` or from `TUXWEB_CHAIN`/`TUXWEB_KEY`, and
    /// refuses to serve in the clear if they are set but unusable.
    pub tls: Option<Arc<crate::certinstall::LiveTls>>,
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
    /// The `/tuxedo` binary the account store's key is read from, and the
    /// account store the sign-in page checks (`accounts::Source`).
    pub tuxedo: String,
    pub accounts: String,
}

/// Default silence before a re-register: four idle status periods.
pub const DEFAULT_SILENCE: Duration = Duration::from_secs(120);

/// How long to wait for an arm/disarm to be confirmed by a state-byte flip on
/// the push stream. The consumer's own client waits ~1.5–1.8 s against an 8 s
/// ceiling (`ha-tuxedo-touch/api.py`); match the ceiling.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(8);

/// Concurrent push + API connections being read or answered. Subscribers
/// leave the count once enrolled; one connection more is closed at once.
const MAX_CONNECTIONS: usize = 8;

/// Concurrent connections on the `80 -> 301` leg.
const MAX_REDIRECT_CONNECTIONS: usize = 4;

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
    crate::conn::serve(
        l,
        MAX_REDIRECT_CONNECTIONS,
        "serve redirect",
        |sock, peer| {
            let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
            let mut sock = crate::conn::Conn::for_request(sock);
            match crate::proxy::read_head(&mut sock, 8 * 1024) {
                Ok((head, _)) => {
                    let _ = sock.write_all(&crate::redirect::respond(&head));
                    let _ = sock.flush();
                }
                Err(e) => eprintln!("serve redirect: {peer}: {e}"),
            }
        },
    );
}

fn command(session: u32, code: u32) -> Vec<u8> {
    let v = Command {
        head: session,
        code,
        p1: 0,
        p2: 0,
    }
    .encode();
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

/// What a typed-API request needs next, decided from its route and token alone.
#[derive(Debug, PartialEq, Eq)]
enum ApiNext {
    /// Answer with these bytes.
    Reply(Vec<u8>),
    Status,
    Security(crate::api::Action),
    InstallCertificate,
}

/// Route a typed-API request. The capability answer and the 404/405 need no
/// token; everything else answers [`unauthorized`] without a valid one.
fn api_next(action: crate::api::Action, authed: bool, can_install: bool) -> ApiNext {
    use crate::api::Action;
    match action {
        // Session-optional: 200 on custom is how a client tells us apart from
        // stock (§4.10.6), so it must not require a token.
        Action::Capabilities => ApiNext::Reply(crate::api::capabilities_response(can_install)),
        Action::MethodNotAllowed => ApiNext::Reply(crate::api::method_not_allowed()),
        Action::NotFound => ApiNext::Reply(crate::api::not_found()),
        // The rest require a token.
        _ if !authed => ApiNext::Reply(unauthorized()),
        Action::Status => ApiNext::Status,
        a @ (Action::Arm { .. } | Action::Disarm) => ApiNext::Security(a),
        Action::InstallCertificate => ApiNext::InstallCertificate,
    }
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
pub(crate) fn form_get(body: &str, key: &str) -> Option<String> {
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

/// What an API arm or disarm asks the panel to do, decided from the route and
/// the form alone.
#[derive(Debug, PartialEq, Eq)]
struct SecurityCommand {
    code: u32,
    /// `+0x0C`: the user code, or [`NO_CODE`] for an arm without one.
    p2: u32,
    /// The state byte that confirms it: `0xFF` armed/arming, `0xFE` disarmed.
    target: u8,
    disarm: bool,
}

fn refuse(msg: &str) -> Vec<u8> {
    json_response(
        "400 Bad Request",
        format!("{{\"Status\":\"Failure\",\"Result\":{{\"Response\":\"{msg}\"}}}}").as_bytes(),
    )
}

/// The command an API arm or disarm sends, or the answer that refuses it before
/// anything is sent.
///
/// Arming takes no code: a `ucode` that is absent, empty or 0 sends
/// [`NO_CODE`], as Barracuda's `/handlerequest.html` did for arm Types 1, 2
/// and 4 and as the touchscreen does. A code that is sent is passed through.
/// Disarming needs one: missing, 0 or not a number is refused with 400, because
/// code 0 is the literal code 0000 and the declined path changes panel state
/// before its own guard (register.rs).
fn security_command(action: &crate::api::Action, form: &str) -> Result<SecurityCommand, Vec<u8>> {
    let ucode = form_get(form, "ucode");
    let ucode = ucode.as_deref().map(str::trim).filter(|v| !v.is_empty());
    match action {
        crate::api::Action::Arm { .. } => {
            let level = form_get(form, "arming").unwrap_or_default();
            let p2 = match ucode.map(str::parse::<u32>) {
                None | Some(Ok(0)) => NO_CODE,
                Some(Ok(n)) => n,
                Some(Err(_)) => return Err(refuse("the user code is not a number")),
            };
            Ok(SecurityCommand {
                code: crate::api::arm_code_for(&level),
                p2,
                target: 0xFF,
                disarm: false,
            })
        }
        crate::api::Action::Disarm => match ucode.and_then(|v| v.parse::<u32>().ok()) {
            None | Some(0) => Err(refuse("a user code is required")),
            Some(n) => Ok(SecurityCommand {
                code: cmd::DISARM,
                p2: n,
                target: 0xFE,
                disarm: true,
            }),
        },
        _ => Err(json_response(
            "500 Internal Server Error",
            b"{\"Status\":\"Failure\"}",
        )),
    }
}

/// Send one command and wait for the panel to confirm it acted (a state-byte
/// flip on the push stream). The API and the pages both come through here.
fn send_and_confirm(
    commands: &Queue,
    state: &Arc<Mutex<PanelState>>,
    session: u32,
    code: u32,
    p2: u32,
    target: u8,
) -> Outcome {
    let msg = Command {
        head: session,
        code,
        p1: 0,
        p2,
    }
    .encode();
    if let Err(e) = commands.send(&msg) {
        eprintln!("serve: command {code} send failed: {e}");
        return Outcome::SendFailed;
    }
    if confirm(state, target) {
        Outcome::Confirmed
    } else {
        Outcome::NotConfirmed
    }
}

/// Serve an API arm or disarm: send the command, then wait for the panel to
/// confirm it acted. Response keeps the vendor JSON shapes (§4.10.4): arm's
/// inner key is `Response`, disarm's is `Result`.
fn handle_security(
    action: &crate::api::Action,
    form: &str,
    session: u32,
    commands: &Queue,
    state: &Arc<Mutex<PanelState>>,
) -> Vec<u8> {
    let c = match security_command(action, form) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match send_and_confirm(commands, state, session, c.code, c.p2, c.target) {
        Outcome::SendFailed => json_response(
            "502 Bad Gateway",
            b"{\"Status\":\"Failure\",\"Result\":{\"Response\":\"could not reach the panel\"}}",
        ),
        // Sent, but not confirmed within the ceiling. Say so rather than the
        // vendor's unconditional Sucess -- the whole point of command_result.
        Outcome::NotConfirmed => json_response(
            "504 Gateway Timeout",
            b"{\"Status\":\"Failure\",\"Result\":{\"Response\":\"command sent but not confirmed\"}}",
        ),
        Outcome::Confirmed if c.disarm => crate::api::disarm_success("Disarmed"),
        Outcome::Confirmed => crate::api::arm_success(),
    }
}

/// The serve mode as the browser pages see it (`ui::Panel`).
struct ServePanel {
    state: Arc<Mutex<PanelState>>,
    commands: Arc<Queue>,
    session: u32,
    /// Shared with the API: one command in flight at a time.
    security: Arc<Mutex<()>>,
    accounts: crate::accounts::Source,
    tls: Option<Arc<crate::certinstall::LiveTls>>,
}

impl ui::Panel for ServePanel {
    fn view(&self) -> ui::View {
        ui::View::from_state(&self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn command(&self, code: u32, p2: u32, target: u8) -> Outcome {
        let _one = self.security.lock().unwrap_or_else(|p| p.into_inner());
        send_and_confirm(&self.commands, &self.state, self.session, code, p2, target)
    }

    fn authenticate(&self, user: &str, password: &str) -> Result<String, ui::LoginError> {
        match self.accounts.authenticate(user, password) {
            Ok(Ok(name)) => Ok(name),
            Ok(Err(why)) => Err(ui::LoginError::Denied(why)),
            Err(e) => Err(ui::LoginError::Unavailable(e)),
        }
    }

    fn cert_not_after(&self) -> Option<String> {
        self.tls.as_ref()?.not_after()
    }
}

/// An open `/ui/events` stream.
struct UiStream {
    sink: Sink,
    session: String,
    /// The view JSON this stream last received.
    sent: String,
}

/// Bring every open event stream up to date with the current view; on a tick,
/// also send a keep-alive and close the streams whose session has ended.
/// Returns how many streams were closed.
fn fan_out_ui(streams: &Mutex<Vec<UiStream>>, view: &str, ui: &ui::Ui, tick: bool) -> usize {
    let now = Instant::now();
    let mut ss = streams.lock().unwrap_or_else(|p| p.into_inner());
    let before = ss.len();
    ss.retain_mut(|s| {
        if tick && !ui.session_alive(&s.session, now) {
            return false;
        }
        let out = if s.sent != view {
            s.sent = view.to_string();
            ui::state_event(view)
        } else if tick {
            ui::KEEPALIVE.to_vec()
        } else {
            return true;
        };
        s.sink.write_all(&out).is_ok() && s.sink.flush().is_ok()
    });
    before - ss.len()
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

    // Re-read on every check (auth::LiveTokenStore), so `--issue-token` and
    // `--revoke-token` take effect on the next request, not the next relaunch.
    let store = Arc::new(crate::auth::LiveTokenStore::open(&cfg.token_store)?);
    match store.len() {
        0 => println!(
            "serve: *** token store {} has NO tokens -- the push stream and the write \
             API will deny everyone until one is issued (tuxweb --issue-token) ***",
            cfg.token_store
        ),
        n => println!(
            "serve: {n} token(s) loaded from {} (re-read on every check)",
            cfg.token_store
        ),
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
        println!(
            "serve: sending 500 REGISTER, session {} ({why})",
            cfg.session
        );
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
    let acc_security = Arc::new(Mutex::new(()));
    // The browser pages: sessions, the sign-in backoff, and the live streams.
    let pages = Arc::new(ui::Ui::new());
    let streams: Arc<Mutex<Vec<UiStream>>> = Arc::new(Mutex::new(Vec::new()));
    let panel = Arc::new(ServePanel {
        state: Arc::clone(&state),
        commands: Arc::clone(&commands),
        session: cfg.session,
        security: Arc::clone(&acc_security),
        accounts: crate::accounts::Source::new(&cfg.tuxedo, &cfg.accounts),
        tls: cfg.tls.clone(),
    });
    println!(
        "serve: pages on / (sign-in against {}, key from {})",
        cfg.accounts, cfg.tuxedo
    );
    let acc_pages = Arc::clone(&pages);
    let acc_streams = Arc::clone(&streams);
    // A thread per connection (`conn::serve`): a client that stalls in the
    // handshake or the head holds its own thread until the request deadline,
    // never the listener.
    let accept = std::thread::spawn(move || {
        crate::conn::serve(listener, MAX_CONNECTIONS, "serve", move |raw, peer| {
            // A stuck write must not wedge the fan-out. Reads are bounded by
            // the request deadline `Sink::accept` sets. TLS (if configured)
            // wraps the same socket; the handshake happens lazily on the first
            // read.
            let _ = raw.set_write_timeout(Some(Duration::from_secs(5)));
            // The config is read once here and the connection keeps it for its
            // life, so an InstallCertificate changes new connections only.
            let tls_now = acc_tls.as_ref().map(|t| t.current());
            let mut sink = match Sink::accept(raw, tls_now.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("serve: {peer}: {e}");
                    return;
                }
            };
            let (head, body0) = match crate::proxy::read_head(&mut sink, 16 * 1024) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("serve: {peer}: {e}");
                    return;
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
                    return;
                }
                if sink.write_all(HEAD).is_err() || sink.flush().is_err() {
                    return;
                }
                // Current state before enrolling, so the client is never behind.
                let my_cid = acc_cid.fetch_add(1, Ordering::Relaxed);
                let n = acc_clients.lock().unwrap().len() as u32 + 1;
                let snapshot = acc_state.lock().unwrap().snapshot(my_cid, n, &acc_quickarm);
                if !write_parts(&mut sink, &snapshot) {
                    return;
                }
                println!("serve: {peer} subscribed (cid {my_cid}, {n} client(s))");
                sink.clear_deadline();
                acc_clients.lock().unwrap().push(sink);
                return;
            }

            // The typed API.
            let resp = if target.starts_with("/system_http_api/") {
                let action = crate::api::classify(method, target, 0);
                match api_next(action, authed, acc_tls.is_some()) {
                    ApiNext::Reply(r) => r,
                    ApiNext::Status => {
                        json_response("200 OK", acc_state.lock().unwrap().status_json().as_bytes())
                    }
                    ApiNext::InstallCertificate => {
                        let (resp, log) = crate::certinstall::respond(
                            acc_tls.as_deref(),
                            sink.is_encrypted(),
                            &head,
                            |n| read_body(&mut sink, &body0, n),
                            crate::certinstall::now_unix(),
                        );
                        println!("serve: {peer}: {log}");
                        resp
                    }
                    ApiNext::Security(action) => {
                        let body = read_body(&mut sink, &body0, content_length(&head));
                        let form = String::from_utf8_lossy(&body);
                        // One command in flight at a time, as when the accept
                        // loop served connections in turn: the confirm wait
                        // reads a state byte any other command would move.
                        let _one = acc_security.lock().unwrap_or_else(|p| p.into_inner());
                        handle_security(&action, &form, acc_session, &acc_commands, &acc_state)
                    }
                }
            } else {
                // The browser pages; everything outside them is their 404.
                let ip = peer
                    .parse::<std::net::SocketAddr>()
                    .map(|a| a.ip())
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let req = ui::Request {
                    head: &head,
                    peer: ip,
                    encrypted: sink.is_encrypted(),
                };
                let reply = acc_pages.handle(
                    &req,
                    &mut |n| read_body(&mut sink, &body0, n),
                    &*panel,
                    Instant::now(),
                );
                match reply {
                    ui::Reply::Bytes(b) => b,
                    ui::Reply::Stream {
                        head: stream_head,
                        view,
                        session,
                    } => {
                        let open = acc_streams.lock().unwrap_or_else(|p| p.into_inner()).len();
                        if open >= ui::MAX_STREAMS {
                            eprintln!("serve: {peer}: event stream refused, {open} open");
                            ui::too_many_streams()
                        } else {
                            let mut first = stream_head;
                            first.extend_from_slice(&ui::state_event(&view));
                            if sink.write_all(&first).is_err() || sink.flush().is_err() {
                                return;
                            }
                            sink.clear_deadline();
                            acc_streams
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .push(UiStream {
                                    sink,
                                    session,
                                    sent: view,
                                });
                            return;
                        }
                    }
                }
            };
            let _ = sink.write_all(&resp);
            let _ = sink.flush();
        })
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
    let mut last_tick = Instant::now();
    loop {
        // The pages' live streams: every pass brings them up to date (at most
        // one reader tick, 500 ms, behind a reply), and every STREAM_TICK sends
        // a keep-alive and closes the streams whose session has ended.
        let tick = last_tick.elapsed() >= ui::STREAM_TICK;
        if tick {
            last_tick = Instant::now();
        }
        let view = ui::View::from_state(&state.lock().unwrap()).to_json();
        let closed = fan_out_ui(&streams, &view, &pages, tick);
        if closed > 0 {
            println!("serve: {closed} page stream(s) closed");
        }
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

    const INSTALL: &str = "/system_http_api/API_REV01/InstallCertificate";

    #[test]
    fn install_certificate_needs_the_token_and_post() {
        use crate::api::{classify, Action};
        let route = |m: &str, authed: bool| api_next(classify(m, INSTALL, 0), authed, true);
        // without a token: the same 401 the arm/disarm endpoints give
        assert_eq!(route("POST", false), ApiNext::Reply(unauthorized()));
        assert_eq!(
            api_next(
                classify(
                    "POST",
                    "/system_http_api/API_REV01/AdvancedSecurity/ArmWithCode",
                    0
                ),
                false,
                true
            ),
            ApiNext::Reply(unauthorized())
        );
        assert_eq!(route("POST", true), ApiNext::InstallCertificate);
        // any other method is the 405 the other endpoints give
        assert_eq!(
            route("GET", true),
            ApiNext::Reply(crate::api::method_not_allowed())
        );
        assert_eq!(
            route("PUT", false),
            ApiNext::Reply(crate::api::method_not_allowed())
        );
        // a plaintext bench routes it too; certinstall answers 409 there
        assert_eq!(
            api_next(Action::InstallCertificate, true, false),
            ApiNext::InstallCertificate
        );
    }

    #[test]
    fn the_capability_answer_follows_the_tls_setup_and_needs_no_token() {
        use crate::api::Action;
        assert_eq!(
            api_next(Action::Capabilities, false, true),
            ApiNext::Reply(crate::api::capabilities_response(true))
        );
        assert_eq!(
            api_next(Action::Capabilities, false, false),
            ApiNext::Reply(crate::api::capabilities_response(false))
        );
    }

    #[test]
    fn an_api_arm_without_a_code_sends_the_no_code_sentinel() {
        use crate::api::Action;
        let arm = Action::Arm { code: 0 };
        let want = |code, p2| SecurityCommand {
            code,
            p2,
            target: 0xFF,
            disarm: false,
        };
        assert_eq!(
            security_command(&arm, "arming=stay&pID=1&operation=set"),
            Ok(want(cmd::ARM_STAY, 0xFFFF))
        );
        for form in [
            "arming=away&pID=1&ucode=&operation=set",
            "arming=away&pID=1&ucode=0&operation=set",
            "arming=away&pID=1&ucode=%20&operation=set",
        ] {
            assert_eq!(
                security_command(&arm, form),
                Ok(want(cmd::ARM_AWAY, 0xFFFF)),
                "{form}"
            );
        }
        assert_eq!(
            security_command(&arm, "arming=night&pID=1&operation=set"),
            Ok(want(cmd::ARM_NIGHT, NO_CODE))
        );
        // a code that is sent still goes through, as the consumer sends it
        assert_eq!(
            security_command(&arm, "arming=stay&pID=1&ucode=1234&operation=set"),
            Ok(want(cmd::ARM_STAY, 1234))
        );
        // garbage is refused, never read as "no code"
        let r = security_command(&arm, "arming=stay&ucode=12x4").unwrap_err();
        assert!(String::from_utf8(r).unwrap().starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn an_api_disarm_without_a_code_is_refused_before_sending() {
        use crate::api::Action;
        for form in [
            "pID=1&operation=set",
            "pID=1&ucode=&operation=set",
            "pID=1&ucode=0&operation=set",
            "pID=1&ucode=0000&operation=set",
            "pID=1&ucode=abcd&operation=set",
        ] {
            let r =
                String::from_utf8(security_command(&Action::Disarm, form).unwrap_err()).unwrap();
            assert!(r.starts_with("HTTP/1.1 400"), "{form}: {r}");
            assert!(r.contains("a user code is required"), "{form}: {r}");
        }
        assert_eq!(
            security_command(&Action::Disarm, "pID=1&ucode=1234&operation=set"),
            Ok(SecurityCommand {
                code: cmd::DISARM,
                p2: 1234,
                target: 0xFE,
                disarm: true,
            })
        );
    }

    #[test]
    fn page_streams_get_each_change_once_and_close_with_their_session() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut live_client = std::net::TcpStream::connect(addr).unwrap();
        let (live, _) = l.accept().unwrap();
        let mut dead_client = std::net::TcpStream::connect(addr).unwrap();
        let (dead, _) = l.accept().unwrap();
        let pages = ui::Ui::new();
        pages.open_session_for_test("live", Instant::now());
        let streams = Mutex::new(vec![
            UiStream {
                sink: Sink::accept(live, None).unwrap(),
                session: "live".into(),
                sent: "A".into(),
            },
            UiStream {
                sink: Sink::accept(dead, None).unwrap(),
                session: "signed-out".into(),
                sent: "A".into(),
            },
        ]);
        assert_eq!(
            fan_out_ui(&streams, "A", &pages, false),
            0,
            "no change, no tick"
        );
        assert_eq!(fan_out_ui(&streams, "B", &pages, false), 0);
        assert_eq!(
            fan_out_ui(&streams, "B", &pages, false),
            0,
            "B is not sent twice"
        );
        assert_eq!(
            fan_out_ui(&streams, "B", &pages, true),
            1,
            "the signed-out one closes"
        );
        drop(streams);
        let read_all = |c: &mut std::net::TcpStream| {
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut v = Vec::new();
            let _ = c.read_to_end(&mut v);
            String::from_utf8(v).unwrap()
        };
        assert_eq!(
            read_all(&mut live_client),
            format!(
                "event: state\ndata: B\n\n{}",
                String::from_utf8_lossy(ui::KEEPALIVE)
            )
        );
        assert_eq!(read_all(&mut dead_client), "event: state\ndata: B\n\n");
    }

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
            tuxedo: "/nonexistent".into(),
            accounts: "/nonexistent".into(),
        })
        .unwrap_err();
        assert!(e.contains("non-zero"), "{e}");
    }

    #[test]
    fn the_subscribe_head_carries_the_vendor_quirks() {
        let h = String::from_utf8(HEAD.to_vec()).unwrap();
        assert!(
            h.contains("\r\nServer: \r\n"),
            "empty Server is a preserved quirk"
        );
        assert!(h.contains("Connection: Close"));
        assert!(h.contains("multipart/x-mixed-replace;boundary=\"EH912ZZ\""));
    }
}
