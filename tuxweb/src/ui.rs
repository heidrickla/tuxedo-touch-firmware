//! The browser pages: sign-in, status, and a code pad that opens only for Disarm.
//!
//! Our own pages, CSS and JS, embedded in the binary and served under a strict
//! CSP (`default-src 'self'`, no inline script or style), dark by default. No
//! vendor asset is used (§1.4: the vendor JS depends on page shells and a
//! transport we do not implement).
//!
//! * **Sign-in** checks a username and password against the vendor account
//!   store (`accounts.rs`, §1.6 decision (a)), so the keypad's account screen
//!   and the web stay one list. A success opens an in-memory session: a random
//!   32-byte id in a cookie (HttpOnly, Secure, SameSite=Strict, Path=/), idle
//!   expiry [`SESSION_IDLE`], forgotten on sign-out and on restart.
//! * **Failed sign-ins back off per source address**, exponentially and capped
//!   ([`Backoff`]). The password on this panel is a four-digit code, so the
//!   guessing rate is the only protection; the backoff never locks an account
//!   and never touches the store (P1 removed the vendor's on-disk lockout and
//!   this does not bring it back, §1.6).
//! * **State-changing requests** need the session's CSRF token in a header,
//!   plus SameSite, plus a matching `Origin` when the browser sends one.
//! * **Live state** reaches the page by Server-Sent Events from the model the
//!   serve mode already keeps ([`View::from_state`]). The page adds no timer:
//!   the exit countdown is the panel's own, and Armed is shown only once the
//!   panel reports it.
//! * **Arming takes no code** (p2 = `ipc::NO_CODE`, what the touchscreen
//!   sends); disarming needs the user's code, and a missing or zero code is
//!   refused before anything is sent.
//!
//! The API's bearer-token auth (`auth.rs`) is separate and unchanged: a browser
//! session does not authorize `/system_http_api/…`, and a token does not open a
//! browser session.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::rand::SecureRandom;
use serde::Serialize;

use crate::accounts::Denied;
use crate::ipc::{self, cmd};
use crate::push::PanelState;

/// The browser session cookie. Not `tuxweb_token`, which is the API's.
pub const SESSION_COOKIE: &str = "tuxweb_session";
/// A session unused for this long is gone.
pub const SESSION_IDLE: Duration = Duration::from_secs(12 * 3600);
/// Sessions held at once; past this the least recently used one is dropped.
const MAX_SESSIONS: usize = 64;
/// The header a state-changing request carries the session's CSRF token in.
pub const CSRF_HEADER: &str = "x-csrf-token";
/// Largest form body a page posts (a username and password, or one field).
const MAX_FORM: usize = 4 * 1024;
/// Live event streams open at once; one more is answered 503.
pub const MAX_STREAMS: usize = 8;
/// How often an open event stream gets a keep-alive comment and its session
/// is checked.
pub const STREAM_TICK: Duration = Duration::from_secs(15);

/// Every response from this module carries it. `default-src 'self'` covers
/// scripts, styles, images and the event stream; nothing inline is allowed.
pub const CSP: &str = "default-src 'self'; base-uri 'none'; form-action 'self'; \
                       frame-ancestors 'none'; object-src 'none'";

/// Failed sign-ins from one address before any wait.
const FREE_FAILURES: u32 = 3;
/// The longest wait between attempts from one address.
const BACKOFF_CAP: Duration = Duration::from_secs(15 * 60);
/// An address with no failure for this long starts clean.
const BACKOFF_FORGET: Duration = Duration::from_secs(24 * 3600);
/// Addresses tracked at once; past this the one quiet longest is forgotten.
const MAX_TRACKED: usize = 256;

const LOGIN_HTML: &str = include_str!("../ui/login.html");
const INDEX_HTML: &str = include_str!("../ui/index.html");

/// `(name under /ui/assets/, content type, bytes)`.
const ASSETS: &[(&str, &str, &str)] = &[
    (
        "app.css",
        "text/css; charset=utf-8",
        include_str!("../ui/app.css"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_str!("../ui/app.js"),
    ),
    ("icon.svg", "image/svg+xml", include_str!("../ui/icon.svg")),
];

const ASSET_PREFIX: &str = "/ui/assets/";

/// What a request resolves to, from its method and path alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `GET /`: the status page when signed in, else a redirect to sign-in.
    Index,
    /// `GET /login`.
    LoginPage,
    /// `POST /login`.
    LoginSubmit,
    /// `POST /logout`.
    Logout,
    /// `GET /ui/events`: the live state stream.
    Events,
    /// `POST /ui/arm`, field `mode`.
    Arm,
    /// `POST /ui/disarm`, field `code`.
    Disarm,
    /// `GET /ui/assets/<name>`, an index into [`ASSETS`].
    Asset(usize),
    /// A known path with the wrong method; carries the `Allow` value.
    MethodNotAllowed(&'static str),
    NotFound,
}

/// Route a request. The query string is ignored.
pub fn route(method: &str, target: &str) -> Route {
    let path = target.split('?').next().unwrap_or(target);
    let get = method.eq_ignore_ascii_case("GET");
    let post = method.eq_ignore_ascii_case("POST");
    let pick = |ok: bool, r: Route, allow: &'static str| {
        if ok {
            r
        } else {
            Route::MethodNotAllowed(allow)
        }
    };
    match path {
        "/" => pick(get, Route::Index, "GET"),
        "/login" => {
            if get {
                Route::LoginPage
            } else if post {
                Route::LoginSubmit
            } else {
                Route::MethodNotAllowed("GET, POST")
            }
        }
        "/logout" => pick(post, Route::Logout, "POST"),
        "/ui/events" => pick(get, Route::Events, "GET"),
        "/ui/arm" => pick(post, Route::Arm, "POST"),
        "/ui/disarm" => pick(post, Route::Disarm, "POST"),
        _ => match path.strip_prefix(ASSET_PREFIX) {
            Some(name) => match ASSETS.iter().position(|(n, _, _)| *n == name) {
                Some(i) => pick(get, Route::Asset(i), "GET"),
                None => Route::NotFound,
            },
            None => Route::NotFound,
        },
    }
}

// -- responses ----------------------------------------------------------------

/// A response with the security headers every answer here carries.
///
/// `Referrer-Policy: same-origin`, not `no-referrer`: under `no-referrer` a
/// browser sends `Origin: null` on a form POST, and the sign-in form (whose
/// POST [`same_origin`] checks) was refused 403 in Chromium on the bench. A
/// same-origin policy still sends nothing to another site.
fn response(
    status: &str,
    content_type: &str,
    cache: &str,
    extra: &[String],
    body: &[u8],
) -> Vec<u8> {
    let mut h = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Content-Security-Policy: {CSP}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: same-origin\r\n\
         Cache-Control: {cache}\r\n",
        body.len()
    );
    for e in extra {
        h.push_str(e);
        h.push_str("\r\n");
    }
    h.push_str("Connection: close\r\n\r\n");
    let mut v = h.into_bytes();
    v.extend_from_slice(body);
    v
}

fn html(status: &str, extra: &[String], body: &str) -> Vec<u8> {
    response(
        status,
        "text/html; charset=utf-8",
        "no-store",
        extra,
        body.as_bytes(),
    )
}

fn json(status: &str, extra: &[String], ok: bool, message: &str) -> Vec<u8> {
    let body = serde_json::json!({ "ok": ok, "message": message }).to_string();
    response(
        status,
        "application/json",
        "no-store",
        extra,
        body.as_bytes(),
    )
}

fn redirect(to: &str, extra: &[String]) -> Vec<u8> {
    let mut e = vec![format!("Location: {to}")];
    e.extend_from_slice(extra);
    response(
        "303 See Other",
        "text/plain; charset=utf-8",
        "no-store",
        &e,
        b"",
    )
}

fn not_found() -> Vec<u8> {
    response(
        "404 Not Found",
        "text/plain; charset=utf-8",
        "no-store",
        &[],
        b"",
    )
}

/// The head that opens an event stream: no length, the stream ends at close.
pub fn stream_head() -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Content-Security-Policy: {CSP}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: same-origin\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}

/// The answer when [`MAX_STREAMS`] are already open.
pub fn too_many_streams() -> Vec<u8> {
    response(
        "503 Service Unavailable",
        "text/plain; charset=utf-8",
        "no-store",
        &["Retry-After: 30".to_string()],
        b"",
    )
}

/// One `state` event carrying the view as JSON.
pub fn state_event(view_json: &str) -> Vec<u8> {
    format!("event: state\ndata: {view_json}\n\n").into_bytes()
}

/// An SSE comment: keeps the connection alive and finds dead ones.
pub const KEEPALIVE: &[u8] = b": keep-alive\n\n";

/// The session cookie as set on sign-in.
pub fn set_cookie(id: &str) -> String {
    format!("Set-Cookie: {SESSION_COOKIE}={id}; HttpOnly; Secure; SameSite=Strict; Path=/")
}

/// The session cookie cleared, on sign-out.
pub fn clear_cookie() -> String {
    format!("Set-Cookie: {SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Put HTML-escaped values into a page's `{{name}}` slots.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (k, v) in values {
        out = out.replace(&format!("{{{{{k}}}}}"), &html_escape(v));
    }
    out
}

// -- request helpers -----------------------------------------------------------

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    crate::proxy::header(head, name)
}

/// The session id from the request's cookies, if it has the shape of one.
pub fn session_id(head: &str) -> Option<String> {
    for line in head.split("\r\n").skip(1) {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case("cookie") {
            continue;
        }
        for c in v.split(';') {
            if let Some((n, val)) = c.trim().split_once('=') {
                let val = val.trim();
                if n.trim() == SESSION_COOKIE
                    && val.len() == 64
                    && val.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Some(val.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

/// Whether the request's `Origin`, when it sends one, is this server. A browser
/// sends `Origin` on every POST; an absent one is an older client, still held
/// to the CSRF token and SameSite.
fn same_origin(head: &str, encrypted: bool) -> bool {
    let Some(origin) = header(head, "origin") else {
        return true;
    };
    let Some(host) = header(head, "host") else {
        return false;
    };
    let scheme = if encrypted { "https" } else { "http" };
    let ok = origin.eq_ignore_ascii_case(&format!("{scheme}://{host}"));
    if !ok {
        eprintln!("ui: refused a POST from origin {origin:?} for host {host:?}");
    }
    ok
}

fn content_length(head: &str) -> Option<usize> {
    match header(head, "content-length") {
        None => Some(0),
        Some(v) => v.trim().parse().ok(),
    }
}

fn form_field(body: &[u8], key: &str) -> Option<String> {
    crate::serve::form_get(&String::from_utf8_lossy(body), key)
}

fn random_hex(rng: &ring::rand::SystemRandom) -> Option<String> {
    let mut raw = [0u8; 32];
    rng.fill(&mut raw).ok()?;
    Some(raw.iter().map(|b| format!("{b:02x}")).collect())
}

// -- sessions ------------------------------------------------------------------

struct Session {
    user: String,
    csrf: String,
    last: Instant,
}

/// Signed-in browsers, in memory only: a restart signs everyone out.
#[derive(Default)]
pub struct Sessions {
    map: HashMap<String, Session>,
}

impl Sessions {
    fn insert(&mut self, id: String, user: String, csrf: String, now: Instant) {
        self.map
            .retain(|_, s| now.saturating_duration_since(s.last) < SESSION_IDLE);
        if self.map.len() >= MAX_SESSIONS {
            if let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, s)| s.last)
                .map(|(k, _)| k.clone())
            {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(
            id,
            Session {
                user,
                csrf,
                last: now,
            },
        );
    }

    /// The session's user and CSRF token, marking it used now. An expired one
    /// is removed and answers `None`.
    fn touch(&mut self, id: &str, now: Instant) -> Option<(String, String)> {
        let s = self.map.get_mut(id)?;
        if now.saturating_duration_since(s.last) >= SESSION_IDLE {
            self.map.remove(id);
            return None;
        }
        s.last = now;
        Some((s.user.clone(), s.csrf.clone()))
    }

    /// Whether the session is still valid, without marking it used. An open
    /// event stream does not keep a session alive.
    fn alive(&self, id: &str, now: Instant) -> bool {
        self.map
            .get(id)
            .is_some_and(|s| now.saturating_duration_since(s.last) < SESSION_IDLE)
    }

    fn remove(&mut self, id: &str) {
        self.map.remove(id);
    }
}

// -- sign-in backoff -------------------------------------------------------------

struct Strikes {
    failures: u32,
    last: Instant,
}

/// Failed sign-ins per source address. After [`FREE_FAILURES`] the next
/// attempt waits 1 s, then 2, 4, 8 … up to [`BACKOFF_CAP`]; a success clears
/// the address. Attempts refused during a wait are not checked and not counted.
/// Per address, never per account: a guesser elsewhere cannot lock anyone out.
#[derive(Default)]
pub struct Backoff {
    map: HashMap<IpAddr, Strikes>,
}

/// The wait after `failures` failed attempts.
pub fn backoff_delay(failures: u32) -> Duration {
    if failures < FREE_FAILURES {
        return Duration::ZERO;
    }
    let exp = (failures - FREE_FAILURES).min(20);
    Duration::from_secs(1u64 << exp).min(BACKOFF_CAP)
}

impl Backoff {
    /// How long this address must still wait before another attempt, if at all.
    pub fn wait(&mut self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let s = self.map.get(&ip)?;
        if now.saturating_duration_since(s.last) >= BACKOFF_FORGET {
            self.map.remove(&ip);
            return None;
        }
        let until = s.last + backoff_delay(s.failures);
        (now < until).then(|| until - now)
    }

    /// Record a failure; returns the address's failure count.
    pub fn fail(&mut self, ip: IpAddr, now: Instant) -> u32 {
        if !self.map.contains_key(&ip) && self.map.len() >= MAX_TRACKED {
            if let Some(quiet) = self.map.iter().min_by_key(|(_, s)| s.last).map(|(k, _)| *k) {
                self.map.remove(&quiet);
            }
        }
        let s = self.map.entry(ip).or_insert(Strikes {
            failures: 0,
            last: now,
        });
        if now.saturating_duration_since(s.last) >= BACKOFF_FORGET {
            s.failures = 0;
        }
        s.failures += 1;
        s.last = now;
        s.failures
    }

    pub fn clear(&mut self, ip: IpAddr) {
        self.map.remove(&ip);
    }
}

// -- the view the page renders -------------------------------------------------

/// What the status page shows, derived from the serve mode's [`PanelState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct View {
    /// `unknown`, `disarmed`, `arming`, `armed`, `alarm` or `other`.
    pub phase: &'static str,
    /// The one line the page leads with.
    pub headline: String,
    /// The panel's status text, the bar-colour digit removed.
    pub status: String,
    /// The `0xFE`/`0xFF` byte: false disarmed, true armed or arming.
    pub armed: Option<bool>,
    /// Seconds left in the exit delay, as the panel counts them.
    pub countdown: Option<u32>,
    /// `stay`, `away` or `night`, when the panel's display names one.
    pub mode: Option<&'static str>,
    /// The keypad LCD, one entry per line.
    pub lcd: Vec<String>,
    /// `ok`, `offline` (the VISTA reports itself not online: a msgType 22) or
    /// `lost` (the Tuxedo cannot hear the VISTA: `+0x08` is -1).
    pub link: &'static str,
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// `"59  Secs Remaining"` -> 59. The panel's own exit-delay text.
pub fn countdown(status: &str) -> Option<u32> {
    status
        .trim()
        .strip_suffix("Secs Remaining")?
        .trim()
        .parse()
        .ok()
}

/// The arming mode named by the keypad display or the status text.
fn mode_of(lcd: &str, status: &str) -> Option<&'static str> {
    let l = lcd.to_ascii_uppercase();
    let s = status.to_ascii_uppercase();
    for (word, mode) in [("NIGHT", "night"), ("AWAY", "away"), ("STAY", "stay")] {
        if l.contains(word) || s.contains(word) {
            return Some(mode);
        }
    }
    None
}

impl View {
    pub fn from_state(st: &PanelState) -> View {
        let lcd_raw = st.console_text().map(|t| latin1(&t)).unwrap_or_default();
        let lcd: Vec<String> = if lcd_raw.is_empty() {
            Vec::new()
        } else {
            lcd_raw
                .split('|')
                .map(|l| l.trim_end().to_string())
                .collect()
        };
        let Some(r) = st.status_reply() else {
            return View {
                phase: "unknown",
                headline: "Waiting for the panel".into(),
                status: String::new(),
                armed: None,
                countdown: None,
                mode: None,
                lcd,
                link: "ok",
            };
        };
        View::from_status(&r, &lcd_raw, lcd)
    }

    fn from_status(r: &ipc::Reply, lcd_raw: &str, lcd: Vec<String>) -> View {
        // text = state byte, bar-colour digit, status (`ipc.rs`, §8d.2)
        let byte = r.state_byte();
        let rest = r.text.get(1..).unwrap_or(&[]);
        let rest = match rest.first() {
            Some(d) if d.is_ascii_digit() => &rest[1..],
            _ => rest,
        };
        let status = latin1(rest).trim().to_string();
        let link = if r.arg as i32 == -1 {
            "lost"
        } else if r.msg_type == 22 {
            "offline"
        } else {
            "ok"
        };
        let armed = match byte {
            Some(0xFF) => Some(true),
            Some(0xFE) => Some(false),
            _ => None,
        };
        let count = countdown(&status);
        let mode = if armed == Some(true) {
            mode_of(lcd_raw, &status)
        } else {
            None
        };
        let (phase, headline) = match (armed, count) {
            (Some(false), _) => ("disarmed", status.clone()),
            (Some(true), Some(n)) => (
                "arming",
                match mode {
                    Some(m) => format!("Arming {m}, {n} s to leave"),
                    None => format!("Arming, {n} s to leave"),
                },
            ),
            (Some(true), None) if status.contains("Alarm") => ("alarm", status.clone()),
            (Some(true), None) if status.starts_with("Armed") => ("armed", status.clone()),
            (Some(true), None) => ("other", status.clone()),
            (None, _) => ("unknown", status.clone()),
        };
        View {
            phase,
            headline,
            status,
            armed,
            countdown: count,
            mode,
            lcd,
            link,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

// -- what the pages need from the serve mode --------------------------------------

/// The result of sending a command and waiting for the panel to act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The state byte moved to the target within the ceiling.
    Confirmed,
    /// Sent, but the panel did not move within the ceiling.
    NotConfirmed,
    /// The command could not be put on the queue.
    SendFailed,
}

/// Why a sign-in did not open a session.
#[derive(Debug, PartialEq)]
pub enum LoginError {
    /// The store answered no. Never distinguished to the client (§1.6).
    Denied(Denied),
    /// The account list could not be read at all.
    Unavailable(String),
}

/// The serve mode, as the pages see it.
pub trait Panel {
    fn view(&self) -> View;
    /// Send `code` with `p2` at `+0x0C` and wait for the state byte to reach
    /// `target`.
    fn command(&self, code: u32, p2: u32, target: u8) -> Outcome;
    /// The account's stored name on success.
    fn authenticate(&self, user: &str, password: &str) -> Result<String, LoginError>;
    /// The certificate's expiry, RFC 3339, or `None` when serving plaintext.
    fn cert_not_after(&self) -> Option<String>;
}

/// One request as the pages see it.
pub struct Request<'a> {
    pub head: &'a str,
    pub peer: IpAddr,
    /// Whether the connection is TLS (the `Origin` scheme to expect).
    pub encrypted: bool,
}

/// What to do with the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// Write these bytes and close.
    Bytes(Vec<u8>),
    /// Write `head` and a `state` event carrying `view` (the view as JSON),
    /// then keep the connection as an event stream for `session`. The serve
    /// mode remembers `view` as what this stream last received, so a change it
    /// has not seen yet is sent on the next tick whatever the timing.
    Stream {
        head: Vec<u8>,
        view: String,
        session: String,
    },
}

/// The pages' state: sessions and the sign-in backoff.
pub struct Ui {
    sessions: Mutex<Sessions>,
    backoff: Mutex<Backoff>,
    rng: ring::rand::SystemRandom,
}

impl Default for Ui {
    fn default() -> Self {
        Ui::new()
    }
}

/// `Certificate expires 2027-11-06 12:00 UTC`, from `2027-11-06T12:00:00Z`.
fn cert_line(not_after: Option<String>) -> String {
    match not_after {
        None => "No certificate: plaintext".into(),
        Some(t) => {
            let t = t.trim_end_matches('Z');
            let (date, time) = t.split_once('T').unwrap_or((t, ""));
            let hm: String = time.chars().take(5).collect();
            if hm.is_empty() {
                format!("Certificate expires {date}")
            } else {
                format!("Certificate expires {date} {hm} UTC")
            }
        }
    }
}

impl Ui {
    pub fn new() -> Ui {
        Ui {
            sessions: Mutex::new(Sessions::default()),
            backoff: Mutex::new(Backoff::default()),
            rng: ring::rand::SystemRandom::new(),
        }
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn backoff(&self) -> std::sync::MutexGuard<'_, Backoff> {
        self.backoff.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A signed-in session with this id, for tests outside this module.
    #[cfg(test)]
    pub fn open_session_for_test(&self, id: &str, now: Instant) {
        self.sessions()
            .insert(id.into(), "test".into(), "csrf".into(), now);
    }

    /// Whether an event stream's session still stands (signed out or expired
    /// streams are closed).
    pub fn session_alive(&self, id: &str, now: Instant) -> bool {
        self.sessions().alive(id, now)
    }

    /// Answer one request. `read_body(n)` reads the `n`-byte body; it is called
    /// only for a POST whose length is acceptable.
    pub fn handle(
        &self,
        req: &Request<'_>,
        read_body: &mut dyn FnMut(usize) -> Vec<u8>,
        panel: &dyn Panel,
        now: Instant,
    ) -> Reply {
        let mut line = req
            .head
            .split("\r\n")
            .next()
            .unwrap_or("")
            .split_whitespace();
        let method = line.next().unwrap_or("");
        let target = line.next().unwrap_or("/");
        let route = route(method, target);
        let session = session_id(req.head);
        Reply::Bytes(match route {
            Route::NotFound => not_found(),
            Route::MethodNotAllowed(allow) => response(
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                "no-store",
                &[format!("Allow: {allow}")],
                b"",
            ),
            Route::Asset(i) => {
                let (_, ctype, body) = ASSETS[i];
                response("200 OK", ctype, "no-cache", &[], body.as_bytes())
            }
            Route::LoginPage => {
                if session.is_some_and(|id| self.sessions().touch(&id, now).is_some()) {
                    redirect("/", &[])
                } else {
                    self.login_page("200 OK", "", "", &[])
                }
            }
            Route::Index => match session.and_then(|id| self.sessions().touch(&id, now)) {
                None => redirect("/login", &[]),
                Some((user, csrf)) => html(
                    "200 OK",
                    &[],
                    &fill(
                        INDEX_HTML,
                        &[
                            ("csrf", &csrf),
                            ("user", &user),
                            ("build", crate::api::FIRMWARE),
                            ("cert", &cert_line(panel.cert_not_after())),
                        ],
                    ),
                ),
            },
            Route::Events => match session
                .as_deref()
                .and_then(|id| self.sessions().touch(id, now))
            {
                None => json("401 Unauthorized", &[], false, "Signed out."),
                Some(_) => {
                    return Reply::Stream {
                        head: stream_head(),
                        view: panel.view().to_json(),
                        session: session.unwrap_or_default(),
                    }
                }
            },
            Route::LoginSubmit => self.login(req, read_body, panel, now),
            Route::Logout | Route::Arm | Route::Disarm => {
                let (id, user) = match self.check_post(req, session, now) {
                    Ok(v) => v,
                    Err(resp) => return Reply::Bytes(resp),
                };
                let body = match content_length(req.head) {
                    Some(n) if n <= MAX_FORM => read_body(n),
                    _ => {
                        return Reply::Bytes(json(
                            "413 Content Too Large",
                            &[],
                            false,
                            "Too large.",
                        ))
                    }
                };
                match route {
                    Route::Logout => {
                        self.sessions().remove(&id);
                        println!("ui: {} ({user}) signed out", req.peer);
                        json("200 OK", &[clear_cookie()], true, "Signed out.")
                    }
                    Route::Arm => arm(req, &user, &body, panel),
                    _ => disarm(req, &user, &body, panel),
                }
            }
        })
    }

    /// A state-changing request: same origin, a live session, and its CSRF token.
    fn check_post(
        &self,
        req: &Request<'_>,
        session: Option<String>,
        now: Instant,
    ) -> Result<(String, String), Vec<u8>> {
        if !same_origin(req.head, req.encrypted) {
            return Err(json(
                "403 Forbidden",
                &[],
                false,
                "Refused: cross-origin request.",
            ));
        }
        let Some(id) = session else {
            return Err(json("401 Unauthorized", &[], false, "Signed out."));
        };
        let Some((user, csrf)) = self.sessions().touch(&id, now) else {
            return Err(json("401 Unauthorized", &[], false, "Signed out."));
        };
        let sent = header(req.head, CSRF_HEADER).unwrap_or("");
        if !crate::accounts::ct_eq(sent, &csrf) {
            eprintln!(
                "ui: {} ({user}): refused, CSRF token missing or wrong",
                req.peer
            );
            return Err(json(
                "403 Forbidden",
                &[],
                false,
                "Refused: this page's token is missing or stale. Reload the page.",
            ));
        }
        Ok((id, user))
    }

    fn login_page(&self, status: &str, username: &str, error: &str, extra: &[String]) -> Vec<u8> {
        html(
            status,
            extra,
            &fill(
                LOGIN_HTML,
                &[
                    ("username", username),
                    ("error", error),
                    ("build", crate::api::FIRMWARE),
                ],
            ),
        )
    }

    fn login(
        &self,
        req: &Request<'_>,
        read_body: &mut dyn FnMut(usize) -> Vec<u8>,
        panel: &dyn Panel,
        now: Instant,
    ) -> Vec<u8> {
        if !same_origin(req.head, req.encrypted) {
            return self.login_page("403 Forbidden", "", "Refused: cross-origin request.", &[]);
        }
        // Checked before the password is even read: an attempt during a wait
        // is not a guess.
        let wait = self.backoff().wait(req.peer, now);
        if let Some(w) = wait {
            let secs = w.as_secs() + u64::from(w.subsec_nanos() > 0);
            return self.login_page(
                "429 Too Many Requests",
                "",
                &format!("Too many failed sign-ins from this address. Try again in {secs} s."),
                &[format!("Retry-After: {secs}")],
            );
        }
        let body = match content_length(req.head) {
            Some(n) if n <= MAX_FORM => read_body(n),
            _ => return self.login_page("413 Content Too Large", "", "Too large.", &[]),
        };
        let user = form_field(&body, "username").unwrap_or_default();
        let password = form_field(&body, "password").unwrap_or_default();
        let user = user.trim();
        if user.is_empty() || password.is_empty() {
            return self.login_page(
                "400 Bad Request",
                user,
                "Enter a username and a password.",
                &[],
            );
        }
        match panel.authenticate(user, &password) {
            Ok(name) => {
                self.backoff().clear(req.peer);
                let (Some(id), Some(csrf)) = (random_hex(&self.rng), random_hex(&self.rng)) else {
                    return self.login_page(
                        "503 Service Unavailable",
                        user,
                        "The server could not make a session. Try again.",
                        &[],
                    );
                };
                self.sessions().insert(id.clone(), name.clone(), csrf, now);
                println!("ui: {} signed in as {name}", req.peer);
                redirect("/", &[set_cookie(&id)])
            }
            Err(LoginError::Unavailable(e)) => {
                eprintln!("ui: {}: sign-in unavailable: {e}", req.peer);
                self.login_page(
                    "503 Service Unavailable",
                    user,
                    "Sign-in is unavailable: the server cannot read the account list.",
                    &[],
                )
            }
            Err(LoginError::Denied(why)) => {
                let n = self.backoff().fail(req.peer, now);
                // The reason is for the operator's log; the page says one thing.
                eprintln!(
                    "ui: {}: sign-in refused ({why:?}), {n} failure(s) from this address",
                    req.peer
                );
                self.login_page("401 Unauthorized", user, "Wrong username or password.", &[])
            }
        }
    }
}

fn outcome_response(o: Outcome, done: &str, not_confirmed: &str) -> Vec<u8> {
    match o {
        Outcome::Confirmed => json("200 OK", &[], true, done),
        Outcome::NotConfirmed => json("504 Gateway Timeout", &[], false, not_confirmed),
        Outcome::SendFailed => json("502 Bad Gateway", &[], false, "Could not reach the panel."),
    }
}

/// `POST /ui/arm`: no code. p2 is `ipc::NO_CODE`, what the touchscreen sends.
fn arm(req: &Request<'_>, user: &str, body: &[u8], panel: &dyn Panel) -> Vec<u8> {
    let code = match form_field(body, "mode").as_deref() {
        Some("stay") => cmd::ARM_STAY,
        Some("away") => cmd::ARM_AWAY,
        Some("night") => cmd::ARM_NIGHT,
        _ => return json("400 Bad Request", &[], false, "Unknown arming mode."),
    };
    if panel.view().armed == Some(true) {
        return json("409 Conflict", &[], false, "The panel is already armed.");
    }
    let o = panel.command(code, ipc::NO_CODE, 0xFF);
    println!("ui: {} ({user}) arm, command {code}: {o:?}", req.peer);
    outcome_response(
        o,
        "The panel is arming.",
        "The panel did not confirm. Check the keypad display.",
    )
}

/// `POST /ui/disarm`: the user's four-digit code. A missing code, or 0000, is
/// refused before anything is sent: code 0 is a literal code, and the panel's
/// declined path changes state (register.rs).
fn disarm(req: &Request<'_>, user: &str, body: &[u8], panel: &dyn Panel) -> Vec<u8> {
    let code = form_field(body, "code").unwrap_or_default();
    let valid = code.len() == 4 && code.bytes().all(|b| b.is_ascii_digit());
    let ucode: u32 = if valid { code.parse().unwrap_or(0) } else { 0 };
    if ucode == 0 {
        return json(
            "400 Bad Request",
            &[],
            false,
            "Enter your four-digit alarm code.",
        );
    }
    if panel.view().armed == Some(false) {
        return json("409 Conflict", &[], false, "The panel is already disarmed.");
    }
    let o = panel.command(cmd::DISARM, ucode, 0xFE);
    println!("ui: {} ({user}) disarm: {o:?}", req.peer);
    outcome_response(o, "Disarmed.", "The panel did not disarm. Check the code.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

    /// A fake serve mode: one account, a settable arm state, and a log of the
    /// commands that reached it.
    struct Fake {
        armed: Mutex<Option<bool>>,
        sent: Mutex<Vec<(u32, u32, u8)>>,
        auth_calls: Mutex<u32>,
        unavailable: bool,
    }

    impl Fake {
        fn new(armed: Option<bool>) -> Fake {
            Fake {
                armed: Mutex::new(armed),
                sent: Mutex::new(Vec::new()),
                auth_calls: Mutex::new(0),
                unavailable: false,
            }
        }
        fn sent(&self) -> Vec<(u32, u32, u8)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl Panel for Fake {
        fn view(&self) -> View {
            View {
                phase: "unknown",
                headline: String::new(),
                status: String::new(),
                armed: *self.armed.lock().unwrap(),
                countdown: None,
                mode: None,
                lcd: Vec::new(),
                link: "ok",
            }
        }
        fn command(&self, code: u32, p2: u32, target: u8) -> Outcome {
            self.sent.lock().unwrap().push((code, p2, target));
            Outcome::Confirmed
        }
        fn authenticate(&self, user: &str, password: &str) -> Result<String, LoginError> {
            *self.auth_calls.lock().unwrap() += 1;
            if self.unavailable {
                return Err(LoginError::Unavailable("no store".into()));
            }
            if user.eq_ignore_ascii_case("owner") && password == "4321" {
                Ok("Owner".into())
            } else {
                Err(LoginError::Denied(Denied::WrongPassword))
            }
        }
        fn cert_not_after(&self) -> Option<String> {
            Some("2027-11-06T12:00:00Z".into())
        }
    }

    fn head(method: &str, path: &str, extra: &[&str]) -> String {
        let mut h = format!("{method} {path} HTTP/1.1\r\nHost: panel.test\r\n");
        for e in extra {
            h.push_str(e);
            h.push_str("\r\n");
        }
        h.push_str("\r\n");
        h
    }

    fn call(ui: &Ui, panel: &Fake, head: &str, body: &[u8], now: Instant) -> Reply {
        call_from(ui, panel, head, body, now, IP)
    }

    fn call_from(
        ui: &Ui,
        panel: &Fake,
        head: &str,
        body: &[u8],
        now: Instant,
        peer: IpAddr,
    ) -> Reply {
        let req = Request {
            head,
            peer,
            encrypted: true,
        };
        let b = body.to_vec();
        ui.handle(&req, &mut |_| b.clone(), panel, now)
    }

    fn bytes(r: Reply) -> String {
        match r {
            Reply::Bytes(b) => String::from_utf8(b).unwrap(),
            Reply::Stream { head, view, .. } => {
                String::from_utf8([head, state_event(&view)].concat()).unwrap()
            }
        }
    }

    fn status(r: &str) -> &str {
        r.split("\r\n").next().unwrap()
    }

    fn post_form(path: &str, body: &str, extra: &[&str]) -> String {
        let cl = format!("Content-Length: {}", body.len());
        let mut e: Vec<&str> = vec!["Content-Type: application/x-www-form-urlencoded", &cl];
        e.extend_from_slice(extra);
        head("POST", path, &e)
    }

    /// Sign in and return (cookie header, csrf token).
    fn sign_in(ui: &Ui, panel: &Fake, now: Instant) -> (String, String) {
        let body = "username=owner&password=4321";
        let r = bytes(call(
            ui,
            panel,
            &post_form("/login", body, &[]),
            body.as_bytes(),
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 303"), "{r}");
        let id = r
            .split("\r\n")
            .find_map(|l| l.strip_prefix("Set-Cookie: tuxweb_session="))
            .and_then(|v| v.split(';').next())
            .unwrap()
            .to_string();
        let cookie = format!("Cookie: {SESSION_COOKIE}={id}");
        let page = bytes(call(ui, panel, &head("GET", "/", &[&cookie]), b"", now));
        let csrf = page
            .split("name=\"csrf-token\" content=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        assert_eq!(csrf.len(), 64);
        (cookie, csrf)
    }

    #[test]
    fn routes_follow_method_and_path() {
        assert_eq!(route("GET", "/"), Route::Index);
        assert_eq!(route("GET", "/?x=1"), Route::Index);
        assert_eq!(route("POST", "/"), Route::MethodNotAllowed("GET"));
        assert_eq!(route("GET", "/login"), Route::LoginPage);
        assert_eq!(route("POST", "/login"), Route::LoginSubmit);
        assert_eq!(route("PUT", "/login"), Route::MethodNotAllowed("GET, POST"));
        assert_eq!(route("POST", "/logout"), Route::Logout);
        assert_eq!(route("GET", "/logout"), Route::MethodNotAllowed("POST"));
        assert_eq!(route("GET", "/ui/events"), Route::Events);
        assert_eq!(route("POST", "/ui/arm"), Route::Arm);
        assert_eq!(route("GET", "/ui/arm"), Route::MethodNotAllowed("POST"));
        assert_eq!(route("POST", "/ui/disarm"), Route::Disarm);
        assert_eq!(route("GET", "/ui/assets/app.js"), Route::Asset(1));
        assert_eq!(route("GET", "/ui/assets/app.css?v=2"), Route::Asset(0));
        for p in [
            "/index.html",
            "/ui/assets/",
            "/ui/assets/../app.js",
            "/ui/assets/nope.js",
            "/authenticated/tuxedoapi.html",
            "/ui",
            "/login/",
            "/favicon.ico",
        ] {
            assert_eq!(route("GET", p), Route::NotFound, "{p}");
        }
    }

    #[test]
    fn every_response_carries_the_csp() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let (cookie, csrf) = sign_in(&ui, &panel, now);
        let tok = format!("X-CSRF-Token: {csrf}");
        let cases: Vec<(String, &str)> = vec![
            (head("GET", "/", &[]), ""),
            (head("GET", "/", &[&cookie]), ""),
            (head("GET", "/login", &[]), ""),
            (head("GET", "/login", &[&cookie]), ""),
            (
                post_form("/login", "username=x&password=y", &[]),
                "username=x&password=y",
            ),
            (post_form("/login", "", &[]), ""),
            (head("GET", "/ui/events", &[]), ""),
            (head("GET", "/ui/events", &[&cookie]), ""),
            (post_form("/ui/arm", "mode=stay", &[&cookie]), "mode=stay"),
            (
                post_form("/ui/arm", "mode=bogus", &[&cookie, &tok]),
                "mode=bogus",
            ),
            (post_form("/ui/disarm", "code=", &[&cookie, &tok]), "code="),
            (post_form("/ui/arm", "mode=stay", &[]), "mode=stay"),
            (head("GET", "/ui/assets/app.css", &[]), ""),
            (head("GET", "/ui/assets/app.js", &[]), ""),
            (head("GET", "/ui/assets/icon.svg", &[]), ""),
            (head("GET", "/nope", &[]), ""),
            (head("DELETE", "/", &[]), ""),
            (post_form("/logout", "", &[&cookie, &tok]), ""),
        ];
        for (h, body) in cases {
            let r = bytes(call(&ui, &panel, &h, body.as_bytes(), now));
            assert!(
                r.contains(&format!("\r\nContent-Security-Policy: {CSP}\r\n")),
                "no CSP on {}: {}",
                h.lines().next().unwrap(),
                status(&r)
            );
            assert!(r.contains("\r\nX-Content-Type-Options: nosniff\r\n"));
            // no-referrer makes a browser send `Origin: null` on the sign-in POST
            assert!(r.contains("\r\nReferrer-Policy: same-origin\r\n"));
        }
        for r in [too_many_streams(), stream_head()] {
            assert!(String::from_utf8(r)
                .unwrap()
                .contains(&format!("\r\nContent-Security-Policy: {CSP}\r\n")));
        }
        assert!(CSP.starts_with("default-src 'self'"));
        assert!(!CSP.contains("unsafe"));
    }

    #[test]
    fn pages_hold_no_inline_script_style_or_outside_resource() {
        // ` onclick=`, ` onload=` ...: an attribute starting "on" and ending "="
        let handler = |page: &str| {
            page.split(" on").skip(1).any(|rest| {
                let word: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphabetic())
                    .collect();
                !word.is_empty() && rest[word.len()..].starts_with('=')
            })
        };
        assert!(handler("<a onclick=\"x\">"), "the check can fail");
        for (name, page) in [("login", LOGIN_HTML), ("index", INDEX_HTML)] {
            assert!(!page.contains("<script>"), "{name}: inline script");
            assert!(!page.contains(" style="), "{name}: inline style");
            assert!(!page.contains("<style"), "{name}: style element");
            assert!(!handler(page), "{name}: inline event handler");
            assert!(
                !page.contains("http://") && !page.contains("https://"),
                "{name}"
            );
        }
        for (name, _, body) in ASSETS {
            // the SVG namespace is a name, not a fetch
            let body = body.replace("xmlns=\"http://www.w3.org/2000/svg\"", "");
            assert!(
                !body.contains("http://") && !body.contains("https://"),
                "{name}"
            );
        }
    }

    #[test]
    fn the_session_cookie_carries_every_attribute() {
        let c = set_cookie("ab");
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(c.split("; ").any(|a| a == attr), "{attr} missing from {c}");
        }
        assert!(c.starts_with("Set-Cookie: tuxweb_session=ab;"));
        let gone = clear_cookie();
        for attr in [
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Path=/",
            "Max-Age=0",
        ] {
            assert!(
                gone.split("; ").any(|a| a == attr),
                "{attr} missing from {gone}"
            );
        }

        // and that is what a sign-in actually sets
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let body = "username=OWNER&password=4321";
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/login", body, &[]),
            body.as_bytes(),
            Instant::now(),
        ));
        assert!(status(&r).starts_with("HTTP/1.1 303"));
        assert!(r.contains("\r\nLocation: /\r\n"));
        let line = r
            .split("\r\n")
            .find(|l| l.starts_with("Set-Cookie:"))
            .unwrap();
        let id = line
            .trim_start_matches("Set-Cookie: tuxweb_session=")
            .split(';')
            .next()
            .unwrap();
        assert_eq!(id.len(), 64, "32 random bytes, hex");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(line, set_cookie(id));
    }

    #[test]
    fn signed_out_requests_go_to_sign_in_or_are_refused() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let r = bytes(call(&ui, &panel, &head("GET", "/", &[]), b"", now));
        assert!(status(&r).starts_with("HTTP/1.1 303"));
        assert!(r.contains("\r\nLocation: /login\r\n"));
        // a well-formed but unknown session id is no session
        let forged = format!("Cookie: {SESSION_COOKIE}={}", "a".repeat(64));
        let r = bytes(call(&ui, &panel, &head("GET", "/", &[&forged]), b"", now));
        assert!(r.contains("\r\nLocation: /login\r\n"));
        let r = bytes(call(
            &ui,
            &panel,
            &head("GET", "/ui/events", &[&forged]),
            b"",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 401"));
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/ui/arm", "mode=stay", &[&forged]),
            b"mode=stay",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 401"));
        assert!(panel.sent().is_empty());
        // the API's token cookie is not a browser session
        let tok = format!("Cookie: tuxweb_token={}", "b".repeat(64));
        let r = bytes(call(&ui, &panel, &head("GET", "/", &[&tok]), b"", now));
        assert!(r.contains("\r\nLocation: /login\r\n"));
    }

    #[test]
    fn a_session_expires_after_twelve_idle_hours() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let t0 = Instant::now();
        let (cookie, _) = sign_in(&ui, &panel, t0);
        let id = cookie.rsplit('=').next().unwrap().to_string();
        let page = |t: Instant| {
            status(&bytes(call(
                &ui,
                &panel,
                &head("GET", "/", &[&cookie]),
                b"",
                t,
            )))
            .to_string()
        };
        // used at 11 h: still good, and the use resets the idle clock
        let t1 = t0 + Duration::from_secs(11 * 3600);
        assert!(page(t1).starts_with("HTTP/1.1 200"));
        let t2 = t1 + Duration::from_secs(11 * 3600);
        assert!(
            page(t2).starts_with("HTTP/1.1 200"),
            "22 h after sign-in, 11 h idle"
        );
        // an open event stream does not keep it alive
        assert!(ui.session_alive(&id, t2 + SESSION_IDLE - Duration::from_secs(1)));
        assert!(!ui.session_alive(&id, t2 + SESSION_IDLE));
        // 12 idle hours: gone, and gone for good
        assert!(page(t2 + SESSION_IDLE).starts_with("HTTP/1.1 303"));
        assert!(page(t2 + Duration::from_secs(1)).starts_with("HTTP/1.1 303"));
    }

    #[test]
    fn sign_out_ends_the_session() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let (cookie, csrf) = sign_in(&ui, &panel, now);
        let tok = format!("X-CSRF-Token: {csrf}");
        // without the token, sign-out is refused like any other state change
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/logout", "", &[&cookie]),
            b"",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 403"));
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/logout", "", &[&cookie, &tok]),
            b"",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 200"));
        assert!(r.contains(&clear_cookie()));
        let r = bytes(call(&ui, &panel, &head("GET", "/", &[&cookie]), b"", now));
        assert!(r.contains("\r\nLocation: /login\r\n"));
    }

    #[test]
    fn a_state_change_without_the_csrf_token_sends_nothing() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let (cookie, csrf) = sign_in(&ui, &panel, now);
        for tok in [
            None,
            Some("X-CSRF-Token: ".to_string()),
            Some(format!("X-CSRF-Token: {}", "0".repeat(64))),
            Some(format!("X-CSRF-Token: {}", &csrf[..63])),
        ] {
            let mut extra = vec![cookie.as_str()];
            if let Some(t) = &tok {
                extra.push(t);
            }
            let r = bytes(call(
                &ui,
                &panel,
                &post_form("/ui/arm", "mode=away", &extra),
                b"mode=away",
                now,
            ));
            assert!(status(&r).starts_with("HTTP/1.1 403"), "{tok:?}: {r}");
            *panel.armed.lock().unwrap() = Some(true);
            let r = bytes(call(
                &ui,
                &panel,
                &post_form("/ui/disarm", "code=1234", &extra),
                b"code=1234",
                now,
            ));
            assert!(status(&r).starts_with("HTTP/1.1 403"), "{tok:?}: {r}");
            *panel.armed.lock().unwrap() = Some(false);
        }
        // a cross-origin request is refused even with the right token
        let tok = format!("X-CSRF-Token: {csrf}");
        let r = bytes(call(
            &ui,
            &panel,
            &post_form(
                "/ui/arm",
                "mode=away",
                &[&cookie, &tok, "Origin: https://evil.test"],
            ),
            b"mode=away",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 403"));
        assert!(panel.sent().is_empty(), "nothing may reach the panel");
        // the same request, same origin: it goes through
        let r = bytes(call(
            &ui,
            &panel,
            &post_form(
                "/ui/arm",
                "mode=away",
                &[&cookie, &tok, "Origin: https://panel.test"],
            ),
            b"mode=away",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 200"), "{r}");
        assert_eq!(panel.sent().len(), 1);
    }

    #[test]
    fn arming_sends_the_no_code_sentinel_and_never_a_code() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let (cookie, csrf) = sign_in(&ui, &panel, now);
        let tok = format!("X-CSRF-Token: {csrf}");
        for (mode, code) in [("stay", 2), ("away", 1), ("night", 4)] {
            let body = format!("mode={mode}");
            let r = bytes(call(
                &ui,
                &panel,
                &post_form("/ui/arm", &body, &[&cookie, &tok]),
                body.as_bytes(),
                now,
            ));
            assert!(status(&r).starts_with("HTTP/1.1 200"), "{r}");
            assert!(r.contains("\"ok\":true"));
            assert_eq!(panel.sent().last(), Some(&(code, 0xFFFF, 0xFF)), "{mode}");
        }
        assert_eq!(crate::ipc::NO_CODE, 0xFFFF);
        // a code sent along is ignored, not forwarded
        let body = "mode=stay&code=1234";
        bytes(call(
            &ui,
            &panel,
            &post_form("/ui/arm", body, &[&cookie, &tok]),
            body.as_bytes(),
            now,
        ));
        assert_eq!(panel.sent().last(), Some(&(2, 0xFFFF, 0xFF)));
        // an unknown mode sends nothing; arming an armed panel sends nothing
        let n = panel.sent().len();
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/ui/arm", "mode=max", &[&cookie, &tok]),
            b"mode=max",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 400"));
        *panel.armed.lock().unwrap() = Some(true);
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/ui/arm", "mode=stay", &[&cookie, &tok]),
            b"mode=stay",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 409"));
        assert_eq!(panel.sent().len(), n);
    }

    #[test]
    fn disarming_needs_a_real_code_and_refuses_zero_before_sending() {
        let ui = Ui::new();
        let panel = Fake::new(Some(true));
        let now = Instant::now();
        let (cookie, csrf) = sign_in(&ui, &panel, now);
        let tok = format!("X-CSRF-Token: {csrf}");
        for body in [
            "",
            "code=",
            "code=0000",
            "code=0",
            "code=12",
            "code=12345",
            "code=12a4",
            "code=%30%30%30%30",
        ] {
            let r = bytes(call(
                &ui,
                &panel,
                &post_form("/ui/disarm", body, &[&cookie, &tok]),
                body.as_bytes(),
                now,
            ));
            assert!(status(&r).starts_with("HTTP/1.1 400"), "{body:?}: {r}");
        }
        assert!(
            panel.sent().is_empty(),
            "no refused disarm may reach the panel"
        );
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/ui/disarm", "code=1234", &[&cookie, &tok]),
            b"code=1234",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 200"), "{r}");
        assert_eq!(panel.sent(), vec![(3, 1234, 0xFE)]);
        // the vendor's atoi: a leading zero is the same number
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/ui/disarm", "code=0123", &[&cookie, &tok]),
            b"code=0123",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 200"));
        assert_eq!(panel.sent().last(), Some(&(3, 123, 0xFE)));
        // disarming a disarmed panel sends nothing
        *panel.armed.lock().unwrap() = Some(false);
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/ui/disarm", "code=1234", &[&cookie, &tok]),
            b"code=1234",
            now,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 409"));
        assert_eq!(panel.sent().len(), 2);
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        assert_eq!(backoff_delay(0), Duration::ZERO);
        assert_eq!(backoff_delay(FREE_FAILURES - 1), Duration::ZERO);
        assert_eq!(backoff_delay(FREE_FAILURES), Duration::from_secs(1));
        assert_eq!(backoff_delay(FREE_FAILURES + 1), Duration::from_secs(2));
        assert_eq!(backoff_delay(FREE_FAILURES + 3), Duration::from_secs(8));
        assert_eq!(backoff_delay(FREE_FAILURES + 30), BACKOFF_CAP);
        assert_eq!(backoff_delay(u32::MAX), BACKOFF_CAP);
        let mut b = Backoff::default();
        let t = Instant::now();
        for _ in 0..FREE_FAILURES - 1 {
            b.fail(IP, t);
        }
        assert_eq!(b.wait(IP, t), None);
        b.fail(IP, t);
        assert_eq!(b.wait(IP, t), Some(Duration::from_secs(1)));
        assert_eq!(b.wait(IP, t + Duration::from_secs(1)), None);
        assert_eq!(b.wait(OTHER, t), None, "per address");
        // a day without failures starts clean
        b.fail(IP, t);
        assert_eq!(b.fail(IP, t + BACKOFF_FORGET), 1);
    }

    #[test]
    fn failed_sign_ins_back_off_per_address_without_locking_the_account() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let t = Instant::now();
        let wrong = "username=owner&password=0000";
        let right = "username=owner&password=4321";
        let login = |body: &str, at: Instant, peer: IpAddr| {
            bytes(call_from(
                &ui,
                &panel,
                &post_form("/login", body, &[]),
                body.as_bytes(),
                at,
                peer,
            ))
        };
        for i in 0..FREE_FAILURES {
            let r = login(wrong, t, IP);
            assert!(status(&r).starts_with("HTTP/1.1 401"), "attempt {i}");
            assert!(r.contains("Wrong username or password."));
            assert!(!r.contains("Set-Cookie"));
        }
        let checked = *panel.auth_calls.lock().unwrap();
        // now even the right password waits, and is not checked
        let r = login(right, t, IP);
        assert!(status(&r).starts_with("HTTP/1.1 429"), "{r}");
        assert!(r.contains("\r\nRetry-After: 1\r\n"));
        assert!(!r.contains("Set-Cookie"));
        assert_eq!(
            *panel.auth_calls.lock().unwrap(),
            checked,
            "a refused attempt is not a guess"
        );
        // another address signs in to the same account at the same moment
        let r = login(right, t, OTHER);
        assert!(
            status(&r).starts_with("HTTP/1.1 303"),
            "the account is not locked: {r}"
        );
        // after the wait the next wrong one doubles it
        let t1 = t + Duration::from_secs(1);
        assert!(status(&login(wrong, t1, IP)).starts_with("HTTP/1.1 401"));
        let r = login(right, t1 + Duration::from_millis(1500), IP);
        assert!(status(&r).starts_with("HTTP/1.1 429"));
        assert!(
            r.contains("\r\nRetry-After: 1\r\n"),
            "2 s from the failure, 0.5 s left rounds up"
        );
        // a success clears the address
        let t2 = t1 + Duration::from_secs(2);
        assert!(status(&login(right, t2, IP)).starts_with("HTTP/1.1 303"));
        assert!(status(&login(wrong, t2, IP)).starts_with("HTTP/1.1 401"));
        assert!(
            status(&login(wrong, t2, IP)).starts_with("HTTP/1.1 401"),
            "free failures again"
        );
    }

    #[test]
    fn sign_in_errors_say_one_thing_and_an_unreadable_store_is_not_a_failure() {
        let ui = Ui::new();
        let mut panel = Fake::new(Some(false));
        let t = Instant::now();
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/login", "username=&password=1", &[]),
            b"username=&password=1",
            t,
        ));
        assert!(status(&r).starts_with("HTTP/1.1 400"));
        panel.unavailable = true;
        for _ in 0..10 {
            let body = "username=owner&password=4321";
            let r = bytes(call(
                &ui,
                &panel,
                &post_form("/login", body, &[]),
                body.as_bytes(),
                t,
            ));
            assert!(status(&r).starts_with("HTTP/1.1 503"));
        }
        assert_eq!(ui.backoff().wait(IP, t), None, "not the client's failure");
        // a username is echoed escaped, never as markup
        panel.unavailable = false;
        let body = "username=%3Cb%3E&password=1";
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/login", body, &[]),
            body.as_bytes(),
            t,
        ));
        assert!(r.contains("value=\"&lt;b&gt;\""));
        assert!(!r.contains("<b>"));
        // cross-origin sign-in is refused before anything is checked
        let calls = *panel.auth_calls.lock().unwrap();
        let body = "username=owner&password=4321";
        let r = bytes(call(
            &ui,
            &panel,
            &post_form("/login", body, &["Origin: http://panel.test"]),
            body.as_bytes(),
            t,
        ));
        assert!(
            status(&r).starts_with("HTTP/1.1 403"),
            "http origin on an https connection"
        );
        assert_eq!(*panel.auth_calls.lock().unwrap(), calls);
    }

    #[test]
    fn the_status_page_and_stream_need_a_session() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let (cookie, _) = sign_in(&ui, &panel, now);
        let page = bytes(call(&ui, &panel, &head("GET", "/", &[&cookie]), b"", now));
        assert!(status(&page).starts_with("HTTP/1.1 200"));
        assert!(!page.contains("{{"), "every slot filled");
        assert!(page.contains("Owner"));
        assert!(page.contains(crate::api::FIRMWARE));
        assert!(page.contains("Certificate expires 2027-11-06 12:00 UTC"));
        assert!(page.contains("\r\nCache-Control: no-store\r\n"));
        // signed in, /login goes home
        let r = bytes(call(
            &ui,
            &panel,
            &head("GET", "/login", &[&cookie]),
            b"",
            now,
        ));
        assert!(r.contains("\r\nLocation: /\r\n"));
        match call(
            &ui,
            &panel,
            &head("GET", "/ui/events", &[&cookie]),
            b"",
            now,
        ) {
            Reply::Stream {
                head,
                view,
                session,
            } => {
                let head = String::from_utf8(head).unwrap();
                assert!(head.contains("Content-Type: text/event-stream"));
                assert!(!head.contains("Content-Length"));
                let first = String::from_utf8(state_event(&view)).unwrap();
                assert!(first.starts_with("event: state\ndata: {"));
                assert!(first.ends_with("}\n\n"));
                assert_eq!(cookie, format!("Cookie: {SESSION_COOKIE}={session}"));
            }
            other => panic!("expected a stream, got {other:?}"),
        }
        let login = bytes(call(&ui, &panel, &head("GET", "/login", &[]), b"", now));
        assert!(!login.contains("{{"));
        assert_eq!(cert_line(None), "No certificate: plaintext");
    }

    #[test]
    fn a_large_form_is_refused_unread() {
        let ui = Ui::new();
        let panel = Fake::new(Some(false));
        let now = Instant::now();
        let (cookie, csrf) = sign_in(&ui, &panel, now);
        let tok = format!("X-CSRF-Token: {csrf}");
        let h = head("POST", "/ui/arm", &[&cookie, &tok, "Content-Length: 99999"]);
        let req = Request {
            head: &h,
            peer: IP,
            encrypted: true,
        };
        let r = ui.handle(
            &req,
            &mut |_| panic!("read a body over the limit"),
            &panel,
            now,
        );
        assert!(status(&bytes(r)).starts_with("HTTP/1.1 413"));
        assert!(panel.sent().is_empty());
    }

    fn status_raw(msg_type: u32, arg: u32, text: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; crate::ipc::REPLY_LEN];
        b[0x04..0x08].copy_from_slice(&msg_type.to_le_bytes());
        b[0x08..0x0C].copy_from_slice(&arg.to_le_bytes());
        b[0x0E..0x0E + text.len()].copy_from_slice(text);
        b
    }

    #[test]
    fn the_view_shows_the_panels_countdown_and_armed_only_when_reported() {
        let mut st = PanelState::new();
        let v = View::from_state(&st);
        assert_eq!((v.phase, v.armed), ("unknown", None));
        assert_eq!(v.headline, "Waiting for the panel");

        st.observe(&status_raw(21, 1, b"\xfe1Ready To Arm"), 0);
        st.observe(&status_raw(20, 0, b"****DISARMED****|  Ready to Arm  "), 0);
        let v = View::from_state(&st);
        assert_eq!((v.phase, v.armed, v.link), ("disarmed", Some(false), "ok"));
        assert_eq!(v.headline, "Ready To Arm");
        assert_eq!(v.lcd, vec!["****DISARMED****", "  Ready to Arm"]);
        assert_eq!(v.mode, None);

        // the captured exit delay: the leading 2 is the bar colour, not the count
        st.observe(&status_raw(21, 1, b"\xff259  Secs Remaining"), 0);
        st.observe(&status_raw(20, 0, b"ARMED ***AWAY***|May Exit Now  60"), 0);
        let v = View::from_state(&st);
        assert_eq!(
            (v.phase, v.armed, v.countdown),
            ("arming", Some(true), Some(59))
        );
        assert_eq!(v.headline, "Arming away, 59 s to leave");
        st.observe(&status_raw(21, 1, b"\xff21  Secs Remaining"), 0);
        assert_eq!(View::from_state(&st).headline, "Arming away, 1 s to leave");

        st.observe(&status_raw(21, 1, b"\xff2Armed Away"), 0);
        let v = View::from_state(&st);
        assert_eq!((v.phase, v.countdown), ("armed", None));
        assert_eq!(v.headline, "Armed Away");

        st.observe(&status_raw(21, 1, b"\xff2Armed Stay Alarm"), 0);
        assert_eq!(View::from_state(&st).phase, "alarm");
        st.observe(&status_raw(21, 1, b"\xff2Entry Delay Active"), 0);
        assert_eq!(View::from_state(&st).phase, "other");

        // no mode on the display: the countdown alone
        st.observe(&status_raw(20, 0, b"PLEASE WAIT|"), 0);
        st.observe(&status_raw(21, 1, b"\xff230  Secs Remaining"), 0);
        assert_eq!(View::from_state(&st).headline, "Arming, 30 s to leave");

        // the link: -1 at +0x08 is lost, a 22 is the VISTA calling itself offline
        st.observe(&status_raw(21, u32::MAX, b"\xfe1Ready To Arm"), 0);
        assert_eq!(View::from_state(&st).link, "lost");
        st.observe(&status_raw(22, 3, b"\xfe1Ready To Arm"), 0);
        assert_eq!(View::from_state(&st).link, "offline");

        let j = View::from_state(&st).to_json();
        assert!(j.contains("\"phase\":\"disarmed\""), "{j}");
        assert!(!j.contains('\n'), "one SSE data line");
    }

    #[test]
    fn countdown_reads_only_the_panels_spelling() {
        assert_eq!(countdown("59  Secs Remaining"), Some(59));
        assert_eq!(countdown("1  Secs Remaining"), Some(1));
        assert_eq!(countdown("Armed Stay"), None);
        assert_eq!(countdown("Secs Remaining"), None);
        assert_eq!(countdown("x  Secs Remaining"), None);
    }

    #[test]
    fn session_ids_are_read_only_in_their_own_shape() {
        let id = "A".repeat(64);
        let h = head(
            "GET",
            "/",
            &[&format!("Cookie: other=1; {SESSION_COOKIE}={id}; x=y")],
        );
        assert_eq!(session_id(&h), Some("a".repeat(64)));
        let h = head("GET", "/", &[&format!("Cookie: {SESSION_COOKIE}=short")]);
        assert_eq!(session_id(&h), None);
        let h = head(
            "GET",
            "/",
            &[
                "Cookie: tuxweb_token=abc",
                &format!("Cookie: {SESSION_COOKIE}={id}"),
            ],
        );
        assert_eq!(
            session_id(&h),
            Some("a".repeat(64)),
            "a second Cookie header is read"
        );
    }

    #[test]
    fn sessions_are_bounded() {
        let mut s = Sessions::default();
        let t = Instant::now();
        for i in 0..MAX_SESSIONS + 5 {
            s.insert(
                format!("{i}"),
                "u".into(),
                "c".into(),
                t + Duration::from_secs(i as u64),
            );
        }
        assert_eq!(s.map.len(), MAX_SESSIONS);
        assert!(
            !s.map.contains_key("0"),
            "the least recently used went first"
        );
    }
}
