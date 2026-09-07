//! Log in to the vendor server and obtain a session cookie.
//!
//! The shim needs this because **panel sessions are bound to the client's
//! source IP** (measured 2026-09-06): a cookie obtained anywhere else is
//! rejected, so whatever uses a session has to create it itself.
//!
//! The exchange, reproduced from the working Python client:
//!
//! 1. `GET /authenticated/index.html?url=tuxedoapi.html`. The response headers
//!    carry `Random` (the challenge), `RandomID`, and a `_zFL` cookie.
//! 2. POST the same URL with
//!    `log  = HMAC-SHA512(challenge, username)`,
//!    `log1 = HMAC-SHA512(challenge, username + password)`,
//!    `identity = RandomID`, carrying the `_zFL` cookie.
//! 3. The reply's `Set-Cookie` holds the session — the cookie that is *not*
//!    `_zFL`.
//!
//! THE QUIRK THAT BREAKS REIMPLEMENTATIONS: the HMAC key is the challenge's
//! literal **hex text**, used as ASCII bytes. Hex-decoding it first produces a
//! client that authenticates against nothing and fails every call.
//!
//! Plain HTTP only. That is not a shortcut: this runs on the panel and talks to
//! Barracuda over loopback, where there is no wire to protect and the vendor's
//! TLS is the expired compiled-in certificate anyway.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ring::hmac;

const LOGIN_PATH: &str = "/authenticated/index.html?url=tuxedoapi.html";

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// HMAC-SHA512 with the key taken as ASCII text, per the quirk above.
fn hmac_hex(key_text: &str, msg: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA512, key_text.as_bytes());
    hex(hmac::sign(&key, msg.as_bytes()).as_ref())
}

fn percent_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// Every `Set-Cookie`, since the panel sends two and only one is the session.
    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn request(
    upstream: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> Result<Response, String> {
    let mut s = TcpStream::connect(upstream).map_err(|e| format!("connect {upstream}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let host = upstream.split(':').next().unwrap_or("panel");

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 256 * 1024 {
                    break;
                }
                if find(&raw, b"\r\n\r\n").is_some() && method == "GET" && raw.len() > 2048 {
                    break; // headers are all we need; do not drain the page
                }
            }
            Err(_) => break,
        }
    }
    let end = find(&raw, b"\r\n\r\n").ok_or("no header terminator in response")?;
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("unparsable status line: {status_line:?}"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    Ok(Response { status, headers })
}

/// Returns the session cookie, ready to put in a `Cookie:` header.
pub fn login(upstream: &str, username: &str, password: &str) -> Result<String, String> {
    let r = request(upstream, "GET", LOGIN_PATH, &[], None)?;
    if r.status != 200 && r.status != 302 {
        return Err(format!("login page returned HTTP {}", r.status));
    }
    let challenge = r
        .header("Random")
        .ok_or("login page sent no Random header -- not a Tuxedo Touch?")?
        .to_string();
    let random_id = r
        .header("RandomID")
        .ok_or("login page sent no RandomID header")?
        .to_string();
    let zfl = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("_zFL"))
        .and_then(|c| c.split(';').next())
        .map(|s| s.to_string());

    let user = username.to_lowercase();
    let body = format!(
        "log={}&log1={}&identity={}",
        hmac_hex(&challenge, &user),
        hmac_hex(&challenge, &(user.clone() + password)),
        percent_encode(&random_id),
    );

    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(z) = zfl.as_deref() {
        extra.push(("Cookie", z));
    }
    let r = request(upstream, "POST", LOGIN_PATH, &extra, Some(&body))?;
    if r.status != 200 && r.status != 302 {
        return Err(format!("login POST returned HTTP {}", r.status));
    }
    for c in r.set_cookies() {
        let pair = c.split(';').next().unwrap_or("");
        if pair.starts_with("_zFL") || pair.is_empty() {
            continue;
        }
        return Ok(pair.to_string());
    }
    Err("no session cookie returned -- check the username and password".into())
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

    /// The key is the challenge's HEX TEXT, not its decoded bytes. This vector
    /// is produced by the working Python client, so a change that "fixes" the
    /// key handling breaks here rather than in the field.
    #[test]
    fn hmac_uses_the_challenge_as_ascii_text() {
        // python: hmac.new(b"abc123", b"lewis", sha512).hexdigest()
        let got = hmac_hex("abc123", "lewis");
        assert_eq!(got.len(), 128, "SHA-512 is 64 bytes = 128 hex chars");
        assert_eq!(
            got,
            "21e806dc99a7625f4e19d12a65530aacc39f1cd3888eb6ed2d3df4c15e43e669\
7d9efa98f832da1e6209f8c01e105b42694a2496125a72473601a0f20985301a",
            "if this fails, compare against the Python client rather than \
             adjusting the expectation"
        );
    }

    #[test]
    fn percent_encoding_leaves_unreserved_alone() {
        assert_eq!(percent_encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(percent_encode("a+b c/d"), "a%2Bb%20c%2Fd");
    }
}
